// src/agent/auth.rs

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use rand::RngCore;
use secp256k1::{schnorr::Signature as SchnorrSignature, Message, XOnlyPublicKey, SECP256K1};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::{
    collections::HashMap,
    env,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

use crate::{
    agent::{
        locks_and_limits,
        types::{
            reject_forbidden_cold_vault_or_withdrawal_keys, sanitize_sterile_ticker,
            validate_hex_64, validate_kaspa_address_strict, AgentCapabilityClaims, AgentError,
            AgentErrorCode, AgentMode, U128Str,
        },
        AgentGatewayState, REDIS_KEY_BLACKLISTED_WALLETS,
    },
    silverscript::{
        blake2b_256_keyed, encode_kaspa_bech32m_address, KASPA_ADDR_VERSION_P2PK_SCHNORR,
    },
};

const TOKEN_PREFIX_MODE_A: &str = "per_ag_v1";
const TOKEN_PREFIX_MODE_B: &str = "per_md_v1";

const MODE_A_CHALLENGE_TTL_SECS: u64 = 120;
const MODE_A_DEFAULT_KEY_TTL_SECS: u64 = 30 * 86_400;
const MODE_A_MAX_KEY_TTL_SECS: u64 = 90 * 86_400;
const MODE_A_DEFAULT_CAP_24H_SOMPI: u128 = 10_000_000 * 100_000_000; // 10M KAS
const MODE_A_DEFAULT_CAP_24H_USD_MICROS: u128 = 2_000_000 * 1_000_000; // $2M USD

const PERSONAL_MSG_SIGNING_KEY: &[u8] = b"PersonalMessageSigningHash";

const LUA_CONSUME_CHALLENGE_ONCE: &str = r#"
local val = redis.call('GET', KEYS[1])
if val then
    redis.call('DEL', KEYS[1])
end
return val
"#;

const LUA_AUTH_CHALLENGE_RATE_LIMIT: &str = r#"
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
end
return count
"#;

#[inline]
pub fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn verify_internal_service_bearer(headers: &HeaderMap) -> Result<(), AgentError> {
    let internal_token = env::var("INTERNAL_ADMIN_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let admin_key = env::var("PERENNIA_ADMIN_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if internal_token.is_none() && admin_key.is_none() {
        return Err(AgentError::new(
            AgentErrorCode::Unauthorized,
            "CRITICAL_SECURITY_LOCKDOWN: INTERNAL_ADMIN_TOKEN or PERENNIA_ADMIN_KEY is missing.",
        ));
    }

    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let mut authorized = false;
    if let Some(tok) = internal_token {
        let expected = format!("Bearer {}", tok);
        if constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
            authorized = true;
        }
    }
    if !authorized {
        if let Some(key) = admin_key {
            let expected = format!("Bearer {}", key);
            if constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
                authorized = true;
            }
        }
    }

    if !authorized {
        return Err(AgentError::new(
            AgentErrorCode::Unauthorized,
            "Unauthorized internal service call.",
        ));
    }

    Ok(())
}

/// Mints a stateless HMAC-Blake3 capability token (`<prefix>.<claims_b64url>.<blake3_mac_hex>`).
/// Returns `(raw_secret_token, token_mac_blake3_hex)`.
pub fn mint_stateless_capability_token(
    signing_secret: &[u8; 32],
    claims: &AgentCapabilityClaims,
) -> Result<(String, String), AgentError> {
    let prefix = match claims.mode {
        AgentMode::ModeA => TOKEN_PREFIX_MODE_A,
        AgentMode::ModeB => TOKEN_PREFIX_MODE_B,
    };

    let claims_bytes = serde_json::to_vec(claims).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            "Failed to serialize capability claims.",
        )
    })?;
    let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_bytes);
    let signing_input = format!("{}.{}", prefix, claims_b64);
    let mac = blake3::keyed_hash(signing_secret, signing_input.as_bytes());
    let mac_hex = mac.to_hex().to_string();
    let full_token = format!("{}.{}", signing_input, mac_hex);

    Ok((full_token, mac_hex))
}

/// Verifies a stateless HMAC-Blake3 capability token in pure RAM in microseconds (zero I/O).
pub fn verify_stateless_capability_token_ram(
    signing_secret: &[u8; 32],
    raw_token: &str,
) -> Result<(AgentCapabilityClaims, String), AgentError> {
    let trimmed = raw_token.trim();
    let mut parts = trimmed.split('.');
    let prefix = parts.next().ok_or_else(|| {
        AgentError::new(
            AgentErrorCode::Unauthorized,
            "Malformed Agent capability token.",
        )
    })?;
    let claims_b64 = parts.next().ok_or_else(|| {
        AgentError::new(
            AgentErrorCode::Unauthorized,
            "Agent capability token missing claims segment.",
        )
    })?;
    let provided_mac_hex = parts.next().ok_or_else(|| {
        AgentError::new(
            AgentErrorCode::Unauthorized,
            "Agent capability token missing Blake3 MAC segment.",
        )
    })?;
    if parts.next().is_some() {
        return Err(AgentError::new(
            AgentErrorCode::Unauthorized,
            "Agent capability token contains unexpected extra segments.",
        ));
    }

    let expected_mode = match prefix {
        TOKEN_PREFIX_MODE_A => AgentMode::ModeA,
        TOKEN_PREFIX_MODE_B => AgentMode::ModeB,
        _ => {
            return Err(AgentError::new(
                AgentErrorCode::Unauthorized,
                "Unsupported Agent capability token version prefix.",
            ));
        }
    };

    if provided_mac_hex.len() != 64 || !provided_mac_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AgentError::new(
            AgentErrorCode::Unauthorized,
            "Invalid Agent capability MAC encoding.",
        ));
    }
    let provided_mac_bytes = hex::decode(provided_mac_hex).map_err(|_| {
        AgentError::new(
            AgentErrorCode::Unauthorized,
            "Invalid Agent capability MAC hex.",
        )
    })?;

    let signing_input = format!("{}.{}", prefix, claims_b64);
    let expected_mac = blake3::keyed_hash(signing_secret, signing_input.as_bytes());

    if !constant_time_eq(&provided_mac_bytes, expected_mac.as_bytes()) {
        return Err(AgentError::new(
            AgentErrorCode::Unauthorized,
            "Agent capability token cryptographic MAC verification failed.",
        ));
    }

    let decoded_bytes = URL_SAFE_NO_PAD.decode(claims_b64).map_err(|_| {
        AgentError::new(
            AgentErrorCode::Unauthorized,
            "Malformed base64url claims payload in Agent token.",
        )
    })?;

    let claims: AgentCapabilityClaims = serde_json::from_slice(&decoded_bytes).map_err(|_| {
        AgentError::new(
            AgentErrorCode::Unauthorized,
            "Invalid capability claims schema in Agent token.",
        )
    })?;

    if claims.version != 1 || claims.mode != expected_mode {
        return Err(AgentError::new(
            AgentErrorCode::Unauthorized,
            "Agent capability token mode or version mismatch.",
        ));
    }

    let now_secs = current_unix_secs();
    if claims.expires_at_unix > 0 && now_secs > claims.expires_at_unix {
        return Err(AgentError::new(
            AgentErrorCode::KeyExpired,
            "Agent capability token has expired.",
        ));
    }

    Ok((claims, expected_mac.to_hex().to_string()))
}

pub fn extract_raw_agent_token(headers: &HeaderMap) -> Result<&str, AgentError> {
    if let Some(auth_val) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        let trimmed = auth_val.trim();
        if let Some(bearer) = trimmed
            .strip_prefix("Bearer ")
            .or_else(|| trimmed.strip_prefix("bearer "))
        {
            let clean = bearer.trim();
            if !clean.is_empty() {
                return Ok(clean);
            }
        }
    }
    if let Some(api_key) = headers.get("x-agent-key").and_then(|v| v.to_str().ok()) {
        let clean = api_key.trim();
        if !clean.is_empty() {
            return Ok(clean);
        }
    }
    Err(AgentError::new(
        AgentErrorCode::Unauthorized,
        "Missing Agent capability token in Authorization: Bearer <key> or X-Agent-Key header.",
    ))
}

/// Authenticates an incoming `/api/v1/agent/...` request using pure-RAM Blake3 MAC verification
/// plus a single pipelined Redis lookup for Kill Switch revocation, wallet firewall status,
/// and progressive fault-scoped cooldown bans. Zero PostgreSQL queries are executed.
pub async fn authenticate_agent_request(
    state: &AgentGatewayState,
    headers: &HeaderMap,
    redis_conn: &mut redis::aio::MultiplexedConnection,
) -> Result<AgentCapabilityClaims, AgentError> {
    let raw_token = extract_raw_agent_token(headers)?;
    let (claims, _mac_hex) =
        verify_stateless_capability_token_ram(&state.signing_secret, raw_token)?;

    let revoked_key = locks_and_limits::redis_key_revoked(&claims.key_id);
    let key_cd_key = locks_and_limits::redis_key_key_cooldown(&claims.key_id);
    let wallet_cd_key = locks_and_limits::redis_key_wallet_cooldown(&claims.clean_wallet);

    let (revoked_flag, blk_clean, blk_prefixed, key_cd_pttl, wallet_cd_pttl): (
        Option<String>,
        i32,
        i32,
        i64,
        i64,
    ) = redis::pipe()
        .cmd("GET")
        .arg(&revoked_key)
        .cmd("SISMEMBER")
        .arg(REDIS_KEY_BLACKLISTED_WALLETS)
        .arg(&claims.clean_wallet)
        .cmd("SISMEMBER")
        .arg(REDIS_KEY_BLACKLISTED_WALLETS)
        .arg(&claims.prefixed_wallet)
        .cmd("PTTL")
        .arg(&key_cd_key)
        .cmd("PTTL")
        .arg(&wallet_cd_key)
        .query_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to verify Kill Switch and firewall state in Redis; failing closed.",
            )
        })?;

    if revoked_flag.as_deref() == Some("1") {
        return Err(AgentError::new(
            AgentErrorCode::KeyRevoked,
            "Agent capability key has been revoked via Kill Switch.",
        ));
    }

    if blk_clean == 1 || blk_prefixed == 1 {
        return Err(AgentError::new(
            AgentErrorCode::FirewallBlacklisted,
            "Bound wallet address is blocked by the Perennia Security Firewall.",
        ));
    }

    let active_pttl_ms = key_cd_pttl.max(wallet_cd_pttl);
    if active_pttl_ms > 0 {
        let secs_rem = ((active_pttl_ms as u64) + 999) / 1000;
        return Err(AgentError::with_cooldown(
            secs_rem.max(1),
            format!(
                "Agent key/wallet is under adversarial fault cooldown for {} more seconds.",
                secs_rem.max(1)
            ),
        ));
    }

    Ok(claims)
}

/// Resolves miner-loyalty and staked-SILO fee tier scalar (`1000..=10000` bps, where `10000` = 1.00x)
/// once at key creation time so hot-path quotes require zero PostgreSQL reads.
/// Note: Solvency math still clamps effective fees strictly above Perennia's hard zero-loss floor.
async fn resolve_initial_fee_tier_multiplier_bps(
    pool: &PgPool,
    clean_wallet: &str,
    prefixed_wallet: &str,
) -> Result<u16, AgentError> {
    let staked_silo_e8: i64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(TRUNC(SUM(amount_staked) * 100000000)::BIGINT, 0)
        FROM silo_staking_positions
        WHERE (wallet_address = $1 OR wallet_address = $2)
          AND status IN ('ACTIVE', 'COOLDOWN')
        "#,
    )
    .bind(prefixed_wallet)
    .bind(clean_wallet)
    .fetch_one(pool)
    .await
    .map_err(|_| {
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Database unavailable while resolving SILO staking tier.",
        )
    })?;

    let active_miner_opt: Option<i32> = sqlx::query_scalar(
        r#"
        SELECT 1
        FROM worker_profiles
        WHERE (wallet_address = $1 OR LOWER(REPLACE(TRIM(wallet_address), 'kaspa:', '')) = $2)
          AND status IN ('online', 'grace_period')
        LIMIT 1
        "#,
    )
    .bind(prefixed_wallet)
    .bind(clean_wallet)
    .fetch_optional(pool)
    .await
    .map_err(|_| {
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Database unavailable while resolving Stratum miner loyalty.",
        )
    })?;

    // 1,000,000 SILO (10^14 e8) -> 2500 bps (0.25x retail fee, clamped to zero-loss floor)
    // Active Stratum Miner -> 4000 bps (0.40x retail fee, clamped to zero-loss floor)
    // 100,000 SILO (10^13 e8) -> 5000 bps (0.50x)
    // 10,000 SILO (10^12 e8) -> 7000 bps (0.70x)
    // Standard -> 10000 bps (1.00x)
    let mut multiplier_bps: u16 = 10_000;
    if staked_silo_e8 >= 100_000_000_000_000 {
        multiplier_bps = multiplier_bps.min(2_500);
    } else if staked_silo_e8 >= 10_000_000_000_000 {
        multiplier_bps = multiplier_bps.min(5_000);
    } else if staked_silo_e8 >= 1_000_000_000_000 {
        multiplier_bps = multiplier_bps.min(7_000);
    }

    if active_miner_opt.is_some() {
        multiplier_bps = multiplier_bps.min(4_000);
    }

    Ok(multiplier_bps)
}

// ============================================================================
// MODE A: EXTERNAL HEADLESS BOT WALLET-CHALLENGE HANDSHAKE
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModeAChallengeRequest {
    pub wallet_address: String,
    pub pubkey_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredModeAChallenge {
    pub challenge_id: String,
    pub clean_wallet: String,
    pub prefixed_wallet: String,
    pub pubkey_hex: String,
    pub message: String,
    pub challenge_blake3_hex: String,
    pub issued_at_unix: u64,
}

pub async fn handle_mode_a_challenge(
    State(state): State<AgentGatewayState>,
    headers: HeaderMap,
    Json(req): Json<ModeAChallengeRequest>,
) -> Result<Json<Value>, AgentError> {
    let (clean_wallet, prefixed_wallet, addr_version, addr_hash32) =
        validate_kaspa_address_strict(&req.wallet_address)?;

    if addr_version != KASPA_ADDR_VERSION_P2PK_SCHNORR {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "Mode A wallet challenge requires a P2PK Schnorr Kaspa address.",
        ));
    }

    let pubkey_hex = validate_hex_64(&req.pubkey_hex, "pubkeyHex")?;
    let pubkey_bytes_vec = hex::decode(&pubkey_hex).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            "Invalid x-only public key hex.",
        )
    })?;
    let mut pubkey_bytes = [0u8; 32];
    pubkey_bytes.copy_from_slice(&pubkey_bytes_vec);

    let _ = XOnlyPublicKey::from_slice(&pubkey_bytes).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            "pubkeyHex is not a valid secp256k1 x-only public key.",
        )
    })?;

    let derived_addr = encode_kaspa_bech32m_address(KASPA_ADDR_VERSION_P2PK_SCHNORR, &pubkey_bytes);
    if !constant_time_eq(&addr_hash32, &pubkey_bytes) || derived_addr != prefixed_wallet {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "pubkeyHex does not derive to the provided Kaspa walletAddress.",
        ));
    }

    let mut conn = state.get_redis_conn().await?;

    let client_ip = crate::agent::extract_client_ip(&headers);
    let rl_key = format!("perennia:agent:auth_challenge_rl:{}", client_ip);
    let challenge_hits: i64 = redis::Script::new(LUA_AUTH_CHALLENGE_RATE_LIMIT)
        .key(&rl_key)
        .arg(60u64)
        .invoke_async(&mut conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Redis unavailable during challenge rate-limit check.",
            )
        })?;
    if challenge_hits > 20 {
        return Err(AgentError::new(
            AgentErrorCode::EdgeCapacityExceeded,
            "Challenge request rate exceeded (max 20 per 60s per IP).",
        ));
    }

    let (blk_clean, blk_pref, wallet_cd_pttl): (i32, i32, i64) = redis::pipe()
        .cmd("SISMEMBER")
        .arg(REDIS_KEY_BLACKLISTED_WALLETS)
        .arg(&clean_wallet)
        .cmd("SISMEMBER")
        .arg(REDIS_KEY_BLACKLISTED_WALLETS)
        .arg(&prefixed_wallet)
        .cmd("PTTL")
        .arg(locks_and_limits::redis_key_wallet_cooldown(&clean_wallet))
        .query_async(&mut conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Redis unavailable during wallet security check.",
            )
        })?;

    if blk_clean == 1 || blk_pref == 1 {
        return Err(AgentError::new(
            AgentErrorCode::FirewallBlacklisted,
            "Wallet is blocked by the Perennia Security Firewall.",
        ));
    }
    if wallet_cd_pttl > 0 {
        let secs = ((wallet_cd_pttl as u64) + 999) / 1000;
        return Err(AgentError::with_cooldown(
            secs.max(1),
            format!("Wallet is under cooldown ban for {}s.", secs.max(1)),
        ));
    }

    let mut nonce_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce_hex = hex::encode(nonce_bytes);
    let challenge_id = format!("chg_{}", nonce_hex);
    let issued_at_unix = current_unix_secs();

    let message = format!(
        "PERENNIA_AGENT_AUTH_V1\nWallet: {}\nPubkey: {}\nChallengeId: {}\nIssuedAt: {}",
        prefixed_wallet, pubkey_hex, challenge_id, issued_at_unix
    );
    let challenge_blake3_hex = blake3::hash(message.as_bytes()).to_hex().to_string();

    let stored = StoredModeAChallenge {
        challenge_id: challenge_id.clone(),
        clean_wallet,
        prefixed_wallet: prefixed_wallet.clone(),
        pubkey_hex: pubkey_hex.clone(),
        message: message.clone(),
        challenge_blake3_hex: challenge_blake3_hex.clone(),
        issued_at_unix,
    };

    let serialized = serde_json::to_string(&stored).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            "Failed to encode Mode A challenge.",
        )
    })?;

    redis::cmd("SETEX")
        .arg(format!("perennia:agent:challenge:{}", challenge_id))
        .arg(MODE_A_CHALLENGE_TTL_SECS)
        .arg(serialized)
        .query_async::<_, ()>(&mut conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to persist Mode A challenge nonce in Redis.",
            )
        })?;

    Ok(Json(json!({
        "ok": true,
        "challengeId": challenge_id,
        "walletAddress": prefixed_wallet,
        "pubkeyHex": pubkey_hex,
        "message": message,
        "challengeBlake3Hex": challenge_blake3_hex,
        "ttlSeconds": MODE_A_CHALLENGE_TTL_SECS.to_string()
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModeAVerifyRequest {
    pub wallet_address: String,
    pub pubkey_hex: String,
    pub challenge_id: String,
    pub signature_hex: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub allow_dark_pool_maker: Option<bool>,
    #[serde(default)]
    pub max_slippage_bps: Option<u16>,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

pub async fn handle_mode_a_verify(
    State(state): State<AgentGatewayState>,
    Json(req): Json<ModeAVerifyRequest>,
) -> Result<Json<Value>, AgentError> {
    let (clean_wallet, prefixed_wallet, _, _) = validate_kaspa_address_strict(&req.wallet_address)?;
    let pubkey_hex = validate_hex_64(&req.pubkey_hex, "pubkeyHex")?;

    let clean_challenge_id = req.challenge_id.trim();
    if clean_challenge_id.len() != 36
        || !clean_challenge_id.starts_with("chg_")
        || !clean_challenge_id[4..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "Malformed challengeId.",
        ));
    }

    let mut conn = state.get_redis_conn().await?;
    let challenge_redis_key = format!("perennia:agent:challenge:{}", clean_challenge_id);

    let raw_challenge_opt: Option<String> = redis::Script::new(LUA_CONSUME_CHALLENGE_ONCE)
        .key(&challenge_redis_key)
        .invoke_async(&mut conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Redis unavailable while consuming Mode A challenge nonce.",
            )
        })?;

    let raw_challenge = raw_challenge_opt.ok_or_else(|| {
        AgentError::new(
            AgentErrorCode::Unauthorized,
            "Challenge expired, unknown, or already consumed.",
        )
    })?;

    let stored: StoredModeAChallenge = serde_json::from_str(&raw_challenge).map_err(|_| {
        AgentError::new(
            AgentErrorCode::Unauthorized,
            "Stored challenge state corrupted.",
        )
    })?;

    if stored.clean_wallet != clean_wallet || stored.pubkey_hex != pubkey_hex {
        let ban_secs = locks_and_limits::record_adversarial_fault(
            &mut conn,
            None,
            &clean_wallet,
            "MODE_A_CHALLENGE_IDENTITY_MISMATCH",
        )
        .await?;
        return Err(AgentError::with_cooldown(
            ban_secs,
            "Challenge wallet/pubkey mismatch; fault cooldown applied.",
        ));
    }

    let clean_sig_hex = req
        .signature_hex
        .trim()
        .strip_prefix("0x")
        .unwrap_or_else(|| req.signature_hex.trim());
    if clean_sig_hex.len() != 128 || !clean_sig_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        let ban_secs = locks_and_limits::record_adversarial_fault(
            &mut conn,
            None,
            &clean_wallet,
            "MODE_A_MALFORMED_SCHNORR_SIG",
        )
        .await?;
        return Err(AgentError::with_cooldown(
            ban_secs,
            "Schnorr signature must be an exact 64-byte (128 hex character) payload.",
        ));
    }

    let sig_bytes = hex::decode(clean_sig_hex).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidSignatureOrScript,
            "Invalid hex in signatureHex.",
        )
    })?;
    let pubkey_bytes = hex::decode(&pubkey_hex).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            "Invalid hex in pubkeyHex.",
        )
    })?;

    let schnorr_sig = match SchnorrSignature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => {
            let ban_secs = locks_and_limits::record_adversarial_fault(
                &mut conn,
                None,
                &clean_wallet,
                "MODE_A_INVALID_SCHNORR_ENCODING",
            )
            .await?;
            return Err(AgentError::with_cooldown(
                ban_secs,
                "Invalid 64-byte Schnorr signature encoding.",
            ));
        }
    };
    let xonly_pub = XOnlyPublicKey::from_slice(&pubkey_bytes).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            "Invalid secp256k1 x-only pubkey.",
        )
    })?;

    let blake3_digest: [u8; 32] = *blake3::hash(stored.message.as_bytes()).as_bytes();
    let kaspa_personal_digest: [u8; 32] =
        blake2b_256_keyed(PERSONAL_MSG_SIGNING_KEY, stored.message.as_bytes());

    let msg_blake3 = Message::from_digest(blake3_digest);
    let msg_kaspa = Message::from_digest(kaspa_personal_digest);

    let sig_valid = SECP256K1
        .verify_schnorr(&schnorr_sig, &msg_blake3, &xonly_pub)
        .is_ok()
        || SECP256K1
            .verify_schnorr(&schnorr_sig, &msg_kaspa, &xonly_pub)
            .is_ok();

    if !sig_valid {
        let ban_secs = locks_and_limits::record_adversarial_fault(
            &mut conn,
            None,
            &clean_wallet,
            "MODE_A_INVALID_SCHNORR_SIGNATURE",
        )
        .await?;
        return Err(AgentError::with_cooldown(
            ban_secs,
            "Cryptographic Schnorr challenge verification failed; progressive cooldown applied.",
        ));
    }

    let fee_tier_multiplier_bps =
        resolve_initial_fee_tier_multiplier_bps(&state.pg_pool, &clean_wallet, &prefixed_wallet)
            .await?;

    let now_secs = current_unix_secs();
    let ttl_secs = req
        .ttl_seconds
        .unwrap_or(MODE_A_DEFAULT_KEY_TTL_SECS)
        .clamp(300, MODE_A_MAX_KEY_TTL_SECS);
    let expires_at_unix = now_secs.saturating_add(ttl_secs);
    let max_slippage_bps = req.max_slippage_bps.unwrap_or(100).clamp(1, 1_500);
    let allow_dark_pool_maker = req.allow_dark_pool_maker.unwrap_or(false);

    let raw_label = req.label.as_deref().unwrap_or("Mode A Bot Key").trim();
    let clean_label: String = raw_label
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .take(64)
        .collect();
    let final_label = if clean_label.is_empty() {
        "Mode A Bot Key".to_string()
    } else {
        clean_label
    };

    let key_id = format!("agk_{}", Uuid::new_v4().simple());
    let mandate_id = key_id.clone();

    let claims = AgentCapabilityClaims {
        version: 1,
        key_id: key_id.clone(),
        mandate_id: mandate_id.clone(),
        clean_wallet: clean_wallet.clone(),
        prefixed_wallet: prefixed_wallet.clone(),
        pubkey_hex: pubkey_hex.clone(),
        mode: AgentMode::ModeA,
        whitelisted_assets: vec!["*".to_string()],
        allow_swaps: true,
        allow_bucket_updates: false,
        allow_dark_pool_maker,
        max_slippage_bps,
        fee_tier_multiplier_bps,
        cap_24h_sompi: U128Str(MODE_A_DEFAULT_CAP_24H_SOMPI),
        cap_24h_usd_micros: U128Str(MODE_A_DEFAULT_CAP_24H_USD_MICROS),
        issued_at_unix: now_secs,
        expires_at_unix,
    };

    let (secret_token, token_mac_blake3) =
        mint_stateless_capability_token(&state.signing_secret, &claims)?;

    let expires_dt = DateTime::<Utc>::from_timestamp(expires_at_unix as i64, 0)
        .unwrap_or_else(Utc::now);

    sqlx::query(
        r#"
        INSERT INTO agent_api_keys (
            key_id, wallet_address, clean_wallet, agent_mode, label,
            token_mac_blake3, pubkey_hex, whitelisted_assets,
            allow_swaps, allow_bucket_updates, allow_dark_pool_maker,
            max_slippage_bps, fee_tier_multiplier_bps,
            cap_24h_sompi, cap_24h_usd_micros, expires_at
        ) VALUES (
            $1, $2, $3, 'MODE_A', $4,
            $5, $6, $7,
            TRUE, FALSE, $8,
            $9, $10,
            $11::NUMERIC(39, 0), $12::NUMERIC(39, 0), $13
        )
        "#,
    )
    .bind(&key_id)
    .bind(&prefixed_wallet)
    .bind(&clean_wallet)
    .bind(&final_label)
    .bind(&token_mac_blake3)
    .bind(&pubkey_hex)
    .bind(&claims.whitelisted_assets)
    .bind(allow_dark_pool_maker)
    .bind(max_slippage_bps as i32)
    .bind(fee_tier_multiplier_bps as i32)
    .bind(claims.cap_24h_sompi.to_string())
    .bind(claims.cap_24h_usd_micros.to_string())
    .bind(expires_dt)
    .execute(&state.pg_pool)
    .await
    .map_err(|e| {
        tracing::error!("❌ [AGENT AUTH] Failed to persist Mode A key metadata: {}", e);
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Failed to persist Mode A Agent Key record.",
        )
    })?;

    let _: redis::RedisResult<()> = redis::cmd("SET")
        .arg(format!("perennia:agent:key_fills:{}", key_id))
        .arg(0u64)
        .query_async(&mut conn)
        .await;

    Ok(Json(json!({
        "ok": true,
        "agentKey": secret_token,
        "keyId": key_id,
        "mode": "MODE_A",
        "walletAddress": prefixed_wallet,
        "allowDarkPoolMaker": allow_dark_pool_maker,
        "maxSlippageBps": max_slippage_bps,
        "feeTierMultiplierBps": fee_tier_multiplier_bps,
        "cap24hSompi": claims.cap_24h_sompi,
        "cap24hUsdMicros": claims.cap_24h_usd_micros,
        "issuedAtUnix": now_secs.to_string(),
        "expiresAtUnix": expires_at_unix.to_string(),
        "streamEndpoint": "/api/v1/agent/stream",
        "mcpEndpoint": "/api/v1/agent/mcp"
    })))
}

// ============================================================================
// MODE B: HUMAN USER PERSONAL AUTOMATION MANDATES (INTERNAL BRIDGE FOR SVELTEKIT)
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InternalCreateMandateRequest {
    pub wallet_address: String,
    #[serde(default)]
    pub pubkey_hex: Option<String>,
    pub label: String,
    pub whitelisted_assets: Vec<String>,
    pub allow_swaps: bool,
    pub allow_bucket_updates: bool,
    pub max_slippage_bps: u16,
    pub cap_24h_sompi: U128Str,
    pub cap_24h_usd_micros: U128Str,
    #[serde(default)]
    pub expires_in_hours: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InternalRevokeMandateRequest {
    pub wallet_address: String,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub revoke_all_for_wallet: Option<bool>,
}

pub async fn handle_internal_list_mandates(
    State(state): State<AgentGatewayState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AgentError> {
    let raw_wallet = params.get("wallet").ok_or_else(|| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            "Missing wallet query parameter.",
        )
    })?;
    let (clean_wallet, prefixed_wallet, _, _) = validate_kaspa_address_strict(raw_wallet)?;

    let mut conn = state.get_redis_conn().await?;
    let now_secs = current_unix_secs();

    let key_rows = sqlx::query(
        r#"
        SELECT key_id, agent_mode, label, whitelisted_assets,
               allow_swaps, allow_bucket_updates, allow_dark_pool_maker,
               max_slippage_bps, fee_tier_multiplier_bps,
               cap_24h_sompi::TEXT AS cap_24h_sompi,
               cap_24h_usd_micros::TEXT AS cap_24h_usd_micros,
               verified_fills_count,
               cumulative_volume_usd_micros::TEXT AS cumulative_volume_usd_micros,
               expires_at, is_revoked, revoked_reason, revoked_at,
               created_at, last_settled_at
        FROM agent_api_keys
        WHERE clean_wallet = $1
        ORDER BY created_at DESC
        LIMIT 50
        "#,
    )
    .bind(&clean_wallet)
    .fetch_all(&state.pg_pool)
    .await
    .map_err(|_| {
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Database unavailable while loading Agent Mandates.",
        )
    })?;

    let mut mandates = Vec::with_capacity(key_rows.len());
    for row in key_rows {
        let key_id: String = row.try_get("key_id").unwrap_or_default();
        let (spent_sompi, spent_usd_micros) =
            locks_and_limits::read_rolling_24h_spend(&mut conn, &key_id, now_secs)
                .await
                .unwrap_or((0, 0));

        let expires_at_opt: Option<DateTime<Utc>> = row.try_get("expires_at").ok().flatten();
        let is_expired = expires_at_opt
            .map(|dt| (dt.timestamp().max(0) as u64) < now_secs)
            .unwrap_or(false);

        mandates.push(json!({
            "keyId": key_id,
            "mode": row.try_get::<String, _>("agent_mode").unwrap_or_else(|_| "MODE_B".to_string()),
            "label": row.try_get::<String, _>("label").unwrap_or_default(),
            "whitelistedAssets": row.try_get::<Vec<String>, _>("whitelisted_assets").unwrap_or_default(),
            "allowSwaps": row.try_get::<bool, _>("allow_swaps").unwrap_or(true),
            "allowBucketUpdates": row.try_get::<bool, _>("allow_bucket_updates").unwrap_or(false),
            "allowDarkPoolMaker": row.try_get::<bool, _>("allow_dark_pool_maker").unwrap_or(false),
            "maxSlippageBps": row.try_get::<i32, _>("max_slippage_bps").unwrap_or(50),
            "feeTierMultiplierBps": row.try_get::<i32, _>("fee_tier_multiplier_bps").unwrap_or(10000),
            "cap24hSompi": row.try_get::<String, _>("cap_24h_sompi").unwrap_or_else(|_| "0".to_string()),
            "cap24hUsdMicros": row.try_get::<String, _>("cap_24h_usd_micros").unwrap_or_else(|_| "0".to_string()),
            "spent24hSompi": spent_sompi.to_string(),
            "spent24hUsdMicros": spent_usd_micros.to_string(),
            "verifiedFillsCount": row.try_get::<i64, _>("verified_fills_count").unwrap_or(0).to_string(),
            "cumulativeVolumeUsdMicros": row.try_get::<String, _>("cumulative_volume_usd_micros").unwrap_or_else(|_| "0".to_string()),
            "isRevoked": row.try_get::<bool, _>("is_revoked").unwrap_or(false),
            "isExpired": is_expired,
            "revokedReason": row.try_get::<Option<String>, _>("revoked_reason").ok().flatten(),
            "expiresAt": expires_at_opt.map(|d| d.to_rfc3339()),
            "createdAt": row.try_get::<DateTime<Utc>, _>("created_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
            "lastSettledAt": row.try_get::<Option<DateTime<Utc>>, _>("last_settled_at").ok().flatten().map(|d| d.to_rfc3339())
        }));
    }

    let receipt_rows = sqlx::query(
        r#"
        SELECT receipt_id, quote_id, key_id, venue, pay_asset, receive_asset,
               amount_in_atomic::TEXT AS amount_in_atomic,
               settled_out_atomic::TEXT AS settled_out_atomic,
               total_fee_usd_micros::TEXT AS total_fee_usd_micros,
               notional_usd_micros::TEXT AS notional_usd_micros,
               execution_commitment_hash, l1_txid, status, executed_at
        FROM agent_execution_receipts
        WHERE clean_wallet = $1
        ORDER BY executed_at DESC
        LIMIT 25
        "#,
    )
    .bind(&clean_wallet)
    .fetch_all(&state.pg_pool)
    .await
    .map_err(|_| {
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Database unavailable while loading Agent execution receipts.",
        )
    })?;

    let mut live_fills = Vec::with_capacity(receipt_rows.len());
    for r in receipt_rows {
        live_fills.push(json!({
            "receiptId": r.try_get::<String, _>("receipt_id").unwrap_or_default(),
            "quoteId": r.try_get::<String, _>("quote_id").unwrap_or_default(),
            "keyId": r.try_get::<String, _>("key_id").unwrap_or_default(),
            "venue": r.try_get::<String, _>("venue").unwrap_or_default(),
            "payAsset": r.try_get::<String, _>("pay_asset").unwrap_or_default(),
            "receiveAsset": r.try_get::<String, _>("receive_asset").unwrap_or_default(),
            "amountInAtomic": r.try_get::<String, _>("amount_in_atomic").unwrap_or_else(|_| "0".to_string()),
            "settledOutAtomic": r.try_get::<String, _>("settled_out_atomic").unwrap_or_else(|_| "0".to_string()),
            "totalFeeUsdMicros": r.try_get::<String, _>("total_fee_usd_micros").unwrap_or_else(|_| "0".to_string()),
            "notionalUsdMicros": r.try_get::<String, _>("notional_usd_micros").unwrap_or_else(|_| "0".to_string()),
            "executionCommitmentHash": r.try_get::<String, _>("execution_commitment_hash").unwrap_or_default(),
            "l1Txid": r.try_get::<String, _>("l1_txid").unwrap_or_default(),
            "status": r.try_get::<String, _>("status").unwrap_or_else(|_| "SETTLED".to_string()),
            "dryRun": false,
            "executedAt": r.try_get::<DateTime<Utc>, _>("executed_at").map(|d| d.to_rfc3339()).unwrap_or_default()
        }));
    }

    let raw_dry_runs: Vec<String> = redis::cmd("LRANGE")
        .arg(format!("perennia:agent:dry_run_logs:{}", clean_wallet))
        .arg(0)
        .arg(24)
        .query_async(&mut conn)
        .await
        .unwrap_or_default();

    let dry_run_logs: Vec<Value> = raw_dry_runs
        .into_iter()
        .filter_map(|s| serde_json::from_str::<Value>(&s).ok())
        .collect();

    Ok(Json(json!({
        "ok": true,
        "walletAddress": prefixed_wallet,
        "mandates": mandates,
        "liveFills": live_fills,
        "dryRunLogs": dry_run_logs
    })))
}

pub async fn handle_internal_create_mandate(
    State(state): State<AgentGatewayState>,
    Json(raw_body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), AgentError> {
    reject_forbidden_cold_vault_or_withdrawal_keys(&raw_body)?;

    let req: InternalCreateMandateRequest = serde_json::from_value(raw_body).map_err(|e| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            format!("Invalid Mandate creation payload: {}", e),
        )
    })?;

    let (clean_wallet, prefixed_wallet, addr_ver, addr_hash32) =
        validate_kaspa_address_strict(&req.wallet_address)?;

    if !req.allow_swaps && !req.allow_bucket_updates {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "At least one capability (allowSwaps or allowBucketUpdates) must be enabled.",
        ));
    }

    if req.whitelisted_assets.is_empty() || req.whitelisted_assets.len() > 24 {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "Mode B Mandate requires 1..=24 explicitly whitelisted asset tickers.",
        ));
    }

    let mut sterile_assets = Vec::with_capacity(req.whitelisted_assets.len());
    for raw_tick in &req.whitelisted_assets {
        let tick = sanitize_sterile_ticker(raw_tick)?;
        if !sterile_assets.contains(&tick) {
            sterile_assets.push(tick);
        }
    }

    if !(1..=500).contains(&req.max_slippage_bps) {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "Mode B Mandate maxSlippageBps must be between 1 and 500 bps (0.01% - 5.00%).",
        ));
    }

    if req.cap_24h_sompi.as_u128() == 0 || req.cap_24h_usd_micros.as_u128() == 0 {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "Mode B Mandate requires positive 24h KAS sompi and USD micro caps.",
        ));
    }

    let resolved_pubkey_hex = if let Some(ref pk) = req.pubkey_hex {
        if pk.trim().is_empty() {
            if addr_ver == KASPA_ADDR_VERSION_P2PK_SCHNORR {
                hex::encode(addr_hash32)
            } else {
                String::new()
            }
        } else {
            validate_hex_64(pk, "pubkeyHex")?
        }
    } else if addr_ver == KASPA_ADDR_VERSION_P2PK_SCHNORR {
        hex::encode(addr_hash32)
    } else {
        String::new()
    };

    let clean_label: String = req
        .label
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .take(64)
        .collect();
    let final_label = if clean_label.is_empty() {
        "Personal Mandate".to_string()
    } else {
        clean_label
    };

    let fee_tier_multiplier_bps =
        resolve_initial_fee_tier_multiplier_bps(&state.pg_pool, &clean_wallet, &prefixed_wallet)
            .await?;

    let now_secs = current_unix_secs();
    let (expires_at_unix, expires_dt_opt) = match req.expires_in_hours {
        Some(hours) if hours > 0 => {
            let clamped_hours = hours.min(8_760);
            let exp_unix = now_secs.saturating_add(clamped_hours.saturating_mul(3_600));
            let dt = DateTime::<Utc>::from_timestamp(exp_unix as i64, 0);
            (exp_unix, dt)
        }
        _ => (0u64, None),
    };

    let key_id = format!("mdk_{}", Uuid::new_v4().simple());
    let mandate_id = key_id.clone();

    let claims = AgentCapabilityClaims {
        version: 1,
        key_id: key_id.clone(),
        mandate_id: mandate_id.clone(),
        clean_wallet: clean_wallet.clone(),
        prefixed_wallet: prefixed_wallet.clone(),
        pubkey_hex: resolved_pubkey_hex.clone(),
        mode: AgentMode::ModeB,
        whitelisted_assets: sterile_assets.clone(),
        allow_swaps: req.allow_swaps,
        allow_bucket_updates: req.allow_bucket_updates,
        allow_dark_pool_maker: false,
        max_slippage_bps: req.max_slippage_bps,
        fee_tier_multiplier_bps,
        cap_24h_sompi: req.cap_24h_sompi,
        cap_24h_usd_micros: req.cap_24h_usd_micros,
        issued_at_unix: now_secs,
        expires_at_unix,
    };

    let (secret_token, token_mac_blake3) =
        mint_stateless_capability_token(&state.signing_secret, &claims)?;

    sqlx::query(
        r#"
        INSERT INTO agent_api_keys (
            key_id, wallet_address, clean_wallet, agent_mode, label,
            token_mac_blake3, pubkey_hex, whitelisted_assets,
            allow_swaps, allow_bucket_updates, allow_dark_pool_maker,
            max_slippage_bps, fee_tier_multiplier_bps,
            cap_24h_sompi, cap_24h_usd_micros, expires_at
        ) VALUES (
            $1, $2, $3, 'MODE_B', $4,
            $5, $6, $7,
            $8, $9, FALSE,
            $10, $11,
            $12::NUMERIC(39, 0), $13::NUMERIC(39, 0), $14
        )
        "#,
    )
    .bind(&key_id)
    .bind(&prefixed_wallet)
    .bind(&clean_wallet)
    .bind(&final_label)
    .bind(&token_mac_blake3)
    .bind(&resolved_pubkey_hex)
    .bind(&sterile_assets)
    .bind(req.allow_swaps)
    .bind(req.allow_bucket_updates)
    .bind(req.max_slippage_bps as i32)
    .bind(fee_tier_multiplier_bps as i32)
    .bind(req.cap_24h_sompi.to_string())
    .bind(req.cap_24h_usd_micros.to_string())
    .bind(expires_dt_opt)
    .execute(&state.pg_pool)
    .await
    .map_err(|e| {
        tracing::error!("❌ [AGENT AUTH] Failed to persist Mode B Mandate: {}", e);
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Failed to persist Mode B Mandate in PostgreSQL.",
        )
    })?;

    let mut conn = state.get_redis_conn().await?;
    let _: redis::RedisResult<()> = redis::cmd("SET")
        .arg(format!("perennia:agent:key_fills:{}", key_id))
        .arg(0u64)
        .query_async(&mut conn)
        .await;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "secretDisplayedOnce": true,
            "agentKey": secret_token,
            "mandate": {
                "keyId": key_id,
                "mode": "MODE_B",
                "label": final_label,
                "walletAddress": prefixed_wallet,
                "whitelistedAssets": sterile_assets,
                "allowSwaps": req.allow_swaps,
                "allowBucketUpdates": req.allow_bucket_updates,
                "maxSlippageBps": req.max_slippage_bps,
                "feeTierMultiplierBps": fee_tier_multiplier_bps,
                "cap24hSompi": req.cap_24h_sompi,
                "cap24hUsdMicros": req.cap_24h_usd_micros,
                "expiresAt": expires_dt_opt.map(|d| d.to_rfc3339()),
                "createdAt": Utc::now().to_rfc3339()
            }
        })),
    ))
}

pub async fn handle_internal_revoke_mandate(
    State(state): State<AgentGatewayState>,
    Json(req): Json<InternalRevokeMandateRequest>,
) -> Result<Json<Value>, AgentError> {
    let (clean_wallet, prefixed_wallet, _, _) = validate_kaspa_address_strict(&req.wallet_address)?;
    let revoke_all = req.revoke_all_for_wallet.unwrap_or(false);

    let mut conn = state.get_redis_conn().await?;

    let target_key_ids: Vec<String> = if revoke_all {
        let rows = sqlx::query(
            r#"
            UPDATE agent_api_keys
            SET is_revoked = TRUE,
                revoked_reason = 'HUMAN_KILL_SWITCH_ALL',
                revoked_at = CURRENT_TIMESTAMP
            WHERE clean_wallet = $1
              AND is_revoked = FALSE
            RETURNING key_id
            "#,
        )
        .bind(&clean_wallet)
        .fetch_all(&state.pg_pool)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::DatabaseUnavailable,
                "Database unavailable while executing wallet-wide Kill Switch.",
            )
        })?;
        rows.into_iter()
            .filter_map(|r| r.try_get::<String, _>("key_id").ok())
            .collect()
    } else {
        let key_id = req
            .key_id
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && s.len() <= 64)
            .ok_or_else(|| {
                AgentError::new(
                    AgentErrorCode::InvalidInput,
                    "Provide keyId or set revokeAllForWallet: true.",
                )
            })?
            .to_string();

        let row_opt = sqlx::query(
            r#"
            UPDATE agent_api_keys
            SET is_revoked = TRUE,
                revoked_reason = 'HUMAN_KILL_SWITCH',
                revoked_at = CURRENT_TIMESTAMP
            WHERE key_id = $1
              AND clean_wallet = $2
            RETURNING key_id
            "#,
        )
        .bind(&key_id)
        .bind(&clean_wallet)
        .fetch_optional(&state.pg_pool)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::DatabaseUnavailable,
                "Database unavailable while executing Kill Switch revocation.",
            )
        })?;

        if row_opt.is_none() {
            return Err(AgentError::new(
                AgentErrorCode::MandateViolation,
                "Mandate key not found for this Sovereign Wallet.",
            ));
        }
        vec![key_id]
    };

    let mut released_locks_total: u64 = 0;
    for kid in &target_key_ids {
        redis::cmd("SET")
            .arg(locks_and_limits::redis_key_revoked(kid))
            .arg("1")
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|_| {
                AgentError::new(
                    AgentErrorCode::RedisUnavailable,
                    "Failed to write immediate Kill Switch revocation flag to Redis.",
                )
            })?;

        let released =
            locks_and_limits::release_all_locks_for_key(&mut conn, kid, &clean_wallet).await?;
        released_locks_total = released_locks_total.saturating_add(released);
    }

    Ok(Json(json!({
        "ok": true,
        "walletAddress": prefixed_wallet,
        "revokedKeyIds": target_key_ids,
        "releasedActiveLocks": released_locks_total.to_string(),
        "revokedAt": Utc::now().to_rfc3339()
    })))
}