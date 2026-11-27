// src/agent/types.rs

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use std::fmt;

use crate::silverscript::{
    decode_kaspa_address_payload, encode_kaspa_bech32m_address, KASPA_ADDR_VERSION_P2PK_SCHNORR,
    KASPA_ADDR_VERSION_P2SH,
};

/// 1 KAS = 100,000,000 sompi (10^8).
pub const SOMPI_PER_KAS: u128 = 100_000_000;
/// Oracle USD prices are represented as exact integer USD * 10^8 (`$1.00 = 100_000_000`).
pub const ORACLE_USD_E8_SCALE: u128 = 100_000_000;
/// USD notional caps and fee totals are tracked in integer micro-USD (`$1.00 = 1_000_000`).
pub const USD_MICROS_SCALE: u128 = 1_000_000;
/// Basis points denominator (`100% = 10_000 bps`).
pub const BPS_DENOMINATOR: u128 = 10_000;

/// Minimum swap notional across `/api/v1/agent` ($1.00 = 1,000,000 micro-USD) to block 1-sompi dust attacks.
pub const MIN_AGENT_NOTIONAL_USD_MICROS: u128 = 1_000_000;
/// UTXO outputs below 0.10 KAS (10,000,000 sompi) are classified as dust for lane health scoring.
pub const DUST_UTXO_THRESHOLD_SOMPI: u64 = 10_000_000;

/// Maximum Taker quote TTL (anti-"free option" cap: 5 seconds).
pub const MAX_TAKER_QUOTE_TTL_SECS: u64 = 5;
/// Allowed resting Maker Dark Pool RFQ TTL bounds (5 to 15 seconds).
pub const MIN_MAKER_RFQ_TTL_SECS: u64 = 5;
pub const MAX_MAKER_RFQ_TTL_SECS: u64 = 15;

/// Stringified `u128` wrapper that serializes strictly as `"0"`..`"340282366920938463463374607431768211455"`
/// and rejects floating-point numbers, scientific notation, signs, or whitespace padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct U128Str(pub u128);

impl U128Str {
    #[inline]
    pub const fn new(val: u128) -> Self {
        Self(val)
    }

    #[inline]
    pub const fn as_u128(self) -> u128 {
        self.0
    }
}

impl From<u128> for U128Str {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<u64> for U128Str {
    fn from(value: u64) -> Self {
        Self(value as u128)
    }
}

impl fmt::Display for U128Str {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for U128Str {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for U128Str {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct U128Visitor;

        impl<'de> de::Visitor<'de> for U128Visitor {
            type Value = U128Str;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a canonical base-10 unsigned u128 integer string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.is_empty() || v.len() > 39 || !v.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(E::custom(
                        "u128 field must contain 1..=39 ASCII digits with no decimals, signs, or exponents",
                    ));
                }
                v.parse::<u128>()
                    .map(U128Str)
                    .map_err(|_| E::custom("u128 integer overflow"))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(U128Str(v as u128))
            }

            fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(U128Str(v))
            }
        }

        deserializer.deserialize_any(U128Visitor)
    }
}

/// Returns exact atomic unit decimals for supported assets (zero floating-point scaling).
pub fn atomic_decimals_for_asset(ticker: &str) -> u8 {
    match ticker {
        "USDC" | "USDT" | "USD" | "XRP" | "TRX" | "ADA" => 6,
        "SOL" | "SUI" | "TON" => 9,
        "ETH" | "ARB" | "BASE" | "POL" | "AVAX" | "LINK" => 18,
        // KAS, BTC, DOGE, LTC, ZEC, KRC-20, KCC-20, and RWA feeds use 8 atomic decimals (10^8).
        _ => 8,
    }
}

/// Computes `10^decimals` in `u128` cleanly.
pub fn pow10_u128(decimals: u8) -> Result<u128, AgentError> {
    if decimals > 30 {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "Unsupported asset decimal precision.",
        ));
    }
    Ok(10u128.pow(decimals as u32))
}

/// Enforces sterile `^[A-Z0-9]{2,10}$` tickers to prevent prompt-injection or untrusted metadata bleed.
pub fn sanitize_sterile_ticker(raw: &str) -> Result<String, AgentError> {
    let clean = raw.trim().to_ascii_uppercase();
    if !(2..=10).contains(&clean.len())
        || !clean
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "Asset ticker must match sterile pattern ^[A-Z0-9]{2,10}$.",
        ));
    }
    Ok(clean)
}

/// Validates a canonical 32-byte (64-character lowercase hex) digest, txid, covenant ID, or x-only pubkey.
pub fn validate_hex_64(raw: &str, field_name: &str) -> Result<String, AgentError> {
    let trimmed = raw.trim().strip_prefix("0x").unwrap_or_else(|| raw.trim());
    let lower = trimmed.to_ascii_lowercase();
    if lower.len() != 64 || !lower.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            format!("{} must be an exact 64-character hexadecimal string.", field_name),
        ));
    }
    Ok(lower)
}

/// Validates bounded hex payloads (e.g., `proof_payload` or script bytes).
pub fn validate_hex_bounded(
    raw: &str,
    max_bytes: usize,
    field_name: &str,
) -> Result<(String, Vec<u8>), AgentError> {
    let trimmed = raw.trim().strip_prefix("0x").unwrap_or_else(|| raw.trim());
    let lower = trimmed.to_ascii_lowercase();
    if lower.len() % 2 != 0
        || lower.len() > max_bytes.saturating_mul(2)
        || !lower.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            format!(
                "{} must be valid even-length hex up to {} bytes.",
                field_name, max_bytes
            ),
        ));
    }
    let decoded = hex::decode(&lower).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            format!("{} failed hexadecimal decoding.", field_name),
        )
    })?;
    Ok((lower, decoded))
}

/// Validates a Kaspa Bech32m address AND verifies the full 8-character polymod checksum
/// by re-encoding the decoded `(version, hash32)` payload and requiring exact equality.
pub fn validate_kaspa_address_strict(
    raw: &str,
) -> Result<(String, String, u8, [u8; 32]), AgentError> {
    let trimmed = raw.trim().to_ascii_lowercase();
    let clean = trimmed.strip_prefix("kaspa:").unwrap_or(&trimmed).trim();
    if clean.len() < 58 || clean.len() > 72 {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "Invalid Kaspa Bech32m address length.",
        ));
    }
    let prefixed = format!("kaspa:{}", clean);
    let (version, hash32) = decode_kaspa_address_payload(&prefixed).ok_or_else(|| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            "Malformed Kaspa Bech32m address payload.",
        )
    })?;
    if version != KASPA_ADDR_VERSION_P2PK_SCHNORR && version != KASPA_ADDR_VERSION_P2SH {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "Unsupported Kaspa address version byte (must be P2PK Schnorr or P2SH).",
        ));
    }
    let canonical = encode_kaspa_bech32m_address(version, &hash32);
    if canonical != prefixed {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "Kaspa Bech32m polymod checksum verification failed.",
        ));
    }
    Ok((clean.to_string(), canonical, version, hash32))
}

/// Validates a sterile `idempotency_key` (`^[A-Za-z0-9_-]{8,128}$`).
pub fn validate_idempotency_key(raw: &str) -> Result<String, AgentError> {
    let trimmed = raw.trim();
    if !(8..=128).contains(&trimmed.len())
        || !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "idempotency_key must match ^[A-Za-z0-9_-]{8,128}$.",
        ));
    }
    Ok(trimmed.to_string())
}

/// Scans an untrusted JSON payload recursively to hard-block any attempt to read, inject,
/// or mutate cold-vault airlock rules or external withdrawal destinations.
pub fn reject_forbidden_cold_vault_or_withdrawal_keys(val: &Value) -> Result<(), AgentError> {
    const FORBIDDEN_KEYS: &[&str] = &[
        "colddestinationaddress",
        "coldkaspaaddress",
        "cold_destination_address",
        "cold_kaspa_address",
        "cold_kas_address",
        "cold_btc_address",
        "cold_eth_address",
        "cold_sol_address",
        "coldvaultaddress",
        "cold_vault_address",
        "autosweepenabled",
        "auto_sweep_enabled",
        "overflowceiling",
        "overflow_ceiling",
        "overflowthresholdkas",
        "overflow_threshold_kas",
        "sweepdestination",
        "withdrawaddress",
        "externaldestination",
        "payoutaddress",
        "payout_address",
        "destinationaddress",
        "destination_address",
    ];

    match val {
        Value::Object(map) => {
            for (k, v) in map {
                let norm = k.trim().to_ascii_lowercase();
                if FORBIDDEN_KEYS.contains(&norm.as_str()) {
                    return Err(AgentError::new(
                        AgentErrorCode::MandateViolation,
                        "SECURITY_AIRLOCK_BLOCK: Cold-vault rules and external payout destinations are strictly off-limits to Agent keys.",
                    ));
                }
                reject_forbidden_cold_vault_or_withdrawal_keys(v)?;
            }
            Ok(())
        }
        Value::Array(arr) => {
            for item in arr {
                reject_forbidden_cold_vault_or_withdrawal_keys(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "camelCase")]
pub struct OutpointRef {
    pub transaction_id: String,
    pub index: u32,
}

impl OutpointRef {
    pub fn canonical_key(&self) -> String {
        format!("{}:{}", self.transaction_id, self.index)
    }

    pub fn parse_str(raw: &str) -> Result<Self, AgentError> {
        let mut parts = raw.trim().split(':');
        let txid_raw = parts.next().ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::InvalidInput,
                "UTXO outpoint must be formatted as txid:vout.",
            )
        })?;
        let vout_raw = parts.next().ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::InvalidInput,
                "UTXO outpoint missing :vout index.",
            )
        })?;
        if parts.next().is_some() {
            return Err(AgentError::new(
                AgentErrorCode::InvalidInput,
                "UTXO outpoint contains unexpected extra ':' delimiter.",
            ));
        }
        let transaction_id = validate_hex_64(txid_raw, "outpoint.txid")?;
        let index: u32 = vout_raw.parse::<u32>().map_err(|_| {
            AgentError::new(
                AgentErrorCode::InvalidInput,
                "UTXO outpoint vout must be a valid u32 integer.",
            )
        })?;
        if index > 10_000 {
            return Err(AgentError::new(
                AgentErrorCode::InvalidInput,
                "UTXO outpoint vout exceeds consensus maximum.",
            ));
        }
        Ok(Self {
            transaction_id,
            index,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentMode {
    #[serde(rename = "MODE_A")]
    ModeA,
    #[serde(rename = "MODE_B")]
    ModeB,
}

impl AgentMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModeA => "MODE_A",
            Self::ModeB => "MODE_B",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentVenue {
    #[serde(rename = "spot")]
    Spot,
    #[serde(rename = "dark_pool")]
    DarkPool,
    #[serde(rename = "dark_pool_rfq_maker")]
    DarkPoolRfqMaker,
}

impl AgentVenue {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Spot => "spot",
            Self::DarkPool => "dark_pool",
            Self::DarkPoolRfqMaker => "dark_pool_rfq_maker",
        }
    }
}

/// Immutable caveats embedded inside the cryptographically signed HMAC-Blake3 capability key.
/// Verified in pure RAM in microseconds with zero PostgreSQL reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilityClaims {
    pub version: u8,
    pub key_id: String,
    pub mandate_id: String,
    pub clean_wallet: String,
    pub prefixed_wallet: String,
    pub pubkey_hex: String,
    pub mode: AgentMode,
    pub whitelisted_assets: Vec<String>,
    pub allow_swaps: bool,
    pub allow_bucket_updates: bool,
    pub allow_dark_pool_maker: bool,
    pub max_slippage_bps: u16,
    pub fee_tier_multiplier_bps: u16,
    pub cap_24h_sompi: U128Str,
    pub cap_24h_usd_micros: U128Str,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

impl AgentCapabilityClaims {
    pub fn is_asset_whitelisted(&self, ticker: &str) -> bool {
        if self.mode == AgentMode::ModeA
            && self.whitelisted_assets.iter().any(|t| t == "*")
        {
            return true;
        }
        self.whitelisted_assets.iter().any(|t| t == ticker)
    }
}

/// Forward-compatible post-Toccata Kaspa Transaction v1 & Covenant / Proof envelope.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostToccataEnvelope {
    #[serde(default = "default_tx_version_v1")]
    pub tx_version: u16,
    #[serde(default)]
    pub compute_budget: Option<u64>,
    #[serde(default)]
    pub storage_mass: Option<u64>,
    #[serde(default)]
    pub covenant_id: Option<String>,
    #[serde(default)]
    pub proof_payload: Option<String>,
}

const fn default_tx_version_v1() -> u16 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UtxoLaneHealth {
    pub total_utxo_count: u32,
    pub confirmed_clean_lanes: u32,
    pub dust_utxo_count: u32,
    pub locked_outpoint_count: u32,
    pub active_wallet_quotes: u32,
    pub max_concurrent_quotes: u32,
    pub recommended_target_lanes_min: u32,
    pub recommended_target_lanes_max: u32,
    pub lane_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentChallenge {
    pub protocol: String,
    pub key_id: String,
    pub rolling_quotes_window: u64,
    pub rolling_fills_window: u64,
    pub quote_to_fill_ratio_bps: u64,
    pub current_rpm_limit: u64,
    pub treasury_kaspa_address: String,
    pub sompi_per_burst_pack: U128Str,
    pub usdc_micros_per_burst_pack: U128Str,
    pub credits_per_burst_pack: u64,
    pub claim_endpoint: String,
    pub challenge_memo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockedUtxoSnapshot {
    pub transaction_id: String,
    pub index: u32,
    pub amount_sompi: U128Str,
    pub script_public_key_version: u16,
    pub script_public_key_hex: String,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

/// Deterministic quote state persisted in Redis for `5s` (Taker) or `5..=15s` (Maker RFQ).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredAgentQuote {
    pub quote_id: String,
    pub key_id: String,
    pub mandate_id: String,
    pub mode: AgentMode,
    pub clean_wallet: String,
    pub prefixed_wallet: String,
    pub pubkey_hex: String,
    pub venue: AgentVenue,
    pub pay_asset: String,
    pub receive_asset: String,
    pub pay_decimals: u8,
    pub receive_decimals: u8,
    pub amount_in_atomic: U128Str,
    pub expected_amount_out_atomic: U128Str,
    pub min_amount_out_atomic: U128Str,
    pub max_slippage_bps: u16,
    pub applied_fee_bps: u16,
    pub fee_tier_multiplier_bps: u16,
    pub protocol_fee_atomic: U128Str,
    pub network_fee_sompi: U128Str,
    pub total_fee_usd_micros: U128Str,
    pub notional_usd_micros: U128Str,
    pub spend_sompi_equiv: U128Str,
    pub pay_oracle_usd_e8: U128Str,
    pub receive_oracle_usd_e8: U128Str,
    pub kas_oracle_usd_e8: U128Str,
    pub tx_version: u16,
    pub compute_grams: u64,
    pub tx_bytes: u64,
    pub storage_mass: u64,
    pub covenant_id: Option<String>,
    pub proof_payload: Option<String>,
    pub locked_outpoints: Vec<String>,
    pub locked_utxos: Vec<LockedUtxoSnapshot>,
    pub unsigned_tx_json: Value,
    pub sighash_hex_per_input: Vec<String>,
    pub payload_0x83_hex: String,
    pub preimage_hash: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub ttl_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentErrorCode {
    InvalidInput,
    Unauthorized,
    KeyRevoked,
    KeyExpired,
    ForbiddenMode,
    MandateViolation,
    FirewallBlacklisted,
    CooldownBanned,
    PaymentRequiredX402,
    EdgeCapacityExceeded,
    CircuitBreakerTripped,
    StablecoinDepegHalt,
    OracleUnavailable,
    OracleDivergenceHalt,
    RedisUnavailable,
    DatabaseUnavailable,
    NodeUnavailable,
    UtxoContentionLocked,
    ConcurrencyCapReached,
    UnconfirmedParentUtxo,
    QuoteExpiredOrNotFound,
    PreimageMismatch,
    InvalidSignatureOrScript,
    SolvencyFloorViolation,
    SlippageExceededPostJitter,
    IdempotencyConflict,
}

impl AgentErrorCode {
    pub const fn status_code(self) -> StatusCode {
        match self {
            Self::InvalidInput => StatusCode::BAD_REQUEST,
            Self::Unauthorized | Self::KeyRevoked | Self::KeyExpired => StatusCode::UNAUTHORIZED,
            Self::ForbiddenMode
            | Self::MandateViolation
            | Self::FirewallBlacklisted
            | Self::CooldownBanned => StatusCode::FORBIDDEN,
            Self::PaymentRequiredX402 => StatusCode::PAYMENT_REQUIRED,
            Self::QuoteExpiredOrNotFound => StatusCode::GONE,
            Self::UtxoContentionLocked
            | Self::ConcurrencyCapReached
            | Self::IdempotencyConflict => StatusCode::CONFLICT,
            Self::UnconfirmedParentUtxo
            | Self::PreimageMismatch
            | Self::InvalidSignatureOrScript
            | Self::SolvencyFloorViolation
            | Self::SlippageExceededPostJitter => StatusCode::UNPROCESSABLE_ENTITY,
            Self::EdgeCapacityExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::CircuitBreakerTripped
            | Self::StablecoinDepegHalt
            | Self::OracleUnavailable
            | Self::OracleDivergenceHalt
            | Self::RedisUnavailable
            | Self::DatabaseUnavailable
            | Self::NodeUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "INVALID_INPUT",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::KeyRevoked => "KEY_REVOKED",
            Self::KeyExpired => "KEY_EXPIRED",
            Self::ForbiddenMode => "FORBIDDEN_MODE",
            Self::MandateViolation => "MANDATE_VIOLATION",
            Self::FirewallBlacklisted => "FIREWALL_BLACKLISTED",
            Self::CooldownBanned => "COOLDOWN_BANNED",
            Self::PaymentRequiredX402 => "PAYMENT_REQUIRED_X402",
            Self::EdgeCapacityExceeded => "EDGE_CAPACITY_EXCEEDED",
            Self::CircuitBreakerTripped => "CIRCUIT_BREAKER_TRIPPED",
            Self::StablecoinDepegHalt => "STABLECOIN_DEPEG_HALT",
            Self::OracleUnavailable => "ORACLE_UNAVAILABLE",
            Self::OracleDivergenceHalt => "ORACLE_DIVERGENCE_HALT",
            Self::RedisUnavailable => "REDIS_UNAVAILABLE",
            Self::DatabaseUnavailable => "DATABASE_UNAVAILABLE",
            Self::NodeUnavailable => "NODE_UNAVAILABLE",
            Self::UtxoContentionLocked => "UTXO_CONTENTION_LOCKED",
            Self::ConcurrencyCapReached => "CONCURRENCY_CAP_REACHED",
            Self::UnconfirmedParentUtxo => "UNCONFIRMED_PARENT_UTXO",
            Self::QuoteExpiredOrNotFound => "QUOTE_EXPIRED_OR_NOT_FOUND",
            Self::PreimageMismatch => "PREIMAGE_MISMATCH",
            Self::InvalidSignatureOrScript => "INVALID_SIGNATURE_OR_SCRIPT",
            Self::SolvencyFloorViolation => "SOLVENCY_FLOOR_VIOLATION",
            Self::SlippageExceededPostJitter => "SLIPPAGE_EXCEEDED_POST_JITTER",
            Self::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AgentError {
    pub code: AgentErrorCode,
    pub message: String,
    pub x402_challenge: Option<X402PaymentChallenge>,
    pub cooldown_seconds_remaining: Option<u64>,
}

impl AgentError {
    pub fn new(code: AgentErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            x402_challenge: None,
            cooldown_seconds_remaining: None,
        }
    }

    pub fn with_x402(challenge: X402PaymentChallenge, message: impl Into<String>) -> Self {
        Self {
            code: AgentErrorCode::PaymentRequiredX402,
            message: message.into(),
            x402_challenge: Some(challenge),
            cooldown_seconds_remaining: None,
        }
    }

    pub fn with_cooldown(seconds_remaining: u64, message: impl Into<String>) -> Self {
        Self {
            code: AgentErrorCode::CooldownBanned,
            message: message.into(),
            x402_challenge: None,
            cooldown_seconds_remaining: Some(seconds_remaining),
        }
    }

    pub fn to_json_body(&self) -> Value {
        let mut body = json!({
            "ok": false,
            "isError": true,
            "error": self.code.as_str(),
            "message": self.message,
        });
        if let Some(ref ch) = self.x402_challenge {
            body["x402"] = serde_json::to_value(ch).unwrap_or_else(|_| json!({}));
        }
        if let Some(cd) = self.cooldown_seconds_remaining {
            body["cooldownSecondsRemaining"] = json!(cd.to_string());
        }
        body
    }
}

impl IntoResponse for AgentError {
    fn into_response(self) -> Response {
        let status = self.code.status_code();
        let body = self.to_json_body();
        let mut resp = (status, Json(body)).into_response();

        if let Some(ref ch) = self.x402_challenge {
            if let Ok(hdr_val) = HeaderValue::from_str(&format!(
                "x402 realm=\"perennia-agent\", address=\"{}\", sompi=\"{}\", usdc_micros=\"{}\", credits=\"{}\"",
                ch.treasury_kaspa_address,
                ch.sompi_per_burst_pack,
                ch.usdc_micros_per_burst_pack,
                ch.credits_per_burst_pack
            )) {
                resp.headers_mut()
                    .insert(header::WWW_AUTHENTICATE, hdr_val);
            }
        }
        if let Some(cd) = self.cooldown_seconds_remaining {
            if let Ok(retry_val) = HeaderValue::from_str(&cd.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, retry_val);
            }
        }

        resp
    }
}