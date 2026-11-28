use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use chrono::Utc;
use rand::RngCore;
use secp256k1::{schnorr::Signature as SchnorrSignature, Message, XOnlyPublicKey, SECP256K1};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::env;

use crate::silverscript::decode_kaspa_address_payload;
use crate::state_api::{compile_silverscript_proof_of_lock_vault, KASPA_ADDR_VERSION_P2PK_SCHNORR};

pub const SILO_MAX_SUPPLY_WHOLE: u128 = 100_000_000;
pub const SILO_ATOMIC_DECIMALS: u32 = 8;
pub const SILO_ATOMIC_UNIT: u128 = 100_000_000;
pub const SILO_MAX_SUPPLY_ATOMIC: u128 = SILO_MAX_SUPPLY_WHOLE * SILO_ATOMIC_UNIT;

pub const SILO_SLEEVE_MINING_LP_PCT: u16 = 40;
pub const SILO_SLEEVE_TREASURY_PCT: u16 = 25;
pub const SILO_SLEEVE_GENESIS_LP_PCT: u16 = 20;
pub const SILO_SLEEVE_FOUNDER_VEST_PCT: u16 = 15;

pub const SILO_TIER_0_BPS: u16 = 50;
pub const SILO_TIER_10K_BPS: u16 = 35;
pub const SILO_TIER_100K_BPS: u16 = 25;
pub const SILO_TIER_1M_BPS: u16 = 15;

/// Deterministic non-custodial SILO UTXO lock swap taker fee tier (`>= 2 bps` floor).
pub fn compute_silo_utxo_fee_tier_bps(locked_silo_atomic: u128) -> u16 {
    if locked_silo_atomic >= 1_000_000 * SILO_ATOMIC_UNIT {
        SILO_TIER_1M_BPS
    } else if locked_silo_atomic >= 100_000 * SILO_ATOMIC_UNIT {
        SILO_TIER_100K_BPS
    } else if locked_silo_atomic >= 10_000 * SILO_ATOMIC_UNIT {
        SILO_TIER_10K_BPS
    } else {
        SILO_TIER_0_BPS
    }
}

pub fn resolve_master_treasury_pubkey_hex() -> Option<String> {
    if let Ok(raw) = env::var("MASTER_TREASURY_PUBKEY") {
        let trimmed = raw.trim().strip_prefix("0x").unwrap_or(raw.trim()).to_ascii_lowercase();
        if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(trimmed);
        }
    }
    if let Ok(addr) = crate::chronos::resolve_master_treasury_prefixed() {
        if let Some((ver, hash32)) = decode_kaspa_address_payload(&addr) {
            if ver == KASPA_ADDR_VERSION_P2PK_SCHNORR {
                return Some(hex::encode(hash32));
            }
        }
    }
    None
}

fn verify_schnorr_founder_signature(
    expected_pubkey_hex: &str,
    message_text: &str,
    sig_hex_raw: &str,
) -> bool {
    let Ok(pk_bytes) = hex::decode(expected_pubkey_hex.trim()) else {
        return false;
    };
    let Ok(xonly) = XOnlyPublicKey::from_slice(&pk_bytes) else {
        return false;
    };
    let clean_sig = sig_hex_raw.trim().strip_prefix("0x").unwrap_or(sig_hex_raw.trim());
    let Ok(sig_bytes) = hex::decode(clean_sig) else {
        return false;
    };
    if sig_bytes.len() != 64 {
        return false;
    }
    let Ok(sig) = SchnorrSignature::from_slice(&sig_bytes) else {
        return false;
    };
    let digest = *blake3::hash(message_text.as_bytes()).as_bytes();
    let Ok(msg) = Message::from_digest_slice(&digest) else {
        return false;
    };
    SECP256K1.verify_schnorr(&sig, &msg, &xonly).is_ok()
}

pub async fn query_forge_tokenomics_bundle(
    pool: &PgPool,
    ticker_opt: Option<&str>,
    include_all_vaults: bool,
) -> Result<Value, String> {
    let clean_ticker = ticker_opt
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "SILO".to_string());

    let policy_row = sqlx::query(
        r#"
        SELECT token_ticker, creator_address, max_supply, burn_rate_bps,
               burn_address, total_burned_tokens, emission_schedule_type,
               daily_emission_rate, halving_interval_days, reserve_locked_tokens,
               reserve_emitted_tokens, zero_rug_lp_pct, zero_rug_lock_days,
               is_retroactive_upgrade, charter_sha256, anchor_tx_hash
        FROM forge_monetary_policies
        WHERE token_ticker = $1
        "#,
    )
    .bind(&clean_ticker)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("Policy query failed: {}", e))?;

    let policy_json = if let Some(r) = policy_row {
        json!({
            "tokenTicker": r.try_get::<String, _>("token_ticker").unwrap_or_default(),
            "creatorAddress": r.try_get::<String, _>("creator_address").unwrap_or_default(),
            "maxSupply": r.try_get::<f64, _>("max_supply").unwrap_or(21_000_000.0),
            "burnRateBps": r.try_get::<i32, _>("burn_rate_bps").unwrap_or(100),
            "burnAddress": r.try_get::<String, _>("burn_address").unwrap_or_default(),
            "totalBurnedTokens": r.try_get::<f64, _>("total_burned_tokens").unwrap_or(0.0),
            "emissionScheduleType": r.try_get::<String, _>("emission_schedule_type").unwrap_or_else(|_| "CHROMATIC_HALVING".to_string()),
            "dailyEmissionRate": r.try_get::<f64, _>("daily_emission_rate").unwrap_or(0.0),
            "halvingIntervalDays": r.try_get::<i32, _>("halving_interval_days").unwrap_or(365),
            "reserveLockedTokens": r.try_get::<f64, _>("reserve_locked_tokens").unwrap_or(0.0),
            "reserveEmittedTokens": r.try_get::<f64, _>("reserve_emitted_tokens").unwrap_or(0.0),
            "zeroRugLpPct": r.try_get::<f64, _>("zero_rug_lp_pct").unwrap_or(50.0),
            "zeroRugLockDays": r.try_get::<i32, _>("zero_rug_lock_days").unwrap_or(365),
            "isRetroactiveUpgrade": r.try_get::<bool, _>("is_retroactive_upgrade").unwrap_or(false),
            "charterSha256": r.try_get::<String, _>("charter_sha256").unwrap_or_default(),
            "anchorTxHash": r.try_get::<Option<String>, _>("anchor_tx_hash").ok().flatten()
        })
    } else {
        Value::Null
    };

    let vault_row = sqlx::query(
        r#"
        SELECT vault_id::text AS vault_id, token_ticker, creator_address, vault_label,
               total_funded_tokens, remaining_vault_tokens, daily_emission_tokens,
               distributed_tokens, min_hashrate_ths, syndicate_sector_enabled,
               active_miners_count, status, funding_tx_hash
        FROM forge_mineable_vaults
        WHERE token_ticker = $1
        "#,
    )
    .bind(&clean_ticker)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("Mineable vault query failed: {}", e))?;

    let mineable_vault_json = if let Some(v) = vault_row {
        json!({
            "vaultId": v.try_get::<String, _>("vault_id").unwrap_or_default(),
            "tokenTicker": v.try_get::<String, _>("token_ticker").unwrap_or_default(),
            "creatorAddress": v.try_get::<String, _>("creator_address").unwrap_or_default(),
            "vaultLabel": v.try_get::<String, _>("vault_label").unwrap_or_default(),
            "totalFundedTokens": v.try_get::<f64, _>("total_funded_tokens").unwrap_or(0.0),
            "remainingVaultTokens": v.try_get::<f64, _>("remaining_vault_tokens").unwrap_or(0.0),
            "dailyEmissionTokens": v.try_get::<f64, _>("daily_emission_tokens").unwrap_or(0.0),
            "distributedTokens": v.try_get::<f64, _>("distributed_tokens").unwrap_or(0.0),
            "minHashrateThs": v.try_get::<f64, _>("min_hashrate_ths").unwrap_or(0.1),
            "syndicateSectorEnabled": v.try_get::<bool, _>("syndicate_sector_enabled").unwrap_or(true),
            "activeMinersCount": v.try_get::<i32, _>("active_miners_count").unwrap_or(1),
            "status": v.try_get::<String, _>("status").unwrap_or_else(|_| "ACTIVE".to_string()),
            "fundingTxHash": v.try_get::<Option<String>, _>("funding_tx_hash").ok().flatten()
        })
    } else {
        Value::Null
    };

    let vesting_rows = sqlx::query(
        r#"
        SELECT vesting_id::text AS vesting_id, token_ticker, beneficiary_address,
               creator_address, label, total_allocated, unlocked_amount,
               claimed_amount, cliff_days, linear_days, daily_unlock_rate,
               covenant_rule, vprog_state_root, lock_tx_hash, status
        FROM forge_vesting_schedules
        WHERE token_ticker = $1
        ORDER BY created_at ASC
        "#,
    )
    .bind(&clean_ticker)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("Vesting query failed: {}", e))?;

    let vesting_schedules: Vec<Value> = vesting_rows
        .into_iter()
        .map(|row| {
            let ben_addr = row
                .try_get::<String, _>("beneficiary_address")
                .unwrap_or_default();
            let total_alloc = row.try_get::<f64, _>("total_allocated").unwrap_or(0.0);
            let cliff_d = row.try_get::<i32, _>("cliff_days").unwrap_or(0) as i64;
            let linear_d = row.try_get::<i32, _>("linear_days").unwrap_or(365) as i64;
            let label = row
                .try_get::<String, _>("label")
                .unwrap_or_else(|_| "Genesis Tranche".to_string());
            let compiled = compile_silverscript_proof_of_lock_vault(
                &clean_ticker,
                "KRC-20",
                &label,
                &ben_addr,
                total_alloc,
                cliff_d,
                linear_d,
                None,
            );
            json!({
                "vestingId": row.try_get::<String, _>("vesting_id").unwrap_or_default(),
                "tokenTicker": row.try_get::<String, _>("token_ticker").unwrap_or_default(),
                "beneficiaryAddress": ben_addr,
                "creatorAddress": row.try_get::<String, _>("creator_address").unwrap_or_default(),
                "label": label,
                "totalAllocated": total_alloc,
                "unlockedAmount": row.try_get::<f64, _>("unlocked_amount").unwrap_or(0.0),
                "claimedAmount": row.try_get::<f64, _>("claimed_amount").unwrap_or(0.0),
                "cliffDays": cliff_d,
                "linearDays": linear_d,
                "dailyUnlockRate": row.try_get::<f64, _>("daily_unlock_rate").unwrap_or(0.0),
                "covenantRule": row.try_get::<String, _>("covenant_rule").unwrap_or_default(),
                "vprogStateRoot": row.try_get::<String, _>("vprog_state_root").unwrap_or(compiled.kcc20_state.state_root_hex),
                "covenantAddress": compiled.covenant_address,
                "silverscriptSource": compiled.silverscript_source,
                "redeemScriptHex": compiled.redeem_script_hex,
                "lockTxHash": row.try_get::<Option<String>, _>("lock_tx_hash").ok().flatten(),
                "status": row.try_get::<String, _>("status").unwrap_or_else(|_| "LOCKED".to_string())
            })
        })
        .collect();

    let mut all_mineable_vaults = Vec::new();
    if include_all_vaults {
        if let Ok(rows) = sqlx::query(
            r#"
            SELECT vault_id::text AS vault_id, token_ticker, vault_label,
                   total_funded_tokens, remaining_vault_tokens, daily_emission_tokens,
                   distributed_tokens, min_hashrate_ths, syndicate_sector_enabled,
                   active_miners_count, status
            FROM forge_mineable_vaults
            WHERE status = 'ACTIVE'
            ORDER BY created_at ASC
            "#,
        )
        .fetch_all(pool)
        .await
        {
            for v in rows {
                all_mineable_vaults.push(json!({
                    "vaultId": v.try_get::<String, _>("vault_id").unwrap_or_default(),
                    "tokenTicker": v.try_get::<String, _>("token_ticker").unwrap_or_default(),
                    "vaultLabel": v.try_get::<String, _>("vault_label").unwrap_or_default(),
                    "totalFundedTokens": v.try_get::<f64, _>("total_funded_tokens").unwrap_or(0.0),
                    "remainingVaultTokens": v.try_get::<f64, _>("remaining_vault_tokens").unwrap_or(0.0),
                    "dailyEmissionTokens": v.try_get::<f64, _>("daily_emission_tokens").unwrap_or(0.0),
                    "distributedTokens": v.try_get::<f64, _>("distributed_tokens").unwrap_or(0.0),
                    "minHashrateThs": v.try_get::<f64, _>("min_hashrate_ths").unwrap_or(0.1),
                    "syndicateSectorEnabled": v.try_get::<bool, _>("syndicate_sector_enabled").unwrap_or(true),
                    "activeMinersCount": v.try_get::<i32, _>("active_miners_count").unwrap_or(1),
                    "status": v.try_get::<String, _>("status").unwrap_or_else(|_| "ACTIVE".to_string())
                }));
            }
        }
    }

    let _ = KASPA_ADDR_VERSION_P2PK_SCHNORR;

    Ok(json!({
        "ticker": clean_ticker,
        "monetaryPolicy": policy_json,
        "mineableVault": mineable_vault_json,
        "vestingSchedules": vesting_schedules,
        "allMineableVaults": all_mineable_vaults
    }))
}

pub async fn deploy_forge_tokenomics_bundle(
    pool: &PgPool,
    creator_wallet: &str,
    payload: &Value,
) -> Result<Value, String> {
    let ticker = payload
        .get("ticker")
        .and_then(|v| v.as_str())
        .unwrap_or("SILO")
        .trim()
        .to_uppercase();
    let max_supply = payload
        .get("maxSupply")
        .and_then(|v| v.as_f64())
        .unwrap_or(21_000_000.0);
    let burn_rate_bps = payload
        .get("burnRateBps")
        .and_then(|v| v.as_i64())
        .unwrap_or(100) as i32;
    let emission_schedule_type = payload
        .get("emissionScheduleType")
        .and_then(|v| v.as_str())
        .unwrap_or("CHROMATIC_HALVING");
    let daily_emission_rate = payload
        .get("dailyEmissionRate")
        .and_then(|v| v.as_f64())
        .unwrap_or(13_698.0);
    let halving_interval_days = payload
        .get("halvingIntervalDays")
        .and_then(|v| v.as_i64())
        .unwrap_or(365) as i32;
    let reserve_locked_tokens = payload
        .get("reserveLockedTokens")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let zero_rug_lp_pct = payload
        .get("zeroRugLpPct")
        .and_then(|v| v.as_f64())
        .unwrap_or(50.0);
    let zero_rug_lock_days = payload
        .get("zeroRugLockDays")
        .and_then(|v| v.as_i64())
        .unwrap_or(365) as i32;
    let is_retroactive = payload
        .get("isRetroactiveUpgrade")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let charter_sha256 = payload
        .get("charterSha256")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let anchor_tx_hash = payload.get("anchorTxHash").and_then(|v| v.as_str());

    sqlx::query(
        r#"
        INSERT INTO forge_monetary_policies (
            token_ticker, creator_address, max_supply, burn_rate_bps,
            emission_schedule_type, daily_emission_rate, halving_interval_days,
            reserve_locked_tokens, zero_rug_lp_pct, zero_rug_lock_days,
            is_retroactive_upgrade, charter_sha256, anchor_tx_hash
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        ON CONFLICT (token_ticker) DO UPDATE SET
            max_supply = EXCLUDED.max_supply,
            burn_rate_bps = EXCLUDED.burn_rate_bps,
            emission_schedule_type = EXCLUDED.emission_schedule_type,
            daily_emission_rate = EXCLUDED.daily_emission_rate,
            halving_interval_days = EXCLUDED.halving_interval_days,
            reserve_locked_tokens = EXCLUDED.reserve_locked_tokens,
            zero_rug_lp_pct = EXCLUDED.zero_rug_lp_pct,
            zero_rug_lock_days = EXCLUDED.zero_rug_lock_days,
            is_retroactive_upgrade = EXCLUDED.is_retroactive_upgrade,
            charter_sha256 = EXCLUDED.charter_sha256,
            anchor_tx_hash = COALESCE(EXCLUDED.anchor_tx_hash, forge_monetary_policies.anchor_tx_hash),
            updated_at = CURRENT_TIMESTAMP
        "#,
    )
    .bind(&ticker)
    .bind(creator_wallet)
    .bind(max_supply)
    .bind(burn_rate_bps)
    .bind(emission_schedule_type)
    .bind(daily_emission_rate)
    .bind(halving_interval_days)
    .bind(reserve_locked_tokens)
    .bind(zero_rug_lp_pct)
    .bind(zero_rug_lock_days)
    .bind(is_retroactive)
    .bind(charter_sha256)
    .bind(anchor_tx_hash)
    .execute(pool)
    .await
    .map_err(|e| format!("Failed to upsert forge_monetary_policies: {}", e))?;

    if let Some(vault_obj) = payload.get("mineableVault").and_then(|v| v.as_object()) {
        let total_funded = vault_obj
            .get("totalFundedTokens")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if total_funded > 0.0 {
            let daily_emit = vault_obj
                .get("dailyEmissionTokens")
                .and_then(|v| v.as_f64())
                .unwrap_or(1000.0);
            let vault_label = vault_obj
                .get("vaultLabel")
                .and_then(|v| v.as_str())
                .unwrap_or("Proof-of-Hashrate Mining Vault");
            let min_hash = vault_obj
                .get("minHashrateThs")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.1);
            let syndicate_enabled = vault_obj
                .get("syndicateSectorEnabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            let _ = sqlx::query(
                r#"
                INSERT INTO forge_mineable_vaults (
                    token_ticker, creator_address, vault_label, total_funded_tokens,
                    remaining_vault_tokens, daily_emission_tokens, min_hashrate_ths,
                    syndicate_sector_enabled, funding_tx_hash
                ) VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8)
                ON CONFLICT (token_ticker) DO UPDATE SET
                    vault_label = EXCLUDED.vault_label,
                    total_funded_tokens = EXCLUDED.total_funded_tokens,
                    remaining_vault_tokens = EXCLUDED.remaining_vault_tokens,
                    daily_emission_tokens = EXCLUDED.daily_emission_tokens,
                    min_hashrate_ths = EXCLUDED.min_hashrate_ths,
                    syndicate_sector_enabled = EXCLUDED.syndicate_sector_enabled,
                    updated_at = CURRENT_TIMESTAMP
                "#,
            )
            .bind(&ticker)
            .bind(creator_wallet)
            .bind(vault_label)
            .bind(total_funded)
            .bind(daily_emit)
            .bind(min_hash)
            .bind(syndicate_enabled)
            .bind(anchor_tx_hash)
            .execute(pool)
            .await;
        }
    }

    if let Some(cap_table) = payload.get("capTable").and_then(|v| v.as_array()) {
        for entry in cap_table {
            let ben_addr = entry
                .get("address")
                .and_then(|v| v.as_str())
                .unwrap_or(creator_wallet);
            let label = entry
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("Genesis Tranche");
            let amount = entry.get("amount").and_then(|v| v.as_f64()).unwrap_or(0.0);
            if amount <= 0.0 {
                continue;
            }
            let cliff_d = entry.get("cliffDays").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let linear_d = entry
                .get("linearDays")
                .and_then(|v| v.as_i64())
                .unwrap_or(365) as i32;
            let daily_rate = if linear_d > 0 {
                amount / (linear_d as f64)
            } else {
                amount
            };
            let unlocked_init = if cliff_d == 0 && linear_d == 0 {
                amount
            } else {
                0.0
            };
            let status_init = if cliff_d == 0 && linear_d == 0 {
                "UNLOCKED"
            } else {
                "LOCKED"
            };
            let compiled = compile_silverscript_proof_of_lock_vault(
                &ticker,
                "KRC-20",
                label,
                ben_addr,
                amount,
                cliff_d as i64,
                linear_d as i64,
                Some(charter_sha256),
            );

            let _ = sqlx::query(
                r#"
                INSERT INTO forge_vesting_schedules (
                    token_ticker, beneficiary_address, creator_address, label,
                    total_allocated, unlocked_amount, cliff_days, linear_days,
                    daily_unlock_rate, vprog_state_root, lock_tx_hash, status
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                "#,
            )
            .bind(&ticker)
            .bind(ben_addr)
            .bind(creator_wallet)
            .bind(label)
            .bind(amount)
            .bind(unlocked_init)
            .bind(cliff_d)
            .bind(linear_d)
            .bind(daily_rate)
            .bind(&compiled.kcc20_state.state_root_hex)
            .bind(anchor_tx_hash)
            .bind(status_init)
            .execute(pool)
            .await;
        }
    }

    query_forge_tokenomics_bundle(pool, Some(&ticker), true).await
}

pub async fn claim_vested_forge_tranche(
    pool: &PgPool,
    wallet: &str,
    payload: &Value,
) -> Result<Value, String> {
    let vesting_id = payload
        .get("vestingId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing vestingId".to_string())?;

    let row_opt = sqlx::query(
        r#"
        SELECT token_ticker, beneficiary_address, unlocked_amount, claimed_amount
        FROM forge_vesting_schedules
        WHERE vesting_id::text = $1
        "#,
    )
    .bind(vesting_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("Vesting lookup failed: {}", e))?;

    let Some(row) = row_opt else {
        return Err("Vesting tranche not found".to_string());
    };

    let ticker: String = row.try_get("token_ticker").unwrap_or_else(|_| "SILO".to_string());
    let beneficiary: String = row
        .try_get("beneficiary_address")
        .unwrap_or_else(|_| wallet.to_string());
    let unlocked: f64 = row.try_get("unlocked_amount").unwrap_or(0.0);
    let claimed: f64 = row.try_get("claimed_amount").unwrap_or(0.0);
    let claimable = (unlocked - claimed).max(0.0);

    if claimable <= 0.0 {
        return Err("No unlocked tokens currently available to claim.".to_string());
    }

    sqlx::query(
        r#"
        UPDATE forge_vesting_schedules
        SET claimed_amount = unlocked_amount,
            updated_at = CURRENT_TIMESTAMP
        WHERE vesting_id::text = $1
        "#,
    )
    .bind(vesting_id)
    .execute(pool)
    .await
    .map_err(|e| format!("Claim update failed: {}", e))?;

    let _ = sqlx::query(
        r#"
        UPDATE forge_monetary_policies
        SET reserve_emitted_tokens = reserve_emitted_tokens + $2,
            updated_at = CURRENT_TIMESTAMP
        WHERE token_ticker = $1
        "#,
    )
    .bind(&ticker)
    .bind(claimable)
    .execute(pool)
    .await;

    Ok(json!({
        "vestingId": vesting_id,
        "tokenTicker": ticker,
        "claimedAmount": claimable,
        "beneficiary": beneficiary
    }))
}

// ============================================================================
// STEALTH FOUNDER-ONLY `/v1/forge/*` API (STRICT 404 FOR ALL NON-FOUNDERS)
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForgeChallengeRequest {
    pub pubkey_hex: Option<String>,
    pub wallet_address: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForgeAuthPayload {
    pub pubkey_hex: Option<String>,
    pub challenge: Option<String>,
    pub signature_hex: Option<String>,
    pub action: Option<String>,
    pub payload: Option<Value>,
}

async fn authorize_founder_request(
    headers: &HeaderMap,
    pubkey_opt: Option<&str>,
    challenge_opt: Option<&str>,
    signature_opt: Option<&str>,
) -> Option<(String, String)> {
    let founder_pk_hex = resolve_master_treasury_pubkey_hex()?;
    let redis_url = env::var("REDIS_URL").ok()?;
    let client = redis::Client::open(redis_url.trim()).ok()?;
    let mut conn = client.get_multiplexed_async_connection().await.ok()?;

    // Path 1: Short-lived founder session token verified in Redis
    if let Some(sess_tok) = headers.get("x-forge-session").and_then(|v| v.to_str().ok()) {
        let clean_tok = sess_tok.trim();
        if clean_tok.len() >= 32 && clean_tok.len() <= 128 && clean_tok.bytes().all(|b| b.is_ascii_hexdigit()) {
            let stored_pk: Option<String> = redis::cmd("GET")
                .arg(format!("perennia:forge:session:{}", clean_tok))
                .query_async(&mut conn)
                .await
                .ok()
                .flatten();
            if let Some(pk) = stored_pk {
                if pk.eq_ignore_ascii_case(&founder_pk_hex) {
                    return Some((founder_pk_hex, clean_tok.to_string()));
                }
            }
        }
    }

    // Path 2: Single-use 64-byte Schnorr challenge verification against MASTER_TREASURY_PUBKEY
    let pk_raw = pubkey_opt
        .or_else(|| headers.get("x-forge-pubkey").and_then(|v| v.to_str().ok()))?
        .trim()
        .strip_prefix("0x")
        .unwrap_or("")
        .to_ascii_lowercase();
    let pk_clean = if pk_raw.is_empty() {
        pubkey_opt
            .or_else(|| headers.get("x-forge-pubkey").and_then(|v| v.to_str().ok()))
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
    } else {
        pk_raw
    };
    if !crate::agent::auth::constant_time_eq(pk_clean.as_bytes(), founder_pk_hex.as_bytes()) {
        return None;
    }

    let challenge = challenge_opt
        .or_else(|| headers.get("x-forge-challenge").and_then(|v| v.to_str().ok()))?
        .trim();
    if challenge.len() != 64 || !challenge.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let sig_hex = signature_opt
        .or_else(|| headers.get("x-forge-sig").and_then(|v| v.to_str().ok()))?
        .trim();

    let chg_key = format!("perennia:forge:challenge:{}", challenge);
    let stored_chg_pk: Option<String> = redis::cmd("GET")
        .arg(&chg_key)
        .query_async(&mut conn)
        .await
        .ok()
        .flatten();
    let Some(expected_for_chg) = stored_chg_pk else {
        return None;
    };
    if !expected_for_chg.eq_ignore_ascii_case(&founder_pk_hex) {
        return None;
    }

    let msg_text = format!("PERENNIA_FORGE_FOUNDER_AUTH_V1:{}", challenge);
    if !verify_schnorr_founder_signature(&founder_pk_hex, &msg_text, sig_hex) {
        return None;
    }
    let _: redis::RedisResult<()> = redis::cmd("DEL").arg(&chg_key).query_async(&mut conn).await;

    let mut sess_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut sess_bytes);
    let session_tok = hex::encode(sess_bytes);
    let _: redis::RedisResult<()> = redis::cmd("SETEX")
        .arg(format!("perennia:forge:session:{}", session_tok))
        .arg(900u64)
        .arg(&founder_pk_hex)
        .query_async(&mut conn)
        .await;

    Some((founder_pk_hex, session_tok))
}

pub async fn handle_forge_challenge(
    Json(req): Json<ForgeChallengeRequest>,
) -> impl IntoResponse {
    let Some(founder_pk_hex) = resolve_master_treasury_pubkey_hex() else {
        return (StatusCode::NOT_FOUND, "").into_response();
    };
    let supplied_pk = if let Some(ref pk) = req.pubkey_hex {
        pk.trim().strip_prefix("0x").unwrap_or(pk.trim()).to_ascii_lowercase()
    } else if let Some(ref addr) = req.wallet_address {
        match decode_kaspa_address_payload(addr.trim()) {
            Some((KASPA_ADDR_VERSION_P2PK_SCHNORR, hash32)) => hex::encode(hash32),
            _ => return (StatusCode::NOT_FOUND, "").into_response(),
        }
    } else {
        return (StatusCode::NOT_FOUND, "").into_response();
    };

    if !crate::agent::auth::constant_time_eq(supplied_pk.as_bytes(), founder_pk_hex.as_bytes()) {
        return (StatusCode::NOT_FOUND, "").into_response();
    }
    let Ok(redis_url) = env::var("REDIS_URL") else {
        return (StatusCode::NOT_FOUND, "").into_response();
    };
    let Ok(client) = redis::Client::open(redis_url.trim()) else {
        return (StatusCode::NOT_FOUND, "").into_response();
    };
    let Ok(mut conn) = client.get_multiplexed_async_connection().await else {
        return (StatusCode::NOT_FOUND, "").into_response();
    };

    let mut chg_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut chg_bytes);
    let challenge = hex::encode(chg_bytes);
    let msg_text = format!("PERENNIA_FORGE_FOUNDER_AUTH_V1:{}", challenge);
    let digest_hex = blake3::hash(msg_text.as_bytes()).to_hex().to_string();

    let _: redis::RedisResult<()> = redis::cmd("SETEX")
        .arg(format!("perennia:forge:challenge:{}", challenge))
        .arg(60u64)
        .arg(&founder_pk_hex)
        .query_async(&mut conn)
        .await;

    (
        StatusCode::OK,
        Json(json!({
            "challenge": challenge,
            "message": msg_text,
            "digestHex": digest_hex,
            "expiresInSecs": 60
        })),
    )
        .into_response()
}

pub async fn handle_forge_overview(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(req): Json<ForgeAuthPayload>,
) -> impl IntoResponse {
    let Some((founder_pk_hex, session_token)) = authorize_founder_request(
        &headers,
        req.pubkey_hex.as_deref(),
        req.challenge.as_deref(),
        req.signature_hex.as_deref(),
    )
    .await
    else {
        return (StatusCode::NOT_FOUND, "").into_response();
    };

    let master_treasury = crate::chronos::resolve_master_treasury_prefixed().unwrap_or_default();
    let (siphon_halt, siphon_tel_raw): (Option<String>, Option<String>) =
        if let Ok(redis_url) = env::var("REDIS_URL") {
            if let Ok(client) = redis::Client::open(redis_url.trim()) {
                if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                    redis::pipe()
                        .cmd("GET")
                        .arg("perennia:killswitch:silo_siphon")
                        .cmd("GET")
                        .arg("perennia:solver:silo_siphon_telemetry")
                        .query_async(&mut conn)
                        .await
                        .unwrap_or((None, None))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

    let total_fee_sompi: String = sqlx::query_scalar::<_, Option<String>>(
        r#"
        SELECT COALESCE(SUM(house_fee_sompi), 0)::NUMERIC(39,0)::TEXT
        FROM settlement_receipts
        "#,
    )
    .fetch_one(&pool)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| "0".to_string());

    let sweep_rows = sqlx::query(
        r#"
        SELECT sweep_id, destination_address, amount_kas, status, tx_hash, created_at
        FROM treasury_airlock_sweeps
        ORDER BY created_at DESC
        LIMIT 25
        "#,
    )
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    let sweeps: Vec<Value> = sweep_rows
        .into_iter()
        .map(|r| {
            json!({
                "sweepId": r.try_get::<String, _>("sweep_id").unwrap_or_default(),
                "destinationAddress": r.try_get::<String, _>("destination_address").unwrap_or_default(),
                "amountKas": r.try_get::<f64, _>("amount_kas").unwrap_or(0.0).to_string(),
                "status": r.try_get::<String, _>("status").unwrap_or_default(),
                "txHash": r.try_get::<Option<String>, _>("tx_hash").ok().flatten(),
                "createdAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok().map(|d| d.to_rfc3339())
            })
        })
        .collect();

    let bundle = query_forge_tokenomics_bundle(&pool, Some("SILO"), true)
        .await
        .unwrap_or_else(|_| json!({}));

    let siphon_telemetry = siphon_tel_raw
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .unwrap_or_else(|| json!({ "lastSiphonedKasSompi": "0", "maxValveBps": 2000 }));

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "founderPubkeyHex": founder_pk_hex,
            "forgeSessionToken": session_token,
            "panelA": {
                "ticker": "SILO",
                "maxSupplyAtomic": SILO_MAX_SUPPLY_ATOMIC.to_string(),
                "maxSupplyWhole": SILO_MAX_SUPPLY_WHOLE.to_string(),
                "sleeves": [
                    { "name": "Mining & LP Incentives", "pct": SILO_SLEEVE_MINING_LP_PCT, "atomic": (40_000_000u128 * SILO_ATOMIC_UNIT).to_string() },
                    { "name": "Protocol Treasury Reserve", "pct": SILO_SLEEVE_TREASURY_PCT, "atomic": (25_000_000u128 * SILO_ATOMIC_UNIT).to_string() },
                    { "name": "Genesis Liquidity & Ecosystem", "pct": SILO_SLEEVE_GENESIS_LP_PCT, "atomic": (20_000_000u128 * SILO_ATOMIC_UNIT).to_string() },
                    { "name": "Founder / Core 4yr Vest (6m cliff)", "pct": SILO_SLEEVE_FOUNDER_VEST_PCT, "atomic": (15_000_000u128 * SILO_ATOMIC_UNIT).to_string() }
                ],
                "feeTiers": [
                    { "minSiloWhole": "0", "feeBps": SILO_TIER_0_BPS },
                    { "minSiloWhole": "10000", "feeBps": SILO_TIER_10K_BPS },
                    { "minSiloWhole": "100000", "feeBps": SILO_TIER_100K_BPS },
                    { "minSiloWhole": "1000000", "feeBps": SILO_TIER_1M_BPS }
                ],
                "tokenomicsBundle": bundle
            },
            "panelB": {
                "emergencyHalted": siphon_halt.as_deref() == Some("1"),
                "maxValveBps": 2000,
                "telemetry": siphon_telemetry
            },
            "panelC": {
                "masterTreasuryAddress": master_treasury,
                "totalProtocolFeeSompi": total_fee_sompi,
                "coldAirlockSweeps": sweeps,
                "asOfUtc": Utc::now().to_rfc3339()
            }
        })),
    )
        .into_response()
}

pub async fn handle_forge_action(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(req): Json<ForgeAuthPayload>,
) -> impl IntoResponse {
    let Some((founder_pk_hex, _)) = authorize_founder_request(
        &headers,
        req.pubkey_hex.as_deref(),
        req.challenge.as_deref(),
        req.signature_hex.as_deref(),
    )
    .await
    else {
        return (StatusCode::NOT_FOUND, "").into_response();
    };

    let action = req.action.as_deref().unwrap_or("").trim().to_uppercase();
    let payload = req.payload.unwrap_or_else(|| json!({}));

    match action.as_str() {
        "TOGGLE_SILO_SIPHON_HALT" => {
            let halted = payload.get("halted").and_then(|v| v.as_bool()).unwrap_or(true);
            if let Ok(redis_url) = env::var("REDIS_URL") {
                if let Ok(client) = redis::Client::open(redis_url.trim()) {
                    if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                        let _: redis::RedisResult<()> = redis::cmd("SET")
                            .arg("perennia:killswitch:silo_siphon")
                            .arg(if halted { "1" } else { "0" })
                            .query_async(&mut conn)
                            .await;
                    }
                }
            }
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "emergencyHalted": halted })),
            )
                .into_response()
        }
        "BUILD_SILO_GENESIS_DEPLOY" => {
            let deploy_payload = json!({
                "p": "krc-20",
                "op": "deploy",
                "tick": "SILO",
                "max": SILO_MAX_SUPPLY_ATOMIC.to_string(),
                "lim": (1_000_000u128 * SILO_ATOMIC_UNIT).to_string(),
                "pre": SILO_MAX_SUPPLY_ATOMIC.to_string(),
                "dec": SILO_ATOMIC_DECIMALS,
                "founderPubkeyHex": founder_pk_hex
            });
            (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "unsignedDeployPayloadHex": hex::encode(deploy_payload.to_string().as_bytes()),
                    "deployManifest": deploy_payload,
                    "requiresClientSchnorrSignature": true
                })),
            )
                .into_response()
        }
        "BUILD_GENESIS_LP_SEED" => {
            let kas_sompi = payload
                .get("kasSompi")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(10_000 * 100_000_000);
            let silo_atomic = payload
                .get("siloAtomic")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(20_000_000 * SILO_ATOMIC_UNIT);
            let master_addr = crate::chronos::resolve_master_treasury_prefixed().unwrap_or_default();
            (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "pair": "KAS/SILO",
                    "kasSompi": kas_sompi.to_string(),
                    "siloAtomic": silo_atomic.to_string(),
                    "masterTreasuryAddress": master_addr,
                    "requiresClientSchnorrSignature": true
                })),
            )
                .into_response()
        }
        "EXPORT_TREASURY_REVENUE_CSV" => {
            let rows = sqlx::query(
                r#"
                SELECT receipt_id, epoch_id, target_asset, house_fee_sompi::NUMERIC(39,0)::TEXT AS house_fee_sompi,
                       kaspa_l1_txid, status, settled_at
                FROM settlement_receipts
                ORDER BY settled_at DESC
                LIMIT 500
                "#,
            )
            .fetch_all(&pool)
            .await
            .unwrap_or_default();
            let mut csv_lines = vec!["receipt_id,epoch_id,target_asset,house_fee_sompi,kaspa_l1_txid,status,settled_at".to_string()];
            for r in rows {
                let line = format!(
                    "{},{},{},{},{},{},{}",
                    r.try_get::<String, _>("receipt_id").unwrap_or_default(),
                    r.try_get::<String, _>("epoch_id").unwrap_or_default(),
                    r.try_get::<String, _>("target_asset").unwrap_or_default(),
                    r.try_get::<String, _>("house_fee_sompi").unwrap_or_else(|_| "0".to_string()),
                    r.try_get::<String, _>("kaspa_l1_txid").unwrap_or_default(),
                    r.try_get::<String, _>("status").unwrap_or_default(),
                    r.try_get::<chrono::DateTime<chrono::Utc>, _>("settled_at").ok().map(|d| d.to_rfc3339()).unwrap_or_default()
                );
                csv_lines.push(line);
            }
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "csv": csv_lines.join("\n") })),
            )
                .into_response()
        }
        _ => (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": "UNKNOWN_FORGE_ACTION" }))).into_response(),
    }
}

pub fn forge_routes() -> Router<PgPool> {
    Router::new()
        .route("/v1/forge/challenge", post(handle_forge_challenge))
        .route("/v1/forge/overview", post(handle_forge_overview))
        .route("/v1/forge/action", post(handle_forge_action))
}