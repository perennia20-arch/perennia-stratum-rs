#[path = "chronos/netting.rs"]
pub mod netting;
#[path = "chronos/forge_bell.rs"]
pub mod forge_bell;
#[path = "chronos/daemons.rs"]
pub mod daemons;

pub use daemons::*;
pub use forge_bell::*;
pub use netting::*;

use chrono::{Timelike, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::{PgPool, Row};
use std::env;
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemTreasuryConfig {
    pub config_id: String,
    pub hot_ceiling_kas: f64,
    pub min_runway_kas: f64,
    pub fpps_max_float_kas: f64,
    pub pool_fee_rate: f64,
    pub outflow_breaker_tripped: bool,
    pub cold_kas_address: String,
    pub cold_btc_address: String,
    pub cold_eth_address: String,
    pub cold_sol_address: String,
    pub updated_by: String,
    pub updated_at: String,
}

pub fn resolve_master_treasury_address() -> String {
    env::var("PERENNIA_MASTER_TREASURY_KAS")
        .or_else(|_| env::var("MASTER_ADMIN_ADDRESS"))
        .or_else(|_| env::var("MASTER_TREASURY_ADDRESS"))
        .ok()
        .map(|s| s.trim().to_lowercase().replace("kaspa:", "").trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_default()
}

pub fn resolve_master_treasury_prefixed() -> Result<String, String> {
    let clean = resolve_master_treasury_address();
    if clean.len() < 55 {
        return Err(
            "CONFIG_HALT: PERENNIA_MASTER_TREASURY_KAS is not configured in .env.".to_string(),
        );
    }
    Ok(format!("kaspa:{}", clean))
}

pub fn resolve_hot_dispatcher_address() -> Option<String> {
    env::var("PERENNIA_HOT_KAS_ADDRESS")
        .or_else(|_| env::var("PERENNIA_TREASURY_KAS_ADDRESS"))
        .ok()
        .map(|s| s.trim().to_lowercase().replace("kaspa:", "").trim().to_string())
        .filter(|s| s.len() >= 55)
        .map(|clean| format!("kaspa:{}", clean))
}

fn resolve_ledger_hmac_secret() -> Result<Vec<u8>, String> {
    let raw = env::var("LEDGER_HMAC_SECRET")
        .or_else(|_| env::var("KYC_MASTER_KEY"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if raw.len() < 32 {
        return Err(
            "CRITICAL_SECURITY_LOCKDOWN: LEDGER_HMAC_SECRET or KYC_MASTER_KEY (min 32 chars) must be set in .env."
                .to_string(),
        );
    }
    Ok(raw.into_bytes())
}

pub fn canonicalize_lp_tokens_for_hmac(lp_tokens: &Value) -> String {
    let Some(obj) = lp_tokens.as_object() else {
        return "{}".to_string();
    };
    let mut pairs: Vec<(String, f64)> = obj
        .iter()
        .map(|(k, v)| {
            let amt = v
                .as_f64()
                .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
                .unwrap_or(0.0);
            (k.trim().to_uppercase(), (amt * 1e8).round() / 1e8)
        })
        .filter(|(_, amt)| *amt > 1e-8)
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let formatted: Vec<String> = pairs
        .into_iter()
        .map(|(k, v)| format!("{}:{:.8}", k, v))
        .collect();
    format!("{{{}}}", formatted.join(","))
}

pub fn compute_reservoir_hmac(
    wallet_address: &str,
    streaming_balance_kas: f64,
    total_yield_kas: f64,
    lp_tokens: &Value,
) -> Result<String, String> {
    let secret = resolve_ledger_hmac_secret()?;
    let clean_wallet = wallet_address
        .trim()
        .to_lowercase()
        .replace("kaspa:", "")
        .trim()
        .to_string();
    let canonical_lp = canonicalize_lp_tokens_for_hmac(lp_tokens);
    let preimage = format!(
        "PERENNIA_RESERVOIR_V1|kaspa:{}|{:.8}|{:.8}|{}",
        clean_wallet,
        (streaming_balance_kas.max(0.0) * 1e8).round() / 1e8,
        (total_yield_kas.max(0.0) * 1e8).round() / 1e8,
        canonical_lp
    );
    let mut mac = HmacSha256::new_from_slice(&secret)
        .map_err(|e| format!("HMAC initialization failed: {}", e))?;
    mac.update(preimage.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn constant_time_hex_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.trim().as_bytes();
    let b_bytes = b.trim().as_bytes();
    if a_bytes.len() != b_bytes.len() || a_bytes.is_empty() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub async fn quarantine_single_wallet(
    pool: &PgPool,
    wallet_address: &str,
    reason: &str,
) {
    let clean = wallet_address
        .trim()
        .to_lowercase()
        .replace("kaspa:", "")
        .trim()
        .to_string();
    let prefixed = format!("kaspa:{}", clean);
    tracing::error!(
        "🚨 [LEDGER INVARIANT QUARANTINE] Quarantining single wallet {} | Reason: {}",
        prefixed,
        reason
    );
    let _ = sqlx::query(
        r#"
        UPDATE yield_reservoirs
        SET quarantined = TRUE,
            quarantine_reason = $3,
            quarantined_at = CURRENT_TIMESTAMP,
            last_updated = CURRENT_TIMESTAMP
        WHERE wallet_address = $1 OR wallet_address = $2
        "#,
    )
    .bind(&prefixed)
    .bind(&clean)
    .bind(reason)
    .execute(pool)
    .await;
}

pub async fn verify_wallet_ledger_invariant_or_quarantine(
    pool: &PgPool,
    wallet_address: &str,
    requested_kas_debit: f64,
) -> Result<(), String> {
    let clean = wallet_address
        .trim()
        .to_lowercase()
        .replace("kaspa:", "")
        .trim()
        .to_string();
    let prefixed = format!("kaspa:{}", clean);

    let sys_cfg = load_system_treasury_config(pool).await;
    if sys_cfg.outflow_breaker_tripped {
        return Err(
            "CIRCUIT_BREAKER_TRIPPED: Director has paused automated L1 outflows.".to_string(),
        );
    }

    let row_opt = sqlx::query(
        r#"
        SELECT wallet_address, streaming_balance_kas, total_yield_kas,
               COALESCE(lp_tokens, '{}'::jsonb) AS lp_tokens,
               COALESCE(verified_onchain_credits_kas, 0.0) AS verified_onchain_credits_kas,
               COALESCE(row_hmac_sig, '') AS row_hmac_sig,
               COALESCE(quarantined, FALSE) AS quarantined,
               quarantine_reason
        FROM yield_reservoirs
        WHERE wallet_address = $1 OR wallet_address = $2
        ORDER BY streaming_balance_kas DESC
        LIMIT 1
        "#,
    )
    .bind(&prefixed)
    .bind(&clean)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("Failed to query yield_reservoirs invariant: {}", e))?;

    let Some(row) = row_opt else {
        if requested_kas_debit > 0.0 {
            return Err(format!(
                "INSUFFICIENT_VERIFIED_RESERVOIR: No yield_reservoirs record found for {}.",
                prefixed
            ));
        }
        return Ok(());
    };

    let is_quarantined: bool = row.try_get("quarantined").unwrap_or(false);
    if is_quarantined {
        let q_reason: Option<String> = row.try_get("quarantine_reason").ok().flatten();
        return Err(format!(
            "WALLET_QUARANTINED: Automated L1 payouts are suspended for {} ({}).",
            prefixed,
            q_reason.unwrap_or_else(|| "Ledger invariant mismatch".to_string())
        ));
    }

    let streaming_kas: f64 = row.try_get("streaming_balance_kas").unwrap_or(0.0);
    let total_yield_kas: f64 = row.try_get("total_yield_kas").unwrap_or(0.0);
    let verified_credits_kas: f64 = row.try_get("verified_onchain_credits_kas").unwrap_or(0.0);
    let lp_tokens: Value = row.try_get("lp_tokens").unwrap_or_else(|_| json!({}));
    let stored_hmac: String = row.try_get("row_hmac_sig").unwrap_or_default();

    let expected_hmac = compute_reservoir_hmac(&prefixed, streaming_kas, total_yield_kas, &lp_tokens)?;

    if stored_hmac.trim().is_empty() {
        let _ = sqlx::query(
            r#"
            UPDATE yield_reservoirs
            SET row_hmac_sig = $3,
                verified_onchain_credits_kas = GREATEST(verified_onchain_credits_kas, total_yield_kas, streaming_balance_kas)
            WHERE wallet_address = $1 OR wallet_address = $2
            "#,
        )
        .bind(&prefixed)
        .bind(&clean)
        .bind(&expected_hmac)
        .execute(pool)
        .await;
    } else if !constant_time_hex_eq(&stored_hmac, &expected_hmac) {
        let reason = format!(
            "HMAC row signature mismatch on yield_reservoirs (stored {}..., expected {}...)",
            &stored_hmac.chars().take(12).collect::<String>(),
            &expected_hmac.chars().take(12).collect::<String>()
        );
        quarantine_single_wallet(pool, &prefixed, &reason).await;
        return Err(format!("LEDGER_HMAC_VIOLATION: {}", reason));
    }

    let settled_onramp_kas: f64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(delivered_kas), 0.0)
        FROM fiat_onramp_orders
        WHERE (wallet_address = $1 OR wallet_address = $2)
          AND status = 'COMPLETED'
        "#,
    )
    .bind(&prefixed)
    .bind(&clean)
    .fetch_one(pool)
    .await
    .unwrap_or(0.0);

    let max_verified_ceiling =
        total_yield_kas.max(verified_credits_kas) + settled_onramp_kas + 1.0;
    if streaming_kas > max_verified_ceiling {
        let reason = format!(
            "Balance drift detected: streaming_balance_kas ({:.4} KAS) exceeds verified credits ceiling ({:.4} KAS)",
            streaming_kas, max_verified_ceiling
        );
        quarantine_single_wallet(pool, &prefixed, &reason).await;
        return Err(format!("SOLVENCY_INVARIANT_VIOLATION: {}", reason));
    }

    if requested_kas_debit > 0.0 && streaming_kas + 1e-6 < requested_kas_debit {
        return Err(format!(
            "INSUFFICIENT_RESERVOIR_BALANCE: Requested {:.4} KAS, available {:.4} KAS.",
            requested_kas_debit, streaming_kas
        ));
    }

    Ok(())
}

pub async fn upsert_signed_yield_reservoir_kas(
    pool: &PgPool,
    wallet_address: &str,
    delta_streaming_kas: f64,
    delta_total_yield_kas: f64,
    delta_verified_credits_kas: f64,
) -> Result<f64, String> {
    let clean = wallet_address
        .trim()
        .to_lowercase()
        .replace("kaspa:", "")
        .trim()
        .to_string();
    let prefixed = format!("kaspa:{}", clean);

    let existing_opt = sqlx::query(
        r#"
        SELECT wallet_address, streaming_balance_kas, total_yield_kas,
               COALESCE(lp_tokens, '{}'::jsonb) AS lp_tokens,
               COALESCE(verified_onchain_credits_kas, 0.0) AS verified_onchain_credits_kas,
               COALESCE(quarantined, FALSE) AS quarantined
        FROM yield_reservoirs
        WHERE wallet_address = $1 OR wallet_address = $2
        ORDER BY streaming_balance_kas DESC
        LIMIT 1
        "#,
    )
    .bind(&prefixed)
    .bind(&clean)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("DB read failed in upsert_signed_yield_reservoir_kas: {}", e))?;

    let (cur_streaming, cur_total_yield, cur_verified, lp_tokens, target_pk) =
        if let Some(r) = existing_opt {
            if r.try_get::<bool, _>("quarantined").unwrap_or(false) {
                return Err(format!("Wallet {} is quarantined.", prefixed));
            }
            (
                r.try_get::<f64, _>("streaming_balance_kas").unwrap_or(0.0),
                r.try_get::<f64, _>("total_yield_kas").unwrap_or(0.0),
                r.try_get::<f64, _>("verified_onchain_credits_kas")
                    .unwrap_or(0.0),
                r.try_get::<Value, _>("lp_tokens")
                    .unwrap_or_else(|_| json!({})),
                r.try_get::<String, _>("wallet_address")
                    .unwrap_or_else(|_| prefixed.clone()),
            )
        } else {
            (0.0, 0.0, 0.0, json!({}), prefixed.clone())
        };

    if delta_streaming_kas < 0.0 && cur_streaming + delta_streaming_kas < -1e-6 {
        return Err(format!(
            "INSUFFICIENT_BALANCE: Cannot debit {:.6} KAS from {:.6} KAS.",
            delta_streaming_kas.abs(),
            cur_streaming
        ));
    }

    let next_streaming = (cur_streaming + delta_streaming_kas).max(0.0);
    let next_total_yield = (cur_total_yield + delta_total_yield_kas.max(0.0)).max(0.0);
    let next_verified = (cur_verified + delta_verified_credits_kas.max(0.0)).max(next_total_yield);
    let new_hmac = compute_reservoir_hmac(&prefixed, next_streaming, next_total_yield, &lp_tokens)?;

    sqlx::query(
        r#"
        INSERT INTO yield_reservoirs (
            wallet_address, streaming_balance_kas, total_yield_kas,
            lp_tokens, verified_onchain_credits_kas, row_hmac_sig, last_updated
        ) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
        ON CONFLICT (wallet_address) DO UPDATE SET
            streaming_balance_kas = EXCLUDED.streaming_balance_kas,
            total_yield_kas = EXCLUDED.total_yield_kas,
            verified_onchain_credits_kas = EXCLUDED.verified_onchain_credits_kas,
            row_hmac_sig = EXCLUDED.row_hmac_sig,
            last_updated = CURRENT_TIMESTAMP
        "#,
    )
    .bind(&target_pk)
    .bind(next_streaming)
    .bind(next_total_yield)
    .bind(&lp_tokens)
    .bind(next_verified)
    .bind(&new_hmac)
    .execute(pool)
    .await
    .map_err(|e| format!("Failed to persist signed yield_reservoirs row: {}", e))?;

    Ok(next_streaming)
}

pub async fn load_system_treasury_config(pool: &PgPool) -> SystemTreasuryConfig {
    let default_cold_kas = resolve_master_treasury_prefixed().unwrap_or_default();
    let row_opt = sqlx::query(
        r#"
        SELECT config_id, hot_ceiling_kas, min_runway_kas, fpps_max_float_kas,
               pool_fee_rate, outflow_breaker_tripped, cold_kas_address,
               cold_btc_address, cold_eth_address, cold_sol_address,
               updated_by, updated_at
        FROM system_treasury_config
        WHERE config_id = 'PRIMARY'
        LIMIT 1
        "#,
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    if let Some(r) = row_opt {
        let db_cold_kas: String = r.try_get("cold_kas_address").unwrap_or_default();
        return SystemTreasuryConfig {
            config_id: r
                .try_get("config_id")
                .unwrap_or_else(|_| "PRIMARY".to_string()),
            hot_ceiling_kas: r.try_get("hot_ceiling_kas").unwrap_or(5000.0),
            min_runway_kas: r.try_get("min_runway_kas").unwrap_or(250.0),
            fpps_max_float_kas: r.try_get("fpps_max_float_kas").unwrap_or(50.0),
            pool_fee_rate: r.try_get("pool_fee_rate").unwrap_or(0.01),
            outflow_breaker_tripped: r.try_get("outflow_breaker_tripped").unwrap_or(false),
            cold_kas_address: if db_cold_kas.trim().is_empty() {
                default_cold_kas
            } else {
                db_cold_kas
            },
            cold_btc_address: r
                .try_get("cold_btc_address")
                .unwrap_or_else(|_| env::var("PERENNIA_COLD_BTC_ADDRESS").unwrap_or_default()),
            cold_eth_address: r
                .try_get("cold_eth_address")
                .unwrap_or_else(|_| env::var("PERENNIA_COLD_ETH_ADDRESS").unwrap_or_default()),
            cold_sol_address: r
                .try_get("cold_sol_address")
                .unwrap_or_else(|_| env::var("PERENNIA_COLD_SOL_ADDRESS").unwrap_or_default()),
            updated_by: r
                .try_get("updated_by")
                .unwrap_or_else(|_| "SYSTEM".to_string()),
            updated_at: r
                .try_get::<chrono::DateTime<Utc>, _>("updated_at")
                .map(|d| d.to_rfc3339())
                .unwrap_or_else(|_| Utc::now().to_rfc3339()),
        };
    }

    SystemTreasuryConfig {
        config_id: "PRIMARY".to_string(),
        hot_ceiling_kas: 5000.0,
        min_runway_kas: 250.0,
        fpps_max_float_kas: 50.0,
        pool_fee_rate: 0.01,
        outflow_breaker_tripped: false,
        cold_kas_address: default_cold_kas,
        cold_btc_address: env::var("PERENNIA_COLD_BTC_ADDRESS").unwrap_or_default(),
        cold_eth_address: env::var("PERENNIA_COLD_ETH_ADDRESS").unwrap_or_default(),
        cold_sol_address: env::var("PERENNIA_COLD_SOL_ADDRESS").unwrap_or_default(),
        updated_by: "DEFAULT".to_string(),
        updated_at: Utc::now().to_rfc3339(),
    }
}

pub async fn update_system_treasury_config(
    pool: &PgPool,
    payload: &Value,
    updated_by: &str,
) -> Result<SystemTreasuryConfig, String> {
    let current = load_system_treasury_config(pool).await;

    let hot_ceiling_kas = payload
        .get("hotCeilingKas")
        .and_then(|v| v.as_f64())
        .unwrap_or(current.hot_ceiling_kas)
        .max(50.0);

    let min_runway_kas = payload
        .get("minRunwayKas")
        .and_then(|v| v.as_f64())
        .unwrap_or(current.min_runway_kas)
        .max(0.0);

    let fpps_max_float_kas = payload
        .get("fppsMaxFloatKas")
        .and_then(|v| v.as_f64())
        .unwrap_or(current.fpps_max_float_kas)
        .max(1.0);

    let pool_fee_rate = payload
        .get("poolFeeRate")
        .and_then(|v| v.as_f64())
        .or_else(|| {
            payload
                .get("poolFeeRatePct")
                .and_then(|v| v.as_f64())
                .map(|pct| pct / 100.0)
        })
        .unwrap_or(current.pool_fee_rate)
        .clamp(0.0, 0.25);

    let outflow_breaker_tripped = payload
        .get("outflowBreakerTripped")
        .or_else(|| payload.get("lowRunwayBreakerTripped"))
        .and_then(|v| v.as_bool())
        .unwrap_or(current.outflow_breaker_tripped);

    let cold_kas_address = payload
        .get("coldKasAddress")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or(current.cold_kas_address);

    let cold_btc_address = payload
        .get("coldBtcAddress")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or(current.cold_btc_address);

    let cold_eth_address = payload
        .get("coldEthAddress")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or(current.cold_eth_address);

    let cold_sol_address = payload
        .get("coldSolAddress")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or(current.cold_sol_address);

    sqlx::query(
        r#"
        INSERT INTO system_treasury_config (
            config_id, hot_ceiling_kas, min_runway_kas, fpps_max_float_kas,
            pool_fee_rate, outflow_breaker_tripped, cold_kas_address,
            cold_btc_address, cold_eth_address, cold_sol_address,
            updated_by, updated_at
        ) VALUES ('PRIMARY', $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP)
        ON CONFLICT (config_id) DO UPDATE SET
            hot_ceiling_kas = EXCLUDED.hot_ceiling_kas,
            min_runway_kas = EXCLUDED.min_runway_kas,
            fpps_max_float_kas = EXCLUDED.fpps_max_float_kas,
            pool_fee_rate = EXCLUDED.pool_fee_rate,
            outflow_breaker_tripped = EXCLUDED.outflow_breaker_tripped,
            cold_kas_address = EXCLUDED.cold_kas_address,
            cold_btc_address = EXCLUDED.cold_btc_address,
            cold_eth_address = EXCLUDED.cold_eth_address,
            cold_sol_address = EXCLUDED.cold_sol_address,
            updated_by = EXCLUDED.updated_by,
            updated_at = CURRENT_TIMESTAMP
        "#,
    )
    .bind(hot_ceiling_kas)
    .bind(min_runway_kas)
    .bind(fpps_max_float_kas)
    .bind(pool_fee_rate)
    .bind(outflow_breaker_tripped)
    .bind(&cold_kas_address)
    .bind(&cold_btc_address)
    .bind(&cold_eth_address)
    .bind(&cold_sol_address)
    .bind(updated_by)
    .execute(pool)
    .await
    .map_err(|e| format!("Failed to update system_treasury_config: {}", e))?;

    let updated = load_system_treasury_config(pool).await;

    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                if let Ok(serialized) = serde_json::to_string(&updated) {
                    let _: redis::RedisResult<()> = redis::cmd("SET")
                        .arg("perennia:treasury:system_config")
                        .arg(serialized)
                        .query_async(&mut conn)
                        .await;
                }
            }
        }
    }

    Ok(updated)
}

pub fn compute_jerusalem_epoch_window(now_secs: u64) -> (u64, u64, u64) {
    let day_secs: u64 = 86_400;
    let bell_offset_secs: u64 = 22 * 3_600;
    let current_day_start = (now_secs / day_secs) * day_secs;
    let today_bell = current_day_start + bell_offset_secs;
    let (epoch_start_ts, next_bell_ts) = if now_secs < today_bell {
        (today_bell.saturating_sub(day_secs), today_bell)
    } else {
        (today_bell, today_bell + day_secs)
    };
    let secs_until_bell = next_bell_ts.saturating_sub(now_secs);
    (epoch_start_ts, next_bell_ts, secs_until_bell)
}

pub async fn execute_full_2200_utc_settlement_bell(pool: &PgPool) -> anyhow::Result<Value> {
    tracing::info!("🔔 [22:00 UTC BELL] Executing Global Epoch Netting & Forge Settlement...");
    let netting_res = execute_epoch_delta_netting_and_lp_compounding(pool).await?;
    let forge_res = execute_2200_utc_forge_bell_settlement(pool).await?;
    Ok(json!({
        "netting": netting_res,
        "forge": forge_res,
        "bellTimestampUtc": Utc::now().to_rfc3339()
    }))
}

pub async fn trigger_immediate_epoch_bell_sweep(pool: &PgPool) -> Result<Value, String> {
    execute_full_2200_utc_settlement_bell(pool)
        .await
        .map_err(|e| format!("Epoch bell sweep failed: {}", e))
}

pub async fn start_chronos_daemon(pool: PgPool) {
    tracing::info!("🕰️ [CHRONOS ENGINE] 22:00 UTC Settlement Bell Scheduler Armed.");
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    let mut last_bell_day: Option<u32> = None;
    loop {
        interval.tick().await;
        let now = Utc::now();
        let ordinal_day = now.format("%j").to_string().parse::<u32>().unwrap_or(0);
        if now.hour() == 22 && now.minute() == 0 && last_bell_day != Some(ordinal_day) {
            last_bell_day = Some(ordinal_day);
            if let Err(e) = execute_full_2200_utc_settlement_bell(&pool).await {
                tracing::error!("❌ [22:00 UTC BELL] Execution error: {}", e);
            }
        }
    }
}