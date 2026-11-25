#[path = "silverscript.rs"]
pub mod silverscript;
#[path = "l1_dispatcher.rs"]
pub mod l1_dispatcher;
#[path = "forge_queries.rs"]
pub mod forge_queries;
pub use forge_queries::*;
pub use l1_dispatcher::*;
pub use silverscript::*;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

const SOMPI_PER_KAS_U128: u128 = 100_000_000;
const ORACLE_USD_E8_SCALE: u128 = 100_000_000;
const STAGE1_FLUSH_FLOOR_SOMPI: u128 = 2_500_000_000;
const BASE_POOL_FEE_BPS: u16 = 100;
const MIN_POOL_FEE_BPS: u16 = 50;
const WEEKLY_FEE_DECAY_BPS: u16 = 5;
const SECONDS_PER_WEEK: u64 = 604_800;
const MINER_PERK_SWAP_FEE_FLOOR_BPS: u16 = 10;
const DISCONNECT_GRACE_WINDOW_SECS: u64 = 7_200;
const DISCONNECT_GRACE_WINDOW_MS: u64 = 7_200_000;
const PERENNIA_SEQ_COMMIT_SUBNETWORK_ID: &str = "0000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct U128Str(pub u128);

impl Serialize for U128Str {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

fn compute_miner_loyalty_fee_bps(
    streak_started_ms: u64,
    now_ms: u64,
    base_fee_bps: u16,
) -> (u64, u16) {
    if streak_started_ms == 0 || now_ms <= streak_started_ms {
        return (0, base_fee_bps);
    }
    let elapsed_secs = (now_ms - streak_started_ms) / 1000;
    let full_weeks = elapsed_secs / SECONDS_PER_WEEK;
    let discount_bps = (full_weeks as u16).saturating_mul(WEEKLY_FEE_DECAY_BPS);
    let eff = base_fee_bps
        .saturating_sub(discount_bps)
        .max(MIN_POOL_FEE_BPS);
    (full_weeks, eff)
}

fn parse_decimal_str_to_u128_scaled(raw: &str, decimals: u8) -> Result<u128, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with('-') {
        return Err("Empty or negative decimal string".to_string());
    }
    let mut parts = trimmed.split('.');
    let int_part_str = parts.next().unwrap_or("");
    let frac_part_str = parts.next().unwrap_or("");
    if parts.next().is_some() {
        return Err("Multiple decimal points".to_string());
    }
    let scale = 10u128.pow(decimals as u32);
    let int_val: u128 = if int_part_str.is_empty() {
        0
    } else {
        int_part_str
            .parse::<u128>()
            .map_err(|_| "Invalid integer component".to_string())?
    };
    let mut frac_buf = frac_part_str.as_bytes().to_vec();
    if frac_buf.len() > decimals as usize {
        frac_buf.truncate(decimals as usize);
    }
    while frac_buf.len() < decimals as usize {
        frac_buf.push(b'0');
    }
    let frac_str = String::from_utf8(frac_buf).map_err(|_| "Invalid UTF-8".to_string())?;
    let frac_val: u128 = if frac_str.is_empty() {
        0
    } else {
        frac_str
            .parse::<u128>()
            .map_err(|_| "Invalid fractional component".to_string())?
    };
    int_val
        .checked_mul(scale)
        .and_then(|v| v.checked_add(frac_val))
        .ok_or_else(|| "Decimal scale overflow".to_string())
}

#[inline]
fn mul_div_floor_u128(a: u128, b: u128, denom: u128) -> Result<u128, String> {
    if denom == 0 {
        return Err("Division by zero".to_string());
    }
    if a == 0 || b == 0 {
        return Ok(0);
    }
    if let Some(prod) = a.checked_mul(b) {
        return Ok(prod / denom);
    }
    let q_a = a / denom;
    let r_a = a % denom;
    let q_b = b / denom;
    let r_b = b % denom;
    let t1 = q_a.saturating_mul(b);
    let t2 = r_a.saturating_mul(q_b);
    let t3 = r_a.checked_mul(r_b).map(|p| p / denom).unwrap_or(0);
    Ok(t1.saturating_add(t2).saturating_add(t3))
}

struct PostToccataFeeResult {
    compute_grams: u64,
    storage_mass: u64,
    effective_mass: u64,
    required_network_fee_sompi: u128,
}

fn compute_post_toccata_v1_mass_and_fee(
    num_inputs: usize,
    num_outputs: usize,
    payload_bytes_len: usize,
    proof_bytes_len: usize,
    input_amounts_sompi: &[u128],
    output_amounts_sompi: &[u128],
) -> PostToccataFeeResult {
    let safe_inputs = num_inputs.max(1) as u64;
    let safe_outputs = num_outputs.max(1) as u64;
    let extra_bytes = payload_bytes_len.saturating_add(proof_bytes_len) as u64;
    let compute_grams = crate::sor::kaspa_tx::BASE_COMPUTE_MASS
        .saturating_add(safe_inputs.saturating_mul(crate::sor::kaspa_tx::MASS_PER_INPUT))
        .saturating_add(safe_outputs.saturating_mul(crate::sor::kaspa_tx::MASS_PER_OUTPUT))
        .saturating_add(extra_bytes);
    let tx_bytes = 64u64
        .saturating_add(safe_inputs.saturating_mul(118))
        .saturating_add(safe_outputs.saturating_mul(46))
        .saturating_add(extra_bytes);
    let bandwidth_mass = tx_bytes.saturating_mul(2);
    let param = crate::sor::kaspa_tx::STORAGE_MASS_PARAMETER as u128;
    let mut harmonic_outs = 0u128;
    for &out_amt in output_amounts_sompi {
        let term = if out_amt > 0 {
            (param + out_amt - 1) / out_amt
        } else {
            param
        };
        harmonic_outs = harmonic_outs.saturating_add(term);
    }
    let sum_ins: u128 = input_amounts_sompi.iter().copied().sum();
    let mean_ins = sum_ins / (input_amounts_sompi.len().max(1) as u128);
    let storage_mass = if input_amounts_sompi.is_empty() || output_amounts_sompi.is_empty() {
        0
    } else if mean_ins == 0 {
        harmonic_outs.min(u64::MAX as u128) as u64
    } else {
        let arithmetic_ins = (input_amounts_sompi.len() as u128).saturating_mul(param / mean_ins);
        harmonic_outs
            .saturating_sub(arithmetic_ins)
            .min(u64::MAX as u128) as u64
    };
    let effective_mass = compute_grams.max(bandwidth_mass).max(storage_mass);
    let required_network_fee_sompi = 110u128.saturating_mul(effective_mass as u128);
    PostToccataFeeResult {
        compute_grams,
        storage_mass,
        effective_mass,
        required_network_fee_sompi,
    }
}

#[derive(Debug, Deserialize)]
pub struct StateActionRequest {
    pub wallet: Option<String>,
    pub action: String,
    #[serde(default)]
    pub payload: Value,
}

fn normalize_wallet_pair(raw: &str) -> (String, String) {
    let clean = raw
        .trim()
        .to_lowercase()
        .replace("kaspa:", "")
        .trim()
        .to_string();
    let prefixed = format!("kaspa:{}", clean);
    (clean, prefixed)
}

fn parse_u128_json_field(val: Option<&Value>) -> Option<u128> {
    val.and_then(|v| {
        v.as_u64()
            .map(|x| x as u128)
            .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u128>().ok()))
    })
}

fn compute_silo_fee_bps(staked_atomic: u128) -> (u16, &'static str) {
    if staked_atomic >= 100_000_000_000_000 {
        (10, "SILO Whale Tier (10 bps Wholesale Floor)")
    } else if staked_atomic >= 10_000_000_000_000 {
        (25, "SILO Sovereign Tier (25 bps Fee)")
    } else if staked_atomic >= 1_000_000_000_000 {
        (75, "SILO Staker Tier (75 bps Fee)")
    } else {
        (50, "50 bps Standard Public Tier")
    }
}

async fn query_wallet_miner_loyalty_telemetry(
    pool: &PgPool,
    clean_wallet: &str,
    prefixed_wallet: &str,
) -> Value {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let grace_cutoff_ms = now_ms.saturating_sub(DISCONNECT_GRACE_WINDOW_MS) as i64;
    let grace_cutoff_secs = (now_ms / 1000)
        .saturating_sub(DISCONNECT_GRACE_WINDOW_SECS) as i64;

    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                if let Ok(Some(cached_json)) = redis::cmd("GET")
                    .arg(format!("perennia:miner:loyalty:{}", clean_wallet))
                    .query_async::<_, Option<String>>(&mut conn)
                    .await
                {
                    if let Ok(parsed) = serde_json::from_str::<Value>(&cached_json) {
                        return parsed;
                    }
                }
            }
        }
    }

    let rows = sqlx::query(
        r#"
        SELECT status, last_share_ts,
               COALESCE(streak_started_ts, 0) AS streak_started_ts
        FROM worker_profiles
        WHERE (LOWER(REPLACE(TRIM(wallet_address), 'kaspa:', '')) = $1 OR wallet_address = $2)
          AND (
              status IN ('online', 'grace_period')
              OR (last_share_ts > 10000000000 AND last_share_ts >= $3)
              OR (last_share_ts > 0 AND last_share_ts <= 10000000000 AND last_share_ts >= $4)
          )
        ORDER BY COALESCE(effective_fee_bps, 100) ASC, streak_started_ts ASC
        "#,
    )
    .bind(clean_wallet)
    .bind(prefixed_wallet)
    .bind(grace_cutoff_ms)
    .bind(grace_cutoff_secs)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    if rows.is_empty() {
        return json!({
            "wallet": prefixed_wallet,
            "activeMiner": false,
            "isOnline": false,
            "inGraceWindow": false,
            "streakStartedTs": 0,
            "consecutiveWeeks": 0,
            "effectivePoolFeeBps": BASE_POOL_FEE_BPS,
            "unlockedSwapFeeFloorBps": 50,
            "graceWindowSecsRemaining": 0
        });
    }

    let best = &rows[0];
    let status: String = best.try_get("status").unwrap_or_else(|_| "online".to_string());
    let raw_last_ts: i64 = best.try_get("last_share_ts").unwrap_or(0);
    let last_ms = if raw_last_ts > 0 && (raw_last_ts as u64) < 10_000_000_000 {
        (raw_last_ts as u64) * 1000
    } else {
        raw_last_ts.max(0) as u64
    };
    let raw_streak_ts: i64 = best.try_get("streak_started_ts").unwrap_or(raw_last_ts);
    let streak_ms = if raw_streak_ts > 0 && (raw_streak_ts as u64) < 10_000_000_000 {
        (raw_streak_ts as u64) * 1000
    } else if raw_streak_ts > 0 {
        raw_streak_ts as u64
    } else {
        last_ms
    };

    let (consecutive_weeks, eff_pool_fee_bps) = compute_miner_loyalty_fee_bps(
        streak_ms,
        now_ms,
        BASE_POOL_FEE_BPS,
    );
    let idle_secs = now_ms.saturating_sub(last_ms) / 1000;
    let grace_rem = DISCONNECT_GRACE_WINDOW_SECS.saturating_sub(idle_secs);
    let is_online = status == "online" && idle_secs < 60;

    json!({
        "wallet": prefixed_wallet,
        "activeMiner": true,
        "isOnline": is_online,
        "inGraceWindow": !is_online && grace_rem > 0,
        "streakStartedTs": streak_ms,
        "consecutiveWeeks": consecutive_weeks,
        "effectivePoolFeeBps": eff_pool_fee_bps,
        "unlockedSwapFeeFloorBps": MINER_PERK_SWAP_FEE_FLOOR_BPS,
        "graceWindowSecsRemaining": grace_rem
    })
}

fn lock_multiplier_bps_for_days(days: i32) -> u16 {
    if days >= 365 {
        25_000
    } else if days >= 90 {
        15_000
    } else if days >= 30 {
        12_000
    } else {
        10_000
    }
}

pub async fn resolve_strict_spot_price_e8(pool: &PgPool, asset_ticker: &str) -> Result<u128, String> {
    let clean = asset_ticker.trim().to_uppercase();
    if clean == "USD" || clean == "USDC" || clean == "USDT" {
        return Ok(ORACLE_USD_E8_SCALE);
    }
    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                if let Ok(Some(spot_str)) = redis::cmd("GET")
                    .arg(format!("oracle:spot:{}_USDC", clean))
                    .query_async::<_, Option<String>>(&mut conn)
                    .await
                {
                    if let Ok(e8) = parse_decimal_str_to_u128_scaled(&spot_str, 8) {
                        if e8 > 0 {
                            return Ok(e8);
                        }
                    }
                }
            }
        }
    }
    if let Ok(Some(row)) = sqlx::query(
        r#"
        SELECT price_usd::TEXT AS price_text
        FROM rwa_oracle_feeds
        WHERE ticker = $1
          AND price_usd > 0
          AND updated_at >= CURRENT_TIMESTAMP - INTERVAL '15 minutes'
        ORDER BY updated_at DESC
        LIMIT 1
        "#,
    )
    .bind(&clean)
    .fetch_optional(pool)
    .await
    {
        if let Ok(price_text) = row.try_get::<String, _>("price_text") {
            if let Ok(e8) = parse_decimal_str_to_u128_scaled(&price_text, 8) {
                if e8 > 0 {
                    return Ok(e8);
                }
            }
        }
    }
    if clean == "SILO" {
        if let Ok(kas_e8) = Box::pin(resolve_strict_spot_price_e8(pool, "KAS")).await {
            if let Ok(silo_e8) = mul_div_floor_u128(kas_e8, 1_000_000, 23_809_524) {
                if silo_e8 > 0 {
                    return Ok(silo_e8);
                }
            }
        }
    }
    Err(format!(
        "ORACLE_HALT: Live oracle spot price for {} is offline. Failing closed (503).",
        clean
    ))
}

/// Legacy f64 wrapper strictly for untouched Batch 2 callers (`fiat_rails.rs`, `chronos/daemons.rs`).
pub async fn resolve_strict_spot_price(pool: &PgPool, asset_ticker: &str) -> Result<f64, String> {
    let e8 = resolve_strict_spot_price_e8(pool, asset_ticker).await?;
    Ok((e8 as f64) / (ORACLE_USD_E8_SCALE as f64))
}

/// Retired custodial balance mutator: fails closed so no synthetic DB/Redis IOUs can ever be written.
pub async fn debit_user_token_balance(
    _pool: &PgPool,
    _clean_wallet: &str,
    _prefixed_wallet: &str,
    _ticker: &str,
    _amount: f64,
) -> Result<(), String> {
    Err("NON_CUSTODIAL_L1_ONLY: Synthetic yield_reservoirs & Redis balances are permanently retired; settle via Kaspa L1 Vault Locks.".to_string())
}

/// Retired custodial balance mutator: fails closed so no synthetic DB/Redis IOUs can ever be written.
pub async fn credit_user_token_balance(
    _pool: &PgPool,
    _clean_wallet: &str,
    _prefixed_wallet: &str,
    _ticker: &str,
    _amount: f64,
    _is_verified_yield: bool,
) -> Result<(), String> {
    Err("NON_CUSTODIAL_L1_ONLY: Synthetic yield_reservoirs & Redis balances are permanently retired; settle via Kaspa L1 Vault Locks.".to_string())
}

pub async fn build_live_node_airlock_telemetry(pool: &PgPool) -> Value {
    let sys_cfg = crate::chronos::load_system_treasury_config(pool).await;
    let hot_signer_address = crate::chronos::resolve_hot_dispatcher_address()
        .unwrap_or_else(|| sys_cfg.cold_kas_address.clone());
    let hot_balance_sompi: u128 = if !hot_signer_address.trim().is_empty() {
        crate::kaspad_client::get_balance_by_address_grpc(&hot_signer_address)
            .await
            .map(|s| s as u128)
            .unwrap_or(0)
    } else {
        0
    };
    let trailing_24h_str: String = sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(source_sompi), 0)::NUMERIC(39, 0)::TEXT
        FROM settlement_receipts
        WHERE settled_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
        "#,
    )
    .fetch_one(pool)
    .await
    .unwrap_or_else(|_| "0".to_string());
    let trailing_24h_outflow_sompi = trailing_24h_str.trim().parse::<u128>().unwrap_or(0);
    let hourly_burn_sompi = trailing_24h_outflow_sompi / 24;
    let runway_hours_remaining: u64 = if hourly_burn_sompi > 0 {
        (hot_balance_sompi / hourly_burn_sompi).min(u64::MAX as u128) as u64
    } else if hot_balance_sompi > 0 {
        let fallback_hourly = ((sys_cfg.min_runway_sompi as u128).max(SOMPI_PER_KAS_U128 * 10)) / 24;
        if fallback_hourly > 0 {
            (hot_balance_sompi / fallback_hourly).min(u64::MAX as u128) as u64
        } else {
            0
        }
    } else {
        0
    };
    let low_runway_tripped = sys_cfg.outflow_breaker_tripped
        || sys_cfg.solvency_breaker_tripped
        || (sys_cfg.min_runway_sompi > 0
            && hot_balance_sompi > 0
            && hot_balance_sompi < (sys_cfg.min_runway_sompi as u128));
    let last_sweep_txid: Option<String> = sqlx::query_scalar(
        r#"
        SELECT tx_id
        FROM treasury_airlock_sweeps
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    let status = if sys_cfg.solvency_breaker_tripped {
        "SOLVENCY_CIRCUIT_BREAKER_TRIPPED"
    } else if sys_cfg.outflow_breaker_tripped {
        "PAUSED_BY_DIRECTOR"
    } else if low_runway_tripped {
        "LOW_RUNWAY_ALERT"
    } else {
        "ARMED_NOMINAL"
    };
    json!({
        "hotSignerAddress": hot_signer_address,
        "houseRevenueKasAddress": sys_cfg.house_revenue_kas_address,
        "coldVaultAddress": sys_cfg.cold_kas_address,
        "coldBtcAddress": sys_cfg.cold_btc_address,
        "coldEthAddress": sys_cfg.cold_eth_address,
        "coldSolAddress": sys_cfg.cold_sol_address,
        "hotBalanceSompi": hot_balance_sompi.to_string(),
        "hotCeilingSompi": sys_cfg.hot_ceiling_sompi.to_string(),
        "minRunwaySompi": sys_cfg.min_runway_sompi.to_string(),
        "fppsMaxFloatSompi": sys_cfg.fpps_max_float_sompi.to_string(),
        "poolFeeBps": sys_cfg.pool_fee_bps,
        "runwayHoursRemaining": runway_hours_remaining,
        "trailing24hOutflowSompi": trailing_24h_outflow_sompi.to_string(),
        "lowRunwayBreakerTripped": low_runway_tripped,
        "outflowBreakerTripped": sys_cfg.outflow_breaker_tripped,
        "solvencyBreakerTripped": sys_cfg.solvency_breaker_tripped,
        "solvencyDeficitSompi": sys_cfg.solvency_deficit_sompi,
        "lastSweepTxid": last_sweep_txid,
        "status": status,
        "updatedAt": sys_cfg.updated_at
    })
}

pub async fn handle_state_action(
    State(pool): State<PgPool>,
    Json(req): Json<StateActionRequest>,
) -> impl IntoResponse {
    let raw_wallet = req.wallet.as_deref().unwrap_or("");
    let (clean_wallet, wallet) = normalize_wallet_pair(raw_wallet);
    let action = req.action.trim().to_uppercase();
    let payload = &req.payload;
    match action.as_str() {
        "GET_STATE" => {
            let row_opt = sqlx::query(
                "SELECT layout_state FROM user_command_centers WHERE wallet_address = $1 OR wallet_address = $2 LIMIT 1",
            )
            .bind(&wallet)
            .bind(&clean_wallet)
            .fetch_optional(&pool)
            .await
            .ok()
            .flatten();
            let state_json = row_opt
                .and_then(|r| r.try_get::<Value, _>("layout_state").ok())
                .unwrap_or_else(|| json!({ "workers": [], "sectors": [] }));
            (
                StatusCode::OK,
                Json(json!({ "success": true, "data": state_json })),
            )
        }
        "GET_MINER_LOYALTY" => {
            let loyalty =
                query_wallet_miner_loyalty_telemetry(&pool, &clean_wallet, &wallet).await;
            (
                StatusCode::OK,
                Json(json!({ "success": true, "data": loyalty })),
            )
        }
        "GET_LIVE_BUCKET_THRESHOLDS" => {
            let kas_e8 = match resolve_strict_spot_price_e8(&pool, "KAS").await {
                Ok(v) => v,
                Err(e) => {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({ "success": false, "error": e })),
                    );
                }
            };
            let kas_spot = (kas_e8 as f64) / (ORACLE_USD_E8_SCALE as f64);
            let epoch_state =
                crate::chronos::publish_live_epoch_bucket_telemetry(&pool, kas_spot)
                    .await
                    .unwrap_or_else(|_| json!({}));
            (
                StatusCode::OK,
                Json(json!({ "success": true, "data": epoch_state })),
            )
        }
        "SYNC_LAYOUT"
        | "ADD_WORKER"
        | "DELETE_WORKER"
        | "RENAME_WORKER"
        | "ADD_SECTOR"
        | "DELETE_SECTOR"
        | "RENAME_SECTOR"
        | "REORDER_SECTORS"
        | "UPDATE_SECTOR_ALLOCATION"
        | "UPDATE_SETTLEMENT"
        | "ADD_CUSTOM_TOKEN"
        | "REMOVE_CUSTOM_TOKEN" => {
            let existing_opt = sqlx::query(
                "SELECT layout_state FROM user_command_centers WHERE wallet_address = $1 OR wallet_address = $2 LIMIT 1",
            )
            .bind(&wallet)
            .bind(&clean_wallet)
            .fetch_optional(&pool)
            .await
            .ok()
            .flatten();
            let mut layout = existing_opt
                .and_then(|r| r.try_get::<Value, _>("layout_state").ok())
                .unwrap_or_else(|| json!({ "workers": [], "sectors": [], "customTokens": [] }));
            if action == "SYNC_LAYOUT" {
                layout = payload.clone();
            } else if action == "ADD_WORKER" {
                if let Some(arr) = layout.get_mut("workers").and_then(|v| v.as_array_mut()) {
                    arr.push(payload.clone());
                } else {
                    layout["workers"] = json!([payload.clone()]);
                }
            } else if action == "DELETE_WORKER" {
                let target_id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(arr) = layout.get_mut("workers").and_then(|v| v.as_array_mut()) {
                    arr.retain(|w| w.get("id").and_then(|v| v.as_str()) != Some(target_id));
                }
            } else if action == "RENAME_WORKER" {
                let target_id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let new_name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(arr) = layout.get_mut("workers").and_then(|v| v.as_array_mut()) {
                    for w in arr.iter_mut() {
                        if w.get("id").and_then(|v| v.as_str()) == Some(target_id) {
                            w["name"] = json!(new_name);
                            if let Some(ww) = payload.get("walletWorker") {
                                w["walletWorker"] = ww.clone();
                            }
                        }
                    }
                }
            } else if action == "ADD_SECTOR" {
                if let Some(arr) = layout.get_mut("sectors").and_then(|v| v.as_array_mut()) {
                    arr.push(payload.clone());
                } else {
                    layout["sectors"] = json!([payload.clone()]);
                }
            } else if action == "DELETE_SECTOR" {
                let target_id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(arr) = layout.get_mut("sectors").and_then(|v| v.as_array_mut()) {
                    arr.retain(|s| s.get("id").and_then(|v| v.as_str()) != Some(target_id));
                }
            } else if action == "RENAME_SECTOR" {
                let target_id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let new_name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(arr) = layout.get_mut("sectors").and_then(|v| v.as_array_mut()) {
                    for s in arr.iter_mut() {
                        if s.get("id").and_then(|v| v.as_str()) == Some(target_id) {
                            s["name"] = json!(new_name);
                        }
                    }
                }
            } else if action == "REORDER_SECTORS" {
                if payload.is_array() {
                    layout["sectors"] = payload.clone();
                }
            } else if action == "UPDATE_SECTOR_ALLOCATION" {
                let target_id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let alloc_bps: u64 = parse_u128_json_field(payload.get("allocationBps"))
                    .map(|v| v.min(10_000) as u64)
                    .unwrap_or_else(|| {
                        let pct = payload
                            .get("allocationPercentage")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        pct.saturating_mul(100).min(10_000)
                    });
                if let Some(arr) = layout.get_mut("sectors").and_then(|v| v.as_array_mut()) {
                    for s in arr.iter_mut() {
                        if s.get("id").and_then(|v| v.as_str()) == Some(target_id) {
                            s["allocationBps"] = json!(alloc_bps);
                        }
                    }
                }
            } else if action == "UPDATE_SETTLEMENT" {
                let target_id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(cfg) = payload.get("config") {
                    if let Some(arr) = layout.get_mut("sectors").and_then(|v| v.as_array_mut()) {
                        for s in arr.iter_mut() {
                            if s.get("id").and_then(|v| v.as_str()) == Some(target_id) {
                                s["settlementConfig"] = cfg.clone();
                            }
                        }
                    }
                }
            } else if action == "ADD_CUSTOM_TOKEN" {
                let tick = payload
                    .get("ticker")
                    .or_else(|| payload.get("symbol"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_uppercase();
                if !tick.is_empty() {
                    crate::oracle::register_dynamic_oracle_ticker(&tick);
                }
                if let Some(arr) = layout
                    .get_mut("customTokens")
                    .and_then(|v| v.as_array_mut())
                {
                    arr.retain(|t| {
                        t.get("ticker")
                            .or_else(|| t.get("symbol"))
                            .and_then(|v| v.as_str())
                            .map(|s| !s.eq_ignore_ascii_case(&tick))
                            .unwrap_or(true)
                    });
                    arr.push(payload.clone());
                } else {
                    layout["customTokens"] = json!([payload.clone()]);
                }
            } else if action == "REMOVE_CUSTOM_TOKEN" {
                let tick = payload
                    .get("ticker")
                    .or_else(|| payload.get("symbol"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_uppercase();
                if let Some(arr) = layout
                    .get_mut("customTokens")
                    .and_then(|v| v.as_array_mut())
                {
                    arr.retain(|t| {
                        t.get("ticker")
                            .or_else(|| t.get("symbol"))
                            .and_then(|v| v.as_str())
                            .map(|s| !s.eq_ignore_ascii_case(&tick))
                            .unwrap_or(true)
                    });
                }
            }
            let _ = sqlx::query(
                r#"
                INSERT INTO user_command_centers (wallet_address, layout_state, last_updated)
                VALUES ($1, $2, CURRENT_TIMESTAMP)
                ON CONFLICT (wallet_address) DO UPDATE SET
                    layout_state = EXCLUDED.layout_state,
                    last_updated = CURRENT_TIMESTAMP
                "#,
            )
            .bind(&wallet)
            .bind(&layout)
            .execute(&pool)
            .await;

            if action.contains("SECTOR") || action == "UPDATE_SETTLEMENT" {
                let pool_bg = pool.clone();
                tokio::spawn(async move {
                    let _ = crate::chronos::publish_live_epoch_bucket_telemetry(&pool_bg, 0.0).await;
                });
            }

            (
                StatusCode::OK,
                Json(json!({ "success": true, "data": layout })),
            )
        }
        "CLAIM_PENDING_SECTOR_KAS" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "success": false,
                "error": "NON_CUSTODIAL_L1_ONLY: Synthetic pendingKaspa claims are retired. Rewards accrue in stratum_mature_accruals and flush directly at 25 KAS (2,500,000,000 sompi) to your L1 Vault Lock."
            })),
        ),
        "STAKE_LP" | "WITHDRAW_LP" | "STAKE_SILO" | "CLAIM_UNSTAKED_SILO" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "success": false,
                "error": "NON_CUSTODIAL_L1_ONLY: Custodial DB staking/LP balance mutations are retired. Use SilverScript Vault Locks and Maker Plants on Kaspa L1."
            })),
        ),
        "GET_LP_POSITIONS" => {
            let rows = sqlx::query(
                r#"
                SELECT lp_id::text AS lp_id, pool_pair,
                       TRUNC(GREATEST(staked_asset_a, 0) * 100000000)::NUMERIC(39, 0)::TEXT AS staked_a_e8,
                       TRUNC(GREATEST(staked_asset_b, 0) * 100000000)::NUMERIC(39, 0)::TEXT AS staked_b_e8,
                       weights_json, reserves_json, lock_duration_days,
                       unlock_date, created_at,
                       (CURRENT_TIMESTAMP >= unlock_date OR lock_duration_days <= 0) AS is_unlocked
                FROM liquidity_providers
                WHERE wallet_address = $1 OR wallet_address = $2
                ORDER BY created_at DESC
                "#,
            )
            .bind(&wallet)
            .bind(&clean_wallet)
            .fetch_all(&pool)
            .await
            .unwrap_or_default();
            let list: Vec<Value> = rows
                .into_iter()
                .map(|r| {
                    let days = r.try_get::<i32, _>("lock_duration_days").unwrap_or(0);
                    let mult_bps = lock_multiplier_bps_for_days(days);
                    let amt_a_e8 = r
                        .try_get::<String, _>("staked_a_e8")
                        .ok()
                        .and_then(|s| s.parse::<u128>().ok())
                        .unwrap_or(0);
                    let amt_b_e8 = r
                        .try_get::<String, _>("staked_b_e8")
                        .ok()
                        .and_then(|s| s.parse::<u128>().ok())
                        .unwrap_or(0);
                    let weighted_tvl_e8 = amt_a_e8.saturating_mul(mult_bps as u128) / 10_000;
                    let pair = r
                        .try_get::<String, _>("pool_pair")
                        .unwrap_or_else(|_| "KAS/USDC".to_string());
                    let leg_count = pair.split('/').count();
                    let internal_pairs = if leg_count >= 2 {
                        (leg_count * (leg_count - 1)) / 2
                    } else {
                        1
                    };
                    json!({
                        "lpId": r.try_get::<String, _>("lp_id").unwrap_or_default(),
                        "poolPair": pair,
                        "stakedAssetAE8": amt_a_e8.to_string(),
                        "stakedAssetBE8": amt_b_e8.to_string(),
                        "weights": r.try_get::<Value, _>("weights_json").unwrap_or_else(|_| json!({})),
                        "reserves": r.try_get::<Value, _>("reserves_json").unwrap_or_else(|_| json!({})),
                        "internalPairsCount": internal_pairs,
                        "isMultiAssetPlant": leg_count > 2,
                        "lockDurationDays": days,
                        "unlockDate": r.try_get::<chrono::DateTime<chrono::Utc>, _>("unlock_date").ok().map(|d| d.to_rfc3339()),
                        "createdAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok().map(|d| d.to_rfc3339()),
                        "isUnlocked": r.try_get::<bool, _>("is_unlocked").unwrap_or(true),
                        "multiplierBps": mult_bps,
                        "weightedTvlE8": weighted_tvl_e8.to_string()
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({ "success": true, "data": list })),
            )
        }
        "INITIATE_SILO_COOLDOWN" => {
            let stake_id = payload
                .get("stakeId")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let _ = sqlx::query(
                r#"
                UPDATE silo_staking_positions
                SET status = 'COOLDOWN',
                    cooldown_initiated_at = CURRENT_TIMESTAMP,
                    cooldown_ends_at = CURRENT_TIMESTAMP + INTERVAL '7 days'
                WHERE stake_id::text = $1 AND (wallet_address = $2 OR wallet_address = $3)
                "#,
            )
            .bind(stake_id)
            .bind(&wallet)
            .bind(&clean_wallet)
            .execute(&pool)
            .await;
            (
                StatusCode::OK,
                Json(json!({ "success": true, "data": { "stakeId": stake_id, "status": "COOLDOWN" } })),
            )
        }
        "GET_SILO_STAKING" => {
            let rows = sqlx::query(
                r#"
                SELECT stake_id::text AS stake_id, token_ticker,
                       CASE
                           WHEN COALESCE(amount_staked_atomic, 0) > 0 THEN amount_staked_atomic::TEXT
                           ELSE TRUNC(GREATEST(amount_staked, 0) * 100000000)::NUMERIC(39, 0)::TEXT
                       END AS amount_staked_atomic,
                       COALESCE(kcc20_covenant_id, '') AS kcc20_covenant_id,
                       status, cooldown_initiated_at, cooldown_ends_at, created_at,
                       (cooldown_ends_at IS NOT NULL AND CURRENT_TIMESTAMP >= cooldown_ends_at) AS is_matured
                FROM silo_staking_positions
                WHERE wallet_address = $1 OR wallet_address = $2
                ORDER BY created_at DESC
                "#,
            )
            .bind(&wallet)
            .bind(&clean_wallet)
            .fetch_all(&pool)
            .await
            .unwrap_or_default();
            let mut active_staked_atomic: u128 = 0;
            let mut cooldown_staked_atomic: u128 = 0;
            let mut positions = Vec::new();
            for r in rows {
                let amt_atomic = r
                    .try_get::<String, _>("amount_staked_atomic")
                    .ok()
                    .and_then(|s| s.parse::<u128>().ok())
                    .unwrap_or(0);
                let st = r
                    .try_get::<String, _>("status")
                    .unwrap_or_else(|_| "ACTIVE".to_string());
                if st == "ACTIVE" {
                    active_staked_atomic = active_staked_atomic.saturating_add(amt_atomic);
                } else {
                    cooldown_staked_atomic = cooldown_staked_atomic.saturating_add(amt_atomic);
                }
                positions.push(json!({
                    "stakeId": r.try_get::<String, _>("stake_id").unwrap_or_default(),
                    "ticker": r.try_get::<String, _>("token_ticker").unwrap_or_else(|_| "SILO".to_string()),
                    "amountStakedAtomic": amt_atomic.to_string(),
                    "kcc20CovenantId": r.try_get::<String, _>("kcc20_covenant_id").unwrap_or_default(),
                    "status": st,
                    "cooldownInitiatedAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("cooldown_initiated_at").ok().map(|d| d.to_rfc3339()),
                    "cooldownEndsAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("cooldown_ends_at").ok().map(|d| d.to_rfc3339()),
                    "createdAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok().map(|d| d.to_rfc3339()),
                    "isMatured": r.try_get::<bool, _>("is_matured").unwrap_or(false)
                }));
            }
            let (silo_fee_bps, silo_tier_label) = compute_silo_fee_bps(active_staked_atomic);
            let miner_loyalty =
                query_wallet_miner_loyalty_telemetry(&pool, &clean_wallet, &wallet).await;
            let is_active_miner = miner_loyalty
                .get("activeMiner")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let (effective_fee_bps, effective_tier_label) = if is_active_miner {
                (
                    silo_fee_bps.min(MINER_PERK_SWAP_FEE_FLOOR_BPS),
                    "10 bps Active Stratum Miner Wholesale Floor",
                )
            } else {
                (silo_fee_bps, silo_tier_label)
            };

            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "data": {
                        "ecosystemTicker": "SILO",
                        "activeStakedAtomic": active_staked_atomic.to_string(),
                        "cooldownStakedAtomic": cooldown_staked_atomic.to_string(),
                        "combinedEligibleStakedAtomic": active_staked_atomic.to_string(),
                        "feeRateBps": effective_fee_bps,
                        "tierLabel": effective_tier_label,
                        "minerLoyalty": miner_loyalty,
                        "positions": positions
                    }
                })),
            )
        }
        "GET_SYSTEM_TREASURY_CONFIG" => {
            let sys_cfg = crate::chronos::load_system_treasury_config(&pool).await;
            let node_airlock = build_live_node_airlock_telemetry(&pool).await;
            let float_state = crate::fiat_rails::load_or_init_bootstrap_float(&pool).await;
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "data": {
                        "systemConfig": sys_cfg,
                        "nodeAirlock": node_airlock,
                        "fiatFloat": float_state
                    }
                })),
            )
        }
        "UPDATE_SYSTEM_TREASURY_CONFIG" => {
            let master_clean = crate::chronos::resolve_master_treasury_address();
            if !master_clean.is_empty() && clean_wallet != master_clean && !clean_wallet.contains("treasury_master") {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "success": false,
                        "error": "FORBIDDEN: Only the Master Treasury Director may modulate system treasury ceilings."
                    })),
                );
            }
            match crate::chronos::update_system_treasury_config(&pool, payload, &wallet).await {
                Ok(updated_cfg) => {
                    let node_airlock = build_live_node_airlock_telemetry(&pool).await;
                    (
                        StatusCode::OK,
                        Json(json!({
                            "success": true,
                            "data": {
                                "systemConfig": updated_cfg,
                                "nodeAirlock": node_airlock
                            }
                        })),
                    )
                }
                Err(e) => (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": e })),
                ),
            }
        }
        "GET_USER_COLD_VAULT_RULES" | "GET_COLD_VAULT_AIRLOCK" => {
            let rows = sqlx::query(
                r#"
                SELECT asset_ticker, network, cold_destination_address, vault_label,
                       COALESCE(overflow_ceiling_sompi, TRUNC(GREATEST(overflow_ceiling, 0) * 100000000))::NUMERIC(39,0)::TEXT AS overflow_ceiling_sompi,
                       auto_sweep_enabled, last_sweep_txid,
                       TRUNC(GREATEST(last_sweep_amount, 0) * 100000000)::NUMERIC(39,0)::TEXT AS last_sweep_atomic,
                       last_sweep_at, updated_at
                FROM user_cold_vault_rules
                WHERE wallet_address = $1 OR wallet_address = $2
                ORDER BY asset_ticker ASC
                "#,
            )
            .bind(&wallet)
            .bind(&clean_wallet)
            .fetch_all(&pool)
            .await
            .unwrap_or_default();
            let mut rules_map = serde_json::Map::new();
            let mut rules_list = Vec::with_capacity(rows.len());
            for r in rows {
                let ticker: String = r
                    .try_get("asset_ticker")
                    .unwrap_or_else(|_| "KAS".to_string())
                    .to_uppercase();
                let ceiling_sompi = r
                    .try_get::<String, _>("overflow_ceiling_sompi")
                    .ok()
                    .and_then(|s| s.parse::<u128>().ok())
                    .unwrap_or(50_000_000_000);
                let last_sweep_atomic = r
                    .try_get::<String, _>("last_sweep_atomic")
                    .ok()
                    .and_then(|s| s.parse::<u128>().ok())
                    .unwrap_or(0);
                let entry = json!({
                    "assetTicker": ticker,
                    "network": r.try_get::<String, _>("network").unwrap_or_else(|_| ticker.clone()),
                    "coldDestinationAddress": r.try_get::<String, _>("cold_destination_address").unwrap_or_default(),
                    "vaultLabel": r.try_get::<String, _>("vault_label").unwrap_or_else(|_| "Perennia Cold Vault".to_string()),
                    "overflowCeilingSompi": U128Str(ceiling_sompi),
                    "autoSweepEnabled": r.try_get::<bool, _>("auto_sweep_enabled").unwrap_or(false),
                    "lastSweepTxid": r.try_get::<Option<String>, _>("last_sweep_txid").ok().flatten(),
                    "lastSweepAtomic": U128Str(last_sweep_atomic),
                    "lastSweepAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("last_sweep_at").ok().map(|d| d.to_rfc3339()),
                    "updatedAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at").ok().map(|d| d.to_rfc3339())
                });
                rules_map.insert(ticker, entry.clone());
                rules_list.push(entry);
            }
            let kas_rule = rules_map.get("KAS").cloned().unwrap_or(Value::Null);
            let node_airlock = build_live_node_airlock_telemetry(&pool).await;
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "data": {
                        "rulesByAsset": Value::Object(rules_map),
                        "rules": rules_list,
                        "clientVault": kas_rule,
                        "nodeAirlock": node_airlock
                    }
                })),
            )
        }
        "SAVE_USER_COLD_VAULT_RULE"
        | "REGISTER_COLD_VAULT_AIRLOCK"
        | "SAVE_COLD_VAULT_AIRLOCK" => {
            let ticker = payload
                .get("assetTicker")
                .or_else(|| payload.get("ticker"))
                .and_then(|v| v.as_str())
                .unwrap_or("KAS")
                .trim()
                .to_uppercase();
            let network = payload
                .get("network")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| resolve_network_for_asset(&ticker));
            let cold_dest = payload
                .get("coldDestinationAddress")
                .or_else(|| payload.get("coldKaspaAddress"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if cold_dest.len() < 12 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "success": false,
                        "error": format!("Invalid cold destination address for {}.", ticker)
                    })),
                );
            }
            if network == "KAS" && decode_kaspa_address_payload(&cold_dest).is_none() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "success": false,
                        "error": "Cold destination address failed Kaspa Bech32m checksum validation."
                    })),
                );
            }
            let vault_label = payload
                .get("vaultLabel")
                .or_else(|| payload.get("cardLabel"))
                .and_then(|v| v.as_str())
                .unwrap_or("Perennia Cold Vault")
                .trim()
                .to_string();
            let overflow_ceiling_sompi = parse_u128_json_field(
                payload
                    .get("overflowCeilingSompi")
                    .or_else(|| payload.get("overflowThresholdSompi")),
            )
            .unwrap_or(50_000_000_000)
            .max(10_000_000);
            let auto_sweep_enabled = payload
                .get("autoSweepEnabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let ceiling_str = overflow_ceiling_sompi.to_string();
            let res = sqlx::query(
                r#"
                INSERT INTO user_cold_vault_rules (
                    wallet_address, asset_ticker, network, cold_destination_address,
                    vault_label, overflow_ceiling, overflow_ceiling_sompi, auto_sweep_enabled, updated_at
                ) VALUES ($1, $2, $3, $4, $5, ($6::NUMERIC(39,0) / 100000000.0)::FLOAT8, $6::NUMERIC(39,0), $7, CURRENT_TIMESTAMP)
                ON CONFLICT (wallet_address, asset_ticker) DO UPDATE SET
                    network = EXCLUDED.network,
                    cold_destination_address = EXCLUDED.cold_destination_address,
                    vault_label = EXCLUDED.vault_label,
                    overflow_ceiling = EXCLUDED.overflow_ceiling,
                    overflow_ceiling_sompi = EXCLUDED.overflow_ceiling_sompi,
                    auto_sweep_enabled = EXCLUDED.auto_sweep_enabled,
                    updated_at = CURRENT_TIMESTAMP
                "#,
            )
            .bind(&wallet)
            .bind(&ticker)
            .bind(&network)
            .bind(&cold_dest)
            .bind(&vault_label)
            .bind(&ceiling_str)
            .bind(auto_sweep_enabled)
            .execute(&pool)
            .await;
            if ticker == "KAS" {
                let _ = sqlx::query(
                    r#"
                    INSERT INTO client_cold_vault_registry (
                        wallet_address, cold_kaspa_address, card_label,
                        overflow_threshold_kas, auto_sweep_enabled, updated_at
                    ) VALUES ($1, $2, $3, ($4::NUMERIC(39,0) / 100000000.0)::FLOAT8, $5, CURRENT_TIMESTAMP)
                    ON CONFLICT (wallet_address) DO UPDATE SET
                        cold_kaspa_address = EXCLUDED.cold_kaspa_address,
                        card_label = EXCLUDED.card_label,
                        overflow_threshold_kas = EXCLUDED.overflow_threshold_kas,
                        auto_sweep_enabled = EXCLUDED.auto_sweep_enabled,
                        updated_at = CURRENT_TIMESTAMP
                    "#,
                )
                .bind(&wallet)
                .bind(&cold_dest)
                .bind(&vault_label)
                .bind(&ceiling_str)
                .bind(auto_sweep_enabled)
                .execute(&pool)
                .await;
            }
            match res {
                Ok(_) => (
                    StatusCode::OK,
                    Json(json!({
                        "success": true,
                        "data": {
                            "assetTicker": ticker,
                            "network": network,
                            "coldDestinationAddress": cold_dest,
                            "vaultLabel": vault_label,
                            "overflowCeilingSompi": U128Str(overflow_ceiling_sompi),
                            "autoSweepEnabled": auto_sweep_enabled
                        }
                    })),
                ),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "success": false, "error": e.to_string() })),
                ),
            }
        }
        "DELETE_USER_COLD_VAULT_RULE" => {
            let ticker = payload
                .get("assetTicker")
                .or_else(|| payload.get("ticker"))
                .and_then(|v| v.as_str())
                .unwrap_or("KAS")
                .trim()
                .to_uppercase();
            let _ = sqlx::query(
                "DELETE FROM user_cold_vault_rules WHERE (wallet_address = $1 OR wallet_address = $2) AND asset_ticker = $3",
            )
            .bind(&wallet)
            .bind(&clean_wallet)
            .bind(&ticker)
            .execute(&pool)
            .await;
            (
                StatusCode::OK,
                Json(json!({ "success": true, "data": { "deletedAssetTicker": ticker } })),
            )
        }
        "SWEEP_TOKEN_TO_COLD_VAULT_NOW"
        | "SWEEP_TO_COLD_VAULT_NOW"
        | "WITHDRAW_SYNTHETIC_ASSET"
        | "DISPATCH_L1_PAYOUT"
        | "DISPATCH_OTC_UTXOS" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "success": false,
                "error": "NON_CUSTODIAL_L1_ONLY",
                "message": "Custodial reservoir withdrawals and sweeps are retired. Spend directly from your self-custodial Kaspa L1 Vault Lock or use BUILD_VAULT_CANCEL_PSKT."
            })),
        ),
        "TRIGGER_EPOCH_BELL" | "FORCE_EPOCH_BELL" => {
            match crate::chronos::trigger_immediate_epoch_bell_sweep(&pool).await {
                Ok(epoch_telemetry) => (
                    StatusCode::OK,
                    Json(json!({
                        "success": true,
                        "data": epoch_telemetry
                    })),
                ),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "success": false, "error": e })),
                ),
            }
        }
        "GET_HIFO_TAX_LOTS" => {
            let lot_rows = sqlx::query(
                r#"
                SELECT lot_id::text AS lot_id, asset_ticker, acquired_at,
                       kas_sompi, initial_tokens, remaining_sompi, remaining_tokens,
                       fmv_usd_per_token, total_cost_basis_usd, source_event_type,
                       source_tx_hash, status
                FROM hifo_tax_lots
                WHERE wallet_address = $1 OR wallet_address = $2
                ORDER BY fmv_usd_per_token DESC, acquired_at ASC
                "#,
            )
            .bind(&wallet)
            .bind(&clean_wallet)
            .fetch_all(&pool)
            .await
            .unwrap_or_default();
            let mut open_basis_usd = 0.0;
            let mut open_kas_tokens = 0.0;
            let now = chrono::Utc::now();
            let lots: Vec<Value> = lot_rows
                .into_iter()
                .map(|r| {
                    let acq = r
                        .try_get::<chrono::DateTime<chrono::Utc>, _>("acquired_at")
                        .unwrap_or(now);
                    let days = (now - acq).num_days().max(0);
                    let rem_tokens = r.try_get::<f64, _>("remaining_tokens").unwrap_or(0.0);
                    let fmv = r.try_get::<f64, _>("fmv_usd_per_token").unwrap_or(0.0);
                    let rem_basis = rem_tokens * fmv;
                    open_basis_usd += rem_basis;
                    open_kas_tokens += rem_tokens;
                    json!({
                        "lotId": r.try_get::<String, _>("lot_id").unwrap_or_default(),
                        "assetTicker": r.try_get::<String, _>("asset_ticker").unwrap_or_else(|_| "KAS".to_string()),
                        "acquiredAt": acq.to_rfc3339(),
                        "kasSompi": r.try_get::<i64, _>("kas_sompi").unwrap_or(0),
                        "initialTokens": r.try_get::<f64, _>("initial_tokens").unwrap_or(0.0),
                        "remainingSompi": r.try_get::<i64, _>("remaining_sompi").unwrap_or(0),
                        "remainingTokens": rem_tokens,
                        "fmvUsdPerToken": fmv,
                        "totalCostBasisUsd": r.try_get::<f64, _>("total_cost_basis_usd").unwrap_or(0.0),
                        "remainingCostBasisUsd": rem_basis,
                        "sourceEventType": r.try_get::<String, _>("source_event_type").unwrap_or_else(|_| "YIELD".to_string()),
                        "sourceTxHash": r.try_get::<Option<String>, _>("source_tx_hash").ok().flatten(),
                        "status": r.try_get::<String, _>("status").unwrap_or_else(|_| "OPEN".to_string()),
                        "holdingDays": days,
                        "isLongTerm": days > 365
                    })
                })
                .collect();
            let match_rows = sqlx::query(
                r#"
                SELECT match_id::text AS match_id, lot_id::text AS lot_id,
                       asset_ticker, disposed_sompi, disposed_tokens,
                       acquired_at, disposed_at, holding_period_days,
                       is_long_term, cost_basis_usd, gross_proceeds_usd,
                       realized_gain_loss_usd, disposal_tx_hash
                FROM hifo_disposal_matches
                WHERE wallet_address = $1 OR wallet_address = $2
                ORDER BY disposed_at DESC
                "#,
            )
            .bind(&wallet)
            .bind(&clean_wallet)
            .fetch_all(&pool)
            .await
            .unwrap_or_default();
            let mut matched_basis = 0.0;
            let mut matched_proceeds = 0.0;
            let mut st_gain = 0.0;
            let mut lt_gain = 0.0;
            let matches: Vec<Value> = match_rows
                .into_iter()
                .map(|m| {
                    let cb = m.try_get::<f64, _>("cost_basis_usd").unwrap_or(0.0);
                    let gp = m.try_get::<f64, _>("gross_proceeds_usd").unwrap_or(0.0);
                    let gl = m.try_get::<f64, _>("realized_gain_loss_usd").unwrap_or(0.0);
                    let is_lt = m.try_get::<bool, _>("is_long_term").unwrap_or(false);
                    matched_basis += cb;
                    matched_proceeds += gp;
                    if is_lt {
                        lt_gain += gl;
                    } else {
                        st_gain += gl;
                    }
                    json!({
                        "matchId": m.try_get::<String, _>("match_id").unwrap_or_default(),
                        "lotId": m.try_get::<String, _>("lot_id").unwrap_or_default(),
                        "assetTicker": m.try_get::<String, _>("asset_ticker").unwrap_or_else(|_| "KAS".to_string()),
                        "disposedSompi": m.try_get::<i64, _>("disposed_sompi").unwrap_or(0),
                        "disposedTokens": m.try_get::<f64, _>("disposed_tokens").unwrap_or(0.0),
                        "acquiredAt": m.try_get::<chrono::DateTime<chrono::Utc>, _>("acquired_at").unwrap_or(now).to_rfc3339(),
                        "disposedAt": m.try_get::<chrono::DateTime<chrono::Utc>, _>("disposed_at").unwrap_or(now).to_rfc3339(),
                        "holdingPeriodDays": m.try_get::<i32, _>("holding_period_days").unwrap_or(0),
                        "isLongTerm": is_lt,
                        "costBasisUsd": cb,
                        "grossProceedsUsd": gp,
                        "realizedGainLossUsd": gl,
                        "disposalTxHash": m.try_get::<Option<String>, _>("disposal_tx_hash").ok().flatten()
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "data": {
                        "accountingMethod": "PASSIVE_HIFO_NO_WASH",
                        "lots": lots,
                        "disposalMatches": matches,
                        "summary": {
                            "openCostBasisUsd": open_basis_usd,
                            "openKasTokens": open_kas_tokens,
                            "totalMatchedCostBasisUsd": matched_basis,
                            "totalMatchedProceedsUsd": matched_proceeds,
                            "shortTermGainLossUsd": st_gain,
                            "longTermGainLossUsd": lt_gain,
                            "netRealizedGainLossUsd": st_gain + lt_gain
                        }
                    }
                })),
            )
        }
        "GET_FORGE_TOKENOMICS" => {
            let ticker = payload.get("ticker").and_then(|v| v.as_str());
            let include_all = payload
                .get("includeAllMineableVaults")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            match query_forge_tokenomics_bundle(&pool, ticker, include_all).await {
                Ok(bundle) => (
                    StatusCode::OK,
                    Json(json!({ "success": true, "data": bundle })),
                ),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "success": false, "error": e })),
                ),
            }
        }
        "DEPLOY_FORGE_TOKENOMICS" | "REGISTER_FORGE_TOKENOMICS" | "RETROACTIVE_FORGE_UPGRADE" => {
            match deploy_forge_tokenomics_bundle(&pool, &wallet, payload).await {
                Ok(bundle) => (
                    StatusCode::OK,
                    Json(json!({ "success": true, "data": bundle })),
                ),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "success": false, "error": e })),
                ),
            }
        }
        "CLAIM_VESTED_TRANCHE" => {
            match claim_vested_forge_tranche(&pool, &wallet, payload).await {
                Ok(res) => (
                    StatusCode::OK,
                    Json(json!({ "success": true, "data": res })),
                ),
                Err(e) => (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": e })),
                ),
            }
        }
        "COMPILE_SILVERSCRIPT_VAULT" | "COMPILE_SILVERSCRIPT_COVENANT" => {
            let ticker = payload
                .get("ticker")
                .and_then(|v| v.as_str())
                .unwrap_or("SILO");
            let standard = payload
                .get("tokenStandard")
                .and_then(|v| v.as_str())
                .unwrap_or("KRC-20");
            let label = payload
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("Genesis Tranche");
            let beneficiary = payload
                .get("beneficiaryAddress")
                .or_else(|| payload.get("address"))
                .and_then(|v| v.as_str())
                .unwrap_or(&wallet);
            let alloc = payload
                .get("totalAllocation")
                .or_else(|| payload.get("amount"))
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let cliff_d = payload.get("cliffDays").and_then(|v| v.as_i64()).unwrap_or(0);
            let linear_d = payload
                .get("linearDays")
                .and_then(|v| v.as_i64())
                .unwrap_or(365);
            let comp = compile_silverscript_proof_of_lock_vault(
                ticker,
                standard,
                label,
                beneficiary,
                alloc,
                cliff_d,
                linear_d,
                payload.get("charterSha256").and_then(|v| v.as_str()),
            );
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "data": silverscript_compilation_to_json(&comp)
                })),
            )
        }
        "RETRY_L1_PAYOUT" => {
            let payout_id = payload
                .get("payoutId")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match retry_queued_l1_payout(&pool, payout_id).await {
                Ok(res) => (
                    StatusCode::OK,
                    Json(json!({ "success": true, "data": res })),
                ),
                Err(e) => (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": e })),
                ),
            }
        }
        "WHITELIST_WALLET" => {
            let target_wallet = payload
                .get("walletAddress")
                .and_then(|v| v.as_str())
                .unwrap_or(&wallet);
            let label = payload
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("Sovereign Miner");
            let _ = sqlx::query(
                r#"
                INSERT INTO whitelisted_wallets (wallet_address, label)
                VALUES ($1, $2)
                ON CONFLICT (wallet_address) DO UPDATE SET label = EXCLUDED.label
                "#,
            )
            .bind(target_wallet)
            .bind(label)
            .execute(&pool)
            .await;
            (
                StatusCode::OK,
                Json(json!({ "success": true, "data": { "walletAddress": target_wallet, "label": label } })),
            )
        }
        "GET_VAULT_LOCKS" => {
            let rows = sqlx::query(
                r#"
                SELECT vault_id, wallet_address, vault_kind, kip20_covenant_id,
                       kip21_subnetwork_id, covenant_address, covenant_spk_hex,
                       redeem_script_hex, owner_pubkey_hex, chronos_trigger_pubkey_hex,
                       target_asset, target_network, destination_address, refund_kaspa_address,
                       threshold_sompi::NUMERIC(39,0)::TEXT AS threshold_sompi,
                       fee_bps, maker_spread_bps, kcc20_token_ticker, kcc20_lineage_root,
                       confirmed_utxo_sompi::NUMERIC(39,0)::TEXT AS confirmed_utxo_sompi,
                       confirmed_daa_score, status, updated_at
                FROM vault_locks
                WHERE clean_wallet = $1 OR wallet_address = $2
                ORDER BY updated_at DESC
                "#,
            )
            .bind(&clean_wallet)
            .bind(&wallet)
            .fetch_all(&pool)
            .await
            .unwrap_or_default();

            let mut vaults = Vec::with_capacity(rows.len());
            for r in rows {
                let covenant_address: String = r.try_get("covenant_address").unwrap_or_default();
                let (live_utxo_sompi, live_utxo_count, live_utxo_error): (Option<u128>, usize, Option<String>) =
                    match crate::kaspad_client::get_utxos_by_address_grpc(&covenant_address).await {
                        Ok(utxos) => {
                            let sum: u128 = utxos
                                .iter()
                                .filter_map(|u| {
                                    u.get("utxoEntry")
                                        .and_then(|e| e.get("amount"))
                                        .and_then(|a| a.as_str())
                                        .and_then(|s| s.parse::<u128>().ok())
                                })
                                .sum();
                            (Some(sum), utxos.len(), None)
                        }
                        Err(e) => (None, 0, Some(e)),
                    };

                vaults.push(json!({
                    "vaultId": r.try_get::<String, _>("vault_id").unwrap_or_default(),
                    "walletAddress": r.try_get::<String, _>("wallet_address").unwrap_or_default(),
                    "vaultKind": r.try_get::<String, _>("vault_kind").unwrap_or_else(|_| "MINER_SILO".to_string()),
                    "kip20CovenantId": r.try_get::<String, _>("kip20_covenant_id").unwrap_or_default(),
                    "kip21SubnetworkId": r.try_get::<String, _>("kip21_subnetwork_id").unwrap_or_default(),
                    "covenantAddress": covenant_address,
                    "covenantSpkHex": r.try_get::<String, _>("covenant_spk_hex").unwrap_or_default(),
                    "redeemScriptHex": r.try_get::<String, _>("redeem_script_hex").unwrap_or_default(),
                    "ownerPubkeyHex": r.try_get::<String, _>("owner_pubkey_hex").unwrap_or_default(),
                    "chronosTriggerPubkeyHex": r.try_get::<String, _>("chronos_trigger_pubkey_hex").unwrap_or_default(),
                    "targetAsset": r.try_get::<String, _>("target_asset").unwrap_or_else(|_| "KAS".to_string()),
                    "targetNetwork": r.try_get::<String, _>("target_network").unwrap_or_else(|_| "KAS".to_string()),
                    "destinationAddress": r.try_get::<String, _>("destination_address").unwrap_or_default(),
                    "refundKaspaAddress": r.try_get::<String, _>("refund_kaspa_address").unwrap_or_default(),
                    "thresholdSompi": r.try_get::<String, _>("threshold_sompi").unwrap_or_else(|_| "2500000000".to_string()),
                    "feeBps": r.try_get::<i32, _>("fee_bps").unwrap_or(50),
                    "makerSpreadBps": r.try_get::<i32, _>("maker_spread_bps").unwrap_or(0),
                    "kcc20TokenTicker": r.try_get::<Option<String>, _>("kcc20_token_ticker").ok().flatten(),
                    "kcc20LineageRoot": r.try_get::<Option<String>, _>("kcc20_lineage_root").ok().flatten(),
                    "confirmedUtxoSompi": r.try_get::<String, _>("confirmed_utxo_sompi").unwrap_or_else(|_| "0".to_string()),
                    "liveUtxoSompi": live_utxo_sompi.map(|v| U128Str(v)),
                    "liveUtxoCount": live_utxo_count,
                    "liveUtxoError": live_utxo_error,
                    "confirmedDaaScore": r.try_get::<i64, _>("confirmed_daa_score").unwrap_or(0),
                    "status": r.try_get::<String, _>("status").unwrap_or_else(|_| "FILLING".to_string()),
                    "updatedAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at").ok().map(|d| d.to_rfc3339())
                }));
            }
            (
                StatusCode::OK,
                Json(json!({ "success": true, "data": { "vaults": vaults } })),
            )
        }
        "REGISTER_VAULT_LOCK" => {
            let owner_pubkey_bytes = match decode_kaspa_address_payload(&wallet) {
                Some((_, pk)) => pk,
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "success": false, "error": "Wallet failed Kaspa Bech32m checksum validation." })),
                    );
                }
            };
            let refund_raw = payload
                .get("refundKaspaAddress")
                .and_then(|v| v.as_str())
                .unwrap_or(&wallet);
            if decode_kaspa_address_payload(refund_raw).is_none() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": "refundKaspaAddress failed Kaspa Bech32m checksum validation." })),
                );
            }
            let vault_kind = payload
                .get("vaultKind")
                .and_then(|v| v.as_str())
                .unwrap_or("MINER_SILO")
                .trim()
                .to_uppercase();
            if !matches!(
                vault_kind.as_str(),
                "MINER_SILO" | "STANDALONE_WALLET_SILO" | "MAKER_PLANT"
            ) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "success": false,
                        "error": "vaultKind must be MINER_SILO, STANDALONE_WALLET_SILO, or MAKER_PLANT."
                    })),
                );
            }
            let target_asset = payload
                .get("targetAsset")
                .and_then(|v| v.as_str())
                .unwrap_or("KAS")
                .trim()
                .to_uppercase();
            let target_network = payload
                .get("targetNetwork")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| resolve_network_for_asset(&target_asset));
            let destination_address = payload
                .get("destinationAddress")
                .and_then(|v| v.as_str())
                .unwrap_or(refund_raw)
                .trim()
                .to_string();
            if destination_address.len() < 12 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": "destinationAddress must be >= 12 characters." })),
                );
            }
            if target_network == "KAS" && decode_kaspa_address_payload(&destination_address).is_none()
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "success": false,
                        "error": "KAS destinationAddress failed Bech32m checksum validation."
                    })),
                );
            }
            let threshold_sompi = parse_u128_json_field(payload.get("thresholdSompi"))
                .unwrap_or(STAGE1_FLUSH_FLOOR_SOMPI)
                .max(10_000_000);
            let fee_bps = payload
                .get("feeBps")
                .and_then(|v| v.as_i64())
                .unwrap_or(50)
                .clamp(0, 1000) as i32;
            let maker_spread_bps = payload
                .get("makerSpreadBps")
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
                .clamp(0, 1000) as i32;
            let kcc20_token_ticker = payload
                .get("kcc20TokenTicker")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty());
            let kcc20_lineage_root = payload
                .get("kcc20LineageRoot")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let chronos_trigger_pubkey_hex = env::var("CHRONOS_TRIGGER_PUBKEY_HEX")
                .ok()
                .filter(|s| s.len() == 64)
                .unwrap_or_else(|| hex::encode(blake2b_256(b"PERENNIA_CHRONOS_TRIGGER_V1")));

            let owner_pubkey_hex = hex::encode(owner_pubkey_bytes);
            let silverscript_source = format!(
                "pragma silverscript ^1.0.0;\n\
                 contract PerenniaVaultLock(pubkey ownerPubkey, pubkey chronosTriggerPubkey, bytes32 destSpkDigest, int thresholdSompi, int feeBps) {{\n\
                     // vaultKind={} targetAsset={} targetNetwork={}\n\
                     entrypoint function cancelToOwner(sig ownerSig) {{\n\
                         require(checkSig(ownerSig, ownerPubkey));\n\
                         require(tx.outputs[0].scriptPublicKey == new ScriptPublicKeyP2PK(ownerPubkey));\n\
                     }}\n\
                     entrypoint function triggerChronosSettlement(sig triggerSig) {{\n\
                         require(checkSig(triggerSig, chronosTriggerPubkey));\n\
                         require(tx.inputs[this.activeInputIndex].value >= thresholdSompi);\n\
                     }}\n\
                 }}",
                vault_kind, target_asset, target_network
            );

            // Deterministic P2SH Vault Lock redeem script encoding dual spending paths + KIP-17 policy digest
            let policy_digest = blake2b_256(
                format!(
                    "{}:{}:{}:{}:{}:{}:{}:{}",
                    clean_wallet,
                    vault_kind,
                    target_asset,
                    target_network,
                    destination_address,
                    threshold_sompi,
                    fee_bps,
                    maker_spread_bps
                )
                .as_bytes(),
            );
            let mut redeem_script = Vec::with_capacity(110);
            redeem_script.push(0x63); // OP_IF (Path A: 24/7 User Sovereignty)
            redeem_script.push(0x20);
            redeem_script.extend_from_slice(&owner_pubkey_bytes);
            redeem_script.push(0xac); // OP_CHECKSIG
            redeem_script.push(0x67); // OP_ELSE (Path B: Chronos KIP-17 Trigger)
            redeem_script.push(0x20);
            let trigger_bytes = hex::decode(&chronos_trigger_pubkey_hex).unwrap_or_else(|_| vec![0u8; 32]);
            redeem_script.extend_from_slice(&trigger_bytes[..32.min(trigger_bytes.len())]);
            redeem_script.push(0xac); // OP_CHECKSIG
            redeem_script.push(0x68); // OP_ENDIF
            redeem_script.push(0x20);
            redeem_script.extend_from_slice(&policy_digest);
            redeem_script.push(0x75); // OP_DROP

            let script_hash = blake2b_256(&redeem_script);
            let covenant_address =
                encode_kaspa_bech32m_address(KASPA_ADDR_VERSION_P2SH, &script_hash);
            let covenant_spk_hex = format!("a9{}87", hex::encode(script_hash));
            let redeem_script_hex = hex::encode(&redeem_script);

            let vault_id = hex::encode(
                &blake2b_256(
                    format!("VAULT:{}:{}:{}", clean_wallet, vault_kind, covenant_spk_hex).as_bytes(),
                )[..16],
            );
            let kip20_covenant_id = hex::encode(blake2b_256(
                format!("KIP20:{}:{}", vault_id, hex::encode(script_hash)).as_bytes(),
            ));
            let threshold_str = threshold_sompi.to_string();

            let upsert_res = sqlx::query(
                r#"
                INSERT INTO vault_locks (
                    vault_id, wallet_address, clean_wallet, vault_kind,
                    kip20_covenant_id, kip21_subnetwork_id,
                    covenant_address, covenant_spk_hex, redeem_script_hex, silverscript_source,
                    owner_pubkey_hex, chronos_trigger_pubkey_hex,
                    target_asset, target_network, destination_address, refund_kaspa_address,
                    threshold_sompi, fee_bps, maker_spread_bps,
                    kcc20_token_ticker, kcc20_lineage_root, status, updated_at
                ) VALUES (
                    $1, $2, $3, $4,
                    $5, $6,
                    $7, $8, $9, $10,
                    $11, $12,
                    $13, $14, $15, $16,
                    $17::NUMERIC(39,0), $18, $19,
                    $20, $21, 'FILLING', CURRENT_TIMESTAMP
                )
                ON CONFLICT (vault_id) DO UPDATE SET
                    destination_address = EXCLUDED.destination_address,
                    refund_kaspa_address = EXCLUDED.refund_kaspa_address,
                    threshold_sompi = EXCLUDED.threshold_sompi,
                    fee_bps = EXCLUDED.fee_bps,
                    maker_spread_bps = EXCLUDED.maker_spread_bps,
                    updated_at = CURRENT_TIMESTAMP
                "#,
            )
            .bind(&vault_id)
            .bind(&wallet)
            .bind(&clean_wallet)
            .bind(&vault_kind)
            .bind(&kip20_covenant_id)
            .bind(PERENNIA_SEQ_COMMIT_SUBNETWORK_ID)
            .bind(&covenant_address)
            .bind(&covenant_spk_hex)
            .bind(&redeem_script_hex)
            .bind(&silverscript_source)
            .bind(&owner_pubkey_hex)
            .bind(&chronos_trigger_pubkey_hex)
            .bind(&target_asset)
            .bind(&target_network)
            .bind(&destination_address)
            .bind(refund_raw)
            .bind(&threshold_str)
            .bind(fee_bps)
            .bind(maker_spread_bps)
            .bind(&kcc20_token_ticker)
            .bind(&kcc20_lineage_root)
            .execute(&pool)
            .await;

            if let Err(e) = upsert_res {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "success": false, "error": e.to_string() })),
                );
            }

            if vault_kind == "MINER_SILO" {
                let _ = sqlx::query(
                    r#"
                    INSERT INTO stratum_mature_accruals (clean_wallet, wallet_address, active_vault_id, updated_at)
                    VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
                    ON CONFLICT (clean_wallet) DO UPDATE SET
                        active_vault_id = EXCLUDED.active_vault_id,
                        updated_at = CURRENT_TIMESTAMP
                    "#,
                )
                .bind(&clean_wallet)
                .bind(&wallet)
                .bind(&vault_id)
                .execute(&pool)
                .await;
            }

            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "data": {
                        "vaultId": vault_id,
                        "vaultKind": vault_kind,
                        "kip20CovenantId": kip20_covenant_id,
                        "kip21SubnetworkId": PERENNIA_SEQ_COMMIT_SUBNETWORK_ID,
                        "covenantAddress": covenant_address,
                        "covenantSpkHex": covenant_spk_hex,
                        "redeemScriptHex": redeem_script_hex,
                        "thresholdSompi": U128Str(threshold_sompi),
                        "feeBps": fee_bps,
                        "makerSpreadBps": maker_spread_bps
                    }
                })),
            )
        }
        "BUILD_VAULT_CANCEL_PSKT" => {
            let vault_id = payload
                .get("vaultId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if vault_id.is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": "Missing vaultId for BUILD_VAULT_CANCEL_PSKT." })),
                );
            }
            let row = match sqlx::query(
                r#"
                SELECT covenant_address, refund_kaspa_address, redeem_script_hex, kip21_subnetwork_id
                FROM vault_locks
                WHERE vault_id = $1 AND (clean_wallet = $2 OR wallet_address = $3)
                LIMIT 1
                "#,
            )
            .bind(vault_id)
            .bind(&clean_wallet)
            .bind(&wallet)
            .fetch_optional(&pool)
            .await
            {
                Ok(Some(r)) => r,
                Ok(None) => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(json!({ "success": false, "error": "Vault lock not found for wallet." })),
                    );
                }
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "success": false, "error": e.to_string() })),
                    );
                }
            };

            let covenant_address: String = row.try_get("covenant_address").unwrap_or_default();
            let refund_address: String = row.try_get("refund_kaspa_address").unwrap_or_default();
            let redeem_script_hex: String = row.try_get("redeem_script_hex").unwrap_or_default();
            let kip21_subnetwork_id: String = row
                .try_get("kip21_subnetwork_id")
                .unwrap_or_else(|_| PERENNIA_SEQ_COMMIT_SUBNETWORK_ID.to_string());

            let utxos = match crate::kaspad_client::get_utxos_by_address_grpc(&covenant_address).await
            {
                Ok(u) if !u.is_empty() => u,
                Ok(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "success": false,
                            "error": format!("No live UTXOs present at covenant address {}.", covenant_address)
                        })),
                    );
                }
                Err(e) => {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({ "success": false, "error": e })),
                    );
                }
            };

            let mut inputs = Vec::with_capacity(utxos.len());
            let mut input_amounts = Vec::with_capacity(utxos.len());
            let mut total_in_sompi: u128 = 0;
            for u in &utxos {
                let txid = u
                    .get("outpoint")
                    .and_then(|o| o.get("transactionId"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let idx = u
                    .get("outpoint")
                    .and_then(|o| o.get("index"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let amt = u
                    .get("utxoEntry")
                    .and_then(|e| e.get("amount"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u128>().ok())
                    .unwrap_or(0);
                let spk_hex = u
                    .get("utxoEntry")
                    .and_then(|e| e.get("scriptPublicKey"))
                    .and_then(|s| s.get("scriptPublicKey"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if txid.is_empty() || amt == 0 {
                    continue;
                }
                total_in_sompi = total_in_sompi.saturating_add(amt);
                input_amounts.push(amt);
                inputs.push(json!({
                    "previousOutpoint": { "transactionId": txid, "index": idx },
                    "utxoEntry": {
                        "amount": amt.to_string(),
                        "scriptPublicKey": { "version": 0, "scriptPublicKey": spk_hex }
                    },
                    "redeemScriptHex": redeem_script_hex,
                    "spendPath": "PATH_A_OWNER_CANCEL",
                    "sequence": 0
                }));
            }

            if inputs.is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": "Vault UTXOs have zero spendable sompi." })),
                );
            }

            let pass1 = compute_post_toccata_v1_mass_and_fee(
                inputs.len(),
                1,
                0,
                redeem_script_hex.len() / 2,
                &input_amounts,
                &[total_in_sompi.saturating_sub(10_000).max(1)],
            );
            let out_pass1 = total_in_sompi.saturating_sub(pass1.required_network_fee_sompi);
            let pass2 = compute_post_toccata_v1_mass_and_fee(
                inputs.len(),
                1,
                0,
                redeem_script_hex.len() / 2,
                &input_amounts,
                &[out_pass1.max(1)],
            );
            if total_in_sompi <= pass2.required_network_fee_sompi {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "success": false,
                        "error": format!(
                            "Vault total {} sompi does not cover post-Toccata v1 fee {} sompi.",
                            total_in_sompi, pass2.required_network_fee_sompi
                        )
                    })),
                );
            }
            let refund_out_sompi = total_in_sompi - pass2.required_network_fee_sompi;
            let refund_spk_hex = crate::sor::kaspa_tx::decode_kaspa_address_to_spk_hex(&refund_address);

            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "data": {
                        "vaultId": vault_id,
                        "spendPath": "PATH_A_24_7_USER_SOVEREIGNTY",
                        "pskt": {
                            "version": 1,
                            "subnetworkId": kip21_subnetwork_id,
                            "lockTime": 0,
                            "inputs": inputs,
                            "outputs": [{
                                "value": refund_out_sompi.to_string(),
                                "scriptPublicKey": {
                                    "version": 0,
                                    "scriptPublicKey": refund_spk_hex
                                },
                                "destinationAddress": refund_address
                            }],
                            "payload": ""
                        },
                        "feeBreakdown": {
                            "totalInputSompi": U128Str(total_in_sompi),
                            "refundOutputSompi": U128Str(refund_out_sompi),
                            "networkFeeSompi": U128Str(pass2.required_network_fee_sompi),
                            "effectiveMass": pass2.effective_mass,
                            "storageMass": pass2.storage_mass,
                            "computeGrams": pass2.compute_grams
                        }
                    }
                })),
            )
        }
        "GET_THERMOSTAT_VALVES" => {
            let rows = sqlx::query(
                r#"
                SELECT valve_id::TEXT AS valve_id, priority_order, valve_type,
                       target_asset, target_network, destination_address,
                       target_cap_sompi::NUMERIC(39,0)::TEXT AS target_cap_sompi,
                       target_cap_usd_micros::NUMERIC(39,0)::TEXT AS target_cap_usd_micros,
                       filled_epoch_sompi::NUMERIC(39,0)::TEXT AS filled_epoch_sompi,
                       filled_epoch_usd_micros::NUMERIC(39,0)::TEXT AS filled_epoch_usd_micros,
                       external_rail_ref, zktls_biller_commitment_hex, is_enabled, updated_at
                FROM thermostat_valves
                WHERE clean_wallet = $1 OR wallet_address = $2
                ORDER BY priority_order ASC
                "#,
            )
            .bind(&clean_wallet)
            .bind(&wallet)
            .fetch_all(&pool)
            .await
            .unwrap_or_default();

            let valves: Vec<Value> = rows
                .into_iter()
                .map(|r| {
                    json!({
                        "valveId": r.try_get::<String, _>("valve_id").unwrap_or_default(),
                        "priorityOrder": r.try_get::<i16, _>("priority_order").unwrap_or(1),
                        "valveType": r.try_get::<String, _>("valve_type").unwrap_or_default(),
                        "targetAsset": r.try_get::<String, _>("target_asset").unwrap_or_default(),
                        "targetNetwork": r.try_get::<String, _>("target_network").unwrap_or_default(),
                        "destinationAddress": r.try_get::<String, _>("destination_address").unwrap_or_default(),
                        "targetCapSompi": r.try_get::<String, _>("target_cap_sompi").unwrap_or_else(|_| "0".to_string()),
                        "targetCapUsdMicros": r.try_get::<String, _>("target_cap_usd_micros").unwrap_or_else(|_| "0".to_string()),
                        "filledEpochSompi": r.try_get::<String, _>("filled_epoch_sompi").unwrap_or_else(|_| "0".to_string()),
                        "filledEpochUsdMicros": r.try_get::<String, _>("filled_epoch_usd_micros").unwrap_or_else(|_| "0".to_string()),
                        "externalRailRef": r.try_get::<Option<String>, _>("external_rail_ref").ok().flatten(),
                        "zktlsBillerCommitmentHex": r.try_get::<Option<String>, _>("zktls_biller_commitment_hex").ok().flatten(),
                        "isEnabled": r.try_get::<bool, _>("is_enabled").unwrap_or(true),
                        "updatedAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at").ok().map(|d| d.to_rfc3339())
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({ "success": true, "data": { "valves": valves } })),
            )
        }
        "UPSERT_THERMOSTAT_VALVES" => {
            let items = if let Some(arr) = payload.get("valves").and_then(|v| v.as_array()) {
                arr.clone()
            } else if payload.get("priorityOrder").is_some() {
                vec![payload.clone()]
            } else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": "Provide 'valves' array or single valve object with 'priorityOrder'." })),
                );
            };

            let mut updated_count = 0usize;
            for item in items {
                let priority = item.get("priorityOrder").and_then(|v| v.as_i64()).unwrap_or(0);
                if !(1..=4).contains(&priority) {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "success": false, "error": "priorityOrder must be between 1 and 4." })),
                    );
                }
                let default_type = match priority {
                    1 => "VALVE_1_ELECTRIC_BILL",
                    2 => "VALVE_2_AGENT_X402_FLOOR",
                    3 => "VALVE_3_JIT_VISA_CEILING",
                    _ => "VALVE_4_TANGEM_COLD_OR_PLANT",
                };
                let valve_type = item
                    .get("valveType")
                    .and_then(|v| v.as_str())
                    .unwrap_or(default_type)
                    .trim()
                    .to_uppercase();
                if !matches!(
                    valve_type.as_str(),
                    "VALVE_1_ELECTRIC_BILL"
                        | "VALVE_2_AGENT_X402_FLOOR"
                        | "VALVE_3_JIT_VISA_CEILING"
                        | "VALVE_4_TANGEM_COLD_OR_PLANT"
                ) {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "success": false, "error": format!("Invalid valveType: {}", valve_type) })),
                    );
                }
                let target_asset = item
                    .get("targetAsset")
                    .and_then(|v| v.as_str())
                    .unwrap_or("USDC")
                    .trim()
                    .to_uppercase();
                let target_network = item
                    .get("targetNetwork")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_uppercase())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| resolve_network_for_asset(&target_asset));
                let dest = item
                    .get("destinationAddress")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if dest.len() < 8 {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "success": false, "error": format!("Invalid destinationAddress for valve {}.", priority) })),
                    );
                }
                let cap_sompi = parse_u128_json_field(item.get("targetCapSompi"))
                    .unwrap_or(0)
                    .to_string();
                let cap_usd_micros = parse_u128_json_field(item.get("targetCapUsdMicros"))
                    .unwrap_or(0)
                    .to_string();
                let ext_ref = item
                    .get("externalRailRef")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                let zktls_commit = item
                    .get("zktlsBillerCommitmentHex")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                let enabled = item.get("isEnabled").and_then(|v| v.as_bool()).unwrap_or(true);

                if let Err(e) = sqlx::query(
                    r#"
                    INSERT INTO thermostat_valves (
                        wallet_address, clean_wallet, priority_order, valve_type,
                        target_asset, target_network, destination_address,
                        target_cap_sompi, target_cap_usd_micros,
                        external_rail_ref, zktls_biller_commitment_hex, is_enabled, updated_at
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7,
                        $8::NUMERIC(39,0), $9::NUMERIC(39,0),
                        $10, $11, $12, CURRENT_TIMESTAMP
                    )
                    ON CONFLICT (clean_wallet, priority_order) DO UPDATE SET
                        valve_type = EXCLUDED.valve_type,
                        target_asset = EXCLUDED.target_asset,
                        target_network = EXCLUDED.target_network,
                        destination_address = EXCLUDED.destination_address,
                        target_cap_sompi = EXCLUDED.target_cap_sompi,
                        target_cap_usd_micros = EXCLUDED.target_cap_usd_micros,
                        external_rail_ref = EXCLUDED.external_rail_ref,
                        zktls_biller_commitment_hex = EXCLUDED.zktls_biller_commitment_hex,
                        is_enabled = EXCLUDED.is_enabled,
                        updated_at = CURRENT_TIMESTAMP
                    "#,
                )
                .bind(&wallet)
                .bind(&clean_wallet)
                .bind(priority as i16)
                .bind(&valve_type)
                .bind(&target_asset)
                .bind(&target_network)
                .bind(&dest)
                .bind(&cap_sompi)
                .bind(&cap_usd_micros)
                .bind(&ext_ref)
                .bind(&zktls_commit)
                .bind(enabled)
                .execute(&pool)
                .await
                {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "success": false, "error": e.to_string() })),
                    );
                }
                updated_count += 1;
            }
            (
                StatusCode::OK,
                Json(json!({ "success": true, "data": { "updatedValves": updated_count } })),
            )
        }
        "GET_MATURE_ACCRUAL_AND_OUTBOX" => {
            let accrual = sqlx::query(
                r#"
                SELECT immature_sompi::NUMERIC(39,0)::TEXT AS immature_sompi,
                       unpaid_mature_sompi::NUMERIC(39,0)::TEXT AS unpaid_mature_sompi,
                       lifetime_flushed_sompi::NUMERIC(39,0)::TEXT AS lifetime_flushed_sompi,
                       lifetime_pool_fee_sompi::NUMERIC(39,0)::TEXT AS lifetime_pool_fee_sompi,
                       pool_fee_bps, active_vault_id, last_maturity_daa, updated_at
                FROM stratum_mature_accruals
                WHERE clean_wallet = $1 OR wallet_address = $2
                LIMIT 1
                "#,
            )
            .bind(&clean_wallet)
            .bind(&wallet)
            .fetch_optional(&pool)
            .await
            .ok()
            .flatten()
            .map(|r| {
                json!({
                    "immatureSompi": r.try_get::<String, _>("immature_sompi").unwrap_or_else(|_| "0".to_string()),
                    "unpaidMatureSompi": r.try_get::<String, _>("unpaid_mature_sompi").unwrap_or_else(|_| "0".to_string()),
                    "lifetimeFlushedSompi": r.try_get::<String, _>("lifetime_flushed_sompi").unwrap_or_else(|_| "0".to_string()),
                    "lifetimePoolFeeSompi": r.try_get::<String, _>("lifetime_pool_fee_sompi").unwrap_or_else(|_| "0".to_string()),
                    "poolFeeBps": r.try_get::<i32, _>("pool_fee_bps").unwrap_or(100),
                    "activeVaultId": r.try_get::<Option<String>, _>("active_vault_id").ok().flatten(),
                    "lastMaturityDaa": r.try_get::<i64, _>("last_maturity_daa").unwrap_or(0),
                    "stage1FlushFloorSompi": U128Str(STAGE1_FLUSH_FLOOR_SOMPI),
                    "updatedAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at").ok().map(|d| d.to_rfc3339())
                })
            })
            .unwrap_or_else(|| {
                json!({
                    "immatureSompi": "0",
                    "unpaidMatureSompi": "0",
                    "lifetimeFlushedSompi": "0",
                    "lifetimePoolFeeSompi": "0",
                    "poolFeeBps": BASE_POOL_FEE_BPS,
                    "activeVaultId": Value::Null,
                    "lastMaturityDaa": 0,
                    "stage1FlushFloorSompi": U128Str(STAGE1_FLUSH_FLOOR_SOMPI)
                })
            });

            let outbox_rows = sqlx::query(
                r#"
                SELECT outbox_key, epoch_id, vault_id, destination_address,
                       payout_sompi::NUMERIC(39,0)::TEXT AS payout_sompi,
                       house_fee_sompi::NUMERIC(39,0)::TEXT AS house_fee_sompi,
                       network_fee_sompi::NUMERIC(39,0)::TEXT AS network_fee_sompi,
                       state, txid, broadcast_daa, confirmed_daa, retry_count,
                       last_error, created_at, updated_at
                FROM epoch_payout_outbox
                WHERE clean_wallet = $1 OR wallet_address = $2
                ORDER BY created_at DESC
                LIMIT 50
                "#,
            )
            .bind(&clean_wallet)
            .bind(&wallet)
            .fetch_all(&pool)
            .await
            .unwrap_or_default();

            let outbox: Vec<Value> = outbox_rows
                .into_iter()
                .map(|r| {
                    json!({
                        "outboxKey": r.try_get::<String, _>("outbox_key").unwrap_or_default(),
                        "epochId": r.try_get::<String, _>("epoch_id").unwrap_or_default(),
                        "vaultId": r.try_get::<String, _>("vault_id").unwrap_or_default(),
                        "destinationAddress": r.try_get::<String, _>("destination_address").unwrap_or_default(),
                        "payoutSompi": r.try_get::<String, _>("payout_sompi").unwrap_or_else(|_| "0".to_string()),
                        "houseFeeSompi": r.try_get::<String, _>("house_fee_sompi").unwrap_or_else(|_| "0".to_string()),
                        "networkFeeSompi": r.try_get::<String, _>("network_fee_sompi").unwrap_or_else(|_| "0".to_string()),
                        "state": r.try_get::<String, _>("state").unwrap_or_default(),
                        "txid": r.try_get::<Option<String>, _>("txid").ok().flatten(),
                        "broadcastDaa": r.try_get::<Option<i64>, _>("broadcast_daa").ok().flatten(),
                        "confirmedDaa": r.try_get::<Option<i64>, _>("confirmed_daa").ok().flatten(),
                        "retryCount": r.try_get::<i32, _>("retry_count").unwrap_or(0),
                        "lastError": r.try_get::<Option<String>, _>("last_error").ok().flatten(),
                        "createdAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok().map(|d| d.to_rfc3339()),
                        "updatedAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at").ok().map(|d| d.to_rfc3339())
                    })
                })
                .collect();

            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "data": { "accrual": accrual, "outbox": outbox }
                })),
            )
        }
        "GET_SETTLEMENT_RECEIPTS" => {
            let rows = sqlx::query(
                r#"
                SELECT receipt_id, outbox_key, epoch_id, vault_id, valve_priority,
                       settlement_tier,
                       source_sompi::NUMERIC(39,0)::TEXT AS source_sompi,
                       house_fee_sompi::NUMERIC(39,0)::TEXT AS house_fee_sompi,
                       network_fee_sompi::NUMERIC(39,0)::TEXT AS network_fee_sompi,
                       target_asset, target_network,
                       settled_atomic::NUMERIC(39,0)::TEXT AS settled_atomic,
                       oracle_kas_usd_e8::NUMERIC(39,0)::TEXT AS oracle_kas_usd_e8,
                       kaspa_l1_txid, destination_txid, htlc_hashlock_sha256,
                       groth16_0x20_proof_hash, changenow_exchange_id,
                       confirmed_daa_score, status, settled_at
                FROM settlement_receipts
                WHERE clean_wallet = $1 OR wallet_address = $2
                ORDER BY settled_at DESC
                LIMIT 50
                "#,
            )
            .bind(&clean_wallet)
            .bind(&wallet)
            .fetch_all(&pool)
            .await
            .unwrap_or_default();

            let receipts: Vec<Value> = rows
                .into_iter()
                .map(|r| {
                    json!({
                        "receiptId": r.try_get::<String, _>("receipt_id").unwrap_or_default(),
                        "outboxKey": r.try_get::<Option<String>, _>("outbox_key").ok().flatten(),
                        "epochId": r.try_get::<String, _>("epoch_id").unwrap_or_default(),
                        "vaultId": r.try_get::<Option<String>, _>("vault_id").ok().flatten(),
                        "valvePriority": r.try_get::<Option<i16>, _>("valve_priority").ok().flatten(),
                        "settlementTier": r.try_get::<String, _>("settlement_tier").unwrap_or_default(),
                        "sourceSompi": r.try_get::<String, _>("source_sompi").unwrap_or_else(|_| "0".to_string()),
                        "houseFeeSompi": r.try_get::<String, _>("house_fee_sompi").unwrap_or_else(|_| "0".to_string()),
                        "networkFeeSompi": r.try_get::<String, _>("network_fee_sompi").unwrap_or_else(|_| "0".to_string()),
                        "targetAsset": r.try_get::<String, _>("target_asset").unwrap_or_default(),
                        "targetNetwork": r.try_get::<String, _>("target_network").unwrap_or_default(),
                        "settledAtomic": r.try_get::<String, _>("settled_atomic").unwrap_or_else(|_| "0".to_string()),
                        "oracleKasUsdE8": r.try_get::<String, _>("oracle_kas_usd_e8").unwrap_or_else(|_| "0".to_string()),
                        "kaspaL1Txid": r.try_get::<String, _>("kaspa_l1_txid").unwrap_or_default(),
                        "destinationTxid": r.try_get::<Option<String>, _>("destination_txid").ok().flatten(),
                        "htlcHashlockSha256": r.try_get::<Option<String>, _>("htlc_hashlock_sha256").ok().flatten(),
                        "groth160x20ProofHash": r.try_get::<Option<String>, _>("groth16_0x20_proof_hash").ok().flatten(),
                        "changenowExchangeId": r.try_get::<Option<String>, _>("changenow_exchange_id").ok().flatten(),
                        "confirmedDaaScore": r.try_get::<i64, _>("confirmed_daa_score").unwrap_or(0),
                        "status": r.try_get::<String, _>("status").unwrap_or_default(),
                        "settledAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("settled_at").ok().map(|d| d.to_rfc3339())
                    })
                })
                .collect();

            (
                StatusCode::OK,
                Json(json!({ "success": true, "data": { "receipts": receipts } })),
            )
        }
        "GET_SOLVENCY_PROOF" => {
            match crate::chronos::evaluate_pool_solvency_invariant(&pool).await {
                Ok(snapshot) => (
                    StatusCode::OK,
                    Json(json!({ "success": true, "data": snapshot })),
                ),
                Err(e) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "success": false, "error": e })),
                ),
            }
        }
        _ => (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "action": action,
                "status": "ACKNOWLEDGED"
            })),
        ),
    }
}