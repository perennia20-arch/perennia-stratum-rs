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
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::env;

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

fn compute_silo_fee_tier(staked: f64) -> (f64, &'static str) {
    if staked >= 1_000_000.0 {
        (0.0025, "SILO Whale Tier (0.25% Fee)")
    } else if staked >= 100_000.0 {
        (0.005, "SILO Institutional Tier (0.50% Fee)")
    } else if staked >= 10_000.0 {
        (0.0075, "SILO Staker Tier (0.75% Fee)")
    } else {
        (0.015, "1.50% Standard Tier")
    }
}

fn lock_multiplier_for_days(days: i32) -> f64 {
    if days >= 365 {
        2.5
    } else if days >= 90 {
        1.5
    } else if days >= 30 {
        1.2
    } else {
        1.0
    }
}

pub async fn resolve_strict_spot_price(pool: &PgPool, asset_ticker: &str) -> Result<f64, String> {
    let clean = asset_ticker.trim().to_uppercase();
    if clean == "USD" || clean == "USDC" || clean == "USDT" {
        return Ok(1.0);
    }

    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                if let Ok(Some(spot_str)) = redis::cmd("GET")
                    .arg(format!("oracle:spot:{}_USDC", clean))
                    .query_async::<_, Option<String>>(&mut conn)
                    .await
                {
                    if let Ok(parsed) = spot_str.parse::<f64>() {
                        if parsed.is_finite() && parsed > 0.0 {
                            return Ok(parsed);
                        }
                    }
                }
            }
        }
    }

    if let Ok(Some(row)) = sqlx::query(
        r#"
        SELECT price_usd
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
        if let Ok(price) = row.try_get::<f64, _>("price_usd") {
            if price.is_finite() && price > 0.0 {
                return Ok(price);
            }
        }
    }

    if clean == "SILO" {
        if let Ok(kas_spot) = Box::pin(resolve_strict_spot_price(pool, "KAS")).await {
            if kas_spot > 0.0 {
                return Ok(((kas_spot / 23.809524) * 1_000_000.0).round() / 1_000_000.0);
            }
        }
    }

    Err(format!(
        "ORACLE_HALT: Live oracle spot price for {} is offline. Failing closed (503).",
        clean
    ))
}

pub async fn debit_user_token_balance(
    pool: &PgPool,
    clean_wallet: &str,
    prefixed_wallet: &str,
    ticker: &str,
    amount: f64,
) -> Result<(), String> {
    if amount <= 0.0 {
        return Err("Debit amount must be greater than 0.".to_string());
    }
    let clean_ticker = ticker.trim().to_uppercase();

    if clean_ticker == "KAS" {
        if crate::chronos::upsert_signed_yield_reservoir_kas(
            pool,
            prefixed_wallet,
            -amount,
            0.0,
            0.0,
        )
        .await
        .is_ok()
        {
            if let Ok(redis_url) = env::var("REDIS_URL") {
                if let Ok(client) = redis::Client::open(redis_url) {
                    if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                        let key = format!("dev:sor:treasury:balances:{}", clean_wallet);
                        let cur: f64 = redis::cmd("HGET")
                            .arg(&key)
                            .arg("KAS")
                            .query_async::<_, Option<String>>(&mut conn)
                            .await
                            .ok()
                            .flatten()
                            .and_then(|s| s.parse::<f64>().ok())
                            .unwrap_or(0.0);
                        let next = (cur - amount).max(0.0);
                        let _: redis::RedisResult<()> = redis::cmd("HSET")
                            .arg(&key)
                            .arg("KAS")
                            .arg(next.to_string())
                            .query_async(&mut conn)
                            .await;
                    }
                }
            }
            return Ok(());
        }
    }

    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let key = format!("dev:sor:treasury:balances:{}", clean_wallet);
                let cur: f64 = redis::cmd("HGET")
                    .arg(&key)
                    .arg(&clean_ticker)
                    .query_async::<_, Option<String>>(&mut conn)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                if cur + 1e-8 >= amount {
                    let next = (cur - amount).max(0.0);
                    let _: redis::RedisResult<()> = redis::cmd("HSET")
                        .arg(&key)
                        .arg(&clean_ticker)
                        .arg(next.to_string())
                        .query_async(&mut conn)
                        .await;
                    return Ok(());
                }
            }
        }
    }

    let row_opt = sqlx::query(
        r#"
        SELECT wallet_address, streaming_balance_kas, total_yield_kas,
               COALESCE(lp_tokens, '{}'::jsonb) AS lp_tokens,
               COALESCE(quarantined, FALSE) AS quarantined
        FROM yield_reservoirs
        WHERE wallet_address = $1 OR wallet_address = $2
        LIMIT 1
        "#,
    )
    .bind(prefixed_wallet)
    .bind(clean_wallet)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("DB lookup failed: {}", e))?;

    let Some(row) = row_opt else {
        return Err(format!(
            "INSUFFICIENT_BALANCE: 0.0000 {} available for {}.",
            clean_ticker, prefixed_wallet
        ));
    };

    if row.try_get::<bool, _>("quarantined").unwrap_or(false) {
        return Err(format!("Wallet {} is quarantined.", prefixed_wallet));
    }

    let streaming_kas: f64 = row.try_get("streaming_balance_kas").unwrap_or(0.0);
    let total_yield_kas: f64 = row.try_get("total_yield_kas").unwrap_or(0.0);
    let mut lp_tokens: Value = row.try_get("lp_tokens").unwrap_or_else(|_| json!({}));
    let target_pk: String = row
        .try_get("wallet_address")
        .unwrap_or_else(|_| prefixed_wallet.to_string());

    let cur_tok = lp_tokens
        .get(&clean_ticker)
        .and_then(|v| {
            v.as_f64()
                .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
        })
        .unwrap_or(0.0);

    if cur_tok + 1e-8 < amount {
        return Err(format!(
            "INSUFFICIENT_BALANCE: Requested {:.4} {}, available {:.4} {}.",
            amount, clean_ticker, cur_tok, clean_ticker
        ));
    }

    let next_tok = (cur_tok - amount).max(0.0);
    if let Some(obj) = lp_tokens.as_object_mut() {
        obj.insert(clean_ticker.clone(), json!(next_tok));
    }

    let new_hmac =
        crate::chronos::compute_reservoir_hmac(prefixed_wallet, streaming_kas, total_yield_kas, &lp_tokens)?;

    sqlx::query(
        r#"
        UPDATE yield_reservoirs
        SET lp_tokens = $2,
            row_hmac_sig = $3,
            last_updated = CURRENT_TIMESTAMP
        WHERE wallet_address = $1
        "#,
    )
    .bind(&target_pk)
    .bind(&lp_tokens)
    .bind(&new_hmac)
    .execute(pool)
    .await
    .map_err(|e| format!("Failed to update token reservoir balance: {}", e))?;

    Ok(())
}

pub async fn credit_user_token_balance(
    pool: &PgPool,
    clean_wallet: &str,
    prefixed_wallet: &str,
    ticker: &str,
    amount: f64,
    is_verified_yield: bool,
) -> Result<(), String> {
    if amount <= 0.0 {
        return Ok(());
    }
    let clean_ticker = ticker.trim().to_uppercase();

    if clean_ticker == "KAS" {
        let yield_add = if is_verified_yield { amount } else { 0.0 };
        crate::chronos::upsert_signed_yield_reservoir_kas(
            pool,
            prefixed_wallet,
            amount,
            yield_add,
            amount,
        )
        .await?;
    } else {
        let existing_opt = sqlx::query(
            r#"
            SELECT wallet_address, streaming_balance_kas, total_yield_kas,
                   COALESCE(lp_tokens, '{}'::jsonb) AS lp_tokens
            FROM yield_reservoirs
            WHERE wallet_address = $1 OR wallet_address = $2
            LIMIT 1
            "#,
        )
        .bind(prefixed_wallet)
        .bind(clean_wallet)
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("DB lookup failed: {}", e))?;

        let (streaming_kas, total_yield_kas, mut lp_tokens, target_pk) =
            if let Some(r) = existing_opt {
                (
                    r.try_get::<f64, _>("streaming_balance_kas").unwrap_or(0.0),
                    r.try_get::<f64, _>("total_yield_kas").unwrap_or(0.0),
                    r.try_get::<Value, _>("lp_tokens")
                        .unwrap_or_else(|_| json!({})),
                    r.try_get::<String, _>("wallet_address")
                        .unwrap_or_else(|_| prefixed_wallet.to_string()),
                )
            } else {
                (0.0, 0.0, json!({}), prefixed_wallet.to_string())
            };

        let cur_tok = lp_tokens
            .get(&clean_ticker)
            .and_then(|v| {
                v.as_f64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
            })
            .unwrap_or(0.0);
        if let Some(obj) = lp_tokens.as_object_mut() {
            obj.insert(clean_ticker.clone(), json!(cur_tok + amount));
        } else {
            lp_tokens = json!({ clean_ticker.clone(): cur_tok + amount });
        }

        let new_hmac = crate::chronos::compute_reservoir_hmac(
            prefixed_wallet,
            streaming_kas,
            total_yield_kas,
            &lp_tokens,
        )?;

        sqlx::query(
            r#"
            INSERT INTO yield_reservoirs (
                wallet_address, streaming_balance_kas, total_yield_kas,
                lp_tokens, row_hmac_sig, last_updated
            ) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
            ON CONFLICT (wallet_address) DO UPDATE SET
                lp_tokens = EXCLUDED.lp_tokens,
                row_hmac_sig = EXCLUDED.row_hmac_sig,
                last_updated = CURRENT_TIMESTAMP
            "#,
        )
        .bind(&target_pk)
        .bind(streaming_kas)
        .bind(total_yield_kas)
        .bind(&lp_tokens)
        .bind(&new_hmac)
        .execute(pool)
        .await
        .map_err(|e| format!("Failed to credit token reservoir: {}", e))?;
    }

    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let key = format!("dev:sor:treasury:balances:{}", clean_wallet);
                let _: redis::RedisResult<()> = redis::cmd("HINCRBYFLOAT")
                    .arg(&key)
                    .arg(&clean_ticker)
                    .arg(amount)
                    .query_async(&mut conn)
                    .await;
            }
        }
    }

    Ok(())
}

pub async fn build_live_node_airlock_telemetry(pool: &PgPool) -> Value {
    let sys_cfg = crate::chronos::load_system_treasury_config(pool).await;
    let hot_signer_address = crate::chronos::resolve_hot_dispatcher_address()
        .unwrap_or_else(|| sys_cfg.cold_kas_address.clone());

    let hot_balance_kas = if !hot_signer_address.trim().is_empty() {
        match crate::kaspad_client::get_balance_by_address_grpc(&hot_signer_address).await {
            Ok(sompi) => (sompi as f64) / 100_000_000.0,
            Err(_) => 0.0,
        }
    } else {
        0.0
    };

    let trailing_24h_outflow_kas: f64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(amount_tokens), 0.0)
        FROM l1_payout_queue
        WHERE asset_ticker = 'KAS'
          AND status = 'DISPATCHED_ONCHAIN'
          AND created_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
        "#,
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0.0);

    let hourly_burn_kas = (trailing_24h_outflow_kas / 24.0).max(0.0);
    let runway_hours_remaining = if hourly_burn_kas > 0.01 {
        ((hot_balance_kas / hourly_burn_kas) * 10.0).round() / 10.0
    } else if hot_balance_kas > 0.0 {
        ((hot_balance_kas / (sys_cfg.min_runway_kas.max(10.0) / 24.0)) * 10.0).round() / 10.0
    } else {
        0.0
    };

    let low_runway_tripped = sys_cfg.outflow_breaker_tripped
        || (sys_cfg.min_runway_kas > 0.0
            && hot_balance_kas > 0.0
            && hot_balance_kas < sys_cfg.min_runway_kas);

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

    let status = if sys_cfg.outflow_breaker_tripped {
        "PAUSED_BY_DIRECTOR"
    } else if low_runway_tripped {
        "LOW_RUNWAY_ALERT"
    } else {
        "ARMED_NOMINAL"
    };

    json!({
        "hotSignerAddress": hot_signer_address,
        "coldVaultAddress": sys_cfg.cold_kas_address,
        "coldBtcAddress": sys_cfg.cold_btc_address,
        "coldEthAddress": sys_cfg.cold_eth_address,
        "coldSolAddress": sys_cfg.cold_sol_address,
        "hotBalanceKas": (hot_balance_kas * 10000.0).round() / 10000.0,
        "hotCeilingKas": sys_cfg.hot_ceiling_kas,
        "minRunwayKas": sys_cfg.min_runway_kas,
        "fppsMaxFloatKas": sys_cfg.fpps_max_float_kas,
        "poolFeeRate": sys_cfg.pool_fee_rate,
        "poolFeeRatePct": (sys_cfg.pool_fee_rate * 10000.0).round() / 100.0,
        "runwayHoursRemaining": runway_hours_remaining,
        "trailing24hOutflowKas": trailing_24h_outflow_kas,
        "lowRunwayBreakerTripped": low_runway_tripped,
        "outflowBreakerTripped": sys_cfg.outflow_breaker_tripped,
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
                let pct = payload
                    .get("allocationPercentage")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                if let Some(arr) = layout.get_mut("sectors").and_then(|v| v.as_array_mut()) {
                    for s in arr.iter_mut() {
                        if s.get("id").and_then(|v| v.as_str()) == Some(target_id) {
                            s["allocationPercentage"] = json!(pct);
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

            (
                StatusCode::OK,
                Json(json!({ "success": true, "data": layout })),
            )
        }
        "CLAIM_PENDING_SECTOR_KAS" => {
            let target_sector_id = payload
                .get("sectorId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let target_asset = payload
                .get("targetAsset")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_uppercase();

            let row_opt = sqlx::query(
                "SELECT wallet_address, layout_state FROM user_command_centers WHERE wallet_address = $1 OR wallet_address = $2 LIMIT 1",
            )
            .bind(&wallet)
            .bind(&clean_wallet)
            .fetch_optional(&pool)
            .await
            .ok()
            .flatten();

            let mut verified_claimed_kas = 0.0_f64;

            if let Some(row) = row_opt {
                let db_pk: String = row
                    .try_get("wallet_address")
                    .unwrap_or_else(|_| wallet.clone());
                let mut layout: Value = row
                    .try_get("layout_state")
                    .unwrap_or_else(|_| json!({ "workers": [], "sectors": [] }));

                if let Some(sectors) = layout.get_mut("sectors").and_then(|v| v.as_array_mut()) {
                    for sec in sectors.iter_mut() {
                        let pending = sec
                            .get("pendingKaspa")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0)
                            .max(0.0);
                        if pending <= 0.0 {
                            continue;
                        }
                        let sec_id = sec.get("id").and_then(|v| v.as_str()).unwrap_or("");
                        let sec_ticker = sec
                            .get("settlementConfig")
                            .and_then(|c| c.get("targetAsset"))
                            .and_then(|t| t.get("ticker"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_uppercase();

                        let matched = (!target_sector_id.is_empty() && sec_id == target_sector_id)
                            || (!target_asset.is_empty() && sec_ticker == target_asset);

                        if matched {
                            verified_claimed_kas += pending;
                            sec["pendingKaspa"] = json!(0.0);
                        }
                    }
                }

                if verified_claimed_kas > 0.0 {
                    let _ = sqlx::query(
                        "UPDATE user_command_centers SET layout_state = $2, last_updated = CURRENT_TIMESTAMP WHERE wallet_address = $1",
                    )
                    .bind(&db_pk)
                    .bind(&layout)
                    .execute(&pool)
                    .await;

                    if let Err(e) = credit_user_token_balance(
                        &pool,
                        &clean_wallet,
                        &wallet,
                        "KAS",
                        verified_claimed_kas,
                        true,
                    )
                    .await
                    {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "success": false, "error": e })),
                        );
                    }
                }
            }

            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "data": { "claimedKas": verified_claimed_kas }
                })),
            )
        }
        "STAKE_LP" => {
            let pool_pair = payload
                .get("poolPair")
                .and_then(|v| v.as_str())
                .unwrap_or("KAS/USDC");
            let amount_a = payload
                .get("amountA")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let amount_b = payload
                .get("amountB")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let lock_days = payload
                .get("lockDurationDays")
                .and_then(|v| v.as_i64())
                .unwrap_or(0) as i32;

            if amount_a <= 0.0 || amount_b <= 0.0 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": "LP stake amounts must be > 0." })),
                );
            }

            if let Err(e) =
                debit_user_token_balance(&pool, &clean_wallet, &wallet, "KAS", amount_a).await
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": e })),
                );
            }

            let weights_json = payload
                .get("weights")
                .cloned()
                .unwrap_or_else(|| json!({ "KAS": 0.5, "USDC": 0.5 }));
            let reserves_json = payload
                .get("reserves")
                .cloned()
                .unwrap_or_else(|| json!({ "KAS": amount_a, "USDC": amount_b }));

            let res = sqlx::query(
                r#"
                INSERT INTO liquidity_providers (
                    wallet_address, pool_pair, staked_asset_a, staked_asset_b,
                    weights_json, reserves_json, lock_duration_days,
                    unlock_date
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7,
                    CURRENT_TIMESTAMP + ($7::text || ' days')::interval
                )
                RETURNING lp_id::text AS lp_id
                "#,
            )
            .bind(&wallet)
            .bind(pool_pair)
            .bind(amount_a)
            .bind(amount_b)
            .bind(&weights_json)
            .bind(&reserves_json)
            .bind(lock_days)
            .fetch_one(&pool)
            .await;

            match res {
                Ok(row) => {
                    let lp_id: String = row.try_get("lp_id").unwrap_or_default();
                    (
                        StatusCode::OK,
                        Json(json!({
                            "success": true,
                            "data": {
                                "lpId": lp_id,
                                "poolPair": pool_pair,
                                "stakedAssetA": amount_a,
                                "stakedAssetB": amount_b,
                                "lockDurationDays": lock_days
                            }
                        })),
                    )
                }
                Err(e) => {
                    let _ = credit_user_token_balance(
                        &pool,
                        &clean_wallet,
                        &wallet,
                        "KAS",
                        amount_a,
                        false,
                    )
                    .await;
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "success": false, "error": e.to_string() })),
                    )
                }
            }
        }
        "GET_LP_POSITIONS" => {
            let rows = sqlx::query(
                r#"
                SELECT lp_id::text AS lp_id, pool_pair, staked_asset_a, staked_asset_b,
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
                    let mult = lock_multiplier_for_days(days);
                    let amt_a = r.try_get::<f64, _>("staked_asset_a").unwrap_or(0.0);
                    let amt_b = r.try_get::<f64, _>("staked_asset_b").unwrap_or(0.0);
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
                        "stakedAssetA": amt_a,
                        "stakedAssetB": amt_b,
                        "weights": r.try_get::<Value, _>("weights_json").unwrap_or_else(|_| json!({})),
                        "reserves": r.try_get::<Value, _>("reserves_json").unwrap_or_else(|_| json!({})),
                        "internalPairsCount": internal_pairs,
                        "isMultiAssetPlant": leg_count > 2,
                        "lockDurationDays": days,
                        "unlockDate": r.try_get::<chrono::DateTime<chrono::Utc>, _>("unlock_date").ok().map(|d| d.to_rfc3339()),
                        "createdAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok().map(|d| d.to_rfc3339()),
                        "isUnlocked": r.try_get::<bool, _>("is_unlocked").unwrap_or(true),
                        "multiplier": mult,
                        "weightedTvl": amt_a * mult
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({ "success": true, "data": list })),
            )
        }
        "WITHDRAW_LP" => {
            let lp_id = payload.get("lpId").and_then(|v| v.as_str()).unwrap_or("");
            let row_opt = sqlx::query(
                r#"
                SELECT staked_asset_a, staked_asset_b, pool_pair,
                       (CURRENT_TIMESTAMP >= unlock_date OR lock_duration_days <= 0) AS is_unlocked
                FROM liquidity_providers
                WHERE lp_id::text = $1 AND (wallet_address = $2 OR wallet_address = $3)
                LIMIT 1
                "#,
            )
            .bind(lp_id)
            .bind(&wallet)
            .bind(&clean_wallet)
            .fetch_optional(&pool)
            .await
            .ok()
            .flatten();

            let Some(row) = row_opt else {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "success": false, "error": "LP position not found." })),
                );
            };

            let is_unlocked: bool = row.try_get("is_unlocked").unwrap_or(false);
            if !is_unlocked {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": "LP position timelock is still active." })),
                );
            }

            let amt_a: f64 = row.try_get("staked_asset_a").unwrap_or(0.0);
            let amt_b: f64 = row.try_get("staked_asset_b").unwrap_or(0.0);
            let pair: String = row
                .try_get("pool_pair")
                .unwrap_or_else(|_| "KAS/USDC".to_string());
            let parts: Vec<&str> = pair.split('/').collect();
            let token_b = parts.get(1).copied().unwrap_or("USDC");

            let _ = sqlx::query(
                "DELETE FROM liquidity_providers WHERE lp_id::text = $1 AND (wallet_address = $2 OR wallet_address = $3)",
            )
            .bind(lp_id)
            .bind(&wallet)
            .bind(&clean_wallet)
            .execute(&pool)
            .await;

            if amt_a > 0.0 {
                let _ =
                    credit_user_token_balance(&pool, &clean_wallet, &wallet, "KAS", amt_a, false)
                        .await;
            }
            if amt_b > 0.0 {
                let _ = credit_user_token_balance(
                    &pool,
                    &clean_wallet,
                    &wallet,
                    token_b,
                    amt_b,
                    false,
                )
                .await;
            }

            (
                StatusCode::OK,
                Json(json!({ "success": true, "data": { "withdrawnLpId": lp_id } })),
            )
        }
        "STAKE_SILO" => {
            let amount = payload
                .get("amount")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let ticker = payload
                .get("ticker")
                .and_then(|v| v.as_str())
                .unwrap_or("SILO")
                .trim()
                .to_uppercase();
            if amount <= 0.0 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": "Stake amount must be > 0" })),
                );
            }

            if let Err(e) =
                debit_user_token_balance(&pool, &clean_wallet, &wallet, &ticker, amount).await
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": e })),
                );
            }

            let row_res = sqlx::query(
                r#"
                INSERT INTO silo_staking_positions (wallet_address, token_ticker, amount_staked, status)
                VALUES ($1, $2, $3, 'ACTIVE')
                RETURNING stake_id::text AS stake_id
                "#,
            )
            .bind(&wallet)
            .bind(&ticker)
            .bind(amount)
            .fetch_one(&pool)
            .await;

            match row_res {
                Ok(r) => {
                    let stake_id: String = r.try_get("stake_id").unwrap_or_default();
                    let total_staked: f64 = sqlx::query_scalar(
                        "SELECT COALESCE(SUM(amount_staked), 0.0) FROM silo_staking_positions WHERE (wallet_address = $1 OR wallet_address = $2) AND status = 'ACTIVE'",
                    )
                    .bind(&wallet)
                    .bind(&clean_wallet)
                    .fetch_one(&pool)
                    .await
                    .unwrap_or(amount);
                    let (fee_cap, tier_label) = compute_silo_fee_tier(total_staked);
                    (
                        StatusCode::OK,
                        Json(json!({
                            "success": true,
                            "data": {
                                "stakeId": stake_id,
                                "ticker": ticker,
                                "stakedAmount": amount,
                                "totalActiveStaked": total_staked,
                                "feeRateCap": fee_cap,
                                "tierLabel": tier_label
                            }
                        })),
                    )
                }
                Err(e) => {
                    let _ = credit_user_token_balance(
                        &pool,
                        &clean_wallet,
                        &wallet,
                        &ticker,
                        amount,
                        false,
                    )
                    .await;
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "success": false, "error": e.to_string() })),
                    )
                }
            }
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
        "CLAIM_UNSTAKED_SILO" => {
            let stake_id = payload
                .get("stakeId")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let row_opt = sqlx::query(
                r#"
                SELECT token_ticker, amount_staked,
                       (cooldown_ends_at IS NOT NULL AND CURRENT_TIMESTAMP >= cooldown_ends_at) AS is_matured
                FROM silo_staking_positions
                WHERE stake_id::text = $1 AND (wallet_address = $2 OR wallet_address = $3)
                LIMIT 1
                "#,
            )
            .bind(stake_id)
            .bind(&wallet)
            .bind(&clean_wallet)
            .fetch_optional(&pool)
            .await
            .ok()
            .flatten();

            let Some(row) = row_opt else {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "success": false, "error": "Staking position not found." })),
                );
            };

            let is_matured: bool = row.try_get("is_matured").unwrap_or(false);
            if !is_matured {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": "7-day unbonding cooldown is still active." })),
                );
            }

            let ticker: String = row
                .try_get("token_ticker")
                .unwrap_or_else(|_| "SILO".to_string());
            let amt: f64 = row.try_get("amount_staked").unwrap_or(0.0);

            let _ = sqlx::query(
                "DELETE FROM silo_staking_positions WHERE stake_id::text = $1 AND (wallet_address = $2 OR wallet_address = $3)",
            )
            .bind(stake_id)
            .bind(&wallet)
            .bind(&clean_wallet)
            .execute(&pool)
            .await;

            if amt > 0.0 {
                let _ = credit_user_token_balance(
                    &pool,
                    &clean_wallet,
                    &wallet,
                    &ticker,
                    amt,
                    false,
                )
                .await;
            }

            (
                StatusCode::OK,
                Json(json!({ "success": true, "data": { "claimedStakeId": stake_id, "claimedAmount": amt } })),
            )
        }
        "GET_SILO_STAKING" => {
            let rows = sqlx::query(
                r#"
                SELECT stake_id::text AS stake_id, token_ticker, amount_staked, status,
                       cooldown_initiated_at, cooldown_ends_at, created_at,
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
            let mut active_staked = 0.0;
            let mut cooldown_staked = 0.0;
            let mut positions = Vec::new();
            for r in rows {
                let amt = r.try_get::<f64, _>("amount_staked").unwrap_or(0.0);
                let st = r
                    .try_get::<String, _>("status")
                    .unwrap_or_else(|_| "ACTIVE".to_string());
                if st == "ACTIVE" {
                    active_staked += amt;
                } else {
                    cooldown_staked += amt;
                }
                positions.push(json!({
                    "stakeId": r.try_get::<String, _>("stake_id").unwrap_or_default(),
                    "ticker": r.try_get::<String, _>("token_ticker").unwrap_or_else(|_| "SILO".to_string()),
                    "amountStaked": amt,
                    "status": st,
                    "cooldownInitiatedAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("cooldown_initiated_at").ok().map(|d| d.to_rfc3339()),
                    "cooldownEndsAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("cooldown_ends_at").ok().map(|d| d.to_rfc3339()),
                    "createdAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok().map(|d| d.to_rfc3339()),
                    "isMatured": r.try_get::<bool, _>("is_matured").unwrap_or(false)
                }));
            }
            let (fee_cap, tier_label) = compute_silo_fee_tier(active_staked);
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "data": {
                        "ecosystemTicker": "SILO",
                        "activeStaked": active_staked,
                        "cooldownStaked": cooldown_staked,
                        "combinedEligibleStaked": active_staked,
                        "feeRateCap": fee_cap,
                        "tierLabel": tier_label,
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
                       overflow_ceiling, auto_sweep_enabled, last_sweep_txid,
                       last_sweep_amount, last_sweep_at, updated_at
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
                let entry = json!({
                    "assetTicker": ticker,
                    "network": r.try_get::<String, _>("network").unwrap_or_else(|_| ticker.clone()),
                    "coldDestinationAddress": r.try_get::<String, _>("cold_destination_address").unwrap_or_default(),
                    "vaultLabel": r.try_get::<String, _>("vault_label").unwrap_or_else(|_| "Perennia Cold Vault".to_string()),
                    "overflowCeiling": r.try_get::<f64, _>("overflow_ceiling").unwrap_or(500.0),
                    "autoSweepEnabled": r.try_get::<bool, _>("auto_sweep_enabled").unwrap_or(false),
                    "lastSweepTxid": r.try_get::<Option<String>, _>("last_sweep_txid").ok().flatten(),
                    "lastSweepAmount": r.try_get::<f64, _>("last_sweep_amount").unwrap_or(0.0),
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
            let overflow_ceiling = payload
                .get("overflowCeiling")
                .or_else(|| payload.get("overflowThresholdKas"))
                .and_then(|v| v.as_f64())
                .unwrap_or(500.0)
                .max(0.0001);
            let auto_sweep_enabled = payload
                .get("autoSweepEnabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            let res = sqlx::query(
                r#"
                INSERT INTO user_cold_vault_rules (
                    wallet_address, asset_ticker, network, cold_destination_address,
                    vault_label, overflow_ceiling, auto_sweep_enabled, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
                ON CONFLICT (wallet_address, asset_ticker) DO UPDATE SET
                    network = EXCLUDED.network,
                    cold_destination_address = EXCLUDED.cold_destination_address,
                    vault_label = EXCLUDED.vault_label,
                    overflow_ceiling = EXCLUDED.overflow_ceiling,
                    auto_sweep_enabled = EXCLUDED.auto_sweep_enabled,
                    updated_at = CURRENT_TIMESTAMP
                "#,
            )
            .bind(&wallet)
            .bind(&ticker)
            .bind(&network)
            .bind(&cold_dest)
            .bind(&vault_label)
            .bind(overflow_ceiling)
            .bind(auto_sweep_enabled)
            .execute(&pool)
            .await;

            if ticker == "KAS" {
                let _ = sqlx::query(
                    r#"
                    INSERT INTO client_cold_vault_registry (
                        wallet_address, cold_kaspa_address, card_label,
                        overflow_threshold_kas, auto_sweep_enabled, updated_at
                    ) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
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
                .bind(overflow_ceiling)
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
                            "overflowCeiling": overflow_ceiling,
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
        "SWEEP_TOKEN_TO_COLD_VAULT_NOW" | "SWEEP_TO_COLD_VAULT_NOW" => {
            let ticker = payload
                .get("assetTicker")
                .or_else(|| payload.get("ticker"))
                .and_then(|v| v.as_str())
                .unwrap_or("KAS")
                .trim()
                .to_uppercase();
            let amount = payload
                .get("amount")
                .or_else(|| payload.get("amountTokens"))
                .or_else(|| payload.get("amountKas"))
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);

            if amount <= 0.0 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": "Sweep amount must be greater than 0." })),
                );
            }

            let mut cold_dest = payload
                .get("coldDestinationAddress")
                .or_else(|| payload.get("coldKaspaAddress"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();

            if cold_dest.is_empty() {
                cold_dest = sqlx::query_scalar(
                    "SELECT cold_destination_address FROM user_cold_vault_rules WHERE (wallet_address = $1 OR wallet_address = $2) AND asset_ticker = $3 LIMIT 1",
                )
                .bind(&wallet)
                .bind(&clean_wallet)
                .bind(&ticker)
                .fetch_optional(&pool)
                .await
                .ok()
                .flatten()
                .unwrap_or_default();
            }

            if cold_dest.is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "success": false,
                        "error": format!("Save a Cold Storage destination address for {} before sweeping.", ticker)
                    })),
                );
            }

            let spot_price = match resolve_strict_spot_price(&pool, &ticker).await {
                Ok(p) => p,
                Err(e) => {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({ "success": false, "error": e })),
                    );
                }
            };

            if let Err(e) =
                debit_user_token_balance(&pool, &clean_wallet, &wallet, &ticker, amount).await
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": e })),
                );
            }

            let network = resolve_network_for_asset(&ticker);
            match dispatch_or_queue_l1_payout(
                &pool,
                &wallet,
                &cold_dest,
                &ticker,
                Some(&network),
                amount,
                spot_price,
                "cold_airlock_sweep",
            )
            .await
            {
                Ok(receipt) => {
                    let tx_hash = receipt
                        .get("txHash")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let _ = sqlx::query(
                        r#"
                        UPDATE user_cold_vault_rules
                        SET last_sweep_txid = $3,
                            last_sweep_amount = $4,
                            last_sweep_at = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE (wallet_address = $1 OR wallet_address = $2) AND asset_ticker = $5
                        "#,
                    )
                    .bind(&wallet)
                    .bind(&clean_wallet)
                    .bind(&tx_hash)
                    .bind(amount)
                    .bind(&ticker)
                    .execute(&pool)
                    .await;

                    let _ = sqlx::query(
                        r#"
                        INSERT INTO treasury_airlock_sweeps (
                            hot_wallet_address, cold_vault_address, swept_kas,
                            hot_balance_before_kas, hot_balance_after_kas, tx_id, status
                        ) VALUES ($1, $2, $3, $3, 0.0, $4, 'SWEPT_TO_COLD')
                        "#,
                    )
                    .bind(&wallet)
                    .bind(&cold_dest)
                    .bind(amount)
                    .bind(&tx_hash)
                    .execute(&pool)
                    .await;

                    (
                        StatusCode::OK,
                        Json(json!({
                            "success": true,
                            "transaction_id": tx_hash,
                            "data": receipt
                        })),
                    )
                }
                Err(e) => {
                    let _ = credit_user_token_balance(
                        &pool,
                        &clean_wallet,
                        &wallet,
                        &ticker,
                        amount,
                        false,
                    )
                    .await;
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "success": false, "error": e })),
                    )
                }
            }
        }
        "WITHDRAW_SYNTHETIC_ASSET" | "DISPATCH_L1_PAYOUT" => {
            let dest = payload
                .get("destination")
                .or_else(|| payload.get("destinationAddress"))
                .and_then(|v| v.as_str())
                .unwrap_or(&wallet);
            let ticker = payload
                .get("asset")
                .or_else(|| payload.get("assetTicker"))
                .and_then(|v| v.as_str())
                .unwrap_or("KAS")
                .trim()
                .to_uppercase();
            let net = payload.get("network").and_then(|v| v.as_str());
            let amt = payload
                .get("amount")
                .or_else(|| payload.get("amountTokens"))
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);

            if amt <= 0.0 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": "Withdrawal amount must be > 0." })),
                );
            }

            let spot = match resolve_strict_spot_price(&pool, &ticker).await {
                Ok(p) => p,
                Err(e) => {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({ "success": false, "error": e })),
                    );
                }
            };

            if let Err(e) =
                debit_user_token_balance(&pool, &clean_wallet, &wallet, &ticker, amt).await
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": e })),
                );
            }

            match dispatch_or_queue_l1_payout(
                &pool,
                &wallet,
                dest,
                &ticker,
                net,
                amt,
                spot,
                "ledger_withdrawal",
            )
            .await
            {
                Ok(receipt) => {
                    let tx_hash = receipt
                        .get("txHash")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    (
                        StatusCode::OK,
                        Json(json!({
                            "success": true,
                            "transaction_id": tx_hash,
                            "data": receipt
                        })),
                    )
                }
                Err(e) => {
                    let _ = credit_user_token_balance(
                        &pool,
                        &clean_wallet,
                        &wallet,
                        &ticker,
                        amt,
                        false,
                    )
                    .await;
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "success": false, "error": e })),
                    )
                }
            }
        }
        "DISPATCH_OTC_UTXOS" => {
            let dest = payload
                .get("destination")
                .or_else(|| payload.get("destinationAddress"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ticker = payload
                .get("asset")
                .or_else(|| payload.get("assetTicker"))
                .and_then(|v| v.as_str())
                .unwrap_or("KAS")
                .trim()
                .to_uppercase();
            let amt = payload
                .get("amount")
                .or_else(|| payload.get("amountTokens"))
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);

            if dest.is_empty() || amt <= 0.0 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "success": false, "error": "Invalid destination or amount for DISPATCH_OTC_UTXOS." })),
                );
            }

            let spot = match resolve_strict_spot_price(&pool, &ticker).await {
                Ok(p) => p,
                Err(e) => {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({ "success": false, "error": e })),
                    );
                }
            };

            match dispatch_or_queue_l1_payout(
                &pool,
                "kaspa:treasury_master",
                dest,
                &ticker,
                None,
                amt,
                spot,
                "otc_settlement",
            )
            .await
            {
                Ok(receipt) => {
                    let tx_hash = receipt
                        .get("txHash")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    (
                        StatusCode::OK,
                        Json(json!({
                            "success": true,
                            "transaction_id": tx_hash,
                            "data": receipt
                        })),
                    )
                }
                Err(e) => (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({ "success": false, "error": e })),
                ),
            }
        }
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