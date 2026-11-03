use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::env;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
struct ShieldActionReq {
    ip: String,
    action: Option<String>,
}

#[derive(Deserialize)]
struct WhitelistReq {
    wallet: String,
    label: Option<String>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct PassthroughAdminReq {
    action: String,
    orderIndex: Option<usize>,
    wallet: Option<String>,
    targetAsset: Option<String>,
    grossKas: Option<f64>,
    upfrontFeeKas: Option<f64>,
    estimatedOutput: Option<f64>,
    spotPrice: Option<f64>,
    txHash: Option<String>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct FiatAdminReq {
    action: String,
    payoutId: Option<String>,
    orderId: Option<String>,
    traceId: Option<String>,
    batchTracePrefix: Option<String>,
    settlementTarget: Option<String>,
    txHash: Option<String>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct L1PayoutAdminReq {
    action: String,
    payoutId: String,
    txHash: Option<String>,
}

const LUA_CLAMPED_FEE_REVERSAL: &str = r#"
local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
local rev = tonumber(ARGV[1] or '0')
local next_val = math.max(0, cur - rev)
redis.call('SET', KEYS[1], tostring(next_val))
return tostring(next_val)
"#;

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn verify_internal_admin_headers(headers: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let internal_token = env::var("INTERNAL_ADMIN_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let admin_key = env::var("PERENNIA_ADMIN_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let mut authorized = false;
    if let Some(tok) = internal_token {
        let expected = format!("Bearer {}", tok);
        if constant_time_eq(auth_header.as_bytes(), expected.as_bytes()) {
            authorized = true;
        }
    }
    if !authorized {
        if let Some(key) = admin_key {
            let expected = format!("Bearer {}", key);
            if constant_time_eq(auth_header.as_bytes(), expected.as_bytes()) {
                authorized = true;
            }
        }
    }
    if !authorized {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Unauthorized Access: Internal token mismatch."})),
        ));
    }
    Ok(())
}

pub fn admin_routes() -> Router<PgPool> {
    Router::new()
        .route("/v1/admin/db/:table", get(get_table_data))
        .route("/v1/admin/shield", get(get_shield_status).post(modify_shield_ip))
        .route(
            "/v1/admin/whitelist",
            get(get_whitelisted_wallets)
                .post(add_whitelisted_wallet)
                .delete(remove_whitelisted_wallet),
        )
        .route("/v1/admin/passthrough", post(handle_passthrough_action))
        .route("/v1/admin/fiat", post(handle_fiat_action))
        .route("/v1/admin/l1-payout", post(handle_l1_payout_action))
        .route("/v1/admin/epoch-bell", post(handle_force_epoch_bell))
}

async fn handle_force_epoch_bell(
    headers: HeaderMap,
    State(pool): State<PgPool>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    verify_internal_admin_headers(&headers)?;
    match crate::chronos::trigger_immediate_epoch_bell_sweep(&pool).await {
        Ok(epoch_telemetry) => Ok(Json(json!({
            "success": true,
            "action": "FORCE_EPOCH_BELL",
            "epochTelemetry": epoch_telemetry
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to trigger 22:00 UTC Bell sweep: {}", e)})),
        )),
    }
}

async fn get_table_data(
    headers: HeaderMap,
    Path(table): Path<String>,
    State(pool): State<PgPool>,
) -> Result<Json<Vec<Value>>, (StatusCode, Json<Value>)> {
    verify_internal_admin_headers(&headers)?;
    let allowed_tables = vec![
        "worker_profiles",
        "yield_reservoirs",
        "micro_shares",
        "network_blocks",
        "user_command_centers",
        "entity_kyc",
        "tax_ledger_events",
        "liquidity_providers",
        "silo_staking_positions",
        "yield_distributions",
        "pending_transactions",
        "whitelisted_wallets",
        "p2p_orders",
        "fiat_payout_queue",
        "fiat_bank_rails",
        "fiat_onramp_orders",
        "l1_payout_queue",
        "rwa_oracle_feeds",
        "forge_vesting_schedules",
        "forge_monetary_policies",
        "forge_mineable_vaults",
        "idempotent_payout_batches",
        "client_cold_vault_registry",
        "treasury_airlock_sweeps",
        "hifo_tax_lots",
        "hifo_disposal_matches",
    ];
    if !allowed_tables.contains(&table.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Table not authorized in internal matrix."})),
        ));
    }
    let query = format!(
        "SELECT row_to_json(t) AS data FROM (SELECT * FROM {} ORDER BY 1 DESC LIMIT 5000) t",
        table
    );
    let rows = sqlx::query(&query).fetch_all(&pool).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Database Error: {}", e)})),
        )
    })?;
    let mut results = Vec::new();
    for row in rows {
        if let Ok(val) = row.try_get::<Value, _>("data") {
            results.push(val);
        }
    }
    Ok(Json(results))
}

async fn get_shield_status(
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    verify_internal_admin_headers(&headers)?;
    let mut banned = Vec::new();
    let mut expired = Vec::new();
    for entry in crate::stratum_tcp::BANNED_IPS.iter() {
        let ip = entry.key().clone();
        let banned_at = *entry.value();
        let elapsed = banned_at.elapsed();
        if elapsed < Duration::from_secs(crate::stratum_tcp::BAN_DURATION_SECS) {
            let remaining_secs = crate::stratum_tcp::BAN_DURATION_SECS.saturating_sub(elapsed.as_secs());
            banned.push(json!({
                "ip": ip,
                "elapsedSeconds": elapsed.as_secs(),
                "remainingSeconds": remaining_secs
            }));
        } else {
            expired.push(ip);
        }
    }
    for ip in expired {
        crate::stratum_tcp::BANNED_IPS.remove(&ip);
        crate::stratum_tcp::STRIKE_COUNTERS.remove(&ip);
    }

    let mut active_strikes = Vec::new();
    for entry in crate::stratum_tcp::STRIKE_COUNTERS.iter() {
        active_strikes.push(json!({
            "key": entry.key(),
            "strikes": *entry.value(),
            "maxStrikes": crate::stratum_tcp::MAX_CONSECUTIVE_STRIKES
        }));
    }

    Ok(Json(json!({
        "bannedIps": banned,
        "count": banned.len(),
        "activeStrikeCounters": active_strikes,
        "maxConsecutiveStrikes": crate::stratum_tcp::MAX_CONSECUTIVE_STRIKES
    })))
}

async fn modify_shield_ip(
    headers: HeaderMap,
    Json(req): Json<ShieldActionReq>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    verify_internal_admin_headers(&headers)?;
    let clean_ip = req.ip.trim().to_string();
    if clean_ip.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "IP address required"})),
        ));
    }
    let action = req.action.unwrap_or_else(|| "BAN".to_string()).to_uppercase();
    if action == "UNBAN" || action == "REMOVE" {
        crate::stratum_tcp::BANNED_IPS.remove(&clean_ip);
        crate::stratum_tcp::STRIKE_COUNTERS.remove(&clean_ip);
        Ok(Json(json!({
            "success": true,
            "action": "UNBANNED",
            "ip": clean_ip
        })))
    } else {
        crate::stratum_tcp::BANNED_IPS.insert(clean_ip.clone(), Instant::now());
        crate::stratum_tcp::STRIKE_COUNTERS.remove(&clean_ip);
        Ok(Json(json!({
            "success": true,
            "action": "BANNED",
            "ip": clean_ip
        })))
    }
}

async fn get_whitelisted_wallets(
    headers: HeaderMap,
    State(pool): State<PgPool>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    verify_internal_admin_headers(&headers)?;
    let rows = sqlx::query(
        "SELECT row_to_json(t) AS data FROM (SELECT * FROM whitelisted_wallets ORDER BY created_at DESC LIMIT 1000) t",
    )
    .fetch_all(&pool)
    .await
    .unwrap_or_default();
    let mut list = Vec::new();
    for r in rows {
        if let Ok(v) = r.try_get::<Value, _>("data") {
            list.push(v);
        }
    }
    Ok(Json(json!({ "wallets": list })))
}

async fn add_whitelisted_wallet(
    headers: HeaderMap,
    State(pool): State<PgPool>,
    Json(req): Json<WhitelistReq>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    verify_internal_admin_headers(&headers)?;
    let clean = req.wallet.trim().to_lowercase().replace("kaspa:", "");
    if clean.len() < 55 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid Kaspa wallet address"})),
        ));
    }
    let prefixed = format!("kaspa:{}", clean);
    let label = req.label.unwrap_or_else(|| "Director Whitelisted".to_string());
    sqlx::query(
        "INSERT INTO whitelisted_wallets (wallet_address, label) VALUES ($1, $2)
         ON CONFLICT (wallet_address) DO UPDATE SET label = EXCLUDED.label",
    )
    .bind(&prefixed)
    .bind(&label)
    .execute(&pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;
    Ok(Json(json!({ "success": true, "wallet": prefixed })))
}

async fn remove_whitelisted_wallet(
    headers: HeaderMap,
    State(pool): State<PgPool>,
    Json(req): Json<WhitelistReq>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    verify_internal_admin_headers(&headers)?;
    let clean = req.wallet.trim().to_lowercase().replace("kaspa:", "");
    let prefixed = format!("kaspa:{}", clean);
    let _ = sqlx::query(
        "DELETE FROM whitelisted_wallets WHERE wallet_address = $1 OR wallet_address = $2",
    )
    .bind(&prefixed)
    .bind(&clean)
    .execute(&pool)
    .await;
    Ok(Json(json!({ "success": true, "removed": prefixed })))
}

async fn handle_l1_payout_action(
    headers: HeaderMap,
    State(pool): State<PgPool>,
    Json(req): Json<L1PayoutAdminReq>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    verify_internal_admin_headers(&headers)?;
    let mode = req.action.trim().to_uppercase();
    let payout_id = req.payoutId.trim().to_string();
    if payout_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "payoutId is required"})),
        ));
    }
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = redis::Client::open(redis_url).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;
    let mut redis_conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?;
    let row_opt = sqlx::query(
        "SELECT wallet_address, destination_address, asset_ticker, amount_tokens, gross_usd, spot_price, status FROM l1_payout_queue WHERE payout_id = $1 LIMIT 1",
    )
    .bind(&payout_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("DB lookup failed: {}", e)})),
        )
    })?;
    let row = row_opt.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "L1 payout record not found."})),
        )
    })?;
    let wallet_address: String = row.try_get("wallet_address").unwrap_or_default();
    let clean_wallet = wallet_address.trim().to_lowercase().replace("kaspa:", "");
    let prefixed_wallet = format!("kaspa:{}", clean_wallet);
    let asset_ticker: String = row
        .try_get::<String, _>("asset_ticker")
        .unwrap_or_else(|_| "KAS".to_string())
        .to_uppercase();
    let amount_tokens: f64 = row.try_get("amount_tokens").unwrap_or(0.0);
    let gross_usd: f64 = row.try_get("gross_usd").unwrap_or(0.0);
    let spot_price: f64 = row.try_get("spot_price").unwrap_or(0.0);
    if mode == "CONFIRM_L1_PAYOUT" {
        let resolved_tx_hash = req
            .txHash
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("0x{}", uuid::Uuid::new_v4().simple()));
        let explorer_url = crate::state_api::build_explorer_tx_url(&asset_ticker, &resolved_tx_hash);
        let _ = sqlx::query(
            "UPDATE l1_payout_queue SET status = 'DISPATCHED_ONCHAIN', tx_hash = $2, explorer_url = $3, updated_at = CURRENT_TIMESTAMP WHERE payout_id = $1",
        )
        .bind(&payout_id)
        .bind(&resolved_tx_hash)
        .bind(&explorer_url)
        .execute(&pool)
        .await;
        let _ = sqlx::query("UPDATE tax_ledger_events SET tx_hash = $2 WHERE tx_hash = $1")
            .bind(&payout_id)
            .bind(&resolved_tx_hash)
            .execute(&pool)
            .await;
        let _ = sqlx::query(
            "INSERT INTO pending_transactions (tx_id, wallet_address, amount_kas, action_type, status) VALUES ($1, $2, $3, 'L1_MULTI_CHAIN_PAYOUT', 'SETTLED') ON CONFLICT (tx_id) DO UPDATE SET status = 'SETTLED'",
        )
        .bind(&resolved_tx_hash)
        .bind(&prefixed_wallet)
        .bind(amount_tokens)
        .execute(&pool)
        .await;
        let sse_evt = json!({
            "l1_event": true,
            "fiat_event": true,
            "eventType": "L1_DISPATCHED",
            "wallet": clean_wallet,
            "payoutId": payout_id,
            "assetTicker": asset_ticker,
            "amountTokens": amount_tokens,
            "txHash": resolved_tx_hash,
            "explorerUrl": explorer_url
        });
        let _: () = redis::cmd("PUBLISH")
            .arg("telemetry:updates")
            .arg(sse_evt.to_string())
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(());
        return Ok(Json(json!({
            "success": true,
            "action": "CONFIRM_L1_PAYOUT",
            "payoutId": payout_id,
            "txHash": resolved_tx_hash,
            "explorerUrl": explorer_url,
            "status": "DISPATCHED_ONCHAIN"
        })));
    } else if mode == "REFUND_L1_PAYOUT" {
        let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
        let _: () = redis::cmd("HINCRBYFLOAT")
            .arg(&user_ledger_key)
            .arg(&asset_ticker)
            .arg(amount_tokens)
            .query_async(&mut redis_conn)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("Failed to refund ledger: {}", e)})),
                )
            })?;
        let _ = sqlx::query(
            "UPDATE l1_payout_queue SET status = 'REFUNDED_TO_LEDGER', updated_at = CURRENT_TIMESTAMP WHERE payout_id = $1",
        )
        .bind(&payout_id)
        .execute(&pool)
        .await;
        let _ = sqlx::query(
            "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash) VALUES ($1, $2, 'L1_REFUND', $3, $4, $5, $6)",
        )
        .bind(&clean_wallet)
        .bind(&asset_ticker)
        .bind(gross_usd)
        .bind(amount_tokens)
        .bind(spot_price)
        .bind(&payout_id)
        .execute(&pool)
        .await;
        let sse_evt = json!({
            "l1_event": true,
            "fiat_event": true,
            "eventType": "L1_REFUND",
            "wallet": clean_wallet,
            "payoutId": payout_id,
            "assetTicker": asset_ticker,
            "amountTokens": amount_tokens
        });
        let _: () = redis::cmd("PUBLISH")
            .arg("telemetry:updates")
            .arg(sse_evt.to_string())
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(());
        return Ok(Json(json!({
            "success": true,
            "action": "REFUND_L1_PAYOUT",
            "payoutId": payout_id,
            "refundedAsset": asset_ticker,
            "refundedAmount": amount_tokens,
            "status": "REFUNDED_TO_LEDGER"
        })));
    }
    Err((
        StatusCode::BAD_REQUEST,
        Json(json!({"error": format!("Unsupported L1 payout action: {}", mode)})),
    ))
}

async fn handle_passthrough_action(
    headers: HeaderMap,
    State(pool): State<PgPool>,
    Json(req): Json<PassthroughAdminReq>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    verify_internal_admin_headers(&headers)?;
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = redis::Client::open(redis_url).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Redis init error: {}", e)})),
        )
    })?;
    let mut redis_conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Redis conn error: {}", e)})),
            )
        })?;
    let queue_key = "perennia:sor:third_party_passthrough_queue";
    let raw_items: Vec<String> = redis::cmd("LRANGE")
        .arg(queue_key)
        .arg(0)
        .arg(199)
        .query_async(&mut redis_conn)
        .await
        .unwrap_or_default();
    let mut matched_raw: Option<String> = None;
    let mut matched_json: Option<Value> = None;
    if let Some(idx) = req.orderIndex {
        if let Some(item_str) = raw_items.get(idx) {
            matched_raw = Some(item_str.clone());
            matched_json = serde_json::from_str::<Value>(item_str).ok();
        }
    }
    if matched_json.is_none() {
        let req_wallet_clean = req
            .wallet
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_lowercase()
            .replace("kaspa:", "");
        let req_target = req
            .targetAsset
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_uppercase();
        for item_str in &raw_items {
            if let Ok(parsed) = serde_json::from_str::<Value>(item_str) {
                let w_clean = parsed
                    .get("wallet")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_lowercase()
                    .replace("kaspa:", "");
                let t_asset = parsed
                    .get("target_asset")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_uppercase();
                if (!req_wallet_clean.is_empty() && w_clean == req_wallet_clean)
                    && (req_target.is_empty() || t_asset == req_target)
                {
                    matched_raw = Some(item_str.clone());
                    matched_json = Some(parsed);
                    break;
                }
            }
        }
    }
    let order_val = matched_json.unwrap_or_else(|| {
        json!({
            "wallet": req.wallet.clone().unwrap_or_default(),
            "target_asset": req.targetAsset.clone().unwrap_or_else(|| "CUSTOM".to_string()),
            "gross_kas": req.grossKas.unwrap_or(0.0),
            "upfront_fee_kas": req.upfrontFeeKas.unwrap_or(0.0),
            "estimated_output": req.estimatedOutput.unwrap_or(0.0),
            "spot_price": req.spotPrice.unwrap_or(0.0)
        })
    });
    if let Some(raw_to_remove) = matched_raw {
        let _: () = redis::cmd("LREM")
            .arg(queue_key)
            .arg(1)
            .arg(raw_to_remove)
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(());
    }
    let wallet_str = order_val
        .get("wallet")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let clean_wallet = wallet_str
        .trim()
        .to_lowercase()
        .replace("kaspa:", "");
    let prefixed_wallet = format!("kaspa:{}", clean_wallet);
    let target_asset = order_val
        .get("target_asset")
        .and_then(|v| v.as_str())
        .unwrap_or("CUSTOM")
        .to_uppercase();
    let gross_kas = order_val
        .get("gross_kas")
        .and_then(|v| v.as_f64())
        .or(req.grossKas)
        .unwrap_or(0.0)
        .max(0.0);
    let upfront_fee_kas = order_val
        .get("upfront_fee_kas")
        .and_then(|v| v.as_f64())
        .or(req.upfrontFeeKas)
        .unwrap_or(0.0)
        .max(0.0);
    let estimated_output = order_val
        .get("estimated_output")
        .and_then(|v| v.as_f64())
        .or(req.estimatedOutput)
        .unwrap_or(0.0)
        .max(0.0);
    let spot_price = order_val
        .get("spot_price")
        .and_then(|v| v.as_f64())
        .or(req.spotPrice)
        .unwrap_or(0.0)
        .max(0.0);
    let kas_spot_str: Option<String> = redis::cmd("GET")
        .arg("oracle:spot:KAS_USDC")
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(None);
    let live_kas_spot = kas_spot_str
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|&v| v > 0.0)
        .unwrap_or(0.0);
    let mode = req.action.trim().to_uppercase();
    if mode == "CONFIRM_PASSTHROUGH_FILL" {
        if spot_price <= 0.0 && live_kas_spot <= 0.0 {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "ORACLE_HALT: Live KAS/USDC spot price is unavailable and no execution spot price was provided."})),
            ));
        }
        let resolved_tx = req
            .txHash
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("PT-FILL-{}", uuid::Uuid::new_v4().simple()));
        let _ = sqlx::query(
            "INSERT INTO pending_transactions (tx_id, wallet_address, amount_kas, action_type, status)
             VALUES ($1, $2, $3, 'PASSTHROUGH_L1_FILL', 'SETTLED')
             ON CONFLICT (tx_id) DO UPDATE SET status = 'SETTLED'",
        )
        .bind(&resolved_tx)
        .bind(&prefixed_wallet)
        .bind(gross_kas)
        .execute(&pool)
        .await;
        let gross_usd = if spot_price > 0.0 && estimated_output > 0.0 {
            estimated_output * spot_price
        } else {
            gross_kas * live_kas_spot
        };
        let resolved_unit_spot = if spot_price > 0.0 {
            spot_price
        } else if estimated_output > 0.0 {
            gross_usd / estimated_output
        } else {
            live_kas_spot
        };
        crate::sor::record_hifo_acquisition_lot(
            &pool,
            &clean_wallet,
            &target_asset,
            estimated_output,
            resolved_unit_spot,
            "PASSTHROUGH_SETTLED",
            Some(&resolved_tx),
        )
        .await;
        let _ = sqlx::query(
            "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash, cost_basis_usd, realized_gain_loss_usd, holding_period)
             VALUES ($1, $2, 'PASSTHROUGH_SETTLED', $3, $4, $5, $6, $3, 0.0, 'SHORT_TERM')",
        )
        .bind(&clean_wallet)
        .bind(&target_asset)
        .bind(gross_usd)
        .bind(estimated_output)
        .bind(resolved_unit_spot)
        .bind(&resolved_tx)
        .execute(&pool)
        .await;
        let sse_event = json!({
            "fiat_event": true,
            "eventType": "PASSTHROUGH_SETTLED",
            "wallet": clean_wallet,
            "assetTicker": target_asset,
            "amountTokens": estimated_output,
            "txHash": resolved_tx
        });
        let _: () = redis::cmd("PUBLISH")
            .arg("telemetry:updates")
            .arg(sse_event.to_string())
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(());
        return Ok(Json(json!({
            "success": true,
            "action": "CONFIRM_PASSTHROUGH_FILL",
            "wallet": prefixed_wallet,
            "targetAsset": target_asset,
            "txHash": resolved_tx
        })));
    } else if mode == "REFUND_PASSTHROUGH_ORDER" {
        if clean_wallet.is_empty() || gross_kas <= 0.0 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid pass-through wallet or gross_kas amount to refund."})),
            ));
        }
        let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
        let _: () = redis::cmd("HINCRBYFLOAT")
            .arg(&user_ledger_key)
            .arg("KAS")
            .arg(gross_kas)
            .query_async(&mut redis_conn)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("Failed to credit miner ledger: {}", e)})),
                )
            })?;
        if upfront_fee_kas > 0.0 {
            let _: Result<String, _> = redis::cmd("EVAL")
                .arg(LUA_CLAMPED_FEE_REVERSAL)
                .arg(1)
                .arg("perennia:fees:batch_accumulated:KAS")
                .arg(upfront_fee_kas)
                .query_async(&mut redis_conn)
                .await;
        }
        let refund_kas_spot = if live_kas_spot > 0.0 { live_kas_spot } else { spot_price };
        let _ = sqlx::query(
            "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution)
             VALUES ($1, 'KAS', 'PASSTHROUGH_REFUND', $2, $3, $4)",
        )
        .bind(&clean_wallet)
        .bind(gross_kas * refund_kas_spot)
        .bind(gross_kas)
        .bind(refund_kas_spot)
        .execute(&pool)
        .await;
        let sse_event = json!({
            "fiat_event": true,
            "eventType": "PASSTHROUGH_REFUND",
            "wallet": clean_wallet,
            "assetTicker": "KAS",
            "amountTokens": gross_kas
        });
        let _: () = redis::cmd("PUBLISH")
            .arg("telemetry:updates")
            .arg(sse_event.to_string())
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(());
        return Ok(Json(json!({
            "success": true,
            "action": "REFUND_PASSTHROUGH_ORDER",
            "wallet": prefixed_wallet,
            "refundedKas": gross_kas,
            "reversedFeeKas": upfront_fee_kas
        })));
    }
    Err((
        StatusCode::BAD_REQUEST,
        Json(json!({"error": format!("Unsupported pass-through action: {}", mode)})),
    ))
}

async fn handle_fiat_action(
    headers: HeaderMap,
    State(pool): State<PgPool>,
    Json(req): Json<FiatAdminReq>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    verify_internal_admin_headers(&headers)?;
    let mode = req.action.trim().to_uppercase();
    if mode == "FORCE_EPOCH_BELL" {
        return handle_force_epoch_bell(headers, State(pool)).await;
    }
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = redis::Client::open(redis_url).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;
    let mut redis_conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?;
    if mode == "BULK_SETTLE_FIAT_PAYOUTS" {
        let prefix = req
            .batchTracePrefix
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                let date_str = chrono::Utc::now().format("%Y%m%d").to_string();
                let short_hex = &uuid::Uuid::new_v4().simple().to_string().to_uppercase()[..4];
                format!("ACH-BATCH-{}-{}", date_str, short_hex)
            });
        let pending_rows = sqlx::query(
            "SELECT payout_id, wallet_address, net_fiat_usd FROM fiat_payout_queue WHERE status = 'QUEUED_FOR_TREASURY_DISPATCH' ORDER BY created_at ASC"
        )
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to fetch pending payouts: {}", e)})),
            )
        })?;
        let mut settled_count = 0usize;
        let mut total_usd = 0.0f64;
        for (idx, r) in pending_rows.iter().enumerate() {
            let pid: String = r.try_get("payout_id").unwrap_or_default();
            let w_addr: String = r.try_get("wallet_address").unwrap_or_default();
            let net_usd: f64 = r.try_get("net_fiat_usd").unwrap_or(0.0);
            let trace_id = format!("{}-{:03}", prefix, idx + 1);
            let res = sqlx::query(
                "UPDATE fiat_payout_queue SET status = 'DISPATCHED_BY_DIRECTOR', trace_id = $2, updated_at = CURRENT_TIMESTAMP WHERE payout_id = $1 AND status = 'QUEUED_FOR_TREASURY_DISPATCH'"
            )
            .bind(&pid)
            .bind(&trace_id)
            .execute(&pool)
            .await;
            if res.is_ok() {
                settled_count += 1;
                total_usd += net_usd;
                let clean_wallet = w_addr.trim().to_lowercase().replace("kaspa:", "");
                let sse_event = json!({
                    "fiat_event": true,
                    "eventType": "FIAT_DISPATCHED",
                    "wallet": clean_wallet,
                    "payoutId": pid,
                    "traceId": trace_id,
                    "netFiatUsd": net_usd
                });
                let _: () = redis::cmd("PUBLISH")
                    .arg("telemetry:updates")
                    .arg(sse_event.to_string())
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(());
            }
        }
        return Ok(Json(json!({
            "success": true,
            "action": "BULK_SETTLE_FIAT_PAYOUTS",
            "settledCount": settled_count,
            "totalDispatchedUsd": (total_usd * 100.0).round() / 100.0,
            "batchTracePrefix": prefix
        })));
    }
    if mode == "SETTLE_FIAT_PAYOUT" {
        let payout_id = req.payoutId.as_deref().unwrap_or("").trim().to_string();
        if payout_id.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "payoutId is required"})),
            ));
        }
        let resolved_trace_id = req
            .traceId
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                let hex_str = uuid::Uuid::new_v4().simple().to_string().to_uppercase();
                format!("ACH-TRACE-{}", &hex_str[..10])
            });
        let updated = sqlx::query(
            "UPDATE fiat_payout_queue
             SET status = 'DISPATCHED_BY_DIRECTOR', trace_id = $2, updated_at = CURRENT_TIMESTAMP
             WHERE payout_id = $1 AND status = 'QUEUED_FOR_TREASURY_DISPATCH'
             RETURNING wallet_address, net_fiat_usd",
        )
        .bind(&payout_id)
        .bind(&resolved_trace_id)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to update payout status: {}", e)})),
            )
        })?;
        let Some(row) = updated else {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Fiat payout not found or already finalized."})),
            ));
        };
        let wallet_address: String = row.try_get("wallet_address").unwrap_or_default();
        let clean_wallet = wallet_address.trim().to_lowercase().replace("kaspa:", "");
        let net_fiat_usd: f64 = row.try_get("net_fiat_usd").unwrap_or(0.0);
        let sse_event = json!({
            "fiat_event": true,
            "eventType": "FIAT_DISPATCHED",
            "wallet": clean_wallet,
            "payoutId": payout_id,
            "traceId": resolved_trace_id,
            "netFiatUsd": net_fiat_usd
        });
        let _: () = redis::cmd("PUBLISH")
            .arg("telemetry:updates")
            .arg(sse_event.to_string())
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(());
        return Ok(Json(json!({
            "success": true,
            "payoutId": payout_id,
            "traceId": resolved_trace_id,
            "status": "DISPATCHED_BY_DIRECTOR"
        })));
    }
    if mode == "REFUND_FIAT_PAYOUT" {
        let payout_id = req.payoutId.as_deref().unwrap_or("").trim().to_string();
        if payout_id.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "payoutId is required"})),
            ));
        }
        let row_opt = sqlx::query(
            "SELECT wallet_address, source_asset, amount_crypto, gross_usd, fee_usd, status FROM fiat_payout_queue WHERE payout_id = $1 LIMIT 1",
        )
        .bind(&payout_id)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("DB lookup failed: {}", e)})),
            )
        })?;
        let row = row_opt.ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Fiat payout record not found."})),
            )
        })?;
        let current_status: String = row.try_get("status").unwrap_or_default();
        if current_status != "QUEUED_FOR_TREASURY_DISPATCH" {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Payout {} cannot be refunded from status {}.", payout_id, current_status)})),
            ));
        }
        let wallet_address: String = row.try_get("wallet_address").unwrap_or_default();
        let source_asset: String = row
            .try_get::<String, _>("source_asset")
            .unwrap_or_else(|_| "KAS".to_string())
            .to_uppercase();
        let amount_crypto: f64 = row.try_get("amount_crypto").unwrap_or(0.0);
        let gross_usd: f64 = row.try_get("gross_usd").unwrap_or(0.0);
        let fee_usd: f64 = row.try_get("fee_usd").unwrap_or(0.0);
        let clean_wallet = wallet_address
            .trim()
            .to_lowercase()
            .replace("kaspa:", "");
        let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
        let _: () = redis::cmd("HINCRBYFLOAT")
            .arg(&user_ledger_key)
            .arg(&source_asset)
            .arg(amount_crypto)
            .query_async(&mut redis_conn)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("Failed to refund ledger: {}", e)})),
                )
            })?;
        if fee_usd > 0.0 {
            let _: Result<String, _> = redis::cmd("EVAL")
                .arg(LUA_CLAMPED_FEE_REVERSAL)
                .arg(1)
                .arg("perennia:treasury:netting_profit_usd")
                .arg(fee_usd)
                .query_async(&mut redis_conn)
                .await;
        }
        sqlx::query(
            "UPDATE fiat_payout_queue SET status = 'REFUNDED_TO_LEDGER', updated_at = CURRENT_TIMESTAMP WHERE payout_id = $1",
        )
        .bind(&payout_id)
        .execute(&pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to update payout status: {}", e)})),
            )
        })?;
        let spot = if amount_crypto > 0.0 {
            gross_usd / amount_crypto
        } else {
            1.0
        };
        let _ = sqlx::query(
            "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash)
             VALUES ($1, $2, 'FIAT_REFUND', $3, $4, $5, $6)",
        )
        .bind(&clean_wallet)
        .bind(&source_asset)
        .bind(gross_usd)
        .bind(amount_crypto)
        .bind(spot)
        .bind(&payout_id)
        .execute(&pool)
        .await;
        let sse_event = json!({
            "fiat_event": true,
            "eventType": "FIAT_REFUND",
            "wallet": clean_wallet,
            "payoutId": payout_id,
            "assetTicker": source_asset,
            "amountTokens": amount_crypto
        });
        let _: () = redis::cmd("PUBLISH")
            .arg("telemetry:updates")
            .arg(sse_event.to_string())
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(());
        return Ok(Json(json!({
            "success": true,
            "payoutId": payout_id,
            "status": "REFUNDED_TO_LEDGER",
            "refundedAsset": source_asset,
            "refundedAmount": amount_crypto
        })));
    }
    if mode == "FULFILL_FIAT_ONRAMP" || mode == "CANCEL_FIAT_ONRAMP" {
        let order_id = req.orderId.as_deref().unwrap_or("").trim().to_string();
        if order_id.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "orderId is required"})),
            ));
        }
        let row_opt = sqlx::query(
            "SELECT wallet_address, settlement_target, fiat_amount_usd, fee_usd, net_usd_converted, locked_spot_price, estimated_kas, status
             FROM fiat_onramp_orders
             WHERE order_id = $1
             LIMIT 1",
        )
        .bind(&order_id)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("DB lookup failed: {}", e)})),
            )
        })?;
        let row = row_opt.ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Fiat on-ramp order not found."})),
            )
        })?;
        let current_status: String = row.try_get("status").unwrap_or_default();
        if current_status == "COMPLETED" || current_status == "CANCELLED" {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("On-ramp order {} is already {}.", order_id, current_status)})),
            ));
        }
        let wallet_address: String = row.try_get("wallet_address").unwrap_or_default();
        let clean_wallet = wallet_address.trim().to_lowercase().replace("kaspa:", "");
        let prefixed_wallet = format!("kaspa:{}", clean_wallet);
        if mode == "CANCEL_FIAT_ONRAMP" {
            let _ = sqlx::query(
                "UPDATE fiat_onramp_orders SET status = 'CANCELLED', updated_at = CURRENT_TIMESTAMP WHERE order_id = $1",
            )
            .bind(&order_id)
            .execute(&pool)
            .await;
            return Ok(Json(json!({
                "success": true,
                "orderId": order_id,
                "status": "CANCELLED"
            })));
        }
        let fiat_amount_usd: f64 = row.try_get("fiat_amount_usd").unwrap_or(0.0);
        let fee_usd: f64 = row.try_get("fee_usd").unwrap_or(0.0);
        let net_usd_converted: f64 = row.try_get("net_usd_converted").unwrap_or(0.0);
        let locked_spot_price: f64 = row.try_get("locked_spot_price").unwrap_or(0.0);
        let live_spot_str: Option<String> = redis::cmd("GET")
            .arg("oracle:spot:KAS_USDC")
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(None);
        let execution_spot = live_spot_str
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|&v| v > 0.0)
            .unwrap_or(locked_spot_price);
        if execution_spot <= 0.0 {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "ORACLE_HALT: Live KAS/USDC spot price is unavailable and order has no valid locked spot price."})),
            ));
        }
        let delivered_kas = ((net_usd_converted / execution_spot) * 10000.0).round() / 10000.0;
        let settlement_target = req
            .settlementTarget
            .clone()
            .or_else(|| row.try_get::<String, _>("settlement_target").ok())
            .unwrap_or_else(|| "LEDGER_KAS".to_string())
            .to_uppercase();
        let mut resolved_tx_hash = req
            .txHash
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_default();
        if settlement_target == "L1_KAS" {
            let idemp_key = format!(
                "FIAT-ONRAMP-L1-{}-{}",
                order_id,
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() / 60
            );
            let payouts_vec = vec![(prefixed_wallet.clone(), delivered_kas)];
            match crate::sor::execute_idempotent_mass_physical_settlement(&pool, &idemp_key, &payouts_vec).await {
                Ok(tx_id) => {
                    resolved_tx_hash = tx_id;
                }
                Err(e) => {
                    return Err((
                        StatusCode::BAD_GATEWAY,
                        Json(json!({"error": format!("L1 KAS dispatch failed: {}", e)})),
                    ));
                }
            }
        } else {
            let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
            let _: () = redis::cmd("HINCRBYFLOAT")
                .arg(&user_ledger_key)
                .arg("KAS")
                .arg(delivered_kas)
                .query_async(&mut redis_conn)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": format!("Failed to credit user ledger: {}", e)})),
                    )
                })?;
            if resolved_tx_hash.is_empty() {
                let hex_str = uuid::Uuid::new_v4().simple().to_string().to_uppercase();
                resolved_tx_hash = format!("LEDGER-ONRAMP-{}", &hex_str[..10]);
            }
        }
        sqlx::query(
            "UPDATE fiat_onramp_orders
             SET status = 'COMPLETED', delivered_kas = $2, tx_hash = $3, settlement_target = $4, updated_at = CURRENT_TIMESTAMP
             WHERE order_id = $1",
        )
        .bind(&order_id)
        .bind(delivered_kas)
        .bind(&resolved_tx_hash)
        .bind(&settlement_target)
        .execute(&pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to finalize on-ramp order: {}", e)})),
            )
        })?;
        let effective_unit_basis = if delivered_kas > 0.0 {
            fiat_amount_usd / delivered_kas
        } else {
            execution_spot
        };
        crate::sor::record_hifo_acquisition_lot(
            &pool,
            &clean_wallet,
            "KAS",
            delivered_kas,
            effective_unit_basis,
            "FIAT_ONRAMP",
            Some(&resolved_tx_hash),
        )
        .await;
        let _ = sqlx::query(
            "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash, cost_basis_usd, realized_gain_loss_usd, holding_period)
             VALUES ($1, 'KAS', 'FIAT_ONRAMP', $2, $3, $4, $5, $2, 0.0, 'SHORT_TERM')",
        )
        .bind(&clean_wallet)
        .bind(fiat_amount_usd)
        .bind(delivered_kas)
        .bind(execution_spot)
        .bind(&resolved_tx_hash)
        .execute(&pool)
        .await;
        let netting_order = json!({
            "wallet": "kaspa:treasury_onramp_credit",
            "direction": "BUY_KAS",
            "amount_kas": delivered_kas,
            "spot_price": execution_spot,
            "fee_captured_usd": fee_usd,
            "target_asset": "USD",
            "estimated_output": delivered_kas
        });
        let _: () = redis::cmd("RPUSH")
            .arg("perennia:sor:netting_queue")
            .arg(netting_order.to_string())
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(());
        let sse_event = json!({
            "fiat_event": true,
            "eventType": "FIAT_ONRAMP",
            "status": "COMPLETED",
            "wallet": clean_wallet,
            "sessionId": order_id,
            "assetTicker": "KAS",
            "amountTokens": delivered_kas,
            "fiatAmountUsd": fiat_amount_usd,
            "spotPrice": execution_spot,
            "txHash": resolved_tx_hash
        });
        let _: () = redis::cmd("PUBLISH")
            .arg("telemetry:updates")
            .arg(sse_event.to_string())
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(());
        return Ok(Json(json!({
            "success": true,
            "orderId": order_id,
            "status": "COMPLETED",
            "deliveredKas": delivered_kas,
            "txHash": resolved_tx_hash
        })));
    }
    Err((
        StatusCode::BAD_REQUEST,
        Json(json!({"error": format!("Unsupported fiat action: {}", mode)})),
    ))
}