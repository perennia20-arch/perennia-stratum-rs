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
    ticker: Option<String>,
    steeringState: Option<String>,
    targetWeightPct: Option<f64>,
    subsystem: Option<String>,
    paused: Option<bool>,
    enabled: Option<bool>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct L1PayoutAdminReq {
    action: String,
    payoutId: String,
    txHash: Option<String>,
}

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
        .route("/v1/admin/netting-cycle", post(handle_force_netting_cycle))
        .route("/v1/admin/netting-lab", post(handle_netting_lab))
}

async fn handle_force_netting_cycle(
    headers: HeaderMap,
    State(pool): State<PgPool>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    verify_internal_admin_headers(&headers)?;
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let client = redis::Client::open(redis_url).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Redis client error: {}", e)})),
        )
    })?;
    match crate::chronos::run_delta_netting_cycle(&client, &pool).await {
        Ok(receipt) => Ok(Json(json!({
            "success": true,
            "action": "FORCE_NETTING_CYCLE",
            "batchReceipt": receipt
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Netting cycle failed: {}", e)})),
        )),
    }
}

async fn handle_netting_lab(
    headers: HeaderMap,
    State(pool): State<PgPool>,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    verify_internal_admin_headers(&headers)?;
    if payload
        .get("labCohortTag")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        != "PERENNIA_NETTING_MATH_V5"
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid labCohortTag."})),
        ));
    }
    let action = payload.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let master_clean = crate::chronos::resolve_master_treasury_address();
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let r_client = redis::Client::open(redis_url)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;
    let mut r_conn = r_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;

    if action == "SEED_COHORT" {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "NON_CUSTODIAL_L1_ONLY",
                "message": "Synthetic yield_reservoirs cohort seeding is retired. Register real Kaspa L1 Vault Locks via REGISTER_VAULT_LOCK."
            })),
        ));
    }

    if action == "INSPECT_COHORT" {
        let empty_w = vec![];
        let wallets = payload
            .get("wallets")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty_w);
        let mut pref_list: Vec<String> = Vec::new();
        let mut clean_list: Vec<String> = Vec::new();
        for w in wallets {
            if let Some(ws) = w.as_str() {
                let c = ws
                    .trim()
                    .to_lowercase()
                    .replace("kaspa:", "")
                    .trim()
                    .to_string();
                if !c.is_empty() {
                    pref_list.push(format!("kaspa:{}", c));
                    clean_list.push(c);
                }
            }
        }
        let vault_rows = sqlx::query(
            r#"
            SELECT vault_id, clean_wallet, vault_kind, covenant_address, target_asset, target_network,
                   threshold_sompi::NUMERIC(39,0)::TEXT AS threshold_sompi,
                   confirmed_utxo_sompi::NUMERIC(39,0)::TEXT AS confirmed_utxo_sompi,
                   status
            FROM vault_locks
            WHERE clean_wallet = ANY($1) OR wallet_address = ANY($2)
            "#,
        )
        .bind(&clean_list)
        .bind(&pref_list)
        .fetch_all(&pool)
        .await
        .unwrap_or_default();

        let vaults: Vec<Value> = vault_rows
            .into_iter()
            .map(|r| {
                json!({
                    "vaultId": r.try_get::<String, _>("vault_id").unwrap_or_default(),
                    "cleanWallet": r.try_get::<String, _>("clean_wallet").unwrap_or_default(),
                    "vaultKind": r.try_get::<String, _>("vault_kind").unwrap_or_default(),
                    "covenantAddress": r.try_get::<String, _>("covenant_address").unwrap_or_default(),
                    "targetAsset": r.try_get::<String, _>("target_asset").unwrap_or_default(),
                    "targetNetwork": r.try_get::<String, _>("target_network").unwrap_or_default(),
                    "thresholdSompi": r.try_get::<String, _>("threshold_sompi").unwrap_or_else(|_| "0".to_string()),
                    "confirmedUtxoSompi": r.try_get::<String, _>("confirmed_utxo_sompi").unwrap_or_else(|_| "0".to_string()),
                    "status": r.try_get::<String, _>("status").unwrap_or_default()
                })
            })
            .collect();

        let accrual_rows = sqlx::query(
            r#"
            SELECT clean_wallet,
                   immature_sompi::NUMERIC(39,0)::TEXT AS immature_sompi,
                   unpaid_mature_sompi::NUMERIC(39,0)::TEXT AS unpaid_mature_sompi,
                   lifetime_flushed_sompi::NUMERIC(39,0)::TEXT AS lifetime_flushed_sompi
            FROM stratum_mature_accruals
            WHERE clean_wallet = ANY($1)
            "#,
        )
        .bind(&clean_list)
        .fetch_all(&pool)
        .await
        .unwrap_or_default();
        let accruals: Vec<Value> = accrual_rows
            .into_iter()
            .map(|r| {
                json!({
                    "cleanWallet": r.try_get::<String, _>("clean_wallet").unwrap_or_default(),
                    "immatureSompi": r.try_get::<String, _>("immature_sompi").unwrap_or_else(|_| "0".to_string()),
                    "unpaidMatureSompi": r.try_get::<String, _>("unpaid_mature_sompi").unwrap_or_else(|_| "0".to_string()),
                    "lifetimeFlushedSompi": r.try_get::<String, _>("lifetime_flushed_sompi").unwrap_or_else(|_| "0".to_string())
                })
            })
            .collect();

        let solvency = crate::chronos::evaluate_pool_solvency_invariant(&pool)
            .await
            .map(|s| serde_json::to_value(s).unwrap_or_else(|_| json!({})))
            .unwrap_or_else(|e| json!({ "error": e }));
        let rfq_len: i64 = redis::cmd("HLEN")
            .arg(crate::chronos::REDIS_KEY_CHRONOS_RFQ_BATCHES)
            .query_async(&mut r_conn)
            .await
            .unwrap_or(0);
        return Ok(Json(json!({
            "success": true,
            "vaultLocks": vaults,
            "stratumMatureAccruals": accruals,
            "solvencySnapshot": solvency,
            "redis": {
                "activeChronosRfqBatches": rfq_len
            }
        })));
    }

    if action == "TEARDOWN_COHORT" || action == "PURGE_COHORT" {
        let empty_w = vec![];
        let wallets = payload
            .get("wallets")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty_w);
        let mut pref_list: Vec<String> = Vec::new();
        let mut clean_list: Vec<String> = Vec::new();
        for w in wallets {
            if let Some(ws) = w.as_str() {
                let c = ws
                    .trim()
                    .to_lowercase()
                    .replace("kaspa:", "")
                    .trim()
                    .to_string();
                if !c.is_empty() && c != master_clean {
                    pref_list.push(format!("kaspa:{}", c));
                    clean_list.push(c);
                }
            }
        }
        let kas_usd_e8 = crate::state_api::resolve_strict_spot_price_e8(&pool, "KAS")
            .await
            .map_err(|e| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": e })),
                )
            })?;
        let _ = crate::chronos::publish_live_epoch_bucket_telemetry(&pool, 0.0).await;
        return Ok(Json(json!({
            "success": true,
            "checkedWallets": pref_list.len(),
            "kasSpotUsdE8": kas_usd_e8.to_string()
        })));
    }

    Err((
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "Unsupported netting-lab action."})),
    ))
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
        "system_treasury_config",
        "user_cold_vault_rules",
        "worker_profiles",
        "stratum_mature_accruals",
        "epoch_payout_outbox",
        "vault_locks",
        "thermostat_valves",
        "settlement_receipts",
        "solvency_circuit_events",
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
        "fiat_float_ledger",
        "fiat_post_trade_sweeps",
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
        "token_steering_matrix",
        "security_firewall_blacklist",
        "director_audit_log",
        "corporate_expense_vouchers",
        "corporate_owner_draws",
        "agent_api_keys",
        "agent_execution_receipts",
        "agent_x402_credits",
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
            let remaining_secs =
                crate::stratum_tcp::BAN_DURATION_SECS.saturating_sub(elapsed.as_secs());
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
    State(pool): State<PgPool>,
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
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    if action == "UNBAN" || action == "REMOVE" {
        crate::stratum_tcp::BANNED_IPS.remove(&clean_ip);
        crate::stratum_tcp::STRIKE_COUNTERS.remove(&clean_ip);
        let _ = sqlx::query(
            "UPDATE security_firewall_blacklist SET active = FALSE, updated_at = CURRENT_TIMESTAMP WHERE LOWER(target_value) = LOWER($1)",
        )
        .bind(&clean_ip)
        .execute(&pool)
        .await;
        if let Ok(r_client) = redis::Client::open(redis_url) {
            if let Ok(mut r_conn) = r_client.get_multiplexed_async_connection().await {
                let _: redis::RedisResult<()> = redis::cmd("SREM")
                    .arg("perennia:firewall:blacklisted_ips")
                    .arg(&clean_ip)
                    .query_async(&mut r_conn)
                    .await;
            }
        }
        Ok(Json(json!({
            "success": true,
            "action": "UNBANNED",
            "ip": clean_ip
        })))
    } else {
        crate::stratum_tcp::BANNED_IPS.insert(clean_ip.clone(), Instant::now());
        crate::stratum_tcp::STRIKE_COUNTERS.remove(&clean_ip);
        let _ = sqlx::query(
            r#"
            INSERT INTO security_firewall_blacklist (entity_type, target_value, reason, active, added_by)
            VALUES ('IP', $1, 'Director Stratum Shield Ban', TRUE, 'DIRECTOR')
            ON CONFLICT (target_value) DO UPDATE SET active = TRUE, updated_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(&clean_ip)
        .execute(&pool)
        .await;
        if let Ok(r_client) = redis::Client::open(redis_url) {
            if let Ok(mut r_conn) = r_client.get_multiplexed_async_connection().await {
                let _: redis::RedisResult<()> = redis::cmd("SADD")
                    .arg("perennia:firewall:blacklisted_ips")
                    .arg(&clean_ip)
                    .query_async(&mut r_conn)
                    .await;
            }
        }
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
    let label = req
        .label
        .unwrap_or_else(|| "Director Whitelisted".to_string());
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
        let explorer_url =
            crate::state_api::build_explorer_tx_url(&asset_ticker, &resolved_tx_hash);
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
        let Some(refund_tx_hash) = req
            .txHash
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
        else {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error": "NON_CUSTODIAL_L1_ONLY",
                    "message": "Custodial ledger refunds are retired. Supply an on-chain refund txHash settled directly to the user's self-custodial wallet."
                })),
            ));
        };
        let _ = sqlx::query(
            "UPDATE l1_payout_queue SET status = 'REFUNDED_ONCHAIN_TO_USER', tx_hash = $2, updated_at = CURRENT_TIMESTAMP WHERE payout_id = $1",
        )
        .bind(&payout_id)
        .bind(&refund_tx_hash)
        .execute(&pool)
        .await;
        let _ = (gross_usd, spot_price);
        let sse_evt = json!({
            "l1_event": true,
            "fiat_event": true,
            "eventType": "L1_REFUND",
            "wallet": clean_wallet,
            "payoutId": payout_id,
            "assetTicker": asset_ticker,
            "amountTokens": amount_tokens,
            "txHash": refund_tx_hash
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
        let _ = crate::sor::record_hifo_acquisition_lot(
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
        let Some(refund_tx_hash) = req
            .txHash
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
        else {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error": "NON_CUSTODIAL_L1_ONLY",
                    "message": "Custodial passthrough ledger refunds are retired. Supply an on-chain refund txHash."
                })),
            ));
        };
        let _ = (upfront_fee_kas, live_kas_spot, spot_price);
        let sse_event = json!({
            "fiat_event": true,
            "eventType": "PASSTHROUGH_REFUND",
            "wallet": clean_wallet,
            "assetTicker": "KAS",
            "amountKas": gross_kas,
            "txHash": refund_tx_hash
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
            "txHash": refund_tx_hash
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

    if mode == "SET_TOKEN_STEERING_STATE" || mode == "UPSERT_STEERING_TOKEN" {
        let ticker = req
            .ticker
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_uppercase();
        let next_state = req
            .steeringState
            .as_deref()
            .unwrap_or("AUTO_BALANCE")
            .trim()
            .to_uppercase();
        if ticker.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "ticker is required for SET_TOKEN_STEERING_STATE"})),
            ));
        }
        let is_whitelisted = next_state == "AUTO_BALANCE"
            || next_state == "ACCUMULATE"
            || next_state == "FREEZE";
        let target_weight = req.targetWeightPct.unwrap_or(5.0).clamp(0.0, 100.0);
        let _ = sqlx::query(
            r#"
            INSERT INTO token_steering_matrix (ticker, asset_name, steering_state, is_whitelisted, target_weight_pct, updated_at)
            VALUES ($1, $1, $2, $3, $4, CURRENT_TIMESTAMP)
            ON CONFLICT (ticker) DO UPDATE SET
                steering_state = EXCLUDED.steering_state,
                is_whitelisted = EXCLUDED.is_whitelisted,
                target_weight_pct = EXCLUDED.target_weight_pct,
                updated_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(&ticker)
        .bind(&next_state)
        .bind(is_whitelisted)
        .bind(target_weight)
        .execute(&pool)
        .await;

        let mut pipe = redis::pipe();
        pipe.cmd("HSET")
            .arg("perennia:steering:token_states")
            .arg(&ticker)
            .arg(&next_state)
            .ignore();

        if next_state == "BLACKLISTED" {
            pipe.cmd("SREM")
                .arg("perennia:steering:whitelist")
                .arg(&ticker)
                .ignore();
            pipe.cmd("SADD")
                .arg("perennia:firewall:blacklisted_tokens")
                .arg(&ticker)
                .ignore();
        } else if is_whitelisted {
            pipe.cmd("SADD")
                .arg("perennia:steering:whitelist")
                .arg(&ticker)
                .ignore();
            pipe.cmd("SREM")
                .arg("perennia:firewall:blacklisted_tokens")
                .arg(&ticker)
                .ignore();
        } else {
            pipe.cmd("SREM")
                .arg("perennia:steering:whitelist")
                .arg(&ticker)
                .ignore();
            pipe.cmd("SREM")
                .arg("perennia:firewall:blacklisted_tokens")
                .arg(&ticker)
                .ignore();
        }

        let _: redis::RedisResult<()> = pipe.query_async(&mut redis_conn).await;

        return Ok(Json(json!({
            "success": true,
            "action": "SET_TOKEN_STEERING_STATE",
            "ticker": ticker,
            "steeringState": next_state,
            "isWhitelisted": is_whitelisted
        })));
    }

    if mode == "TOGGLE_MAINTENANCE_GRACE_SHIELD" {
        let next_enabled = req.enabled.unwrap_or(true);
        let _: redis::RedisResult<()> = redis::cmd("SET")
            .arg("perennia:stratum:maintenance_grace_shield")
            .arg(if next_enabled { "1" } else { "0" })
            .query_async(&mut redis_conn)
            .await;
        return Ok(Json(json!({
            "success": true,
            "action": "TOGGLE_MAINTENANCE_GRACE_SHIELD",
            "maintenanceGraceShield": next_enabled
        })));
    }

    if mode == "TOGGLE_SUBSYSTEM_KILLSWITCH" {
        let sub = req
            .subsystem
            .as_deref()
            .unwrap_or("fiat_onramp")
            .trim()
            .to_lowercase();
        let paused = req.paused.unwrap_or(true);
        let key = format!("perennia:killswitch:{}", sub);
        let _: redis::RedisResult<()> = redis::cmd("SET")
            .arg(&key)
            .arg(if paused { "1" } else { "0" })
            .query_async(&mut redis_conn)
            .await;
        if sub == "agent" || sub == "agent_gateway" {
            if paused {
                let _: redis::RedisResult<()> = redis::cmd("SET")
                    .arg("perennia:agent:circuit_breaker")
                    .arg("MANUAL_DIRECTOR_KILLSWITCH")
                    .query_async(&mut redis_conn)
                    .await;
            } else {
                let _: redis::RedisResult<()> = redis::cmd("DEL")
                    .arg("perennia:agent:circuit_breaker")
                    .query_async(&mut redis_conn)
                    .await;
            }
        }
        return Ok(Json(json!({
            "success": true,
            "action": "TOGGLE_SUBSYSTEM_KILLSWITCH",
            "subsystem": sub,
            "paused": paused
        })));
    }

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
            "SELECT payout_id, wallet_address, net_fiat_usd FROM fiat_payout_queue WHERE status = 'QUEUED_FOR_TREASURY_DISPATCH' ORDER BY created_at ASC",
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
                "UPDATE fiat_payout_queue SET status = 'DISPATCHED_BY_DIRECTOR', trace_id = $2, updated_at = CURRENT_TIMESTAMP WHERE payout_id = $1 AND status = 'QUEUED_FOR_TREASURY_DISPATCH'",
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
        let Some(refund_tx_hash) = req
            .txHash
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
        else {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error": "NON_CUSTODIAL_L1_ONLY",
                    "message": "Custodial ledger fiat refunds are retired. Provide an on-chain refund txHash settled directly to the user's self-custodial wallet."
                })),
            ));
        };
        let row_opt = sqlx::query(
            "SELECT wallet_address, source_asset, amount_crypto, status FROM fiat_payout_queue WHERE payout_id = $1 LIMIT 1",
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
        let clean_wallet = wallet_address
            .trim()
            .to_lowercase()
            .replace("kaspa:", "");
        sqlx::query(
            "UPDATE fiat_payout_queue SET status = 'REFUNDED_ONCHAIN_TO_USER', tx_id = $2, updated_at = CURRENT_TIMESTAMP WHERE payout_id = $1",
        )
        .bind(&payout_id)
        .bind(&refund_tx_hash)
        .execute(&pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to update payout status: {}", e)})),
            )
        })?;
        let sse_event = json!({
            "fiat_event": true,
            "eventType": "FIAT_REFUND",
            "wallet": clean_wallet,
            "payoutId": payout_id,
            "assetTicker": source_asset,
            "amountTokens": amount_crypto,
            "txHash": refund_tx_hash
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
            "status": "REFUNDED_ONCHAIN_TO_USER",
            "txHash": refund_tx_hash,
            "refundedAsset": source_asset,
            "refundedAmount": amount_crypto
        })));
    }

    if mode == "FULFILL_FIAT_ONRAMP"
        || mode == "CONFIRM_INSTITUTIONAL_WIRE"
        || mode == "RELEASE_QUARANTINED_STRIPE_ORDER"
        || mode == "REFUND_QUARANTINED_STRIPE_ORDER"
        || mode == "CANCEL_FIAT_ONRAMP"
    {
        let order_id = req.orderId.as_deref().unwrap_or("").trim().to_string();
        if order_id.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "orderId is required"})),
            ));
        }
        let row_opt = sqlx::query(
            r#"
            SELECT wallet_address, settlement_target, COALESCE(target_asset, 'KAS') AS target_asset,
                   fiat_amount_usd, fee_usd, net_usd_converted, locked_spot_price, estimated_kas,
                   COALESCE(quoted_principal_cents, 0) AS quoted_principal_cents,
                   COALESCE(perennia_fee_cents, 250) AS perennia_fee_cents,
                   settled_net_cents, status
            FROM fiat_onramp_orders
            WHERE order_id = $1
            LIMIT 1
            "#,
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

        if mode == "CANCEL_FIAT_ONRAMP" || mode == "REFUND_QUARANTINED_STRIPE_ORDER" {
            let new_st = if mode == "REFUND_QUARANTINED_STRIPE_ORDER" {
                "REFUNDED_BY_DIRECTOR"
            } else {
                "CANCELLED"
            };
            let _ = sqlx::query(
                "UPDATE fiat_onramp_orders SET status = $2, updated_at = CURRENT_TIMESTAMP WHERE order_id = $1",
            )
            .bind(&order_id)
            .bind(new_st)
            .execute(&pool)
            .await;
            return Ok(Json(json!({
                "success": true,
                "orderId": order_id,
                "status": new_st
            })));
        }

        let target_asset: String = row
            .try_get("target_asset")
            .unwrap_or_else(|_| "KAS".to_string())
            .to_uppercase();
        let fiat_amount_usd: f64 = row.try_get("fiat_amount_usd").unwrap_or(0.0);
        let fee_usd: f64 = row.try_get("fee_usd").unwrap_or(0.0);
        let raw_net_usd: f64 = row.try_get("net_usd_converted").unwrap_or(0.0);
        let locked_spot_price: f64 = row.try_get("locked_spot_price").unwrap_or(0.0);
        let quoted_principal_cents: i64 = row.try_get("quoted_principal_cents").unwrap_or(0);
        let perennia_fee_cents: i64 = row.try_get("perennia_fee_cents").unwrap_or(250).max(250);
        let settled_net_cents_opt: Option<i64> = row.try_get("settled_net_cents").ok().flatten();

        let net_usd_converted = if let Some(settled_net) = settled_net_cents_opt {
            let qp = if quoted_principal_cents > 0 {
                quoted_principal_cents
            } else {
                (raw_net_usd * 100.0).round() as i64
            };
            let capped = qp.min((settled_net - perennia_fee_cents).max(0));
            (capped as f64) / 100.0
        } else {
            raw_net_usd
        };

        if net_usd_converted <= 0.0 {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": "ZERO_LOSS_LOCK: Safe fulfilled principal after locking Perennia fee is $0.00."})),
            ));
        }

        let live_spot_str: Option<String> = redis::cmd("GET")
            .arg(format!("oracle:spot:{}_USDC", target_asset))
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(None);
        let execution_spot = if target_asset == "USDC" || target_asset == "USDT" {
            1.0
        } else {
            live_spot_str
                .and_then(|s| s.parse::<f64>().ok())
                .filter(|&v| v > 0.0)
                .unwrap_or(locked_spot_price)
        };
        if execution_spot <= 0.0 {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": format!("ORACLE_HALT: Live {}/USDC spot price is unavailable and order has no valid locked spot price.", target_asset)})),
            ));
        }
        let delivered_tokens =
            ((net_usd_converted / execution_spot) * 10000.0).round() / 10000.0;
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
        if settlement_target == "L1_KAS" && target_asset == "KAS" {
            let idemp_key = format!(
                "FIAT-ONRAMP-L1-{}-{}",
                order_id,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    / 60
            );
            let sompi_u64 = (delivered_tokens.max(0.0) * 100_000_000.0).round() as u64;
            let payouts_vec = vec![(prefixed_wallet.clone(), sompi_u64)];
            match crate::sor::execute_idempotent_mass_physical_settlement(
                &pool,
                &idemp_key,
                &payouts_vec,
            )
            .await
            {
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
        } else if resolved_tx_hash.is_empty() {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error": "NON_CUSTODIAL_L1_ONLY",
                    "message": "Custodial synthetic ledger credits are retired. Use settlementTarget=L1_KAS or supply an on-chain dropship txHash."
                })),
            ));
        }
        sqlx::query(
            "UPDATE fiat_onramp_orders
             SET status = 'COMPLETED', delivered_kas = $2, estimated_tokens = $2, tx_hash = $3, settlement_target = $4, updated_at = CURRENT_TIMESTAMP
             WHERE order_id = $1",
        )
        .bind(&order_id)
        .bind(delivered_tokens)
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
        let effective_unit_basis = if delivered_tokens > 0.0 {
            fiat_amount_usd / delivered_tokens
        } else {
            execution_spot
        };
        let _ = crate::sor::record_hifo_acquisition_lot(
            &pool,
            &clean_wallet,
            &target_asset,
            delivered_tokens,
            effective_unit_basis,
            "FIAT_ONRAMP",
            Some(&resolved_tx_hash),
        )
        .await;
        let _ = sqlx::query(
            "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash, cost_basis_usd, realized_gain_loss_usd, holding_period)
             VALUES ($1, $2, 'FIAT_ONRAMP', $3, $4, $5, $6, $3, 0.0, 'SHORT_TERM')",
        )
        .bind(&clean_wallet)
        .bind(&target_asset)
        .bind(fiat_amount_usd)
        .bind(delivered_tokens)
        .bind(execution_spot)
        .bind(&resolved_tx_hash)
        .execute(&pool)
        .await;
        let netting_order = json!({
            "wallet": "kaspa:treasury_onramp_credit",
            "direction": "BUY_KAS",
            "amount_kas": delivered_tokens,
            "spot_price": execution_spot,
            "fee_captured_usd": fee_usd,
            "target_asset": "USD",
            "estimated_output": delivered_tokens
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
            "assetTicker": target_asset,
            "amountTokens": delivered_tokens,
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
            "deliveredKas": delivered_tokens,
            "deliveredTokens": delivered_tokens,
            "targetAsset": target_asset,
            "txHash": resolved_tx_hash
        })));
    }

    Err((
        StatusCode::BAD_REQUEST,
        Json(json!({"error": format!("Unsupported fiat action: {}", mode)})),
    ))
}