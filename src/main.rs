mod config;
mod schema;
mod stratum_tcp;
mod telemetry;
mod kaspad_client;
mod job_manager;
mod diff_engine;
mod oracle;
mod sor;
mod chronos;
mod state_api;
mod admin_api;
mod fiat_rails;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use axum::{
    extract::{Query, Request},
    http::{StatusCode, HeaderMap},
    middleware::{self, Next},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use job_manager::JobManager;

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

async fn internal_auth_guard(
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let internal_token = std::env::var("INTERNAL_ADMIN_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let admin_key = std::env::var("PERENNIA_ADMIN_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let has_configured_secret = internal_token.is_some() || admin_key.is_some();
    let enforce_strict = std::env::var("ENFORCE_INTERNAL_AUTH")
        .ok()
        .map(|v| !v.trim().eq_ignore_ascii_case("false"))
        .unwrap_or(true);

    if enforce_strict {
        if !has_configured_secret {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": "CRITICAL_SECURITY_LOCKDOWN: INTERNAL_ADMIN_TOKEN or PERENNIA_ADMIN_KEY must be configured in .env."
                })),
            ));
        }

        let provided = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let mut authorized = false;

        if let Some(ref tok) = internal_token {
            let expected = format!("Bearer {}", tok);
            if constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
                authorized = true;
            }
        }
        if !authorized {
            if let Some(ref key) = admin_key {
                let expected = format!("Bearer {}", key);
                if constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
                    authorized = true;
                }
            }
        }
        if !authorized {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "UNAUTHORIZED_INTERNAL_RPC" })),
            ));
        }
    }

    Ok(next.run(request).await)
}

async fn handle_get_balance(
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let raw_address = params
        .get("address")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Missing address query parameter." })),
            )
        })?;
    let clean_addr = raw_address.to_lowercase().replace("kaspa:", "");
    let formatted_addr = format!("kaspa:{}", clean_addr);

    if let Ok(sompi) = kaspad_client::get_balance_by_address_grpc(&formatted_addr).await {
        let balance_kas = (sompi as f64) / 100_000_000.0;
        return Ok(Json(json!({
            "balance": balance_kas,
            "balanceKas": balance_kas,
            "source": "kaspad_grpc"
        })));
    }

    let rest_url = std::env::var("KASPA_REST_URL")
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .unwrap_or_else(|_| "https://api.kaspa.org".to_string());
    let endpoint = format!("{}/addresses/{}/balance", rest_url, formatted_addr);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let response = client.get(&endpoint).send().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": format!("Upstream node balance query failed: {}", e) })),
        )
    })?;
    if !response.status().is_success() {
        let err_body = response.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": format!("Node rejected balance lookup: {}", err_body) })),
        ));
    }
    let data: Value = response.json().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Invalid JSON from upstream node: {}", e) })),
        )
    })?;
    let sompi = data
        .get("balance")
        .and_then(|v| {
            v.as_f64()
                .or_else(|| v.as_u64().map(|u| u as f64))
                .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
        })
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Malformed balance payload from node." })),
            )
        })?;
    let balance_kas = sompi / 100_000_000.0;
    Ok(Json(json!({
        "balance": balance_kas,
        "balanceKas": balance_kas,
        "source": "rest_fallback"
    })))
}

async fn handle_get_utxos(
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let raw_address = params
        .get("address")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Missing address query parameter." })),
            )
        })?;
    let clean_addr = raw_address.to_lowercase().replace("kaspa:", "");
    let formatted_addr = format!("kaspa:{}", clean_addr);

    if let Ok(entries) = kaspad_client::get_utxos_by_address_grpc(&formatted_addr).await {
        return Ok(Json(json!({
            "entries": entries,
            "source": "kaspad_grpc"
        })));
    }

    let rest_url = std::env::var("KASPA_REST_URL")
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .unwrap_or_else(|_| "https://api.kaspa.org".to_string());
    let endpoint = format!("{}/addresses/{}/utxos", rest_url, formatted_addr);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(6))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let response = client.get(&endpoint).send().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": format!("Upstream node UTXO query failed: {}", e) })),
        )
    })?;
    if !response.status().is_success() {
        let err_body = response.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": format!("Node rejected UTXO lookup: {}", err_body) })),
        ));
    }
    let entries: Value = response.json().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Invalid UTXO JSON from upstream node: {}", e) })),
        )
    })?;
    Ok(Json(json!({
        "entries": entries,
        "source": "rest_fallback"
    })))
}

async fn handle_post_broadcast(
    Json(payload): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match kaspad_client::submit_transaction_grpc(&payload, false).await {
        Ok(tx_id) => {
            return Ok(Json(json!({
                "success": true,
                "transactionId": tx_id,
                "source": "kaspad_grpc"
            })));
        }
        Err(grpc_err) => {
            tracing::warn!(
                "⚠️ [LOCAL GRPC BROADCAST] /v1/broadcast gRPC attempt failed ({}); falling back to REST...",
                grpc_err
            );
        }
    }

    let rest_url = std::env::var("KASPA_REST_URL")
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .unwrap_or_else(|_| "https://api.kaspa.org".to_string());
    let endpoint = format!("{}/transactions", rest_url);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let rest_payload = if payload.get("transaction").is_some() {
        payload
    } else {
        json!({ "transaction": payload })
    };
    let response = client.post(&endpoint).json(&rest_payload).send().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": format!("Broadcast network error: {}", e) })),
        )
    })?;
    if !response.status().is_success() {
        let err_body = response.text().await.unwrap_or_default();
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": format!("Node rejected transaction broadcast: {}", err_body) })),
        ));
    }
    let data: Value = response.json().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Invalid broadcast JSON response: {}", e) })),
        )
    })?;
    let tx_id = data
        .get("transactionId")
        .or_else(|| data.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Node returned no transactionId." })),
            )
        })?;
    Ok(Json(json!({
        "success": true,
        "transactionId": tx_id,
        "source": "rest_fallback"
    })))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to init tracing");
    tracing::info!("Booting Perennia Core Engine (Hybrid Mainnet + Stratum)...");

    let mut raw_config = config::StratumConfig::load("config.yaml")?;

    if let Some(env_mining_addr) = chronos::resolve_hot_dispatcher_address()
        .or_else(|| chronos::resolve_master_treasury_prefixed().ok())
    {
        raw_config.mining_address = env_mining_addr;
    }

    let config = Arc::new(raw_config);
    tracing::info!("Targeted Treasury / Stratum Coinbase Wallet: {}", config.mining_address);

    let db_url = std::env::var("DATABASE_URL")
        .expect("CRITICAL: DATABASE_URL environment variable is required.");
    let redis_url = std::env::var("REDIS_URL")
        .expect("CRITICAL: REDIS_URL environment variable is required.");

    let pool = PgPoolOptions::new()
        .max_connections(50)
        .connect(&db_url)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to connect to PostgreSQL (Ensure DB is running): {}", e);
            panic!("Database connection required for routing dependencies: {}", e);
        });

    schema::ensure_database_schema(&pool).await?;

    let (daa_tx, _) = tokio::sync::broadcast::channel::<u64>(100);
    let (utxo_tx, _) =
        tokio::sync::broadcast::channel::<kaspad_client::protowire::UtxosChangedNotificationMessage>(
            1000,
        );

    let pool_chronos = pool.clone();
    tokio::spawn(async move {
        chronos::start_chronos_daemon(pool_chronos).await;
    });

    let pool_watcher = pool.clone();
    let daa_rx = daa_tx.subscribe();
    let utxo_rx = utxo_tx.subscribe();
    tokio::spawn(async move {
        chronos::start_mempool_watcher_daemon(pool_watcher, daa_rx, utxo_rx).await;
    });

    let utxo_rx_cons = utxo_tx.subscribe();
    tokio::spawn(async move {
        chronos::start_utxo_consolidation_daemon(utxo_rx_cons).await;
    });

    let pool_airlock = pool.clone();
    tokio::spawn(async move {
        chronos::start_hot_cold_airlock_daemon(pool_airlock).await;
    });

    let pool_recovery = pool.clone();
    tokio::spawn(async move {
        chronos::start_idempotent_payout_recovery_daemon(pool_recovery).await;
    });

    if let Ok(redis_client_netting) = redis::Client::open(redis_url.clone()) {
        let pool_netting = pool.clone();
        tokio::spawn(async move {
            chronos::start_delta_netting_engine(redis_client_netting, pool_netting).await;
        });
    }

    telemetry::init_telemetry();
    let prom_port = config.prom_port.clone();
    tokio::spawn(async move {
        telemetry::start_prometheus_exporter(prom_port).await;
    });

    let (valid_share_tx, valid_share_rx) = mpsc::channel::<(String, f64, bool)>(10000);
    tokio::spawn(async move {
        telemetry::start_accounting_engine(valid_share_rx).await;
    });

    tokio::spawn(async move {
        oracle::start_oracle_daemon().await;
    });

    tokio::spawn(async move {
        oracle::start_spot_pricing_daemon().await;
    });

    let pool_pyth = pool.clone();
    tokio::spawn(async move {
        oracle::start_pyth_rwa_oracle_daemon(pool_pyth).await;
    });

    let (job_manager_arc, _job_rx, block_submit_rx) = JobManager::new();
    let config_clone = config.clone();
    let jm_clone = job_manager_arc.clone();
    let daa_tx_clone = daa_tx.clone();
    let utxo_tx_clone = utxo_tx.clone();
    let share_tx_kaspad = valid_share_tx.clone();

    tokio::spawn(async move {
        if let Err(e) = kaspad_client::start_kaspad_client(
            config_clone,
            jm_clone,
            block_submit_rx,
            share_tx_kaspad,
            daa_tx_clone,
            utxo_tx_clone,
        )
        .await
        {
            tracing::error!("Kaspa gRPC Connection Fatal Error: {}", e);
        }
    });

    let protected_routes = Router::new()
        .route("/v1/sor/execute", post(sor::handle_sor_execute))
        .route("/v1/state/action", post(state_api::handle_state_action))
        .route_layer(middleware::from_fn(internal_auth_guard));

    let app = Router::new()
        .route("/v1/balance", get(handle_get_balance))
        .route("/v1/utxos", get(handle_get_utxos))
        .route("/v1/broadcast", post(handle_post_broadcast))
        .merge(protected_routes)
        .merge(admin_api::admin_routes())
        .merge(fiat_rails::fiat_routes())
        .with_state(pool.clone());

    let bind_host =
        std::env::var("RUST_BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8002".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_host).await?;
    tokio::spawn(async move {
        tracing::info!(
            "🚀 Axum HTTP Server bound on {} (SOR, State, Fiat, Balance, UTXOs, Broadcast & Admin API Armed)",
            bind_host
        );
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("Axum Server Error: {}", e);
        }
    });

    let cfg_t1 = config.clone();
    let jm_t1 = job_manager_arc.clone();
    let tx_t1 = valid_share_tx.clone();
    let pool_t1 = pool.clone();
    tokio::spawn(async move {
        if let Err(e) =
            stratum_tcp::start_stratum_server(cfg_t1, jm_t1, tx_t1, pool_t1, 6551, 1.0, 0).await
        {
            tracing::error!("Tier 1 (GPU) failed: {}", e);
        }
    });

    let cfg_t2 = config.clone();
    let jm_t2 = job_manager_arc.clone();
    let tx_t2 = valid_share_tx.clone();
    let pool_t2 = pool.clone();
    tokio::spawn(async move {
        if let Err(e) =
            stratum_tcp::start_stratum_server(cfg_t2, jm_t2, tx_t2, pool_t2, 6552, 256.0, 2500)
                .await
        {
            tracing::error!("Tier 2 (Home ASICs) failed: {}", e);
        }
    });

    let cfg_t3 = config.clone();
    let jm_t3 = job_manager_arc.clone();
    let tx_t3 = valid_share_tx.clone();
    let pool_t3 = pool.clone();
    stratum_tcp::start_stratum_server(cfg_t3, jm_t3, tx_t3, pool_t3, 6553, 1024.0, 3000).await?;

    Ok(())
}