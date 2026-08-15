// src/main.rs
mod config;
mod stratum_tcp;
mod telemetry;
mod kaspad_client;
mod job_manager; 
mod diff_engine; 
mod oracle;
mod sor; 
mod chronos; 
mod state_api; 

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use axum::{routing::post, Router};
use sqlx::postgres::PgPoolOptions;
use job_manager::JobManager;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to init tracing");

    tracing::info!("Booting Perennia Core Engine (Hybrid Mainnet + Stratum)...");

    let config = Arc::new(config::StratumConfig::load("config.yaml")?);
    tracing::info!("Targeted Treasury Wallet: {}", config.mining_address);

    tracing::info!("Initializing PostgreSQL Pool...");
    
    // ⚡ INFRASTRUCTURE HARDENING
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://postgres:password@127.0.0.1:5432/perennia".to_string());
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&db_url)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to connect to PostgreSQL (Ensure DB is running): {}", e);
            panic!("Database connection required for routing dependencies: {}", e);
        });

    let pool_chronos = pool.clone();
    tokio::spawn(async move {
        chronos::start_chronos_daemon(pool_chronos).await;
    });

    if let Ok(redis_client_netting) = redis::Client::open(redis_url.clone()) {
        tokio::spawn(async move {
            chronos::start_delta_netting_engine(redis_client_netting).await;
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

    let (job_manager_arc, _job_rx, block_submit_rx) = JobManager::new();

    let config_clone = config.clone();
    let jm_clone = job_manager_arc.clone();
    
    tokio::spawn(async move {
        if let Err(e) = kaspad_client::start_kaspad_client(config_clone, jm_clone, block_submit_rx).await {
            tracing::error!("Kaspa gRPC Connection Failed: {}", e);
        }
    });

    let app = Router::new()
        .route("/v1/sor/execute", post(sor::handle_sor_execute))
        .route("/v1/state/action", post(state_api::handle_state_action))
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8002").await?;
    tokio::spawn(async move {
        tracing::info!("🚀 Axum HTTP Server bound instantly on port 8002 (SOR & State API Armed)");
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("Axum Server Error: {}", e);
        }
    });

    let cfg_t1 = config.clone();
    let jm_t1 = job_manager_arc.clone();
    let tx_t1 = valid_share_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = stratum_tcp::start_stratum_server(cfg_t1, jm_t1, tx_t1, 5551, 1.0, 0).await {
            tracing::error!("Tier 1 (GPU) failed: {}", e);
        }
    });

    let cfg_t2 = config.clone();
    let jm_t2 = job_manager_arc.clone();
    let tx_t2 = valid_share_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = stratum_tcp::start_stratum_server(cfg_t2, jm_t2, tx_t2, 5552, 256.0, 2500).await {
            tracing::error!("Tier 2 (Home ASICs) failed: {}", e);
        }
    });

    let cfg_t3 = config.clone();
    let jm_t3 = job_manager_arc.clone();
    let tx_t3 = valid_share_tx.clone();
    
    stratum_tcp::start_stratum_server(cfg_t3, jm_t3, tx_t3, 5553, 1024.0, 3000).await?;

    Ok(())
}