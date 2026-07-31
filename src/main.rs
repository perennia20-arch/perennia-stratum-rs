// src/main.rs

use perennia_stratum_rs::{
    api, config, diff_engine, job_manager, kaspad_client, 
    omnichain, oracle, stratum_tcp, telemetry
};

use std::sync::Arc;
use std::env;
use tokio::sync::mpsc;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use job_manager::JobManager;
use deadpool_redis::{Config, Runtime};
use axum::{routing::post, Router};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ⚡ Load environment variables
    dotenvy::dotenv().ok();

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to init tracing");

    // ==============================================================================
    // 🧪 PHASE 1.5 TEST HARNESS: PRINT P2SH COVENANT TO CONSOLE
    // ==============================================================================
    let (test_script, test_addr) = omnichain::scripts::SilverscriptCompiler::compile_test_lock();
    let redeem_hex = test_script.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    
    tracing::info!("==================================================");
    tracing::info!("🧪 TN12 BURN TEST COVENANT COMPILED SUCCESSFULLY");
    tracing::info!("   -> Redeem Script Hex: {}", redeem_hex); // Expected: 014287
    tracing::info!("   -> Target P2SH Address: {}", test_addr);
    tracing::info!("==================================================");
    // ==============================================================================

    tracing::info!("Booting Perennia Multi-Tier Stratum Engine...");

    let config = Arc::new(config::StratumConfig::load("config.yaml")?);
    tracing::info!("Targeted Pool Wallet: {}", config.mining_address);

    telemetry::init_telemetry();
    let prom_port = config.prom_port.clone();
    tokio::spawn(async move {
        telemetry::start_prometheus_exporter(prom_port).await;
    });

    // ⚡ Build the shared Accounting Channel
    let (valid_share_tx, valid_share_rx) = mpsc::channel(10000);

    // ⚡ Spawn the background Redis Ledger Thread (Phase 1 Ingestion)
    tokio::spawn(async move {
        telemetry::start_accounting_engine(valid_share_rx).await;
    });

    // ⚡ Spawn the Persistent Yield Streaming Oracle (PostgreSQL WAL)
    tokio::spawn(async move {
        oracle::start_oracle_daemon().await;
    });

    let (job_manager_arc, _job_rx, block_submit_rx) = JobManager::new();

    let config_clone = config.clone();
    let jm_clone = job_manager_arc.clone();
    
    tokio::spawn(async move {
        if let Err(e) = kaspad_client::start_kaspad_client(config_clone, jm_clone, block_submit_rx).await {
            tracing::error!("Kaspa gRPC Connection Failed: {}", e);
        }
    });

    // ==============================================================================
    // ⚡ AXUM SOR HTTP SERVER WIRING (Port 8082)
    // ==============================================================================
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let redis_cfg = Config::from_url(redis_url);
    let redis_pool = redis_cfg.create_pool(Some(Runtime::Tokio1)).expect("Failed to create Redis pool");
    
    // ⚡ Spawn the External Liquidity Poller (Tier 2/3 Aggregation)
    let poller_pool = redis_pool.clone();
    tokio::spawn(async move {
        omnichain::liquidity_poller::start_liquidity_poller(poller_pool).await;
    });

    let provider = omnichain::initialize_provider().await;
    let sor = Arc::new(omnichain::router::SmartOrderRouter::new(Arc::new(provider), redis_pool));

    let app = Router::new()
        .route("/v1/sor/lock", post(api::sor_lock_handler))
        .with_state(sor);

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:8082").await.unwrap();
        tracing::info!("🚀 Axum SOR HTTP Server listening on 0.0.0.0:8082");
        axum::serve(listener, app).await.unwrap();
    });
    // ==============================================================================

    // ⚡ STRICT REQUIREMENT 1: 3-Tier Tokio Listeners
    
    // Tier 1: GPU/Mobile | Bind: 0.0.0.0:5551 | Diff: 1.0 | Throttle: 0ms
    let cfg_t1 = config.clone();
    let jm_t1 = job_manager_arc.clone();
    let tx_t1 = valid_share_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = stratum_tcp::start_stratum_server(cfg_t1, jm_t1, tx_t1, 5551, 1.0, 0).await {
            tracing::error!("Tier 1 (GPU) failed: {}", e);
        }
    });

    // Tier 2: Home ASICs | Bind: 0.0.0.0:5552 | Diff: 256.0 | Throttle: 2500ms
    let cfg_t2 = config.clone();
    let jm_t2 = job_manager_arc.clone();
    let tx_t2 = valid_share_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = stratum_tcp::start_stratum_server(cfg_t2, jm_t2, tx_t2, 5552, 256.0, 2500).await {
            tracing::error!("Tier 2 (Home ASICs) failed: {}", e);
        }
    });

    // Tier 3: Industrial ASICs | Bind: 0.0.0.0:5553 | Diff: 1024.0 | Throttle: 3000ms
    let cfg_t3 = config.clone();
    let jm_t3 = job_manager_arc.clone();
    let tx_t3 = valid_share_tx.clone();
    
    // Blocking call on the final tier to keep the main thread alive
    stratum_tcp::start_stratum_server(cfg_t3, jm_t3, tx_t3, 5553, 1024.0, 3000).await?;

    Ok(())
}