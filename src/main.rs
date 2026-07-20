mod config;
mod stratum_tcp;
mod telemetry;
mod kaspad_client;
mod job_manager; 
mod diff_engine; 

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use job_manager::JobManager;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to init tracing");

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

    // ⚡ Spawn the background Redis Ledger Thread
    tokio::spawn(async move {
        telemetry::start_accounting_engine(valid_share_rx).await;
    });

    let (job_manager_arc, _job_rx, block_submit_rx) = JobManager::new();

    let config_clone = config.clone();
    let jm_clone = job_manager_arc.clone();
    
    tokio::spawn(async move {
        if let Err(e) = kaspad_client::start_kaspad_client(config_clone, jm_clone, block_submit_rx).await {
            tracing::error!("Kaspa gRPC Connection Failed: {}", e);
        }
    });

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