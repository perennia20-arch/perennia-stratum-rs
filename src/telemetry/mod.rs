use prometheus::{GaugeVec, IntCounterVec, Opts, Registry, TextEncoder, Encoder};
use lazy_static::lazy_static;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use std::collections::HashMap;
use serde_json::json;

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    pub static ref WORKER_HASHRATE: GaugeVec = GaugeVec::new(
        Opts::new("ks_worker_hashrate", "Strictly verified unsimulated hashrate per worker"),
        &["worker"]
    ).expect("Metric setup failed");

    pub static ref WORKER_SHARES: IntCounterVec = IntCounterVec::new(
        Opts::new("ks_worker_shares", "Cryptographically validated shares per worker"),
        &["worker", "type"]
    ).expect("Metric setup failed");
}

pub fn init_telemetry() {
    REGISTRY.register(Box::new(WORKER_HASHRATE.clone())).unwrap();
    REGISTRY.register(Box::new(WORKER_SHARES.clone())).unwrap();
}

pub async fn start_prometheus_exporter(_bind_addr: String) {
    let addr = "0.0.0.0:8081";
    let listener = TcpListener::bind(addr).await.expect("Failed to bind Prometheus port");
    
    tracing::info!("📊 Zero-Simulation Telemetry exporter natively active on http://{}/metrics", addr);

    loop {
        if let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                let _ = socket.read(&mut buf).await; 

                let mut buffer = vec![];
                let encoder = TextEncoder::new();
                let metric_families = REGISTRY.gather();
                encoder.encode(&metric_families, &mut buffer).unwrap();

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                    buffer.len(),
                    String::from_utf8_lossy(&buffer)
                );
                
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    }
}

pub async fn start_accounting_engine(mut valid_share_rx: mpsc::Receiver<(String, f64)>) {
    tracing::info!("🏦 Institutional Accounting Engine Booted. Awaiting verified shares...");

    let redis_client = redis::Client::open("redis://127.0.0.1/").expect("Redis connection failed");
    let mut redis_conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("❌ CRITICAL: Could not connect to Redis for Accounting! {}", e);
            return;
        }
    };

    let mut flush_interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    let mut share_batch: HashMap<String, f64> = HashMap::new();
    let mut worker_emas: HashMap<String, f64> = HashMap::new();
    let mut worker_total_shares: HashMap<String, f64> = HashMap::new();

    const EMA_ALPHA: f64 = 0.20; 
    const KASPA_HASHRATE_MULTIPLIER: f64 = 55000000000.0; 

    loop {
        tokio::select! {
            Some((full_worker_name, difficulty)) = valid_share_rx.recv() => {
                let count = share_batch.entry(full_worker_name.clone()).or_insert(0.0);
                *count += difficulty;
                
                let total = worker_total_shares.entry(full_worker_name).or_insert(0.0);
                *total += difficulty;
            }

            _ = flush_interval.tick() => {
                let mut pipeline = redis::pipe();
                let mut total_hashrate = 0.0;
                let mut keys_to_remove = Vec::new();

                for (full_worker, current_ema) in worker_emas.iter_mut() {
                    let diff_sum = share_batch.remove(full_worker).unwrap_or(0.0);
                    let instant_hashrate = (diff_sum as f64) * KASPA_HASHRATE_MULTIPLIER;
                    
                    *current_ema = (instant_hashrate * EMA_ALPHA) + (*current_ema * (1.0 - EMA_ALPHA));

                    if diff_sum > 0.0 {
                        let parts: Vec<&str> = full_worker.split('.').collect();
                        let wallet = parts[0];
                        let wallet_key = format!("perennia:ledger:wallet:{}", wallet);
                        
                        pipeline.cmd("INCRBYFLOAT").arg(&wallet_key).arg(diff_sum).ignore();
                        pipeline.cmd("SADD").arg("pool:workers").arg(full_worker.clone()).ignore();
                        pipeline.cmd("INCRBYFLOAT").arg(format!("worker:{}:shares", full_worker)).arg(diff_sum).ignore();
                    }

                    if *current_ema < 0.05 {
                        keys_to_remove.push(full_worker.clone());
                        pipeline.cmd("SET").arg(format!("worker:{}:hashrate", full_worker)).arg(0.0).ignore();
                        pipeline.cmd("SREM").arg("pool:workers").arg(full_worker.clone()).ignore();
                    } else {
                        pipeline.cmd("SET").arg(format!("worker:{}:hashrate", full_worker)).arg(*current_ema).ignore();
                        total_hashrate += *current_ema;
                    }
                }

                for (full_worker, diff_sum) in &share_batch {
                    let instant_hashrate = (*diff_sum as f64) * KASPA_HASHRATE_MULTIPLIER;
                    worker_emas.insert(full_worker.clone(), instant_hashrate);

                    let parts: Vec<&str> = full_worker.split('.').collect();
                    let wallet = parts[0];
                    let wallet_key = format!("perennia:ledger:wallet:{}", wallet);
                    
                    pipeline.cmd("INCRBYFLOAT").arg(&wallet_key).arg(diff_sum).ignore();
                    pipeline.cmd("SADD").arg("pool:workers").arg(full_worker.clone()).ignore();
                    pipeline.cmd("INCRBYFLOAT").arg(format!("worker:{}:shares", full_worker)).arg(diff_sum).ignore();
                    pipeline.cmd("SET").arg(format!("worker:{}:hashrate", full_worker)).arg(instant_hashrate).ignore();
                    
                    total_hashrate += instant_hashrate;
                }

                for key in keys_to_remove {
                    worker_emas.remove(&key);
                    worker_total_shares.remove(&key); 
                }
                share_batch.clear();

                pipeline.cmd("SET").arg("pool:hashrate").arg(total_hashrate).ignore();

                let mut workers_array = Vec::new();
                for (full_worker, hashrate) in &worker_emas {
                    let parts: Vec<&str> = full_worker.split('.').collect();
                    let wallet_address = if !parts.is_empty() { parts[0] } else { full_worker.as_str() };
                    
                    // ⚡ FIX: Explicitly call .to_string() on both branches to satisfy E0308 Compiler constraint
                    let worker_name = if parts.len() > 1 { parts[1..].join(".") } else { full_worker.to_string() };
                    
                    let shares_accepted = worker_total_shares.get(full_worker).unwrap_or(&0.0);

                    workers_array.push(json!({
                        "fullIdentity": full_worker,
                        "walletAddress": wallet_address,
                        "name": worker_name,
                        "trackingRate": hashrate,
                        "sharesContributed": shares_accepted,
                        "blocksFound": 0,
                        "status": "online"
                    }));
                }

                let telemetry_payload = json!({
                    "totalHashrate": total_hashrate,
                    "workers": workers_array
                });

                pipeline.cmd("SET")
                    .arg("perennia:telemetry")
                    .arg(telemetry_payload.to_string())
                    .ignore();

                if let Err(e) = pipeline.query_async::<_, ()>(&mut redis_conn).await {
                    tracing::error!("🚨 CRITICAL LEDGER FAILURE: {}", e);
                    tracing::warn!("🔄 Attempting to re-establish broken Redis multiplexer pipeline...");
                    
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    
                    if let Ok(new_conn) = redis_client.get_multiplexed_async_connection().await {
                        tracing::info!("✅ Redis connection successfully restored.");
                        redis_conn = new_conn;
                    }
                }
            }
        }
    }
}