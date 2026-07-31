use prometheus::{GaugeVec, IntCounterVec, Opts, Registry, TextEncoder, Encoder};
use lazy_static::lazy_static;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use std::collections::HashMap;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use redis::AsyncCommands;

const EMA_WINDOWS: [f64; 7] = [1.0, 3.0, 8.0, 21.0, 55.0, 144.0, 377.0];
const KASPA_DIFF_CONSTANT: f64 = 4_294_967_296.0;

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    pub static ref WORKER_HASHRATE: GaugeVec = GaugeVec::new(
        Opts::new("ks_worker_hashrate", "Strictly verified unsimulated hashrate per worker in TH/s"),
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

struct WorkerState {
    last_share_ts: u64,
    emas: [f64; 7],
    shares_contributed: f64,
    unflushed_difficulty: f64,
    unflushed_oracle_shares: Vec<(f64, u64)>,
}

pub async fn start_accounting_engine(mut valid_share_rx: mpsc::Receiver<(String, f64)>) {
    tracing::info!("🏦 Institutional Accounting & Telemetry Engine Booted. Awaiting verified shares...");

    let redis_client = redis::Client::open("redis://127.0.0.1/").expect("Redis connection failed");
    let mut redis_conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("❌ CRITICAL: Could not connect to Redis for Accounting! {}", e);
            return;
        }
    };

    let mut flush_interval = tokio::time::interval(tokio::time::Duration::from_millis(1000));
    let mut worker_states: HashMap<String, WorkerState> = HashMap::new();

    loop {
        tokio::select! {
            Some((full_worker_name, difficulty)) = valid_share_rx.recv() => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
                let work = difficulty * KASPA_DIFF_CONSTANT;

                let state = worker_states.entry(full_worker_name.clone()).or_insert_with(|| WorkerState {
                    last_share_ts: now,
                    emas: [0.0; 7],
                    shares_contributed: 0.0,
                    unflushed_difficulty: 0.0,
                    unflushed_oracle_shares: Vec::new(),
                });

                let dt_sec = (now.saturating_sub(state.last_share_ts)) as f64 / 1000.0;

                for (i, &tau) in EMA_WINDOWS.iter().enumerate() {
                    let alpha = 1.0 - f64::exp(-dt_sec / tau);
                    let contribution = if dt_sec > 0.001 {
                        (work / dt_sec) * alpha
                    } else {
                        work / tau
                    };

                    state.emas[i] = (state.emas[i] * (1.0 - alpha)) + contribution;
                }

                state.last_share_ts = now;
                state.shares_contributed += difficulty;
                state.unflushed_difficulty += difficulty;
                state.unflushed_oracle_shares.push((difficulty, now));

                WORKER_SHARES.with_label_values(&[&full_worker_name, "valid"]).inc_by(difficulty as u64);
            }

            _ = flush_interval.tick() => {
                if worker_states.is_empty() {
                    continue;
                }

                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
                let mut pipeline = redis::pipe();
                let mut total_hashrate = 0.0;
                let mut workers_array = Vec::new();
                let mut keys_to_remove = Vec::new();

                for (full_worker, state) in worker_states.iter_mut() {
                    let dt_idle = (now.saturating_sub(state.last_share_ts)) as f64 / 1000.0;
                    let mut projected_emas = [0.0; 7];

                    for (i, &tau) in EMA_WINDOWS.iter().enumerate() {
                        let alpha = 1.0 - f64::exp(-dt_idle / tau);
                        let projected = state.emas[i] * (1.0 - alpha);
                        
                        // Treat extremely small or negative values as zero to prevent UI errors
                        projected_emas[i] = if projected > 0.000001 { projected } else { 0.0 };
                    }

                    let current_hashrate = projected_emas[2];
                    let is_online = current_hashrate > 5_000_000_000.0 || dt_idle < 30.0;

                    if !is_online {
                        keys_to_remove.push(full_worker.clone());
                        pipeline.cmd("SET").arg(format!("worker:{}:hashrate", full_worker)).arg(0.0).ignore();
                        pipeline.cmd("SREM").arg("pool:workers").arg(full_worker.clone()).ignore();
                    } else {
                        total_hashrate += current_hashrate;
                        WORKER_HASHRATE.with_label_values(&[full_worker]).set(current_hashrate / 1e12);

                        pipeline.cmd("SET").arg(format!("worker:{}:hashrate", full_worker)).arg(current_hashrate).ignore();

                        if state.unflushed_difficulty > 0.0 {
                            let parts: Vec<&str> = full_worker.split('.').collect();
                            let wallet = parts[0];
                            let wallet_key = format!("perennia:ledger:wallet:{}", wallet);

                            pipeline.cmd("INCRBYFLOAT").arg(&wallet_key).arg(state.unflushed_difficulty).ignore();
                            pipeline.cmd("SADD").arg("pool:workers").arg(full_worker.clone()).ignore();
                            pipeline.cmd("INCRBYFLOAT").arg(format!("worker:{}:shares", full_worker)).arg(state.unflushed_difficulty).ignore();

                            for (diff, ts) in state.unflushed_oracle_shares.drain(..) {
                                let oracle_event = json!({
                                    "worker": full_worker,
                                    "difficulty": diff,
                                    "timestamp": ts
                                });
                                pipeline.cmd("RPUSH").arg("perennia:oracle:share_buffer").arg(oracle_event.to_string()).ignore();
                            }
                            state.unflushed_difficulty = 0.0;
                        }

                        let parts: Vec<&str> = full_worker.split('.').collect();
                        let wallet_address = if !parts.is_empty() { parts[0] } else { full_worker.as_str() };
                        let worker_name = if parts.len() > 1 { parts[1..].join(".") } else { full_worker.to_string() };

                        workers_array.push(json!({
                            "fullIdentity": full_worker,
                            "walletAddress": wallet_address,
                            "name": worker_name,
                            "trackingRate": current_hashrate,
                            "sharesContributed": state.shares_contributed,
                            "blocksFound": 0,
                            "status": "online",
                            "harmonicMesh": projected_emas
                        }));
                    }
                }

                for key in keys_to_remove {
                    worker_states.remove(&key);
                }

                pipeline.cmd("SET").arg("pool:hashrate").arg(total_hashrate).ignore();

                let telemetry_payload = json!({
                    "totalHashrate": total_hashrate,
                    "workers": workers_array
                });

                let payload_str = telemetry_payload.to_string();

                // ⚡ RESTORED: The wide JSON console log to visually confirm multiplexer broadcast
                tracing::info!("📡 [MULTIPLEXER OUT] {}", payload_str);

                pipeline.cmd("SET")
                    .arg("perennia:telemetry")
                    .arg(&payload_str)
                    .ignore();

                // ⚡ FIX: Adjusted channel name to "pool_telemetry" to perfectly match your SvelteKit +server.ts
                pipeline.cmd("PUBLISH")
                    .arg("pool_telemetry")
                    .arg(&payload_str)
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