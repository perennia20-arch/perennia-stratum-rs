// src/telemetry/mod.rs
use prometheus::{GaugeVec, IntCounterVec, Opts, Registry, TextEncoder, Encoder};
use lazy_static::lazy_static;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use std::collections::{HashMap, VecDeque};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use std::env;

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
    share_history: VecDeque<(u64, f64)>,
    shares_contributed: f64,
    blocks_found: u64,
    unflushed_difficulty: f64,
    unflushed_blocks: u64, 
}

pub async fn start_accounting_engine(mut valid_share_rx: mpsc::Receiver<(String, f64, bool)>) {
    tracing::info!("🏦 Institutional Accounting & Telemetry Engine Booted. Awaiting verified shares...");

    // ⚡ INFRASTRUCTURE HARDENING
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = redis::Client::open(redis_url).expect("Redis connection failed");
    
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
            Some((full_worker_name, difficulty, is_network_block)) = valid_share_rx.recv() => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;

                let state = worker_states.entry(full_worker_name.clone()).or_insert_with(|| WorkerState {
                    last_share_ts: now,
                    share_history: VecDeque::new(),
                    shares_contributed: 0.0,
                    blocks_found: 0,
                    unflushed_difficulty: 0.0,
                    unflushed_blocks: 0,
                });

                state.share_history.push_back((now, difficulty));
                state.last_share_ts = now;
                state.shares_contributed += difficulty;
                state.unflushed_difficulty += difficulty;

                if is_network_block {
                    state.blocks_found += 1;
                    state.unflushed_blocks += 1;
                }

                WORKER_SHARES.with_label_values(&[&full_worker_name, "valid"]).inc_by(difficulty as u64);
            }

            _ = flush_interval.tick() => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
                let mut pipeline = redis::pipe();
                let mut total_hashrate = 0.0;
                let mut workers_array = Vec::new();
                let mut keys_to_remove = Vec::new();

                let cutoff_300s = now.saturating_sub(300_000);
                let cutoff_60s = now.saturating_sub(60_000); 

                if !worker_states.is_empty() {
                    for (full_worker, state) in worker_states.iter_mut() {
                        let dt_idle = (now.saturating_sub(state.last_share_ts)) as f64 / 1000.0;

                        while let Some(&(ts, _)) = state.share_history.front() {
                            if ts < cutoff_300s {
                                state.share_history.pop_front();
                            } else {
                                break;
                            }
                        }

                        let mut work_60s = 0.0;
                        let mut work_300s = 0.0;
                        let mut oldest_ts = now;

                        for &(ts, diff) in state.share_history.iter() {
                            let work = diff * KASPA_DIFF_CONSTANT;
                            work_300s += work;
                            if ts >= cutoff_60s {
                                work_60s += work;
                            }
                            if ts < oldest_ts {
                                oldest_ts = ts;
                            }
                        }

                        let mut elapsed_total = ((now - oldest_ts) as f64) / 1000.0;
                        if elapsed_total < 1.0 { elapsed_total = 1.0; }

                        let mut elapsed_60s = elapsed_total.min(60.0);
                        if elapsed_60s < 1.0 { elapsed_60s = 1.0; }

                        let hr_300s = work_300s / elapsed_total;
                        let hr_60s = work_60s / elapsed_60s;

                        let current_hashrate = (hr_60s * 0.4) + (hr_300s * 0.6);
                        let is_online = current_hashrate > 0.0 || dt_idle < 60.0;

                        if !is_online {
                            keys_to_remove.push(full_worker.clone());
                            pipeline.cmd("SET").arg(format!("worker:{}:hashrate", full_worker)).arg(0.0).ignore();
                            pipeline.cmd("SREM").arg("pool:workers").arg(full_worker.clone()).ignore();
                        } else {
                            total_hashrate += current_hashrate;

                            WORKER_HASHRATE.with_label_values(&[full_worker]).set(current_hashrate / 1e12);
                            pipeline.cmd("SET").arg(format!("worker:{}:hashrate", full_worker)).arg(current_hashrate).ignore();

                            if state.unflushed_difficulty > 0.0 || state.unflushed_blocks > 0 {
                                let parts: Vec<&str> = full_worker.split('.').collect();
                                let wallet = parts[0];
                                let wallet_key = format!("perennia:ledger:wallet:{}", wallet);

                                pipeline.cmd("SADD").arg("pool:workers").arg(full_worker.clone()).ignore();

                                if state.unflushed_difficulty > 0.0 {
                                    pipeline.cmd("INCRBYFLOAT").arg(&wallet_key).arg(state.unflushed_difficulty).ignore();
                                    pipeline.cmd("INCRBYFLOAT").arg(format!("worker:{}:shares", full_worker)).arg(state.unflushed_difficulty).ignore();
                                    state.unflushed_difficulty = 0.0;
                                }

                                if state.unflushed_blocks > 0 {
                                    pipeline.cmd("INCRBY").arg(format!("worker:{}:blocks_unpaid", full_worker)).arg(state.unflushed_blocks).ignore();
                                    state.unflushed_blocks = 0;
                                }
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
                                "blocksFound": state.blocks_found,
                                "status": "online"
                            }));
                        }
                    }

                    for key in keys_to_remove {
                        worker_states.remove(&key);
                    }
                }

                pipeline.cmd("SET").arg("pool:hashrate").arg(total_hashrate).ignore();

                let telemetry_payload = json!({
                    "totalHashrate": total_hashrate,
                    "workers": workers_array
                });

                let payload_str = telemetry_payload.to_string();

                pipeline.cmd("SET").arg("perennia:telemetry").arg(&payload_str).ignore();
                pipeline.cmd("XADD").arg("telemetry:stream").arg("MAXLEN").arg("~").arg(100).arg("*").arg("payload").arg(&payload_str).ignore();
                pipeline.cmd("PUBLISH").arg("telemetry:updates").arg(&payload_str).ignore();

                if let Err(e) = pipeline.query_async::<_, ()>(&mut redis_conn).await {
                    tracing::error!("🚨 CRITICAL LEDGER FAILURE: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    if let Ok(new_conn) = redis_client.get_multiplexed_async_connection().await {
                        redis_conn = new_conn;
                    }
                }
            }
        }
    }
}