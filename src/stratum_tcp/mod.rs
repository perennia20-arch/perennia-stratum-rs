use tokio::net::{TcpListener, TcpStream};
use tokio::io::AsyncWriteExt;
use tokio_util::codec::{FramedRead, LinesCodec};
use tokio_stream::StreamExt;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, Duration};
use crate::config::StratumConfig;
use crate::job_manager::JobManager;
use redis::AsyncCommands; 

static WORKER_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Deserialize, Debug)]
pub struct RpcRequest {
    pub id: Option<serde_json::Value>,
    pub method: Option<String>,
    pub params: Option<Vec<serde_json::Value>>,
}

fn clamp_to_power_of_2(diff: f64) -> u64 {
    if diff <= 1.0 { return 1; }
    let next_pow = diff.log2().round() as u32;
    2u64.pow(next_pow)
}

pub async fn start_stratum_server(
    config: Arc<StratumConfig>, 
    job_manager: Arc<JobManager>,
    valid_share_tx: mpsc::Sender<(String, f64)>,
    port: u16,
    difficulty: f64,
    throttle_ms: u64
) -> anyhow::Result<()> {
    let bind_addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&bind_addr).await?;
    
    // ⚡ FIX: Implemented Semaphore to strictly limit File Descriptors and prevent SYN Flood crashes
    let connection_limit = Arc::new(Semaphore::new(5000));
    
    tracing::info!("🛡️ STRATUM TIER ACTIVE ON {} (Diff: {}, Throttle: {}ms)", bind_addr, difficulty, throttle_ms);

    loop {
        // Wait safely until a slot opens in the connection pool
        let permit = connection_limit.clone().acquire_owned().await?;
        let (socket, addr) = listener.accept().await?;
        tracing::info!("🔌 [{}] Hardware connection established to Tier Port {}", addr.ip(), port);

        let config_clone = config.clone();
        let job_manager_clone = job_manager.clone();
        let share_tx_clone = valid_share_tx.clone();
        let peer_ip = addr.ip().to_string();

        tokio::spawn(async move {
            let _permit = permit; // Safely hold the permit; dropped automatically on disconnect
            if let Err(e) = handle_worker_connection(socket, peer_ip.clone(), config_clone, job_manager_clone, share_tx_clone, difficulty, throttle_ms).await {
                tracing::warn!("⚠️ [{}] Worker disconnected: {}", peer_ip, e);
            }
        });
    }
}

async fn handle_worker_connection(
    socket: TcpStream, 
    peer_addr: String,
    config: Arc<StratumConfig>,
    job_manager: Arc<JobManager>,
    valid_share_tx: mpsc::Sender<(String, f64)>,
    difficulty: f64,
    throttle_ms: u64
) -> anyhow::Result<()> {
    let mut job_rx = job_manager.job_tx.subscribe();
    let conn_id = WORKER_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    let extranonce1 = format!("{:04x}", conn_id & 0xFFFF); 
    
    let mut current_diff = clamp_to_power_of_2(difficulty);

    let (read_half, mut write_half) = socket.into_split();
    
    // ⚡ FIX: OOM memory exhaustion patched via strict LinesCodec bounds (Max 2048 bytes per payload)
    let mut reader = FramedRead::new(read_half, LinesCodec::new_with_max_length(2048));

    let mut handshake_state = 0; 
    let mut current_worker_name = String::new();

    // ⚡ FIX: VarDiff Tracking Variables
    let mut share_count = 0;
    let mut last_vardiff_retarget = Instant::now();
    let target_shares_per_min = config.shares_per_min as f64;

    while handshake_state < 2 {
        let line_res = reader.next().await;
        if line_res.is_none() { anyhow::bail!("EOF - Client closed connection during handshake"); }
        
        let payload_str = match line_res.unwrap() {
            Ok(s) => s,
            Err(e) => anyhow::bail!("Client Payload Violation: {}", e),
        };
        
        let trimmed = payload_str.trim_matches('\0').trim();
        if trimmed.is_empty() { continue; }
        
        tracing::info!("⬇️ [RX | {}] {}", peer_addr, trimmed);
        
        if let Ok(req) = serde_json::from_str::<RpcRequest>(trimmed) {
            let method = req.method.unwrap_or_else(|| "unknown".to_string());
            let req_id = req.id.clone().unwrap_or(serde_json::Value::Null);

            if handshake_state == 0 && method == "mining.subscribe" {
                let sub_json = json!({
                    "id": req_id,
                    "result": [true, "EthereumStratum/1.0.0"],
                    "error": null
                });
                let mut response = sub_json.to_string();
                response.push('\n');
                write_half.write_all(response.as_bytes()).await?;

                let en_json = json!({
                    "id": null,
                    "method": "mining.set_extranonce",
                    "params": [extranonce1.clone()]
                });
                let mut en_resp = en_json.to_string();
                en_resp.push('\n');
                write_half.write_all(en_resp.as_bytes()).await?;
                
                handshake_state = 1;
            } else if handshake_state == 1 && method == "mining.authorize" {
                let auth_json = json!({
                    "id": req_id,
                    "result": true,
                    "error": null
                });
                let mut response = auth_json.to_string();
                response.push('\n');
                write_half.write_all(response.as_bytes()).await?;
                
                handshake_state = 2;
            }
        }
    }

    let diff_json = json!({
        "id": null,
        "method": "mining.set_difficulty",
        "params": [current_diff]
    });
    let mut diff_msg = diff_json.to_string();
    diff_msg.push('\n'); 
    write_half.write_all(diff_msg.as_bytes()).await?;

    let initial_job = {
        if let Ok(cache) = job_manager.cached_job.read() {
            (*cache).clone() 
        } else {
            None
        }
    }; 

    if let Some(cached_payload) = initial_job {
        write_half.write_all(&cached_payload[..]).await?; 
    }

    let safe_throttle = if throttle_ms == 0 { 10 } else { throttle_ms };
    let mut throttle_interval = tokio::time::interval(Duration::from_millis(safe_throttle));
    throttle_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Dynamic VarDiff Check Interval (evaluate every 30s)
    let mut vardiff_interval = tokio::time::interval(Duration::from_secs(30));

    let mut pending_job_payload = None;

    loop {
        tokio::select! {
            Ok(job) = job_rx.recv() => {
                pending_job_payload = Some(job.payload.clone());
            }

            _ = throttle_interval.tick() => {
                if let Some(payload) = pending_job_payload.take() {
                    let _ = write_half.write_all(&payload[..]).await;
                }
            }

            _ = vardiff_interval.tick() => {
                // ⚡ FIX: True VarDiff Calculation and Retargeting Mechanism
                if config.var_diff && last_vardiff_retarget.elapsed().as_secs() >= 60 {
                    let elapsed_mins = last_vardiff_retarget.elapsed().as_secs_f64() / 60.0;
                    let shares_per_min = share_count as f64 / elapsed_mins;
                    
                    let mut new_diff = current_diff;
                    if shares_per_min < target_shares_per_min * 0.5 {
                        new_diff = (current_diff / 2).max(clamp_to_power_of_2(config.min_share_diff));
                    } else if shares_per_min > target_shares_per_min * 2.0 {
                        new_diff = current_diff * 2;
                    }
                    
                    if new_diff != current_diff {
                        current_diff = new_diff;
                        let retarget_json = json!({
                            "id": null,
                            "method": "mining.set_difficulty",
                            "params": [current_diff]
                        });
                        let mut retarget_msg = retarget_json.to_string();
                        retarget_msg.push('\n');
                        let _ = write_half.write_all(retarget_msg.as_bytes()).await;
                        tracing::info!("🔄 VarDiff Adjusted for {} -> New Diff: {}", current_worker_name, current_diff);
                    }
                    
                    share_count = 0;
                    last_vardiff_retarget = Instant::now();
                }
            }

            line_res = reader.next() => {
                if line_res.is_none() { anyhow::bail!("EOF - Client closed connection"); }
                
                let payload_str = match line_res.unwrap() {
                    Ok(s) => s,
                    Err(e) => anyhow::bail!("Client payload violation: {}", e),
                };
                
                let trimmed = payload_str.trim_matches('\0').trim();
                if !trimmed.is_empty() {
                    if let Ok(req) = serde_json::from_str::<RpcRequest>(trimmed) {
                        let method = req.method.unwrap_or_else(|| "unknown".to_string());
                        let req_id = req.id.clone().unwrap_or(serde_json::Value::Null);
                        
                        if method == "mining.submit" {
                            if let Some(params) = req.params {
                                if params.len() >= 3 {
                                    let req_worker = match &params[0] {
                                        serde_json::Value::String(s) => s.clone(),
                                        v => v.to_string(),
                                    }.replace('"', "").replace('\0', "").trim().to_string();
                                    
                                    current_worker_name = req_worker.clone();
                                    
                                    let job_id = match &params[1] {
                                        serde_json::Value::String(s) => s.clone(),
                                        v => v.to_string(),
                                    }.replace('"', "").replace('\0', "").trim().to_string();
                                    
                                    let nonce_str = match &params[2] {
                                        serde_json::Value::String(s) => s.clone(),
                                        v => v.to_string(),
                                    }.replace('"', "").replace('\0', "").trim().to_string();

                                    let clean_nonce = nonce_str.trim_start_matches("0x");
                                    let mut nonce: u64 = u64::from_str_radix(clean_nonce, 16).unwrap_or(0);

                                    if clean_nonce.len() <= 12 { 
                                        let full_nonce_hex = format!("{}{:0>12}", extranonce1, clean_nonce);
                                        nonce = u64::from_str_radix(&full_nonce_hex, 16).unwrap_or(nonce);
                                    }

                                    if let Some(job_entry) = job_manager.active_jobs.get(&job_id) {
                                        let (consensus_header, mut rpc_block) = job_entry.value().clone();
                                        
                                        let (is_valid_share, is_network_block) = crate::diff_engine::verify_share(
                                            &consensus_header, nonce, current_diff as f64
                                        );

                                        if is_network_block {
                                            tracing::info!("💎💎💎 [{}] NETWORK BLOCK ACQUIRED! Nonce: {:016x}", peer_addr, nonce);
                                            
                                            let mut final_header = consensus_header.clone();
                                            final_header.nonce = nonce;
                                            let block_hash = kaspa_consensus_core::hashing::header::hash(&final_header).to_string();

                                            if let Some(ref mut rpc_header) = rpc_block.header { rpc_header.nonce = nonce; }
                                            
                                            let worker_clone = req_worker.clone();
                                            let diff_clone = current_diff as f64;
                                            
                                            tokio::spawn(async move {
                                                if let Ok(client) = redis::Client::open("redis://127.0.0.1/") {
                                                    if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                                                        let block_event = serde_json::json!({
                                                            "worker": worker_clone,
                                                            "block_hash": block_hash,
                                                            "nonce": nonce,
                                                            "network_diff": diff_clone
                                                        });
                                                        let _: () = redis::cmd("RPUSH").arg("perennia:oracle:block_buffer").arg(block_event.to_string()).query_async(&mut conn).await.unwrap_or(());
                                                    }
                                                }
                                            });

                                            let _ = job_manager.block_submit_tx.try_send(rpc_block);
                                            
                                        } else if is_valid_share {
                                            tracing::info!("✅ [{}] TIER SHARE ACCEPTED | Job: {}", peer_addr, job_id);
                                            crate::telemetry::WORKER_SHARES.with_label_values(&[&req_worker, "valid"]).inc();
                                            share_count += 1;
                                            let _ = valid_share_tx.try_send((req_worker.clone(), current_diff as f64));
                                        } else {
                                            tracing::warn!("🚫 [{}] INVALID SHARE | Worker: {}", peer_addr, req_worker);
                                        }
                                    } else {
                                        tracing::warn!("⚠️ [{}] STALE JOB REJECTED: {}", peer_addr, job_id);
                                    }
                                }
                            }

                            let submit_reply = json!({
                                "id": req_id,
                                "result": true,
                                "error": null
                            });
                            let mut response = submit_reply.to_string();
                            response.push('\n'); 
                            let _ = write_half.write_all(response.as_bytes()).await;

                        } else {
                            let catch_json = json!({
                                "id": req_id,
                                "result": true,
                                "error": null
                            });
                            let mut response = catch_json.to_string();
                            response.push('\n'); 
                            let _ = write_half.write_all(response.as_bytes()).await;
                        }
                    }
                }
            }
        }
    }
}