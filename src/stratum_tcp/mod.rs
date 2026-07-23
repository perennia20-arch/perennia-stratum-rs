use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::mpsc;
use std::sync::atomic::{AtomicU64, Ordering};
use crate::config::StratumConfig;
use crate::job_manager::JobManager;
use redis::AsyncCommands; // ⚡ INQUIRY 3 IMPORT: Required for Block Discovery Oracle Injection

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
    tracing::info!("🛡️ STRATUM TIER ACTIVE ON {} (Diff: {}, Throttle: {}ms)", bind_addr, difficulty, throttle_ms);

    loop {
        let (socket, addr) = listener.accept().await?;
        tracing::info!("🔌 [{}] Hardware connection established to Tier Port {}", addr.ip(), port);

        let config_clone = config.clone();
        let job_manager_clone = job_manager.clone();
        let share_tx_clone = valid_share_tx.clone();
        let peer_ip = addr.ip().to_string();

        tokio::spawn(async move {
            if let Err(e) = handle_worker_connection(socket, peer_ip.clone(), config_clone, job_manager_clone, share_tx_clone, difficulty, throttle_ms).await {
                tracing::warn!("⚠️ [{}] Worker disconnected: {}", peer_ip, e);
            }
        });
    }
}

async fn handle_worker_connection(
    socket: TcpStream, 
    peer_addr: String,
    _config: Arc<StratumConfig>,
    job_manager: Arc<JobManager>,
    valid_share_tx: mpsc::Sender<(String, f64)>,
    difficulty: f64,
    throttle_ms: u64
) -> anyhow::Result<()> {
    let mut job_rx = job_manager.job_tx.subscribe();
    let conn_id = WORKER_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    
    // ⚡ GO-BRIDGE SPEC: Pool extranonce is exactly 2 bytes (4 hex chars).
    let extranonce1 = format!("{:04x}", conn_id & 0xFFFF); 
    
    let current_diff = clamp_to_power_of_2(difficulty);

    let (read_half, mut write_half) = socket.into_split();
    let mut reader = BufReader::with_capacity(32768, read_half);
    let mut line_buf = Vec::new();

    let mut handshake_state = 0; 

    while handshake_state < 2 {
        line_buf.clear();
        let bytes_read = reader.read_until(b'\n', &mut line_buf).await?;
        if bytes_read == 0 { anyhow::bail!("EOF - Client closed connection during handshake"); }
        
        let payload_str = std::str::from_utf8(&line_buf).unwrap_or("");
        let trimmed = payload_str.trim_matches('\0').trim();
        if trimmed.is_empty() { continue; }
        
        tracing::info!("⬇️ [RX | {}] {}", peer_addr, trimmed);
        
        if let Ok(req) = serde_json::from_str::<RpcRequest>(trimmed) {
            let method = req.method.unwrap_or_else(|| "unknown".to_string());
            let req_id = req.id.clone().unwrap_or(serde_json::Value::Null);

            if handshake_state == 0 && method == "mining.subscribe" {
                // ⚡ EthereumStratum handshake bypasses IceRiver parser strictness
                let sub_json = json!({
                    "id": req_id,
                    "result": [true, "EthereumStratum/1.0.0"],
                    "error": null
                });
                let mut response = sub_json.to_string();
                response.push('\n');
                tracing::info!("⬆️ [TX | {}] {}", peer_addr, response.trim());
                write_half.write_all(response.as_bytes()).await?;

                // ⚡ Immediately push the extranonce1 explicitly
                let en_json = json!({
                    "id": null,
                    "method": "mining.set_extranonce",
                    "params": [extranonce1.clone()]
                });
                let mut en_resp = en_json.to_string();
                en_resp.push('\n');
                tracing::info!("⬆️ [TX | {}] {}", peer_addr, en_resp.trim());
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
                tracing::info!("⬆️ [TX | {}] {}", peer_addr, response.trim());
                write_half.write_all(response.as_bytes()).await?;
                
                handshake_state = 2;
            } else {
                tracing::warn!("⚠️ [{}] Unexpected handshake message: {}", peer_addr, method);
            }
        } else {
            tracing::error!("❌ [{}] JSON PARSE ERROR during handshake | Raw: {}", peer_addr, trimmed);
        }
    }

    let diff_json = json!({
        "id": null,
        "method": "mining.set_difficulty",
        "params": [current_diff]
    });
    let mut diff_msg = diff_json.to_string();
    diff_msg.push('\n'); 
    tracing::info!("⬆️ [TX | {}] {}", peer_addr, diff_msg.trim());
    write_half.write_all(diff_msg.as_bytes()).await?;

    let initial_job = {
        if let Ok(cache) = job_manager.cached_job.read() {
            (*cache).clone() 
        } else {
            None
        }
    }; 

    if let Some(cached_payload) = initial_job {
        if let Ok(job_str) = std::str::from_utf8(&cached_payload[..]) {
            tracing::info!("⬆️ [TX | {}] {}", peer_addr, job_str.trim());
        }
        write_half.write_all(&cached_payload[..]).await?; 
    }

    let safe_throttle = if throttle_ms == 0 { 10 } else { throttle_ms };
    let mut throttle_interval = tokio::time::interval(tokio::time::Duration::from_millis(safe_throttle));
    throttle_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut pending_job_payload = None;

    loop {
        tokio::select! {
            Ok(job) = job_rx.recv() => {
                pending_job_payload = Some(job.payload.clone());
            }

            _ = throttle_interval.tick() => {
                if let Some(payload) = pending_job_payload.take() {
                    if let Ok(job_str) = std::str::from_utf8(&payload[..]) {
                        tracing::info!("⬆️ [TX | {}] {}", peer_addr, job_str.trim());
                    }
                    let _ = write_half.write_all(&payload[..]).await;
                }
            }

            read_res = reader.read_until(b'\n', &mut line_buf) => {
                let bytes_read = read_res?;
                if bytes_read == 0 { anyhow::bail!("EOF - Client closed connection"); }
                
                if let Ok(payload_str) = std::str::from_utf8(&line_buf) {
                    let trimmed = payload_str.trim_matches('\0').trim();
                    
                    if !trimmed.is_empty() {
                        tracing::info!("⬇️ [RX | {}] {}", peer_addr, trimmed);
                        
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

                                        // ⚡ RECONSTRUCT THE FULL NONCE
                                        if clean_nonce.len() <= 12 { // 6 bytes = 12 chars
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
                                                
                                                // ⚡ INQUIRY 3 INJECTION: Pipe discovery directly to the Oracle
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
                                                let _ = valid_share_tx.try_send((req_worker.clone(), current_diff as f64));
                                            } else {
                                                tracing::warn!("🚫 [{}] INVALID SHARE | Worker: {}", peer_addr, req_worker);
                                            }
                                        } else {
                                            tracing::warn!("⚠️ [{}] STALE JOB REJECTED: {}", peer_addr, job_id);
                                        }
                                    } else {
                                        tracing::warn!("⚠️ [{}] MALFORMED PARAMS REJECTED", peer_addr);
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
                        } else {
                            tracing::error!("❌ [{}] JSON PARSE ERROR | Raw: {}", peer_addr, trimmed);
                        }
                    }
                } else {
                    tracing::error!("❌ [{}] UTF-8 PARSE ERROR / DROPPED | Raw Bytes: {:02X?}", peer_addr, line_buf);
                }
                
                line_buf.clear();
            }
        }
    }
}