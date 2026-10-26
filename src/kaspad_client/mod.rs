// src/kaspad_client/mod.rs

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use redis::AsyncCommands; 
use dashmap::DashMap;
use crate::config::StratumConfig;
use crate::job_manager::{JobManager, PendingBlockSubmission}; 
use std::env;

pub mod protowire {
    tonic::include_proto!("protowire");
}

use protowire::rpc_client::RpcClient;
use protowire::{
    KaspadRequest, GetBlockTemplateRequestMessage, NotifyBlockAddedRequestMessage,
    SubmitBlockRequestMessage, NotifyNewBlockTemplateRequestMessage,
    GetBlockDagInfoRequestMessage, GetBlockRewardInfoRequestMessage
};
use protowire::kaspad_request::Payload as RequestPayload;
use protowire::kaspad_response::Payload as ResponsePayload;

static SUBMIT_REQ_COUNTER: AtomicU64 = AtomicU64::new(1_000_000);
static REWARD_REQ_COUNTER: AtomicU64 = AtomicU64::new(2_000_000);

pub async fn start_kaspad_client(
    config: Arc<StratumConfig>, 
    job_manager: Arc<JobManager>,
    mut block_submit_rx: mpsc::Receiver<PendingBlockSubmission>,
    valid_share_tx: mpsc::Sender<(String, f64, bool)>,
    daa_tx: tokio::sync::broadcast::Sender<u64>,
    utxo_tx: tokio::sync::broadcast::Sender<protowire::UtxosChangedNotificationMessage>
) -> anyhow::Result<()> {
    
    tracing::info!("🔌 Connecting to Distributed Redis Cluster for Frontend UI...");
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = redis::Client::open(redis_url)?;
    let mut redis_conn = redis_client.get_multiplexed_async_connection().await?;

    let active_node_tx = Arc::new(RwLock::new(None::<mpsc::Sender<KaspadRequest>>));
    let active_tx_clone = active_node_tx.clone();
    let pending_submissions: Arc<DashMap<u64, PendingBlockSubmission>> = Arc::new(DashMap::new());
    let pending_submissions_writer = pending_submissions.clone();
    
    // Detached task for dispatching candidate blocks submitted from Stratum
    tokio::spawn(async move {
        while let Some(submission) = block_submit_rx.recv().await {
            tracing::info!(
                "🚀🚀🚀 DISPATCHING BLOCK {} (Diff: {:.2}) TO MAINNET CONVERGENCE LAYER 🚀🚀🚀",
                submission.block_hash,
                submission.network_diff
            );
            let req_id = SUBMIT_REQ_COUNTER.fetch_add(1, Ordering::SeqCst);
            let winning_block = submission.block.clone();
            pending_submissions_writer.insert(req_id, submission);

            let req = KaspadRequest {
                id: req_id,
                payload: Some(RequestPayload::SubmitBlockRequest(SubmitBlockRequestMessage {
                    block: Some(winning_block),
                    allow_non_daa_blocks: false,
                })),
            };

            if let Some(tx) = &*active_tx_clone.read().await {
                if tx.send(req).await.is_err() {
                    pending_submissions_writer.remove(&req_id);
                    tracing::error!("❌ FAILED TO DISPATCH BLOCK: Node request stream closed!");
                }
            } else {
                pending_submissions_writer.remove(&req_id);
                tracing::error!("❌ FAILED TO DISPATCH BLOCK: No active node connected!");
            }
        }
    });

    let mut current_node_idx = 0;
    let node_array = if config.kaspad_addresses.is_empty() {
        vec!["127.0.0.1:16110".to_string()]
    } else {
        config.kaspad_addresses.clone()
    };

    // Build the scoped list of Treasury addresses to watch on the UTXO index
    let mut watched_addresses = vec![config.mining_address.clone()];
    if let Ok(env_treasury) = env::var("PERENNIA_TREASURY_KAS_ADDRESS") {
        let formatted = format!("kaspa:{}", env_treasury.trim().replace("kaspa:", ""));
        if !watched_addresses.contains(&formatted) {
            watched_addresses.push(formatted);
        }
    }

    // ROUND-ROBIN FAILOVER LOOP
    loop {
        let mut url = node_array[current_node_idx].clone();
        if !url.starts_with("http") {
            url = format!("http://{}", url);
        }
        
        tracing::info!("🔗 Booting gRPC Uplink to Upstream Node: {}", url);
        
        match RpcClient::connect(url.clone()).await {
            Ok(mut client) => {
                tracing::info!("✅ Uplink Established to {}. Subscribing to DAG consensus...", url);

                let (tx, rx) = mpsc::channel::<KaspadRequest>(256);
                let request_stream = ReceiverStream::new(rx);

                *active_node_tx.write().await = Some(tx.clone());
                
                match client.message_stream(request_stream).await {
                    Ok(response) => {
                        let mut response_stream = response.into_inner();

                        let _ = tx.send(KaspadRequest {
                            id: 1,
                            payload: Some(RequestPayload::NotifyBlockAddedRequest(NotifyBlockAddedRequestMessage { command: 0 })),
                        }).await;

                        let _ = tx.send(KaspadRequest {
                            id: 2,
                            payload: Some(RequestPayload::NotifyNewBlockTemplateRequest(NotifyNewBlockTemplateRequestMessage { command: 0 })),
                        }).await;

                        let _ = tx.send(KaspadRequest {
                            id: 3,
                            payload: Some(RequestPayload::GetBlockTemplateRequest(GetBlockTemplateRequestMessage {
                                pay_address: config.mining_address.clone(),
                                extra_data: "Perennia-Zero-Allocation".to_string(),
                            })),
                        }).await;

                        let _ = tx.send(KaspadRequest {
                            id: 4,
                            payload: Some(RequestPayload::NotifyVirtualDaaScoreChangedRequest(
                                protowire::NotifyVirtualDaaScoreChangedRequestMessage { command: 0 }
                            )),
                        }).await;

                        // Scoped strictly to Master Treasury addresses to prevent Mainnet UTXO channel flooding
                        let _ = tx.send(KaspadRequest {
                            id: 5,
                            payload: Some(RequestPayload::NotifyUtxosChangedRequest(
                                protowire::NotifyUtxosChangedRequestMessage {
                                    addresses: watched_addresses.clone(),
                                    command: 0,
                                }
                            )),
                        }).await;

                        let _ = tx.send(KaspadRequest {
                            id: 6,
                            payload: Some(RequestPayload::GetBlockDagInfoRequest(GetBlockDagInfoRequestMessage {})),
                        }).await;

                        let tx_poll = tx.clone();
                        let mining_address_poll = config.mining_address.clone();
                        
                        let poll_task = tokio::spawn(async move {
                            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(1000));
                            let mut req_id = 50000;
                            loop {
                                interval.tick().await;
                                req_id += 1;
                                let req_template = KaspadRequest {
                                    id: req_id,
                                    payload: Some(RequestPayload::GetBlockTemplateRequest(GetBlockTemplateRequestMessage {
                                        pay_address: mining_address_poll.clone(),
                                        extra_data: "Perennia-Zero-Allocation".to_string(),
                                    })),
                                };
                                if tx_poll.send(req_template).await.is_err() { break; }
                                
                                req_id += 1;
                                let req_dag = KaspadRequest {
                                    id: req_id,
                                    payload: Some(RequestPayload::GetBlockDagInfoRequest(GetBlockDagInfoRequestMessage {})),
                                };
                                if tx_poll.send(req_dag).await.is_err() { break; }
                            }
                        });

                        let mining_address = config.mining_address.clone();
                        let tx_clone = tx.clone();
                        let mut req_id = 10;
                        let mut sync_warned = false; 
                        let mut last_queried_reward_hash = String::new();
                        let mut has_live_grpc_reward = false;

                        while let Ok(Some(response)) = response_stream.message().await {
                            match response.payload {
                                Some(ResponsePayload::GetBlockTemplateResponse(res)) => {
                                    if let Some(err) = res.error {
                                        tracing::error!("❌ GET_BLOCK_TEMPLATE REJECTED BY NODE: {}", err.message);
                                    } else if !res.is_synced {
                                        if !sync_warned {
                                            tracing::warn!("⏳ Kaspa Node is currently syncing (IBD). Awaiting network convergence...");
                                            sync_warned = true;
                                        }
                                    } else if let Some(block) = res.block {
                                        sync_warned = false; 
                                        
                                        let parent_hash_opt = block
                                            .header
                                            .as_ref()
                                            .and_then(|h| h.parents.first())
                                            .and_then(|lvl| lvl.parent_hashes.first())
                                            .cloned();

                                        if let Some(header) = &block.header {
                                            tracing::debug!("🧊 Toccata Block Template Acquired! Blue Score: {}", header.blue_score);
                                            let set_res: redis::RedisResult<()> = redis_conn.set("perennia:node:sync_status", "Online").await;
                                            if set_res.is_err() {
                                                if let Ok(new_conn) = redis_client.get_multiplexed_async_connection().await {
                                                    redis_conn = new_conn;
                                                }
                                            }
                                        }

                                        let (template_net_diff, coinbase_reward_sompi) = job_manager.process_new_block(block);

                                        if template_net_diff > 0.0 {
                                            let _: redis::RedisResult<()> = redis_conn.set("pool:network_diff", template_net_diff).await;
                                        }

                                        // Seed from exact consensus coinbase payload if GetBlockRewardInfoResponse has not yet resolved
                                        if coinbase_reward_sompi > 0 && !has_live_grpc_reward {
                                            job_manager.update_latest_reward_sompi(coinbase_reward_sompi);
                                            let reward_kas = coinbase_reward_sompi as f64 / 100_000_000.0;
                                            let _: redis::RedisResult<()> = redis_conn.set("pool:block_reward", reward_kas).await;
                                            let _: redis::RedisResult<()> = redis_conn.set("pool:block_reward_sompi", coinbase_reward_sompi).await;
                                            tracing::debug!("🎯 [CONSENSUS COINBASE] Block Reward: {:.8} KAS ({} sompi)", reward_kas, coinbase_reward_sompi);
                                        }

                                        if let Some(parent_hash) = parent_hash_opt {
                                            if !parent_hash.is_empty() && parent_hash != last_queried_reward_hash {
                                                last_queried_reward_hash = parent_hash.clone();
                                                let reward_req_id = REWARD_REQ_COUNTER.fetch_add(1, Ordering::SeqCst);
                                                let _ = tx_clone.send(KaspadRequest {
                                                    id: reward_req_id,
                                                    payload: Some(RequestPayload::GetBlockRewardInfoRequest(
                                                        GetBlockRewardInfoRequestMessage { hash: parent_hash }
                                                    )),
                                                }).await;
                                            }
                                        }
                                    }
                                }
                                Some(ResponsePayload::GetBlockDagInfoResponse(res)) => {
                                    if let Some(err) = res.error {
                                        tracing::error!("❌ GET_BLOCK_DAG_INFO REJECTED: {}", err.message);
                                    } else {
                                        if res.difficulty > 0.0 {
                                            job_manager.update_latest_network_diff(res.difficulty);
                                            let _: redis::RedisResult<()> = redis_conn.set("pool:network_diff", res.difficulty).await;
                                        }

                                        if !res.sink.is_empty() && res.sink != last_queried_reward_hash {
                                            last_queried_reward_hash = res.sink.clone();
                                            let reward_req_id = REWARD_REQ_COUNTER.fetch_add(1, Ordering::SeqCst);
                                            let _ = tx_clone.send(KaspadRequest {
                                                id: reward_req_id,
                                                payload: Some(RequestPayload::GetBlockRewardInfoRequest(
                                                    GetBlockRewardInfoRequestMessage { hash: res.sink }
                                                )),
                                            }).await;
                                        }
                                    }
                                }
                                Some(ResponsePayload::GetBlockRewardInfoResponse(res)) => {
                                    if res.error.is_none() {
                                        if let Some(reward_sompi) = res.reward_amount {
                                            if reward_sompi > 0 {
                                                has_live_grpc_reward = true;
                                                job_manager.update_latest_reward_sompi(reward_sompi);
                                                let reward_kas = reward_sompi as f64 / 100_000_000.0;
                                                let _: redis::RedisResult<()> = redis_conn.set("pool:block_reward", reward_kas).await;
                                                let _: redis::RedisResult<()> = redis_conn.set("pool:block_reward_sompi", reward_sompi).await;
                                                tracing::debug!(
                                                    "🎯 [GRPC REWARD ORACLE] Exact Block Reward (Base + TX Fees): {:.8} KAS ({} sompi)",
                                                    reward_kas,
                                                    reward_sompi
                                                );
                                            }
                                        } else if let Some(header) = res.header {
                                            // If the queried tip block is not yet merged, query its selected parent which is merged
                                            if let Some(parent_hash) = header.parents.first().and_then(|p| p.parent_hashes.first()) {
                                                if !parent_hash.is_empty() && *parent_hash != last_queried_reward_hash {
                                                    last_queried_reward_hash = parent_hash.clone();
                                                    let reward_req_id = REWARD_REQ_COUNTER.fetch_add(1, Ordering::SeqCst);
                                                    let _ = tx_clone.send(KaspadRequest {
                                                        id: reward_req_id,
                                                        payload: Some(RequestPayload::GetBlockRewardInfoRequest(
                                                            GetBlockRewardInfoRequestMessage { hash: parent_hash.clone() }
                                                        )),
                                                    }).await;
                                                }
                                            }
                                        }
                                    }
                                }
                                Some(ResponsePayload::BlockAddedNotification(_)) |
                                Some(ResponsePayload::NewBlockTemplateNotification(_)) => {
                                    req_id += 1;
                                    let _ = tx_clone.send(KaspadRequest {
                                        id: req_id,
                                        payload: Some(RequestPayload::GetBlockTemplateRequest(GetBlockTemplateRequestMessage {
                                            pay_address: mining_address.clone(),
                                            extra_data: "Perennia-Zero-Allocation".to_string(),
                                        })),
                                    }).await;
                                }
                                Some(ResponsePayload::SubmitBlockResponse(res)) => {
                                    let submission_opt = pending_submissions
                                        .remove(&response.id)
                                        .map(|(_, v)| v)
                                        .or_else(|| {
                                            let oldest_key = pending_submissions.iter().next().map(|entry| *entry.key());
                                            oldest_key.and_then(|k| pending_submissions.remove(&k).map(|(_, v)| v))
                                        });

                                    if let Some(err) = res.error {
                                        tracing::error!("❌ BLOCK VALIDATION ERROR (RejectReason {}): {}", res.reject_reason, err.message);
                                    } else if res.reject_reason != 0 {
                                        tracing::error!("❌ BLOCK REJECTED BY CONSENSUS (RejectReason {})", res.reject_reason);
                                    } else {
                                        tracing::info!("💰💰💰 BLOCK ACCEPTED! CONVERGENCE SETTLED. REWARD LOCKED. 💰💰💰");
                                        if let Some(sub) = submission_opt {
                                            let resolved_reward_sompi = if sub.reward_sompi > 0 {
                                                sub.reward_sompi
                                            } else {
                                                job_manager.get_latest_reward_sompi()
                                            };
                                            let resolved_reward_kas = resolved_reward_sompi as f64 / 100_000_000.0;

                                            // Credit the worker's verified block count only after node acceptance
                                            let _ = valid_share_tx.send((sub.worker.clone(), 0.0, true)).await;

                                            let block_event = serde_json::json!({
                                                "worker": sub.worker,
                                                "block_hash": sub.block_hash,
                                                "nonce": sub.nonce,
                                                "network_diff": sub.network_diff,
                                                "reward_sompi": resolved_reward_sompi,
                                                "reward_kas": resolved_reward_kas
                                            });
                                            let _: redis::RedisResult<()> = redis::cmd("RPUSH")
                                                .arg("perennia:oracle:block_buffer")
                                                .arg(block_event.to_string())
                                                .query_async(&mut redis_conn)
                                                .await;

                                            // Request native block reward info for the newly accepted block
                                            let reward_req_id = REWARD_REQ_COUNTER.fetch_add(1, Ordering::SeqCst);
                                            let _ = tx_clone.send(KaspadRequest {
                                                id: reward_req_id,
                                                payload: Some(RequestPayload::GetBlockRewardInfoRequest(
                                                    GetBlockRewardInfoRequestMessage { hash: sub.block_hash }
                                                )),
                                            }).await;
                                        }
                                    }
                                }
                                Some(ResponsePayload::VirtualDaaScoreChangedNotification(msg)) => {
                                    let _ = daa_tx.send(msg.virtual_daa_score);
                                }
                                Some(ResponsePayload::UtxosChangedNotification(msg)) => {
                                    let _ = utxo_tx.send(msg);
                                }
                                _ => {}
                            }
                        }
                        
                        poll_task.abort();
                        *active_node_tx.write().await = None;
                        pending_submissions.clear();
                        tracing::error!("🚨 Node {} dropped the gRPC connection.", url);
                    }
                    Err(e) => {
                        *active_node_tx.write().await = None;
                        pending_submissions.clear();
                        tracing::error!("⚠️ Failed to establish gRPC stream to {}: {}", url, e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("⚠️ Node {} is unreachable: {}. Moving to failover...", url, e);
            }
        }
        
        let _: redis::RedisResult<()> = redis_conn.set("perennia:node:sync_status", "Failover Reconnecting").await;
        
        current_node_idx = (current_node_idx + 1) % node_array.len();
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    }
}