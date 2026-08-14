use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use redis::AsyncCommands; 
use crate::config::StratumConfig;
use crate::job_manager::JobManager; 

pub mod protowire {
    tonic::include_proto!("protowire");
}

use protowire::rpc_client::RpcClient;
use protowire::{KaspadRequest, GetBlockTemplateRequestMessage, NotifyBlockAddedRequestMessage, SubmitBlockRequestMessage, NotifyNewBlockTemplateRequestMessage, GetBlockDagInfoRequestMessage};
use protowire::kaspad_request::Payload as RequestPayload;
use protowire::kaspad_response::Payload as ResponsePayload;
use protowire::RpcBlock;

pub async fn start_kaspad_client(
    config: Arc<StratumConfig>, 
    job_manager: Arc<JobManager>,
    mut block_submit_rx: mpsc::Receiver<RpcBlock>
) -> anyhow::Result<()> {
    let mut url = config.kaspad_address.clone();
    if !url.starts_with("http") {
        url = format!("http://{}", url);
    }
    
    tracing::info!("🔌 Connecting to local Redis Cache for Frontend UI...");
    let redis_client = redis::Client::open("redis://127.0.0.1/")?;
    let mut redis_conn = redis_client.get_multiplexed_async_connection().await?;
    
    tracing::info!("🔗 Booting gRPC Uplink to Upstream Node: {}", url);
    let mut client = RpcClient::connect(url).await?;
    tracing::info!("✅ Uplink Established. Subscribing to DAG consensus...");

    let (tx, rx) = mpsc::channel::<KaspadRequest>(100);
    let request_stream = ReceiverStream::new(rx);
    let mut response_stream = client.message_stream(request_stream).await?.into_inner();

    let tx_submit = tx.clone();
    tokio::spawn(async move {
        while let Some(winning_block) = block_submit_rx.recv().await {
            tracing::info!("🚀🚀🚀 DISPATCHING BLOCK TO MAINNET CONVERGENCE LAYER 🚀🚀🚀");
            let req = KaspadRequest {
                id: 999,
                payload: Some(RequestPayload::SubmitBlockRequest(SubmitBlockRequestMessage {
                    block: Some(winning_block),
                    allow_non_daa_blocks: false,
                })),
            };
            let _ = tx_submit.send(req).await;
        }
    });

    tx.send(KaspadRequest {
        id: 1,
        payload: Some(RequestPayload::NotifyBlockAddedRequest(NotifyBlockAddedRequestMessage { command: 0 })),
    }).await?;

    tx.send(KaspadRequest {
        id: 2,
        payload: Some(RequestPayload::NotifyNewBlockTemplateRequest(NotifyNewBlockTemplateRequestMessage { command: 0 })),
    }).await?;

    tx.send(KaspadRequest {
        id: 3,
        payload: Some(RequestPayload::GetBlockTemplateRequest(GetBlockTemplateRequestMessage {
            pay_address: config.mining_address.clone(),
            extra_data: "Perennia-Zero-Allocation".to_string(),
        })),
    }).await?;

    let tx_poll = tx.clone();
    let mining_address_poll = config.mining_address.clone();
    tokio::spawn(async move {
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
            if tx_poll.send(req_template).await.is_err() {
                break;
            }
            
            req_id += 1;
            let req_dag = KaspadRequest {
                id: req_id,
                payload: Some(RequestPayload::GetBlockDagInfoRequest(GetBlockDagInfoRequestMessage {})),
            };
            if tx_poll.send(req_dag).await.is_err() {
                break;
            }
        }
    });

    let mining_address = config.mining_address.clone();
    let tx_clone = tx.clone();
    
    tokio::spawn(async move {
        let mut req_id = 3;
        while let Ok(Some(response)) = response_stream.message().await {
            match response.payload {
                Some(ResponsePayload::GetBlockTemplateResponse(res)) => {
                    if let Some(err) = res.error {
                        tracing::error!("❌ GET_BLOCK_TEMPLATE REJECTED BY NODE: {}", err.message);
                    } else if let Some(block) = res.block {
                        
                        // ⚡ Mainnet Math: Ensures block reward is securely captured so Chronos doesn't fault out
                        let mut block_reward = 50.0;
                        if let Some(coinbase_tx) = block.transactions.first() {
                            let total_sompi: u64 = coinbase_tx.outputs.iter().map(|o| o.amount).sum();
                            if total_sompi > 0 {
                                block_reward = total_sompi as f64 / 100_000_000.0;
                            }
                        }
                        let _: redis::RedisResult<()> = redis_conn.set("pool:block_reward", block_reward).await;

                        if let Some(header) = &block.header {
                            tracing::debug!("🧊 Toccata Block Template Acquired! Blue Score: {} | Reward: {} KAS", header.blue_score, block_reward);
                            let set_res: redis::RedisResult<()> = redis_conn.set("perennia:node:sync_status", "Online (Toccata Core)").await;
                            if set_res.is_err() {
                                if let Ok(new_conn) = redis_client.get_multiplexed_async_connection().await {
                                    redis_conn = new_conn;
                                }
                            }
                            job_manager.process_new_block(block.clone());
                        }
                    }
                }
                Some(ResponsePayload::GetBlockDagInfoResponse(res)) => {
                    if let Some(err) = res.error {
                        tracing::error!("❌ GET_BLOCK_DAG_INFO REJECTED BY NODE: {}", err.message);
                    } else {
                        // ⚡ Pushes real-time network expected hashes (Difficulty) into Redis
                        let _: redis::RedisResult<()> = redis_conn.set("pool:network_diff", res.difficulty).await;
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
                    if let Some(err) = res.error {
                        tracing::error!("❌ BLOCK VALIDATION ERROR: {}", err.message);
                    } else {
                        tracing::info!("💰💰💰 BLOCK ACCEPTED! CONVERGENCE SETTLED. REWARD LOCKED. 💰💰💰");
                    }
                }
                _ => {}
            }
        }
        
        tracing::error!("🚨 Kaspa node gRPC connection lost! Stratum halting to force restart...");
        std::process::exit(1);
    });

    Ok(())
}