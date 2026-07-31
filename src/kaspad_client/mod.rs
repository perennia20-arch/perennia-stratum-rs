// src/kaspad_client/mod.rs

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
use protowire::{KaspadRequest, GetBlockTemplateRequestMessage, NotifyBlockAddedRequestMessage, SubmitBlockRequestMessage};
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

    // ⚡ Dynamically poll Redis for the mining address before the first request
    let mut initial_pay_address = config.mining_address.clone();
    if let Ok(Some(addr)) = redis_conn.get::<_, Option<String>>("perennia:stratum:mining_address").await {
        if !addr.is_empty() {
            initial_pay_address = addr;
        }
    }

    tx.send(KaspadRequest {
        id: 2,
        payload: Some(RequestPayload::GetBlockTemplateRequest(GetBlockTemplateRequestMessage {
            pay_address: initial_pay_address,
            extra_data: "Perennia-Zero-Allocation".to_string(),
        })),
    }).await?;

    let fallback_address = config.mining_address.clone();
    let tx_clone = tx.clone();
    
    tokio::spawn(async move {
        let mut req_id = 3;
        while let Ok(Some(response)) = response_stream.message().await {
            match response.payload {
                Some(ResponsePayload::GetBlockTemplateResponse(res)) => {
                    if let Some(block) = res.block {
                        if let Some(header) = &block.header {
                            tracing::debug!("🧊 Toccata Block Template Acquired! Blue Score: {}", header.blue_score);
                            // ⚡ FIX: Re-establish dropped node ping dynamically
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
                Some(ResponsePayload::BlockAddedNotification(_)) => {
                    req_id += 1;
                    
                    // ⚡ Dynamically poll Redis to hot-swap the address on the fly
                    let mut current_pay_address = fallback_address.clone();
                    if let Ok(Some(addr)) = redis_conn.get::<_, Option<String>>("perennia:stratum:mining_address").await {
                        if !addr.is_empty() {
                            current_pay_address = addr;
                        }
                    }

                    let _ = tx_clone.send(KaspadRequest {
                        id: req_id,
                        payload: Some(RequestPayload::GetBlockTemplateRequest(GetBlockTemplateRequestMessage {
                            pay_address: current_pay_address,
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
    });

    Ok(())
}