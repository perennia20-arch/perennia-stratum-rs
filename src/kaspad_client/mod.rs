use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use redis::AsyncCommands;
use dashmap::DashMap;
use serde_json::{json, Value};
use crate::config::StratumConfig;
use crate::job_manager::{JobManager, PendingBlockSubmission};
use std::env;
use std::time::Duration;

pub mod protowire {
    tonic::include_proto!("protowire");
}

use protowire::rpc_client::RpcClient;
use protowire::{
    KaspadRequest, GetBlockTemplateRequestMessage, NotifyBlockAddedRequestMessage,
    SubmitBlockRequestMessage, NotifyNewBlockTemplateRequestMessage,
    GetBlockDagInfoRequestMessage, GetBlockRewardInfoRequestMessage,
    GetBalanceByAddressRequestMessage, GetUtxosByAddressesRequestMessage,
    SubmitTransactionRequestMessage, RpcTransaction, RpcTransactionInput,
    RpcTransactionOutput, RpcOutpoint, RpcScriptPublicKey,
};
use protowire::kaspad_request::Payload as RequestPayload;
use protowire::kaspad_response::Payload as ResponsePayload;

static SUBMIT_REQ_COUNTER: AtomicU64 = AtomicU64::new(1_000_000);
static REWARD_REQ_COUNTER: AtomicU64 = AtomicU64::new(2_000_000);
static DIRECT_RPC_REQ_COUNTER: AtomicU64 = AtomicU64::new(5_000_000);

fn is_local_or_lan_endpoint(addr: &str) -> bool {
    let clean = addr
        .trim()
        .to_lowercase()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .to_string();
    clean.starts_with("127.")
        || clean.starts_with("localhost")
        || clean.starts_with("192.168.")
        || clean.starts_with("10.")
        || clean.starts_with("172.16.")
        || clean.starts_with("172.17.")
        || clean.starts_with("172.18.")
        || clean.starts_with("172.19.")
        || clean.starts_with("172.2")
        || clean.starts_with("172.30.")
        || clean.starts_with("172.31.")
}

pub fn resolve_local_first_grpc_endpoints() -> Vec<String> {
    let mut raw_endpoints: Vec<String> = Vec::new();
    if let Ok(env_grpc) = env::var("KASPAD_GRPC_URL") {
        let trimmed = env_grpc.trim().to_string();
        if !trimmed.is_empty() {
            raw_endpoints.push(trimmed);
        }
    }
    if let Ok(env_ip) = env::var("KASPA_NODE_IP") {
        let trimmed = env_ip.trim().to_string();
        if !trimmed.is_empty() {
            let candidate = if trimmed.contains(':') {
                trimmed
            } else {
                format!("{}:16110", trimmed)
            };
            if !raw_endpoints.contains(&candidate) {
                raw_endpoints.push(candidate);
            }
        }
    }
    if let Ok(cfg) = StratumConfig::load("config.yaml") {
        for addr in cfg.kaspad_addresses {
            let trimmed = addr.trim().to_string();
            if !trimmed.is_empty() && !raw_endpoints.contains(&trimmed) {
                raw_endpoints.push(trimmed);
            }
        }
    }
    if raw_endpoints.is_empty() {
        raw_endpoints.push("127.0.0.1:16110".to_string());
    }
    let mut local_endpoints = Vec::new();
    let mut remote_endpoints = Vec::new();
    for ep in raw_endpoints {
        let formatted = if ep.starts_with("http://") || ep.starts_with("https://") {
            ep
        } else {
            format!("http://{}", ep)
        };
        if is_local_or_lan_endpoint(&formatted) {
            local_endpoints.push(formatted);
        } else {
            remote_endpoints.push(formatted);
        }
    }
    local_endpoints.extend(remote_endpoints);
    local_endpoints
}

async fn execute_single_grpc_request(payload: RequestPayload) -> Result<ResponsePayload, String> {
    let endpoints = resolve_local_first_grpc_endpoints();
    let mut last_err = String::from("No kaspad gRPC endpoints configured");
    for endpoint in endpoints {
        let connect_res = tokio::time::timeout(
            Duration::from_millis(2500),
            RpcClient::connect(endpoint.clone()),
        )
        .await;
        let mut client = match connect_res {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                last_err = format!("{} connect error: {}", endpoint, e);
                continue;
            }
            Err(_) => {
                last_err = format!("{} connect timeout", endpoint);
                continue;
            }
        };
        let (tx, rx) = mpsc::channel::<KaspadRequest>(2);
        let req_id = DIRECT_RPC_REQ_COUNTER.fetch_add(1, Ordering::Relaxed);
        let _ = tx
            .send(KaspadRequest {
                id: req_id,
                payload: Some(payload.clone()),
            })
            .await;
        let stream_res = tokio::time::timeout(
            Duration::from_millis(3500),
            client.message_stream(ReceiverStream::new(rx)),
        )
        .await;
        let mut response_stream = match stream_res {
            Ok(Ok(resp)) => resp.into_inner(),
            Ok(Err(e)) => {
                last_err = format!("{} stream error: {}", endpoint, e);
                continue;
            }
            Err(_) => {
                last_err = format!("{} stream timeout", endpoint);
                continue;
            }
        };
        match tokio::time::timeout(Duration::from_millis(3500), response_stream.message()).await {
            Ok(Ok(Some(msg))) => {
                if let Some(resp_payload) = msg.payload {
                    return Ok(resp_payload);
                }
                last_err = format!("{} returned empty gRPC payload", endpoint);
            }
            Ok(Ok(None)) => {
                last_err = format!("{} closed gRPC stream without response", endpoint);
            }
            Ok(Err(e)) => {
                last_err = format!("{} message error: {}", endpoint, e);
            }
            Err(_) => {
                last_err = format!("{} response timeout", endpoint);
            }
        }
    }
    Err(last_err)
}

pub async fn get_balance_by_address_grpc(address: &str) -> Result<u64, String> {
    let clean = address.trim().to_lowercase().replace("kaspa:", "");
    let formatted = format!("kaspa:{}", clean);
    let req = RequestPayload::GetBalanceByAddressRequest(GetBalanceByAddressRequestMessage {
        address: formatted,
    });
    match execute_single_grpc_request(req).await? {
        ResponsePayload::GetBalanceByAddressResponse(res) => {
            if let Some(err) = res.error {
                return Err(format!("kaspad gRPC GetBalanceByAddress error: {}", err.message));
            }
            Ok(res.balance)
        }
        _ => Err("Unexpected gRPC response variant for GetBalanceByAddress".to_string()),
    }
}

pub async fn get_utxos_by_address_grpc(address: &str) -> Result<Vec<Value>, String> {
    let clean = address.trim().to_lowercase().replace("kaspa:", "");
    let formatted = format!("kaspa:{}", clean);
    let req = RequestPayload::GetUtxosByAddressesRequest(GetUtxosByAddressesRequestMessage {
        addresses: vec![formatted],
    });
    match execute_single_grpc_request(req).await? {
        ResponsePayload::GetUtxosByAddressesResponse(res) => {
            if let Some(err) = res.error {
                return Err(format!("kaspad gRPC GetUtxosByAddresses error: {}", err.message));
            }
            let mut entries = Vec::with_capacity(res.entries.len());
            for entry in res.entries {
                let (Some(outpoint), Some(utxo_entry)) = (entry.outpoint, entry.utxo_entry) else {
                    continue;
                };
                let (spk_version, spk_hex) = match utxo_entry.script_public_key {
                    Some(spk) => (spk.version, spk.script_public_key),
                    None => (0, String::new()),
                };
                entries.push(json!({
                    "address": entry.address,
                    "outpoint": {
                        "transactionId": outpoint.transaction_id,
                        "index": outpoint.index
                    },
                    "utxoEntry": {
                        "amount": utxo_entry.amount.to_string(),
                        "scriptPublicKey": {
                            "version": spk_version,
                            "scriptPublicKey": spk_hex
                        },
                        "blockDaaScore": utxo_entry.block_daa_score.to_string(),
                        "isCoinbase": utxo_entry.is_coinbase
                    }
                }));
            }
            Ok(entries)
        }
        _ => Err("Unexpected gRPC response variant for GetUtxosByAddresses".to_string()),
    }
}

fn parse_json_to_rpc_transaction(tx_payload: &Value) -> Result<RpcTransaction, String> {
    let tx_obj = tx_payload.get("transaction").unwrap_or(tx_payload);
    let version = tx_obj
        .get("version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let lock_time = tx_obj
        .get("lockTime")
        .or_else(|| tx_obj.get("lock_time"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let subnetwork_id = tx_obj
        .get("subnetworkId")
        .or_else(|| tx_obj.get("subnetwork_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("0000000000000000000000000000000000000000")
        .to_string();
    let gas = tx_obj.get("gas").and_then(|v| v.as_u64()).unwrap_or(0);
    let payload = tx_obj
        .get("payload")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let raw_inputs = tx_obj
        .get("inputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Transaction JSON missing inputs array".to_string())?;
    let mut inputs = Vec::with_capacity(raw_inputs.len());
    for inp in raw_inputs {
        let prev = inp.get("previousOutpoint").unwrap_or(inp);
        let tx_id = prev
            .get("transactionId")
            .or_else(|| prev.get("transaction_id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Input missing previousOutpoint.transactionId".to_string())?
            .to_string();
        let index = prev
            .get("index")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let signature_script = inp
            .get("signatureScript")
            .or_else(|| inp.get("signature_script"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let sequence = inp.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0);
        let sig_op_count = inp
            .get("sigOpCount")
            .or_else(|| inp.get("sig_op_count"))
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u32;
        inputs.push(RpcTransactionInput {
            previous_outpoint: Some(RpcOutpoint {
                transaction_id: tx_id,
                index,
            }),
            signature_script,
            sequence,
            sig_op_count,
            ..Default::default()
        });
    }

    let raw_outputs = tx_obj
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Transaction JSON missing outputs array".to_string())?;
    let mut outputs = Vec::with_capacity(raw_outputs.len());
    for out in raw_outputs {
        let amount = out
            .get("amount")
            .or_else(|| out.get("value"))
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_f64().map(|f| f.round() as u64))
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            })
            .ok_or_else(|| "Output missing amount".to_string())?;
        let spk_field = out.get("scriptPublicKey").or_else(|| out.get("script_public_key"));
        let (spk_version, spk_hex) = match spk_field {
            Some(Value::String(s)) => (0u32, s.clone()),
            Some(Value::Object(map)) => {
                let ver = map
                    .get("version")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                let hex_str = map
                    .get("scriptPublicKey")
                    .or_else(|| map.get("script_public_key"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                (ver, hex_str)
            }
            _ => return Err("Output missing scriptPublicKey".to_string()),
        };
        outputs.push(RpcTransactionOutput {
            amount,
            script_public_key: Some(RpcScriptPublicKey {
                version: spk_version,
                script_public_key: spk_hex,
            }),
            ..Default::default()
        });
    }

    Ok(RpcTransaction {
        version,
        inputs,
        outputs,
        lock_time,
        subnetwork_id,
        gas,
        payload,
        ..Default::default()
    })
}

pub async fn submit_transaction_grpc(tx_payload: &Value, allow_orphan: bool) -> Result<String, String> {
    let rpc_tx = parse_json_to_rpc_transaction(tx_payload)?;
    let req = RequestPayload::SubmitTransactionRequest(SubmitTransactionRequestMessage {
        transaction: Some(rpc_tx),
        allow_orphan,
    });
    match execute_single_grpc_request(req).await? {
        ResponsePayload::SubmitTransactionResponse(res) => {
            if let Some(err) = res.error {
                return Err(format!("kaspad gRPC SubmitTransaction rejected: {}", err.message));
            }
            if res.transaction_id.trim().is_empty() {
                return Err("kaspad gRPC SubmitTransaction returned empty transaction_id".to_string());
            }
            Ok(res.transaction_id)
        }
        _ => Err("Unexpected gRPC response variant for SubmitTransaction".to_string()),
    }
}

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
                                            if header.daa_score > 0 {
                                                let _: redis::RedisResult<()> = redis_conn.set("pool:virtual_daa_score", header.daa_score).await;
                                            }
                                        }
                                        let (template_net_diff, coinbase_reward_sompi) = job_manager.process_new_block(block);
                                        if template_net_diff > 0.0 {
                                            let _: redis::RedisResult<()> = redis_conn.set("pool:network_diff", template_net_diff).await;
                                        }
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
                                        if res.virtual_daa_score > 0 {
                                            let _: redis::RedisResult<()> = redis_conn.set("pool:virtual_daa_score", res.virtual_daa_score).await;
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
                                            let block_daa_score = sub
                                                .block
                                                .header
                                                .as_ref()
                                                .map(|h| h.daa_score)
                                                .unwrap_or(0);
                                            let _ = valid_share_tx.send((sub.worker.clone(), 0.0, true)).await;
                                            let block_event = serde_json::json!({
                                                "worker": sub.worker,
                                                "block_hash": sub.block_hash,
                                                "nonce": sub.nonce,
                                                "network_diff": sub.network_diff,
                                                "reward_sompi": resolved_reward_sompi,
                                                "reward_kas": resolved_reward_kas,
                                                "daa_score": block_daa_score
                                            });
                                            let _: redis::RedisResult<()> = redis::cmd("RPUSH")
                                                .arg("perennia:oracle:block_buffer")
                                                .arg(block_event.to_string())
                                                .query_async(&mut redis_conn)
                                                .await;
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
                                    if msg.virtual_daa_score > 0 {
                                        let _: redis::RedisResult<()> = redis_conn.set("pool:virtual_daa_score", msg.virtual_daa_score).await;
                                    }
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