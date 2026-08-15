// src/oracle.rs

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use std::env;

// Matrix: Asset -> (Exchange -> (Price, LastUpdatedTimestamp))
type PriceMap = Arc<RwLock<HashMap<String, HashMap<String, (f64, Instant)>>>>;

pub async fn start_spot_pricing_daemon() {
    tracing::info!("🌐 Global 5-Node Sovereign Oracle Daemon Booting...");
    
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    
    let redis_client = match redis::Client::open(redis_url) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Spot Oracle Redis connection failed: {}", e);
            return;
        }
    };

    let mut redis_conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Spot Oracle Redis multiplexer failed: {}", e);
            return;
        }
    };

    // Initialize the Zero-Trust Price Matrix
    let prices: PriceMap = Arc::new(RwLock::new(HashMap::new()));
    for asset in ["KAS", "BTC", "ETH", "SOL"] {
        prices.write().await.insert(asset.to_string(), HashMap::new());
    }

    // Spawn the 5 independent WebSocket telemetry nodes
    tokio::spawn(bybit_ws(prices.clone()));
    tokio::spawn(gate_ws(prices.clone()));
    tokio::spawn(mexc_ws(prices.clone()));
    tokio::spawn(bitget_ws(prices.clone()));
    tokio::spawn(coinex_ws(prices.clone()));

    // ⚡ THE MEDIAN SAFETY LOCK (Executes every 1 second)
    let mut interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        interval.tick().await;
        let mut medians = HashMap::new();
        let now = Instant::now();

        {
            let p_lock = prices.read().await;
            for asset in ["KAS", "BTC", "ETH", "SOL"] {
                if let Some(exchanges) = p_lock.get(asset) {
                    
                    // 1. Stale-Data Lockout: Drop any exchange that hasn't pushed an update in 10s
                    let mut vals: Vec<f64> = exchanges.values()
                        .filter(|(_, ts)| now.duration_since(*ts).as_secs() < 10)
                        .map(|(v, _)| *v)
                        .collect();

                    // 2. Median Consensus Filter
                    if !vals.is_empty() {
                        vals.sort_by(|a, b| a.partial_cmp(b).unwrap());
                        let mid = vals.len() / 2;
                        let median = if vals.len() % 2 == 0 {
                            (vals[mid - 1] + vals[mid]) / 2.0
                        } else {
                            vals[mid]
                        };
                        medians.insert(asset.to_string(), median);
                    }
                }
            }
        }

        // Push scrubbed medians to the internal Dark Pool IPC
        if !medians.is_empty() {
            let mut pipeline = redis::pipe();
            let mut json_data = json!({});
            
            for (asset, median) in &medians {
                let pair_id = format!("{}_USDC", asset);
                pipeline.cmd("SET").arg(format!("oracle:spot:{}", pair_id)).arg(median.to_string()).ignore();
                
                // Front-end mapping translation
                let asset_key = match asset.as_str() {
                    "KAS" => "kaspa",
                    "BTC" => "bitcoin",
                    "ETH" => "ethereum",
                    "SOL" => "solana",
                    _ => asset.as_str()
                };
                json_data[asset_key] = json!({ "usd": median, "usd_24h_change": 0.0 });
            }
            
            pipeline.cmd("SET").arg("oracle:spot:prices_json").arg(json_data.to_string()).ignore();

            if let Err(e) = pipeline.query_async::<_, ()>(&mut redis_conn).await {
                tracing::error!("Spot Oracle Redis Pipeline Failed: {}", e);
            }
        }
    }
}

// ============================================================================
// 📡 THE 5-NODE EXCHANGE WEBSOCKET ARRAY
// ============================================================================

async fn bybit_ws(prices: PriceMap) {
    loop {
        if let Ok((ws_stream, _)) = connect_async("wss://stream.bybit.com/v5/public/spot").await {
            tracing::info!("📡 [Oracle Array] Node 1 Online: Bybit");
            let (mut write, mut read) = ws_stream.split();
            
            let sub = json!({"op": "subscribe", "args": ["tickers.KASUSDT", "tickers.BTCUSDT", "tickers.ETHUSDT", "tickers.SOLUSDT"]});
            let _ = write.send(Message::Text(sub.to_string())).await;

            while let Some(msg) = read.next().await {
                if let Ok(Message::Text(text)) = msg {
                    if let Ok(json) = serde_json::from_str::<Value>(&text) {
                        if let Some(topic) = json.get("topic").and_then(|t| t.as_str()) {
                            if let Some(last_price) = json.get("data").and_then(|d| d.get("lastPrice")).and_then(|p| p.as_str()) {
                                if let Ok(val) = last_price.parse::<f64>() {
                                    let asset = topic.replace("tickers.", "").replace("USDT", "");
                                    if let Some(ex_map) = prices.write().await.get_mut(&asset) {
                                        ex_map.insert("bybit".to_string(), (val, Instant::now()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn gate_ws(prices: PriceMap) {
    loop {
        if let Ok((ws_stream, _)) = connect_async("wss://api.gateio.ws/ws/v4/").await {
            tracing::info!("📡 [Oracle Array] Node 2 Online: Gate.io");
            let (mut write, mut read) = ws_stream.split();
            
            let sub = json!({
                "time": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                "channel": "spot.tickers",
                "event": "subscribe",
                "payload": ["KAS_USDT", "BTC_USDT", "ETH_USDT", "SOL_USDT"]
            });
            let _ = write.send(Message::Text(sub.to_string())).await;

            while let Some(msg) = read.next().await {
                if let Ok(Message::Text(text)) = msg {
                    if let Ok(json) = serde_json::from_str::<Value>(&text) {
                        if json.get("event").and_then(|e| e.as_str()) == Some("update") {
                            if let Some(result) = json.get("result") {
                                let items = if result.is_array() { result.as_array().unwrap().clone() } else { vec![result.clone()] };
                                for item in items {
                                    if let (Some(pair), Some(last)) = (item.get("currency_pair").and_then(|p| p.as_str()), item.get("last").and_then(|l| l.as_str())) {
                                        if let Ok(val) = last.parse::<f64>() {
                                            let asset = pair.replace("_USDT", "");
                                            if let Some(ex_map) = prices.write().await.get_mut(&asset) {
                                                ex_map.insert("gate".to_string(), (val, Instant::now()));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn mexc_ws(prices: PriceMap) {
    loop {
        if let Ok((ws_stream, _)) = connect_async("wss://wbs.mexc.com/ws").await {
            tracing::info!("📡 [Oracle Array] Node 3 Online: MEXC");
            let (mut write, mut read) = ws_stream.split();
            
            let sub = json!({
                "method": "SUBSCRIPTION",
                "params": [
                    "spot@public.miniTicker.v3.api@KASUSDT",
                    "spot@public.miniTicker.v3.api@BTCUSDT",
                    "spot@public.miniTicker.v3.api@ETHUSDT",
                    "spot@public.miniTicker.v3.api@SOLUSDT"
                ]
            });
            let _ = write.send(Message::Text(sub.to_string())).await;

            while let Some(msg) = read.next().await {
                if let Ok(Message::Text(text)) = msg {
                    if let Ok(json) = serde_json::from_str::<Value>(&text) {
                        if let Some(c) = json.get("c").and_then(|c| c.as_str()) {
                            if let Some(p) = json.get("d").and_then(|d| d.get("p")).and_then(|p| p.as_str()) {
                                if let Ok(val) = p.parse::<f64>() {
                                    let asset = c.split('@').last().unwrap_or("").replace("USDT", "");
                                    if let Some(ex_map) = prices.write().await.get_mut(&asset) {
                                        ex_map.insert("mexc".to_string(), (val, Instant::now()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn bitget_ws(prices: PriceMap) {
    loop {
        if let Ok((ws_stream, _)) = connect_async("wss://ws.bitget.com/v2/ws/public").await {
            tracing::info!("📡 [Oracle Array] Node 4 Online: Bitget");
            let (mut write, mut read) = ws_stream.split();
            
            let sub = json!({
                "op": "subscribe",
                "args": [
                    {"instType": "SPOT", "channel": "ticker", "instId": "KASUSDT"},
                    {"instType": "SPOT", "channel": "ticker", "instId": "BTCUSDT"},
                    {"instType": "SPOT", "channel": "ticker", "instId": "ETHUSDT"},
                    {"instType": "SPOT", "channel": "ticker", "instId": "SOLUSDT"}
                ]
            });
            let _ = write.send(Message::Text(sub.to_string())).await;

            while let Some(msg) = read.next().await {
                if let Ok(Message::Text(text)) = msg {
                    if text == "pong" { continue; }
                    if let Ok(json) = serde_json::from_str::<Value>(&text) {
                        if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                            for item in data {
                                if let (Some(inst), Some(last)) = (item.get("instId").and_then(|i| i.as_str()), item.get("lastPr").and_then(|l| l.as_str())) {
                                    if let Ok(val) = last.parse::<f64>() {
                                        let asset = inst.replace("USDT", "");
                                        if let Some(ex_map) = prices.write().await.get_mut(&asset) {
                                            ex_map.insert("bitget".to_string(), (val, Instant::now()));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn coinex_ws(prices: PriceMap) {
    loop {
        if let Ok((ws_stream, _)) = connect_async("wss://socket.coinex.com/v2/spot").await {
            tracing::info!("📡 [Oracle Array] Node 5 Online: CoinEx");
            let (mut write, mut read) = ws_stream.split();
            
            let sub = json!({
                "method": "state.subscribe",
                "params": {"market_list": ["KASUSDT", "BTCUSDT", "ETHUSDT", "SOLUSDT"]},
                "id": 1
            });
            let _ = write.send(Message::Text(sub.to_string())).await;

            while let Some(msg) = read.next().await {
                if let Ok(Message::Text(text)) = msg {
                    if let Ok(json) = serde_json::from_str::<Value>(&text) {
                        if json.get("method").and_then(|m| m.as_str()) == Some("state.update") {
                            if let Some(state_list) = json.get("data").and_then(|d| d.get("state_list")).and_then(|l| l.as_array()) {
                                for item in state_list {
                                    if let (Some(market), Some(last)) = (item.get("market").and_then(|m| m.as_str()), item.get("last").and_then(|l| l.as_str())) {
                                        if let Ok(val) = last.parse::<f64>() {
                                            let asset = market.replace("USDT", "");
                                            if let Some(ex_map) = prices.write().await.get_mut(&asset) {
                                                ex_map.insert("coinex".to_string(), (val, Instant::now()));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

// ============================================================================
// THE L1 NETWORK BLOCK SETTLEMENT DAEMON
// ============================================================================
pub async fn start_oracle_daemon() {
    tracing::info!("🔮 Yield Oracle Daemon Booting...");

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@127.0.0.1:5432/perennia".to_string());
    
    let pool = match sqlx::PgPool::connect(&db_url).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Oracle DB connection failed: {}", e);
            return;
        }
    };

    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = match redis::Client::open(redis_url) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Oracle Redis connection failed: {}", e);
            return;
        }
    };

    let mut redis_conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Oracle Redis multiplexer failed: {}", e);
            return;
        }
    };

    let mut interval = tokio::time::interval(Duration::from_secs(5));

    loop {
        interval.tick().await;

        let mut block_events = Vec::new();
        loop {
            let result: redis::RedisResult<Option<String>> = redis::cmd("LPOP")
                .arg("perennia:oracle:block_buffer")
                .query_async(&mut redis_conn)
                .await;

            match result {
                Ok(Some(event_str)) => {
                    if let Ok(parsed) = serde_json::from_str::<Value>(&event_str) {
                        block_events.push(parsed);
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }

        if !block_events.is_empty() {
            let mut tx_blocks = match pool.begin().await {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!("Oracle failed to start DB transaction for blocks: {}", e);
                    continue;
                }
            };
            
            let mut hashes = Vec::with_capacity(block_events.len());
            let mut workers = Vec::with_capacity(block_events.len());
            let mut nonces = Vec::with_capacity(block_events.len());
            let mut diffs = Vec::with_capacity(block_events.len());

            for evt in &block_events {
                if let (Some(hash), Some(worker), Some(nonce), Some(diff)) = (
                    evt["block_hash"].as_str(),
                    evt["worker"].as_str(),
                    evt["nonce"].as_u64(),
                    evt["network_diff"].as_f64()
                ) {
                    hashes.push(hash.to_string());
                    workers.push(worker.to_string());
                    nonces.push(nonce as i64); 
                    diffs.push(diff);
                }
            }

            if !hashes.is_empty() {
                let insert_res = sqlx::query(
                    r#"
                    INSERT INTO network_blocks (block_hash, worker_id, nonce, network_diff)
                    SELECT * FROM UNNEST($1::text[], $2::text[], $3::bigint[], $4::float8[])
                    ON CONFLICT (block_hash) DO NOTHING
                    "#
                )
                .bind(&hashes).bind(&workers).bind(&nonces).bind(&diffs)
                .execute(&mut *tx_blocks).await;

                if let Err(e) = insert_res {
                    tracing::error!("Failed to insert network blocks: {}", e);
                    let _ = tx_blocks.rollback().await;
                } else {
                    let _ = tx_blocks.commit().await;
                    tracing::info!("🧱 [ORACLE] Settled {} L1 network blocks into Postgres.", hashes.len());
                }
            }
        }
    }
}