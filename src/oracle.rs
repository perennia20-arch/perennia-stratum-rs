use std::time::Duration;
use serde_json::Value;

pub async fn start_spot_pricing_daemon() {
    tracing::info!("🌐 Global Spot Price Oracle Daemon Booting...");
    
    let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).build().unwrap();
    let redis_client = match redis::Client::open("redis://127.0.0.1/") {
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

    let mut interval = tokio::time::interval(Duration::from_secs(15));

    loop {
        interval.tick().await;

        let url = "https://api.coingecko.com/api/v3/simple/price?ids=kaspa,bitcoin,ethereum,solana&vs_currencies=usd&include_24hr_change=true";
        
        match client.get(url).header("User-Agent", "Perennia-Core-Backend/1.0").send().await {
            Ok(res) => {
                if let Ok(data) = res.json::<serde_json::Value>().await {
                    let mut pipeline = redis::pipe();
                    
                    pipeline.cmd("SET").arg("oracle:spot:prices_json").arg(data.to_string()).ignore();

                    let assets = [
                        ("kaspa", "KAS_USDC"),
                        ("bitcoin", "BTC_USDC"),
                        ("ethereum", "ETH_USDC"),
                        ("solana", "SOL_USDC")
                    ];

                    for (cg_id, pair_id) in assets.iter() {
                        if let Some(asset_data) = data.get(*cg_id) {
                            if let Some(usd) = asset_data.get("usd").and_then(|v| v.as_f64()) {
                                pipeline.cmd("SET").arg(format!("oracle:spot:{}", pair_id)).arg(usd.to_string()).ignore();
                            }
                            if let Some(change) = asset_data.get("usd_24h_change").and_then(|v| v.as_f64()) {
                                pipeline.cmd("SET").arg(format!("oracle:change:{}", pair_id)).arg(change.to_string()).ignore();
                            }
                        }
                    }

                    if let Err(e) = pipeline.query_async::<_, ()>(&mut redis_conn).await {
                        tracing::error!("Spot Oracle Redis Pipeline Failed: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Spot Oracle Upstream Fetch Failed: {}", e);
            }
        }
    }
}

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

    let redis_client = match redis::Client::open("redis://127.0.0.1/") {
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

        // ⚡ PHASE 2 PURGE: Legacy share_buffer and double-accounting removed. 
        // Yield routing is now strictly handled by chronos.rs for absolute Silo precision.

        // ⚡ Process Network Block Buffer into PostgreSQL 
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