use std::collections::HashMap;
use std::time::Duration;
use redis::AsyncCommands;
use serde_json::Value;

// ⚡ GLOBAL PRICING DAEMON - Isolates 3rd Party APIs internally into local Redis states
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

    // Safe 15-second tick to prevent downstream rate-limiting from free-tier providers
    let mut interval = tokio::time::interval(Duration::from_secs(15));

    loop {
        interval.tick().await;

        let url = "https://api.coingecko.com/api/v3/simple/price?ids=kaspa,bitcoin,ethereum,solana&vs_currencies=usd&include_24hr_change=true";
        
        match client.get(url).header("User-Agent", "Perennia-Core-Backend/1.0").send().await {
            Ok(res) => {
                if let Ok(data) = res.json::<serde_json::Value>().await {
                    let mut pipeline = redis::pipe();
                    
                    // Master payload for the SvelteKit frontend cache (Read natively via SvelteKit)
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

                    // Execute the atomic Redis pipeline flush
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

        let mut wallet_aggregates: HashMap<String, f64> = HashMap::new();
        
        // 1. Pop shares from the Redis buffer
        loop {
            let result: redis::RedisResult<Option<String>> = redis::cmd("LPOP")
                .arg("perennia:oracle:share_buffer")
                .query_async(&mut redis_conn)
                .await;

            match result {
                Ok(Some(event_str)) => {
                    if let Ok(parsed) = serde_json::from_str::<Value>(&event_str) {
                        if let (Some(worker), Some(diff)) = (parsed["worker"].as_str(), parsed["difficulty"].as_f64()) {
                            let parts: Vec<&str> = worker.split('.').collect();
                            let wallet = if !parts.is_empty() { parts[0].to_string() } else { worker.to_string() };
                            *wallet_aggregates.entry(wallet).or_insert(0.0) += diff;
                        }
                    }
                }
                Ok(None) => break, // Buffer empty
                Err(_) => break, // Redis error
            }
        }

        if wallet_aggregates.is_empty() {
            continue;
        }

        let mut tx = match pool.begin().await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Oracle failed to start DB transaction: {}", e);
                continue;
            }
        };

        let mut commit_success = true;

        // 2. Bulk Aggregated Upsert into Yield Reservoirs
        let mut agg_wallets = Vec::with_capacity(wallet_aggregates.len());
        let mut agg_deltas = Vec::with_capacity(wallet_aggregates.len());
        
        for (w, d) in &wallet_aggregates {
            agg_wallets.push(w.clone());
            agg_deltas.push(*d);
        }

        if commit_success {
            let upsert_res = sqlx::query(
                r#"
                INSERT INTO yield_reservoirs (wallet_address, streaming_balance_kas, total_yield_kas)
                SELECT * FROM UNNEST($1::text[], $2::float8[], $2::float8[])
                ON CONFLICT (wallet_address)
                DO UPDATE SET
                    streaming_balance_kas = yield_reservoirs.streaming_balance_kas + EXCLUDED.streaming_balance_kas,
                    total_yield_kas = yield_reservoirs.total_yield_kas + EXCLUDED.total_yield_kas,
                    last_updated = CURRENT_TIMESTAMP
                "#
            )
            .bind(&agg_wallets).bind(&agg_deltas)
            .execute(&mut *tx).await;

            if let Err(e) = upsert_res {
                tracing::error!("Upsert failed: {}", e);
                commit_success = false; 
            }
        }

        // 3. 1099-DA Compliance Stamping (Gross Proceeds Ledger)
        if commit_success && !agg_wallets.is_empty() {
            // Fetch live spot price from Redis to stamp the financial event
            let kas_spot_price: f64 = redis::cmd("GET")
                .arg("oracle:spot:KAS_USDC")
                .query_async(&mut redis_conn)
                .await
                .unwrap_or(0.16); // Failsafe to static baseline if oracle desyncs

            let mut event_types = Vec::with_capacity(agg_wallets.len());
            let mut tickers = Vec::with_capacity(agg_wallets.len());
            let mut gross_proceeds = Vec::with_capacity(agg_wallets.len());
            let mut spot_prices = Vec::with_capacity(agg_wallets.len());

            for delta in &agg_deltas {
                event_types.push("YIELD");
                tickers.push("KAS");
                gross_proceeds.push(delta * kas_spot_price);
                spot_prices.push(kas_spot_price);
            }

            let tax_ledger_res = sqlx::query(
                r#"
                INSERT INTO tax_ledger_events 
                (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution)
                SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::float8[], $5::float8[], $6::float8[])
                "#
            )
            .bind(&agg_wallets)
            .bind(&tickers)
            .bind(&event_types)
            .bind(&gross_proceeds)
            .bind(&agg_deltas)
            .bind(&spot_prices)
            .execute(&mut *tx).await;

            if let Err(e) = tax_ledger_res {
                tracing::error!("Tax ledger failed: {}", e);
                commit_success = false; 
            }
        }

        if commit_success {
            let _ = tx.commit().await;
        } else {
            let _ = tx.rollback().await;
        }
    }
}