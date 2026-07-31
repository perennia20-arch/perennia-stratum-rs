use std::collections::HashMap;
use std::env;
use std::time::Duration;
use redis::AsyncCommands;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use serde_json::Value;

pub async fn start_oracle_daemon() {
    tracing::info!("🛡️ Starting Perennia Sovereign Oracle Daemon (PostgreSQL WAL Pipeline)...");

    // 1. Establish PostgreSQL Connection Pool
    let db_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
        let node_ip = env::var("UBUNTU_NODE_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
        format!("postgres://postgres:password@{}:5432/perennia", node_ip)
    });

    let pg_pool = match PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&db_url)
        .await
    {
        Ok(pool) => {
            tracing::info!("🟢 Connected to PostgreSQL WAL Database.");
            pool
        }
        Err(e) => {
            tracing::error!("🔴 PostgreSQL Connection Failed: {}. Oracle daemon hibernating...", e);
            return;
        }
    };

    // 2. Establish Redis Multiplexed Connection
    let redis_client = match redis::Client::open("redis://127.0.0.1/") {
        Ok(client) => client,
        Err(e) => {
            tracing::error!("🔴 Redis client initialization failed for Oracle: {}", e);
            return;
        }
    };

    let mut redis_conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("🔴 Redis connection failed for Oracle: {}", e);
            return;
        }
    };

    let mut interval = tokio::time::interval(Duration::from_secs(2));

    loop {
        interval.tick().await;

        // ==============================================================================
        // A. PROCESS BUFFERED SHARES & STAMP YIELD + 1099-DA TAX LEDGER
        // ==============================================================================
        let share_events: Vec<String> = match redis_conn.lrange("perennia:oracle:share_buffer", 0, 500).await {
            Ok(events) => events,
            Err(_) => Vec::new(),
        };

        if !share_events.is_empty() {
            // Trim processed elements from buffer
            let _: redis::RedisResult<()> = redis_conn.ltrim("perennia:oracle:share_buffer", share_events.len() as isize, -1).await;

            let mut wallet_aggregates: HashMap<String, f64> = HashMap::new();

            for raw_evt in &share_events {
                if let Ok(json_val) = serde_json::from_str::<Value>(raw_evt) {
                    let worker = json_val["worker"].as_str().unwrap_or("");
                    let diff = json_val["difficulty"].as_f64().unwrap_or(0.0);

                    if !worker.is_empty() {
                        let wallet = worker.split('.').next().unwrap_or(worker).to_string();
                        // Kaspa yield conversion factor from share difficulty
                        let kas_delta = diff * 0.000005; 
                        *wallet_aggregates.entry(wallet).or_insert(0.0) += kas_delta;
                    }
                }
            }

            if !wallet_aggregates.is_empty() {
                if let Ok(mut tx) = pg_pool.begin().await {
                    let mut commit_success = true;

                    // 1. Bulk Aggregated Upsert into Yield Reservoirs
                    let mut agg_wallets = Vec::with_capacity(wallet_aggregates.len());
                    let mut agg_deltas = Vec::with_capacity(wallet_aggregates.len());

                    for (w, d) in wallet_aggregates {
                        agg_wallets.push(w);
                        agg_deltas.push(d);
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
                        .bind(&agg_wallets)
                        .bind(&agg_deltas)
                        .execute(&mut *tx).await;

                        if upsert_res.is_err() { 
                            commit_success = false; 
                        }
                    }

                    // 2. 1099-DA Compliance Stamping (Gross Proceeds Ledger)
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

                        if tax_ledger_res.is_err() { 
                            commit_success = false; 
                        }
                    }

                    if commit_success {
                        if let Err(e) = tx.commit().await {
                            tracing::error!("🔴 PostgreSQL Transaction Commit Failed: {}", e);
                        } else {
                            tracing::debug!("✅ Successfully committed yield deltas to PostgreSQL WAL.");
                        }
                    } else {
                        let _ = tx.rollback().await;
                    }
                }
            }
        }

        // ==============================================================================
        // B. PROCESS BUFFERED NETWORK BLOCKS
        // ==============================================================================
        let block_events: Vec<String> = match redis_conn.lrange("perennia:oracle:block_buffer", 0, 50).await {
            Ok(events) => events,
            Err(_) => Vec::new(),
        };

        if !block_events.is_empty() {
            let _: redis::RedisResult<()> = redis_conn.ltrim("perennia:oracle:block_buffer", block_events.len() as isize, -1).await;

            for raw_block in block_events {
                if let Ok(json_val) = serde_json::from_str::<Value>(&raw_block) {
                    let worker = json_val["worker"].as_str().unwrap_or("unknown");
                    let block_hash = json_val["block_hash"].as_str().unwrap_or("");
                    let nonce = json_val["nonce"].as_i64().unwrap_or(0);
                    let diff = json_val["network_diff"].as_f64().unwrap_or(0.0);

                    if !block_hash.is_empty() {
                        let _ = sqlx::query(
                            r#"
                            INSERT INTO network_blocks (block_hash, worker_id, nonce, network_diff)
                            VALUES ($1, $2, $3, $4)
                            ON CONFLICT (block_hash) DO NOTHING
                            "#
                        )
                        .bind(block_hash)
                        .bind(worker)
                        .bind(nonce)
                        .bind(diff)
                        .execute(&pg_pool).await;
                    }
                }
            }
        }
    }
}