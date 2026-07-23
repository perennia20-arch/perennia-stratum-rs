use sqlx::postgres::PgPoolOptions;
use redis::AsyncCommands;
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize, Debug)]
pub struct OracleShare {
    pub worker: String,
    pub difficulty: f64,
    pub timestamp: u64,
}

// 💎 INQUIRY 3 STRUCT
#[derive(Deserialize, Debug)]
pub struct OracleBlock {
    pub worker: String,
    pub block_hash: String,
    pub nonce: u64,
    pub network_diff: f64,
}

const KAS_EMISSION_RATE: f64 = 117.0; 
const NETWORK_DIFFICULTY_BASELINE: f64 = 1_000_000_000.0; 

pub async fn start_oracle_daemon() {
    tracing::info!("🔮 Real-Time Yield Streaming Oracle Booting. Target: Sovereign PostgreSQL WAL.");

    let pg_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1/perennia".to_string());
    
    let pool = PgPoolOptions::new()
        .max_connections(50)
        .connect(&pg_url)
        .await
        .expect("❌ CRITICAL: Oracle failed to bind to PostgreSQL WAL.");

    let redis_client = redis::Client::open("redis://127.0.0.1/").expect("Redis connection failed");
    let mut redis_conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis Oracle multiplexer failed");

    // 🧹 INQUIRY 2: THE AUTONOMOUS PRUNING DAEMON (NVME SHIELD)
    let pruner_pool = pool.clone();
    tokio::spawn(async move {
        tracing::info!("🧹 Pruning Daemon Armed: Waking every 24 hours to enforce NVMe lifecycle.");
        let mut pruner_interval = tokio::time::interval(Duration::from_secs(86400));
        pruner_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        
        loop {
            pruner_interval.tick().await;
            tracing::info!("🧹 Initiating NVMe lifecycle purge sequence...");
            
            let purge_res = sqlx::query(
                "DELETE FROM micro_shares WHERE is_settled = true AND recorded_at < NOW() - INTERVAL '48 hours'"
            )
            .execute(&pruner_pool)
            .await;

            match purge_res {
                Ok(result) => tracing::info!("✅ Purge Complete: {} obsolete micro-shares obliterated.", result.rows_affected()),
                Err(e) => tracing::error!("🚨 Pruning Daemon Fault: {}", e),
            }
        }
    });

    // ⚡ ORIGINAL ORACLE YIELD LOGIC
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        // 💎 INQUIRY 3: L1 BLOCK DISCOVERY LISTENER
        let block_batch: Vec<String> = match redis::cmd("LPOP")
            .arg("perennia:oracle:block_buffer")
            .arg(10)
            .query_async(&mut redis_conn)
            .await
        {
            Ok(b) => b,
            Err(_) => vec![],
        };

        for raw_block in block_batch {
            if let Ok(block) = serde_json::from_str::<OracleBlock>(&raw_block) {
                tracing::info!("🏦 ORACLE: Anchoring L1 Block {} to ledger.", block.block_hash);
                let _ = sqlx::query(
                    r#"
                    INSERT INTO network_blocks (block_hash, worker_id, nonce, network_diff)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (block_hash) DO NOTHING
                    "#
                )
                .bind(block.block_hash)
                .bind(block.worker)
                .bind(block.nonce as i64)
                .bind(block.network_diff)
                .execute(&pool)
                .await;
            }
        }

        // ⚡ MICRO-SHARE YIELD STREAMING SETTLEMENT
        let batch: Vec<String> = match redis::cmd("LPOP")
            .arg("perennia:oracle:share_buffer")
            .arg(5000)
            .query_async(&mut redis_conn)
            .await
        {
            Ok(b) => b,
            Err(_) => continue,
        };

        if batch.is_empty() { continue; }

        let mut tx = match pool.begin().await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("🚨 Oracle PostgreSQL Transaction Failure: {}", e);
                for raw_share in batch.into_iter().rev() {
                    let mut conn = redis_conn.clone();
                    tokio::spawn(async move {
                        let _: () = redis::cmd("LPUSH").arg("perennia:oracle:share_buffer").arg(raw_share).query_async(&mut conn).await.unwrap_or(());
                    });
                }
                continue;
            }
        };

        let mut commit_success = true;

        for raw_share in &batch {
            if let Ok(share) = serde_json::from_str::<OracleShare>(raw_share) {
                let parts: Vec<&str> = share.worker.split('.').collect();
                let wallet = if !parts.is_empty() { parts[0] } else { &share.worker };

                let share_ratio = share.difficulty / NETWORK_DIFFICULTY_BASELINE;
                let micro_kas_delta = share_ratio * KAS_EMISSION_RATE * 1_000_000.0; 

                let insert_res = sqlx::query(
                    r#"
                    INSERT INTO micro_shares (worker_id, difficulty_weight, kas_value_delta, network_diff, is_settled)
                    VALUES ($1, $2, $3, $4, false)
                    "#
                )
                .bind(&share.worker)
                .bind(share.difficulty)
                .bind(micro_kas_delta)
                .bind(NETWORK_DIFFICULTY_BASELINE)
                .execute(&mut *tx)
                .await;

                if insert_res.is_err() { commit_success = false; break; }

                let upsert_res = sqlx::query(
                    r#"
                    INSERT INTO yield_reservoirs (wallet_address, streaming_balance_kas, total_yield_kas)
                    VALUES ($1, $2, $2)
                    ON CONFLICT (wallet_address)
                    DO UPDATE SET
                        streaming_balance_kas = yield_reservoirs.streaming_balance_kas + EXCLUDED.streaming_balance_kas,
                        total_yield_kas = yield_reservoirs.total_yield_kas + EXCLUDED.total_yield_kas,
                        last_updated = CURRENT_TIMESTAMP
                    "#
                )
                .bind(wallet)
                .bind(micro_kas_delta)
                .execute(&mut *tx)
                .await;

                if upsert_res.is_err() { commit_success = false; break; }
            }
        }

        if commit_success {
            if let Err(e) = tx.commit().await {
                tracing::error!("🚨 WAL Commit Failure! Rolling back batch to volatile state. Err: {}", e);
                for raw_share in batch.into_iter().rev() {
                    let mut conn = redis_conn.clone();
                    tokio::spawn(async move {
                        let _: () = redis::cmd("LPUSH").arg("perennia:oracle:share_buffer").arg(raw_share).query_async(&mut conn).await.unwrap_or(());
                    });
                }
            }
        } else {
            let _ = tx.rollback().await;
            for raw_share in batch.into_iter().rev() {
                let mut conn = redis_conn.clone();
                tokio::spawn(async move {
                    let _: () = redis::cmd("LPUSH").arg("perennia:oracle:share_buffer").arg(raw_share).query_async(&mut conn).await.unwrap_or(());
                });
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}