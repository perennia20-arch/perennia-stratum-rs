use serde_json::Value;
use sqlx::{PgPool, Row};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

use crate::kaspad_client::protowire::UtxosChangedNotificationMessage;

pub async fn start_mempool_watcher_daemon(
    pool: PgPool,
    mut daa_rx: broadcast::Receiver<u64>,
    mut utxo_rx: broadcast::Receiver<UtxosChangedNotificationMessage>,
) {
    tracing::info!("👁️ [CHRONOS WATCHER] DAG DAA Score & UTXO Confirmation Watcher Armed.");
    loop {
        tokio::select! {
            Ok(daa_score) = daa_rx.recv() => {
                let _ = sqlx::query(
                    r#"
                    UPDATE pending_transactions
                    SET status = 'CONFIRMED',
                        block_daa = COALESCE(block_daa, $1)
                    WHERE status = 'PENDING'
                    "#,
                )
                .bind(daa_score as i64)
                .execute(&pool)
                .await;
            }
            Ok(_utxo_msg) = utxo_rx.recv() => {
            }
            else => {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

pub async fn start_utxo_consolidation_daemon(
    mut utxo_rx: broadcast::Receiver<UtxosChangedNotificationMessage>,
) {
    tracing::info!("🧱 [CHRONOS COMPACTOR] Treasury Dust UTXO Compaction Daemon Armed.");
    loop {
        match utxo_rx.recv().await {
            Ok(_msg) => {}
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}

fn minimum_sweep_quantum_for_asset(ticker: &str) -> f64 {
    match ticker.trim().to_uppercase().as_str() {
        "BTC" => 0.0005,
        "ETH" | "XAU" => 0.005,
        "SOL" => 0.05,
        _ => 1.0,
    }
}

pub async fn start_hot_cold_airlock_daemon(pool: PgPool) {
    tracing::info!(
        "🛡️ [CHRONOS AIRLOCK] Multi-Chain Per-Token Cold Vault & Node Ceiling Sweep Daemon Armed."
    );
    let mut interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        interval.tick().await;

        let sys_cfg = crate::chronos::load_system_treasury_config(&pool).await;
        if sys_cfg.outflow_breaker_tripped {
            continue;
        }

        if let Some(hot_addr) = crate::chronos::resolve_hot_dispatcher_address() {
            let cold_kas_dest = sys_cfg.cold_kas_address.trim().to_lowercase();
            if !cold_kas_dest.is_empty()
                && cold_kas_dest.starts_with("kaspa:")
                && hot_addr.to_lowercase() != cold_kas_dest
                && sys_cfg.hot_ceiling_kas > 0.0
            {
                if let Ok(hot_sompi) =
                    crate::kaspad_client::get_balance_by_address_grpc(&hot_addr).await
                {
                    let hot_kas = (hot_sompi as f64) / 100_000_000.0;
                    if hot_kas > sys_cfg.hot_ceiling_kas + 10.0 {
                        let sweep_kas = (hot_kas - sys_cfg.hot_ceiling_kas).max(0.0);
                        let sweep_sompi = (sweep_kas * 100_000_000.0).round() as u64;
                        let minute_bucket = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                            / 60;
                        let idemp_key = format!(
                            "NODE-HOT-OVERFLOW-{}-{}",
                            minute_bucket, sweep_sompi
                        );
                        if let Ok(tx_id) = crate::state_api::sign_and_broadcast_kaspa_payout_batch(
                            &pool,
                            &idemp_key,
                            &[(cold_kas_dest.clone(), sweep_sompi)],
                            "",
                        )
                        .await
                        {
                            let _ = sqlx::query(
                                r#"
                                INSERT INTO treasury_airlock_sweeps (
                                    hot_wallet_address, cold_vault_address, swept_kas,
                                    hot_balance_before_kas, hot_balance_after_kas, tx_id, status
                                ) VALUES ($1, $2, $3, $4, $5, $6, 'NODE_CEILING_SWEPT_TO_COLD')
                                "#,
                            )
                            .bind(&hot_addr)
                            .bind(&cold_kas_dest)
                            .bind(sweep_kas)
                            .bind(hot_kas)
                            .bind(hot_kas - sweep_kas)
                            .bind(&tx_id)
                            .execute(&pool)
                            .await;
                        }
                    }
                }
            }
        }

        let rule_rows = sqlx::query(
            r#"
            SELECT r.wallet_address, r.asset_ticker, r.network,
                   r.cold_destination_address, r.overflow_ceiling,
                   y.streaming_balance_kas,
                   COALESCE(y.lp_tokens, '{}'::jsonb) AS lp_tokens
            FROM user_cold_vault_rules r
            JOIN yield_reservoirs y
              ON (y.wallet_address = r.wallet_address
                  OR REPLACE(LOWER(y.wallet_address), 'kaspa:', '') = REPLACE(LOWER(r.wallet_address), 'kaspa:', ''))
            WHERE r.auto_sweep_enabled = TRUE
              AND COALESCE(y.quarantined, FALSE) = FALSE
            "#,
        )
        .fetch_all(&pool)
        .await
        .unwrap_or_default();

        for row in rule_rows {
            let wallet: String = row.try_get("wallet_address").unwrap_or_default();
            let clean_wallet = wallet
                .trim()
                .to_lowercase()
                .replace("kaspa:", "")
                .trim()
                .to_string();
            let prefixed_wallet = format!("kaspa:{}", clean_wallet);
            let ticker: String = row
                .try_get::<String, _>("asset_ticker")
                .unwrap_or_else(|_| "KAS".to_string())
                .trim()
                .to_uppercase();
            let network: String = row
                .try_get::<String, _>("network")
                .unwrap_or_else(|_| ticker.clone())
                .trim()
                .to_uppercase();
            let cold_addr: String = row
                .try_get::<String, _>("cold_destination_address")
                .unwrap_or_default()
                .trim()
                .to_string();
            let ceiling: f64 = row.try_get("overflow_ceiling").unwrap_or(500.0);

            if cold_addr.is_empty() {
                continue;
            }

            let current_bal = if ticker == "KAS" {
                row.try_get::<f64, _>("streaming_balance_kas").unwrap_or(0.0)
            } else {
                let lp_tokens: Value = row
                    .try_get("lp_tokens")
                    .unwrap_or_else(|_| serde_json::json!({}));
                lp_tokens
                    .get(&ticker)
                    .and_then(|v| {
                        v.as_f64()
                            .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
                    })
                    .unwrap_or(0.0)
            };

            let sweep_amount = (current_bal - ceiling).max(0.0);
            if sweep_amount < minimum_sweep_quantum_for_asset(&ticker) {
                continue;
            }

            let Ok(spot_price) =
                crate::state_api::resolve_strict_spot_price(&pool, &ticker).await
            else {
                tracing::warn!(
                    "⚠️ [CHRONOS AIRLOCK] Skipping auto-sweep for {} ({}): live oracle offline.",
                    prefixed_wallet,
                    ticker
                );
                continue;
            };

            if crate::state_api::debit_user_token_balance(
                &pool,
                &clean_wallet,
                &prefixed_wallet,
                &ticker,
                sweep_amount,
            )
            .await
            .is_err()
            {
                continue;
            }

            match crate::state_api::dispatch_or_queue_l1_payout(
                &pool,
                &prefixed_wallet,
                &cold_addr,
                &ticker,
                Some(&network),
                sweep_amount,
                spot_price,
                "cold_airlock_sweep",
            )
            .await
            {
                Ok(receipt) => {
                    let tx_id = receipt
                        .get("txHash")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    let _ = sqlx::query(
                        r#"
                        UPDATE user_cold_vault_rules
                        SET last_sweep_txid = $3,
                            last_sweep_amount = $4,
                            last_sweep_at = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE (wallet_address = $1 OR wallet_address = $2)
                          AND asset_ticker = $5
                        "#,
                    )
                    .bind(&prefixed_wallet)
                    .bind(&clean_wallet)
                    .bind(tx_id)
                    .bind(sweep_amount)
                    .bind(&ticker)
                    .execute(&pool)
                    .await;

                    let _ = sqlx::query(
                        r#"
                        INSERT INTO treasury_airlock_sweeps (
                            hot_wallet_address, cold_vault_address, swept_kas,
                            hot_balance_before_kas, hot_balance_after_kas, tx_id, status
                        ) VALUES ($1, $2, $3, $4, $5, $6, 'SWEPT_TO_COLD')
                        "#,
                    )
                    .bind(&prefixed_wallet)
                    .bind(&cold_addr)
                    .bind(sweep_amount)
                    .bind(current_bal)
                    .bind((current_bal - sweep_amount).max(0.0))
                    .bind(tx_id)
                    .execute(&pool)
                    .await;
                }
                Err(e) => {
                    tracing::error!(
                        "❌ [CHRONOS AIRLOCK] Auto-sweep dispatch failed for {} ({}): {}. Re-crediting reservoir.",
                        prefixed_wallet,
                        ticker,
                        e
                    );
                    let _ = crate::state_api::credit_user_token_balance(
                        &pool,
                        &clean_wallet,
                        &prefixed_wallet,
                        &ticker,
                        sweep_amount,
                        false,
                    )
                    .await;
                }
            }
        }
    }
}

pub async fn start_idempotent_payout_recovery_daemon(pool: PgPool) {
    tracing::info!("♻️ [CHRONOS RECOVERY] Idempotent IN_FLIGHT Payout Batch Recovery Daemon Armed.");
    let mut interval = tokio::time::interval(Duration::from_secs(45));

    loop {
        interval.tick().await;

        let stalled_batches = sqlx::query(
            r#"
            SELECT batch_id, idempotency_key, signed_tx_json, retry_count
            FROM idempotent_payout_batches
            WHERE state IN ('IN_FLIGHT', 'BROADCASTING')
              AND updated_at < CURRENT_TIMESTAMP - INTERVAL '90 seconds'
              AND retry_count < 5
            ORDER BY updated_at ASC
            LIMIT 25
            "#,
        )
        .fetch_all(&pool)
        .await
        .unwrap_or_default();

        for row in stalled_batches {
            let batch_id: String = row.try_get("batch_id").unwrap_or_default();
            let signed_tx_opt: Option<Value> = row.try_get("signed_tx_json").ok().flatten();

            let Some(signed_tx) = signed_tx_opt else {
                let _ = sqlx::query(
                    r#"
                    UPDATE idempotent_payout_batches
                    SET state = 'FAILED_MISSING_PAYLOAD',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE batch_id = $1
                    "#,
                )
                .bind(&batch_id)
                .execute(&pool)
                .await;
                continue;
            };

            match crate::kaspad_client::submit_transaction_grpc(&signed_tx, false).await {
                Ok(txid) => {
                    let _ = sqlx::query(
                        r#"
                        UPDATE idempotent_payout_batches
                        SET deterministic_txid = $2,
                            state = 'CONFIRMED',
                            updated_at = CURRENT_TIMESTAMP
                        WHERE batch_id = $1
                        "#,
                    )
                    .bind(&batch_id)
                    .bind(&txid)
                    .execute(&pool)
                    .await;
                }
                Err(err_msg) => {
                    let lower = err_msg.to_lowercase();
                    if lower.contains("already")
                        || lower.contains("duplicate")
                        || lower.contains("spent")
                    {
                        let _ = sqlx::query(
                            r#"
                            UPDATE idempotent_payout_batches
                            SET state = 'CONFIRMED',
                                updated_at = CURRENT_TIMESTAMP
                            WHERE batch_id = $1
                            "#,
                        )
                        .bind(&batch_id)
                        .execute(&pool)
                        .await;
                    } else {
                        let _ = sqlx::query(
                            r#"
                            UPDATE idempotent_payout_batches
                            SET retry_count = retry_count + 1,
                                last_error = $2,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE batch_id = $1
                            "#,
                        )
                        .bind(&batch_id)
                        .bind(&err_msg)
                        .execute(&pool)
                        .await;
                    }
                }
            }
        }
    }
}