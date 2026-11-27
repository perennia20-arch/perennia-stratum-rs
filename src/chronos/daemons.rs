use chrono::{Timelike, Utc};
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

use crate::kaspad_client::protowire::UtxosChangedNotificationMessage;

const AIRLOCK_HYSTERESIS_SOMPI: u64 = 1_000_000_000; // 10 KAS overflow hysteresis
const OUTBOX_DAA_CONFIRM_DEPTH: u64 = 10;
const COMPACTION_MAX_INPUTS: usize = 400;

static UTXO_COMPACTION_REQUESTED: AtomicBool = AtomicBool::new(false);

async fn refresh_active_vault_locks_from_node(pool: &PgPool, virtual_daa: u64) {
    let rows = sqlx::query(
        r#"
        SELECT vault_id, covenant_address,
               threshold_sompi::NUMERIC(39, 0)::TEXT AS threshold_sompi
        FROM vault_locks
        WHERE status IN ('FILLING', 'THRESHOLD_MET')
        ORDER BY updated_at ASC
        LIMIT 50
        "#,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    for row in rows {
        let vault_id: String = row.try_get("vault_id").unwrap_or_default();
        let covenant_address: String = row.try_get("covenant_address").unwrap_or_default();
        let threshold_sompi: u128 = row
            .try_get::<String, _>("threshold_sompi")
            .ok()
            .and_then(|s| s.trim().parse::<u128>().ok())
            .unwrap_or(2_500_000_000);
        if vault_id.is_empty() || covenant_address.is_empty() {
            continue;
        }
        let Ok(utxos) = crate::kaspad_client::get_utxos_by_address_grpc(&covenant_address).await else {
            continue;
        };
        let mut total_sompi: u128 = 0;
        let mut first_txid: Option<String> = None;
        let mut first_vout: Option<i32> = None;
        for u in &utxos {
            let amt = u
                .get("utxoEntry")
                .and_then(|e| e.get("amount"))
                .and_then(|a| {
                    a.as_u64()
                        .map(|v| v as u128)
                        .or_else(|| a.as_str().and_then(|s| s.trim().parse::<u128>().ok()))
                })
                .unwrap_or(0);
            if amt == 0 {
                continue;
            }
            if first_txid.is_none() {
                first_txid = u
                    .get("outpoint")
                    .and_then(|o| o.get("transactionId"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                first_vout = u
                    .get("outpoint")
                    .and_then(|o| o.get("index"))
                    .and_then(|v| v.as_i64())
                    .map(|i| i as i32);
            }
            total_sompi = total_sompi.saturating_add(amt);
        }
        let next_status = if total_sompi >= threshold_sompi {
            "THRESHOLD_MET"
        } else {
            "FILLING"
        };
        let _ = sqlx::query(
            r#"
            UPDATE vault_locks
            SET confirmed_utxo_sompi = $2::NUMERIC(39, 0),
                confirmed_daa_score = GREATEST(confirmed_daa_score, $3),
                onchain_utxo_txid = COALESCE($4, onchain_utxo_txid),
                onchain_utxo_vout = COALESCE($5, onchain_utxo_vout),
                status = $6,
                updated_at = CURRENT_TIMESTAMP
            WHERE vault_id = $1
              AND status IN ('FILLING', 'THRESHOLD_MET')
            "#,
        )
        .bind(&vault_id)
        .bind(total_sompi.to_string())
        .bind(virtual_daa as i64)
        .bind(first_txid.as_deref())
        .bind(first_vout)
        .bind(next_status)
        .execute(pool)
        .await;
    }
}

pub async fn start_mempool_watcher_daemon(
    pool: PgPool,
    mut daa_rx: broadcast::Receiver<u64>,
    mut utxo_rx: broadcast::Receiver<UtxosChangedNotificationMessage>,
) {
    tracing::info!(
        "👁️ [CHRONOS WATCHER] DAG DAA Score, Outbox Finality & Vault Lock UTXO Watcher Armed."
    );
    let mut last_vault_sync_secs: u64 = 0;

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

                if daa_score >= OUTBOX_DAA_CONFIRM_DEPTH {
                    let confirm_cutoff = (daa_score - OUTBOX_DAA_CONFIRM_DEPTH) as i64;
                    let _ = sqlx::query(
                        r#"
                        UPDATE epoch_payout_outbox
                        SET state = 'CONFIRMED',
                            confirmed_daa = COALESCE(confirmed_daa, $1),
                            updated_at = CURRENT_TIMESTAMP
                        WHERE state = 'BROADCAST'
                          AND broadcast_daa IS NOT NULL
                          AND broadcast_daa <= $2
                        "#,
                    )
                    .bind(daa_score as i64)
                    .bind(confirm_cutoff)
                    .execute(&pool)
                    .await;
                }

                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now_secs.saturating_sub(last_vault_sync_secs) >= 15 {
                    last_vault_sync_secs = now_secs;
                    refresh_active_vault_locks_from_node(&pool, daa_score).await;
                }
            }
            Ok(utxo_msg) = utxo_rx.recv() => {
                if utxo_msg.added.len() > 8 {
                    UTXO_COMPACTION_REQUESTED.store(true, Ordering::Relaxed);
                }
                if let Ok(v_daa) = crate::kaspad_client::get_virtual_daa_score_grpc().await {
                    refresh_active_vault_locks_from_node(&pool, v_daa).await;
                }
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
    tracing::info!("🧱 [CHRONOS COMPACTOR] Pre-Bell UTXO Consolidation Trigger Armed.");
    loop {
        match utxo_rx.recv().await {
            Ok(msg) => {
                if msg.added.len() > 8 {
                    UTXO_COMPACTION_REQUESTED.store(true, Ordering::Relaxed);
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}

pub async fn start_hot_cold_airlock_daemon(pool: PgPool) {
    tracing::info!(
        "🛡️ [CHRONOS AIRLOCK] Pure-Sompi House Tangem Overflow, Stage 1 25-KAS Flush & 21:55 UTC Compactor Armed."
    );
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    let mut last_compaction_ordinal_day: Option<u32> = None;

    loop {
        interval.tick().await;

        let sys_cfg = crate::chronos::load_system_treasury_config(&pool).await;
        if sys_cfg.outflow_breaker_tripped || sys_cfg.solvency_breaker_tripped {
            tracing::warn!(
                "🚨 [CHRONOS AIRLOCK] Skipping outbound sweeps/flushes: breaker tripped (outflow={}, solvency={}).",
                sys_cfg.outflow_breaker_tripped,
                sys_cfg.solvency_breaker_tripped
            );
            continue;
        }

        let now = Utc::now();
        let ordinal_day = now.format("%j").to_string().parse::<u32>().unwrap_or(0);
        let is_2155_bell_window = now.hour() == 21
            && now.minute() >= 55
            && last_compaction_ordinal_day != Some(ordinal_day);
        let needs_fanin_compaction = UTXO_COMPACTION_REQUESTED.swap(false, Ordering::Relaxed);

        if is_2155_bell_window || needs_fanin_compaction {
            if is_2155_bell_window {
                last_compaction_ordinal_day = Some(ordinal_day);
            }
            match crate::state_api::compact_wallet_utxos_pre_bell(&pool, COMPACTION_MAX_INPUTS).await
            {
                Ok(Some(txid)) => {
                    tracing::info!("🧱 [CHRONOS COMPACTOR] Consolidated UTXOs -> {}", txid);
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("⚠️ [CHRONOS COMPACTOR] UTXO compaction deferred: {}", e);
                }
            }
        }

        let stage1_epoch_id = format!("STAGE1-{}", now.format("%Y%m%d-%H%M"));
        match crate::state_api::execute_stage1_mechanical_pool_flush_batch(&pool, &stage1_epoch_id)
            .await
        {
            Ok(summary) => {
                if summary
                    .get("flushedWallets")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
                    > 0
                {
                    tracing::info!("🌊 [STAGE 1 FLUSH] Completed 25 KAS flush: {}", summary);
                }
            }
            Err(e) => {
                tracing::warn!("⚠️ [STAGE 1 FLUSH] Skipped cycle: {}", e);
            }
        }

        if let Some(hot_addr) = crate::chronos::resolve_hot_dispatcher_address() {
            let cold_kas_dest = sys_cfg.cold_kas_address.trim().to_lowercase();
            if !cold_kas_dest.is_empty()
                && cold_kas_dest.starts_with("kaspa:")
                && hot_addr.to_lowercase() != cold_kas_dest
                && sys_cfg.hot_ceiling_sompi > 0
            {
                if let Ok(hot_sompi) =
                    crate::kaspad_client::get_balance_by_address_grpc(&hot_addr).await
                {
                    let trigger_sompi = sys_cfg
                        .hot_ceiling_sompi
                        .saturating_add(AIRLOCK_HYSTERESIS_SOMPI);
                    if hot_sompi > trigger_sompi {
                        let sweep_sompi = hot_sompi.saturating_sub(sys_cfg.hot_ceiling_sompi);
                        if sweep_sompi > 0 {
                            let minute_bucket = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs()
                                / 60;
                            let idemp_key = format!(
                                "NODE-HOT-OVERFLOW-{}-{}",
                                minute_bucket, sweep_sompi
                            );
                            if let Ok(tx_id) =
                                crate::state_api::sign_and_broadcast_kaspa_payout_batch(
                                    &pool,
                                    &idemp_key,
                                    &[(cold_kas_dest.clone(), sweep_sompi)],
                                    "",
                                )
                                .await
                            {
                                let after_sompi = hot_sompi.saturating_sub(sweep_sompi);
                                let _ = sqlx::query(
                                    r#"
                                    INSERT INTO treasury_airlock_sweeps (
                                        hot_wallet_address, cold_vault_address,
                                        swept_kas, hot_balance_before_kas, hot_balance_after_kas,
                                        tx_id, status
                                    ) VALUES (
                                        $1, $2,
                                        ($3::NUMERIC(39,0) / 100000000.0)::FLOAT8,
                                        ($4::NUMERIC(39,0) / 100000000.0)::FLOAT8,
                                        ($5::NUMERIC(39,0) / 100000000.0)::FLOAT8,
                                        $6, 'NODE_CEILING_SWEPT_TO_COLD'
                                    )
                                    "#,
                                )
                                .bind(&hot_addr)
                                .bind(&cold_kas_dest)
                                .bind(sweep_sompi.to_string())
                                .bind(hot_sompi.to_string())
                                .bind(after_sompi.to_string())
                                .bind(&tx_id)
                                .execute(&pool)
                                .await;
                            }
                        }
                    }
                }
            }
        }
    }
}

pub async fn start_idempotent_payout_recovery_daemon(pool: PgPool) {
    tracing::info!(
        "♻️ [CHRONOS RECOVERY] Outbox + Idempotent Batch + ChangeNOW Status Reconciler Armed."
    );
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

        let stalled_outbox = sqlx::query(
            r#"
            SELECT outbox_key, signed_tx_json
            FROM epoch_payout_outbox
            WHERE state IN ('SIGNING', 'BROADCAST')
              AND signed_tx_json IS NOT NULL
              AND updated_at < CURRENT_TIMESTAMP - INTERVAL '90 seconds'
              AND retry_count < 5
            ORDER BY updated_at ASC
            LIMIT 25
            "#,
        )
        .fetch_all(&pool)
        .await
        .unwrap_or_default();

        for row in stalled_outbox {
            let outbox_key: String = row.try_get("outbox_key").unwrap_or_default();
            let Some(signed_tx) = row
                .try_get::<Option<Value>, _>("signed_tx_json")
                .ok()
                .flatten()
            else {
                continue;
            };

            match crate::kaspad_client::submit_transaction_grpc(&signed_tx, false).await {
                Ok(txid) => {
                    let _ = sqlx::query(
                        r#"
                        UPDATE epoch_payout_outbox
                        SET txid = $2,
                            state = 'BROADCAST',
                            updated_at = CURRENT_TIMESTAMP
                        WHERE outbox_key = $1
                        "#,
                    )
                    .bind(&outbox_key)
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
                            UPDATE epoch_payout_outbox
                            SET state = 'CONFIRMED',
                                updated_at = CURRENT_TIMESTAMP
                            WHERE outbox_key = $1
                            "#,
                        )
                        .bind(&outbox_key)
                        .execute(&pool)
                        .await;
                    } else {
                        let _ = sqlx::query(
                            r#"
                            UPDATE epoch_payout_outbox
                            SET retry_count = retry_count + 1,
                                last_error = $2,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE outbox_key = $1
                            "#,
                        )
                        .bind(&outbox_key)
                        .bind(&err_msg)
                        .execute(&pool)
                        .await;
                    }
                }
            }
        }

        if let Err(e) = crate::fiat_rails::reconcile_changenow_settlement_receipts(&pool).await {
            tracing::warn!("⚠️ [CHANGENOW RECONCILER] Status poll skipped: {}", e);
        }
    }
}