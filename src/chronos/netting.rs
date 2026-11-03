use chrono::Utc;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::time::Duration;

pub async fn start_delta_netting_engine(redis_client: redis::Client, pool: PgPool) {
    tracing::info!("⚡ [CHRONOS NETTING] Delta Netting & 50%-KAS LP Invariant Engine Armed.");
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        if let Err(e) = run_delta_netting_cycle(&redis_client, &pool).await {
            tracing::warn!("⚠️ [CHRONOS NETTING] Cycle warning: {}", e);
        }
    }
}

pub async fn run_delta_netting_cycle(
    _redis_client: &redis::Client,
    pool: &PgPool,
) -> anyhow::Result<()> {
    let lp_rows = sqlx::query(
        r#"
        SELECT lp_id::text AS lp_id, wallet_address, pool_pair,
               staked_asset_a, staked_asset_b, lock_duration_days
        FROM liquidity_providers
        "#,
    )
    .fetch_all(pool)
    .await?;

    if lp_rows.is_empty() {
        return Ok(());
    }

    let mut total_weighted_kas = 0.0_f64;
    for r in &lp_rows {
        let amt_a: f64 = r.try_get("staked_asset_a").unwrap_or(0.0);
        let days: i32 = r.try_get("lock_duration_days").unwrap_or(0);
        let mult = if days >= 365 {
            2.5
        } else if days >= 90 {
            1.5
        } else if days >= 30 {
            1.2
        } else {
            1.0
        };
        total_weighted_kas += amt_a * mult;
    }

    if total_weighted_kas <= 0.0 {
        return Ok(());
    }

    Ok(())
}

pub async fn execute_epoch_delta_netting_and_lp_compounding(
    pool: &PgPool,
) -> anyhow::Result<Value> {
    let kas_spot_usd = crate::state_api::resolve_strict_spot_price(pool, "KAS")
        .await
        .map_err(|e| anyhow::anyhow!("Epoch netting aborted (fail-closed): {}", e))?;

    let rows = sqlx::query(
        r#"
        SELECT wallet_address, layout_state
        FROM user_command_centers
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut settled_sectors_count = 0usize;
    let mut total_swept_kas = 0.0_f64;

    for row in rows {
        let raw_wallet: String = row.try_get("wallet_address").unwrap_or_default();
        let clean_wallet = raw_wallet
            .trim()
            .to_lowercase()
            .replace("kaspa:", "")
            .trim()
            .to_string();
        if clean_wallet.is_empty() {
            continue;
        }
        let prefixed_wallet = format!("kaspa:{}", clean_wallet);

        let mut layout: Value = row
            .try_get("layout_state")
            .unwrap_or_else(|_| json!({ "workers": [], "sectors": [] }));
        let mut wallet_credited_kas = 0.0_f64;
        let mut layout_mutated = false;

        if let Some(sectors) = layout.get_mut("sectors").and_then(|v| v.as_array_mut()) {
            for sec in sectors.iter_mut() {
                let pending = sec
                    .get("pendingKaspa")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                if pending <= 0.0 {
                    continue;
                }

                let route_mode = sec
                    .get("routeMode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("hold");
                let target_ticker = sec
                    .get("settlementConfig")
                    .and_then(|c| c.get("targetAsset"))
                    .and_then(|t| t.get("ticker"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("KAS")
                    .trim()
                    .to_uppercase();

                if route_mode == "auto-lp" {
                    let secondary_ticker = if target_ticker == "KAS" || target_ticker.is_empty() {
                        "USDC".to_string()
                    } else {
                        target_ticker.clone()
                    };

                    let Ok(secondary_spot_usd) =
                        crate::state_api::resolve_strict_spot_price(pool, &secondary_ticker).await
                    else {
                        tracing::warn!(
                            "⚠️ [EPOCH NETTING] Skipping auto-lp sector for {} (KAS/{}): live oracle for {} is offline.",
                            prefixed_wallet,
                            secondary_ticker,
                            secondary_ticker
                        );
                        continue;
                    };

                    let kas_leg = pending * 0.5;
                    let leg_usd_val = kas_leg * kas_spot_usd;
                    let secondary_leg = if secondary_spot_usd > 0.0 {
                        leg_usd_val / secondary_spot_usd
                    } else {
                        continue;
                    };

                    let pair_name = format!("KAS/{}", secondary_ticker);
                    let weights_json = json!({
                        "KAS": 0.5,
                        secondary_ticker.clone(): 0.5
                    });
                    let reserves_json = json!({
                        "KAS": kas_leg,
                        secondary_ticker: secondary_leg
                    });

                    let _ = sqlx::query(
                        r#"
                        INSERT INTO liquidity_providers (
                            wallet_address, pool_pair, staked_asset_a, staked_asset_b,
                            weights_json, reserves_json, lock_duration_days,
                            unlock_date
                        ) VALUES (
                            $1, $2, $3, $4, $5, $6, 30,
                            CURRENT_TIMESTAMP + INTERVAL '30 days'
                        )
                        "#,
                    )
                    .bind(&prefixed_wallet)
                    .bind(&pair_name)
                    .bind(kas_leg)
                    .bind(secondary_leg)
                    .bind(&weights_json)
                    .bind(&reserves_json)
                    .execute(pool)
                    .await;
                } else {
                    wallet_credited_kas += pending;
                }

                sec["pendingKaspa"] = json!(0.0);
                layout_mutated = true;
                settled_sectors_count += 1;
                total_swept_kas += pending;
            }
        }

        if wallet_credited_kas > 0.0 {
            if let Err(e) = crate::state_api::credit_user_token_balance(
                pool,
                &clean_wallet,
                &prefixed_wallet,
                "KAS",
                wallet_credited_kas,
                true,
            )
            .await
            {
                tracing::error!(
                    "❌ [EPOCH NETTING] Failed to credit signed yield reservoir for {}: {}",
                    prefixed_wallet,
                    e
                );
                continue;
            }

            let _ = crate::sor::record_hifo_acquisition_lot(
                pool,
                &clean_wallet,
                "KAS",
                wallet_credited_kas,
                kas_spot_usd,
                "EPOCH_BELL_YIELD",
                None,
            )
            .await;

            let gross_usd = wallet_credited_kas * kas_spot_usd;
            let _ = sqlx::query(
                r#"
                INSERT INTO tax_ledger_events (
                    wallet_address, asset_ticker, event_type, gross_proceeds_usd,
                    amount_tokens, spot_price_at_execution, cost_basis_usd,
                    realized_gain_loss_usd, holding_period
                ) VALUES ($1, 'KAS', 'YIELD', $2, $3, $4, $2, 0.0, 'SHORT_TERM')
                "#,
            )
            .bind(&clean_wallet)
            .bind(gross_usd)
            .bind(wallet_credited_kas)
            .bind(kas_spot_usd)
            .execute(pool)
            .await;
        }

        if layout_mutated {
            let _ = sqlx::query(
                r#"
                UPDATE user_command_centers
                SET layout_state = $2,
                    last_updated = CURRENT_TIMESTAMP
                WHERE wallet_address = $1
                "#,
            )
            .bind(&raw_wallet)
            .bind(&layout)
            .execute(pool)
            .await;
        }
    }

    Ok(json!({
        "settledSectorsCount": settled_sectors_count,
        "totalSweptKas": total_swept_kas,
        "executionKasSpotUsd": kas_spot_usd,
        "settledAt": Utc::now().to_rfc3339()
    }))
}