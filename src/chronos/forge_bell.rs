use serde_json::{json, Value};
use sqlx::{PgPool, Row};

pub async fn execute_2200_utc_forge_bell_settlement(pool: &PgPool) -> anyhow::Result<Value> {
    let vesting_updated = sqlx::query(
        r#"
        UPDATE forge_vesting_schedules
        SET unlocked_amount = LEAST(
                total_allocated,
                unlocked_amount + GREATEST(0.0, daily_unlock_rate)
            ),
            status = CASE
                WHEN unlocked_amount + GREATEST(0.0, daily_unlock_rate) >= total_allocated THEN 'UNLOCKED'
                ELSE 'VESTING'
            END,
            last_bell_unlocked_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE status != 'UNLOCKED'
          AND CURRENT_TIMESTAMP >= cliff_unlock_at
        "#,
    )
    .execute(pool)
    .await?
    .rows_affected();

    let policy_updated = sqlx::query(
        r#"
        UPDATE forge_monetary_policies
        SET reserve_emitted_tokens = LEAST(
                reserve_locked_tokens,
                reserve_emitted_tokens + GREATEST(0.0, daily_emission_rate)
            ),
            total_burned_tokens = total_burned_tokens + (GREATEST(0.0, daily_emission_rate) * (burn_rate_bps::float8 / 10000.0)),
            last_bell_processed_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        "#,
    )
    .execute(pool)
    .await?
    .rows_affected();

    let vault_rows = sqlx::query(
        r#"
        SELECT vault_id::text AS vault_id, token_ticker, remaining_vault_tokens, daily_emission_tokens
        FROM forge_mineable_vaults
        WHERE status = 'ACTIVE' AND remaining_vault_tokens > 0
        "#,
    )
    .fetch_all(pool)
    .await?;

    let worker_rows = sqlx::query(
        r#"
        SELECT wallet_address, SUM(GREATEST(0.0, hashrate_ths)) AS total_ths
        FROM worker_profiles
        WHERE status = 'online' AND wallet_address != ''
        GROUP BY wallet_address
        "#,
    )
    .fetch_all(pool)
    .await?;

    let total_pool_ths: f64 = worker_rows
        .iter()
        .map(|w| w.try_get::<f64, _>("total_ths").unwrap_or(0.0))
        .sum();

    let mut vaults_distributed = 0usize;
    for v in vault_rows {
        let vault_id: String = v.try_get("vault_id").unwrap_or_default();
        let ticker: String = v.try_get("token_ticker").unwrap_or_else(|_| "SILO".to_string());
        let rem: f64 = v.try_get("remaining_vault_tokens").unwrap_or(0.0);
        let daily: f64 = v.try_get("daily_emission_tokens").unwrap_or(0.0);
        let emit_today = rem.min(daily).max(0.0);
        if emit_today <= 0.0 {
            continue;
        }

        if total_pool_ths > 0.0 {
            for w in &worker_rows {
                let miner_wallet: String = w.try_get("wallet_address").unwrap_or_default();
                let miner_ths: f64 = w.try_get("total_ths").unwrap_or(0.0);
                let share = (miner_ths / total_pool_ths) * emit_today;
                if share > 0.0 {
                    let _ = sqlx::query(
                        r#"
                        INSERT INTO yield_reservoirs (wallet_address, lp_tokens)
                        VALUES ($1, jsonb_build_object($2::text, $3::float8))
                        ON CONFLICT (wallet_address) DO UPDATE SET
                            lp_tokens = jsonb_set(
                                COALESCE(yield_reservoirs.lp_tokens, '{}'::jsonb),
                                ARRAY[$2::text],
                                to_jsonb(COALESCE((yield_reservoirs.lp_tokens->>$2)::float8, 0.0) + $3::float8),
                                true
                            ),
                            last_updated = CURRENT_TIMESTAMP
                        "#,
                    )
                    .bind(&miner_wallet)
                    .bind(&ticker)
                    .bind(share)
                    .execute(pool)
                    .await;
                }
            }
        }

        let _ = sqlx::query(
            r#"
            UPDATE forge_mineable_vaults
            SET remaining_vault_tokens = GREATEST(0.0, remaining_vault_tokens - $2),
                distributed_tokens = distributed_tokens + $2,
                last_bell_distributed_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE vault_id::text = $1
            "#,
        )
        .bind(&vault_id)
        .bind(emit_today)
        .execute(pool)
        .await;

        vaults_distributed += 1;
    }

    Ok(json!({
        "vestingTranchesUnlocked": vesting_updated,
        "monetaryPoliciesProcessed": policy_updated,
        "mineableVaultsDistributed": vaults_distributed
    }))
}