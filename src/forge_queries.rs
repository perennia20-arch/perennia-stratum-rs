use serde_json::{json, Value};
use sqlx::{PgPool, Row};

use crate::state_api::{compile_silverscript_proof_of_lock_vault, KASPA_ADDR_VERSION_P2PK_SCHNORR};

pub async fn query_forge_tokenomics_bundle(
    pool: &PgPool,
    ticker_opt: Option<&str>,
    include_all_vaults: bool,
) -> Result<Value, String> {
    let clean_ticker = ticker_opt
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "SILO".to_string());

    let policy_row = sqlx::query(
        r#"
        SELECT token_ticker, creator_address, max_supply, burn_rate_bps,
               burn_address, total_burned_tokens, emission_schedule_type,
               daily_emission_rate, halving_interval_days, reserve_locked_tokens,
               reserve_emitted_tokens, zero_rug_lp_pct, zero_rug_lock_days,
               is_retroactive_upgrade, charter_sha256, anchor_tx_hash
        FROM forge_monetary_policies
        WHERE token_ticker = $1
        "#,
    )
    .bind(&clean_ticker)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("Policy query failed: {}", e))?;

    let policy_json = if let Some(r) = policy_row {
        json!({
            "tokenTicker": r.try_get::<String, _>("token_ticker").unwrap_or_default(),
            "creatorAddress": r.try_get::<String, _>("creator_address").unwrap_or_default(),
            "maxSupply": r.try_get::<f64, _>("max_supply").unwrap_or(21_000_000.0),
            "burnRateBps": r.try_get::<i32, _>("burn_rate_bps").unwrap_or(100),
            "burnAddress": r.try_get::<String, _>("burn_address").unwrap_or_default(),
            "totalBurnedTokens": r.try_get::<f64, _>("total_burned_tokens").unwrap_or(0.0),
            "emissionScheduleType": r.try_get::<String, _>("emission_schedule_type").unwrap_or_else(|_| "CHROMATIC_HALVING".to_string()),
            "dailyEmissionRate": r.try_get::<f64, _>("daily_emission_rate").unwrap_or(0.0),
            "halvingIntervalDays": r.try_get::<i32, _>("halving_interval_days").unwrap_or(365),
            "reserveLockedTokens": r.try_get::<f64, _>("reserve_locked_tokens").unwrap_or(0.0),
            "reserveEmittedTokens": r.try_get::<f64, _>("reserve_emitted_tokens").unwrap_or(0.0),
            "zeroRugLpPct": r.try_get::<f64, _>("zero_rug_lp_pct").unwrap_or(50.0),
            "zeroRugLockDays": r.try_get::<i32, _>("zero_rug_lock_days").unwrap_or(365),
            "isRetroactiveUpgrade": r.try_get::<bool, _>("is_retroactive_upgrade").unwrap_or(false),
            "charterSha256": r.try_get::<String, _>("charter_sha256").unwrap_or_default(),
            "anchorTxHash": r.try_get::<Option<String>, _>("anchor_tx_hash").ok().flatten()
        })
    } else {
        Value::Null
    };

    let vault_row = sqlx::query(
        r#"
        SELECT vault_id::text AS vault_id, token_ticker, creator_address, vault_label,
               total_funded_tokens, remaining_vault_tokens, daily_emission_tokens,
               distributed_tokens, min_hashrate_ths, syndicate_sector_enabled,
               active_miners_count, status, funding_tx_hash
        FROM forge_mineable_vaults
        WHERE token_ticker = $1
        "#,
    )
    .bind(&clean_ticker)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("Mineable vault query failed: {}", e))?;

    let mineable_vault_json = if let Some(v) = vault_row {
        json!({
            "vaultId": v.try_get::<String, _>("vault_id").unwrap_or_default(),
            "tokenTicker": v.try_get::<String, _>("token_ticker").unwrap_or_default(),
            "creatorAddress": v.try_get::<String, _>("creator_address").unwrap_or_default(),
            "vaultLabel": v.try_get::<String, _>("vault_label").unwrap_or_default(),
            "totalFundedTokens": v.try_get::<f64, _>("total_funded_tokens").unwrap_or(0.0),
            "remainingVaultTokens": v.try_get::<f64, _>("remaining_vault_tokens").unwrap_or(0.0),
            "dailyEmissionTokens": v.try_get::<f64, _>("daily_emission_tokens").unwrap_or(0.0),
            "distributedTokens": v.try_get::<f64, _>("distributed_tokens").unwrap_or(0.0),
            "minHashrateThs": v.try_get::<f64, _>("min_hashrate_ths").unwrap_or(0.1),
            "syndicateSectorEnabled": v.try_get::<bool, _>("syndicate_sector_enabled").unwrap_or(true),
            "activeMinersCount": v.try_get::<i32, _>("active_miners_count").unwrap_or(1),
            "status": v.try_get::<String, _>("status").unwrap_or_else(|_| "ACTIVE".to_string()),
            "fundingTxHash": v.try_get::<Option<String>, _>("funding_tx_hash").ok().flatten()
        })
    } else {
        Value::Null
    };

    let vesting_rows = sqlx::query(
        r#"
        SELECT vesting_id::text AS vesting_id, token_ticker, beneficiary_address,
               creator_address, label, total_allocated, unlocked_amount,
               claimed_amount, cliff_days, linear_days, daily_unlock_rate,
               covenant_rule, vprog_state_root, lock_tx_hash, status
        FROM forge_vesting_schedules
        WHERE token_ticker = $1
        ORDER BY created_at ASC
        "#,
    )
    .bind(&clean_ticker)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("Vesting query failed: {}", e))?;

    let vesting_schedules: Vec<Value> = vesting_rows
        .into_iter()
        .map(|row| {
            let ben_addr = row
                .try_get::<String, _>("beneficiary_address")
                .unwrap_or_default();
            let total_alloc = row.try_get::<f64, _>("total_allocated").unwrap_or(0.0);
            let cliff_d = row.try_get::<i32, _>("cliff_days").unwrap_or(0) as i64;
            let linear_d = row.try_get::<i32, _>("linear_days").unwrap_or(365) as i64;
            let label = row
                .try_get::<String, _>("label")
                .unwrap_or_else(|_| "Genesis Tranche".to_string());
            let compiled = compile_silverscript_proof_of_lock_vault(
                &clean_ticker,
                "KRC-20",
                &label,
                &ben_addr,
                total_alloc,
                cliff_d,
                linear_d,
                None,
            );
            json!({
                "vestingId": row.try_get::<String, _>("vesting_id").unwrap_or_default(),
                "tokenTicker": row.try_get::<String, _>("token_ticker").unwrap_or_default(),
                "beneficiaryAddress": ben_addr,
                "creatorAddress": row.try_get::<String, _>("creator_address").unwrap_or_default(),
                "label": label,
                "totalAllocated": total_alloc,
                "unlockedAmount": row.try_get::<f64, _>("unlocked_amount").unwrap_or(0.0),
                "claimedAmount": row.try_get::<f64, _>("claimed_amount").unwrap_or(0.0),
                "cliffDays": cliff_d,
                "linearDays": linear_d,
                "dailyUnlockRate": row.try_get::<f64, _>("daily_unlock_rate").unwrap_or(0.0),
                "covenantRule": row.try_get::<String, _>("covenant_rule").unwrap_or_default(),
                "vprogStateRoot": row.try_get::<String, _>("vprog_state_root").unwrap_or(compiled.kcc20_state.state_root_hex),
                "covenantAddress": compiled.covenant_address,
                "silverscriptSource": compiled.silverscript_source,
                "redeemScriptHex": compiled.redeem_script_hex,
                "lockTxHash": row.try_get::<Option<String>, _>("lock_tx_hash").ok().flatten(),
                "status": row.try_get::<String, _>("status").unwrap_or_else(|_| "LOCKED".to_string())
            })
        })
        .collect();

    let mut all_mineable_vaults = Vec::new();
    if include_all_vaults {
        if let Ok(rows) = sqlx::query(
            r#"
            SELECT vault_id::text AS vault_id, token_ticker, vault_label,
                   total_funded_tokens, remaining_vault_tokens, daily_emission_tokens,
                   distributed_tokens, min_hashrate_ths, syndicate_sector_enabled,
                   active_miners_count, status
            FROM forge_mineable_vaults
            WHERE status = 'ACTIVE'
            ORDER BY created_at ASC
            "#,
        )
        .fetch_all(pool)
        .await
        {
            for v in rows {
                all_mineable_vaults.push(json!({
                    "vaultId": v.try_get::<String, _>("vault_id").unwrap_or_default(),
                    "tokenTicker": v.try_get::<String, _>("token_ticker").unwrap_or_default(),
                    "vaultLabel": v.try_get::<String, _>("vault_label").unwrap_or_default(),
                    "totalFundedTokens": v.try_get::<f64, _>("total_funded_tokens").unwrap_or(0.0),
                    "remainingVaultTokens": v.try_get::<f64, _>("remaining_vault_tokens").unwrap_or(0.0),
                    "dailyEmissionTokens": v.try_get::<f64, _>("daily_emission_tokens").unwrap_or(0.0),
                    "distributedTokens": v.try_get::<f64, _>("distributed_tokens").unwrap_or(0.0),
                    "minHashrateThs": v.try_get::<f64, _>("min_hashrate_ths").unwrap_or(0.1),
                    "syndicateSectorEnabled": v.try_get::<bool, _>("syndicate_sector_enabled").unwrap_or(true),
                    "activeMinersCount": v.try_get::<i32, _>("active_miners_count").unwrap_or(1),
                    "status": v.try_get::<String, _>("status").unwrap_or_else(|_| "ACTIVE".to_string())
                }));
            }
        }
    }

    let _ = KASPA_ADDR_VERSION_P2PK_SCHNORR;

    Ok(json!({
        "ticker": clean_ticker,
        "monetaryPolicy": policy_json,
        "mineableVault": mineable_vault_json,
        "vestingSchedules": vesting_schedules,
        "allMineableVaults": all_mineable_vaults
    }))
}

pub async fn deploy_forge_tokenomics_bundle(
    pool: &PgPool,
    creator_wallet: &str,
    payload: &Value,
) -> Result<Value, String> {
    let ticker = payload
        .get("ticker")
        .and_then(|v| v.as_str())
        .unwrap_or("SILO")
        .trim()
        .to_uppercase();
    let max_supply = payload
        .get("maxSupply")
        .and_then(|v| v.as_f64())
        .unwrap_or(21_000_000.0);
    let burn_rate_bps = payload
        .get("burnRateBps")
        .and_then(|v| v.as_i64())
        .unwrap_or(100) as i32;
    let emission_schedule_type = payload
        .get("emissionScheduleType")
        .and_then(|v| v.as_str())
        .unwrap_or("CHROMATIC_HALVING");
    let daily_emission_rate = payload
        .get("dailyEmissionRate")
        .and_then(|v| v.as_f64())
        .unwrap_or(13_698.0);
    let halving_interval_days = payload
        .get("halvingIntervalDays")
        .and_then(|v| v.as_i64())
        .unwrap_or(365) as i32;
    let reserve_locked_tokens = payload
        .get("reserveLockedTokens")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let zero_rug_lp_pct = payload
        .get("zeroRugLpPct")
        .and_then(|v| v.as_f64())
        .unwrap_or(50.0);
    let zero_rug_lock_days = payload
        .get("zeroRugLockDays")
        .and_then(|v| v.as_i64())
        .unwrap_or(365) as i32;
    let is_retroactive = payload
        .get("isRetroactiveUpgrade")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let charter_sha256 = payload
        .get("charterSha256")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let anchor_tx_hash = payload.get("anchorTxHash").and_then(|v| v.as_str());

    sqlx::query(
        r#"
        INSERT INTO forge_monetary_policies (
            token_ticker, creator_address, max_supply, burn_rate_bps,
            emission_schedule_type, daily_emission_rate, halving_interval_days,
            reserve_locked_tokens, zero_rug_lp_pct, zero_rug_lock_days,
            is_retroactive_upgrade, charter_sha256, anchor_tx_hash
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        ON CONFLICT (token_ticker) DO UPDATE SET
            max_supply = EXCLUDED.max_supply,
            burn_rate_bps = EXCLUDED.burn_rate_bps,
            emission_schedule_type = EXCLUDED.emission_schedule_type,
            daily_emission_rate = EXCLUDED.daily_emission_rate,
            halving_interval_days = EXCLUDED.halving_interval_days,
            reserve_locked_tokens = EXCLUDED.reserve_locked_tokens,
            zero_rug_lp_pct = EXCLUDED.zero_rug_lp_pct,
            zero_rug_lock_days = EXCLUDED.zero_rug_lock_days,
            is_retroactive_upgrade = EXCLUDED.is_retroactive_upgrade,
            charter_sha256 = EXCLUDED.charter_sha256,
            anchor_tx_hash = COALESCE(EXCLUDED.anchor_tx_hash, forge_monetary_policies.anchor_tx_hash),
            updated_at = CURRENT_TIMESTAMP
        "#,
    )
    .bind(&ticker)
    .bind(creator_wallet)
    .bind(max_supply)
    .bind(burn_rate_bps)
    .bind(emission_schedule_type)
    .bind(daily_emission_rate)
    .bind(halving_interval_days)
    .bind(reserve_locked_tokens)
    .bind(zero_rug_lp_pct)
    .bind(zero_rug_lock_days)
    .bind(is_retroactive)
    .bind(charter_sha256)
    .bind(anchor_tx_hash)
    .execute(pool)
    .await
    .map_err(|e| format!("Failed to upsert forge_monetary_policies: {}", e))?;

    if let Some(vault_obj) = payload.get("mineableVault").and_then(|v| v.as_object()) {
        let total_funded = vault_obj
            .get("totalFundedTokens")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if total_funded > 0.0 {
            let daily_emit = vault_obj
                .get("dailyEmissionTokens")
                .and_then(|v| v.as_f64())
                .unwrap_or(1000.0);
            let vault_label = vault_obj
                .get("vaultLabel")
                .and_then(|v| v.as_str())
                .unwrap_or("Proof-of-Hashrate Mining Vault");
            let min_hash = vault_obj
                .get("minHashrateThs")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.1);
            let syndicate_enabled = vault_obj
                .get("syndicateSectorEnabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            let _ = sqlx::query(
                r#"
                INSERT INTO forge_mineable_vaults (
                    token_ticker, creator_address, vault_label, total_funded_tokens,
                    remaining_vault_tokens, daily_emission_tokens, min_hashrate_ths,
                    syndicate_sector_enabled, funding_tx_hash
                ) VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8)
                ON CONFLICT (token_ticker) DO UPDATE SET
                    vault_label = EXCLUDED.vault_label,
                    total_funded_tokens = EXCLUDED.total_funded_tokens,
                    remaining_vault_tokens = EXCLUDED.remaining_vault_tokens,
                    daily_emission_tokens = EXCLUDED.daily_emission_tokens,
                    min_hashrate_ths = EXCLUDED.min_hashrate_ths,
                    syndicate_sector_enabled = EXCLUDED.syndicate_sector_enabled,
                    updated_at = CURRENT_TIMESTAMP
                "#,
            )
            .bind(&ticker)
            .bind(creator_wallet)
            .bind(vault_label)
            .bind(total_funded)
            .bind(daily_emit)
            .bind(min_hash)
            .bind(syndicate_enabled)
            .bind(anchor_tx_hash)
            .execute(pool)
            .await;
        }
    }

    if let Some(cap_table) = payload.get("capTable").and_then(|v| v.as_array()) {
        for entry in cap_table {
            let ben_addr = entry
                .get("address")
                .and_then(|v| v.as_str())
                .unwrap_or(creator_wallet);
            let label = entry
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("Genesis Tranche");
            let amount = entry.get("amount").and_then(|v| v.as_f64()).unwrap_or(0.0);
            if amount <= 0.0 {
                continue;
            }
            let cliff_d = entry.get("cliffDays").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let linear_d = entry
                .get("linearDays")
                .and_then(|v| v.as_i64())
                .unwrap_or(365) as i32;
            let daily_rate = if linear_d > 0 {
                amount / (linear_d as f64)
            } else {
                amount
            };
            let unlocked_init = if cliff_d == 0 && linear_d == 0 {
                amount
            } else {
                0.0
            };
            let status_init = if cliff_d == 0 && linear_d == 0 {
                "UNLOCKED"
            } else {
                "LOCKED"
            };
            let compiled = compile_silverscript_proof_of_lock_vault(
                &ticker,
                "KRC-20",
                label,
                ben_addr,
                amount,
                cliff_d as i64,
                linear_d as i64,
                Some(charter_sha256),
            );

            let _ = sqlx::query(
                r#"
                INSERT INTO forge_vesting_schedules (
                    token_ticker, beneficiary_address, creator_address, label,
                    total_allocated, unlocked_amount, cliff_days, linear_days,
                    daily_unlock_rate, vprog_state_root, lock_tx_hash, status
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                "#,
            )
            .bind(&ticker)
            .bind(ben_addr)
            .bind(creator_wallet)
            .bind(label)
            .bind(amount)
            .bind(unlocked_init)
            .bind(cliff_d)
            .bind(linear_d)
            .bind(daily_rate)
            .bind(&compiled.kcc20_state.state_root_hex)
            .bind(anchor_tx_hash)
            .bind(status_init)
            .execute(pool)
            .await;
        }
    }

    query_forge_tokenomics_bundle(pool, Some(&ticker), true).await
}

pub async fn claim_vested_forge_tranche(
    pool: &PgPool,
    wallet: &str,
    payload: &Value,
) -> Result<Value, String> {
    let vesting_id = payload
        .get("vestingId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing vestingId".to_string())?;

    let row_opt = sqlx::query(
        r#"
        SELECT token_ticker, beneficiary_address, unlocked_amount, claimed_amount
        FROM forge_vesting_schedules
        WHERE vesting_id::text = $1
        "#,
    )
    .bind(vesting_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("Vesting lookup failed: {}", e))?;

    let Some(row) = row_opt else {
        return Err("Vesting tranche not found".to_string());
    };

    let ticker: String = row.try_get("token_ticker").unwrap_or_else(|_| "SILO".to_string());
    let beneficiary: String = row
        .try_get("beneficiary_address")
        .unwrap_or_else(|_| wallet.to_string());
    let unlocked: f64 = row.try_get("unlocked_amount").unwrap_or(0.0);
    let claimed: f64 = row.try_get("claimed_amount").unwrap_or(0.0);
    let claimable = (unlocked - claimed).max(0.0);

    if claimable <= 0.0 {
        return Err("No unlocked tokens currently available to claim.".to_string());
    }

    sqlx::query(
        r#"
        UPDATE forge_vesting_schedules
        SET claimed_amount = unlocked_amount,
            updated_at = CURRENT_TIMESTAMP
        WHERE vesting_id::text = $1
        "#,
    )
    .bind(vesting_id)
    .execute(pool)
    .await
    .map_err(|e| format!("Claim update failed: {}", e))?;

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
    .bind(&beneficiary)
    .bind(&ticker)
    .bind(claimable)
    .execute(pool)
    .await;

    Ok(json!({
        "vestingId": vesting_id,
        "tokenTicker": ticker,
        "claimedAmount": claimable,
        "beneficiary": beneficiary
    }))
}