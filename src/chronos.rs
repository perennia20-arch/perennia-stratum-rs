#[path = "chronos/netting.rs"]
pub mod netting;
#[path = "chronos/forge_bell.rs"]
pub mod forge_bell;
#[path = "chronos/daemons.rs"]
pub mod daemons;

pub use daemons::*;
pub use forge_bell::*;
pub use netting::*;

use chrono::{Timelike, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::env;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::kaspad_client::protowire::kaspad_request::Payload as RequestPayload;
use crate::kaspad_client::protowire::kaspad_response::Payload as ResponsePayload;
use crate::kaspad_client::protowire::rpc_client::RpcClient;
use crate::kaspad_client::protowire::{GetBlockDagInfoRequestMessage, KaspadRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U128Str(pub u128);

impl Serialize for U128Str {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for U128Str {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.trim()
            .parse::<u128>()
            .map(U128Str)
            .map_err(serde::de::Error::custom)
    }
}

#[inline]
fn mul_div_floor_u128(a: u128, b: u128, denom: u128) -> u128 {
    if denom == 0 || a == 0 || b == 0 {
        return 0;
    }
    if let Some(prod) = a.checked_mul(b) {
        return prod / denom;
    }
    // Exact bitwise (a * b) / denom using wide u128 remainder without overflow
    let q_hi = a / denom;
    let r_hi = a % denom;
    let first = q_hi.saturating_mul(b);
    let q_b = b / denom;
    let r_b = b % denom;
    let cross = r_hi.saturating_mul(q_b);
    let rem_prod = r_hi.checked_mul(r_b).map(|p| p / denom).unwrap_or(0);
    first.saturating_add(cross).saturating_add(rem_prod)
}

#[allow(dead_code)]
pub const SOMPI_PER_KAS_U64: u64 = 100_000_000;
#[allow(dead_code)]
pub const SOMPI_PER_KAS_U128: u128 = 100_000_000;
#[allow(dead_code)]
pub const STAGE1_POOL_FLUSH_FLOOR_SOMPI: u128 = 2_500_000_000;
pub const COINBASE_MATURITY_DAA_BLOCKS: u64 = 1_000;
pub const SOLVENCY_CHECK_INTERVAL_SECS: u64 = 30;
pub const REDIS_KEY_SOLVENCY_BREAKER: &str = "perennia:solvency:circuit_breaker";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemTreasuryConfig {
    pub config_id: String,
    pub hot_ceiling_sompi: u64,
    pub min_runway_sompi: u64,
    pub fpps_max_float_sompi: u64,
    pub pool_fee_bps: u16,
    pub house_revenue_kas_address: String,
    pub outflow_breaker_tripped: bool,
    pub solvency_breaker_tripped: bool,
    pub solvency_deficit_sompi: U128Str,
    pub cold_kas_address: String,
    pub cold_btc_address: String,
    pub cold_eth_address: String,
    pub cold_sol_address: String,
    pub updated_by: String,
    pub updated_at: String,
    /// Temporary compile guard for untouched Batch 2 `chronos/daemons.rs`; always 0.0.
    #[serde(skip)]
    pub hot_ceiling_kas: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SolvencyProofSnapshot {
    pub is_solvent: bool,
    pub pool_vault_address: String,
    pub virtual_daa_score: u64,
    pub unpaid_mature_sompi: U128Str,
    pub inflight_outbox_sompi: U128Str,
    pub required_total_sompi: U128Str,
    pub confirmed_pool_vault_utxo_sompi: U128Str,
    pub immature_coinbase_utxo_sompi: U128Str,
    pub surplus_sompi: U128Str,
    pub deficit_sompi: U128Str,
    pub checked_at: String,
}

pub fn resolve_master_treasury_address() -> String {
    env::var("PERENNIA_MASTER_TREASURY_KAS")
        .or_else(|_| env::var("MASTER_ADMIN_ADDRESS"))
        .or_else(|_| env::var("MASTER_TREASURY_ADDRESS"))
        .ok()
        .map(|s| s.trim().to_lowercase().replace("kaspa:", "").trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_default()
}

pub fn resolve_master_treasury_prefixed() -> Result<String, String> {
    let clean = resolve_master_treasury_address();
    if clean.len() < 55 {
        return Err(
            "CONFIG_HALT: PERENNIA_MASTER_TREASURY_KAS is not configured in .env.".to_string(),
        );
    }
    Ok(format!("kaspa:{}", clean))
}

pub fn resolve_hot_dispatcher_address() -> Option<String> {
    env::var("PERENNIA_HOT_KAS_ADDRESS")
        .or_else(|_| env::var("PERENNIA_TREASURY_KAS_ADDRESS"))
        .ok()
        .map(|s| s.trim().to_lowercase().replace("kaspa:", "").trim().to_string())
        .filter(|s| s.len() >= 55)
        .map(|clean| format!("kaspa:{}", clean))
}

#[allow(dead_code)]
pub fn resolve_house_revenue_kas_address(sys_cfg: &SystemTreasuryConfig) -> Option<String> {
    if let Ok(env_rev) = env::var("PERENNIA_HOUSE_REVENUE_KAS_ADDRESS") {
        let clean = env_rev.trim().to_lowercase().replace("kaspa:", "").trim().to_string();
        if clean.len() >= 55 {
            return Some(format!("kaspa:{}", clean));
        }
    }
    let db_rev = sys_cfg
        .house_revenue_kas_address
        .trim()
        .to_lowercase()
        .replace("kaspa:", "")
        .trim()
        .to_string();
    if db_rev.len() >= 55 {
        return Some(format!("kaspa:{}", db_rev));
    }
    let cold = sys_cfg
        .cold_kas_address
        .trim()
        .to_lowercase()
        .replace("kaspa:", "")
        .trim()
        .to_string();
    if cold.len() >= 55 {
        return Some(format!("kaspa:{}", cold));
    }
    resolve_master_treasury_prefixed().ok()
}

#[allow(dead_code)]
pub fn compute_outbox_idempotency_key(
    epoch_id: &str,
    clean_wallet: &str,
    vault_id: &str,
) -> String {
    let preimage = format!(
        "{}|{}|{}",
        epoch_id.trim(),
        clean_wallet.trim().to_ascii_lowercase(),
        vault_id.trim()
    );
    blake3::hash(preimage.as_bytes()).to_hex().to_string()
}

/// Deprecated custodial HMAC shim retained for Batch 2/4 callers (`admin_api.rs`, tests).
pub fn compute_reservoir_hmac(
    _wallet_address: &str,
    _legacy_a: f64,
    _legacy_b: f64,
    _lp_tokens: &Value,
) -> Result<String, String> {
    Err("DEPRECATED_CUSTODIAL_RESERVOIR_RETIRED: Use live Kaspa L1 UTXO vault verification.".to_string())
}

/// Enforces the pool-wide 30s Solvency Circuit Breaker and fails closed on any custodial debit request.
pub async fn verify_wallet_ledger_invariant_or_quarantine(
    pool: &PgPool,
    _wallet_address: &str,
    requested_kas_debit: f64,
) -> Result<(), String> {
    let sys_cfg = load_system_treasury_config(pool).await;
    if sys_cfg.outflow_breaker_tripped || sys_cfg.solvency_breaker_tripped {
        return Err(
            "CIRCUIT_BREAKER_TRIPPED: Automated L1 outflows are halted by Solvency or Director breaker."
                .to_string(),
        );
    }
    let _ = evaluate_pool_solvency_invariant(pool).await?;
    if requested_kas_debit != 0.0 {
        return Err(
            "NON_CUSTODIAL_L1_ONLY: Custodial yield_reservoirs debits are permanently retired."
                .to_string(),
        );
    }
    Ok(())
}

async fn query_live_virtual_daa_score() -> Result<u64, String> {
    let endpoints = crate::kaspad_client::resolve_local_first_grpc_endpoints();
    let mut last_err = String::from("No kaspad gRPC endpoints available");
    for endpoint in endpoints {
        let Ok(Ok(mut client)) = tokio::time::timeout(
            Duration::from_millis(2500),
            RpcClient::connect(endpoint.clone()),
        )
        .await
        else {
            last_err = format!("{} connect failed", endpoint);
            continue;
        };

        let (tx, rx) = mpsc::channel::<KaspadRequest>(2);
        let _ = tx
            .send(KaspadRequest {
                id: 9_001_001,
                payload: Some(RequestPayload::GetBlockDagInfoRequest(
                    GetBlockDagInfoRequestMessage {},
                )),
            })
            .await;

        let Ok(Ok(stream_resp)) = tokio::time::timeout(
            Duration::from_millis(3000),
            client.message_stream(ReceiverStream::new(rx)),
        )
        .await
        else {
            last_err = format!("{} stream failed", endpoint);
            continue;
        };

        let mut resp_stream = stream_resp.into_inner();
        if let Ok(Ok(Some(msg))) =
            tokio::time::timeout(Duration::from_millis(3000), resp_stream.message()).await
        {
            if let Some(ResponsePayload::GetBlockDagInfoResponse(dag)) = msg.payload {
                if dag.error.is_none() && dag.virtual_daa_score > 0 {
                    return Ok(dag.virtual_daa_score);
                }
            }
        }
    }

    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url.trim()) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                if let Ok(Some(daa_str)) = redis::cmd("GET")
                    .arg("pool:virtual_daa_score")
                    .query_async::<_, Option<String>>(&mut conn)
                    .await
                {
                    if let Ok(daa) = daa_str.trim().parse::<u64>() {
                        if daa > 0 {
                            return Ok(daa);
                        }
                    }
                }
            }
        }
    }

    Err(format!(
        "KASPAD_DAA_UNAVAILABLE: Unable to read live virtual DAA score ({}). Failing closed.",
        last_err
    ))
}

pub async fn query_live_virtual_daa_and_pool_utxos(
    pool_vault_addr: &str,
) -> Result<(u64, u128, u128), String> {
    let virtual_daa = query_live_virtual_daa_score().await?;
    let raw_entries = crate::kaspad_client::get_utxos_by_address_grpc(pool_vault_addr).await?;

    let mut confirmed_sompi: u128 = 0;
    let mut immature_coinbase_sompi: u128 = 0;

    for entry in raw_entries {
        let Some(utxo_entry) = entry.get("utxoEntry") else {
            continue;
        };
        let amount_sompi = utxo_entry
            .get("amount")
            .and_then(|v| {
                v.as_u64()
                    .map(|x| x as u128)
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u128>().ok()))
            })
            .unwrap_or(0);
        if amount_sompi == 0 {
            continue;
        }
        let block_daa = utxo_entry
            .get("blockDaaScore")
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            })
            .unwrap_or(0);
        let is_coinbase = utxo_entry
            .get("isCoinbase")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if block_daa == 0 || block_daa == u64::MAX || virtual_daa < block_daa {
            continue;
        }

        if is_coinbase && virtual_daa.saturating_sub(block_daa) < COINBASE_MATURITY_DAA_BLOCKS {
            immature_coinbase_sompi = immature_coinbase_sompi.saturating_add(amount_sompi);
        } else {
            confirmed_sompi = confirmed_sompi.saturating_add(amount_sompi);
        }
    }

    Ok((virtual_daa, confirmed_sompi, immature_coinbase_sompi))
}

pub async fn advance_1000_daa_coinbase_maturity(
    pool: &PgPool,
    virtual_daa: u64,
    default_pool_fee_bps: u16,
) -> Result<(u64, u128), String> {
    let fee_bps = (default_pool_fee_bps as u128).clamp(50, 200);
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| format!("Failed to begin SERIALIZABLE maturity tx: {}", e))?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Failed to set SERIALIZABLE isolation: {}", e))?;

    let unmatured_rows = sqlx::query(
        r#"
        SELECT block_hash, reward_sompi
        FROM network_blocks
        WHERE COALESCE(is_orphaned, FALSE) = FALSE
          AND COALESCE(is_mature, FALSE) = FALSE
          AND daa_score > 0
          AND $1 >= daa_score + $2
        FOR UPDATE
        "#,
    )
    .bind(virtual_daa as i64)
    .bind(COINBASE_MATURITY_DAA_BLOCKS as i64)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("Failed to lock unmatured network_blocks: {}", e))?;

    let mut newly_matured_blocks: u64 = 0;
    let mut newly_matured_net_sompi: u128 = 0;

    for row in unmatured_rows {
        let block_hash: String = row.try_get("block_hash").unwrap_or_default();
        let reward_sompi_raw: i64 = row.try_get("reward_sompi").unwrap_or(0);
        let reward_sompi = reward_sompi_raw.max(0) as u128;
        let fee_sompi = reward_sompi.saturating_mul(fee_bps) / 10_000;
        let miner_net = reward_sompi.saturating_sub(fee_sompi);

        sqlx::query(
            r#"
            UPDATE network_blocks
            SET is_mature = TRUE,
                matured_at_daa = $2,
                pool_fee_sompi = $3,
                miner_net_sompi = $4,
                flushed_to_accruals = TRUE
            WHERE block_hash = $1
            "#,
        )
        .bind(&block_hash)
        .bind(virtual_daa as i64)
        .bind(fee_sompi as i64)
        .bind(miner_net as i64)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Failed to mark block {} mature: {}", block_hash, e))?;

        newly_matured_blocks = newly_matured_blocks.saturating_add(1);
        newly_matured_net_sompi = newly_matured_net_sompi.saturating_add(miner_net);
    }

    if newly_matured_net_sompi > 0 {
        let accrual_rows = sqlx::query(
            r#"
            SELECT clean_wallet, immature_sompi::TEXT AS immature_sompi
            FROM stratum_mature_accruals
            WHERE immature_sompi > 0
            ORDER BY clean_wallet ASC
            FOR UPDATE
            "#,
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| format!("Failed to lock stratum_mature_accruals: {}", e))?;

        let mut parsed_accruals: Vec<(String, u128)> = Vec::with_capacity(accrual_rows.len());
        let mut total_immature: u128 = 0;
        for r in accrual_rows {
            let cw: String = r.try_get("clean_wallet").unwrap_or_default();
            let imm: u128 = r
                .try_get::<String, _>("immature_sompi")
                .ok()
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(0);
            if !cw.is_empty() && imm > 0 {
                total_immature = total_immature.saturating_add(imm);
                parsed_accruals.push((cw, imm));
            }
        }

        if total_immature > 0 {
            let promotable_budget = total_immature.min(newly_matured_net_sompi);
            for (cw, imm) in parsed_accruals {
                let promoted = if total_immature <= promotable_budget {
                    imm
                } else {
                    mul_div_floor_u128(imm, promotable_budget, total_immature)
                };
                if promoted == 0 {
                    continue;
                }
                sqlx::query(
                    r#"
                    UPDATE stratum_mature_accruals
                    SET immature_sompi = GREATEST(0, immature_sompi - $2::NUMERIC(39, 0)),
                        unpaid_mature_sompi = unpaid_mature_sompi + $2::NUMERIC(39, 0),
                        last_maturity_daa = $3,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE clean_wallet = $1
                    "#,
                )
                .bind(&cw)
                .bind(promoted.to_string())
                .bind(virtual_daa as i64)
                .execute(&mut *tx)
                .await
                .map_err(|e| format!("Failed to promote mature accruals for {}: {}", cw, e))?;
            }
        }
    }

    tx.commit()
        .await
        .map_err(|e| format!("Failed to commit SERIALIZABLE maturity tx: {}", e))?;

    Ok((newly_matured_blocks, newly_matured_net_sompi))
}

async fn trip_solvency_circuit_breaker(
    pool: &PgPool,
    unpaid_mature_sompi: u128,
    inflight_outbox_sompi: u128,
    confirmed_pool_vault_utxo_sompi: u128,
    deficit_sompi: u128,
    virtual_daa_score: u64,
    reason: &str,
) {
    tracing::error!(
        "🚨 [30s SOLVENCY BREAKER TRIPPED] unpaid_mature={} + inflight={} > confirmed_utxo={} | deficit={} sompi | daa={} | reason={}",
        unpaid_mature_sompi,
        inflight_outbox_sompi,
        confirmed_pool_vault_utxo_sompi,
        deficit_sompi,
        virtual_daa_score,
        reason
    );

    let _ = sqlx::query(
        r#"
        UPDATE system_treasury_config
        SET outflow_breaker_tripped = TRUE,
            solvency_breaker_tripped = TRUE,
            solvency_deficit_sompi = $1::NUMERIC(39, 0),
            updated_by = 'SOLVENCY_CIRCUIT_BREAKER',
            updated_at = CURRENT_TIMESTAMP
        WHERE config_id = 'PRIMARY'
        "#,
    )
    .bind(deficit_sompi.to_string())
    .execute(pool)
    .await;

    let _ = sqlx::query(
        r#"
        INSERT INTO solvency_circuit_events (
            unpaid_mature_sompi, inflight_outbox_sompi,
            confirmed_pool_vault_utxo_sompi, deficit_sompi,
            virtual_daa_score, trigger_reason
        ) VALUES ($1::NUMERIC(39,0), $2::NUMERIC(39,0), $3::NUMERIC(39,0), $4::NUMERIC(39,0), $5, $6)
        "#,
    )
    .bind(unpaid_mature_sompi.to_string())
    .bind(inflight_outbox_sompi.to_string())
    .bind(confirmed_pool_vault_utxo_sompi.to_string())
    .bind(deficit_sompi.to_string())
    .bind(virtual_daa_score as i64)
    .bind(reason)
    .execute(pool)
    .await;

    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url.trim()) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let alert = json!({
                    "solvency_breaker_tripped": true,
                    "eventType": "SOLVENCY_BREAKER_TRIPPED",
                    "unpaidMatureSompi": unpaid_mature_sompi.to_string(),
                    "inflightOutboxSompi": inflight_outbox_sompi.to_string(),
                    "confirmedPoolVaultUtxoSompi": confirmed_pool_vault_utxo_sompi.to_string(),
                    "deficitSompi": deficit_sompi.to_string(),
                    "virtualDaaScore": virtual_daa_score,
                    "reason": reason,
                    "timestamp": Utc::now().to_rfc3339()
                });
                let _: redis::RedisResult<()> = redis::cmd("SET")
                    .arg(REDIS_KEY_SOLVENCY_BREAKER)
                    .arg(alert.to_string())
                    .query_async(&mut conn)
                    .await;
                let _: redis::RedisResult<()> = redis::cmd("SET")
                    .arg("perennia:agent:circuit_breaker")
                    .arg("SOLVENCY_BREAKER_TRIPPED")
                    .query_async(&mut conn)
                    .await;
                let _: redis::RedisResult<()> = redis::cmd("PUBLISH")
                    .arg("telemetry:updates")
                    .arg(alert.to_string())
                    .query_async(&mut conn)
                    .await;
            }
        }
    }
}

pub async fn evaluate_pool_solvency_invariant(
    pool: &PgPool,
) -> Result<SolvencyProofSnapshot, String> {
    let sys_cfg = load_system_treasury_config(pool).await;
    let pool_vault_addr = resolve_hot_dispatcher_address()
        .or_else(|| resolve_master_treasury_prefixed().ok())
        .ok_or_else(|| {
            "SOLVENCY_CONFIG_HALT: Pool vault Kaspa address is not configured in .env.".to_string()
        })?;

    let (virtual_daa, confirmed_pool_vault_utxo_sompi, immature_coinbase_utxo_sompi) =
        match query_live_virtual_daa_and_pool_utxos(&pool_vault_addr).await {
            Ok(vals) => vals,
            Err(e) => {
                trip_solvency_circuit_breaker(pool, 0, 0, 0, 1, 0, &e).await;
                return Err(e);
            }
        };

    if let Err(e) = advance_1000_daa_coinbase_maturity(pool, virtual_daa, sys_cfg.pool_fee_bps).await
    {
        tracing::warn!("⚠️ [MATURITY ENGINE] 1,000-DAA maturity check warning: {}", e);
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| format!("Failed to begin SERIALIZABLE solvency read tx: {}", e))?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Failed to set SERIALIZABLE isolation: {}", e))?;

    let unpaid_mature_str: String = sqlx::query_scalar(
        "SELECT COALESCE(SUM(unpaid_mature_sompi), 0)::NUMERIC(39, 0)::TEXT FROM stratum_mature_accruals",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("Failed to sum unpaid_mature_sompi: {}", e))?;

    let inflight_outbox_str: String = sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(payout_sompi + house_fee_sompi + network_fee_sompi), 0)::NUMERIC(39, 0)::TEXT
        FROM epoch_payout_outbox
        WHERE state IN ('CREATED', 'SIGNING', 'BROADCAST')
        "#,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("Failed to sum inflight_outbox_sompi: {}", e))?;

    tx.commit()
        .await
        .map_err(|e| format!("Failed to commit solvency read tx: {}", e))?;

    let unpaid_mature_sompi = unpaid_mature_str.trim().parse::<u128>().unwrap_or(0);
    let inflight_outbox_sompi = inflight_outbox_str.trim().parse::<u128>().unwrap_or(0);
    let required_total_sompi = unpaid_mature_sompi.saturating_add(inflight_outbox_sompi);

    if required_total_sompi > confirmed_pool_vault_utxo_sompi {
        let deficit_sompi = required_total_sompi.saturating_sub(confirmed_pool_vault_utxo_sompi);
        let reason = format!(
            "SOLVENCY_INVARIANT_VIOLATION: unpaid_mature ({}) + inflight_outbox ({}) = {} > confirmed_pool_vault_utxo ({}) [deficit={} sompi]",
            unpaid_mature_sompi,
            inflight_outbox_sompi,
            required_total_sompi,
            confirmed_pool_vault_utxo_sompi,
            deficit_sompi
        );
        trip_solvency_circuit_breaker(
            pool,
            unpaid_mature_sompi,
            inflight_outbox_sompi,
            confirmed_pool_vault_utxo_sompi,
            deficit_sompi,
            virtual_daa,
            &reason,
        )
        .await;
        return Err(reason);
    }

    if sys_cfg.solvency_breaker_tripped {
        let _ = sqlx::query(
            r#"
            UPDATE system_treasury_config
            SET solvency_breaker_tripped = FALSE,
                solvency_deficit_sompi = 0,
                updated_at = CURRENT_TIMESTAMP
            WHERE config_id = 'PRIMARY'
            "#,
        )
        .execute(pool)
        .await;
    }

    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url.trim()) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let _: redis::RedisResult<i64> = redis::cmd("DEL")
                    .arg(REDIS_KEY_SOLVENCY_BREAKER)
                    .query_async(&mut conn)
                    .await;
            }
        }
    }

    let surplus_sompi = confirmed_pool_vault_utxo_sompi.saturating_sub(required_total_sompi);
    Ok(SolvencyProofSnapshot {
        is_solvent: true,
        pool_vault_address: pool_vault_addr,
        virtual_daa_score: virtual_daa,
        unpaid_mature_sompi: U128Str(unpaid_mature_sompi),
        inflight_outbox_sompi: U128Str(inflight_outbox_sompi),
        required_total_sompi: U128Str(required_total_sompi),
        confirmed_pool_vault_utxo_sompi: U128Str(confirmed_pool_vault_utxo_sompi),
        immature_coinbase_utxo_sompi: U128Str(immature_coinbase_utxo_sompi),
        surplus_sompi: U128Str(surplus_sompi),
        deficit_sompi: U128Str(0),
        checked_at: Utc::now().to_rfc3339(),
    })
}

pub async fn load_system_treasury_config(pool: &PgPool) -> SystemTreasuryConfig {
    let default_cold_kas = resolve_master_treasury_prefixed().unwrap_or_default();
    let row_opt = sqlx::query(
        r#"
        SELECT config_id,
               COALESCE(hot_ceiling_sompi, 500000000000) AS hot_ceiling_sompi,
               COALESCE(min_runway_sompi, 25000000000) AS min_runway_sompi,
               COALESCE(fpps_max_float_sompi, 5000000000) AS fpps_max_float_sompi,
               COALESCE(pool_fee_bps, 100) AS pool_fee_bps,
               COALESCE(house_revenue_kas_address, '') AS house_revenue_kas_address,
               outflow_breaker_tripped,
               COALESCE(solvency_breaker_tripped, FALSE) AS solvency_breaker_tripped,
               COALESCE(solvency_deficit_sompi, 0)::NUMERIC(39, 0)::TEXT AS solvency_deficit_sompi,
               cold_kas_address,
               cold_btc_address,
               cold_eth_address,
               cold_sol_address,
               updated_by,
               updated_at
        FROM system_treasury_config
        WHERE config_id = 'PRIMARY'
        LIMIT 1
        "#,
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    if let Some(r) = row_opt {
        let db_cold_kas: String = r.try_get("cold_kas_address").unwrap_or_default();
        let db_house_rev: String = r.try_get("house_revenue_kas_address").unwrap_or_default();
        let resolved_cold_kas = if db_cold_kas.trim().is_empty() {
            default_cold_kas.clone()
        } else {
            db_cold_kas
        };
        let resolved_house_rev = if db_house_rev.trim().is_empty() {
            env::var("PERENNIA_HOUSE_REVENUE_KAS_ADDRESS")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| resolved_cold_kas.clone())
        } else {
            db_house_rev
        };
        let deficit_u128 = r
            .try_get::<String, _>("solvency_deficit_sompi")
            .ok()
            .and_then(|s| s.trim().parse::<u128>().ok())
            .unwrap_or(0);

        return SystemTreasuryConfig {
            config_id: r
                .try_get("config_id")
                .unwrap_or_else(|_| "PRIMARY".to_string()),
            hot_ceiling_sompi: r
                .try_get::<i64, _>("hot_ceiling_sompi")
                .unwrap_or(500_000_000_000)
                .max(0) as u64,
            min_runway_sompi: r
                .try_get::<i64, _>("min_runway_sompi")
                .unwrap_or(25_000_000_000)
                .max(0) as u64,
            fpps_max_float_sompi: r
                .try_get::<i64, _>("fpps_max_float_sompi")
                .unwrap_or(5_000_000_000)
                .max(0) as u64,
            pool_fee_bps: r
                .try_get::<i32, _>("pool_fee_bps")
                .unwrap_or(100)
                .clamp(50, 200) as u16,
            house_revenue_kas_address: resolved_house_rev,
            outflow_breaker_tripped: r.try_get("outflow_breaker_tripped").unwrap_or(false),
            solvency_breaker_tripped: r.try_get("solvency_breaker_tripped").unwrap_or(false),
            solvency_deficit_sompi: U128Str(deficit_u128),
            cold_kas_address: resolved_cold_kas,
            cold_btc_address: r
                .try_get("cold_btc_address")
                .unwrap_or_else(|_| env::var("PERENNIA_COLD_BTC_ADDRESS").unwrap_or_default()),
            cold_eth_address: r
                .try_get("cold_eth_address")
                .unwrap_or_else(|_| env::var("PERENNIA_COLD_ETH_ADDRESS").unwrap_or_default()),
            cold_sol_address: r
                .try_get("cold_sol_address")
                .unwrap_or_else(|_| env::var("PERENNIA_COLD_SOL_ADDRESS").unwrap_or_default()),
            updated_by: r
                .try_get("updated_by")
                .unwrap_or_else(|_| "SYSTEM".to_string()),
            updated_at: r
                .try_get::<chrono::DateTime<Utc>, _>("updated_at")
                .map(|d| d.to_rfc3339())
                .unwrap_or_else(|_| Utc::now().to_rfc3339()),
            hot_ceiling_kas: 0.0,
        };
    }

    let env_house_rev = env::var("PERENNIA_HOUSE_REVENUE_KAS_ADDRESS")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| default_cold_kas.clone());
    SystemTreasuryConfig {
        config_id: "PRIMARY".to_string(),
        hot_ceiling_sompi: 500_000_000_000,
        min_runway_sompi: 25_000_000_000,
        fpps_max_float_sompi: 5_000_000_000,
        pool_fee_bps: 100,
        house_revenue_kas_address: env_house_rev,
        outflow_breaker_tripped: false,
        solvency_breaker_tripped: false,
        solvency_deficit_sompi: U128Str(0),
        cold_kas_address: default_cold_kas,
        cold_btc_address: env::var("PERENNIA_COLD_BTC_ADDRESS").unwrap_or_default(),
        cold_eth_address: env::var("PERENNIA_COLD_ETH_ADDRESS").unwrap_or_default(),
        cold_sol_address: env::var("PERENNIA_COLD_SOL_ADDRESS").unwrap_or_default(),
        updated_by: "DEFAULT".to_string(),
        updated_at: Utc::now().to_rfc3339(),
        hot_ceiling_kas: 0.0,
    }
}

fn parse_u64_json_field(val: Option<&Value>) -> Option<u64> {
    val.and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
    })
}

pub async fn update_system_treasury_config(
    pool: &PgPool,
    payload: &Value,
    updated_by: &str,
) -> Result<SystemTreasuryConfig, String> {
    let current = load_system_treasury_config(pool).await;

    let hot_ceiling_sompi = parse_u64_json_field(payload.get("hotCeilingSompi"))
        .unwrap_or(current.hot_ceiling_sompi)
        .max(5_000_000_000);

    let min_runway_sompi =
        parse_u64_json_field(payload.get("minRunwaySompi")).unwrap_or(current.min_runway_sompi);

    let fpps_max_float_sompi = parse_u64_json_field(payload.get("fppsMaxFloatSompi"))
        .unwrap_or(current.fpps_max_float_sompi)
        .max(100_000_000);

    let pool_fee_bps = parse_u64_json_field(payload.get("poolFeeBps"))
        .map(|v| v.clamp(50, 200) as u16)
        .unwrap_or(current.pool_fee_bps);

    let outflow_breaker_tripped = payload
        .get("outflowBreakerTripped")
        .or_else(|| payload.get("lowRunwayBreakerTripped"))
        .and_then(|v| v.as_bool())
        .unwrap_or(current.outflow_breaker_tripped);

    let house_revenue_kas_address = payload
        .get("houseRevenueKasAddress")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or(current.house_revenue_kas_address);

    let cold_kas_address = payload
        .get("coldKasAddress")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or(current.cold_kas_address);

    let cold_btc_address = payload
        .get("coldBtcAddress")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or(current.cold_btc_address);

    let cold_eth_address = payload
        .get("coldEthAddress")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or(current.cold_eth_address);

    let cold_sol_address = payload
        .get("coldSolAddress")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or(current.cold_sol_address);

    sqlx::query(
        r#"
        INSERT INTO system_treasury_config (
            config_id, hot_ceiling_sompi, min_runway_sompi, fpps_max_float_sompi,
            pool_fee_bps, house_revenue_kas_address, outflow_breaker_tripped,
            cold_kas_address, cold_btc_address, cold_eth_address, cold_sol_address,
            updated_by, updated_at
        ) VALUES ('PRIMARY', $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, CURRENT_TIMESTAMP)
        ON CONFLICT (config_id) DO UPDATE SET
            hot_ceiling_sompi = EXCLUDED.hot_ceiling_sompi,
            min_runway_sompi = EXCLUDED.min_runway_sompi,
            fpps_max_float_sompi = EXCLUDED.fpps_max_float_sompi,
            pool_fee_bps = EXCLUDED.pool_fee_bps,
            house_revenue_kas_address = EXCLUDED.house_revenue_kas_address,
            outflow_breaker_tripped = EXCLUDED.outflow_breaker_tripped,
            cold_kas_address = EXCLUDED.cold_kas_address,
            cold_btc_address = EXCLUDED.cold_btc_address,
            cold_eth_address = EXCLUDED.cold_eth_address,
            cold_sol_address = EXCLUDED.cold_sol_address,
            updated_by = EXCLUDED.updated_by,
            updated_at = CURRENT_TIMESTAMP
        "#,
    )
    .bind(hot_ceiling_sompi as i64)
    .bind(min_runway_sompi as i64)
    .bind(fpps_max_float_sompi as i64)
    .bind(pool_fee_bps as i32)
    .bind(&house_revenue_kas_address)
    .bind(outflow_breaker_tripped)
    .bind(&cold_kas_address)
    .bind(&cold_btc_address)
    .bind(&cold_eth_address)
    .bind(&cold_sol_address)
    .bind(updated_by)
    .execute(pool)
    .await
    .map_err(|e| format!("Failed to update system_treasury_config: {}", e))?;

    let updated = load_system_treasury_config(pool).await;

    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                if let Ok(serialized) = serde_json::to_string(&updated) {
                    let _: redis::RedisResult<()> = redis::cmd("SET")
                        .arg("perennia:treasury:system_config")
                        .arg(serialized)
                        .query_async(&mut conn)
                        .await;
                }
            }
        }
    }

    Ok(updated)
}

pub fn compute_jerusalem_epoch_window(now_secs: u64) -> (u64, u64, u64) {
    let day_secs: u64 = 86_400;
    let bell_offset_secs: u64 = 22 * 3_600;
    let current_day_start = (now_secs / day_secs) * day_secs;
    let today_bell = current_day_start + bell_offset_secs;
    let (epoch_start_ts, next_bell_ts) = if now_secs < today_bell {
        (today_bell.saturating_sub(day_secs), today_bell)
    } else {
        (today_bell, today_bell + day_secs)
    };
    let secs_until_bell = next_bell_ts.saturating_sub(now_secs);
    (epoch_start_ts, next_bell_ts, secs_until_bell)
}

async fn execute_2200_utc_settlement_with_anti_sandwich(
    pool: &PgPool,
    immediate_admin_force: bool,
) -> anyhow::Result<Value> {
    let snapshot_ts_utc = Utc::now().to_rfc3339();
    tracing::info!(
        "🔔 [22:00 UTC BELL] Exact Accounting Snapshot Frozen ({}) | Crossing Internal Dark Pool First...",
        snapshot_ts_utc
    );

    let redis_url =
        env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let redis_client = redis::Client::open(redis_url)?;

    if let Ok(mut snap_conn) = redis_client.get_multiplexed_async_connection().await {
        let _: redis::RedisResult<()> = redis::cmd("SET")
            .arg("perennia:chronos:last_snapshot_utc")
            .arg(&snapshot_ts_utc)
            .query_async(&mut snap_conn)
            .await;
    }

    // Step 1: Cross internal Dark Pool liquidity first before touching external swaps
    let pre_bell_dp_cross = run_delta_netting_cycle(&redis_client, pool)
        .await
        .unwrap_or_else(|_| json!({ "ordersPopped": 0 }));

    // Step 2: Settle 22:00:00 UTC miner buckets, LP compounding & Forge daily tranches
    let netting_res = execute_epoch_delta_netting_and_lp_compounding(pool).await?;
    let forge_res = execute_2200_utc_forge_bell_settlement(pool).await?;

    // Step 3: Cross any newly generated offsetting Dark Pool delta internally
    let post_bell_dp_cross = run_delta_netting_cycle(&redis_client, pool)
        .await
        .unwrap_or_else(|_| json!({ "ordersPopped": 0 }));

    if immediate_admin_force {
        return Ok(json!({
            "snapshotTimestampUtc": snapshot_ts_utc,
            "antiSandwichMode": "IMMEDIATE_DIRECTOR_OVERRIDE",
            "preBellDarkPoolCross": pre_bell_dp_cross,
            "postBellDarkPoolCross": post_bell_dp_cross,
            "netting": netting_res,
            "forge": forge_res,
            "bellTimestampUtc": Utc::now().to_rfc3339()
        }));
    }

    // Step 4: Anti-Sandwich Multi-Minute Slicer for Residual External Execution
    // Pop NET_RESIDUAL_AUTOBALANCE tickets so external bots cannot sandwich a predictable 22:00:01 UTC swap,
    // then slice and jitter execution across randomized 20s..=65s intervals with fresh Redis oracle checks.
    let Ok(mut conn) = redis_client.get_multiplexed_async_connection().await else {
        return Ok(json!({
            "snapshotTimestampUtc": snapshot_ts_utc,
            "antiSandwichMode": "REDIS_UNAVAILABLE_INTERNAL_ONLY",
            "netting": netting_res,
            "forge": forge_res,
            "bellTimestampUtc": Utc::now().to_rfc3339()
        }));
    };

    let raw_passthrough: Vec<String> = redis::cmd("LRANGE")
        .arg("perennia:sor:third_party_passthrough_queue")
        .arg(0)
        .arg(199)
        .query_async(&mut conn)
        .await
        .unwrap_or_default();

    let mut bell_residuals: Vec<Value> = Vec::new();
    let mut non_bell_items: Vec<String> = Vec::new();

    for item_str in raw_passthrough {
        if let Ok(parsed) = serde_json::from_str::<Value>(&item_str) {
            let is_residual = parsed
                .get("type")
                .and_then(|v| v.as_str())
                .map(|t| t == "NET_RESIDUAL_AUTOBALANCE")
                .unwrap_or(false);
            if is_residual {
                bell_residuals.push(parsed);
            } else {
                non_bell_items.push(item_str);
            }
        }
    }

    let residual_count = bell_residuals.len();
    if residual_count > 0 {
        let _: redis::RedisResult<()> = redis::cmd("DEL")
            .arg("perennia:sor:third_party_passthrough_queue")
            .query_async(&mut conn)
            .await;
        for keep in non_bell_items.into_iter().rev() {
            let _: redis::RedisResult<()> = redis::cmd("LPUSH")
                .arg("perennia:sor:third_party_passthrough_queue")
                .arg(keep)
                .query_async(&mut conn)
                .await;
        }

        let num_slices: usize = {
            rand::rngs::OsRng.gen_range(4usize..=8usize)
        };
        let r_client_bg = redis_client.clone();

        tokio::spawn(async move {
            for (group_idx, ticket) in bell_residuals.into_iter().enumerate() {
                let slice_count = num_slices.max(2);
                let total_res_usd = ticket
                    .get("residual_usd")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let total_kas_eq = ticket
                    .get("kas_equiv")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let slice_ratio = 1.0 / (slice_count as f64);

                for slice_idx in 0..slice_count {
                    let sleep_ms: u64 = {
                        rand::rngs::OsRng.gen_range(20_000u64..=65_000u64)
                    };
                    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;

                    let Ok(mut slice_conn) =
                        r_client_bg.get_multiplexed_async_connection().await
                    else {
                        tracing::error!(
                            "❌ [CHRONOS ANTI-SANDWICH] Redis unreachable during jittered slice; failing closed."
                        );
                        break;
                    };

                    let target_asset = ticket
                        .get("target_asset")
                        .and_then(|v| v.as_str())
                        .unwrap_or("USDC")
                        .trim()
                        .to_uppercase();

                    let (cb_flag, ext_kill, depeg_flag, spot_raw, kas_raw): (
                        Option<String>,
                        Option<String>,
                        Option<String>,
                        Option<String>,
                        Option<String>,
                    ) = redis::pipe()
                        .cmd("GET")
                        .arg("perennia:agent:circuit_breaker")
                        .cmd("GET")
                        .arg("perennia:killswitch:external_dex")
                        .cmd("GET")
                        .arg(format!("oracle:depeg_halt:{}", target_asset))
                        .cmd("GET")
                        .arg(format!("oracle:spot:{}_USDC", target_asset))
                        .cmd("GET")
                        .arg("oracle:spot:KAS_USDC")
                        .query_async(&mut slice_conn)
                        .await
                        .unwrap_or((None, None, None, None, None));

                    let cb_tripped = cb_flag
                        .as_deref()
                        .map(|s| !s.trim().is_empty() && s.trim() != "0" && !s.trim().eq_ignore_ascii_case("false"))
                        .unwrap_or(false);
                    let ext_paused = ext_kill
                        .as_deref()
                        .map(|s| s.trim() == "1" || s.trim().eq_ignore_ascii_case("true"))
                        .unwrap_or(false);
                    let depeg_halted = depeg_flag
                        .as_deref()
                        .map(|s| s.trim() == "1" || s.trim().eq_ignore_ascii_case("true"))
                        .unwrap_or(false);
                    let kas_live = kas_raw
                        .as_deref()
                        .and_then(|s| s.parse::<f64>().ok())
                        .map(|v| v.is_finite() && v > 0.0)
                        .unwrap_or(false);
                    let target_live = target_asset == "USD"
                        || spot_raw
                            .as_deref()
                            .and_then(|s| s.parse::<f64>().ok())
                            .map(|v| v.is_finite() && v > 0.0)
                            .unwrap_or(false);

                    if cb_tripped || ext_paused || depeg_halted || !kas_live || !target_live {
                        tracing::warn!(
                            "⚠️ [CHRONOS ANTI-SANDWICH] Failing closed on residual slice {}/{} for {} (cb={}, ext_paused={}, depeg={}, kas_live={}, target_live={}).",
                            slice_idx + 1,
                            slice_count,
                            target_asset,
                            cb_tripped,
                            ext_paused,
                            depeg_halted,
                            kas_live,
                            target_live
                        );
                        continue;
                    }

                    let mut sliced_ticket = ticket.clone();
                    if let Some(obj) = sliced_ticket.as_object_mut() {
                        obj.insert(
                            "slice_index".to_string(),
                            json!(format!("{}/{}", slice_idx + 1, slice_count)),
                        );
                        obj.insert(
                            "residual_usd".to_string(),
                            json!(((total_res_usd * slice_ratio) * 10_000.0).round() / 10_000.0),
                        );
                        obj.insert(
                            "kas_equiv".to_string(),
                            json!(((total_kas_eq * slice_ratio) * 10_000.0).round() / 10_000.0),
                        );
                        obj.insert(
                            "anti_sandwich_dispatched_at".to_string(),
                            json!(Utc::now().to_rfc3339()),
                        );
                        obj.insert("residual_group_idx".to_string(), json!(group_idx));
                    }

                    let _: redis::RedisResult<()> = redis::cmd("LPUSH")
                        .arg("perennia:sor:third_party_passthrough_queue")
                        .arg(sliced_ticket.to_string())
                        .query_async(&mut slice_conn)
                        .await;
                    let _: redis::RedisResult<()> = redis::cmd("LTRIM")
                        .arg("perennia:sor:third_party_passthrough_queue")
                        .arg(0)
                        .arg(199)
                        .query_async(&mut slice_conn)
                        .await;
                }
            }
        });

        return Ok(json!({
            "snapshotTimestampUtc": snapshot_ts_utc,
            "antiSandwichMode": "JITTERED_MULTI_MINUTE_SLICER",
            "residualTicketsSliced": residual_count,
            "slicesPerTicket": num_slices,
            "preBellDarkPoolCross": pre_bell_dp_cross,
            "postBellDarkPoolCross": post_bell_dp_cross,
            "netting": netting_res,
            "forge": forge_res,
            "bellTimestampUtc": Utc::now().to_rfc3339()
        }));
    }

    Ok(json!({
        "snapshotTimestampUtc": snapshot_ts_utc,
        "antiSandwichMode": "100_PCT_INTERNAL_DARK_POOL_CROSSED",
        "residualTicketsSliced": 0,
        "preBellDarkPoolCross": pre_bell_dp_cross,
        "postBellDarkPoolCross": post_bell_dp_cross,
        "netting": netting_res,
        "forge": forge_res,
        "bellTimestampUtc": Utc::now().to_rfc3339()
    }))
}

pub async fn execute_full_2200_utc_settlement_bell(pool: &PgPool) -> anyhow::Result<Value> {
    execute_2200_utc_settlement_with_anti_sandwich(pool, false).await
}

pub async fn trigger_immediate_epoch_bell_sweep(pool: &PgPool) -> Result<Value, String> {
    execute_2200_utc_settlement_with_anti_sandwich(pool, true)
        .await
        .map_err(|e| format!("Epoch bell sweep failed: {}", e))
}

pub async fn start_chronos_daemon(pool: PgPool) {
    tracing::info!(
        "🕰️ [CHRONOS ENGINE] Exact 22:00:00 UTC Snapshot + 30s Solvency Circuit Breaker Armed."
    );
    let solvency_pool = pool.clone();
    tokio::spawn(async move {
        let mut solvency_interval =
            tokio::time::interval(Duration::from_secs(SOLVENCY_CHECK_INTERVAL_SECS));
        loop {
            solvency_interval.tick().await;
            if let Err(e) = evaluate_pool_solvency_invariant(&solvency_pool).await {
                tracing::error!("🚨 [30s SOLVENCY CIRCUIT BREAKER] Halted: {}", e);
            }
        }
    });

    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let mut last_bell_day: Option<u32> = None;
    loop {
        interval.tick().await;
        let now = Utc::now();
        let ordinal_day = now.format("%j").to_string().parse::<u32>().unwrap_or(0);
        if now.hour() == 22
            && now.minute() == 0
            && now.second() <= 5
            && last_bell_day != Some(ordinal_day)
        {
            last_bell_day = Some(ordinal_day);
            if let Err(e) = execute_full_2200_utc_settlement_bell(&pool).await {
                tracing::error!("❌ [22:00 UTC BELL] Execution error: {}", e);
            }
        }
    }
}