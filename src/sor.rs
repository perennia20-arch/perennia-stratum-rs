#[path = "hifo.rs"]
pub mod hifo;
#[path = "kaspa_tx.rs"]
pub mod kaspa_tx;

pub use hifo::*;
pub use kaspa_tx::*;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::env;
use uuid::Uuid;

pub trait PayoutBatchEntry {
    fn recipient_address(&self) -> String;
    fn amount_sompi(&self) -> u64;
}

impl PayoutBatchEntry for (String, u64) {
    fn recipient_address(&self) -> String {
        self.0.clone()
    }
    fn amount_sompi(&self) -> u64 {
        self.1
    }
}

impl PayoutBatchEntry for (String, f64) {
    fn recipient_address(&self) -> String {
        self.0.clone()
    }
    fn amount_sompi(&self) -> u64 {
        (self.1.max(0.0) * 100_000_000.0).round() as u64
    }
}

impl PayoutBatchEntry for Value {
    fn recipient_address(&self) -> String {
        self.get("address")
            .or_else(|| self.get("wallet"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }
    fn amount_sompi(&self) -> u64 {
        if let Some(s) = self.get("sompi").and_then(|v| v.as_u64()) {
            return s;
        }
        let kas = self
            .get("amountKas")
            .or_else(|| self.get("amount"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        (kas.max(0.0) * 100_000_000.0).round() as u64
    }
}

pub async fn execute_idempotent_mass_physical_settlement<T: PayoutBatchEntry>(
    pool: &PgPool,
    idempotency_key: &str,
    payouts: &[T],
) -> Result<String, String> {
    let mut recipients: Vec<(String, u64)> = Vec::with_capacity(payouts.len());
    for item in payouts {
        let addr = item.recipient_address().trim().to_string();
        let sompi = item.amount_sompi();
        if !addr.is_empty() && sompi > 0 {
            recipients.push((addr, sompi));
        }
    }
    if recipients.is_empty() {
        return Err("No valid recipients in payout batch.".to_string());
    }
    crate::state_api::sign_and_broadcast_kaspa_payout_batch(pool, idempotency_key, &recipients, "")
        .await
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SorExecuteRequest {
    pub wallet: String,
    pub pay_asset: String,
    pub receive_asset: String,
    pub amount: f64,
    #[serde(default)]
    pub slippage_tolerance: Option<f64>,
    #[serde(default)]
    pub utxos: Option<Vec<Value>>,
    #[serde(default)]
    pub system_mode: Option<String>,
}

async fn resolve_user_fee_rate(
    pool: &PgPool,
    prefixed_wallet: &str,
    clean_wallet: &str,
    usd_volume: f64,
) -> f64 {
    let staked_silo: f64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(amount_staked), 0.0)
        FROM silo_staking_positions
        WHERE (wallet_address = $1 OR wallet_address = $2)
          AND status IN ('ACTIVE', 'COOLDOWN')
        "#,
    )
    .bind(prefixed_wallet)
    .bind(clean_wallet)
    .fetch_one(pool)
    .await
    .unwrap_or(0.0);

    let mut fee_rate: f64 = if usd_volume >= 2000.0 { 0.005 } else { 0.015 };
    if staked_silo >= 1_000_000.0 {
        fee_rate = fee_rate.min(0.0025_f64);
    } else if staked_silo >= 100_000.0 {
        fee_rate = fee_rate.min(0.005_f64);
    } else if staked_silo >= 10_000.0 {
        fee_rate = fee_rate.min(0.0075_f64);
    }
    fee_rate
}

pub async fn handle_sor_execute(
    State(pool): State<PgPool>,
    Json(req): Json<SorExecuteRequest>,
) -> impl IntoResponse {
    let clean_wallet = req
        .wallet
        .trim()
        .to_lowercase()
        .replace("kaspa:", "")
        .trim()
        .to_string();
    let prefixed_wallet = format!("kaspa:{}", clean_wallet);
    let pay_asset = req.pay_asset.trim().to_uppercase();
    let receive_asset = req.receive_asset.trim().to_uppercase();
    let amount = req.amount;

    if clean_wallet.is_empty() || amount <= 0.0 || pay_asset == receive_asset {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Invalid swap parameters: amount must be > 0 and assets must differ."
            })),
        );
    }

    let pay_spot = match crate::state_api::resolve_strict_spot_price(&pool, &pay_asset).await {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": e })),
            );
        }
    };

    let receive_spot =
        match crate::state_api::resolve_strict_spot_price(&pool, &receive_asset).await {
            Ok(p) => p,
            Err(e) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": e })),
                );
            }
        };

    let gross_usd = amount * pay_spot;
    let fee_rate = resolve_user_fee_rate(&pool, &prefixed_wallet, &clean_wallet, gross_usd).await;
    let fee_usd = gross_usd * fee_rate;
    let net_usd = (gross_usd - fee_usd).max(0.0);
    let estimated_output = if receive_spot > 0.0 {
        net_usd / receive_spot
    } else {
        0.0
    };
    let unified_rate = if pay_spot > 0.0 && receive_spot > 0.0 {
        (pay_spot / receive_spot) * (1.0 - fee_rate)
    } else {
        0.0
    };

    let tx_uuid = format!(
        "PER-SOR-{}",
        Uuid::new_v4()
            .to_string()
            .replace('-', "")
            .chars()
            .take(12)
            .collect::<String>()
            .to_uppercase()
    );

    if let Err(ledger_debit_err) = crate::state_api::debit_user_token_balance(
        &pool,
        &clean_wallet,
        &prefixed_wallet,
        &pay_asset,
        amount,
    )
    .await
    {
        if pay_asset == "KAS" {
            if let Some(ref utxo_list) = req.utxos {
                if !utxo_list.is_empty() {
                    let sys_cfg = crate::chronos::load_system_treasury_config(&pool).await;
                    let treasury_dest = crate::chronos::resolve_hot_dispatcher_address()
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or(sys_cfg.cold_kas_address);

                    if !treasury_dest.trim().is_empty() {
                        let amount_sompi = (amount * 100_000_000.0).round() as u64;
                        if let Some((psbt, formatted_utxos)) = assemble_unsigned_kaspa_psbt(
                            &prefixed_wallet,
                            &treasury_dest,
                            amount_sompi,
                            utxo_list,
                        ) {
                            if let Ok(redis_url) = env::var("REDIS_URL") {
                                if let Ok(client) = redis::Client::open(redis_url) {
                                    if let Ok(mut conn) =
                                        client.get_multiplexed_async_connection().await
                                    {
                                        let pending_order = json!({
                                            "wallet": prefixed_wallet,
                                            "direction": "SELL_KAS",
                                            "amount_kas": amount,
                                            "spot_price": pay_spot,
                                            "fee_captured_usd": fee_usd,
                                            "target_asset": receive_asset,
                                            "estimated_output": estimated_output,
                                            "transaction_uuid": tx_uuid
                                        });
                                        let _: redis::RedisResult<()> = redis::cmd("SETEX")
                                            .arg(format!("perennia:pending_swap:{}", clean_wallet))
                                            .arg(900u64)
                                            .arg(pending_order.to_string())
                                            .query_async(&mut conn)
                                            .await;
                                    }
                                }
                            }

                            return (
                                StatusCode::OK,
                                Json(json!({
                                    "success": true,
                                    "transaction_uuid": tx_uuid,
                                    "unifiedRate": unified_rate,
                                    "unified_rate": unified_rate,
                                    "estimatedOutput": estimated_output,
                                    "estimated_output": estimated_output,
                                    "feeRate": fee_rate,
                                    "fee_rate": fee_rate,
                                    "feeUsd": fee_usd,
                                    "fee_usd": fee_usd,
                                    "legs": [
                                        {
                                            "tier": 1,
                                            "provider": "Perennia L1 Atomic Settlement Router",
                                            "filledAmount": amount,
                                            "executionRate": unified_rate,
                                            "marginCaptured": fee_usd
                                        }
                                    ],
                                    "psbt": psbt,
                                    "formattedUtxos": formatted_utxos
                                })),
                            );
                        }
                    }
                }
            }
        }

        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": ledger_debit_err
            })),
        );
    }

    if let Err(credit_err) = crate::state_api::credit_user_token_balance(
        &pool,
        &clean_wallet,
        &prefixed_wallet,
        &receive_asset,
        estimated_output,
        false,
    )
    .await
    {
        let _ = crate::state_api::credit_user_token_balance(
            &pool,
            &clean_wallet,
            &prefixed_wallet,
            &pay_asset,
            amount,
            false,
        )
        .await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": format!("Failed to credit {} output after debit: {}", receive_asset, credit_err)
            })),
        );
    }

    let hifo_summary = match_and_consume_hifo_lots(
        &pool,
        &clean_wallet,
        &pay_asset,
        amount,
        pay_spot,
        Some(&tx_uuid),
    )
    .await
    .ok();

    let _ = record_hifo_acquisition_lot(
        &pool,
        &clean_wallet,
        &receive_asset,
        estimated_output,
        receive_spot,
        "DEX_SWAP",
        Some(&tx_uuid),
    )
    .await;

    let cost_basis_usd = hifo_summary
        .as_ref()
        .map(|s| s.matched_cost_basis_usd)
        .unwrap_or(gross_usd);
    let realized_gain_usd = hifo_summary
        .as_ref()
        .map(|s| s.realized_gain_loss_usd)
        .unwrap_or(0.0);
    let holding_period = hifo_summary
        .as_ref()
        .map(|s| s.holding_period.as_str())
        .unwrap_or("SHORT_TERM");

    let _ = sqlx::query(
        r#"
        INSERT INTO tax_ledger_events (
            wallet_address, asset_ticker, event_type, gross_proceeds_usd,
            amount_tokens, spot_price_at_execution, tx_hash,
            cost_basis_usd, realized_gain_loss_usd, holding_period
        ) VALUES ($1, $2, 'DEX_SWAP', $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(&clean_wallet)
    .bind(&pay_asset)
    .bind(gross_usd)
    .bind(amount)
    .bind(pay_spot)
    .bind(&tx_uuid)
    .bind(cost_basis_usd)
    .bind(realized_gain_usd)
    .bind(holding_period)
    .execute(&pool)
    .await;

    let _ = sqlx::query(
        r#"
        INSERT INTO yield_distributions (pool_pair, total_fees_distributed_usd)
        VALUES ($1, $2)
        "#,
    )
    .bind(format!("{}/{}", pay_asset, receive_asset))
    .bind(fee_usd * 0.80)
    .execute(&pool)
    .await;

    let _ = (&req.slippage_tolerance, &req.system_mode);

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "transaction_uuid": tx_uuid,
            "unifiedRate": unified_rate,
            "unified_rate": unified_rate,
            "estimatedOutput": estimated_output,
            "estimated_output": estimated_output,
            "feeRate": fee_rate,
            "fee_rate": fee_rate,
            "feeUsd": fee_usd,
            "fee_usd": fee_usd,
            "legs": [
                {
                    "tier": 1,
                    "provider": "Perennia 50%-KAS Liquidity Pool",
                    "filledAmount": amount,
                    "executionRate": unified_rate,
                    "marginCaptured": fee_usd
                }
            ],
            "psbt": Value::Null,
            "formattedUtxos": []
        })),
    )
}