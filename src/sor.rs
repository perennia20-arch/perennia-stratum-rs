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
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::collections::HashSet;
use std::env;
use uuid::Uuid;

const DEFAULT_RESERVE_WHITELIST: &[&str] = &["KAS", "BTC", "ETH", "SOL", "USDC", "USDT", "SILO"];
const LP_BASE_HURDLE_MIN_APR_PCT: f64 = 14.2;
const LP_BASE_HURDLE_TARGET_APR_PCT: f64 = 14.6;
const COMPETITOR_STANDARD_AMM_APR_PCT: f64 = 9.1;

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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SteeringFeeLeg {
    pub asset: String,
    pub share_ratio: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenSteeringDecision {
    pub allowed: bool,
    pub reject_reason: Option<String>,
    pub pay_state: String,
    pub receive_state: String,
    pub allow_dark_pool_internal_clearing: bool,
    pub fee_legs: Vec<SteeringFeeLeg>,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DynamicHurdleWaterfall {
    pub hard_floor_perennia_usd: f64,
    pub lp_allocated_fee_usd: f64,
    pub perennia_total_cut_usd: f64,
    pub perennia_lp_compound_60_usd: f64,
    pub perennia_liquid_reserve_40_usd: f64,
    pub projected_base_lp_apr_pct: f64,
    pub projected_max_multiplier_apr_pct: f64,
    pub competitor_amm_apr_pct: f64,
    pub surplus_volume_sweep_active: bool,
}

async fn resolve_token_steering_and_firewall(
    pool: &PgPool,
    clean_wallet: &str,
    prefixed_wallet: &str,
    pay_asset: &str,
    receive_asset: &str,
) -> Result<(TokenSteeringDecision, bool, bool), (StatusCode, Json<Value>)> {
    let p_tick = pay_asset.trim().to_uppercase();
    let r_tick = receive_asset.trim().to_uppercase();
    let mut dark_pool_paused = false;
    let mut external_dex_paused = false;

    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let dp_flag: Option<String> = redis::cmd("GET")
                    .arg("perennia:killswitch:dark_pool")
                    .query_async(&mut conn)
                    .await
                    .ok()
                    .flatten();
                if let Some(f) = dp_flag {
                    if f.trim() == "1" || f.trim().eq_ignore_ascii_case("true") {
                        dark_pool_paused = true;
                    }
                }
                let ext_flag: Option<String> = redis::cmd("GET")
                    .arg("perennia:killswitch:external_dex")
                    .query_async(&mut conn)
                    .await
                    .ok()
                    .flatten();
                if let Some(f) = ext_flag {
                    if f.trim() == "1" || f.trim().eq_ignore_ascii_case("true") {
                        external_dex_paused = true;
                    }
                }

                let blk_w1: i32 = redis::cmd("SISMEMBER")
                    .arg("perennia:firewall:blacklisted_wallets")
                    .arg(clean_wallet)
                    .query_async(&mut conn)
                    .await
                    .unwrap_or(0);
                let blk_w2: i32 = redis::cmd("SISMEMBER")
                    .arg("perennia:firewall:blacklisted_wallets")
                    .arg(prefixed_wallet)
                    .query_async(&mut conn)
                    .await
                    .unwrap_or(0);
                if blk_w1 == 1 || blk_w2 == 1 {
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": "FIREWALL_BLACKLISTED_WALLET: Wallet address is blocked by the Perennia Security Firewall."
                        })),
                    ));
                }

                let blk_p: i32 = redis::cmd("SISMEMBER")
                    .arg("perennia:firewall:blacklisted_tokens")
                    .arg(&p_tick)
                    .query_async(&mut conn)
                    .await
                    .unwrap_or(0);
                let blk_r: i32 = redis::cmd("SISMEMBER")
                    .arg("perennia:firewall:blacklisted_tokens")
                    .arg(&r_tick)
                    .query_async(&mut conn)
                    .await
                    .unwrap_or(0);
                if blk_p == 1 || blk_r == 1 {
                    let bad = if blk_p == 1 { &p_tick } else { &r_tick };
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": format!("FIREWALL_BLACKLISTED_TOKEN: {} is flagged as a blacklisted contract and rejected at the API edge.", bad)
                        })),
                    ));
                }
            }
        }
    }

    let whitelist_set: HashSet<String> = DEFAULT_RESERVE_WHITELIST
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    let rows = sqlx::query(
        r#"
        SELECT ticker, steering_state, is_whitelisted, target_weight_pct, actual_weight_pct
        FROM token_steering_matrix
        WHERE ticker = $1 OR ticker = $2
        "#,
    )
    .bind(&p_tick)
    .bind(&r_tick)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut pay_state = if whitelist_set.contains(&p_tick) {
        "AUTO_BALANCE".to_string()
    } else {
        "PASS_THROUGH".to_string()
    };
    let mut receive_state = if whitelist_set.contains(&r_tick) {
        "AUTO_BALANCE".to_string()
    } else {
        "PASS_THROUGH".to_string()
    };
    let mut pay_whitelisted = whitelist_set.contains(&p_tick);
    let mut receive_whitelisted = whitelist_set.contains(&r_tick);
    let mut p_deficit = 0.0_f64;
    let mut r_deficit = 0.0_f64;

    for row in rows {
        let tick: String = row
            .try_get::<String, _>("ticker")
            .unwrap_or_default()
            .trim()
            .to_uppercase();
        let st: String = row
            .try_get::<String, _>("steering_state")
            .unwrap_or_else(|_| "AUTO_BALANCE".to_string())
            .trim()
            .to_uppercase();
        let wl: bool = row.try_get("is_whitelisted").unwrap_or(false);
        let target_w: f64 = row.try_get("target_weight_pct").unwrap_or(10.0);
        let actual_w: f64 = row.try_get("actual_weight_pct").unwrap_or(10.0);
        if tick == p_tick {
            pay_state = st.clone();
            pay_whitelisted = wl && st != "PASS_THROUGH" && st != "BLACKLISTED";
            p_deficit = target_w - actual_w;
        } else if tick == r_tick {
            receive_state = st.clone();
            receive_whitelisted = wl && st != "PASS_THROUGH" && st != "BLACKLISTED";
            r_deficit = target_w - actual_w;
        }
    }

    if pay_state == "BLACKLISTED" || receive_state == "BLACKLISTED" {
        let bad = if pay_state == "BLACKLISTED" {
            &p_tick
        } else {
            &r_tick
        };
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": format!("FIREWALL_BLACKLISTED_TOKEN: {} is blacklisted by the Token Steering Matrix.", bad)
            })),
        ));
    }

    let allow_dark_pool = pay_state != "PASS_THROUGH" && receive_state != "PASS_THROUGH";
    if !allow_dark_pool && external_dex_paused {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "SUBSYSTEM_PAUSED: External DEX pass-through routing is currently paused by Director kill-switch."
            })),
        ));
    }
    if allow_dark_pool && dark_pool_paused && external_dex_paused {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "SUBSYSTEM_PAUSED: Both Dark Pool Internal Clearing and External DEX Routing are paused by Director kill-switches."
            })),
        ));
    }

    let (fee_legs, explanation) = if pay_state == "ACCUMULATE" && pay_whitelisted {
        (
            vec![SteeringFeeLeg {
                asset: p_tick.clone(),
                share_ratio: 1.0,
            }],
            format!("ACCUMULATE override: 100% fee skimmed in {}", p_tick),
        )
    } else if receive_state == "ACCUMULATE" && receive_whitelisted {
        (
            vec![SteeringFeeLeg {
                asset: r_tick.clone(),
                share_ratio: 1.0,
            }],
            format!("ACCUMULATE override: 100% fee skimmed in {}", r_tick),
        )
    } else {
        let p_elig = pay_whitelisted && pay_state != "FREEZE";
        let r_elig = receive_whitelisted && receive_state != "FREEZE";
        if p_elig && r_elig {
            if (p_deficit - r_deficit).abs() <= 0.5 {
                (
                    vec![
                        SteeringFeeLeg {
                            asset: p_tick.clone(),
                            share_ratio: 0.5,
                        },
                        SteeringFeeLeg {
                            asset: r_tick.clone(),
                            share_ratio: 0.5,
                        },
                    ],
                    format!(
                        "AUTO_BALANCE (Balanced Master Buckets): 50/50 fee split in {} & {}",
                        p_tick, r_tick
                    ),
                )
            } else {
                let under = if p_deficit > r_deficit {
                    &p_tick
                } else {
                    &r_tick
                };
                (
                    vec![SteeringFeeLeg {
                        asset: under.clone(),
                        share_ratio: 1.0,
                    }],
                    format!(
                        "AUTO_BALANCE (Underweight Bucket): 100% fee skimmed in {}",
                        under
                    ),
                )
            }
        } else if p_elig {
            (
                vec![SteeringFeeLeg {
                    asset: p_tick.clone(),
                    share_ratio: 1.0,
                }],
                format!(
                    "Reserve Whitelist Firewall: 100% fee skimmed in verified {}",
                    p_tick
                ),
            )
        } else if r_elig {
            (
                vec![SteeringFeeLeg {
                    asset: r_tick.clone(),
                    share_ratio: 1.0,
                }],
                format!(
                    "Reserve Whitelist Firewall: 100% fee skimmed in verified {}",
                    r_tick
                ),
            )
        } else {
            let hop_asset = if p_tick == "KAS" || r_tick == "KAS" {
                "KAS".to_string()
            } else {
                "USDC".to_string()
            };
            (
                vec![SteeringFeeLeg {
                    asset: hop_asset.clone(),
                    share_ratio: 1.0,
                }],
                format!(
                    "PASS_THROUGH / Anti-Poisoning Hop: 100% fee skimmed in {}",
                    hop_asset
                ),
            )
        }
    };

    Ok((
        TokenSteeringDecision {
            allowed: true,
            reject_reason: None,
            pay_state,
            receive_state,
            allow_dark_pool_internal_clearing: allow_dark_pool,
            fee_legs,
            explanation,
        },
        dark_pool_paused,
        external_dex_paused,
    ))
}

async fn compute_dynamic_hurdle_waterfall(
    pool: &PgPool,
    pool_pair: &str,
    gross_usd: f64,
    total_protocol_fee_usd: f64,
    kas_spot_usd: f64,
) -> DynamicHurdleWaterfall {
    let safe_gross = gross_usd.max(0.0);
    let total_fee = total_protocol_fee_usd.max(0.0);

    // Step 1: Lock Perennia's 0.10% hard cost-plus protocol floor above gas first
    let hard_floor_perennia_usd = total_fee.min((safe_gross * crate::fiat_rails::HARD_PROFIT_FLOOR_PCT).max(0.01));
    let remaining_distributable_usd = (total_fee - hard_floor_perennia_usd).max(0.0);

    let staked_kas: f64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(staked_asset_a), 0.0)
        FROM liquidity_providers
        WHERE pool_pair = $1
        "#,
    )
    .bind(pool_pair)
    .fetch_one(pool)
    .await
    .unwrap_or(0.0);

    let rolling_24h_lp_fees_usd: f64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(total_fees_distributed_usd), 0.0)
        FROM yield_distributions
        WHERE pool_pair = $1
          AND distributed_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
        "#,
    )
    .bind(pool_pair)
    .fetch_one(pool)
    .await
    .unwrap_or(0.0);

    let pair_tvl_usd = if staked_kas > 0.0 && kas_spot_usd > 0.0 {
        (staked_kas * kas_spot_usd * 2.0).max(1_000.0)
    } else {
        25_000.0
    };

    let daily_hurdle_target_usd =
        (pair_tvl_usd * (LP_BASE_HURDLE_TARGET_APR_PCT / 100.0)) / 365.0;
    let daily_hurdle_min_usd =
        (pair_tvl_usd * (LP_BASE_HURDLE_MIN_APR_PCT / 100.0)) / 365.0;

    let (lp_share_of_remaining, surplus_volume_sweep_active) =
        if rolling_24h_lp_fees_usd >= daily_hurdle_target_usd {
            (0.20, true)
        } else if rolling_24h_lp_fees_usd < daily_hurdle_min_usd {
            (0.45, false)
        } else {
            (0.4444, false)
        };

    let lp_allocated_fee_usd =
        ((remaining_distributable_usd * lp_share_of_remaining) * 1_000_000.0).round() / 1_000_000.0;
    let perennia_total_cut_usd = ((total_fee - lp_allocated_fee_usd)
        .max(hard_floor_perennia_usd)
        * 1_000_000.0)
        .round()
        / 1_000_000.0;

    // Internal Treasury 60/40 Reserve Split:
    // 60% into Perennia-owned LP positions to compound, 40% in liquid USD/stablecoin clearing reserve
    let perennia_lp_compound_60_usd =
        ((perennia_total_cut_usd * 0.60) * 1_000_000.0).round() / 1_000_000.0;
    let perennia_liquid_reserve_40_usd = ((perennia_total_cut_usd - perennia_lp_compound_60_usd)
        .max(0.0)
        * 1_000_000.0)
        .round()
        / 1_000_000.0;

    let new_rolling_24h_lp_usd = rolling_24h_lp_fees_usd + lp_allocated_fee_usd;
    let raw_apr = if pair_tvl_usd > 0.0 {
        ((new_rolling_24h_lp_usd * 365.0) / pair_tvl_usd) * 100.0
    } else {
        14.4
    };
    let projected_base_lp_apr_pct =
        ((raw_apr.clamp(LP_BASE_HURDLE_MIN_APR_PCT, 24.0)) * 100.0).round() / 100.0;
    let projected_max_multiplier_apr_pct =
        ((projected_base_lp_apr_pct * 2.5) * 100.0).round() / 100.0;

    DynamicHurdleWaterfall {
        hard_floor_perennia_usd,
        lp_allocated_fee_usd,
        perennia_total_cut_usd,
        perennia_lp_compound_60_usd,
        perennia_liquid_reserve_40_usd,
        projected_base_lp_apr_pct,
        projected_max_multiplier_apr_pct,
        competitor_amm_apr_pct: COMPETITOR_STANDARD_AMM_APR_PCT,
        surplus_volume_sweep_active,
    }
}

async fn resolve_user_fee_rate(
    pool: &PgPool,
    prefixed_wallet: &str,
    clean_wallet: &str,
    usd_volume: f64,
) -> (f64, &'static str) {
    let (wallet_floor_rate, tier_label, has_wholesale_perk) =
        crate::fiat_rails::resolve_wallet_swap_fee_floor_pct(pool, prefixed_wallet).await;
    if has_wholesale_perk {
        return (
            wallet_floor_rate.max(crate::fiat_rails::HARD_PROFIT_FLOOR_PCT),
            tier_label,
        );
    }
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
    let mut fee_rate: f64 = if usd_volume >= 2000.0 {
        crate::fiat_rails::HARD_PROFIT_FLOOR_PCT
    } else {
        wallet_floor_rate.max(crate::fiat_rails::STANDARD_PUBLIC_SWAP_FEE_PCT)
    };
    if staked_silo >= 100_000.0 {
        fee_rate = fee_rate.min(crate::fiat_rails::HARD_PROFIT_FLOOR_PCT);
        return (fee_rate, "0.10% SILO Sovereign Staker Wholesale Floor");
    } else if staked_silo >= 10_000.0 {
        fee_rate = fee_rate.min(0.0012_f64);
        return (fee_rate, "0.12% SILO Shield Staker Tier");
    }
    (
        fee_rate.max(crate::fiat_rails::HARD_PROFIT_FLOOR_PCT),
        tier_label,
    )
}

async fn has_sufficient_local_lp_depth(
    pool: &PgPool,
    pay_asset: &str,
    receive_asset: &str,
    required_receive_tokens: f64,
) -> (bool, String) {
    let direct_pair = format!("{}/{}", pay_asset, receive_asset);
    let reverse_pair = format!("{}/{}", receive_asset, pay_asset);
    let kas_pair = format!("KAS/{}", receive_asset);
    let rows = sqlx::query(
        r#"
        SELECT pool_pair, staked_asset_a, staked_asset_b, COALESCE(reserves_json, '{}'::jsonb) AS reserves_json
        FROM liquidity_providers
        WHERE pool_pair = $1 OR pool_pair = $2 OR pool_pair = $3 OR pool_pair LIKE '%' || $4 || '%'
        "#,
    )
    .bind(&direct_pair)
    .bind(&reverse_pair)
    .bind(&kas_pair)
    .bind(receive_asset)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    let mut available_receive_reserve = 0.0_f64;
    let mut matched_pair_label = format!("KAS/{}", receive_asset);
    for r in rows {
        let pair: String = r.try_get("pool_pair").unwrap_or_default();
        let reserves: Value = r.try_get("reserves_json").unwrap_or_else(|_| json!({}));
        if let Some(res_amt) = reserves.get(receive_asset).and_then(|v| v.as_f64()) {
            available_receive_reserve += res_amt.max(0.0);
            matched_pair_label = pair;
            continue;
        }
        let parts: Vec<&str> = pair.split('/').collect();
        if parts.first().copied() == Some(receive_asset) {
            available_receive_reserve += r
                .try_get::<f64, _>("staked_asset_a")
                .unwrap_or(0.0)
                .max(0.0);
            matched_pair_label = pair;
        } else if parts.get(1).copied() == Some(receive_asset) {
            available_receive_reserve += r
                .try_get::<f64, _>("staked_asset_b")
                .unwrap_or(0.0)
                .max(0.0);
            matched_pair_label = pair;
        }
    }
    let has_depth = available_receive_reserve >= (required_receive_tokens * 2.0).max(1e-6);
    (has_depth, matched_pair_label)
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

    let (steering, dark_pool_paused, _external_dex_paused) =
        match resolve_token_steering_and_firewall(
            &pool,
            &clean_wallet,
            &prefixed_wallet,
            &pay_asset,
            &receive_asset,
        )
        .await
        {
            Ok(res) => res,
            Err(err_resp) => return err_resp,
        };

    let pay_spot = match crate::fiat_rails::resolve_live_spot_price(&pool, &pay_asset).await {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": e })),
            );
        }
    };
    let receive_spot =
        match crate::fiat_rails::resolve_live_spot_price(&pool, &receive_asset).await {
            Ok(p) => p,
            Err(e) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": e })),
                );
            }
        };
    let kas_spot = if pay_asset == "KAS" {
        pay_spot
    } else if receive_asset == "KAS" {
        receive_spot
    } else {
        crate::fiat_rails::resolve_live_spot_price(&pool, "KAS")
            .await
            .unwrap_or(0.15)
            .max(0.01)
    };
    let gross_usd = amount * pay_spot;
    if gross_usd < 1.0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "ANTI_DUST_FLOOR: Minimum swap value is $1.00 USD (submitted ${:.2} USD).",
                    gross_usd
                )
            })),
        );
    }
    let (fee_rate, fee_tier_label) =
        resolve_user_fee_rate(&pool, &prefixed_wallet, &clean_wallet, gross_usd).await;
    let hard_floor_usd = (gross_usd * crate::fiat_rails::HARD_PROFIT_FLOOR_PCT).max(0.01);
    let fee_usd = (gross_usd * fee_rate).max(hard_floor_usd);
    let net_usd = (gross_usd - fee_usd).max(0.0);
    if net_usd <= 0.0 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "ZERO_LOSS_INVARIANT_VIOLATION: Net swap value after protocol fee must be > $0.00."
            })),
        );
    }
    let mut estimated_output = if receive_spot > 0.0 {
        net_usd / receive_spot
    } else {
        0.0
    };
    let (raw_has_local_lp, matched_pool_pair) =
        has_sufficient_local_lp_depth(&pool, &pay_asset, &receive_asset, estimated_output).await;
    let has_local_lp =
        raw_has_local_lp && steering.allow_dark_pool_internal_clearing && !dark_pool_paused;

    let provider_label = if has_local_lp {
        "Perennia 50%-KAS Liquidity Pool"
    } else if receive_asset != "KAS" && receive_asset != "SILO" && receive_asset != "USDC" {
        if let Ok(cn_net_out) =
            crate::fiat_rails::fetch_changenow_estimated_amount("USDC", &receive_asset, net_usd)
                .await
        {
            if cn_net_out > 0.0 {
                estimated_output = estimated_output.min(cn_net_out);
            }
        }
        "Perennia Hybrid SOR + Wholesale Pass-Through"
    } else {
        "Perennia 50%-KAS Liquidity Pool"
    };
    estimated_output = (estimated_output * 100_000_000.0).round() / 100_000_000.0;
    let unified_rate = if amount > 0.0 {
        estimated_output / amount
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
    let anchor_kas_volume = if pay_asset == "KAS" {
        amount
    } else if kas_spot > 0.0 {
        gross_usd / kas_spot
    } else {
        0.0
    };

    let target_distribution_pair = if has_local_lp {
        matched_pool_pair
    } else if pay_asset == "KAS" {
        format!("KAS/{}", receive_asset)
    } else if receive_asset == "KAS" {
        format!("KAS/{}", pay_asset)
    } else {
        format!("{}/{}", pay_asset, receive_asset)
    };

    let waterfall = compute_dynamic_hurdle_waterfall(
        &pool,
        &target_distribution_pair,
        gross_usd,
        fee_usd,
        kas_spot,
    )
    .await;

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
                            let anchor_layer_sweep =
                                crate::chronos::sweep_layered_buckets_on_anchor_order(
                                    &pool,
                                    &receive_asset,
                                    anchor_kas_volume,
                                    kas_spot,
                                    receive_spot,
                                )
                                .await
                                .unwrap_or_else(|_| json!({ "layeredBucketsCleared": 0 }));
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
                                    "feeTierLabel": fee_tier_label,
                                    "feeUsd": fee_usd,
                                    "fee_usd": fee_usd,
                                    "tokenSteering": steering,
                                    "dynamicHurdleWaterfall": waterfall,
                                    "anchorLayerSweep": anchor_layer_sweep,
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

    let anchor_layer_sweep = crate::chronos::sweep_layered_buckets_on_anchor_order(
        &pool,
        &receive_asset,
        anchor_kas_volume,
        kas_spot,
        receive_spot,
    )
    .await
    .unwrap_or_else(|_| json!({ "layeredBucketsCleared": 0 }));

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
    .bind(&target_distribution_pair)
    .bind(waterfall.lp_allocated_fee_usd)
    .execute(&pool)
    .await;

    let _ = sqlx::query(
        r#"
        UPDATE fiat_float_ledger
        SET dark_pool_lp_vault_usd = dark_pool_lp_vault_usd + $1,
            master_treasury_usdc_reserve = COALESCE(master_treasury_usdc_reserve, 0.0) + $2,
            updated_at = CURRENT_TIMESTAMP
        WHERE ledger_id IN ('BOOTSTRAP_PRIMARY', 'PRIMARY_FLOAT')
        "#,
    )
    .bind(waterfall.perennia_lp_compound_60_usd)
    .bind(waterfall.perennia_liquid_reserve_40_usd)
    .execute(&pool)
    .await;

    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let _: redis::RedisResult<()> = redis::cmd("INCRBYFLOAT")
                    .arg("perennia:treasury:netting_profit_usd")
                    .arg(waterfall.perennia_total_cut_usd)
                    .query_async(&mut conn)
                    .await;
                let _: redis::RedisResult<()> = redis::cmd("INCRBYFLOAT")
                    .arg("perennia:fees:batch_accumulated:USDC")
                    .arg(waterfall.perennia_lp_compound_60_usd)
                    .query_async(&mut conn)
                    .await;
                for leg in &steering.fee_legs {
                    let leg_usd = waterfall.perennia_total_cut_usd * leg.share_ratio;
                    let leg_spot = if leg.asset == pay_asset {
                        pay_spot
                    } else if leg.asset == receive_asset {
                        receive_spot
                    } else if leg.asset == "KAS" {
                        kas_spot
                    } else {
                        1.0
                    };
                    let leg_tokens = if leg_spot > 0.0 {
                        leg_usd / leg_spot
                    } else {
                        leg_usd
                    };
                    if leg.asset != "USDC" {
                        let _: redis::RedisResult<()> = redis::cmd("INCRBYFLOAT")
                            .arg(format!("perennia:fees:batch_accumulated:{}", leg.asset))
                            .arg(leg_tokens)
                            .query_async(&mut conn)
                            .await;
                    }
                }
                let _: redis::RedisResult<()> = redis::cmd("INCRBYFLOAT")
                    .arg(format!(
                        "perennia:lp:pending_yield_usd:{}",
                        target_distribution_pair
                    ))
                    .arg(waterfall.lp_allocated_fee_usd)
                    .query_async(&mut conn)
                    .await;
            }
        }
    }
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
            "feeTierLabel": fee_tier_label,
            "feeUsd": fee_usd,
            "fee_usd": fee_usd,
            "tokenSteering": steering,
            "dynamicHurdleWaterfall": waterfall,
            "anchorLayerSweep": anchor_layer_sweep,
            "legs": [
                {
                    "tier": 1,
                    "provider": provider_label,
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