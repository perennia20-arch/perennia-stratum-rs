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

impl PayoutBatchEntry for Value {
    fn recipient_address(&self) -> String {
        self.get("address")
            .or_else(|| self.get("wallet"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }
    fn amount_sompi(&self) -> u64 {
        self.get("sompi")
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
            })
            .unwrap_or(0)
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
    #[serde(default)]
    pub target_network: Option<String>,
    #[serde(default)]
    pub amount_atomic: Option<String>,
    #[serde(default)]
    pub amount: Option<Value>,
    #[serde(default)]
    pub min_output_atomic: Option<String>,
    #[serde(default)]
    pub slippage_bps: Option<u16>,
    #[serde(default)]
    pub destination_address: Option<String>,
    #[serde(default)]
    pub refund_kaspa_address: Option<String>,
    #[serde(default)]
    pub utxos: Option<Vec<Value>>,
    #[serde(default)]
    pub htlc_sha256_hashlock_hex: Option<String>,
    #[serde(default)]
    pub counterparty_pubkey_hex: Option<String>,
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

fn atomic_decimals_for_sor_asset(ticker: &str) -> u8 {
    match ticker.trim().to_uppercase().as_str() {
        "USDC" | "USDT" | "KUSDT" | "USD" | "XRP" | "TRX" | "ADA" => 6,
        "SOL" | "SUI" | "TON" => 9,
        "ETH" | "ARB" | "BASE" | "POL" | "AVAX" | "LINK" => 18,
        _ => 8,
    }
}

fn parse_decimal_or_json_to_atomic_u128(raw_str: &str, decimals: u8) -> Result<u128, String> {
    let trimmed = raw_str.trim();
    if trimmed.is_empty() || trimmed.starts_with('-') {
        return Err("Empty or negative amount".to_string());
    }
    let mut parts = trimmed.split('.');
    let int_part = parts.next().unwrap_or("");
    let frac_part = parts.next().unwrap_or("");
    if parts.next().is_some() {
        return Err("Multiple decimal points in amount".to_string());
    }
    let scale = 10u128.pow(decimals as u32);
    let whole: u128 = if int_part.is_empty() {
        0
    } else {
        int_part
            .parse::<u128>()
            .map_err(|_| "Invalid whole integer amount".to_string())?
    };
    let mut frac_buf = frac_part.as_bytes().to_vec();
    frac_buf.truncate(decimals as usize);
    while frac_buf.len() < decimals as usize {
        frac_buf.push(b'0');
    }
    let frac: u128 = String::from_utf8(frac_buf)
        .unwrap_or_default()
        .parse::<u128>()
        .unwrap_or(0);
    whole
        .checked_mul(scale)
        .and_then(|v| v.checked_add(frac))
        .ok_or_else(|| "Atomic amount overflow".to_string())
}

async fn resolve_sor_fee_bps(
    pool: &PgPool,
    prefixed_wallet: &str,
    clean_wallet: &str,
    gross_usd_micros: u128,
    pay_asset: &str,
    receive_asset: &str,
    allow_dark_pool: bool,
) -> (u16, &'static str) {
    let is_active_miner: bool = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*) FROM worker_profiles
        WHERE (LOWER(REPLACE(TRIM(wallet_address), 'kaspa:', '')) = $1 OR wallet_address = $2)
          AND status IN ('online', 'grace_period')
        "#,
    )
    .bind(clean_wallet)
    .bind(prefixed_wallet)
    .fetch_one(pool)
    .await
    .unwrap_or(0)
        > 0;
    if is_active_miner {
        return (10, "10 bps Active Stratum Miner Wholesale Floor");
    }

    let staked_silo_atomic: u128 = sqlx::query_scalar::<_, Option<String>>(
        r#"
        SELECT COALESCE(SUM(COALESCE(amount_staked_atomic, TRUNC(GREATEST(amount_staked, 0) * 100000000))), 0)::NUMERIC(39,0)::TEXT
        FROM silo_staking_positions
        WHERE (wallet_address = $1 OR wallet_address = $2)
          AND status IN ('ACTIVE', 'COOLDOWN')
        "#,
    )
    .bind(prefixed_wallet)
    .bind(clean_wallet)
    .fetch_one(pool)
    .await
    .ok()
    .flatten()
    .and_then(|s| s.parse::<u128>().ok())
    .unwrap_or(0);

    let is_buy_kas = receive_asset == "KAS" && pay_asset != "USD";
    if staked_silo_atomic >= 100_000_000_000_000 {
        return (10, "10 bps SILO Sovereign Staker Floor");
    }
    if is_buy_kas {
        return (20, "20 bps Buy-KAS Inbound Tier");
    }
    if staked_silo_atomic >= 10_000_000_000_000 || gross_usd_micros >= 2_500_000_000 {
        return (25, "25 bps Wholesale / Vanguard Tier");
    }
    if staked_silo_atomic >= 1_000_000_000_000 {
        return (35, "35 bps SILO Shield Staker Tier");
    }
    let is_dp_major = allow_dark_pool
        && DEFAULT_RESERVE_WHITELIST.iter().any(|&t| t == pay_asset)
        && DEFAULT_RESERVE_WHITELIST.iter().any(|&t| t == receive_asset);
    if is_dp_major {
        (50, "50 bps Dark Pool CoW Major Tier")
    } else {
        (85, "85 bps External Non-Custodial Pass-Through Tier")
    }
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
    let pay_decimals = atomic_decimals_for_sor_asset(&pay_asset);
    let rec_decimals = atomic_decimals_for_sor_asset(&receive_asset);

    if clean_wallet.is_empty()
        || crate::state_api::decode_kaspa_address_payload(&prefixed_wallet).is_none()
        || pay_asset == receive_asset
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Invalid non-custodial swap parameters or Kaspa Bech32m wallet."
            })),
        );
    }

    let amount_in_atomic: u128 = if let Some(ref s) = req.amount_atomic {
        match s.trim().parse::<u128>() {
            Ok(v) if v > 0 => v,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "amountAtomic must be a positive integer string." })),
                );
            }
        }
    } else if let Some(ref val) = req.amount {
        let raw_s = val
            .as_str()
            .map(|s| s.to_string())
            .or_else(|| val.as_u64().map(|n| n.to_string()))
            .or_else(|| val.as_f64().filter(|f| f.is_finite() && *f > 0.0).map(|f| format!("{:.8}", f)))
            .unwrap_or_default();
        match parse_decimal_or_json_to_atomic_u128(&raw_s, pay_decimals) {
            Ok(v) if v > 0 => v,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "amount must be positive." })),
                );
            }
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Provide amountAtomic or amount." })),
        );
    };

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

    // Strict live oracles (zero 0.15 fallback — fail closed with 503)
    let pay_usd_e8 = match crate::state_api::resolve_strict_spot_price_e8(&pool, &pay_asset).await {
        Ok(p) if p > 0 => p,
        Ok(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": format!("ORACLE_HALT: {} oracle returned 0.", pay_asset) })),
            );
        }
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": e })),
            );
        }
    };
    let receive_usd_e8 =
        match crate::state_api::resolve_strict_spot_price_e8(&pool, &receive_asset).await {
            Ok(p) if p > 0 => p,
            Ok(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": format!("ORACLE_HALT: {} oracle returned 0.", receive_asset) })),
                );
            }
            Err(e) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": e })),
                );
            }
        };
    let kas_usd_e8 = match crate::state_api::resolve_strict_spot_price_e8(&pool, "KAS").await {
        Ok(p) if p > 0 => p,
        Ok(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "ORACLE_HALT: KAS oracle returned 0." })),
            );
        }
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": e })),
            );
        }
    };

    let pay_scale = 10u128.pow(pay_decimals as u32);
    let rec_scale = 10u128.pow(rec_decimals as u32);
    // usd_micros = amount_in_atomic * pay_usd_e8 / (pay_scale * 100)
    let gross_usd_micros = amount_in_atomic.saturating_mul(pay_usd_e8) / (pay_scale.saturating_mul(100));
    if gross_usd_micros < 1_000_000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "ANTI_DUST_FLOOR: Minimum non-custodial swap notional is $1.00 USD (1000000 usdMicros)."
            })),
        );
    }

    let allow_dp = steering.allow_dark_pool_internal_clearing && !dark_pool_paused;
    let (fee_bps, fee_tier_label) = resolve_sor_fee_bps(
        &pool,
        &prefixed_wallet,
        &clean_wallet,
        gross_usd_micros,
        &pay_asset,
        &receive_asset,
        allow_dp,
    )
    .await;

    let protocol_fee_atomic = (amount_in_atomic.saturating_mul(fee_bps as u128) + 9_999) / 10_000;
    let net_in_atomic = amount_in_atomic.saturating_sub(protocol_fee_atomic);
    if net_in_atomic == 0 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "ZERO_LOSS_INVARIANT_VIOLATION: Net swap input after fee is 0." })),
        );
    }

    let net_usd_micros = net_in_atomic.saturating_mul(pay_usd_e8) / (pay_scale.saturating_mul(100));
    let estimated_out_atomic =
        (net_in_atomic.saturating_mul(pay_usd_e8) / receive_usd_e8.max(1)).saturating_mul(rec_scale)
            / pay_scale.max(1);
    let slippage_bps = req.slippage_bps.unwrap_or(50).clamp(1, 2500) as u128;
    let computed_min_out = estimated_out_atomic.saturating_mul(10_000 - slippage_bps) / 10_000;
    let min_out_atomic = req
        .min_output_atomic
        .as_deref()
        .and_then(|s| s.trim().parse::<u128>().ok())
        .map(|u| u.max(computed_min_out))
        .unwrap_or(computed_min_out);

    let sys_cfg = crate::chronos::load_system_treasury_config(&pool).await;
    let house_revenue_addr = crate::chronos::resolve_house_revenue_kas_address(&sys_cfg)
        .unwrap_or_else(|| sys_cfg.cold_kas_address.clone());
    let tx_uuid = format!(
        "PER-SOR-{}",
        &Uuid::new_v4().simple().to_string().to_uppercase()[..12]
    );

    if pay_asset != "KAS" {
        return (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "transactionUuid": tx_uuid,
                "routeType": "CROSS_CHAIN_DEPOSIT_INTENT",
                "amountInAtomic": amount_in_atomic.to_string(),
                "protocolFeeAtomic": protocol_fee_atomic.to_string(),
                "networkFeeSompi": "0",
                "estimatedOutputAtomic": estimated_out_atomic.to_string(),
                "minOutputAtomic": min_out_atomic.to_string(),
                "feeBps": fee_bps,
                "feeTierLabel": fee_tier_label,
                "grossUsdMicros": gross_usd_micros.to_string(),
                "netUsdMicros": net_usd_micros.to_string(),
                "payOracleUsdE8": pay_usd_e8.to_string(),
                "receiveOracleUsdE8": receive_usd_e8.to_string(),
                "kasOracleUsdE8": kas_usd_e8.to_string(),
                "targetNetwork": req.target_network.clone().unwrap_or_else(|| crate::state_api::resolve_network_for_asset(&receive_asset)),
                "destinationAddress": req.destination_address.clone().unwrap_or_else(|| prefixed_wallet.clone()),
                "refundKaspaAddress": req.refund_kaspa_address.clone().unwrap_or_else(|| prefixed_wallet.clone()),
                "tokenSteering": steering,
                "pskt": Value::Null,
                "htlcCovenant": Value::Null,
                "formattedUtxos": []
            })),
        );
    }

    let utxo_list = match req.utxos {
        Some(ref list) if !list.is_empty() => list.clone(),
        _ => crate::kaspad_client::get_utxos_by_address_grpc(&prefixed_wallet)
            .await
            .unwrap_or_default(),
    };
    if utxo_list.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "NON_CUSTODIAL_UTXOS_REQUIRED: Wallet has 0 live L1 UTXOs on local kaspad (custodial DB/Redis balances are retired)."
            })),
        );
    }

    let pay_sompi = u64::try_from(amount_in_atomic).unwrap_or(0);
    if pay_sompi == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "KAS input sompi exceeds u64 consensus cap." })),
        );
    }

    let is_l1_cow_token = matches!(
        receive_asset.as_str(),
        "SILO" | "PERX" | "KUSDT" | "NACHO" | "BEDRCK"
    );
    let mut htlc_covenant_json = Value::Null;
    let (route_type, target_l1_dest) = if req.htlc_sha256_hashlock_hex.is_some()
        || (!is_l1_cow_token
            && matches!(receive_asset.as_str(), "USDC" | "USDT")
            && matches!(
                req.target_network.as_deref().map(|s| s.to_uppercase()).as_deref(),
                Some("BASE") | Some("SOL") | Some("ARB")
            ))
    {
        let hl_hex = req.htlc_sha256_hashlock_hex.clone().unwrap_or_else(|| {
            blake3::hash(format!("SOR-HTLC:{}:{}", tx_uuid, clean_wallet).as_bytes())
                .to_hex()
                .to_string()
        });
        let mut hl_arr = [0u8; 32];
        if let Ok(b) = hex::decode(hl_hex.trim().trim_start_matches("0x")) {
            if b.len() == 32 {
                hl_arr.copy_from_slice(&b);
            }
        }
        let (_, owner_pk) =
            crate::state_api::decode_kaspa_address_payload(&prefixed_wallet).unwrap();
        let mut cp_pk = owner_pk;
        if let Some(ref cpk) = req.counterparty_pubkey_hex {
            if let Ok(b) = hex::decode(cpk.trim().trim_start_matches("0x")) {
                if b.len() == 32 {
                    cp_pk.copy_from_slice(&b);
                }
            }
        }
        let v_daa = crate::kaspad_client::get_virtual_daa_score_grpc()
            .await
            .unwrap_or(0);
        let htlc = crate::chronos::build_kaspa_opsha256_htlc_covenant(
            &hl_arr,
            &cp_pk,
            &owner_pk,
            v_daa.saturating_add(crate::chronos::DEFAULT_HTLC_DAA_REFUND_DELTA),
        );
        let p2sh_addr = htlc.p2sh_address.clone();
        htlc_covenant_json = serde_json::to_value(htlc).unwrap_or(Value::Null);
        ("CROSS_CHAIN_OPSHA256_HTLC", p2sh_addr)
    } else if is_l1_cow_token {
        let dest = if house_revenue_addr.starts_with("kaspa:") {
            house_revenue_addr.clone()
        } else {
            prefixed_wallet.clone()
        };
        ("L1_COW_ATOMIC_PSKT", dest)
    } else {
        let dest = req
            .destination_address
            .clone()
            .filter(|s| s.starts_with("kaspa:"))
            .unwrap_or_else(|| {
                if house_revenue_addr.starts_with("kaspa:") {
                    house_revenue_addr.clone()
                } else {
                    prefixed_wallet.clone()
                }
            });
        ("TIER3_CHANGENOW_SPLIT_PSKT", dest)
    };

    let Some((mut psbt, formatted_utxos)) =
        assemble_unsigned_kaspa_psbt(&prefixed_wallet, &target_l1_dest, pay_sompi, &utxo_list)
    else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "INSUFFICIENT_CONFIRMED_UTXOS: Wallet UTXOs do not cover requested KAS sompi + Post-Toccata Transaction v1 fee."
            })),
        );
    };
    if let Some(obj) = psbt.as_object_mut() {
        obj.insert("version".to_string(), json!(1));
    }

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "transactionUuid": tx_uuid,
            "routeType": route_type,
            "amountInAtomic": amount_in_atomic.to_string(),
            "protocolFeeAtomic": protocol_fee_atomic.to_string(),
            "networkFeeSompi": "0",
            "estimatedOutputAtomic": estimated_out_atomic.to_string(),
            "minOutputAtomic": min_out_atomic.to_string(),
            "feeBps": fee_bps,
            "feeTierLabel": fee_tier_label,
            "grossUsdMicros": gross_usd_micros.to_string(),
            "netUsdMicros": net_usd_micros.to_string(),
            "payOracleUsdE8": pay_usd_e8.to_string(),
            "receiveOracleUsdE8": receive_usd_e8.to_string(),
            "kasOracleUsdE8": kas_usd_e8.to_string(),
            "refundKaspaAddress": req.refund_kaspa_address.unwrap_or_else(|| prefixed_wallet.clone()),
            "tokenSteering": steering,
            "pskt": psbt,
            "htlcCovenant": htlc_covenant_json,
            "formattedUtxos": formatted_utxos
        })),
    )
}