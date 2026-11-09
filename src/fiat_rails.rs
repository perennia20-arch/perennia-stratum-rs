use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub const INITIAL_LOCAL_KAS_FLOAT_USD: f64 = 500.0;
pub const INITIAL_WHOLESALE_API_USD_FLOAT: f64 = 400.0;
pub const TARGET_RATCHET_FLOAT_CAP_USD: f64 = 5_000.0;
pub const HARD_PROFIT_FLOOR_PCT: f64 = 0.001;
pub const STANDARD_PUBLIC_SWAP_FEE_PCT: f64 = 0.0015;

pub const RETAIL_ONRAMP_FEE_BPS: u64 = 85;
pub const PRO_MINER_ONRAMP_FEE_BPS: u64 = 35;
pub const INSTITUTIONAL_WIRE_ONRAMP_FEE_BPS: u64 = 20;
pub const MIN_ONRAMP_FEE_FLOOR_CENTS: i64 = 250;
pub const ACH_AUTO_DEFAULT_THRESHOLD_CENTS: i64 = 62_500;
pub const PRO_TIER_THRESHOLD_CENTS: i64 = 1_000_000;
pub const INSTITUTIONAL_WIRE_THRESHOLD_CENTS: i64 = 10_000_000;

pub const MERCURY_COLUMN_ABA_ROUTING: &str = "121145433";
pub const MERCURY_COLUMN_ACCOUNT_NUMBER: &str = "580798008849901";
pub const MERCURY_COLUMN_BANK_NAME: &str = "Column N.A. (Mercury)";

const MIN_DISCOVERY_CEX_VOLUME_USD: f64 = 25_000.0;
const MAX_DISCOVERY_CEX_SPREAD_RATIO: f64 = 0.05;
const MAX_CANONICAL_DEVIATION_RATIO: f64 = 0.08;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayGrossUpBreakdown {
    pub tier_name: String,
    pub tier_bps: u64,
    pub payment_method: String,
    pub principal_cents: i64,
    pub perennia_fee_cents: i64,
    pub target_net_cents: i64,
    pub stripe_gateway_fee_cents: i64,
    pub gross_charge_cents: i64,
    pub requires_institutional_wire: bool,
    pub auto_defaulted_to_ach: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CostPlusQuoteBreakdown {
    pub direction: String,
    pub asset_ticker: String,
    pub gross_usd: f64,
    pub hard_execution_and_repar_cost_usd: f64,
    pub guaranteed_net_profit_usd: f64,
    pub quoted_guest_fee_usd: f64,
    pub effective_fee_pct: f64,
    pub protocol_fee_floor_pct: f64,
    pub miner_or_pass_discount_active: bool,
    pub guest_net_usd: f64,
    pub estimated_tokens: f64,
    pub spot_price_usd: f64,
    pub competitor_fee_usd: f64,
    pub competitor_net_usd: f64,
    pub guest_savings_vs_competitor_usd: f64,
    pub routing_topology: String,
    pub bank_rail: String,
    pub whale_wire_fee_waived: bool,
    pub bundled_usdc_fee_waived: bool,
    pub circuit_breaker_tripped: bool,
    pub circuit_breaker_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostTradeUsdAllocation {
    pub gross_inbound_usd: f64,
    pub wholesale_api_float_sweep_usd: f64,
    pub chronos_miner_settlement_usd: f64,
    pub llc_tax_and_rail_reserve_usd: f64,
    pub net_profit_and_ratchet_usd: f64,
    pub float_ratchet_reinvest_usd: f64,
    pub dark_pool_lp_and_owner_draw_usd: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapFloatState {
    pub local_kas_reserve_usd: f64,
    pub local_kas_target_cap_usd: f64,
    pub wholesale_api_working_usd: f64,
    pub wholesale_api_target_cap_usd: f64,
    pub combined_float_usd: f64,
    pub ratchet_target_cap_usd: f64,
    pub commercial_checking_cleared_usd: f64,
    pub llc_tax_escrow_reserve_usd: f64,
    pub dark_pool_lp_vault_usd: f64,
    pub master_treasury_wallet: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteQueryParams {
    pub direction: Option<String>,
    pub asset: Option<String>,
    pub amount_usd: Option<f64>,
    pub amount_tokens: Option<f64>,
    pub payment_rail: Option<String>,
    pub payment_method: Option<String>,
    pub settlement_target: Option<String>,
    pub auto_stake_silo: Option<bool>,
    pub bundled_kas_or_silo: Option<bool>,
    pub wallet: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnrampOrderRequest {
    pub wallet_address: String,
    pub fiat_amount_usd: f64,
    pub target_asset: Option<String>,
    pub payment_rail: Option<String>,
    pub payment_method: Option<String>,
    pub settlement_target: Option<String>,
    pub destination_wallet_address: Option<String>,
    pub auto_stake_silo: Option<bool>,
    pub bundled_kas_or_silo: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfframpOrderRequest {
    pub wallet_address: String,
    pub source_asset: String,
    pub amount_crypto: Option<f64>,
    pub gross_usd: Option<f64>,
    pub payout_method: Option<String>,
    pub bank_label: Option<String>,
    pub account_type: Option<String>,
    pub bank_last4: Option<String>,
    pub routing_number: Option<String>,
    pub tx_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveWebhookRequest {
    pub event_type: String,
    pub order_id: Option<String>,
    pub payout_id: Option<String>,
    pub confirmations: Option<i32>,
    pub trace_id: Option<String>,
    pub tx_hash: Option<String>,
    pub settled_net_cents: Option<i64>,
    pub quarantine_on_shortfall: Option<bool>,
}

fn round_cents(val: f64) -> f64 {
    (val * 100.0).round() / 100.0
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn verify_director_or_webhook_headers(headers: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let internal_token = env::var("INTERNAL_ADMIN_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let admin_key = env::var("PERENNIA_ADMIN_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let mut authorized = false;
    if let Some(tok) = internal_token {
        let expected = format!("Bearer {}", tok);
        if constant_time_eq(auth_header.as_bytes(), expected.as_bytes()) {
            authorized = true;
        }
    }
    if !authorized {
        if let Some(key) = admin_key {
            let expected = format!("Bearer {}", key);
            if constant_time_eq(auth_header.as_bytes(), expected.as_bytes()) {
                authorized = true;
            }
        }
    }
    if !authorized {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "UNAUTHORIZED: Valid Director or internal webhook bearer token required."
            })),
        ));
    }
    Ok(())
}

pub fn calculate_gateway_gross_up_cents(
    principal_cents: i64,
    loyal_miner_or_subscriber: bool,
    payment_method: &str,
) -> GatewayGrossUpBreakdown {
    let safe_principal = principal_cents.max(0);
    if safe_principal >= INSTITUTIONAL_WIRE_THRESHOLD_CENTS {
        let pct_fee = ((safe_principal as f64)
            * (INSTITUTIONAL_WIRE_ONRAMP_FEE_BPS as f64)
            / 10_000.0)
            .ceil() as i64;
        let perennia_fee = pct_fee.max(MIN_ONRAMP_FEE_FLOOR_CENTS);
        let target_net = safe_principal + perennia_fee;
        return GatewayGrossUpBreakdown {
            tier_name: "INSTITUTIONAL_WIRE".to_string(),
            tier_bps: INSTITUTIONAL_WIRE_ONRAMP_FEE_BPS,
            payment_method: "wire".to_string(),
            principal_cents: safe_principal,
            perennia_fee_cents: perennia_fee,
            target_net_cents: target_net,
            stripe_gateway_fee_cents: 0,
            gross_charge_cents: target_net,
            requires_institutional_wire: true,
            auto_defaulted_to_ach: false,
        };
    }

    let is_pro_or_miner =
        safe_principal >= PRO_TIER_THRESHOLD_CENTS || loyal_miner_or_subscriber;
    let (tier_name, tier_bps) = if is_pro_or_miner {
        ("PRO_MINER".to_string(), PRO_MINER_ONRAMP_FEE_BPS)
    } else {
        ("RETAIL".to_string(), RETAIL_ONRAMP_FEE_BPS)
    };

    let perennia_fee = if safe_principal > 0 {
        let pct_fee =
            ((safe_principal as f64) * (tier_bps as f64) / 10_000.0).ceil() as i64;
        pct_fee.max(MIN_ONRAMP_FEE_FLOOR_CENTS)
    } else {
        0
    };
    let target_net = safe_principal + perennia_fee;

    let method_lower = payment_method.trim().to_lowercase();
    let auto_defaulted_to_ach =
        safe_principal >= ACH_AUTO_DEFAULT_THRESHOLD_CENTS && method_lower != "card";
    let resolved_method = if method_lower == "card" {
        "card"
    } else if method_lower == "wire" {
        "wire"
    } else {
        "ach"
    };

    let gross_charge = if safe_principal <= 0 || resolved_method == "wire" {
        target_net
    } else if resolved_method == "card" {
        (((target_net + 30) as f64) / 0.971).ceil() as i64
    } else if safe_principal >= ACH_AUTO_DEFAULT_THRESHOLD_CENTS {
        target_net + 500
    } else {
        let grossed_below_cap = ((target_net as f64) / 0.992).ceil() as i64;
        if (grossed_below_cap - target_net) > 500 {
            target_net + 500
        } else {
            grossed_below_cap
        }
    };

    let stripe_gateway_fee = (gross_charge - target_net).max(0);

    GatewayGrossUpBreakdown {
        tier_name,
        tier_bps,
        payment_method: resolved_method.to_string(),
        principal_cents: safe_principal,
        perennia_fee_cents: perennia_fee,
        target_net_cents: target_net,
        stripe_gateway_fee_cents: stripe_gateway_fee,
        gross_charge_cents: gross_charge,
        requires_institutional_wire: false,
        auto_defaulted_to_ach,
    }
}

pub async fn resolve_wallet_swap_fee_floor_pct(
    pool: &PgPool,
    wallet_address: &str,
) -> (f64, &'static str, bool) {
    let promo_cohort_active = env::var("KICKOFF_PROMO_COHORT_ACTIVE")
        .ok()
        .map(|v| !v.trim().eq_ignore_ascii_case("false"))
        .unwrap_or(true);
    let clean_wallet = wallet_address
        .trim()
        .to_lowercase()
        .replace("kaspa:", "")
        .trim()
        .to_string();
    if clean_wallet.is_empty() {
        return if promo_cohort_active {
            (HARD_PROFIT_FLOOR_PCT, "0.10% Kickoff Promo Floor", true)
        } else {
            (
                STANDARD_PUBLIC_SWAP_FEE_PCT,
                "0.15% Standard Public Tier",
                false,
            )
        };
    }
    let prefixed_wallet = format!("kaspa:{}", clean_wallet);
    let mut maintenance_grace_shield = false;

    // 1. Check Redis for active Stratum miner loyalty streak, monthly pass, or maintenance grace shield
    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let loyalty_raw: Option<String> = redis::cmd("GET")
                    .arg(format!("perennia:miner:loyalty:{}", clean_wallet))
                    .query_async(&mut conn)
                    .await
                    .ok()
                    .flatten();
                if loyalty_raw.is_some() {
                    return (
                        HARD_PROFIT_FLOOR_PCT,
                        "0.10% Active Stratum Miner Wholesale Floor",
                        true,
                    );
                }
                let pass_raw: Option<String> = redis::cmd("GET")
                    .arg(format!("perennia:subscription:pass:{}", clean_wallet))
                    .query_async(&mut conn)
                    .await
                    .ok()
                    .flatten();
                if pass_raw.is_some() {
                    return (
                        HARD_PROFIT_FLOOR_PCT,
                        "0.10% Monthly Routing Pass Wholesale Floor",
                        true,
                    );
                }
                let shield_raw: Option<String> = redis::cmd("GET")
                    .arg("perennia:stratum:maintenance_grace_shield")
                    .query_async(&mut conn)
                    .await
                    .ok()
                    .flatten();
                if let Some(s) = shield_raw {
                    if s.trim() == "1" || s.trim().eq_ignore_ascii_case("true") {
                        maintenance_grace_shield = true;
                    }
                }
            }
        }
    }

    // 2. Check PostgreSQL worker_profiles within the 2-hour disconnect grace window (or 24h when Maintenance Grace Shield is armed)
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let window_ms: i64 = if maintenance_grace_shield {
        86_400_000
    } else {
        7_200_000
    };
    let grace_cutoff_ms = now_ms - window_ms;
    let grace_cutoff_secs = (now_ms / 1000) - (window_ms / 1000);
    let has_active_miner: Option<i32> = sqlx::query_scalar(
        r#"
        SELECT 1
        FROM worker_profiles
        WHERE (LOWER(REPLACE(TRIM(wallet_address), 'kaspa:', '')) = $1 OR wallet_address = $2)
          AND (
              status IN ('online', 'grace_period')
              OR (last_share_ts > 10000000000 AND last_share_ts >= $3)
              OR (last_share_ts > 0 AND last_share_ts <= 10000000000 AND last_share_ts >= $4)
          )
        LIMIT 1
        "#,
    )
    .bind(&clean_wallet)
    .bind(&prefixed_wallet)
    .bind(grace_cutoff_ms)
    .bind(grace_cutoff_secs)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    if has_active_miner.is_some() {
        return (
            HARD_PROFIT_FLOOR_PCT,
            "0.10% Active Stratum Miner Wholesale Floor",
            true,
        );
    }
    if promo_cohort_active {
        (
            HARD_PROFIT_FLOOR_PCT,
            "0.10% Kickoff Promo Wholesale Floor",
            true,
        )
    } else {
        (
            STANDARD_PUBLIC_SWAP_FEE_PCT,
            "0.15% Standard Public Tier",
            false,
        )
    }
}

async fn check_fiat_killswitch_and_firewall(
    clean_wallet: &str,
    prefixed_wallet: &str,
    asset_ticker: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    let clean_asset = asset_ticker.trim().to_uppercase();
    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let ks_flag: Option<String> = redis::cmd("GET")
                    .arg("perennia:killswitch:fiat_onramp")
                    .query_async(&mut conn)
                    .await
                    .ok()
                    .flatten();
                if let Some(f) = ks_flag {
                    if f.trim() == "1" || f.trim().eq_ignore_ascii_case("true") {
                        return Err((
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(json!({
                                "error": "SUBSYSTEM_PAUSED: Fiat On-Ramp is currently paused by Director kill-switch."
                            })),
                        ));
                    }
                }
                if !clean_wallet.is_empty() {
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
                                "error": "FIREWALL_REJECTED: Wallet address is blacklisted by the Perennia Security Firewall."
                            })),
                        ));
                    }
                }
                let blk_tok: i32 = redis::cmd("SISMEMBER")
                    .arg("perennia:firewall:blacklisted_tokens")
                    .arg(&clean_asset)
                    .query_async(&mut conn)
                    .await
                    .unwrap_or(0);
                if blk_tok == 1 {
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": format!("FIREWALL_REJECTED: Asset {} is blacklisted by the Perennia Reserve Firewall.", clean_asset)
                        })),
                    ));
                }
            }
        }
    }
    Ok(())
}

async fn discover_and_cache_canonical_spot_price(
    pool: &PgPool,
    asset_ticker: &str,
) -> Result<f64, String> {
    let clean: String = asset_ticker
        .trim()
        .to_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(14)
        .collect();
    if clean.len() < 2 {
        return Err(format!("ORACLE_HALT: Invalid asset ticker '{}'.", asset_ticker));
    }
    crate::oracle::register_dynamic_oracle_ticker(&clean);
    let client = reqwest::Client::builder()
        .user_agent("Perennia-Fiat-Rails-Oracle/2.0")
        .timeout(std::time::Duration::from_secs(4))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let mut canonical_price = 0.0_f64;
    let mut canonical_change = 0.0_f64;
    let mut cg_coin_id = String::new();
    let search_url = format!(
        "https://api.coingecko.com/api/v3/search?query={}",
        urlencoding::encode(&clean)
    );
    if let Ok(resp) = client.get(&search_url).send().await {
        if resp.status().is_success() {
            if let Ok(search_json) = resp.json::<Value>().await {
                if let Some(coins) = search_json.get("coins").and_then(|v| v.as_array()) {
                    let mut exact: Vec<&Value> = coins
                        .iter()
                        .filter(|c| {
                            c.get("symbol")
                                .and_then(|s| s.as_str())
                                .map(|s| s.trim().eq_ignore_ascii_case(&clean))
                                .unwrap_or(false)
                        })
                        .collect();
                    if exact.is_empty() {
                        exact = coins.iter().collect();
                    }
                    exact.sort_by_key(|c| {
                        c.get("market_cap_rank")
                            .and_then(|r| r.as_u64())
                            .filter(|&r| r > 0)
                            .unwrap_or(999_999)
                    });
                    if let Some(best) = exact.first() {
                        if let Some(id_str) = best.get("id").and_then(|v| v.as_str()) {
                            cg_coin_id = id_str.trim().to_string();
                        }
                    }
                }
            }
        }
    }
    if !cg_coin_id.is_empty() {
        let price_url = format!(
            "https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd&include_24hr_change=true",
            urlencoding::encode(&cg_coin_id)
        );
        if let Ok(resp) = client.get(&price_url).send().await {
            if resp.status().is_success() {
                if let Ok(price_json) = resp.json::<Value>().await {
                    if let Some(obj) = price_json.get(&cg_coin_id) {
                        let usd = obj.get("usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        if usd > 0.0 && usd.is_finite() {
                            canonical_price = usd;
                            canonical_change = obj
                                .get("usd_24h_change")
                                .and_then(|v| v.as_f64())
                                .unwrap_or(0.0);
                        }
                    }
                }
            }
        }
    }
    let mut valid_quotes: Vec<f64> = Vec::new();
    if canonical_price > 0.0 {
        valid_quotes.push(canonical_price);
    }
    let mexc_url = format!(
        "https://api.mexc.com/api/v3/ticker/24hr?symbol={}USDT",
        clean
    );
    let gate_url = format!(
        "https://api.gateio.ws/api/v4/spot/tickers?currency_pair={}_USDT",
        clean
    );
    let kucoin_url = format!(
        "https://api.kucoin.com/api/v1/market/stats?symbol={}-USDT",
        clean
    );
    let (mexc_res, gate_res, kucoin_res) = tokio::join!(
        client.get(&mexc_url).send(),
        client.get(&gate_url).send(),
        client.get(&kucoin_url).send()
    );
    if let Ok(resp) = mexc_res {
        if resp.status().is_success() {
            if let Ok(d) = resp.json::<Value>().await {
                let last = d
                    .get("lastPrice")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let vol = d
                    .get("quoteVolume")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let bid = d
                    .get("bidPrice")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let ask = d
                    .get("askPrice")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let spread_ok = bid <= 0.0
                    || ask < bid
                    || ((ask - bid) / ask) <= MAX_DISCOVERY_CEX_SPREAD_RATIO;
                let canon_ok = canonical_price <= 0.0
                    || ((last - canonical_price).abs() / canonical_price)
                        <= MAX_CANONICAL_DEVIATION_RATIO;
                if last > 0.0 && vol >= MIN_DISCOVERY_CEX_VOLUME_USD && spread_ok && canon_ok {
                    valid_quotes.push(last);
                }
            }
        }
    }
    if let Ok(resp) = gate_res {
        if resp.status().is_success() {
            if let Ok(raw) = resp.json::<Value>().await {
                let d = if let Some(arr) = raw.as_array() {
                    arr.first().cloned().unwrap_or(Value::Null)
                } else {
                    raw
                };
                let last = d
                    .get("last")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let vol = d
                    .get("quote_volume")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let bid = d
                    .get("highest_bid")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let ask = d
                    .get("lowest_ask")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let spread_ok = bid <= 0.0
                    || ask < bid
                    || ((ask - bid) / ask) <= MAX_DISCOVERY_CEX_SPREAD_RATIO;
                let canon_ok = canonical_price <= 0.0
                    || ((last - canonical_price).abs() / canonical_price)
                        <= MAX_CANONICAL_DEVIATION_RATIO;
                if last > 0.0 && vol >= MIN_DISCOVERY_CEX_VOLUME_USD && spread_ok && canon_ok {
                    valid_quotes.push(last);
                }
            }
        }
    }
    if let Ok(resp) = kucoin_res {
        if resp.status().is_success() {
            if let Ok(raw) = resp.json::<Value>().await {
                let last = raw
                    .pointer("/data/last")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let vol = raw
                    .pointer("/data/volValue")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let bid = raw
                    .pointer("/data/buy")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let ask = raw
                    .pointer("/data/sell")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let spread_ok = bid <= 0.0
                    || ask < bid
                    || ((ask - bid) / ask) <= MAX_DISCOVERY_CEX_SPREAD_RATIO;
                let canon_ok = canonical_price <= 0.0
                    || ((last - canonical_price).abs() / canonical_price)
                        <= MAX_CANONICAL_DEVIATION_RATIO;
                if last > 0.0 && vol >= MIN_DISCOVERY_CEX_VOLUME_USD && spread_ok && canon_ok {
                    valid_quotes.push(last);
                }
            }
        }
    }
    if valid_quotes.is_empty() {
        return Err(format!(
            "ORACLE_HALT: Live oracle spot price for {} is offline. Failing closed (503).",
            clean
        ));
    }
    valid_quotes.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = valid_quotes.len() / 2;
    let resolved_spot = if valid_quotes.len() % 2 == 0 {
        (valid_quotes[mid - 1] + valid_quotes[mid]) / 2.0
    } else {
        valid_quotes[mid]
    };
    if !resolved_spot.is_finite() || resolved_spot <= 0.0 {
        return Err(format!(
            "ORACLE_HALT: Live oracle spot price for {} is offline. Failing closed (503).",
            clean
        ));
    }
    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(r_client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = r_client.get_multiplexed_async_connection().await {
                let _: redis::RedisResult<()> = redis::cmd("SADD")
                    .arg("oracle:dynamic_tickers")
                    .arg(&clean)
                    .query_async(&mut conn)
                    .await;
                let _: redis::RedisResult<()> = redis::cmd("SETEX")
                    .arg(format!("oracle:spot:{}_USDC", clean))
                    .arg(30u64)
                    .arg(resolved_spot.to_string())
                    .query_async(&mut conn)
                    .await;
                if !cg_coin_id.is_empty() {
                    let _: redis::RedisResult<()> = redis::cmd("SETEX")
                        .arg(format!("oracle:cg_id:{}", clean))
                        .arg(86_400u64)
                        .arg(&cg_coin_id)
                        .query_async(&mut conn)
                        .await;
                }
            }
        }
    }
    let _ = sqlx::query(
        r#"
        INSERT INTO rwa_oracle_feeds (ticker, asset_class, price_usd, change_24h_pct, oracle_source, updated_at)
        VALUES ($1, 'DYNAMIC_TOKEN', $2, $3, 'COINGECKO_CEX_QUORUM', CURRENT_TIMESTAMP)
        ON CONFLICT (ticker) DO UPDATE SET
            price_usd = EXCLUDED.price_usd,
            change_24h_pct = EXCLUDED.change_24h_pct,
            oracle_source = EXCLUDED.oracle_source,
            updated_at = CURRENT_TIMESTAMP
        "#,
    )
    .bind(&clean)
    .bind(resolved_spot)
    .bind(canonical_change)
    .execute(pool)
    .await;
    Ok(resolved_spot)
}

pub async fn resolve_live_spot_price(pool: &PgPool, asset_ticker: &str) -> Result<f64, String> {
    match crate::state_api::resolve_strict_spot_price(pool, asset_ticker).await {
        Ok(p) if p.is_finite() && p > 0.0 => Ok(p),
        _ => discover_and_cache_canonical_spot_price(pool, asset_ticker).await,
    }
}

fn resolve_changenow_currency_and_network(ticker: &str) -> (String, &'static str, i32) {
    let clean = ticker.trim().to_uppercase();
    match clean.as_str() {
        "KAS" => ("kas".to_string(), "kas", 10),
        "BTC" => ("btc".to_string(), "btc", 2),
        "ETH" => ("eth".to_string(), "eth", 6),
        "SOL" => ("sol".to_string(), "sol", 12),
        "USDC" => ("usdc".to_string(), "eth", 6),
        "USDT" => ("usdt".to_string(), "eth", 6),
        "XRP" => ("xrp".to_string(), "xrp", 4),
        "DOGE" => ("doge".to_string(), "doge", 6),
        "POL" => ("pol".to_string(), "matic", 12),
        "AVAX" => ("avax".to_string(), "cchain", 12),
        "SUI" => ("sui".to_string(), "sui", 12),
        "TRX" => ("trx".to_string(), "trx", 12),
        "ZEC" => ("zec".to_string(), "zec", 6),
        "ARB" => ("arb".to_string(), "arbitrum", 12),
        "BASE" => ("eth".to_string(), "base", 12),
        "TON" => ("ton".to_string(), "ton", 6),
        "ADA" => ("ada".to_string(), "ada", 6),
        "LINK" => ("link".to_string(), "eth", 6),
        "LTC" => ("ltc".to_string(), "ltc", 4),
        "HYPE" => ("hype".to_string(), "hyperliquid", 6),
        "XAU" => ("paxg".to_string(), "eth", 6),
        other => (other.to_lowercase(), "eth", 6),
    }
}

pub async fn fetch_changenow_min_amount(
    from_ticker: &str,
    to_ticker: &str,
) -> Result<f64, String> {
    let api_key = env::var("CHANGENOW_API_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "CHANGENOW_API_KEY_MISSING: Configure CHANGENOW_API_KEY in .env for live min-amount queries."
                .to_string()
        })?;
    let (from_cur, from_net, _) = resolve_changenow_currency_and_network(from_ticker);
    let (to_cur, to_net, _) = resolve_changenow_currency_and_network(to_ticker);
    if from_cur == to_cur && from_net == to_net {
        return Ok(1.0);
    }
    let url = format!(
        "https://api.changenow.io/v2/exchange/min-amount?fromCurrency={}&toCurrency={}&fromNetwork={}&toNetwork={}&flow=standard",
        from_cur, to_cur, from_net, to_net
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let res = client
        .get(&url)
        .header("x-changenow-api-key", api_key)
        .send()
        .await
        .map_err(|e| format!("ChangeNOW v2 min-amount request failed: {}", e))?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        return Err(format!(
            "ChangeNOW v2 min-amount rejected ({}): {}",
            status, body
        ));
    }
    let data: Value = res
        .json()
        .await
        .map_err(|e| format!("Invalid ChangeNOW v2 min-amount JSON: {}", e))?;
    let min_amount = data
        .get("minAmount")
        .and_then(|v| {
            v.as_f64()
                .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
        })
        .filter(|&v| v > 0.0)
        .ok_or_else(|| "ChangeNOW v2 returned 0 minAmount.".to_string())?;
    Ok(min_amount)
}

pub async fn resolve_live_profitable_bucket_threshold(
    pool: &PgPool,
    target_ticker: &str,
    kas_spot_usd: f64,
) -> (f64, f64) {
    let clean = target_ticker.trim().to_uppercase();
    let safe_kas_spot = if kas_spot_usd.is_finite() && kas_spot_usd > 0.0 {
        kas_spot_usd
    } else {
        resolve_live_spot_price(pool, "KAS")
            .await
            .unwrap_or(0.15)
            .max(0.01)
    };
    if clean == "USD" {
        let min_usd = 25.28;
        let min_kas = ((min_usd / safe_kas_spot) * 10.0).ceil() / 10.0;
        return (min_kas, round_cents(min_kas * safe_kas_spot));
    }
    if clean == "SILO" || clean == "NACHO" || clean == "BEDRCK" || clean == "PERX" {
        let min_usd = 3.50;
        let min_kas = ((min_usd / safe_kas_spot) * 10.0).ceil() / 10.0;
        return (min_kas, round_cents(min_kas * safe_kas_spot));
    }
    let cache_key = format!("perennia:changenow:min_kas:{}", clean);
    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                if let Ok(Some(cached_str)) = redis::cmd("GET")
                    .arg(&cache_key)
                    .query_async::<_, Option<String>>(&mut conn)
                    .await
                {
                    if let Ok(cached_kas) = cached_str.parse::<f64>() {
                        if cached_kas.is_finite() && cached_kas > 0.0 {
                            let min_usd = round_cents(cached_kas * safe_kas_spot);
                            return (cached_kas, min_usd);
                        }
                    }
                }
            }
        }
    }
    let base_bridge_min_kas = match fetch_changenow_min_amount("KAS", &clean).await {
        Ok(live_min_kas) if live_min_kas.is_finite() && live_min_kas > 0.0 => live_min_kas,
        _ => {
            let min_bridge_usd = match clean.as_str() {
                "BTC" => 22.0,
                "ETH" | "XAU" | "XAG" | "USTB" | "USDT" => 14.0,
                "USDC" | "SOL" | "ARB" | "BASE" | "POL" | "AVAX" => 6.5,
                "SPY" | "QQQ" | "NVDA" | "AAPL" | "TSLA" | "AMD" | "TSM" | "AVGO" | "XLE" => 8.5,
                _ => 5.5,
            };
            min_bridge_usd / safe_kas_spot
        }
    };
    let margin_kas = 0.50 / safe_kas_spot;
    let profitable_min_kas = (((base_bridge_min_kas * 1.015) + margin_kas) * 10.0).ceil() / 10.0;
    let profitable_min_usd = round_cents(profitable_min_kas * safe_kas_spot);
    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let _: redis::RedisResult<()> = redis::cmd("SETEX")
                    .arg(&cache_key)
                    .arg(180u64)
                    .arg(format!("{:.4}", profitable_min_kas))
                    .query_async(&mut conn)
                    .await;
            }
        }
    }
    (profitable_min_kas, profitable_min_usd)
}

pub async fn fetch_changenow_estimated_amount(
    from_ticker: &str,
    to_ticker: &str,
    from_amount: f64,
) -> Result<f64, String> {
    let api_key = env::var("CHANGENOW_API_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "CHANGENOW_API_KEY_MISSING: Configure CHANGENOW_API_KEY in .env for live exchange quotes."
                .to_string()
        })?;
    let (from_cur, from_net, _) = resolve_changenow_currency_and_network(from_ticker);
    let (to_cur, to_net, _) = resolve_changenow_currency_and_network(to_ticker);
    if from_cur == to_cur && from_net == to_net {
        return Ok(from_amount);
    }
    let url = format!(
        "https://api.changenow.io/v2/exchange/estimated-amount?fromCurrency={}&toCurrency={}&fromAmount={:.8}&fromNetwork={}&toNetwork={}&flow=standard",
        from_cur, to_cur, from_amount, from_net, to_net
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(6))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let res = client
        .get(&url)
        .header("x-changenow-api-key", api_key)
        .send()
        .await
        .map_err(|e| format!("ChangeNOW v2 quote request failed: {}", e))?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        return Err(format!(
            "ChangeNOW v2 quote rejected ({}): {}",
            status, body
        ));
    }
    let data: Value = res
        .json()
        .await
        .map_err(|e| format!("Invalid ChangeNOW v2 quote JSON: {}", e))?;
    let raw_to_amount = data
        .get("toAmount")
        .and_then(|v| {
            v.as_f64()
                .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
        })
        .filter(|&v| v > 0.0)
        .ok_or_else(|| "ChangeNOW v2 returned 0 toAmount.".to_string())?;
    let withdrawal_fee = data
        .get("withdrawalFee")
        .and_then(|v| {
            v.as_f64()
                .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
        })
        .unwrap_or(0.0)
        .max(0.0);
    let _ = withdrawal_fee;
    Ok(raw_to_amount)
}

pub async fn create_changenow_exchange_order(
    from_ticker: &str,
    to_ticker: &str,
    from_amount: f64,
    payout_address: &str,
    refund_address: Option<&str>,
) -> Result<(String, String, String, i32), String> {
    let api_key = env::var("CHANGENOW_API_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "CHANGENOW_API_KEY_MISSING: Configure CHANGENOW_API_KEY in .env to generate live deposit addresses."
                .to_string()
        })?;
    let (from_cur, from_net, confs_req) = resolve_changenow_currency_and_network(from_ticker);
    let (to_cur, to_net, _) = resolve_changenow_currency_and_network(to_ticker);
    let mut payload = json!({
        "fromCurrency": from_cur,
        "toCurrency": to_cur,
        "fromNetwork": from_net,
        "toNetwork": to_net,
        "fromAmount": format!("{:.8}", from_amount),
        "address": payout_address.trim(),
        "flow": "standard"
    });
    if let Some(refund) = refund_address.filter(|r| !r.trim().is_empty()) {
        payload["refundAddress"] = json!(refund.trim());
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let res = client
        .post("https://api.changenow.io/v2/exchange")
        .header("x-changenow-api-key", api_key)
        .header("content-type", "application/json")
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("ChangeNOW v2 exchange creation failed: {}", e))?;
    if !res.status().is_success() {
        let status = res.status();
        let err_body = res.text().await.unwrap_or_default();
        return Err(format!(
            "ChangeNOW v2 exchange creation rejected ({}): {}",
            status, err_body
        ));
    }
    let data: Value = res
        .json()
        .await
        .map_err(|e| format!("Malformed ChangeNOW v2 exchange response: {}", e))?;
    let exchange_id = data
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "ChangeNOW v2 response missing exchange id.".to_string())?
        .to_string();
    let payin_address = data
        .get("payinAddress")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "ChangeNOW v2 response missing payinAddress.".to_string())?
        .to_string();
    let route_label = format!(
        "CHANGENOW_V2_LIVE_{}_TO_{}",
        from_cur.to_uppercase(),
        to_cur.to_uppercase()
    );
    Ok((exchange_id, payin_address, route_label, confs_req))
}

pub fn compute_post_trade_usd_allocation(gross_usd: f64) -> PostTradeUsdAllocation {
    let safe_gross = gross_usd.max(0.0);
    let wholesale_api_float_sweep_usd = round_cents(safe_gross * 0.485);
    let chronos_miner_settlement_usd = round_cents(safe_gross * 0.490);
    let llc_tax_and_rail_reserve_usd = round_cents(safe_gross * 0.007);
    let net_profit_and_ratchet_usd = round_cents(
        (safe_gross
            - wholesale_api_float_sweep_usd
            - chronos_miner_settlement_usd
            - llc_tax_and_rail_reserve_usd)
            .max(safe_gross * 0.018),
    );
    // Internal Treasury 60/40 Reserve Split:
    // 60% into Perennia-owned LP positions to compound (`float_ratchet_reinvest_usd`),
    // 40% into liquid USD/stablecoin clearing reserve (`dark_pool_lp_and_owner_draw_usd`)
    let float_ratchet_reinvest_usd = round_cents(net_profit_and_ratchet_usd * 0.60);
    let dark_pool_lp_and_owner_draw_usd =
        round_cents((net_profit_and_ratchet_usd - float_ratchet_reinvest_usd).max(0.0));
    PostTradeUsdAllocation {
        gross_inbound_usd: round_cents(safe_gross),
        wholesale_api_float_sweep_usd,
        chronos_miner_settlement_usd,
        llc_tax_and_rail_reserve_usd,
        net_profit_and_ratchet_usd,
        float_ratchet_reinvest_usd,
        dark_pool_lp_and_owner_draw_usd,
    }
}

pub fn calculate_onramp_cost_plus_quote(
    asset_ticker: &str,
    gross_usd: f64,
    spot_price_usd: f64,
    payment_rail: &str,
    settlement_target: &str,
    auto_stake_silo: bool,
    bundled_kas_or_silo: bool,
) -> CostPlusQuoteBreakdown {
    let ticker = asset_ticker.trim().to_uppercase();
    let gross = gross_usd.max(10.0);
    let is_whale_wire = gross >= 2_500.0;
    let is_mid_tier = gross >= 1_000.0 && gross < 2_500.0;
    let is_silo_or_kas_bundle = auto_stake_silo
        || bundled_kas_or_silo
        || settlement_target.eq_ignore_ascii_case("AUTO_STAKE_SILO");
    let bundled_usdc_fee_waived = ticker == "USDC" && is_silo_or_kas_bundle;
    let hard_profit_floor_usd = round_cents((gross * HARD_PROFIT_FLOOR_PCT).max(0.01));
    let (base_hard_cost, raw_base_profit, competitor_fee, routing_topology) =
        if bundled_usdc_fee_waived {
            let comp = round_cents((gross * 0.035).max(5.0));
            (
                0.0,
                hard_profit_floor_usd,
                comp,
                "WHOLESALE_0_10_PCT_FLOOR_USDC_BUNDLE_TO_KAS_SILO_VAULT".to_string(),
            )
        } else if is_whale_wire {
            let scale = gross / 2_500.0;
            let hard_cost = round_cents(4.0 * scale);
            let net_profit = round_cents((gross * 0.015).max(22.0 * scale));
            let comp = round_cents(gross * 0.035 + 15.0);
            (
                hard_cost,
                net_profit,
                comp,
                if ticker == "KAS" || ticker == "SILO" {
                    "LOCAL_CHRONOS_MINER_REPAR_WHALE_WIRE".to_string()
                } else {
                    "CHANGENOW_V2_SINGLE_HOP_DROPSHIP".to_string()
                },
            )
        } else if is_mid_tier {
            if ticker == "USDC" {
                let hard_cost = round_cents(gross * 0.0005);
                let net_profit = round_cents(gross * 0.0040);
                let comp = round_cents(gross * 0.025);
                (
                    hard_cost,
                    net_profit,
                    comp,
                    "CHANGENOW_V2_L2_BASE_USDC_DROPSHIP".to_string(),
                )
            } else {
                let hard_cost = if ticker == "KAS" || ticker == "SILO" {
                    round_cents(gross * 0.002)
                } else if ticker == "BTC" {
                    round_cents(4.0 * (gross / 1_000.0).max(1.0))
                } else {
                    round_cents(3.0 * (gross / 1_000.0).max(1.0))
                };
                let net_profit = round_cents(gross * 0.015);
                let comp = round_cents(gross * 0.034);
                (
                    hard_cost,
                    net_profit,
                    comp,
                    if ticker == "KAS" || ticker == "SILO" {
                        "LOCAL_CHRONOS_MINER_REPAR_NETTING".to_string()
                    } else {
                        "CHANGENOW_V2_SINGLE_HOP_DROPSHIP".to_string()
                    },
                )
            }
        } else {
            match ticker.as_str() {
                "KAS" | "SILO" => {
                    let hard_cost = round_cents(gross * 0.002);
                    let net_profit = round_cents(gross * 0.018);
                    let comp = round_cents(gross * 0.034);
                    (
                        hard_cost,
                        net_profit,
                        comp,
                        "LOCAL_CHRONOS_MINER_REPAR_0_PCT_EXCHANGE_FEE".to_string(),
                    )
                }
                "BTC" => {
                    let scale = (gross / 100.0).max(1.0);
                    let hard_cost = round_cents(4.0 + (scale - 1.0) * 1.25);
                    let net_profit = round_cents(3.0 * scale);
                    let comp = round_cents(9.0 * scale);
                    (
                        hard_cost,
                        net_profit,
                        comp,
                        "CHANGENOW_V2_SINGLE_HOP_BTC_DROPSHIP".to_string(),
                    )
                }
                "ETH" | "SOL" => {
                    let scale = gross / 100.0;
                    let hard_cost = round_cents(1.50 * scale);
                    let net_profit = round_cents(1.50 * scale);
                    let comp = round_cents(6.00 * scale);
                    (
                        hard_cost,
                        net_profit,
                        comp,
                        format!("CHANGENOW_V2_SINGLE_HOP_{}_DROPSHIP", ticker),
                    )
                }
                "USDC" | "USDT" => {
                    let scale = (gross / 100.0).max(1.0);
                    let hard_cost = round_cents(0.35 * scale);
                    let net_profit = round_cents(1.65 * scale);
                    let comp = round_cents(5.00 * scale);
                    (
                        hard_cost,
                        net_profit,
                        comp,
                        "CHANGENOW_V2_USDC_DROPSHIP".to_string(),
                    )
                }
                _ => {
                    let scale = gross / 100.0;
                    let hard_cost = round_cents(1.50 * scale);
                    let net_profit = round_cents(1.50 * scale);
                    let comp = round_cents(6.00 * scale);
                    (
                        hard_cost,
                        net_profit,
                        comp,
                        format!("CHANGENOW_V2_SINGLE_HOP_{}_DROPSHIP", ticker),
                    )
                }
            }
        };
    let base_profit = raw_base_profit.max(hard_profit_floor_usd);
    let quoted_guest_fee_usd = round_cents(base_hard_cost + base_profit);
    let effective_fee_pct = if gross > 0.0 {
        round_cents((quoted_guest_fee_usd / gross) * 100.0)
    } else {
        0.0
    };
    let guest_net_usd = round_cents((gross - quoted_guest_fee_usd).max(0.0));
    let competitor_net_usd = round_cents((gross - competitor_fee).max(0.0));
    let guest_savings_vs_competitor_usd =
        round_cents((competitor_fee - quoted_guest_fee_usd).max(0.0));
    let (circuit_breaker_tripped, circuit_breaker_reason) = if !spot_price_usd.is_finite()
        || spot_price_usd <= 0.0
    {
        (
            true,
            Some(format!(
                "CIRCUIT_BREAKER_TRIPPED: Live oracle spot price for {} is offline; failing closed.",
                ticker
            )),
        )
    } else if base_profit < hard_profit_floor_usd {
        (
            true,
            Some(format!(
                "CIRCUIT_BREAKER_TRIPPED: Guaranteed net profit (${:.2}) fell below the 0.10% hard floor (${:.2}); failing closed.",
                base_profit, hard_profit_floor_usd
            )),
        )
    } else if quoted_guest_fee_usd > competitor_fee && competitor_fee > 0.0 {
        (
            true,
            Some(format!(
                "CIRCUIT_BREAKER_TRIPPED: Quoted_Guest_Fee (${:.2}) exceeded Competitor Ceiling (${:.2}); failing closed.",
                quoted_guest_fee_usd, competitor_fee
            )),
        )
    } else {
        (false, None)
    };
    let estimated_tokens = if spot_price_usd > 0.0 {
        ((guest_net_usd / spot_price_usd) * 100_000_000.0).round() / 100_000_000.0
    } else {
        0.0
    };
    let resolved_rail = if is_whale_wire {
        "SOVEREIGN_WHALE_FEDWIRE_WAIVED".to_string()
    } else if payment_rail.trim().is_empty() {
        "FREE_ACH_CLEARING".to_string()
    } else {
        payment_rail.trim().to_uppercase()
    };
    CostPlusQuoteBreakdown {
        direction: "ONRAMP".to_string(),
        asset_ticker: ticker,
        gross_usd: round_cents(gross),
        hard_execution_and_repar_cost_usd: base_hard_cost,
        guaranteed_net_profit_usd: base_profit,
        quoted_guest_fee_usd,
        effective_fee_pct,
        protocol_fee_floor_pct: 0.10,
        miner_or_pass_discount_active: true,
        guest_net_usd,
        estimated_tokens,
        spot_price_usd,
        competitor_fee_usd: competitor_fee,
        competitor_net_usd,
        guest_savings_vs_competitor_usd,
        routing_topology,
        bank_rail: resolved_rail,
        whale_wire_fee_waived: is_whale_wire,
        bundled_usdc_fee_waived,
        circuit_breaker_tripped,
        circuit_breaker_reason,
    }
}

pub fn calculate_offramp_cost_plus_quote(
    asset_ticker: &str,
    gross_usd: f64,
    spot_price_usd: f64,
    payout_method: &str,
) -> CostPlusQuoteBreakdown {
    let ticker = asset_ticker.trim().to_uppercase();
    let gross = gross_usd.max(10.0);
    let is_whale_wire = gross >= 2_500.0 || payout_method.eq_ignore_ascii_case("WIRE");
    let hard_profit_floor_usd = round_cents((gross * HARD_PROFIT_FLOOR_PCT).max(0.01));
    let (base_hard_cost, raw_base_profit, competitor_fee, routing_topology) = if is_whale_wire
        && gross >= 2_500.0
    {
        let scale = gross / 2_500.0;
        let hard_cost = round_cents(6.0 * scale);
        let net_profit = round_cents(24.0 * scale);
        let comp = round_cents(63.0 * scale);
        (
            hard_cost,
            net_profit,
            comp,
            if ticker == "KAS" || ticker == "SILO" {
                "LOCAL_MASTER_TREASURY_VAULT_REFILL_PLUS_FEDWIRE".to_string()
            } else {
                "CHANGENOW_V2_PAYIN_ADDRESS_PLUS_FEDWIRE".to_string()
            },
        )
    } else {
        match ticker.as_str() {
            "KAS" | "SILO" => {
                let scale = gross / 500.0;
                let hard_cost = round_cents((0.25 * scale).max(0.25));
                let total_target_fee = round_cents(9.0 * scale);
                let net_profit = round_cents((total_target_fee - hard_cost).max(1.0));
                let comp = round_cents(15.0 * scale);
                (
                    hard_cost,
                    net_profit,
                    comp,
                    "LOCAL_MASTER_TREASURY_VAULT_REFILL_0_PCT_EXCHANGE_FEE".to_string(),
                )
            }
            "BTC" => {
                let scale = gross / 100.0;
                let hard_cost = round_cents(1.0 * scale);
                let net_profit = round_cents(2.0 * scale);
                let comp = round_cents(4.0 * scale);
                (
                    hard_cost,
                    net_profit,
                    comp,
                    "CHANGENOW_V2_BTC_PAYIN_ADDRESS".to_string(),
                )
            }
            "ETH" | "SOL" => {
                let scale = gross / 200.0;
                let hard_cost = round_cents(2.0 * scale);
                let net_profit = round_cents(3.0 * scale);
                let comp = round_cents(7.0 * scale);
                (
                    hard_cost,
                    net_profit,
                    comp,
                    format!("CHANGENOW_V2_{}_PAYIN_ADDRESS", ticker),
                )
            }
            "USDC" | "USDT" => {
                let hard_cost = round_cents(gross * 0.0005);
                let net_profit = round_cents(gross * 0.0045);
                let comp = round_cents(gross * 0.015);
                (
                    hard_cost,
                    net_profit,
                    comp,
                    "CHANGENOW_V2_USDC_PAYIN_ADDRESS".to_string(),
                )
            }
            _ => {
                let scale = gross / 200.0;
                let hard_cost = round_cents(2.0 * scale);
                let net_profit = round_cents(3.0 * scale);
                let comp = round_cents(7.0 * scale);
                (
                    hard_cost,
                    net_profit,
                    comp,
                    format!("CHANGENOW_V2_{}_PAYIN_ADDRESS", ticker),
                )
            }
        }
    };
    let base_profit = raw_base_profit.max(hard_profit_floor_usd);
    let quoted_guest_fee_usd = round_cents(base_hard_cost + base_profit);
    let effective_fee_pct = if gross > 0.0 {
        round_cents((quoted_guest_fee_usd / gross) * 100.0)
    } else {
        0.0
    };
    let guest_net_usd = round_cents((gross - quoted_guest_fee_usd).max(0.0));
    let competitor_net_usd = round_cents((gross - competitor_fee).max(0.0));
    let guest_savings_vs_competitor_usd =
        round_cents((competitor_fee - quoted_guest_fee_usd).max(0.0));
    let (circuit_breaker_tripped, circuit_breaker_reason) = if !spot_price_usd.is_finite()
        || spot_price_usd <= 0.0
    {
        (
            true,
            Some(format!(
                "CIRCUIT_BREAKER_TRIPPED: Live oracle spot price for {} is offline; failing closed.",
                ticker
            )),
        )
    } else if base_profit < hard_profit_floor_usd {
        (
            true,
            Some(format!(
                "CIRCUIT_BREAKER_TRIPPED: Off-ramp guaranteed net profit (${:.2}) fell below the 0.10% hard floor (${:.2}); failing closed.",
                base_profit, hard_profit_floor_usd
            )),
        )
    } else if quoted_guest_fee_usd > competitor_fee && competitor_fee > 0.0 {
        (
            true,
            Some(format!(
                "CIRCUIT_BREAKER_TRIPPED: Off-ramp Quoted_Guest_Fee (${:.2}) exceeded Competitor Ceiling (${:.2}); failing closed.",
                quoted_guest_fee_usd, competitor_fee
            )),
        )
    } else {
        (false, None)
    };
    let estimated_tokens = if spot_price_usd > 0.0 {
        ((gross / spot_price_usd) * 100_000_000.0).round() / 100_000_000.0
    } else {
        0.0
    };
    let resolved_rail = if is_whale_wire && gross >= 2_500.0 {
        "SAME_DAY_WHALE_FEDWIRE".to_string()
    } else {
        "FREE_COMMERCIAL_ACH".to_string()
    };
    CostPlusQuoteBreakdown {
        direction: "OFFRAMP".to_string(),
        asset_ticker: ticker,
        gross_usd: round_cents(gross),
        hard_execution_and_repar_cost_usd: base_hard_cost,
        guaranteed_net_profit_usd: base_profit,
        quoted_guest_fee_usd,
        effective_fee_pct,
        protocol_fee_floor_pct: 0.10,
        miner_or_pass_discount_active: true,
        guest_net_usd,
        estimated_tokens,
        spot_price_usd,
        competitor_fee_usd: competitor_fee,
        competitor_net_usd,
        guest_savings_vs_competitor_usd,
        routing_topology,
        bank_rail: resolved_rail,
        whale_wire_fee_waived: is_whale_wire && gross >= 2_500.0,
        bundled_usdc_fee_waived: false,
        circuit_breaker_tripped,
        circuit_breaker_reason,
    }
}

pub async fn resolve_live_offramp_deposit_coordinates(
    pool: &PgPool,
    asset_ticker: &str,
    amount_crypto: f64,
    refund_wallet: &str,
) -> Result<(String, String, i32, Option<String>), String> {
    let clean = asset_ticker.trim().to_uppercase();
    let sys_cfg = crate::chronos::load_system_treasury_config(pool).await;
    let master_kas = if !sys_cfg.cold_kas_address.trim().is_empty() {
        sys_cfg.cold_kas_address.trim().to_string()
    } else {
        crate::chronos::resolve_master_treasury_prefixed()?
    };
    if clean == "KAS" || clean == "SILO" {
        return Ok((
            master_kas,
            "LOCAL_PERENNIA_NODE_MASTER_TREASURY".to_string(),
            10,
            None,
        ));
    }
    let (exchange_id, payin_address, route_label, confs_req) = create_changenow_exchange_order(
        &clean,
        "KAS",
        amount_crypto,
        &master_kas,
        Some(refund_wallet),
    )
    .await?;
    Ok((payin_address, route_label, confs_req, Some(exchange_id)))
}

pub async fn load_or_init_bootstrap_float(pool: &PgPool) -> BootstrapFloatState {
    let master_treasury_wallet =
        crate::chronos::resolve_master_treasury_prefixed().unwrap_or_default();
    let row_opt = sqlx::query(
        r#"
        SELECT local_kas_reserve_usd, local_kas_target_cap_usd,
               wholesale_api_working_usd, wholesale_api_target_cap_usd,
               ratchet_target_cap_usd, commercial_checking_cleared_usd,
               llc_tax_escrow_reserve_usd, dark_pool_lp_vault_usd
        FROM fiat_float_ledger
        WHERE ledger_id IN ('BOOTSTRAP_PRIMARY', 'PRIMARY_FLOAT')
        ORDER BY updated_at DESC
        LIMIT 1
        "#,
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    if let Some(r) = row_opt {
        let local_kas: f64 = r
            .try_get("local_kas_reserve_usd")
            .unwrap_or(INITIAL_LOCAL_KAS_FLOAT_USD);
        let local_cap: f64 = r
            .try_get("local_kas_target_cap_usd")
            .unwrap_or(INITIAL_LOCAL_KAS_FLOAT_USD);
        let api_usd: f64 = r
            .try_get("wholesale_api_working_usd")
            .unwrap_or(INITIAL_WHOLESALE_API_USD_FLOAT);
        let api_cap: f64 = r
            .try_get("wholesale_api_target_cap_usd")
            .unwrap_or(INITIAL_WHOLESALE_API_USD_FLOAT);
        let ratchet_cap: f64 = r
            .try_get("ratchet_target_cap_usd")
            .unwrap_or(TARGET_RATCHET_FLOAT_CAP_USD);
        let checking_usd: f64 = r
            .try_get("commercial_checking_cleared_usd")
            .unwrap_or(1_500.0);
        let tax_usd: f64 = r.try_get("llc_tax_escrow_reserve_usd").unwrap_or(0.0);
        let lp_usd: f64 = r.try_get("dark_pool_lp_vault_usd").unwrap_or(0.0);
        return BootstrapFloatState {
            local_kas_reserve_usd: round_cents(local_kas),
            local_kas_target_cap_usd: round_cents(local_cap),
            wholesale_api_working_usd: round_cents(api_usd),
            wholesale_api_target_cap_usd: round_cents(api_cap),
            combined_float_usd: round_cents(local_kas + api_usd),
            ratchet_target_cap_usd: round_cents(ratchet_cap),
            commercial_checking_cleared_usd: round_cents(checking_usd),
            llc_tax_escrow_reserve_usd: round_cents(tax_usd),
            dark_pool_lp_vault_usd: round_cents(lp_usd),
            master_treasury_wallet,
            updated_at: Utc::now().to_rfc3339(),
        };
    }
    let _ = sqlx::query(
        r#"
        INSERT INTO fiat_float_ledger (
            ledger_id, local_kas_reserve_usd, local_kas_target_cap_usd,
            wholesale_api_working_usd, wholesale_api_target_cap_usd,
            ratchet_target_cap_usd, commercial_checking_cleared_usd,
            llc_tax_escrow_reserve_usd, dark_pool_lp_vault_usd
        ) VALUES ('BOOTSTRAP_PRIMARY', $1, $1, $2, $2, $3, 1500.0, 0.0, 0.0)
        ON CONFLICT (ledger_id) DO NOTHING
        "#,
    )
    .bind(INITIAL_LOCAL_KAS_FLOAT_USD)
    .bind(INITIAL_WHOLESALE_API_USD_FLOAT)
    .bind(TARGET_RATCHET_FLOAT_CAP_USD)
    .execute(pool)
    .await;
    BootstrapFloatState {
        local_kas_reserve_usd: INITIAL_LOCAL_KAS_FLOAT_USD,
        local_kas_target_cap_usd: INITIAL_LOCAL_KAS_FLOAT_USD,
        wholesale_api_working_usd: INITIAL_WHOLESALE_API_USD_FLOAT,
        wholesale_api_target_cap_usd: INITIAL_WHOLESALE_API_USD_FLOAT,
        combined_float_usd: INITIAL_LOCAL_KAS_FLOAT_USD + INITIAL_WHOLESALE_API_USD_FLOAT,
        ratchet_target_cap_usd: TARGET_RATCHET_FLOAT_CAP_USD,
        commercial_checking_cleared_usd: 1_500.0,
        llc_tax_escrow_reserve_usd: 0.0,
        dark_pool_lp_vault_usd: 0.0,
        master_treasury_wallet,
        updated_at: Utc::now().to_rfc3339(),
    }
}

pub async fn update_bootstrap_float_caps(
    pool: &PgPool,
    payload: &Value,
) -> Result<BootstrapFloatState, String> {
    let current = load_or_init_bootstrap_float(pool).await;
    let local_kas_target_cap_usd = payload
        .get("localKasTargetCapUsd")
        .and_then(|v| v.as_f64())
        .unwrap_or(current.local_kas_target_cap_usd)
        .max(50.0);
    let wholesale_api_target_cap_usd = payload
        .get("wholesaleApiTargetCapUsd")
        .and_then(|v| v.as_f64())
        .unwrap_or(current.wholesale_api_target_cap_usd)
        .max(50.0);
    let ratchet_target_cap_usd = payload
        .get("ratchetTargetCapUsd")
        .and_then(|v| v.as_f64())
        .unwrap_or(current.ratchet_target_cap_usd)
        .max(local_kas_target_cap_usd + wholesale_api_target_cap_usd);
    let local_kas_reserve_usd = payload
        .get("localKasReserveUsd")
        .and_then(|v| v.as_f64())
        .unwrap_or(current.local_kas_reserve_usd)
        .max(0.0);
    let wholesale_api_working_usd = payload
        .get("wholesaleApiWorkingUsd")
        .and_then(|v| v.as_f64())
        .unwrap_or(current.wholesale_api_working_usd)
        .max(0.0);
    let commercial_checking_cleared_usd = payload
        .get("commercialCheckingClearedUsd")
        .and_then(|v| v.as_f64())
        .unwrap_or(current.commercial_checking_cleared_usd)
        .max(0.0);
    sqlx::query(
        r#"
        UPDATE fiat_float_ledger
        SET local_kas_reserve_usd = $1,
            local_kas_target_cap_usd = $2,
            wholesale_api_working_usd = $3,
            wholesale_api_target_cap_usd = $4,
            ratchet_target_cap_usd = $5,
            commercial_checking_cleared_usd = $6,
            updated_at = CURRENT_TIMESTAMP
        WHERE ledger_id IN ('BOOTSTRAP_PRIMARY', 'PRIMARY_FLOAT')
        "#,
    )
    .bind(round_cents(local_kas_reserve_usd))
    .bind(round_cents(local_kas_target_cap_usd))
    .bind(round_cents(wholesale_api_working_usd))
    .bind(round_cents(wholesale_api_target_cap_usd))
    .bind(round_cents(ratchet_target_cap_usd))
    .bind(round_cents(commercial_checking_cleared_usd))
    .execute(pool)
    .await
    .map_err(|e| format!("Failed to update fiat_float_ledger caps: {}", e))?;
    Ok(load_or_init_bootstrap_float(pool).await)
}

pub async fn apply_onramp_post_trade_sweep(
    pool: &PgPool,
    order_id: &str,
    asset_ticker: &str,
    gross_usd: f64,
) -> BootstrapFloatState {
    let sweep = compute_post_trade_usd_allocation(gross_usd);
    let current = load_or_init_bootstrap_float(pool).await;
    let combined_cap = current.local_kas_target_cap_usd + current.wholesale_api_target_cap_usd;
    let ratchet_headroom = (current.ratchet_target_cap_usd - combined_cap).max(0.0);
    let applied_ratchet = sweep.float_ratchet_reinvest_usd.min(ratchet_headroom);
    let next_local_cap = round_cents(current.local_kas_target_cap_usd + applied_ratchet * 0.55);
    let next_api_cap = round_cents(current.wholesale_api_target_cap_usd + applied_ratchet * 0.45);
    let next_local_kas = if asset_ticker.eq_ignore_ascii_case("KAS")
        || asset_ticker.eq_ignore_ascii_case("SILO")
    {
        round_cents(
            (current.local_kas_reserve_usd + sweep.chronos_miner_settlement_usd * 0.05)
                .min(next_local_cap),
        )
    } else {
        current.local_kas_reserve_usd
    };
    let next_api_usd =
        round_cents((current.wholesale_api_working_usd + applied_ratchet * 0.45).min(next_api_cap));
    // 60% into Perennia-owned LP positions to compound (`float_ratchet_reinvest_usd`),
    // 40% into liquid USD/stablecoin clearing reserve (`dark_pool_lp_and_owner_draw_usd`)
    let next_checking_usd = round_cents(
        current.commercial_checking_cleared_usd + sweep.dark_pool_lp_and_owner_draw_usd,
    );
    let next_tax_usd =
        round_cents(current.llc_tax_escrow_reserve_usd + sweep.llc_tax_and_rail_reserve_usd);
    let next_lp_usd =
        round_cents(current.dark_pool_lp_vault_usd + sweep.float_ratchet_reinvest_usd);
    let _ = sqlx::query(
        r#"
        UPDATE fiat_float_ledger
        SET local_kas_reserve_usd = $1,
            local_kas_target_cap_usd = $2,
            wholesale_api_working_usd = $3,
            wholesale_api_target_cap_usd = $4,
            commercial_checking_cleared_usd = $5,
            llc_tax_escrow_reserve_usd = $6,
            dark_pool_lp_vault_usd = $7,
            master_treasury_usdc_reserve = COALESCE(master_treasury_usdc_reserve, 0.0) + $8,
            updated_at = CURRENT_TIMESTAMP
        WHERE ledger_id IN ('BOOTSTRAP_PRIMARY', 'PRIMARY_FLOAT')
        "#,
    )
    .bind(next_local_kas)
    .bind(next_local_cap)
    .bind(next_api_usd)
    .bind(next_api_cap)
    .bind(next_checking_usd)
    .bind(next_tax_usd)
    .bind(next_lp_usd)
    .bind(sweep.dark_pool_lp_and_owner_draw_usd)
    .execute(pool)
    .await;
    let _ = sqlx::query(
        r#"
        INSERT INTO fiat_post_trade_sweeps (
            order_id, direction, asset_ticker, gross_usd,
            wholesale_api_float_sweep_usd, chronos_miner_settlement_usd,
            llc_tax_and_rail_reserve_usd, net_profit_and_ratchet_usd,
            float_ratchet_reinvest_usd, dark_pool_lp_and_owner_draw_usd
        ) VALUES ($1, 'ONRAMP', $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(order_id)
    .bind(asset_ticker.trim().to_uppercase())
    .bind(sweep.gross_inbound_usd)
    .bind(sweep.wholesale_api_float_sweep_usd)
    .bind(sweep.chronos_miner_settlement_usd)
    .bind(sweep.llc_tax_and_rail_reserve_usd)
    .bind(sweep.net_profit_and_ratchet_usd)
    .bind(sweep.float_ratchet_reinvest_usd)
    .bind(sweep.dark_pool_lp_and_owner_draw_usd)
    .execute(pool)
    .await;
    load_or_init_bootstrap_float(pool).await
}

pub async fn apply_offramp_two_way_rebalance(
    pool: &PgPool,
    payout_id: &str,
    asset_ticker: &str,
    gross_usd: f64,
    net_fiat_usd: f64,
    net_profit_usd: f64,
) -> (BootstrapFloatState, String) {
    let current = load_or_init_bootstrap_float(pool).await;
    let clean = asset_ticker.trim().to_uppercase();
    let (next_local_kas, next_api_usd, rebalance_action) = if clean == "KAS" || clean == "SILO" {
        let room_in_local_vault =
            (current.local_kas_target_cap_usd - current.local_kas_reserve_usd).max(0.0);
        let retained_locally = gross_usd.min(room_in_local_vault);
        let overflow_to_exchange = (gross_usd - retained_locally).max(0.0);
        let action_desc = if overflow_to_exchange > 0.0 {
            format!(
                "LOCAL_VAULT_REFILLED_${:.2}_OVERFLOW_${:.2}_FORWARDED_TO_WHOLESALE_API",
                retained_locally, overflow_to_exchange
            )
        } else {
            format!(
                "RETAINED_100_PCT_${:.2}_IN_LOCAL_MASTER_TREASURY_0_PCT_EXCHANGE_FEE",
                retained_locally
            )
        };
        (
            round_cents(current.local_kas_reserve_usd + retained_locally),
            round_cents(current.wholesale_api_working_usd + overflow_to_exchange),
            action_desc,
        )
    } else {
        (
            current.local_kas_reserve_usd,
            round_cents(current.wholesale_api_working_usd + gross_usd),
            format!(
                "WHOLESALE_API_USD_FLOAT_AUTO_REFILLED_BY_${:.2}_{}_LIQUIDATION",
                gross_usd, clean
            ),
        )
    };
    let lp_compound_60 = round_cents(net_profit_usd.max(0.0) * 0.60);
    let liquid_reserve_40 = round_cents(net_profit_usd.max(0.0) * 0.40);
    let next_checking = round_cents(
        (current.commercial_checking_cleared_usd - net_fiat_usd + liquid_reserve_40).max(250.0),
    );
    let _ = sqlx::query(
        r#"
        UPDATE fiat_float_ledger
        SET local_kas_reserve_usd = $1,
            wholesale_api_working_usd = $2,
            wholesale_api_target_cap_usd = LEAST(ratchet_target_cap_usd, wholesale_api_target_cap_usd + $3),
            commercial_checking_cleared_usd = $4,
            dark_pool_lp_vault_usd = dark_pool_lp_vault_usd + $3,
            master_treasury_usdc_reserve = COALESCE(master_treasury_usdc_reserve, 0.0) + $5,
            updated_at = CURRENT_TIMESTAMP
        WHERE ledger_id IN ('BOOTSTRAP_PRIMARY', 'PRIMARY_FLOAT')
        "#,
    )
    .bind(next_local_kas)
    .bind(next_api_usd)
    .bind(lp_compound_60)
    .bind(next_checking)
    .bind(liquid_reserve_40)
    .execute(pool)
    .await;
    let _ = sqlx::query(
        r#"
        INSERT INTO fiat_post_trade_sweeps (
            order_id, direction, asset_ticker, gross_usd,
            wholesale_api_float_sweep_usd, chronos_miner_settlement_usd,
            llc_tax_and_rail_reserve_usd, net_profit_and_ratchet_usd,
            float_ratchet_reinvest_usd, dark_pool_lp_and_owner_draw_usd
        ) VALUES ($1, 'OFFRAMP', $2, $3, $4, 0.0, 0.0, $5, $6, $7)
        "#,
    )
    .bind(payout_id)
    .bind(&clean)
    .bind(round_cents(gross_usd))
    .bind(round_cents(gross_usd))
    .bind(round_cents(net_profit_usd))
    .bind(lp_compound_60)
    .bind(liquid_reserve_40)
    .execute(pool)
    .await;
    (load_or_init_bootstrap_float(pool).await, rebalance_action)
}

pub fn fiat_routes() -> Router<PgPool> {
    Router::new()
        .route(
            "/v1/fiat/quote",
            get(handle_get_fiat_quote).post(handle_post_fiat_quote),
        )
        .route("/v1/fiat/onramp", post(handle_create_onramp_order))
        .route("/v1/fiat/offramp", post(handle_create_offramp_order))
        .route(
            "/v1/fiat/float",
            get(handle_get_bootstrap_float).post(handle_update_bootstrap_float),
        )
        .route("/v1/fiat/webhook", post(handle_authenticated_webhook))
}

async fn handle_get_fiat_quote(
    State(pool): State<PgPool>,
    Query(params): Query<QuoteQueryParams>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let direction = params
        .direction
        .as_deref()
        .unwrap_or("ONRAMP")
        .trim()
        .to_uppercase();
    let asset = params
        .asset
        .as_deref()
        .unwrap_or("KAS")
        .trim()
        .to_uppercase();
    let spot = match resolve_live_spot_price(&pool, &asset).await {
        Ok(p) => p,
        Err(err) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "success": false,
                    "circuitBreakerTripped": true,
                    "error": err
                })),
            ));
        }
    };
    let gross_usd = params
        .amount_usd
        .or_else(|| params.amount_tokens.map(|t| t * spot))
        .unwrap_or(500.0)
        .max(10.0);
    let rail = params
        .payment_rail
        .as_deref()
        .unwrap_or("SOVEREIGN_WIRE_ACH");
    let method = params.payment_method.as_deref().unwrap_or("ach");
    let target = params
        .settlement_target
        .as_deref()
        .unwrap_or("SELF_CUSTODY_WALLET");
    let auto_stake = params.auto_stake_silo.unwrap_or(false);
    let bundled = params.bundled_kas_or_silo.unwrap_or(false);
    let (floor_rate, tier_label, discount_active) =
        resolve_wallet_swap_fee_floor_pct(&pool, params.wallet.as_deref().unwrap_or("")).await;
    let mut quote = if direction == "OFFRAMP" || direction == "SELL" {
        calculate_offramp_cost_plus_quote(&asset, gross_usd, spot, rail)
    } else {
        calculate_onramp_cost_plus_quote(
            &asset, gross_usd, spot, rail, target, auto_stake, bundled,
        )
    };
    quote.protocol_fee_floor_pct = (floor_rate * 10000.0).round() / 100.0;
    quote.miner_or_pass_discount_active = discount_active;
    if !quote.circuit_breaker_tripped && asset != "KAS" && asset != "SILO" && asset != "USDC" {
        if direction != "OFFRAMP" && direction != "SELL" {
            if let Ok(cn_est) =
                fetch_changenow_estimated_amount("USDC", &asset, quote.guest_net_usd).await
            {
                if cn_est > 0.0 {
                    let capped_out = cn_est.min(quote.estimated_tokens);
                    quote.estimated_tokens =
                        (capped_out * 100_000_000.0).round() / 100_000_000.0;
                }
            }
        }
    }
    if quote.circuit_breaker_tripped {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "success": false,
                "circuitBreakerTripped": true,
                "error": quote.circuit_breaker_reason,
                "quote": quote
            })),
        ));
    }
    let gross_up = calculate_gateway_gross_up_cents(
        (gross_usd * 100.0).round() as i64,
        discount_active,
        method,
    );
    let post_trade_allocation = compute_post_trade_usd_allocation(gross_usd);
    Ok(Json(json!({
        "success": true,
        "feeTierLabel": tier_label,
        "quote": quote,
        "gatewayGrossUp": gross_up,
        "mercuryWireCoordinates": {
            "beneficiaryName": "Perennia, LLC",
            "bankName": MERCURY_COLUMN_BANK_NAME,
            "routingNumber": MERCURY_COLUMN_ABA_ROUTING,
            "accountNumber": MERCURY_COLUMN_ACCOUNT_NUMBER
        },
        "postTradeAllocation": post_trade_allocation
    })))
}

async fn handle_post_fiat_quote(
    State(pool): State<PgPool>,
    Json(params): Json<QuoteQueryParams>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    handle_get_fiat_quote(State(pool), Query(params)).await
}

async fn handle_get_bootstrap_float(
    State(pool): State<PgPool>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let float_state = load_or_init_bootstrap_float(&pool).await;
    Ok(Json(json!({
        "success": true,
        "float": float_state
    })))
}

async fn handle_update_bootstrap_float(
    headers: HeaderMap,
    State(pool): State<PgPool>,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    verify_director_or_webhook_headers(&headers)?;
    match update_bootstrap_float_caps(&pool, &payload).await {
        Ok(updated) => Ok(Json(json!({
            "success": true,
            "float": updated
        }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": e })),
        )),
    }
}

async fn handle_create_onramp_order(
    State(pool): State<PgPool>,
    Json(req): Json<OnrampOrderRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let clean_wallet = req
        .wallet_address
        .trim()
        .to_lowercase()
        .replace("kaspa:", "")
        .trim()
        .to_string();
    if clean_wallet.len() < 55 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "INVALID_KASPA_ADDRESS: Valid Kaspa wallet required." })),
        ));
    }
    let prefixed_wallet = format!("kaspa:{}", clean_wallet);
    let target_asset = req
        .target_asset
        .as_deref()
        .unwrap_or("KAS")
        .trim()
        .to_uppercase();

    check_fiat_killswitch_and_firewall(&clean_wallet, &prefixed_wallet, &target_asset).await?;

    let payment_rail = req
        .payment_rail
        .as_deref()
        .unwrap_or("SOVEREIGN_WIRE_ACH")
        .trim()
        .to_uppercase();
    let payment_method = req
        .payment_method
        .as_deref()
        .unwrap_or(if req.fiat_amount_usd >= 100_000.0 {
            "wire"
        } else {
            "ach"
        })
        .trim()
        .to_lowercase();
    let auto_stake_silo = req.auto_stake_silo.unwrap_or(false) && target_asset == "SILO";
    let bundled_kas_or_silo = req.bundled_kas_or_silo.unwrap_or(false) || auto_stake_silo;
    let settlement_target = if auto_stake_silo {
        "AUTO_STAKE_SILO".to_string()
    } else {
        req.settlement_target
            .as_deref()
            .unwrap_or("L1_SELF_CUSTODY")
            .trim()
            .to_uppercase()
    };
    let kas_spot = match resolve_live_spot_price(&pool, "KAS").await {
        Ok(p) => p,
        Err(e) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "success": false, "circuitBreakerTripped": true, "error": e })),
            ));
        }
    };
    let target_spot = match resolve_live_spot_price(&pool, &target_asset).await {
        Ok(p) => p,
        Err(e) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "success": false, "circuitBreakerTripped": true, "error": e })),
            ));
        }
    };
    let (floor_rate, tier_label, discount_active) =
        resolve_wallet_swap_fee_floor_pct(&pool, &prefixed_wallet).await;
    let mut quote = calculate_onramp_cost_plus_quote(
        &target_asset,
        req.fiat_amount_usd,
        target_spot,
        &payment_rail,
        &settlement_target,
        auto_stake_silo,
        bundled_kas_or_silo,
    );
    quote.protocol_fee_floor_pct = (floor_rate * 10000.0).round() / 100.0;
    quote.miner_or_pass_discount_active = discount_active;
    if quote.circuit_breaker_tripped {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "success": false,
                "circuitBreakerTripped": true,
                "error": quote.circuit_breaker_reason,
                "quote": quote
            })),
        ));
    }
    if target_asset != "KAS" && target_asset != "SILO" && target_asset != "USDC" {
        match fetch_changenow_estimated_amount("USDC", &target_asset, quote.guest_net_usd).await {
            Ok(cn_est) if cn_est > 0.0 => {
                let capped_out = cn_est.min(quote.estimated_tokens);
                quote.estimated_tokens = (capped_out * 100_000_000.0).round() / 100_000_000.0;
            }
            Err(cn_err) => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "success": false,
                        "circuitBreakerTripped": true,
                        "error": cn_err
                    })),
                ));
            }
            _ => {}
        }
    }

    let gross_up = calculate_gateway_gross_up_cents(
        (req.fiat_amount_usd * 100.0).round() as i64,
        discount_active,
        &payment_method,
    );

    let order_id = format!(
        "PER-ONRAMP-{}",
        &Uuid::new_v4().simple().to_string().to_uppercase()[..6]
    );
    let estimated_kas = if kas_spot > 0.0 {
        ((quote.guest_net_usd / kas_spot) * 10_000.0).round() / 10_000.0
    } else {
        0.0
    };
    let post_trade_sweep = compute_post_trade_usd_allocation(quote.gross_usd);
    let destination_wallet = req
        .destination_wallet_address
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&prefixed_wallet)
        .to_string();
    let wholesale_order_id = if target_asset == "KAS" || target_asset == "SILO" {
        format!("CHRONOS-REPAR-{}", &order_id[11..])
    } else {
        format!("CHANGENOW-V2-{}", &order_id[11..])
    };
    let wholesale_withdraw_id = if target_asset == "KAS" || target_asset == "SILO" {
        format!("LOCAL-VAULT-UTXO-{}", &order_id[11..])
    } else {
        format!("DROPSHIP-WD-{}", &order_id[11..])
    };
    let status = if gross_up.requires_institutional_wire {
        "AWAITING_INSTITUTIONAL_WIRE"
    } else {
        "AWAITING_WIRE_RECEIPT"
    };
    let sweep_json = serde_json::to_value(&post_trade_sweep).unwrap_or_else(|_| json!({}));

    let _ = sqlx::query(
        r#"
        INSERT INTO fiat_onramp_orders (
            order_id, wallet_address, payment_rail, payment_method, tier_name, tier_bps,
            settlement_target, target_asset, target_spot_price, estimated_tokens, auto_stake_silo,
            quoted_principal_cents, perennia_fee_cents, stripe_gateway_fee_cents, gross_charge_cents,
            fiat_amount_usd, fee_usd, hard_cost_usd, guaranteed_profit_usd,
            competitor_fee_usd, guest_savings_usd, net_usd_converted,
            locked_spot_price, estimated_kas, delivered_kas, wire_memo,
            routing_topology, wholesale_order_id, wholesale_withdraw_id,
            bridge_wire_routing, bridge_wire_account,
            master_treasury_fee_usdc, post_trade_sweep_json, status
        ) VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9, $10, $11,
            $12, $13, $14, $15,
            $16, $17, $18, $19,
            $20, $21, $22,
            $23, $24, 0.0, $1,
            $25, $26, $27,
            $28, $29,
            $17, $30, $31
        )
        "#,
    )
    .bind(&order_id)
    .bind(&prefixed_wallet)
    .bind(&quote.bank_rail)
    .bind(&gross_up.payment_method)
    .bind(&gross_up.tier_name)
    .bind(gross_up.tier_bps as i32)
    .bind(&settlement_target)
    .bind(&target_asset)
    .bind(target_spot)
    .bind(quote.estimated_tokens)
    .bind(auto_stake_silo)
    .bind(gross_up.principal_cents)
    .bind(gross_up.perennia_fee_cents)
    .bind(gross_up.stripe_gateway_fee_cents)
    .bind(gross_up.gross_charge_cents)
    .bind(quote.gross_usd)
    .bind(quote.quoted_guest_fee_usd)
    .bind(quote.hard_execution_and_repar_cost_usd)
    .bind(quote.guaranteed_net_profit_usd)
    .bind(quote.competitor_fee_usd)
    .bind(quote.guest_savings_vs_competitor_usd)
    .bind(quote.guest_net_usd)
    .bind(kas_spot)
    .bind(estimated_kas)
    .bind(&quote.routing_topology)
    .bind(&wholesale_order_id)
    .bind(&wholesale_withdraw_id)
    .bind(MERCURY_COLUMN_ABA_ROUTING)
    .bind(MERCURY_COLUMN_ACCOUNT_NUMBER)
    .bind(&sweep_json)
    .bind(status)
    .execute(&pool)
    .await;

    let updated_float = load_or_init_bootstrap_float(&pool).await;
    Ok(Json(json!({
        "success": true,
        "sessionId": order_id,
        "orderId": order_id,
        "walletAddress": prefixed_wallet,
        "destinationWalletAddress": destination_wallet,
        "targetAsset": target_asset,
        "targetSpotPrice": target_spot,
        "spotPrice": kas_spot,
        "fiatAmountUsd": quote.gross_usd,
        "feeUsd": quote.quoted_guest_fee_usd,
        "hardCostUsd": quote.hard_execution_and_repar_cost_usd,
        "guaranteedProfitUsd": quote.guaranteed_net_profit_usd,
        "protocolFeeFloorPct": quote.protocol_fee_floor_pct,
        "feeTierLabel": tier_label,
        "minerOrPassDiscountActive": discount_active,
        "competitorFeeUsd": quote.competitor_fee_usd,
        "guestSavingsUsd": quote.guest_savings_vs_competitor_usd,
        "netUsdConverted": quote.guest_net_usd,
        "estimatedKas": estimated_kas,
        "estimatedTokens": quote.estimated_tokens,
        "autoStakeSilo": auto_stake_silo,
        "whaleWireFeeWaived": quote.whale_wire_fee_waived,
        "bundledUsdcFeeWaived": quote.bundled_usdc_fee_waived,
        "paymentRail": quote.bank_rail,
        "settlementTarget": settlement_target,
        "routingTopology": quote.routing_topology,
        "wholesaleOrderId": wholesale_order_id,
        "wholesaleWithdrawId": wholesale_withdraw_id,
        "wireMemo": order_id,
        "gatewayGrossUp": gross_up,
        "wireInstructions": {
            "beneficiaryName": "Perennia, LLC",
            "bankName": MERCURY_COLUMN_BANK_NAME,
            "routingNumber": MERCURY_COLUMN_ABA_ROUTING,
            "accountNumber": MERCURY_COLUMN_ACCOUNT_NUMBER,
            "wireMemo": order_id
        },
        "stageIndex": 1,
        "status": status,
        "txHash": Value::Null,
        "postTradeAllocation": post_trade_sweep,
        "bootstrapFloat": updated_float
    })))
}

async fn handle_create_offramp_order(
    State(pool): State<PgPool>,
    Json(req): Json<OfframpOrderRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let clean_wallet = req
        .wallet_address
        .trim()
        .to_lowercase()
        .replace("kaspa:", "")
        .trim()
        .to_string();
    let prefixed_wallet = format!("kaspa:{}", clean_wallet);
    let source_asset = req.source_asset.trim().to_uppercase();
    let spot = match resolve_live_spot_price(&pool, &source_asset).await {
        Ok(p) => p,
        Err(e) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "success": false, "circuitBreakerTripped": true, "error": e })),
            ));
        }
    };
    let gross_usd = req
        .gross_usd
        .or_else(|| req.amount_crypto.map(|amt| amt * spot))
        .unwrap_or(500.0)
        .max(10.0);
    let amount_crypto = req
        .amount_crypto
        .unwrap_or_else(|| if spot > 0.0 { gross_usd / spot } else { 0.0 });
    let payout_method = req
        .payout_method
        .as_deref()
        .unwrap_or(if gross_usd >= 2_500.0 { "WIRE" } else { "ACH" })
        .trim()
        .to_uppercase();
    let quote = calculate_offramp_cost_plus_quote(&source_asset, gross_usd, spot, &payout_method);
    if quote.circuit_breaker_tripped {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "success": false,
                "circuitBreakerTripped": true,
                "error": quote.circuit_breaker_reason,
                "quote": quote
            })),
        ));
    }
    let (deposit_address, deposit_route_type, confirmations_required, changenow_exchange_id) =
        match resolve_live_offramp_deposit_coordinates(
            &pool,
            &source_asset,
            amount_crypto,
            &prefixed_wallet,
        )
        .await
        {
            Ok(coords) => coords,
            Err(err) => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "success": false,
                        "circuitBreakerTripped": true,
                        "error": err
                    })),
                ));
            }
        };
    let payout_id = format!(
        "PER-OFFRAMP-{}",
        &Uuid::new_v4().simple().to_string().to_uppercase()[..6]
    );
    let bank_last4 = req
        .bank_last4
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "BANK_RAIL_REQUIRED: Link your bank account before generating an Off-Ramp Settlement Pass."
                })),
            )
        })?
        .to_string();
    let status = "AWAITING_ONCHAIN_CONFIRMATIONS";
    let _ = sqlx::query(
        r#"
        INSERT INTO fiat_payout_queue (
            payout_id, wallet_address, source_type, source_asset,
            amount_crypto, gross_usd, fee_usd, hard_cost_usd,
            guaranteed_profit_usd, competitor_fee_usd, guest_savings_usd,
            net_fiat_usd, payout_method, bank_last4, deposit_address,
            changenow_exchange_id, routing_topology, confirmations_required,
            confirmations_current, tx_id, status
        ) VALUES (
            $1, $2, $3, $4,
            $5, $6, $7, $8,
            $9, $10, $11,
            $12, $13, $14, $15,
            $16, $17, $18,
            0, $19, $20
        )
        "#,
    )
    .bind(&payout_id)
    .bind(&prefixed_wallet)
    .bind(&deposit_route_type)
    .bind(&source_asset)
    .bind(amount_crypto)
    .bind(quote.gross_usd)
    .bind(quote.quoted_guest_fee_usd)
    .bind(quote.hard_execution_and_repar_cost_usd)
    .bind(quote.guaranteed_net_profit_usd)
    .bind(quote.competitor_fee_usd)
    .bind(quote.guest_savings_vs_competitor_usd)
    .bind(quote.guest_net_usd)
    .bind(&payout_method)
    .bind(&bank_last4)
    .bind(&deposit_address)
    .bind(changenow_exchange_id.as_deref())
    .bind(&quote.routing_topology)
    .bind(confirmations_required)
    .bind(req.tx_id.as_deref())
    .bind(status)
    .execute(&pool)
    .await;
    let float_state = load_or_init_bootstrap_float(&pool).await;
    Ok(Json(json!({
        "success": true,
        "payoutId": payout_id,
        "wireReferenceId": payout_id,
        "walletAddress": prefixed_wallet,
        "sourceAsset": source_asset,
        "amountCrypto": amount_crypto,
        "spotPrice": spot,
        "grossUsd": quote.gross_usd,
        "feeUsd": quote.quoted_guest_fee_usd,
        "hardCostUsd": quote.hard_execution_and_repar_cost_usd,
        "guaranteedProfitUsd": quote.guaranteed_net_profit_usd,
        "competitorFeeUsd": quote.competitor_fee_usd,
        "guestSavingsUsd": quote.guest_savings_vs_competitor_usd,
        "netFiatPayout": quote.guest_net_usd,
        "payoutMethod": payout_method,
        "bankAccountLast4": bank_last4,
        "depositAddress": deposit_address,
        "changenowExchangeId": changenow_exchange_id,
        "depositRouteType": deposit_route_type,
        "routingTopology": quote.routing_topology,
        "confirmationsRequired": confirmations_required,
        "confirmationsCurrent": 0,
        "confirmationLockActive": true,
        "stageIndex": 1,
        "status": status,
        "bootstrapFloat": float_state
    })))
}

async fn handle_authenticated_webhook(
    headers: HeaderMap,
    State(pool): State<PgPool>,
    Json(req): Json<LiveWebhookRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    verify_director_or_webhook_headers(&headers)?;
    let evt = req.event_type.trim().to_uppercase();

    // STRICT ACH PROCESSING HOLD: Never release crypto on payment_intent.processing!
    if evt == "PAYMENT_INTENT_PROCESSING" || evt == "ACH_PROCESSING" {
        let order_id = req.order_id.as_deref().unwrap_or("").trim().to_string();
        if !order_id.is_empty() {
            let _ = sqlx::query(
                r#"
                UPDATE fiat_onramp_orders
                SET status = 'ACH_PROCESSING_HOLD',
                    updated_at = CURRENT_TIMESTAMP
                WHERE order_id = $1 AND status != 'COMPLETED'
                "#,
            )
            .bind(&order_id)
            .execute(&pool)
            .await;
        }
        return Ok(Json(json!({
            "success": true,
            "eventType": evt,
            "orderId": order_id,
            "heldForAchClearing": true,
            "status": "ACH_PROCESSING_HOLD"
        })));
    }

    if evt == "ACH_CLEARED"
        || evt == "WIRE_CLEARED"
        || evt == "CONFIRM_WIRE_RECEIPT"
        || evt == "PAYMENT_INTENT_SUCCEEDED"
    {
        let order_id = req.order_id.as_deref().unwrap_or("").trim().to_string();
        if order_id.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "orderId is required for ACH_CLEARED webhook" })),
            ));
        }
        let row_opt = sqlx::query(
            r#"
            SELECT wallet_address, target_asset, settlement_target, auto_stake_silo,
                   fiat_amount_usd, fee_usd, guaranteed_profit_usd, net_usd_converted,
                   estimated_tokens, estimated_kas,
                   COALESCE(quoted_principal_cents, 0) AS quoted_principal_cents,
                   COALESCE(perennia_fee_cents, 250) AS perennia_fee_cents
            FROM fiat_onramp_orders
            WHERE order_id = $1
            LIMIT 1
            "#,
        )
        .bind(&order_id)
        .fetch_optional(&pool)
        .await
        .ok()
        .flatten();
        let Some(row) = row_opt else {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({ "error": format!("On-ramp order {} not found", order_id) })),
            ));
        };
        let wallet_address: String = row.try_get("wallet_address").unwrap_or_default();
        let clean_wallet = wallet_address.trim().to_lowercase().replace("kaspa:", "");
        let prefixed_wallet = format!("kaspa:{}", clean_wallet);
        let target_asset: String = row
            .try_get("target_asset")
            .unwrap_or_else(|_| "KAS".to_string())
            .to_uppercase();
        let settlement_target: String = row
            .try_get("settlement_target")
            .unwrap_or_else(|_| "LEDGER_KAS".to_string())
            .to_uppercase();
        let auto_stake_silo: bool = row.try_get("auto_stake_silo").unwrap_or(false);
        let fiat_usd: f64 = row.try_get("fiat_amount_usd").unwrap_or(0.0);
        let fee_usd: f64 = row.try_get("fee_usd").unwrap_or(0.0);
        let guaranteed_profit_usd: f64 = row.try_get("guaranteed_profit_usd").unwrap_or(0.0);
        let raw_net_usd: f64 = row.try_get("net_usd_converted").unwrap_or(0.0);
        let prequoted_tokens: f64 = row.try_get("estimated_tokens").unwrap_or(0.0);
        let db_quoted_principal_cents: i64 = row.try_get("quoted_principal_cents").unwrap_or(0);
        let db_perennia_fee_cents: i64 = row.try_get("perennia_fee_cents").unwrap_or(250).max(250);

        let min_profit_floor = round_cents((fiat_usd * HARD_PROFIT_FLOOR_PCT).max(0.01));
        if guaranteed_profit_usd + 1e-6 < min_profit_floor
            && settlement_target != "AUTO_STAKE_SILO"
        {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error": "ZERO_LOSS_INVARIANT_VIOLATION: Order net profit margin is below the 0.10% hard floor; failing closed."
                })),
            ));
        }

        // Zero-Loss Principal Cap when settled_net_cents is provided
        let mut net_usd = raw_net_usd;
        let quoted_principal_cents = if db_quoted_principal_cents > 0 {
            db_quoted_principal_cents
        } else {
            (raw_net_usd * 100.0).round() as i64
        };
        let mut settled_net_cents = quoted_principal_cents + db_perennia_fee_cents;
        let mut fulfilled_principal_cents = quoted_principal_cents;

        if let Some(provided_net_cents) = req.settled_net_cents {
            settled_net_cents = provided_net_cents;
            let capped_principal_cents =
                quoted_principal_cents.min((provided_net_cents - db_perennia_fee_cents).max(0));
            fulfilled_principal_cents = capped_principal_cents;
            if provided_net_cents < quoted_principal_cents + db_perennia_fee_cents
                && (capped_principal_cents <= 0 || req.quarantine_on_shortfall.unwrap_or(false))
            {
                let q_reason = format!(
                    "Shortfall detected: settled_net_cents ({}) < target_net_cents ({})",
                    provided_net_cents,
                    quoted_principal_cents + db_perennia_fee_cents
                );
                let _ = sqlx::query(
                    r#"
                    UPDATE fiat_onramp_orders
                    SET status = 'QUARANTINED_SHORTFALL',
                        settled_net_cents = $2,
                        fulfilled_principal_cents = $3,
                        quarantine_reason = $4,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE order_id = $1
                    "#,
                )
                .bind(&order_id)
                .bind(settled_net_cents)
                .bind(fulfilled_principal_cents)
                .bind(&q_reason)
                .execute(&pool)
                .await;
                return Ok(Json(json!({
                    "success": true,
                    "quarantined": true,
                    "orderId": order_id,
                    "status": "QUARANTINED_SHORTFALL",
                    "settledNetCents": settled_net_cents,
                    "fulfilledPrincipalCents": fulfilled_principal_cents,
                    "quarantineReason": q_reason
                })));
            }
            net_usd = round_cents((capped_principal_cents as f64) / 100.0);
        }

        let live_spot = resolve_live_spot_price(&pool, &target_asset)
            .await
            .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": e }))))?;
        let kas_spot = resolve_live_spot_price(&pool, "KAS")
            .await
            .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": e }))))?;
        let mut delivered_tokens =
            ((net_usd / live_spot) * 100_000_000.0).round() / 100_000_000.0;
        if target_asset != "KAS" && target_asset != "SILO" && target_asset != "USDC" {
            if let Ok(cn_net) =
                fetch_changenow_estimated_amount("USDC", &target_asset, net_usd).await
            {
                if cn_net > 0.0 {
                    delivered_tokens = delivered_tokens.min(cn_net);
                }
            }
            if prequoted_tokens > 0.0 && fulfilled_principal_cents == quoted_principal_cents {
                delivered_tokens = delivered_tokens.min(prequoted_tokens);
            }
            delivered_tokens = (delivered_tokens * 100_000_000.0).round() / 100_000_000.0;
        }
        let delivered_kas = ((net_usd / kas_spot) * 10_000.0).round() / 10_000.0;
        let tx_hash = req.tx_hash.unwrap_or_else(|| {
            format!(
                "DROPSHIP-{}-{}",
                target_asset,
                &Uuid::new_v4().simple().to_string().to_uppercase()[..8]
            )
        });
        if auto_stake_silo && target_asset == "SILO" {
            let _ = sqlx::query(
                r#"
                INSERT INTO silo_staking_positions (wallet_address, token_ticker, amount_staked, status, tx_hash)
                VALUES ($1, 'SILO', $2, 'ACTIVE', $3)
                "#,
            )
            .bind(&prefixed_wallet)
            .bind(delivered_tokens)
            .bind(&tx_hash)
            .execute(&pool)
            .await;
        } else {
            let _ = crate::state_api::credit_user_token_balance(
                &pool,
                &clean_wallet,
                &prefixed_wallet,
                &target_asset,
                delivered_tokens,
                false,
            )
            .await;
        }
        let _ = sqlx::query(
            r#"
            UPDATE fiat_onramp_orders
            SET status = 'COMPLETED',
                delivered_kas = $2,
                estimated_tokens = $3,
                target_spot_price = $4,
                tx_hash = $5,
                master_treasury_fee_usdc = $6,
                settled_net_cents = $7,
                fulfilled_principal_cents = $8,
                updated_at = CURRENT_TIMESTAMP
            WHERE order_id = $1
            "#,
        )
        .bind(&order_id)
        .bind(delivered_kas)
        .bind(delivered_tokens)
        .bind(live_spot)
        .bind(&tx_hash)
        .bind(fee_usd.max(0.0))
        .bind(settled_net_cents)
        .bind(fulfilled_principal_cents)
        .execute(&pool)
        .await;
        let unit_basis = if delivered_tokens > 0.0 {
            fiat_usd / delivered_tokens
        } else {
            live_spot
        };
        let _ = crate::sor::record_hifo_acquisition_lot(
            &pool,
            &clean_wallet,
            &target_asset,
            delivered_tokens,
            unit_basis,
            "FIAT_ONRAMP",
            Some(&tx_hash),
        )
        .await;
        let updated_float =
            apply_onramp_post_trade_sweep(&pool, &order_id, &target_asset, fiat_usd).await;
        let sweep_allocation = compute_post_trade_usd_allocation(fiat_usd);
        return Ok(Json(json!({
            "success": true,
            "eventType": evt,
            "orderId": order_id,
            "status": "COMPLETED",
            "stageIndex": 4,
            "executionLockedOnClearing": true,
            "targetAsset": target_asset,
            "deliveredTokens": delivered_tokens,
            "deliveredKas": delivered_kas,
            "settledNetCents": settled_net_cents,
            "fulfilledPrincipalCents": fulfilled_principal_cents,
            "executionSpotUsd": live_spot,
            "txHash": tx_hash,
            "postTradeAllocation": sweep_allocation,
            "bootstrapFloat": updated_float
        })));
    }
    if evt == "DEPOSIT_CONFIRMED" || evt == "FEDWIRE_DISPATCHED" || evt == "MARK_PAYOUT_DISPATCHED"
    {
        let payout_id = req.payout_id.as_deref().unwrap_or("").trim().to_string();
        if payout_id.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "payoutId is required for DEPOSIT_CONFIRMED webhook" })),
            ));
        }
        let row_opt = sqlx::query(
            r#"
            SELECT wallet_address, source_asset, amount_crypto, gross_usd,
                   fee_usd, guaranteed_profit_usd, net_fiat_usd,
                   confirmations_required
            FROM fiat_payout_queue
            WHERE payout_id = $1
            LIMIT 1
            "#,
        )
        .bind(&payout_id)
        .fetch_optional(&pool)
        .await
        .ok()
        .flatten();
        let Some(row) = row_opt else {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({ "error": format!("Off-ramp payout {} not found", payout_id) })),
            ));
        };
        let req_confs: i32 = row.try_get("confirmations_required").unwrap_or(6);
        let provided_confs = req.confirmations.unwrap_or(req_confs);
        if provided_confs < req_confs {
            let _ = sqlx::query(
                r#"
                UPDATE fiat_payout_queue
                SET confirmations_current = $2,
                    status = 'CONFIRMING_ONCHAIN_DEPOSIT',
                    updated_at = CURRENT_TIMESTAMP
                WHERE payout_id = $1
                "#,
            )
            .bind(&payout_id)
            .bind(provided_confs)
            .execute(&pool)
            .await;
            return Ok(Json(json!({
                "success": true,
                "payoutId": payout_id,
                "status": "CONFIRMING_ONCHAIN_DEPOSIT",
                "stageIndex": 2,
                "confirmationsCurrent": provided_confs,
                "confirmationsRequired": req_confs,
                "usdRateLocked": false
            })));
        }
        let source_asset: String = row
            .try_get("source_asset")
            .unwrap_or_else(|_| "KAS".to_string());
        let gross_usd: f64 = row.try_get("gross_usd").unwrap_or(0.0);
        let net_fiat_usd: f64 = row.try_get("net_fiat_usd").unwrap_or(0.0);
        let profit_usd: f64 = row.try_get("guaranteed_profit_usd").unwrap_or(2.0);
        let trace_id = req.trace_id.unwrap_or_else(|| {
            format!(
                "FED-ACH-{}",
                &Uuid::new_v4().simple().to_string().to_uppercase()[..8]
            )
        });
        let _ = sqlx::query(
            r#"
            UPDATE fiat_payout_queue
            SET confirmations_current = $2,
                trace_id = $3,
                status = 'DISPATCHED_BY_DIRECTOR',
                updated_at = CURRENT_TIMESTAMP
            WHERE payout_id = $1
            "#,
        )
        .bind(&payout_id)
        .bind(provided_confs)
        .bind(&trace_id)
        .execute(&pool)
        .await;
        let (updated_float, rebalance_action) = apply_offramp_two_way_rebalance(
            &pool,
            &payout_id,
            &source_asset,
            gross_usd,
            net_fiat_usd,
            profit_usd,
        )
        .await;
        return Ok(Json(json!({
            "success": true,
            "payoutId": payout_id,
            "status": "DISPATCHED_BY_DIRECTOR",
            "stageIndex": 4,
            "confirmationsCurrent": provided_confs,
            "confirmationsRequired": req_confs,
            "usdRateLocked": true,
            "traceId": trace_id,
            "rebalanceAction": rebalance_action,
            "bootstrapFloat": updated_float
        })));
    }
    Err((
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": format!("Unsupported webhook eventType: {}", evt) })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_onramp_900_instant_basket_cost_plus_math() {
        let kas_500 = calculate_onramp_cost_plus_quote(
            "KAS",
            500.0,
            0.15,
            "SOVEREIGN_WIRE_ACH",
            "L1_SELF_CUSTODY",
            false,
            false,
        );
        assert_eq!(kas_500.quoted_guest_fee_usd, 10.0);
        assert_eq!(kas_500.hard_execution_and_repar_cost_usd, 1.0);
        assert_eq!(kas_500.guaranteed_net_profit_usd, 9.0);
        assert_eq!(kas_500.guest_net_usd, 490.0);
        assert_eq!(kas_500.competitor_fee_usd, 17.0);

        let btc_100 = calculate_onramp_cost_plus_quote(
            "BTC",
            100.0,
            90_000.0,
            "SOVEREIGN_WIRE_ACH",
            "L1_SELF_CUSTODY",
            false,
            false,
        );
        assert_eq!(btc_100.quoted_guest_fee_usd, 7.0);
        assert_eq!(btc_100.hard_execution_and_repar_cost_usd, 4.0);
        assert_eq!(btc_100.guaranteed_net_profit_usd, 3.0);
        assert_eq!(btc_100.guest_net_usd, 93.0);
        assert_eq!(btc_100.competitor_fee_usd, 9.0);
    }

    #[test]
    fn verify_offramp_3300_volume_and_oracle_halt_breaker() {
        let kas_500 = calculate_offramp_cost_plus_quote("KAS", 500.0, 0.15, "ACH");
        let btc_100 = calculate_offramp_cost_plus_quote("BTC", 100.0, 90_000.0, "ACH");
        let eth_200 = calculate_offramp_cost_plus_quote("ETH", 200.0, 3_000.0, "ACH");
        let whale_2500 = calculate_offramp_cost_plus_quote("BTC", 2500.0, 90_000.0, "WIRE");
        assert_eq!(kas_500.quoted_guest_fee_usd, 9.0);
        assert_eq!(btc_100.quoted_guest_fee_usd, 3.0);
        assert_eq!(eth_200.quoted_guest_fee_usd, 5.0);
        assert_eq!(whale_2500.quoted_guest_fee_usd, 30.0);

        let split = compute_post_trade_usd_allocation(1_000.0);
        assert_eq!(split.wholesale_api_float_sweep_usd, 485.0);
        assert_eq!(split.chronos_miner_settlement_usd, 490.0);
        assert_eq!(split.llc_tax_and_rail_reserve_usd, 7.0);
        assert_eq!(split.net_profit_and_ratchet_usd, 18.0);

        let tripped = calculate_onramp_cost_plus_quote(
            "BTC",
            100.0,
            0.0,
            "SOVEREIGN_WIRE_ACH",
            "L1_SELF_CUSTODY",
            false,
            false,
        );
        assert!(tripped.circuit_breaker_tripped);
    }

    #[test]
    fn verify_gateway_gross_up_cents_math() {
        let ach_650 = calculate_gateway_gross_up_cents(65_000, false, "ach");
        assert_eq!(ach_650.tier_name, "RETAIL");
        assert_eq!(ach_650.perennia_fee_cents, 553);
        assert_eq!(ach_650.stripe_gateway_fee_cents, 500);
        assert_eq!(ach_650.gross_charge_cents, 66_053);

        let pro_miner_1000 = calculate_gateway_gross_up_cents(100_000, true, "ach");
        assert_eq!(pro_miner_1000.tier_name, "PRO_MINER");
        assert_eq!(pro_miner_1000.perennia_fee_cents, 350);
        assert_eq!(pro_miner_1000.stripe_gateway_fee_cents, 500);

        let wire_100k = calculate_gateway_gross_up_cents(10_000_000, false, "wire");
        assert_eq!(wire_100k.tier_name, "INSTITUTIONAL_WIRE");
        assert_eq!(wire_100k.perennia_fee_cents, 20_000);
        assert_eq!(wire_100k.stripe_gateway_fee_cents, 0);
        assert!(wire_100k.requires_institutional_wire);
    }
}