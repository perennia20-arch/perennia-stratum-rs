use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sqlx::{PgPool, Postgres, Row, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use reqwest::Client;
use chrono::{Datelike, NaiveDate, NaiveDateTime, Utc};
use uuid::Uuid;

const _NETWORK_FEE_PERCENTAGE: f64 = 0.005;
const _SECTOR_MINIMUM_THRESHOLD: f64 = 0.5;
const DEFAULT_UNASSIGNED_SETTLEMENT_THRESHOLD: f64 = 50.0;
const JERUSALEM_EPOCH_UTC_OFFSET_SECS: u64 = 22 * 3600;
const DAY_SECONDS: u64 = 86_400;
const DEFAULT_VOLATILITY_SWEEP_WEIGHT_PCT: f64 = 450.0;
const MIN_HOUSE_NET_MARGIN_RATE: f64 = 0.0025;
const EXTERNAL_CEX_TAKER_FEE_RATE: f64 = 0.0010;
const LONG_TAIL_PASSTHROUGH_FEE_RATE: f64 = 0.015;
const MIN_FIAT_ACH_BATCH_USD: f64 = 25.00;
const FIAT_ACH_RAIL_FEE_USD: f64 = 2.00;
const FIAT_WIRE_RAIL_FEE_USD: f64 = 15.00;
pub const KASPA_UNSPENDABLE_BURN_ADDRESS: &str =
    "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e";

const TRACKED_CORE_BUCKETS: [&str; 17] = [
    "USDC", "USD", "BTC", "ETH", "SOL",
    "SPY", "QQQ", "NVDA", "AAPL", "TSLA", "AMD", "TSM", "AVGO", "XLE",
    "XAU", "XAG", "USTB"
];

#[derive(Serialize, Deserialize, Debug)]
pub struct NettingOrder {
    pub wallet: String,
    pub direction: String,
    pub amount_kas: f64,
    pub spot_price: f64,
    pub fee_captured_usd: f64,
    pub target_asset: Option<String>,
    pub estimated_output: Option<f64>,
    #[serde(default)]
    pub pay_asset: Option<String>,
    #[serde(default)]
    pub pay_amount: Option<f64>,
    #[serde(default)]
    pub dust_fee_kas: Option<f64>,
    #[serde(default)]
    pub upfront_fee_kas: Option<f64>,
    #[serde(default)]
    pub net_passthrough_kas: Option<f64>,
    #[serde(default)]
    pub destination_l1_address: Option<String>,
}

#[derive(Default, Clone, Debug)]
struct PairBatchFlow {
    buy_kas: f64,
    sell_kas: f64,
    fee_usd: f64,
}

#[derive(Clone, Debug)]
struct SectorSwapParticipant {
    wallet_db_key: String,
    clean_wallet: String,
    prefixed_wallet: String,
    payout_address: String,
    sector_id: String,
    route_mode: String,
    #[allow(dead_code)]
    target_asset: String,
    plant_pair: String,
    plant_weights: HashMap<String, f64>,
    total_sector_pending_kas: f64,
    total_pending_kas: f64,
    swap_kas: f64,
    lp_pair_kas_half: f64,
    clear_appointment: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[allow(non_snake_case)]
pub struct AssetBucketTelemetry {
    pub asset: String,
    pub pendingKas: f64,
    pub pendingUsd: f64,
    pub minProfitableKas: f64,
    pub minProfitableUsd: f64,
    pub weightPct: f64,
    pub participantCount: usize,
    pub lpAvailableKasCapacity: f64,
    pub lpCoveragePct: f64,
    pub effectiveSpreadFloorPct: f64,
    pub railCostUsd: f64,
    pub status: String,
    pub lastClearedAt: u64,
    pub lastClearType: String,
}

fn normalize_kaspa_base32(addr: &str) -> String {
    addr.trim()
        .to_lowercase()
        .trim_start_matches("kaspa:")
        .trim()
        .to_string()
}

pub fn resolve_master_treasury_address() -> String {
    if let Ok(addr) = std::env::var("PERENNIA_TREASURY_KAS_ADDRESS") {
        let clean = normalize_kaspa_base32(&addr);
        if !clean.is_empty() {
            return clean;
        }
    }
    if let Ok(addr) = std::env::var("PERENNIA_HOT_KAS_ADDRESS") {
        let clean = normalize_kaspa_base32(&addr);
        if !clean.is_empty() {
            return clean;
        }
    }
    if let Ok(cfg) = crate::config::StratumConfig::load("config.yaml") {
        let clean = normalize_kaspa_base32(&cfg.mining_address);
        if !clean.is_empty() {
            return clean;
        }
    }
    String::new()
}

pub fn compute_jerusalem_epoch_window(now_secs: u64) -> (u64, u64, u64) {
    let day_start = now_secs - (now_secs % DAY_SECONDS);
    let today_bell = day_start + JERUSALEM_EPOCH_UTC_OFFSET_SECS;
    let (current_epoch_bell_ts, next_epoch_bell_ts) = if now_secs >= today_bell {
        (today_bell, today_bell + DAY_SECONDS)
    } else {
        (today_bell.saturating_sub(DAY_SECONDS), today_bell)
    };
    let seconds_remaining = next_epoch_bell_ts.saturating_sub(now_secs);
    (current_epoch_bell_ts, next_epoch_bell_ts, seconds_remaining)
}

fn get_volatility_sweep_threshold_pct() -> f64 {
    std::env::var("VOLATILITY_SWEEP_THRESHOLD_PCT")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|&v| v >= 200.0 && v <= 1000.0)
        .unwrap_or(DEFAULT_VOLATILITY_SWEEP_WEIGHT_PCT)
}

fn get_secure_client() -> Client {
    Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| Client::new())
}

fn extract_tax_escrow_config(user_state: &Value) -> (bool, f64, i32) {
    let Some(tf) = user_state.get("taxFortress") else {
        return (false, 0.0, 90);
    };
    let escrow_active = tf
        .get("escrowActive")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !escrow_active {
        return (false, 0.0, 90);
    }
    let raw_rate = tf
        .get("withholdingRate")
        .or_else(|| tf.get("effectiveTaxRate"))
        .and_then(|v| v.as_f64())
        .unwrap_or(15.0);
    let rate_fraction = if raw_rate > 1.0 {
        (raw_rate / 100.0).clamp(0.0, 0.50)
    } else if raw_rate > 0.0 {
        raw_rate.clamp(0.0, 0.50)
    } else {
        0.0
    };
    let entity_type = tf
        .get("entityType")
        .and_then(|v| v.as_str())
        .unwrap_or("LLC")
        .to_uppercase();
    let today = Utc::now().date_naive();
    let target_month = if entity_type == "S-CORP" || entity_type == "PARTNERSHIP" {
        3u32
    } else {
        4u32
    };
    let mut target_year = today.year();
    let mut candidate_date = NaiveDate::from_ymd_opt(target_year, target_month, 15)
        .unwrap_or(today);
    if candidate_date <= today {
        target_year += 1;
        candidate_date = NaiveDate::from_ymd_opt(target_year, target_month, 15)
            .unwrap_or(today);
    }
    if let Some(maturity_str) = tf.get("maturityDate").and_then(|v| v.as_str()) {
        if let Ok(parsed_date) = NaiveDate::parse_from_str(maturity_str.trim(), "%Y-%m-%d") {
            if parsed_date > today {
                candidate_date = parsed_date;
            }
        }
    }
    let days_until_maturity = (candidate_date - today).num_days().clamp(30, 365) as i32;
    (escrow_active && rate_fraction > 0.0, rate_fraction, days_until_maturity)
}

async fn route_tax_escrow_auto_lp(
    tx_db: &mut Transaction<'_, Postgres>,
    prefixed_wallet: &str,
    clean_wallet: &str,
    escrow_kas: f64,
    kas_price: f64,
    lock_days: i32,
) -> anyhow::Result<f64> {
    if escrow_kas <= 1e-8 || kas_price <= 0.0 {
        return Ok(0.0);
    }
    let escrow_usd = escrow_kas * kas_price;
    let kas_half = escrow_kas * 0.50;
    let usdc_half = escrow_usd * 0.50;
    let existing_lp = sqlx::query(
        "SELECT lp_id, staked_asset_a, staked_asset_b FROM liquidity_providers WHERE wallet_address = $1 AND pool_pair = 'KAS/USDC' AND lock_duration_days >= 30 ORDER BY created_at DESC LIMIT 1"
    )
    .bind(prefixed_wallet)
    .fetch_optional(&mut **tx_db)
    .await?;
    if let Some(lp_row) = existing_lp {
        let lp_id: Uuid = lp_row.get("lp_id");
        let cur_a: f64 = lp_row.try_get("staked_asset_a").unwrap_or(0.0);
        let cur_b: f64 = lp_row.try_get("staked_asset_b").unwrap_or(0.0);
        let next_a = cur_a + kas_half;
        let next_b = cur_b + usdc_half;
        let w_json = json!({ "KAS": 0.50, "USDC": 0.50 });
        let r_json = json!({ "KAS": next_a, "USDC": next_b });
        sqlx::query(
            "UPDATE liquidity_providers SET staked_asset_a = $1, staked_asset_b = $2, weights_json = $3, reserves_json = $4, last_yield_distribution = CURRENT_TIMESTAMP WHERE lp_id = $5"
        )
        .bind(next_a)
        .bind(next_b)
        .bind(w_json)
        .bind(r_json)
        .bind(lp_id)
        .execute(&mut **tx_db)
        .await?;
    } else {
        let w_json = json!({ "KAS": 0.50, "USDC": 0.50 });
        let r_json = json!({ "KAS": kas_half, "USDC": usdc_half });
        sqlx::query(
            "INSERT INTO liquidity_providers (wallet_address, pool_pair, staked_asset_a, staked_asset_b, weights_json, reserves_json, lock_duration_days, unlock_date) VALUES ($1, 'KAS/USDC', $2, $3, $4, $5, $6, CURRENT_TIMESTAMP + make_interval(days => $6))"
        )
        .bind(prefixed_wallet)
        .bind(kas_half)
        .bind(usdc_half)
        .bind(w_json)
        .bind(r_json)
        .bind(lock_days)
        .execute(&mut **tx_db)
        .await?;
    }
    sqlx::query(
        "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, payout_address) VALUES ($1, 'USDC', 'TAX_ESCROW_LP', $2, $3, 1.0, $4)"
    )
    .bind(clean_wallet)
    .bind(escrow_usd)
    .bind(escrow_usd)
    .bind(prefixed_wallet)
    .execute(&mut **tx_db)
    .await?;
    Ok(escrow_usd)
}

async fn fetch_third_party_passthrough_price_usd(client: &Client, ticker: &str, kas_usd: f64) -> f64 {
    let clean = ticker.trim().to_uppercase();
    if let Ok(res) = client
        .get(&format!("https://api.kas.fyi/v1/tokens/krc20/{}/market", clean))
        .send()
        .await
    {
        if res.status().is_success() {
            if let Ok(data) = res.json::<Value>().await {
                if let Some(p_usd) = data
                    .pointer("/price/usd")
                    .or_else(|| data.get("priceUsd"))
                    .or_else(|| data.get("price"))
                    .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok())))
                {
                    if p_usd > 0.0 {
                        return p_usd;
                    }
                }
                if let Some(p_kas) = data
                    .pointer("/price/kas")
                    .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok())))
                {
                    if p_kas > 0.0 && kas_usd > 0.0 {
                        return p_kas * kas_usd;
                    }
                }
            }
        }
    }
    if let Ok(res) = client
        .get(&format!("https://api.dexscreener.com/latest/dex/search?q={}", clean))
        .send()
        .await
    {
        if res.status().is_success() {
            if let Ok(data) = res.json::<Value>().await {
                if let Some(pairs) = data.get("pairs").and_then(|p| p.as_array()) {
                    for pair in pairs {
                        let sym = pair
                            .pointer("/baseToken/symbol")
                            .and_then(|s| s.as_str())
                            .unwrap_or("")
                            .to_uppercase();
                        if sym == clean {
                            if let Some(p_usd) = pair
                                .get("priceUsd")
                                .and_then(|v| v.as_str().and_then(|s| s.parse::<f64>().ok()).or_else(|| v.as_f64()))
                            {
                                if p_usd > 0.0 {
                                    return p_usd;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    0.0
}

async fn upsert_master_treasury_365d_lp(
    pool: &PgPool,
    prefixed_treasury: &str,
    pool_pair: &str,
    add_kas_a: f64,
    add_asset_b: f64,
) -> anyhow::Result<()> {
    if add_kas_a <= 0.0 || add_asset_b <= 0.0 {
        return Ok(());
    }
    let quote_ticker = pool_pair.split('/').nth(1).unwrap_or("USDC").trim().to_uppercase();
    let existing = sqlx::query(
        "SELECT lp_id, staked_asset_a, staked_asset_b FROM liquidity_providers WHERE wallet_address = $1 AND pool_pair = $2 AND lock_duration_days = 365 ORDER BY created_at ASC LIMIT 1"
    )
    .bind(prefixed_treasury)
    .bind(pool_pair)
    .fetch_optional(pool)
    .await?;
    if let Some(row) = existing {
        let lp_id: Uuid = row.get("lp_id");
        let cur_a: f64 = row.try_get("staked_asset_a").unwrap_or(0.0);
        let cur_b: f64 = row.try_get("staked_asset_b").unwrap_or(0.0);
        let next_a = cur_a + add_kas_a;
        let next_b = cur_b + add_asset_b;
        let w_json = json!({ "KAS": 0.50, quote_ticker.clone(): 0.50 });
        let r_json = json!({ "KAS": next_a, quote_ticker: next_b });
        sqlx::query(
            "UPDATE liquidity_providers SET staked_asset_a = $1, staked_asset_b = $2, weights_json = $3, reserves_json = $4, last_yield_distribution = CURRENT_TIMESTAMP WHERE lp_id = $5"
        )
        .bind(next_a)
        .bind(next_b)
        .bind(w_json)
        .bind(r_json)
        .bind(lp_id)
        .execute(pool)
        .await?;
    } else {
        let w_json = json!({ "KAS": 0.50, quote_ticker.clone(): 0.50 });
        let r_json = json!({ "KAS": add_kas_a, quote_ticker: add_asset_b });
        sqlx::query(
            "INSERT INTO liquidity_providers (wallet_address, pool_pair, staked_asset_a, staked_asset_b, weights_json, reserves_json, lock_duration_days, unlock_date) VALUES ($1, $2, $3, $4, $5, $6, 365, CURRENT_TIMESTAMP + INTERVAL '365 days')"
        )
        .bind(prefixed_treasury)
        .bind(pool_pair)
        .bind(add_kas_a)
        .bind(add_asset_b)
        .bind(w_json)
        .bind(r_json)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn compound_master_treasury_lp_positions(
    pool: &PgPool,
    redis_conn: &mut redis::aio::MultiplexedConnection,
) {
    let corp_kas_clean = resolve_master_treasury_address();
    if corp_kas_clean.is_empty() {
        return;
    }
    let prefixed_treasury = format!("kaspa:{}", corp_kas_clean);
    let kas_price = get_oracle_price(pool, redis_conn, "KAS").await;
    if kas_price <= 0.0 {
        return;
    }
    let min_dark_pool_usd = crate::sor::get_min_dark_pool_position_usd();
    if let Ok(fee_keys) = redis::cmd("KEYS")
        .arg("perennia:fees:batch_accumulated:*")
        .query_async::<_, Vec<String>>(redis_conn)
        .await
    {
        for fkey in fee_keys {
            let ticker = fkey
                .trim_start_matches("perennia:fees:batch_accumulated:")
                .trim()
                .to_uppercase();
            if ticker.is_empty() || ticker == "KAS" || crate::oracle::is_oracle_supported_asset(&ticker) {
                continue;
            }
            let swept_unverified: Option<String> = redis::cmd("GETDEL")
                .arg(&fkey)
                .query_async(redis_conn)
                .await
                .unwrap_or(None);
            if let Some(raw_val) = swept_unverified {
                if let Ok(unverified_qty) = raw_val.parse::<f64>() {
                    if unverified_qty > 0.0 {
                        tracing::info!(
                            "🛡️ [KAS FEE FIREWALL] Quarantined unverified custom token fee key {} ({:.6}) -> Master Treasury retains fees strictly in KAS.",
                            ticker,
                            unverified_qty
                        );
                    }
                }
            }
        }
    }
    let profit_str: Option<String> = redis::cmd("GET")
        .arg("perennia:treasury:netting_profit_usd")
        .query_async(redis_conn)
        .await
        .unwrap_or(None);
    let current_profit_usd = profit_str
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);
    if current_profit_usd >= min_dark_pool_usd {
        let swept_str: Option<String> = redis::cmd("GETSET")
            .arg("perennia:treasury:netting_profit_usd")
            .arg(0.0)
            .query_async(redis_conn)
            .await
            .unwrap_or(None);
        let swept_usd = swept_str
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);
        if swept_usd > 0.0 {
            let kas_half = (swept_usd * 0.50) / kas_price;
            let usdc_half = swept_usd * 0.50;
            if let Err(e) = upsert_master_treasury_365d_lp(
                pool,
                &prefixed_treasury,
                "KAS/USDC",
                kas_half,
                usdc_half,
            )
            .await
            {
                tracing::error!("Failed to auto-compound Master Treasury netting_profit_usd: {}", e);
                let _: () = redis::cmd("INCRBYFLOAT")
                    .arg("perennia:treasury:netting_profit_usd")
                    .arg(swept_usd)
                    .query_async(redis_conn)
                    .await
                    .unwrap_or(());
            } else {
                tracing::info!(
                    "🏦 [HOUSE 2.5x AUTO-COMPOUND] Swept ${:.2} USD netting profit into Master Treasury 365D (2.5x) KAS/USDC LP (+{:.4} KAS / +{:.2} USDC).",
                    swept_usd,
                    kas_half,
                    usdc_half
                );
            }
        }
    }
    for &asset in crate::oracle::ORACLE_SUPPORTED_ASSETS {
        if asset == "KAS" || asset == "USD" {
            continue;
        }
        let fee_key = format!("perennia:fees:batch_accumulated:{}", asset);
        let fee_str: Option<String> = redis::cmd("GET")
            .arg(&fee_key)
            .query_async(redis_conn)
            .await
            .unwrap_or(None);
        let fee_tokens = fee_str
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);
        if fee_tokens <= 0.0 {
            continue;
        }
        let asset_price = get_oracle_price(pool, redis_conn, asset).await;
        if asset_price <= 0.0 {
            continue;
        }
        let fee_usd = fee_tokens * asset_price;
        if fee_usd < min_dark_pool_usd {
            continue;
        }
        let swept_str: Option<String> = redis::cmd("GETSET")
            .arg(&fee_key)
            .arg(0.0)
            .query_async(redis_conn)
            .await
            .unwrap_or(None);
        let swept_tokens = swept_str
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);
        if swept_tokens <= 0.0 {
            continue;
        }
        let swept_usd = swept_tokens * asset_price;
        let pool_pair = format!("KAS/{}", asset);
        let kas_half = (swept_usd * 0.50) / kas_price;
        let token_half = swept_tokens * 0.50;
        if let Err(e) = upsert_master_treasury_365d_lp(
            pool,
            &prefixed_treasury,
            &pool_pair,
            kas_half,
            token_half,
        )
        .await
        {
            tracing::error!("Failed to auto-compound Master Treasury {} fee reserve: {}", asset, e);
            let _: () = redis::cmd("INCRBYFLOAT")
                .arg(&fee_key)
                .arg(swept_tokens)
                .query_async(redis_conn)
                .await
                .unwrap_or(());
        } else {
            tracing::info!(
                "🏦 [HOUSE 2.5x AUTO-COMPOUND] Swept {:.6} {} (${:.2}) into Master Treasury 365D (2.5x) {} LP (+{:.4} KAS / +{:.6} {}).",
                swept_tokens,
                asset,
                swept_usd,
                pool_pair,
                kas_half,
                token_half,
                asset
            );
        }
    }
    let kas_fee_key = "perennia:fees:batch_accumulated:KAS";
    let kas_fee_str: Option<String> = redis::cmd("GET")
        .arg(kas_fee_key)
        .query_async(redis_conn)
        .await
        .unwrap_or(None);
    let kas_fee_tokens = kas_fee_str
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);
    let kas_fee_usd = kas_fee_tokens * kas_price;
    if kas_fee_usd >= min_dark_pool_usd {
        let swept_str: Option<String> = redis::cmd("GETSET")
            .arg(kas_fee_key)
            .arg(0.0)
            .query_async(redis_conn)
            .await
            .unwrap_or(None);
        let swept_kas = swept_str
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);
        if swept_kas > 0.0 {
            let kas_half = swept_kas * 0.50;
            let usdc_half = kas_half * kas_price;
            if let Err(e) = upsert_master_treasury_365d_lp(
                pool,
                &prefixed_treasury,
                "KAS/USDC",
                kas_half,
                usdc_half,
            )
            .await
            {
                tracing::error!("Failed to auto-compound Master Treasury KAS fees: {}", e);
                let _: () = redis::cmd("INCRBYFLOAT")
                    .arg(kas_fee_key)
                    .arg(swept_kas)
                    .query_async(redis_conn)
                    .await
                    .unwrap_or(());
            } else {
                tracing::info!(
                    "🏦 [HOUSE 2.5x AUTO-COMPOUND] Swept {:.4} KAS (${:.2}) accumulated fees into Master Treasury 365D (2.5x) KAS/USDC LP (+{:.4} KAS / +{:.2} USDC).",
                    swept_kas,
                    swept_kas * kas_price,
                    kas_half,
                    usdc_half
                );
            }
        }
    }
}

pub async fn rebalance_multi_asset_liquidity_plants(
    pool: &PgPool,
    redis_conn: &mut redis::aio::MultiplexedConnection,
    kas_price: f64,
) {
    if kas_price <= 0.0 {
        return;
    }
    let rows = match sqlx::query(
        "SELECT lp_id, pool_pair, staked_asset_a, staked_asset_b, weights_json, reserves_json FROM liquidity_providers"
    )
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(_) => return,
    };
    for r in rows {
        let lp_id: Uuid = r.get("lp_id");
        let pool_pair: String = r.get("pool_pair");
        let staked_a: f64 = r.get("staked_asset_a");
        let staked_b: f64 = r.get("staked_asset_b");
        let mut weights_val: Value = r.try_get("weights_json").unwrap_or_else(|_| json!({}));
        let mut reserves_val: Value = r.try_get("reserves_json").unwrap_or_else(|_| json!({}));
        let parts: Vec<String> = pool_pair
            .split('/')
            .map(|s| s.trim().to_uppercase())
            .filter(|s| !s.is_empty())
            .collect();
        if parts.len() < 2 {
            continue;
        }
        if weights_val.as_object().map(|m| m.is_empty()).unwrap_or(true) {
            let mut w_map = serde_json::Map::new();
            w_map.insert("KAS".to_string(), json!(0.50));
            let sec_count = (parts.len() - 1).max(1);
            for sec in parts.iter().skip(1) {
                w_map.insert(sec.clone(), json!(0.50 / (sec_count as f64)));
            }
            weights_val = Value::Object(w_map);
        }
        if reserves_val.as_object().map(|m| m.is_empty()).unwrap_or(true) {
            let mut r_map = serde_json::Map::new();
            r_map.insert("KAS".to_string(), json!(staked_a));
            if let Some(sec) = parts.get(1) {
                r_map.insert(sec.clone(), json!(staked_b));
            }
            reserves_val = Value::Object(r_map);
        }
        let mut prices: HashMap<String, f64> = HashMap::new();
        prices.insert("KAS".to_string(), kas_price);
        let mut all_prices_ready = true;
        for sec in parts.iter().skip(1) {
            let p = get_oracle_price(pool, redis_conn, sec).await;
            if p <= 0.0 {
                all_prices_ready = false;
                break;
            }
            prices.insert(sec.clone(), p);
        }
        if !all_prices_ready {
            continue;
        }
        let mut total_plant_usd = 0.0;
        if let Some(r_obj) = reserves_val.as_object() {
            for (asset, qty_val) in r_obj {
                let qty = qty_val.as_f64().unwrap_or(0.0).max(0.0);
                let p = prices.get(asset).copied().unwrap_or(0.0);
                total_plant_usd += qty * p;
            }
        }
        if total_plant_usd <= 0.0 {
            continue;
        }
        let mut rebalanced_reserves = serde_json::Map::new();
        let mut new_kas_a = staked_a;
        let mut new_secondary_b = 0.0;
        if let Some(w_obj) = weights_val.as_object() {
            for (idx, asset) in parts.iter().enumerate() {
                let w = if asset == "KAS" {
                    0.50
                } else {
                    w_obj
                        .get(asset)
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.50 / ((parts.len() - 1).max(1) as f64))
                        .clamp(0.01, 0.50)
                };
                let p = prices.get(asset).copied().unwrap_or(1.0);
                let target_qty = (total_plant_usd * w) / p;
                rebalanced_reserves.insert(asset.clone(), json!(target_qty));
                if asset == "KAS" {
                    new_kas_a = target_qty;
                } else if parts.len() == 2 && idx == 1 {
                    new_secondary_b = target_qty;
                } else {
                    new_secondary_b += target_qty * p;
                }
            }
        }
        let _ = sqlx::query(
            "UPDATE liquidity_providers SET staked_asset_a = $1, staked_asset_b = $2, weights_json = $3, reserves_json = $4, last_yield_distribution = CURRENT_TIMESTAMP WHERE lp_id = $5"
        )
        .bind(new_kas_a)
        .bind(new_secondary_b)
        .bind(&weights_val)
        .bind(Value::Object(rebalanced_reserves))
        .bind(lp_id)
        .execute(pool)
        .await;
    }
}

pub async fn start_mempool_watcher_daemon(
    pool: PgPool,
    mut daa_rx: tokio::sync::broadcast::Receiver<u64>,
    mut utxo_rx: tokio::sync::broadcast::Receiver<crate::kaspad_client::protowire::UtxosChangedNotificationMessage>
) {
    tracing::info!("👁 Mempool Watcher Daemon Online. Listening to native gRPC streams...");
    let _ = sqlx::query("ALTER TABLE pending_transactions ADD COLUMN IF NOT EXISTS block_daa BIGINT").execute(&pool).await;
    let mut cleanup_interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tokio::select! {
            Ok(daa_score) = daa_rx.recv() => {
                let _ = sqlx::query!(
                    "UPDATE pending_transactions SET status = 'SETTLED' WHERE status = 'PENDING' AND block_daa IS NOT NULL AND $1 >= block_daa + 50",
                    daa_score as i64
                ).execute(&pool).await;
            }
            Ok(utxo_msg) = utxo_rx.recv() => {
                for added in utxo_msg.added {
                    if let (Some(outpoint), Some(utxo_entry)) = (added.outpoint, added.utxo_entry) {
                        let tx_id = outpoint.transaction_id;
                        let block_daa = utxo_entry.block_daa_score;
                        let res = sqlx::query!(
                            "UPDATE pending_transactions SET block_daa = $1 WHERE tx_id = $2 AND status = 'PENDING'",
                            block_daa as i64, tx_id
                        ).execute(&pool).await;
                        if let Ok(result) = res {
                            if result.rows_affected() > 0 {
                                tracing::info!("✅ [DAG FINALITY] Transaction {} accepted into the BlockDAG at DAA {}. Awaiting 50 blocks depth.", tx_id, block_daa);
                            }
                        }
                    }
                }
            }
            _ = cleanup_interval.tick() => {
                let _ = sqlx::query!(
                    "UPDATE pending_transactions SET status = 'FAILED' WHERE status = 'PENDING' AND created_at < CURRENT_TIMESTAMP - INTERVAL '15 minutes'"
                ).execute(&pool).await;
            }
        }
    }
}

pub async fn start_delta_netting_engine(redis_client: redis::Client, pg_pool: PgPool) {
    tracing::info!("🕸️ Multi-Asset Pool Netting Engine Online. Accumulating internal liquidity & executing 2-Asset + Multi-Asset Liquidity Plant settlement.");
    let mut redis_conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Netting Engine Redis failure: {}", e);
            return;
        }
    };
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    let hedging_threshold = std::env::var("HEDGING_THRESHOLD_KAS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(10.0);
    loop {
        interval.tick().await;
        let mut current_batch = Vec::new();
        loop {
            let result: redis::RedisResult<Option<String>> = redis::cmd("LPOP")
                .arg("perennia:sor:netting_queue")
                .query_async(&mut redis_conn)
                .await;
            match result {
                Ok(Some(order_json)) => {
                    if let Ok(order) = serde_json::from_str::<NettingOrder>(&order_json) {
                        current_batch.push(order);
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        if current_batch.is_empty() {
            compound_master_treasury_lp_positions(&pg_pool, &mut redis_conn).await;
            continue;
        }
        let kas_price = get_oracle_price(&pg_pool, &mut redis_conn, "KAS").await;
        if kas_price <= 0.0 {
            for ord in current_batch.iter().rev() {
                if let Ok(s) = serde_json::to_string(ord) {
                    let _: () = redis::cmd("LPUSH")
                        .arg("perennia:sor:netting_queue")
                        .arg(s)
                        .query_async(&mut redis_conn)
                        .await
                        .unwrap_or(());
                }
            }
            continue;
        }
        let min_dark_pool_usd = crate::sor::get_min_dark_pool_position_usd();
        let mut total_buy_kas = 0.0;
        let mut total_sell_kas = 0.0;
        let mut gross_volume_kas = 0.0;
        let mut pair_flows: HashMap<String, PairBatchFlow> = HashMap::new();
        let mut ledger_pipeline = redis::pipe();
        for order in &current_batch {
            let clean_wallet = normalize_kaspa_base32(&order.wallet);
            let prefixed_wallet = format!("kaspa:{}", clean_wallet);
            let ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
            let raw_target_asset = order.target_asset.as_deref().unwrap_or("USDC").trim().to_uppercase();
            if order.direction == "THIRD_PARTY_PASSTHROUGH" || !crate::oracle::is_oracle_supported_asset(&raw_target_asset) {
                let upfront_fee_kas = order
                    .upfront_fee_kas
                    .unwrap_or_else(|| order.amount_kas * LONG_TAIL_PASSTHROUGH_FEE_RATE)
                    .max(0.0);
                let net_passthrough_kas = order
                    .net_passthrough_kas
                    .unwrap_or_else(|| (order.amount_kas - upfront_fee_kas).max(0.0));
                if upfront_fee_kas > 0.0 {
                    ledger_pipeline
                        .cmd("INCRBYFLOAT")
                        .arg("perennia:fees:batch_accumulated:KAS")
                        .arg(upfront_fee_kas)
                        .ignore();
                } else if order.fee_captured_usd > 0.0 {
                    let fee_in_kas = order.fee_captured_usd / kas_price;
                    ledger_pipeline
                        .cmd("INCRBYFLOAT")
                        .arg("perennia:fees:batch_accumulated:KAS")
                        .arg(fee_in_kas)
                        .ignore();
                }
                let passthrough_dispatch = json!({
                    "wallet": prefixed_wallet,
                    "destination_l1_address": order.destination_l1_address.clone().unwrap_or(prefixed_wallet.clone()),
                    "target_asset": raw_target_asset,
                    "gross_kas": order.amount_kas,
                    "upfront_fee_kas": upfront_fee_kas,
                    "net_passthrough_kas": net_passthrough_kas,
                    "estimated_output": order.estimated_output.unwrap_or(0.0),
                    "spot_price": order.spot_price
                });
                ledger_pipeline
                    .cmd("RPUSH")
                    .arg("perennia:sor:third_party_passthrough_queue")
                    .arg(passthrough_dispatch.to_string())
                    .ignore();
                continue;
            }
            if let Some(dust_kas) = order.dust_fee_kas {
                if dust_kas > 0.0 {
                    ledger_pipeline
                        .cmd("INCRBYFLOAT")
                        .arg("perennia:fees:batch_accumulated:KAS")
                        .arg(dust_kas)
                        .ignore();
                }
            }
            gross_volume_kas += order.amount_kas;
            let lp_quote_asset = if raw_target_asset == "KAS" || raw_target_asset == "USD" {
                "USDC".to_string()
            } else {
                raw_target_asset.clone()
            };
            let pool_pair = format!("KAS/{}", lp_quote_asset);
            let flow = pair_flows.entry(pool_pair).or_default();
            if order.fee_captured_usd > 0.0 && order.fee_captured_usd < min_dark_pool_usd {
                let dust_kas = order.fee_captured_usd / kas_price;
                ledger_pipeline
                    .cmd("INCRBYFLOAT")
                    .arg("perennia:fees:batch_accumulated:KAS")
                    .arg(dust_kas)
                    .ignore();
            } else {
                flow.fee_usd += order.fee_captured_usd;
            }
            if order.direction == "BUY_KAS" {
                let kas_credited = order.estimated_output.unwrap_or(order.amount_kas);
                total_buy_kas += kas_credited;
                flow.buy_kas += kas_credited;
                if clean_wallet != "treasury_onramp_credit" {
                    ledger_pipeline.cmd("HINCRBYFLOAT").arg(&ledger_key).arg("KAS").arg(kas_credited).ignore();
                }
            } else if order.direction == "SELL_KAS" {
                total_sell_kas += order.amount_kas;
                flow.sell_kas += order.amount_kas;
                let output = order.estimated_output.unwrap_or(order.amount_kas * order.spot_price * 0.985);
                if clean_wallet != "treasury_auto_lp"
                    && clean_wallet != "treasury_sector_swap"
                    && clean_wallet != "treasury_epoch_batch"
                    && raw_target_asset != "USD"
                {
                    ledger_pipeline.cmd("HINCRBYFLOAT").arg(&ledger_key).arg(&raw_target_asset).arg(output).ignore();
                }
            } else if order.direction == "CROSS_SYNTHETIC" {
                if let Some(output) = order.estimated_output {
                    if output > 0.0 && raw_target_asset != "USD" {
                        ledger_pipeline.cmd("HINCRBYFLOAT").arg(&ledger_key).arg(&raw_target_asset).arg(output).ignore();
                    }
                }
            }
        }
        if let Err(e) = ledger_pipeline.query_async::<_, ()>(&mut redis_conn).await {
            tracing::error!("🚨 Failed to credit double-entry ledgers in Redis: {}", e);
        }
        let mut residual_treasury_signed_delta_kas = 0.0;
        let mut total_fees_usd = 0.0;
        for (pool_pair, flow) in pair_flows {
            total_fees_usd += flow.fee_usd;
            let target_asset = pool_pair.split('/').nth(1).unwrap_or("USDC");
            let target_price = get_oracle_price(&pg_pool, &mut redis_conn, target_asset).await;
            if target_price <= 0.0 {
                continue;
            }
            let pair_signed_delta_kas = flow.buy_kas - flow.sell_kas;
            let mut lp_absorbed_kas = 0.0;
            let mut uncovered_signed_delta_kas = pair_signed_delta_kas;
            if let Ok(lps) = sqlx::query(
                "SELECT lp_id, wallet_address, pool_pair, staked_asset_a, staked_asset_b, reserves_json, lock_duration_days FROM liquidity_providers WHERE pool_pair = $1 OR pool_pair LIKE $2"
            )
            .bind(&pool_pair)
            .bind(format!("%/{}%", target_asset))
            .fetch_all(&pg_pool)
            .await
            {
                let mut total_a_kas = 0.0;
                let mut total_b_quote = 0.0;
                let mut total_weighted_tvl = 0.0;
                let mut lp_records = Vec::new();
                for r in lps {
                    let lp_id: Uuid = r.get("lp_id");
                    let w_addr: String = r.get("wallet_address");
                    let row_pair: String = r.get("pool_pair");
                    let sa: f64 = r.get::<f64, _>("staked_asset_a").max(0.0);
                    let sb: f64 = r.get::<f64, _>("staked_asset_b").max(0.0);
                    let reserves_val: Value = r.try_get("reserves_json").unwrap_or_else(|_| json!({}));
                    let is_multi = row_pair.split('/').count() > 2;
                    let eff_b = if is_multi {
                        reserves_val
                            .get(target_asset)
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0)
                            .max(0.0)
                    } else {
                        sb
                    };
                    if eff_b <= 0.0 && sa <= 0.0 {
                        continue;
                    }
                    let lock_days: i32 = r.get("lock_duration_days");
                    let mult = match lock_days {
                        d if d >= 365 => 2.5,
                        d if d >= 90 => 1.5,
                        d if d >= 30 => 1.2,
                        _ => 1.0,
                    };
                    total_a_kas += sa;
                    total_b_quote += eff_b;
                    let weighted = sa * mult;
                    total_weighted_tvl += weighted;
                    lp_records.push((lp_id, w_addr, row_pair, sa, eff_b, reserves_val, weighted));
                }
                if pair_signed_delta_kas < -1e-9 && total_b_quote > 0.0 {
                    let net_sell_kas = -pair_signed_delta_kas;
                    let lp_quote_capacity_kas = (total_b_quote * target_price) / kas_price;
                    lp_absorbed_kas = net_sell_kas.min(lp_quote_capacity_kas);
                    let quote_disbursed = (lp_absorbed_kas * kas_price) / target_price;
                    uncovered_signed_delta_kas = -(net_sell_kas - lp_absorbed_kas).max(0.0);
                    if lp_absorbed_kas > 0.0 {
                        for (lp_id, _w_addr, row_pair, sa, eff_b, mut reserves_val, _weighted) in lp_records.clone() {
                            if eff_b > 0.0 {
                                let share = eff_b / total_b_quote;
                                let delta_a = lp_absorbed_kas * share;
                                let delta_b = quote_disbursed * share;
                                if row_pair.split('/').count() > 2 {
                                    if let Some(obj) = reserves_val.as_object_mut() {
                                        let next_kas = sa + delta_a;
                                        let next_q = (eff_b - delta_b).max(0.0);
                                        obj.insert("KAS".to_string(), json!(next_kas));
                                        obj.insert(target_asset.to_string(), json!(next_q));
                                    }
                                    let _ = sqlx::query(
                                        "UPDATE liquidity_providers SET staked_asset_a = staked_asset_a + $1, reserves_json = $2, last_yield_distribution = CURRENT_TIMESTAMP WHERE lp_id = $3"
                                    )
                                    .bind(delta_a)
                                    .bind(&reserves_val)
                                    .bind(lp_id)
                                    .execute(&pg_pool)
                                    .await;
                                } else {
                                    let _ = sqlx::query(
                                        "UPDATE liquidity_providers SET staked_asset_a = staked_asset_a + $1, staked_asset_b = GREATEST(0.0, staked_asset_b - $2), last_yield_distribution = CURRENT_TIMESTAMP WHERE lp_id = $3"
                                    )
                                    .bind(delta_a)
                                    .bind(delta_b)
                                    .bind(lp_id)
                                    .execute(&pg_pool)
                                    .await;
                                }
                            }
                        }
                    }
                } else if pair_signed_delta_kas > 1e-9 && total_a_kas > 0.0 {
                    let net_buy_kas = pair_signed_delta_kas;
                    lp_absorbed_kas = net_buy_kas.min(total_a_kas);
                    let quote_received = (lp_absorbed_kas * kas_price) / target_price;
                    uncovered_signed_delta_kas = (net_buy_kas - lp_absorbed_kas).max(0.0);
                    if lp_absorbed_kas > 0.0 {
                        for (lp_id, _w_addr, row_pair, sa, eff_b, mut reserves_val, _weighted) in lp_records.clone() {
                            if sa > 0.0 {
                                let share = sa / total_a_kas;
                                let delta_a = lp_absorbed_kas * share;
                                let delta_b = quote_received * share;
                                if row_pair.split('/').count() > 2 {
                                    if let Some(obj) = reserves_val.as_object_mut() {
                                        let next_kas = (sa - delta_a).max(0.0);
                                        let next_q = eff_b + delta_b;
                                        obj.insert("KAS".to_string(), json!(next_kas));
                                        obj.insert(target_asset.to_string(), json!(next_q));
                                    }
                                    let _ = sqlx::query(
                                        "UPDATE liquidity_providers SET staked_asset_a = GREATEST(0.0, staked_asset_a - $1), reserves_json = $2, last_yield_distribution = CURRENT_TIMESTAMP WHERE lp_id = $3"
                                    )
                                    .bind(delta_a)
                                    .bind(&reserves_val)
                                    .bind(lp_id)
                                    .execute(&pg_pool)
                                    .await;
                                } else {
                                    let _ = sqlx::query(
                                        "UPDATE liquidity_providers SET staked_asset_a = GREATEST(0.0, staked_asset_a - $1), staked_asset_b = staked_asset_b + $2, last_yield_distribution = CURRENT_TIMESTAMP WHERE lp_id = $3"
                                    )
                                    .bind(delta_a)
                                    .bind(delta_b)
                                    .bind(lp_id)
                                    .execute(&pg_pool)
                                    .await;
                                }
                            }
                        }
                    }
                }
                if flow.fee_usd > 0.0 {
                    let pair_gross_kas = flow.buy_kas + flow.sell_kas;
                    let peer_matched_kas = 2.0 * flow.buy_kas.min(flow.sell_kas);
                    let lp_backed_fraction = if total_weighted_tvl <= 0.0 {
                        0.0
                    } else if pair_gross_kas > 0.0 {
                        ((peer_matched_kas + lp_absorbed_kas) / pair_gross_kas).clamp(0.0, 1.0)
                    } else {
                        1.0
                    };
                    let lp_reward_pool = flow.fee_usd * 0.80 * lp_backed_fraction;
                    let treasury_share = (flow.fee_usd - lp_reward_pool).max(0.0);
                    if treasury_share > 0.0 {
                        if crate::oracle::is_oracle_supported_asset(target_asset)
                            && treasury_share >= min_dark_pool_usd
                            && target_price > 0.0
                        {
                            let treasury_tokens = treasury_share / target_price;
                            let _: () = redis::cmd("INCRBYFLOAT")
                                .arg(format!("perennia:fees:batch_accumulated:{}", target_asset))
                                .arg(treasury_tokens)
                                .query_async(&mut redis_conn)
                                .await
                                .unwrap_or(());
                        } else {
                            let dust_kas = treasury_share / kas_price;
                            let _: () = redis::cmd("INCRBYFLOAT")
                                .arg("perennia:fees:batch_accumulated:KAS")
                                .arg(dust_kas)
                                .query_async(&mut redis_conn)
                                .await
                                .unwrap_or(());
                        }
                    }
                    if total_weighted_tvl > 0.0 && lp_reward_pool > 0.0 {
                        let mut lp_pipeline = redis::pipe();
                        for (_lp_id, wallet, _row_pair, _sa, _sb, _res, weighted_a) in lp_records {
                            let user_share_pct = weighted_a / total_weighted_tvl;
                            let user_reward_usd = lp_reward_pool * user_share_pct;
                            let clean_wallet = normalize_kaspa_base32(&wallet);
                            let ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
                            if user_reward_usd >= min_dark_pool_usd || target_asset == "KAS" || target_asset == "USDC" || target_asset == "USDT" {
                                let user_reward_tokens = user_reward_usd / target_price;
                                if user_reward_tokens > 0.00000001 {
                                    lp_pipeline.cmd("HINCRBYFLOAT").arg(&ledger_key).arg(target_asset).arg(user_reward_tokens).ignore();
                                }
                            } else {
                                let reward_kas = user_reward_usd / kas_price;
                                if reward_kas > 0.00000001 {
                                    lp_pipeline.cmd("HINCRBYFLOAT").arg(&ledger_key).arg("KAS").arg(reward_kas).ignore();
                                }
                            }
                        }
                        if let Err(e) = lp_pipeline.query_async::<_, ()>(&mut redis_conn).await {
                            tracing::error!("🚨 Failed to distribute LP yields for {}: {}", pool_pair, e);
                        }
                        let _ = sqlx::query(
                            "INSERT INTO yield_distributions (pool_pair, total_fees_distributed_usd) VALUES ($1, $2)"
                        )
                        .bind(&pool_pair)
                        .bind(lp_reward_pool)
                        .execute(&pg_pool)
                        .await;
                    }
                }
            } else if flow.fee_usd > 0.0 {
                let dust_kas = flow.fee_usd / kas_price;
                let _: () = redis::cmd("INCRBYFLOAT")
                    .arg("perennia:fees:batch_accumulated:KAS")
                    .arg(dust_kas)
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(());
            }
            residual_treasury_signed_delta_kas += uncovered_signed_delta_kas;
        }
        compound_master_treasury_lp_positions(&pg_pool, &mut redis_conn).await;
        let signed_batch_delta = total_buy_kas - total_sell_kas;
        let dominant_direction = if signed_batch_delta >= 0.0 { "BUY_HEAVY" } else { "SELL_HEAVY" };
        tracing::info!(
            "🦇 [POOL NETTING BATCH] Gross: {:.2} KAS | Batch Delta: {:.2} KAS ({}) | Uncovered Treasury Delta: {:.4} KAS | Spread: ${:.4}",
            gross_volume_kas,
            signed_batch_delta.abs(),
            dominant_direction,
            residual_treasury_signed_delta_kas,
            total_fees_usd
        );
        let unhedged_key = "perennia:treasury:unhedged_delta_kas";
        let unhedged_str: Option<String> = redis::cmd("GET").arg(unhedged_key).query_async(&mut redis_conn).await.unwrap_or(None);
        let mut running_unhedged_signed: f64 = unhedged_str.unwrap_or_else(|| "0".to_string()).parse().unwrap_or(0.0);
        running_unhedged_signed += residual_treasury_signed_delta_kas;
        let cex_configured = crate::sor::is_cex_hedging_configured();
        let max_unhedged_liability = crate::sor::get_max_unhedged_liability_kas();
        if running_unhedged_signed.abs() >= hedging_threshold {
            if !cex_configured {
                let _: () = redis::cmd("SET").arg(unhedged_key).arg(running_unhedged_signed).query_async(&mut redis_conn).await.unwrap_or(());
            } else {
                let hedge_side = if running_unhedged_signed > 0.0 { "BUY" } else { "SELL" };
                let hedge_qty = running_unhedged_signed.abs();
                match crate::sor::execute_autonomous_hedge(hedge_qty, hedge_side).await {
                    Ok(tx_id) => {
                        tracing::info!("✅ [HEDGE EXECUTED] Successfully executed {} {:.2} KAS on MEXC. Order: {}", hedge_side, hedge_qty, tx_id);
                        running_unhedged_signed = 0.0;
                        let _: () = redis::cmd("SET").arg(unhedged_key).arg(0.0).query_async(&mut redis_conn).await.unwrap_or(());
                    },
                    Err(e) => {
                        tracing::error!("❌ [HEDGE FAILED] {}. Retaining signed accumulator for next cycle.", e);
                        let _: () = redis::cmd("SET").arg(unhedged_key).arg(running_unhedged_signed).query_async(&mut redis_conn).await.unwrap_or(());
                    }
                }
            }
        } else {
            let _: () = redis::cmd("SET").arg(unhedged_key).arg(running_unhedged_signed).query_async(&mut redis_conn).await.unwrap_or(());
        }
        let hedge_telemetry = json!({
            "mode": if cex_configured { "LIVE_CEX_HEDGE" } else { "LP_ABSORPTION_AND_SKEW_GUARD" },
            "cexConfigured": cex_configured,
            "unhedgedDeltaKas": running_unhedged_signed,
            "hedgingThresholdKas": hedging_threshold,
            "maxUnhedgedLiabilityKas": max_unhedged_liability
        });
        let _: () = redis::cmd("SET")
            .arg("perennia:treasury:hedge_status")
            .arg(hedge_telemetry.to_string())
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(());
    }
}
pub async fn process_forge_2200_utc_bell_covenants(
    pool: &PgPool,
    redis_conn: &mut redis::aio::MultiplexedConnection,
) {
    // 1. DELIVERABLE L2: Cliff & Linear Token Unlock Covenants ("Proof-of-Lock")
    if let Ok(vesting_rows) = sqlx::query(
        r#"
        SELECT vesting_id, token_ticker, beneficiary_address, total_allocated,
               unlocked_amount, daily_unlock_rate
        FROM forge_vesting_schedules
        WHERE status != 'FULLY_UNLOCKED'
          AND unlocked_amount < total_allocated
          AND CURRENT_TIMESTAMP >= cliff_unlock_at
        "#
    )
    .fetch_all(pool)
    .await
    {
        for r in vesting_rows {
            let vid: Uuid = r.get("vesting_id");
            let ticker: String = r.get::<String, _>("token_ticker").to_uppercase();
            let beneficiary: String = r.get("beneficiary_address");
            let total_alloc: f64 = r.get("total_allocated");
            let unlocked: f64 = r.get("unlocked_amount");
            let daily_rate: f64 = r.get("daily_unlock_rate");
            let remaining = (total_alloc - unlocked).max(0.0);
            if remaining <= 0.0 {
                continue;
            }
            let release_now = if daily_rate > 0.0 {
                daily_rate.min(remaining)
            } else {
                remaining
            };
            let next_unlocked = unlocked + release_now;
            let next_status = if (total_alloc - next_unlocked) <= 1e-6 {
                "FULLY_UNLOCKED"
            } else {
                "VESTING_ACTIVE"
            };
            let _ = sqlx::query(
                r#"
                UPDATE forge_vesting_schedules
                SET unlocked_amount = $1,
                    status = $2,
                    last_bell_unlocked_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE vesting_id = $3
                "#
            )
            .bind(next_unlocked)
            .bind(next_status)
            .bind(vid)
            .execute(pool)
            .await;

            let clean_ben = normalize_kaspa_base32(&beneficiary);
            if !clean_ben.is_empty() && release_now > 0.0 {
                let ben_ledger_key = format!("dev:sor:treasury:balances:{}", clean_ben);
                let _: () = redis::cmd("HINCRBYFLOAT")
                    .arg(&ben_ledger_key)
                    .arg(&ticker)
                    .arg(release_now)
                    .query_async(redis_conn)
                    .await
                    .unwrap_or(());
                tracing::info!(
                    "🔓 [PROOF-OF-LOCK 22:00 UTC UNLOCK] Released {:.4} {} to {} (Vesting ID: {}, Status: {})",
                    release_now,
                    ticker,
                    beneficiary,
                    vid,
                    next_status
                );
            }
        }
    }

    // 2. DELIVERABLE L3: Deflationary Auto-Burn & Buyback Sinks + Chromatic Halving Emissions
    if let Ok(policy_rows) = sqlx::query(
        r#"
        SELECT policy_id, token_ticker, creator_address, max_supply, burn_rate_bps,
               burn_address, total_burned_tokens, emission_schedule_type,
               daily_emission_rate, halving_interval_days, reserve_locked_tokens,
               reserve_emitted_tokens, EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - created_at)) / 86400.0 AS elapsed_days
        FROM forge_monetary_policies
        "#
    )
    .fetch_all(pool)
    .await
    {
        for r in policy_rows {
            let pid: Uuid = r.get("policy_id");
            let ticker: String = r.get::<String, _>("token_ticker").to_uppercase();
            let creator: String = r.get("creator_address");
            let max_supply: f64 = r.get("max_supply");
            let burn_bps: i32 = r.get("burn_rate_bps");
            let burn_addr: String = r
                .try_get::<String, _>("burn_address")
                .unwrap_or_else(|_| KASPA_UNSPENDABLE_BURN_ADDRESS.to_string());
            let emission_type: String = r.get("emission_schedule_type");
            let daily_emission_rate: f64 = r.get("daily_emission_rate");
            let halving_days: i32 = r.get::<i32, _>("halving_interval_days").max(1);
            let reserve_locked: f64 = r.get("reserve_locked_tokens");
            let reserve_emitted: f64 = r.get("reserve_emitted_tokens");
            let elapsed_days: f64 = r.try_get::<f64, _>("elapsed_days").unwrap_or(0.0).max(0.0);

            let mut burn_delta_tokens = 0.0;
            if burn_bps > 0 && max_supply > 0.0 {
                // Daily deflationary sink proportional to configured bps
                burn_delta_tokens = (max_supply * (burn_bps as f64 / 10_000.0) * 0.0025).max(1.0);
                let burn_tx_id = format!("BURN-{}-{}", ticker, &Uuid::new_v4().simple().to_string().to_uppercase()[..8]);
                let clean_creator = normalize_kaspa_base32(&creator);
                let _ = sqlx::query(
                    r#"
                    INSERT INTO tax_ledger_events
                    (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash, payout_address)
                    VALUES ($1, $2, 'AUTO_BURN_SINK', 0.0, $3, 0.0, $4, $5)
                    "#
                )
                .bind(&clean_creator)
                .bind(&ticker)
                .bind(burn_delta_tokens)
                .bind(&burn_tx_id)
                .bind(&burn_addr)
                .execute(pool)
                .await;
                tracing::info!(
                    "🔥 [22:00 UTC AUTO-BURN SINK] Burned {:.4} {} ({} bps) -> Unspendable L1 Burn Address {}",
                    burn_delta_tokens,
                    ticker,
                    burn_bps,
                    burn_addr
                );
            }

            let mut emitted_delta_tokens = 0.0;
            let remaining_reserve = (reserve_locked - reserve_emitted).max(0.0);
            if remaining_reserve > 0.0 && daily_emission_rate > 0.0 {
                let decay_factor = if emission_type.contains("CHROMATIC") {
                    0.5_f64.powf(elapsed_days / (halving_days as f64))
                } else if emission_type.contains("PERIODIC") {
                    let epochs = (elapsed_days / (halving_days as f64)).floor();
                    0.5_f64.powf(epochs)
                } else {
                    1.0
                };
                emitted_delta_tokens = (daily_emission_rate * decay_factor).min(remaining_reserve);
                if emitted_delta_tokens > 0.0 {
                    let clean_creator = normalize_kaspa_base32(&creator);
                    let creator_ledger = format!("dev:sor:treasury:balances:{}", clean_creator);
                    let _: () = redis::cmd("HINCRBYFLOAT")
                        .arg(&creator_ledger)
                        .arg(&ticker)
                        .arg(emitted_delta_tokens)
                        .query_async(redis_conn)
                        .await
                        .unwrap_or(());
                }
            }

            if burn_delta_tokens > 0.0 || emitted_delta_tokens > 0.0 {
                let _ = sqlx::query(
                    r#"
                    UPDATE forge_monetary_policies
                    SET total_burned_tokens = total_burned_tokens + $1,
                        reserve_emitted_tokens = reserve_emitted_tokens + $2,
                        last_bell_processed_at = CURRENT_TIMESTAMP,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE policy_id = $3
                    "#
                )
                .bind(burn_delta_tokens)
                .bind(emitted_delta_tokens)
                .bind(pid)
                .execute(pool)
                .await;
            }
        }
    }

    // 3. DELIVERABLE L4: Proof-of-Hashrate Mineable KRC-20s & Syndicate Sectors
    if let Ok(vault_rows) = sqlx::query(
        r#"
        SELECT vault_id, token_ticker, remaining_vault_tokens, daily_emission_tokens
        FROM forge_mineable_vaults
        WHERE status = 'ACTIVE' AND remaining_vault_tokens > 0 AND daily_emission_tokens > 0
        "#
    )
    .fetch_all(pool)
    .await
    {
        if !vault_rows.is_empty() {
            let cc_rows = sqlx::query("SELECT wallet_address, layout_state FROM user_command_centers")
                .fetch_all(pool)
                .await
                .unwrap_or_default();

            let worker_rows = sqlx::query(
                "SELECT wallet_address, COALESCE(SUM(GREATEST(hashrate_ths, 0.1)), 0.1) AS total_ths, COALESCE(SUM(GREATEST(valid_shares, 1)), 1) AS total_shares FROM worker_profiles GROUP BY wallet_address"
            )
            .fetch_all(pool)
            .await
            .unwrap_or_default();

            let mut miner_power_map: HashMap<String, f64> = HashMap::new();
            for wr in worker_rows {
                let w_addr: String = wr.try_get("wallet_address").unwrap_or_default();
                let clean_w = normalize_kaspa_base32(&w_addr);
                let ths: f64 = wr.try_get("total_ths").unwrap_or(1.0);
                let shares: i64 = wr.try_get("total_shares").unwrap_or(1);
                if !clean_w.is_empty() {
                    miner_power_map.insert(clean_w, (ths * (shares as f64).sqrt()).max(1.0));
                }
            }

            for vr in vault_rows {
                let vault_id: Uuid = vr.get("vault_id");
                let vault_ticker: String = vr.get::<String, _>("token_ticker").to_uppercase();
                let remaining_tokens: f64 = vr.get("remaining_vault_tokens");
                let daily_emission: f64 = vr.get("daily_emission_tokens");
                let dispatch_pool_tokens = daily_emission.min(remaining_tokens);
                if dispatch_pool_tokens <= 0.0 {
                    continue;
                }

                let mut participating_miners: Vec<(String, String, f64)> = Vec::new();
                let mut total_weighted_hash_score = 0.0;

                for ccr in &cc_rows {
                    let w_addr: String = ccr.try_get("wallet_address").unwrap_or_default();
                    let clean_w = normalize_kaspa_base32(&w_addr);
                    let prefixed_w = format!("kaspa:{}", clean_w);
                    let layout: Value = ccr.try_get("layout_state").unwrap_or_else(|_| json!({}));
                    let mut miner_ticker_pct = 0.0;
                    if let Some(sectors) = layout.get("sectors").and_then(|s| s.as_array()) {
                        for sec in sectors {
                            let target_tick = sec
                                .pointer("/settlementConfig/targetAsset/ticker")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .trim()
                                .to_uppercase();
                            let pct = sec
                                .get("allocationPercentage")
                                .and_then(|v| v.as_f64())
                                .unwrap_or(0.0);
                            if target_tick == vault_ticker && pct > 0.0 {
                                miner_ticker_pct += pct;
                            }
                        }
                    }
                    if miner_ticker_pct > 0.0 {
                        let base_power = miner_power_map.get(&clean_w).copied().unwrap_or(1.0);
                        let weight = base_power * (miner_ticker_pct / 100.0);
                        total_weighted_hash_score += weight;
                        participating_miners.push((clean_w, prefixed_w, weight));
                    }
                }

                let active_miners_count = participating_miners.len() as i32;
                if total_weighted_hash_score > 0.0 && !participating_miners.is_empty() {
                    for (clean_m, prefixed_m, weight) in participating_miners {
                        let share = (weight / total_weighted_hash_score).clamp(0.0, 1.0);
                        let miner_tokens = dispatch_pool_tokens * share;
                        if miner_tokens > 0.0 {
                            let ledger_key = format!("dev:sor:treasury:balances:{}", clean_m);
                            let _: () = redis::cmd("HINCRBYFLOAT")
                                .arg(&ledger_key)
                                .arg(&vault_ticker)
                                .arg(miner_tokens)
                                .query_async(redis_conn)
                                .await
                                .unwrap_or(());
                            let tx_ref = format!(
                                "POH-{}-{}",
                                vault_ticker,
                                &Uuid::new_v4().simple().to_string().to_uppercase()[..8]
                            );
                            let _ = sqlx::query(
                                r#"
                                INSERT INTO tax_ledger_events
                                (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash, payout_address)
                                VALUES ($1, $2, 'YIELD', 0.0, $3, 0.0, $4, $5)
                                "#
                            )
                            .bind(&clean_m)
                            .bind(&vault_ticker)
                            .bind(miner_tokens)
                            .bind(&tx_ref)
                            .bind(&prefixed_m)
                            .execute(pool)
                            .await;
                        }
                    }

                    let next_rem = (remaining_tokens - dispatch_pool_tokens).max(0.0);
                    let next_status = if next_rem <= 1e-6 { "DEPLETED" } else { "ACTIVE" };
                    let _ = sqlx::query(
                        r#"
                        UPDATE forge_mineable_vaults
                        SET remaining_vault_tokens = $1,
                            distributed_tokens = distributed_tokens + $2,
                            active_miners_count = $3,
                            status = $4,
                            last_bell_distributed_at = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE vault_id = $5
                        "#
                    )
                    .bind(next_rem)
                    .bind(dispatch_pool_tokens)
                    .bind(active_miners_count)
                    .bind(next_status)
                    .bind(vault_id)
                    .execute(pool)
                    .await;

                    tracing::info!(
                        "⛏️ [PROOF-OF-HASHRATE KRC-20 BELL] Distributed {:.4} {} pro-rata across {} ASIC miners.",
                        dispatch_pool_tokens,
                        vault_ticker,
                        active_miners_count
                    );
                } else {
                    let _ = sqlx::query(
                        "UPDATE forge_mineable_vaults SET active_miners_count = 0, updated_at = CURRENT_TIMESTAMP WHERE vault_id = $1"
                    )
                    .bind(vault_id)
                    .execute(pool)
                    .await;
                }
            }
        }
    }
}

pub async fn trigger_immediate_epoch_bell_sweep(pool: &PgPool) -> anyhow::Result<Value> {
    let redis_url = std::env::var("REDIS_URL")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = redis::Client::open(redis_url)?;
    let mut redis_conn = redis_client.get_multiplexed_async_connection().await?;
    let _: () = redis::cmd("SET")
        .arg("perennia:chronos:last_epoch_bell_ts")
        .arg(0u64)
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(());
    let _: () = redis::cmd("SET")
        .arg("perennia:chronos:force_bell_now")
        .arg("1")
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(());
    let http_client = get_secure_client();
    execute_settlement_tick(pool, &redis_client, &http_client).await?;
    let epoch_raw: Option<String> = redis::cmd("GET")
        .arg("perennia:settlement:epoch_telemetry")
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(None);
    let epoch_json = epoch_raw
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .unwrap_or_else(|| json!({}));
    Ok(epoch_json)
}

pub async fn start_chronos_daemon(pool: PgPool) {
    tracing::info!("⏳ Chronos Yield Accumulator & 22:00 UTC Global Settlement Bell Engine Armed.");
    let _ = sqlx::query("ALTER TABLE yield_reservoirs ADD COLUMN IF NOT EXISTS lp_tokens JSONB DEFAULT '{}'::jsonb")
        .execute(&pool)
        .await;
    let redis_url = std::env::var("REDIS_URL").map(|s| s.trim().to_string()).expect("CRITICAL: REDIS_URL environment variable is required.");
    let redis_client = redis::Client::open(redis_url).expect("Failed to connect to Redis for Chronos");
    let http_client = get_secure_client();
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    loop {
        interval.tick().await;
        if let Err(e) = execute_settlement_tick(&pool, &redis_client, &http_client).await {
            tracing::error!("🚨 Chronos Tick Error: {}", e);
        }
        if let Err(e) = process_unassigned_reserve_settlements(&pool, &redis_client).await {
            tracing::error!("🚨 Chronos Reserve Settlement Error: {}", e);
        }
    }
}

async fn get_oracle_price(
    pool: &PgPool,
    redis_conn: &mut redis::aio::MultiplexedConnection,
    ticker: &str,
) -> f64 {
    let clean = ticker.trim().to_uppercase();
    if clean == "USDC" || clean == "USDT" || clean == "USD" {
        return 1.0;
    }
    let key = format!("oracle:spot:{}_USDC", clean);
    let val_str: Option<String> = redis::cmd("GET").arg(&key).query_async(redis_conn).await.unwrap_or(None);
    if let Some(p) = val_str.and_then(|s| s.parse::<f64>().ok()).filter(|&v| v > 0.0) {
        return p;
    }
    if crate::oracle::is_pyth_rwa_asset(&clean) {
        if let Ok(Some(row)) = sqlx::query(
            "SELECT price_usd FROM rwa_oracle_feeds WHERE ticker = $1 AND price_usd > 0 ORDER BY updated_at DESC LIMIT 1"
        )
        .bind(&clean)
        .fetch_optional(pool)
        .await
        {
            let p = row.try_get::<f64, _>("price_usd").unwrap_or(0.0);
            if p > 0.0 {
                let _: () = redis::cmd("SET")
                    .arg(&key)
                    .arg(p.to_string())
                    .query_async(redis_conn)
                    .await
                    .unwrap_or(());
                return p;
            }
        }
    }
    0.0
}

async fn get_external_rail_cost_usd(redis_conn: &mut redis::aio::MultiplexedConnection, ticker: &str) -> f64 {
    let clean = ticker.trim().to_uppercase();
    let redis_key = format!("oracle:gas_fee_usd:{}", clean);
    if let Ok(Some(val_str)) = redis::cmd("GET").arg(&redis_key).query_async::<_, Option<String>>(redis_conn).await {
        if let Ok(parsed) = val_str.trim().parse::<f64>() {
            if parsed >= 0.0 {
                return parsed;
            }
        }
    }
    let env_key = format!("BATCH_RAIL_COST_USD_{}", clean);
    if let Ok(val_str) = std::env::var(&env_key) {
        if let Ok(parsed) = val_str.trim().parse::<f64>() {
            if parsed >= 0.0 {
                return parsed;
            }
        }
    }
    match clean.as_str() {
        "USD" => FIAT_ACH_RAIL_FEE_USD,
        "USDC" | "USDT" => 0.50,
        "SOL" | "SUI" | "TON" | "TRX" | "BASE" => 0.25,
        "SPY" | "QQQ" | "NVDA" | "AAPL" | "TSLA" | "AMD" | "TSM" | "AVGO" | "XLE" | "USTB" => 0.35,
        "XAU" | "XAG" => 0.75,
        "XRP" | "DOGE" | "ADA" | "LTC" | "POL" | "AVAX" | "ARB" | "ZEC" => 0.35,
        "ETH" | "LINK" => 1.50,
        "BTC" => 2.50,
        _ => 1.00,
    }
}

async fn get_lp_pool_reserves(pool: &PgPool, pool_pair: &str) -> (f64, f64) {
    let quote = pool_pair.split('/').nth(1).unwrap_or("USDC");
    crate::sor::get_lp_pair_reserves(pool, quote).await
}

fn evaluate_bucket_economics(
    asset: &str,
    accumulated_kas: f64,
    kas_price: f64,
    target_price: f64,
    rail_cost_usd: f64,
    l1_fee_usd: f64,
    lp_reserve_b_tokens: f64,
) -> (f64, f64, f64, f64, f64, f64) {
    let env_min_usd: f64 = std::env::var(format!("MIN_BATCH_USD_{}", asset.to_uppercase()))
        .or_else(|_| std::env::var("MIN_BATCH_USD"))
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .unwrap_or(0.0);
    let base_spread_rate: f64 = 0.015;
    let total_fixed_cost_usd: f64 = (rail_cost_usd + l1_fee_usd).max(0.05);
    let cost_derived_min_usd: f64 = (total_fixed_cost_usd * 2.0) / base_spread_rate;
    let min_profitable_usd: f64 = if asset.eq_ignore_ascii_case("USD") {
        MIN_FIAT_ACH_BATCH_USD.max(env_min_usd)
    } else {
        cost_derived_min_usd
            .max(env_min_usd)
            .max(crate::sor::get_min_dark_pool_position_usd())
    };
    let min_profitable_kas: f64 = if kas_price > 0.0 {
        min_profitable_usd / kas_price
    } else {
        0.0
    };
    let weight_pct: f64 = if min_profitable_kas > 0.0 {
        (accumulated_kas / min_profitable_kas) * 100.0
    } else {
        0.0
    };
    let lp_capacity_usd: f64 = lp_reserve_b_tokens * target_price;
    let lp_capacity_kas: f64 = if kas_price > 0.0 {
        lp_capacity_usd / kas_price
    } else {
        0.0
    };
    let lp_coverage_pct: f64 = if accumulated_kas > 0.0 {
        ((lp_capacity_kas / accumulated_kas) * 100.0).min(100.0)
    } else if lp_capacity_kas > 0.0 {
        100.0
    } else {
        0.0
    };
    let batch_gross_usd: f64 = accumulated_kas * kas_price;
    let tier_base_spread: f64 = if batch_gross_usd >= 2000.0 { 0.005 } else { 0.015 };
    let reference_usd: f64 = if batch_gross_usd > 0.0 { batch_gross_usd } else { min_profitable_usd.max(1.0) };
    let internal_share: f64 = if accumulated_kas > 0.0 {
        (lp_capacity_kas / accumulated_kas).clamp(0.0, 1.0)
    } else {
        (lp_capacity_usd / reference_usd).clamp(0.0, 1.0)
    };
    let external_share: f64 = 1.0 - internal_share;
    let external_cost_usd: f64 = l1_fee_usd + if external_share > 0.0 {
        rail_cost_usd + (reference_usd * external_share * EXTERNAL_CEX_TAKER_FEE_RATE)
    } else {
        0.0
    };
    let treasury_retention_fraction: f64 = (1.0_f64 - (0.80_f64 * internal_share)).max(0.20_f64);
    let required_treasury_gross_usd: f64 = external_cost_usd + (reference_usd * MIN_HOUSE_NET_MARGIN_RATE);
    let dynamic_floor_rate: f64 = (required_treasury_gross_usd / (reference_usd * treasury_retention_fraction)).clamp(0.0, 0.25);
    let effective_spread_rate: f64 = tier_base_spread.max(dynamic_floor_rate);
    (
        min_profitable_kas,
        min_profitable_usd,
        weight_pct,
        lp_capacity_kas,
        lp_coverage_pct,
        effective_spread_rate,
    )
}

async fn execute_settlement_tick(
    pool: &PgPool,
    redis_client: &redis::Client,
    http_client: &Client
) -> anyhow::Result<()> {
    let mut redis_conn = redis_client.get_multiplexed_async_connection().await?;
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let corp_kas_clean = resolve_master_treasury_address();
    let kas_price = get_oracle_price(pool, &mut redis_conn, "KAS").await;
    let min_dark_pool_usd = crate::sor::get_min_dark_pool_position_usd();
    let fee_per_gram = std::env::var("KASPA_FEE_PER_GRAM")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&v| v >= 100)
        .unwrap_or(110);
    let l1_fee_kas = ((2000u64 * fee_per_gram) as f64) / 100_000_000.0;
    let l1_fee_usd = l1_fee_kas * kas_price;
    let active_pool_workers: Vec<String> = redis::cmd("SMEMBERS")
        .arg("pool:workers")
        .query_async(&mut redis_conn)
        .await
        .unwrap_or_default();
    let addresses: Vec<String> = sqlx::query("SELECT wallet_address FROM user_command_centers")
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| row.get("wallet_address"))
        .collect();
    let mut swap_buckets: HashMap<String, Vec<SectorSwapParticipant>> = HashMap::new();
    for address in addresses {
        let state_row = sqlx::query("SELECT layout_state FROM user_command_centers WHERE wallet_address = $1")
            .bind(&address)
            .fetch_optional(pool)
            .await?;
        let state: Value = match state_row {
            Some(row) => row.get("layout_state"),
            None => continue,
        };
        let clean_address = normalize_kaspa_base32(&address);
        let prefixed_address = format!("kaspa:{}", clean_address);
        let is_treasury_self = !corp_kas_clean.is_empty() && clean_address == corp_kas_clean;
        let mut sum_of_individual_unpaid_yields = 0.0;
        let mut swept_yields: Vec<(String, f64)> = Vec::new();
        let blocks_keys = [
            format!("perennia:wallet:{}:blocks_unpaid", clean_address),
            format!("perennia:wallet:{}:blocks_unpaid", prefixed_address)
        ];
        for bk in blocks_keys {
            let _: () = redis::cmd("DEL").arg(&bk).query_async(&mut redis_conn).await.unwrap_or(());
        }
        let mut candidate_workers = HashSet::new();
        if let Some(workers) = state.get("workers").and_then(|w| w.as_array()) {
            for worker in workers {
                if let Some(ww) = worker.get("walletWorker").and_then(|v| v.as_str()) {
                    if !ww.is_empty() {
                        candidate_workers.insert(ww.to_string());
                    }
                }
            }
        }
        for pw in &active_pool_workers {
            let pw_clean = normalize_kaspa_base32(pw);
            if pw_clean == clean_address || pw_clean.starts_with(&format!("{}.", clean_address)) {
                candidate_workers.insert(pw.clone());
            }
        }
        for wallet_worker in candidate_workers {
            let clean_w = wallet_worker.replace("kaspa:", "");
            let yield_keys = [
                format!("worker:{}:unpaid_yield", wallet_worker),
                format!("worker:{}:unpaid_yield", clean_w),
                format!("worker:kaspa:{}:unpaid_yield", clean_w)
            ];
            for yk in yield_keys {
                let yield_str: Option<String> = redis::cmd("GETSET").arg(&yk).arg(0).query_async(&mut redis_conn).await.unwrap_or(None);
                if let Some(ys) = yield_str {
                    if let Ok(earned) = ys.parse::<f64>() {
                        if earned > 0.0 {
                            sum_of_individual_unpaid_yields += earned;
                            swept_yields.push((yk.clone(), earned));
                        }
                    }
                }
            }
            let block_keys = [
                format!("worker:{}:blocks_unpaid", wallet_worker),
                format!("worker:{}:blocks_unpaid", clean_w),
                format!("worker:kaspa:{}:blocks_unpaid", clean_w)
            ];
            for bk in block_keys {
                let _: () = redis::cmd("DEL").arg(&bk).query_async(&mut redis_conn).await.unwrap_or(());
            }
        }
        let total_earned_kaspa = sum_of_individual_unpaid_yields;
        if total_earned_kaspa > 0.0 {
            let mut total_allocated_pct_audit = 0.0;
            let mut total_distributed_audit = 0.0;
            if let Some(sectors) = state.get("sectors").and_then(|s| s.as_array()) {
                for sec in sectors {
                    let pct = sec.get("allocationPercentage").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    total_allocated_pct_audit += pct;
                    total_distributed_audit += total_earned_kaspa * (pct / 100.0);
                }
            }
            let unallocated_pct_audit = (100.0 - total_allocated_pct_audit).max(0.0);
            let unassigned_audit = total_earned_kaspa * (unallocated_pct_audit / 100.0);
            total_distributed_audit += unassigned_audit;
            let epsilon = 1e-8;
            if (total_earned_kaspa - total_distributed_audit).abs() > epsilon {
                for (key, amount) in swept_yields {
                    let _: () = redis::cmd("INCRBYFLOAT").arg(&key).arg(amount).query_async(&mut redis_conn).await.unwrap_or(());
                }
                continue;
            }
        }
        let mut sector_pending_map: HashMap<String, f64> = HashMap::new();
        let mut total_allocated_pct = 0.0;
        if let Some(sectors) = state.get("sectors").and_then(|s| s.as_array()) {
            for sec in sectors {
                let pct = sec.get("allocationPercentage").and_then(|v| v.as_f64()).unwrap_or(0.0);
                total_allocated_pct += pct;
                let newly_earned = total_earned_kaspa * (pct / 100.0);
                if let Some(id) = sec.get("id").and_then(|v| v.as_str()) {
                    let existing_pending = sec.get("pendingKaspa").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    sector_pending_map.insert(id.to_string(), existing_pending + newly_earned);
                }
            }
        }
        let unallocated_pct = (100.0 - total_allocated_pct).max(0.0);
        let unassigned_this_tick = total_earned_kaspa * (unallocated_pct / 100.0);
        let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_address);
        if is_treasury_self {
            if unassigned_this_tick > 0.0 {
                let _ = sqlx::query(
                    "INSERT INTO yield_reservoirs (wallet_address, streaming_balance_kas, total_yield_kas)
                     VALUES ($1, 0.0, $2::FLOAT8)
                     ON CONFLICT (wallet_address) DO UPDATE SET
                     streaming_balance_kas = 0.0,
                     total_yield_kas = yield_reservoirs.total_yield_kas + EXCLUDED.total_yield_kas,
                     last_updated = CURRENT_TIMESTAMP"
                )
                .bind(&prefixed_address)
                .bind(unassigned_this_tick)
                .execute(pool)
                .await;
            }
            let _: () = redis::cmd("HDEL")
                .arg(&user_ledger_key)
                .arg("Unassigned KAS")
                .query_async(&mut redis_conn)
                .await
                .unwrap_or(());
        } else if unassigned_this_tick > 0.0 {
            let reservoir_row = sqlx::query(
                "INSERT INTO yield_reservoirs (wallet_address, streaming_balance_kas, total_yield_kas)
                 VALUES ($1, $2::FLOAT8, $2::FLOAT8)
                 ON CONFLICT (wallet_address) DO UPDATE SET
                 streaming_balance_kas = GREATEST(0.0, yield_reservoirs.streaming_balance_kas) + EXCLUDED.streaming_balance_kas,
                 total_yield_kas = yield_reservoirs.total_yield_kas + EXCLUDED.total_yield_kas,
                 last_updated = CURRENT_TIMESTAMP
                 RETURNING streaming_balance_kas"
            )
            .bind(&prefixed_address)
            .bind(unassigned_this_tick)
            .fetch_optional(pool)
            .await?;
            if let Some(r) = reservoir_row {
                let synced_balance: f64 = r.try_get::<f64, _>("streaming_balance_kas").unwrap_or(0.0).max(0.0);
                let _: () = redis::cmd("HSET")
                    .arg(&user_ledger_key)
                    .arg("Unassigned KAS")
                    .arg(synced_balance)
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(());
            }
        }
        let mut updated_sectors_payload = None;
        let mut tx = pool.begin().await?;
        let latest_row = sqlx::query("SELECT layout_state FROM user_command_centers WHERE wallet_address = $1 FOR UPDATE")
            .bind(&address)
            .fetch_optional(&mut *tx)
            .await?;
        if let Some(row) = latest_row {
            let mut final_state: Value = row.get("layout_state");
            let (escrow_active, escrow_rate_fraction, escrow_lock_days) = extract_tax_escrow_config(&final_state);
            let mut state_mutated = false;
            if let Some(sectors) = final_state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                for sec in sectors.iter_mut() {
                    if let Some(id) = sec.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()) {
                        if let Some(&new_pending) = sector_pending_map.get(&id) {
                            let current_val = sec.get("pendingKaspa").and_then(|v| v.as_f64()).unwrap_or(0.0);
                            if (new_pending - current_val).abs() > 0.0 || (new_pending == 0.0 && current_val > 0.0) {
                                sec["pendingKaspa"] = json!(new_pending);
                                state_mutated = true;
                            }
                            let route_mode = sec.get("routeMode").and_then(|m| m.as_str()).unwrap_or("hold").to_string();
                            let last_settled_at = sec.get("lastSettledAt").and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))).unwrap_or(0);
                            let (target, mode, threshold, auto_payout, dest, appt_date, appt_time, plant_weights_opt) = if let Some(config) = sec.get("settlementConfig") {
                                (
                                    config.get("targetAsset").and_then(|a| a.get("ticker")).and_then(|t| t.as_str()).unwrap_or("KAS").to_uppercase(),
                                    config.get("mode").and_then(|m| m.as_str()).unwrap_or("epoch").to_string(),
                                    config.get("threshold").and_then(|t| t.as_f64()).unwrap_or(50.0),
                                    config.get("autoPayout").and_then(|a| a.as_bool()).unwrap_or(false),
                                    config.get("payoutAddress").and_then(|a| a.as_str()).unwrap_or(prefixed_address.as_str()).to_string(),
                                    config.get("appointmentDate").and_then(|d| d.as_str()).unwrap_or("").to_string(),
                                    config.get("appointmentTime").and_then(|t| t.as_str()).unwrap_or("17:00").to_string(),
                                    config.get("plantWeights").and_then(|v| v.as_object()).cloned(),
                                )
                            } else {
                                continue;
                            };
                            if !auto_payout || new_pending <= 0.0 {
                                continue;
                            }
                            let is_auto_swap_sector = route_mode == "auto-lp" || route_mode == "swap" || target != "KAS";
                            if is_auto_swap_sector {
                                let mut eligible_for_batch = true;
                                let mut clear_appointment = false;
                                if mode == "appointment" && !appt_date.trim().is_empty() {
                                    let dt_str = format!("{} {}", appt_date.trim(), appt_time.trim());
                                    if let Ok(scheduled_dt) = NaiveDateTime::parse_from_str(&dt_str, "%Y-%m-%d %H:%M") {
                                        if Utc::now().naive_utc() >= scheduled_dt {
                                            clear_appointment = true;
                                        } else {
                                            eligible_for_batch = false;
                                        }
                                    }
                                }
                                if eligible_for_batch {
                                    if route_mode == "auto-lp" {
                                        let mut sec_weights: Vec<(String, f64)> = Vec::new();
                                        if let Some(pw_obj) = plant_weights_opt {
                                            for (k, v) in pw_obj {
                                                let clean_t = k.trim().to_uppercase();
                                                if clean_t != "KAS" && !clean_t.is_empty() {
                                                    let w_pct = v.as_f64().unwrap_or(0.0).max(0.0);
                                                    if w_pct > 0.0 {
                                                        sec_weights.push((clean_t, w_pct));
                                                    }
                                                }
                                            }
                                        }
                                        if sec_weights.is_empty() {
                                            let default_sec = if target == "KAS" { "USDC".to_string() } else { target.clone() };
                                            sec_weights.push((default_sec, 50.0));
                                        }
                                        let sec_sum: f64 = sec_weights.iter().map(|(_, w)| *w).sum::<f64>().max(1e-9);
                                        let mut full_pair_list = vec!["KAS".to_string()];
                                        let mut normalized_plant_weights: HashMap<String, f64> = HashMap::new();
                                        normalized_plant_weights.insert("KAS".to_string(), 0.50);
                                        for (t, w) in &sec_weights {
                                            full_pair_list.push(t.clone());
                                            normalized_plant_weights.insert(t.clone(), (*w / sec_sum) * 0.50);
                                        }
                                        let plant_pair_str = full_pair_list.join("/");
                                        for (sec_ticker, raw_w) in sec_weights {
                                            let share_of_secondary = (raw_w / sec_sum).clamp(0.0, 1.0);
                                            let leg_pending_kas = new_pending * share_of_secondary;
                                            let leg_swap_kas = (new_pending * 0.50) * share_of_secondary;
                                            let leg_kas_half = (new_pending * 0.50) * share_of_secondary;
                                            swap_buckets
                                                .entry(sec_ticker.clone())
                                                .or_default()
                                                .push(SectorSwapParticipant {
                                                    wallet_db_key: address.clone(),
                                                    clean_wallet: clean_address.clone(),
                                                    prefixed_wallet: prefixed_address.clone(),
                                                    payout_address: if dest.trim().is_empty() { prefixed_address.clone() } else { dest.clone() },
                                                    sector_id: id.clone(),
                                                    route_mode: route_mode.clone(),
                                                    target_asset: sec_ticker,
                                                    plant_pair: plant_pair_str.clone(),
                                                    plant_weights: normalized_plant_weights.clone(),
                                                    total_sector_pending_kas: new_pending,
                                                    total_pending_kas: leg_pending_kas,
                                                    swap_kas: leg_swap_kas,
                                                    lp_pair_kas_half: leg_kas_half,
                                                    clear_appointment,
                                                });
                                        }
                                    } else {
                                        let mut single_w = HashMap::new();
                                        single_w.insert(target.clone(), 1.0);
                                        swap_buckets
                                            .entry(target.clone())
                                            .or_default()
                                            .push(SectorSwapParticipant {
                                                wallet_db_key: address.clone(),
                                                clean_wallet: clean_address.clone(),
                                                prefixed_wallet: prefixed_address.clone(),
                                                payout_address: if dest.trim().is_empty() { prefixed_address.clone() } else { dest.clone() },
                                                sector_id: id.clone(),
                                                route_mode: route_mode.clone(),
                                                target_asset: target.clone(),
                                                plant_pair: format!("KAS/{}", target),
                                                plant_weights: single_w,
                                                total_sector_pending_kas: new_pending,
                                                total_pending_kas: new_pending,
                                                swap_kas: new_pending,
                                                lp_pair_kas_half: 0.0,
                                                clear_appointment,
                                            });
                                    }
                                }
                            } else {
                                let dest_clean = normalize_kaspa_base32(&dest);
                                let is_house_anchor_kas = is_treasury_self || (!corp_kas_clean.is_empty() && dest_clean == corp_kas_clean);
                                let mut should_settle = false;
                                let mut clear_appointment = false;
                                if is_house_anchor_kas {
                                    should_settle = true;
                                } else if new_pending >= _SECTOR_MINIMUM_THRESHOLD {
                                    if mode == "threshold" {
                                        if new_pending >= threshold {
                                            should_settle = true;
                                        }
                                    } else if mode == "epoch" {
                                        let (current_bell_ts, _, _) = compute_jerusalem_epoch_window(now_secs);
                                        if last_settled_at == 0 {
                                            sec["lastSettledAt"] = json!(current_bell_ts);
                                            state_mutated = true;
                                        } else if last_settled_at < current_bell_ts {
                                            should_settle = true;
                                        }
                                    } else if mode == "appointment" && !appt_date.trim().is_empty() {
                                        let dt_str = format!("{} {}", appt_date.trim(), appt_time.trim());
                                        if let Ok(scheduled_dt) = NaiveDateTime::parse_from_str(&dt_str, "%Y-%m-%d %H:%M") {
                                            if Utc::now().naive_utc() >= scheduled_dt {
                                                should_settle = true;
                                                clear_appointment = true;
                                            }
                                        }
                                    }
                                }
                                if should_settle && kas_price > 0.0 {
                                    let execute_amount = new_pending;
                                    if is_house_anchor_kas {
                                        let _ = sqlx::query("INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash, payout_address) VALUES ($1, 'KAS', 'YIELD', $2, $3, $4, 'TREASURY_HOUSE_ANCHOR', $5)")
                                            .bind(&clean_address)
                                            .bind(execute_amount * kas_price)
                                            .bind(execute_amount)
                                            .bind(kas_price)
                                            .bind(&prefixed_address)
                                            .execute(&mut *tx)
                                            .await;
                                        sec["pendingKaspa"] = json!(0.0);
                                        sec["lastSettledAt"] = json!(now_secs);
                                        if clear_appointment {
                                            sec["settlementConfig"]["appointmentDate"] = json!("");
                                        }
                                        state_mutated = true;
                                    } else {
                                        let (escrow_kas, net_physical_kas) = if escrow_active && escrow_rate_fraction > 0.0 {
                                            let withheld = execute_amount * escrow_rate_fraction;
                                            (withheld, (execute_amount - withheld).max(0.0))
                                        } else {
                                            (0.0, execute_amount)
                                        };
                                        let dest_clone = dest.clone();
                                        let settle_res = if net_physical_kas > 0.0 {
                                            crate::sor::execute_physical_settlement(&dest_clone, net_physical_kas).await
                                        } else {
                                            Ok("TAX_ESCROW_FULL_INTERCEPT".to_string())
                                        };
                                        match settle_res {
                                            Ok(tx_id) => {
                                                let _ = sqlx::query("INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash, payout_address) VALUES ($1, 'KAS', 'YIELD', $2, $3, $4, $5, $6)")
                                                    .bind(&clean_address)
                                                    .bind(execute_amount * kas_price)
                                                    .bind(execute_amount)
                                                    .bind(kas_price)
                                                    .bind(&tx_id)
                                                    .bind(&dest_clone)
                                                    .execute(&mut *tx)
                                                    .await;
                                                if escrow_kas > 0.0 {
                                                    let _ = route_tax_escrow_auto_lp(
                                                        &mut tx,
                                                        &prefixed_address,
                                                        &clean_address,
                                                        escrow_kas,
                                                        kas_price,
                                                        escrow_lock_days,
                                                    )
                                                    .await;
                                                }
                                                sec["pendingKaspa"] = json!(0.0);
                                                sec["lastSettledAt"] = json!(now_secs);
                                                if clear_appointment {
                                                    sec["settlementConfig"]["appointmentDate"] = json!("");
                                                }
                                                state_mutated = true;
                                            }
                                            Err(_) => {
                                                if escrow_kas > 0.0 {
                                                    let _ = route_tax_escrow_auto_lp(
                                                        &mut tx,
                                                        &prefixed_address,
                                                        &clean_address,
                                                        escrow_kas,
                                                        kas_price,
                                                        escrow_lock_days,
                                                    )
                                                    .await;
                                                }
                                                let _ = crate::state_api::dispatch_or_queue_multi_chain_l1(
                                                    &mut tx,
                                                    &mut redis_conn,
                                                    &prefixed_address,
                                                    &clean_address,
                                                    &dest_clone,
                                                    "KAS",
                                                    net_physical_kas,
                                                    kas_price,
                                                    "chronos_epoch_bell",
                                                )
                                                .await;
                                                sec["pendingKaspa"] = json!(0.0);
                                                sec["lastSettledAt"] = json!(now_secs);
                                                if clear_appointment {
                                                    sec["settlementConfig"]["appointmentDate"] = json!("");
                                                }
                                                state_mutated = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if state_mutated {
                sqlx::query("UPDATE user_command_centers SET layout_state = $1, last_updated = CURRENT_TIMESTAMP WHERE wallet_address = $2")
                    .bind(&final_state)
                    .bind(&address)
                    .execute(&mut *tx)
                    .await?;
                updated_sectors_payload = Some(final_state.get("sectors").cloned().unwrap_or_else(|| json!([])));
            }
        }
        let _ = tx.commit().await;
        if let Some(sectors) = updated_sectors_payload {
            let yield_update_payload = json!({
                "wallet": clean_address,
                "yield_update": true,
                "sectors": sectors
            });
            let _: () = redis::cmd("PUBLISH")
                .arg("telemetry:updates")
                .arg(yield_update_payload.to_string())
                .query_async(&mut redis_conn)
                .await
                .unwrap_or(());
        }
    }
    let (current_epoch_bell_ts, next_epoch_bell_ts, seconds_remaining) = compute_jerusalem_epoch_window(now_secs);
    let volatility_sweep_threshold_pct = get_volatility_sweep_threshold_pct();
    let last_bell_key = "perennia:chronos:last_epoch_bell_ts";
    let force_bell_flag: Option<String> = redis::cmd("GETDEL")
        .arg("perennia:chronos:force_bell_now")
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(None);
    let is_forced_bell = force_bell_flag.as_deref() == Some("1");
    let stored_last_bell: Option<u64> = redis::cmd("GET")
        .arg(last_bell_key)
        .query_async::<_, Option<String>>(&mut redis_conn)
        .await
        .ok()
        .flatten()
        .and_then(|s| s.parse::<u64>().ok());
    let is_bell_ringing = if is_forced_bell {
        true
    } else {
        match stored_last_bell {
            Some(last_ts) => current_epoch_bell_ts > last_ts,
            None => {
                let ring_now = now_secs.saturating_sub(current_epoch_bell_ts) <= 60;
                if !ring_now {
                    let _: () = redis::cmd("SET")
                        .arg(last_bell_key)
                        .arg(current_epoch_bell_ts)
                        .query_async(&mut redis_conn)
                        .await
                        .unwrap_or(());
                }
                ring_now
            }
        }
    };
    if is_bell_ringing {
        tracing::info!(
            "🔔🔔🔔 [22:00 UTC GLOBAL SETTLEMENT BELL] Evaluating pool-wide multi-asset silos, Proof-of-Lock Vesting, Auto-Burn Sinks, Mineable KRC-20 Vaults & Liquidity Plants... 🔔🔔🔔"
        );
        let _: () = redis::cmd("SET")
            .arg(last_bell_key)
            .arg(current_epoch_bell_ts)
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(());
        rebalance_multi_asset_liquidity_plants(pool, &mut redis_conn, kas_price).await;
        process_forge_2200_utc_bell_covenants(pool, &mut redis_conn).await;
    }
    let mut all_bucket_tickers: Vec<String> = TRACKED_CORE_BUCKETS.iter().map(|s| s.to_string()).collect();
    if let Ok(active_pairs) = sqlx::query("SELECT DISTINCT pool_pair FROM liquidity_providers")
        .fetch_all(pool)
        .await
    {
        for row in active_pairs {
            if let Ok(pair_str) = row.try_get::<String, _>("pool_pair") {
                for quote in pair_str.split('/').skip(1) {
                    let q_clean = quote.trim().to_uppercase();
                    if !q_clean.is_empty() && q_clean != "KAS" && !all_bucket_tickers.contains(&q_clean) {
                        all_bucket_tickers.push(q_clean);
                    }
                }
            }
        }
    }
    for k in swap_buckets.keys() {
        if !all_bucket_tickers.contains(k) {
            all_bucket_tickers.push(k.clone());
        }
    }
    let cex_configured = crate::sor::is_cex_hedging_configured();
    let max_unhedged_kas = crate::sor::get_max_unhedged_liability_kas();
    let unhedged_str: Option<String> = redis::cmd("GET")
        .arg("perennia:treasury:unhedged_delta_kas")
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(None);
    let mut current_unhedged_sell_kas = (-unhedged_str.and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0)).max(0.0);
    let mut buckets_telemetry_map: HashMap<String, AssetBucketTelemetry> = HashMap::new();
    for asset in all_bucket_tickers {
        let participants = swap_buckets.remove(&asset).unwrap_or_default();
        let accumulated_kas: f64 = participants.iter().map(|p| p.swap_kas).sum();
        let participant_count = participants.len();
        let is_oracle_supported = crate::oracle::is_oracle_supported_asset(&asset);
        let mut target_price = if is_oracle_supported {
            get_oracle_price(pool, &mut redis_conn, &asset).await
        } else {
            0.0
        };
        let rail_cost_usd = get_external_rail_cost_usd(&mut redis_conn, &asset).await;
        let pool_pair = if asset == "USD" {
            "KAS/USDC".to_string()
        } else {
            format!("KAS/{}", asset)
        };
        let (_lp_reserve_a_kas, lp_reserve_b_target) = if is_oracle_supported {
            get_lp_pool_reserves(pool, &pool_pair).await
        } else {
            (0.0, 0.0)
        };
        let (
            min_profitable_kas,
            min_profitable_usd,
            weight_pct,
            lp_capacity_kas,
            lp_coverage_pct,
            effective_spread_rate,
        ) = evaluate_bucket_economics(
            &asset,
            accumulated_kas,
            kas_price,
            if target_price > 0.0 { target_price } else { 1.0 },
            rail_cost_usd,
            l1_fee_usd,
            lp_reserve_b_target,
        );
        let meta_key = format!("perennia:settlement:bucket_meta:{}", asset);
        let prev_meta_str: Option<String> = redis::cmd("GET").arg(&meta_key).query_async(&mut redis_conn).await.unwrap_or(None);
        let (mut last_cleared_at, mut last_clear_type, mut bucket_status) = if let Some(ms) = prev_meta_str {
            if let Ok(v) = serde_json::from_str::<Value>(&ms) {
                (
                    v.get("lastClearedAt").and_then(|x| x.as_u64()).unwrap_or(0),
                    v.get("lastClearType").and_then(|x| x.as_str()).unwrap_or("NONE").to_string(),
                    v.get("status").and_then(|x| x.as_str()).unwrap_or("ACCUMULATING").to_string(),
                )
            } else {
                (0, "NONE".to_string(), "ACCUMULATING".to_string())
            }
        } else {
            (0, "NONE".to_string(), "ACCUMULATING".to_string())
        };
        if asset == "USD" {
            let internal_lp_kas = accumulated_kas.min(lp_capacity_kas);
            let external_cex_kas = (accumulated_kas - internal_lp_kas).max(0.0);
            let available_unhedged_headroom_kas = (max_unhedged_kas - current_unhedged_sell_kas).max(0.0);
            let unhedged_safe_to_clear = cex_configured || external_cex_kas <= available_unhedged_headroom_kas;
            let is_volatility_sweep = weight_pct >= volatility_sweep_threshold_pct && accumulated_kas > 0.0 && unhedged_safe_to_clear;
            let is_daily_epoch_clear = is_bell_ringing && weight_pct >= 100.0 && accumulated_kas > 0.0 && unhedged_safe_to_clear;
            if (is_volatility_sweep || is_daily_epoch_clear) && kas_price > 0.0 {
                let clear_reason = if is_volatility_sweep {
                    "USD_SILO_VOLATILITY_SWEEP"
                } else {
                    "USD_SILO_EPOCH_2200_UTC"
                };
                let mut cleared_any_usd_silo = false;
                let mut remaining_pending_kas = 0.0;
                let mut remaining_participants = 0usize;
                let mut participants_by_wallet: HashMap<String, Vec<SectorSwapParticipant>> = HashMap::new();
                for p in participants {
                    participants_by_wallet.entry(p.wallet_db_key.clone()).or_default().push(p);
                }
                for (wallet_db_key, wallet_participants) in participants_by_wallet {
                    let clean_w = normalize_kaspa_base32(&wallet_db_key);
                    let prefixed_w = format!("kaspa:{}", clean_w);
                    let bank_rail_row = sqlx::query(
                        "SELECT payout_method, bank_last4 FROM fiat_bank_rails WHERE wallet_address = $1 OR wallet_address = $2 LIMIT 1"
                    )
                    .bind(&prefixed_w)
                    .bind(&clean_w)
                    .fetch_optional(pool)
                    .await
                    .ok()
                    .flatten();
                    let Some(rail) = bank_rail_row else {
                        for part in &wallet_participants {
                            remaining_pending_kas += part.swap_kas;
                            remaining_participants += 1;
                        }
                        continue;
                    };
                    let saved_payout_method = rail
                        .try_get::<String, _>("payout_method")
                        .unwrap_or_else(|_| "ACH".to_string())
                        .to_uppercase();
                    let saved_bank_last4 = rail
                        .try_get::<String, _>("bank_last4")
                        .unwrap_or_else(|_| "0000".to_string());
                    let mut tx_user = pool.begin().await?;
                    let row_opt = sqlx::query("SELECT layout_state FROM user_command_centers WHERE wallet_address = $1 FOR UPDATE")
                        .bind(&wallet_db_key)
                        .fetch_optional(&mut *tx_user)
                        .await?;
                    if let Some(row) = row_opt {
                        let mut user_state: Value = row.get("layout_state");
                        let (escrow_active, escrow_rate_fraction, escrow_lock_days) = extract_tax_escrow_config(&user_state);
                        let mut user_mutated = false;
                        let mut pending_fiat_sse_events: Vec<Value> = Vec::new();
                        for part in &wallet_participants {
                            let (escrow_kas, payout_kas) = if escrow_active && escrow_rate_fraction > 0.0 {
                                let withheld = part.total_pending_kas * escrow_rate_fraction;
                                (withheld, (part.total_pending_kas - withheld).max(0.0))
                            } else {
                                (0.0, part.total_pending_kas)
                            };
                            let gross_usd = payout_kas * kas_price;
                            if gross_usd + 1e-6 < MIN_FIAT_ACH_BATCH_USD {
                                remaining_pending_kas += part.swap_kas;
                                remaining_participants += 1;
                                continue;
                            }
                            if escrow_kas > 0.0 {
                                let _ = route_tax_escrow_auto_lp(
                                    &mut tx_user,
                                    &part.prefixed_wallet,
                                    &part.clean_wallet,
                                    escrow_kas,
                                    kas_price,
                                    escrow_lock_days,
                                )
                                .await;
                            }
                            let is_whale = gross_usd >= 2000.0;
                            let spread_rate = if is_whale {
                                0.005
                            } else {
                                effective_spread_rate.max(0.015)
                            };
                            let rail_fee_usd = if is_whale {
                                0.0
                            } else if saved_payout_method == "WIRE" {
                                FIAT_WIRE_RAIL_FEE_USD
                            } else {
                                FIAT_ACH_RAIL_FEE_USD
                            };
                            let fee_usd = ((gross_usd * spread_rate + rail_fee_usd) * 100.0).round() / 100.0;
                            let net_fiat_usd = ((gross_usd - fee_usd).max(0.0) * 100.0).round() / 100.0;
                            if net_fiat_usd <= 0.0 {
                                remaining_pending_kas += part.swap_kas;
                                remaining_participants += 1;
                                continue;
                            }
                            let uuid_hex = Uuid::new_v4().simple().to_string().to_uppercase();
                            let payout_id = format!("PER-ACH-{}", &uuid_hex[..10]);
                            let settlement_tx_id = format!("CHRONOS-USD-{}", &uuid_hex[..12]);
                            let _ = sqlx::query(
                                r#"
                                INSERT INTO fiat_payout_queue
                                (payout_id, wallet_address, source_type, source_asset, amount_crypto, gross_usd, fee_usd, net_fiat_usd, payout_method, bank_last4, tx_id, status)
                                VALUES ($1, $2, 'chronos_usd_silo', 'KAS', $3, $4, $5, $6, $7, $8, $9, 'QUEUED_FOR_TREASURY_DISPATCH')
                                "#
                            )
                            .bind(&payout_id)
                            .bind(&part.prefixed_wallet)
                            .bind(payout_kas)
                            .bind((gross_usd * 100.0).round() / 100.0)
                            .bind(fee_usd)
                            .bind(net_fiat_usd)
                            .bind(&saved_payout_method)
                            .bind(&saved_bank_last4)
                            .bind(&settlement_tx_id)
                            .execute(&mut *tx_user)
                            .await;
                            let _ = sqlx::query(
                                "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash, payout_address) VALUES ($1, 'KAS', 'FIAT_OFFRAMP', $2, $3, $4, $5, $6)"
                            )
                            .bind(&part.clean_wallet)
                            .bind(gross_usd)
                            .bind(payout_kas)
                            .bind(kas_price)
                            .bind(&payout_id)
                            .bind(format!("*{}", saved_bank_last4))
                            .execute(&mut *tx_user)
                            .await;
                            if let Some(sectors) = user_state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                                for sec in sectors.iter_mut() {
                                    if sec.get("id").and_then(|v| v.as_str()) == Some(&part.sector_id) {
                                        sec["pendingKaspa"] = json!(0.0);
                                        sec["lastSettledAt"] = json!(now_secs);
                                        if part.clear_appointment {
                                            sec["settlementConfig"]["appointmentDate"] = json!("");
                                        }
                                        user_mutated = true;
                                    }
                                }
                            }
                            let payout_record_json = json!({
                                "payoutId": payout_id,
                                "walletAddress": part.prefixed_wallet,
                                "sourceType": "chronos_usd_silo",
                                "sourceAsset": "KAS",
                                "amountCrypto": payout_kas,
                                "grossUsd": (gross_usd * 100.0).round() / 100.0,
                                "feeUsd": fee_usd,
                                "netFiatUsd": net_fiat_usd,
                                "payoutMethod": saved_payout_method,
                                "bankLast4": saved_bank_last4,
                                "txId": settlement_tx_id,
                                "status": "QUEUED_FOR_TREASURY_DISPATCH",
                                "createdAt": Utc::now().to_rfc3339()
                            });
                            let _: () = redis::cmd("LPUSH")
                                .arg("perennia:fiat:payout_queue")
                                .arg(payout_record_json.to_string())
                                .query_async(&mut redis_conn)
                                .await
                                .unwrap_or(());
                            let _: () = redis::cmd("LTRIM")
                                .arg("perennia:fiat:payout_queue")
                                .arg(0)
                                .arg(199)
                                .query_async(&mut redis_conn)
                                .await
                                .unwrap_or(());
                            let netting_order = json!({
                                "wallet": part.prefixed_wallet,
                                "direction": "SELL_KAS",
                                "amount_kas": payout_kas,
                                "spot_price": kas_price,
                                "fee_captured_usd": fee_usd,
                                "target_asset": "USD",
                                "estimated_output": net_fiat_usd
                            });
                            let _: () = redis::cmd("RPUSH")
                                .arg("perennia:sor:netting_queue")
                                .arg(netting_order.to_string())
                                .query_async(&mut redis_conn)
                                .await
                                .unwrap_or(());
                            pending_fiat_sse_events.push(json!({
                                "fiat_event": true,
                                "eventType": "FIAT_OFFRAMP",
                                "wallet": part.clean_wallet,
                                "payout": payout_record_json
                            }));
                            cleared_any_usd_silo = true;
                        }
                        if user_mutated {
                            sqlx::query("UPDATE user_command_centers SET layout_state = $1, last_updated = CURRENT_TIMESTAMP WHERE wallet_address = $2")
                                .bind(&user_state)
                                .bind(&wallet_db_key)
                                .execute(&mut *tx_user)
                                .await?;
                        }
                        tx_user.commit().await?;
                        if user_mutated {
                            let yield_update = json!({
                                "wallet": clean_w,
                                "yield_update": true,
                                "sectors": user_state.get("sectors").cloned().unwrap_or_else(|| json!([]))
                            });
                            let _: () = redis::cmd("PUBLISH")
                                .arg("telemetry:updates")
                                .arg(yield_update.to_string())
                                .query_async(&mut redis_conn)
                                .await
                                .unwrap_or(());
                            for evt in pending_fiat_sse_events {
                                let _: () = redis::cmd("PUBLISH")
                                    .arg("telemetry:updates")
                                    .arg(evt.to_string())
                                    .query_async(&mut redis_conn)
                                    .await
                                    .unwrap_or(());
                            }
                        }
                    } else {
                        let _ = tx_user.rollback().await;
                    }
                }
                if cleared_any_usd_silo {
                    last_cleared_at = now_secs;
                    last_clear_type = clear_reason.to_string();
                    bucket_status = if is_volatility_sweep {
                        "SWEPT_VOLATILITY".to_string()
                    } else {
                        "CLEARED_EPOCH".to_string()
                    };
                } else {
                    bucket_status = "ROLLED_OVER".to_string();
                }
                let meta_val = json!({
                    "lastClearedAt": last_cleared_at,
                    "lastClearType": last_clear_type,
                    "status": bucket_status
                });
                let _: () = redis::cmd("SET")
                    .arg(&meta_key)
                    .arg(meta_val.to_string())
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(());
                let rem_weight_pct = if min_profitable_kas > 0.0 {
                    (remaining_pending_kas / min_profitable_kas) * 100.0
                } else {
                    0.0
                };
                buckets_telemetry_map.insert(
                    asset.clone(),
                    AssetBucketTelemetry {
                        asset: asset.clone(),
                        pendingKas: remaining_pending_kas,
                        pendingUsd: remaining_pending_kas * kas_price,
                        minProfitableKas: min_profitable_kas,
                        minProfitableUsd: min_profitable_usd,
                        weightPct: rem_weight_pct,
                        participantCount: remaining_participants,
                        lpAvailableKasCapacity: lp_capacity_kas,
                        lpCoveragePct: lp_coverage_pct,
                        effectiveSpreadFloorPct: effective_spread_rate * 100.0,
                        railCostUsd: rail_cost_usd,
                        status: bucket_status,
                        lastClearedAt: last_cleared_at,
                        lastClearType: last_clear_type,
                    },
                );
                continue;
            } else {
                if is_bell_ringing && accumulated_kas > 0.0 {
                    bucket_status = "ROLLED_OVER".to_string();
                    let meta_val = json!({
                        "lastClearedAt": last_cleared_at,
                        "lastClearType": last_clear_type,
                        "status": bucket_status
                    });
                    let _: () = redis::cmd("SET")
                        .arg(&meta_key)
                        .arg(meta_val.to_string())
                        .query_async(&mut redis_conn)
                        .await
                        .unwrap_or(());
                } else if weight_pct >= 100.0 && unhedged_safe_to_clear {
                    bucket_status = "READY_FOR_BELL".to_string();
                } else if accumulated_kas > 0.0 && bucket_status != "ROLLED_OVER" {
                    bucket_status = "ACCUMULATING".to_string();
                } else if accumulated_kas == 0.0 {
                    bucket_status = "IDLE".to_string();
                }
                buckets_telemetry_map.insert(
                    asset.clone(),
                    AssetBucketTelemetry {
                        asset: asset.clone(),
                        pendingKas: accumulated_kas,
                        pendingUsd: accumulated_kas * kas_price,
                        minProfitableKas: min_profitable_kas,
                        minProfitableUsd: min_profitable_usd,
                        weightPct: weight_pct,
                        participantCount: participant_count,
                        lpAvailableKasCapacity: lp_capacity_kas,
                        lpCoveragePct: lp_coverage_pct,
                        effectiveSpreadFloorPct: effective_spread_rate * 100.0,
                        railCostUsd: rail_cost_usd,
                        status: bucket_status,
                        lastClearedAt: last_cleared_at,
                        lastClearType: last_clear_type,
                    },
                );
                continue;
            }
        }
        if !is_oracle_supported {
            let is_volatility_sweep = weight_pct >= volatility_sweep_threshold_pct && accumulated_kas > 0.0;
            let is_daily_epoch_clear = is_bell_ringing && weight_pct >= 100.0 && accumulated_kas > 0.0;
            if (is_volatility_sweep || is_daily_epoch_clear) && kas_price > 0.0 {
                target_price = fetch_third_party_passthrough_price_usd(http_client, &asset, kas_price).await;
            }
            if (is_volatility_sweep || is_daily_epoch_clear) && kas_price > 0.0 && target_price > 0.0 {
                let clear_reason = if is_volatility_sweep {
                    "PASSTHROUGH_VOLATILITY_SWEEP"
                } else {
                    "PASSTHROUGH_EPOCH_2200_UTC"
                };
                let upfront_fee_kas = accumulated_kas * LONG_TAIL_PASSTHROUGH_FEE_RATE;
                let net_passthrough_kas = (accumulated_kas - upfront_fee_kas).max(0.0);
                let net_batch_usd = net_passthrough_kas * kas_price;
                let total_net_target_output = net_batch_usd / target_price;
                let _: () = redis::cmd("INCRBYFLOAT")
                    .arg("perennia:fees:batch_accumulated:KAS")
                    .arg(upfront_fee_kas)
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(());
                let mut participants_by_wallet: HashMap<String, Vec<SectorSwapParticipant>> = HashMap::new();
                for p in participants {
                    participants_by_wallet.entry(p.wallet_db_key.clone()).or_default().push(p);
                }
                for (wallet_db_key, wallet_participants) in participants_by_wallet {
                    let mut tx_user = pool.begin().await?;
                    let row_opt = sqlx::query("SELECT layout_state FROM user_command_centers WHERE wallet_address = $1 FOR UPDATE")
                        .bind(&wallet_db_key)
                        .fetch_optional(&mut *tx_user)
                        .await?;
                    if let Some(row) = row_opt {
                        let mut user_state: Value = row.get("layout_state");
                        let (escrow_active, escrow_rate_fraction, escrow_lock_days) = extract_tax_escrow_config(&user_state);
                        let mut user_mutated = false;
                        for part in &wallet_participants {
                            let pro_rata_share = if accumulated_kas > 0.0 {
                                (part.total_pending_kas / accumulated_kas).clamp(0.0, 1.0)
                            } else {
                                0.0
                            };
                            let gross_miner_target_proceeds = total_net_target_output * pro_rata_share;
                            let (escrow_kas, net_fraction) = if escrow_active && escrow_rate_fraction > 0.0 {
                                (part.total_pending_kas * escrow_rate_fraction, (1.0 - escrow_rate_fraction).max(0.0))
                            } else {
                                (0.0, 1.0)
                            };
                            if escrow_kas > 0.0 {
                                let _ = route_tax_escrow_auto_lp(
                                    &mut tx_user,
                                    &part.prefixed_wallet,
                                    &part.clean_wallet,
                                    escrow_kas,
                                    kas_price,
                                    escrow_lock_days,
                                )
                                .await;
                            }
                            let miner_target_proceeds = gross_miner_target_proceeds * net_fraction;
                            let miner_fee_kas = (part.total_pending_kas * net_fraction) * LONG_TAIL_PASSTHROUGH_FEE_RATE;
                            let miner_net_kas = ((part.total_pending_kas * net_fraction) - miner_fee_kas).max(0.0);
                            let passthrough_order = json!({
                                "wallet": part.prefixed_wallet,
                                "destination_l1_address": part.payout_address,
                                "target_asset": asset,
                                "gross_kas": part.total_pending_kas * net_fraction,
                                "upfront_fee_kas": miner_fee_kas,
                                "net_passthrough_kas": miner_net_kas,
                                "estimated_output": miner_target_proceeds,
                                "spot_price": target_price,
                                "timestamp": now_secs
                            });
                            let _: () = redis::cmd("RPUSH")
                                .arg("perennia:sor:third_party_passthrough_queue")
                                .arg(passthrough_order.to_string())
                                .query_async(&mut redis_conn)
                                .await
                                .unwrap_or(());
                            let _ = crate::state_api::dispatch_or_queue_multi_chain_l1(
                                &mut tx_user,
                                &mut redis_conn,
                                &part.prefixed_wallet,
                                &part.clean_wallet,
                                &part.payout_address,
                                &asset,
                                miner_target_proceeds,
                                target_price,
                                "chronos_epoch_bell",
                            )
                            .await;
                            if let Some(sectors) = user_state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                                for sec in sectors.iter_mut() {
                                    if sec.get("id").and_then(|v| v.as_str()) == Some(&part.sector_id) {
                                        sec["pendingKaspa"] = json!(0.0);
                                        sec["lastSettledAt"] = json!(now_secs);
                                        if part.clear_appointment {
                                            sec["settlementConfig"]["appointmentDate"] = json!("");
                                        }
                                        user_mutated = true;
                                    }
                                }
                            }
                        }
                        if user_mutated {
                            sqlx::query("UPDATE user_command_centers SET layout_state = $1, last_updated = CURRENT_TIMESTAMP WHERE wallet_address = $2")
                                .bind(&user_state)
                                .bind(&wallet_db_key)
                                .execute(&mut *tx_user)
                                .await?;
                            let clean_w = normalize_kaspa_base32(&wallet_db_key);
                            let yield_update = json!({
                                "wallet": clean_w,
                                "yield_update": true,
                                "sectors": user_state.get("sectors").cloned().unwrap_or_else(|| json!([]))
                            });
                            let _: () = redis::cmd("PUBLISH")
                                .arg("telemetry:updates")
                                .arg(yield_update.to_string())
                                .query_async(&mut redis_conn)
                                .await
                                .unwrap_or(());
                        }
                    }
                    let _ = tx_user.commit().await;
                }
                last_cleared_at = now_secs;
                last_clear_type = clear_reason.to_string();
                bucket_status = "CLEARED_EPOCH".to_string();
                let meta_val = json!({
                    "lastClearedAt": last_cleared_at,
                    "lastClearType": last_clear_type,
                    "status": bucket_status
                });
                let _: () = redis::cmd("SET")
                    .arg(&meta_key)
                    .arg(meta_val.to_string())
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(());
                buckets_telemetry_map.insert(
                    asset.clone(),
                    AssetBucketTelemetry {
                        asset: asset.clone(),
                        pendingKas: 0.0,
                        pendingUsd: 0.0,
                        minProfitableKas: min_profitable_kas,
                        minProfitableUsd: min_profitable_usd,
                        weightPct: 0.0,
                        participantCount: 0,
                        lpAvailableKasCapacity: 0.0,
                        lpCoveragePct: 0.0,
                        effectiveSpreadFloorPct: LONG_TAIL_PASSTHROUGH_FEE_RATE * 100.0,
                        railCostUsd: rail_cost_usd,
                        status: bucket_status,
                        lastClearedAt: last_cleared_at,
                        lastClearType: last_clear_type,
                    },
                );
                continue;
            } else {
                if is_bell_ringing && accumulated_kas > 0.0 {
                    bucket_status = "ROLLED_OVER".to_string();
                    let meta_val = json!({
                        "lastClearedAt": last_cleared_at,
                        "lastClearType": last_clear_type,
                        "status": bucket_status
                    });
                    let _: () = redis::cmd("SET")
                        .arg(&meta_key)
                        .arg(meta_val.to_string())
                        .query_async(&mut redis_conn)
                        .await
                        .unwrap_or(());
                } else if weight_pct >= 100.0 {
                    bucket_status = "READY_FOR_BELL".to_string();
                } else if accumulated_kas > 0.0 && bucket_status != "ROLLED_OVER" {
                    bucket_status = "ACCUMULATING".to_string();
                } else if accumulated_kas == 0.0 {
                    bucket_status = "IDLE".to_string();
                }
                buckets_telemetry_map.insert(
                    asset.clone(),
                    AssetBucketTelemetry {
                        asset: asset.clone(),
                        pendingKas: accumulated_kas,
                        pendingUsd: accumulated_kas * kas_price,
                        minProfitableKas: min_profitable_kas,
                        minProfitableUsd: min_profitable_usd,
                        weightPct: weight_pct,
                        participantCount: participant_count,
                        lpAvailableKasCapacity: 0.0,
                        lpCoveragePct: 0.0,
                        effectiveSpreadFloorPct: LONG_TAIL_PASSTHROUGH_FEE_RATE * 100.0,
                        railCostUsd: rail_cost_usd,
                        status: bucket_status,
                        lastClearedAt: last_cleared_at,
                        lastClearType: last_clear_type,
                    },
                );
                continue;
            }
        }
        let internal_lp_kas = accumulated_kas.min(lp_capacity_kas);
        let external_cex_kas = (accumulated_kas - internal_lp_kas).max(0.0);
        let available_unhedged_headroom_kas = (max_unhedged_kas - current_unhedged_sell_kas).max(0.0);
        let unhedged_safe_to_clear = cex_configured || external_cex_kas <= available_unhedged_headroom_kas;
        let is_volatility_sweep = weight_pct >= volatility_sweep_threshold_pct && accumulated_kas > 0.0 && unhedged_safe_to_clear;
        let is_daily_epoch_clear = is_bell_ringing && weight_pct >= 100.0 && accumulated_kas > 0.0 && unhedged_safe_to_clear;
        if (is_volatility_sweep || is_daily_epoch_clear) && kas_price > 0.0 && target_price > 0.0 {
            let clear_reason = if is_volatility_sweep {
                "VOLATILITY_SWEEP"
            } else {
                "EPOCH_2200_UTC"
            };
            let batch_gross_usd = accumulated_kas * kas_price;
            let total_fee_usd = batch_gross_usd * effective_spread_rate;
            let net_batch_usd = (batch_gross_usd - total_fee_usd).max(0.0);
            let total_net_target_output = net_batch_usd / target_price;
            let internal_share = if accumulated_kas > 0.0 {
                (internal_lp_kas / accumulated_kas).clamp(0.0, 1.0)
            } else {
                0.0
            };
            let external_share = 1.0 - internal_share;
            let internal_fee_usd = total_fee_usd * internal_share;
            let external_fee_usd = total_fee_usd * external_share;
            if internal_lp_kas > 0.0 {
                let internal_target_disbursed = total_net_target_output * internal_share;
                let lp_staker_reward_usd = internal_fee_usd * 0.80;
                let treasury_lp_cut_usd = internal_fee_usd * 0.20;
                if treasury_lp_cut_usd >= min_dark_pool_usd {
                    let treasury_tokens = treasury_lp_cut_usd / target_price;
                    let _: () = redis::cmd("INCRBYFLOAT")
                        .arg(format!("perennia:fees:batch_accumulated:{}", asset))
                        .arg(treasury_tokens)
                        .query_async(&mut redis_conn)
                        .await
                        .unwrap_or(());
                } else if treasury_lp_cut_usd > 0.0 {
                    let dust_kas = treasury_lp_cut_usd / kas_price;
                    let _: () = redis::cmd("INCRBYFLOAT")
                        .arg("perennia:fees:batch_accumulated:KAS")
                        .arg(dust_kas)
                        .query_async(&mut redis_conn)
                        .await
                        .unwrap_or(());
                }
                if let Ok(lps) = sqlx::query(
                    "SELECT lp_id, wallet_address, pool_pair, staked_asset_a, staked_asset_b, reserves_json, lock_duration_days FROM liquidity_providers WHERE pool_pair = $1 OR pool_pair LIKE $2"
                )
                .bind(&pool_pair)
                .bind(format!("%/{}%", asset))
                .fetch_all(pool)
                .await
                {
                    let mut total_b = 0.0;
                    let mut total_weighted_tvl = 0.0;
                    let mut lp_records = Vec::new();
                    for r in lps {
                        let lp_id: Uuid = r.get("lp_id");
                        let w_addr: String = r.get("wallet_address");
                        let row_pair: String = r.get("pool_pair");
                        let sa: f64 = r.get("staked_asset_a");
                        let sb: f64 = r.get("staked_asset_b");
                        let reserves_val: Value = r.try_get("reserves_json").unwrap_or_else(|_| json!({}));
                        let eff_b = if row_pair.split('/').count() > 2 {
                            reserves_val.get(&asset).and_then(|v| v.as_f64()).unwrap_or(0.0).max(0.0)
                        } else {
                            sb.max(0.0)
                        };
                        let lock_days: i32 = r.get("lock_duration_days");
                        let mult = match lock_days {
                            d if d >= 365 => 2.5,
                            d if d >= 90 => 1.5,
                            d if d >= 30 => 1.2,
                            _ => 1.0,
                        };
                        total_b += eff_b;
                        let weighted = sa.max(0.0) * mult;
                        total_weighted_tvl += weighted;
                        lp_records.push((lp_id, w_addr, row_pair, sa.max(0.0), eff_b, reserves_val, weighted));
                    }
                    let mut lp_pipe = redis::pipe();
                    for (lp_id, w_addr, row_pair, sa, eff_b, mut reserves_val, weighted) in lp_records {
                        if total_b > 0.0 && eff_b > 0.0 {
                            let reserve_share = eff_b / total_b;
                            let delta_a = internal_lp_kas * reserve_share;
                            let delta_b = internal_target_disbursed * reserve_share;
                            if row_pair.split('/').count() > 2 {
                                if let Some(obj) = reserves_val.as_object_mut() {
                                    obj.insert("KAS".to_string(), json!(sa + delta_a));
                                    obj.insert(asset.clone(), json!((eff_b - delta_b).max(0.0)));
                                }
                                let _ = sqlx::query(
                                    "UPDATE liquidity_providers SET staked_asset_a = staked_asset_a + $1, reserves_json = $2, last_yield_distribution = CURRENT_TIMESTAMP WHERE lp_id = $3"
                                )
                                .bind(delta_a)
                                .bind(&reserves_val)
                                .bind(lp_id)
                                .execute(pool)
                                .await;
                            } else {
                                let _ = sqlx::query(
                                    "UPDATE liquidity_providers SET staked_asset_a = staked_asset_a + $1, staked_asset_b = GREATEST(0.0, staked_asset_b - $2), last_yield_distribution = CURRENT_TIMESTAMP WHERE lp_id = $3"
                                )
                                .bind(delta_a)
                                .bind(delta_b)
                                .bind(lp_id)
                                .execute(pool)
                                .await;
                            }
                        }
                        if total_weighted_tvl > 0.0 && weighted > 0.0 {
                            let reward_share = weighted / total_weighted_tvl;
                            let staker_reward_usd = lp_staker_reward_usd * reward_share;
                            let clean_lp_wallet = normalize_kaspa_base32(&w_addr);
                            let lp_ledger_key = format!("dev:sor:treasury:balances:{}", clean_lp_wallet);
                            if staker_reward_usd >= min_dark_pool_usd || asset == "USDC" || asset == "USDT" {
                                let staker_reward_tokens = staker_reward_usd / target_price;
                                if staker_reward_tokens > 0.00000001 {
                                    lp_pipe.cmd("HINCRBYFLOAT").arg(&lp_ledger_key).arg(&asset).arg(staker_reward_tokens).ignore();
                                }
                            } else {
                                let staker_reward_kas = staker_reward_usd / kas_price;
                                if staker_reward_kas > 0.00000001 {
                                    lp_pipe.cmd("HINCRBYFLOAT").arg(&lp_ledger_key).arg("KAS").arg(staker_reward_kas).ignore();
                                }
                            }
                        }
                    }
                    let _: Result<(), _> = lp_pipe.query_async(&mut redis_conn).await;
                    let _ = sqlx::query(
                        "INSERT INTO yield_distributions (pool_pair, total_fees_distributed_usd) VALUES ($1, $2)"
                    )
                    .bind(&pool_pair)
                    .bind(lp_staker_reward_usd)
                    .execute(pool)
                    .await;
                }
            }
            if external_cex_kas > 0.0 {
                current_unhedged_sell_kas += external_cex_kas;
                let external_target_output = total_net_target_output * external_share;
                let netting_order = json!({
                    "wallet": "kaspa:treasury_epoch_batch",
                    "direction": "SELL_KAS",
                    "amount_kas": external_cex_kas,
                    "spot_price": kas_price / target_price,
                    "fee_captured_usd": external_fee_usd,
                    "target_asset": asset,
                    "estimated_output": external_target_output
                });
                let _: () = redis::cmd("RPUSH")
                    .arg("perennia:sor:netting_queue")
                    .arg(netting_order.to_string())
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(());
            }
            let mut participants_by_wallet: HashMap<String, Vec<SectorSwapParticipant>> = HashMap::new();
            for p in participants {
                participants_by_wallet.entry(p.wallet_db_key.clone()).or_default().push(p);
            }
            for (wallet_db_key, wallet_participants) in participants_by_wallet {
                let mut tx_user = pool.begin().await?;
                let row_opt = sqlx::query("SELECT layout_state FROM user_command_centers WHERE wallet_address = $1 FOR UPDATE")
                    .bind(&wallet_db_key)
                    .fetch_optional(&mut *tx_user)
                    .await?;
                if let Some(row) = row_opt {
                    let mut user_state: Value = row.get("layout_state");
                    let (escrow_active, escrow_rate_fraction, escrow_lock_days) = extract_tax_escrow_config(&user_state);
                    let mut user_mutated = false;
                    for part in &wallet_participants {
                        let pro_rata_share = if accumulated_kas > 0.0 {
                            part.swap_kas / accumulated_kas
                        } else {
                            0.0
                        };
                        let gross_miner_target_proceeds = total_net_target_output * pro_rata_share;
                        let gross_miner_net_usd = net_batch_usd * pro_rata_share;
                        let (escrow_kas, net_fraction) = if escrow_active && escrow_rate_fraction > 0.0 {
                            (part.total_pending_kas * escrow_rate_fraction, (1.0 - escrow_rate_fraction).max(0.0))
                        } else {
                            (0.0, 1.0)
                        };
                        if escrow_kas > 0.0 {
                            let _ = route_tax_escrow_auto_lp(
                                &mut tx_user,
                                &part.prefixed_wallet,
                                &part.clean_wallet,
                                escrow_kas,
                                kas_price,
                                escrow_lock_days,
                            )
                            .await;
                        }
                        let miner_target_proceeds = gross_miner_target_proceeds * net_fraction;
                        let miner_net_usd = gross_miner_net_usd * net_fraction;
                        let effective_lp_pair_kas_half = part.lp_pair_kas_half * net_fraction;
                        if part.route_mode == "auto-lp" {
                            let target_plant_pair = part.plant_pair.clone();
                            let existing_lp = sqlx::query(
                                "SELECT lp_id, staked_asset_a, staked_asset_b, weights_json, reserves_json FROM liquidity_providers WHERE wallet_address = $1 AND pool_pair = $2 AND lock_duration_days = 0 LIMIT 1"
                            )
                            .bind(&part.prefixed_wallet)
                            .bind(&target_plant_pair)
                            .fetch_optional(&mut *tx_user)
                            .await?;
                            let position_usd = (effective_lp_pair_kas_half * kas_price) + miner_net_usd;
                            if let Some(lp_row) = existing_lp {
                                let lp_id: Uuid = lp_row.get("lp_id");
                                let cur_a: f64 = lp_row.get("staked_asset_a");
                                let cur_b: f64 = lp_row.get("staked_asset_b");
                                let mut reserves_val: Value = lp_row.try_get("reserves_json").unwrap_or_else(|_| json!({}));
                                let is_multi = target_plant_pair.split('/').count() > 2;
                                let next_a = cur_a + effective_lp_pair_kas_half;
                                let next_b = if is_multi {
                                    cur_b + miner_net_usd
                                } else {
                                    cur_b + miner_target_proceeds
                                };
                                if let Some(obj) = reserves_val.as_object_mut() {
                                    let prev_kas = obj.get("KAS").and_then(|v| v.as_f64()).unwrap_or(cur_a);
                                    let prev_tok = obj.get(&asset).and_then(|v| v.as_f64()).unwrap_or(0.0);
                                    obj.insert("KAS".to_string(), json!(prev_kas + effective_lp_pair_kas_half));
                                    obj.insert(asset.clone(), json!(prev_tok + miner_target_proceeds));
                                }
                                let weights_json_val = serde_json::to_value(&part.plant_weights).unwrap_or_else(|_| json!({}));
                                let _ = sqlx::query(
                                    "UPDATE liquidity_providers SET staked_asset_a = $1, staked_asset_b = $2, weights_json = $3, reserves_json = $4 WHERE lp_id = $5"
                                )
                                .bind(next_a)
                                .bind(next_b)
                                .bind(&weights_json_val)
                                .bind(&reserves_val)
                                .bind(lp_id)
                                .execute(&mut *tx_user)
                                .await;
                            } else if position_usd >= min_dark_pool_usd {
                                let is_multi = target_plant_pair.split('/').count() > 2;
                                let init_b = if is_multi { miner_net_usd } else { miner_target_proceeds };
                                let weights_json_val = serde_json::to_value(&part.plant_weights).unwrap_or_else(|_| json!({}));
                                let reserves_json_val = json!({
                                    "KAS": effective_lp_pair_kas_half,
                                    asset.clone(): miner_target_proceeds
                                });
                                let _ = sqlx::query(
                                    "INSERT INTO liquidity_providers (wallet_address, pool_pair, staked_asset_a, staked_asset_b, weights_json, reserves_json, lock_duration_days, unlock_date) VALUES ($1, $2, $3, $4, $5, $6, 0, CURRENT_TIMESTAMP)"
                                )
                                .bind(&part.prefixed_wallet)
                                .bind(&target_plant_pair)
                                .bind(effective_lp_pair_kas_half)
                                .bind(init_b)
                                .bind(&weights_json_val)
                                .bind(&reserves_json_val)
                                .execute(&mut *tx_user)
                                .await;
                            } else {
                                let user_ledger_key = format!("dev:sor:treasury:balances:{}", part.clean_wallet);
                                let total_kas_equivalent = effective_lp_pair_kas_half + (miner_net_usd / kas_price);
                                let _: () = redis::cmd("HINCRBYFLOAT")
                                    .arg(&user_ledger_key)
                                    .arg("KAS")
                                    .arg(total_kas_equivalent)
                                    .query_async(&mut redis_conn)
                                    .await
                                    .unwrap_or(());
                            }
                            let _ = sqlx::query(
                                "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash, payout_address) VALUES ($1, $2, 'YIELD', $3, $4, $5, 'AUTO_LP_COMPOUNDED', $6)"
                            )
                            .bind(&part.clean_wallet)
                            .bind(&asset)
                            .bind(miner_net_usd)
                            .bind(miner_target_proceeds)
                            .bind(target_price)
                            .bind(&part.payout_address)
                            .execute(&mut *tx_user)
                            .await;
                        } else {
                            let _ = crate::state_api::dispatch_or_queue_multi_chain_l1(
                                &mut tx_user,
                                &mut redis_conn,
                                &part.prefixed_wallet,
                                &part.clean_wallet,
                                &part.payout_address,
                                &asset,
                                miner_target_proceeds,
                                target_price,
                                "chronos_epoch_bell",
                            )
                            .await;
                        }
                        if let Some(sectors) = user_state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                            for sec in sectors.iter_mut() {
                                if sec.get("id").and_then(|v| v.as_str()) == Some(&part.sector_id) {
                                    let cur_pend = sec.get("pendingKaspa").and_then(|v| v.as_f64()).unwrap_or(0.0);
                                    let next_pend = (cur_pend - part.total_pending_kas).max(0.0);
                                    sec["pendingKaspa"] = json!(if next_pend < 1e-6 { 0.0 } else { next_pend });
                                    sec["lastSettledAt"] = json!(now_secs);
                                    if part.clear_appointment {
                                        sec["settlementConfig"]["appointmentDate"] = json!("");
                                    }
                                    user_mutated = true;
                                }
                            }
                        }
                    }
                    if user_mutated {
                        sqlx::query("UPDATE user_command_centers SET layout_state = $1, last_updated = CURRENT_TIMESTAMP WHERE wallet_address = $2")
                            .bind(&user_state)
                            .bind(&wallet_db_key)
                            .execute(&mut *tx_user)
                            .await?;
                        let clean_w = normalize_kaspa_base32(&wallet_db_key);
                        let yield_update = json!({
                            "wallet": clean_w,
                            "yield_update": true,
                            "sectors": user_state.get("sectors").cloned().unwrap_or_else(|| json!([]))
                        });
                        let _: () = redis::cmd("PUBLISH")
                            .arg("telemetry:updates")
                            .arg(yield_update.to_string())
                            .query_async(&mut redis_conn)
                            .await
                            .unwrap_or(());
                    }
                }
                let _ = tx_user.commit().await;
            }
            last_cleared_at = now_secs;
            last_clear_type = clear_reason.to_string();
            bucket_status = if is_volatility_sweep {
                "SWEPT_VOLATILITY".to_string()
            } else {
                "CLEARED_EPOCH".to_string()
            };
            let meta_val = json!({
                "lastClearedAt": last_cleared_at,
                "lastClearType": last_clear_type,
                "status": bucket_status
            });
            let _: () = redis::cmd("SET")
                .arg(&meta_key)
                .arg(meta_val.to_string())
                .query_async(&mut redis_conn)
                .await
                .unwrap_or(());
            buckets_telemetry_map.insert(
                asset.clone(),
                AssetBucketTelemetry {
                    asset: asset.clone(),
                    pendingKas: 0.0,
                    pendingUsd: 0.0,
                    minProfitableKas: min_profitable_kas,
                    minProfitableUsd: min_profitable_usd,
                    weightPct: 0.0,
                    participantCount: 0,
                    lpAvailableKasCapacity: (lp_capacity_kas - internal_lp_kas).max(0.0),
                    lpCoveragePct: 100.0,
                    effectiveSpreadFloorPct: effective_spread_rate * 100.0,
                    railCostUsd: rail_cost_usd,
                    status: bucket_status,
                    lastClearedAt: last_cleared_at,
                    lastClearType: last_clear_type,
                },
            );
        } else {
            if is_bell_ringing && accumulated_kas > 0.0 && (weight_pct < 100.0 || !unhedged_safe_to_clear) {
                bucket_status = "ROLLED_OVER".to_string();
                let meta_val = json!({
                    "lastClearedAt": last_cleared_at,
                    "lastClearType": last_clear_type,
                    "status": bucket_status
                });
                let _: () = redis::cmd("SET")
                    .arg(&meta_key)
                    .arg(meta_val.to_string())
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(());
            } else if weight_pct >= 100.0 && unhedged_safe_to_clear {
                bucket_status = "READY_FOR_BELL".to_string();
            } else if accumulated_kas > 0.0 && bucket_status != "ROLLED_OVER" {
                bucket_status = "ACCUMULATING".to_string();
            } else if accumulated_kas == 0.0 {
                bucket_status = "IDLE".to_string();
            }
            buckets_telemetry_map.insert(
                asset.clone(),
                AssetBucketTelemetry {
                    asset: asset.clone(),
                    pendingKas: accumulated_kas,
                    pendingUsd: accumulated_kas * kas_price,
                    minProfitableKas: min_profitable_kas,
                    minProfitableUsd: min_profitable_usd,
                    weightPct: weight_pct,
                    participantCount: participant_count,
                    lpAvailableKasCapacity: lp_capacity_kas,
                    lpCoveragePct: lp_coverage_pct,
                    effectiveSpreadFloorPct: effective_spread_rate * 100.0,
                    railCostUsd: rail_cost_usd,
                    status: bucket_status,
                    lastClearedAt: last_cleared_at,
                    lastClearType: last_clear_type,
                },
            );
        }
    }
    compound_master_treasury_lp_positions(pool, &mut redis_conn).await;
    let epoch_telemetry_payload = json!({
        "anchorUtcHour": 22,
        "anchorLabel": "22:00 UTC (00:00 JST / 16:00 CT)",
        "currentEpochBellTs": current_epoch_bell_ts,
        "nextEpochBellTs": next_epoch_bell_ts,
        "secondsRemaining": seconds_remaining,
        "volatilitySweepThresholdPct": volatility_sweep_threshold_pct,
        "updatedAt": now_secs,
        "buckets": buckets_telemetry_map
    });
    let _: () = redis::cmd("SET")
        .arg("perennia:settlement:epoch_telemetry")
        .arg(epoch_telemetry_payload.to_string())
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(());
    let sse_epoch_msg = json!({
        "epoch_telemetry_update": true,
        "epoch": epoch_telemetry_payload
    });
    let _: () = redis::cmd("PUBLISH")
        .arg("telemetry:updates")
        .arg(sse_epoch_msg.to_string())
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(());
    Ok(())
}

async fn process_unassigned_reserve_settlements(
    pool: &PgPool,
    redis_client: &redis::Client
) -> anyhow::Result<()> {
    let mut redis_conn = redis_client.get_multiplexed_async_connection().await?;
    let corp_kas_clean = resolve_master_treasury_address();
    if corp_kas_clean.is_empty() {
        return Ok(());
    }
    let corp_kas_prefixed = format!("kaspa:{}", corp_kas_clean);
    let _ = sqlx::query(
        "UPDATE yield_reservoirs SET streaming_balance_kas = 0.0, last_updated = CURRENT_TIMESTAMP WHERE LOWER(REPLACE(TRIM(wallet_address), 'kaspa:', '')) = $1 AND streaming_balance_kas != 0.0"
    )
    .bind(&corp_kas_clean)
    .execute(pool)
    .await;
    let corp_ledger_key = format!("dev:sor:treasury:balances:{}", corp_kas_clean);
    let _: () = redis::cmd("HDEL")
        .arg(&corp_ledger_key)
        .arg("Unassigned KAS")
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(());
    let settlement_threshold = crate::config::StratumConfig::load("config.yaml")
        .ok()
        .and_then(|_| {
            std::env::var("UNASSIGNED_SETTLEMENT_THRESHOLD_KAS")
                .ok()
                .and_then(|v| v.trim().parse::<f64>().ok())
        })
        .unwrap_or(DEFAULT_UNASSIGNED_SETTLEMENT_THRESHOLD);
    let kas_price = get_oracle_price(pool, &mut redis_conn, "KAS").await;
    if kas_price <= 0.0 {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    let rows = sqlx::query(
        r#"
        SELECT wallet_address, streaming_balance_kas
        FROM yield_reservoirs
        WHERE streaming_balance_kas >= $1
          AND LOWER(REPLACE(TRIM(wallet_address), 'kaspa:', '')) != $2
          AND wallet_address != $3
        FOR UPDATE SKIP LOCKED
        "#
    )
    .bind(settlement_threshold)
    .bind(&corp_kas_clean)
    .bind(&corp_kas_prefixed)
    .fetch_all(&mut *tx)
    .await?;
    let mut payouts = Vec::new();
    for row in &rows {
        let wallet_address: String = row.get("wallet_address");
        let streaming_balance_kas: f64 = row.get("streaming_balance_kas");
        if normalize_kaspa_base32(&wallet_address) != corp_kas_clean && streaming_balance_kas > 0.0 {
            payouts.push((wallet_address, streaming_balance_kas));
        }
    }
    if !payouts.is_empty() {
        match crate::sor::execute_mass_physical_settlement(&payouts).await {
            Ok(tx_id) => {
                for (target_wallet, payout_amount) in &payouts {
                    let updated_row = sqlx::query(
                        "UPDATE yield_reservoirs SET streaming_balance_kas = GREATEST(0.0, streaming_balance_kas - $1), last_updated = CURRENT_TIMESTAMP WHERE wallet_address = $2 RETURNING streaming_balance_kas"
                    )
                    .bind(*payout_amount)
                    .bind(target_wallet)
                    .fetch_optional(&mut *tx)
                    .await?;
                    let remaining_kas = updated_row
                        .and_then(|r| r.try_get::<f64, _>("streaming_balance_kas").ok())
                        .unwrap_or(0.0)
                        .max(0.0);
                    let clean_address = normalize_kaspa_base32(target_wallet);
                    let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_address);
                    let _: () = redis::cmd("HSET")
                        .arg(&user_ledger_key)
                        .arg("Unassigned KAS")
                        .arg(remaining_kas)
                        .query_async(&mut redis_conn)
                        .await
                        .unwrap_or(());
                    let _ = sqlx::query(
                        "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash, payout_address) VALUES ($1, 'KAS', 'YIELD', $2, $3, $4, $5, $6)"
                    )
                    .bind(&clean_address)
                    .bind((*payout_amount) * kas_price)
                    .bind(*payout_amount)
                    .bind(kas_price)
                    .bind(&tx_id)
                    .bind(target_wallet)
                    .execute(&mut *tx)
                    .await;
                }
            }
            Err(e) => {
                tracing::error!("[MASS PAYOUT FAILED] Could not settle batch: {}", e);
            }
        }
    }
    tx.commit().await?;
    Ok(())
}

pub async fn start_utxo_consolidation_daemon(
    mut utxo_rx: tokio::sync::broadcast::Receiver<crate::kaspad_client::protowire::UtxosChangedNotificationMessage>
) {
    tracing::info!("🧹 UTXO Consolidation Daemon Online. Tracking Treasury UTXOs in-memory via gRPC...");
    let corp_kas_clean = resolve_master_treasury_address();
    if corp_kas_clean.is_empty() {
        return;
    }
    let corp_kas = format!("kaspa:{}", corp_kas_clean);
    if std::env::var("PERENNIA_TREASURY_PRIVATE_KEY").map(|k| k.trim().is_empty()).unwrap_or(true) {
        return;
    }
    let mut treasury_utxos: std::collections::HashMap<String, crate::sor::UtxoInput> = std::collections::HashMap::new();
    let http_client = get_secure_client();
    let base_rest_url = std::env::var("KASPA_REST_URL").unwrap_or_else(|_| "https://api.kaspa.org".to_string());
    let utxos_endpoint = format!("{}/addresses/{}/utxos", base_rest_url, corp_kas);
    if let Ok(res) = http_client.get(&utxos_endpoint).send().await {
        if res.status().is_success() {
            if let Ok(text_payload) = res.text().await {
                if let Ok(utxos) = serde_json::from_str::<Vec<serde_json::Value>>(&text_payload) {
                    for u in utxos {
                        if let (Some(tx_id), Some(index), Some(amount), Some(script)) = (
                            u.pointer("/outpoint/transactionId").and_then(|v| v.as_str()),
                            crate::sor::parse_json_u64(u.pointer("/outpoint/index")),
                            crate::sor::parse_json_u64(u.pointer("/utxoEntry/amount")),
                            u.pointer("/utxoEntry/scriptPublicKey/scriptPublicKey").and_then(|v| v.as_str())
                        ) {
                            let key = format!("{}:{}", tx_id, index);
                            treasury_utxos.insert(key, crate::sor::UtxoInput {
                                transactionId: tx_id.to_string(),
                                index: index as u32,
                                amount: amount as f64,
                                scriptPublicKey: script.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
    loop {
        if let Ok(utxo_msg) = utxo_rx.recv().await {
            let mut modified = false;
            for removed in utxo_msg.removed {
                if normalize_kaspa_base32(&removed.address) == normalize_kaspa_base32(&corp_kas) {
                    if let Some(outpoint) = removed.outpoint {
                        let key = format!("{}:{}", outpoint.transaction_id, outpoint.index);
                        if treasury_utxos.remove(&key).is_some() {
                            modified = true;
                        }
                    }
                }
            }
            for added in utxo_msg.added {
                if normalize_kaspa_base32(&added.address) == normalize_kaspa_base32(&corp_kas) {
                    if let (Some(outpoint), Some(entry)) = (added.outpoint, added.utxo_entry) {
                        let tx_id = outpoint.transaction_id;
                        let index = outpoint.index;
                        if let Some(spk) = entry.script_public_key {
                            let script_hex = spk.script_public_key;
                            let key = format!("{}:{}", tx_id, index);
                            treasury_utxos.insert(key, crate::sor::UtxoInput {
                                transactionId: tx_id.clone(),
                                index: index as u32,
                                amount: entry.amount as f64,
                                scriptPublicKey: script_hex,
                            });
                            modified = true;
                        }
                    }
                }
            }
            if modified && treasury_utxos.len() > 150 {
                let mut parsed_utxos: Vec<crate::sor::UtxoInput> = treasury_utxos.values().cloned().collect();
                parsed_utxos.sort_by(|a, b| a.amount.partial_cmp(&b.amount).unwrap());
                for chunk in parsed_utxos.chunks(80) {
                    if chunk.len() < 2 { continue; }
                    match crate::sor::execute_utxo_consolidation_chunk(chunk).await {
                        Ok(_) => {
                            for spent in chunk {
                                let spent_key = format!("{}:{}", spent.transactionId, spent.index);
                                treasury_utxos.remove(&spent_key);
                            }
                        }
                        Err(e) => {
                            tracing::error!("❌ [UTXO DAEMON] Consolidation chunk failed: {}", e);
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        }
    }
}