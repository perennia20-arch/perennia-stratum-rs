use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use tokio_stream::wrappers::ReceiverStream;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use std::env;
use sqlx::{PgPool, Row};
use dashmap::DashSet;
use lazy_static::lazy_static;
use crate::kaspad_client::protowire::rpc_client::RpcClient;
use crate::kaspad_client::protowire::{
    KaspadRequest, GetBlockRewardInfoRequestMessage, GetBlockRequestMessage, BlockColor
};
use crate::kaspad_client::protowire::kaspad_request::Payload as RequestPayload;
use crate::kaspad_client::protowire::kaspad_response::Payload as ResponsePayload;
use crate::job_manager::{difficulty_from_bits, extract_coinbase_reward_sompi};

const DEFAULT_MIN_ORACLE_QUORUM: usize = 2;
const MAX_OUTLIER_DEVIATION_RATIO: f64 = 0.12;
const SPOT_ORACLE_TTL_SECS: u64 = 30;
const CHANGE_24H_TTL_SECS: u64 = 300;
const RWA_ORACLE_TTL_SECS: u64 = 60;

pub const ORACLE_SUPPORTED_ASSETS: &[&str] = &[
    "KAS", "USDC", "USDT", "USD", "BTC", "ETH", "SOL", "XRP", "DOGE",
    "TON", "SUI", "ADA", "AVAX", "LINK", "LTC", "POL", "TRX", "ZEC", "ARB", "BASE",
    "SPY", "QQQ", "NVDA", "AAPL", "TSLA", "AMD", "TSM", "AVGO", "XLE",
    "XAU", "XAG", "USTB"
];

pub const ORACLE_VOLATILE_ASSETS: &[&str] = &[
    "KAS", "BTC", "ETH", "SOL", "XRP", "DOGE",
    "TON", "SUI", "ADA", "AVAX", "LINK", "LTC", "POL", "TRX", "ZEC", "ARB"
];

pub const PYTH_RWA_FEEDS: &[(&str, &str, &str)] = &[
    ("SPY", "0x19e09bb805456ada3979a7d1cbb4b6d63babc3a0f8e8a9509f68afa5c4c11cd5", "EQUITY"),
    ("QQQ", "0x9695e2b96ea7b38596fb62eefb1e5f2b670b6c0f8236d9b1b12c38f0a4b2a9d2", "EQUITY"),
    ("NVDA", "0xb1073854ed24cbc755dc527418f52b7d271f6cc967bbf8d8129112b18860a593", "EQUITY"),
    ("AAPL", "0x49f6b65cb1de6b10eaf75e7c03ca029c306d0357e91b5311b175084a5ad55688", "EQUITY"),
    ("TSLA", "0x16dad506d7db8da01c87581c87ca897a012a153557d4d578c3b9c9e1bc0632f1", "EQUITY"),
    ("AMD", "0x2f95862b045670cd22bee3114c39763a4a08beeb663b145d283c31d7d1101c4f", "EQUITY"),
    ("TSM", "0x69145a36d62e91113b86b2e5b88f68f7f781c08d22d55848a0a0c4b113867223", "EQUITY"),
    ("AVGO", "0x72b021217ca3fe68922a19aaf990109cb9d84e9ad004b4d2025ad6f529314419", "EQUITY"),
    ("XLE", "0x277b69923f8886d886c920d3616c2182f9d59c9c4397015a78529e3b5c4f1d2c", "EQUITY"),
    ("XAU", "0x765d2ba906dbc32ca17cc11f5310a89e9ee1f6420508c63861f2f8ba4ee34bb2", "COMMODITY"),
    ("XAG", "0xf2fb02c32b055c805e7238d628e5e9dadef274376114eb1f012337cabe93871e", "COMMODITY"),
    ("USTB", "0xe393449f6aff8a4b6d3e1165a7c9ebec103685f3b41e60db4277b5b6d10e7326", "TREASURY"),
];

lazy_static! {
    pub static ref DYNAMIC_ORACLE_TICKERS: DashSet<String> = DashSet::new();
}

pub fn register_dynamic_oracle_ticker(ticker: &str) {
    let clean: String = ticker
        .trim()
        .to_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(12)
        .collect();
    if clean.len() >= 2 && !ORACLE_SUPPORTED_ASSETS.iter().any(|&a| a == clean) {
        DYNAMIC_ORACLE_TICKERS.insert(clean);
    }
}

pub fn is_oracle_supported_asset(ticker: &str) -> bool {
    let clean = ticker.trim().to_uppercase();
    ORACLE_SUPPORTED_ASSETS.iter().any(|&a| a == clean)
        || DYNAMIC_ORACLE_TICKERS.contains(&clean)
}

pub fn is_pyth_rwa_asset(ticker: &str) -> bool {
    let clean = ticker.trim().to_uppercase();
    PYTH_RWA_FEEDS.iter().any(|&(t, _, _)| t == clean)
}

fn normalize_hex_feed_id(id: &str) -> String {
    id.trim().to_lowercase().trim_start_matches("0x").to_string()
}

type PriceQuote = (f64, Option<f64>, Instant);
type PriceMap = Arc<RwLock<HashMap<String, HashMap<String, PriceQuote>>>>;

fn record_exchange_quote(
    ex_map: &mut HashMap<String, PriceQuote>,
    exchange: &str,
    spot_price: f64,
    change_24h_pct: Option<f64>,
) {
    let prev_change = ex_map.get(exchange).and_then(|(_, chg, _)| *chg);
    let resolved_change = change_24h_pct
        .filter(|v| v.is_finite())
        .or(prev_change);
    ex_map.insert(
        exchange.to_string(),
        (spot_price, resolved_change, Instant::now()),
    );
}

fn compute_sorted_median(sorted: &[f64]) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    }
}

async fn resolve_dynamic_pyth_feed_ids(client: &reqwest::Client) -> HashMap<String, String> {
    let mut feed_map: HashMap<String, String> = HashMap::new();
    for &(ticker, default_id, _) in PYTH_RWA_FEEDS {
        feed_map.insert(ticker.to_string(), default_id.to_string());
    }
    for &(ticker, _, _) in PYTH_RWA_FEEDS {
        let query_symbol = match ticker {
            "USTB" => "IB01",
            other => other,
        };
        let url = format!(
            "https://hermes.pyth.network/v2/price_feeds?query={}",
            query_symbol
        );
        if let Ok(res) = client.get(&url).send().await {
            if res.status().is_success() {
                if let Ok(arr) = res.json::<Vec<Value>>().await {
                    for entry in arr {
                        let base = entry
                            .pointer("/attributes/base")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_uppercase();
                        let quote = entry
                            .pointer("/attributes/quote_currency")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_uppercase();
                        let id_str = entry.get("id").and_then(|v| v.as_str()).unwrap_or("");
                        if !id_str.is_empty()
                            && quote == "USD"
                            && (base == ticker || (ticker == "USTB" && (base == "USTB" || base == "IB01" || base == "SHY")))
                        {
                            feed_map.insert(
                                ticker.to_string(),
                                format!("0x{}", normalize_hex_feed_id(id_str)),
                            );
                            break;
                        }
                    }
                }
            }
        }
    }
    feed_map
}

async fn ensure_rwa_oracle_upsert_constraint(pool: &PgPool) {
    let _ = sqlx::query(
        r#"
        DELETE FROM rwa_oracle_feeds a
        USING rwa_oracle_feeds b
        WHERE a.id < b.id AND a.ticker = b.ticker
        "#,
    )
    .execute(pool)
    .await;
    let _ = sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_rwa_oracle_feeds_ticker_unique ON rwa_oracle_feeds (ticker)",
    )
    .execute(pool)
    .await;
}

pub async fn start_pyth_rwa_oracle_daemon(pool: PgPool) {
    tracing::info!("🏛️ Booting Pyth Hermes Institutional RWA & Equity Oracle Daemon (SPY, QQQ, NVDA, AAPL, TSLA, AMD, TSM, AVGO, XLE, XAU, XAG, USTB)...");
    ensure_rwa_oracle_upsert_constraint(&pool).await;
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = match redis::Client::open(redis_url) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Pyth RWA Oracle Redis client init failed: {}", e);
            return;
        }
    };
    let mut redis_conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Pyth RWA Oracle Redis connection failed: {}", e);
            return;
        }
    };
    let client = reqwest::Client::builder()
        .user_agent("Perennia-Pyth-Hermes-Oracle/4.0")
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let resolved_feed_ids = resolve_dynamic_pyth_feed_ids(&client).await;
    let mut interval = tokio::time::interval(Duration::from_secs(12));
    loop {
        interval.tick().await;
        let mut query_parts: Vec<String> = Vec::new();
        for feed_id in resolved_feed_ids.values() {
            query_parts.push(format!("ids[]={}", feed_id));
        }
        query_parts.push("ignore_invalid_price_ids=true".to_string());
        let url = format!(
            "https://hermes.pyth.network/v2/updates/price/latest?{}",
            query_parts.join("&")
        );
        let mut latest_quotes: HashMap<String, (f64, f64, i64)> = HashMap::new();
        if let Ok(res) = client.get(&url).send().await {
            if res.status().is_success() {
                if let Ok(data) = res.json::<Value>().await {
                    if let Some(parsed_arr) = data.get("parsed").and_then(|v| v.as_array()) {
                        for item in parsed_arr {
                            let feed_id_norm = item
                                .get("id")
                                .and_then(|v| v.as_str())
                                .map(normalize_hex_feed_id)
                                .unwrap_or_default();
                            if feed_id_norm.is_empty() {
                                continue;
                            }
                            let matched_ticker = resolved_feed_ids.iter().find_map(|(t, fid)| {
                                if normalize_hex_feed_id(fid) == feed_id_norm {
                                    Some(t.clone())
                                } else {
                                    None
                                }
                            });
                            let Some(ticker) = matched_ticker else {
                                continue;
                            };
                            let raw_spot = item
                                .pointer("/price/price")
                                .and_then(|v| v.as_str().and_then(|s| s.parse::<f64>().ok()).or_else(|| v.as_f64()))
                                .unwrap_or(0.0);
                            let spot_expo = item
                                .pointer("/price/expo")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(0) as i32;
                            let raw_ema = item
                                .pointer("/ema_price/price")
                                .and_then(|v| v.as_str().and_then(|s| s.parse::<f64>().ok()).or_else(|| v.as_f64()))
                                .unwrap_or(0.0);
                            let ema_expo = item
                                .pointer("/ema_price/expo")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(0) as i32;
                            let spot_usd = if raw_spot > 0.0 {
                                raw_spot * 10.0_f64.powi(spot_expo)
                            } else if raw_ema > 0.0 {
                                raw_ema * 10.0_f64.powi(ema_expo)
                            } else {
                                0.0
                            };
                            let ema_usd = if raw_ema > 0.0 {
                                raw_ema * 10.0_f64.powi(ema_expo)
                            } else {
                                spot_usd
                            };
                            let delta_pct = if ema_usd > 0.0 && spot_usd > 0.0 {
                                (((spot_usd - ema_usd) / ema_usd) * 100.0).clamp(-25.0, 25.0)
                            } else {
                                0.0
                            };
                            let pub_ts = item
                                .pointer("/price/publish_time")
                                .or_else(|| item.pointer("/ema_price/publish_time"))
                                .and_then(|v| v.as_i64())
                                .unwrap_or_else(|| chrono::Utc::now().timestamp());
                            if spot_usd > 0.0 {
                                latest_quotes.insert(ticker, (spot_usd, delta_pct, pub_ts));
                            }
                        }
                    }
                }
            }
        }
        let mut pipe = redis::pipe();
        let mut rwa_assets_json = Vec::new();
        for &(ticker, _, asset_class) in PYTH_RWA_FEEDS {
            let resolved_entry = if let Some(&(spot_usd, delta_pct, pub_ts)) = latest_quotes.get(ticker) {
                let _ = sqlx::query(
                    r#"
                    INSERT INTO rwa_oracle_feeds (ticker, asset_class, price_usd, change_24h_pct, oracle_source, updated_at)
                    VALUES ($1, $2, $3, $4, 'PYTH_HERMES', CURRENT_TIMESTAMP)
                    ON CONFLICT (ticker) DO UPDATE SET
                        asset_class = EXCLUDED.asset_class,
                        price_usd = EXCLUDED.price_usd,
                        change_24h_pct = EXCLUDED.change_24h_pct,
                        oracle_source = EXCLUDED.oracle_source,
                        updated_at = CURRENT_TIMESTAMP
                    "#,
                )
                .bind(ticker)
                .bind(asset_class)
                .bind(spot_usd)
                .bind(delta_pct)
                .execute(&pool)
                .await;
                Some((spot_usd, delta_pct, pub_ts))
            } else {
                sqlx::query(
                    r#"
                    SELECT price_usd, change_24h_pct, EXTRACT(EPOCH FROM updated_at)::BIGINT AS pub_ts
                    FROM rwa_oracle_feeds
                    WHERE ticker = $1
                      AND price_usd > 0
                      AND updated_at >= CURRENT_TIMESTAMP - INTERVAL '15 minutes'
                    ORDER BY updated_at DESC
                    LIMIT 1
                    "#,
                )
                .bind(ticker)
                .fetch_optional(&pool)
                .await
                .ok()
                .flatten()
                .and_then(|row| {
                    let p = row.try_get::<f64, _>("price_usd").unwrap_or(0.0);
                    let d = row.try_get::<f64, _>("change_24h_pct").unwrap_or(0.0);
                    let ts = row.try_get::<i64, _>("pub_ts").unwrap_or(0);
                    if p > 0.0 { Some((p, d, ts)) } else { None }
                })
            };
            if let Some((spot_usd, delta_pct, pub_ts)) = resolved_entry {
                pipe.cmd("SETEX")
                    .arg(format!("oracle:spot:{}_USDC", ticker))
                    .arg(RWA_ORACLE_TTL_SECS)
                    .arg(spot_usd.to_string())
                    .ignore();
                pipe.cmd("SETEX")
                    .arg(format!("oracle:change24h:{}_USDC", ticker))
                    .arg(CHANGE_24H_TTL_SECS)
                    .arg(delta_pct.to_string())
                    .ignore();
                rwa_assets_json.push(json!({
                    "ticker": ticker,
                    "assetClass": asset_class,
                    "price": format!("{:.2}", spot_usd),
                    "spotPrice": spot_usd,
                    "change24h": delta_pct,
                    "publishTime": chrono::DateTime::from_timestamp(pub_ts, 0)
                        .unwrap_or_else(chrono::Utc::now)
                        .to_rfc3339()
                }));
            }
        }
        if !rwa_assets_json.is_empty() {
            pipe.cmd("SETEX")
                .arg("oracle:spot:rwa_prices_json")
                .arg(RWA_ORACLE_TTL_SECS)
                .arg(serde_json::to_string(&rwa_assets_json).unwrap_or_else(|_| "[]".to_string()))
                .ignore();
        }
        if let Err(e) = pipe.query_async::<_, ()>(&mut redis_conn).await {
            tracing::warn!("Pyth RWA Redis pipeline warning: {}", e);
        }
    }
}

pub async fn start_spot_pricing_daemon() {
    tracing::info!("🌐 Global 7-Node Multi-Asset Sovereign Oracle Daemon Booting (Multi-Node Quorum + Outlier Rejection + Dynamic Ticker Discovery Armed)...");
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = match redis::Client::open(redis_url) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Spot Oracle Redis connection failed: {}", e);
            return;
        }
    };
    let mut redis_conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Spot Oracle Redis multiplexer failed: {}", e);
            return;
        }
    };
    let min_quorum: usize = env::var("ORACLE_MIN_QUORUM")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&q| (1..=7).contains(&q))
        .unwrap_or(DEFAULT_MIN_ORACLE_QUORUM);
    let prices: PriceMap = Arc::new(RwLock::new(HashMap::new()));
    let mut last_circuit_breaker_state: HashMap<String, bool> = HashMap::new();
    {
        let mut w_lock = prices.write().await;
        for &asset in ORACLE_VOLATILE_ASSETS {
            w_lock.insert(asset.to_string(), HashMap::new());
            last_circuit_breaker_state.insert(asset.to_string(), false);
        }
    }

    tokio::spawn(bybit_ws(prices.clone()));
    tokio::spawn(gate_ws(prices.clone()));
    tokio::spawn(mexc_ws(prices.clone()));
    tokio::spawn(bitget_ws(prices.clone()));
    tokio::spawn(coinex_ws(prices.clone()));
    tokio::spawn(kucoin_ws(prices.clone()));
    tokio::spawn(kraken_ws(prices.clone()));
    tokio::spawn(coingecko_rest_fallback(prices.clone()));
    tokio::spawn(dynamic_tickers_rest_poller(
        prices.clone(),
        redis_client.clone(),
    ));

    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        let mut active_medians: HashMap<String, f64> = HashMap::new();
        let mut active_changes_24h: HashMap<String, f64> = HashMap::new();
        active_medians.insert("USDC".to_string(), 1.0);
        active_medians.insert("USDT".to_string(), 1.0);
        active_medians.insert("USD".to_string(), 1.0);
        active_changes_24h.insert("USDC".to_string(), 0.0);
        active_changes_24h.insert("USDT".to_string(), 0.0);
        active_changes_24h.insert("USD".to_string(), 0.0);

        let now = Instant::now();
        let dynamic_list: Vec<String> = DYNAMIC_ORACLE_TICKERS
            .iter()
            .map(|r| r.key().clone())
            .collect();

        {
            let p_lock = prices.read().await;
            for &asset in ORACLE_VOLATILE_ASSETS {
                if let Some(exchanges) = p_lock.get(asset) {
                    let mut raw_vals: Vec<f64> = exchanges
                        .values()
                        .filter(|(v, _, ts)| *v > 0.0 && v.is_finite() && now.duration_since(*ts).as_secs() < 60)
                        .map(|(v, _, _)| *v)
                        .collect();
                    let mut chg_vals: Vec<f64> = exchanges
                        .values()
                        .filter(|(v, _, ts)| *v > 0.0 && now.duration_since(*ts).as_secs() < 300)
                        .filter_map(|(_, chg, _)| *chg)
                        .filter(|c| c.is_finite())
                        .collect();
                    if raw_vals.len() >= min_quorum {
                        raw_vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                        let raw_median = compute_sorted_median(&raw_vals);
                        let filtered_vals: Vec<f64> = if raw_median > 0.0 {
                            raw_vals
                                .into_iter()
                                .filter(|&v| ((v - raw_median).abs() / raw_median) <= MAX_OUTLIER_DEVIATION_RATIO)
                                .collect()
                        } else {
                            Vec::new()
                        };
                        let active_count = filtered_vals.len();
                        if active_count >= min_quorum {
                            let median = compute_sorted_median(&filtered_vals);
                            active_medians.insert(asset.to_string(), median);
                            let median_chg = if !chg_vals.is_empty() {
                                chg_vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                                compute_sorted_median(&chg_vals)
                            } else {
                                0.0
                            };
                            active_changes_24h.insert(asset.to_string(), median_chg);
                            if last_circuit_breaker_state.get(asset) == Some(&true) {
                                tracing::info!(
                                    "🟢 [CIRCUIT BREAKER RESOLVED] {} Oracle consensus restored ({} quorum nodes within outlier bounds).",
                                    asset,
                                    active_count
                                );
                                last_circuit_breaker_state.insert(asset.to_string(), false);
                            }
                        } else if last_circuit_breaker_state.get(asset) == Some(&false) {
                            tracing::warn!(
                                "⚠️ [ORACLE OUTLIER BREAKER] {} failed outlier-filtered quorum ({}/{} valid nodes). Expiring cached quote...",
                                asset,
                                active_count,
                                min_quorum
                            );
                            last_circuit_breaker_state.insert(asset.to_string(), true);
                        }
                    } else if last_circuit_breaker_state.get(asset) == Some(&false) {
                        tracing::debug!(
                            "⏳ [ORACLE QUORUM PENDING] Awaiting {}-node quorum for {} (currently {} active)...",
                            min_quorum,
                            asset,
                            raw_vals.len()
                        );
                        last_circuit_breaker_state.insert(asset.to_string(), true);
                    }
                }
            }

            for dyn_asset in &dynamic_list {
                if active_medians.contains_key(dyn_asset) {
                    continue;
                }
                if let Some(exchanges) = p_lock.get(dyn_asset) {
                    let mut raw_vals: Vec<f64> = exchanges
                        .values()
                        .filter(|(v, _, ts)| *v > 0.0 && v.is_finite() && now.duration_since(*ts).as_secs() < 60)
                        .map(|(v, _, _)| *v)
                        .collect();
                    let mut chg_vals: Vec<f64> = exchanges
                        .values()
                        .filter(|(v, _, ts)| *v > 0.0 && now.duration_since(*ts).as_secs() < 300)
                        .filter_map(|(_, chg, _)| *chg)
                        .filter(|c| c.is_finite())
                        .collect();
                    if !raw_vals.is_empty() {
                        raw_vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                        let raw_median = compute_sorted_median(&raw_vals);
                        let filtered_vals: Vec<f64> = if raw_median > 0.0 {
                            raw_vals
                                .into_iter()
                                .filter(|&v| ((v - raw_median).abs() / raw_median) <= MAX_OUTLIER_DEVIATION_RATIO)
                                .collect()
                        } else {
                            Vec::new()
                        };
                        let resolved = if !filtered_vals.is_empty() {
                            compute_sorted_median(&filtered_vals)
                        } else {
                            raw_median
                        };
                        if resolved > 0.0 {
                            active_medians.insert(dyn_asset.clone(), resolved);
                            let median_chg = if !chg_vals.is_empty() {
                                chg_vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                                compute_sorted_median(&chg_vals)
                            } else {
                                0.0
                            };
                            active_changes_24h.insert(dyn_asset.clone(), median_chg);
                        }
                    }
                }
            }
        }

        if let Some(&eth_med) = active_medians.get("ETH") {
            active_medians.insert("BASE".to_string(), eth_med);
            active_changes_24h.insert(
                "BASE".to_string(),
                active_changes_24h.get("ETH").copied().unwrap_or(0.0),
            );
        }

        if !active_medians.is_empty() {
            let mut pipeline = redis::pipe();
            let mut json_data = json!({});
            let mut supported_vec: Vec<String> = ORACLE_SUPPORTED_ASSETS
                .iter()
                .map(|s| (*s).to_string())
                .collect();
            for dt in &dynamic_list {
                if !supported_vec.contains(dt) {
                    supported_vec.push(dt.clone());
                }
            }
            pipeline
                .cmd("SETEX")
                .arg("oracle:spot:supported_assets")
                .arg(CHANGE_24H_TTL_SECS)
                .arg(serde_json::to_string(&supported_vec).unwrap_or_else(|_| "[]".to_string()))
                .ignore();
            for (asset, median) in &active_medians {
                let pair_id = format!("{}_USDC", asset);
                let change_24h = active_changes_24h.get(asset).copied().unwrap_or(0.0);
                pipeline
                    .cmd("SETEX")
                    .arg(format!("oracle:spot:{}", pair_id))
                    .arg(SPOT_ORACLE_TTL_SECS)
                    .arg(median.to_string())
                    .ignore();
                pipeline
                    .cmd("SETEX")
                    .arg(format!("oracle:change24h:{}", pair_id))
                    .arg(CHANGE_24H_TTL_SECS)
                    .arg(change_24h.to_string())
                    .ignore();
                let asset_key = match asset.as_str() {
                    "KAS" => "kaspa".to_string(),
                    "BTC" => "bitcoin".to_string(),
                    "ETH" => "ethereum".to_string(),
                    "SOL" => "solana".to_string(),
                    "XRP" => "ripple".to_string(),
                    "DOGE" => "dogecoin".to_string(),
                    "TON" => "the-open-network".to_string(),
                    "SUI" => "sui".to_string(),
                    "ADA" => "cardano".to_string(),
                    "AVAX" => "avalanche-2".to_string(),
                    "LINK" => "chainlink".to_string(),
                    "LTC" => "litecoin".to_string(),
                    "POL" => "polygon-ecosystem-token".to_string(),
                    "TRX" => "tron".to_string(),
                    "ZEC" => "zcash".to_string(),
                    "ARB" => "arbitrum".to_string(),
                    "USDC" => "usd-coin".to_string(),
                    "USDT" => "tether".to_string(),
                    "USD" => "usd".to_string(),
                    other => other.to_lowercase(),
                };
                json_data[asset_key] = json!({
                    "usd": median,
                    "usd_24h_change": change_24h
                });
            }
            if active_medians.contains_key("KAS")
                && active_medians.contains_key("BTC")
                && active_medians.contains_key("ETH")
                && active_medians.contains_key("SOL")
            {
                pipeline
                    .cmd("SETEX")
                    .arg("oracle:spot:prices_json")
                    .arg(SPOT_ORACLE_TTL_SECS)
                    .arg(json_data.to_string())
                    .ignore();
            }
            if let Err(e) = pipeline.query_async::<_, ()>(&mut redis_conn).await {
                tracing::error!("Spot Oracle Redis Pipeline Failed: {}", e);
            }
        }
    }
}

async fn dynamic_tickers_rest_poller(prices: PriceMap, redis_client: redis::Client) {
    let client = reqwest::Client::builder()
        .user_agent("Perennia-Dynamic-Oracle/1.0")
        .timeout(Duration::from_secs(4))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let mut interval = tokio::time::interval(Duration::from_secs(6));

    loop {
        interval.tick().await;
        let Ok(mut conn) = redis_client.get_multiplexed_async_connection().await else {
            continue;
        };
        let raw_members: Vec<String> = redis::cmd("SMEMBERS")
            .arg("oracle:dynamic_tickers")
            .query_async(&mut conn)
            .await
            .unwrap_or_default();
        if raw_members.is_empty() {
            continue;
        }

        let mut active_dynamic = Vec::new();
        {
            let mut lock = prices.write().await;
            for raw in raw_members.into_iter().take(40) {
                let clean: String = raw
                    .trim()
                    .to_uppercase()
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .take(12)
                    .collect();
                if clean.len() < 2 || ORACLE_SUPPORTED_ASSETS.iter().any(|&a| a == clean) {
                    continue;
                }
                DYNAMIC_ORACLE_TICKERS.insert(clean.clone());
                lock.entry(clean.clone()).or_insert_with(HashMap::new);
                active_dynamic.push(clean);
            }
        }

        let kas_usd = {
            let r_lock = prices.read().await;
            r_lock
                .get("KAS")
                .and_then(|m| m.values().next().map(|(p, _, _)| *p))
                .unwrap_or(0.0)
        };

        for ticker in active_dynamic {
            let mexc_url = format!(
                "https://api.mexc.com/api/v3/ticker/24hr?symbol={}USDT",
                ticker
            );
            let gate_url = format!(
                "https://api.gateio.ws/api/v4/spot/tickers?currency_pair={}_USDT",
                ticker
            );
            let kucoin_url = format!(
                "https://api.kucoin.com/api/v1/market/stats?symbol={}-USDT",
                ticker
            );
            let bitget_url = format!(
                "https://api.bitget.com/api/v2/spot/market/tickers?symbol={}USDT",
                ticker
            );
            let coinex_url = format!(
                "https://api.coinex.com/v2/spot/ticker?market={}USDT",
                ticker
            );
            let kasfyi_url = format!(
                "https://api.kas.fyi/v1/tokens/krc20/{}/market",
                ticker
            );

            let (mexc_res, gate_res, kucoin_res, bitget_res, coinex_res, kasfyi_res) = tokio::join!(
                client.get(&mexc_url).send(),
                client.get(&gate_url).send(),
                client.get(&kucoin_url).send(),
                client.get(&bitget_url).send(),
                client.get(&coinex_url).send(),
                client.get(&kasfyi_url).send(),
            );

            let mut discovered_quotes: Vec<(&str, f64, Option<f64>)> = Vec::new();

            if let Ok(resp) = mexc_res {
                if resp.status().is_success() {
                    if let Ok(data) = resp.json::<Value>().await {
                        if let Some(p) = data
                            .get("lastPrice")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse::<f64>().ok())
                        {
                            if p > 0.0 {
                                let chg = data
                                    .get("priceChangePercent")
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| s.parse::<f64>().ok())
                                    .map(|r| r * 100.0);
                                discovered_quotes.push(("mexc", p, chg));
                            }
                        }
                    }
                }
            }

            if let Ok(resp) = gate_res {
                if resp.status().is_success() {
                    if let Ok(data) = resp.json::<Value>().await {
                        let item = if let Some(arr) = data.as_array() {
                            arr.first().cloned().unwrap_or(Value::Null)
                        } else {
                            data
                        };
                        if let Some(p) = item
                            .get("last")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse::<f64>().ok())
                        {
                            if p > 0.0 {
                                let chg = item
                                    .get("change_percentage")
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| s.parse::<f64>().ok());
                                discovered_quotes.push(("gate", p, chg));
                            }
                        }
                    }
                }
            }

            if let Ok(resp) = kucoin_res {
                if resp.status().is_success() {
                    if let Ok(data) = resp.json::<Value>().await {
                        if let Some(p) = data
                            .pointer("/data/last")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse::<f64>().ok())
                        {
                            if p > 0.0 {
                                let chg = data
                                    .pointer("/data/changeRate")
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| s.parse::<f64>().ok())
                                    .map(|r| r * 100.0);
                                discovered_quotes.push(("kucoin", p, chg));
                            }
                        }
                    }
                }
            }

            if let Ok(resp) = bitget_res {
                if resp.status().is_success() {
                    if let Ok(data) = resp.json::<Value>().await {
                        if let Some(item) = data
                            .get("data")
                            .and_then(|d| d.as_array())
                            .and_then(|a| a.first())
                        {
                            if let Some(p) = item
                                .get("lastPr")
                                .and_then(|v| v.as_str())
                                .and_then(|s| s.parse::<f64>().ok())
                            {
                                if p > 0.0 {
                                    let chg = item
                                        .get("change24h")
                                        .and_then(|v| v.as_str())
                                        .and_then(|s| s.parse::<f64>().ok())
                                        .map(|r| r * 100.0);
                                    discovered_quotes.push(("bitget", p, chg));
                                }
                            }
                        }
                    }
                }
            }

            if let Ok(resp) = coinex_res {
                if resp.status().is_success() {
                    if let Ok(data) = resp.json::<Value>().await {
                        if let Some(item) = data
                            .get("data")
                            .and_then(|d| d.as_array())
                            .and_then(|a| a.first())
                        {
                            if let Some(p) = item
                                .get("last")
                                .and_then(|v| v.as_str())
                                .and_then(|s| s.parse::<f64>().ok())
                            {
                                if p > 0.0 {
                                    let open_v = item
                                        .get("open")
                                        .and_then(|v| v.as_str())
                                        .and_then(|s| s.parse::<f64>().ok())
                                        .unwrap_or(0.0);
                                    let chg = if open_v > 0.0 {
                                        Some(((p - open_v) / open_v) * 100.0)
                                    } else {
                                        None
                                    };
                                    discovered_quotes.push(("coinex", p, chg));
                                }
                            }
                        }
                    }
                }
            }

            if let Ok(resp) = kasfyi_res {
                if resp.status().is_success() {
                    if let Ok(data) = resp.json::<Value>().await {
                        let usd_p = data
                            .pointer("/price/usd")
                            .or_else(|| data.get("priceUsd"))
                            .or_else(|| data.get("price"))
                            .and_then(|v| {
                                v.as_f64()
                                    .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
                            })
                            .unwrap_or(0.0);
                        let kas_p = data
                            .pointer("/price/kas")
                            .and_then(|v| {
                                v.as_f64()
                                    .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
                            })
                            .unwrap_or(0.0);
                        let resolved_usd = if usd_p > 0.0 {
                            usd_p
                        } else if kas_p > 0.0 && kas_usd > 0.0 {
                            kas_p * kas_usd
                        } else {
                            0.0
                        };
                        if resolved_usd > 0.0 {
                            let chg = data
                                .get("change24h")
                                .and_then(|v| v.as_f64());
                            discovered_quotes.push(("kasfyi", resolved_usd, chg));
                        }
                    }
                }
            }

            if !discovered_quotes.is_empty() {
                let mut lock = prices.write().await;
                if let Some(ex_map) = lock.get_mut(&ticker) {
                    for (ex_name, spot_val, chg_val) in discovered_quotes {
                        record_exchange_quote(ex_map, ex_name, spot_val, chg_val);
                    }
                }
            }
        }
    }
}

async fn coingecko_rest_fallback(prices: PriceMap) {
    let client = reqwest::Client::builder()
        .user_agent("Perennia-Sovereign-Oracle/1.0")
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let mut interval = tokio::time::interval(Duration::from_secs(20));
    let mapping = [
        ("KAS", "kaspa"),
        ("BTC", "bitcoin"),
        ("ETH", "ethereum"),
        ("SOL", "solana"),
        ("XRP", "ripple"),
        ("DOGE", "dogecoin"),
        ("TON", "the-open-network"),
        ("SUI", "sui"),
        ("ADA", "cardano"),
        ("AVAX", "avalanche-2"),
        ("LINK", "chainlink"),
        ("LTC", "litecoin"),
        ("POL", "polygon-ecosystem-token"),
        ("TRX", "tron"),
        ("ZEC", "zcash"),
        ("ARB", "arbitrum"),
    ];
    let ids_param: String = mapping.iter().map(|(_, cg)| *cg).collect::<Vec<_>>().join(",");
    let url = format!(
        "https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd&include_24hr_change=true",
        ids_param
    );
    loop {
        interval.tick().await;
        if let Ok(res) = client.get(&url).send().await {
            if let Ok(data) = res.json::<Value>().await {
                let mut lock = prices.write().await;
                for (ticker, cg_id) in mapping {
                    if let Some(usd) = data.pointer(&format!("/{}/usd", cg_id)).and_then(|v| v.as_f64()) {
                        let chg_24h = data
                            .pointer(&format!("/{}/usd_24h_change", cg_id))
                            .and_then(|v| v.as_f64());
                        if usd > 0.0 {
                            if let Some(ex_map) = lock.get_mut(ticker) {
                                record_exchange_quote(ex_map, "coingecko", usd, chg_24h);
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn bybit_ws(prices: PriceMap) {
    let args: Vec<String> = ORACLE_VOLATILE_ASSETS
        .iter()
        .map(|a| format!("tickers.{}USDT", a))
        .collect();
    loop {
        if let Ok((ws_stream, _)) = connect_async("wss://stream.bybit.com/v5/public/spot").await {
            tracing::info!("📡 [Oracle Array] Node 1 Online: Bybit");
            let (mut write, mut read) = ws_stream.split();
            for chunk in args.chunks(10) {
                let sub = json!({"op": "subscribe", "args": chunk});
                let _ = write.send(Message::Text(sub.to_string())).await;
            }
            while let Some(msg) = read.next().await {
                if let Ok(Message::Text(text)) = msg {
                    if let Ok(json) = serde_json::from_str::<Value>(&text) {
                        if let Some(topic) = json.get("topic").and_then(|t| t.as_str()) {
                            if let Some(data_obj) = json.get("data") {
                                if let Some(last_price) = data_obj.get("lastPrice").and_then(|p| p.as_str()) {
                                    if let Ok(val) = last_price.parse::<f64>() {
                                        let chg_pct = data_obj
                                            .get("price24hPcnt")
                                            .and_then(|c| c.as_str())
                                            .and_then(|s| s.parse::<f64>().ok())
                                            .map(|r| r * 100.0);
                                        let asset = topic.replace("tickers.", "").replace("USDT", "");
                                        if let Some(ex_map) = prices.write().await.get_mut(&asset) {
                                            record_exchange_quote(ex_map, "bybit", val, chg_pct);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn kucoin_ws(prices: PriceMap) {
    let client = reqwest::Client::new();
    let pairs_csv: String = ORACLE_VOLATILE_ASSETS
        .iter()
        .map(|a| format!("{}-USDT", a))
        .collect::<Vec<_>>()
        .join(",");
    let topic_str = format!("/market/ticker:{}", pairs_csv);
    loop {
        if let Ok(res) = client.post("https://api.kucoin.com/api/v1/bullet-public").send().await {
            if let Ok(data) = res.json::<Value>().await {
                if let Some(token) = data.pointer("/data/token").and_then(|t| t.as_str()) {
                    let ws_url = format!("wss://ws-api-spot.kucoin.com/?token={}", token);
                    if let Ok((ws_stream, _)) = connect_async(&ws_url).await {
                        tracing::info!("📡 [Oracle Array] Node 2 Online: KuCoin");
                        let (mut write, mut read) = ws_stream.split();
                        let sub = json!({
                            "id": 1,
                            "type": "subscribe",
                            "topic": topic_str,
                            "privateChannel": false,
                            "response": true
                        });
                        let _ = write.send(Message::Text(sub.to_string())).await;
                        while let Some(msg) = read.next().await {
                            if let Ok(Message::Text(text)) = msg {
                                if let Ok(json) = serde_json::from_str::<Value>(&text) {
                                    if json.get("type").and_then(|t| t.as_str()) == Some("message") {
                                        if let Some(topic) = json.get("topic").and_then(|t| t.as_str()) {
                                            if let Some(price_str) = json.pointer("/data/price").and_then(|p| p.as_str()) {
                                                if let Ok(val) = price_str.parse::<f64>() {
                                                    let chg_pct = json
                                                        .pointer("/data/changeRate")
                                                        .and_then(|c| c.as_str())
                                                        .and_then(|s| s.parse::<f64>().ok())
                                                        .map(|r| r * 100.0);
                                                    let asset = topic.replace("/market/ticker:", "").replace("-USDT", "");
                                                    if let Some(ex_map) = prices.write().await.get_mut(&asset) {
                                                        record_exchange_quote(ex_map, "kucoin", val, chg_pct);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn kraken_ws(prices: PriceMap) {
    let symbols: Vec<String> = ORACLE_VOLATILE_ASSETS
        .iter()
        .map(|a| format!("{}/USD", a))
        .collect();
    loop {
        if let Ok((ws_stream, _)) = connect_async("wss://ws.kraken.com/v2").await {
            tracing::info!("📡 [Oracle Array] Node 3 Online: Kraken");
            let (mut write, mut read) = ws_stream.split();
            let sub = json!({
                "method": "subscribe",
                "params": {
                    "channel": "ticker",
                    "symbol": symbols
                }
            });
            let _ = write.send(Message::Text(sub.to_string())).await;
            while let Some(msg) = read.next().await {
                if let Ok(Message::Text(text)) = msg {
                    if let Ok(json) = serde_json::from_str::<Value>(&text) {
                        if json.get("channel").and_then(|c| c.as_str()) == Some("ticker") {
                            if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                                for item in data {
                                    if let (Some(sym), Some(last)) = (
                                        item.get("symbol").and_then(|s| s.as_str()),
                                        item.get("last").and_then(|l| l.as_f64()),
                                    ) {
                                        let chg_pct = item.get("change_pct").and_then(|c| c.as_f64());
                                        let asset = sym.replace("/USD", "");
                                        if let Some(ex_map) = prices.write().await.get_mut(&asset) {
                                            record_exchange_quote(ex_map, "kraken", last, chg_pct);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn gate_ws(prices: PriceMap) {
    let payload: Vec<String> = ORACLE_VOLATILE_ASSETS
        .iter()
        .map(|a| format!("{}_USDT", a))
        .collect();
    loop {
        if let Ok((ws_stream, _)) = connect_async("wss://api.gateio.ws/ws/v4/").await {
            tracing::info!("📡 [Oracle Array] Node 4 Online: Gate.io");
            let (mut write, mut read) = ws_stream.split();
            let sub = json!({
                "time": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                "channel": "spot.tickers",
                "event": "subscribe",
                "payload": payload
            });
            let _ = write.send(Message::Text(sub.to_string())).await;
            while let Some(msg) = read.next().await {
                if let Ok(Message::Text(text)) = msg {
                    if let Ok(json) = serde_json::from_str::<Value>(&text) {
                        if json.get("event").and_then(|e| e.as_str()) == Some("update") {
                            if let Some(result) = json.get("result") {
                                let items = if result.is_array() {
                                    result.as_array().unwrap().clone()
                                } else {
                                    vec![result.clone()]
                                };
                                for item in items {
                                    if let (Some(pair), Some(last)) = (
                                        item.get("currency_pair").and_then(|p| p.as_str()),
                                        item.get("last").and_then(|l| l.as_str()),
                                    ) {
                                        if let Ok(val) = last.parse::<f64>() {
                                            let chg_pct = item
                                                .get("change_percentage")
                                                .and_then(|c| c.as_str())
                                                .and_then(|s| s.parse::<f64>().ok());
                                            let asset = pair.replace("_USDT", "");
                                            if let Some(ex_map) = prices.write().await.get_mut(&asset) {
                                                record_exchange_quote(ex_map, "gate", val, chg_pct);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn mexc_ws(prices: PriceMap) {
    let params: Vec<String> = ORACLE_VOLATILE_ASSETS
        .iter()
        .map(|a| format!("spot@public.miniTicker.v3.api@{}USDT", a))
        .collect();
    loop {
        if let Ok((ws_stream, _)) = connect_async("wss://wbs.mexc.com/ws").await {
            tracing::info!("📡 [Oracle Array] Node 5 Online: MEXC");
            let (mut write, mut read) = ws_stream.split();
            let sub = json!({
                "method": "SUBSCRIPTION",
                "params": params
            });
            let _ = write.send(Message::Text(sub.to_string())).await;
            while let Some(msg) = read.next().await {
                if let Ok(Message::Text(text)) = msg {
                    if let Ok(json) = serde_json::from_str::<Value>(&text) {
                        if let Some(c) = json.get("c").and_then(|c| c.as_str()) {
                            if let Some(d_obj) = json.get("d") {
                                if let Some(p) = d_obj.get("p").and_then(|p| p.as_str()) {
                                    if let Ok(val) = p.parse::<f64>() {
                                        let chg_pct = d_obj
                                            .get("r")
                                            .and_then(|r| r.as_str())
                                            .and_then(|s| s.parse::<f64>().ok())
                                            .map(|r| r * 100.0);
                                        let asset = c.split('@').last().unwrap_or("").replace("USDT", "");
                                        if let Some(ex_map) = prices.write().await.get_mut(&asset) {
                                            record_exchange_quote(ex_map, "mexc", val, chg_pct);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn bitget_ws(prices: PriceMap) {
    let args: Vec<Value> = ORACLE_VOLATILE_ASSETS
        .iter()
        .map(|a| json!({"instType": "SPOT", "channel": "ticker", "instId": format!("{}USDT", a)}))
        .collect();
    loop {
        if let Ok((ws_stream, _)) = connect_async("wss://ws.bitget.com/v2/ws/public").await {
            tracing::info!("📡 [Oracle Array] Node 6 Online: Bitget");
            let (mut write, mut read) = ws_stream.split();
            let sub = json!({
                "op": "subscribe",
                "args": args
            });
            let _ = write.send(Message::Text(sub.to_string())).await;
            while let Some(msg) = read.next().await {
                if let Ok(Message::Text(text)) = msg {
                    if text == "pong" { continue; }
                    if let Ok(json) = serde_json::from_str::<Value>(&text) {
                        if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                            for item in data {
                                if let (Some(inst), Some(last)) = (
                                    item.get("instId").and_then(|i| i.as_str()),
                                    item.get("lastPr").and_then(|l| l.as_str()),
                                ) {
                                    if let Ok(val) = last.parse::<f64>() {
                                        let chg_pct = item
                                            .get("change24h")
                                            .and_then(|c| c.as_str())
                                            .and_then(|s| s.parse::<f64>().ok())
                                            .map(|r| r * 100.0);
                                        let asset = inst.replace("USDT", "");
                                        if let Some(ex_map) = prices.write().await.get_mut(&asset) {
                                            record_exchange_quote(ex_map, "bitget", val, chg_pct);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn coinex_ws(prices: PriceMap) {
    let market_list: Vec<String> = ORACLE_VOLATILE_ASSETS
        .iter()
        .map(|a| format!("{}USDT", a))
        .collect();
    loop {
        if let Ok((ws_stream, _)) = connect_async("wss://socket.coinex.com/v2/spot").await {
            tracing::info!("📡 [Oracle Array] Node 7 Online: CoinEx");
            let (mut write, mut read) = ws_stream.split();
            let sub = json!({
                "method": "state.subscribe",
                "params": {"market_list": market_list},
                "id": 1
            });
            let _ = write.send(Message::Text(sub.to_string())).await;
            while let Some(msg) = read.next().await {
                if let Ok(Message::Text(text)) = msg {
                    if let Ok(json) = serde_json::from_str::<Value>(&text) {
                        if json.get("method").and_then(|m| m.as_str()) == Some("state.update") {
                            if let Some(state_list) = json
                                .get("data")
                                .and_then(|d| d.get("state_list"))
                                .and_then(|l| l.as_array())
                            {
                                for item in state_list {
                                    if let (Some(market), Some(last)) = (
                                        item.get("market").and_then(|m| m.as_str()),
                                        item.get("last").and_then(|l| l.as_str()),
                                    ) {
                                        if let Ok(val) = last.parse::<f64>() {
                                            let open_val = item
                                                .get("open")
                                                .and_then(|o| o.as_str())
                                                .and_then(|s| s.parse::<f64>().ok())
                                                .unwrap_or(0.0);
                                            let chg_pct = if open_val > 0.0 {
                                                Some(((val - open_val) / open_val) * 100.0)
                                            } else {
                                                None
                                            };
                                            let asset = market.replace("USDT", "");
                                            if let Some(ex_map) = prices.write().await.get_mut(&asset) {
                                                record_exchange_quote(ex_map, "coinex", val, chg_pct);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn query_kaspad_block_consensus(
    block_hash: &str,
) -> Option<(u64, f64, u64, Option<bool>)> {
    let endpoints = crate::kaspad_client::resolve_local_first_grpc_endpoints();
    for endpoint in endpoints {
        let Ok(Ok(mut client)) = tokio::time::timeout(
            Duration::from_secs(3),
            RpcClient::connect(endpoint),
        )
        .await
        else {
            continue;
        };
        let (tx, rx) = mpsc::channel::<KaspadRequest>(4);
        let Ok(Ok(response)) = tokio::time::timeout(
            Duration::from_secs(3),
            client.message_stream(ReceiverStream::new(rx)),
        )
        .await
        else {
            continue;
        };
        let mut stream = response.into_inner();
        let _ = tx.send(KaspadRequest {
            id: 1,
            payload: Some(RequestPayload::GetBlockRewardInfoRequest(GetBlockRewardInfoRequestMessage {
                hash: block_hash.to_string(),
            })),
        }).await;
        let _ = tx.send(KaspadRequest {
            id: 2,
            payload: Some(RequestPayload::GetBlockRequest(GetBlockRequestMessage {
                hash: block_hash.to_string(),
                include_transactions: true,
            })),
        }).await;
        let mut resolved_reward_sompi = 0u64;
        let mut resolved_diff = 0.0f64;
        let mut resolved_daa_score = 0u64;
        let mut is_orphaned_opt: Option<bool> = None;
        for _ in 0..2 {
            if let Ok(Ok(Some(msg))) = tokio::time::timeout(Duration::from_secs(2), stream.message()).await {
                match msg.payload {
                    Some(ResponsePayload::GetBlockRewardInfoResponse(res)) => {
                        if res.error.is_none() {
                            if let Some(amt) = res.reward_amount {
                                if amt > 0 {
                                    resolved_reward_sompi = amt;
                                }
                            }
                            if let Some(hdr) = res.header {
                                if resolved_diff <= 0.0 {
                                    resolved_diff = difficulty_from_bits(hdr.bits);
                                }
                                if hdr.daa_score > 0 {
                                    resolved_daa_score = hdr.daa_score;
                                }
                            }
                            if res.block_color == (BlockColor::Red as i32) {
                                is_orphaned_opt = Some(true);
                            } else if res.block_color == (BlockColor::Blue as i32) {
                                is_orphaned_opt = Some(false);
                            }
                        }
                    }
                    Some(ResponsePayload::GetBlockResponse(res)) => {
                        if res.error.is_none() {
                            if let Some(block) = res.block {
                                if let Some(vd) = &block.verbose_data {
                                    if vd.difficulty > 0.0 {
                                        resolved_diff = vd.difficulty;
                                    }
                                }
                                if let Some(hdr) = &block.header {
                                    if resolved_diff <= 0.0 {
                                        resolved_diff = difficulty_from_bits(hdr.bits);
                                    }
                                    if resolved_daa_score == 0 && hdr.daa_score > 0 {
                                        resolved_daa_score = hdr.daa_score;
                                    }
                                }
                                if resolved_reward_sompi == 0 {
                                    resolved_reward_sompi = extract_coinbase_reward_sompi(&block);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if resolved_reward_sompi > 0 || resolved_diff > 0.0 || resolved_daa_score > 0 || is_orphaned_opt.is_some() {
            return Some((resolved_reward_sompi, resolved_diff, resolved_daa_score, is_orphaned_opt));
        }
    }
    None
}

pub async fn start_oracle_daemon() {
    tracing::info!("🔮 Yield Oracle & Block Maturity Daemon Booting...");
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@127.0.0.1:5432/perennia".to_string());
    let pool = match sqlx::PgPool::connect(&db_url).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Oracle DB connection failed: {}", e);
            return;
        }
    };
    let _ = sqlx::query("ALTER TABLE network_blocks ADD COLUMN IF NOT EXISTS reward_sompi BIGINT NOT NULL DEFAULT 0")
        .execute(&pool)
        .await;
    let _ = sqlx::query("ALTER TABLE network_blocks ADD COLUMN IF NOT EXISTS reward_kas DOUBLE PRECISION NOT NULL DEFAULT 0.0")
        .execute(&pool)
        .await;
    let _ = sqlx::query("ALTER TABLE network_blocks ADD COLUMN IF NOT EXISTS daa_score BIGINT NOT NULL DEFAULT 0")
        .execute(&pool)
        .await;
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = match redis::Client::open(redis_url) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Oracle Redis connection failed: {}", e);
            return;
        }
    };
    let mut redis_conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Oracle Redis multiplexer failed: {}", e);
            return;
        }
    };
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        let mut block_events = Vec::new();
        loop {
            let result: redis::RedisResult<Option<String>> = redis::cmd("LPOP")
                .arg("perennia:oracle:block_buffer")
                .query_async(&mut redis_conn)
                .await;
            match result {
                Ok(Some(event_str)) => {
                    if let Ok(parsed) = serde_json::from_str::<Value>(&event_str) {
                        block_events.push(parsed);
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        if !block_events.is_empty() {
            let fallback_net_diff: f64 = redis::cmd("GET")
                .arg("pool:network_diff")
                .query_async::<_, Option<String>>(&mut redis_conn)
                .await
                .ok()
                .flatten()
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(0.0);
            let fallback_reward_sompi: u64 = redis::cmd("GET")
                .arg("pool:block_reward_sompi")
                .query_async::<_, Option<String>>(&mut redis_conn)
                .await
                .ok()
                .flatten()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let fallback_virtual_daa: u64 = redis::cmd("GET")
                .arg("pool:virtual_daa_score")
                .query_async::<_, Option<String>>(&mut redis_conn)
                .await
                .ok()
                .flatten()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let mut hashes = Vec::with_capacity(block_events.len());
            let mut workers = Vec::with_capacity(block_events.len());
            let mut nonces = Vec::with_capacity(block_events.len());
            let mut diffs = Vec::with_capacity(block_events.len());
            let mut rewards_sompi = Vec::with_capacity(block_events.len());
            let mut rewards_kas = Vec::with_capacity(block_events.len());
            let mut daa_scores = Vec::with_capacity(block_events.len());
            for evt in &block_events {
                if let (Some(hash), Some(worker), Some(nonce)) = (
                    evt["block_hash"].as_str(),
                    evt["worker"].as_str(),
                    evt["nonce"].as_u64(),
                ) {
                    let mut diff = evt["network_diff"].as_f64().filter(|&d| d > 0.0).unwrap_or(fallback_net_diff);
                    let mut reward_sompi = evt["reward_sompi"].as_u64().filter(|&r| r > 0).unwrap_or(fallback_reward_sompi);
                    let mut daa_score = evt["daa_score"].as_u64().filter(|&d| d > 0).unwrap_or(fallback_virtual_daa);
                    if let Some((node_sompi, node_diff, node_daa, _)) = query_kaspad_block_consensus(hash).await {
                        if node_sompi > 0 {
                            reward_sompi = node_sompi;
                        }
                        if node_diff > 0.0 {
                            diff = node_diff;
                        }
                        if node_daa > 0 {
                            daa_score = node_daa;
                        }
                    }
                    let reward_kas = (reward_sompi as f64) / 100_000_000.0;
                    hashes.push(hash.to_string());
                    workers.push(worker.to_string());
                    nonces.push(nonce as i64);
                    diffs.push(diff);
                    rewards_sompi.push(reward_sompi as i64);
                    rewards_kas.push(reward_kas);
                    daa_scores.push(daa_score as i64);
                }
            }
            if !hashes.is_empty() {
                let mut tx_blocks = match pool.begin().await {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::error!("Oracle failed to start DB transaction for blocks: {}", e);
                        continue;
                    }
                };
                let insert_res = sqlx::query(
                    r#"
                    INSERT INTO network_blocks (block_hash, worker_id, nonce, network_diff, reward_sompi, reward_kas, daa_score)
                    SELECT * FROM UNNEST($1::text[], $2::text[], $3::bigint[], $4::float8[], $5::bigint[], $6::float8[], $7::bigint[])
                    ON CONFLICT (block_hash) DO UPDATE SET
                        network_diff = CASE WHEN EXCLUDED.network_diff > 0 THEN EXCLUDED.network_diff ELSE network_blocks.network_diff END,
                        reward_sompi = CASE WHEN EXCLUDED.reward_sompi > 0 THEN EXCLUDED.reward_sompi ELSE network_blocks.reward_sompi END,
                        reward_kas = CASE WHEN EXCLUDED.reward_kas > 0 THEN EXCLUDED.reward_kas ELSE network_blocks.reward_kas END,
                        daa_score = CASE WHEN EXCLUDED.daa_score > 0 THEN EXCLUDED.daa_score ELSE network_blocks.daa_score END
                    "#
                )
                .bind(&hashes)
                .bind(&workers)
                .bind(&nonces)
                .bind(&diffs)
                .bind(&rewards_sompi)
                .bind(&rewards_kas)
                .bind(&daa_scores)
                .execute(&mut *tx_blocks)
                .await;
                if let Err(e) = insert_res {
                    tracing::error!("Failed to insert network blocks: {}", e);
                    let _ = tx_blocks.rollback().await;
                } else {
                    let _ = tx_blocks.commit().await;
                    tracing::info!("🧱 [ORACLE] Settled {} L1 network blocks into Postgres.", hashes.len());
                }
            }
        }
        if let Ok(pending_rows) = sqlx::query(
            "SELECT block_hash, reward_sompi, network_diff, COALESCE(daa_score, 0) AS daa_score FROM network_blocks WHERE (reward_sompi = 0 OR daa_score = 0 OR discovered_at > CURRENT_TIMESTAMP - INTERVAL '10 minutes') ORDER BY discovered_at DESC LIMIT 20"
        )
        .fetch_all(&pool)
        .await
        {
            for row in pending_rows {
                let block_hash: String = row.try_get("block_hash").unwrap_or_default();
                if block_hash.is_empty() {
                    continue;
                }
                if let Some((node_sompi, node_diff, node_daa, is_orphaned_opt)) = query_kaspad_block_consensus(&block_hash).await {
                    let current_sompi: i64 = row.try_get("reward_sompi").unwrap_or(0);
                    let current_diff: f64 = row.try_get("network_diff").unwrap_or(0.0);
                    let current_daa: i64 = row.try_get("daa_score").unwrap_or(0);
                    let final_sompi = if node_sompi > 0 { node_sompi as i64 } else { current_sompi };
                    let final_kas = (final_sompi as f64) / 100_000_000.0;
                    let final_diff = if node_diff > 0.0 { node_diff } else { current_diff };
                    let final_daa = if node_daa > 0 { node_daa as i64 } else { current_daa };
                    if let Some(is_orphaned) = is_orphaned_opt {
                        let _ = sqlx::query(
                            "UPDATE network_blocks SET reward_sompi = $1, reward_kas = $2, network_diff = $3, daa_score = $4, is_orphaned = $5 WHERE block_hash = $6"
                        )
                        .bind(final_sompi)
                        .bind(final_kas)
                        .bind(final_diff)
                        .bind(final_daa)
                        .bind(is_orphaned)
                        .bind(&block_hash)
                        .execute(&pool)
                        .await;
                    } else if final_sompi != current_sompi || (final_diff - current_diff).abs() > 1.0 || final_daa != current_daa {
                        let _ = sqlx::query(
                            "UPDATE network_blocks SET reward_sompi = $1, reward_kas = $2, network_diff = $3, daa_score = $4 WHERE block_hash = $5"
                        )
                        .bind(final_sompi)
                        .bind(final_kas)
                        .bind(final_diff)
                        .bind(final_daa)
                        .bind(&block_hash)
                        .execute(&pool)
                        .await;
                    }
                }
            }
        }
    }
}