use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;

use crate::config::SolverConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookLevel {
    pub price_usd: f64,
    pub qty: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VenueOrderBook {
    pub venue: String,
    pub asset: String,
    pub quote_currency: String,
    pub bids: Vec<BookLevel>,
    pub asks: Vec<BookLevel>,
    pub taker_fee_bps: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VwapFillQuote {
    pub venue: String,
    pub vwap_price_usd: f64,
    pub top_of_book_usd: f64,
    pub slippage_bps: f64,
    pub venue_fee_bps: f64,
    pub net_effective_price_usd: f64,
    pub filled_qty: f64,
}

pub struct CexOrderbookClient {
    http: Client,
    kucoin_taker_bps: f64,
    bitget_taker_bps: f64,
    kraken_taker_bps: f64,
}

impl CexOrderbookClient {
    pub fn new(cfg: &SolverConfig) -> Self {
        let http = Client::builder()
            .user_agent("Perennia-Solver-Books/0.1")
            .timeout(Duration::from_millis(2600))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self {
            http,
            kucoin_taker_bps: cfg.kucoin_taker_bps,
            bitget_taker_bps: cfg.bitget_taker_bps,
            kraken_taker_bps: cfg.kraken_taker_bps,
        }
    }

    pub async fn fetch_all_core_books(
        &self,
        usdt_usd_parity: f64,
    ) -> HashMap<String, Vec<VenueOrderBook>> {
        let mut by_asset: HashMap<String, Vec<VenueOrderBook>> = HashMap::new();
        if !usdt_usd_parity.is_finite() || usdt_usd_parity <= 0.99 || usdt_usd_parity >= 1.01 {
            return by_asset;
        }

        let assets = ["KAS", "BTC", "ETH", "SOL", "USDC", "USDT"];
        for asset in assets {
            by_asset.insert(asset.to_string(), Vec::new());
        }

        let (
            kc_kas, kc_btc, kc_eth, kc_sol, kc_usdc,
            bg_kas, bg_btc, bg_eth, bg_sol, bg_usdc,
            kr_kas, kr_btc, kr_eth, kr_sol, kr_usdc, kr_usdt
        ) = tokio::join!(
            self.fetch_kucoin("KAS", "KAS-USDT", usdt_usd_parity),
            self.fetch_kucoin("BTC", "BTC-USDT", usdt_usd_parity),
            self.fetch_kucoin("ETH", "ETH-USDT", usdt_usd_parity),
            self.fetch_kucoin("SOL", "SOL-USDT", usdt_usd_parity),
            self.fetch_kucoin("USDC", "USDC-USDT", usdt_usd_parity),
            self.fetch_bitget("KAS", "KASUSDT", usdt_usd_parity),
            self.fetch_bitget("BTC", "BTCUSDT", usdt_usd_parity),
            self.fetch_bitget("ETH", "ETHUSDT", usdt_usd_parity),
            self.fetch_bitget("SOL", "SOLUSDT", usdt_usd_parity),
            self.fetch_bitget("USDC", "USDCUSDT", usdt_usd_parity),
            self.fetch_kraken("KAS", "KASUSD"),
            self.fetch_kraken("BTC", "XBTUSD"),
            self.fetch_kraken("ETH", "ETHUSD"),
            self.fetch_kraken("SOL", "SOLUSD"),
            self.fetch_kraken("USDC", "USDCUSD"),
            self.fetch_kraken("USDT", "USDTZUSD"),
        );

        for opt in [
            kc_kas, kc_btc, kc_eth, kc_sol, kc_usdc,
            bg_kas, bg_btc, bg_eth, bg_sol, bg_usdc,
            kr_kas, kr_btc, kr_eth, kr_sol, kr_usdc, kr_usdt,
        ] {
            if let Some(book) = opt {
                by_asset.entry(book.asset.clone()).or_default().push(book);
            }
        }

        by_asset
    }

    async fn fetch_kucoin(
        &self,
        asset: &str,
        symbol: &str,
        quote_to_usd: f64,
    ) -> Option<VenueOrderBook> {
        let url = format!(
            "https://api.kucoin.com/api/v1/market/orderbook/level2_100?symbol={}",
            symbol
        );
        let resp = self.http.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let json: Value = resp.json().await.ok()?;
        if json.get("code").and_then(|c| c.as_str()) != Some("200000") {
            return None;
        }
        let bids = parse_levels(json.pointer("/data/bids"), quote_to_usd, true);
        let asks = parse_levels(json.pointer("/data/asks"), quote_to_usd, false);
        if bids.is_empty() || asks.is_empty() {
            return None;
        }
        Some(VenueOrderBook {
            venue: "kucoin".to_string(),
            asset: asset.to_string(),
            quote_currency: "USDT".to_string(),
            bids,
            asks,
            taker_fee_bps: self.kucoin_taker_bps,
        })
    }

    async fn fetch_bitget(
        &self,
        asset: &str,
        symbol: &str,
        quote_to_usd: f64,
    ) -> Option<VenueOrderBook> {
        let url = format!(
            "https://api.bitget.com/api/v2/spot/market/orderbook?symbol={}&type=step0&limit=100",
            symbol
        );
        let resp = self.http.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let json: Value = resp.json().await.ok()?;
        if json.get("code").and_then(|c| c.as_str()) != Some("00000") {
            return None;
        }
        let data_node = match json.get("data") {
            Some(Value::Array(arr)) => arr.first()?,
            Some(obj) => obj,
            None => return None,
        };
        let bids = parse_levels(data_node.get("bids"), quote_to_usd, true);
        let asks = parse_levels(data_node.get("asks"), quote_to_usd, false);
        if bids.is_empty() || asks.is_empty() {
            return None;
        }
        Some(VenueOrderBook {
            venue: "bitget".to_string(),
            asset: asset.to_string(),
            quote_currency: "USDT".to_string(),
            bids,
            asks,
            taker_fee_bps: self.bitget_taker_bps,
        })
    }

    async fn fetch_kraken(&self, asset: &str, pair: &str) -> Option<VenueOrderBook> {
        let url = format!(
            "https://api.kraken.com/0/public/Depth?pair={}&count=100",
            pair
        );
        let resp = self.http.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let json: Value = resp.json().await.ok()?;
        if json
            .get("error")
            .and_then(|e| e.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(true)
        {
            return None;
        }
        let inner = json
            .get("result")
            .and_then(|r| r.as_object())
            .and_then(|m| m.values().next())?;
        let bids = parse_levels(inner.get("bids"), 1.0, true);
        let asks = parse_levels(inner.get("asks"), 1.0, false);
        if bids.is_empty() || asks.is_empty() {
            return None;
        }
        Some(VenueOrderBook {
            venue: "kraken".to_string(),
            asset: asset.to_string(),
            quote_currency: "USD".to_string(),
            bids,
            asks,
            taker_fee_bps: self.kraken_taker_bps,
        })
    }
}

fn parse_levels(node: Option<&Value>, quote_to_usd: f64, desc_bids: bool) -> Vec<BookLevel> {
    let Some(arr) = node.and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(arr.len());
    for row in arr {
        let Some(cols) = row.as_array() else { continue };
        if cols.len() < 2 {
            continue;
        }
        let p = cols[0]
            .as_str()
            .and_then(|s| s.parse::<f64>().ok())
            .or_else(|| cols[0].as_f64())
            .unwrap_or(0.0);
        let q = cols[1]
            .as_str()
            .and_then(|s| s.parse::<f64>().ok())
            .or_else(|| cols[1].as_f64())
            .unwrap_or(0.0);
        if p > 0.0 && q > 0.0 && p.is_finite() && q.is_finite() {
            out.push(BookLevel {
                price_usd: p * quote_to_usd,
                qty: q,
            });
        }
    }
    if desc_bids {
        out.sort_by(|a, b| b.price_usd.partial_cmp(&a.price_usd).unwrap_or(std::cmp::Ordering::Equal));
    } else {
        out.sort_by(|a, b| a.price_usd.partial_cmp(&b.price_usd).unwrap_or(std::cmp::Ordering::Equal));
    }
    out
}

/// Walks L2 bids to sell `target_qty` of `asset` via IOC Taker order. Fails closed if book lacks depth.
pub fn best_sell_vwap(books: &[VenueOrderBook], target_qty: f64) -> Option<VwapFillQuote> {
    if target_qty <= 0.0 || !target_qty.is_finite() {
        return None;
    }
    let mut best: Option<VwapFillQuote> = None;
    for b in books {
        let Some(top) = b.bids.first().map(|l| l.price_usd) else { continue };
        let mut rem = target_qty;
        let mut usd_sum = 0.0;
        for lvl in &b.bids {
            let take = rem.min(lvl.qty);
            usd_sum += take * lvl.price_usd;
            rem -= take;
            if rem <= 1e-9 {
                break;
            }
        }
        if rem > 1e-6 {
            continue;
        }
        let vwap = usd_sum / target_qty;
        let slip_bps = (((top - vwap).max(0.0)) / top) * 10_000.0;
        let net_eff = vwap * (1.0 - b.taker_fee_bps / 10_000.0);
        let cand = VwapFillQuote {
            venue: b.venue.clone(),
            vwap_price_usd: vwap,
            top_of_book_usd: top,
            slippage_bps: slip_bps,
            venue_fee_bps: b.taker_fee_bps,
            net_effective_price_usd: net_eff,
            filled_qty: target_qty,
        };
        if best
            .as_ref()
            .map(|cur| cand.net_effective_price_usd > cur.net_effective_price_usd)
            .unwrap_or(true)
        {
            best = Some(cand);
        }
    }
    best
}

/// Walks L2 asks to buy `target_qty` of `asset` via IOC Taker order. Fails closed if book lacks depth.
pub fn best_buy_vwap(books: &[VenueOrderBook], target_qty: f64) -> Option<VwapFillQuote> {
    if target_qty <= 0.0 || !target_qty.is_finite() {
        return None;
    }
    let mut best: Option<VwapFillQuote> = None;
    for b in books {
        let Some(top) = b.asks.first().map(|l| l.price_usd) else { continue };
        let mut rem = target_qty;
        let mut usd_sum = 0.0;
        for lvl in &b.asks {
            let take = rem.min(lvl.qty);
            usd_sum += take * lvl.price_usd;
            rem -= take;
            if rem <= 1e-9 {
                break;
            }
        }
        if rem > 1e-6 {
            continue;
        }
        let vwap = usd_sum / target_qty;
        let slip_bps = (((vwap - top).max(0.0)) / top) * 10_000.0;
        let net_eff = vwap * (1.0 + b.taker_fee_bps / 10_000.0);
        let cand = VwapFillQuote {
            venue: b.venue.clone(),
            vwap_price_usd: vwap,
            top_of_book_usd: top,
            slippage_bps: slip_bps,
            venue_fee_bps: b.taker_fee_bps,
            net_effective_price_usd: net_eff,
            filled_qty: target_qty,
        };
        if best
            .as_ref()
            .map(|cur| cand.net_effective_price_usd < cur.net_effective_price_usd)
            .unwrap_or(true)
        {
            best = Some(cand);
        }
    }
    best
}

/// Selects best 0-bps Post-Only Maker venue (resting on passive bid to buy or passive ask to sell).
pub fn best_post_only_maker_buy(books: &[VenueOrderBook], target_qty: f64) -> Option<VwapFillQuote> {
    if target_qty <= 0.0 || !target_qty.is_finite() {
        return None;
    }
    let mut best: Option<VwapFillQuote> = None;
    for b in books {
        let Some(passive_bid) = b.bids.first().map(|l| l.price_usd) else { continue };
        let cand = VwapFillQuote {
            venue: b.venue.clone(),
            vwap_price_usd: passive_bid,
            top_of_book_usd: passive_bid,
            slippage_bps: 0.0,
            venue_fee_bps: 0.0, // 0 bps Post-Only Maker
            net_effective_price_usd: passive_bid,
            filled_qty: target_qty,
        };
        if best
            .as_ref()
            .map(|cur| cand.net_effective_price_usd < cur.net_effective_price_usd)
            .unwrap_or(true)
        {
            best = Some(cand);
        }
    }
    best
}

pub fn best_post_only_maker_sell(books: &[VenueOrderBook], target_qty: f64) -> Option<VwapFillQuote> {
    if target_qty <= 0.0 || !target_qty.is_finite() {
        return None;
    }
    let mut best: Option<VwapFillQuote> = None;
    for b in books {
        let Some(passive_ask) = b.asks.first().map(|l| l.price_usd) else { continue };
        let cand = VwapFillQuote {
            venue: b.venue.clone(),
            vwap_price_usd: passive_ask,
            top_of_book_usd: passive_ask,
            slippage_bps: 0.0,
            venue_fee_bps: 0.0, // 0 bps Post-Only Maker
            net_effective_price_usd: passive_ask,
            filled_qty: target_qty,
        };
        if best
            .as_ref()
            .map(|cur| cand.net_effective_price_usd > cur.net_effective_price_usd)
            .unwrap_or(true)
        {
            best = Some(cand);
        }
    }
    best
}