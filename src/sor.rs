use axum::{Json, extract::State};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::env;
use std::str::FromStr;
use uuid::Uuid;
use kaspa_consensus_core::tx::{
    Transaction, TransactionInput, TransactionOutput, TransactionId,
    ScriptPublicKey, UtxoEntry, PopulatedTransaction, TransactionOutpoint
};
use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use secp256k1::{Keypair, Message, Secp256k1};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

const LUA_ATOMIC_DEBIT_SINGLE: &str = r#"
local asset = ARGV[1]
local req = tonumber(ARGV[2])
local primary = tonumber(redis.call('HGET', KEYS[1], asset) or '0')
if primary >= req then
    redis.call('HINCRBYFLOAT', KEYS[1], asset, -req)
    return {1, tostring(0)}
end
if asset == 'KAS' then
    local unassigned = tonumber(redis.call('HGET', KEYS[1], 'Unassigned KAS') or '0')
    if (primary + unassigned) >= req then
        local from_unassigned = req - primary
        if primary > 0 then
            redis.call('HSET', KEYS[1], 'KAS', '0')
        end
        redis.call('HINCRBYFLOAT', KEYS[1], 'Unassigned KAS', -from_unassigned)
        return {1, tostring(from_unassigned)}
    end
end
return {0, tostring(0)}
"#;

const STORAGE_MASS_PARAMETER: u64 = 1_000_000_000_000;
const DEFAULT_FEE_PER_GRAM: u64 = 110;
const MIN_CHANGE_SOMPI: u64 = 10_000_000;
const DEFAULT_OFFLINE_MAX_UNHEDGED_KAS: f64 = 250.0;
const DEFAULT_ONLINE_MAX_UNHEDGED_KAS: f64 = 50_000.0;
pub const MIN_DARK_POOL_POSITION_USD: f64 = 5.00;
const LONG_TAIL_PASSTHROUGH_FEE_RATE: f64 = 0.015;
pub const DEFAULT_ECOSYSTEM_TICKER: &str = "SILO";

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
pub struct UtxoInput {
    pub transactionId: String,
    pub index: u32,
    pub amount: f64,
    pub scriptPublicKey: String,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case, dead_code)]
pub struct SorExecuteRequest {
    pub wallet: String,
    pub payAsset: String,
    pub receiveAsset: String,
    pub amount: f64,
    pub slippageTolerance: Option<f64>,
    pub utxos: Option<Vec<UtxoInput>>,
    pub systemMode: Option<String>,
}

#[derive(Serialize, Debug)]
#[allow(non_snake_case)]
pub struct WaterfallLeg {
    pub tier: u32,
    pub provider: String,
    pub filledAmount: f64,
    pub executionRate: f64,
    pub marginCaptured: f64,
}

#[derive(Serialize, Debug)]
#[allow(non_snake_case)]
pub struct SorExecutionPlan {
    pub totalAmount: f64,
    pub unifiedRate: f64,
    pub estimatedOutput: f64,
    pub legs: Vec<WaterfallLeg>,
    pub transaction_uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psbt: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formattedUtxos: Option<Vec<UtxoInput>>,
}

#[derive(Serialize)]
pub struct SorError {
    pub error: String,
}

pub fn resolve_ecosystem_ticker() -> String {
    env::var("PERENNIA_ECOSYSTEM_TICKER")
        .ok()
        .map(|s| s.trim().to_uppercase())
        .filter(|s| s.len() >= 4 && s.len() <= 6)
        .unwrap_or_else(|| DEFAULT_ECOSYSTEM_TICKER.to_string())
}

fn normalize_kaspa_base32(addr: &str) -> String {
    addr.trim()
        .to_lowercase()
        .trim_start_matches("kaspa:")
        .trim()
        .to_string()
}

fn resolve_treasury_kas_address() -> Result<String, String> {
    let clean = crate::chronos::resolve_master_treasury_address();
    if clean.is_empty() {
        return Err("CRITICAL: Master Treasury KAS address not configured in environment or config.yaml.".to_string());
    }
    Ok(format!("kaspa:{}", clean))
}

fn get_secure_client() -> Client {
    Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_else(|_| Client::new())
}

fn get_fee_per_gram() -> u64 {
    env::var("KASPA_FEE_PER_GRAM")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&v| v >= 100)
        .unwrap_or(DEFAULT_FEE_PER_GRAM)
}

pub fn is_cex_hedging_configured() -> bool {
    env::var("MEXC_API_KEY").map(|k| !k.trim().is_empty()).unwrap_or(false)
        && env::var("MEXC_SECRET_KEY").map(|s| !s.trim().is_empty()).unwrap_or(false)
}

pub fn get_max_unhedged_liability_kas() -> f64 {
    let default_cap = if is_cex_hedging_configured() {
        DEFAULT_ONLINE_MAX_UNHEDGED_KAS
    } else {
        DEFAULT_OFFLINE_MAX_UNHEDGED_KAS
    };
    env::var("MAX_UNHEDGED_LIABILITY_KAS")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|&v| v > 0.0)
        .unwrap_or(default_cap)
}

pub fn get_min_dark_pool_position_usd() -> f64 {
    env::var("MIN_DARK_POOL_POSITION_USD")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|&v| v >= 1.0)
        .unwrap_or(MIN_DARK_POOL_POSITION_USD)
}

pub fn compute_constant_mean_invariant(
    reserves: &HashMap<String, f64>,
    weights: &HashMap<String, f64>,
) -> f64 {
    if reserves.is_empty() || weights.is_empty() {
        return 0.0;
    }
    let mut k = 1.0_f64;
    for (asset, &w) in weights {
        if w <= 0.0 {
            continue;
        }
        let b = reserves.get(asset).copied().unwrap_or(0.0);
        if b <= 0.0 {
            return 0.0;
        }
        k *= b.powf(w);
    }
    k
}

fn calculate_transaction_mass(num_inputs: usize, num_outputs: usize, payload_len: usize) -> u64 {
    let base_mass = 200;
    let input_mass = num_inputs as u64 * 1200;
    let output_mass = num_outputs as u64 * 450;
    let payload_mass = payload_len as u64;
    base_mass + input_mass + output_mass + payload_mass
}

fn calculate_storage_mass(input_amounts: &[u64], output_amounts: &[u64]) -> u64 {
    if input_amounts.is_empty() || output_amounts.is_empty() {
        return 0;
    }
    let harmonic_outs: u64 = output_amounts
        .iter()
        .map(|&v| if v > 0 { STORAGE_MASS_PARAMETER / v } else { STORAGE_MASS_PARAMETER })
        .sum();
    if output_amounts.len() == 1 || input_amounts.len() >= output_amounts.len() {
        let sum_ins: u64 = input_amounts.iter().sum();
        let mean_ins = sum_ins / (input_amounts.len() as u64);
        if mean_ins == 0 {
            return harmonic_outs;
        }
        let arithmetic_ins = (input_amounts.len() as u64).saturating_mul(STORAGE_MASS_PARAMETER / mean_ins);
        harmonic_outs.saturating_sub(arithmetic_ins)
    } else {
        let harmonic_ins: u64 = input_amounts
            .iter()
            .map(|&v| if v > 0 { STORAGE_MASS_PARAMETER / v } else { 0 })
            .sum();
        harmonic_outs.saturating_sub(harmonic_ins)
    }
}

pub fn parse_json_u64(val: Option<&Value>) -> Option<u64> {
    val.and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok())))
}

fn decode_address_to_script(address: &str) -> Result<String, String> {
    let clean_addr = address.trim().replace("kaspa:", "");
    let formatted_addr = format!("kaspa:{}", clean_addr);
    let parts: Vec<&str> = formatted_addr.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid address format".to_string());
    }
    let base32 = parts[1];
    if base32.len() < 8 {
        return Err("Address too short".to_string());
    }
    let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut decoded = Vec::new();
    for c in base32[..base32.len() - 8].chars() {
        if let Some(idx) = charset.find(c) {
            decoded.push(idx as u8);
        } else {
            return Err(format!("Invalid base32 character detected: {}", c));
        }
    }
    let mut out = Vec::new();
    let mut val = 0u32;
    let mut bits = 0;
    for &d in &decoded {
        val = (val << 5) | (d as u32);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push((val >> bits) as u8);
        }
    }
    if out.len() < 33 {
        return Err(format!("Decoded public key is too short. Expected 33 bytes, got {}", out.len()));
    }
    let pubkey = &out[1..33];
    let mut hex_str = String::new();
    for byte in pubkey {
        use std::fmt::Write;
        write!(&mut hex_str, "{:02x}", byte).unwrap();
    }
    Ok(format!("20{}ac", hex_str))
}

async fn get_usd_price(
    pool: &PgPool,
    redis_conn: &mut redis::aio::MultiplexedConnection,
    asset: &str,
) -> f64 {
    let clean = asset.trim().to_uppercase();
    if clean == "USDC" || clean == "USDT" || clean == "USD" {
        return 1.0;
    }
    let key = format!("oracle:spot:{}_USDC", clean);
    let val_str: Option<String> = redis::cmd("GET")
        .arg(&key)
        .query_async(redis_conn)
        .await
        .unwrap_or(None);
    if let Some(v) = val_str {
        if let Ok(parsed) = v.parse::<f64>() {
            if parsed > 0.0 {
                return parsed;
            }
        }
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

async fn fetch_third_party_long_tail_price_usd(client: &Client, ticker: &str, kas_usd: f64) -> f64 {
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

pub async fn get_lp_pair_reserves(pool: &PgPool, quote_asset: &str) -> (f64, f64) {
    let clean_quote = quote_asset.trim().to_uppercase();
    let pool_pair = format!("KAS/{}", clean_quote);
    let mut total_kas = 0.0;
    let mut total_quote = 0.0;

    if let Ok(Some(row)) = sqlx::query(
        "SELECT COALESCE(SUM(staked_asset_a), 0.0) AS reserve_a, COALESCE(SUM(staked_asset_b), 0.0) AS reserve_b FROM liquidity_providers WHERE pool_pair = $1"
    )
    .bind(&pool_pair)
    .fetch_optional(pool)
    .await
    {
        total_kas += row.try_get::<f64, _>("reserve_a").unwrap_or(0.0).max(0.0);
        total_quote += row.try_get::<f64, _>("reserve_b").unwrap_or(0.0).max(0.0);
    }

    if let Ok(rows) = sqlx::query(
        "SELECT pool_pair, staked_asset_a, weights_json, reserves_json FROM liquidity_providers WHERE pool_pair LIKE 'KAS/%/%'"
    )
    .fetch_all(pool)
    .await
    {
        for r in rows {
            let p_pair: String = r.try_get("pool_pair").unwrap_or_default();
            let parts: Vec<&str> = p_pair.split('/').collect();
            if !parts.iter().any(|&t| t.eq_ignore_ascii_case(&clean_quote)) {
                continue;
            }
            let reserves_val: Value = r.try_get("reserves_json").unwrap_or_else(|_| json!({}));
            let weights_val: Value = r.try_get("weights_json").unwrap_or_else(|_| json!({}));
            let quote_res = reserves_val
                .get(&clean_quote)
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0)
                .max(0.0);
            if quote_res > 0.0 {
                let kas_res = reserves_val
                    .get("KAS")
                    .and_then(|v| v.as_f64())
                    .unwrap_or_else(|| r.try_get::<f64, _>("staked_asset_a").unwrap_or(0.0))
                    .max(0.0);
                let quote_weight = weights_val
                    .get(&clean_quote)
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.25)
                    .clamp(0.01, 0.50);
                let kas_share_for_quote = kas_res * (quote_weight / 0.50).clamp(0.05, 1.0);
                total_kas += kas_share_for_quote;
                total_quote += quote_res;
            }
        }
    }

    (total_kas, total_quote)
}

pub async fn get_multi_asset_cross_pair_reserves(
    pool: &PgPool,
    asset_in: &str,
    asset_out: &str,
) -> (f64, f64, usize) {
    let clean_in = asset_in.trim().to_uppercase();
    let clean_out = asset_out.trim().to_uppercase();
    let mut reserve_in = 0.0;
    let mut reserve_out = 0.0;
    let mut matching_plants = 0usize;

    if let Ok(rows) = sqlx::query(
        "SELECT pool_pair, staked_asset_a, staked_asset_b, weights_json, reserves_json FROM liquidity_providers"
    )
    .fetch_all(pool)
    .await
    {
        for r in rows {
            let p_pair: String = r.try_get("pool_pair").unwrap_or_default();
            let parts: Vec<String> = p_pair.split('/').map(|s| s.trim().to_uppercase()).collect();
            if parts.contains(&clean_in) && parts.contains(&clean_out) {
                matching_plants += 1;
                let reserves_val: Value = r.try_get("reserves_json").unwrap_or_else(|_| json!({}));
                if let (Some(r_in), Some(r_out)) = (
                    reserves_val.get(&clean_in).and_then(|v| v.as_f64()),
                    reserves_val.get(&clean_out).and_then(|v| v.as_f64()),
                ) {
                    reserve_in += r_in.max(0.0);
                    reserve_out += r_out.max(0.0);
                } else if parts.len() == 2 {
                    let sa: f64 = r.try_get("staked_asset_a").unwrap_or(0.0);
                    let sb: f64 = r.try_get("staked_asset_b").unwrap_or(0.0);
                    if parts[0] == clean_in {
                        reserve_in += sa.max(0.0);
                        reserve_out += sb.max(0.0);
                    } else {
                        reserve_in += sb.max(0.0);
                        reserve_out += sa.max(0.0);
                    }
                }
            }
        }
    }
    (reserve_in, reserve_out, matching_plants)
}

pub async fn get_silo_staking_fee_cap(
    pool: &PgPool,
    clean_wallet: &str,
    prefixed_wallet: &str,
) -> Option<(f64, String, f64)> {
    let eco_ticker = resolve_ecosystem_ticker();
    let mut total_staked_silo = 0.0;

    if let Ok(Some(row)) = sqlx::query(
        "SELECT COALESCE(SUM(amount_staked), 0.0) AS staked_sum FROM silo_staking_positions WHERE (wallet_address = $1 OR wallet_address = $2) AND token_ticker = $3 AND status = 'ACTIVE'"
    )
    .bind(prefixed_wallet)
    .bind(clean_wallet)
    .bind(&eco_ticker)
    .fetch_optional(pool)
    .await
    {
        total_staked_silo += row.try_get::<f64, _>("staked_sum").unwrap_or(0.0).max(0.0);
    }

    let eco_pair = format!("KAS/{}", eco_ticker);
    if let Ok(Some(row)) = sqlx::query(
        "SELECT COALESCE(SUM(staked_asset_b), 0.0) AS lp_silo_sum FROM liquidity_providers WHERE (wallet_address = $1 OR wallet_address = $2) AND pool_pair = $3"
    )
    .bind(prefixed_wallet)
    .bind(clean_wallet)
    .bind(&eco_pair)
    .fetch_optional(pool)
    .await
    {
        total_staked_silo += row.try_get::<f64, _>("lp_silo_sum").unwrap_or(0.0).max(0.0);
    }

    if total_staked_silo >= 1_000_000.0 {
        Some((
            0.0025,
            format!("{} Sovereign Core Tier (0.25% Fee)", eco_ticker),
            total_staked_silo,
        ))
    } else if total_staked_silo >= 100_000.0 {
        Some((
            0.0050,
            format!("{} Institutional Tier (0.50% Fee)", eco_ticker),
            total_staked_silo,
        ))
    } else if total_staked_silo >= 10_000.0 {
        Some((
            0.0075,
            format!("{} Staker Tier (0.75% Fee)", eco_ticker),
            total_staked_silo,
        ))
    } else {
        None
    }
}

async fn compute_inventory_skew_and_guard(
    pool: &PgPool,
    redis_conn: &mut redis::aio::MultiplexedConnection,
    clean_wallet: &str,
    prefixed_wallet: &str,
    pay_asset: &str,
    receive_asset: &str,
    amount: f64,
    pay_usd: f64,
    rec_usd: f64,
    spot_rate: f64,
) -> Result<(f64, String), String> {
    let unhedged_str: Option<String> = redis::cmd("GET")
        .arg("perennia:treasury:unhedged_delta_kas")
        .query_async(redis_conn)
        .await
        .unwrap_or(None);
    let running_unhedged_signed: f64 = unhedged_str
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);
    let cex_configured = is_cex_hedging_configured();
    let max_unhedged_kas = get_max_unhedged_liability_kas();
    let gross_trade_usd = amount * pay_usd;
    let is_whale = gross_trade_usd >= 2000.0;
    let mut base_tier_rate = if is_whale { 0.005 } else { 0.015 };
    let mut silo_tier_label: Option<String> = None;

    if let Some((silo_cap_rate, label, _staked_qty)) =
        get_silo_staking_fee_cap(pool, clean_wallet, prefixed_wallet).await
    {
        if silo_cap_rate < base_tier_rate {
            base_tier_rate = silo_cap_rate;
            silo_tier_label = Some(label);
        }
    }

    if pay_asset == "KAS" && receive_asset != "KAS" {
        let (_lp_kas_reserve, lp_quote_reserve) = get_lp_pair_reserves(pool, receive_asset).await;
        let lp_absorbable_kas = ((lp_quote_reserve * rec_usd) / pay_usd).max(0.0);
        let uncovered_sell_kas = (amount - lp_absorbable_kas).max(0.0);
        let current_excess_sell_kas = (-running_unhedged_signed).max(0.0);
        let projected_excess_sell_kas = current_excess_sell_kas + uncovered_sell_kas;
        if !cex_configured && uncovered_sell_kas > 0.0 && projected_excess_sell_kas > max_unhedged_kas {
            return Err(format!(
                "UNHEDGED_KAS_CIRCUIT_BREAKER: Selling {:.2} KAS exceeds LP quote capacity ({:.2} KAS) and Max Unhedged Treasury Cap ({:.2}/{:.2} KAS) while CEX hedging is offline.",
                amount, lp_absorbable_kas, projected_excess_sell_kas, max_unhedged_kas
            ));
        }
        if running_unhedged_signed > 5.0 {
            return Ok((0.0025, "Perennia Liquidity Pool (Inventory Rebalance Rebate)".to_string()));
        }
        if uncovered_sell_kas <= 0.0 && current_excess_sell_kas <= max_unhedged_kas * 0.25 {
            let label = silo_tier_label
                .unwrap_or_else(|| "Perennia Liquidity Pool (LP Counterparty Matched)".to_string());
            return Ok((base_tier_rate, label));
        }
        let skew_ratio = (projected_excess_sell_kas / max_unhedged_kas).clamp(0.0, 1.5);
        let volatility_buffer_premium = (skew_ratio * 0.030).clamp(0.0, 0.030);
        let effective_rate = (base_tier_rate + volatility_buffer_premium).clamp(base_tier_rate, 0.045);
        return Ok((
            effective_rate,
            format!("Perennia Liquidity Pool (Skew-Protected {:.2}%)", effective_rate * 100.0),
        ));
    } else if receive_asset == "KAS" && pay_asset != "KAS" {
        let (lp_kas_reserve, _lp_quote_reserve) = get_lp_pair_reserves(pool, pay_asset).await;
        let est_kas_bought = amount * spot_rate;
        let uncovered_buy_kas = (est_kas_bought - lp_kas_reserve).max(0.0);
        let current_excess_buy_kas = running_unhedged_signed.max(0.0);
        let projected_excess_buy_kas = current_excess_buy_kas + uncovered_buy_kas;
        if !cex_configured && uncovered_buy_kas > 0.0 && projected_excess_buy_kas > max_unhedged_kas {
            return Err(format!(
                "UNHEDGED_KAS_CIRCUIT_BREAKER: Buying {:.2} KAS exceeds LP KAS capacity ({:.2} KAS) and Max Unhedged Cap ({:.2} KAS).",
                est_kas_bought, lp_kas_reserve, max_unhedged_kas
            ));
        }
        if running_unhedged_signed < -1.0 {
            return Ok((
                0.0015,
                "Perennia Liquidity Pool (Drain Discount 0.15%)".to_string(),
            ));
        }
        let skew_ratio = (projected_excess_buy_kas / max_unhedged_kas).clamp(0.0, 1.0);
        let effective_rate = (base_tier_rate + skew_ratio * 0.015).clamp(base_tier_rate, 0.030);
        let label = silo_tier_label.unwrap_or_else(|| "Perennia Liquidity Pool (Batched)".to_string());
        return Ok((effective_rate, label));
    }

    let (_res_in, _res_out, plant_count) =
        get_multi_asset_cross_pair_reserves(pool, pay_asset, receive_asset).await;
    let default_label = if plant_count > 0 {
        format!(
            "Perennia Multi-Asset Liquidity Plant ({}/{} Cross-Pair)",
            pay_asset, receive_asset
        )
    } else {
        "Perennia Liquidity Pool (Cross-Asset)".to_string()
    };
    let label = silo_tier_label.unwrap_or(default_label);
    Ok((base_tier_rate, label))
}

fn build_netting_order_json(
    wallet: &str,
    pay_asset: &str,
    receive_asset: &str,
    pay_amount: f64,
    estimated_output: f64,
    spot_rate: f64,
    fee_captured_usd: f64,
) -> Value {
    let direction = if pay_asset == "KAS" {
        "SELL_KAS"
    } else if receive_asset == "KAS" {
        "BUY_KAS"
    } else {
        "CROSS_SYNTHETIC"
    };
    let amount_kas = if pay_asset == "KAS" {
        pay_amount
    } else if receive_asset == "KAS" {
        estimated_output
    } else {
        0.0
    };
    let target_asset = if receive_asset == "KAS" {
        pay_asset
    } else {
        receive_asset
    };
    json!({
        "wallet": wallet,
        "direction": direction,
        "amount_kas": amount_kas,
        "spot_price": spot_rate,
        "fee_captured_usd": fee_captured_usd,
        "pay_asset": pay_asset,
        "pay_amount": pay_amount,
        "target_asset": target_asset,
        "estimated_output": estimated_output
    })
}

async fn sync_unassigned_kas_debit(pool: &PgPool, clean_wallet: &str, from_unassigned: f64) {
    if from_unassigned > 1e-9 {
        let prefixed = format!("kaspa:{}", clean_wallet);
        let _ = sqlx::query(
            "UPDATE yield_reservoirs SET streaming_balance_kas = GREATEST(0.0, streaming_balance_kas - $1), last_updated = CURRENT_TIMESTAMP WHERE LOWER(REPLACE(TRIM(wallet_address), 'kaspa:', '')) = $2 OR wallet_address = $3"
        )
        .bind(from_unassigned)
        .bind(clean_wallet)
        .bind(&prefixed)
        .execute(pool)
        .await;
    }
}

async fn record_dex_swap_tax_event(
    pool: &PgPool,
    clean_wallet: &str,
    receive_asset: &str,
    pay_amount: f64,
    estimated_output: f64,
    pay_usd: f64,
    rec_usd: f64,
    spot_rate: f64,
) {
    let target_ticker = receive_asset.trim().to_uppercase();
    let gross_usd = if target_ticker == "USDC" || target_ticker == "USDT" || target_ticker == "USD" {
        estimated_output
    } else if rec_usd > 0.0 {
        estimated_output * rec_usd
    } else if pay_usd > 0.0 {
        pay_amount * pay_usd
    } else {
        pay_amount * spot_rate
    };
    let execution_spot = if rec_usd > 0.0 { rec_usd } else { spot_rate };
    if gross_usd > 0.0 && estimated_output > 0.0 {
        let _ = sqlx::query(
            "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution) VALUES ($1, $2, 'DEX_SWAP', $3, $4, $5)"
        )
        .bind(clean_wallet)
        .bind(&target_ticker)
        .bind(gross_usd)
        .bind(estimated_output)
        .bind(execution_spot)
        .execute(pool)
        .await;
    }
}

pub async fn handle_sor_execute(
    State(pool): State<PgPool>,
    Json(payload): Json<SorExecuteRequest>,
) -> Result<Json<SorExecutionPlan>, Json<SorError>> {
    if payload.amount <= 0.0 {
        return Err(Json(SorError { error: "Swap amount must be strictly greater than zero.".to_string() }));
    }
    let client = get_secure_client();
    let fee_per_gram = get_fee_per_gram();
    let redis_url = env::var("REDIS_URL").map(|s| s.trim().to_string()).unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = match redis::Client::open(redis_url) {
        Ok(c) => c,
        Err(e) => return Err(Json(SorError { error: format!("Redis Error: {}", e) })),
    };
    let mut redis_conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => return Err(Json(SorError { error: format!("Redis Connection Error: {}", e) })),
    };

    let pay_asset_clean = payload.payAsset.trim().to_uppercase();
    let receive_asset_clean = payload.receiveAsset.trim().to_uppercase();
    let pay_oracle_supported = crate::oracle::is_oracle_supported_asset(&pay_asset_clean);
    let rec_oracle_supported = crate::oracle::is_oracle_supported_asset(&receive_asset_clean);
    let pay_usd = get_usd_price(&pool, &mut redis_conn, &pay_asset_clean).await;
    let rec_usd = get_usd_price(&pool, &mut redis_conn, &receive_asset_clean).await;
    let min_dark_pool_usd = get_min_dark_pool_position_usd();
    let clean_wallet = normalize_kaspa_base32(&payload.wallet);
    let prefixed_wallet = format!("kaspa:{}", clean_wallet);
    let ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
    let tx_uuid = Uuid::new_v4().to_string();
    let corp_kas = resolve_treasury_kas_address()
        .map_err(|e| Json(SorError { error: e }))?;

    if pay_oracle_supported && pay_usd <= 0.0 {
        return Err(Json(SorError {
            error: format!(
                "ORACLE_HALT: Live oracle spot feed for {} is currently unavailable. Zero hardcoded prices permitted.",
                pay_asset_clean
            ),
        }));
    }
    if rec_oracle_supported && rec_usd <= 0.0 {
        return Err(Json(SorError {
            error: format!(
                "ORACLE_HALT: Live oracle spot feed for {} is currently unavailable. Zero hardcoded prices permitted.",
                receive_asset_clean
            ),
        }));
    }

    if !pay_oracle_supported || !rec_oracle_supported {
        if pay_asset_clean != "KAS" {
            return Err(Json(SorError {
                error: format!(
                    "UNVERIFIED_ASSET_GUARD: Unverified/custom long-tail token {} cannot be held in Pool reserves. Custom pass-through swaps must originate from KAS.",
                    pay_asset_clean
                )
            }));
        }
        if pay_usd <= 0.0 {
            return Err(Json(SorError {
                error: "ORACLE_HALT: Live KAS/USDC oracle spot price is required for 3rd-party pass-through routing.".to_string()
            }));
        }
        let kas_spot = pay_usd;
        let l1_fee_kas = ((2000u64 * fee_per_gram) as f64) / 100_000_000.0;
        let l1_fee_usd = l1_fee_kas * kas_spot;
        let third_party_rail_usd = env::var(format!("BATCH_RAIL_COST_USD_{}", receive_asset_clean))
            .ok()
            .and_then(|v| v.trim().parse::<f64>().ok())
            .unwrap_or(1.00);
        let third_party_min_usd = env::var(format!("MIN_PASSTHROUGH_USD_{}", receive_asset_clean))
            .ok()
            .and_then(|v| v.trim().parse::<f64>().ok())
            .unwrap_or(5.00);
        let min_profitable_usd = (third_party_min_usd + third_party_rail_usd + l1_fee_usd)
            .max(((third_party_rail_usd + l1_fee_usd) * 2.0) / LONG_TAIL_PASSTHROUGH_FEE_RATE);
        let min_profitable_kas = min_profitable_usd / kas_spot;
        let gross_swap_usd = payload.amount * kas_spot;
        if gross_swap_usd < min_profitable_usd {
            return Err(Json(SorError {
                error: format!(
                    "[ROLLED_OVER]: Unverified/long-tail 3rd-party pass-through for {} ({:.4} KAS / ${:.2}) is below minimum profitable batch + gas floor (${:.2} / {:.4} KAS).",
                    receive_asset_clean, payload.amount, gross_swap_usd, min_profitable_usd, min_profitable_kas
                )
            }));
        }
        let mut third_party_token_usd = fetch_third_party_long_tail_price_usd(&client, &receive_asset_clean, kas_spot).await;
        if third_party_token_usd <= 0.0 {
            let pool_pair_1 = format!("KAS/{}", receive_asset_clean);
            let pool_pair_2 = format!("{}/KAS", receive_asset_clean);
            if let Ok(Some(row)) = sqlx::query(
                "SELECT pool_pair, SUM(staked_asset_a) as reserve_a, SUM(staked_asset_b) as reserve_b FROM liquidity_providers WHERE pool_pair = $1 OR pool_pair = $2 GROUP BY pool_pair"
            )
            .bind(&pool_pair_1)
            .bind(&pool_pair_2)
            .fetch_optional(&pool)
            .await
            {
                let p_pair: String = row.try_get("pool_pair").unwrap_or_default();
                let ra: f64 = row.try_get::<f64, _>("reserve_a").unwrap_or(0.0);
                let rb: f64 = row.try_get::<f64, _>("reserve_b").unwrap_or(0.0);
                let (res_kas, res_tok) = if p_pair == pool_pair_1 { (ra, rb) } else { (rb, ra) };
                if res_kas > 0.0 && res_tok > 0.0 {
                    third_party_token_usd = (res_kas * kas_spot) / res_tok;
                }
            }
        }
        if third_party_token_usd <= 0.0 {
            return Err(Json(SorError {
                error: format!(
                    "3RD_PARTY_PASSTHROUGH_UNAVAILABLE: No external 3rd-party quote found for unverified token {}.",
                    receive_asset_clean
                )
            }));
        }
        let upfront_fee_kas = payload.amount * LONG_TAIL_PASSTHROUGH_FEE_RATE;
        let net_passthrough_kas = (payload.amount - upfront_fee_kas).max(0.0);
        let passthrough_spot_rate = kas_spot / third_party_token_usd;
        let execution_rate = passthrough_spot_rate * (1.0 - LONG_TAIL_PASSTHROUGH_FEE_RATE);
        let estimated_output = payload.amount * execution_rate;
        let fee_captured_usd = upfront_fee_kas * kas_spot;
        let debit_res: (i32, String) = redis::cmd("EVAL")
            .arg(LUA_ATOMIC_DEBIT_SINGLE)
            .arg(1)
            .arg(&ledger_key)
            .arg("KAS")
            .arg(payload.amount)
            .query_async(&mut redis_conn)
            .await
            .unwrap_or((0, "0".to_string()));
        if debit_res.0 == 1 {
            if let Ok(from_unassigned) = debit_res.1.parse::<f64>() {
                sync_unassigned_kas_debit(&pool, &clean_wallet, from_unassigned).await;
            }
            let _: () = redis::cmd("INCRBYFLOAT")
                .arg("perennia:fees:batch_accumulated:KAS")
                .arg(upfront_fee_kas)
                .query_async(&mut redis_conn)
                .await
                .unwrap_or(());
            let passthrough_record = json!({
                "wallet": prefixed_wallet,
                "destination_l1_address": prefixed_wallet,
                "target_asset": receive_asset_clean,
                "gross_kas": payload.amount,
                "upfront_fee_kas": upfront_fee_kas,
                "net_passthrough_kas": net_passthrough_kas,
                "estimated_output": estimated_output,
                "execution_rate": execution_rate,
                "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
            });
            let _: () = redis::cmd("RPUSH")
                .arg("perennia:sor:third_party_passthrough_queue")
                .arg(passthrough_record.to_string())
                .query_async(&mut redis_conn)
                .await
                .unwrap_or(());
            record_dex_swap_tax_event(
                &pool,
                &clean_wallet,
                &receive_asset_clean,
                payload.amount,
                estimated_output,
                kas_spot,
                third_party_token_usd,
                passthrough_spot_rate,
            )
            .await;
            return Ok(Json(SorExecutionPlan {
                totalAmount: payload.amount,
                unifiedRate: execution_rate,
                estimatedOutput: estimated_output,
                legs: vec![WaterfallLeg {
                    tier: 1,
                    provider: format!("3rd-Party L1 Pass-Through (1.50% KAS Fee Shaved -> {})", prefixed_wallet),
                    filledAmount: payload.amount,
                    executionRate: execution_rate,
                    marginCaptured: fee_captured_usd,
                }],
                transaction_uuid: tx_uuid,
                psbt: None,
                formattedUtxos: payload.utxos.clone(),
            }));
        }
        let utxos = payload.utxos.as_ref().ok_or_else(|| Json(SorError {
            error: "Insufficient synthetic KAS balance and no on-chain UTXOs provided.".to_string()
        }))?;
        if utxos.is_empty() {
            return Err(Json(SorError {
                error: "Insufficient synthetic KAS balance and 0 on-chain UTXOs available.".to_string()
            }));
        }
        let target_amount_sompi = (payload.amount * 1e8).floor() as u64;
        let fee_shave_sompi = (upfront_fee_kas * 1e8).floor() as u64;
        let passthrough_sompi = target_amount_sompi.saturating_sub(fee_shave_sompi);
        let mut gathered_sompi = 0u64;
        let mut tx_inputs = Vec::new();
        let mut input_amounts = Vec::new();
        let mut current_mass = calculate_transaction_mass(0, 3, 0);
        for utxo in utxos {
            let amt = utxo.amount.round() as u64;
            tx_inputs.push(json!({
                "previousOutpoint": {
                    "transactionId": utxo.transactionId,
                    "index": utxo.index
                },
                "signatureScript": "",
                "sequence": 0,
                "sigOpCount": 1
            }));
            gathered_sompi += amt;
            input_amounts.push(amt);
            current_mass += 1200;
            let provisional_change = gathered_sompi.saturating_sub(target_amount_sompi + current_mass * fee_per_gram);
            let provisional_outputs = if provisional_change >= MIN_CHANGE_SOMPI {
                vec![fee_shave_sompi.max(1), passthrough_sompi.max(1), provisional_change]
            } else {
                vec![fee_shave_sompi.max(1), passthrough_sompi.max(1)]
            };
            let storage_mass = calculate_storage_mass(&input_amounts, &provisional_outputs);
            let effective_mass = current_mass.max(storage_mass);
            let network_fee_sompi = effective_mass * fee_per_gram;
            if gathered_sompi >= target_amount_sompi + network_fee_sompi {
                break;
            }
        }
        let provisional_change = gathered_sompi.saturating_sub(target_amount_sompi + current_mass * fee_per_gram);
        let provisional_outputs = if provisional_change >= MIN_CHANGE_SOMPI {
            vec![fee_shave_sompi.max(1), passthrough_sompi.max(1), provisional_change]
        } else {
            vec![fee_shave_sompi.max(1), passthrough_sompi.max(1)]
        };
        let storage_mass = calculate_storage_mass(&input_amounts, &provisional_outputs);
        let effective_mass = current_mass.max(storage_mass);
        let network_fee_sompi = effective_mass * fee_per_gram;
        let total_required = target_amount_sompi + network_fee_sompi;
        if gathered_sompi < total_required {
            return Err(Json(SorError {
                error: format!("ERR_INSUFFICIENT_MASS: Required {} sompi, Found {} sompi", total_required, gathered_sompi)
            }));
        }
        let dest_script = decode_address_to_script(&corp_kas)
            .map_err(|e| Json(SorError { error: format!("Invalid treasury destination address: {}", e) }))?;
        let mut tx_outputs = vec![json!({
            "amount": target_amount_sompi,
            "scriptPublicKey": dest_script,
            "_metadata": { "provider": "3rd-Party L1 Pass-Through (1.50% KAS Fee Upfront)", "tier": 1 }
        })];
        let change_sompi = gathered_sompi - total_required;
        if change_sompi >= MIN_CHANGE_SOMPI {
            let change_script = decode_address_to_script(&payload.wallet)
                .map_err(|e| Json(SorError { error: format!("Invalid change address: {}", e) }))?;
            tx_outputs.push(json!({
                "amount": change_sompi,
                "scriptPublicKey": change_script,
                "_metadata": { "type": "change" }
            }));
        }
        let psbt = json!({
            "version": 0,
            "inputs": tx_inputs,
            "outputs": tx_outputs,
            "lockTime": 0,
            "subnetworkId": "0000000000000000000000000000000000000000",
            "gas": 0,
            "payload": "",
            "mass": 0,
            "storageMass": 0
        });
        let passthrough_order = json!({
            "wallet": prefixed_wallet,
            "direction": "THIRD_PARTY_PASSTHROUGH",
            "amount_kas": payload.amount,
            "upfront_fee_kas": upfront_fee_kas,
            "net_passthrough_kas": net_passthrough_kas,
            "spot_price": passthrough_spot_rate,
            "fee_captured_usd": fee_captured_usd,
            "target_asset": receive_asset_clean,
            "estimated_output": estimated_output,
            "destination_l1_address": prefixed_wallet
        });
        let _: () = redis::cmd("SETEX")
            .arg(format!("perennia:pending_swap:{}", clean_wallet))
            .arg(600)
            .arg(passthrough_order.to_string())
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(());
        return Ok(Json(SorExecutionPlan {
            totalAmount: payload.amount,
            unifiedRate: execution_rate,
            estimatedOutput: estimated_output,
            legs: vec![WaterfallLeg {
                tier: 1,
                provider: format!("3rd-Party L1 Pass-Through (1.50% KAS Fee Shaved -> {})", prefixed_wallet),
                filledAmount: payload.amount,
                executionRate: execution_rate,
                marginCaptured: fee_captured_usd,
            }],
            transaction_uuid: tx_uuid,
            psbt: Some(psbt),
            formattedUtxos: payload.utxos.clone(),
        }));
    }

    let spot_rate = pay_usd / rec_usd;
    let (dynamic_fee_rate, route_provider_label) = compute_inventory_skew_and_guard(
        &pool,
        &mut redis_conn,
        &clean_wallet,
        &prefixed_wallet,
        &pay_asset_clean,
        &receive_asset_clean,
        payload.amount,
        pay_usd,
        rec_usd,
        spot_rate,
    )
    .await
    .map_err(|e| Json(SorError { error: e }))?;

    let protocol_fee_rate = dynamic_fee_rate;
    let execution_rate = spot_rate * (1.0 - protocol_fee_rate);
    let estimated_output = payload.amount * execution_rate;
    let trade_usd_value = payload.amount * pay_usd;
    let output_usd_value = estimated_output * rec_usd;

    if receive_asset_clean != "KAS" && output_usd_value < min_dark_pool_usd {
        let existing_bal_str: Option<String> = redis::cmd("HGET")
            .arg(&ledger_key)
            .arg(&receive_asset_clean)
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(None);
        let existing_bal = existing_bal_str
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);
        let resulting_usd = (existing_bal + estimated_output) * rec_usd;
        if resulting_usd < min_dark_pool_usd {
            return Err(Json(SorError {
                error: format!(
                    "ANTI_DUST_GUARD: Pool position for {} (${:.2} USD) is below the minimum position floor (${:.2} USD). Increase swap size above ${:.2} USD.",
                    receive_asset_clean, output_usd_value, min_dark_pool_usd, min_dark_pool_usd
                )
            }));
        }
    }

    let fee_captured_usd = trade_usd_value * protocol_fee_rate;
    let kas_spot = if pay_asset_clean == "KAS" {
        pay_usd
    } else if receive_asset_clean == "KAS" {
        rec_usd
    } else {
        get_usd_price(&pool, &mut redis_conn, "KAS").await
    };

    let mut netting_order = build_netting_order_json(
        &payload.wallet,
        &pay_asset_clean,
        &receive_asset_clean,
        payload.amount,
        estimated_output,
        spot_rate,
        fee_captured_usd,
    );
    if fee_captured_usd > 0.0 && fee_captured_usd < min_dark_pool_usd && kas_spot > 0.0 {
        let dust_fee_kas = fee_captured_usd / kas_spot;
        netting_order["fee_captured_usd"] = json!(0.0);
        netting_order["dust_fee_kas"] = json!(dust_fee_kas);
    }

    let debit_res: (i32, String) = redis::cmd("EVAL")
        .arg(LUA_ATOMIC_DEBIT_SINGLE)
        .arg(1)
        .arg(&ledger_key)
        .arg(&pay_asset_clean)
        .arg(payload.amount)
        .query_async(&mut redis_conn)
        .await
        .unwrap_or((0, "0".to_string()));

    if debit_res.0 == 1 {
        if let Ok(from_unassigned) = debit_res.1.parse::<f64>() {
            sync_unassigned_kas_debit(&pool, &clean_wallet, from_unassigned).await;
        }
        if let Some(dust_kas) = netting_order.get("dust_fee_kas").and_then(|v| v.as_f64()) {
            if dust_kas > 0.0 {
                let _: () = redis::cmd("INCRBYFLOAT")
                    .arg("perennia:fees:batch_accumulated:KAS")
                    .arg(dust_kas)
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(());
            }
        }
        let _: () = redis::cmd("RPUSH")
            .arg("perennia:sor:netting_queue")
            .arg(netting_order.to_string())
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(());
        record_dex_swap_tax_event(
            &pool,
            &clean_wallet,
            &receive_asset_clean,
            payload.amount,
            estimated_output,
            pay_usd,
            rec_usd,
            spot_rate,
        )
        .await;
        return Ok(Json(SorExecutionPlan {
            totalAmount: payload.amount,
            unifiedRate: execution_rate,
            estimatedOutput: estimated_output,
            legs: vec![WaterfallLeg {
                tier: 0,
                provider: route_provider_label,
                filledAmount: payload.amount,
                executionRate: execution_rate,
                marginCaptured: fee_captured_usd,
            }],
            transaction_uuid: tx_uuid,
            psbt: None,
            formattedUtxos: payload.utxos.clone(),
        }));
    }

    if pay_asset_clean != "KAS" {
        return Err(Json(SorError {
            error: format!("Insufficient synthetic {} balance in Treasury Ledger.", pay_asset_clean)
        }));
    }

    let utxos = payload.utxos.as_ref().ok_or_else(|| Json(SorError {
        error: "Insufficient synthetic KAS balance and no on-chain UTXOs provided.".to_string()
    }))?;
    if utxos.is_empty() {
        return Err(Json(SorError {
            error: "Insufficient synthetic KAS balance and 0 on-chain UTXOs available.".to_string()
        }));
    }

    let target_amount_sompi = (payload.amount * 1e8).floor() as u64;
    let mut gathered_sompi = 0u64;
    let mut tx_inputs = Vec::new();
    let mut input_amounts = Vec::new();
    let mut current_mass = calculate_transaction_mass(0, 2, 0);
    for utxo in utxos {
        let amt = utxo.amount.round() as u64;
        tx_inputs.push(json!({
            "previousOutpoint": {
                "transactionId": utxo.transactionId,
                "index": utxo.index
            },
            "signatureScript": "",
            "sequence": 0,
            "sigOpCount": 1
        }));
        gathered_sompi += amt;
        input_amounts.push(amt);
        current_mass += 1200;
        let provisional_change = gathered_sompi.saturating_sub(target_amount_sompi + current_mass * fee_per_gram);
        let provisional_outputs = if provisional_change >= MIN_CHANGE_SOMPI {
            vec![target_amount_sompi, provisional_change]
        } else {
            vec![target_amount_sompi]
        };
        let storage_mass = calculate_storage_mass(&input_amounts, &provisional_outputs);
        let effective_mass = current_mass.max(storage_mass);
        let network_fee_sompi = effective_mass * fee_per_gram;
        if gathered_sompi >= target_amount_sompi + network_fee_sompi {
            break;
        }
    }
    let provisional_change = gathered_sompi.saturating_sub(target_amount_sompi + current_mass * fee_per_gram);
    let provisional_outputs = if provisional_change >= MIN_CHANGE_SOMPI {
        vec![target_amount_sompi, provisional_change]
    } else {
        vec![target_amount_sompi]
    };
    let storage_mass = calculate_storage_mass(&input_amounts, &provisional_outputs);
    let effective_mass = current_mass.max(storage_mass);
    let network_fee_sompi = effective_mass * fee_per_gram;
    let total_required = target_amount_sompi + network_fee_sompi;
    if gathered_sompi < total_required {
        return Err(Json(SorError {
            error: format!("ERR_INSUFFICIENT_MASS: Required {} sompi, Found {} sompi", total_required, gathered_sompi)
        }));
    }
    let dest_script = decode_address_to_script(&corp_kas)
        .map_err(|e| Json(SorError { error: format!("Invalid treasury destination address: {}", e) }))?;
    let mut tx_outputs = vec![json!({
        "amount": target_amount_sompi,
        "scriptPublicKey": dest_script,
        "_metadata": { "provider": "Perennia Liquidity Pool (On-Chain Settlement)", "tier": 0 }
    })];
    let change_sompi = gathered_sompi - total_required;
    if change_sompi >= MIN_CHANGE_SOMPI {
        let change_script = decode_address_to_script(&payload.wallet)
            .map_err(|e| Json(SorError { error: format!("Invalid change address: {}", e) }))?;
        tx_outputs.push(json!({
            "amount": change_sompi,
            "scriptPublicKey": change_script,
            "_metadata": { "type": "change" }
        }));
    }
    let psbt = json!({
        "version": 0,
        "inputs": tx_inputs,
        "outputs": tx_outputs,
        "lockTime": 0,
        "subnetworkId": "0000000000000000000000000000000000000000",
        "gas": 0,
        "payload": "",
        "mass": 0,
        "storageMass": 0
    });
    let _: () = redis::cmd("SETEX")
        .arg(format!("perennia:pending_swap:{}", clean_wallet))
        .arg(600)
        .arg(netting_order.to_string())
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(());
    Ok(Json(SorExecutionPlan {
        totalAmount: payload.amount,
        unifiedRate: execution_rate,
        estimatedOutput: estimated_output,
        legs: vec![WaterfallLeg {
            tier: 0,
            provider: route_provider_label,
            filledAmount: payload.amount,
            executionRate: execution_rate,
            marginCaptured: fee_captured_usd,
        }],
        transaction_uuid: tx_uuid,
        psbt: Some(psbt),
        formattedUtxos: payload.utxos.clone(),
    }))
}

pub async fn execute_autonomous_hedge(amount_kas: f64, side: &str) -> Result<String, String> {
    let api_key = env::var("MEXC_API_KEY")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "CRITICAL: MEXC_API_KEY not configured in environment.".to_string())?;
    let secret_key = env::var("MEXC_SECRET_KEY")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "CRITICAL: MEXC_SECRET_KEY not configured in environment.".to_string())?;
    let order_side = if side.eq_ignore_ascii_case("BUY") { "BUY" } else { "SELL" };
    let client = get_secure_client();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Time went backwards".to_string())?
        .as_millis()
        .to_string();
    let formatted_amount = format!("{:.2}", amount_kas.abs());
    let query_string = format!(
        "quantity={}&recvWindow=5000&side={}&symbol=KASUSDT&timestamp={}&type=MARKET",
        formatted_amount, order_side, timestamp
    );
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes())
        .map_err(|_| "Invalid HMAC secret key length".to_string())?;
    mac.update(query_string.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    let final_url = format!("https://api.mexc.com/api/v3/order?{}&signature={}", query_string, signature);
    let response = client.post(&final_url)
        .header("X-MEXC-APIKEY", api_key)
        .header("Content-Type", "application/json")
        .send()
        .await
        .map_err(|e| format!("Exchange API dispatch failed: {}", e))?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if status.is_success() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(order_id) = json.get("orderId").and_then(|id| id.as_str()) {
                tracing::info!("✅ [HEDGE EXECUTED] MEXC Market {} confirmed. Order ID: {}", order_side, order_id);
                return Ok(order_id.to_string());
            }
        }
        Ok(format!("MEXC_{}_EXECUTION_TRIGGERED", order_side))
    } else {
        Err(format!("Exchange Rejected Hedge Order: {}", text))
    }
}

pub async fn execute_utxo_consolidation_chunk(chunk: &[UtxoInput]) -> Result<String, String> {
    if chunk.len() < 2 {
        return Ok("SKIPPED_SINGLE_UTXO".to_string());
    }
    let client = get_secure_client();
    let fee_per_gram = get_fee_per_gram();
    let corp_kas = resolve_treasury_kas_address()?;
    let private_key_hex = env::var("PERENNIA_TREASURY_PRIVATE_KEY")
        .map(|s| s.trim().to_string())
        .map_err(|_| "CRITICAL: PERENNIA_TREASURY_PRIVATE_KEY not configured.".to_string())?;
    let rest_url = std::env::var("KASPA_REST_URL")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "https://api.kaspa.org".to_string());
    let mut gathered_sompi: u64 = 0;
    let mut core_inputs = Vec::new();
    let mut utxo_entries = Vec::new();
    for utxo in chunk {
        let amt = utxo.amount.round() as u64;
        gathered_sompi += amt;
        let prev_id = TransactionId::from_str(&utxo.transactionId).unwrap_or_default();
        core_inputs.push(TransactionInput::new(
            TransactionOutpoint::new(prev_id, utxo.index),
            vec![],
            0,
            1,
        ));
        let spk_bytes = hex::decode(&utxo.scriptPublicKey).unwrap_or_default();
        utxo_entries.push(UtxoEntry::new(amt, ScriptPublicKey::from_vec(0, spk_bytes), 0, false, None));
    }
    let fee_sompi = calculate_transaction_mass(core_inputs.len(), 1, 0) * fee_per_gram;
    if gathered_sompi <= fee_sompi {
        return Err("Chunk UTXO sum insufficient to cover consolidation fee.".to_string());
    }
    let target_amount_sompi = gathered_sompi - fee_sompi;
    let corp_script = decode_address_to_script(&corp_kas)?;
    let core_outputs = vec![TransactionOutput {
        value: target_amount_sompi,
        script_public_key: ScriptPublicKey::from_vec(0, hex::decode(&corp_script).unwrap_or_default()),
        covenant: None,
    }];
    let mut transaction = Transaction::new(0, core_inputs, core_outputs, 0, SubnetworkId::default(), 0, vec![]);
    let secp = Secp256k1::new();
    let private_key_clean = private_key_hex.trim_start_matches("0x");
    let keypair = Keypair::from_seckey_slice(&secp, &hex::decode(private_key_clean).unwrap_or_default())
        .map_err(|e| e.to_string())?;
    let mut generated_signatures = Vec::new();
    {
        let populated_tx = PopulatedTransaction::new(&transaction, utxo_entries);
        let mut reused_values = SigHashReusedValuesUnsync::new();
        for i in 0..transaction.inputs.len() {
            let sighash = calc_schnorr_signature_hash(&populated_tx, i, SIG_HASH_ALL, &mut reused_values);
            let message = Message::from_digest_slice(&sighash.as_bytes()).unwrap();
            let sig = secp.sign_schnorr(&message, &keypair);
            let mut sig_script = vec![0x41];
            sig_script.extend_from_slice(sig.as_ref());
            sig_script.push(1);
            generated_signatures.push(sig_script);
        }
    }
    for (i, sig_script) in generated_signatures.into_iter().enumerate() {
        transaction.inputs[i].signature_script = sig_script;
    }
    let broadcast_payload = json!({
        "transaction": {
            "version": transaction.version,
            "inputs": transaction.inputs.iter().map(|i| json!({
                "previousOutpoint": {
                    "transactionId": i.previous_outpoint.transaction_id.to_string(),
                    "index": i.previous_outpoint.index
                },
                "signatureScript": hex::encode(&i.signature_script),
                "sequence": i.sequence,
                "sigOpCount": 1
            })).collect::<Vec<_>>(),
            "outputs": transaction.outputs.iter().map(|o| json!({
                "amount": o.value,
                "scriptPublicKey": {
                    "version": o.script_public_key.version(),
                    "scriptPublicKey": hex::encode(o.script_public_key.script())
                }
            })).collect::<Vec<_>>(),
            "lockTime": transaction.lock_time,
            "subnetworkId": transaction.subnetwork_id.to_string(),
            "gas": transaction.gas,
            "payload": hex::encode(&transaction.payload)
        }
    });
    let broadcast_res = client.post(format!("{}/transactions", rest_url))
        .json(&broadcast_payload)
        .send()
        .await
        .map_err(|e| format!("Consolidation Broadcast Failed: {}", e))?;
    if broadcast_res.status().is_success() {
        if let Ok(resp_json) = broadcast_res.json::<Value>().await {
            if let Some(tx_id) = resp_json.get("transactionId").and_then(|v| v.as_str()) {
                return Ok(tx_id.to_string());
            }
        }
        Err("Consolidation broadcast returned no transactionId.".to_string())
    } else {
        let err_text = broadcast_res.text().await.unwrap_or_default();
        Err(format!("Consolidation rejected by node: {}", err_text))
    }
}

pub async fn execute_physical_settlement(destination: &str, amount_kas: f64) -> Result<String, String> {
    let payouts = vec![(destination.to_string(), amount_kas)];
    execute_mass_physical_settlement(&payouts).await
}

pub async fn execute_mass_physical_settlement(payouts: &[(String, f64)]) -> Result<String, String> {
    let client = get_secure_client();
    let fee_per_gram = get_fee_per_gram();
    let corp_kas = resolve_treasury_kas_address()?;
    let corp_kas_clean = normalize_kaspa_base32(&corp_kas);
    let external_payouts: Vec<(String, f64)> = payouts
        .iter()
        .filter(|(dest, amt)| {
            let dest_clean = normalize_kaspa_base32(dest);
            if dest_clean == corp_kas_clean {
                tracing::info!(
                    "🏦 [HOUSE ANCHOR GUARD] Suppressed redundant L1 self-transfer of {:.4} KAS to Master Treasury {}.",
                    amt,
                    corp_kas
                );
                false
            } else {
                *amt > 0.0
            }
        })
        .cloned()
        .collect();
    if external_payouts.is_empty() {
        return Ok("TREASURY_HOUSE_ANCHOR_NO_OP".to_string());
    }
    let private_key_hex = env::var("PERENNIA_TREASURY_PRIVATE_KEY")
        .map(|s| s.trim().to_string())
        .map_err(|_| "CRITICAL: PERENNIA_TREASURY_PRIVATE_KEY not configured in environment.".to_string())?;
    let rest_url = std::env::var("KASPA_REST_URL")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "https://api.kaspa.org".to_string());
    let utxos_url = format!("{}/addresses/{}/utxos", rest_url, corp_kas);
    let utxo_res = client.get(&utxos_url).send().await.map_err(|e| format!("UTXO Network Fetch Error: {}", e))?;
    if !utxo_res.status().is_success() {
        let err_text = utxo_res.text().await.unwrap_or_default();
        return Err(format!("L1 Node Rejected UTXO Query: {}", err_text));
    }
    let text_payload = utxo_res.text().await.unwrap_or_default();
    let raw_utxos: Vec<Value> = serde_json::from_str(&text_payload)
        .map_err(|e| format!("UTXO Parsing Error: {}. Payload: {}", e, text_payload))?;
    let mut total_target_sompi: u64 = 0;
    let mut tx_outputs = Vec::new();
    let mut core_outputs = Vec::new();
    let mut payout_output_amounts = Vec::new();
    for (destination, amount_kas) in &external_payouts {
        let target_amount_sompi = (amount_kas * 1e8).floor() as u64;
        if target_amount_sompi == 0 { continue; }
        total_target_sompi += target_amount_sompi;
        payout_output_amounts.push(target_amount_sompi);
        let dest_script = decode_address_to_script(destination.trim())
            .map_err(|e| format!("Destination script error for {}: {}", destination, e))?;
        tx_outputs.push(json!({
            "amount": target_amount_sompi,
            "scriptPublicKey": dest_script
        }));
        core_outputs.push(TransactionOutput {
            value: target_amount_sompi,
            script_public_key: ScriptPublicKey::from_vec(0, hex::decode(&dest_script).unwrap_or_default()),
            covenant: None,
        });
    }
    if total_target_sompi == 0 {
        return Ok("NO_PAYOUTS_REQUIRED".to_string());
    }
    let mut parsed_utxos = Vec::new();
    for u in raw_utxos {
        if let (Some(tx_id), Some(index), Some(amount), Some(script)) = (
            u.pointer("/outpoint/transactionId").and_then(|v| v.as_str()),
            parse_json_u64(u.pointer("/outpoint/index")),
            parse_json_u64(u.pointer("/utxoEntry/amount")),
            u.pointer("/utxoEntry/scriptPublicKey/scriptPublicKey").and_then(|v| v.as_str())
        ) {
            parsed_utxos.push((
                amount,
                UtxoInput {
                    transactionId: tx_id.to_string(),
                    index: index as u32,
                    amount: amount as f64,
                    scriptPublicKey: script.to_string(),
                }
            ));
        }
    }
    parsed_utxos.sort_by(|a, b| b.0.cmp(&a.0));
    let mut gathered_sompi = 0u64;
    let mut selected_utxos = Vec::new();
    let mut input_amounts = Vec::new();
    let mut current_mass = calculate_transaction_mass(0, core_outputs.len() + 1, 0);
    for (amount, utxo_input) in parsed_utxos {
        selected_utxos.push(utxo_input);
        input_amounts.push(amount);
        gathered_sompi += amount;
        current_mass += 1200;
        let mut provisional_outputs = payout_output_amounts.clone();
        let provisional_change = gathered_sompi.saturating_sub(total_target_sompi + current_mass * fee_per_gram);
        if provisional_change >= MIN_CHANGE_SOMPI {
            provisional_outputs.push(provisional_change);
        }
        let storage_mass = calculate_storage_mass(&input_amounts, &provisional_outputs);
        let effective_mass = current_mass.max(storage_mass);
        let network_fee_sompi = effective_mass * fee_per_gram;
        if gathered_sompi >= total_target_sompi + network_fee_sompi {
            break;
        }
    }
    let mut provisional_outputs = payout_output_amounts.clone();
    let provisional_change = gathered_sompi.saturating_sub(total_target_sompi + current_mass * fee_per_gram);
    if provisional_change >= MIN_CHANGE_SOMPI {
        provisional_outputs.push(provisional_change);
    }
    let storage_mass = calculate_storage_mass(&input_amounts, &provisional_outputs);
    let effective_mass = current_mass.max(storage_mass);
    let network_fee_sompi = effective_mass * fee_per_gram;
    let total_required = total_target_sompi + network_fee_sompi;
    if gathered_sompi < total_required {
        return Err(format!("Insufficient Master Treasury Mass. Required {} sompi, Found {} sompi", total_required, gathered_sompi));
    }
    let mut tx_inputs = Vec::new();
    let mut core_inputs = Vec::new();
    let mut utxo_entries = Vec::new();
    for utxo in &selected_utxos {
        let prev_id = TransactionId::from_str(&utxo.transactionId).unwrap_or_default();
        tx_inputs.push(json!({
            "previousOutpoint": { "transactionId": utxo.transactionId, "index": utxo.index },
            "signatureScript": "", "sequence": 0, "sigOpCount": 1
        }));
        core_inputs.push(TransactionInput::new(
            TransactionOutpoint::new(prev_id, utxo.index),
            vec![],
            0,
            1,
        ));
        let spk_bytes = hex::decode(&utxo.scriptPublicKey).unwrap_or_default();
        utxo_entries.push(UtxoEntry::new(utxo.amount.round() as u64, ScriptPublicKey::from_vec(0, spk_bytes), 0, false, None));
    }
    let change_sompi = gathered_sompi - total_required;
    if change_sompi >= MIN_CHANGE_SOMPI {
        let corp_script = decode_address_to_script(&corp_kas).map_err(|e| format!("Corp script error: {}", e))?;
        tx_outputs.push(json!({
            "amount": change_sompi,
            "scriptPublicKey": corp_script
        }));
        core_outputs.push(TransactionOutput {
            value: change_sompi,
            script_public_key: ScriptPublicKey::from_vec(0, hex::decode(&corp_script).unwrap_or_default()),
            covenant: None,
        });
    }
    let mut transaction = Transaction::new(0, core_inputs, core_outputs, 0, SubnetworkId::default(), 0, vec![]);
    let secp = Secp256k1::new();
    let private_key_clean = private_key_hex.trim_start_matches("0x");
    let keypair = Keypair::from_seckey_slice(&secp, &hex::decode(private_key_clean).unwrap_or_default()).map_err(|e| e.to_string())?;
    let mut generated_signatures = Vec::new();
    {
        let populated_tx = PopulatedTransaction::new(&transaction, utxo_entries.clone());
        let mut reused_values = SigHashReusedValuesUnsync::new();
        for i in 0..transaction.inputs.len() {
            let sighash = calc_schnorr_signature_hash(&populated_tx, i, SIG_HASH_ALL, &mut reused_values);
            let message = Message::from_digest_slice(&sighash.as_bytes()).unwrap();
            let sig = secp.sign_schnorr(&message, &keypair);
            let mut sig_script = vec![0x41];
            sig_script.extend_from_slice(sig.as_ref());
            sig_script.push(1);
            generated_signatures.push(sig_script);
        }
    }
    for (i, sig_script) in generated_signatures.into_iter().enumerate() {
        transaction.inputs[i].signature_script = sig_script;
    }
    let broadcast_payload = json!({
        "transaction": {
            "version": transaction.version,
            "inputs": transaction.inputs.iter().map(|i| json!({
                "previousOutpoint": {
                    "transactionId": i.previous_outpoint.transaction_id.to_string(),
                    "index": i.previous_outpoint.index
                },
                "signatureScript": hex::encode(&i.signature_script),
                "sequence": i.sequence,
                "sigOpCount": 1
            })).collect::<Vec<_>>(),
            "outputs": transaction.outputs.iter().map(|o| json!({
                "amount": o.value,
                "scriptPublicKey": {
                    "version": o.script_public_key.version(),
                    "scriptPublicKey": hex::encode(o.script_public_key.script())
                }
            })).collect::<Vec<_>>(),
            "lockTime": transaction.lock_time,
            "subnetworkId": transaction.subnetwork_id.to_string(),
            "gas": transaction.gas,
            "payload": hex::encode(&transaction.payload)
        }
    });
    let broadcast_res = client.post(format!("{}/transactions", rest_url))
        .json(&broadcast_payload)
        .send()
        .await
        .map_err(|e| format!("Broadcast Dispatch Failed: {}", e))?;
    if broadcast_res.status().is_success() {
        if let Ok(resp_json) = broadcast_res.json::<Value>().await {
            if let Some(tx_id) = resp_json.get("transactionId").and_then(|v| v.as_str()) {
                return Ok(tx_id.to_string());
            }
        }
        Err("Broadcast verification rejected the PSBT payload. No Transaction ID returned.".to_string())
    } else {
        let err_text = broadcast_res.text().await.unwrap_or_default();
        Err(format!("Broadcast verification rejected the PSBT payload: {}", err_text))
    }
}