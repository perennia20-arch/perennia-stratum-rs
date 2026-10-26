use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Row, Transaction as SqlTransaction};
use std::collections::HashMap;
use std::env;
use std::str::FromStr;
use reqwest::Client;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const KASPA_BURN_ADDRESS: &str =
    "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e";

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

const LUA_ATOMIC_DEBIT_MULTI_LP: &str = r#"
local count = tonumber(ARGV[1] or '0')
if count <= 0 then
    return {0, tostring(0), 'EMPTY_BASKET'}
end
for i = 1, count do
    local asset = ARGV[1 + (i - 1) * 2 + 1]
    local req = tonumber(ARGV[1 + (i - 1) * 2 + 2] or '0')
    local primary = tonumber(redis.call('HGET', KEYS[1], asset) or '0')
    local unassigned = 0
    if asset == 'KAS' then
        unassigned = tonumber(redis.call('HGET', KEYS[1], 'Unassigned KAS') or '0')
    end
    if (primary + unassigned + 1e-9) < req then
        return {0, tostring(0), asset}
    end
end
local from_unassigned = 0
for i = 1, count do
    local asset = ARGV[1 + (i - 1) * 2 + 1]
    local req = tonumber(ARGV[1 + (i - 1) * 2 + 2] or '0')
    local primary = tonumber(redis.call('HGET', KEYS[1], asset) or '0')
    if asset == 'KAS' then
        if primary >= req then
            redis.call('HINCRBYFLOAT', KEYS[1], 'KAS', -req)
        else
            local diff = math.max(0, req - primary)
            from_unassigned = from_unassigned + diff
            if primary > 0 then
                redis.call('HSET', KEYS[1], 'KAS', '0')
            end
            redis.call('HINCRBYFLOAT', KEYS[1], 'Unassigned KAS', -diff)
        end
    else
        if math.abs(primary - req) <= 1e-9 then
            redis.call('HSET', KEYS[1], asset, '0')
        else
            redis.call('HINCRBYFLOAT', KEYS[1], asset, -req)
        end
    end
end
return {1, tostring(from_unassigned), 'OK'}
"#;

#[derive(Deserialize, Debug)]
pub struct StateActionReq {
    pub wallet: String,
    pub action: String,
    pub payload: Value,
}

#[derive(Serialize)]
pub struct ActionResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_psbt_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

async fn ensure_silo_and_forge_schema(pool: &PgPool) {
    let ddl = [
        r#"
        CREATE TABLE IF NOT EXISTS silo_staking_positions (
            stake_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            wallet_address VARCHAR(255) NOT NULL,
            token_ticker VARCHAR(32) NOT NULL DEFAULT 'SILO',
            amount_staked DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
            tx_hash VARCHAR(255),
            cooldown_initiated_at TIMESTAMP WITH TIME ZONE,
            cooldown_ends_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "CREATE INDEX IF NOT EXISTS idx_silo_staking_wallet ON silo_staking_positions (wallet_address, status)",
        "ALTER TABLE liquidity_providers ADD COLUMN IF NOT EXISTS weights_json JSONB NOT NULL DEFAULT '{}'::jsonb",
        "ALTER TABLE liquidity_providers ADD COLUMN IF NOT EXISTS reserves_json JSONB NOT NULL DEFAULT '{}'::jsonb",
        r#"
        CREATE TABLE IF NOT EXISTS forge_vesting_schedules (
            vesting_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            token_ticker VARCHAR(32) NOT NULL,
            beneficiary_address VARCHAR(255) NOT NULL,
            creator_address VARCHAR(255) NOT NULL,
            label VARCHAR(128) NOT NULL DEFAULT 'Genesis Tranche',
            total_allocated DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            unlocked_amount DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            claimed_amount DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            cliff_days INTEGER NOT NULL DEFAULT 0,
            linear_days INTEGER NOT NULL DEFAULT 365,
            cliff_unlock_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            full_unlock_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            daily_unlock_rate DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            covenant_rule VARCHAR(64) NOT NULL DEFAULT 'TIMELOCK_ESCROW_COVENANT',
            vprog_state_root VARCHAR(128) NOT NULL DEFAULT '',
            lock_tx_hash VARCHAR(255),
            status VARCHAR(32) NOT NULL DEFAULT 'LOCKED',
            last_bell_unlocked_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "CREATE INDEX IF NOT EXISTS idx_forge_vesting_ticker ON forge_vesting_schedules (token_ticker, status)",
        r#"
        CREATE TABLE IF NOT EXISTS forge_monetary_policies (
            policy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            token_ticker VARCHAR(32) UNIQUE NOT NULL,
            creator_address VARCHAR(255) NOT NULL,
            max_supply DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            burn_rate_bps INTEGER NOT NULL DEFAULT 0,
            burn_address VARCHAR(255) NOT NULL DEFAULT 'kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e',
            total_burned_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            emission_schedule_type VARCHAR(48) NOT NULL DEFAULT 'CHROMATIC_HALVING',
            daily_emission_rate DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            halving_interval_days INTEGER NOT NULL DEFAULT 365,
            reserve_locked_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            reserve_emitted_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            zero_rug_lp_pct DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            zero_rug_lock_days INTEGER NOT NULL DEFAULT 365,
            is_retroactive_upgrade BOOLEAN NOT NULL DEFAULT FALSE,
            charter_sha256 VARCHAR(128) NOT NULL DEFAULT '',
            anchor_tx_hash VARCHAR(255),
            last_bell_processed_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS forge_mineable_vaults (
            vault_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            token_ticker VARCHAR(32) UNIQUE NOT NULL,
            creator_address VARCHAR(255) NOT NULL,
            vault_label VARCHAR(128) NOT NULL DEFAULT 'Proof-of-Hashrate Mining Vault',
            total_funded_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            remaining_vault_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            daily_emission_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            distributed_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            min_hashrate_ths DOUBLE PRECISION NOT NULL DEFAULT 0.1,
            syndicate_sector_enabled BOOLEAN NOT NULL DEFAULT TRUE,
            active_miners_count INTEGER NOT NULL DEFAULT 0,
            status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
            funding_tx_hash VARCHAR(255),
            last_bell_distributed_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    ];
    for stmt in ddl {
        let _ = sqlx::query(stmt).execute(pool).await;
    }
}

fn contains_forbidden_private_key_material(payload: &Value) -> bool {
    match payload {
        Value::Object(map) => {
            for (k, v) in map {
                let key_lower = k.to_lowercase();
                if key_lower == "privatekeyhex"
                    || key_lower == "buyerprivatekeyhex"
                    || key_lower == "private_key"
                    || key_lower == "mnemonic"
                    || key_lower == "seedphrase"
                {
                    if let Some(s) = v.as_str() {
                        if !s.trim().is_empty() {
                            return true;
                        }
                    }
                }
                if contains_forbidden_private_key_material(v) {
                    return true;
                }
            }
            false
        }
        Value::Array(arr) => arr.iter().any(contains_forbidden_private_key_material),
        _ => false,
    }
}

fn compute_sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn normalize_sector_plant_or_silo_rules(sector_val: &mut Value) {
    let mut target_tickers: Vec<String> = Vec::new();
    let mut raw_weights_pct: HashMap<String, f64> = HashMap::new();
    let mut is_syndicate_mineable = false;

    if let Some(cfg) = sector_val.get("settlementConfig") {
        if cfg.get("isMineableKrc20").and_then(|v| v.as_bool()) == Some(true)
            || cfg.get("syndicateVault").and_then(|v| v.as_bool()) == Some(true)
        {
            is_syndicate_mineable = true;
        }
        if let Some(arr) = cfg.get("targetAssets").and_then(|v| v.as_array()) {
            for item in arr {
                let tick_opt = item
                    .get("ticker")
                    .and_then(|t| t.as_str())
                    .or_else(|| item.as_str());
                if let Some(t) = tick_opt {
                    let clean = t.trim().to_uppercase();
                    if !clean.is_empty() && !target_tickers.contains(&clean) {
                        target_tickers.push(clean.clone());
                    }
                    if let Some(w) = item
                        .get("weightPct")
                        .or_else(|| item.get("weight"))
                        .and_then(|v| v.as_f64())
                    {
                        if w > 0.0 {
                            raw_weights_pct.insert(clean, w);
                        }
                    }
                }
            }
        }
        if let Some(weights_obj) = cfg.get("plantWeights").and_then(|v| v.as_object()) {
            for (k, v) in weights_obj {
                let clean = k.trim().to_uppercase();
                if let Some(w) = v.as_f64() {
                    if w > 0.0 {
                        raw_weights_pct.insert(clean.clone(), w);
                        if !target_tickers.contains(&clean) {
                            target_tickers.push(clean);
                        }
                    }
                }
            }
        }
        if target_tickers.is_empty() {
            if let Some(primary_tick) = cfg
                .get("targetAsset")
                .and_then(|a| a.get("ticker"))
                .and_then(|t| t.as_str())
            {
                let clean = primary_tick.trim().to_uppercase();
                if !clean.is_empty() {
                    target_tickers.push(clean);
                }
            }
        }
    }

    let explicit_route_mode = sector_val
        .get("routeMode")
        .and_then(|v| v.as_str())
        .unwrap_or("hold")
        .to_lowercase();

    let non_kas_targets: Vec<String> = target_tickers
        .iter()
        .filter(|t| *t != "KAS")
        .cloned()
        .collect();

    let is_multi_asset_plant = (target_tickers.len() >= 2
        || non_kas_targets.len() >= 2
        || explicit_route_mode == "auto-lp")
        && !is_syndicate_mineable;

    if is_multi_asset_plant {
        sector_val["routeMode"] = json!("auto-lp");
        let mut secondary_tickers = non_kas_targets;
        if secondary_tickers.is_empty() {
            secondary_tickers.push("USDC".to_string());
        }
        let mut normalized_weights_pct = serde_json::Map::new();
        normalized_weights_pct.insert("KAS".to_string(), json!(50.0_f64));
        let custom_sum: f64 = secondary_tickers
            .iter()
            .map(|t| raw_weights_pct.get(t).copied().unwrap_or(0.0_f64).max(0.0_f64))
            .sum();
        let n_sec = secondary_tickers.len();
        let mut allocated_sec_pct: f64 = 0.0;
        for (idx, sec_ticker) in secondary_tickers.iter().enumerate() {
            let pct: f64 = if idx + 1 == n_sec {
                ((50.0_f64 - allocated_sec_pct) * 100.0_f64).round() / 100.0_f64
            } else if custom_sum > 0.0_f64 {
                let raw: f64 = raw_weights_pct
                    .get(sec_ticker)
                    .copied()
                    .unwrap_or(0.0_f64)
                    .max(0.0_f64);
                (((raw / custom_sum) * 50.0_f64) * 100.0_f64).round() / 100.0_f64
            } else {
                ((50.0_f64 / (n_sec as f64)) * 100.0_f64).round() / 100.0_f64
            };
            let clamped: f64 = pct.clamp(0.01_f64, 50.0_f64);
            allocated_sec_pct += clamped;
            normalized_weights_pct.insert(sec_ticker.clone(), json!(clamped));
        }
        if let Some(cfg_obj) = sector_val
            .get_mut("settlementConfig")
            .and_then(|v| v.as_object_mut())
        {
            cfg_obj.insert("plantWeights".to_string(), Value::Object(normalized_weights_pct.clone()));
            cfg_obj.insert("mode".to_string(), json!("epoch"));
            let mut full_list = vec!["KAS".to_string()];
            full_list.extend(secondary_tickers.clone());
            cfg_obj.insert("plantPair".to_string(), json!(full_list.join("/")));
        }
    } else {
        let single_ticker = target_tickers
            .first()
            .cloned()
            .unwrap_or_else(|| "KAS".to_string());
        if single_ticker == "KAS" {
            sector_val["routeMode"] = json!("hold");
        } else {
            sector_val["routeMode"] = json!("swap");
        }
    }
}

pub fn build_explorer_tx_url(asset: &str, tx_or_addr: &str) -> String {
    let clean_asset = asset.trim().to_uppercase();
    let clean_ref = tx_or_addr.trim();
    if clean_ref.is_empty() {
        return "#".to_string();
    }
    let is_queued_ref = clean_ref.starts_with("PER-L1-");
    match clean_asset.as_str() {
        "KAS" => {
            if is_queued_ref {
                "https://kas.fyi".to_string()
            } else {
                format!("https://kas.fyi/transaction/{}", clean_ref)
            }
        }
        "BTC" => {
            if is_queued_ref {
                "https://mempool.space".to_string()
            } else {
                format!("https://mempool.space/tx/{}", clean_ref)
            }
        }
        "ETH" | "USDC" | "USDT" | "XAU" | "XAG" | "USTB" => {
            if is_queued_ref {
                "https://etherscan.io".to_string()
            } else {
                format!("https://etherscan.io/tx/{}", clean_ref)
            }
        }
        "SPY" | "QQQ" | "NVDA" | "AAPL" | "TSLA" | "AMD" | "TSM" | "AVGO" | "XLE" | "BASE" => {
            if is_queued_ref {
                "https://basescan.org".to_string()
            } else {
                format!("https://basescan.org/tx/{}", clean_ref)
            }
        }
        "SOL" => {
            if is_queued_ref {
                "https://solscan.io".to_string()
            } else {
                format!("https://solscan.io/tx/{}", clean_ref)
            }
        }
        "POL" => format!("https://polygonscan.com/tx/{}", clean_ref),
        "AVAX" => format!("https://snowtrace.com/tx/{}", clean_ref),
        "ARB" => format!("https://arbiscan.io/tx/{}", clean_ref),
        "XRP" => format!("https://xrpscan.com/tx/{}", clean_ref),
        "DOGE" => format!("https://blockchair.com/dogecoin/transaction/{}", clean_ref),
        "SUI" => format!("https://suiscan.xyz/mainnet/tx/{}", clean_ref),
        "TRX" => format!("https://tronscan.org/#/transaction/{}", clean_ref),
        "ZEC" => format!("https://blockchair.com/zcash/transaction/{}", clean_ref),
        _ => format!("https://kas.fyi/transaction/{}", clean_ref),
    }
}

pub async fn dispatch_or_queue_multi_chain_l1(
    tx_db: &mut SqlTransaction<'_, Postgres>,
    redis_conn: &mut redis::aio::MultiplexedConnection,
    prefixed_wallet: &str,
    clean_wallet: &str,
    destination: &str,
    asset: &str,
    amount: f64,
    spot_price: f64,
    source_type: &str,
) -> (String, String, String) {
    let clean_asset = asset.trim().to_uppercase();
    let resolved_spot: f64 = if spot_price > 0.0 {
        spot_price
    } else if clean_asset == "USDC" || clean_asset == "USDT" || clean_asset == "USD" {
        1.0
    } else {
        get_spot_usd(redis_conn, &clean_asset).await
    };
    let gross_usd: f64 = ((amount * resolved_spot) * 100.0_f64).round() / 100.0_f64;
    let network = match clean_asset.as_str() {
        "USDC" | "USDT" | "XAU" | "XAG" | "USTB" => "ETH".to_string(),
        "SPY" | "QQQ" | "NVDA" | "AAPL" | "TSLA" | "AMD" | "TSM" | "AVGO" | "XLE" => "BASE".to_string(),
        _ => clean_asset.clone(),
    };
    if clean_asset == "KAS" {
        if let Ok(tx_id) = crate::sor::execute_physical_settlement(destination, amount).await {
            let explorer_url = build_explorer_tx_url("KAS", &tx_id);
            let _ = sqlx::query(
                "INSERT INTO pending_transactions (tx_id, wallet_address, amount_kas, action_type, status) VALUES ($1, $2, $3, 'SYNTHETIC_KAS_WITHDRAWAL', 'PENDING') ON CONFLICT DO NOTHING"
            )
            .bind(&tx_id)
            .bind(prefixed_wallet)
            .bind(amount)
            .execute(&mut **tx_db)
            .await;
            let event_type = if source_type == "chronos_epoch_bell" {
                "YIELD"
            } else {
                "L1_WITHDRAWAL"
            };
            let _ = sqlx::query(
                "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash, payout_address) VALUES ($1, 'KAS', $2, $3, $4, $5, $6, $7)"
            )
            .bind(clean_wallet)
            .bind(event_type)
            .bind(gross_usd)
            .bind(amount)
            .bind(resolved_spot)
            .bind(&tx_id)
            .bind(destination)
            .execute(&mut **tx_db)
            .await;
            return (tx_id, "DISPATCHED_ONCHAIN".to_string(), explorer_url);
        }
    }
    let internal_token = env::var("INTERNAL_ADMIN_TOKEN")
        .or_else(|_| env::var("PERENNIA_ADMIN_KEY"))
        .unwrap_or_default();
    let candidate_urls = [
        env::var("FRONTEND_INTERNAL_URL").unwrap_or_default(),
        "http://127.0.0.1:5173".to_string(),
        "http://127.0.0.1:4173".to_string(),
        "http://127.0.0.1:3000".to_string(),
    ];
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(6))
        .build()
        .unwrap_or_else(|_| Client::new());
    for base_url in candidate_urls {
        let trimmed = base_url.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            continue;
        }
        let endpoint = format!("{}/api/sor/l1_dispatch", trimmed);
        if let Ok(res) = client
            .post(&endpoint)
            .header("Authorization", format!("Bearer {}", internal_token))
            .json(&json!({
                "wallet": prefixed_wallet,
                "destinationAddress": destination,
                "asset": clean_asset,
                "amount": amount,
                "sourceType": source_type,
                "spotPrice": resolved_spot
            }))
            .send()
            .await
        {
            if res.status().is_success() {
                if let Ok(data) = res.json::<Value>().await {
                    if data.get("success").and_then(|v| v.as_bool()) == Some(true) {
                        let tx_hash = data
                            .get("txHash")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let status = data
                            .get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("DISPATCHED_ONCHAIN")
                            .to_string();
                        let explorer_url = data
                            .get("explorerUrl")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| build_explorer_tx_url(&clean_asset, &tx_hash));
                        if !tx_hash.is_empty() {
                            return (tx_hash, status, explorer_url);
                        }
                    }
                }
            }
        }
    }
    let uuid_hex = Uuid::new_v4().simple().to_string().to_uppercase();
    let payout_id = format!("PER-L1-{}", &uuid_hex[..10]);
    let explorer_url = build_explorer_tx_url(&clean_asset, destination);
    let queue_reason = format!(
        "Hot wallet key or UTXO mass pending for {}; queued in l1_payout_queue for 1-click L1 confirmation.",
        clean_asset
    );
    let _ = sqlx::query(
        r#"
        INSERT INTO l1_payout_queue
        (payout_id, wallet_address, destination_address, asset_ticker, network, amount_tokens, gross_usd, spot_price, source_type, tx_hash, explorer_url, queue_reason, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $1, $10, $11, 'QUEUED_FOR_L1_DISPATCH')
        ON CONFLICT (payout_id) DO NOTHING
        "#,
    )
    .bind(&payout_id)
    .bind(prefixed_wallet)
    .bind(destination)
    .bind(&clean_asset)
    .bind(&network)
    .bind(amount)
    .bind(gross_usd)
    .bind(resolved_spot)
    .bind(source_type)
    .bind(&explorer_url)
    .bind(&queue_reason)
    .execute(&mut **tx_db)
    .await;
    let event_type = if source_type == "chronos_epoch_bell" {
        "YIELD"
    } else {
        "L1_WITHDRAWAL"
    };
    let _ = sqlx::query(
        "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash, payout_address) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    )
    .bind(clean_wallet)
    .bind(&clean_asset)
    .bind(event_type)
    .bind(gross_usd)
    .bind(amount)
    .bind(resolved_spot)
    .bind(&payout_id)
    .bind(destination)
    .execute(&mut **tx_db)
    .await;
    let queue_record = json!({
        "payoutId": payout_id,
        "walletAddress": prefixed_wallet,
        "destinationAddress": destination,
        "assetTicker": clean_asset,
        "network": network,
        "amountTokens": amount,
        "grossUsd": gross_usd,
        "spotPrice": resolved_spot,
        "sourceType": source_type,
        "txHash": payout_id,
        "explorerUrl": explorer_url,
        "queueReason": queue_reason,
        "status": "QUEUED_FOR_L1_DISPATCH",
        "createdAt": chrono::Utc::now().to_rfc3339()
    });
    let _: () = redis::cmd("LPUSH")
        .arg("perennia:l1:payout_queue")
        .arg(queue_record.to_string())
        .query_async(redis_conn)
        .await
        .unwrap_or(());
    let _: () = redis::cmd("LTRIM")
        .arg("perennia:l1:payout_queue")
        .arg(0)
        .arg(199)
        .query_async(redis_conn)
        .await
        .unwrap_or(());
    let sse_evt = json!({
        "l1_event": true,
        "fiat_event": true,
        "eventType": "L1_QUEUED",
        "wallet": clean_wallet,
        "payout": queue_record
    });
    let _: () = redis::cmd("PUBLISH")
        .arg("telemetry:updates")
        .arg(sse_evt.to_string())
        .query_async(redis_conn)
        .await
        .unwrap_or(());
    (payout_id, "QUEUED_FOR_L1_DISPATCH".to_string(), explorer_url)
}

async fn get_spot_usd(redis_conn: &mut redis::aio::MultiplexedConnection, ticker: &str) -> f64 {
    let clean = ticker.trim().to_uppercase();
    if clean == "USDC" || clean == "USDT" || clean == "USD" {
        return 1.0;
    }
    let key = format!("oracle:spot:{}_USDC", clean);
    let val_str: Option<String> = redis::cmd("GET")
        .arg(&key)
        .query_async(redis_conn)
        .await
        .unwrap_or(None);
    val_str.and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0)
}

pub async fn query_forge_tokenomics_bundle(
    pool: &PgPool,
    ticker_opt: Option<&str>,
    include_all_mineable_vaults: bool,
) -> Value {
    let mut vesting_schedules: Vec<Value> = Vec::new();
    let mut monetary_policy: Option<Value> = None;
    let mut mineable_vault: Option<Value> = None;
    let mut all_mineable_vaults: Vec<Value> = Vec::new();
    let mut locked_vesting_supply: f64 = 0.0;
    let mut unlocked_vested_supply: f64 = 0.0;
    let mut daily_unlock_total: f64 = 0.0;
    let mut burned_supply: f64 = 0.0;
    let mut reserve_locked_supply: f64 = 0.0;

    if let Some(raw_ticker) = ticker_opt {
        let clean_ticker = raw_ticker.trim().to_uppercase();
        if !clean_ticker.is_empty() {
            if let Ok(rows) = sqlx::query(
                r#"
                SELECT vesting_id, token_ticker, beneficiary_address, creator_address, label,
                       total_allocated, unlocked_amount, claimed_amount, cliff_days, linear_days,
                       cliff_unlock_at, full_unlock_at, daily_unlock_rate, covenant_rule,
                       vprog_state_root, lock_tx_hash, status, last_bell_unlocked_at, created_at
                FROM forge_vesting_schedules
                WHERE token_ticker = $1
                ORDER BY created_at ASC
                "#,
            )
            .bind(&clean_ticker)
            .fetch_all(pool)
            .await
            {
                for r in rows {
                    let vid: Uuid = r.get("vesting_id");
                    let beneficiary: String = r.get("beneficiary_address");
                    let creator: String = r.get("creator_address");
                    let label: String = r.get("label");
                    let total_alloc: f64 = r.get("total_allocated");
                    let unlocked: f64 = r.get("unlocked_amount");
                    let claimed: f64 = r.get("claimed_amount");
                    let cliff_days: i32 = r.get("cliff_days");
                    let linear_days: i32 = r.get("linear_days");
                    let cliff_at: chrono::DateTime<chrono::Utc> = r.get("cliff_unlock_at");
                    let full_at: chrono::DateTime<chrono::Utc> = r.get("full_unlock_at");
                    let daily_rate: f64 = r.get("daily_unlock_rate");
                    let cov_rule: String = r.get("covenant_rule");
                    let state_root: String = r.get("vprog_state_root");
                    let lock_tx: Option<String> = r.try_get("lock_tx_hash").ok();
                    let status: String = r.get("status");
                    let last_bell: Option<chrono::DateTime<chrono::Utc>> =
                        r.try_get("last_bell_unlocked_at").ok();
                    let remaining_locked = (total_alloc - unlocked).max(0.0);
                    locked_vesting_supply += remaining_locked;
                    unlocked_vested_supply += unlocked;
                    if remaining_locked > 0.0 {
                        daily_unlock_total += daily_rate;
                    }
                    vesting_schedules.push(json!({
                        "vestingId": vid.to_string(),
                        "tokenTicker": clean_ticker,
                        "beneficiaryAddress": beneficiary,
                        "creatorAddress": creator,
                        "label": label,
                        "totalAllocated": total_alloc,
                        "unlockedAmount": unlocked,
                        "remainingLocked": remaining_locked,
                        "claimedAmount": claimed,
                        "cliffDays": cliff_days,
                        "linearDays": linear_days,
                        "cliffUnlockAt": cliff_at.to_rfc3339(),
                        "fullUnlockAt": full_at.to_rfc3339(),
                        "dailyUnlockRate": daily_rate,
                        "covenantRule": cov_rule,
                        "vprogStateRoot": state_root,
                        "lockTxHash": lock_tx,
                        "status": status,
                        "lastBellUnlockedAt": last_bell.map(|d| d.to_rfc3339())
                    }));
                }
            }

            if let Ok(Some(row)) = sqlx::query(
                r#"
                SELECT policy_id, token_ticker, creator_address, max_supply, burn_rate_bps,
                       burn_address, total_burned_tokens, emission_schedule_type,
                       daily_emission_rate, halving_interval_days, reserve_locked_tokens,
                       reserve_emitted_tokens, zero_rug_lp_pct, zero_rug_lock_days,
                       is_retroactive_upgrade, charter_sha256, anchor_tx_hash,
                       last_bell_processed_at, created_at
                FROM forge_monetary_policies
                WHERE token_ticker = $1
                LIMIT 1
                "#,
            )
            .bind(&clean_ticker)
            .fetch_optional(pool)
            .await
            {
                let pid: Uuid = row.get("policy_id");
                let burned: f64 = row.get("total_burned_tokens");
                let res_locked: f64 = row.get("reserve_locked_tokens");
                let res_emitted: f64 = row.get("reserve_emitted_tokens");
                burned_supply = burned;
                reserve_locked_supply = (res_locked - res_emitted).max(0.0);
                monetary_policy = Some(json!({
                    "policyId": pid.to_string(),
                    "tokenTicker": clean_ticker,
                    "creatorAddress": row.get::<String, _>("creator_address"),
                    "maxSupply": row.get::<f64, _>("max_supply"),
                    "burnRateBps": row.get::<i32, _>("burn_rate_bps"),
                    "burnAddress": row.get::<String, _>("burn_address"),
                    "totalBurnedTokens": burned,
                    "emissionScheduleType": row.get::<String, _>("emission_schedule_type"),
                    "dailyEmissionRate": row.get::<f64, _>("daily_emission_rate"),
                    "halvingIntervalDays": row.get::<i32, _>("halving_interval_days"),
                    "reserveLockedTokens": res_locked,
                    "reserveEmittedTokens": res_emitted,
                    "remainingReserveTokens": reserve_locked_supply,
                    "zeroRugLpPct": row.get::<f64, _>("zero_rug_lp_pct"),
                    "zeroRugLockDays": row.get::<i32, _>("zero_rug_lock_days"),
                    "isRetroactiveUpgrade": row.get::<bool, _>("is_retroactive_upgrade"),
                    "charterSha256": row.get::<String, _>("charter_sha256"),
                    "anchorTxHash": row.try_get::<String, _>("anchor_tx_hash").ok(),
                    "lastBellProcessedAt": row.try_get::<chrono::DateTime<chrono::Utc>, _>("last_bell_processed_at").ok().map(|d| d.to_rfc3339())
                }));
            }

            if let Ok(Some(row)) = sqlx::query(
                r#"
                SELECT vault_id, token_ticker, creator_address, vault_label,
                       total_funded_tokens, remaining_vault_tokens, daily_emission_tokens,
                       distributed_tokens, min_hashrate_ths, syndicate_sector_enabled,
                       active_miners_count, status, funding_tx_hash, last_bell_distributed_at
                FROM forge_mineable_vaults
                WHERE token_ticker = $1
                LIMIT 1
                "#,
            )
            .bind(&clean_ticker)
            .fetch_optional(pool)
            .await
            {
                let vid: Uuid = row.get("vault_id");
                mineable_vault = Some(json!({
                    "vaultId": vid.to_string(),
                    "tokenTicker": clean_ticker,
                    "creatorAddress": row.get::<String, _>("creator_address"),
                    "vaultLabel": row.get::<String, _>("vault_label"),
                    "totalFundedTokens": row.get::<f64, _>("total_funded_tokens"),
                    "remainingVaultTokens": row.get::<f64, _>("remaining_vault_tokens"),
                    "dailyEmissionTokens": row.get::<f64, _>("daily_emission_tokens"),
                    "distributedTokens": row.get::<f64, _>("distributed_tokens"),
                    "minHashrateThs": row.get::<f64, _>("min_hashrate_ths"),
                    "syndicateSectorEnabled": row.get::<bool, _>("syndicate_sector_enabled"),
                    "activeMinersCount": row.get::<i32, _>("active_miners_count"),
                    "status": row.get::<String, _>("status"),
                    "fundingTxHash": row.try_get::<String, _>("funding_tx_hash").ok(),
                    "lastBellDistributedAt": row.try_get::<chrono::DateTime<chrono::Utc>, _>("last_bell_distributed_at").ok().map(|d| d.to_rfc3339())
                }));
            }
        }
    }

    if include_all_mineable_vaults {
        if let Ok(rows) = sqlx::query(
            r#"
            SELECT vault_id, token_ticker, creator_address, vault_label,
                   total_funded_tokens, remaining_vault_tokens, daily_emission_tokens,
                   distributed_tokens, min_hashrate_ths, syndicate_sector_enabled,
                   active_miners_count, status, funding_tx_hash
            FROM forge_mineable_vaults
            WHERE status = 'ACTIVE' AND remaining_vault_tokens > 0
            ORDER BY remaining_vault_tokens DESC
            LIMIT 100
            "#,
        )
        .fetch_all(pool)
        .await
        {
            for r in rows {
                let vid: Uuid = r.get("vault_id");
                all_mineable_vaults.push(json!({
                    "vaultId": vid.to_string(),
                    "tokenTicker": r.get::<String, _>("token_ticker"),
                    "creatorAddress": r.get::<String, _>("creator_address"),
                    "vaultLabel": r.get::<String, _>("vault_label"),
                    "totalFundedTokens": r.get::<f64, _>("total_funded_tokens"),
                    "remainingVaultTokens": r.get::<f64, _>("remaining_vault_tokens"),
                    "dailyEmissionTokens": r.get::<f64, _>("daily_emission_tokens"),
                    "distributedTokens": r.get::<f64, _>("distributed_tokens"),
                    "minHashrateThs": r.get::<f64, _>("min_hashrate_ths"),
                    "syndicateSectorEnabled": r.get::<bool, _>("syndicate_sector_enabled"),
                    "activeMinersCount": r.get::<i32, _>("active_miners_count"),
                    "status": r.get::<String, _>("status"),
                    "fundingTxHash": r.try_get::<String, _>("funding_tx_hash").ok()
                }));
            }
        }
    }

    let mining_vault_remaining = mineable_vault
        .as_ref()
        .and_then(|v| v.get("remainingVaultTokens").and_then(|x| x.as_f64()))
        .unwrap_or(0.0);

    json!({
        "vestingSchedules": vesting_schedules,
        "monetaryPolicy": monetary_policy,
        "mineableVault": mineable_vault,
        "allMineableVaults": all_mineable_vaults,
        "proofOfLockSummary": {
            "lockedVestingSupply": locked_vesting_supply,
            "unlockedVestedSupply": unlocked_vested_supply,
            "reserveLockedSupply": reserve_locked_supply,
            "miningVaultLockedSupply": mining_vault_remaining,
            "totalLockedSupply": locked_vesting_supply + reserve_locked_supply + mining_vault_remaining,
            "burnedSupply": burned_supply,
            "daily2200UtcUnlockRate": daily_unlock_total,
            "burnAddress": KASPA_BURN_ADDRESS
        }
    })
}

pub async fn handle_state_action(
    State(pool): State<PgPool>,
    Json(req): Json<StateActionReq>,
) -> Result<Json<ActionResponse>, Json<ActionResponse>> {
    if contains_forbidden_private_key_material(&req.payload)
        || req.action == "SIGN_AND_BROADCAST"
        || req.action == "SIGN_P2P_OFFER"
        || req.action == "BROADCAST_ATOMIC_SWAP"
    {
        return Err(Json(ActionResponse {
            success: false,
            error: Some(
                "ZERO_TRUST_VIOLATION: Client private keys must never leave browser memory. Use client-side signing in transaction.svelte.ts.".to_string()
            ),
            transaction_id: None,
            signed_psbt_hex: None,
            data: None,
        }));
    }
    ensure_silo_and_forge_schema(&pool).await;
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = match redis::Client::open(redis_url) {
        Ok(c) => c,
        Err(e) => return Err(Json(ActionResponse { success: false, error: Some(e.to_string()), transaction_id: None, signed_psbt_hex: None, data: None })),
    };
    let mut redis_conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => return Err(Json(ActionResponse { success: false, error: Some(e.to_string()), transaction_id: None, signed_psbt_hex: None, data: None })),
    };
    let clean_wallet = req.wallet.to_lowercase().replace("kaspa:", "").trim().to_string();
    let master_identity = format!("kaspa:{}", clean_wallet);
    let mut tx_db = match pool.begin().await {
        Ok(t) => t,
        Err(e) => return Err(Json(ActionResponse { success: false, error: Some(e.to_string()), transaction_id: None, signed_psbt_hex: None, data: None })),
    };
    let rows = sqlx::query(
        "SELECT layout_state FROM user_command_centers WHERE wallet_address = $1 OR wallet_address = $2"
    )
    .bind(&master_identity)
    .bind(&clean_wallet)
    .fetch_all(&mut *tx_db)
    .await;
    let mut state: Value = json!({"workers": [], "sectors": [], "manualLps": []});
    if let Ok(results) = rows {
        for r in results {
            if let Ok(st) = r.try_get::<Value, _>("layout_state") {
                state = st;
                if state.get("sectors").and_then(|s| s.as_array()).map(|a| a.len()).unwrap_or(0) > 0 {
                    break;
                }
            }
        }
    }
    match req.action.as_str() {
        "ADD_WORKER" => {
            if let Some(workers) = state.get_mut("workers").and_then(|w| w.as_array_mut()) {
                let new_id = req.payload.get("id").and_then(|i| i.as_str()).unwrap_or("");
                let exists = workers.iter().any(|w| w.get("id").and_then(|i| i.as_str()).unwrap_or("") == new_id);
                if !exists {
                    workers.push(req.payload.clone());
                }
            } else {
                state["workers"] = json!([req.payload.clone()]);
            }
        },
        "DELETE_WORKER" => {
            if let Some(id) = req.payload.get("id").and_then(|i| i.as_str()) {
                if let Some(workers) = state.get_mut("workers").and_then(|w| w.as_array_mut()) {
                    workers.retain(|w| w.get("id").and_then(|i| i.as_str()).unwrap_or("") != id);
                }
            }
        },
        "RENAME_WORKER" => {
            if let (Some(id), Some(name), Some(wallet_worker)) = (
                req.payload.get("id").and_then(|i| i.as_str()),
                req.payload.get("name").and_then(|n| n.as_str()),
                req.payload.get("walletWorker").and_then(|w| w.as_str())
            ) {
                if let Some(workers) = state.get_mut("workers").and_then(|w| w.as_array_mut()) {
                    for w in workers.iter_mut() {
                        if w.get("id").and_then(|i| i.as_str()).unwrap_or("") == id {
                            w["name"] = json!(name);
                            w["walletWorker"] = json!(wallet_worker);
                        }
                    }
                }
            }
        },
        "ADD_SECTOR" => {
            let new_pct = req.payload.get("allocationPercentage").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let mut total_pct = new_pct;
            if let Some(sectors) = state.get("sectors").and_then(|s| s.as_array()) {
                for sec in sectors {
                    total_pct += sec.get("allocationPercentage").and_then(|v| v.as_f64()).unwrap_or(0.0);
                }
            }
            if total_pct > 100.001 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse { success: false, error: Some("Total sector allocation cannot exceed 100%".to_string()), transaction_id: None, signed_psbt_hex: None, data: None }));
            }
            let mut normalized_sector = req.payload.clone();
            normalize_sector_plant_or_silo_rules(&mut normalized_sector);
            if let Some(sectors) = state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                sectors.push(normalized_sector);
            } else {
                state["sectors"] = json!([normalized_sector]);
            }
        },
        "DELETE_SECTOR" => {
            if let Some(id) = req.payload.get("id").and_then(|i| i.as_str()) {
                if let Some(sectors) = state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                    sectors.retain(|s| s.get("id").and_then(|i| i.as_str()).unwrap_or("") != id);
                }
            }
        },
        "RENAME_SECTOR" => {
            if let (Some(id), Some(name)) = (
                req.payload.get("id").and_then(|i| i.as_str()),
                req.payload.get("name").and_then(|n| n.as_str())
            ) {
                if let Some(sectors) = state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                    for sec in sectors.iter_mut() {
                        if sec.get("id").and_then(|i| i.as_str()).unwrap_or("") == id {
                            sec["name"] = json!(name);
                        }
                    }
                }
            }
        },
        "UPDATE_SECTOR_ALLOCATION" => {
            if let (Some(id), Some(new_pct)) = (
                req.payload.get("id").and_then(|i| i.as_str()),
                req.payload.get("allocationPercentage").and_then(|p| p.as_f64())
            ) {
                let mut total_pct = new_pct;
                if let Some(sectors) = state.get("sectors").and_then(|s| s.as_array()) {
                    for sec in sectors {
                        if sec.get("id").and_then(|i| i.as_str()).unwrap_or("") != id {
                            total_pct += sec.get("allocationPercentage").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        }
                    }
                }
                if total_pct > 100.001 {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse { success: false, error: Some("Total sector allocation cannot exceed 100%".to_string()), transaction_id: None, signed_psbt_hex: None, data: None }));
                }
                if let Some(sectors) = state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                    for sec in sectors.iter_mut() {
                        if sec.get("id").and_then(|i| i.as_str()).unwrap_or("") == id {
                            sec["allocationPercentage"] = json!(new_pct);
                        }
                    }
                }
            }
        },
        "UPDATE_SETTLEMENT" => {
            if let (Some(id), Some(config)) = (
                req.payload.get("id").and_then(|i| i.as_str()),
                req.payload.get("config")
            ) {
                if let Some(sectors) = state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                    for sec in sectors.iter_mut() {
                        if sec.get("id").and_then(|i| i.as_str()).unwrap_or("") == id {
                            sec["settlementConfig"] = config.clone();
                            normalize_sector_plant_or_silo_rules(sec);
                        }
                    }
                }
            }
        },
        "REORDER_SECTORS" => {
            if let Some(new_array) = req.payload.as_array() {
                let mut total_pct = 0.0;
                for sec in new_array {
                    total_pct += sec.get("allocationPercentage").and_then(|v| v.as_f64()).unwrap_or(0.0);
                }
                if total_pct > 100.001 {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse { success: false, error: Some("Payload manipulation detected. Total allocation exceeds 100%".to_string()), transaction_id: None, signed_psbt_hex: None, data: None }));
                }
                state["sectors"] = json!(new_array);
            }
        },
        "ADD_MANUAL_LP" => {
            if let Some(pos) = req.payload.get("position") {
                if let Some(lps) = state.get_mut("manualLps").and_then(|l| l.as_array_mut()) {
                    lps.push(pos.clone());
                } else {
                    state["manualLps"] = json!([pos.clone()]);
                }
            }
        },
        "REGISTER_FORGE_TOKENOMICS" | "RETROACTIVE_FORGE_UPGRADE" => {
            let is_retro = req.action == "RETROACTIVE_FORGE_UPGRADE"
                || req
                    .payload
                    .get("isRetroactiveUpgrade")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
            let raw_ticker = req
                .payload
                .get("ticker")
                .or_else(|| req.payload.get("tokenTicker"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_uppercase();
            if raw_ticker.len() < 4 || raw_ticker.len() > 6 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("KRC-20 ticker must be 4 to 6 alphabetic characters.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let max_supply: f64 = req
                .payload
                .get("maxSupply")
                .and_then(|v| v.as_f64())
                .unwrap_or(21_000_000.0)
                .max(1.0);
            let deploy_tx_hash = req
                .payload
                .get("deployTxHash")
                .or_else(|| req.payload.get("anchorTxHash"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            // KAS-ONLY TREASURY FIREWALL FOR CUSTOM TOKENS (Rule 8)
            let kas_protocol_fee: f64 = req
                .payload
                .get("protocolFeeKas")
                .and_then(|v| v.as_f64())
                .unwrap_or(1.50)
                .clamp(0.0, 500.0);
            if kas_protocol_fee > 0.0 {
                let _: () = redis::cmd("INCRBYFLOAT")
                    .arg("perennia:fees:batch_accumulated:KAS")
                    .arg(kas_protocol_fee)
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(());
            }

            // 1. Cap Table & Timelocked Vesting Covenants ("Proof-of-Lock")
            let mut inserted_vesting_count = 0usize;
            if let Some(cap_rows) = req.payload.get("capTable").and_then(|v| v.as_array()) {
                for row_val in cap_rows {
                    let raw_addr = row_val
                        .get("address")
                        .or_else(|| row_val.get("beneficiaryAddress"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    if raw_addr.is_empty() {
                        continue;
                    }
                    let clean_ben = raw_addr.to_lowercase().replace("kaspa:", "");
                    let prefixed_ben = format!("kaspa:{}", clean_ben);
                    let label = row_val
                        .get("label")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Genesis Allocation")
                        .trim()
                        .to_string();
                    let amount_tokens: f64 = row_val
                        .get("amount")
                        .or_else(|| row_val.get("totalAllocated"))
                        .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok())))
                        .unwrap_or(0.0)
                        .max(0.0);
                    if amount_tokens <= 0.0 {
                        continue;
                    }
                    let cliff_days: i32 = row_val
                        .get("cliffDays")
                        .or_else(|| row_val.get("cliff_days"))
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0)
                        .clamp(0, 3650) as i32;
                    let linear_days: i32 = row_val
                        .get("linearDays")
                        .or_else(|| row_val.get("linear_days"))
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0)
                        .clamp(0, 3650) as i32;
                    let is_locked_covenant = cliff_days > 0 || linear_days > 0;
                    let effective_linear_days = if is_locked_covenant {
                        linear_days.max(1)
                    } else {
                        0
                    };
                    let daily_unlock_rate: f64 = if effective_linear_days > 0 {
                        amount_tokens / (effective_linear_days as f64)
                    } else {
                        amount_tokens
                    };
                    let initial_unlocked: f64 = if is_locked_covenant {
                        0.0
                    } else {
                        amount_tokens
                    };
                    let initial_status = if is_locked_covenant {
                        "LOCKED"
                    } else {
                        "UNLOCKED"
                    };
                    let state_root_seed = format!(
                        "TIMELOCK_ESCROW_COVENANT:{}:{}:{}:{}:{}",
                        raw_ticker, prefixed_ben, amount_tokens, cliff_days, effective_linear_days
                    );
                    let vprog_state_root = row_val
                        .get("vprogStateRoot")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| compute_sha256_hex(&state_root_seed));
                    let row_tx_hash = row_val
                        .get("txHash")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .or_else(|| deploy_tx_hash.clone());
                    let total_lock_days = cliff_days + effective_linear_days;
                    let _ = sqlx::query(
                        r#"
                        INSERT INTO forge_vesting_schedules
                        (token_ticker, beneficiary_address, creator_address, label, total_allocated,
                         unlocked_amount, claimed_amount, cliff_days, linear_days,
                         cliff_unlock_at, full_unlock_at, daily_unlock_rate, covenant_rule,
                         vprog_state_root, lock_tx_hash, status)
                        VALUES (
                            $1, $2, $3, $4, $5,
                            $6, 0.0, $7, $8,
                            CURRENT_TIMESTAMP + make_interval(days => $7),
                            CURRENT_TIMESTAMP + make_interval(days => $9),
                            $10, 'TIMELOCK_ESCROW_COVENANT', $11, $12, $13
                        )
                        "#,
                    )
                    .bind(&raw_ticker)
                    .bind(&prefixed_ben)
                    .bind(&master_identity)
                    .bind(&label)
                    .bind(amount_tokens)
                    .bind(initial_unlocked)
                    .bind(cliff_days)
                    .bind(effective_linear_days)
                    .bind(total_lock_days)
                    .bind(daily_unlock_rate)
                    .bind(&vprog_state_root)
                    .bind(&row_tx_hash)
                    .bind(initial_status)
                    .execute(&mut *tx_db)
                    .await;
                    if !is_locked_covenant {
                        let ben_ledger_key = format!("dev:sor:treasury:balances:{}", clean_ben);
                        let _: () = redis::cmd("HINCRBYFLOAT")
                            .arg(&ben_ledger_key)
                            .arg(&raw_ticker)
                            .arg(amount_tokens)
                            .query_async(&mut redis_conn)
                            .await
                            .unwrap_or(());
                    }
                    inserted_vesting_count += 1;
                }
            }

            // 2. Monetary Policy Charter (Auto-Burn & Chromatic Halving Emissions + Zero-Rug LP)
            if let Some(policy_obj) = req.payload.get("monetaryPolicy") {
                let burn_rate_bps: i32 = policy_obj
                    .get("burnRateBps")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(50)
                    .clamp(0, 2000) as i32;
                let emission_schedule_type = policy_obj
                    .get("emissionScheduleType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("CHROMATIC_HALVING")
                    .trim()
                    .to_uppercase();
                let daily_emission_rate: f64 = policy_obj
                    .get("dailyEmissionRate")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    .max(0.0);
                let halving_interval_days: i32 = policy_obj
                    .get("halvingIntervalDays")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(365)
                    .clamp(30, 1825) as i32;
                let reserve_locked_tokens: f64 = policy_obj
                    .get("reserveLockedTokens")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    .max(0.0);
                let zero_rug_lp_pct: f64 = policy_obj
                    .get("zeroRugLpPct")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    .clamp(0.0, 100.0);
                let zero_rug_lock_days: i32 = policy_obj
                    .get("zeroRugLockDays")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(365)
                    .clamp(30, 365) as i32;
                let charter_seed = format!(
                    "MONETARY_CHARTER:{}:{}:{}:{}:{}:{}:{}",
                    raw_ticker,
                    max_supply,
                    burn_rate_bps,
                    emission_schedule_type,
                    daily_emission_rate,
                    halving_interval_days,
                    zero_rug_lp_pct
                );
                let charter_sha256 = policy_obj
                    .get("charterSha256")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| compute_sha256_hex(&charter_seed));

                let _ = sqlx::query(
                    r#"
                    INSERT INTO forge_monetary_policies
                    (token_ticker, creator_address, max_supply, burn_rate_bps, burn_address,
                     emission_schedule_type, daily_emission_rate, halving_interval_days,
                     reserve_locked_tokens, zero_rug_lp_pct, zero_rug_lock_days,
                     is_retroactive_upgrade, charter_sha256, anchor_tx_hash, updated_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, CURRENT_TIMESTAMP)
                    ON CONFLICT (token_ticker) DO UPDATE SET
                        burn_rate_bps = EXCLUDED.burn_rate_bps,
                        emission_schedule_type = EXCLUDED.emission_schedule_type,
                        daily_emission_rate = EXCLUDED.daily_emission_rate,
                        halving_interval_days = EXCLUDED.halving_interval_days,
                        reserve_locked_tokens = forge_monetary_policies.reserve_locked_tokens + EXCLUDED.reserve_locked_tokens,
                        zero_rug_lp_pct = EXCLUDED.zero_rug_lp_pct,
                        zero_rug_lock_days = EXCLUDED.zero_rug_lock_days,
                        is_retroactive_upgrade = EXCLUDED.is_retroactive_upgrade,
                        charter_sha256 = EXCLUDED.charter_sha256,
                        anchor_tx_hash = COALESCE(EXCLUDED.anchor_tx_hash, forge_monetary_policies.anchor_tx_hash),
                        updated_at = CURRENT_TIMESTAMP
                    "#,
                )
                .bind(&raw_ticker)
                .bind(&master_identity)
                .bind(max_supply)
                .bind(burn_rate_bps)
                .bind(KASPA_BURN_ADDRESS)
                .bind(&emission_schedule_type)
                .bind(daily_emission_rate)
                .bind(halving_interval_days)
                .bind(reserve_locked_tokens)
                .bind(zero_rug_lp_pct)
                .bind(zero_rug_lock_days)
                .bind(is_retro)
                .bind(&charter_sha256)
                .bind(&deploy_tx_hash)
                .execute(&mut *tx_db)
                .await;

                // Zero-Rug Liquidity Bootstrapper: auto-create 365-Day (2.5x) KAS/TOKEN LP Plant
                let zero_rug_initial_kas: f64 = policy_obj
                    .get("zeroRugInitialKas")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    .max(0.0);
                let zero_rug_initial_tokens: f64 = policy_obj
                    .get("zeroRugInitialTokens")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    .max(0.0);
                if zero_rug_lp_pct >= 80.0 && zero_rug_initial_kas > 0.0 && zero_rug_initial_tokens > 0.0 {
                    let locked_kas = zero_rug_initial_kas * (zero_rug_lp_pct / 100.0);
                    let pool_pair = format!("KAS/{}", raw_ticker);
                    let w_json = json!({ "KAS": 0.50, raw_ticker.clone(): 0.50 });
                    let r_json = json!({ "KAS": locked_kas, raw_ticker.clone(): zero_rug_initial_tokens });
                    let _ = sqlx::query(
                        r#"
                        INSERT INTO liquidity_providers
                        (wallet_address, pool_pair, staked_asset_a, staked_asset_b, weights_json, reserves_json, lock_duration_days, unlock_date)
                        VALUES ($1, $2, $3, $4, $5, $6, 365, CURRENT_TIMESTAMP + INTERVAL '365 days')
                        "#,
                    )
                    .bind(&master_identity)
                    .bind(&pool_pair)
                    .bind(locked_kas)
                    .bind(zero_rug_initial_tokens)
                    .bind(w_json)
                    .bind(r_json)
                    .execute(&mut *tx_db)
                    .await;
                }
            }

            // 3. Proof-of-Hashrate Mineable KRC-20 Vault
            if let Some(vault_obj) = req.payload.get("mineableVault") {
                let enabled = vault_obj
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let funded_tokens: f64 = vault_obj
                    .get("totalFundedTokens")
                    .or_else(|| vault_obj.get("fundedTokens"))
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    .max(0.0);
                let daily_emission: f64 = vault_obj
                    .get("dailyEmissionTokens")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(funded_tokens / 365.0)
                    .max(0.0);
                let min_hashrate_ths: f64 = vault_obj
                    .get("minHashrateThs")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.1)
                    .max(0.01);
                let syndicate_enabled = vault_obj
                    .get("syndicateSectorEnabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let vault_label = vault_obj
                    .get("vaultLabel")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Proof-of-Hashrate Mining Vault")
                    .trim()
                    .to_string();

                if enabled && funded_tokens > 0.0 {
                    let _ = sqlx::query(
                        r#"
                        INSERT INTO forge_mineable_vaults
                        (token_ticker, creator_address, vault_label, total_funded_tokens,
                         remaining_vault_tokens, daily_emission_tokens, distributed_tokens,
                         min_hashrate_ths, syndicate_sector_enabled, status, funding_tx_hash, updated_at)
                        VALUES ($1, $2, $3, $4, $4, $5, 0.0, $6, $7, 'ACTIVE', $8, CURRENT_TIMESTAMP)
                        ON CONFLICT (token_ticker) DO UPDATE SET
                            total_funded_tokens = forge_mineable_vaults.total_funded_tokens + EXCLUDED.total_funded_tokens,
                            remaining_vault_tokens = forge_mineable_vaults.remaining_vault_tokens + EXCLUDED.remaining_vault_tokens,
                            daily_emission_tokens = EXCLUDED.daily_emission_tokens,
                            min_hashrate_ths = EXCLUDED.min_hashrate_ths,
                            syndicate_sector_enabled = EXCLUDED.syndicate_sector_enabled,
                            status = 'ACTIVE',
                            funding_tx_hash = COALESCE(EXCLUDED.funding_tx_hash, forge_mineable_vaults.funding_tx_hash),
                            updated_at = CURRENT_TIMESTAMP
                        "#,
                    )
                    .bind(&raw_ticker)
                    .bind(&master_identity)
                    .bind(&vault_label)
                    .bind(funded_tokens)
                    .bind(daily_emission)
                    .bind(min_hashrate_ths)
                    .bind(syndicate_enabled)
                    .bind(&deploy_tx_hash)
                    .execute(&mut *tx_db)
                    .await;
                }
            }

            let _ = tx_db.commit().await;
            let bundle = query_forge_tokenomics_bundle(&pool, Some(&raw_ticker), true).await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: deploy_tx_hash,
                signed_psbt_hex: None,
                data: Some(json!({
                    "ticker": raw_ticker,
                    "isRetroactiveUpgrade": is_retro,
                    "insertedVestingCount": inserted_vesting_count,
                    "protocolFeeKas": kas_protocol_fee,
                    "kasFeeFirewallEnforced": true,
                    "tokenomics": bundle
                })),
            }));
        },
        "GET_FORGE_TOKENOMICS" => {
            let _ = tx_db.rollback().await;
            let ticker_opt = req
                .payload
                .get("ticker")
                .or_else(|| req.payload.get("tokenTicker"))
                .and_then(|v| v.as_str());
            let include_all = req
                .payload
                .get("includeAllMineableVaults")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let bundle = query_forge_tokenomics_bundle(&pool, ticker_opt, include_all).await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: None,
                signed_psbt_hex: None,
                data: Some(bundle),
            }));
        },
        "FUND_MINEABLE_KRC20_VAULT" => {
            let raw_ticker = req
                .payload
                .get("ticker")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_uppercase();
            let add_tokens: f64 = req
                .payload
                .get("amountTokens")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0)
                .max(0.0);
            let daily_emission: f64 = req
                .payload
                .get("dailyEmissionTokens")
                .and_then(|v| v.as_f64())
                .unwrap_or(add_tokens / 365.0)
                .max(0.0);
            let tx_hash_opt = req
                .payload
                .get("txHash")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string());
            if raw_ticker.len() < 4 || add_tokens <= 0.0 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("Valid KRC-20 ticker and positive token funding amount required.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let _ = sqlx::query(
                r#"
                INSERT INTO forge_mineable_vaults
                (token_ticker, creator_address, total_funded_tokens, remaining_vault_tokens, daily_emission_tokens, status, funding_tx_hash)
                VALUES ($1, $2, $3, $3, $4, 'ACTIVE', $5)
                ON CONFLICT (token_ticker) DO UPDATE SET
                    total_funded_tokens = forge_mineable_vaults.total_funded_tokens + EXCLUDED.total_funded_tokens,
                    remaining_vault_tokens = forge_mineable_vaults.remaining_vault_tokens + EXCLUDED.remaining_vault_tokens,
                    daily_emission_tokens = EXCLUDED.daily_emission_tokens,
                    status = 'ACTIVE',
                    funding_tx_hash = COALESCE(EXCLUDED.funding_tx_hash, forge_mineable_vaults.funding_tx_hash),
                    updated_at = CURRENT_TIMESTAMP
                "#,
            )
            .bind(&raw_ticker)
            .bind(&master_identity)
            .bind(add_tokens)
            .bind(daily_emission)
            .bind(&tx_hash_opt)
            .execute(&mut *tx_db)
            .await;
            let _ = tx_db.commit().await;
            let bundle = query_forge_tokenomics_bundle(&pool, Some(&raw_ticker), true).await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: tx_hash_opt,
                signed_psbt_hex: None,
                data: Some(bundle),
            }));
        },
        "STAKE_SILO" => {
            let eco_ticker = req
                .payload
                .get("ticker")
                .and_then(|t| t.as_str())
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(crate::sor::resolve_ecosystem_ticker);
            let amount = req
                .payload
                .get("amount")
                .and_then(|a| a.as_f64().or_else(|| a.as_str().and_then(|s| s.parse::<f64>().ok())))
                .unwrap_or(0.0);
            let tx_hash_opt = req
                .payload
                .get("txHash")
                .and_then(|t| t.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            if amount <= 0.0 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some(format!("{} stake amount must be greater than zero.", eco_ticker)),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
            if tx_hash_opt.is_none() {
                let debit_res: (i32, String) = redis::cmd("EVAL")
                    .arg(LUA_ATOMIC_DEBIT_SINGLE)
                    .arg(1)
                    .arg(&user_ledger_key)
                    .arg(&eco_ticker)
                    .arg(amount)
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or((0, "0".to_string()));
                if debit_res.0 == 0 {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse {
                        success: false,
                        error: Some(format!(
                            "Insufficient {} balance in Treasury Ledger to stake.",
                            eco_ticker
                        )),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                }
            }
            let existing_active = sqlx::query(
                "SELECT stake_id FROM silo_staking_positions WHERE (wallet_address = $1 OR wallet_address = $2) AND token_ticker = $3 AND status = 'ACTIVE' ORDER BY created_at DESC LIMIT 1"
            )
            .bind(&master_identity)
            .bind(&clean_wallet)
            .bind(&eco_ticker)
            .fetch_optional(&mut *tx_db)
            .await
            .ok()
            .flatten();
            let resolved_stake_id: Uuid = if let Some(row) = existing_active {
                let sid: Uuid = row.get("stake_id");
                let _ = sqlx::query(
                    "UPDATE silo_staking_positions SET amount_staked = amount_staked + $1, tx_hash = COALESCE($2, tx_hash) WHERE stake_id = $3"
                )
                .bind(amount)
                .bind(&tx_hash_opt)
                .bind(sid)
                .execute(&mut *tx_db)
                .await;
                sid
            } else {
                let inserted = sqlx::query(
                    "INSERT INTO silo_staking_positions (wallet_address, token_ticker, amount_staked, status, tx_hash) VALUES ($1, $2, $3, 'ACTIVE', $4) RETURNING stake_id"
                )
                .bind(&master_identity)
                .bind(&eco_ticker)
                .bind(amount)
                .bind(&tx_hash_opt)
                .fetch_one(&mut *tx_db)
                .await
                .map_err(|e| {
                    Json(ActionResponse {
                        success: false,
                        error: Some(format!("Failed to record {} stake: {}", eco_ticker, e)),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    })
                })?;
                inserted.get("stake_id")
            };
            let _ = tx_db.commit().await;
            let tier_info = crate::sor::get_silo_staking_fee_cap(&pool, &clean_wallet, &master_identity).await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: tx_hash_opt,
                signed_psbt_hex: None,
                data: Some(json!({
                    "stakeId": resolved_stake_id.to_string(),
                    "ticker": eco_ticker,
                    "stakedAmount": amount,
                    "feeRateCap": tier_info.as_ref().map(|(r, _, _)| *r).unwrap_or(0.015),
                    "tierLabel": tier_info.as_ref().map(|(_, l, _)| l.clone()).unwrap_or_else(|| "Standard Tier (1.50% Fee)".to_string()),
                    "totalActiveStaked": tier_info.map(|(_, _, s)| s).unwrap_or(amount)
                })),
            }));
        },
        "INITIATE_SILO_COOLDOWN" => {
            let stake_id_str = req.payload.get("stakeId").and_then(|v| v.as_str()).unwrap_or("");
            let stake_uuid = Uuid::from_str(stake_id_str).map_err(|_| {
                Json(ActionResponse {
                    success: false,
                    error: Some("Invalid stakeId format.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                })
            })?;
            let updated = sqlx::query(
                r#"
                UPDATE silo_staking_positions
                SET status = 'COOLDOWN',
                    cooldown_initiated_at = CURRENT_TIMESTAMP,
                    cooldown_ends_at = CURRENT_TIMESTAMP + INTERVAL '7 days'
                WHERE stake_id = $1
                  AND (wallet_address = $2 OR wallet_address = $3)
                  AND status = 'ACTIVE'
                RETURNING cooldown_ends_at, amount_staked, token_ticker
                "#,
            )
            .bind(stake_uuid)
            .bind(&master_identity)
            .bind(&clean_wallet)
            .fetch_optional(&mut *tx_db)
            .await
            .map_err(|e| {
                Json(ActionResponse {
                    success: false,
                    error: Some(format!("Database error initiating cooldown: {}", e)),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                })
            })?;
            let Some(row) = updated else {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("Active SILO stake position not found or already in 7-day cooldown.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            };
            let cooldown_ends: chrono::DateTime<chrono::Utc> = row.get("cooldown_ends_at");
            let amount_staked: f64 = row.get("amount_staked");
            let ticker: String = row.get("token_ticker");
            let _ = tx_db.commit().await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: None,
                signed_psbt_hex: None,
                data: Some(json!({
                    "stakeId": stake_uuid.to_string(),
                    "status": "COOLDOWN",
                    "ticker": ticker,
                    "amountStaked": amount_staked,
                    "cooldownDays": 7,
                    "cooldownEndsAt": cooldown_ends.to_rfc3339()
                })),
            }));
        },
        "CLAIM_UNSTAKED_SILO" => {
            let stake_id_str = req.payload.get("stakeId").and_then(|v| v.as_str()).unwrap_or("");
            let stake_uuid = Uuid::from_str(stake_id_str).map_err(|_| {
                Json(ActionResponse {
                    success: false,
                    error: Some("Invalid stakeId format.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                })
            })?;
            let row_opt = sqlx::query(
                r#"
                SELECT stake_id, token_ticker, amount_staked, status, cooldown_ends_at,
                       (cooldown_ends_at IS NOT NULL AND CURRENT_TIMESTAMP >= cooldown_ends_at) AS is_matured
                FROM silo_staking_positions
                WHERE stake_id = $1 AND (wallet_address = $2 OR wallet_address = $3)
                FOR UPDATE
                "#,
            )
            .bind(stake_uuid)
            .bind(&master_identity)
            .bind(&clean_wallet)
            .fetch_optional(&mut *tx_db)
            .await
            .map_err(|e| {
                Json(ActionResponse {
                    success: false,
                    error: Some(format!("Database lookup failed: {}", e)),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                })
            })?;
            let Some(row) = row_opt else {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("SILO stake position not found.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            };
            let status: String = row.get("status");
            let is_matured: bool = row.try_get("is_matured").unwrap_or(false);
            let cooldown_ends_opt: Option<chrono::DateTime<chrono::Utc>> = row.try_get("cooldown_ends_at").ok();
            if status != "COOLDOWN" || !is_matured {
                let _ = tx_db.rollback().await;
                let unlock_label = cooldown_ends_opt
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| "7 days after initiating cooldown".to_string());
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some(format!(
                        "COOLDOWN_LOCK_ACTIVE: 7-day unbonding cooldown is active until {}.",
                        unlock_label
                    )),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let amount_staked: f64 = row.get("amount_staked");
            let token_ticker: String = row.get("token_ticker");
            sqlx::query("DELETE FROM silo_staking_positions WHERE stake_id = $1")
                .bind(stake_uuid)
                .execute(&mut *tx_db)
                .await
                .map_err(|e| {
                    Json(ActionResponse {
                        success: false,
                        error: Some(format!("Failed to finalize unstake: {}", e)),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    })
                })?;
            let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
            let _: () = redis::cmd("HINCRBYFLOAT")
                .arg(&user_ledger_key)
                .arg(&token_ticker)
                .arg(amount_staked)
                .query_async(&mut redis_conn)
                .await
                .map_err(|e| {
                    Json(ActionResponse {
                        success: false,
                        error: Some(format!("Redis credit failed during SILO claim: {}", e)),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    })
                })?;
            let _ = tx_db.commit().await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: None,
                signed_psbt_hex: None,
                data: Some(json!({
                    "stakeId": stake_uuid.to_string(),
                    "claimedAmount": amount_staked,
                    "ticker": token_ticker
                })),
            }));
        },
        "GET_SILO_STAKING" => {
            let rows = sqlx::query(
                r#"
                SELECT stake_id, token_ticker, amount_staked, status, tx_hash,
                       cooldown_initiated_at, cooldown_ends_at, created_at,
                       (cooldown_ends_at IS NOT NULL AND CURRENT_TIMESTAMP >= cooldown_ends_at) AS is_matured
                FROM silo_staking_positions
                WHERE wallet_address = $1 OR wallet_address = $2
                ORDER BY created_at DESC
                "#,
            )
            .bind(&master_identity)
            .bind(&clean_wallet)
            .fetch_all(&mut *tx_db)
            .await
            .unwrap_or_default();
            let _ = tx_db.rollback().await;
            let mut positions = Vec::new();
            let mut active_staked_total = 0.0;
            let mut cooldown_staked_total = 0.0;
            for r in rows {
                let sid: Uuid = r.get("stake_id");
                let ticker: String = r.get("token_ticker");
                let amt: f64 = r.get("amount_staked");
                let st: String = r.get("status");
                let tx_h: Option<String> = r.try_get("tx_hash").ok();
                let cd_init: Option<chrono::DateTime<chrono::Utc>> = r.try_get("cooldown_initiated_at").ok();
                let cd_end: Option<chrono::DateTime<chrono::Utc>> = r.try_get("cooldown_ends_at").ok();
                let created: Option<chrono::DateTime<chrono::Utc>> = r.try_get("created_at").ok();
                let matured: bool = r.try_get("is_matured").unwrap_or(false);
                if st == "ACTIVE" {
                    active_staked_total += amt;
                } else {
                    cooldown_staked_total += amt;
                }
                positions.push(json!({
                    "stakeId": sid.to_string(),
                    "ticker": ticker,
                    "amountStaked": amt,
                    "status": st,
                    "txHash": tx_h,
                    "cooldownInitiatedAt": cd_init.map(|d| d.to_rfc3339()),
                    "cooldownEndsAt": cd_end.map(|d| d.to_rfc3339()),
                    "createdAt": created.map(|d| d.to_rfc3339()),
                    "isMatured": matured
                }));
            }
            let tier_info = crate::sor::get_silo_staking_fee_cap(&pool, &clean_wallet, &master_identity).await;
            let (fee_rate_cap, tier_label, combined_staked) = tier_info.unwrap_or((
                0.015,
                "Standard Tier (1.50% Fee)".to_string(),
                active_staked_total,
            ));
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: None,
                signed_psbt_hex: None,
                data: Some(json!({
                    "ecosystemTicker": crate::sor::resolve_ecosystem_ticker(),
                    "activeStaked": active_staked_total,
                    "cooldownStaked": cooldown_staked_total,
                    "combinedEligibleStaked": combined_staked,
                    "feeRateCap": fee_rate_cap,
                    "tierLabel": tier_label,
                    "positions": positions
                })),
            }));
        },
        "UPDATE_TAX_FORTRESS" => {
            let existing_tf = state.get("taxFortress").cloned().unwrap_or_else(|| json!({}));
            let escrow_active = req
                .payload
                .get("escrowActive")
                .and_then(|v| v.as_bool())
                .or_else(|| existing_tf.get("escrowActive").and_then(|v| v.as_bool()))
                .unwrap_or(false);
            let raw_rate: f64 = req
                .payload
                .get("withholdingRate")
                .or_else(|| req.payload.get("effectiveTaxRate"))
                .and_then(|v| v.as_f64())
                .or_else(|| existing_tf.get("withholdingRate").and_then(|v| v.as_f64()))
                .unwrap_or(15.0_f64);
            let normalized_rate_pct: f64 = if raw_rate > 0.0_f64 && raw_rate < 1.0_f64 {
                (raw_rate * 100.0_f64).clamp(0.0_f64, 50.0_f64)
            } else {
                raw_rate.clamp(0.0_f64, 50.0_f64)
            };
            let country_code = req
                .payload
                .get("countryCode")
                .and_then(|v| v.as_str())
                .or_else(|| existing_tf.get("countryCode").and_then(|v| v.as_str()))
                .unwrap_or("US")
                .trim()
                .to_uppercase();
            let state_region = req
                .payload
                .get("stateRegion")
                .and_then(|v| v.as_str())
                .or_else(|| existing_tf.get("stateRegion").and_then(|v| v.as_str()))
                .unwrap_or("TX")
                .trim()
                .to_uppercase();
            let jurisdiction_code = req
                .payload
                .get("jurisdictionCode")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_uppercase())
                .unwrap_or_else(|| format!("{}-{}", country_code, state_region));
            let entity_type = req
                .payload
                .get("entityType")
                .and_then(|v| v.as_str())
                .or_else(|| existing_tf.get("entityType").and_then(|v| v.as_str()))
                .unwrap_or("LLC")
                .trim()
                .to_uppercase();
            let filing_status = req
                .payload
                .get("filingStatus")
                .and_then(|v| v.as_str())
                .or_else(|| existing_tf.get("filingStatus").and_then(|v| v.as_str()))
                .unwrap_or("SINGLE")
                .trim()
                .to_uppercase();
            let default_maturity = if entity_type == "S-CORP" || entity_type == "PARTNERSHIP" {
                "2027-03-15"
            } else {
                "2027-04-15"
            };
            let maturity_date = req
                .payload
                .get("maturityDate")
                .and_then(|v| v.as_str())
                .or_else(|| existing_tf.get("maturityDate").and_then(|v| v.as_str()))
                .unwrap_or(default_maturity)
                .trim()
                .to_string();
            let rounded_rate: f64 = (normalized_rate_pct * 100.0_f64).round() / 100.0_f64;
            state["taxFortress"] = json!({
                "escrowActive": escrow_active,
                "withholdingRate": rounded_rate,
                "jurisdictionCode": jurisdiction_code,
                "countryCode": country_code,
                "stateRegion": state_region,
                "entityType": entity_type,
                "filingStatus": filing_status,
                "maturityDate": maturity_date,
                "updatedAt": chrono::Utc::now().to_rfc3339()
            });
            let _ = sqlx::query(
                r#"
                INSERT INTO entity_kyc
                (wallet_address, legal_name, entity_type, tax_id_hash, business_address, country_code, state_region, filing_status, effective_tax_rate, verification_status, verified_at)
                VALUES ($1, 'ZERO_PII_SOVEREIGN', $2, 'ZERO_PII_LOCAL_ONLY', 'ZERO_PII_LOCAL_ONLY', $3, $4, $5, $6, 'verified', CURRENT_TIMESTAMP)
                ON CONFLICT (wallet_address) DO UPDATE SET
                    legal_name = 'ZERO_PII_SOVEREIGN',
                    entity_type = EXCLUDED.entity_type,
                    tax_id_hash = 'ZERO_PII_LOCAL_ONLY',
                    business_address = 'ZERO_PII_LOCAL_ONLY',
                    country_code = EXCLUDED.country_code,
                    state_region = EXCLUDED.state_region,
                    filing_status = EXCLUDED.filing_status,
                    effective_tax_rate = EXCLUDED.effective_tax_rate,
                    verification_status = 'verified',
                    verified_at = CURRENT_TIMESTAMP
                "#
            )
            .bind(&master_identity)
            .bind(&entity_type)
            .bind(&country_code)
            .bind(&state_region)
            .bind(&filing_status)
            .bind(rounded_rate)
            .execute(&mut *tx_db)
            .await;
        },
        "WITHDRAW_SYNTHETIC_ASSET" => {
            let destination = req.payload
                .get("destination")
                .or_else(|| req.payload.get("destinationAddress"))
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let amount = req.payload
                .get("amount")
                .and_then(|a| a.as_f64().or_else(|| a.as_str().and_then(|s| s.parse::<f64>().ok())))
                .unwrap_or(0.0);
            let asset = req.payload
                .get("asset")
                .and_then(|a| a.as_str())
                .unwrap_or("KAS")
                .trim()
                .to_uppercase();
            if destination.is_empty() || amount <= 0.0 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("Missing destination address or valid withdrawal amount.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
            let debit_res: (i32, String) = redis::cmd("EVAL")
                .arg(LUA_ATOMIC_DEBIT_SINGLE)
                .arg(1)
                .arg(&user_ledger_key)
                .arg(&asset)
                .arg(amount)
                .query_async(&mut redis_conn)
                .await
                .unwrap_or((0, "0".to_string()));
            if debit_res.0 == 0 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some(format!("Insufficient {} balance in Batch Settlement Queue / Treasury Ledger.", asset)),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let from_unassigned = debit_res.1.parse::<f64>().unwrap_or(0.0);
            if from_unassigned > 1e-9 {
                let _ = sqlx::query(
                    "UPDATE yield_reservoirs SET streaming_balance_kas = GREATEST(0.0, streaming_balance_kas - $1), last_updated = CURRENT_TIMESTAMP WHERE LOWER(REPLACE(TRIM(wallet_address), 'kaspa:', '')) = $2 OR wallet_address = $3"
                )
                .bind(from_unassigned)
                .bind(&clean_wallet)
                .bind(&master_identity)
                .execute(&mut *tx_db)
                .await;
            }
            let spot_price = get_spot_usd(&mut redis_conn, &asset).await;
            let (tx_id, dispatch_status, explorer_url) = dispatch_or_queue_multi_chain_l1(
                &mut tx_db,
                &mut redis_conn,
                &master_identity,
                &clean_wallet,
                &destination,
                &asset,
                amount,
                spot_price,
                "ledger_withdrawal",
            )
            .await;
            let _ = tx_db.commit().await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: Some(tx_id.clone()),
                signed_psbt_hex: None,
                data: Some(json!({
                    "txHash": tx_id,
                    "status": dispatch_status,
                    "explorerUrl": explorer_url,
                    "asset": asset,
                    "amount": amount,
                    "destination": destination
                })),
            }));
        },
        "DISPATCH_OTC_UTXOS" => {
            let destination = req.payload.get("destination").and_then(|d| d.as_str()).unwrap_or("");
            let amount = req.payload.get("amount").and_then(|a| a.as_f64()).unwrap_or(0.0);
            let asset = req.payload.get("asset").and_then(|a| a.as_str()).unwrap_or("KAS").to_uppercase();
            if destination.is_empty() || amount <= 0.0 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("Missing destination or valid amount for OTC dispatch.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            if asset == "KAS" {
                match crate::sor::execute_physical_settlement(destination, amount).await {
                    Ok(tx_id) => {
                        let _ = tx_db.commit().await;
                        return Ok(Json(ActionResponse {
                            success: true,
                            error: None,
                            transaction_id: Some(tx_id),
                            signed_psbt_hex: None,
                            data: None,
                        }));
                    }
                    Err(_) => {
                        let spot_price = get_spot_usd(&mut redis_conn, "KAS").await;
                        let (tx_id, status, explorer_url) = dispatch_or_queue_multi_chain_l1(
                            &mut tx_db,
                            &mut redis_conn,
                            &master_identity,
                            &clean_wallet,
                            destination,
                            "KAS",
                            amount,
                            spot_price,
                            "otc_dispatch",
                        )
                        .await;
                        let _ = tx_db.commit().await;
                        return Ok(Json(ActionResponse {
                            success: true,
                            error: None,
                            transaction_id: Some(tx_id),
                            signed_psbt_hex: None,
                            data: Some(json!({ "status": status, "explorerUrl": explorer_url })),
                        }));
                    }
                }
            } else {
                let spot_price = get_spot_usd(&mut redis_conn, &asset).await;
                let (tx_id, status, explorer_url) = dispatch_or_queue_multi_chain_l1(
                    &mut tx_db,
                    &mut redis_conn,
                    &master_identity,
                    &clean_wallet,
                    destination,
                    &asset,
                    amount,
                    spot_price,
                    "otc_dispatch",
                )
                .await;
                let _ = tx_db.commit().await;
                return Ok(Json(ActionResponse {
                    success: true,
                    error: None,
                    transaction_id: Some(tx_id),
                    signed_psbt_hex: None,
                    data: Some(json!({ "status": status, "explorerUrl": explorer_url })),
                }));
            }
        },
        "STAKE_LP" => {
            let lock_days = req.payload.get("lockDurationDays").and_then(|d| d.as_i64()).unwrap_or(0) as i32;
            if lock_days != 0 && lock_days != 30 && lock_days != 90 && lock_days != 365 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("Invalid lock duration. Permitted periods: 0 (Flexible), 30, 90, or 365 days.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let raw_pair = req.payload.get("poolPair").and_then(|p| p.as_str()).unwrap_or("KAS/USDC");
            let amount_a: f64 = req.payload.get("amountA").and_then(|a| a.as_f64()).unwrap_or(0.0_f64);
            let amount_b: f64 = req.payload.get("amountB").and_then(|b| b.as_f64()).unwrap_or(0.0_f64);
            let eco_ticker = crate::sor::resolve_ecosystem_ticker();
            let mut reserves_map: HashMap<String, f64> = HashMap::new();
            let mut weights_map: HashMap<String, f64> = HashMap::new();
            let mut secondary_order: Vec<String> = Vec::new();
            if let Some(sec_arr) = req.payload.get("secondaryAssets").and_then(|v| v.as_array()) {
                if !sec_arr.is_empty() && amount_a > 0.0_f64 {
                    reserves_map.insert("KAS".to_string(), amount_a);
                    weights_map.insert("KAS".to_string(), 0.50_f64);
                    let mut raw_sec_weights: Vec<(String, f64, f64)> = Vec::new();
                    for item in sec_arr {
                        let tick = item
                            .get("ticker")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .trim()
                            .to_uppercase();
                        let amt: f64 = item.get("amount").and_then(|v| v.as_f64()).unwrap_or(0.0_f64);
                        let w_pct: f64 = item
                            .get("weightPct")
                            .or_else(|| item.get("weight"))
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0_f64);
                        if !tick.is_empty() && tick != "KAS" && amt > 0.0_f64 {
                            raw_sec_weights.push((tick, w_pct.max(0.0_f64), amt));
                        }
                    }
                    let w_sum: f64 = raw_sec_weights.iter().map(|(_, w, _)| *w).sum();
                    let n_sec = raw_sec_weights.len();
                    for (t, w, amt) in raw_sec_weights {
                        let norm_w: f64 = if w_sum > 0.0_f64 {
                            (w / w_sum) * 0.50_f64
                        } else if n_sec > 0 {
                            0.50_f64 / (n_sec as f64)
                        } else {
                            0.50_f64
                        };
                        secondary_order.push(t.clone());
                        reserves_map.insert(t.clone(), amt);
                        weights_map.insert(t, norm_w);
                    }
                }
            }
            if reserves_map.is_empty() {
                if let (Some(r_obj), Some(w_obj)) = (
                    req.payload.get("reserves").and_then(|v| v.as_object()),
                    req.payload.get("weights").and_then(|v| v.as_object()),
                ) {
                    for (k, v) in r_obj {
                        let clean = k.trim().to_uppercase();
                        if let Some(amt) = v.as_f64() {
                            if amt > 0.0_f64 {
                                reserves_map.insert(clean.clone(), amt);
                                if clean != "KAS" {
                                    secondary_order.push(clean);
                                }
                            }
                        }
                    }
                    weights_map.insert("KAS".to_string(), 0.50_f64);
                    let mut sec_w_sum: f64 = 0.0_f64;
                    for sec in &secondary_order {
                        let w: f64 = w_obj
                            .get(sec)
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0_f64)
                            .max(0.0_f64);
                        sec_w_sum += w;
                    }
                    let n_sec = secondary_order.len();
                    for sec in &secondary_order {
                        let raw_w: f64 = w_obj
                            .get(sec)
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0_f64)
                            .max(0.0_f64);
                        let norm_w: f64 = if sec_w_sum > 0.0_f64 {
                            (raw_w / sec_w_sum) * 0.50_f64
                        } else if n_sec > 0 {
                            0.50_f64 / (n_sec as f64)
                        } else {
                            0.50_f64
                        };
                        weights_map.insert(sec.clone(), norm_w);
                    }
                }
            }
            if reserves_map.is_empty() {
                let pair_parts: Vec<String> = raw_pair
                    .split('/')
                    .map(|s| s.trim().to_uppercase())
                    .filter(|s| !s.is_empty())
                    .collect();
                let asset_a = pair_parts.first().cloned().unwrap_or_else(|| "KAS".to_string());
                let asset_b = pair_parts.get(1).cloned().unwrap_or_else(|| "USDC".to_string());
                if asset_a != "KAS" || amount_a <= 0.0_f64 || amount_b <= 0.0_f64 {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse {
                        success: false,
                        error: Some("Liquidity Plant staking requires KAS anchored at 50% with positive amounts.".to_string()),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                }
                reserves_map.insert("KAS".to_string(), amount_a);
                reserves_map.insert(asset_b.clone(), amount_b);
                weights_map.insert("KAS".to_string(), 0.50_f64);
                weights_map.insert(asset_b.clone(), 0.50_f64);
                secondary_order.push(asset_b);
            }
            let kas_amount: f64 = reserves_map.get("KAS").copied().unwrap_or(0.0_f64);
            if kas_amount <= 0.0_f64 || secondary_order.is_empty() {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("Liquidity Plant requires 50% KAS and at least 1 secondary asset.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            for sec_ticker in &secondary_order {
                let is_eligible = crate::oracle::is_oracle_supported_asset(sec_ticker)
                    || *sec_ticker == eco_ticker;
                if *sec_ticker == "KAS" || !is_eligible {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse {
                        success: false,
                        error: Some(format!(
                            "UNSUPPORTED_LP_ASSET: Liquidity Plant asset {} is not backed by a verified 7-Node or Pyth Hermes oracle feed.",
                            sec_ticker
                        )),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                }
            }
            let kas_usd: f64 = get_spot_usd(&mut redis_conn, "KAS").await;
            if kas_usd <= 0.0_f64 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("ORACLE_HALT: Live KAS/USDC spot feed is required to provision Liquidity Plants.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let mut total_stake_usd: f64 = kas_amount * kas_usd;
            let mut secondary_total_b: f64 = 0.0_f64;
            for (idx, sec_ticker) in secondary_order.iter().enumerate() {
                let sec_amt: f64 = reserves_map.get(sec_ticker).copied().unwrap_or(0.0_f64);
                let sec_usd: f64 = get_spot_usd(&mut redis_conn, sec_ticker).await;
                if sec_usd <= 0.0_f64 && *sec_ticker != eco_ticker {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse {
                        success: false,
                        error: Some(format!(
                            "ORACLE_HALT: Live oracle spot feed for {} is currently unavailable.",
                            sec_ticker
                        )),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                }
                total_stake_usd += sec_amt * sec_usd;
                if secondary_order.len() == 1 || idx == 0 {
                    secondary_total_b = if secondary_order.len() == 1 {
                        sec_amt
                    } else {
                        secondary_total_b + (sec_amt * sec_usd)
                    };
                } else {
                    secondary_total_b += sec_amt * sec_usd;
                }
            }
            let min_position_usd = crate::sor::get_min_dark_pool_position_usd();
            if total_stake_usd < min_position_usd {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some(format!(
                        "ANTI_DUST_GUARD: Liquidity Plant stake value (${:.2} USD) is below the minimum position floor (${:.2} USD).",
                        total_stake_usd, min_position_usd
                    )),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
            let mut eval_cmd = redis::cmd("EVAL");
            eval_cmd
                .arg(LUA_ATOMIC_DEBIT_MULTI_LP)
                .arg(1)
                .arg(&user_ledger_key)
                .arg(reserves_map.len());
            for (asset_tick, req_amt) in &reserves_map {
                eval_cmd.arg(asset_tick).arg(*req_amt);
            }
            let debit_res: (i32, String, String) = eval_cmd
                .query_async(&mut redis_conn)
                .await
                .unwrap_or((0, "0".to_string(), "REDIS_EVAL_ERR".to_string()));
            if debit_res.0 == 0 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some(format!(
                        "Insufficient {} balance in Treasury Ledger to provision Liquidity Plant.",
                        debit_res.2
                    )),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let from_unassigned = debit_res.1.parse::<f64>().unwrap_or(0.0);
            if from_unassigned > 1e-9 {
                let _ = sqlx::query(
                    "UPDATE yield_reservoirs SET streaming_balance_kas = GREATEST(0.0, streaming_balance_kas - $1), last_updated = CURRENT_TIMESTAMP WHERE LOWER(REPLACE(TRIM(wallet_address), 'kaspa:', '')) = $2 OR wallet_address = $3"
                )
                .bind(from_unassigned)
                .bind(&clean_wallet)
                .bind(&master_identity)
                .execute(&mut *tx_db)
                .await;
            }
            let mut full_tickers = vec!["KAS".to_string()];
            full_tickers.extend(secondary_order.clone());
            let normalized_pair = full_tickers.join("/");
            let weights_json_val = serde_json::to_value(&weights_map).unwrap_or_else(|_| json!({}));
            let reserves_json_val = serde_json::to_value(&reserves_map).unwrap_or_else(|_| json!({}));
            let invariant_k = crate::sor::compute_constant_mean_invariant(&reserves_map, &weights_map);
            let n_total = full_tickers.len();
            let internal_pairs_count = (n_total * n_total.saturating_sub(1)) / 2;
            let insert_res = if lock_days == 0 {
                sqlx::query(
                    r#"
                    INSERT INTO liquidity_providers
                    (wallet_address, pool_pair, staked_asset_a, staked_asset_b, weights_json, reserves_json, lock_duration_days, unlock_date)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
                    "#
                )
                .bind(&master_identity)
                .bind(&normalized_pair)
                .bind(kas_amount)
                .bind(secondary_total_b)
                .bind(&weights_json_val)
                .bind(&reserves_json_val)
                .bind(lock_days)
                .execute(&mut *tx_db)
                .await
            } else {
                sqlx::query(
                    r#"
                    INSERT INTO liquidity_providers
                    (wallet_address, pool_pair, staked_asset_a, staked_asset_b, weights_json, reserves_json, lock_duration_days, unlock_date)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP + make_interval(days => $7))
                    "#
                )
                .bind(&master_identity)
                .bind(&normalized_pair)
                .bind(kas_amount)
                .bind(secondary_total_b)
                .bind(&weights_json_val)
                .bind(&reserves_json_val)
                .bind(lock_days)
                .execute(&mut *tx_db)
                .await
            };
            if let Err(e) = insert_res {
                let _ = tx_db.rollback().await;
                let mut refund_pipe = redis::pipe();
                for (asset_tick, req_amt) in &reserves_map {
                    refund_pipe.cmd("HINCRBYFLOAT").arg(&user_ledger_key).arg(asset_tick).arg(*req_amt).ignore();
                }
                let _: Result<(), _> = refund_pipe.query_async(&mut redis_conn).await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some(format!("Database execution error during Liquidity Plant staking: {}", e)),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let _ = tx_db.commit().await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: None,
                signed_psbt_hex: None,
                data: Some(json!({
                    "poolPair": normalized_pair,
                    "weights": weights_json_val,
                    "reserves": reserves_json_val,
                    "invariantK": invariant_k,
                    "internalPairsCount": internal_pairs_count
                })),
            }));
        },
        "GET_LP_POSITIONS" => {
            let positions = sqlx::query(
                r#"
                SELECT
                    lp_id,
                    pool_pair,
                    staked_asset_a,
                    staked_asset_b,
                    weights_json,
                    reserves_json,
                    lock_duration_days,
                    unlock_date,
                    created_at,
                    (CURRENT_TIMESTAMP >= unlock_date) AS is_unlocked
                FROM liquidity_providers
                WHERE wallet_address = $1 OR wallet_address = $2
                ORDER BY created_at DESC
                "#
            )
            .bind(&master_identity)
            .bind(&clean_wallet)
            .fetch_all(&mut *tx_db)
            .await;
            let _ = tx_db.rollback().await;
            match positions {
                Ok(rows) => {
                    let list: Vec<Value> = rows.into_iter().map(|r| {
                        let lp_id: Uuid = r.get("lp_id");
                        let pool_pair: String = r.get("pool_pair");
                        let staked_a: f64 = r.get("staked_asset_a");
                        let staked_b: f64 = r.get("staked_asset_b");
                        let lock_days: i32 = r.get("lock_duration_days");
                        let unlock_date: Option<chrono::DateTime<chrono::Utc>> = r.try_get("unlock_date").ok();
                        let created_at: Option<chrono::DateTime<chrono::Utc>> = r.try_get("created_at").ok();
                        let is_unlocked: bool = r.try_get("is_unlocked").unwrap_or(true);
                        let mut weights_val: Value = r.try_get("weights_json").unwrap_or_else(|_| json!({}));
                        let mut reserves_val: Value = r.try_get("reserves_json").unwrap_or_else(|_| json!({}));
                        let parts: Vec<String> = pool_pair.split('/').map(|s| s.trim().to_uppercase()).collect();
                        if weights_val.as_object().map(|m| m.is_empty()).unwrap_or(true) {
                            let mut w_map = serde_json::Map::new();
                            w_map.insert("KAS".to_string(), json!(0.50_f64));
                            let sec_count = parts.len().saturating_sub(1).max(1);
                            for sec in parts.iter().skip(1) {
                                w_map.insert(sec.clone(), json!(0.50_f64 / (sec_count as f64)));
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
                        let mut r_hash: HashMap<String, f64> = HashMap::new();
                        let mut w_hash: HashMap<String, f64> = HashMap::new();
                        if let Some(obj) = reserves_val.as_object() {
                            for (k, v) in obj {
                                if let Some(f) = v.as_f64() {
                                    r_hash.insert(k.clone(), f);
                                }
                            }
                        }
                        if let Some(obj) = weights_val.as_object() {
                            for (k, v) in obj {
                                if let Some(f) = v.as_f64() {
                                    w_hash.insert(k.clone(), f);
                                }
                            }
                        }
                        let invariant_k = crate::sor::compute_constant_mean_invariant(&r_hash, &w_hash);
                        let n_assets = parts.len().max(2);
                        let internal_pairs_count = (n_assets * (n_assets - 1)) / 2;
                        let multiplier = match lock_days {
                            d if d >= 365 => 2.5,
                            d if d >= 90 => 1.5,
                            d if d >= 30 => 1.2,
                            _ => 1.0,
                        };
                        let weighted_tvl = staked_a * multiplier;
                        json!({
                            "lpId": lp_id.to_string(),
                            "poolPair": pool_pair,
                            "stakedAssetA": staked_a,
                            "stakedAssetB": staked_b,
                            "weights": weights_val,
                            "reserves": reserves_val,
                            "invariantK": invariant_k,
                            "internalPairsCount": internal_pairs_count,
                            "isMultiAssetPlant": parts.len() > 2,
                            "lockDurationDays": lock_days,
                            "unlockDate": unlock_date.map(|d| d.to_rfc3339()),
                            "createdAt": created_at.map(|d| d.to_rfc3339()),
                            "isUnlocked": is_unlocked,
                            "multiplier": multiplier,
                            "weightedTvl": weighted_tvl
                        })
                    }).collect();
                    return Ok(Json(ActionResponse {
                        success: true,
                        error: None,
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: Some(json!(list)),
                    }));
                },
                Err(e) => {
                    return Err(Json(ActionResponse {
                        success: false,
                        error: Some(format!("Database error fetching LP positions: {}", e)),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                }
            }
        },
        "WITHDRAW_LP" => {
            let lp_id_str = req.payload.get("lpId").and_then(|id| id.as_str()).unwrap_or("");
            let lp_uuid = match Uuid::from_str(lp_id_str) {
                Ok(u) => u,
                Err(_) => {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse {
                        success: false,
                        error: Some("Invalid LP identifier format".to_string()),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                }
            };
            let row = sqlx::query(
                r#"
                SELECT
                    lp_id,
                    pool_pair,
                    staked_asset_a,
                    staked_asset_b,
                    reserves_json,
                    lock_duration_days,
                    unlock_date,
                    (CURRENT_TIMESTAMP >= unlock_date) AS is_unlocked
                FROM liquidity_providers
                WHERE lp_id = $1 AND (wallet_address = $2 OR wallet_address = $3)
                FOR UPDATE
                "#
            )
            .bind(lp_uuid)
            .bind(&master_identity)
            .bind(&clean_wallet)
            .fetch_optional(&mut *tx_db)
            .await;
            match row {
                Ok(Some(record)) => {
                    let is_unlocked: bool = record.try_get("is_unlocked").unwrap_or(false);
                    let unlock_date: Option<chrono::DateTime<chrono::Utc>> = record.try_get("unlock_date").ok();
                    if !is_unlocked {
                        let unlock_str = unlock_date.map(|d| d.to_rfc3339()).unwrap_or_else(|| "Unknown".to_string());
                        let _ = tx_db.rollback().await;
                        return Err(Json(ActionResponse {
                            success: false,
                            error: Some(format!(
                                "EARLY_WITHDRAWAL_FORBIDDEN: Capital is timelocked until {}. Protocol-enforced supply shock active.",
                                unlock_str
                            )),
                            transaction_id: None,
                            signed_psbt_hex: None,
                            data: None,
                        }));
                    }
                    let rec_lp_id: Uuid = record.get("lp_id");
                    let pool_pair: String = record.get("pool_pair");
                    let staked_a: f64 = record.get("staked_asset_a");
                    let staked_b: f64 = record.get("staked_asset_b");
                    let reserves_val: Value = record.try_get("reserves_json").unwrap_or_else(|_| json!({}));
                    let del_res = sqlx::query("DELETE FROM liquidity_providers WHERE lp_id = $1")
                        .bind(rec_lp_id)
                        .execute(&mut *tx_db)
                        .await;
                    if let Err(e) = del_res {
                        let _ = tx_db.rollback().await;
                        return Err(Json(ActionResponse {
                            success: false,
                            error: Some(format!("Failed to execute LP withdrawal: {}", e)),
                            transaction_id: None,
                            signed_psbt_hex: None,
                            data: None,
                        }));
                    }
                    let mut credits: Vec<(String, f64)> = Vec::new();
                    if let Some(obj) = reserves_val.as_object() {
                        for (k, v) in obj {
                            if let Some(amt) = v.as_f64() {
                                if amt > 0.0 {
                                    credits.push((k.trim().to_uppercase(), amt));
                                }
                            }
                        }
                    }
                    if credits.is_empty() {
                        let pair_parts: Vec<&str> = pool_pair.split('/').collect();
                        let asset_a = pair_parts.first().copied().unwrap_or("KAS").to_uppercase();
                        let asset_b = pair_parts.get(1).copied().unwrap_or("USDC").to_uppercase();
                        credits.push((asset_a, staked_a));
                        credits.push((asset_b, staked_b));
                    }
                    let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
                    let mut pipe = redis::pipe();
                    pipe.atomic();
                    for (asset_tick, amt) in &credits {
                        pipe.cmd("HINCRBYFLOAT").arg(&user_ledger_key).arg(asset_tick).arg(*amt).ignore();
                    }
                    if let Err(e) = pipe.query_async::<_, ()>(&mut redis_conn).await {
                        let _ = tx_db.rollback().await;
                        return Err(Json(ActionResponse {
                            success: false,
                            error: Some(format!("Redis ledger credit failed during LP withdrawal (position preserved): {}", e)),
                            transaction_id: None,
                            signed_psbt_hex: None,
                            data: None,
                        }));
                    }
                    if let Err(e) = tx_db.commit().await {
                        let mut revert_pipe = redis::pipe();
                        revert_pipe.atomic();
                        for (asset_tick, amt) in &credits {
                            revert_pipe.cmd("HINCRBYFLOAT").arg(&user_ledger_key).arg(asset_tick).arg(-(*amt)).ignore();
                        }
                        let _: Result<(), _> = revert_pipe.query_async(&mut redis_conn).await;
                        return Err(Json(ActionResponse {
                            success: false,
                            error: Some(format!("Database commit failed during LP withdrawal: {}", e)),
                            transaction_id: None,
                            signed_psbt_hex: None,
                            data: None,
                        }));
                    }
                    return Ok(Json(ActionResponse {
                        success: true,
                        error: None,
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                },
                Ok(None) => {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse {
                        success: false,
                        error: Some("LP position not found or ownership mismatch".to_string()),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                },
                Err(e) => {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse {
                        success: false,
                        error: Some(format!("Database error querying LP record: {}", e)),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                }
            }
        },
        _ => {}
    }
    let save_res = sqlx::query(
        "INSERT INTO user_command_centers (wallet_address, layout_state, last_updated)
         VALUES ($1, $2, CURRENT_TIMESTAMP)
         ON CONFLICT (wallet_address) DO UPDATE SET layout_state = EXCLUDED.layout_state, last_updated = CURRENT_TIMESTAMP"
    )
    .bind(&master_identity)
    .bind(&state)
    .execute(&mut *tx_db)
    .await;
    if let Err(e) = save_res {
        let _ = tx_db.rollback().await;
        return Err(Json(ActionResponse { success: false, error: Some(e.to_string()), transaction_id: None, signed_psbt_hex: None, data: None }));
    }
    let _ = sqlx::query("DELETE FROM user_command_centers WHERE wallet_address = $1")
        .bind(&clean_wallet)
        .execute(&mut *tx_db)
        .await;
    let _ = tx_db.commit().await;
    let update_payload = json!({
        "layout_state_update": true,
        "wallet": master_identity,
        "state": state
    });
    let _: () = redis::cmd("PUBLISH")
        .arg("telemetry:updates")
        .arg(update_payload.to_string())
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(());
    Ok(Json(ActionResponse {
        success: true,
        error: None,
        transaction_id: None,
        signed_psbt_hex: None,
        data: Some(state),
    }))
}