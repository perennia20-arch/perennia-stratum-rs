use chrono::Utc;
use serde_json::{json, Map, Value};
use sqlx::{PgPool, Row};
use std::collections::{HashMap, HashSet};
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CORE_POOL_BUCKET_ASSETS: &[&str] = &[
    "USDC", "USDT", "USD", "BTC", "ETH", "SOL", "SILO", "XRP", "DOGE", "POL", "AVAX", "SUI",
    "TRX", "ZEC", "ARB", "BASE", "NVDA", "SPY", "XAU",
];

fn lock_multiplier_for_days(days: i32) -> f64 {
    if days >= 365 {
        2.5
    } else if days >= 90 {
        1.5
    } else if days >= 30 {
        1.2
    } else {
        1.0
    }
}

pub async fn start_delta_netting_engine(redis_client: redis::Client, pool: PgPool) {
    tracing::info!("⚡ [CHRONOS NETTING] Delta Netting, Live ChangeNOW Bucket Telemetry & 50%-KAS LP Invariant Engine Armed.");
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        if let Err(e) = run_delta_netting_cycle(&redis_client, &pool).await {
            tracing::warn!("⚠️ [CHRONOS NETTING] Cycle warning: {}", e);
        }
    }
}

pub async fn publish_live_epoch_bucket_telemetry(
    pool: &PgPool,
    kas_spot_usd: f64,
) -> anyhow::Result<Value> {
    let safe_kas_spot = if kas_spot_usd.is_finite() && kas_spot_usd > 0.0 {
        kas_spot_usd
    } else {
        crate::fiat_rails::resolve_live_spot_price(pool, "KAS")
            .await
            .unwrap_or(0.15)
            .max(0.01)
    };

    let cc_rows = sqlx::query(
        r#"
        SELECT wallet_address, layout_state
        FROM user_command_centers
        "#,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut pending_kas_by_asset: HashMap<String, f64> = HashMap::new();
    let mut participants_by_asset: HashMap<String, HashSet<String>> = HashMap::new();
    let mut discovered_tickers: HashSet<String> = CORE_POOL_BUCKET_ASSETS
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    for row in &cc_rows {
        let wallet: String = row.try_get("wallet_address").unwrap_or_default();
        let layout: Value = row
            .try_get("layout_state")
            .unwrap_or_else(|_| json!({ "sectors": [] }));
        if let Some(sectors) = layout.get("sectors").and_then(|v| v.as_array()) {
            for sec in sectors {
                let alloc_pct = sec
                    .get("allocationPercentage")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let sec_pending_kas = sec
                    .get("pendingKaspa")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    .max(0.0);
                if alloc_pct <= 0.0 && sec_pending_kas <= 0.0 {
                    continue;
                }
                if let Some(target_assets) = sec
                    .get("settlementConfig")
                    .and_then(|c| c.get("targetAssets"))
                    .and_then(|v| v.as_array())
                {
                    if target_assets.len() >= 2 {
                        for leg in target_assets {
                            let tick = leg
                                .get("ticker")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .trim()
                                .to_uppercase();
                            if tick.is_empty() || tick == "KAS" {
                                continue;
                            }
                            discovered_tickers.insert(tick.clone());
                            let leg_weight_ratio = (leg
                                .get("weightPct")
                                .and_then(|v| v.as_f64())
                                .unwrap_or(50.0)
                                .max(0.0))
                                / 100.0;
                            let leg_kas = sec_pending_kas * leg_weight_ratio;
                            *pending_kas_by_asset.entry(tick.clone()).or_insert(0.0) += leg_kas;
                            if !wallet.is_empty() {
                                participants_by_asset
                                    .entry(tick)
                                    .or_default()
                                    .insert(wallet.clone());
                            }
                        }
                        continue;
                    }
                }
                let primary_tick = sec
                    .get("settlementConfig")
                    .and_then(|c| c.get("targetAsset"))
                    .and_then(|t| t.get("ticker"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_uppercase();
                if !primary_tick.is_empty() && primary_tick != "KAS" {
                    discovered_tickers.insert(primary_tick.clone());
                    *pending_kas_by_asset
                        .entry(primary_tick.clone())
                        .or_insert(0.0) += sec_pending_kas;
                    if !wallet.is_empty() {
                        participants_by_asset
                            .entry(primary_tick)
                            .or_default()
                            .insert(wallet.clone());
                    }
                }
            }
        }
    }

    let lp_rows = sqlx::query(
        r#"
        SELECT pool_pair, COALESCE(SUM(staked_asset_a), 0.0) AS total_kas_a
        FROM liquidity_providers
        GROUP BY pool_pair
        "#,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut lp_kas_by_asset: HashMap<String, f64> = HashMap::new();
    for r in lp_rows {
        let pair: String = r.try_get("pool_pair").unwrap_or_default();
        let kas_a: f64 = r.try_get::<f64, _>("total_kas_a").unwrap_or(0.0_f64).max(0.0_f64);
        for part in pair.split('/') {
            let clean = part.trim().to_uppercase();
            if !clean.is_empty() && clean != "KAS" {
                *lp_kas_by_asset.entry(clean).or_insert(0.0) += kas_a;
            }
        }
    }

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (current_epoch_bell_ts, next_epoch_bell_ts, seconds_remaining) =
        crate::chronos::compute_jerusalem_epoch_window(now_secs);

    let mut buckets_map = Map::new();
    for ticker in discovered_tickers {
        let pending_kas = pending_kas_by_asset.get(&ticker).copied().unwrap_or(0.0);
        let pending_usd = ((pending_kas * safe_kas_spot) * 100.0).round() / 100.0;
        let (min_profitable_kas, min_profitable_usd) =
            crate::fiat_rails::resolve_live_profitable_bucket_threshold(
                pool,
                &ticker,
                safe_kas_spot,
            )
            .await;
        let weight_pct = if min_profitable_kas > 0.0 {
            ((pending_kas / min_profitable_kas) * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        };
        let participant_count = participants_by_asset
            .get(&ticker)
            .map(|s| s.len())
            .unwrap_or(0);
        let lp_avail_kas = lp_kas_by_asset
            .get(&ticker)
            .copied()
            .filter(|&v| v > 0.0)
            .unwrap_or(5_000.0);
        let lp_coverage_pct = if pending_kas > 0.0 {
            ((lp_avail_kas / pending_kas) * 100.0).clamp(0.0, 100.0)
        } else {
            100.0
        };
        let status = if weight_pct >= 100.0 {
            "READY_FOR_BELL"
        } else if pending_kas > 0.0 {
            "FILLING"
        } else {
            "IDLE"
        };
        let rail_cost_usd = if ticker == "USD" { 0.25 } else { 0.0 };

        buckets_map.insert(
            ticker.clone(),
            json!({
                "asset": ticker,
                "pendingKas": (pending_kas * 10000.0).round() / 10000.0,
                "pendingUsd": pending_usd,
                "minProfitableKas": min_profitable_kas,
                "minProfitableUsd": min_profitable_usd,
                "weightPct": (weight_pct * 100.0).round() / 100.0,
                "participantCount": participant_count,
                "lpAvailableKasCapacity": lp_avail_kas,
                "lpCoveragePct": (lp_coverage_pct * 10.0).round() / 10.0,
                "effectiveSpreadFloorPct": 0.10,
                "railCostUsd": rail_cost_usd,
                "status": status,
                "lastClearedAt": current_epoch_bell_ts,
                "lastClearType": "ANCHOR_OR_EPOCH"
            }),
        );
    }

    let epoch_state = json!({
        "anchorUtcHour": 22,
        "anchorLabel": "22:00 UTC Global Settlement",
        "currentEpochBellTs": current_epoch_bell_ts,
        "nextEpochBellTs": next_epoch_bell_ts,
        "secondsRemaining": seconds_remaining,
        "volatilitySweepThresholdPct": 450,
        "updatedAt": now_secs,
        "buckets": Value::Object(buckets_map)
    });

    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let serialized = epoch_state.to_string();
                let _: redis::RedisResult<()> = redis::cmd("SET")
                    .arg("perennia:settlement:epoch_telemetry")
                    .arg(&serialized)
                    .query_async(&mut conn)
                    .await;
                let sse_msg = json!({
                    "epoch_telemetry_update": true,
                    "epoch": epoch_state
                });
                let _: redis::RedisResult<()> = redis::cmd("PUBLISH")
                    .arg("telemetry:updates")
                    .arg(sse_msg.to_string())
                    .query_async(&mut conn)
                    .await;
            }
        }
    }

    Ok(epoch_state)
}

pub async fn sweep_layered_buckets_on_anchor_order(
    pool: &PgPool,
    target_asset: &str,
    anchor_kas_volume: f64,
    kas_spot_usd: f64,
    target_spot_usd: f64,
) -> anyhow::Result<Value> {
    let clean_target = target_asset.trim().to_uppercase();
    if clean_target.is_empty()
        || clean_target == "KAS"
        || clean_target == "USD"
        || kas_spot_usd <= 0.0
        || target_spot_usd <= 0.0
    {
        return Ok(json!({
            "layeredBucketsCleared": 0,
            "layeredKasSwept": 0.0,
            "layeredTokensDispatched": 0.0
        }));
    }

    let (min_profitable_kas, _) =
        crate::fiat_rails::resolve_live_profitable_bucket_threshold(pool, &clean_target, kas_spot_usd)
            .await;

    let rows = sqlx::query(
        r#"
        SELECT wallet_address, layout_state
        FROM user_command_centers
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut total_pending_bucket_kas = 0.0_f64;
    for r in &rows {
        let layout: Value = r
            .try_get("layout_state")
            .unwrap_or_else(|_| json!({ "sectors": [] }));
        if let Some(sectors) = layout.get("sectors").and_then(|v| v.as_array()) {
            for sec in sectors {
                let pending = sec
                    .get("pendingKaspa")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    .max(0.0);
                if pending <= 0.0 {
                    continue;
                }
                let route_mode = sec
                    .get("routeMode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("hold")
                    .to_lowercase();
                if route_mode == "auto-lp" {
                    continue;
                }
                let sec_ticker = sec
                    .get("settlementConfig")
                    .and_then(|c| c.get("targetAsset"))
                    .and_then(|t| t.get("ticker"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_uppercase();
                if sec_ticker == clean_target {
                    total_pending_bucket_kas += pending;
                }
            }
        }
    }

    // Combined Anchor + Layer volume must clear the live ChangeNOW profitable minimum
    if total_pending_bucket_kas <= 1e-6
        || (anchor_kas_volume + total_pending_bucket_kas) + 1e-6 < min_profitable_kas
    {
        return Ok(json!({
            "layeredBucketsCleared": 0,
            "layeredKasSwept": 0.0,
            "layeredTokensDispatched": 0.0,
            "minProfitableKas": min_profitable_kas
        }));
    }

    let mut cleared_count = 0usize;
    let mut swept_kas_total = 0.0_f64;
    let mut dispatched_tokens_total = 0.0_f64;
    let mut total_protocol_fees_usd = 0.0_f64;

    for row in rows {
        let raw_wallet: String = row.try_get("wallet_address").unwrap_or_default();
        let clean_wallet = raw_wallet
            .trim()
            .to_lowercase()
            .replace("kaspa:", "")
            .trim()
            .to_string();
        if clean_wallet.is_empty() {
            continue;
        }
        let prefixed_wallet = format!("kaspa:{}", clean_wallet);
        let mut layout: Value = row
            .try_get("layout_state")
            .unwrap_or_else(|_| json!({ "sectors": [] }));
        let mut user_swept_kas = 0.0_f64;
        let mut mutated = false;

        if let Some(sectors) = layout.get_mut("sectors").and_then(|v| v.as_array_mut()) {
            for sec in sectors.iter_mut() {
                let pending = sec
                    .get("pendingKaspa")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    .max(0.0);
                if pending <= 0.0 {
                    continue;
                }
                let route_mode = sec
                    .get("routeMode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("hold")
                    .to_lowercase();
                if route_mode == "auto-lp" {
                    continue;
                }
                let sec_ticker = sec
                    .get("settlementConfig")
                    .and_then(|c| c.get("targetAsset"))
                    .and_then(|t| t.get("ticker"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_uppercase();
                if sec_ticker == clean_target {
                    user_swept_kas += pending;
                    sec["pendingKaspa"] = json!(0.0);
                    mutated = true;
                    cleared_count += 1;
                }
            }
        }

        if mutated && user_swept_kas > 0.0 {
            let (user_fee_floor_rate, _, _) =
                crate::fiat_rails::resolve_wallet_swap_fee_floor_pct(pool, &prefixed_wallet).await;
            let effective_fee_rate = user_fee_floor_rate.max(crate::fiat_rails::HARD_PROFIT_FLOOR_PCT);
            let gross_usd = user_swept_kas * kas_spot_usd;
            let fee_usd = (gross_usd * effective_fee_rate).max(0.01);
            let net_usd = (gross_usd - fee_usd).max(0.0);
            if net_usd <= 0.0 {
                continue;
            }
            let out_tokens = ((net_usd / target_spot_usd) * 100_000_000.0).round() / 100_000_000.0;
            if out_tokens <= 0.0 {
                continue;
            }

            if crate::state_api::credit_user_token_balance(
                pool,
                &clean_wallet,
                &prefixed_wallet,
                &clean_target,
                out_tokens,
                false,
            )
            .await
            .is_ok()
            {
                let _ = sqlx::query(
                    r#"
                    UPDATE user_command_centers
                    SET layout_state = $2,
                        last_updated = CURRENT_TIMESTAMP
                    WHERE wallet_address = $1
                    "#,
                )
                .bind(&raw_wallet)
                .bind(&layout)
                .execute(pool)
                .await;

                let tx_ref = format!(
                    "ANCHOR-LAYER-{}-{}",
                    clean_target,
                    &uuid::Uuid::new_v4().simple().to_string().to_uppercase()[..8]
                );
                let _ = crate::sor::record_hifo_acquisition_lot(
                    pool,
                    &clean_wallet,
                    &clean_target,
                    out_tokens,
                    target_spot_usd,
                    "ANCHOR_LAYER_BUCKET_SWEEP",
                    Some(&tx_ref),
                )
                .await;

                let _ = sqlx::query(
                    r#"
                    INSERT INTO tax_ledger_events (
                        wallet_address, asset_ticker, event_type, gross_proceeds_usd,
                        amount_tokens, spot_price_at_execution, tx_hash, cost_basis_usd,
                        realized_gain_loss_usd, holding_period
                    ) VALUES ($1, $2, 'ANCHOR_LAYER_BUCKET_SWEEP', $3, $4, $5, $6, $3, 0.0, 'SHORT_TERM')
                    "#,
                )
                .bind(&clean_wallet)
                .bind(&clean_target)
                .bind(net_usd)
                .bind(out_tokens)
                .bind(target_spot_usd)
                .bind(&tx_ref)
                .execute(pool)
                .await;

                swept_kas_total += user_swept_kas;
                dispatched_tokens_total += out_tokens;
                total_protocol_fees_usd += fee_usd;

                if let Ok(redis_url) = env::var("REDIS_URL") {
                    if let Ok(client) = redis::Client::open(redis_url) {
                        if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                            if let Some(sectors_val) = layout.get("sectors") {
                                let yield_evt = json!({
                                    "wallet": clean_wallet,
                                    "yield_update": true,
                                    "sectors": sectors_val
                                });
                                let _: redis::RedisResult<()> = redis::cmd("PUBLISH")
                                    .arg("telemetry:updates")
                                    .arg(yield_evt.to_string())
                                    .query_async(&mut conn)
                                    .await;
                            }
                        }
                    }
                }
            }
        }
    }

    if total_protocol_fees_usd > 0.0 {
        if let Ok(redis_url) = env::var("REDIS_URL") {
            if let Ok(client) = redis::Client::open(redis_url) {
                if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                    let _: redis::RedisResult<()> = redis::cmd("INCRBYFLOAT")
                        .arg("perennia:treasury:netting_profit_usd")
                        .arg(total_protocol_fees_usd)
                        .query_async(&mut conn)
                        .await;
                    let _: redis::RedisResult<()> = redis::cmd("INCRBYFLOAT")
                        .arg("perennia:fees:batch_accumulated:USDC")
                        .arg(total_protocol_fees_usd)
                        .query_async(&mut conn)
                        .await;
                }
            }
        }
    }

    let _ = publish_live_epoch_bucket_telemetry(pool, kas_spot_usd).await;

    Ok(json!({
        "targetAsset": clean_target,
        "layeredBucketsCleared": cleared_count,
        "layeredKasSwept": (swept_kas_total * 10000.0).round() / 10000.0,
        "layeredTokensDispatched": (dispatched_tokens_total * 100_000_000.0).round() / 100_000_000.0,
        "protocolFeesCapturedUsd": (total_protocol_fees_usd * 10000.0).round() / 10000.0,
        "minProfitableKas": min_profitable_kas
    }))
}

pub async fn run_delta_netting_cycle(
    redis_client: &redis::Client,
    pool: &PgPool,
) -> anyhow::Result<()> {
    let Ok(mut redis_conn) = redis_client.get_multiplexed_async_connection().await else {
        return Ok(());
    };
    let Ok(kas_spot_usd) = crate::fiat_rails::resolve_live_spot_price(pool, "KAS").await else {
        return Ok(());
    };
    if !kas_spot_usd.is_finite() || kas_spot_usd <= 0.0 {
        return Ok(());
    }

    // Publish live ChangeNOW profitable bucket thresholds & pending weights to Redis
    let _ = publish_live_epoch_bucket_telemetry(pool, kas_spot_usd).await;

    let mut queued_orders: Vec<Value> = Vec::new();
    for _ in 0..100 {
        let item_opt: Option<String> = redis::cmd("LPOP")
            .arg("perennia:sor:netting_queue")
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(None);
        let Some(raw_str) = item_opt else {
            break;
        };
        if let Ok(parsed) = serde_json::from_str::<Value>(&raw_str) {
            queued_orders.push(parsed);
        }
    }
    if !queued_orders.is_empty() {
        let mut total_buy_kas = 0.0_f64;
        let mut total_sell_kas = 0.0_f64;
        let mut captured_fees_usd = 0.0_f64;
        for ord in &queued_orders {
            let dir = ord
                .get("direction")
                .and_then(|v| v.as_str())
                .unwrap_or("SELL_KAS");
            let amt_kas = ord
                .get("amount_kas")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0)
                .max(0.0);
            let fee_usd = ord
                .get("fee_captured_usd")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0)
                .max(0.0);
            if dir.eq_ignore_ascii_case("BUY_KAS") {
                total_buy_kas += amt_kas;
            } else {
                total_sell_kas += amt_kas;
            }
            captured_fees_usd += fee_usd;
        }
        let matched_internal_kas = total_buy_kas.min(total_sell_kas);
        let spread_saved_usd = matched_internal_kas * kas_spot_usd * 0.005;
        let total_cycle_profit_usd = captured_fees_usd + spread_saved_usd;
        if total_cycle_profit_usd > 0.0 {
            let _: redis::RedisResult<()> = redis::cmd("INCRBYFLOAT")
                .arg("perennia:treasury:netting_profit_usd")
                .arg(total_cycle_profit_usd)
                .query_async(&mut redis_conn)
                .await;
        }
    }
    let min_dark_pool_usd: f64 = env::var("MIN_DARK_POOL_POSITION_USD")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|&v| v >= 1.0)
        .unwrap_or(5.00);
    let house_usdc_fees: f64 = redis::cmd("GET")
        .arg("perennia:fees:batch_accumulated:USDC")
        .query_async::<_, Option<String>>(&mut redis_conn)
        .await
        .ok()
        .flatten()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);
    if house_usdc_fees >= min_dark_pool_usd {
        if let Ok(master_wallet) = crate::chronos::resolve_master_treasury_prefixed() {
            let half_usd = house_usdc_fees * 0.5;
            let kas_leg = half_usd / kas_spot_usd;
            let usdc_leg = half_usd;
            let existing_house_lp = sqlx::query(
                r#"
                SELECT lp_id::text AS lp_id, staked_asset_a, staked_asset_b
                FROM liquidity_providers
                WHERE wallet_address = $1
                  AND pool_pair = 'KAS/USDC'
                  AND lock_duration_days = 365
                ORDER BY created_at ASC
                LIMIT 1
                "#,
            )
            .bind(&master_wallet)
            .fetch_optional(pool)
            .await?;
            if let Some(row) = existing_house_lp {
                let lp_id: String = row.try_get("lp_id").unwrap_or_default();
                let next_a = row.try_get::<f64, _>("staked_asset_a").unwrap_or(0.0) + kas_leg;
                let next_b = row.try_get::<f64, _>("staked_asset_b").unwrap_or(0.0) + usdc_leg;
                let reserves_json = json!({ "KAS": next_a, "USDC": next_b });
                let _ = sqlx::query(
                    r#"
                    UPDATE liquidity_providers
                    SET staked_asset_a = $2,
                        staked_asset_b = $3,
                        reserves_json = $4,
                        last_yield_distribution = CURRENT_TIMESTAMP
                    WHERE lp_id::text = $1
                    "#,
                )
                .bind(&lp_id)
                .bind(next_a)
                .bind(next_b)
                .bind(&reserves_json)
                .execute(pool)
                .await;
            } else {
                let weights_json = json!({ "KAS": 0.5, "USDC": 0.5 });
                let reserves_json = json!({ "KAS": kas_leg, "USDC": usdc_leg });
                let _ = sqlx::query(
                    r#"
                    INSERT INTO liquidity_providers (
                        wallet_address, pool_pair, staked_asset_a, staked_asset_b,
                        weights_json, reserves_json, lock_duration_days,
                        unlock_date
                    ) VALUES (
                        $1, 'KAS/USDC', $2, $3, $4, $5, 365,
                        CURRENT_TIMESTAMP + INTERVAL '365 days'
                    )
                    "#,
                )
                .bind(&master_wallet)
                .bind(kas_leg)
                .bind(usdc_leg)
                .bind(&weights_json)
                .bind(&reserves_json)
                .execute(pool)
                .await;
            }
            let _: redis::RedisResult<()> = redis::cmd("SET")
                .arg("perennia:fees:batch_accumulated:USDC")
                .arg("0")
                .query_async(&mut redis_conn)
                .await;
        }
    }
    let lp_rows = sqlx::query(
        r#"
        SELECT lp_id::text AS lp_id, wallet_address, pool_pair,
               staked_asset_a, staked_asset_b, lock_duration_days
        FROM liquidity_providers
        "#,
    )
    .fetch_all(pool)
    .await?;
    if lp_rows.is_empty() {
        return Ok(());
    }
    let mut pair_weights: HashMap<String, f64> = HashMap::new();
    let mut lp_entries: Vec<(String, String, String, f64)> = Vec::with_capacity(lp_rows.len());
    for r in &lp_rows {
        let lp_id: String = r.try_get("lp_id").unwrap_or_default();
        let wallet: String = r.try_get("wallet_address").unwrap_or_default();
        let pair: String = r
            .try_get("pool_pair")
            .unwrap_or_else(|_| "KAS/USDC".to_string());
        let amt_a: f64 = r.try_get("staked_asset_a").unwrap_or(0.0_f64).max(0.0_f64);
        let days: i32 = r.try_get("lock_duration_days").unwrap_or(0);
        let weighted_kas = amt_a * lock_multiplier_for_days(days);
        if weighted_kas > 0.0 && !wallet.trim().is_empty() {
            *pair_weights.entry(pair.clone()).or_insert(0.0) += weighted_kas;
            lp_entries.push((lp_id, wallet, pair, weighted_kas));
        }
    }
    for (pair, total_pair_weight) in pair_weights {
        if total_pair_weight <= 0.0 {
            continue;
        }
        let pending_key = format!("perennia:lp:pending_yield_usd:{}", pair);
        let pending_usd: f64 = redis::cmd("GET")
            .arg(&pending_key)
            .query_async::<_, Option<String>>(&mut redis_conn)
            .await
            .ok()
            .flatten()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);
        if pending_usd < 0.05 {
            continue;
        }
        let _: redis::RedisResult<()> = redis::cmd("SET")
            .arg(&pending_key)
            .arg("0")
            .query_async(&mut redis_conn)
            .await;
        let total_yield_kas = pending_usd / kas_spot_usd;
        for (lp_id, wallet, lp_pair, weight) in &lp_entries {
            if *lp_pair != pair {
                continue;
            }
            let share_kas = total_yield_kas * (*weight / total_pair_weight);
            if share_kas <= 1e-6 {
                continue;
            }
            let clean_w = wallet
                .trim()
                .to_lowercase()
                .replace("kaspa:", "")
                .trim()
                .to_string();
            let pref_w = format!("kaspa:{}", clean_w);
            if crate::state_api::credit_user_token_balance(
                pool,
                &clean_w,
                &pref_w,
                "KAS",
                share_kas,
                true,
            )
            .await
            .is_ok()
            {
                let _ = sqlx::query(
                    "UPDATE liquidity_providers SET last_yield_distribution = CURRENT_TIMESTAMP WHERE lp_id::text = $1",
                )
                .bind(lp_id)
                .execute(pool)
                .await;
            }
        }
    }
    Ok(())
}

pub async fn execute_epoch_delta_netting_and_lp_compounding(
    pool: &PgPool,
) -> anyhow::Result<Value> {
    let kas_spot_usd = crate::fiat_rails::resolve_live_spot_price(pool, "KAS")
        .await
        .map_err(|e| anyhow::anyhow!("Epoch netting aborted (fail-closed): {}", e))?;
    let rows = sqlx::query(
        r#"
        SELECT wallet_address, layout_state
        FROM user_command_centers
        "#,
    )
    .fetch_all(pool)
    .await?;
    let mut settled_sectors_count = 0usize;
    let mut total_swept_kas = 0.0_f64;
    for row in rows {
        let raw_wallet: String = row.try_get("wallet_address").unwrap_or_default();
        let clean_wallet = raw_wallet
            .trim()
            .to_lowercase()
            .replace("kaspa:", "")
            .trim()
            .to_string();
        if clean_wallet.is_empty() {
            continue;
        }
        let prefixed_wallet = format!("kaspa:{}", clean_wallet);
        let (user_fee_floor_rate, _, _) =
            crate::fiat_rails::resolve_wallet_swap_fee_floor_pct(pool, &prefixed_wallet).await;
        let effective_swap_fee_rate =
            user_fee_floor_rate.max(crate::fiat_rails::HARD_PROFIT_FLOOR_PCT);

        let mut layout: Value = row
            .try_get("layout_state")
            .unwrap_or_else(|_| json!({ "workers": [], "sectors": [] }));
        let mut wallet_credited_kas = 0.0_f64;
        let mut layout_mutated = false;
        if let Some(sectors) = layout.get_mut("sectors").and_then(|v| v.as_array_mut()) {
            for sec in sectors.iter_mut() {
                let pending = sec
                    .get("pendingKaspa")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                if pending <= 0.0 {
                    continue;
                }
                let route_mode = sec
                    .get("routeMode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("hold")
                    .to_lowercase();
                let target_ticker = sec
                    .get("settlementConfig")
                    .and_then(|c| c.get("targetAsset"))
                    .and_then(|t| t.get("ticker"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("KAS")
                    .trim()
                    .to_uppercase();
                if route_mode == "auto-lp" {
                    let secondary_ticker = if target_ticker == "KAS" || target_ticker.is_empty() {
                        "USDC".to_string()
                    } else {
                        target_ticker.clone()
                    };
                    let Ok(secondary_spot_usd) =
                        crate::fiat_rails::resolve_live_spot_price(pool, &secondary_ticker).await
                    else {
                        tracing::warn!(
                            "⚠️ [EPOCH NETTING] Skipping auto-lp sector for {} (KAS/{}): live oracle for {} is offline.",
                            prefixed_wallet,
                            secondary_ticker,
                            secondary_ticker
                        );
                        continue;
                    };
                    if secondary_spot_usd <= 0.0 {
                        continue;
                    }
                    let kas_leg = pending * 0.5;
                    let converted_leg_gross_usd = kas_leg * kas_spot_usd;
                    let protocol_fee_usd =
                        (converted_leg_gross_usd * effective_swap_fee_rate).max(0.01);
                    let converted_leg_net_usd =
                        (converted_leg_gross_usd - protocol_fee_usd).max(0.0);
                    let secondary_leg = converted_leg_net_usd / secondary_spot_usd;
                    if secondary_leg <= 0.0 {
                        continue;
                    }
                    let pair_name = format!("KAS/{}", secondary_ticker);
                    let weights_json = json!({
                        "KAS": 0.5,
                        secondary_ticker.clone(): 0.5
                    });
                    let reserves_json = json!({
                        "KAS": kas_leg,
                        secondary_ticker: secondary_leg
                    });
                    let _ = sqlx::query(
                        r#"
                        INSERT INTO liquidity_providers (
                            wallet_address, pool_pair, staked_asset_a, staked_asset_b,
                            weights_json, reserves_json, lock_duration_days,
                            unlock_date
                        ) VALUES (
                            $1, $2, $3, $4, $5, $6, 30,
                            CURRENT_TIMESTAMP + INTERVAL '30 days'
                        )
                        "#,
                    )
                    .bind(&prefixed_wallet)
                    .bind(&pair_name)
                    .bind(kas_leg)
                    .bind(secondary_leg)
                    .bind(&weights_json)
                    .bind(&reserves_json)
                    .execute(pool)
                    .await;
                } else if (route_mode == "swap" || route_mode == "convert")
                    && target_ticker != "KAS"
                    && !target_ticker.is_empty()
                {
                    let (min_profitable_kas, _) =
                        crate::fiat_rails::resolve_live_profitable_bucket_threshold(
                            pool,
                            &target_ticker,
                            kas_spot_usd,
                        )
                        .await;
                    if pending + 1e-6 < min_profitable_kas {
                        // Keep filling in bucket until threshold or incoming DEX Anchor order clears it
                        continue;
                    }
                    let Ok(target_spot_usd) =
                        crate::fiat_rails::resolve_live_spot_price(pool, &target_ticker).await
                    else {
                        tracing::warn!(
                            "⚠️ [EPOCH NETTING] Skipping swap sector for {} ({}): live oracle offline.",
                            prefixed_wallet,
                            target_ticker
                        );
                        continue;
                    };
                    if target_spot_usd <= 0.0 {
                        continue;
                    }
                    let gross_usd = pending * kas_spot_usd;
                    let fee_usd = (gross_usd * effective_swap_fee_rate).max(0.01);
                    let net_usd = (gross_usd - fee_usd).max(0.0);
                    if net_usd <= 0.0 {
                        continue;
                    }
                    let mut out_tokens = net_usd / target_spot_usd;
                    if target_ticker != "SILO" && target_ticker != "USDC" {
                        if let Ok(cn_net) = crate::fiat_rails::fetch_changenow_estimated_amount(
                            "USDC",
                            &target_ticker,
                            net_usd,
                        )
                        .await
                        {
                            if cn_net > 0.0 {
                                out_tokens = out_tokens.min(cn_net);
                            }
                        }
                    }
                    if out_tokens <= 0.0 {
                        continue;
                    }
                    if crate::state_api::credit_user_token_balance(
                        pool,
                        &clean_wallet,
                        &prefixed_wallet,
                        &target_ticker,
                        out_tokens,
                        false,
                    )
                    .await
                    .is_err()
                    {
                        continue;
                    }
                    let _ = crate::sor::record_hifo_acquisition_lot(
                        pool,
                        &clean_wallet,
                        &target_ticker,
                        out_tokens,
                        target_spot_usd,
                        "EPOCH_BELL_SWAP",
                        None,
                    )
                    .await;
                    let _ = sqlx::query(
                        r#"
                        INSERT INTO tax_ledger_events (
                            wallet_address, asset_ticker, event_type, gross_proceeds_usd,
                            amount_tokens, spot_price_at_execution, cost_basis_usd,
                            realized_gain_loss_usd, holding_period
                        ) VALUES ($1, $2, 'EPOCH_BELL_SWAP', $3, $4, $5, $3, 0.0, 'SHORT_TERM')
                        "#,
                    )
                    .bind(&clean_wallet)
                    .bind(&target_ticker)
                    .bind(net_usd)
                    .bind(out_tokens)
                    .bind(target_spot_usd)
                    .execute(pool)
                    .await;
                } else {
                    wallet_credited_kas += pending;
                }
                sec["pendingKaspa"] = json!(0.0);
                layout_mutated = true;
                settled_sectors_count += 1;
                total_swept_kas += pending;
            }
        }
        if wallet_credited_kas > 0.0 {
            if let Err(e) = crate::state_api::credit_user_token_balance(
                pool,
                &clean_wallet,
                &prefixed_wallet,
                "KAS",
                wallet_credited_kas,
                true,
            )
            .await
            {
                tracing::error!(
                    "❌ [EPOCH NETTING] Failed to credit signed yield reservoir for {}: {}",
                    prefixed_wallet,
                    e
                );
                continue;
            }
            let _ = crate::sor::record_hifo_acquisition_lot(
                pool,
                &clean_wallet,
                "KAS",
                wallet_credited_kas,
                kas_spot_usd,
                "EPOCH_BELL_YIELD",
                None,
            )
            .await;
            let gross_usd = wallet_credited_kas * kas_spot_usd;
            let _ = sqlx::query(
                r#"
                INSERT INTO tax_ledger_events (
                    wallet_address, asset_ticker, event_type, gross_proceeds_usd,
                    amount_tokens, spot_price_at_execution, cost_basis_usd,
                    realized_gain_loss_usd, holding_period
                ) VALUES ($1, 'KAS', 'YIELD', $2, $3, $4, $2, 0.0, 'SHORT_TERM')
                "#,
            )
            .bind(&clean_wallet)
            .bind(gross_usd)
            .bind(wallet_credited_kas)
            .bind(kas_spot_usd)
            .execute(pool)
            .await;
        }
        if layout_mutated {
            let _ = sqlx::query(
                r#"
                UPDATE user_command_centers
                SET layout_state = $2,
                    last_updated = CURRENT_TIMESTAMP
                WHERE wallet_address = $1
                "#,
            )
            .bind(&raw_wallet)
            .bind(&layout)
            .execute(pool)
            .await;
        }
    }

    let epoch_telemetry = publish_live_epoch_bucket_telemetry(pool, kas_spot_usd)
        .await
        .unwrap_or_else(|_| json!({}));

    Ok(json!({
        "settledSectorsCount": settled_sectors_count,
        "totalSweptKas": total_swept_kas,
        "executionKasSpotUsd": kas_spot_usd,
        "epochTelemetry": epoch_telemetry,
        "settledAt": Utc::now().to_rfc3339()
    }))
}