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
    let mut interval = tokio::time::interval(Duration::from_secs(10));
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
) -> anyhow::Result<Value> {
    let Ok(mut redis_conn) = redis_client.get_multiplexed_async_connection().await else {
        return Ok(json!({ "ordersPopped": 0, "skipped": "redis_unavailable" }));
    };
    let Ok(kas_spot_usd) = crate::fiat_rails::resolve_live_spot_price(pool, "KAS").await else {
        return Ok(json!({ "ordersPopped": 0, "skipped": "oracle_offline" }));
    };
    if !kas_spot_usd.is_finite() || kas_spot_usd <= 0.0_f64 {
        return Ok(json!({ "ordersPopped": 0, "skipped": "invalid_kas_spot" }));
    }

    let _ = publish_live_epoch_bucket_telemetry(pool, kas_spot_usd).await;

    let mut queued_orders: Vec<Value> = Vec::new();
    for _ in 0..2000 {
        let item_opt: Option<String> = redis::cmd("LPOP")
            .arg("perennia:sor:netting_queue")
            .query_async(&mut redis_conn).await.unwrap_or(None);
        let Some(raw_str) = item_opt else { break; };
        if let Ok(parsed) = serde_json::from_str::<Value>(&raw_str) {
            queued_orders.push(parsed);
        }
    }

    let min_dark_pool_usd: f64 = env::var("MIN_DARK_POOL_POSITION_USD")
        .ok().and_then(|v| v.trim().parse::<f64>().ok()).filter(|&v| v >= 1.0_f64).unwrap_or(5.0_f64);
    let batch_id = format!("NET-10S-{}", &uuid::Uuid::new_v4().simple().to_string().to_uppercase()[..10]);
    let mut batch_receipt = json!({
        "batchId": batch_id,
        "ordersPopped": queued_orders.len(),
        "kasSpotUsd": kas_spot_usd,
        "completedAtMs": Utc::now().timestamp_millis()
    });

    if !queued_orders.is_empty() {
        let mut inflow_usd: HashMap<String, f64> = HashMap::new();
        let mut outflow_usd: HashMap<String, f64> = HashMap::new();
        let mut total_gross_usd: f64 = 0.0_f64;
        let mut total_net_principal_usd: f64 = 0.0_f64;
        let mut total_buy_kas: f64 = 0.0_f64;
        let mut total_sell_kas: f64 = 0.0_f64;

        for ord in &queued_orders {
            let dir = ord.get("direction").and_then(|v| v.as_str()).unwrap_or("SELL_KAS");
            let pay_a = ord.get("pay_asset").and_then(|v| v.as_str())
                .unwrap_or(if dir.eq_ignore_ascii_case("BUY_KAS") { "USDC" } else { "KAS" })
                .trim().to_uppercase();
            let rec_a = ord.get("receive_asset").and_then(|v| v.as_str())
                .unwrap_or(if dir.eq_ignore_ascii_case("BUY_KAS") { "KAS" } else { "USDC" })
                .trim().to_uppercase();
            let amt_kas: f64 = ord.get("amount_kas").and_then(|v| v.as_f64()).unwrap_or(0.0_f64).max(0.0_f64);
            let gross_u: f64 = ord.get("gross_usd").and_then(|v| v.as_f64()).unwrap_or(amt_kas * kas_spot_usd).max(0.0_f64);
            let net_u: f64 = ord.get("net_usd").and_then(|v| v.as_f64()).unwrap_or(gross_u).max(0.0_f64);

            total_gross_usd += gross_u;
            total_net_principal_usd += net_u;
            if dir.eq_ignore_ascii_case("BUY_KAS") {
                total_buy_kas += amt_kas;
            } else if dir.eq_ignore_ascii_case("SELL_KAS") {
                total_sell_kas += amt_kas;
            }
            *inflow_usd.entry(pay_a).or_insert(0.0_f64) += net_u;
            *outflow_usd.entry(rec_a).or_insert(0.0_f64) += net_u;
        }

        let mut all_assets: HashSet<String> = inflow_usd.keys().cloned().collect();
        all_assets.extend(outflow_usd.keys().cloned());

        let mut net_delta_usd: HashMap<String, f64> = HashMap::new();
        let mut user_crossed_usd: f64 = 0.0_f64;
        for asset in &all_assets {
            let inf: f64 = inflow_usd.get(asset).copied().unwrap_or(0.0_f64);
            let outf: f64 = outflow_usd.get(asset).copied().unwrap_or(0.0_f64);
            user_crossed_usd += inf.min(outf);
            net_delta_usd.insert(asset.clone(), inf - outf);
        }

        let mut miner_silos_crossed_count: usize = 0;
        let mut miner_silo_crossed_kas: f64 = 0.0_f64;
        let mut miner_silo_crossed_usd: f64 = 0.0_f64;
        let mut silo_fees_captured_usd: f64 = 0.0_f64;

        if net_delta_usd.get("KAS").copied().unwrap_or(0.0_f64) < -0.05_f64 {
            let cc_rows = sqlx::query("SELECT wallet_address, layout_state FROM user_command_centers")
                .fetch_all(pool).await.unwrap_or_default();
            for row in cc_rows {
                if net_delta_usd.get("KAS").copied().unwrap_or(0.0_f64) >= -0.05_f64 { break; }
                let raw_wallet: String = row.try_get("wallet_address").unwrap_or_default();
                let clean_wallet = raw_wallet.trim().to_lowercase().replace("kaspa:", "").trim().to_string();
                if clean_wallet.is_empty() { continue; }
                let prefixed_wallet = format!("kaspa:{}", clean_wallet);
                let mut layout: Value = row.try_get("layout_state").unwrap_or_else(|_| json!({ "sectors": [] }));
                let mut row_mutated = false;

                if let Some(sectors) = layout.get_mut("sectors").and_then(|v| v.as_array_mut()) {
                    for sec in sectors.iter_mut() {
                        let pending: f64 = sec.get("pendingKaspa").and_then(|v| v.as_f64()).unwrap_or(0.0_f64).max(0.0_f64);
                        if pending <= 1e-6_f64 { continue; }
                        let route_mode = sec.get("routeMode").and_then(|v| v.as_str()).unwrap_or("hold").to_lowercase();
                        if route_mode != "swap" && route_mode != "convert" { continue; }
                        let sec_ticker = sec.get("settlementConfig").and_then(|c| c.get("targetAsset"))
                            .and_then(|t| t.get("ticker")).and_then(|v| v.as_str()).unwrap_or("").trim().to_uppercase();
                        if sec_ticker.is_empty() || sec_ticker == "KAS" { continue; }

                        let short_kas_usd: f64 = (-net_delta_usd.get("KAS").copied().unwrap_or(0.0_f64)).max(0.0_f64);
                        let surplus_tok_usd: f64 = net_delta_usd.get(&sec_ticker).copied().unwrap_or(0.0_f64).max(0.0_f64);
                        let matchable_usd: f64 = short_kas_usd.min(surplus_tok_usd);
                        if matchable_usd <= 0.05_f64 { continue; }

                        let target_spot: f64 = if sec_ticker == "USD" {
                            1.0_f64
                        } else {
                            match crate::fiat_rails::resolve_live_spot_price(pool, &sec_ticker).await {
                                Ok(p) if p > 0.0_f64 => p,
                                _ => continue,
                            }
                        };
                        let take_kas: f64 = pending.min(matchable_usd / kas_spot_usd);
                        if take_kas <= 1e-6_f64 { continue; }
                        let (u_floor, _, _) = crate::fiat_rails::resolve_wallet_swap_fee_floor_pct(pool, &prefixed_wallet).await;
                        let eff_rate: f64 = u_floor.max(crate::fiat_rails::HARD_PROFIT_FLOOR_PCT);
                        let gross_silo_usd: f64 = take_kas * kas_spot_usd;
                        let fee_silo_usd: f64 = (gross_silo_usd * eff_rate).max(0.01_f64);
                        let net_silo_usd: f64 = (gross_silo_usd - fee_silo_usd).max(0.0_f64);
                        if net_silo_usd <= 0.0_f64 { continue; }

                        let credit_ticker = if sec_ticker == "USD" { "USDC" } else { sec_ticker.as_str() };
                        let out_tokens: f64 = ((net_silo_usd / target_spot) * 1e8_f64).round() / 1e8_f64;
                        if out_tokens <= 0.0_f64 { continue; }

                        if crate::state_api::credit_user_token_balance(
                            pool, &clean_wallet, &prefixed_wallet, credit_ticker, out_tokens, false,
                        ).await.is_ok() {
                            sec["pendingKaspa"] = json!(((pending - take_kas).max(0.0_f64) * 1e8_f64).round() / 1e8_f64);
                            row_mutated = true;
                            miner_silos_crossed_count += 1;
                            miner_silo_crossed_kas += take_kas;
                            miner_silo_crossed_usd += net_silo_usd;
                            silo_fees_captured_usd += fee_silo_usd;
                            *net_delta_usd.entry("KAS".to_string()).or_insert(0.0_f64) += net_silo_usd;
                            *net_delta_usd.entry(sec_ticker.clone()).or_insert(0.0_f64) -= net_silo_usd;

                            let tx_ref = format!("{}-SILO-{}", batch_id, miner_silos_crossed_count);
                            let _ = crate::sor::record_hifo_acquisition_lot(
                                pool, &clean_wallet, credit_ticker, out_tokens, target_spot, "DARK_POOL_SILO_CROSS", Some(&tx_ref),
                            ).await;
                            let _ = sqlx::query(
                                "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash, cost_basis_usd, realized_gain_loss_usd, holding_period) VALUES ($1, $2, 'DARK_POOL_SILO_CROSS', $3, $4, $5, $6, $3, 0.0, 'SHORT_TERM')",
                            ).bind(&clean_wallet).bind(credit_ticker).bind(net_silo_usd).bind(out_tokens).bind(target_spot).bind(&tx_ref).execute(pool).await;
                        }
                    }
                }
                if row_mutated {
                    let _ = sqlx::query(
                        "UPDATE user_command_centers SET layout_state = $2, last_updated = CURRENT_TIMESTAMP WHERE wallet_address = $1",
                    ).bind(&raw_wallet).bind(&layout).execute(pool).await;
                }
            }
        }

        let final_residual_usd: f64 = 0.5_f64 * net_delta_usd.values().map(|v| v.abs()).sum::<f64>();
        let combined_principal_usd: f64 = total_net_principal_usd + miner_silo_crossed_usd;
        let internal_offset_usd: f64 = (combined_principal_usd - final_residual_usd).max(0.0_f64);
        let offset_efficiency_pct: f64 = if combined_principal_usd > 0.0_f64 {
            ((internal_offset_usd / combined_principal_usd) * 100.0_f64).clamp(0.0_f64, 100.0_f64)
        } else { 100.0_f64 };
        let spread_saved_usd: f64 = internal_offset_usd * 0.005_f64;
        let incremental_profit_usd: f64 = spread_saved_usd + silo_fees_captured_usd;

        if incremental_profit_usd > 0.0_f64 {
            let _: redis::RedisResult<()> = redis::cmd("INCRBYFLOAT")
                .arg("perennia:treasury:netting_profit_usd").arg(incremental_profit_usd)
                .query_async(&mut redis_conn).await;
        }
        if silo_fees_captured_usd > 0.0_f64 {
            let _: redis::RedisResult<()> = redis::cmd("INCRBYFLOAT")
                .arg("perennia:fees:batch_accumulated:USDC").arg(silo_fees_captured_usd * 0.60_f64)
                .query_async(&mut redis_conn).await;
        }
        let residual_kas_delta: f64 = net_delta_usd.get("KAS").copied().unwrap_or(0.0_f64) / kas_spot_usd;
        if residual_kas_delta.abs() > 1e-8_f64 {
            let _: redis::RedisResult<()> = redis::cmd("INCRBYFLOAT")
                .arg("perennia:treasury:unhedged_delta_kas").arg(residual_kas_delta)
                .query_async(&mut redis_conn).await;
        }

        let mut external_tickets_staged: usize = 0;
        let mut sorted_assets: Vec<String> = net_delta_usd.keys().cloned().collect();
        sorted_assets.sort();
        for asset in sorted_assets {
            if asset == "KAS" { continue; }
            let delta_u: f64 = net_delta_usd.get(&asset).copied().unwrap_or(0.0_f64);
            if delta_u.abs() >= min_dark_pool_usd {
                let ticket = json!({
                    "batch_id": batch_id,
                    "type": "NET_RESIDUAL_AUTOBALANCE",
                    "target_asset": asset,
                    "rebalance_action": if delta_u > 0.0_f64 { "SELL_SURPLUS_FOR_KAS" } else { "BUY_DEFICIT_WITH_KAS" },
                    "residual_usd": (delta_u.abs() * 10000.0_f64).round() / 10000.0_f64,
                    "kas_equiv": ((delta_u.abs() / kas_spot_usd) * 10000.0_f64).round() / 10000.0_f64,
                    "orders_consolidated": queued_orders.len(),
                    "offset_efficiency_pct": (offset_efficiency_pct * 100.0_f64).round() / 100.0_f64,
                    "created_at": Utc::now().to_rfc3339()
                });
                let _: redis::RedisResult<()> = redis::cmd("LPUSH")
                    .arg("perennia:sor:third_party_passthrough_queue").arg(ticket.to_string())
                    .query_async(&mut redis_conn).await;
                let _: redis::RedisResult<()> = redis::cmd("LTRIM")
                    .arg("perennia:sor:third_party_passthrough_queue").arg(0).arg(199)
                    .query_async(&mut redis_conn).await;
                external_tickets_staged += 1;
            }
        }

        batch_receipt = json!({
            "batchId": batch_id,
            "ordersPopped": queued_orders.len(),
            "totalGrossUsd": (total_gross_usd * 10000.0_f64).round() / 10000.0_f64,
            "totalNetPrincipalUsd": (total_net_principal_usd * 10000.0_f64).round() / 10000.0_f64,
            "totalBuyKas": (total_buy_kas * 10000.0_f64).round() / 10000.0_f64,
            "totalSellKas": (total_sell_kas * 10000.0_f64).round() / 10000.0_f64,
            "userToUserCrossedUsd": (user_crossed_usd * 10000.0_f64).round() / 10000.0_f64,
            "minerSilosCrossedCount": miner_silos_crossed_count,
            "minerSiloCrossedKas": (miner_silo_crossed_kas * 10000.0_f64).round() / 10000.0_f64,
            "minerSiloCrossedUsd": (miner_silo_crossed_usd * 10000.0_f64).round() / 10000.0_f64,
            "internalDarkPoolOffsetUsd": (internal_offset_usd * 10000.0_f64).round() / 10000.0_f64,
            "finalResidualUsd": (final_residual_usd * 10000.0_f64).round() / 10000.0_f64,
            "offsetEfficiencyPct": (offset_efficiency_pct * 100.0_f64).round() / 100.0_f64,
            "spreadSavedUsd": (spread_saved_usd * 10000.0_f64).round() / 10000.0_f64,
            "siloFeesCapturedUsd": (silo_fees_captured_usd * 10000.0_f64).round() / 10000.0_f64,
            "externalTicketsStaged": external_tickets_staged,
            "netDeltaUsdByAsset": net_delta_usd,
            "kasSpotUsd": kas_spot_usd,
            "completedAtMs": Utc::now().timestamp_millis()
        });

        let serialized_receipt = batch_receipt.to_string();
        let _: redis::RedisResult<()> = redis::cmd("SET")
            .arg("perennia:settlement:last_netting_batch").arg(&serialized_receipt)
            .query_async(&mut redis_conn).await;
        let _: redis::RedisResult<()> = redis::cmd("SET")
            .arg("perennia:treasury:hedge_status").arg(&serialized_receipt)
            .query_async(&mut redis_conn).await;
        if miner_silos_crossed_count > 0 {
            let _ = publish_live_epoch_bucket_telemetry(pool, kas_spot_usd).await;
        }
    }

    let house_usdc_fees: f64 = redis::cmd("GET")
        .arg("perennia:fees:batch_accumulated:USDC")
        .query_async::<_, Option<String>>(&mut redis_conn).await
        .ok().flatten().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0_f64);
    if house_usdc_fees >= min_dark_pool_usd {
        if let Ok(master_wallet) = crate::chronos::resolve_master_treasury_prefixed() {
            let half_usd: f64 = house_usdc_fees * 0.5_f64;
            let kas_leg: f64 = half_usd / kas_spot_usd;
            let usdc_leg: f64 = half_usd;
            let existing_house_lp = sqlx::query(
                "SELECT lp_id::text AS lp_id, staked_asset_a, staked_asset_b FROM liquidity_providers WHERE wallet_address = $1 AND pool_pair = 'KAS/USDC' AND lock_duration_days = 365 ORDER BY created_at ASC LIMIT 1",
            ).bind(&master_wallet).fetch_optional(pool).await?;
            if let Some(row) = existing_house_lp {
                let lp_id: String = row.try_get("lp_id").unwrap_or_default();
                let next_a: f64 = row.try_get::<f64, _>("staked_asset_a").unwrap_or(0.0_f64) + kas_leg;
                let next_b: f64 = row.try_get::<f64, _>("staked_asset_b").unwrap_or(0.0_f64) + usdc_leg;
                let reserves_json = json!({ "KAS": next_a, "USDC": next_b });
                let _ = sqlx::query(
                    "UPDATE liquidity_providers SET staked_asset_a = $2, staked_asset_b = $3, reserves_json = $4, last_yield_distribution = CURRENT_TIMESTAMP WHERE lp_id::text = $1",
                ).bind(&lp_id).bind(next_a).bind(next_b).bind(&reserves_json).execute(pool).await;
            } else {
                let weights_json = json!({ "KAS": 0.5, "USDC": 0.5 });
                let reserves_json = json!({ "KAS": kas_leg, "USDC": usdc_leg });
                let _ = sqlx::query(
                    "INSERT INTO liquidity_providers (wallet_address, pool_pair, staked_asset_a, staked_asset_b, weights_json, reserves_json, lock_duration_days, unlock_date) VALUES ($1, 'KAS/USDC', $2, $3, $4, $5, 365, CURRENT_TIMESTAMP + INTERVAL '365 days')",
                ).bind(&master_wallet).bind(kas_leg).bind(usdc_leg).bind(&weights_json).bind(&reserves_json).execute(pool).await;
            }
            let _: redis::RedisResult<()> = redis::cmd("SET")
                .arg("perennia:fees:batch_accumulated:USDC").arg("0")
                .query_async(&mut redis_conn).await;
        }
    }

    let lp_rows = sqlx::query(
        "SELECT lp_id::text AS lp_id, wallet_address, pool_pair, staked_asset_a, staked_asset_b, lock_duration_days FROM liquidity_providers",
    ).fetch_all(pool).await?;
    if lp_rows.is_empty() { return Ok(batch_receipt); }
    let mut pair_weights: HashMap<String, f64> = HashMap::new();
    let mut lp_entries: Vec<(String, String, String, f64)> = Vec::with_capacity(lp_rows.len());
    for r in &lp_rows {
        let lp_id: String = r.try_get("lp_id").unwrap_or_default();
        let wallet: String = r.try_get("wallet_address").unwrap_or_default();
        let pair: String = r.try_get("pool_pair").unwrap_or_else(|_| "KAS/USDC".to_string());
        let amt_a: f64 = r.try_get("staked_asset_a").unwrap_or(0.0_f64).max(0.0_f64);
        let days: i32 = r.try_get("lock_duration_days").unwrap_or(0);
        let weighted_kas: f64 = amt_a * lock_multiplier_for_days(days);
        if weighted_kas > 0.0_f64 && !wallet.trim().is_empty() {
            *pair_weights.entry(pair.clone()).or_insert(0.0_f64) += weighted_kas;
            lp_entries.push((lp_id, wallet, pair, weighted_kas));
        }
    }
    for (pair, total_pair_weight) in pair_weights {
        if total_pair_weight <= 0.0_f64 { continue; }
        let pending_key = format!("perennia:lp:pending_yield_usd:{}", pair);
        let pending_usd: f64 = redis::cmd("GET").arg(&pending_key)
            .query_async::<_, Option<String>>(&mut redis_conn).await
            .ok().flatten().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0_f64);
        if pending_usd < 0.05_f64 { continue; }
        let _: redis::RedisResult<()> = redis::cmd("SET").arg(&pending_key).arg("0").query_async(&mut redis_conn).await;
        let total_yield_kas: f64 = pending_usd / kas_spot_usd;
        for (lp_id, wallet, lp_pair, weight) in &lp_entries {
            if *lp_pair != pair { continue; }
            let share_kas: f64 = total_yield_kas * (*weight / total_pair_weight);
            if share_kas <= 1e-6_f64 { continue; }
            let clean_w = wallet.trim().to_lowercase().replace("kaspa:", "").trim().to_string();
            let pref_w = format!("kaspa:{}", clean_w);
            if crate::state_api::credit_user_token_balance(pool, &clean_w, &pref_w, "KAS", share_kas, true).await.is_ok() {
                let _ = sqlx::query("UPDATE liquidity_providers SET last_yield_distribution = CURRENT_TIMESTAMP WHERE lp_id::text = $1")
                    .bind(lp_id).execute(pool).await;
            }
        }
    }
    Ok(batch_receipt)
}

pub async fn execute_epoch_delta_netting_and_lp_compounding(
    pool: &PgPool,
) -> anyhow::Result<Value> {
    let kas_spot_usd: f64 = crate::fiat_rails::resolve_live_spot_price(pool, "KAS")
        .await.map_err(|e| anyhow::anyhow!("Epoch netting aborted (fail-closed): {}", e))?;
    let rows = sqlx::query("SELECT wallet_address, layout_state FROM user_command_centers").fetch_all(pool).await?;

    let mut pooled_swap_kas: HashMap<String, f64> = HashMap::new();
    for r in &rows {
        let layout: Value = r.try_get("layout_state").unwrap_or_else(|_| json!({ "sectors": [] }));
        if let Some(sectors) = layout.get("sectors").and_then(|v| v.as_array()) {
            for sec in sectors {
                let pending: f64 = sec.get("pendingKaspa").and_then(|v| v.as_f64()).unwrap_or(0.0_f64);
                if pending <= 0.0_f64 { continue; }
                let route_mode = sec.get("routeMode").and_then(|v| v.as_str()).unwrap_or("hold").to_lowercase();
                if route_mode != "swap" && route_mode != "convert" { continue; }
                let tick = sec.get("settlementConfig").and_then(|c| c.get("targetAsset"))
                    .and_then(|t| t.get("ticker")).and_then(|v| v.as_str()).unwrap_or("KAS").trim().to_uppercase();
                if !tick.is_empty() && tick != "KAS" {
                    *pooled_swap_kas.entry(tick).or_insert(0.0_f64) += pending;
                }
            }
        }
    }

    let mut eligible_bucket_spot: HashMap<String, f64> = HashMap::new();
    for (tick, total_bucket_kas) in &pooled_swap_kas {
        let (min_prof_kas, _) = crate::fiat_rails::resolve_live_profitable_bucket_threshold(pool, tick, kas_spot_usd).await;
        if *total_bucket_kas + 1e-6_f64 < min_prof_kas { continue; }
        let spot_opt: Option<f64> = if tick == "USD" {
            Some(1.0_f64)
        } else {
            crate::fiat_rails::resolve_live_spot_price(pool, tick).await.ok().filter(|&p| p > 0.0_f64)
        };
        if let Some(sp) = spot_opt {
            eligible_bucket_spot.insert(tick.clone(), sp);
        }
    }

    let mut settled_sectors_count: usize = 0;
    let mut total_swept_kas: f64 = 0.0_f64;
    let mut total_epoch_fees_usd: f64 = 0.0_f64;

    for row in rows {
        let raw_wallet: String = row.try_get("wallet_address").unwrap_or_default();
        let clean_wallet = raw_wallet.trim().to_lowercase().replace("kaspa:", "").trim().to_string();
        if clean_wallet.is_empty() { continue; }
        let prefixed_wallet = format!("kaspa:{}", clean_wallet);
        let (user_fee_floor_rate, _, _) = crate::fiat_rails::resolve_wallet_swap_fee_floor_pct(pool, &prefixed_wallet).await;
        let effective_swap_fee_rate: f64 = user_fee_floor_rate.max(crate::fiat_rails::HARD_PROFIT_FLOOR_PCT);

        let mut layout: Value = row.try_get("layout_state").unwrap_or_else(|_| json!({ "workers": [], "sectors": [] }));
        let mut wallet_credited_kas: f64 = 0.0_f64;
        let mut layout_mutated = false;

        if let Some(sectors) = layout.get_mut("sectors").and_then(|v| v.as_array_mut()) {
            for sec in sectors.iter_mut() {
                let pending: f64 = sec.get("pendingKaspa").and_then(|v| v.as_f64()).unwrap_or(0.0_f64);
                if pending <= 0.0_f64 { continue; }
                let route_mode = sec.get("routeMode").and_then(|v| v.as_str()).unwrap_or("hold").to_lowercase();
                let target_ticker = sec.get("settlementConfig").and_then(|c| c.get("targetAsset"))
                    .and_then(|t| t.get("ticker")).and_then(|v| v.as_str()).unwrap_or("KAS").trim().to_uppercase();

                if route_mode == "auto-lp" {
                    let secondary_ticker = if target_ticker == "KAS" || target_ticker.is_empty() || target_ticker == "USD" {
                        "USDC".to_string()
                    } else { target_ticker.clone() };
                    let Ok(secondary_spot_usd) = crate::fiat_rails::resolve_live_spot_price(pool, &secondary_ticker).await else { continue; };
                    if secondary_spot_usd <= 0.0_f64 { continue; }
                    let kas_leg: f64 = pending * 0.5_f64;
                    let converted_leg_gross_usd: f64 = kas_leg * kas_spot_usd;
                    let protocol_fee_usd: f64 = (converted_leg_gross_usd * effective_swap_fee_rate).max(0.01_f64);
                    let secondary_leg: f64 = (converted_leg_gross_usd - protocol_fee_usd).max(0.0_f64) / secondary_spot_usd;
                    if secondary_leg <= 0.0_f64 { continue; }
                    let pair_name = format!("KAS/{}", secondary_ticker);
                    let weights_json = json!({ "KAS": 0.5, secondary_ticker.clone(): 0.5 });
                    let reserves_json = json!({ "KAS": kas_leg, secondary_ticker.clone(): secondary_leg });
                    let _ = sqlx::query(
                        "INSERT INTO liquidity_providers (wallet_address, pool_pair, staked_asset_a, staked_asset_b, weights_json, reserves_json, lock_duration_days, unlock_date) VALUES ($1, $2, $3, $4, $5, $6, 30, CURRENT_TIMESTAMP + INTERVAL '30 days')",
                    ).bind(&prefixed_wallet).bind(&pair_name).bind(kas_leg).bind(secondary_leg).bind(&weights_json).bind(&reserves_json).execute(pool).await;
                    total_epoch_fees_usd += protocol_fee_usd;
                } else if (route_mode == "swap" || route_mode == "convert") && target_ticker != "KAS" && !target_ticker.is_empty() {
                    let Some(&target_spot_usd) = eligible_bucket_spot.get(&target_ticker) else { continue; };
                    let gross_usd: f64 = pending * kas_spot_usd;
                    let fee_usd: f64 = (gross_usd * effective_swap_fee_rate).max(0.01_f64);
                    let net_usd: f64 = (gross_usd - fee_usd).max(0.0_f64);
                    if net_usd <= 0.0_f64 { continue; }
                    let credit_ticker = if target_ticker == "USD" { "USDC" } else { target_ticker.as_str() };
                    let out_tokens: f64 = ((net_usd / target_spot_usd) * 1e8_f64).round() / 1e8_f64;
                    if out_tokens <= 0.0_f64 { continue; }
                    if crate::state_api::credit_user_token_balance(pool, &clean_wallet, &prefixed_wallet, credit_ticker, out_tokens, false).await.is_err() {
                        continue;
                    }
                    total_epoch_fees_usd += fee_usd;
                    let _ = crate::sor::record_hifo_acquisition_lot(pool, &clean_wallet, credit_ticker, out_tokens, target_spot_usd, "EPOCH_BELL_SWAP", None).await;
                    let _ = sqlx::query(
                        "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, cost_basis_usd, realized_gain_loss_usd, holding_period) VALUES ($1, $2, 'EPOCH_BELL_SWAP', $3, $4, $5, $3, 0.0, 'SHORT_TERM')",
                    ).bind(&clean_wallet).bind(credit_ticker).bind(net_usd).bind(out_tokens).bind(target_spot_usd).execute(pool).await;
                } else {
                    wallet_credited_kas += pending;
                }
                sec["pendingKaspa"] = json!(0.0);
                layout_mutated = true;
                settled_sectors_count += 1;
                total_swept_kas += pending;
            }
        }
        if wallet_credited_kas > 0.0_f64 {
            if crate::state_api::credit_user_token_balance(pool, &clean_wallet, &prefixed_wallet, "KAS", wallet_credited_kas, true).await.is_err() {
                continue;
            }
            let _ = crate::sor::record_hifo_acquisition_lot(pool, &clean_wallet, "KAS", wallet_credited_kas, kas_spot_usd, "EPOCH_BELL_YIELD", None).await;
            let gross_usd: f64 = wallet_credited_kas * kas_spot_usd;
            let _ = sqlx::query(
                "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, cost_basis_usd, realized_gain_loss_usd, holding_period) VALUES ($1, 'KAS', 'YIELD', $2, $3, $4, $2, 0.0, 'SHORT_TERM')",
            ).bind(&clean_wallet).bind(gross_usd).bind(wallet_credited_kas).bind(kas_spot_usd).execute(pool).await;
        }
        if layout_mutated {
            let _ = sqlx::query("UPDATE user_command_centers SET layout_state = $2, last_updated = CURRENT_TIMESTAMP WHERE wallet_address = $1")
                .bind(&raw_wallet).bind(&layout).execute(pool).await;
        }
    }

    if total_epoch_fees_usd > 0.0_f64 {
        if let Ok(redis_url) = env::var("REDIS_URL") {
            if let Ok(client) = redis::Client::open(redis_url) {
                if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                    let _: redis::RedisResult<()> = redis::cmd("INCRBYFLOAT")
                        .arg("perennia:treasury:netting_profit_usd").arg(total_epoch_fees_usd).query_async(&mut conn).await;
                    let _: redis::RedisResult<()> = redis::cmd("INCRBYFLOAT")
                        .arg("perennia:fees:batch_accumulated:USDC").arg(total_epoch_fees_usd * 0.60_f64).query_async(&mut conn).await;
                }
            }
        }
    }

    let epoch_telemetry = publish_live_epoch_bucket_telemetry(pool, kas_spot_usd).await.unwrap_or_else(|_| json!({}));
    Ok(json!({
        "pooledBucketsCleared": eligible_bucket_spot.keys().cloned().collect::<Vec<String>>(),
        "settledSectorsCount": settled_sectors_count,
        "totalSweptKas": (total_swept_kas * 10000.0_f64).round() / 10000.0_f64,
        "totalProtocolFeesUsd": (total_epoch_fees_usd * 10000.0_f64).round() / 10000.0_f64,
        "executionKasSpotUsd": kas_spot_usd,
        "epochTelemetry": epoch_telemetry,
        "settledAt": Utc::now().to_rfc3339()
    }))
}
