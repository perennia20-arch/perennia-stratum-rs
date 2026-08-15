// src/chronos.rs
use std::time::Duration;
use sqlx::{PgPool, Row};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use reqwest::Client;

const NETWORK_FEE_PERCENTAGE: f64 = 0.015; 
const MINIMUM_UTXO_SWEEP_THRESHOLD: f64 = 0.0005; 
const OVERCLOCK_BASE_FEE: f64 = 0.0001;
const OVERCLOCK_VAR_FEE: f64 = 0.005;
const OVERCLOCK_PREMIUM_FEE: f64 = 0.005;

#[derive(Serialize, Deserialize, Debug)]
pub struct NettingOrder {
    pub wallet: String,
    pub direction: String, 
    pub amount_kas: f64,
    pub spot_price: f64,
    pub fee_captured_usd: f64,
}

async fn get_spot_price(redis_conn: &mut redis::aio::MultiplexedConnection, ticker: &str) -> f64 {
    if ticker == "USDC" || ticker == "USDT" || ticker == "USD" { return 1.0; }
    let key = format!("oracle:spot:{}_USDC", ticker);
    let val_str: Option<String> = redis::cmd("GET").arg(&key).query_async(redis_conn).await.unwrap_or(None);
    if let Some(v) = val_str {
        v.parse().unwrap_or(0.0)
    } else {
        0.0
    }
}

pub async fn start_delta_netting_engine(redis_client: redis::Client) {
    tracing::info!("🕸️ Dark Pool Netting Engine Online. Batching internal liquidity every 10 seconds.");

    let mut redis_conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Netting Engine Redis failure: {}", e);
            return;
        }
    };

    let mut interval = tokio::time::interval(Duration::from_secs(10));

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
            continue;
        }

        let mut total_buy_kas = 0.0;
        let mut total_sell_kas = 0.0;
        let mut gross_volume_kas = 0.0;
        let mut total_fees_usd = 0.0;

        for order in &current_batch {
            gross_volume_kas += order.amount_kas;
            total_fees_usd += order.fee_captured_usd;

            if order.direction == "BUY_KAS" {
                total_buy_kas += order.amount_kas;
            } else if order.direction == "SELL_KAS" {
                total_sell_kas += order.amount_kas;
            }
        }

        let net_delta = (total_buy_kas - total_sell_kas).abs();
        let dominant_direction = if total_buy_kas > total_sell_kas { "BUY_HEAVY" } else { "SELL_HEAVY" };

        tracing::info!(
            "🦇 [DARK POOL BATCH CLEARED] Gross: {:.2} KAS | Net Delta: {:.2} KAS ({}) | Spread Profit: ${:.2}",
            gross_volume_kas, net_delta, dominant_direction, total_fees_usd
        );

        if total_fees_usd > 0.0 {
            let _: () = redis::cmd("INCRBYFLOAT")
                .arg("perennia:treasury:netting_profit_usd")
                .arg(total_fees_usd)
                .query_async(&mut redis_conn)
                .await
                .unwrap_or(());
        }

        if net_delta > 0.0 {
            tracing::info!("   -> L1 Physical Settlement Required: Moving {:.2} KAS to balance treasury.", net_delta);
        } else {
            tracing::info!("   -> Perfect Equilibrium. Zero L1 settlement required. 100% margin retained.");
        }
    }
}

pub async fn start_chronos_daemon(pool: PgPool) {
    tracing::info!("⏳ Chronos Settlement Engine Online. Executing Single-Sided Sector Matrix.");

    let _ = sqlx::query("ALTER TABLE yield_reservoirs ADD COLUMN IF NOT EXISTS lp_tokens JSONB DEFAULT '{}'::jsonb")
        .execute(&pool)
        .await;

    // ⚡ INFRASTRUCTURE HARDENING
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = redis::Client::open(redis_url).expect("Failed to connect to Redis for Chronos");
    let http_client = Client::new();

    let mut interval = tokio::time::interval(Duration::from_secs(10));

    loop {
        interval.tick().await;
        if let Err(e) = execute_settlement_tick(&pool, &redis_client, &http_client).await {
            tracing::error!("🚨 Chronos Execution Error: {}", e);
        }
    }
}

async fn execute_settlement_tick(
    pool: &PgPool, 
    redis_client: &redis::Client, 
    http_client: &Client
) -> anyhow::Result<()> {
    let mut redis_conn = redis_client.get_multiplexed_async_connection().await?;

    let network_diff_str: Option<String> = redis::cmd("GET").arg("pool:network_diff").query_async(&mut redis_conn).await.unwrap_or(None);
    let block_reward_str: Option<String> = redis::cmd("GET").arg("pool:block_reward").query_async(&mut redis_conn).await.unwrap_or(None);

    if network_diff_str.is_none() || block_reward_str.is_none() {
        tracing::warn!("⚠️ L1 Node Metrics Unreachable. Pausing Chronos Yield Settlement to protect PPS integrity.");
        return Ok(());
    }

    let network_diff: f64 = network_diff_str.unwrap().parse::<f64>().unwrap_or(1.0).max(1.0);
    let block_reward: f64 = block_reward_str.unwrap().parse().unwrap_or(2.31);

    if block_reward <= 0.0 {
        tracing::warn!("⚠️ Block reward is 0. Yield emissions have concluded.");
        return Ok(());
    }

    let hashes_per_share_diff = 4_294_967_296.0;
    let reward_per_diff_unit = (hashes_per_share_diff / network_diff) * block_reward;

    let addresses: Vec<String> = sqlx::query("SELECT wallet_address FROM user_command_centers")
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| row.get("wallet_address"))
        .collect();

    // ⚡ INFRASTRUCTURE HARDENING
    let rust_backend_url = std::env::var("RUST_BACKEND_URL").unwrap_or_else(|_| "http://127.0.0.1:8002".to_string());
    let node_backend_url = std::env::var("NODE_BACKEND_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());

    for address in addresses {
        let state_row = sqlx::query("SELECT layout_state FROM user_command_centers WHERE wallet_address = $1")
            .bind(&address)
            .fetch_optional(pool)
            .await?;

        let mut state: Value = match state_row {
            Some(row) => row.get("layout_state"),
            None => continue,
        };

        let is_overclocked = state.get("systemMode").and_then(|v| v.as_str()) == Some("overclocked");
        let escrow_active = state.pointer("/taxFortress/escrowActive").and_then(|v| v.as_bool()).unwrap_or(false);

        let mut total_earned_kaspa = 0.0;
        let mut unassigned_yield = 0.0;

        if let Some(workers) = state.get_mut("workers").and_then(|w| w.as_array_mut()) {
            for worker in workers.iter_mut() {
                let w_type = worker.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();

                if w_type == "physical" {
                    let wallet_worker = worker.get("walletWorker").and_then(|v| v.as_str()).unwrap_or("");
                    if !wallet_worker.is_empty() {
                        let share_key = format!("worker:{}:shares", wallet_worker);
                        let block_key = format!("worker:{}:blocks_unpaid", wallet_worker);

                        let unprocessed_str: Option<String> = redis::cmd("GET").arg(&share_key).query_async(&mut redis_conn).await.unwrap_or(None);
                        let unprocessed: f64 = unprocessed_str.unwrap_or_else(|| "0".to_string()).parse().unwrap_or(0.0);

                        let unpaid_blocks_str: Option<String> = redis::cmd("GET").arg(&block_key).query_async(&mut redis_conn).await.unwrap_or(None);
                        let unpaid_blocks: f64 = unpaid_blocks_str.unwrap_or_else(|| "0".to_string()).parse().unwrap_or(0.0);

                        if unprocessed > 0.0 {
                            total_earned_kaspa += unprocessed * reward_per_diff_unit;
                            let _: () = redis::cmd("SET").arg(&share_key).arg("0").query_async(&mut redis_conn).await.unwrap_or(());
                        }

                        if unpaid_blocks > 0.0 {
                            let _: () = redis::cmd("SET").arg(&block_key).arg("0").query_async(&mut redis_conn).await.unwrap_or(());
                            tracing::info!("💎 [BLOCK FOUND] {} found {} blocks for the pool!", wallet_worker, unpaid_blocks);
                        }
                    }
                }
            }
        }

        let mut sector_pending_map: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
        let mut total_allocated_pct = 0.0;

        if let Some(sectors) = state.get("sectors").and_then(|s| s.as_array()) {
            for sec in sectors {
                let pct = sec.get("allocationPercentage").and_then(|v| v.as_f64()).unwrap_or(0.0);
                total_allocated_pct += pct;
                
                if let (Some(id), Some(p)) = (sec.get("id").and_then(|v| v.as_str()), sec.get("pendingKaspa").and_then(|v| v.as_f64())) {
                    let newly_earned = total_earned_kaspa * (pct / 100.0);
                    sector_pending_map.insert(id.to_string(), p + newly_earned);
                } else if let Some(id) = sec.get("id").and_then(|v| v.as_str()) {
                    let newly_earned = total_earned_kaspa * (pct / 100.0);
                    sector_pending_map.insert(id.to_string(), newly_earned);
                }
            }
        }

        let unallocated_pct = (100.0 - total_allocated_pct).max(0.0);
        unassigned_yield += total_earned_kaspa * (unallocated_pct / 100.0);

        if unassigned_yield > 0.0 {
            let _ = sqlx::query!(
                "INSERT INTO yield_reservoirs (wallet_address, streaming_balance_kas, total_yield_kas) 
                 VALUES ($1, $2::FLOAT8, $2::FLOAT8) 
                 ON CONFLICT (wallet_address) DO UPDATE SET 
                 streaming_balance_kas = yield_reservoirs.streaming_balance_kas + EXCLUDED.streaming_balance_kas, 
                 total_yield_kas = yield_reservoirs.total_yield_kas + EXCLUDED.total_yield_kas, 
                 last_updated = CURRENT_TIMESTAMP",
                address, unassigned_yield
            ).execute(pool).await;

            let kas_spot_price = get_spot_price(&mut redis_conn, "KAS").await;
            let _ = sqlx::query!(
                "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution)
                 VALUES ($1, 'KAS', 'YIELD', $2::FLOAT8, $3::FLOAT8, $4::FLOAT8)",
                address, unassigned_yield * kas_spot_price, unassigned_yield, kas_spot_price
            ).execute(pool).await;

            if total_earned_kaspa > 0.0 {
                tracing::info!("🚜 [THE FIELD] Directly credited {:.8} Unassigned KAS to {}", unassigned_yield, address);
            }
        }

        if is_overclocked {
            let mut total_tick_fee = OVERCLOCK_BASE_FEE;
            for pending in sector_pending_map.values_mut() {
                if *pending > 0.0 {
                    let var_fee = *pending * OVERCLOCK_VAR_FEE;
                    let deduction = pending.min(total_tick_fee + var_fee);

                    if deduction > 0.0 {
                        *pending -= deduction;
                        total_tick_fee = (total_tick_fee - deduction).max(0.0);

                        let _: () = redis::cmd("INCRBYFLOAT")
                            .arg("perennia:fees:batch_accumulated:KAS")
                            .arg(deduction)
                            .query_async(&mut redis_conn)
                            .await
                            .unwrap_or(());
                    }
                }
            }
        }

        if let Some(sectors) = state.get("sectors").and_then(|s| s.as_array()) {
            for sec in sectors {
                if let Some(id) = sec.get("id").and_then(|v| v.as_str()) {
                    let auto_payout = sec.pointer("/settlementConfig/autoPayout").and_then(|v| v.as_bool()).unwrap_or(false);
                    let pending = *sector_pending_map.get(id).unwrap_or(&0.0);

                    if auto_payout && pending >= MINIMUM_UTXO_SWEEP_THRESHOLD {
                        let threshold = sec.pointer("/settlementConfig/threshold").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let mode = sec.pointer("/settlementConfig/mode").and_then(|v| v.as_str()).unwrap_or("");
                        let route_mode = sec.get("routeMode").and_then(|v| v.as_str()).unwrap_or("hold");

                        if mode == "stream" || (mode == "threshold" && pending >= threshold) {
                            let sec_name = sec.get("name").and_then(|n| n.as_str()).unwrap_or("Unknown").to_string();
                            let target_ticker = sec.pointer("/settlementConfig/targetAsset/ticker").and_then(|t| t.as_str()).unwrap_or("KAS").to_string();

                            tracing::info!("\n💸 [CHRONOS EXECUTION] Settling Sector: {} | Mode: {}", sec_name, route_mode);

                            let mut amount_to_route = pending;
                            if escrow_active {
                                let tax_withholding = pending * 0.15;
                                amount_to_route = pending - tax_withholding;

                                let tax_req = json!({ "wallet": address, "payAsset": "KAS", "receiveAsset": "USDC", "amount": tax_withholding, "slippageTolerance": 0.05 });
                                let tax_url = format!("{}/v1/sor/execute", rust_backend_url);
                                if let Ok(res) = http_client.post(&tax_url).json(&tax_req).send().await {
                                    if let Ok(data) = res.json::<Value>().await {
                                        if let Some(est) = data.get("estimatedOutput").and_then(|v| v.as_f64()) {
                                            let final_settled = est * (1.0 - NETWORK_FEE_PERCENTAGE);
                                            let clean_address = address.replace("kaspa:", "");
                                            let escrow_ledger_key = format!("dev:escrow:locked_balances:{}", clean_address);
                                            let _: () = redis::cmd("HINCRBYFLOAT").arg(&escrow_ledger_key).arg("USDC").arg(final_settled).query_async(&mut redis_conn).await.unwrap_or(());
                                            tracing::info!("🔒 [TAX FORTRESS] Intercepted {:.8} KAS into Escrow LP ({:.2} USDC). Locked until April 15.", tax_withholding, final_settled);
                                        }
                                    }
                                }
                            }

                            if route_mode == "auto-lp" {
                                let amount_to_swap = amount_to_route * 0.5;
                                let amount_to_keep = amount_to_route - amount_to_swap;
                                
                                let req_payload = json!({ "wallet": address, "payAsset": "KAS", "receiveAsset": "USDC", "amount": amount_to_swap, "slippageTolerance": 0.05 });
                                let auto_lp_url = format!("{}/v1/sor/execute", rust_backend_url);
                                if let Ok(res) = http_client.post(&auto_lp_url).json(&req_payload).send().await {
                                    if let Ok(data) = res.json::<Value>().await {
                                        if let Some(est) = data.get("estimatedOutput").and_then(|v| v.as_f64()) {
                                            let final_usdc = est * (1.0 - NETWORK_FEE_PERCENTAGE);
                                            let clean_address = address.replace("kaspa:", "");
                                            let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_address);
                                            let lp_pair_name = "KAS/USDC LP";
                                            
                                            let kas_spot_price = get_spot_price(&mut redis_conn, "KAS").await;
                                            let total_lp_usd = (amount_to_keep * kas_spot_price) + final_usdc;

                                            let _: () = redis::cmd("HINCRBYFLOAT").arg(&user_ledger_key).arg(lp_pair_name).arg(total_lp_usd).query_async(&mut redis_conn).await.unwrap_or(());

                                            let _ = sqlx::query(
                                                r#"INSERT INTO yield_reservoirs (wallet_address, streaming_balance_kas, total_yield_kas, lp_tokens) 
                                                   VALUES ($1, 0.0, 0.0, jsonb_build_object($2::text, $3::float8))
                                                   ON CONFLICT (wallet_address) DO UPDATE SET 
                                                   lp_tokens = jsonb_set(COALESCE(yield_reservoirs.lp_tokens, '{}'::jsonb), ARRAY[$2::text], to_jsonb(COALESCE((yield_reservoirs.lp_tokens->>$2::text)::numeric, 0.0) + $3::numeric)), last_updated = CURRENT_TIMESTAMP"#
                                            ).bind(&address).bind(lp_pair_name).bind(total_lp_usd).execute(pool).await;

                                            tracing::info!("⚡ [SINGLE-SIDED ZAP] {} -> Minted {:.2} KAS/USDC LP", sec_name, total_lp_usd);
                                            sector_pending_map.insert(id.to_string(), 0.0);
                                        }
                                    }
                                }
                            } else {
                                let req_payload = json!({ "wallet": address, "payAsset": "KAS", "receiveAsset": target_ticker, "amount": amount_to_route, "slippageTolerance": 0.05 });
                                let host_api = if target_ticker == "USD" { format!("{}/api/sor/yield_settle", node_backend_url) } else { format!("{}/v1/sor/execute", rust_backend_url) };

                                if let Ok(res) = http_client.post(&host_api).json(&req_payload).send().await {
                                    if let Ok(data) = res.json::<Value>().await {
                                        if let Some(est) = data.get("estimatedOutput").and_then(|v| v.as_f64()) {
                                            let dynamic_system_fee = if is_overclocked { NETWORK_FEE_PERCENTAGE + 0.005 } else { NETWORK_FEE_PERCENTAGE };
                                            let final_settled = est * (1.0 - dynamic_system_fee);
                                            let fee = est * dynamic_system_fee;

                                            let clean_address = address.replace("kaspa:", "");
                                            let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_address);

                                            if target_ticker != "USD" {
                                                let _: () = redis::cmd("HINCRBYFLOAT").arg(&user_ledger_key).arg(&target_ticker).arg(final_settled).query_async(&mut redis_conn).await.unwrap_or(());
                                                let batch_fee_key = format!("perennia:fees:batch_accumulated:{}", target_ticker);
                                                let _: () = redis::cmd("INCRBYFLOAT").arg(&batch_fee_key).arg(fee).query_async(&mut redis_conn).await.unwrap_or(());
                                            }

                                            tracing::info!("   -> Routed {:.8} KAS into {:.6} {} via sorEngine.", amount_to_route, final_settled, target_ticker);
                                            sector_pending_map.insert(id.to_string(), 0.0);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut tx = pool.begin().await?;

        let latest_row = sqlx::query("SELECT layout_state FROM user_command_centers WHERE wallet_address = $1 FOR UPDATE")
            .bind(&address)
            .fetch_optional(&mut *tx)
            .await?;

        if let Some(row) = latest_row {
            let mut final_state: Value = row.get("layout_state");
            let mut state_mutated = false;

            if let Some(sectors) = final_state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                for sec in sectors.iter_mut() {
                    if let Some(id) = sec.get("id").and_then(|v| v.as_str()) {
                        if let Some(new_pending) = sector_pending_map.get(id) {
                            if sec.get("pendingKaspa").and_then(|v| v.as_f64()) != Some(*new_pending) {
                                sec["pendingKaspa"] = json!(*new_pending);
                                state_mutated = true;
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

                let mut sector_yields = Vec::new();
                if let Some(sectors) = final_state.get("sectors").and_then(|s| s.as_array()) {
                    for sec in sectors {
                        if let (Some(id), Some(pending)) = (sec.get("id").and_then(|v| v.as_str()), sec.get("pendingKaspa").and_then(|v| v.as_f64())) {
                            sector_yields.push(json!({"id": id, "pendingKaspa": pending}));
                        }
                    }
                }

                let update_payload = json!({
                    "yield_update": true,
                    "wallet": address,
                    "sectors": sector_yields
                });

                let _: () = redis::cmd("PUBLISH")
                    .arg("telemetry:updates")
                    .arg(update_payload.to_string())
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(());
            }
        }
        let _ = tx.commit().await;
    }

    Ok(())
}