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
    tracing::info!("⏳ Chronos Settlement Engine Online. Natively monitoring Omni-Chain Ledger via Postgres.");
    
    let _ = sqlx::query("ALTER TABLE yield_reservoirs ADD COLUMN IF NOT EXISTS lp_tokens JSONB DEFAULT '{}'::jsonb")
        .execute(&pool)
        .await;

    let redis_client = redis::Client::open("redis://127.0.0.1/").expect("Failed to connect to Redis for Chronos");
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

    // Pull dynamic variables from the node's telemetry
    let network_diff_str: Option<String> = redis::cmd("GET").arg("pool:network_diff").query_async(&mut redis_conn).await.unwrap_or(None);
    let block_reward_str: Option<String> = redis::cmd("GET").arg("pool:block_reward").query_async(&mut redis_conn).await.unwrap_or(None);
    
    // ⚡ STRICT PPS LOCKDOWN: If the node drops and we lose our live metrics, abort the settlement tick entirely.
    // Do not guess the block reward or difficulty. Wait for the node to reconnect.
    if network_diff_str.is_none() || block_reward_str.is_none() {
        tracing::warn!("⚠️ L1 Node Metrics Unreachable. Pausing Chronos Yield Settlement to protect PPS integrity.");
        return Ok(());
    }

    let network_diff: f64 = network_diff_str.unwrap().parse::<f64>().unwrap_or(1.0).max(1.0);
    let mut block_reward: f64 = block_reward_str.unwrap().parse().unwrap_or(2.31);
    
    // Fail-safe: A block reward of 0 means the network has completed its emission schedule (Year 2057+).
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

    for address in addresses {
        // ⚡ PHASE 1: ASYNC PRE-CALCULATION (No DB Locks Held Here)
        let state_row = sqlx::query("SELECT layout_state FROM user_command_centers WHERE wallet_address = $1")
            .bind(&address)
            .fetch_optional(pool)
            .await?;

        let mut state: Value = match state_row {
            Some(row) => row.get("layout_state"),
            None => continue,
        };
        
        let workers_opt = state.get_mut("workers").and_then(|w| w.as_array_mut());
        if workers_opt.is_none() {
            continue;
        }

        let is_overclocked = state.get("systemMode").and_then(|v| v.as_str()) == Some("overclocked");
        let escrow_active = state.pointer("/taxFortress/escrowActive").and_then(|v| v.as_bool()).unwrap_or(false);

        // Map out existing balances before calculation
        let mut silo_pending_map: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
        if let Some(silos) = state.get("silos").and_then(|s| s.as_array()) {
            for silo in silos {
                if let (Some(id), Some(p)) = (silo.get("id").and_then(|v| v.as_str()), silo.get("pendingKaspa").and_then(|v| v.as_f64())) {
                    silo_pending_map.insert(id.to_string(), p);
                }
            }
        }

        let mut unassigned_yield = 0.0;

        // Process hardware shares and block payouts
        if let Some(workers) = state.get_mut("workers").and_then(|w| w.as_array_mut()) {
            for worker in workers.iter_mut() {
                let assigned_silo_id = worker.get("assignedSiloId").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let w_type = worker.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let mut earned_kaspa = 0.0;

                if w_type == "physical" {
                    let wallet_worker = worker.get("walletWorker").and_then(|v| v.as_str()).unwrap_or("");
                    if !wallet_worker.is_empty() {
                        let share_key = format!("worker:{}:shares", wallet_worker);
                        let block_key = format!("worker:{}:blocks_unpaid", wallet_worker); 
                        
                        let unprocessed_str: Option<String> = redis::cmd("GET").arg(&share_key).query_async(&mut redis_conn).await.unwrap_or(None);
                        let unprocessed: f64 = unprocessed_str.unwrap_or_else(|| "0".to_string()).parse().unwrap_or(0.0);

                        let unpaid_blocks_str: Option<String> = redis::cmd("GET").arg(&block_key).query_async(&mut redis_conn).await.unwrap_or(None);
                        let unpaid_blocks: f64 = unpaid_blocks_str.unwrap_or_else(|| "0".to_string()).parse().unwrap_or(0.0);

                        // ⚡ Pay Per Share (PPS) execution
                        if unprocessed > 0.0 {
                            earned_kaspa += unprocessed * reward_per_diff_unit;
                            let _: () = redis::cmd("SET").arg(&share_key).arg("0").query_async(&mut redis_conn).await.unwrap_or(());
                        }

                        // ⚡ Eradicate the Double-Dip: Do NOT award duplicate synthetic Kaspa
                        if unpaid_blocks > 0.0 {
                            let _: () = redis::cmd("SET").arg(&block_key).arg("0").query_async(&mut redis_conn).await.unwrap_or(());
                            tracing::info!("💎 [BLOCK FOUND] {} found {} blocks for the pool!", wallet_worker, unpaid_blocks);
                        }
                    }
                }

                if earned_kaspa > 0.0 {
                    if !assigned_silo_id.is_empty() {
                        if let Some(p) = silo_pending_map.get_mut(&assigned_silo_id) {
                            *p += earned_kaspa;
                        }
                    } else {
                        unassigned_yield += earned_kaspa;
                    }
                }
            }
        }

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
            
            tracing::info!("🚜 [THE FIELD] Directly credited {:.8} KAS to {}", unassigned_yield, address);
        }

        // Apply Overclock Micro-Fee Interceptor
        if is_overclocked {
            let mut total_tick_fee = OVERCLOCK_BASE_FEE;
            for pending in silo_pending_map.values_mut() {
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

        let mut plant_liquidity_updates = std::collections::HashMap::new();

        // Perform Plant LP Synthesis via sorEngine API
        if let Some(plants) = state.get("plants").and_then(|p| p.as_array()) {
            for plant in plants {
                let plant_id = plant.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let plant_name = plant.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                
                let mut assigned_silos = Vec::new();
                if let Some(silos) = state.get("silos").and_then(|s| s.as_array()) {
                    for silo in silos {
                        if silo.get("assignedPlantId").and_then(|v| v.as_str()).unwrap_or("") == plant_id {
                            assigned_silos.push(silo.clone());
                        }
                    }
                }

                if assigned_silos.len() == 2 {
                    let id1 = assigned_silos[0].get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let id2 = assigned_silos[1].get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();

                    let p1 = *silo_pending_map.get(&id1).unwrap_or(&0.0);
                    let p2 = *silo_pending_map.get(&id2).unwrap_or(&0.0);

                    if p1 >= MINIMUM_UTXO_SWEEP_THRESHOLD && p2 >= MINIMUM_UTXO_SWEEP_THRESHOLD {
                        let t1 = assigned_silos[0].pointer("/settlementConfig/targetAsset/ticker").and_then(|t| t.as_str()).unwrap_or("USDC").to_string();
                        let t2 = assigned_silos[1].pointer("/settlementConfig/targetAsset/ticker").and_then(|t| t.as_str()).unwrap_or("USDC").to_string();
                        
                        silo_pending_map.insert(id1.clone(), 0.0);
                        silo_pending_map.insert(id2.clone(), 0.0);

                        let mut executed_assets = Vec::new();
                        let mut total_lp_usd_value = 0.0;

                        let amt1 = if is_overclocked { p1 - (p1 * OVERCLOCK_PREMIUM_FEE) } else { p1 };
                        let amt2 = if is_overclocked { p2 - (p2 * OVERCLOCK_PREMIUM_FEE) } else { p2 };

                        tracing::info!("\n🌱 [CHRONOS SYNTHESIS] Auto-LP Intercept on Plant: {}", plant_name);

                        for (amt, target) in [(amt1, &t1), (amt2, &t2)] {
                            let req_payload = json!({ "wallet": address, "payAsset": "KAS", "receiveAsset": target, "amount": amt, "slippageTolerance": 0.05 });
                            if let Ok(res) = http_client.post("http://127.0.0.1:8002/v1/sor/execute").json(&req_payload).send().await {
                                if let Ok(data) = res.json::<Value>().await {
                                    if let Some(est) = data.get("estimatedOutput").and_then(|v| v.as_f64()) {
                                        let final_settled = est * (1.0 - NETWORK_FEE_PERCENTAGE);
                                        let fee = est * NETWORK_FEE_PERCENTAGE;
                                        executed_assets.push((target.clone(), final_settled, fee));
                                        let spot_price = get_spot_price(&mut redis_conn, target).await;
                                        total_lp_usd_value += final_settled * spot_price;
                                    }
                                }
                            }
                        }

                        let clean_address = address.replace("kaspa:", "");
                        let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_address);
                        let lp_pair_name = format!("{}/{} LP", t1, t2);

                        for (target, _settled, fee) in executed_assets {
                            let batch_fee_key = format!("perennia:fees:batch_accumulated:{}", target);
                            let _: () = redis::cmd("INCRBYFLOAT").arg(&batch_fee_key).arg(fee).query_async(&mut redis_conn).await.unwrap_or(());
                        }

                        let _: () = redis::cmd("HINCRBYFLOAT").arg(&user_ledger_key).arg(&lp_pair_name).arg(total_lp_usd_value).query_async(&mut redis_conn).await.unwrap_or(());

                        let _ = sqlx::query(
                            r#"INSERT INTO yield_reservoirs (wallet_address, streaming_balance_kas, total_yield_kas, lp_tokens) 
                               VALUES ($1, 0.0, 0.0, jsonb_build_object($2::text, $3::float8))
                               ON CONFLICT (wallet_address) DO UPDATE SET 
                               lp_tokens = jsonb_set(COALESCE(yield_reservoirs.lp_tokens, '{}'::jsonb), ARRAY[$2::text], to_jsonb(COALESCE((yield_reservoirs.lp_tokens->>$2::text)::numeric, 0.0) + $3::numeric)), last_updated = CURRENT_TIMESTAMP"#
                        ).bind(&address).bind(&lp_pair_name).bind(total_lp_usd_value).execute(pool).await;

                        tracing::info!("   -> 💧 Liquidity Provision Physics Executed: Minted {:.2} {} LP tokens.", total_lp_usd_value, lp_pair_name);

                        let current_usd = plant.pointer("/liquidityDeposit/totalLiquidityUsd").and_then(|v| v.as_f64()).unwrap_or(0.0) + total_lp_usd_value;
                        let multiplier = plant.pointer("/liquidityDeposit/multiplier").and_then(|v| v.as_f64()).unwrap_or(1.0);
                        let apr = 14.2 * multiplier;
                        
                        plant_liquidity_updates.insert(plant_id.to_string(), (current_usd, true, lp_pair_name, apr));
                    }
                }
            }
        }

        // Perform Standalone Silo Auto Payouts via sorEngine API
        if let Some(silos) = state.get("silos").and_then(|s| s.as_array()) {
            for silo in silos {
                if silo.get("assignedPlantId").map_or(false, |id| !id.is_null()) {
                    continue;
                }

                if let Some(id) = silo.get("id").and_then(|v| v.as_str()) {
                    let auto_payout = silo.pointer("/settlementConfig/autoPayout").and_then(|v| v.as_bool()).unwrap_or(false);
                    let pending = *silo_pending_map.get(id).unwrap_or(&0.0);

                    if auto_payout && pending >= MINIMUM_UTXO_SWEEP_THRESHOLD {
                        let threshold = silo.pointer("/settlementConfig/threshold").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let mode = silo.pointer("/settlementConfig/mode").and_then(|v| v.as_str()).unwrap_or("");

                        if mode == "stream" || (mode == "threshold" && pending >= threshold) {
                            let target_ticker = silo.pointer("/settlementConfig/targetAsset/ticker").and_then(|t| t.as_str()).unwrap_or("KAS").to_string();
                            let silo_name = silo.get("name").and_then(|n| n.as_str()).unwrap_or("Unknown").to_string();
                            
                            tracing::info!("\n💸 [CHRONOS EXECUTION] Settling Standalone Silo: {}", silo_name);

                            let mut amount_to_route = pending;
                            if escrow_active {
                                let tax_withholding = pending * 0.15;
                                amount_to_route = pending - tax_withholding;
                                
                                let tax_req = json!({ "wallet": address, "payAsset": "KAS", "receiveAsset": "USDC", "amount": tax_withholding, "slippageTolerance": 0.05 });
                                if let Ok(res) = http_client.post("http://127.0.0.1:8002/v1/sor/execute").json(&tax_req).send().await {
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

                            let req_payload = json!({ "wallet": address, "payAsset": "KAS", "receiveAsset": target_ticker, "amount": amount_to_route, "slippageTolerance": 0.05 });
                            let host_api = if target_ticker == "USD" { "http://127.0.0.1:3000/api/sor/yield_settle" } else { "http://127.0.0.1:8002/v1/sor/execute" };

                            if let Ok(res) = http_client.post(host_api).json(&req_payload).send().await {
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
                                        silo_pending_map.insert(id.to_string(), 0.0);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }


        // ====================================================================
        // ⚡ PHASE 2: SURGICAL DB MERGE (Sub-Millisecond Row Lock)
        // ====================================================================
        // Instead of saving our old 'state' back, we pull the absolute latest 
        // structural state from the UI to ensure we never overwrite Svelte deletes.
        
        let mut tx = pool.begin().await?;

        let latest_row = sqlx::query("SELECT layout_state FROM user_command_centers WHERE wallet_address = $1 FOR UPDATE")
            .bind(&address)
            .fetch_optional(&mut *tx)
            .await?;

        if let Some(row) = latest_row {
            let mut final_state: Value = row.get("layout_state");
            let mut state_mutated = false;

            // Surgically inject Silo Yields
            if let Some(silos) = final_state.get_mut("silos").and_then(|s| s.as_array_mut()) {
                for silo in silos.iter_mut() {
                    if let Some(id) = silo.get("id").and_then(|v| v.as_str()) {
                        if let Some(new_pending) = silo_pending_map.get(id) {
                            if silo.get("pendingKaspa").and_then(|v| v.as_f64()) != Some(*new_pending) {
                                silo["pendingKaspa"] = json!(*new_pending);
                                state_mutated = true;
                            }
                        }
                    }
                }
            }

            // Surgically inject Plant Liquidity Data
            if let Some(plants) = final_state.get_mut("plants").and_then(|p| p.as_array_mut()) {
                for plant in plants.iter_mut() {
                    if let Some(id) = plant.get("id").and_then(|v| v.as_str()) {
                        if let Some((usd, active, pair, apr)) = plant_liquidity_updates.get(id) {
                            if let Some(ld) = plant.get_mut("liquidityDeposit").and_then(|v| v.as_object_mut()) {
                                ld.insert("totalLiquidityUsd".to_string(), json!(*usd));
                                ld.insert("isActive".to_string(), json!(*active));
                                ld.insert("pairName".to_string(), json!(pair));
                            }
                            plant["currentApr"] = json!(*apr);
                            state_mutated = true;
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

                let mut silo_yields = Vec::new();
                if let Some(silos) = final_state.get("silos").and_then(|s| s.as_array()) {
                    for silo in silos {
                        if let (Some(id), Some(pending)) = (silo.get("id").and_then(|v| v.as_str()), silo.get("pendingKaspa").and_then(|v| v.as_f64())) {
                            silo_yields.push(json!({"id": id, "pendingKaspa": pending}));
                        }
                    }
                }

                let update_payload = json!({
                    "yield_update": true,
                    "wallet": address,
                    "silos": silo_yields
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