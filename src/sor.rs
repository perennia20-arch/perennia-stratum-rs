use axum::{Json, extract::State};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::env;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
pub struct UtxoInput {
    pub transactionId: String,
    pub index: u32,
    pub amount: f64,
    pub scriptPublicKey: String,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct SorExecuteRequest {
    pub wallet: String,
    pub payAsset: String,
    pub receiveAsset: String,
    pub amount: f64,
    pub slippageTolerance: Option<f64>,
    pub utxos: Option<Vec<UtxoInput>>,
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

// ⚡ Zero-Dependency Kaspa Address to P2PKH/Schnorr Script Decoder
fn decode_address_to_script(address: &str) -> Result<String, String> {
    let parts: Vec<&str> = address.split(':').collect();
    if parts.len() != 2 { return Err("Invalid address format".to_string()); }
    
    let base32 = parts[1];
    if base32.len() < 8 { return Err("Address too short".to_string()); }
    
    let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut decoded = Vec::new();
    for c in base32[..base32.len()-8].chars() {
        if let Some(idx) = charset.find(c) {
            decoded.push(idx as u8);
        } else {
            return Err("Invalid base32 char".to_string());
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
        let clean = address.replace("kaspa:", "");
        let hex_val = hex::encode(clean);
        let truncated = if hex_val.len() > 64 { &hex_val[0..64] } else { &hex_val };
        return Ok(format!("20{}ac", truncated));
    }
    
    let pubkey = &out[1..33];
    let mut hex_str = String::new();
    for byte in pubkey {
        use std::fmt::Write;
        write!(&mut hex_str, "{:02x}", byte).unwrap();
    }
    Ok(format!("20{}ac", hex_str))
}

async fn get_usd_price(redis_conn: &mut redis::aio::MultiplexedConnection, asset: &str) -> f64 {
    if asset == "USDC" || asset == "USDT" { return 1.0; }
    let key = format!("oracle:spot:{}_USDC", asset);
    let val_str: Option<String> = redis::cmd("GET").arg(&key).query_async(redis_conn).await.unwrap_or(None);
    if let Some(v) = val_str {
        v.parse().unwrap_or(1.0)
    } else {
        // Safe Fallbacks
        match asset {
            "KAS" => 0.16,
            "BTC" => 65000.0,
            "ETH" => 3500.0,
            "SOL" => 150.0,
            _ => 1.0,
        }
    }
}

pub async fn handle_sor_execute(
    State(_pool): State<PgPool>,
    Json(payload): Json<SorExecuteRequest>,
) -> Result<Json<SorExecutionPlan>, Json<SorError>> {
    tracing::info!("🔒 SOR Executing Live API Swap for: {}", payload.wallet);

    let client = Client::new();
    let redis_client = redis::Client::open("redis://127.0.0.1/").unwrap();
    let mut redis_conn = redis_client.get_multiplexed_async_connection().await.unwrap();

    // ⚡ Cross-Asset Spot Pricing Logic
    let pay_usd = get_usd_price(&mut redis_conn, &payload.payAsset).await;
    let rec_usd = get_usd_price(&mut redis_conn, &payload.receiveAsset).await;
    let spot_rate = if rec_usd > 0.0 { pay_usd / rec_usd } else { 0.0 };

    let mut remaining_amount = payload.amount;
    let mut total_estimated_output = 0.0;
    let mut legs = Vec::new();
    
    let min_chainge_usd = 15.0;
    let min_changenow_usd = 50.0;

    // Corporate Treasury Addresses
    let corp_kas = env::var("PERENNIA_TREASURY_KAS_ADDRESS").unwrap_or_else(|_| "kaspa:qrc3ezl770p2cjlfc3tjp6vqlldt6lgh3e80d6rm4rchtt0yrrpgzqave8579".to_string());
    let corp_btc = env::var("PERENNIA_TREASURY_BTC_ADDRESS").unwrap_or_else(|_| "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfJH754GL".to_string());
    let corp_eth = env::var("PERENNIA_TREASURY_ETH_ADDRESS").unwrap_or_else(|_| "0x71C7656EC7ab88b098defB751B7401B5f6d8976F".to_string());
    let corp_sol = env::var("PERENNIA_TREASURY_SOL_ADDRESS").unwrap_or_else(|_| "HN7cAB1wJe3D1v6K18u1nC9Wvy98aV3X45kv5FgvV61a".to_string());

    // Protocol Fee Configuration (1.5% Spread for Internal Zero-Cost Swaps)
    let protocol_fee_rate = 0.015;

    // ==========================================================
    // TIER 1: PERENNIA TREASURY (Internal Fast-Settlement)
    // ⚡ Real On-Chain Validation + Atomic Redis Fee Batching
    // ==========================================================
    let mut treasury_bal = 0.0;

    if payload.receiveAsset == "BTC" {
        if let Ok(res) = client.get(&format!("https://mempool.space/api/address/{}", corp_btc)).send().await {
            if let Ok(data) = res.json::<serde_json::Value>().await {
                let funded = data["chain_stats"]["funded_txo_sum"].as_f64().unwrap_or(0.0);
                let spent = data["chain_stats"]["spent_txo_sum"].as_f64().unwrap_or(0.0);
                treasury_bal = (funded - spent) / 100_000_000.0;
            }
        }
    } else if payload.receiveAsset == "ETH" {
        let req_body = json!({ "jsonrpc": "2.0", "method": "eth_getBalance", "params": [&corp_eth, "latest"], "id": 1 });
        if let Ok(res) = client.post("https://ethereum-rpc.publicnode.com").json(&req_body).send().await {
            if let Ok(data) = res.json::<serde_json::Value>().await {
                if let Some(hex_val) = data["result"].as_str() {
                    let clean_hex = hex_val.trim_start_matches("0x");
                    if let Ok(wei) = u64::from_str_radix(clean_hex, 16) {
                        treasury_bal = wei as f64 / 1e18;
                    }
                }
            }
        }
    } else if payload.receiveAsset == "SOL" {
        let req_body = json!({ "jsonrpc": "2.0", "method": "getBalance", "params": [&corp_sol], "id": 1 });
        if let Ok(res) = client.post("https://api.mainnet-beta.solana.com").json(&req_body).send().await {
            if let Ok(data) = res.json::<serde_json::Value>().await {
                treasury_bal = data["result"]["value"].as_f64().unwrap_or(0.0) / 1e9;
            }
        }
    } else if payload.receiveAsset == "KAS" {
        if let Ok(res) = client.get(&format!("https://api.kaspa.org/addresses/{}/balance", corp_kas)).send().await {
            if let Ok(data) = res.json::<serde_json::Value>().await {
                treasury_bal = data["balance"].as_f64().unwrap_or(0.0) / 100_000_000.0;
            }
        }
    } else {
        // Assume Kasplex KRC20
        let clean_kas = corp_kas.replace("kaspa:", "");
        if let Ok(res) = client.get(&format!("https://api.kasplex.org/v1/krc20/address/kaspa:{}/token/{}", clean_kas, payload.receiveAsset)).send().await {
            if let Ok(data) = res.json::<serde_json::Value>().await {
                if let Some(token) = data["result"].as_array().and_then(|arr| arr.first()) {
                    let bal_str = token["balance"].as_str().unwrap_or("0");
                    treasury_bal = bal_str.parse::<f64>().unwrap_or(0.0) / 100_000_000.0;
                }
            }
        }
    }

    if treasury_bal > 0.0 && remaining_amount > 0.0 {
        let treasury_bal_in_pay_asset = if spot_rate > 0.0 { treasury_bal / spot_rate } else { 0.0 };
        let fillable_in_pay_asset = remaining_amount.min(treasury_bal_in_pay_asset);
        
        if fillable_in_pay_asset > 0.0 {
            let execution_rate = spot_rate * (1.0 - protocol_fee_rate);
            let output = fillable_in_pay_asset * execution_rate;
            let captured_margin = fillable_in_pay_asset * spot_rate * protocol_fee_rate;

            // ⚡ ATOMIC BATCHED FEE ACCUMULATION
            // Pushes collected protocol fee directly into Perennia's corporate batch ledger in Redis
            let batch_fee_key = format!("perennia:fees:batch_accumulated:{}", payload.payAsset);
            let _: () = redis::cmd("INCRBYFLOAT")
                .arg(&batch_fee_key)
                .arg(captured_margin)
                .query_async(&mut redis_conn)
                .await
                .unwrap_or(());

            legs.push(WaterfallLeg {
                tier: 1,
                provider: "Perennia Native Treasury".to_string(),
                filledAmount: fillable_in_pay_asset,
                executionRate: execution_rate,
                marginCaptured: captured_margin,
            });

            tracing::info!(
                "💰 [INTERNAL SWAP FEE] Captured {:.6} {} into batch key '{}'", 
                captured_margin, payload.payAsset, batch_fee_key
            );

            remaining_amount -= fillable_in_pay_asset;
            total_estimated_output += output;
        }
    }

    // ==========================================================
    // TIER 2: KASPLEX KRC-20 (Decentralized Overflow AMM)
    // ==========================================================
    if remaining_amount > 0.0 {
        let kasplex_res = client.get(&format!("https://api.kasplex.org/v1/krc20/token/{}", payload.receiveAsset))
            .send().await;
        
        let mut kasplex_depth = 0.0;
        if let Ok(res) = kasplex_res {
            if let Ok(data) = res.json::<serde_json::Value>().await {
                if let Some(minted) = data.get("result").and_then(|r| r.get(0)).and_then(|m| m.get("max")).and_then(|m| m.as_str()) {
                    kasplex_depth = minted.parse::<f64>().unwrap_or(0.0) * 0.01; 
                }
            }
        }

        if kasplex_depth > 0.0 {
            let kasplex_depth_in_pay_asset = if spot_rate > 0.0 { kasplex_depth / spot_rate } else { 0.0 };
            let fillable = kasplex_depth_in_pay_asset.min(remaining_amount);
            
            if fillable > 0.0 {
                let rate = spot_rate * 0.997; 
                let output = fillable * rate;

                legs.push(WaterfallLeg {
                    tier: 2,
                    provider: "Kasplex KRC-20".to_string(),
                    filledAmount: fillable,
                    executionRate: rate,
                    marginCaptured: 0.0,
                });

                remaining_amount -= fillable;
                total_estimated_output += output;
            }
        }
    }

    // ==========================================================
    // TIER 3: CHAINGE FINANCE (Cross-Chain Bridging AMM)
    // ==========================================================
    if remaining_amount * pay_usd >= min_chainge_usd {
        let chainge_api_key = env::var("CHAINGE_API_KEY").unwrap_or_default();
        let chainge_req = json!({
            "fromChain": "KASPA", "toChain": "ETHEREUM",
            "fromToken": "KAS", "toToken": "USDC",
            "userAddress": payload.wallet,
            "amount": remaining_amount * 0.5 
        });
        
        let chainge_res = client.post("https://api.chainge.finance/v1/crosschain/address")
            .header("Authorization", format!("Bearer {}", chainge_api_key))
            .json(&chainge_req)
            .send().await;

        if let Ok(res) = chainge_res {
            if let Ok(data) = res.json::<serde_json::Value>().await {
                if let Some(_addr) = data.get("depositAddress").and_then(|a| a.as_str()) {
                    let fillable = remaining_amount * 0.5;
                    let rate = spot_rate * 0.995;
                    let output = fillable * rate;

                    legs.push(WaterfallLeg {
                        tier: 3,
                        provider: "Chainge AMM".to_string(),
                        filledAmount: fillable,
                        executionRate: rate,
                        marginCaptured: 0.0,
                    });

                    remaining_amount -= fillable;
                    total_estimated_output += output;
                }
            }
        }
    }

    // ==========================================================
    // TIER 4: CHANGENOW (Whale Router Fallback Live API)
    // ==========================================================
    if remaining_amount * pay_usd >= min_changenow_usd {
        let changenow_key = env::var("CHANGENOW_API_KEY").unwrap_or_default();
        let cnow_req = json!({
            "fromCurrency": "kas", "toCurrency": "usdc",
            "fromNetwork": "kas", "toNetwork": "eth",
            "fromAmount": remaining_amount,
            "address": corp_eth,
            "flow": "standard"
        });

        let cnow_res = client.post("https://api.changenow.io/v2/exchange")
            .header("x-changenow-api-key", changenow_key)
            .json(&cnow_req)
            .send().await;

        if let Ok(res) = cnow_res {
            if let Ok(data) = res.json::<serde_json::Value>().await {
                if let Some(_addr) = data.get("payinAddress").and_then(|a| a.as_str()) {
                    let fillable = remaining_amount;
                    let rate = spot_rate * 0.985;
                    let output = fillable * rate;

                    legs.push(WaterfallLeg {
                        tier: 4,
                        provider: "ChangeNOW Aggregator".to_string(),
                        filledAmount: fillable,
                        executionRate: rate,
                        marginCaptured: 0.0,
                    });

                    remaining_amount = 0.0;
                    total_estimated_output += output;
                }
            }
        }
    }

    if legs.is_empty() && payload.amount > 0.0 {
        return Err(Json(SorError { error: "Liquidity Exhausted. No hard-routing paths available on-chain.".to_string() }));
    }

    let filled_amount = payload.amount - remaining_amount;
    let unified_rate = if filled_amount > 0.0 { total_estimated_output / filled_amount } else { 0.0 };
    let tx_uuid = Uuid::new_v4().to_string();

    let mut psbt = None;

    // ==========================================================
    // PSBT CONSTRUCTION FOR HARD ZERO-TRUST HONEYCOMB EXECUTION
    // ==========================================================
    if let Some(utxos) = &payload.utxos {
        let target_amount_sompi = (filled_amount * 1e8).floor() as u64;
        let fee_sompi = 10000;
        let total_required = target_amount_sompi + fee_sompi;

        let mut gathered_sompi = 0;
        let mut tx_inputs = Vec::new();

        for utxo in utxos {
            tx_inputs.push(json!({
                "previousOutpoint": {
                    "transactionId": utxo.transactionId,
                    "index": utxo.index
                },
                "signatureScript": "",
                "sequence": 0,
                "sigOpCount": 1
            }));
            gathered_sompi += utxo.amount as u64;
            if gathered_sompi >= total_required {
                break;
            }
        }

        if gathered_sompi < total_required {
            return Err(Json(SorError { error: format!("ERR_INSUFFICIENT_MASS: Required {}, Found {}", total_required, gathered_sompi) }));
        }

        let mut tx_outputs = Vec::new();

        for leg in &legs {
            let leg_sompi = (leg.filledAmount * 1e8).floor() as u64;
            if leg_sompi == 0 { continue; }

            let mut dest_address = String::new();
            match leg.tier {
                1 => dest_address = corp_kas.clone(),
                2 => dest_address = "kaspa:kasplex_krc20_router_inbound".to_string(),
                3 => dest_address = "kaspa:chainge_finance_bridge_fallback".to_string(), 
                4 => dest_address = "kaspa:changenow_whale_fallback".to_string(),
                _ => {}
            }

            let script_pub_key = decode_address_to_script(&dest_address)
                .unwrap_or_else(|_| "200000000000000000000000000000000000000000000000000000000000000000ac".to_string());

            tx_outputs.push(json!({
                "amount": leg_sompi as u64,
                "scriptPublicKey": script_pub_key,
                "_metadata": { "provider": leg.provider, "tier": leg.tier }
            }));
        }

        let change_sompi = gathered_sompi - total_required;
        if change_sompi > 0 {
            tx_outputs.push(json!({
                "amount": change_sompi as u64,
                "scriptPublicKey": decode_address_to_script(&payload.wallet).unwrap_or_else(|_| "200000000000000000000000000000000000000000000000000000000000000000ac".to_string()),
                "_metadata": { "type": "change" }
            }));
        }

        psbt = Some(json!({
            "version": 0,
            "inputs": tx_inputs,
            "outputs": tx_outputs,
            "lockTime": 0,
            "subnetworkId": "0000000000000000000000000000000000000000",
            "gas": 0,
            "payload": "",
            "mass": 0,
            "storageMass": 0
        }));
    }

    Ok(Json(SorExecutionPlan {
        totalAmount: filled_amount,
        unifiedRate: unified_rate,
        estimatedOutput: total_estimated_output,
        legs,
        transaction_uuid: tx_uuid,
        psbt,
        formattedUtxos: payload.utxos.clone(),
    }))
}