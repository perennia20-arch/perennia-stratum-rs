// src/sor.rs
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

fn decode_address_to_script(address: &str) -> Result<String, String> {
    let parts: Vec<&str> = address.split(':').collect();
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
            return Err("Invalid base32 character".to_string());
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
    if asset == "USDC" || asset == "USDT" || asset == "USD" {
        return 1.0;
    }
    let key = format!("oracle:spot:{}_USDC", asset);
    let val_str: Option<String> = redis::cmd("GET")
        .arg(&key)
        .query_async(redis_conn)
        .await
        .unwrap_or(None);
        
    if let Some(v) = val_str {
        v.parse().unwrap_or(0.0)
    } else {
        0.0
    }
}

pub async fn handle_sor_execute(
    State(_pool): State<PgPool>,
    Json(payload): Json<SorExecuteRequest>,
) -> Result<Json<SorExecutionPlan>, Json<SorError>> {
    let client = Client::new();
    
    // ⚡ INFRASTRUCTURE HARDENING
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = match redis::Client::open(redis_url) {
        Ok(c) => c,
        Err(e) => return Err(Json(SorError { error: format!("Redis Error: {}", e) })),
    };
    let mut redis_conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => return Err(Json(SorError { error: format!("Redis Connection Error: {}", e) })),
    };

    let pay_usd = get_usd_price(&mut redis_conn, &payload.payAsset).await;
    let rec_usd = get_usd_price(&mut redis_conn, &payload.receiveAsset).await;
    
    if pay_usd <= 0.0 || rec_usd <= 0.0 {
        return Err(Json(SorError {
            error: format!("Live Oracle feed unavailable for pair {}/{}", payload.payAsset, payload.receiveAsset)
        }));
    }

    let spot_rate = pay_usd / rec_usd;
    let is_overclocked = payload.systemMode.as_deref() == Some("overclocked");
    let tx_uuid = Uuid::new_v4().to_string();

    if !is_overclocked {
        tracing::info!("🕸️ [STANDARD MODE] Routing to Dark Pool: {}", payload.wallet);
        
        let protocol_fee_rate = 0.015; 
        let execution_rate = spot_rate * (1.0 - protocol_fee_rate);
        let estimated_output = payload.amount * execution_rate;
        let fee_captured_usd = payload.amount * pay_usd * protocol_fee_rate;

        let direction = if payload.payAsset == "KAS" { "SELL_KAS" } else { "BUY_KAS" };
        let netting_order = json!({
            "wallet": payload.wallet,
            "direction": direction,
            "amount_kas": if payload.payAsset == "KAS" { payload.amount } else { estimated_output },
            "spot_price": spot_rate,
            "fee_captured_usd": fee_captured_usd
        });

        let _: () = redis::cmd("RPUSH")
            .arg("perennia:sor:netting_queue")
            .arg(netting_order.to_string())
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(());

        return Ok(Json(SorExecutionPlan {
            totalAmount: payload.amount,
            unifiedRate: execution_rate,
            estimatedOutput: estimated_output,
            legs: vec![WaterfallLeg {
                tier: 0,
                provider: "Perennia Dark Pool (Batched)".to_string(),
                filledAmount: payload.amount,
                executionRate: execution_rate,
                marginCaptured: fee_captured_usd,
            }],
            transaction_uuid: tx_uuid,
            psbt: None,
            formattedUtxos: payload.utxos.clone(),
        }));
    }

    tracing::info!("🚀 [OVERCLOCKED] High-Velocity Mode Triggered for {}", payload.wallet);

    let mut remaining_amount = payload.amount;
    let mut total_estimated_output = 0.0;
    let mut legs = Vec::new();
    
    let overclock_fee_rate = 0.025; 
    let min_chainge_usd = 15.0;
    let min_changenow_usd = 50.0;

    let corp_kas = env::var("PERENNIA_TREASURY_KAS_ADDRESS")
        .unwrap_or_else(|_| "kaspa:qrc3ezl770p2cjlfc3tjp6vqlldt6lgh3e80d6rm4rchtt0yrrpgzqave8579".to_string());
    let corp_btc = env::var("PERENNIA_TREASURY_BTC_ADDRESS")
        .unwrap_or_else(|_| "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfJH754GL".to_string());
    let corp_eth = env::var("PERENNIA_TREASURY_ETH_ADDRESS")
        .unwrap_or_else(|_| "0x71C7656EC7ab88b098defB751B7401B5f6d8976F".to_string());
    let corp_sol = env::var("PERENNIA_TREASURY_SOL_ADDRESS")
        .unwrap_or_else(|_| "HN7cAB1wJe3D1v6K18u1nC9Wvy98aV3X45kv5FgvV61a".to_string());

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
            let execution_rate = spot_rate * (1.0 - overclock_fee_rate);
            let output = fillable_in_pay_asset * execution_rate;
            
            let standard_margin = fillable_in_pay_asset * spot_rate * 0.015;
            let _: () = redis::cmd("INCRBYFLOAT")
                .arg(format!("perennia:fees:batch_accumulated:{}", payload.payAsset))
                .arg(standard_margin)
                .query_async(&mut redis_conn)
                .await
                .unwrap_or(());

            let express_margin = fillable_in_pay_asset * spot_rate * 0.01;
            let _: () = redis::cmd("INCRBYFLOAT")
                .arg("perennia:treasury:express_premiums_usd")
                .arg(express_margin * pay_usd)
                .query_async(&mut redis_conn)
                .await
                .unwrap_or(());

            legs.push(WaterfallLeg {
                tier: 1,
                provider: "Perennia Express L1".to_string(),
                filledAmount: fillable_in_pay_asset,
                executionRate: execution_rate,
                marginCaptured: standard_margin + express_margin,
            });

            remaining_amount -= fillable_in_pay_asset;
            total_estimated_output += output;
        }
    }

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
        return Err(Json(SorError {
            error: "Express Liquidity Exhausted. Turn off Overclock to access the batched Dark Pool.".to_string()
        }));
    }

    let filled_amount = payload.amount - remaining_amount;
    let unified_rate = if filled_amount > 0.0 { total_estimated_output / filled_amount } else { 0.0 };
    
    let mut psbt = None;

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
            if gathered_sompi >= total_required { break; }
        }

        if gathered_sompi < total_required {
            return Err(Json(SorError {
                error: format!("ERR_INSUFFICIENT_MASS: Required {}, Found {}", total_required, gathered_sompi)
            }));
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