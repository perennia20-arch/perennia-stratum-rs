use secp256k1::{Keypair, Message, SecretKey, SECP256K1};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::env;
use uuid::Uuid;

use crate::state_api::{
    blake2b_256, blake2b_256_keyed, decode_kaspa_address_payload, encode_kaspa_bech32m_address,
    KASPA_ADDR_VERSION_P2PK_SCHNORR, KASPA_ADDR_VERSION_P2SH,
};

const TX_SIGNING_KEY: &[u8] = b"TransactionSigningHash";
const SIGHASH_ALL: u8 = 0x01;
const FEE_PER_GRAM: u64 = 110;
const MIN_CHANGE_SOMPI: u64 = 10_000_000;

#[derive(Clone, Debug)]
struct SpendableKaspaUtxo {
    transaction_id: String,
    index: u32,
    amount_sompi: u64,
    script_public_key_hex: String,
}

pub fn resolve_network_for_asset(asset_ticker: &str) -> String {
    match asset_ticker.trim().to_uppercase().as_str() {
        "KAS" | "SILO" | "BEDRCK" | "NACHO" | "PERX" => "KAS".to_string(),
        "BTC" => "BTC".to_string(),
        "ETH" | "USDC" | "USDT" | "XAU" | "XAG" | "USTB" => "ETH".to_string(),
        "SOL" => "SOL".to_string(),
        "DOGE" => "DOGE".to_string(),
        "XRP" => "XRP".to_string(),
        "POL" => "POL".to_string(),
        "AVAX" => "AVAX".to_string(),
        "SUI" => "SUI".to_string(),
        "TRX" => "TRX".to_string(),
        "ZEC" => "ZEC".to_string(),
        "ARB" => "ARB".to_string(),
        "BASE" | "NVDA" | "SPY" | "QQQ" | "AAPL" | "TSLA" | "AMD" | "TSM" | "AVGO" | "XLE" => {
            "BASE".to_string()
        }
        other => other.to_string(),
    }
}

pub fn explorer_tx_url_for_asset(asset: &str, network: &str, tx_hash: &str) -> String {
    let clean_tx = tx_hash.trim();
    if clean_tx.is_empty() || clean_tx.starts_with("PER-L1-") {
        return "#".to_string();
    }
    let net = if !network.trim().is_empty() {
        network.trim().to_uppercase()
    } else {
        resolve_network_for_asset(asset)
    };
    match net.as_str() {
        "KAS" => format!("https://kas.fyi/transaction/{}", clean_tx),
        "BTC" => format!("https://mempool.space/tx/{}", clean_tx),
        "ETH" => format!("https://etherscan.io/tx/{}", clean_tx),
        "SOL" => format!("https://solscan.io/tx/{}", clean_tx),
        "XRP" => format!("https://xrpscan.com/tx/{}", clean_tx),
        "DOGE" => format!("https://blockchair.com/dogecoin/transaction/{}", clean_tx),
        "POL" => format!("https://polygonscan.com/tx/{}", clean_tx),
        "AVAX" => format!("https://snowtrace.io/tx/{}", clean_tx),
        "ARB" => format!("https://arbiscan.io/tx/{}", clean_tx),
        "BASE" => format!("https://basescan.org/tx/{}", clean_tx),
        "SUI" => format!("https://suiscan.xyz/mainnet/tx/{}", clean_tx),
        "TRX" => format!("https://tronscan.org/#/transaction/{}", clean_tx),
        "ZEC" => format!("https://blockchair.com/zcash/transaction/{}", clean_tx),
        _ => format!("https://kas.fyi/transaction/{}", clean_tx),
    }
}

pub fn build_explorer_tx_url(asset: &str, tx_hash: &str) -> String {
    explorer_tx_url_for_asset(asset, "", tx_hash)
}

fn address_to_spk_hex(address: &str) -> Result<String, String> {
    let (version, hash32) = decode_kaspa_address_payload(address)
        .ok_or_else(|| format!("Invalid Kaspa Bech32m address: {}", address))?;
    let hex_hash = hex::encode(hash32);
    if version == KASPA_ADDR_VERSION_P2SH {
        Ok(format!("a9{}87", hex_hash))
    } else {
        Ok(format!("20{}ac", hex_hash))
    }
}

fn resolve_hot_kaspa_keypair() -> Result<(Keypair, String, String), String> {
    let raw_hex = env::var("PERENNIA_HOT_KAS_PRIVATE_KEY")
        .or_else(|_| env::var("PERENNIA_TREASURY_PRIVATE_KEY"))
        .map_err(|_| {
            "HOT_WALLET_KEY_MISSING: Set PERENNIA_HOT_KAS_PRIVATE_KEY in .env for automated L1 signing."
                .to_string()
        })?;
    let clean_hex = raw_hex.trim().trim_start_matches("0x");
    let mut priv_bytes =
        hex::decode(clean_hex).map_err(|_| "Invalid hex in PERENNIA_HOT_KAS_PRIVATE_KEY".to_string())?;
    if priv_bytes.len() != 32 {
        priv_bytes.fill(0);
        return Err("PERENNIA_HOT_KAS_PRIVATE_KEY must be exactly 32 bytes (64 hex chars).".to_string());
    }
    let secret_key = SecretKey::from_slice(&priv_bytes)
        .map_err(|e| format!("Invalid secp256k1 secret key: {}", e))?;
    priv_bytes.fill(0);

    let keypair = Keypair::from_secret_key(SECP256K1, &secret_key);
    let (xonly_pub, _) = keypair.x_only_public_key();
    let pub_bytes: [u8; 32] = xonly_pub.serialize();

    let derived_address = encode_kaspa_bech32m_address(KASPA_ADDR_VERSION_P2PK_SCHNORR, &pub_bytes);
    let configured_address = env::var("PERENNIA_HOT_KAS_ADDRESS")
        .or_else(|_| env::var("PERENNIA_TREASURY_KAS_ADDRESS"))
        .ok()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| s.starts_with("kaspa:") && s.len() >= 60)
        .unwrap_or(derived_address);

    let source_spk_hex = format!("20{}ac", hex::encode(pub_bytes));
    Ok((keypair, configured_address, source_spk_hex))
}

async fn fetch_hot_wallet_utxos(
    source_address: &str,
    default_spk_hex: &str,
) -> Result<Vec<SpendableKaspaUtxo>, String> {
    let raw_entries = match crate::kaspad_client::get_utxos_by_address_grpc(source_address).await {
        Ok(entries) if !entries.is_empty() => entries,
        _ => {
            let rest_url = env::var("KASPA_REST_URL")
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .unwrap_or_else(|_| "https://api.kaspa.org".to_string());
            let endpoint = format!("{}/addresses/{}/utxos", rest_url, source_address);
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(6))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());
            let resp = client
                .get(&endpoint)
                .send()
                .await
                .map_err(|e| format!("Failed to fetch hot wallet UTXOs: {}", e))?;
            if !resp.status().is_success() {
                return Err(format!(
                    "UTXO lookup rejected by node with HTTP {}",
                    resp.status()
                ));
            }
            resp.json::<Vec<Value>>()
                .await
                .map_err(|e| format!("Invalid UTXO JSON response: {}", e))?
        }
    };

    let mut utxos = Vec::with_capacity(raw_entries.len());
    for u in raw_entries {
        let tx_id = u
            .get("outpoint")
            .and_then(|o| o.get("transactionId"))
            .or_else(|| u.get("transactionId"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if tx_id.len() != 64 {
            continue;
        }
        let index = u
            .get("outpoint")
            .and_then(|o| o.get("index"))
            .or_else(|| u.get("index"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let amount_sompi = u
            .get("utxoEntry")
            .and_then(|e| e.get("amount"))
            .or_else(|| u.get("amount"))
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            })
            .unwrap_or(0);
        if amount_sompi == 0 {
            continue;
        }
        let spk_hex = u
            .get("utxoEntry")
            .and_then(|e| e.get("scriptPublicKey"))
            .and_then(|s| s.get("scriptPublicKey").or(Some(s)))
            .or_else(|| u.get("scriptPublicKey"))
            .and_then(|v| {
                v.as_str()
                    .or_else(|| v.get("scriptPublicKey").and_then(|s| s.as_str()))
            })
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(default_spk_hex)
            .to_string();

        utxos.push(SpendableKaspaUtxo {
            transaction_id: tx_id,
            index,
            amount_sompi,
            script_public_key_hex: spk_hex,
        });
    }

    utxos.sort_by(|a, b| b.amount_sompi.cmp(&a.amount_sompi));
    if utxos.is_empty() {
        return Err(format!(
            "Hot dispatcher wallet ({}) has 0 spendable UTXOs.",
            source_address
        ));
    }
    Ok(utxos)
}

pub async fn sign_and_broadcast_kaspa_payout_batch(
    pool: &PgPool,
    idempotency_key: &str,
    recipients: &[(String, u64)],
    payload_hex: &str,
) -> Result<String, String> {
    let sys_cfg = crate::chronos::load_system_treasury_config(pool).await;
    if sys_cfg.outflow_breaker_tripped {
        return Err(
            "CIRCUIT_BREAKER_TRIPPED: Director has paused automated L1 outflows.".to_string(),
        );
    }

    if let Ok(Some(existing)) = sqlx::query(
        r#"
        SELECT deterministic_txid, state
        FROM idempotent_payout_batches
        WHERE idempotency_key = $1
        LIMIT 1
        "#,
    )
    .bind(idempotency_key)
    .fetch_optional(pool)
    .await
    {
        let st: String = existing.try_get("state").unwrap_or_default();
        let txid_opt: Option<String> = existing.try_get("deterministic_txid").ok().flatten();
        if (st == "CONFIRMED" || st == "IN_FLIGHT") && txid_opt.is_some() {
            return Ok(txid_opt.unwrap());
        }
    }

    let valid_recipients: Vec<(String, u64, String)> = recipients
        .iter()
        .filter(|(addr, sompi)| !addr.trim().is_empty() && *sompi > 0)
        .map(|(addr, sompi)| {
            let spk = address_to_spk_hex(addr)?;
            Ok((addr.clone(), *sompi, spk))
        })
        .collect::<Result<Vec<_>, String>>()?;

    if valid_recipients.is_empty() {
        return Err("No valid recipients with positive sompi in payout batch.".to_string());
    }

    let (keypair, source_address, source_spk_hex) = resolve_hot_kaspa_keypair()?;
    let available_utxos = fetch_hot_wallet_utxos(&source_address, &source_spk_hex).await?;

    let target_total_sompi: u64 = valid_recipients.iter().map(|(_, s, _)| *s).sum();
    let payload_bytes = if payload_hex.trim().is_empty() {
        Vec::new()
    } else {
        hex::decode(payload_hex.trim())
            .map_err(|_| "Invalid payload_hex in Kaspa transaction".to_string())?
    };

    let mut selected_utxos = Vec::new();
    let mut gathered_sompi: u64 = 0;
    let mut fee_sompi: u64 = 0;
    let num_outputs_est = (valid_recipients.len() + 1) as u64;

    for u in available_utxos {
        gathered_sompi = gathered_sompi.saturating_add(u.amount_sompi);
        selected_utxos.push(u);
        let compute_mass = 200u64
            + (selected_utxos.len() as u64) * 1200u64
            + num_outputs_est * 450u64
            + (payload_bytes.len() as u64);
        fee_sompi = compute_mass * FEE_PER_GRAM;
        if gathered_sompi >= target_total_sompi.saturating_add(fee_sompi) {
            break;
        }
    }

    if gathered_sompi < target_total_sompi.saturating_add(fee_sompi) {
        return Err(format!(
            "INSUFFICIENT_HOT_WALLET_UTXO_MASS: Required {} sompi, available {} sompi on {}.",
            target_total_sompi.saturating_add(fee_sompi),
            gathered_sompi,
            source_address
        ));
    }

    let change_sompi = gathered_sompi.saturating_sub(target_total_sompi.saturating_add(fee_sompi));
    let mut tx_outputs: Vec<(u64, String)> = valid_recipients
        .iter()
        .map(|(_, sompi, spk)| (*sompi, spk.clone()))
        .collect();
    if change_sompi >= MIN_CHANGE_SOMPI {
        tx_outputs.push((change_sompi, source_spk_hex.clone()));
    }

    let mut prev_outs_buf = Vec::with_capacity(selected_utxos.len() * 36);
    let mut sequences_buf = Vec::with_capacity(selected_utxos.len() * 8);
    let mut sig_op_counts_buf = Vec::with_capacity(selected_utxos.len());

    for u in &selected_utxos {
        let txid_bytes = hex::decode(&u.transaction_id)
            .map_err(|_| format!("Malformed UTXO transactionId: {}", u.transaction_id))?;
        prev_outs_buf.extend_from_slice(&txid_bytes);
        prev_outs_buf.extend_from_slice(&u.index.to_le_bytes());
        sequences_buf.extend_from_slice(&0u64.to_le_bytes());
        sig_op_counts_buf.push(1u8);
    }

    let prev_outs_hash = blake2b_256_keyed(TX_SIGNING_KEY, &prev_outs_buf);
    let sequences_hash = blake2b_256_keyed(TX_SIGNING_KEY, &sequences_buf);
    let sig_op_counts_hash = blake2b_256_keyed(TX_SIGNING_KEY, &sig_op_counts_buf);

    let mut outputs_buf = Vec::new();
    for (amt, spk_hex) in &tx_outputs {
        let spk_bytes =
            hex::decode(spk_hex).map_err(|_| format!("Invalid output SPK hex: {}", spk_hex))?;
        outputs_buf.extend_from_slice(&amt.to_le_bytes());
        outputs_buf.extend_from_slice(&0u16.to_le_bytes());
        outputs_buf.extend_from_slice(&(spk_bytes.len() as u64).to_le_bytes());
        outputs_buf.extend_from_slice(&spk_bytes);
    }
    let outputs_hash = blake2b_256_keyed(TX_SIGNING_KEY, &outputs_buf);

    let payload_hash = if payload_bytes.is_empty() {
        [0u8; 32]
    } else {
        let mut p_buf = Vec::with_capacity(8 + payload_bytes.len());
        p_buf.extend_from_slice(&(payload_bytes.len() as u64).to_le_bytes());
        p_buf.extend_from_slice(&payload_bytes);
        blake2b_256_keyed(TX_SIGNING_KEY, &p_buf)
    };

    let mut signed_inputs_json = Vec::with_capacity(selected_utxos.len());
    for u in &selected_utxos {
        let txid_bytes = hex::decode(&u.transaction_id).unwrap_or_default();
        let spk_bytes = hex::decode(&u.script_public_key_hex).unwrap_or_default();

        let mut preimage = Vec::with_capacity(220 + spk_bytes.len());
        preimage.extend_from_slice(&0u16.to_le_bytes());
        preimage.extend_from_slice(&prev_outs_hash);
        preimage.extend_from_slice(&sequences_hash);
        preimage.extend_from_slice(&sig_op_counts_hash);
        preimage.extend_from_slice(&txid_bytes);
        preimage.extend_from_slice(&u.index.to_le_bytes());
        preimage.extend_from_slice(&0u16.to_le_bytes());
        preimage.extend_from_slice(&(spk_bytes.len() as u64).to_le_bytes());
        preimage.extend_from_slice(&spk_bytes);
        preimage.extend_from_slice(&u.amount_sompi.to_le_bytes());
        preimage.extend_from_slice(&0u64.to_le_bytes());
        preimage.push(1u8);
        preimage.extend_from_slice(&outputs_hash);
        preimage.extend_from_slice(&0u64.to_le_bytes());
        preimage.extend_from_slice(&[0u8; 20]);
        preimage.extend_from_slice(&0u64.to_le_bytes());
        preimage.extend_from_slice(&payload_hash);
        preimage.push(SIGHASH_ALL);

        let sighash = blake2b_256_keyed(TX_SIGNING_KEY, &preimage);
        let msg = Message::from_digest(sighash);
        let sig = SECP256K1.sign_schnorr_no_aux_rand(&msg, &keypair);
        let sig_script = format!("41{}01", hex::encode(sig.as_ref()));

        signed_inputs_json.push(json!({
            "previousOutpoint": {
                "transactionId": u.transaction_id,
                "index": u.index
            },
            "signatureScript": sig_script,
            "sequence": 0,
            "sigOpCount": 1
        }));
    }

    let outputs_json: Vec<Value> = tx_outputs
        .iter()
        .map(|(amt, spk)| {
            json!({
                "amount": *amt,
                "scriptPublicKey": {
                    "version": 0,
                    "scriptPublicKey": spk
                }
            })
        })
        .collect();

    let signed_tx_envelope = json!({
        "transaction": {
            "version": 0,
            "inputs": signed_inputs_json,
            "outputs": outputs_json,
            "lockTime": 0,
            "subnetworkId": "0000000000000000000000000000000000000000",
            "gas": 0,
            "payload": payload_hex.trim()
        }
    });

    let pre_broadcast_digest = blake2b_256(
        format!(
            "IN_FLIGHT:{}:{}:{}",
            idempotency_key,
            prev_outs_hash
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            hex::encode(outputs_hash)
        )
        .as_bytes(),
    );
    let provisional_lock_id = hex::encode(pre_broadcast_digest);
    let batch_id = format!("BATCH-{}", &provisional_lock_id[..16].to_uppercase());
    let manifest_json: Vec<Value> = valid_recipients
        .iter()
        .map(|(addr, sompi, _)| {
            json!({
                "address": addr,
                "sompi": *sompi,
                "amountKas": (*sompi as f64) / 100_000_000.0
            })
        })
        .collect();

    sqlx::query(
        r#"
        INSERT INTO idempotent_payout_batches (
            batch_id, idempotency_key, deterministic_txid, signed_tx_json,
            total_sompi, recipient_manifest, state, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, 'IN_FLIGHT', CURRENT_TIMESTAMP)
        ON CONFLICT (idempotency_key) DO UPDATE SET
            signed_tx_json = EXCLUDED.signed_tx_json,
            state = 'IN_FLIGHT',
            updated_at = CURRENT_TIMESTAMP
        "#,
    )
    .bind(&batch_id)
    .bind(idempotency_key)
    .bind(&provisional_lock_id)
    .bind(&signed_tx_envelope)
    .bind(target_total_sompi as i64)
    .bind(Value::Array(manifest_json))
    .execute(pool)
    .await
    .map_err(|e| format!("Failed to persist IN_FLIGHT idempotency lock: {}", e))?;

    let broadcast_txid = match crate::kaspad_client::submit_transaction_grpc(
        &signed_tx_envelope,
        false,
    )
    .await
    {
        Ok(txid) => txid,
        Err(grpc_err) => {
            tracing::warn!(
                "⚠️ [L1 DISPATCHER] gRPC broadcast failed ({}), attempting REST broadcast...",
                grpc_err
            );
            let rest_url = env::var("KASPA_REST_URL")
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .unwrap_or_else(|_| "https://api.kaspa.org".to_string());
            let endpoint = format!("{}/transactions", rest_url);
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());
            let resp = client
                .post(&endpoint)
                .json(&signed_tx_envelope)
                .send()
                .await
                .map_err(|e| {
                    format!(
                        "Both kaspad gRPC ({}) and REST ({}) failed",
                        grpc_err, e
                    )
                })?;
            if !resp.status().is_success() {
                let err_text = resp.text().await.unwrap_or_default();
                let _ = sqlx::query(
                    r#"
                    UPDATE idempotent_payout_batches
                    SET state = 'FAILED_BROADCAST',
                        retry_count = retry_count + 1,
                        last_error = $2,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE idempotency_key = $1
                    "#,
                )
                .bind(idempotency_key)
                .bind(&err_text)
                .execute(pool)
                .await;
                return Err(format!("Kaspa node rejected L1 broadcast: {}", err_text));
            }
            let body_json: Value = resp
                .json()
                .await
                .map_err(|e| format!("Invalid broadcast JSON response: {}", e))?;
            body_json
                .get("transactionId")
                .or_else(|| body_json.get("id"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Kaspa REST broadcast returned no transactionId".to_string())?
                .to_string()
        }
    };

    let _ = sqlx::query(
        r#"
        UPDATE idempotent_payout_batches
        SET deterministic_txid = $2,
            state = 'CONFIRMED',
            updated_at = CURRENT_TIMESTAMP
        WHERE idempotency_key = $1
        "#,
    )
    .bind(idempotency_key)
    .bind(&broadcast_txid)
    .execute(pool)
    .await;

    Ok(broadcast_txid)
}

pub async fn dispatch_or_queue_l1_payout(
    pool: &PgPool,
    wallet_address: &str,
    destination_address: &str,
    asset_ticker: &str,
    network_override: Option<&str>,
    amount_tokens: f64,
    spot_price: f64,
    source_type: &str,
) -> Result<Value, String> {
    if amount_tokens <= 0.0 {
        return Err("L1 payout amount_tokens must be greater than 0.".to_string());
    }

    let clean_asset = asset_ticker.trim().to_uppercase();
    let network = network_override
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| resolve_network_for_asset(&clean_asset));

    let is_system_otc = source_type.eq_ignore_ascii_case("otc_settlement")
        || wallet_address.contains("treasury_master");

    if !is_system_otc && clean_asset == "KAS" {
        let debit_check = if source_type.eq_ignore_ascii_case("cold_airlock_sweep")
            || source_type.eq_ignore_ascii_case("ledger_withdrawal")
        {
            amount_tokens
        } else {
            0.0
        };
        crate::chronos::verify_wallet_ledger_invariant_or_quarantine(
            pool,
            wallet_address,
            debit_check,
        )
        .await?;
    }

    let gross_usd = (amount_tokens * spot_price.max(0.0)).max(0.0);
    let payout_id = format!(
        "PER-L1-{}",
        Uuid::new_v4()
            .to_string()
            .replace('-', "")
            .chars()
            .take(12)
            .collect::<String>()
            .to_uppercase()
    );

    let mut dispatched_tx_hash = String::new();
    let mut queue_reason_opt: Option<String> = None;

    if network == "KAS" {
        let (sompi_to_send, payload_hex) = if clean_asset == "KAS" {
            let sompi = (amount_tokens * 100_000_000.0).round() as u64;
            (sompi, String::new())
        } else {
            let formatted_dest = if destination_address.trim().to_lowercase().starts_with("kaspa:") {
                destination_address.trim().to_lowercase()
            } else {
                format!("kaspa:{}", destination_address.trim().to_lowercase())
            };
            let base_units = ((amount_tokens * 100_000_000.0).round() as u128).to_string();
            let krc20_json = json!({
                "p": "krc-20",
                "op": "transfer",
                "tick": clean_asset,
                "amt": base_units,
                "to": formatted_dest
            });
            (30_000_000u64, hex::encode(krc20_json.to_string().as_bytes()))
        };

        let idemp_key = format!("L1-DISPATCH-{}", payout_id);
        match sign_and_broadcast_kaspa_payout_batch(
            pool,
            &idemp_key,
            &[(destination_address.to_string(), sompi_to_send)],
            &payload_hex,
        )
        .await
        {
            Ok(real_txid) => {
                dispatched_tx_hash = real_txid;
            }
            Err(err) => {
                queue_reason_opt = Some(err);
            }
        }
    } else {
        queue_reason_opt = Some(format!(
            "Queued {} ({}) payout for multi-chain L1 dispatcher.",
            clean_asset, network
        ));
    }

    let status = if !dispatched_tx_hash.is_empty() {
        "DISPATCHED_ONCHAIN"
    } else {
        "QUEUED_FOR_L1_DISPATCH"
    };
    let final_tx_ref = if !dispatched_tx_hash.is_empty() {
        dispatched_tx_hash.clone()
    } else {
        payout_id.clone()
    };
    let explorer_url = explorer_tx_url_for_asset(&clean_asset, &network, &final_tx_ref);

    sqlx::query(
        r#"
        INSERT INTO l1_payout_queue (
            payout_id, wallet_address, destination_address, asset_ticker,
            network, amount_tokens, gross_usd, spot_price, source_type,
            tx_hash, explorer_url, queue_reason, status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        ON CONFLICT (payout_id) DO UPDATE SET
            tx_hash = EXCLUDED.tx_hash,
            explorer_url = EXCLUDED.explorer_url,
            queue_reason = EXCLUDED.queue_reason,
            status = EXCLUDED.status,
            updated_at = CURRENT_TIMESTAMP
        "#,
    )
    .bind(&payout_id)
    .bind(wallet_address)
    .bind(destination_address)
    .bind(&clean_asset)
    .bind(&network)
    .bind(amount_tokens)
    .bind(gross_usd)
    .bind(spot_price)
    .bind(source_type)
    .bind(&final_tx_ref)
    .bind(&explorer_url)
    .bind(queue_reason_opt.as_deref())
    .bind(status)
    .execute(pool)
    .await
    .map_err(|e| format!("Failed to persist L1 payout record: {}", e))?;

    let _ = sqlx::query(
        r#"
        INSERT INTO tax_ledger_events (
            wallet_address, asset_ticker, event_type, gross_proceeds_usd,
            amount_tokens, spot_price_at_execution, tx_hash, payout_address,
            cost_basis_usd, realized_gain_loss_usd, holding_period
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $4, 0.0, 'SHORT_TERM')
        "#,
    )
    .bind(wallet_address)
    .bind(&clean_asset)
    .bind(source_type.to_uppercase())
    .bind(gross_usd)
    .bind(amount_tokens)
    .bind(spot_price)
    .bind(&final_tx_ref)
    .bind(destination_address)
    .execute(pool)
    .await;

    Ok(json!({
        "payoutId": payout_id,
        "walletAddress": wallet_address,
        "destinationAddress": destination_address,
        "assetTicker": clean_asset,
        "network": network,
        "amountTokens": amount_tokens,
        "grossUsd": gross_usd,
        "spotPrice": spot_price,
        "txHash": final_tx_ref,
        "explorerUrl": explorer_url,
        "queueReason": queue_reason_opt,
        "status": status
    }))
}

pub async fn retry_queued_l1_payout(pool: &PgPool, payout_id: &str) -> Result<Value, String> {
    let row_opt = sqlx::query(
        r#"
        SELECT wallet_address, destination_address, asset_ticker, network, amount_tokens
        FROM l1_payout_queue
        WHERE payout_id = $1
        "#,
    )
    .bind(payout_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("DB lookup failed: {}", e))?;

    let Some(row) = row_opt else {
        return Err(format!("Payout ID {} not found in l1_payout_queue", payout_id));
    };

    let wallet: String = row.try_get("wallet_address").unwrap_or_default();
    let dest: String = row.try_get("destination_address").unwrap_or_default();
    let ticker: String = row
        .try_get("asset_ticker")
        .unwrap_or_else(|_| "KAS".to_string());
    let network: String = row
        .try_get("network")
        .unwrap_or_else(|_| "KAS".to_string());
    let amt: f64 = row.try_get("amount_tokens").unwrap_or(0.0);

    if network.trim().to_uppercase() != "KAS" {
        return Err(format!(
            "Retry on Rust node only supports KAS/KRC-20 L1 payouts (found {}). Use the multi-chain L1 dispatcher.",
            network
        ));
    }

    crate::chronos::verify_wallet_ledger_invariant_or_quarantine(pool, &wallet, 0.0).await?;

    let (sompi, payload_hex) = if ticker.trim().eq_ignore_ascii_case("KAS") {
        ((amt * 100_000_000.0).round() as u64, String::new())
    } else {
        let base_units = ((amt * 100_000_000.0).round() as u128).to_string();
        let krc20_json = json!({
            "p": "krc-20",
            "op": "transfer",
            "tick": ticker.trim().to_uppercase(),
            "amt": base_units,
            "to": dest.trim().to_lowercase()
        });
        (30_000_000u64, hex::encode(krc20_json.to_string().as_bytes()))
    };

    let idemp_key = format!("RETRY-L1-{}", payout_id);
    let tx_hash =
        sign_and_broadcast_kaspa_payout_batch(pool, &idemp_key, &[(dest.clone(), sompi)], &payload_hex)
            .await?;
    let explorer_url = explorer_tx_url_for_asset(&ticker, &network, &tx_hash);

    sqlx::query(
        r#"
        UPDATE l1_payout_queue
        SET tx_hash = $2,
            explorer_url = $3,
            queue_reason = NULL,
            status = 'DISPATCHED_ONCHAIN',
            updated_at = CURRENT_TIMESTAMP
        WHERE payout_id = $1
        "#,
    )
    .bind(payout_id)
    .bind(&tx_hash)
    .bind(&explorer_url)
    .execute(pool)
    .await
    .map_err(|e| format!("Failed to update retried L1 payout: {}", e))?;

    Ok(json!({
        "payoutId": payout_id,
        "txHash": tx_hash,
        "explorerUrl": explorer_url,
        "status": "DISPATCHED_ONCHAIN"
    }))
}