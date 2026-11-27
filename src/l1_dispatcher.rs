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
const MIN_CHANGE_SOMPI: u64 = 10_000_000;

pub const POST_TOCCATA_TX_VERSION: u16 = 1;
pub const CONSENSUS_MIN_FEERATE_SOMPI_PER_GRAM: u64 = 100;
pub const DEFAULT_RELAY_FEERATE_SOMPI_PER_GRAM: u64 = 110;
pub const COINBASE_MATURITY_DAA_BLOCKS: u64 = 1_000;
pub const STAGE1_FLUSH_CHUNK_SOMPI: u64 = 2_500_000_000; // 25 KAS
pub const MAX_SAFE_TX_INPUTS: usize = 500;
pub const MAX_SAFE_TX_MASS: u64 = 450_000;
const BASE_COMPUTE_MASS: u64 = 200;
const MASS_PER_INPUT: u64 = 1200;
const MASS_PER_OUTPUT: u64 = 450;
const STORAGE_MASS_PARAMETER_U128: u128 = 1_000_000_000_000;

#[derive(Clone, Debug)]
struct SpendableKaspaUtxo {
    transaction_id: String,
    index: u32,
    amount_sompi: u64,
    script_public_key_hex: String,
    #[allow(dead_code)]
    block_daa_score: u64,
    #[allow(dead_code)]
    is_coinbase: bool,
    #[allow(dead_code)]
    covenant_id: Option<String>,
}

/// Encodes canonical Kaspa `txscript` data push (rejecting non-minimal opcodes).
#[allow(dead_code)]
pub fn encode_txscript_pushdata(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    if len == 0 {
        return vec![0x00];
    }
    let mut out = Vec::with_capacity(len + 4);
    if len <= 75 {
        out.push(len as u8);
    } else if len <= 255 {
        out.push(0x4c);
        out.push(len as u8);
    } else {
        out.push(0x4d);
        out.extend_from_slice(&(len as u16).to_le_bytes());
    }
    out.extend_from_slice(data);
    out
}

/// Pure integer Post-Toccata `Transaction v1` compute, bandwidth, KIP-9 storage mass & fee.
pub fn compute_post_toccata_masses_and_fee(
    input_amounts: &[u64],
    output_amounts: &[u64],
    payload_len: usize,
    extra_sigscript_bytes: usize,
    feerate_sompi_per_gram: u64,
) -> (u64, u64, u64, u64) {
    let n_in = input_amounts.len().max(1) as u64;
    let n_out = output_amounts.len().max(1) as u64;
    let extra = payload_len.saturating_add(extra_sigscript_bytes) as u64;
    let compute_mass = BASE_COMPUTE_MASS
        .saturating_add(n_in.saturating_mul(MASS_PER_INPUT))
        .saturating_add(n_out.saturating_mul(MASS_PER_OUTPUT))
        .saturating_add(extra);
    let tx_bytes = 64u64
        .saturating_add(n_in.saturating_mul(118))
        .saturating_add(n_out.saturating_mul(46))
        .saturating_add(extra);
    let bandwidth_mass = tx_bytes.saturating_mul(2);

    let storage_mass = if input_amounts.is_empty() || output_amounts.is_empty() {
        0
    } else {
        let mut harmonic_outs: u128 = 0;
        for &out_amt in output_amounts {
            let term = if out_amt > 0 {
                let v = out_amt as u128;
                (STORAGE_MASS_PARAMETER_U128 + v - 1) / v
            } else {
                STORAGE_MASS_PARAMETER_U128
            };
            harmonic_outs = harmonic_outs.saturating_add(term);
        }
        let sum_ins: u128 = input_amounts.iter().map(|&v| v as u128).sum();
        let mean_ins = sum_ins / (input_amounts.len() as u128);
        if mean_ins == 0 {
            harmonic_outs.min(u64::MAX as u128) as u64
        } else {
            let arithmetic_ins =
                (input_amounts.len() as u128).saturating_mul(STORAGE_MASS_PARAMETER_U128 / mean_ins);
            harmonic_outs
                .saturating_sub(arithmetic_ins)
                .min(u64::MAX as u128) as u64
        }
    };

    let effective_mass = compute_mass.max(bandwidth_mass).max(storage_mass);
    let safe_feerate = feerate_sompi_per_gram.max(CONSENSUS_MIN_FEERATE_SOMPI_PER_GRAM);
    let fee_sompi = effective_mass.saturating_mul(safe_feerate);
    (compute_mass, storage_mass, effective_mass, fee_sompi)
}

fn resolve_kip21_subnetwork_id() -> (String, [u8; 20]) {
    if let Ok(raw) = env::var("PERENNIA_KIP21_SUBNETWORK_ID") {
        let clean = raw.trim().trim_start_matches("0x").to_lowercase();
        if clean.len() == 40 {
            if let Ok(bytes) = hex::decode(&clean) {
                if bytes.len() == 20 {
                    let mut arr = [0u8; 20];
                    arr.copy_from_slice(&bytes);
                    return (clean, arr);
                }
            }
        }
    }
    (
        "0000000000000000000000000000000000000000".to_string(),
        [0u8; 20],
    )
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

#[allow(dead_code)]
fn resolve_trigger_kaspa_keypair() -> Result<(Keypair, String), String> {
    let raw_hex = env::var("CHRONOS_TRIGGER_PRIVATE_KEY")
        .or_else(|_| env::var("PERENNIA_HOT_KAS_PRIVATE_KEY"))
        .or_else(|_| env::var("PERENNIA_TREASURY_PRIVATE_KEY"))
        .map_err(|_| {
            "CHRONOS_TRIGGER_KEY_MISSING: Set CHRONOS_TRIGGER_PRIVATE_KEY or PERENNIA_HOT_KAS_PRIVATE_KEY in .env."
                .to_string()
        })?;
    let clean_hex = raw_hex.trim().trim_start_matches("0x");
    let mut priv_bytes =
        hex::decode(clean_hex).map_err(|_| "Invalid hex in trigger private key".to_string())?;
    if priv_bytes.len() != 32 {
        priv_bytes.fill(0);
        return Err("Trigger private key must be exactly 32 bytes.".to_string());
    }
    let secret_key = SecretKey::from_slice(&priv_bytes)
        .map_err(|e| format!("Invalid secp256k1 trigger secret key: {}", e))?;
    priv_bytes.fill(0);

    let keypair = Keypair::from_secret_key(SECP256K1, &secret_key);
    let (xonly_pub, _) = keypair.x_only_public_key();
    let pub_hex = hex::encode(xonly_pub.serialize());
    Ok((keypair, pub_hex))
}

async fn fetch_mature_utxos_for_address(
    source_address: &str,
    default_spk_hex: &str,
) -> Result<(Vec<SpendableKaspaUtxo>, u64), String> {
    let virtual_daa = crate::kaspad_client::get_virtual_daa_score_grpc().await?;
    let raw_entries = match crate::kaspad_client::get_utxos_by_address_grpc(source_address).await {
        Ok(entries) => entries,
        Err(grpc_err) => {
            let allow_public_rest = env::var("ALLOW_PUBLIC_KASPA_REST_FALLBACK")
                .map(|v| v.trim().eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !allow_public_rest {
                return Err(format!(
                    "LOCAL_KASPAD_UTXO_UNAVAILABLE: {} (set ALLOW_PUBLIC_KASPA_REST_FALLBACK=true only for non-sovereign debugging)",
                    grpc_err
                ));
            }
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
                .map_err(|e| format!("Failed to fetch UTXOs: {}", e))?;
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
        let block_daa_score = u
            .get("utxoEntry")
            .and_then(|e| e.get("blockDaaScore"))
            .or_else(|| u.get("blockDaaScore"))
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            })
            .unwrap_or(0);
        // Reject unaccepted mempool entries
        if block_daa_score == u64::MAX {
            continue;
        }
        let is_coinbase = u
            .get("utxoEntry")
            .and_then(|e| e.get("isCoinbase"))
            .or_else(|| u.get("isCoinbase"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        // Strict 1,000-block DAA maturity gate for coinbase UTXOs
        if is_coinbase
            && virtual_daa < block_daa_score.saturating_add(COINBASE_MATURITY_DAA_BLOCKS)
        {
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

        let covenant_id = u
            .get("utxoEntry")
            .and_then(|e| e.get("covenantId"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        utxos.push(SpendableKaspaUtxo {
            transaction_id: tx_id,
            index,
            amount_sompi,
            script_public_key_hex: spk_hex,
            block_daa_score,
            is_coinbase,
            covenant_id,
        });
    }

    utxos.sort_by(|a, b| b.amount_sompi.cmp(&a.amount_sompi));
    if utxos.is_empty() {
        return Err(format!(
            "Address ({}) has 0 mature spendable UTXOs at virtual DAA {}.",
            source_address, virtual_daa
        ));
    }
    Ok((utxos, virtual_daa))
}

fn sign_transaction_v1_p2pk_inputs(
    keypair: &Keypair,
    selected_utxos: &[SpendableKaspaUtxo],
    tx_outputs: &[(u64, String, Option<(u32, String)>)],
    payload_bytes: &[u8],
    subnetwork_hex: &str,
    subnetwork_bytes: &[u8; 20],
    storage_mass: u64,
) -> Result<(Value, String, Vec<Value>), String> {
    let mut prev_outs_buf = Vec::with_capacity(selected_utxos.len() * 36);
    let mut sequences_buf = Vec::with_capacity(selected_utxos.len() * 8);
    let mut sig_op_counts_buf = Vec::with_capacity(selected_utxos.len());

    for u in selected_utxos {
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
    for (amt, spk_hex, _) in tx_outputs {
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
        p_buf.extend_from_slice(payload_bytes);
        blake2b_256_keyed(TX_SIGNING_KEY, &p_buf)
    };

    let mut signed_inputs_json = Vec::with_capacity(selected_utxos.len());
    for u in selected_utxos {
        let txid_bytes = hex::decode(&u.transaction_id).unwrap_or_default();
        let spk_bytes = hex::decode(&u.script_public_key_hex).unwrap_or_default();

        let mut preimage = Vec::with_capacity(220 + spk_bytes.len());
        preimage.extend_from_slice(&POST_TOCCATA_TX_VERSION.to_le_bytes());
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
        preimage.extend_from_slice(subnetwork_bytes);
        preimage.extend_from_slice(&0u64.to_le_bytes());
        preimage.extend_from_slice(&payload_hash);
        preimage.push(SIGHASH_ALL);

        let sighash = blake2b_256_keyed(TX_SIGNING_KEY, &preimage);
        let msg = Message::from_digest(sighash);
        let sig = SECP256K1.sign_schnorr_no_aux_rand(&msg, keypair);
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
        .map(|(amt, spk, cov_opt)| {
            let mut obj = json!({
                "amount": *amt,
                "scriptPublicKey": {
                    "version": 0,
                    "scriptPublicKey": spk
                }
            });
            if let Some((auth_input, cov_id)) = cov_opt {
                obj["covenant"] = json!({
                    "authorizingInput": *auth_input,
                    "covenantId": cov_id
                });
            }
            obj
        })
        .collect();

    let envelope = json!({
        "transaction": {
            "version": POST_TOCCATA_TX_VERSION,
            "inputs": signed_inputs_json,
            "outputs": outputs_json.clone(),
            "lockTime": 0,
            "subnetworkId": subnetwork_hex,
            "gas": 0,
            "storageMass": storage_mass,
            "payload": hex::encode(payload_bytes)
        }
    });

    let sighash_digest_hex = format!(
        "{}:{}",
        hex::encode(prev_outs_hash),
        hex::encode(outputs_hash)
    );
    Ok((envelope, sighash_digest_hex, outputs_json))
}

pub async fn sign_and_broadcast_kaspa_payout_batch(
    pool: &PgPool,
    idempotency_key: &str,
    recipients: &[(String, u64)],
    payload_hex: &str,
) -> Result<String, String> {
    let sys_cfg = crate::chronos::load_system_treasury_config(pool).await;
    if sys_cfg.outflow_breaker_tripped || sys_cfg.solvency_breaker_tripped {
        return Err(
            "CIRCUIT_BREAKER_TRIPPED: Outflow or 30s solvency circuit breaker has halted L1 signing."
                .to_string(),
        );
    }

    let solvency = crate::chronos::evaluate_pool_solvency_invariant(pool).await?;
    if !solvency.is_solvent {
        return Err(format!(
            "SOLVENCY_BREAKER_HALT: Pool deficit {} sompi detected before L1 batch signing.",
            solvency.deficit_sompi.0
        ));
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
    let (available_utxos, _virtual_daa) =
        fetch_mature_utxos_for_address(&source_address, &source_spk_hex).await?;
    let feerate = crate::kaspad_client::get_fee_estimate_sompi_per_gram_grpc()
        .await
        .unwrap_or(DEFAULT_RELAY_FEERATE_SOMPI_PER_GRAM)
        .max(CONSENSUS_MIN_FEERATE_SOMPI_PER_GRAM);

    let target_total_sompi: u64 = valid_recipients.iter().map(|(_, s, _)| *s).sum();
    let payload_bytes = if payload_hex.trim().is_empty() {
        Vec::new()
    } else {
        hex::decode(payload_hex.trim())
            .map_err(|_| "Invalid payload_hex in Kaspa transaction".to_string())?
    };

    let mut selected_utxos = Vec::new();
    let mut input_amounts = Vec::new();
    let mut gathered_sompi: u64 = 0;
    let mut fee_sompi: u64 = 0;
    let mut storage_mass_final: u64 = 0;
    let mut effective_mass_final: u64 = 0;
    let recipient_amounts: Vec<u64> = valid_recipients.iter().map(|(_, s, _)| *s).collect();

    for u in available_utxos {
        if selected_utxos.len() >= MAX_SAFE_TX_INPUTS {
            break;
        }
        gathered_sompi = gathered_sompi.saturating_add(u.amount_sompi);
        input_amounts.push(u.amount_sompi);
        selected_utxos.push(u);

        let mut test_outputs = recipient_amounts.clone();
        let approx_fee = ((input_amounts.len() * 1200 + test_outputs.len() * 450 + 650) as u64)
            .saturating_mul(feerate);
        let tentative_change = gathered_sompi.saturating_sub(target_total_sompi.saturating_add(approx_fee));
        if tentative_change >= MIN_CHANGE_SOMPI {
            test_outputs.push(tentative_change);
        }
        let (_, sm, em, calc_fee) = compute_post_toccata_masses_and_fee(
            &input_amounts,
            &test_outputs,
            payload_bytes.len(),
            0,
            feerate,
        );
        fee_sompi = calc_fee;
        storage_mass_final = sm;
        effective_mass_final = em;
        if gathered_sompi >= target_total_sompi.saturating_add(fee_sompi) {
            break;
        }
    }

    if effective_mass_final > MAX_SAFE_TX_MASS {
        return Err(format!(
            "TX_MASS_CAP_EXCEEDED: effective_mass {} exceeds safe ceiling {}. Run pre-bell UTXO compaction.",
            effective_mass_final, MAX_SAFE_TX_MASS
        ));
    }

    if gathered_sompi < target_total_sompi.saturating_add(fee_sompi) {
        return Err(format!(
            "INSUFFICIENT_MATURE_HOT_WALLET_UTXO_MASS: Required {} sompi (incl {} fee), available {} sompi on {}.",
            target_total_sompi.saturating_add(fee_sompi),
            fee_sompi,
            gathered_sompi,
            source_address
        ));
    }

    let change_sompi = gathered_sompi.saturating_sub(target_total_sompi.saturating_add(fee_sompi));
    let mut tx_outputs: Vec<(u64, String, Option<(u32, String)>)> = valid_recipients
        .iter()
        .map(|(_, sompi, spk)| (*sompi, spk.clone(), None))
        .collect();
    if change_sompi >= MIN_CHANGE_SOMPI {
        tx_outputs.push((change_sompi, source_spk_hex.clone(), None));
    }
    let final_out_amounts: Vec<u64> = tx_outputs.iter().map(|(a, _, _)| *a).collect();
    let (_, final_sm, final_em, _) = compute_post_toccata_masses_and_fee(
        &input_amounts,
        &final_out_amounts,
        payload_bytes.len(),
        0,
        feerate,
    );
    let _ = (storage_mass_final, final_em);

    let (subnetwork_hex, subnetwork_bytes) = resolve_kip21_subnetwork_id();
    let (signed_tx_envelope, digest_pair, _) = sign_transaction_v1_p2pk_inputs(
        &keypair,
        &selected_utxos,
        &tx_outputs,
        &payload_bytes,
        &subnetwork_hex,
        &subnetwork_bytes,
        final_sm,
    )?;

    let pre_broadcast_digest = blake2b_256(
        format!("IN_FLIGHT:{}:{}", idempotency_key, digest_pair).as_bytes(),
    );
    let provisional_lock_id = hex::encode(pre_broadcast_digest);
    let batch_id = format!("BATCH-{}", &provisional_lock_id[..16].to_uppercase());
    let manifest_json: Vec<Value> = valid_recipients
        .iter()
        .map(|(addr, sompi, _)| {
            json!({
                "address": addr,
                "sompiStr": sompi.to_string()
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
            let allow_public_rest = env::var("ALLOW_PUBLIC_KASPA_REST_FALLBACK")
                .map(|v| v.trim().eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !allow_public_rest {
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
                .bind(&grpc_err)
                .execute(pool)
                .await;
                return Err(format!("Local kaspad gRPC rejected Transaction v1 broadcast: {}", grpc_err));
            }
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
                .map_err(|e| format!("gRPC ({}) & REST ({}) failed", grpc_err, e))?;
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

/// 21:55 UTC Pre-Bell UTXO Compactor: consolidates fragmented mature UTXOs safely under Kaspa's 1,000-input / 500,000-mass caps.
pub async fn compact_wallet_utxos_pre_bell(
    pool: &PgPool,
    max_inputs: usize,
) -> Result<Option<String>, String> {
    let sys_cfg = crate::chronos::load_system_treasury_config(pool).await;
    if sys_cfg.outflow_breaker_tripped || sys_cfg.solvency_breaker_tripped {
        return Err("COMPACTION_HALTED: Circuit breaker is tripped.".to_string());
    }
    let (keypair, source_address, source_spk_hex) = resolve_hot_kaspa_keypair()?;
    let (mut utxos, _) = fetch_mature_utxos_for_address(&source_address, &source_spk_hex).await?;
    if utxos.len() <= 64 {
        return Ok(None);
    }
    // Compact smallest UTXOs first
    utxos.sort_by_key(|u| u.amount_sompi);
    let take_n = max_inputs.clamp(2, 400);
    let selected: Vec<SpendableKaspaUtxo> = utxos.into_iter().take(take_n).collect();
    let total_in: u64 = selected.iter().map(|u| u.amount_sompi).sum();
    let input_amounts: Vec<u64> = selected.iter().map(|u| u.amount_sompi).collect();
    let feerate = crate::kaspad_client::get_fee_estimate_sompi_per_gram_grpc()
        .await
        .unwrap_or(DEFAULT_RELAY_FEERATE_SOMPI_PER_GRAM)
        .max(CONSENSUS_MIN_FEERATE_SOMPI_PER_GRAM);
    let (_, sm1, _, fee1) = compute_post_toccata_masses_and_fee(
        &input_amounts,
        &[total_in.saturating_sub(100_000)],
        0,
        0,
        feerate,
    );
    if total_in <= fee1.saturating_add(MIN_CHANGE_SOMPI) {
        return Err("Insufficient input mass to compact fragmented UTXOs.".to_string());
    }
    let out_sompi = total_in.saturating_sub(fee1);
    let (subnetwork_hex, subnetwork_bytes) = resolve_kip21_subnetwork_id();
    let (signed_tx, _, _) = sign_transaction_v1_p2pk_inputs(
        &keypair,
        &selected,
        &[(out_sompi, source_spk_hex, None)],
        &[],
        &subnetwork_hex,
        &subnetwork_bytes,
        sm1,
    )?;
    let txid = crate::kaspad_client::submit_transaction_grpc(&signed_tx, false).await?;
    Ok(Some(txid))
}

/// Stage 1 Mechanical Pool Flush (`25 KAS` chunk floor) into miners' self-custodial `MINER_SILO` Vault Locks,
/// skimming `pool_fee_bps` straight to Perennia's segregated House Revenue Address via `SERIALIZABLE` outbox.
pub async fn execute_stage1_mechanical_pool_flush_batch(
    pool: &PgPool,
    epoch_id: &str,
) -> Result<Value, String> {
    let sys_cfg = crate::chronos::load_system_treasury_config(pool).await;
    if sys_cfg.outflow_breaker_tripped || sys_cfg.solvency_breaker_tripped {
        return Err("STAGE1_HALTED: Circuit breaker is tripped.".to_string());
    }
    let solvency = crate::chronos::evaluate_pool_solvency_invariant(pool).await?;
    if !solvency.is_solvent {
        return Err(format!(
            "STAGE1_SOLVENCY_HALT: Deficit {} sompi detected.",
            solvency.deficit_sompi.0
        ));
    }

    let (_, pool_hot_addr, _) = resolve_hot_kaspa_keypair()?;
    let house_rev_addr = crate::chronos::resolve_house_revenue_kas_address(&sys_cfg)
        .unwrap_or_else(|| pool_hot_addr.clone());

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| format!("Failed to begin Stage 1 SERIALIZABLE tx: {}", e))?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Failed to set SERIALIZABLE isolation: {}", e))?;

    let candidate_rows = sqlx::query(
        r#"
        SELECT a.clean_wallet, a.wallet_address,
               a.unpaid_mature_sompi::NUMERIC(39, 0)::TEXT AS unpaid_mature_sompi,
               a.pool_fee_bps, a.active_vault_id,
               v.covenant_address AS vault_covenant_address,
               v.kip20_covenant_id AS vault_kip20_id
        FROM stratum_mature_accruals a
        LEFT JOIN vault_locks v ON v.vault_id = a.active_vault_id AND v.vault_kind = 'MINER_SILO'
        WHERE a.unpaid_mature_sompi >= $1::NUMERIC(39, 0)
          AND NOT EXISTS (
              SELECT 1 FROM epoch_payout_outbox o
              WHERE o.clean_wallet = a.clean_wallet
                AND o.state IN ('CREATED', 'SIGNING')
          )
        ORDER BY a.unpaid_mature_sompi DESC
        LIMIT 100
        FOR UPDATE OF a
        "#,
    )
    .bind(STAGE1_FLUSH_CHUNK_SOMPI.to_string())
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("Failed to lock eligible Stage 1 accruals: {}", e))?;

    if candidate_rows.is_empty() {
        let _ = tx.commit().await;
        return Ok(json!({ "flushedWallets": 0, "totalFlushedSompi": "0" }));
    }

    let (subnetwork_hex, _) = resolve_kip21_subnetwork_id();
    struct PlannedFlush {
        outbox_key: String,
        clean_wallet: String,
        wallet_address: String,
        vault_id: String,
        dest_address: String,
        payout_sompi: u64,
        house_fee_sompi: u64,
        kip20_id: Option<String>,
    }
    let mut planned = Vec::with_capacity(candidate_rows.len());
    let mut recipients: Vec<(String, u64)> = Vec::new();
    let mut total_flushed: u128 = 0;
    let mut total_house_fee: u64 = 0;

    for row in candidate_rows {
        let clean_wallet: String = row.try_get("clean_wallet").unwrap_or_default();
        let wallet_address: String = row.try_get("wallet_address").unwrap_or_default();
        let unpaid_mature: u128 = row
            .try_get::<String, _>("unpaid_mature_sompi")
            .ok()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        let pool_fee_bps = row.try_get::<i32, _>("pool_fee_bps").unwrap_or(100).clamp(50, 200) as u128;
        let chunks = unpaid_mature / (STAGE1_FLUSH_CHUNK_SOMPI as u128);
        let payout_u128 = chunks.saturating_mul(STAGE1_FLUSH_CHUNK_SOMPI as u128);
        let Ok(payout_sompi) = u64::try_from(payout_u128) else {
            continue;
        };
        if payout_sompi == 0 {
            continue;
        }
        let vault_id = row
            .try_get::<Option<String>, _>("active_vault_id")
            .ok()
            .flatten()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "SELF_CUSTODY_WALLET".to_string());
        let dest_address = row
            .try_get::<Option<String>, _>("vault_covenant_address")
            .ok()
            .flatten()
            .filter(|s| s.starts_with("kaspa:"))
            .unwrap_or_else(|| wallet_address.clone());
        let Ok(dest_spk_hex) = address_to_spk_hex(&dest_address) else {
            continue;
        };
        let kip20_id = row
            .try_get::<Option<String>, _>("vault_kip20_id")
            .ok()
            .flatten();

        let house_fee_sompi = ((payout_u128.saturating_mul(pool_fee_bps))
            / 10_000u128.saturating_sub(pool_fee_bps).max(1)) as u64;
        let outbox_key = crate::chronos::compute_outbox_idempotency_key(
            epoch_id,
            &clean_wallet,
            &vault_id,
        );

        let inserted = sqlx::query(
            r#"
            INSERT INTO epoch_payout_outbox (
                outbox_key, epoch_id, wallet_address, clean_wallet, vault_id,
                destination_address, destination_spk_hex, house_revenue_address,
                payout_sompi, house_fee_sompi, kip21_subnetwork_id, kip20_covenant_id, state
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8,
                $9::NUMERIC(39, 0), $10::NUMERIC(39, 0), $11, $12, 'SIGNING'
            )
            ON CONFLICT (outbox_key) DO NOTHING
            "#,
        )
        .bind(&outbox_key)
        .bind(epoch_id)
        .bind(&wallet_address)
        .bind(&clean_wallet)
        .bind(&vault_id)
        .bind(&dest_address)
        .bind(&dest_spk_hex)
        .bind(&house_rev_addr)
        .bind(payout_sompi.to_string())
        .bind(house_fee_sompi.to_string())
        .bind(&subnetwork_hex)
        .bind(kip20_id.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Outbox insert failed: {}", e))?;

        if inserted.rows_affected() == 0 {
            continue;
        }

        sqlx::query(
            r#"
            UPDATE stratum_mature_accruals
            SET unpaid_mature_sompi = unpaid_mature_sompi - $2::NUMERIC(39, 0),
                lifetime_flushed_sompi = lifetime_flushed_sompi + $2::NUMERIC(39, 0),
                updated_at = CURRENT_TIMESTAMP
            WHERE clean_wallet = $1
            "#,
        )
        .bind(&clean_wallet)
        .bind(payout_sompi.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Failed decrementing mature accrual: {}", e))?;

        total_flushed = total_flushed.saturating_add(payout_u128);
        total_house_fee = total_house_fee.saturating_add(house_fee_sompi);
        recipients.push((dest_address.clone(), payout_sompi));
        planned.push(PlannedFlush {
            outbox_key,
            clean_wallet,
            wallet_address,
            vault_id,
            dest_address,
            payout_sompi,
            house_fee_sompi,
            kip20_id,
        });
    }

    tx.commit()
        .await
        .map_err(|e| format!("Stage 1 SERIALIZABLE commit failed: {}", e))?;

    if planned.is_empty() {
        return Ok(json!({ "flushedWallets": 0, "totalFlushedSompi": "0" }));
    }

    if total_house_fee >= MIN_CHANGE_SOMPI && house_rev_addr != pool_hot_addr {
        recipients.push((house_rev_addr.clone(), total_house_fee));
    }

    let batch_key = format!("STAGE1-FLUSH-{}", epoch_id);
    match sign_and_broadcast_kaspa_payout_batch(pool, &batch_key, &recipients, "").await {
        Ok(txid) => {
            let v_daa = crate::kaspad_client::get_virtual_daa_score_grpc()
                .await
                .unwrap_or(0) as i64;
            for item in &planned {
                let _ = sqlx::query(
                    r#"
                    UPDATE epoch_payout_outbox
                    SET state = 'BROADCAST',
                        txid = $2,
                        broadcast_daa = $3,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE outbox_key = $1
                    "#,
                )
                .bind(&item.outbox_key)
                .bind(&txid)
                .bind(v_daa)
                .execute(pool)
                .await;

                let receipt_id = format!("S1-{}", &item.outbox_key[..24]);
                let _ = sqlx::query(
                    r#"
                    INSERT INTO settlement_receipts (
                        receipt_id, outbox_key, epoch_id, wallet_address, clean_wallet,
                        vault_id, settlement_tier, source_sompi, house_fee_sompi, network_fee_sompi,
                        target_asset, target_network, settled_atomic, kaspa_l1_txid,
                        confirmed_daa_score, status
                    ) VALUES (
                        $1, $2, $3, $4, $5,
                        $6, 'STAGE1_POOL_FLUSH', $7::NUMERIC(39,0), $8::NUMERIC(39,0), 0,
                        'KAS', 'KAS', $7::NUMERIC(39,0), $9, $10, 'BROADCAST'
                    )
                    ON CONFLICT (receipt_id) DO NOTHING
                    "#,
                )
                .bind(&receipt_id)
                .bind(&item.outbox_key)
                .bind(epoch_id)
                .bind(&item.wallet_address)
                .bind(&item.clean_wallet)
                .bind(&item.vault_id)
                .bind(item.payout_sompi.to_string())
                .bind(item.house_fee_sompi.to_string())
                .bind(&txid)
                .bind(v_daa)
                .execute(pool)
                .await;
                let _ = (&item.dest_address, &item.kip20_id);
            }
            Ok(json!({
                "flushedWallets": planned.len(),
                "totalFlushedSompi": total_flushed.to_string(),
                "houseFeeSkimmedSompi": total_house_fee.to_string(),
                "txid": txid
            }))
        }
        Err(e) => {
            for item in &planned {
                let _ = sqlx::query(
                    r#"
                    UPDATE epoch_payout_outbox
                    SET state = 'FAILED',
                        last_error = $2,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE outbox_key = $1
                    "#,
                )
                .bind(&item.outbox_key)
                .bind(&e)
                .execute(pool)
                .await;

                let _ = sqlx::query(
                    r#"
                    UPDATE stratum_mature_accruals
                    SET unpaid_mature_sompi = unpaid_mature_sompi + $2::NUMERIC(39,0),
                        lifetime_flushed_sompi = GREATEST(0, lifetime_flushed_sompi - $2::NUMERIC(39,0)),
                        updated_at = CURRENT_TIMESTAMP
                    WHERE clean_wallet = $1
                    "#,
                )
                .bind(&item.clean_wallet)
                .bind(item.payout_sompi.to_string())
                .execute(pool)
                .await;
            }
            Err(e)
        }
    }
}

/// Estimates live confirmed UTXO total and exact Transaction v1 network fee for spending a Vault Lock via Path B.
#[allow(dead_code)]
pub async fn estimate_path_b_vault_network_fee_sompi(
    covenant_address: &str,
    redeem_script_hex: &str,
) -> Result<(u64, u64), String> {
    let redeem_len = hex::decode(redeem_script_hex.trim())
        .map_err(|_| "Invalid vault redeem_script_hex".to_string())?
        .len();
    let (utxos, _) = fetch_mature_utxos_for_address(covenant_address, "").await?;
    let input_amounts: Vec<u64> = utxos.iter().take(MAX_SAFE_TX_INPUTS).map(|u| u.amount_sompi).collect();
    let total_in: u64 = input_amounts.iter().sum();
    let feerate = crate::kaspad_client::get_fee_estimate_sompi_per_gram_grpc()
        .await
        .unwrap_or(DEFAULT_RELAY_FEERATE_SOMPI_PER_GRAM)
        .max(CONSENSUS_MIN_FEERATE_SOMPI_PER_GRAM);
    let extra_bytes = input_amounts.len().saturating_mul(redeem_len + 4);
    let est_payin = (total_in as u128 * 995 / 1000) as u64;
    let est_fee = total_in.saturating_sub(est_payin).max(1);
    let (_, _, _, fee1) = compute_post_toccata_masses_and_fee(
        &input_amounts,
        &[est_payin.max(10_000_000), est_fee.max(10_000_000)],
        0,
        extra_bytes,
        feerate,
    );
    Ok((total_in, fee1))
}

/// Executes a Path B Vault Lock split transaction directly on Kaspa L1:
/// Output 0 (`99.5%`) -> user destination / ChangeNOW non-custodial payinAddress,
/// Output 1 (`0.5%`) -> Perennia House Revenue Vault.
#[allow(dead_code)]
pub async fn execute_path_b_vault_split_tx(
    pool: &PgPool,
    vault_id: &str,
    payin_address: &str,
    payin_sompi: u64,
    house_revenue_address: &str,
    house_fee_sompi: u64,
) -> Result<(String, u64), String> {
    let sys_cfg = crate::chronos::load_system_treasury_config(pool).await;
    if sys_cfg.outflow_breaker_tripped || sys_cfg.solvency_breaker_tripped {
        return Err("PATH_B_HALTED: Circuit breaker is tripped.".to_string());
    }
    let row = sqlx::query(
        r#"
        SELECT covenant_address, redeem_script_hex, kip20_covenant_id
        FROM vault_locks
        WHERE vault_id = $1
        LIMIT 1
        "#,
    )
    .bind(vault_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("DB lookup for vault {} failed: {}", vault_id, e))?
    .ok_or_else(|| format!("Vault lock {} not found.", vault_id))?;

    let covenant_address: String = row.try_get("covenant_address").unwrap_or_default();
    let redeem_script_hex: String = row.try_get("redeem_script_hex").unwrap_or_default();
    let redeem_script_bytes = hex::decode(redeem_script_hex.trim())
        .map_err(|_| "Malformed vault redeem_script_hex".to_string())?;
    let payin_spk_hex = address_to_spk_hex(payin_address)?;
    let house_spk_hex = address_to_spk_hex(house_revenue_address)?;

    let (trigger_keypair, _) = resolve_trigger_kaspa_keypair()?;
    let (utxos, _) = fetch_mature_utxos_for_address(&covenant_address, "").await?;
    let selected: Vec<SpendableKaspaUtxo> = utxos.into_iter().take(MAX_SAFE_TX_INPUTS).collect();
    let input_amounts: Vec<u64> = selected.iter().map(|u| u.amount_sompi).collect();
    let total_in: u64 = input_amounts.iter().sum();

    let mut outputs: Vec<(u64, String, Option<()>)> = vec![(payin_sompi, payin_spk_hex, None)];
    if house_fee_sompi > 0 {
        outputs.push((house_fee_sompi, house_spk_hex, None));
    }
    let out_amounts: Vec<u64> = outputs.iter().map(|(a, _, _)| *a).collect();
    let feerate = crate::kaspad_client::get_fee_estimate_sompi_per_gram_grpc()
        .await
        .unwrap_or(DEFAULT_RELAY_FEERATE_SOMPI_PER_GRAM)
        .max(CONSENSUS_MIN_FEERATE_SOMPI_PER_GRAM);
    let extra_bytes = selected.len().saturating_mul(redeem_script_bytes.len() + 4);
    let (_, storage_mass, effective_mass, min_fee_sompi) = compute_post_toccata_masses_and_fee(
        &input_amounts,
        &out_amounts,
        0,
        extra_bytes,
        feerate,
    );
    if effective_mass > MAX_SAFE_TX_MASS {
        return Err(format!("Path B TX effective_mass {} exceeds safety cap.", effective_mass));
    }
    let required_sompi = payin_sompi.saturating_add(house_fee_sompi).saturating_add(min_fee_sompi);
    if total_in < required_sompi {
        return Err(format!(
            "INSUFFICIENT_VAULT_UTXOS: Vault {} has {} sompi, needs {} sompi (incl {} fee).",
            vault_id, total_in, required_sompi, min_fee_sompi
        ));
    }

    let (subnetwork_hex, subnetwork_bytes) = resolve_kip21_subnetwork_id();
    let mut prev_outs_buf = Vec::with_capacity(selected.len() * 36);
    let mut sequences_buf = Vec::with_capacity(selected.len() * 8);
    let mut sig_op_counts_buf = Vec::with_capacity(selected.len());
    for u in &selected {
        let txid_bytes = hex::decode(&u.transaction_id).unwrap_or_default();
        prev_outs_buf.extend_from_slice(&txid_bytes);
        prev_outs_buf.extend_from_slice(&u.index.to_le_bytes());
        sequences_buf.extend_from_slice(&0u64.to_le_bytes());
        sig_op_counts_buf.push(2u8);
    }
    let prev_outs_hash = blake2b_256_keyed(TX_SIGNING_KEY, &prev_outs_buf);
    let sequences_hash = blake2b_256_keyed(TX_SIGNING_KEY, &sequences_buf);
    let sig_op_counts_hash = blake2b_256_keyed(TX_SIGNING_KEY, &sig_op_counts_buf);

    let mut outputs_buf = Vec::new();
    for (amt, spk_hex, _) in &outputs {
        let spk_bytes = hex::decode(spk_hex).unwrap_or_default();
        outputs_buf.extend_from_slice(&amt.to_le_bytes());
        outputs_buf.extend_from_slice(&0u16.to_le_bytes());
        outputs_buf.extend_from_slice(&(spk_bytes.len() as u64).to_le_bytes());
        outputs_buf.extend_from_slice(&spk_bytes);
    }
    let outputs_hash = blake2b_256_keyed(TX_SIGNING_KEY, &outputs_buf);
    let payload_hash = [0u8; 32];

    let redeem_push = encode_txscript_pushdata(&redeem_script_bytes);
    let mut signed_inputs_json = Vec::with_capacity(selected.len());
    for u in &selected {
        let txid_bytes = hex::decode(&u.transaction_id).unwrap_or_default();
        // P2SH subscript in Kaspa TransactionSigningHash is the executed redeem_script
        let mut preimage = Vec::with_capacity(220 + redeem_script_bytes.len());
        preimage.extend_from_slice(&POST_TOCCATA_TX_VERSION.to_le_bytes());
        preimage.extend_from_slice(&prev_outs_hash);
        preimage.extend_from_slice(&sequences_hash);
        preimage.extend_from_slice(&sig_op_counts_hash);
        preimage.extend_from_slice(&txid_bytes);
        preimage.extend_from_slice(&u.index.to_le_bytes());
        preimage.extend_from_slice(&0u16.to_le_bytes());
        preimage.extend_from_slice(&(redeem_script_bytes.len() as u64).to_le_bytes());
        preimage.extend_from_slice(&redeem_script_bytes);
        preimage.extend_from_slice(&u.amount_sompi.to_le_bytes());
        preimage.extend_from_slice(&0u64.to_le_bytes());
        preimage.push(2u8);
        preimage.extend_from_slice(&outputs_hash);
        preimage.extend_from_slice(&0u64.to_le_bytes());
        preimage.extend_from_slice(&subnetwork_bytes);
        preimage.extend_from_slice(&0u64.to_le_bytes());
        preimage.extend_from_slice(&payload_hash);
        preimage.push(SIGHASH_ALL);

        let sighash = blake2b_256_keyed(TX_SIGNING_KEY, &preimage);
        let msg = Message::from_digest(sighash);
        let sig = SECP256K1.sign_schnorr_no_aux_rand(&msg, &trigger_keypair);
        // signatureScript: <65B sig||0x01> <OP_FALSE=0x00 (select OP_ELSE Path B)> <push(redeem_script)>
        let mut sig_script = Vec::with_capacity(67 + redeem_push.len());
        sig_script.push(0x41);
        sig_script.extend_from_slice(sig.as_ref());
        sig_script.push(SIGHASH_ALL);
        sig_script.push(0x00); // OP_FALSE selects Path B
        sig_script.extend_from_slice(&redeem_push);

        signed_inputs_json.push(json!({
            "previousOutpoint": { "transactionId": u.transaction_id, "index": u.index },
            "signatureScript": hex::encode(sig_script),
            "sequence": 0,
            "sigOpCount": 2
        }));
    }

    let outputs_json: Vec<Value> = outputs
        .iter()
        .map(|(amt, spk, _)| {
            json!({
                "amount": *amt,
                "scriptPublicKey": { "version": 0, "scriptPublicKey": spk }
            })
        })
        .collect();
    let signed_tx = json!({
        "transaction": {
            "version": POST_TOCCATA_TX_VERSION,
            "inputs": signed_inputs_json,
            "outputs": outputs_json,
            "lockTime": 0,
            "subnetworkId": subnetwork_hex,
            "gas": 0,
            "storageMass": storage_mass,
            "payload": ""
        }
    });
    let txid = crate::kaspad_client::submit_transaction_grpc(&signed_tx, false).await?;
    Ok((txid, total_in.saturating_sub(payin_sompi.saturating_add(house_fee_sompi))))
}

#[allow(dead_code)]
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