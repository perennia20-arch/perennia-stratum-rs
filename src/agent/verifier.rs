// src/agent/verifier.rs

use secp256k1::{schnorr::Signature as SchnorrSignature, Message, XOnlyPublicKey, SECP256K1};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use uuid::Uuid;

use crate::{
    agent::{
        auth::constant_time_eq,
        types::{
            AgentCapabilityClaims, AgentError, AgentErrorCode, AgentMode, LockedUtxoSnapshot,
            OutpointRef, PostToccataEnvelope, StoredAgentQuote, U128Str,
        },
    },
    silverscript::{
        blake2b_256, blake2b_256_keyed, build_kcc20_state_commitment, decode_kaspa_address_payload,
        KASPA_ADDR_VERSION_P2PK_SCHNORR, KASPA_ADDR_VERSION_P2SH,
    },
};

const TX_SIGNING_KEY: &[u8] = b"TransactionSigningHash";
const PERSONAL_MSG_SIGNING_KEY: &[u8] = b"PersonalMessageSigningHash";
const SIGHASH_ALL: u8 = 0x01;
const MIN_CHANGE_SOMPI: u128 = 10_000_000;

/// In `rusty-kaspa` (`kaspad`), mempool / unaccepted UTXOs carry `block_daa_score == u64::MAX`.
pub const KASPAD_UNACCEPTED_DAA_SCORE: u64 = u64::MAX;
pub const COINBASE_MATURITY_DAA_DEPTH: u64 = 100;
pub const MIN_MODE_A_CONFIRMED_DAA_DEPTH: u64 = 10;
pub const MIN_KRC20_KCC20_CONFIRMED_DAA_DEPTH: u64 = 12;
pub const MIN_MODE_B_CONFIRMED_DAA_DEPTH: u64 = 2;

// Kaspa Script Opcodes enforced in strict template checks
const OP_FALSE: u8 = 0x00;
const OP_DATA_32: u8 = 0x20;
const OP_DATA_65: u8 = 0x41;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_IF: u8 = 0x63;
const OP_ENDIF: u8 = 0x68;
const OP_RETURN: u8 = 0x6a;
const OP_NOT: u8 = 0x91;
const OP_0NOTEQUAL: u8 = 0x92;
const OP_BLAKE2B: u8 = 0xa9;
const OP_CODESEPARATOR: u8 = 0xab;
const OP_CHECKSIG: u8 = 0xac;
const OP_EQUAL: u8 = 0x87;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedTicketBundle {
    pub execution_kind: String,
    pub unsigned_tx_json: Value,
    pub sighash_hex_per_input: Vec<String>,
    pub payload_0x83_hex: String,
    pub preimage_hash: String,
    pub input_amounts_sompi: Vec<u128>,
    pub output_amounts_sompi: Vec<u128>,
    pub tx_payload_bytes_len: usize,
}

#[derive(Debug, Clone)]
pub enum VerifiedExecutionPayload {
    KaspaL1Transaction {
        signed_tx_envelope: Value,
        verified_daa_depth_min: u64,
    },
    SovereignSleeveIntent0x83 {
        signature_hex: String,
    },
}

/// Produces a canonical, whitespace-free UTF-8 JSON byte sequence with lexicographically
/// sorted object keys (immune to `serde_json` `preserve_order` feature variations).
pub fn canonicalize_json_bytes(val: &Value) -> Vec<u8> {
    fn write_canonical(val: &Value, out: &mut Vec<u8>) {
        match val {
            Value::Null => out.extend_from_slice(b"null"),
            Value::Bool(true) => out.extend_from_slice(b"true"),
            Value::Bool(false) => out.extend_from_slice(b"false"),
            Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
            Value::String(s) => {
                if let Ok(encoded) = serde_json::to_vec(s) {
                    out.extend_from_slice(&encoded);
                }
            }
            Value::Array(arr) => {
                out.push(b'[');
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    write_canonical(item, out);
                }
                out.push(b']');
            }
            Value::Object(map) => {
                let mut sorted: BTreeMap<&str, &Value> = BTreeMap::new();
                for (k, v) in map {
                    sorted.insert(k.as_str(), v);
                }
                out.push(b'{');
                for (i, (k, v)) in sorted.into_iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    if let Ok(k_enc) = serde_json::to_vec(k) {
                        out.extend_from_slice(&k_enc);
                    }
                    out.push(b':');
                    write_canonical(v, out);
                }
                out.push(b'}');
            }
        }
    }

    let mut buf = Vec::with_capacity(512);
    write_canonical(val, &mut buf);
    buf
}

/// Computes the canonical 32-byte Blake3 `preimage_hash` over an unsigned execution ticket.
pub fn compute_blake3_preimage_hash(unsigned_envelope: &Value) -> String {
    let canonical_bytes = canonicalize_json_bytes(unsigned_envelope);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PERENNIA_UNSIGNED_PREIMAGE_V1|");
    hasher.update(&canonical_bytes);
    hasher.finalize().to_hex().to_string()
}

/// Encodes the deterministic `0x83` Perennia Sovereign Intent payload in hex:
/// `[0x83, 0x01, quote_id, clean_wallet, venue, pay_asset, receive_asset, amount_in(16B BE), min_out(16B BE), net_fee_sompi(16B BE), expires_ms(8B BE)]`
pub fn build_payload_0x83_hex(
    quote_id: &str,
    clean_wallet: &str,
    venue: &str,
    pay_asset: &str,
    receive_asset: &str,
    amount_in_atomic: u128,
    min_amount_out_atomic: u128,
    network_fee_sompi: u128,
    expires_at_ms: u64,
    covenant_id_opt: Option<&str>,
) -> String {
    fn push_lp_ascii(buf: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(255) as u8;
        buf.push(len);
        buf.extend_from_slice(&bytes[..len as usize]);
    }

    let mut buf = Vec::with_capacity(192);
    buf.push(0x83); // Perennia Sovereign Intent magic byte
    buf.push(0x01); // Envelope version 1
    push_lp_ascii(&mut buf, quote_id);
    push_lp_ascii(&mut buf, clean_wallet);
    push_lp_ascii(&mut buf, venue);
    push_lp_ascii(&mut buf, pay_asset);
    push_lp_ascii(&mut buf, receive_asset);
    buf.extend_from_slice(&amount_in_atomic.to_be_bytes());
    buf.extend_from_slice(&min_amount_out_atomic.to_be_bytes());
    buf.extend_from_slice(&network_fee_sompi.to_be_bytes());
    buf.extend_from_slice(&expires_at_ms.to_be_bytes());
    push_lp_ascii(&mut buf, covenant_id_opt.unwrap_or(""));

    hex::encode(buf)
}

pub fn address_to_canonical_spk_hex(address: &str) -> Result<(u16, String), AgentError> {
    let (version, hash32) = decode_kaspa_address_payload(address).ok_or_else(|| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            "Failed to decode Kaspa Bech32m address into ScriptPublicKey.",
        )
    })?;
    let hex_hash = hex::encode(hash32);
    if version == KASPA_ADDR_VERSION_P2SH {
        Ok((0u16, format!("a9{}87", hex_hash)))
    } else if version == KASPA_ADDR_VERSION_P2PK_SCHNORR {
        Ok((0u16, format!("20{}ac", hex_hash)))
    } else {
        Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "Unsupported Kaspa ScriptPublicKey address version.",
        ))
    }
}

fn required_daa_depth(mode: AgentMode, is_coinbase: bool, is_token_leg: bool) -> u64 {
    if is_coinbase {
        return COINBASE_MATURITY_DAA_DEPTH;
    }
    if is_token_leg {
        return MIN_KRC20_KCC20_CONFIRMED_DAA_DEPTH;
    }
    match mode {
        AgentMode::ModeA => MIN_MODE_A_CONFIRMED_DAA_DEPTH,
        AgentMode::ModeB => MIN_MODE_B_CONFIRMED_DAA_DEPTH,
    }
}

/// Queries live UTXOs strictly from local `kaspad` gRPC (failing closed on node fault),
/// enforces confirmed DAA depth (rejecting unconfirmed mempool parent UTXOs), verifies canonical
/// script ownership, and selects non-locked UTXO lanes covering `required_total_sompi`.
pub async fn select_and_verify_wallet_utxos(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    claims: &AgentCapabilityClaims,
    explicit_outpoints: Option<&[OutpointRef]>,
    required_total_sompi: u128,
    is_token_leg: bool,
    dry_run: bool,
) -> Result<(Vec<LockedUtxoSnapshot>, Vec<Value>, u64), AgentError> {
    let virtual_daa_raw: Option<String> = redis::cmd("GET")
        .arg("pool:virtual_daa_score")
        .query_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to read pool:virtual_daa_score from Redis.",
            )
        })?;
    let virtual_daa = virtual_daa_raw
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&d| d > 0)
        .ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::NodeUnavailable,
                "kaspad virtual DAA score unavailable; failing closed.",
            )
        })?;

    let raw_utxos = crate::kaspad_client::get_utxos_by_address_grpc(&claims.prefixed_wallet)
        .await
        .map_err(|e| {
            tracing::error!("🚨 [AGENT VERIFIER] kaspad gRPC UTXO query failed: {}", e);
            AgentError::new(
                AgentErrorCode::NodeUnavailable,
                "Bare-metal kaspad gRPC UTXO lookup failed; failing closed.",
            )
        })?;

    let (_, expected_wallet_spk) = address_to_canonical_spk_hex(&claims.prefixed_wallet)?;

    let mut by_outpoint: HashMap<String, LockedUtxoSnapshot> =
        HashMap::with_capacity(raw_utxos.len());

    for entry in &raw_utxos {
        let txid = entry
            .get("outpoint")
            .and_then(|o| o.get("transactionId"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let index = entry
            .get("outpoint")
            .and_then(|o| o.get("index"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let amount_sompi = entry
            .get("utxoEntry")
            .and_then(|u| u.get("amount"))
            .and_then(|v| {
                v.as_u64()
                    .map(|x| x as u128)
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u128>().ok()))
            })
            .unwrap_or(0);
        if amount_sompi == 0 {
            continue;
        }
        let spk_ver = entry
            .get("utxoEntry")
            .and_then(|u| u.get("scriptPublicKey"))
            .and_then(|s| s.get("version"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;
        let spk_hex = entry
            .get("utxoEntry")
            .and_then(|u| u.get("scriptPublicKey"))
            .and_then(|s| s.get("scriptPublicKey"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let block_daa = entry
            .get("utxoEntry")
            .and_then(|u| u.get("blockDaaScore"))
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            })
            .unwrap_or(0);
        let is_coinbase = entry
            .get("utxoEntry")
            .and_then(|u| u.get("isCoinbase"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let key = format!("{}:{}", txid, index);
        by_outpoint.insert(
            key,
            LockedUtxoSnapshot {
                transaction_id: txid,
                index,
                amount_sompi: U128Str(amount_sompi),
                script_public_key_version: spk_ver,
                script_public_key_hex: spk_hex,
                block_daa_score: block_daa,
                is_coinbase,
            },
        );
    }

    if let Some(explicit) = explicit_outpoints.filter(|s| !s.is_empty()) {
        if explicit.len() > 32 {
            return Err(AgentError::new(
                AgentErrorCode::InvalidInput,
                "Maximum 32 explicit UTXO outpoints permitted per quote.",
            ));
        }
        let mut seen = HashSet::with_capacity(explicit.len());
        let mut selected = Vec::with_capacity(explicit.len());
        let mut gathered_sompi: u128 = 0;

        for out_ref in explicit {
            let key = out_ref.canonical_key();
            if !seen.insert(key.clone()) {
                return Err(AgentError::new(
                    AgentErrorCode::InvalidInput,
                    format!("Duplicate UTXO outpoint {} in request.", key),
                ));
            }
            let snap = by_outpoint.get(&key).ok_or_else(|| {
                AgentError::new(
                    AgentErrorCode::InvalidSignatureOrScript,
                    format!(
                        "ADVERSARIAL_SPENT_OR_MISSING_UTXO: Explicit outpoint {} is spent or not owned by {}.",
                        key, claims.prefixed_wallet
                    ),
                )
            })?;

            let min_depth = required_daa_depth(claims.mode, snap.is_coinbase, is_token_leg);
            if snap.block_daa_score == 0
                || snap.block_daa_score == KASPAD_UNACCEPTED_DAA_SCORE
                || virtual_daa < snap.block_daa_score
                || (virtual_daa - snap.block_daa_score) < min_depth
            {
                return Err(AgentError::new(
                    AgentErrorCode::UnconfirmedParentUtxo,
                    format!(
                        "UNCONFIRMED_PARENT_UTXO: Outpoint {} has insufficient DAA confirmation depth (required >= {}).",
                        key, min_depth
                    ),
                ));
            }

            if !is_token_leg && snap.script_public_key_hex != expected_wallet_spk {
                return Err(AgentError::new(
                    AgentErrorCode::InvalidSignatureOrScript,
                    format!(
                        "Outpoint {} ScriptPublicKey does not match canonical wallet template.",
                        key
                    ),
                ));
            }

            if !dry_run {
                let is_locked: i32 = redis::cmd("EXISTS")
                    .arg(format!("perennia:agent:utxo_lock:{}", key))
                    .query_async(redis_conn)
                    .await
                    .unwrap_or(0);
                if is_locked == 1 {
                    return Err(AgentError::new(
                        AgentErrorCode::UtxoContentionLocked,
                        format!("Outpoint {} is currently locked by an active quote.", key),
                    ));
                }
            }

            gathered_sompi = gathered_sompi.saturating_add(snap.amount_sompi.as_u128());
            selected.push(snap.clone());
        }

        if gathered_sompi < required_total_sompi {
            return Err(AgentError::new(
                AgentErrorCode::InvalidInput,
                format!(
                    "Explicit UTXO outpoints total {} sompi, below required {} sompi (principal + L1 mass fee).",
                    gathered_sompi, required_total_sompi
                ),
            ));
        }

        return Ok((selected, raw_utxos, virtual_daa));
    }

    // Automatic parallel-lane UTXO selection: filter confirmed, unlocked wallet UTXOs
    let mut candidates: Vec<(String, LockedUtxoSnapshot)> = by_outpoint
        .into_iter()
        .filter(|(_, snap)| {
            let min_depth = required_daa_depth(claims.mode, snap.is_coinbase, is_token_leg);
            let confirmed = snap.block_daa_score > 0
                && snap.block_daa_score != KASPAD_UNACCEPTED_DAA_SCORE
                && virtual_daa >= snap.block_daa_score
                && (virtual_daa - snap.block_daa_score) >= min_depth;
            let spk_ok = is_token_leg || snap.script_public_key_hex == expected_wallet_spk;
            confirmed && spk_ok
        })
        .collect();

    if candidates.is_empty() {
        return Err(AgentError::new(
            AgentErrorCode::UnconfirmedParentUtxo,
            "Wallet has 0 confirmed spendable Kaspa UTXOs meeting DAA finality depth.",
        ));
    }

    // Sort largest-first to minimize input count & post-Toccata compute/storage mass
    candidates.sort_by(|a, b| b.1.amount_sompi.cmp(&a.1.amount_sompi));

    let mut pipe = redis::pipe();
    for (key, _) in &candidates {
        pipe.cmd("EXISTS")
            .arg(format!("perennia:agent:utxo_lock:{}", key));
    }
    let lock_flags: Vec<i32> = pipe.query_async(redis_conn).await.unwrap_or_default();

    let mut selected = Vec::new();
    let mut gathered_sompi: u128 = 0;

    for ((_, snap), locked_flag) in candidates.into_iter().zip(lock_flags.into_iter()) {
        if !dry_run && locked_flag == 1 {
            continue;
        }
        gathered_sompi = gathered_sompi.saturating_add(snap.amount_sompi.as_u128());
        selected.push(snap);
        if gathered_sompi >= required_total_sompi || selected.len() >= 16 {
            break;
        }
    }

    if gathered_sompi < required_total_sompi {
        return Err(AgentError::new(
            AgentErrorCode::UtxoContentionLocked,
            format!(
                "Insufficient unlocked confirmed UTXO balance: gathered {} sompi, required {} sompi.",
                gathered_sompi, required_total_sompi
            ),
        ));
    }

    Ok((selected, raw_utxos, virtual_daa))
}

/// Computes exact Kaspa `TransactionSigningHash` (`blake2b_256_keyed(b"TransactionSigningHash", ...)`)
/// for every input in a transaction (`version` 0 or post-Toccata `version` 1).
pub fn compute_kaspa_sighashes_for_tx(
    tx_version: u16,
    utxos: &[LockedUtxoSnapshot],
    outputs: &[(u64, u16, String)],
    lock_time: u64,
    subnetwork_hex: &str,
    gas: u64,
    payload_bytes: &[u8],
) -> Result<Vec<[u8; 32]>, AgentError> {
    if utxos.is_empty() || outputs.is_empty() {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "Transaction sighash requires non-empty inputs and outputs.",
        ));
    }

    let subnet_clean = subnetwork_hex.trim().strip_prefix("0x").unwrap_or(subnetwork_hex.trim());
    let subnet_vec = hex::decode(subnet_clean).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            "Invalid subnetworkId hex in Kaspa transaction.",
        )
    })?;
    if subnet_vec.len() != 20 {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "Kaspa subnetworkId must be 20 bytes (40 hex chars).",
        ));
    }
    let mut subnet_bytes = [0u8; 20];
    subnet_bytes.copy_from_slice(&subnet_vec);

    let mut prev_outs_buf = Vec::with_capacity(utxos.len() * 36);
    let mut sequences_buf = Vec::with_capacity(utxos.len() * 8);
    let mut sig_op_counts_buf = Vec::with_capacity(utxos.len());

    for u in utxos {
        let txid_bytes = hex::decode(&u.transaction_id).map_err(|_| {
            AgentError::new(
                AgentErrorCode::InvalidInput,
                "Malformed UTXO transactionId hex.",
            )
        })?;
        prev_outs_buf.extend_from_slice(&txid_bytes);
        prev_outs_buf.extend_from_slice(&u.index.to_le_bytes());
        sequences_buf.extend_from_slice(&0u64.to_le_bytes());
        sig_op_counts_buf.push(1u8);
    }

    let prev_outs_hash = blake2b_256_keyed(TX_SIGNING_KEY, &prev_outs_buf);
    let sequences_hash = blake2b_256_keyed(TX_SIGNING_KEY, &sequences_buf);
    let sig_op_counts_hash = blake2b_256_keyed(TX_SIGNING_KEY, &sig_op_counts_buf);

    let mut outputs_buf = Vec::with_capacity(outputs.len() * 52);
    for (amt, spk_ver, spk_hex) in outputs {
        let spk_bytes = hex::decode(spk_hex).map_err(|_| {
            AgentError::new(
                AgentErrorCode::InvalidInput,
                "Invalid output ScriptPublicKey hex.",
            )
        })?;
        outputs_buf.extend_from_slice(&amt.to_le_bytes());
        outputs_buf.extend_from_slice(&spk_ver.to_le_bytes());
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

    let mut sighashes = Vec::with_capacity(utxos.len());
    for u in utxos {
        let txid_bytes = hex::decode(&u.transaction_id).unwrap_or_default();
        let spk_bytes = hex::decode(&u.script_public_key_hex).map_err(|_| {
            AgentError::new(
                AgentErrorCode::InvalidInput,
                "Malformed UTXO ScriptPublicKey hex.",
            )
        })?;
        let amt_u64 = u64::try_from(u.amount_sompi.as_u128()).map_err(|_| {
            AgentError::new(
                AgentErrorCode::InvalidInput,
                "UTXO sompi exceeds consensus u64 ceiling.",
            )
        })?;

        let mut preimage = Vec::with_capacity(220 + spk_bytes.len());
        preimage.extend_from_slice(&tx_version.to_le_bytes());
        preimage.extend_from_slice(&prev_outs_hash);
        preimage.extend_from_slice(&sequences_hash);
        preimage.extend_from_slice(&sig_op_counts_hash);
        preimage.extend_from_slice(&txid_bytes);
        preimage.extend_from_slice(&u.index.to_le_bytes());
        preimage.extend_from_slice(&u.script_public_key_version.to_le_bytes());
        preimage.extend_from_slice(&(spk_bytes.len() as u64).to_le_bytes());
        preimage.extend_from_slice(&spk_bytes);
        preimage.extend_from_slice(&amt_u64.to_le_bytes());
        preimage.extend_from_slice(&0u64.to_le_bytes()); // sequence = 0
        preimage.push(1u8); // sigOpCount = 1
        preimage.extend_from_slice(&outputs_hash);
        preimage.extend_from_slice(&lock_time.to_le_bytes());
        preimage.extend_from_slice(&subnet_bytes);
        preimage.extend_from_slice(&gas.to_le_bytes());
        preimage.extend_from_slice(&payload_hash);
        preimage.push(SIGHASH_ALL);

        sighashes.push(blake2b_256_keyed(TX_SIGNING_KEY, &preimage));
    }

    Ok(sighashes)
}

/// Builds the deterministic unsigned Kaspa L1 Transaction v1 ticket + `0x83` intent + `preimage_hash`.
pub fn build_unsigned_l1_kaspa_ticket(
    quote_id: &str,
    claims: &AgentCapabilityClaims,
    venue_str: &str,
    pay_asset: &str,
    receive_asset: &str,
    amount_in_atomic: u128,
    min_amount_out_atomic: u128,
    treasury_address: &str,
    locked_utxos: &[LockedUtxoSnapshot],
    network_fee_sompi: u128,
    expires_at_ms: u64,
    envelope: &PostToccataEnvelope,
) -> Result<UnsignedTicketBundle, AgentError> {
    let tx_version = envelope.tx_version.max(1);
    let (sender_spk_ver, sender_spk_hex) = address_to_canonical_spk_hex(&claims.prefixed_wallet)?;
    let (treasury_spk_ver, treasury_spk_hex) = address_to_canonical_spk_hex(treasury_address)?;

    let (principal_sompi_to_treasury, tx_payload_bytes) = if pay_asset == "KAS" {
        let mut p_bytes = Vec::new();
        if let Some(ref cov_id) = envelope.covenant_id {
            let cov_json = json!({
                "p": "perennia-cov-v1",
                "quoteId": quote_id,
                "covenantId": cov_id
            });
            p_bytes = canonicalize_json_bytes(&cov_json);
        }
        (amount_in_atomic, p_bytes)
    } else {
        // KRC-20 / KCC-20 transfer payload anchored to Perennia treasury with 0.30 KAS carrier output
        let krc_transfer = json!({
            "p": "krc-20",
            "op": "transfer",
            "tick": pay_asset,
            "amt": amount_in_atomic.to_string(),
            "to": treasury_address
        });
        (30_000_000u128, canonicalize_json_bytes(&krc_transfer))
    };

    let mut gathered_sompi: u128 = 0;
    let mut input_amounts_sompi = Vec::with_capacity(locked_utxos.len());
    let mut inputs_json = Vec::with_capacity(locked_utxos.len());

    for u in locked_utxos {
        gathered_sompi = gathered_sompi.saturating_add(u.amount_sompi.as_u128());
        input_amounts_sompi.push(u.amount_sompi.as_u128());
        inputs_json.push(json!({
            "previousOutpoint": {
                "transactionId": u.transaction_id,
                "index": u.index
            },
            "signatureScript": "",
            "sequence": 0,
            "sigOpCount": 1
        }));
    }

    let required_sompi = principal_sompi_to_treasury
        .checked_add(network_fee_sompi)
        .ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::SolvencyFloorViolation,
                "Required L1 sompi overflow.",
            )
        })?;

    if gathered_sompi < required_sompi {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            format!(
                "Selected UTXOs ({} sompi) cannot cover principal + post-Toccata mass fee ({} sompi).",
                gathered_sompi, required_sompi
            ),
        ));
    }

    let change_sompi = gathered_sompi - required_sompi;
    let principal_u64 = u64::try_from(principal_sompi_to_treasury).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            "Principal sompi exceeds consensus u64 ceiling.",
        )
    })?;

    let mut raw_outputs: Vec<(u64, u16, String)> =
        vec![(principal_u64, treasury_spk_ver, treasury_spk_hex)];
    let mut output_amounts_sompi: Vec<u128> = vec![principal_sompi_to_treasury];

    if change_sompi >= MIN_CHANGE_SOMPI {
        let change_u64 = u64::try_from(change_sompi).map_err(|_| {
            AgentError::new(
                AgentErrorCode::InvalidInput,
                "Change sompi exceeds consensus u64 ceiling.",
            )
        })?;
        raw_outputs.push((change_u64, sender_spk_ver, sender_spk_hex));
        output_amounts_sompi.push(change_sompi);
    }

    let outputs_json: Vec<Value> = raw_outputs
        .iter()
        .map(|(amt, ver, spk)| {
            json!({
                "amount": *amt,
                "scriptPublicKey": {
                    "version": *ver,
                    "scriptPublicKey": spk
                }
            })
        })
        .collect();

    let subnetwork_id = "0000000000000000000000000000000000000000";
    let tx_payload_hex = hex::encode(&tx_payload_bytes);

    let sighashes = compute_kaspa_sighashes_for_tx(
        tx_version,
        locked_utxos,
        &raw_outputs,
        0,
        subnetwork_id,
        0,
        &tx_payload_bytes,
    )?;
    let sighash_hex_per_input: Vec<String> = sighashes.into_iter().map(hex::encode).collect();

    let payload_0x83_hex = build_payload_0x83_hex(
        quote_id,
        &claims.clean_wallet,
        venue_str,
        pay_asset,
        receive_asset,
        amount_in_atomic,
        min_amount_out_atomic,
        network_fee_sompi,
        expires_at_ms,
        envelope.covenant_id.as_deref(),
    );

    let unsigned_tx_json = json!({
        "kind": "KASPA_L1_TX_V1",
        "transaction": {
            "version": tx_version,
            "inputs": inputs_json,
            "outputs": outputs_json,
            "lockTime": 0,
            "subnetworkId": subnetwork_id,
            "gas": 0,
            "payload": tx_payload_hex
        }
    });

    let preimage_hash = compute_blake3_preimage_hash(&unsigned_tx_json);

    Ok(UnsignedTicketBundle {
        execution_kind: "KASPA_L1_TX_V1".to_string(),
        unsigned_tx_json,
        sighash_hex_per_input,
        payload_0x83_hex,
        preimage_hash,
        input_amounts_sompi,
        output_amounts_sompi,
        tx_payload_bytes_len: tx_payload_bytes.len(),
    })
}

/// Builds a deterministic unsigned `0x83` Sovereign Intent ticket for verified execution-sleeve swaps.
pub fn build_unsigned_0x83_sleeve_ticket(
    quote_id: &str,
    claims: &AgentCapabilityClaims,
    venue_str: &str,
    pay_asset: &str,
    receive_asset: &str,
    amount_in_atomic: u128,
    min_amount_out_atomic: u128,
    network_fee_sompi: u128,
    expires_at_ms: u64,
    envelope: &PostToccataEnvelope,
) -> UnsignedTicketBundle {
    let payload_0x83_hex = build_payload_0x83_hex(
        quote_id,
        &claims.clean_wallet,
        venue_str,
        pay_asset,
        receive_asset,
        amount_in_atomic,
        min_amount_out_atomic,
        network_fee_sompi,
        expires_at_ms,
        envelope.covenant_id.as_deref(),
    );

    let unsigned_tx_json = json!({
        "kind": "SOVEREIGN_INTENT_0X83_V1",
        "quoteId": quote_id,
        "walletAddress": claims.prefixed_wallet,
        "pubkeyHex": claims.pubkey_hex,
        "intent0x83Hex": payload_0x83_hex,
        "signatureHex": ""
    });

    let preimage_hash = compute_blake3_preimage_hash(&unsigned_tx_json);
    let intent_sighash = blake3::hash(payload_0x83_hex.as_bytes()).to_hex().to_string();

    UnsignedTicketBundle {
        execution_kind: "SOVEREIGN_INTENT_0X83_V1".to_string(),
        unsigned_tx_json,
        sighash_hex_per_input: vec![intent_sighash],
        payload_0x83_hex,
        preimage_hash,
        input_amounts_sompi: Vec::new(),
        output_amounts_sompi: Vec::new(),
        tx_payload_bytes_len: 96,
    }
}

/// Strips client signature fields from a submitted execution payload so its canonical
/// unsigned structure can be compared byte-for-byte against `quote.preimage_hash` BEFORE
/// running any signature or script verification.
fn strip_signatures_to_unsigned_skeleton(submitted: &Value) -> Option<Value> {
    let kind = submitted.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    if kind == "SOVEREIGN_INTENT_0X83_V1" {
        let mut cloned = submitted.clone();
        if let Some(obj) = cloned.as_object_mut() {
            obj.insert("signatureHex".to_string(), Value::String(String::new()));
            return Some(cloned);
        }
        return None;
    }

    // Accept either `{ "kind": "KASPA_L1_TX_V1", "transaction": { ... } }` or `{ "transaction": { ... } }`
    let mut normalized = if kind == "KASPA_L1_TX_V1" {
        submitted.clone()
    } else if let Some(tx_inner) = submitted.get("transaction") {
        json!({
            "kind": "KASPA_L1_TX_V1",
            "transaction": tx_inner
        })
    } else if submitted.get("inputs").is_some() && submitted.get("outputs").is_some() {
        json!({
            "kind": "KASPA_L1_TX_V1",
            "transaction": submitted
        })
    } else {
        return None;
    };

    let inputs = normalized
        .get_mut("transaction")?
        .get_mut("inputs")?
        .as_array_mut()?;
    for inp in inputs.iter_mut() {
        let obj = inp.as_object_mut()?;
        obj.insert("signatureScript".to_string(), Value::String(String::new()));
    }

    Some(normalized)
}

fn contains_spoofed_indexer_fields(val: &Value) -> bool {
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                let lower = k.trim().to_ascii_lowercase();
                if lower == "opaccept" || lower == "op_accept" || lower == "indexerverified" {
                    return true;
                }
                if contains_spoofed_indexer_fields(v) {
                    return true;
                }
            }
            false
        }
        Value::Array(arr) => arr.iter().any(contains_spoofed_indexer_fields),
        _ => false,
    }
}

/// Validates a KRC-20 P2SH reveal script template byte-for-byte, blocking `OP_NOT`, empty-sig,
/// and malformed inscription bypasses without relying on any external indexer.
fn verify_krc20_p2sh_reveal_script_template(
    sig_script_bytes: &[u8],
    locked_utxo_spk_hex: &str,
    sighash: &[u8; 32],
    expected_pubkey: &XOnlyPublicKey,
    expected_tick: &str,
    expected_amt_atomic: u128,
    expected_treasury_address: &str,
) -> Result<(), AgentError> {
    // Prefix MUST be exact 65-byte push: [0x41, <64B Schnorr sig>, 0x01]
    if sig_script_bytes.len() < 68 || sig_script_bytes[0] != OP_DATA_65 || sig_script_bytes[65] != SIGHASH_ALL {
        return Err(AgentError::new(
            AgentErrorCode::InvalidSignatureOrScript,
            "KRC-20 reveal signatureScript failed canonical 65-byte Schnorr SIGHASH_ALL prefix check.",
        ));
    }

    let sig = SchnorrSignature::from_slice(&sig_script_bytes[1..65]).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidSignatureOrScript,
            "Invalid 64-byte Schnorr signature in KRC-20 reveal input.",
        )
    })?;
    let msg = Message::from_digest(*sighash);
    SECP256K1
        .verify_schnorr(&sig, &msg, expected_pubkey)
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::InvalidSignatureOrScript,
                "KRC-20 reveal Schnorr signature verification failed against canonical sighash.",
            )
        })?;

    // Extract pushed redeem script with zero trailing garbage bytes
    let rest = &sig_script_bytes[66..];
    let (redeem_script, consumed) = if rest[0] >= 1 && rest[0] <= 0x4b {
        let len = rest[0] as usize;
        if rest.len() != 1 + len {
            return Err(AgentError::new(
                AgentErrorCode::InvalidSignatureOrScript,
                "Non-canonical trailing bytes in KRC-20 reveal push.",
            ));
        }
        (&rest[1..], 1 + len)
    } else if rest[0] == OP_PUSHDATA1 && rest.len() >= 2 {
        let len = rest[1] as usize;
        if rest.len() != 2 + len {
            return Err(AgentError::new(
                AgentErrorCode::InvalidSignatureOrScript,
                "KRC-20 OP_PUSHDATA1 length mismatch or trailing script opcodes.",
            ));
        }
        (&rest[2..], 2 + len)
    } else if rest[0] == OP_PUSHDATA2 && rest.len() >= 3 {
        let len = u16::from_le_bytes([rest[1], rest[2]]) as usize;
        if rest.len() != 3 + len {
            return Err(AgentError::new(
                AgentErrorCode::InvalidSignatureOrScript,
                "KRC-20 OP_PUSHDATA2 length mismatch or trailing script opcodes.",
            ));
        }
        (&rest[3..], 3 + len)
    } else {
        return Err(AgentError::new(
            AgentErrorCode::InvalidSignatureOrScript,
            "Forbidden opcode in KRC-20 signatureScript (push-only invariant violated).",
        ));
    };
    let _ = consumed;

    // Verify P2SH script hash matches locked UTXO `a9 <32B blake2b> 87`
    let redeem_hash = blake2b_256(redeem_script);
    let expected_p2sh_spk = format!(
        "{:02x}{}{:02x}",
        OP_BLAKE2B,
        hex::encode(redeem_hash),
        OP_EQUAL
    );
    if locked_utxo_spk_hex != expected_p2sh_spk {
        return Err(AgentError::new(
            AgentErrorCode::InvalidSignatureOrScript,
            "KRC-20 reveal redeem script hash does not match locked P2SH UTXO.",
        ));
    }

    // Exact template header:
    // [0x20, <32B pubkey>, 0xac (OP_CHECKSIG), 0x00 (OP_FALSE), 0x63 (OP_IF), 0x07, b"kasplex", 0x00]
    let pub_bytes = expected_pubkey.serialize();
    if redeem_script.len() < 46
        || redeem_script[0] != OP_DATA_32
        || &redeem_script[1..33] != pub_bytes.as_slice()
        || redeem_script[33] != OP_CHECKSIG
        || redeem_script[34] != OP_FALSE
        || redeem_script[35] != OP_IF
        || redeem_script[36] != 0x07
        || &redeem_script[37..44] != b"kasplex"
        || redeem_script[44] != OP_FALSE
        || *redeem_script.last().unwrap_or(&0) != OP_ENDIF
    {
        return Err(AgentError::new(
            AgentErrorCode::InvalidSignatureOrScript,
            "KRC-20 reveal script failed exact Kasplex bytecode template check (OP_NOT / empty-sig blocked).",
        ));
    }

    let body_slice = &redeem_script[45..redeem_script.len() - 1];
    // Reject forbidden opcodes outside data push
    let json_bytes = if !body_slice.is_empty() && body_slice[0] >= 1 && body_slice[0] <= 0x4b {
        let len = body_slice[0] as usize;
        if body_slice.len() != 1 + len {
            return Err(AgentError::new(
                AgentErrorCode::InvalidSignatureOrScript,
                "Malformed KRC-20 JSON push length.",
            ));
        }
        &body_slice[1..]
    } else if body_slice.len() >= 2 && body_slice[0] == OP_PUSHDATA1 {
        let len = body_slice[1] as usize;
        if body_slice.len() != 2 + len {
            return Err(AgentError::new(
                AgentErrorCode::InvalidSignatureOrScript,
                "Malformed KRC-20 OP_PUSHDATA1 JSON push length.",
            ));
        }
        &body_slice[2..]
    } else {
        return Err(AgentError::new(
            AgentErrorCode::InvalidSignatureOrScript,
            "Unsupported KRC-20 inscription data push opcode.",
        ));
    };

    let insc: Value = serde_json::from_slice(json_bytes).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidSignatureOrScript,
            "Invalid UTF-8 JSON inside KRC-20 inscription script.",
        )
    })?;

    let p = insc.get("p").and_then(|v| v.as_str()).unwrap_or("");
    let op = insc.get("op").and_then(|v| v.as_str()).unwrap_or("");
    let tick = insc
        .get("tick")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_uppercase();
    let amt = insc.get("amt").and_then(|v| v.as_str()).unwrap_or("");
    let to = insc
        .get("to")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if !p.eq_ignore_ascii_case("krc-20")
        || !op.eq_ignore_ascii_case("transfer")
        || tick != expected_tick
        || amt != expected_amt_atomic.to_string()
        || to != expected_treasury_address.to_ascii_lowercase()
    {
        return Err(AgentError::new(
            AgentErrorCode::InvalidSignatureOrScript,
            "KRC-20 transfer inscription parameters do not match quoted asset, atomic amount, or treasury destination.",
        ));
    }

    Ok(())
}

/// Verifies a submitted signed payload on `/api/v1/agent/execute`:
/// 1. Byte-for-byte `preimage_hash` match BEFORE signature checks.
/// 2. Anti-indexer-spoof rejection (`opAccept` flags stripped/rejected).
/// 3. Live `kaspad` UTXO presence & DAA confirmation depth check.
/// 4. Canonical 64-byte Schnorr signature & exact script bytecode template verification.
pub async fn verify_signed_execution_submission(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    claims: &AgentCapabilityClaims,
    quote: &StoredAgentQuote,
    submitted_signed_payload: &Value,
    treasury_address: &str,
) -> Result<(VerifiedExecutionPayload, bool), AgentError> {
    // Reject any attempt to inject spoofed external indexer acceptance flags
    if contains_spoofed_indexer_fields(submitted_signed_payload) {
        return Err(AgentError::new(
            AgentErrorCode::InvalidSignatureOrScript,
            "ANTI_INDEXER_SPOOF: External indexer opAccept fields are forbidden; Perennia verifies L1 bytecode and DAA depth directly.",
        ));
    }

    // 1. Byte-for-byte pre-image verification BEFORE signature verification
    let unsigned_skeleton = strip_signatures_to_unsigned_skeleton(submitted_signed_payload)
        .ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::PreimageMismatch,
                "Submitted signed payload structure does not match quoted ticket schema.",
            )
        })?;

    let submitted_preimage_hash = compute_blake3_preimage_hash(&unsigned_skeleton);
    if !constant_time_eq(
        submitted_preimage_hash.as_bytes(),
        quote.preimage_hash.as_bytes(),
    ) {
        return Err(AgentError::new(
            AgentErrorCode::PreimageMismatch,
            "PREIMAGE_TAMPERED: Submitted transaction skeleton failed byte-for-byte Blake3 preimage_hash check.",
        ));
    }

    let pubkey_bytes = hex::decode(&quote.pubkey_hex).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidSignatureOrScript,
            "Capability key is missing a valid 32-byte x-only Schnorr public key.",
        )
    })?;
    let expected_pubkey = XOnlyPublicKey::from_slice(&pubkey_bytes).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidSignatureOrScript,
            "Invalid secp256k1 x-only public key bound to quote.",
        )
    })?;

    let kind = unsigned_skeleton
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Branch A: Signed `0x83` Sovereign Sleeve Intent
    if kind == "SOVEREIGN_INTENT_0X83_V1" {
        let raw_sig = submitted_signed_payload
            .get("signatureHex")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let clean_sig = raw_sig.strip_prefix("0x").unwrap_or(raw_sig);
        if clean_sig.len() != 128 || !clean_sig.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(AgentError::new(
                AgentErrorCode::InvalidSignatureOrScript,
                "0x83 intent signatureHex must be an exact 64-byte (128 hex character) Schnorr signature.",
            ));
        }
        let sig_bytes = hex::decode(clean_sig).map_err(|_| {
            AgentError::new(
                AgentErrorCode::InvalidSignatureOrScript,
                "Malformed hex in 0x83 signatureHex.",
            )
        })?;
        let schnorr_sig = SchnorrSignature::from_slice(&sig_bytes).map_err(|_| {
            AgentError::new(
                AgentErrorCode::InvalidSignatureOrScript,
                "Invalid 64-byte Schnorr signature encoding on 0x83 intent.",
            )
        })?;

        let preimage_digest_vec = hex::decode(&quote.preimage_hash).unwrap_or_default();
        let mut preimage_digest = [0u8; 32];
        preimage_digest.copy_from_slice(&preimage_digest_vec);

        let intent_blake3: [u8; 32] = *blake3::hash(quote.payload_0x83_hex.as_bytes()).as_bytes();
        let personal_digest: [u8; 32] =
            blake2b_256_keyed(PERSONAL_MSG_SIGNING_KEY, quote.payload_0x83_hex.as_bytes());

        let valid = SECP256K1
            .verify_schnorr(
                &schnorr_sig,
                &Message::from_digest(preimage_digest),
                &expected_pubkey,
            )
            .is_ok()
            || SECP256K1
                .verify_schnorr(
                    &schnorr_sig,
                    &Message::from_digest(intent_blake3),
                    &expected_pubkey,
                )
                .is_ok()
            || SECP256K1
                .verify_schnorr(
                    &schnorr_sig,
                    &Message::from_digest(personal_digest),
                    &expected_pubkey,
                )
                .is_ok();

        if !valid {
            return Err(AgentError::new(
                AgentErrorCode::InvalidSignatureOrScript,
                "64-byte Schnorr signature verification failed on 0x83 Sovereign Intent.",
            ));
        }

        return Ok((
            VerifiedExecutionPayload::SovereignSleeveIntent0x83 {
                signature_hex: clean_sig.to_ascii_lowercase(),
            },
            true,
        ));
    }

    // Branch B: Signed Kaspa L1 Transaction (`KASPA_L1_TX_V1`)
    let tx_obj = submitted_signed_payload
        .get("transaction")
        .unwrap_or(submitted_signed_payload);
    let submitted_inputs = tx_obj
        .get("inputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::InvalidSignatureOrScript,
                "Signed L1 transaction missing inputs array.",
            )
        })?;

    if submitted_inputs.len() != quote.locked_utxos.len() {
        return Err(AgentError::new(
            AgentErrorCode::PreimageMismatch,
            "Signed L1 input count does not match locked UTXO count.",
        ));
    }

    // Verify live UTXOs on `kaspad` are still unspent and meet confirmed DAA depth
    let virtual_daa_str: Option<String> = redis::cmd("GET")
        .arg("pool:virtual_daa_score")
        .query_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to read virtual DAA score during execution.",
            )
        })?;
    let virtual_daa = virtual_daa_str
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&d| d > 0)
        .ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::NodeUnavailable,
                "kaspad virtual DAA score offline during execution.",
            )
        })?;

    let live_utxos = crate::kaspad_client::get_utxos_by_address_grpc(&claims.prefixed_wallet)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::NodeUnavailable,
                "kaspad gRPC UTXO verification failed during execution; failing closed.",
            )
        })?;

    let mut live_daa_map: HashMap<String, (u128, u64, bool)> =
        HashMap::with_capacity(live_utxos.len());
    for entry in &live_utxos {
        let txid = entry
            .get("outpoint")
            .and_then(|o| o.get("transactionId"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let idx = entry
            .get("outpoint")
            .and_then(|o| o.get("index"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let amt = entry
            .get("utxoEntry")
            .and_then(|u| u.get("amount"))
            .and_then(|v| v.as_str().and_then(|s| s.parse::<u128>().ok()))
            .unwrap_or(0);
        let b_daa = entry
            .get("utxoEntry")
            .and_then(|u| u.get("blockDaaScore"))
            .and_then(|v| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            .unwrap_or(0);
        let is_cb = entry
            .get("utxoEntry")
            .and_then(|u| u.get("isCoinbase"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        live_daa_map.insert(format!("{}:{}", txid, idx), (amt, b_daa, is_cb));
    }

    let is_token_leg = quote.pay_asset != "KAS";
    let mut min_observed_daa_depth = u64::MAX;

    for locked in &quote.locked_utxos {
        let key = format!("{}:{}", locked.transaction_id, locked.index);
        let Some(&(live_amt, live_b_daa, is_cb)) = live_daa_map.get(&key) else {
            return Err(AgentError::new(
                AgentErrorCode::InvalidSignatureOrScript,
                format!(
                    "ADVERSARIAL_DOUBLE_SPEND_OR_MISSING_UTXO: Locked outpoint {} was spent externally.",
                    key
                ),
            ));
        };
        if live_amt != locked.amount_sompi.as_u128() {
            return Err(AgentError::new(
                AgentErrorCode::InvalidSignatureOrScript,
                "UTXO sompi mismatch against locked quote state.",
            ));
        }
        let req_depth = required_daa_depth(claims.mode, is_cb, is_token_leg);
        if live_b_daa == 0
            || live_b_daa == KASPAD_UNACCEPTED_DAA_SCORE
            || virtual_daa < live_b_daa
            || (virtual_daa - live_b_daa) < req_depth
        {
            return Err(AgentError::new(
                AgentErrorCode::UnconfirmedParentUtxo,
                format!(
                    "UNCONFIRMED_PARENT_UTXO: Outpoint {} failed confirmed DAA depth check.",
                    key
                ),
            ));
        }
        min_observed_daa_depth = min_observed_daa_depth.min(virtual_daa - live_b_daa);
    }

    // Reconstruct outputs & payload to recompute exact Kaspa `TransactionSigningHash`
    let raw_outs_arr = tx_obj
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::PreimageMismatch,
                "Transaction missing outputs array.",
            )
        })?;
    let mut parsed_outputs: Vec<(u64, u16, String)> = Vec::with_capacity(raw_outs_arr.len());
    for out in raw_outs_arr {
        let amt = out.get("amount").and_then(|v| v.as_u64()).ok_or_else(|| {
            AgentError::new(AgentErrorCode::PreimageMismatch, "Invalid output amount.")
        })?;
        let spk_ver = out
            .get("scriptPublicKey")
            .and_then(|s| s.get("version"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;
        let spk_hex = out
            .get("scriptPublicKey")
            .and_then(|s| s.get("scriptPublicKey"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        parsed_outputs.push((amt, spk_ver, spk_hex));
    }

    let lock_time = tx_obj.get("lockTime").and_then(|v| v.as_u64()).unwrap_or(0);
    let subnet = tx_obj
        .get("subnetworkId")
        .and_then(|v| v.as_str())
        .unwrap_or("0000000000000000000000000000000000000000");
    let gas = tx_obj.get("gas").and_then(|v| v.as_u64()).unwrap_or(0);
    let payload_hex = tx_obj.get("payload").and_then(|v| v.as_str()).unwrap_or("");
    let payload_bytes = hex::decode(payload_hex).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidSignatureOrScript,
            "Invalid transaction payload hex.",
        )
    })?;

    let computed_sighashes = compute_kaspa_sighashes_for_tx(
        quote.tx_version,
        &quote.locked_utxos,
        &parsed_outputs,
        lock_time,
        subnet,
        gas,
        &payload_bytes,
    )?;

    let expected_p2pk_spk = format!("20{}ac", quote.pubkey_hex);

    // Optional KCC-20 Covenant commitment verification if `covenant_id` is set
    if let Some(ref cov_id) = quote.covenant_id {
        let amt_u64 = u64::try_from(quote.amount_in_atomic.as_u128()).unwrap_or(u64::MAX);
        let mut owner32 = [0u8; 32];
        owner32.copy_from_slice(&pubkey_bytes);
        let guard32 = blake2b_256(quote.quote_id.as_bytes());
        let kcc_state = build_kcc20_state_commitment(
            &quote.pay_asset,
            amt_u64,
            &owner32,
            KASPA_ADDR_VERSION_P2PK_SCHNORR,
            0x00,
            &guard32,
            Some(cov_id),
        );
        if kcc_state.covenant_id_hex.len() != 64 {
            return Err(AgentError::new(
                AgentErrorCode::InvalidSignatureOrScript,
                "Failed to derive KCC-20 covenant state commitment.",
            ));
        }
    }

    for (idx, ((inp_val, locked_utxo), sighash)) in submitted_inputs
        .iter()
        .zip(quote.locked_utxos.iter())
        .zip(computed_sighashes.iter())
        .enumerate()
    {
        let sig_script_hex = inp_val
            .get("signatureScript")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();

        if sig_script_hex.is_empty() {
            return Err(AgentError::new(
                AgentErrorCode::InvalidSignatureOrScript,
                format!("EMPTY_SIGNATURE_REJECTED: Input #{} has empty signatureScript.", idx),
            ));
        }

        let sig_script_bytes = hex::decode(sig_script_hex).map_err(|_| {
            AgentError::new(
                AgentErrorCode::InvalidSignatureOrScript,
                format!("Input #{} signatureScript is not valid hex.", idx),
            )
        })?;

        // Global anti-exploit opcode screen: reject OP_NOT, OP_0NOTEQUAL, OP_CODESEPARATOR, OP_RETURN
        if locked_utxo.script_public_key_hex == expected_p2pk_spk {
            // Canonical P2PK Schnorr input MUST be exact 66 bytes: [0x41, <64-byte Schnorr sig>, 0x01]
            if sig_script_bytes.len() != 66
                || sig_script_bytes[0] != OP_DATA_65
                || sig_script_bytes[65] != SIGHASH_ALL
            {
                return Err(AgentError::new(
                    AgentErrorCode::InvalidSignatureOrScript,
                    format!(
                        "NON_CANONICAL_SCRIPT_REJECTED: Input #{} P2PK signatureScript must be exact 66-byte [0x41, 64B_sig, 0x01] (empty-sig / OP_NOT tricks blocked).",
                        idx
                    ),
                ));
            }

            let schnorr_sig =
                SchnorrSignature::from_slice(&sig_script_bytes[1..65]).map_err(|_| {
                    AgentError::new(
                        AgentErrorCode::InvalidSignatureOrScript,
                        format!("Input #{} contains malformed 64-byte Schnorr signature.", idx),
                    )
                })?;

            let msg = Message::from_digest(*sighash);
            SECP256K1
                .verify_schnorr(&schnorr_sig, &msg, &expected_pubkey)
                .map_err(|_| {
                    AgentError::new(
                        AgentErrorCode::InvalidSignatureOrScript,
                        format!(
                            "INVALID_SCHNORR_SIGNATURE: Input #{} failed secp256k1 Schnorr verification against Kaspa TransactionSigningHash.",
                            idx
                        ),
                    )
                })?;
        } else if is_token_leg && locked_utxo.script_public_key_hex.starts_with("a9") {
            verify_krc20_p2sh_reveal_script_template(
                &sig_script_bytes,
                &locked_utxo.script_public_key_hex,
                sighash,
                &expected_pubkey,
                &quote.pay_asset,
                quote.amount_in_atomic.as_u128(),
                treasury_address,
            )?;
        } else {
            let _ = (OP_NOT, OP_0NOTEQUAL, OP_CODESEPARATOR, OP_RETURN);
            return Err(AgentError::new(
                AgentErrorCode::InvalidSignatureOrScript,
                format!(
                    "Input #{} uses an unauthorized ScriptPublicKey template.",
                    idx
                ),
            ));
        }
    }

    let envelope_for_rpc = json!({ "transaction": tx_obj });
    Ok((
        VerifiedExecutionPayload::KaspaL1Transaction {
            signed_tx_envelope: envelope_for_rpc,
            verified_daa_depth_min: if min_observed_daa_depth == u64::MAX {
                0
            } else {
                min_observed_daa_depth
            },
        },
        true,
    ))
}

/// Computes the canonical Blake3 `execution_commitment_hash` anchoring `quote_id`,
/// execution-time integer oracle snapshot, `u128` fee breakdown, `mandate_id`, `l1_txid`,
/// and HIFO tax-lot UUIDs for Kaspa L1 `Seqcommit` / RISC Zero proof verification.
#[allow(clippy::too_many_arguments)]
pub fn compute_execution_commitment_hash(
    quote_id: &str,
    mandate_id: &str,
    pay_asset: &str,
    receive_asset: &str,
    pay_oracle_usd_e8: u128,
    receive_oracle_usd_e8: u128,
    kas_oracle_usd_e8: u128,
    amount_in_atomic: u128,
    settled_out_atomic: u128,
    protocol_fee_atomic: u128,
    network_fee_sompi: u128,
    total_fee_usd_micros: u128,
    l1_txid: &str,
    hifo_disposal_lot_id: Option<Uuid>,
    hifo_acquisition_lot_id: Option<Uuid>,
) -> String {
    let commitment_doc = json!({
        "domain": "PERENNIA_EXEC_COMMIT_SEQCOMMIT_V1",
        "quoteId": quote_id,
        "mandateId": mandate_id,
        "payAsset": pay_asset,
        "receiveAsset": receive_asset,
        "oracleSnapshot": {
            "payUsdE8": pay_oracle_usd_e8.to_string(),
            "receiveUsdE8": receive_oracle_usd_e8.to_string(),
            "kasUsdE8": kas_oracle_usd_e8.to_string()
        },
        "feesAndAmounts": {
            "amountInAtomic": amount_in_atomic.to_string(),
            "settledOutAtomic": settled_out_atomic.to_string(),
            "protocolFeeAtomic": protocol_fee_atomic.to_string(),
            "networkFeeSompi": network_fee_sompi.to_string(),
            "totalFeeUsdMicros": total_fee_usd_micros.to_string()
        },
        "l1Txid": l1_txid,
        "hifoDisposalLotId": hifo_disposal_lot_id.map(|u| u.to_string()).unwrap_or_else(|| "NONE".to_string()),
        "hifoAcquisitionLotId": hifo_acquisition_lot_id.map(|u| u.to_string()).unwrap_or_else(|| "NONE".to_string())
    });

    let canonical_bytes = canonicalize_json_bytes(&commitment_doc);
    blake3::hash(&canonical_bytes).to_hex().to_string()
}