use serde_json::{json, Value};

use crate::state_api::{decode_kaspa_address_payload, KASPA_ADDR_VERSION_P2SH};

pub const BASE_COMPUTE_MASS: u64 = 200;
pub const MASS_PER_INPUT: u64 = 1200;
pub const MASS_PER_OUTPUT: u64 = 450;
pub const STORAGE_MASS_PARAMETER: u64 = 1_000_000_000_000;
pub const FEE_PER_GRAM: u64 = 110;

pub fn calculate_compute_mass(num_inputs: usize, num_outputs: usize, payload_len: usize) -> u64 {
    BASE_COMPUTE_MASS
        + (num_inputs as u64) * MASS_PER_INPUT
        + (num_outputs as u64) * MASS_PER_OUTPUT
        + (payload_len as u64)
}

pub fn calculate_storage_mass(input_amounts: &[u64], output_amounts: &[u64]) -> u64 {
    if input_amounts.is_empty() || output_amounts.is_empty() {
        return 0;
    }
    let harmonic_outs: u64 = output_amounts
        .iter()
        .map(|&v| {
            if v > 0 {
                STORAGE_MASS_PARAMETER / v
            } else {
                STORAGE_MASS_PARAMETER
            }
        })
        .sum();

    let sum_ins: u64 = input_amounts.iter().sum();
    let mean_ins = sum_ins / (input_amounts.len() as u64).max(1);
    if mean_ins == 0 {
        return harmonic_outs;
    }
    let arithmetic_ins = (input_amounts.len() as u64) * (STORAGE_MASS_PARAMETER / mean_ins);
    harmonic_outs.saturating_sub(arithmetic_ins)
}

pub fn decode_kaspa_address_to_spk_hex(address: &str) -> String {
    if let Some((version, hash32)) = decode_kaspa_address_payload(address) {
        let hex_hash = hex::encode(hash32);
        if version == KASPA_ADDR_VERSION_P2SH {
            return format!("a9{}87", hex_hash);
        }
        return format!("20{}ac", hex_hash);
    }
    let fallback = crate::state_api::blake2b_256(address.trim().as_bytes());
    format!("20{}ac", hex::encode(fallback))
}

pub fn assemble_unsigned_kaspa_psbt(
    sender_address: &str,
    recipient_address: &str,
    amount_sompi: u64,
    utxo_entries: &[Value],
) -> Option<(Value, Vec<Value>)> {
    if utxo_entries.is_empty() || amount_sompi == 0 {
        return None;
    }
    let sender_spk = decode_kaspa_address_to_spk_hex(sender_address);
    let recipient_spk = decode_kaspa_address_to_spk_hex(recipient_address);

    let mut gathered: u64 = 0;
    let mut inputs = Vec::new();
    let mut formatted_utxos = Vec::new();
    let mut input_amounts = Vec::new();

    for u in utxo_entries {
        let tx_id = u
            .get("transactionId")
            .or_else(|| u.get("outpoint").and_then(|o| o.get("transactionId")))
            .and_then(|v| v.as_str())?;
        let index = u
            .get("index")
            .or_else(|| u.get("outpoint").and_then(|o| o.get("index")))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let amt = u
            .get("amount")
            .or_else(|| u.get("utxoEntry").and_then(|e| e.get("amount")))
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            })
            .unwrap_or(0);
        if amt == 0 {
            continue;
        }
        let spk = u
            .get("scriptPublicKey")
            .and_then(|v| {
                v.as_str().or_else(|| {
                    v.get("scriptPublicKey").and_then(|s| s.as_str())
                })
            })
            .unwrap_or(&sender_spk)
            .to_string();

        inputs.push(json!({
            "previousOutpoint": {
                "transactionId": tx_id,
                "index": index
            },
            "signatureScript": "",
            "sequence": 0,
            "sigOpCount": 1
        }));
        formatted_utxos.push(json!({
            "transactionId": tx_id,
            "index": index,
            "amount": amt,
            "scriptPublicKey": spk
        }));
        input_amounts.push(amt);
        gathered += amt;

        let compute_mass = calculate_compute_mass(inputs.len(), 2, 0);
        let fee = compute_mass * FEE_PER_GRAM;
        if gathered >= amount_sompi + fee {
            break;
        }
    }

    let compute_mass = calculate_compute_mass(inputs.len(), 2, 0);
    let fee = compute_mass * FEE_PER_GRAM;
    if gathered < amount_sompi + fee {
        return None;
    }

    let change = gathered - amount_sompi - fee;
    let mut outputs = vec![json!({
        "amount": amount_sompi,
        "scriptPublicKey": recipient_spk
    })];
    if change >= 10_000_000 {
        outputs.push(json!({
            "amount": change,
            "scriptPublicKey": sender_spk
        }));
    }

    let psbt = json!({
        "version": 0,
        "inputs": inputs,
        "outputs": outputs,
        "lockTime": 0,
        "subnetworkId": "0000000000000000000000000000000000000000",
        "gas": 0,
        "payload": ""
    });

    Some((psbt, formatted_utxos))
}