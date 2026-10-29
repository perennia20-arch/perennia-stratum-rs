use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Row, Transaction as SqlTransaction};
use std::collections::HashMap;
use std::env;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use reqwest::Client;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const MASTER_ADMIN_ADDRESS_CLEAN: &str =
    "qrc3ezl770p2cjlfc3tjp6vqlldt6lgh3e80d6rm4rchtt0yrrpgzqave8579";

pub const KASPA_BURN_ADDRESS: &str =
    "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e";
pub const CANONICAL_GENESIS_ANCHOR_EPOCH_SEC: i64 = 1_767_225_600;
pub const KASPA_ADDR_VERSION_P2PK_SCHNORR: u8 = 0x00;
pub const KASPA_ADDR_VERSION_P2PK_ECDSA: u8 = 0x01;
pub const KASPA_ADDR_VERSION_P2SH: u8 = 0x08;
const KASPA_BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

pub fn kaspa_bech32m_polymod(values: &[u8]) -> u64 {
    let mut c: u64 = 1;
    for &v in values {
        let c0 = c >> 35;
        c = ((c & 0x07ff_ffff_ff) << 5) ^ (v as u64);
        if (c0 & 1) != 0 {
            c ^= 0x98f2_bc8e_61;
        }
        if (c0 & 2) != 0 {
            c ^= 0x79b7_6d99_e2;
        }
        if (c0 & 4) != 0 {
            c ^= 0xf33e_5fb3_c4;
        }
        if (c0 & 8) != 0 {
            c ^= 0xae2e_abe2_a8;
        }
        if (c0 & 16) != 0 {
            c ^= 0x1e4f_43e4_70;
        }
    }
    c ^ 1
}

pub fn encode_kaspa_bech32m_address(version: u8, hash32: &[u8; 32]) -> String {
    let prefix = b"kaspa";
    let mut prefix_values: Vec<u8> = prefix.iter().map(|b| b & 31).collect();
    prefix_values.push(0);
    let mut payload = Vec::with_capacity(33);
    payload.push(version);
    payload.extend_from_slice(hash32);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut payload5: Vec<u8> = Vec::with_capacity(54);
    for &byte in &payload {
        acc = (acc << 8) | (byte as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            payload5.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        payload5.push(((acc << (5 - bits)) & 31) as u8);
    }
    let mut mod_input = Vec::with_capacity(prefix_values.len() + payload5.len() + 8);
    mod_input.extend_from_slice(&prefix_values);
    mod_input.extend_from_slice(&payload5);
    mod_input.extend_from_slice(&[0u8; 8]);
    let polymod = kaspa_bech32m_polymod(&mod_input);
    let mut out_str = String::with_capacity(6 + payload5.len() + 8);
    out_str.push_str("kaspa:");
    for &w in &payload5 {
        out_str.push(KASPA_BECH32_CHARSET[(w & 31) as usize] as char);
    }
    for i in 0..8 {
        let idx = ((polymod >> (5 * (7 - i))) & 31) as usize;
        out_str.push(KASPA_BECH32_CHARSET[idx] as char);
    }
    out_str
}

pub fn encode_kaspa_p2sh_address(script_hash32: &[u8; 32]) -> String {
    encode_kaspa_bech32m_address(KASPA_ADDR_VERSION_P2SH, script_hash32)
}

pub fn decode_kaspa_address_version_and_hash(address: &str) -> Result<(u8, [u8; 32]), String> {
    let clean_addr = address.trim().to_lowercase().replace("kaspa:", "");
    if clean_addr.len() < 55 || clean_addr.len() > 75 {
        return Err(format!("Invalid Kaspa Bech32m payload length ({})", clean_addr.len()));
    }
    let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut all_words: Vec<u8> = Vec::with_capacity(clean_addr.len());
    for c in clean_addr.chars() {
        if let Some(idx) = charset.find(c) {
            all_words.push(idx as u8);
        } else {
            return Err(format!("Invalid base32 character detected: {}", c));
        }
    }
    if all_words.len() < 9 {
        return Err("Address payload too short".to_string());
    }
    let mut polymod_input: Vec<u8> = b"kaspa".iter().map(|b| b & 31).collect();
    polymod_input.push(0);
    polymod_input.extend_from_slice(&all_words);
    if kaspa_bech32m_polymod(&polymod_input) != 0 {
        return Err("Kaspa Bech32m polymod checksum verification failed".to_string());
    }
    let data_words = &all_words[..all_words.len() - 8];
    let mut out = Vec::with_capacity(34);
    let mut val = 0u32;
    let mut bits = 0;
    for &d in data_words {
        val = (val << 5) | (d as u32);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push((val >> bits) as u8);
        }
    }
    if out.len() < 33 {
        return Err(format!(
            "Decoded address payload is too short. Expected 33 bytes, got {}",
            out.len()
        ));
    }
    let version = out[0];
    if version != KASPA_ADDR_VERSION_P2PK_SCHNORR
        && version != KASPA_ADDR_VERSION_P2PK_ECDSA
        && version != KASPA_ADDR_VERSION_P2SH
    {
        return Err(format!("Unsupported Kaspa address version byte: 0x{:02x}", version));
    }
    let mut hash32 = [0u8; 32];
    hash32.copy_from_slice(&out[1..33]);
    Ok((version, hash32))
}

const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const BLAKE2B_SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[inline]
fn blake2b_g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn blake2b_compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for i in 0..16 {
        let mut word = [0u8; 8];
        word.copy_from_slice(&block[i * 8..(i + 1) * 8]);
        m[i] = u64::from_le_bytes(word);
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..16].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    for s in &BLAKE2B_SIGMA {
        blake2b_g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        blake2b_g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        blake2b_g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        blake2b_g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        blake2b_g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        blake2b_g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        blake2b_g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        blake2b_g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

pub fn compute_blake2b_256(data: &[u8], key: Option<&[u8]>) -> [u8; 32] {
    let key_slice = key.unwrap_or(&[]);
    let key_len = key_slice.len().min(64);
    let mut h = BLAKE2B_IV;
    h[0] ^= 0x01010000 ^ ((key_len as u64) << 8) ^ 32u64;
    let mut total_blocks: Vec<u8> = Vec::with_capacity(if key_len > 0 { 128 + data.len() } else { data.len() });
    if key_len > 0 {
        let mut key_block = [0u8; 128];
        key_block[..key_len].copy_from_slice(&key_slice[..key_len]);
        total_blocks.extend_from_slice(&key_block);
    }
    total_blocks.extend_from_slice(data);
    if total_blocks.is_empty() {
        let empty_block = [0u8; 128];
        blake2b_compress(&mut h, &empty_block, 0, true);
    } else {
        let mut offset = 0usize;
        let total_len = total_blocks.len();
        while total_len - offset > 128 {
            let mut block = [0u8; 128];
            block.copy_from_slice(&total_blocks[offset..offset + 128]);
            offset += 128;
            blake2b_compress(&mut h, &block, offset as u128, false);
        }
        let rem = total_len - offset;
        let mut final_block = [0u8; 128];
        final_block[..rem].copy_from_slice(&total_blocks[offset..]);
        blake2b_compress(&mut h, &final_block, total_len as u128, true);
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[allow(non_snake_case)]
pub struct KCC20State {
    pub amount: u64,
    pub owner: [u8; 32],
    pub owner_scheme: u8,
    pub borrow_scheme: u8,
    pub borrow_guard: [u8; 32],
    pub extension_commitment: [u8; 32],
}

impl KCC20State {
    pub fn to_packed_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(106);
        buf.extend_from_slice(&self.amount.to_le_bytes());
        buf.extend_from_slice(&self.owner);
        buf.push(self.owner_scheme);
        buf.push(self.borrow_scheme);
        buf.extend_from_slice(&self.borrow_guard);
        buf.extend_from_slice(&self.extension_commitment);
        buf
    }

    pub fn compute_state_root(&self) -> [u8; 32] {
        let packed = self.to_packed_bytes();
        compute_blake2b_256(&packed, Some(b"KCC20StateCommitment"))
    }

    pub fn compute_covenant_id(&self, ticker: &str) -> [u8; 32] {
        let clean = ticker.trim().to_uppercase();
        let state_root = self.compute_state_root();
        let mut preimage = format!("KCC-20:{}:", clean).into_bytes();
        preimage.extend_from_slice(&state_root);
        compute_blake2b_256(&preimage, None)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[allow(non_snake_case)]
pub struct CompiledSilverScriptVault {
    pub contractName: String,
    pub ticker: String,
    pub tokenStandard: String,
    pub label: String,
    pub beneficiaryAddress: String,
    pub beneficiaryPubkeyHex: String,
    pub cliffDays: i32,
    pub cliffTimestamp: i64,
    pub linearDays: i32,
    pub totalAllocation: u64,
    pub silverscriptSource: String,
    pub redeemScriptHex: String,
    pub scriptHashHex: String,
    pub covenantAddress: String,
    pub covenantSpkHex: String,
    pub kcc20PackedHex: String,
    pub kcc20StateRootHex: String,
    pub kcc20CovenantIdHex: String,
}

pub fn compile_silverscript_proof_of_lock_vault(
    ticker: &str,
    token_standard: &str,
    label: &str,
    beneficiary_address: &str,
    total_allocation_tokens: f64,
    decimals: u32,
    cliff_days: i32,
    linear_days: i32,
    anchor_timestamp_sec: Option<i64>,
    charter_sha256_hex: Option<&str>,
) -> CompiledSilverScriptVault {
    let clean_ticker = ticker.trim().to_uppercase();
    let resolved_standard = if token_standard.trim().eq_ignore_ascii_case("KCC-20") {
        "KCC-20".to_string()
    } else {
        "KRC-20".to_string()
    };
    let clean_label = if label.trim().is_empty() {
        "Genesis Tranche".to_string()
    } else {
        label.trim().to_string()
    };
    let clamped_cliff = cliff_days.max(0);
    let clamped_linear = linear_days.max(0);
    let total_whole_tokens = total_allocation_tokens.max(0.0).floor() as u64;
    let clamped_dec = decimals.min(18);
    let base_anchor = anchor_timestamp_sec
        .filter(|&ts| ts > 0)
        .unwrap_or(CANONICAL_GENESIS_ANCHOR_EPOCH_SEC);
    let cliff_timestamp = base_anchor + (clamped_cliff as i64) * 86_400;
    let (owner_scheme, beneficiary_pubkey_bytes, normalized_beneficiary): (u8, [u8; 32], String) =
        match decode_kaspa_address_version_and_hash(beneficiary_address) {
            Ok((ver, hash32)) => {
                let norm = if beneficiary_address.trim().to_lowercase().starts_with("kaspa:") {
                    beneficiary_address.trim().to_lowercase()
                } else {
                    format!("kaspa:{}", beneficiary_address.trim().to_lowercase())
                };
                (ver, hash32, norm)
            }
            Err(_) => {
                let seed = format!(
                    "PERENNIA_BENEFICIARY:{}",
                    beneficiary_address.trim().to_lowercase()
                );
                let digest: [u8; 32] = compute_blake2b_256(seed.as_bytes(), None);
                let addr = encode_kaspa_bech32m_address(
                    KASPA_ADDR_VERSION_P2PK_SCHNORR,
                    &digest,
                );
                (KASPA_ADDR_VERSION_P2PK_SCHNORR, digest, addr)
            }
        };
    let beneficiary_pubkey_hex = hex::encode(beneficiary_pubkey_bytes);
    let silverscript_source = format!(
        "pragma silverscript ^1.0.0;\n\n\
// Perennia Sovereign Forge — L1 UTXO Proof-of-Lock & {} Covenant\n\
// Ticker: {} | Tranche: {} | 22:00 UTC Daily Release\n\
contract ProofOfLockVault(\n\
    pubkey beneficiary,\n\
    int cliffTimestamp,\n\
    int linearDays,\n\
    int totalAllocation\n\
) {{\n\
    // Constructor Bindings:\n\
    // beneficiary     = 0x{}\n\
    // cliffTimestamp  = {} ({}d cliff)\n\
    // linearDays      = {} ({}d linear vesting)\n\
    // totalAllocation = {} {}\n\
    entrypoint function unlockTranche(sig beneficiarySig, int currentEpochTs, int claimAmount) {{\n\
        require(checkSig(beneficiarySig, beneficiary));\n\
        require(tx.time >= cliffTimestamp);\n\
        require(currentEpochTs >= cliffTimestamp);\n\n\
        int elapsedSeconds = currentEpochTs - cliffTimestamp;\n\
        int linearDurationSeconds = linearDays * 86400;\n\
        int maxVested = totalAllocation;\n\
        if (linearDurationSeconds > 0 && elapsedSeconds < linearDurationSeconds) {{\n\
            maxVested = (totalAllocation * elapsedSeconds) / linearDurationSeconds;\n\
        }}\n\
        require(claimAmount > 0 && claimAmount <= maxVested);\n\n\
        bytes32 expectedSpk = new ScriptPublicKeyP2PK(beneficiary);\n\
        require(tx.outputs[0].scriptPublicKey == expectedSpk);\n\
    }}\n\
}}",
        resolved_standard,
        clean_ticker,
        clean_label,
        beneficiary_pubkey_hex,
        cliff_timestamp,
        clamped_cliff,
        clamped_linear,
        clamped_linear,
        total_whole_tokens,
        clean_ticker
    );
    let sil_ast_digest = compute_blake2b_256(silverscript_source.as_bytes(), None);
    let mut redeem_script = Vec::with_capacity(98);
    redeem_script.push(0x20);
    redeem_script.extend_from_slice(&beneficiary_pubkey_bytes);
    redeem_script.push(0xac);
    redeem_script.push(0x08);
    redeem_script.extend_from_slice(&(cliff_timestamp as u64).to_le_bytes());
    redeem_script.push(0xb1);
    redeem_script.push(0x75);
    redeem_script.push(0x08);
    redeem_script.extend_from_slice(&(clamped_linear as u64).to_le_bytes());
    redeem_script.push(0x75);
    redeem_script.push(0x08);
    redeem_script.extend_from_slice(&total_whole_tokens.to_le_bytes());
    redeem_script.push(0x75);
    redeem_script.push(0x20);
    redeem_script.extend_from_slice(&sil_ast_digest);
    redeem_script.push(0x75);
    redeem_script.push(0x51);
    let script_hash_bytes = compute_blake2b_256(&redeem_script, None);
    let script_hash_hex = hex::encode(script_hash_bytes);
    let covenant_address = encode_kaspa_p2sh_address(&script_hash_bytes);
    let covenant_spk_hex = format!("a9{}87", script_hash_hex);
    let ext_seed = format!(
        "{}:{}",
        clean_ticker,
        charter_sha256_hex.unwrap_or("PERENNIA_KCC20_CHARTER_V1")
    );
    let extension_commitment = compute_blake2b_256(ext_seed.as_bytes(), None);
    let amount_base_units = total_whole_tokens.saturating_mul(10u64.saturating_pow(clamped_dec.min(10)));
    let kcc20_state = KCC20State {
        amount: amount_base_units,
        owner: beneficiary_pubkey_bytes,
        owner_scheme,
        borrow_scheme: if clamped_cliff > 0 || clamped_linear > 0 { 0x01 } else { 0x00 },
        borrow_guard: script_hash_bytes,
        extension_commitment,
    };
    let state_root = kcc20_state.compute_state_root();
    let covenant_id = kcc20_state.compute_covenant_id(&clean_ticker);
    CompiledSilverScriptVault {
        contractName: "ProofOfLockVault".to_string(),
        ticker: clean_ticker,
        tokenStandard: resolved_standard,
        label: clean_label,
        beneficiaryAddress: normalized_beneficiary,
        beneficiaryPubkeyHex: beneficiary_pubkey_hex,
        cliffDays: clamped_cliff,
        cliffTimestamp: cliff_timestamp,
        linearDays: clamped_linear,
        totalAllocation: total_whole_tokens,
        silverscriptSource: silverscript_source,
        redeemScriptHex: hex::encode(&redeem_script),
        scriptHashHex: script_hash_hex,
        covenantAddress: covenant_address,
        covenantSpkHex: covenant_spk_hex,
        kcc20PackedHex: hex::encode(kcc20_state.to_packed_bytes()),
        kcc20StateRootHex: hex::encode(state_root),
        kcc20CovenantIdHex: hex::encode(covenant_id),
    }
}

const LUA_ATOMIC_DEBIT_SINGLE: &str = r#"
local asset = ARGV[1]
local req = tonumber(ARGV[2])
local primary = tonumber(redis.call('HGET', KEYS[1], asset) or '0')
if primary >= req then
    redis.call('HINCRBYFLOAT', KEYS[1], asset, -req)
    return {1, tostring(0)}
end
if asset == 'KAS' then
    local unassigned = tonumber(redis.call('HGET', KEYS[1], 'Unassigned KAS') or '0')
    if (primary + unassigned) >= req then
        local from_unassigned = req - primary
        if primary > 0 then
            redis.call('HSET', KEYS[1], 'KAS', '0')
        end
        redis.call('HINCRBYFLOAT', KEYS[1], 'Unassigned KAS', -from_unassigned)
        return {1, tostring(from_unassigned)}
    end
end
return {0, tostring(0)}
"#;

const LUA_ATOMIC_DEBIT_MULTI_LP: &str = r#"
local count = tonumber(ARGV[1] or '0')
if count <= 0 then
    return {0, tostring(0), 'EMPTY_BASKET'}
end
for i = 1, count do
    local asset = ARGV[1 + (i - 1) * 2 + 1]
    local req = tonumber(ARGV[1 + (i - 1) * 2 + 2] or '0')
    local primary = tonumber(redis.call('HGET', KEYS[1], asset) or '0')
    local unassigned = 0
    if asset == 'KAS' then
        unassigned = tonumber(redis.call('HGET', KEYS[1], 'Unassigned KAS') or '0')
    end
    if (primary + unassigned + 1e-9) < req then
        return {0, tostring(0), asset}
    end
end
local from_unassigned = 0
for i = 1, count do
    local asset = ARGV[1 + (i - 1) * 2 + 1]
    local req = tonumber(ARGV[1 + (i - 1) * 2 + 2] or '0')
    local primary = tonumber(redis.call('HGET', KEYS[1], asset) or '0')
    if asset == 'KAS' then
        if primary >= req then
            redis.call('HINCRBYFLOAT', KEYS[1], 'KAS', -req)
        else
            local diff = math.max(0, req - primary)
            from_unassigned = from_unassigned + diff
            if primary > 0 then
                redis.call('HSET', KEYS[1], 'KAS', '0')
            end
            redis.call('HINCRBYFLOAT', KEYS[1], 'Unassigned KAS', -diff)
        end
    else
        if math.abs(primary - req) <= 1e-9 then
            redis.call('HSET', KEYS[1], asset, '0')
        else
            redis.call('HINCRBYFLOAT', KEYS[1], asset, -req)
        end
    end
end
return {1, tostring(from_unassigned), 'OK'}
"#;

#[derive(Deserialize, Debug)]
pub struct StateActionReq {
    pub wallet: String,
    pub action: String,
    pub payload: Value,
}

#[derive(Serialize)]
pub struct ActionResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_psbt_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

fn is_master_admin_wallet(clean_wallet: &str) -> bool {
    let configured = env::var("MASTER_ADMIN_ADDRESS")
        .ok()
        .map(|s| s.trim().to_lowercase().replace("kaspa:", ""))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| MASTER_ADMIN_ADDRESS_CLEAN.to_string());
    clean_wallet == configured || clean_wallet == MASTER_ADMIN_ADDRESS_CLEAN
}

async fn is_forge_public_or_authorized(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    clean_wallet: &str,
) -> bool {
    if is_master_admin_wallet(clean_wallet) {
        return true;
    }
    if let Ok(env_flag) = env::var("FEATURE_FORGE_PUBLIC") {
        let f = env_flag.trim().to_lowercase();
        if f == "true" || f == "1" || f == "public" {
            return true;
        }
    }
    let redis_flag: Option<String> = redis::cmd("GET")
        .arg("feature:forge:public")
        .query_async(redis_conn)
        .await
        .unwrap_or(None);
    if let Some(flag_str) = redis_flag {
        let f = flag_str.trim().to_lowercase();
        if f == "1" || f == "true" || f == "enabled" || f == "public" {
            return true;
        }
    }
    false
}

async fn ensure_silo_and_forge_schema(pool: &PgPool) {
    let ddl = [
        r#"
        CREATE TABLE IF NOT EXISTS silo_staking_positions (
            stake_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            wallet_address VARCHAR(255) NOT NULL,
            token_ticker VARCHAR(32) NOT NULL DEFAULT 'SILO',
            amount_staked DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
            tx_hash VARCHAR(255),
            cooldown_initiated_at TIMESTAMP WITH TIME ZONE,
            cooldown_ends_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "CREATE INDEX IF NOT EXISTS idx_silo_staking_wallet ON silo_staking_positions (wallet_address, status)",
        "ALTER TABLE liquidity_providers ADD COLUMN IF NOT EXISTS weights_json JSONB NOT NULL DEFAULT '{}'::jsonb",
        "ALTER TABLE liquidity_providers ADD COLUMN IF NOT EXISTS reserves_json JSONB NOT NULL DEFAULT '{}'::jsonb",
        r#"
        CREATE TABLE IF NOT EXISTS forge_vesting_schedules (
            vesting_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            token_ticker VARCHAR(32) NOT NULL,
            beneficiary_address VARCHAR(255) NOT NULL,
            creator_address VARCHAR(255) NOT NULL,
            label VARCHAR(128) NOT NULL DEFAULT 'Genesis Tranche',
            total_allocated DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            unlocked_amount DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            claimed_amount DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            cliff_days INTEGER NOT NULL DEFAULT 0,
            linear_days INTEGER NOT NULL DEFAULT 365,
            cliff_unlock_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            full_unlock_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            daily_unlock_rate DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            covenant_rule VARCHAR(64) NOT NULL DEFAULT 'TIMELOCK_ESCROW_COVENANT',
            vprog_state_root VARCHAR(128) NOT NULL DEFAULT '',
            covenant_address VARCHAR(255) NOT NULL DEFAULT '',
            silverscript_source TEXT NOT NULL DEFAULT '',
            redeem_script_hex TEXT NOT NULL DEFAULT '',
            kcc20_state_commitment VARCHAR(128) NOT NULL DEFAULT '',
            token_standard VARCHAR(32) NOT NULL DEFAULT 'KRC-20',
            lock_tx_hash VARCHAR(255),
            status VARCHAR(32) NOT NULL DEFAULT 'LOCKED',
            last_bell_unlocked_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "ALTER TABLE forge_vesting_schedules ADD COLUMN IF NOT EXISTS covenant_address VARCHAR(255) NOT NULL DEFAULT ''",
        "ALTER TABLE forge_vesting_schedules ADD COLUMN IF NOT EXISTS silverscript_source TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE forge_vesting_schedules ADD COLUMN IF NOT EXISTS redeem_script_hex TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE forge_vesting_schedules ADD COLUMN IF NOT EXISTS kcc20_state_commitment VARCHAR(128) NOT NULL DEFAULT ''",
        "ALTER TABLE forge_vesting_schedules ADD COLUMN IF NOT EXISTS token_standard VARCHAR(32) NOT NULL DEFAULT 'KRC-20'",
        "CREATE INDEX IF NOT EXISTS idx_forge_vesting_ticker ON forge_vesting_schedules (token_ticker, status)",
        r#"
        CREATE TABLE IF NOT EXISTS forge_monetary_policies (
            policy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            token_ticker VARCHAR(32) UNIQUE NOT NULL,
            creator_address VARCHAR(255) NOT NULL,
            max_supply DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            burn_rate_bps INTEGER NOT NULL DEFAULT 0,
            burn_address VARCHAR(255) NOT NULL DEFAULT 'kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e',
            total_burned_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            emission_schedule_type VARCHAR(48) NOT NULL DEFAULT 'CHROMATIC_HALVING',
            daily_emission_rate DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            halving_interval_days INTEGER NOT NULL DEFAULT 365,
            reserve_locked_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            reserve_emitted_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            zero_rug_lp_pct DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            zero_rug_lock_days INTEGER NOT NULL DEFAULT 365,
            is_retroactive_upgrade BOOLEAN NOT NULL DEFAULT FALSE,
            charter_sha256 VARCHAR(128) NOT NULL DEFAULT '',
            token_standard VARCHAR(32) NOT NULL DEFAULT 'KRC-20',
            kcc20_covenant_id VARCHAR(128) NOT NULL DEFAULT '',
            kcc20_state_root VARCHAR(128) NOT NULL DEFAULT '',
            silverscript_charter_source TEXT NOT NULL DEFAULT '',
            covenant_vault_address VARCHAR(255) NOT NULL DEFAULT '',
            anchor_tx_hash VARCHAR(255),
            last_bell_processed_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "ALTER TABLE forge_monetary_policies ADD COLUMN IF NOT EXISTS token_standard VARCHAR(32) NOT NULL DEFAULT 'KRC-20'",
        "ALTER TABLE forge_monetary_policies ADD COLUMN IF NOT EXISTS kcc20_covenant_id VARCHAR(128) NOT NULL DEFAULT ''",
        "ALTER TABLE forge_monetary_policies ADD COLUMN IF NOT EXISTS kcc20_state_root VARCHAR(128) NOT NULL DEFAULT ''",
        "ALTER TABLE forge_monetary_policies ADD COLUMN IF NOT EXISTS silverscript_charter_source TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE forge_monetary_policies ADD COLUMN IF NOT EXISTS covenant_vault_address VARCHAR(255) NOT NULL DEFAULT ''",
        r#"
        CREATE TABLE IF NOT EXISTS forge_mineable_vaults (
            vault_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            token_ticker VARCHAR(32) UNIQUE NOT NULL,
            creator_address VARCHAR(255) NOT NULL,
            vault_label VARCHAR(128) NOT NULL DEFAULT 'Proof-of-Hashrate Mining Vault',
            total_funded_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            remaining_vault_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            daily_emission_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            distributed_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            min_hashrate_ths DOUBLE PRECISION NOT NULL DEFAULT 0.1,
            syndicate_sector_enabled BOOLEAN NOT NULL DEFAULT TRUE,
            active_miners_count INTEGER NOT NULL DEFAULT 0,
            status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
            funding_tx_hash VARCHAR(255),
            last_bell_distributed_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS client_cold_vault_registry (
            wallet_address VARCHAR(255) PRIMARY KEY,
            cold_kaspa_address VARCHAR(255) NOT NULL,
            card_public_key_hex VARCHAR(128) NOT NULL DEFAULT '',
            card_label VARCHAR(128) NOT NULL DEFAULT 'Air-Gapped Hardware Vault',
            signer_mode VARCHAR(40) NOT NULL DEFAULT 'WEB_QR_AIRLOCK',
            overflow_threshold_kas DOUBLE PRECISION NOT NULL DEFAULT 500.0,
            auto_sweep_enabled BOOLEAN NOT NULL DEFAULT TRUE,
            last_sweep_txid VARCHAR(128),
            last_sweep_at TIMESTAMP WITH TIME ZONE,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS hifo_tax_lots (
            lot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            wallet_address VARCHAR(255) NOT NULL,
            asset_ticker VARCHAR(32) NOT NULL DEFAULT 'KAS',
            acquired_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            kas_sompi BIGINT NOT NULL DEFAULT 0,
            initial_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            remaining_sompi BIGINT NOT NULL DEFAULT 0,
            remaining_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            fmv_usd_per_token DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            total_cost_basis_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            source_event_type VARCHAR(64) NOT NULL DEFAULT 'YIELD',
            source_tx_hash VARCHAR(255),
            status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS hifo_disposal_matches (
            match_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            disposal_event_id UUID,
            lot_id UUID NOT NULL,
            wallet_address VARCHAR(255) NOT NULL,
            asset_ticker VARCHAR(32) NOT NULL DEFAULT 'KAS',
            disposed_sompi BIGINT NOT NULL DEFAULT 0,
            disposed_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            acquired_at TIMESTAMP WITH TIME ZONE NOT NULL,
            disposed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            holding_period_days INTEGER NOT NULL DEFAULT 0,
            is_long_term BOOLEAN NOT NULL DEFAULT FALSE,
            cost_basis_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            gross_proceeds_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            realized_gain_loss_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            disposal_tx_hash VARCHAR(255)
        )
        "#,
    ];
    for stmt in ddl {
        let _ = sqlx::query(stmt).execute(pool).await;
    }
}

fn contains_forbidden_private_key_material(payload: &Value) -> bool {
    match payload {
        Value::Object(map) => {
            for (k, v) in map {
                let key_lower = k.to_lowercase();
                if key_lower == "privatekeyhex"
                    || key_lower == "buyerprivatekeyhex"
                    || key_lower == "private_key"
                    || key_lower == "mnemonic"
                    || key_lower == "seedphrase"
                {
                    if let Some(s) = v.as_str() {
                        if !s.trim().is_empty() {
                            return true;
                        }
                    }
                }
                if contains_forbidden_private_key_material(v) {
                    return true;
                }
            }
            false
        }
        Value::Array(arr) => arr.iter().any(contains_forbidden_private_key_material),
        _ => false,
    }
}

fn compute_sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn sector_targets_asset(sec: &Value, target_asset_upper: &str) -> bool {
    if target_asset_upper.is_empty() {
        return false;
    }
    let primary = sec
        .pointer("/settlementConfig/targetAsset/ticker")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_uppercase();
    if primary == target_asset_upper {
        return true;
    }
    if let Some(arr) = sec
        .pointer("/settlementConfig/targetAssets")
        .and_then(|v| v.as_array())
    {
        for item in arr {
            let t = item
                .get("ticker")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_uppercase();
            if t == target_asset_upper {
                return true;
            }
        }
    }
    if let Some(w_obj) = sec
        .pointer("/settlementConfig/plantWeights")
        .and_then(|v| v.as_object())
    {
        if w_obj.keys().any(|k| k.trim().eq_ignore_ascii_case(target_asset_upper)) {
            return true;
        }
    }
    false
}

pub fn normalize_sector_plant_or_silo_rules(sector_val: &mut Value) {
    let mut target_tickers: Vec<String> = Vec::new();
    let mut raw_weights_pct: HashMap<String, f64> = HashMap::new();
    let mut is_syndicate_mineable = false;
    if let Some(cfg) = sector_val.get("settlementConfig") {
        if cfg.get("isMineableKrc20").and_then(|v| v.as_bool()) == Some(true)
            || cfg.get("syndicateVault").and_then(|v| v.as_bool()) == Some(true)
        {
            is_syndicate_mineable = true;
        }
        if let Some(arr) = cfg.get("targetAssets").and_then(|v| v.as_array()) {
            for item in arr {
                let tick_opt = item
                    .get("ticker")
                    .and_then(|t| t.as_str())
                    .or_else(|| item.as_str());
                if let Some(t) = tick_opt {
                    let clean = t.trim().to_uppercase();
                    if !clean.is_empty() && !target_tickers.contains(&clean) {
                        target_tickers.push(clean.clone());
                    }
                    if let Some(w) = item
                        .get("weightPct")
                        .or_else(|| item.get("weight"))
                        .and_then(|v| v.as_f64())
                    {
                        if w > 0.0 {
                            raw_weights_pct.insert(clean, w);
                        }
                    }
                }
            }
        }
        if let Some(weights_obj) = cfg.get("plantWeights").and_then(|v| v.as_object()) {
            for (k, v) in weights_obj {
                let clean = k.trim().to_uppercase();
                if let Some(w) = v.as_f64() {
                    if w > 0.0 {
                        raw_weights_pct.insert(clean.clone(), w);
                        if !target_tickers.contains(&clean) {
                            target_tickers.push(clean);
                        }
                    }
                }
            }
        }
        if target_tickers.is_empty() {
            if let Some(primary_tick) = cfg
                .get("targetAsset")
                .and_then(|a| a.get("ticker"))
                .and_then(|t| t.as_str())
            {
                let clean = primary_tick.trim().to_uppercase();
                if !clean.is_empty() {
                    target_tickers.push(clean);
                }
            }
        }
    }
    let explicit_route_mode = sector_val
        .get("routeMode")
        .and_then(|v| v.as_str())
        .unwrap_or("hold")
        .to_lowercase();
    let non_kas_targets: Vec<String> = target_tickers
        .iter()
        .filter(|t| *t != "KAS")
        .cloned()
        .collect();
    let is_multi_asset_plant = (target_tickers.len() >= 2
        || non_kas_targets.len() >= 2
        || explicit_route_mode == "auto-lp")
        && !is_syndicate_mineable;
    if is_multi_asset_plant {
        sector_val["routeMode"] = json!("auto-lp");
        let mut secondary_tickers = non_kas_targets;
        if secondary_tickers.is_empty() {
            secondary_tickers.push("USDC".to_string());
        }
        let mut normalized_weights_pct = serde_json::Map::new();
        normalized_weights_pct.insert("KAS".to_string(), json!(50.0_f64));
        let custom_sum: f64 = secondary_tickers
            .iter()
            .map(|t| raw_weights_pct.get(t).copied().unwrap_or(0.0_f64).max(0.0_f64))
            .sum();
        let n_sec = secondary_tickers.len();
        let mut allocated_sec_pct: f64 = 0.0;
        for (idx, sec_ticker) in secondary_tickers.iter().enumerate() {
            let pct: f64 = if idx + 1 == n_sec {
                ((50.0_f64 - allocated_sec_pct) * 100.0_f64).round() / 100.0_f64
            } else if custom_sum > 0.0_f64 {
                let raw: f64 = raw_weights_pct
                    .get(sec_ticker)
                    .copied()
                    .unwrap_or(0.0_f64)
                    .max(0.0_f64);
                (((raw / custom_sum) * 50.0_f64) * 100.0_f64).round() / 100.0_f64
            } else {
                ((50.0_f64 / (n_sec as f64)) * 100.0_f64).round() / 100.0_f64
            };
            let clamped: f64 = pct.clamp(0.01_f64, 50.0_f64);
            allocated_sec_pct += clamped;
            normalized_weights_pct.insert(sec_ticker.clone(), json!(clamped));
        }
        if let Some(cfg_obj) = sector_val
            .get_mut("settlementConfig")
            .and_then(|v| v.as_object_mut())
        {
            cfg_obj.insert("plantWeights".to_string(), Value::Object(normalized_weights_pct.clone()));
            cfg_obj.insert("mode".to_string(), json!("epoch"));
            let mut full_list = vec!["KAS".to_string()];
            full_list.extend(secondary_tickers.clone());
            cfg_obj.insert("plantPair".to_string(), json!(full_list.join("/")));
        }
    } else {
        let single_ticker = target_tickers
            .first()
            .cloned()
            .unwrap_or_else(|| "KAS".to_string());
        if single_ticker == "KAS" {
            sector_val["routeMode"] = json!("hold");
        } else {
            sector_val["routeMode"] = json!("swap");
        }
    }
}

pub fn build_explorer_tx_url(asset: &str, tx_or_addr: &str) -> String {
    let clean_asset = asset.trim().to_uppercase();
    let clean_ref = tx_or_addr.trim();
    if clean_ref.is_empty() {
        return "#".to_string();
    }
    let is_queued_ref = clean_ref.starts_with("PER-L1-");
    match clean_asset.as_str() {
        "KAS" => {
            if is_queued_ref {
                "https://kas.fyi".to_string()
            } else {
                format!("https://kas.fyi/transaction/{}", clean_ref)
            }
        }
        "BTC" => {
            if is_queued_ref {
                "https://mempool.space".to_string()
            } else {
                format!("https://mempool.space/tx/{}", clean_ref)
            }
        }
        "ETH" | "USDC" | "USDT" | "XAU" | "XAG" | "USTB" => {
            if is_queued_ref {
                "https://etherscan.io".to_string()
            } else {
                format!("https://etherscan.io/tx/{}", clean_ref)
            }
        }
        "SPY" | "QQQ" | "NVDA" | "AAPL" | "TSLA" | "AMD" | "TSM" | "AVGO" | "XLE" | "BASE" => {
            if is_queued_ref {
                "https://basescan.org".to_string()
            } else {
                format!("https://basescan.org/tx/{}", clean_ref)
            }
        }
        "SOL" => {
            if is_queued_ref {
                "https://solscan.io".to_string()
            } else {
                format!("https://solscan.io/tx/{}", clean_ref)
            }
        }
        "POL" => format!("https://polygonscan.com/tx/{}", clean_ref),
        "AVAX" => format!("https://snowtrace.com/tx/{}", clean_ref),
        "ARB" => format!("https://arbiscan.io/tx/{}", clean_ref),
        "XRP" => format!("https://xrpscan.com/tx/{}", clean_ref),
        "DOGE" => format!("https://blockchair.com/dogecoin/transaction/{}", clean_ref),
        "SUI" => format!("https://suiscan.xyz/mainnet/tx/{}", clean_ref),
        "TRX" => format!("https://tronscan.org/#/transaction/{}", clean_ref),
        "ZEC" => format!("https://blockchair.com/zcash/transaction/{}", clean_ref),
        _ => format!("https://kas.fyi/transaction/{}", clean_ref),
    }
}

pub async fn dispatch_or_queue_multi_chain_l1(
    tx_db: &mut SqlTransaction<'_, Postgres>,
    redis_conn: &mut redis::aio::MultiplexedConnection,
    prefixed_wallet: &str,
    clean_wallet: &str,
    destination: &str,
    asset: &str,
    amount: f64,
    spot_price: f64,
    source_type: &str,
) -> (String, String, String) {
    let clean_asset = asset.trim().to_uppercase();
    let resolved_spot: f64 = if spot_price > 0.0 {
        spot_price
    } else if clean_asset == "USDC" || clean_asset == "USDT" || clean_asset == "USD" {
        1.0
    } else {
        get_spot_usd(redis_conn, &clean_asset).await
    };
    let gross_usd: f64 = ((amount * resolved_spot) * 100.0_f64).round() / 100.0_f64;
    let network = match clean_asset.as_str() {
        "USDC" | "USDT" | "XAU" | "XAG" | "USTB" => "ETH".to_string(),
        "SPY" | "QQQ" | "NVDA" | "AAPL" | "TSLA" | "AMD" | "TSM" | "AVGO" | "XLE" => "BASE".to_string(),
        _ => clean_asset.clone(),
    };
    if clean_asset == "KAS" {
        if let Ok(tx_id) = crate::sor::execute_physical_settlement(destination, amount).await {
            let explorer_url = build_explorer_tx_url("KAS", &tx_id);
            let _ = sqlx::query(
                "INSERT INTO pending_transactions (tx_id, wallet_address, amount_kas, action_type, status) VALUES ($1, $2, $3, 'SYNTHETIC_KAS_WITHDRAWAL', 'PENDING') ON CONFLICT DO NOTHING"
            )
            .bind(&tx_id)
            .bind(prefixed_wallet)
            .bind(amount)
            .execute(&mut **tx_db)
            .await;
            let event_type = if source_type == "chronos_epoch_bell" {
                "YIELD"
            } else {
                "L1_WITHDRAWAL"
            };
            let _ = sqlx::query(
                "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash, payout_address, cost_basis_usd, realized_gain_loss_usd, holding_period) VALUES ($1, 'KAS', $2, $3, $4, $5, $6, $7, $3, 0.0, 'SHORT_TERM')"
            )
            .bind(clean_wallet)
            .bind(event_type)
            .bind(gross_usd)
            .bind(amount)
            .bind(resolved_spot)
            .bind(&tx_id)
            .bind(destination)
            .execute(&mut **tx_db)
            .await;
            return (tx_id, "DISPATCHED_ONCHAIN".to_string(), explorer_url);
        }
    }
    let internal_token = env::var("INTERNAL_ADMIN_TOKEN")
        .or_else(|_| env::var("PERENNIA_ADMIN_KEY"))
        .unwrap_or_default();
    let candidate_urls = [
        env::var("FRONTEND_INTERNAL_URL").unwrap_or_default(),
        "http://127.0.0.1:5173".to_string(),
        "http://127.0.0.1:4173".to_string(),
        "http://127.0.0.1:3000".to_string(),
    ];
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(6))
        .build()
        .unwrap_or_else(|_| Client::new());
    for base_url in candidate_urls {
        let trimmed = base_url.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            continue;
        }
        let endpoint = format!("{}/api/sor/l1_dispatch", trimmed);
        if let Ok(res) = client
            .post(&endpoint)
            .header("Authorization", format!("Bearer {}", internal_token))
            .json(&json!({
                "wallet": prefixed_wallet,
                "destinationAddress": destination,
                "asset": clean_asset,
                "amount": amount,
                "sourceType": source_type,
                "spotPrice": resolved_spot
            }))
            .send()
            .await
        {
            if res.status().is_success() {
                if let Ok(data) = res.json::<Value>().await {
                    if data.get("success").and_then(|v| v.as_bool()) == Some(true) {
                        let tx_hash = data
                            .get("txHash")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let status = data
                            .get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("DISPATCHED_ONCHAIN")
                            .to_string();
                        let explorer_url = data
                            .get("explorerUrl")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| build_explorer_tx_url(&clean_asset, &tx_hash));
                        if !tx_hash.is_empty() {
                            return (tx_hash, status, explorer_url);
                        }
                    }
                }
            }
        }
    }
    let uuid_hex = Uuid::new_v4().simple().to_string().to_uppercase();
    let payout_id = format!("PER-L1-{}", &uuid_hex[..10]);
    let explorer_url = build_explorer_tx_url(&clean_asset, destination);
    let queue_reason = format!(
        "Hot wallet key or UTXO mass pending for {}; queued in l1_payout_queue for 1-click L1 confirmation.",
        clean_asset
    );
    let _ = sqlx::query(
        r#"
        INSERT INTO l1_payout_queue
        (payout_id, wallet_address, destination_address, asset_ticker, network, amount_tokens, gross_usd, spot_price, source_type, tx_hash, explorer_url, queue_reason, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $1, $10, $11, 'QUEUED_FOR_L1_DISPATCH')
        ON CONFLICT (payout_id) DO NOTHING
        "#,
    )
    .bind(&payout_id)
    .bind(prefixed_wallet)
    .bind(destination)
    .bind(&clean_asset)
    .bind(&network)
    .bind(amount)
    .bind(gross_usd)
    .bind(resolved_spot)
    .bind(source_type)
    .bind(&explorer_url)
    .bind(&queue_reason)
    .execute(&mut **tx_db)
    .await;
    let event_type = if source_type == "chronos_epoch_bell" {
        "YIELD"
    } else {
        "L1_WITHDRAWAL"
    };
    let _ = sqlx::query(
        "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash, payout_address, cost_basis_usd, realized_gain_loss_usd, holding_period) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $4, 0.0, 'SHORT_TERM')"
    )
    .bind(clean_wallet)
    .bind(&clean_asset)
    .bind(event_type)
    .bind(gross_usd)
    .bind(amount)
    .bind(resolved_spot)
    .bind(&payout_id)
    .bind(destination)
    .execute(&mut **tx_db)
    .await;
    let queue_record = json!({
        "payoutId": payout_id,
        "walletAddress": prefixed_wallet,
        "destinationAddress": destination,
        "assetTicker": clean_asset,
        "network": network,
        "amountTokens": amount,
        "grossUsd": gross_usd,
        "spotPrice": resolved_spot,
        "sourceType": source_type,
        "txHash": payout_id,
        "explorerUrl": explorer_url,
        "queueReason": queue_reason,
        "status": "QUEUED_FOR_L1_DISPATCH",
        "createdAt": chrono::Utc::now().to_rfc3339()
    });
    let _: () = redis::cmd("LPUSH")
        .arg("perennia:l1:payout_queue")
        .arg(queue_record.to_string())
        .query_async(redis_conn)
        .await
        .unwrap_or(());
    let _: () = redis::cmd("LTRIM")
        .arg("perennia:l1:payout_queue")
        .arg(0)
        .arg(199)
        .query_async(redis_conn)
        .await
        .unwrap_or(());
    let sse_evt = json!({
        "l1_event": true,
        "fiat_event": true,
        "eventType": "L1_QUEUED",
        "wallet": clean_wallet,
        "payout": queue_record
    });
    let _: () = redis::cmd("PUBLISH")
        .arg("telemetry:updates")
        .arg(sse_evt.to_string())
        .query_async(redis_conn)
        .await
        .unwrap_or(());
    (payout_id, "QUEUED_FOR_L1_DISPATCH".to_string(), explorer_url)
}

async fn get_spot_usd(redis_conn: &mut redis::aio::MultiplexedConnection, ticker: &str) -> f64 {
    let clean = ticker.trim().to_uppercase();
    if clean == "USDC" || clean == "USDT" || clean == "USD" {
        return 1.0;
    }
    let key = format!("oracle:spot:{}_USDC", clean);
    let val_str: Option<String> = redis::cmd("GET")
        .arg(&key)
        .query_async(redis_conn)
        .await
        .unwrap_or(None);
    val_str.and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0)
}

pub async fn query_forge_tokenomics_bundle(
    pool: &PgPool,
    ticker_opt: Option<&str>,
    include_all_mineable_vaults: bool,
) -> Value {
    let mut vesting_schedules: Vec<Value> = Vec::new();
    let mut monetary_policy: Option<Value> = None;
    let mut mineable_vault: Option<Value> = None;
    let mut all_mineable_vaults: Vec<Value> = Vec::new();
    let mut locked_vesting_supply: f64 = 0.0;
    let mut unlocked_vested_supply: f64 = 0.0;
    let mut daily_unlock_total: f64 = 0.0;
    let mut burned_supply: f64 = 0.0;
    let mut reserve_locked_supply: f64 = 0.0;
    if let Some(raw_ticker) = ticker_opt {
        let clean_ticker = raw_ticker.trim().to_uppercase();
        if !clean_ticker.is_empty() {
            if let Ok(rows) = sqlx::query(
                r#"
                SELECT vesting_id, token_ticker, beneficiary_address, creator_address, label,
                       total_allocated, unlocked_amount, claimed_amount, cliff_days, linear_days,
                       cliff_unlock_at, full_unlock_at, daily_unlock_rate, covenant_rule,
                       vprog_state_root, covenant_address, silverscript_source, redeem_script_hex,
                       kcc20_state_commitment, token_standard, lock_tx_hash, status,
                       last_bell_unlocked_at, created_at
                FROM forge_vesting_schedules
                WHERE token_ticker = $1
                ORDER BY created_at ASC
                "#,
            )
            .bind(&clean_ticker)
            .fetch_all(pool)
            .await
            {
                for r in rows {
                    let vid: Uuid = r.get("vesting_id");
                    let beneficiary: String = r.get("beneficiary_address");
                    let creator: String = r.get("creator_address");
                    let label: String = r.get("label");
                    let total_alloc: f64 = r.get("total_allocated");
                    let unlocked: f64 = r.get("unlocked_amount");
                    let claimed: f64 = r.get("claimed_amount");
                    let cliff_days: i32 = r.get("cliff_days");
                    let linear_days: i32 = r.get("linear_days");
                    let cliff_at: chrono::DateTime<chrono::Utc> = r.get("cliff_unlock_at");
                    let full_at: chrono::DateTime<chrono::Utc> = r.get("full_unlock_at");
                    let daily_rate: f64 = r.get("daily_unlock_rate");
                    let cov_rule: String = r.get("covenant_rule");
                    let state_root: String = r.get("vprog_state_root");
                    let stored_cov_addr: String = r.try_get("covenant_address").unwrap_or_default();
                    let stored_sil_src: String = r.try_get("silverscript_source").unwrap_or_default();
                    let stored_redeem_hex: String = r.try_get("redeem_script_hex").unwrap_or_default();
                    let stored_kcc20_comm: String = r.try_get("kcc20_state_commitment").unwrap_or_default();
                    let token_standard: String = r
                        .try_get::<String, _>("token_standard")
                        .unwrap_or_else(|_| "KRC-20".to_string());
                    let lock_tx: Option<String> = r.try_get("lock_tx_hash").ok();
                    let status: String = r.get("status");
                    let last_bell: Option<chrono::DateTime<chrono::Utc>> =
                        r.try_get("last_bell_unlocked_at").ok();
                    let (covenant_address, silverscript_source, redeem_script_hex, kcc20_state_commitment) =
                        if stored_cov_addr.is_empty() || stored_sil_src.is_empty() {
                            let compiled = compile_silverscript_proof_of_lock_vault(
                                &clean_ticker,
                                &token_standard,
                                &label,
                                &beneficiary,
                                total_alloc,
                                8,
                                cliff_days,
                                linear_days,
                                None,
                                None,
                            );
                            (
                                compiled.covenantAddress,
                                compiled.silverscriptSource,
                                compiled.redeemScriptHex,
                                compiled.kcc20StateRootHex,
                            )
                        } else {
                            (
                                stored_cov_addr,
                                stored_sil_src,
                                stored_redeem_hex,
                                if stored_kcc20_comm.is_empty() {
                                    state_root.clone()
                                } else {
                                    stored_kcc20_comm
                                },
                            )
                        };
                    let remaining_locked = (total_alloc - unlocked).max(0.0);
                    locked_vesting_supply += remaining_locked;
                    unlocked_vested_supply += unlocked;
                    if remaining_locked > 0.0 {
                        daily_unlock_total += daily_rate;
                    }
                    vesting_schedules.push(json!({
                        "vestingId": vid.to_string(),
                        "tokenTicker": clean_ticker,
                        "tokenStandard": token_standard,
                        "beneficiaryAddress": beneficiary,
                        "creatorAddress": creator,
                        "label": label,
                        "totalAllocated": total_alloc,
                        "unlockedAmount": unlocked,
                        "remainingLocked": remaining_locked,
                        "claimedAmount": claimed,
                        "cliffDays": cliff_days,
                        "linearDays": linear_days,
                        "cliffUnlockAt": cliff_at.to_rfc3339(),
                        "fullUnlockAt": full_at.to_rfc3339(),
                        "dailyUnlockRate": daily_rate,
                        "covenantRule": cov_rule,
                        "vprogStateRoot": state_root,
                        "covenantAddress": covenant_address,
                        "silverscriptSource": silverscript_source,
                        "redeemScriptHex": redeem_script_hex,
                        "kcc20StateCommitment": kcc20_state_commitment,
                        "lockTxHash": lock_tx,
                        "status": status,
                        "lastBellUnlockedAt": last_bell.map(|d| d.to_rfc3339())
                    }));
                }
            }
            if let Ok(Some(row)) = sqlx::query(
                r#"
                SELECT policy_id, token_ticker, creator_address, max_supply, burn_rate_bps,
                       burn_address, total_burned_tokens, emission_schedule_type,
                       daily_emission_rate, halving_interval_days, reserve_locked_tokens,
                       reserve_emitted_tokens, zero_rug_lp_pct, zero_rug_lock_days,
                       is_retroactive_upgrade, charter_sha256, token_standard,
                       kcc20_covenant_id, kcc20_state_root, silverscript_charter_source,
                       covenant_vault_address, anchor_tx_hash,
                       last_bell_processed_at, created_at
                FROM forge_monetary_policies
                WHERE token_ticker = $1
                LIMIT 1
                "#,
            )
            .bind(&clean_ticker)
            .fetch_optional(pool)
            .await
            {
                let pid: Uuid = row.get("policy_id");
                let burned: f64 = row.get("total_burned_tokens");
                let res_locked: f64 = row.get("reserve_locked_tokens");
                let res_emitted: f64 = row.get("reserve_emitted_tokens");
                burned_supply = burned;
                reserve_locked_supply = (res_locked - res_emitted).max(0.0);
                monetary_policy = Some(json!({
                    "policyId": pid.to_string(),
                    "tokenTicker": clean_ticker,
                    "tokenStandard": row.try_get::<String, _>("token_standard").unwrap_or_else(|_| "KRC-20".to_string()),
                    "creatorAddress": row.get::<String, _>("creator_address"),
                    "maxSupply": row.get::<f64, _>("max_supply"),
                    "burnRateBps": row.get::<i32, _>("burn_rate_bps"),
                    "burnAddress": row.get::<String, _>("burn_address"),
                    "totalBurnedTokens": burned,
                    "emissionScheduleType": row.get::<String, _>("emission_schedule_type"),
                    "dailyEmissionRate": row.get::<f64, _>("daily_emission_rate"),
                    "halvingIntervalDays": row.get::<i32, _>("halving_interval_days"),
                    "reserveLockedTokens": res_locked,
                    "reserveEmittedTokens": res_emitted,
                    "remainingReserveTokens": reserve_locked_supply,
                    "zeroRugLpPct": row.get::<f64, _>("zero_rug_lp_pct"),
                    "zeroRugLockDays": row.get::<i32, _>("zero_rug_lock_days"),
                    "isRetroactiveUpgrade": row.get::<bool, _>("is_retroactive_upgrade"),
                    "charterSha256": row.get::<String, _>("charter_sha256"),
                    "kcc20CovenantId": row.try_get::<String, _>("kcc20_covenant_id").unwrap_or_default(),
                    "kcc20StateRoot": row.try_get::<String, _>("kcc20_state_root").unwrap_or_default(),
                    "silverscriptCharterSource": row.try_get::<String, _>("silverscript_charter_source").unwrap_or_default(),
                    "covenantVaultAddress": row.try_get::<String, _>("covenant_vault_address").unwrap_or_default(),
                    "anchorTxHash": row.try_get::<String, _>("anchor_tx_hash").ok(),
                    "lastBellProcessedAt": row.try_get::<chrono::DateTime<chrono::Utc>, _>("last_bell_processed_at").ok().map(|d| d.to_rfc3339())
                }));
            }
            if let Ok(Some(row)) = sqlx::query(
                r#"
                SELECT vault_id, token_ticker, creator_address, vault_label,
                       total_funded_tokens, remaining_vault_tokens, daily_emission_tokens,
                       distributed_tokens, min_hashrate_ths, syndicate_sector_enabled,
                       active_miners_count, status, funding_tx_hash, last_bell_distributed_at
                FROM forge_mineable_vaults
                WHERE token_ticker = $1
                LIMIT 1
                "#,
            )
            .bind(&clean_ticker)
            .fetch_optional(pool)
            .await
            {
                let vid: Uuid = row.get("vault_id");
                mineable_vault = Some(json!({
                    "vaultId": vid.to_string(),
                    "tokenTicker": clean_ticker,
                    "creatorAddress": row.get::<String, _>("creator_address"),
                    "vaultLabel": row.get::<String, _>("vault_label"),
                    "totalFundedTokens": row.get::<f64, _>("total_funded_tokens"),
                    "remainingVaultTokens": row.get::<f64, _>("remaining_vault_tokens"),
                    "dailyEmissionTokens": row.get::<f64, _>("daily_emission_tokens"),
                    "distributedTokens": row.get::<f64, _>("distributed_tokens"),
                    "minHashrateThs": row.get::<f64, _>("min_hashrate_ths"),
                    "syndicateSectorEnabled": row.get::<bool, _>("syndicate_sector_enabled"),
                    "activeMinersCount": row.get::<i32, _>("active_miners_count"),
                    "status": row.get::<String, _>("status"),
                    "fundingTxHash": row.try_get::<String, _>("funding_tx_hash").ok(),
                    "lastBellDistributedAt": row.try_get::<chrono::DateTime<chrono::Utc>, _>("last_bell_distributed_at").ok().map(|d| d.to_rfc3339())
                }));
            }
        }
    }
    if include_all_mineable_vaults {
        if let Ok(rows) = sqlx::query(
            r#"
            SELECT vault_id, token_ticker, creator_address, vault_label,
                   total_funded_tokens, remaining_vault_tokens, daily_emission_tokens,
                   distributed_tokens, min_hashrate_ths, syndicate_sector_enabled,
                   active_miners_count, status, funding_tx_hash
            FROM forge_mineable_vaults
            WHERE status = 'ACTIVE' AND remaining_vault_tokens > 0
            ORDER BY remaining_vault_tokens DESC
            LIMIT 100
            "#,
        )
        .fetch_all(pool)
        .await
        {
            for r in rows {
                let vid: Uuid = r.get("vault_id");
                all_mineable_vaults.push(json!({
                    "vaultId": vid.to_string(),
                    "tokenTicker": r.get::<String, _>("token_ticker"),
                    "creatorAddress": r.get::<String, _>("creator_address"),
                    "vaultLabel": r.get::<String, _>("vault_label"),
                    "totalFundedTokens": r.get::<f64, _>("total_funded_tokens"),
                    "remainingVaultTokens": r.get::<f64, _>("remaining_vault_tokens"),
                    "dailyEmissionTokens": r.get::<f64, _>("daily_emission_tokens"),
                    "distributedTokens": r.get::<f64, _>("distributed_tokens"),
                    "minHashrateThs": r.get::<f64, _>("min_hashrate_ths"),
                    "syndicateSectorEnabled": r.get::<bool, _>("syndicate_sector_enabled"),
                    "active_miners_count": r.get::<i32, _>("active_miners_count"),
                    "activeMinersCount": r.get::<i32, _>("active_miners_count"),
                    "status": r.get::<String, _>("status"),
                    "fundingTxHash": r.try_get::<String, _>("funding_tx_hash").ok()
                }));
            }
        }
    }
    let mining_vault_remaining = mineable_vault
        .as_ref()
        .and_then(|v| v.get("remainingVaultTokens").and_then(|x| x.as_f64()))
        .unwrap_or(0.0);
    json!({
        "vestingSchedules": vesting_schedules,
        "monetaryPolicy": monetary_policy,
        "mineableVault": mineable_vault,
        "allMineableVaults": all_mineable_vaults,
        "proofOfLockSummary": {
            "lockedVestingSupply": locked_vesting_supply,
            "unlockedVestedSupply": unlocked_vested_supply,
            "reserveLockedSupply": reserve_locked_supply,
            "miningVaultLockedSupply": mining_vault_remaining,
            "totalLockedSupply": locked_vesting_supply + reserve_locked_supply + mining_vault_remaining,
            "burnedSupply": burned_supply,
            "daily2200UtcUnlockRate": daily_unlock_total,
            "burnAddress": KASPA_BURN_ADDRESS
        }
    })
}

pub async fn handle_state_action(
    State(pool): State<PgPool>,
    Json(req): Json<StateActionReq>,
) -> Result<Json<ActionResponse>, Json<ActionResponse>> {
    if contains_forbidden_private_key_material(&req.payload)
        || req.action == "SIGN_AND_BROADCAST"
        || req.action == "SIGN_P2P_OFFER"
        || req.action == "BROADCAST_ATOMIC_SWAP"
    {
        return Err(Json(ActionResponse {
            success: false,
            error: Some(
                "ZERO_TRUST_VIOLATION: Client private keys must never leave browser memory. Use client-side signing in transaction.svelte.ts.".to_string()
            ),
            transaction_id: None,
            signed_psbt_hex: None,
            data: None,
        }));
    }
    ensure_silo_and_forge_schema(&pool).await;
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = match redis::Client::open(redis_url) {
        Ok(c) => c,
        Err(e) => return Err(Json(ActionResponse { success: false, error: Some(e.to_string()), transaction_id: None, signed_psbt_hex: None, data: None })),
    };
    let mut redis_conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => return Err(Json(ActionResponse { success: false, error: Some(e.to_string()), transaction_id: None, signed_psbt_hex: None, data: None })),
    };
    let clean_wallet = req.wallet.to_lowercase().replace("kaspa:", "").trim().to_string();
    let master_identity = format!("kaspa:{}", clean_wallet);

    if matches!(
        req.action.as_str(),
        "COMPILE_SILVERSCRIPT_COVENANT"
            | "REGISTER_FORGE_TOKENOMICS"
            | "RETROACTIVE_FORGE_UPGRADE"
            | "FUND_MINEABLE_KRC20_VAULT"
    ) {
        if !is_forge_public_or_authorized(&mut redis_conn, &clean_wallet).await {
            return Err(Json(ActionResponse {
                success: false,
                error: Some(
                    "FORGE_STEALTH_LOCK: Sovereign Forge is restricted to Master Treasury Stealth Mode in v1.0.".to_string()
                ),
                transaction_id: None,
                signed_psbt_hex: None,
                data: None,
            }));
        }
    }

    if req.action == "SET_FORGE_PUBLIC_FLAG" {
        if !is_master_admin_wallet(&clean_wallet) {
            return Err(Json(ActionResponse {
                success: false,
                error: Some("FORBIDDEN: Only the Master Treasury wallet may toggle feature:forge:public.".to_string()),
                transaction_id: None,
                signed_psbt_hex: None,
                data: None,
            }));
        }
        let enable_public = req
            .payload
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let _: () = redis::cmd("SET")
            .arg("feature:forge:public")
            .arg(if enable_public { "1" } else { "0" })
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(());
        return Ok(Json(ActionResponse {
            success: true,
            error: None,
            transaction_id: None,
            signed_psbt_hex: None,
            data: Some(json!({ "forgePublicEnabled": enable_public })),
        }));
    }

    let mut tx_db = match pool.begin().await {
        Ok(t) => t,
        Err(e) => return Err(Json(ActionResponse { success: false, error: Some(e.to_string()), transaction_id: None, signed_psbt_hex: None, data: None })),
    };
    let rows = sqlx::query(
        "SELECT layout_state FROM user_command_centers WHERE wallet_address = $1 OR wallet_address = $2"
    )
    .bind(&master_identity)
    .bind(&clean_wallet)
    .fetch_all(&mut *tx_db)
    .await;
    let mut state: Value = json!({"workers": [], "sectors": [], "manualLps": [], "customTokens": []});
    if let Ok(results) = rows {
        for r in results {
            if let Ok(st) = r.try_get::<Value, _>("layout_state") {
                state = st;
                if state.get("sectors").and_then(|s| s.as_array()).map(|a| a.len()).unwrap_or(0) > 0 {
                    break;
                }
            }
        }
    }
    match req.action.as_str() {
        "ADD_CUSTOM_TOKEN" => {
            let raw_ticker: String = req
                .payload
                .get("ticker")
                .or_else(|| req.payload.get("symbol"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_uppercase()
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .take(12)
                .collect();
            if raw_ticker.len() < 2 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("Invalid custom token ticker.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let name = req
                .payload
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(&raw_ticker)
                .trim()
                .to_string();
            let asset_class = req
                .payload
                .get("assetClass")
                .and_then(|v| v.as_str())
                .unwrap_or("DeFi")
                .trim()
                .to_string();
            let network = req
                .payload
                .get("network")
                .and_then(|v| v.as_str())
                .unwrap_or("ETH")
                .trim()
                .to_uppercase();
            let spot_price = req
                .payload
                .get("spotPrice")
                .or_else(|| req.payload.get("price"))
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0)
                .max(0.0);
            let change_24h = req
                .payload
                .get("change24h")
                .or_else(|| req.payload.get("delta"))
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let contract = req
                .payload
                .get("contract")
                .and_then(|v| v.as_str())
                .unwrap_or(&raw_ticker)
                .trim()
                .to_string();
            let img_url = req
                .payload
                .get("imgUrl")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let theme = req
                .payload
                .get("theme")
                .cloned()
                .unwrap_or_else(|| json!({ "hex": "#18C6A5", "pastel": "#99f6e4" }));

            let token_entry = json!({
                "ticker": raw_ticker,
                "symbol": raw_ticker,
                "name": name,
                "assetClass": asset_class,
                "network": network,
                "spotPrice": spot_price,
                "delta": change_24h,
                "contract": contract,
                "imgUrl": img_url,
                "theme": theme
            });

            if let Some(arr) = state.get_mut("customTokens").and_then(|v| v.as_array_mut()) {
                arr.retain(|item| {
                    item.get("ticker")
                        .or_else(|| item.get("symbol"))
                        .and_then(|v| v.as_str())
                        .map(|s| !s.eq_ignore_ascii_case(&raw_ticker))
                        .unwrap_or(true)
                });
                arr.push(token_entry);
            } else {
                state["customTokens"] = json!([token_entry]);
            }

            crate::oracle::register_dynamic_oracle_ticker(&raw_ticker);
            let mut pipe = redis::pipe();
            pipe.cmd("SADD")
                .arg("oracle:dynamic_tickers")
                .arg(&raw_ticker)
                .ignore();
            if spot_price > 0.0 {
                pipe.cmd("SETEX")
                    .arg(format!("oracle:spot:{}_USDC", raw_ticker))
                    .arg(30)
                    .arg(spot_price.to_string())
                    .ignore();
                pipe.cmd("SETEX")
                    .arg(format!("oracle:change24h:{}_USDC", raw_ticker))
                    .arg(300)
                    .arg(change_24h.to_string())
                    .ignore();
            }
            let _: Result<(), _> = pipe.query_async(&mut redis_conn).await;
        },
        "REMOVE_CUSTOM_TOKEN" => {
            let raw_ticker: String = req
                .payload
                .get("ticker")
                .or_else(|| req.payload.get("symbol"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_uppercase();
            if let Some(arr) = state.get_mut("customTokens").and_then(|v| v.as_array_mut()) {
                arr.retain(|item| {
                    item.get("ticker")
                        .or_else(|| item.get("symbol"))
                        .and_then(|v| v.as_str())
                        .map(|s| !s.eq_ignore_ascii_case(&raw_ticker))
                        .unwrap_or(true)
                });
            }
        },
        "ADD_WORKER" => {
            if let Some(workers) = state.get_mut("workers").and_then(|w| w.as_array_mut()) {
                let new_id = req.payload.get("id").and_then(|i| i.as_str()).unwrap_or("");
                let exists = workers.iter().any(|w| w.get("id").and_then(|i| i.as_str()).unwrap_or("") == new_id);
                if !exists {
                    workers.push(req.payload.clone());
                }
            } else {
                state["workers"] = json!([req.payload.clone()]);
            }
        },
        "DELETE_WORKER" => {
            if let Some(id) = req.payload.get("id").and_then(|i| i.as_str()) {
                if let Some(workers) = state.get_mut("workers").and_then(|w| w.as_array_mut()) {
                    workers.retain(|w| w.get("id").and_then(|i| i.as_str()).unwrap_or("") != id);
                }
            }
        },
        "RENAME_WORKER" => {
            if let (Some(id), Some(name), Some(wallet_worker)) = (
                req.payload.get("id").and_then(|i| i.as_str()),
                req.payload.get("name").and_then(|n| n.as_str()),
                req.payload.get("walletWorker").and_then(|w| w.as_str()),
            ) {
                if let Some(workers) = state.get_mut("workers").and_then(|w| w.as_array_mut()) {
                    for w in workers.iter_mut() {
                        if w.get("id").and_then(|i| i.as_str()).unwrap_or("") == id {
                            w["name"] = json!(name);
                            w["walletWorker"] = json!(wallet_worker);
                        }
                    }
                }
            }
        },
        "ADD_SECTOR" => {
            let new_pct = req.payload.get("allocationPercentage").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let mut total_pct = new_pct;
            if let Some(sectors) = state.get("sectors").and_then(|s| s.as_array()) {
                for sec in sectors {
                    total_pct += sec.get("allocationPercentage").and_then(|v| v.as_f64()).unwrap_or(0.0);
                }
            }
            if total_pct > 100.001 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse { success: false, error: Some("Total sector allocation cannot exceed 100%".to_string()), transaction_id: None, signed_psbt_hex: None, data: None }));
            }
            let mut normalized_sector = req.payload.clone();
            normalize_sector_plant_or_silo_rules(&mut normalized_sector);
            if let Some(sectors) = state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                sectors.push(normalized_sector);
            } else {
                state["sectors"] = json!([normalized_sector]);
            }
        },
        "DELETE_SECTOR" => {
            if let Some(id) = req.payload.get("id").and_then(|i| i.as_str()) {
                if let Some(sectors) = state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                    sectors.retain(|s| s.get("id").and_then(|i| i.as_str()).unwrap_or("") != id);
                }
            }
        },
        "RENAME_SECTOR" => {
            if let (Some(id), Some(name)) = (
                req.payload.get("id").and_then(|i| i.as_str()),
                req.payload.get("name").and_then(|n| n.as_str()),
            ) {
                if let Some(sectors) = state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                    for sec in sectors.iter_mut() {
                        if sec.get("id").and_then(|i| i.as_str()).unwrap_or("") == id {
                            sec["name"] = json!(name);
                        }
                    }
                }
            }
        },
        "UPDATE_SECTOR_ALLOCATION" => {
            if let (Some(id), Some(new_pct)) = (
                req.payload.get("id").and_then(|i| i.as_str()),
                req.payload.get("allocationPercentage").and_then(|p| p.as_f64()),
            ) {
                let mut total_pct = new_pct;
                if let Some(sectors) = state.get("sectors").and_then(|s| s.as_array()) {
                    for sec in sectors {
                        if sec.get("id").and_then(|i| i.as_str()).unwrap_or("") != id {
                            total_pct += sec.get("allocationPercentage").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        }
                    }
                }
                if total_pct > 100.001 {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse { success: false, error: Some("Total sector allocation cannot exceed 100%".to_string()), transaction_id: None, signed_psbt_hex: None, data: None }));
                }
                if let Some(sectors) = state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                    for sec in sectors.iter_mut() {
                        if sec.get("id").and_then(|i| i.as_str()).unwrap_or("") == id {
                            sec["allocationPercentage"] = json!(new_pct);
                        }
                    }
                }
            }
        },
        "UPDATE_SETTLEMENT" => {
            if let (Some(id), Some(config)) = (
                req.payload.get("id").and_then(|i| i.as_str()),
                req.payload.get("config"),
            ) {
                if let Some(sectors) = state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                    for sec in sectors.iter_mut() {
                        if sec.get("id").and_then(|i| i.as_str()).unwrap_or("") == id {
                            sec["settlementConfig"] = config.clone();
                            normalize_sector_plant_or_silo_rules(sec);
                        }
                    }
                }
            }
        },
        "REORDER_SECTORS" => {
            if let Some(new_array) = req.payload.as_array() {
                let mut total_pct = 0.0;
                for sec in new_array {
                    total_pct += sec.get("allocationPercentage").and_then(|v| v.as_f64()).unwrap_or(0.0);
                }
                if total_pct > 100.001 {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse { success: false, error: Some("Payload manipulation detected. Total allocation exceeds 100%".to_string()), transaction_id: None, signed_psbt_hex: None, data: None }));
                }
                state["sectors"] = json!(new_array);
            }
        },
        "REGISTER_COLD_VAULT_AIRLOCK" => {
            let raw_cold_addr = req
                .payload
                .get("coldKaspaAddress")
                .or_else(|| req.payload.get("coldAddress"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if let Err(err_msg) = decode_kaspa_address_version_and_hash(raw_cold_addr) {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some(format!("INVALID_COLD_VAULT_ADDRESS: {}", err_msg)),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let normalized_cold = if raw_cold_addr.to_lowercase().starts_with("kaspa:") {
                raw_cold_addr.to_lowercase()
            } else {
                format!("kaspa:{}", raw_cold_addr.to_lowercase())
            };
            let card_pubkey_hex = req
                .payload
                .get("cardPublicKeyHex")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_lowercase();
            let card_label = req
                .payload
                .get("cardLabel")
                .and_then(|v| v.as_str())
                .unwrap_or("Air-Gapped Hardware Vault")
                .trim()
                .to_string();
            let signer_mode = req
                .payload
                .get("signerMode")
                .and_then(|v| v.as_str())
                .unwrap_or("WEB_QR_AIRLOCK")
                .trim()
                .to_uppercase();
            let overflow_threshold_kas = req
                .payload
                .get("overflowThresholdKas")
                .and_then(|v| v.as_f64())
                .unwrap_or(500.0)
                .clamp(50.0, 1_000_000.0);
            let auto_sweep_enabled = req
                .payload
                .get("autoSweepEnabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            sqlx::query(
                r#"
                INSERT INTO client_cold_vault_registry
                (wallet_address, cold_kaspa_address, card_public_key_hex, card_label, signer_mode, overflow_threshold_kas, auto_sweep_enabled, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
                ON CONFLICT (wallet_address) DO UPDATE SET
                    cold_kaspa_address = EXCLUDED.cold_kaspa_address,
                    card_public_key_hex = EXCLUDED.card_public_key_hex,
                    card_label = EXCLUDED.card_label,
                    signer_mode = EXCLUDED.signer_mode,
                    overflow_threshold_kas = EXCLUDED.overflow_threshold_kas,
                    auto_sweep_enabled = EXCLUDED.auto_sweep_enabled,
                    updated_at = CURRENT_TIMESTAMP
                "#,
            )
            .bind(&master_identity)
            .bind(&normalized_cold)
            .bind(&card_pubkey_hex)
            .bind(&card_label)
            .bind(&signer_mode)
            .bind(overflow_threshold_kas)
            .bind(auto_sweep_enabled)
            .execute(&mut *tx_db)
            .await
            .map_err(|e| {
                Json(ActionResponse {
                    success: false,
                    error: Some(format!("Failed to persist Cold Vault Airlock registration: {}", e)),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                })
            })?;
            let airlock_config = json!({
                "walletAddress": master_identity,
                "coldKaspaAddress": normalized_cold,
                "cardPublicKeyHex": card_pubkey_hex,
                "cardLabel": card_label,
                "signerMode": signer_mode,
                "overflowThresholdKas": overflow_threshold_kas,
                "autoSweepEnabled": auto_sweep_enabled,
                "updatedAt": chrono::Utc::now().to_rfc3339()
            });
            state["coldVaultAirlock"] = airlock_config.clone();
            let _ = sqlx::query(
                "INSERT INTO user_command_centers (wallet_address, layout_state, last_updated)
                 VALUES ($1, $2, CURRENT_TIMESTAMP)
                 ON CONFLICT (wallet_address) DO UPDATE SET layout_state = EXCLUDED.layout_state, last_updated = CURRENT_TIMESTAMP"
            )
            .bind(&master_identity)
            .bind(&state)
            .execute(&mut *tx_db)
            .await;
            let _ = tx_db.commit().await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: None,
                signed_psbt_hex: None,
                data: Some(airlock_config),
            }));
        },
        "GET_COLD_VAULT_AIRLOCK" => {
            let row_opt = sqlx::query(
                "SELECT cold_kaspa_address, card_public_key_hex, card_label, signer_mode, overflow_threshold_kas, auto_sweep_enabled, last_sweep_txid, last_sweep_at, updated_at FROM client_cold_vault_registry WHERE wallet_address = $1 OR wallet_address = $2 LIMIT 1"
            )
            .bind(&master_identity)
            .bind(&clean_wallet)
            .fetch_optional(&mut *tx_db)
            .await
            .ok()
            .flatten();
            let _ = tx_db.rollback().await;
            let node_airlock_raw: Option<String> = redis::cmd("GET")
                .arg("perennia:treasury:airlock_status")
                .query_async(&mut redis_conn)
                .await
                .unwrap_or(None);
            let node_airlock = node_airlock_raw
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                .unwrap_or_else(|| json!({}));
            let client_vault = if let Some(r) = row_opt {
                Some(json!({
                    "walletAddress": master_identity,
                    "coldKaspaAddress": r.try_get::<String, _>("cold_kaspa_address").unwrap_or_default(),
                    "cardPublicKeyHex": r.try_get::<String, _>("card_public_key_hex").unwrap_or_default(),
                    "cardLabel": r.try_get::<String, _>("card_label").unwrap_or_else(|_| "Air-Gapped Hardware Vault".to_string()),
                    "signerMode": r.try_get::<String, _>("signer_mode").unwrap_or_else(|_| "WEB_QR_AIRLOCK".to_string()),
                    "overflowThresholdKas": r.try_get::<f64, _>("overflow_threshold_kas").unwrap_or(500.0),
                    "autoSweepEnabled": r.try_get::<bool, _>("auto_sweep_enabled").unwrap_or(true),
                    "lastSweepTxid": r.try_get::<Option<String>, _>("last_sweep_txid").unwrap_or(None),
                    "lastSweepAt": r.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_sweep_at").ok().flatten().map(|d| d.to_rfc3339()),
                    "updatedAt": r.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("updated_at").ok().flatten().map(|d| d.to_rfc3339())
                }))
            } else {
                state.get("coldVaultAirlock").cloned()
            };
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: None,
                signed_psbt_hex: None,
                data: Some(json!({
                    "clientVault": client_vault,
                    "nodeAirlock": node_airlock
                })),
            }));
        },
        "SWEEP_TO_COLD_VAULT_NOW" => {
            let row_opt = sqlx::query(
                "SELECT cold_kaspa_address FROM client_cold_vault_registry WHERE wallet_address = $1 OR wallet_address = $2 LIMIT 1"
            )
            .bind(&master_identity)
            .bind(&clean_wallet)
            .fetch_optional(&mut *tx_db)
            .await
            .ok()
            .flatten();
            let cold_dest = req
                .payload
                .get("coldKaspaAddress")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .or_else(|| row_opt.and_then(|r| r.try_get::<String, _>("cold_kaspa_address").ok()))
                .unwrap_or_default();
            if cold_dest.is_empty() {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("No Cold Vault address registered. Scan your hardware card QR or enter a valid kaspa: cold address first.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let amount_kas = req
                .payload
                .get("amountKas")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            if amount_kas <= 0.0 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("Sweep amount must be strictly greater than 0 KAS.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
            let debit_res: (i32, String) = redis::cmd("EVAL")
                .arg(LUA_ATOMIC_DEBIT_SINGLE)
                .arg(1)
                .arg(&user_ledger_key)
                .arg("KAS")
                .arg(amount_kas)
                .query_async(&mut redis_conn)
                .await
                .unwrap_or((0, "0".to_string()));
            if debit_res.0 == 0 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("Insufficient KAS in Batch Settlement Queue / Internal Ledger to sweep to Cold Vault.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let from_unassigned = debit_res.1.parse::<f64>().unwrap_or(0.0);
            if from_unassigned > 1e-9 {
                let _ = sqlx::query(
                    "UPDATE yield_reservoirs SET streaming_balance_kas = GREATEST(0.0, streaming_balance_kas - $1), last_updated = CURRENT_TIMESTAMP WHERE LOWER(REPLACE(TRIM(wallet_address), 'kaspa:', '')) = $2 OR wallet_address = $3"
                )
                .bind(from_unassigned)
                .bind(&clean_wallet)
                .bind(&master_identity)
                .execute(&mut *tx_db)
                .await;
            }
            let spot_price = get_spot_usd(&mut redis_conn, "KAS").await;
            let (tx_id, dispatch_status, explorer_url) = dispatch_or_queue_multi_chain_l1(
                &mut tx_db,
                &mut redis_conn,
                &master_identity,
                &clean_wallet,
                &cold_dest,
                "KAS",
                amount_kas,
                spot_price,
                "cold_vault_airlock_sweep",
            )
            .await;
            let _ = sqlx::query(
                "UPDATE client_cold_vault_registry SET last_sweep_txid = $1, last_sweep_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE wallet_address = $2 OR wallet_address = $3"
            )
            .bind(&tx_id)
            .bind(&master_identity)
            .bind(&clean_wallet)
            .execute(&mut *tx_db)
            .await;
            let _ = tx_db.commit().await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: Some(tx_id.clone()),
                signed_psbt_hex: None,
                data: Some(json!({
                    "txHash": tx_id,
                    "status": dispatch_status,
                    "explorerUrl": explorer_url,
                    "coldKaspaAddress": cold_dest,
                    "sweptKas": amount_kas
                })),
            }));
        },
        "GET_HIFO_TAX_LOTS" => {
            let lot_rows = sqlx::query(
                r#"
                SELECT lot_id, asset_ticker, acquired_at, kas_sompi, initial_tokens,
                       remaining_sompi, remaining_tokens, fmv_usd_per_token, total_cost_basis_usd,
                       source_event_type, source_tx_hash, status,
                       GREATEST(0, EXTRACT(DAY FROM (CURRENT_TIMESTAMP - acquired_at))::INTEGER) AS holding_days
                FROM hifo_tax_lots
                WHERE wallet_address = $1 OR wallet_address = $2
                ORDER BY fmv_usd_per_token DESC, acquired_at ASC
                LIMIT 500
                "#,
            )
            .bind(&clean_wallet)
            .bind(&master_identity)
            .fetch_all(&mut *tx_db)
            .await
            .unwrap_or_default();
            let match_rows = sqlx::query(
                r#"
                SELECT match_id, lot_id, asset_ticker, disposed_sompi, disposed_tokens,
                       acquired_at, disposed_at, holding_period_days, is_long_term,
                       cost_basis_usd, gross_proceeds_usd, realized_gain_loss_usd, disposal_tx_hash
                FROM hifo_disposal_matches
                WHERE wallet_address = $1 OR wallet_address = $2
                ORDER BY disposed_at DESC
                LIMIT 500
                "#,
            )
            .bind(&clean_wallet)
            .bind(&master_identity)
            .fetch_all(&mut *tx_db)
            .await
            .unwrap_or_default();
            let _ = tx_db.rollback().await;
            let mut lots_json = Vec::new();
            let mut open_cost_basis_usd = 0.0_f64;
            let mut open_kas_tokens = 0.0_f64;
            for r in lot_rows {
                let lid: Uuid = r.get("lot_id");
                let ticker: String = r.get("asset_ticker");
                let acquired_at: chrono::DateTime<chrono::Utc> = r.get("acquired_at");
                let kas_sompi: i64 = r.get("kas_sompi");
                let init_tok: f64 = r.get("initial_tokens");
                let rem_sompi: i64 = r.get("remaining_sompi");
                let rem_tok: f64 = r.get("remaining_tokens");
                let fmv_usd: f64 = r.get("fmv_usd_per_token");
                let total_basis: f64 = r.get("total_cost_basis_usd");
                let src_type: String = r.get("source_event_type");
                let src_tx: Option<String> = r.try_get("source_tx_hash").ok().flatten();
                let st: String = r.get("status");
                let holding_days: i32 = r.try_get("holding_days").unwrap_or(0);
                if st == "OPEN" && rem_tok > 0.0 {
                    open_cost_basis_usd += rem_tok * fmv_usd;
                    if ticker == "KAS" {
                        open_kas_tokens += rem_tok;
                    }
                }
                lots_json.push(json!({
                    "lotId": lid.to_string(),
                    "assetTicker": ticker,
                    "acquiredAt": acquired_at.to_rfc3339(),
                    "kasSompi": kas_sompi,
                    "initialTokens": init_tok,
                    "remainingSompi": rem_sompi,
                    "remainingTokens": rem_tok,
                    "fmvUsdPerToken": fmv_usd,
                    "totalCostBasisUsd": total_basis,
                    "remainingCostBasisUsd": rem_tok * fmv_usd,
                    "sourceEventType": src_type,
                    "sourceTxHash": src_tx,
                    "status": st,
                    "holdingDays": holding_days,
                    "isLongTerm": holding_days > 365
                }));
            }
            let mut disposals_json = Vec::new();
            let mut short_term_gain_loss_usd = 0.0_f64;
            let mut long_term_gain_loss_usd = 0.0_f64;
            let mut total_matched_basis_usd = 0.0_f64;
            let mut total_matched_proceeds_usd = 0.0_f64;
            for m in match_rows {
                let mid: Uuid = m.get("match_id");
                let lid: Uuid = m.get("lot_id");
                let ticker: String = m.get("asset_ticker");
                let disp_sompi: i64 = m.get("disposed_sompi");
                let disp_tok: f64 = m.get("disposed_tokens");
                let acq_at: chrono::DateTime<chrono::Utc> = m.get("acquired_at");
                let disp_at: chrono::DateTime<chrono::Utc> = m.get("disposed_at");
                let hold_days: i32 = m.get("holding_period_days");
                let is_lt: bool = m.get("is_long_term");
                let basis_usd: f64 = m.get("cost_basis_usd");
                let proc_usd: f64 = m.get("gross_proceeds_usd");
                let gain_loss: f64 = m.get("realized_gain_loss_usd");
                let disp_tx: Option<String> = m.try_get("disposal_tx_hash").ok().flatten();
                total_matched_basis_usd += basis_usd;
                total_matched_proceeds_usd += proc_usd;
                if is_lt {
                    long_term_gain_loss_usd += gain_loss;
                } else {
                    short_term_gain_loss_usd += gain_loss;
                }
                disposals_json.push(json!({
                    "matchId": mid.to_string(),
                    "lotId": lid.to_string(),
                    "assetTicker": ticker,
                    "disposedSompi": disp_sompi,
                    "disposedTokens": disp_tok,
                    "acquiredAt": acq_at.to_rfc3339(),
                    "disposedAt": disp_at.to_rfc3339(),
                    "holdingPeriodDays": hold_days,
                    "isLongTerm": is_lt,
                    "costBasisUsd": basis_usd,
                    "grossProceedsUsd": proc_usd,
                    "realizedGainLossUsd": gain_loss,
                    "disposalTxHash": disp_tx
                }));
            }
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: None,
                signed_psbt_hex: None,
                data: Some(json!({
                    "accountingMethod": "PASSIVE_HIFO_NO_WASH",
                    "lots": lots_json,
                    "disposalMatches": disposals_json,
                    "summary": {
                        "openCostBasisUsd": open_cost_basis_usd,
                        "openKasTokens": open_kas_tokens,
                        "totalMatchedCostBasisUsd": total_matched_basis_usd,
                        "totalMatchedProceedsUsd": total_matched_proceeds_usd,
                        "shortTermGainLossUsd": short_term_gain_loss_usd,
                        "longTermGainLossUsd": long_term_gain_loss_usd,
                        "netRealizedGainLossUsd": short_term_gain_loss_usd + long_term_gain_loss_usd
                    }
                })),
            }));
        },
        "CLAIM_PENDING_SECTOR_KAS" => {
            let sector_id_filter = req
                .payload
                .get("sectorId")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let target_asset_filter = req
                .payload
                .get("targetAsset")
                .or_else(|| req.payload.get("asset"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty());
            let dispatch_l1_immediately = req
                .payload
                .get("dispatchL1")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut claimed_kas = 0.0_f64;
            let mut affected_buckets: HashMap<String, f64> = HashMap::new();
            if let Some(sectors) = state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                for sec in sectors.iter_mut() {
                    let sec_id = sec.get("id").and_then(|v| v.as_str()).unwrap_or("");
                    let matches = if let Some(ref sid) = sector_id_filter {
                        sec_id == sid
                    } else if let Some(ref t_asset) = target_asset_filter {
                        sector_targets_asset(sec, t_asset)
                    } else {
                        true
                    };
                    if matches {
                        let pending = sec
                            .get("pendingKaspa")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0_f64)
                            .max(0.0_f64);
                        if pending > 0.0 {
                            let primary_tick = sec
                                .pointer("/settlementConfig/targetAsset/ticker")
                                .and_then(|v| v.as_str())
                                .unwrap_or("KAS")
                                .trim()
                                .to_uppercase();
                            *affected_buckets.entry(primary_tick).or_insert(0.0_f64) += pending;
                            claimed_kas += pending;
                            sec["pendingKaspa"] = json!(0.0_f64);
                            sec["lastSettledAt"] = json!(now_secs);
                        }
                    }
                }
            }
            if claimed_kas <= 0.0 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("No pending KAS available to pull out from the selected sector or bucket.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let kas_spot = get_spot_usd(&mut redis_conn, "KAS").await;
            let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
            let dispatched_tx_id: Option<String>;
            if dispatch_l1_immediately {
                let (tx_id, _status, _exp) = dispatch_or_queue_multi_chain_l1(
                    &mut tx_db,
                    &mut redis_conn,
                    &master_identity,
                    &clean_wallet,
                    &master_identity,
                    "KAS",
                    claimed_kas,
                    kas_spot,
                    "sector_instant_pullout",
                )
                .await;
                dispatched_tx_id = Some(tx_id);
            } else {
                let _: () = redis::cmd("HINCRBYFLOAT")
                    .arg(&user_ledger_key)
                    .arg("KAS")
                    .arg(claimed_kas)
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(());
                let pullout_ref = format!(
                    "PULLOUT-KAS-{}",
                    &Uuid::new_v4().simple().to_string().to_uppercase()[..8]
                );
                let gross_usd = claimed_kas * kas_spot;
                let _ = sqlx::query(
                    "INSERT INTO tax_ledger_events (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution, tx_hash, payout_address, cost_basis_usd, realized_gain_loss_usd, holding_period) VALUES ($1, 'KAS', 'YIELD', $2, $3, $4, $5, $6, $2, 0.0, 'SHORT_TERM')"
                )
                .bind(&clean_wallet)
                .bind(gross_usd)
                .bind(claimed_kas)
                .bind(kas_spot)
                .bind(&pullout_ref)
                .bind(&master_identity)
                .execute(&mut *tx_db)
                .await;
                dispatched_tx_id = Some(pullout_ref);
            }
            if let Some(ref ref_tx) = dispatched_tx_id {
                crate::sor::record_hifo_acquisition_lot(
                    &pool,
                    &clean_wallet,
                    "KAS",
                    claimed_kas,
                    kas_spot,
                    "YIELD",
                    Some(ref_tx),
                )
                .await;
            }
            sqlx::query(
                "INSERT INTO user_command_centers (wallet_address, layout_state, last_updated)
                 VALUES ($1, $2, CURRENT_TIMESTAMP)
                 ON CONFLICT (wallet_address) DO UPDATE SET layout_state = EXCLUDED.layout_state, last_updated = CURRENT_TIMESTAMP"
            )
            .bind(&master_identity)
            .bind(&state)
            .execute(&mut *tx_db)
            .await
            .map_err(|e| {
                Json(ActionResponse {
                    success: false,
                    error: Some(format!("Failed to persist sector pull-out state: {}", e)),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                })
            })?;
            let _ = sqlx::query("DELETE FROM user_command_centers WHERE wallet_address = $1")
                .bind(&clean_wallet)
                .execute(&mut *tx_db)
                .await;
            let _ = tx_db.commit().await;
            if let Ok(Some(epoch_raw)) = redis::cmd("GET")
                .arg("perennia:settlement:epoch_telemetry")
                .query_async::<_, Option<String>>(&mut redis_conn)
                .await
            {
                if let Ok(mut epoch_val) = serde_json::from_str::<Value>(&epoch_raw) {
                    if let Some(buckets_obj) = epoch_val.get_mut("buckets").and_then(|b| b.as_object_mut()) {
                        for (b_tick, deducted_kas) in &affected_buckets {
                            if let Some(b_entry) = buckets_obj.get_mut(b_tick) {
                                let cur_pend: f64 = b_entry.get("pendingKas").and_then(|v| v.as_f64()).unwrap_or(0.0_f64);
                                let min_kas: f64 = b_entry.get("minProfitableKas").and_then(|v| v.as_f64()).unwrap_or(0.0_f64);
                                let next_pend: f64 = (cur_pend - *deducted_kas).max(0.0_f64);
                                let next_weight: f64 = if min_kas > 0.0 {
                                    (next_pend / min_kas) * 100.0_f64
                                } else {
                                    0.0_f64
                                };
                                b_entry["pendingKas"] = json!(next_pend);
                                b_entry["pendingUsd"] = json!(next_pend * kas_spot);
                                b_entry["weightPct"] = json!(next_weight);
                            }
                        }
                        let _: () = redis::cmd("SET")
                            .arg("perennia:settlement:epoch_telemetry")
                            .arg(epoch_val.to_string())
                            .query_async(&mut redis_conn)
                            .await
                            .unwrap_or(());
                        let sse_epoch = json!({
                            "epoch_telemetry_update": true,
                            "epoch": epoch_val
                        });
                        let _: () = redis::cmd("PUBLISH")
                            .arg("telemetry:updates")
                            .arg(sse_epoch.to_string())
                            .query_async(&mut redis_conn)
                            .await
                            .unwrap_or(());
                    }
                }
            }
            let yield_update = json!({
                "wallet": clean_wallet,
                "yield_update": true,
                "sectors": state.get("sectors").cloned().unwrap_or_else(|| json!([]))
            });
            let _: () = redis::cmd("PUBLISH")
                .arg("telemetry:updates")
                .arg(yield_update.to_string())
                .query_async(&mut redis_conn)
                .await
                .unwrap_or(());
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: dispatched_tx_id,
                signed_psbt_hex: None,
                data: Some(json!({
                    "claimedKas": claimed_kas,
                    "sectorId": sector_id_filter,
                    "targetAsset": target_asset_filter,
                    "sectors": state.get("sectors").cloned().unwrap_or_else(|| json!([]))
                })),
            }));
        },
        "ADD_MANUAL_LP" => {
            if let Some(pos) = req.payload.get("position") {
                if let Some(lps) = state.get_mut("manualLps").and_then(|l| l.as_array_mut()) {
                    lps.push(pos.clone());
                } else {
                    state["manualLps"] = json!([pos.clone()]);
                }
            }
        },
        "COMPILE_SILVERSCRIPT_COVENANT" => {
            let _ = tx_db.rollback().await;
            let raw_ticker = req
                .payload
                .get("ticker")
                .and_then(|v| v.as_str())
                .unwrap_or("SILO")
                .trim()
                .to_uppercase();
            let token_standard = req
                .payload
                .get("tokenStandard")
                .and_then(|v| v.as_str())
                .unwrap_or("KCC-20");
            let label = req
                .payload
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("Genesis Tranche");
            let beneficiary = req
                .payload
                .get("beneficiaryAddress")
                .or_else(|| req.payload.get("address"))
                .and_then(|v| v.as_str())
                .unwrap_or(&master_identity);
            let total_alloc = req
                .payload
                .get("totalAllocation")
                .or_else(|| req.payload.get("amount"))
                .and_then(|v| v.as_f64())
                .unwrap_or(1_000_000.0);
            let decimals = req
                .payload
                .get("decimals")
                .and_then(|v| v.as_u64())
                .unwrap_or(8) as u32;
            let cliff_days = req
                .payload
                .get("cliffDays")
                .and_then(|v| v.as_i64())
                .unwrap_or(90) as i32;
            let linear_days = req
                .payload
                .get("linearDays")
                .and_then(|v| v.as_i64())
                .unwrap_or(365) as i32;
            let charter_sha256 = req
                .payload
                .get("charterSha256")
                .and_then(|v| v.as_str());
            let compiled = compile_silverscript_proof_of_lock_vault(
                &raw_ticker,
                token_standard,
                label,
                beneficiary,
                total_alloc,
                decimals,
                cliff_days,
                linear_days,
                None,
                charter_sha256,
            );
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: None,
                signed_psbt_hex: None,
                data: Some(serde_json::to_value(compiled).unwrap_or_else(|_| json!({}))),
            }));
        },
        "REGISTER_FORGE_TOKENOMICS" | "RETROACTIVE_FORGE_UPGRADE" => {
            let is_retro = req.action == "RETROACTIVE_FORGE_UPGRADE"
                || req
                    .payload
                    .get("isRetroactiveUpgrade")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
            let raw_ticker = req
                .payload
                .get("ticker")
                .or_else(|| req.payload.get("tokenTicker"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_uppercase();
            if raw_ticker.len() < 4 || raw_ticker.len() > 6 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("KRC-20 / KCC-20 ticker must be 4 to 6 alphabetic characters.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let token_standard =
                req.payload
                    .get("tokenStandard")
                    .and_then(|v| v.as_str())
                    .map(|s| {
                        if s.trim().eq_ignore_ascii_case("KCC-20") {
                            "KCC-20".to_string()
                        } else {
                            "KRC-20".to_string()
                        }
                    })
                    .unwrap_or_else(|| "KRC-20".to_string());
            let max_supply: f64 = req
                .payload
                .get("maxSupply")
                .and_then(|v| v.as_f64())
                .unwrap_or(21_000_000.0)
                .max(1.0);
            let decimals: u32 = req
                .payload
                .get("decimals")
                .and_then(|v| v.as_u64())
                .unwrap_or(8)
                .min(18) as u32;
            let deploy_tx_hash = req
                .payload
                .get("deployTxHash")
                .or_else(|| req.payload.get("anchorTxHash"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let kas_protocol_fee: f64 = req
                .payload
                .get("protocolFeeKas")
                .and_then(|v| v.as_f64())
                .unwrap_or(1.50)
                .clamp(0.0, 500.0);
            if kas_protocol_fee > 0.0 {
                let _: () = redis::cmd("INCRBYFLOAT")
                    .arg("perennia:fees:batch_accumulated:KAS")
                    .arg(kas_protocol_fee)
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(());
            }
            let mut inserted_vesting_count = 0usize;
            if let Some(cap_rows) = req.payload.get("capTable").and_then(|v| v.as_array()) {
                for row_val in cap_rows {
                    let raw_addr = row_val
                        .get("address")
                        .or_else(|| row_val.get("beneficiaryAddress"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    if raw_addr.is_empty() {
                        continue;
                    }
                    let clean_ben = raw_addr.to_lowercase().replace("kaspa:", "");
                    let prefixed_ben = format!("kaspa:{}", clean_ben);
                    let label = row_val
                        .get("label")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Genesis Allocation")
                        .trim()
                        .to_string();
                    let amount_tokens: f64 = row_val
                        .get("amount")
                        .or_else(|| row_val.get("totalAllocated"))
                        .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok())))
                        .unwrap_or(0.0)
                        .max(0.0);
                    if amount_tokens <= 0.0 {
                        continue;
                    }
                    let cliff_days: i32 = row_val
                        .get("cliffDays")
                        .or_else(|| row_val.get("cliff_days"))
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0)
                        .clamp(0, 3650) as i32;
                    let linear_days: i32 = row_val
                        .get("linearDays")
                        .or_else(|| row_val.get("linear_days"))
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0)
                        .clamp(0, 3650) as i32;
                    let is_locked_covenant = cliff_days > 0 || linear_days > 0;
                    let effective_linear_days = if is_locked_covenant {
                        linear_days.max(1)
                    } else {
                        0
                    };
                    let daily_unlock_rate: f64 = if effective_linear_days > 0 {
                        amount_tokens / (effective_linear_days as f64)
                    } else {
                        amount_tokens
                    };
                    let initial_unlocked: f64 = if is_locked_covenant {
                        0.0
                    } else {
                        amount_tokens
                    };
                    let initial_status = if is_locked_covenant {
                        "LOCKED"
                    } else {
                        "UNLOCKED"
                    };
                    let compiled_vault = compile_silverscript_proof_of_lock_vault(
                        &raw_ticker,
                        &token_standard,
                        &label,
                        &prefixed_ben,
                        amount_tokens,
                        decimals,
                        cliff_days,
                        effective_linear_days,
                        None,
                        None,
                    );
                    let vprog_state_root = row_val
                        .get("vprogStateRoot")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| compiled_vault.kcc20StateRootHex.clone());
                    let covenant_address = row_val
                        .get("covenantAddress")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| compiled_vault.covenantAddress.clone());
                    let silverscript_source = row_val
                        .get("silverscriptSource")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or_else(|| compiled_vault.silverscriptSource.clone());
                    let redeem_script_hex = row_val
                        .get("redeemScriptHex")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| compiled_vault.redeemScriptHex.clone());
                    let kcc20_state_commitment = row_val
                        .get("kcc20StateCommitment")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| compiled_vault.kcc20StateRootHex.clone());
                    let row_tx_hash = row_val
                        .get("txHash")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .or_else(|| deploy_tx_hash.clone());
                    let total_lock_days = cliff_days + effective_linear_days;
                    let _ = sqlx::query(
                        r#"
                        INSERT INTO forge_vesting_schedules
                        (token_ticker, beneficiary_address, creator_address, label, total_allocated,
                         unlocked_amount, claimed_amount, cliff_days, linear_days,
                         cliff_unlock_at, full_unlock_at, daily_unlock_rate, covenant_rule,
                         vprog_state_root, covenant_address, silverscript_source, redeem_script_hex,
                         kcc20_state_commitment, token_standard, lock_tx_hash, status)
                        VALUES (
                            $1, $2, $3, $4, $5,
                            $6, 0.0, $7, $8,
                            CURRENT_TIMESTAMP + make_interval(days => $7),
                            CURRENT_TIMESTAMP + make_interval(days => $9),
                            $10, 'SILVERSCRIPT_PROOF_OF_LOCK_V1', $11, $12, $13, $14, $15, $16, $17, $18
                        )
                        "#,
                    )
                    .bind(&raw_ticker)
                    .bind(&prefixed_ben)
                    .bind(&master_identity)
                    .bind(&label)
                    .bind(amount_tokens)
                    .bind(initial_unlocked)
                    .bind(cliff_days)
                    .bind(effective_linear_days)
                    .bind(total_lock_days)
                    .bind(daily_unlock_rate)
                    .bind(&vprog_state_root)
                    .bind(&covenant_address)
                    .bind(&silverscript_source)
                    .bind(&redeem_script_hex)
                    .bind(&kcc20_state_commitment)
                    .bind(&token_standard)
                    .bind(&row_tx_hash)
                    .bind(initial_status)
                    .execute(&mut *tx_db)
                    .await;
                    if !is_locked_covenant {
                        let ben_ledger_key = format!("dev:sor:treasury:balances:{}", clean_ben);
                        let _: () = redis::cmd("HINCRBYFLOAT")
                            .arg(&ben_ledger_key)
                            .arg(&raw_ticker)
                            .arg(amount_tokens)
                            .query_async(&mut redis_conn)
                            .await
                            .unwrap_or(());
                    }
                    inserted_vesting_count += 1;
                }
            }
            if let Some(policy_obj) = req.payload.get("monetaryPolicy") {
                let burn_rate_bps: i32 = policy_obj
                    .get("burnRateBps")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(50)
                    .clamp(0, 2000) as i32;
                let emission_schedule_type = policy_obj
                    .get("emissionScheduleType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("CHROMATIC_HALVING")
                    .trim()
                    .to_uppercase();
                let daily_emission_rate: f64 = policy_obj
                    .get("dailyEmissionRate")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    .max(0.0);
                let halving_interval_days: i32 = policy_obj
                    .get("halvingIntervalDays")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(365)
                    .clamp(30, 1825) as i32;
                let reserve_locked_tokens: f64 = policy_obj
                    .get("reserveLockedTokens")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    .max(0.0);
                let zero_rug_lp_pct: f64 = policy_obj
                    .get("zeroRugLpPct")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    .clamp(0.0, 100.0);
                let zero_rug_lock_days: i32 = policy_obj
                    .get("zeroRugLockDays")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(365)
                    .clamp(30, 365) as i32;
                let charter_seed = format!(
                    "MONETARY_CHARTER:{}:{}:{}:{}:{}:{}:{}",
                    raw_ticker,
                    max_supply,
                    burn_rate_bps,
                    emission_schedule_type,
                    daily_emission_rate,
                    halving_interval_days,
                    zero_rug_lp_pct
                );
                let charter_sha256 = policy_obj
                    .get("charterSha256")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| compute_sha256_hex(&charter_seed));
                let charter_vault = compile_silverscript_proof_of_lock_vault(
                    &raw_ticker,
                    &token_standard,
                    "Chronos Monetary Policy Reserve",
                    &master_identity,
                    if reserve_locked_tokens > 0.0 {
                        reserve_locked_tokens
                    } else {
                        max_supply
                    },
                    decimals,
                    0,
                    halving_interval_days,
                    None,
                    Some(&charter_sha256),
                );
                let _ = sqlx::query(
                    r#"
                    INSERT INTO forge_monetary_policies
                    (token_ticker, creator_address, max_supply, burn_rate_bps, burn_address,
                     emission_schedule_type, daily_emission_rate, halving_interval_days,
                     reserve_locked_tokens, zero_rug_lp_pct, zero_rug_lock_days,
                     is_retroactive_upgrade, charter_sha256, token_standard,
                     kcc20_covenant_id, kcc20_state_root, silverscript_charter_source,
                     covenant_vault_address, anchor_tx_hash, updated_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, CURRENT_TIMESTAMP)
                    ON CONFLICT (token_ticker) DO UPDATE SET
                        burn_rate_bps = EXCLUDED.burn_rate_bps,
                        emission_schedule_type = EXCLUDED.emission_schedule_type,
                        daily_emission_rate = EXCLUDED.daily_emission_rate,
                        halving_interval_days = EXCLUDED.halving_interval_days,
                        reserve_locked_tokens = forge_monetary_policies.reserve_locked_tokens + EXCLUDED.reserve_locked_tokens,
                        zero_rug_lp_pct = EXCLUDED.zero_rug_lp_pct,
                        zero_rug_lock_days = EXCLUDED.zero_rug_lock_days,
                        is_retroactive_upgrade = EXCLUDED.is_retroactive_upgrade,
                        charter_sha256 = EXCLUDED.charter_sha256,
                        token_standard = EXCLUDED.token_standard,
                        kcc20_covenant_id = EXCLUDED.kcc20_covenant_id,
                        kcc20_state_root = EXCLUDED.kcc20_state_root,
                        silverscript_charter_source = EXCLUDED.silverscript_charter_source,
                        covenant_vault_address = EXCLUDED.covenant_vault_address,
                        anchor_tx_hash = COALESCE(EXCLUDED.anchor_tx_hash, forge_monetary_policies.anchor_tx_hash),
                        updated_at = CURRENT_TIMESTAMP
                    "#,
                )
                .bind(&raw_ticker)
                .bind(&master_identity)
                .bind(max_supply)
                .bind(burn_rate_bps)
                .bind(KASPA_BURN_ADDRESS)
                .bind(&emission_schedule_type)
                .bind(daily_emission_rate)
                .bind(halving_interval_days)
                .bind(reserve_locked_tokens)
                .bind(zero_rug_lp_pct)
                .bind(zero_rug_lock_days)
                .bind(is_retro)
                .bind(&charter_sha256)
                .bind(&token_standard)
                .bind(&charter_vault.kcc20CovenantIdHex)
                .bind(&charter_vault.kcc20StateRootHex)
                .bind(&charter_vault.silverscriptSource)
                .bind(&charter_vault.covenantAddress)
                .bind(&deploy_tx_hash)
                .execute(&mut *tx_db)
                .await;
                let zero_rug_initial_kas: f64 = policy_obj
                    .get("zeroRugInitialKas")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    .max(0.0);
                let zero_rug_initial_tokens: f64 = policy_obj
                    .get("zeroRugInitialTokens")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    .max(0.0);
                if zero_rug_lp_pct >= 80.0 && zero_rug_initial_kas > 0.0 && zero_rug_initial_tokens > 0.0 {
                    let locked_kas = zero_rug_initial_kas * (zero_rug_lp_pct / 100.0);
                    let pool_pair = format!("KAS/{}", raw_ticker);
                    let w_json = json!({ "KAS": 0.50, raw_ticker.clone(): 0.50 });
                    let r_json = json!({ "KAS": locked_kas, raw_ticker.clone(): zero_rug_initial_tokens });
                    let _ = sqlx::query(
                        r#"
                        INSERT INTO liquidity_providers
                        (wallet_address, pool_pair, staked_asset_a, staked_asset_b, weights_json, reserves_json, lock_duration_days, unlock_date)
                        VALUES ($1, $2, $3, $4, $5, $6, 365, CURRENT_TIMESTAMP + INTERVAL '365 days')
                        "#,
                    )
                    .bind(&master_identity)
                    .bind(&pool_pair)
                    .bind(locked_kas)
                    .bind(zero_rug_initial_tokens)
                    .bind(w_json)
                    .bind(r_json)
                    .execute(&mut *tx_db)
                    .await;
                }
            }
            if let Some(vault_obj) = req.payload.get("mineableVault") {
                let enabled = vault_obj
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let funded_tokens: f64 = vault_obj
                    .get("totalFundedTokens")
                    .or_else(|| vault_obj.get("fundedTokens"))
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    .max(0.0);
                let daily_emission: f64 = vault_obj
                    .get("dailyEmissionTokens")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(funded_tokens / 365.0)
                    .max(0.0);
                let min_hashrate_ths: f64 = vault_obj
                    .get("minHashrateThs")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.1)
                    .max(0.01);
                let syndicate_enabled = vault_obj
                    .get("syndicateSectorEnabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let vault_label = vault_obj
                    .get("vaultLabel")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Proof-of-Hashrate Mining Vault")
                    .trim()
                    .to_string();
                if enabled && funded_tokens > 0.0 {
                    let _ = sqlx::query(
                        r#"
                        INSERT INTO forge_mineable_vaults
                        (token_ticker, creator_address, vault_label, total_funded_tokens,
                         remaining_vault_tokens, daily_emission_tokens, distributed_tokens,
                         min_hashrate_ths, syndicate_sector_enabled, status, funding_tx_hash, updated_at)
                        VALUES ($1, $2, $3, $4, $4, $5, 0.0, $6, $7, 'ACTIVE', $8, CURRENT_TIMESTAMP)
                        ON CONFLICT (token_ticker) DO UPDATE SET
                            total_funded_tokens = forge_mineable_vaults.total_funded_tokens + EXCLUDED.total_funded_tokens,
                            remaining_vault_tokens = forge_mineable_vaults.remaining_vault_tokens + EXCLUDED.remaining_vault_tokens,
                            daily_emission_tokens = EXCLUDED.daily_emission_tokens,
                            min_hashrate_ths = EXCLUDED.min_hashrate_ths,
                            syndicate_sector_enabled = EXCLUDED.syndicate_sector_enabled,
                            status = 'ACTIVE',
                            funding_tx_hash = COALESCE(EXCLUDED.funding_tx_hash, forge_mineable_vaults.funding_tx_hash),
                            updated_at = CURRENT_TIMESTAMP
                        "#,
                    )
                    .bind(&raw_ticker)
                    .bind(&master_identity)
                    .bind(&vault_label)
                    .bind(funded_tokens)
                    .bind(daily_emission)
                    .bind(min_hashrate_ths)
                    .bind(syndicate_enabled)
                    .bind(&deploy_tx_hash)
                    .execute(&mut *tx_db)
                    .await;
                }
            }
            let _ = tx_db.commit().await;
            let bundle = query_forge_tokenomics_bundle(&pool, Some(&raw_ticker), true).await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: deploy_tx_hash,
                signed_psbt_hex: None,
                data: Some(json!({
                    "ticker": raw_ticker,
                    "tokenStandard": token_standard,
                    "isRetroactiveUpgrade": is_retro,
                    "insertedVestingCount": inserted_vesting_count,
                    "protocolFeeKas": kas_protocol_fee,
                    "kasFeeFirewallEnforced": true,
                    "tokenomics": bundle
                })),
            }));
        },
        "GET_FORGE_TOKENOMICS" => {
            let _ = tx_db.rollback().await;
            let ticker_opt = req
                .payload
                .get("ticker")
                .or_else(|| req.payload.get("tokenTicker"))
                .and_then(|v| v.as_str());
            let include_all = req
                .payload
                .get("includeAllMineableVaults")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let bundle = query_forge_tokenomics_bundle(&pool, ticker_opt, include_all).await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: None,
                signed_psbt_hex: None,
                data: Some(bundle),
            }));
        },
        "FUND_MINEABLE_KRC20_VAULT" => {
            let raw_ticker = req
                .payload
                .get("ticker")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_uppercase();
            let add_tokens: f64 = req
                .payload
                .get("amountTokens")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0)
                .max(0.0);
            let daily_emission: f64 = req
                .payload
                .get("dailyEmissionTokens")
                .and_then(|v| v.as_f64())
                .unwrap_or(add_tokens / 365.0)
                .max(0.0);
            let tx_hash_opt = req
                .payload
                .get("txHash")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string());
            if raw_ticker.len() < 4 || add_tokens <= 0.0 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("Valid KRC-20 ticker and positive token funding amount required.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let _ = sqlx::query(
                r#"
                INSERT INTO forge_mineable_vaults
                (token_ticker, creator_address, total_funded_tokens, remaining_vault_tokens, daily_emission_tokens, status, funding_tx_hash)
                VALUES ($1, $2, $3, $3, $4, 'ACTIVE', $5)
                ON CONFLICT (token_ticker) DO UPDATE SET
                    total_funded_tokens = forge_mineable_vaults.total_funded_tokens + EXCLUDED.total_funded_tokens,
                    remaining_vault_tokens = forge_mineable_vaults.remaining_vault_tokens + EXCLUDED.remaining_vault_tokens,
                    daily_emission_tokens = EXCLUDED.daily_emission_tokens,
                    status = 'ACTIVE',
                    funding_tx_hash = COALESCE(EXCLUDED.funding_tx_hash, forge_mineable_vaults.funding_tx_hash),
                    updated_at = CURRENT_TIMESTAMP
                "#,
            )
            .bind(&raw_ticker)
            .bind(&master_identity)
            .bind(add_tokens)
            .bind(daily_emission)
            .bind(&tx_hash_opt)
            .execute(&mut *tx_db)
            .await;
            let _ = tx_db.commit().await;
            let bundle = query_forge_tokenomics_bundle(&pool, Some(&raw_ticker), true).await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: tx_hash_opt,
                signed_psbt_hex: None,
                data: Some(bundle),
            }));
        },
        "STAKE_SILO" => {
            let eco_ticker = req
                .payload
                .get("ticker")
                .and_then(|t| t.as_str())
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(crate::sor::resolve_ecosystem_ticker);
            let amount = req
                .payload
                .get("amount")
                .and_then(|a| a.as_f64().or_else(|| a.as_str().and_then(|s| s.parse::<f64>().ok())))
                .unwrap_or(0.0);
            let tx_hash_opt = req
                .payload
                .get("txHash")
                .and_then(|t| t.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            if amount <= 0.0 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some(format!("{} stake amount must be greater than zero.", eco_ticker)),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
            if tx_hash_opt.is_none() {
                let debit_res: (i32, String) = redis::cmd("EVAL")
                    .arg(LUA_ATOMIC_DEBIT_SINGLE)
                    .arg(1)
                    .arg(&user_ledger_key)
                    .arg(&eco_ticker)
                    .arg(amount)
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or((0, "0".to_string()));
                if debit_res.0 == 0 {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse {
                        success: false,
                        error: Some(format!(
                            "Insufficient {} balance in Treasury Ledger to stake.",
                            eco_ticker
                        )),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                }
            }
            let existing_active = sqlx::query(
                "SELECT stake_id FROM silo_staking_positions WHERE (wallet_address = $1 OR wallet_address = $2) AND token_ticker = $3 AND status = 'ACTIVE' ORDER BY created_at DESC LIMIT 1"
            )
            .bind(&master_identity)
            .bind(&clean_wallet)
            .bind(&eco_ticker)
            .fetch_optional(&mut *tx_db)
            .await
            .ok()
            .flatten();
            let resolved_stake_id: Uuid = if let Some(row) = existing_active {
                let sid: Uuid = row.get("stake_id");
                let _ = sqlx::query(
                    "UPDATE silo_staking_positions SET amount_staked = amount_staked + $1, tx_hash = COALESCE($2, tx_hash) WHERE stake_id = $3"
                )
                .bind(amount)
                .bind(&tx_hash_opt)
                .bind(sid)
                .execute(&mut *tx_db)
                .await;
                sid
            } else {
                let inserted = sqlx::query(
                    "INSERT INTO silo_staking_positions (wallet_address, token_ticker, amount_staked, status, tx_hash) VALUES ($1, $2, $3, 'ACTIVE', $4) RETURNING stake_id"
                )
                .bind(&master_identity)
                .bind(&eco_ticker)
                .bind(amount)
                .bind(&tx_hash_opt)
                .fetch_one(&mut *tx_db)
                .await
                .map_err(|e| {
                    Json(ActionResponse {
                        success: false,
                        error: Some(format!("Failed to record {} stake: {}", eco_ticker, e)),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    })
                })?;
                inserted.get("stake_id")
            };
            let _ = tx_db.commit().await;
            let tier_info = crate::sor::get_silo_staking_fee_cap(&pool, &clean_wallet, &master_identity).await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: tx_hash_opt,
                signed_psbt_hex: None,
                data: Some(json!({
                    "stakeId": resolved_stake_id.to_string(),
                    "ticker": eco_ticker,
                    "stakedAmount": amount,
                    "feeRateCap": tier_info.as_ref().map(|(r, _, _)| *r).unwrap_or(0.015),
                    "tierLabel": tier_info.as_ref().map(|(_, l, _)| l.clone()).unwrap_or_else(|| "Standard Tier (1.50% Fee)".to_string()),
                    "totalActiveStaked": tier_info.map(|(_, _, s)| s).unwrap_or(amount)
                })),
            }));
        },
        "INITIATE_SILO_COOLDOWN" => {
            let stake_id_str = req.payload.get("stakeId").and_then(|v| v.as_str()).unwrap_or("");
            let stake_uuid = Uuid::from_str(stake_id_str).map_err(|_| {
                Json(ActionResponse {
                    success: false,
                    error: Some("Invalid stakeId format.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                })
            })?;
            let updated = sqlx::query(
                r#"
                UPDATE silo_staking_positions
                SET status = 'COOLDOWN',
                    cooldown_initiated_at = CURRENT_TIMESTAMP,
                    cooldown_ends_at = CURRENT_TIMESTAMP + INTERVAL '7 days'
                WHERE stake_id = $1
                  AND (wallet_address = $2 OR wallet_address = $3)
                  AND status = 'ACTIVE'
                RETURNING cooldown_ends_at, amount_staked, token_ticker
                "#,
            )
            .bind(stake_uuid)
            .bind(&master_identity)
            .bind(&clean_wallet)
            .fetch_optional(&mut *tx_db)
            .await
            .map_err(|e| {
                Json(ActionResponse {
                    success: false,
                    error: Some(format!("Database error initiating cooldown: {}", e)),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                })
            })?;
            let Some(row) = updated else {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("Active SILO stake position not found or already in 7-day cooldown.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            };
            let cooldown_ends: chrono::DateTime<chrono::Utc> = row.get("cooldown_ends_at");
            let amount_staked: f64 = row.get("amount_staked");
            let ticker: String = row.get("token_ticker");
            let _ = tx_db.commit().await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: None,
                signed_psbt_hex: None,
                data: Some(json!({
                    "stakeId": stake_uuid.to_string(),
                    "status": "COOLDOWN",
                    "ticker": ticker,
                    "amountStaked": amount_staked,
                    "cooldownDays": 7,
                    "cooldownEndsAt": cooldown_ends.to_rfc3339()
                })),
            }));
        },
        "CLAIM_UNSTAKED_SILO" => {
            let stake_id_str = req.payload.get("stakeId").and_then(|v| v.as_str()).unwrap_or("");
            let stake_uuid = Uuid::from_str(stake_id_str).map_err(|_| {
                Json(ActionResponse {
                    success: false,
                    error: Some("Invalid stakeId format.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                })
            })?;
            let row_opt = sqlx::query(
                r#"
                SELECT stake_id, token_ticker, amount_staked, status, cooldown_ends_at,
                       (cooldown_ends_at IS NOT NULL AND CURRENT_TIMESTAMP >= cooldown_ends_at) AS is_matured
                FROM silo_staking_positions
                WHERE stake_id = $1 AND (wallet_address = $2 OR wallet_address = $3)
                FOR UPDATE
                "#,
            )
            .bind(stake_uuid)
            .bind(&master_identity)
            .bind(&clean_wallet)
            .fetch_optional(&mut *tx_db)
            .await
            .map_err(|e| {
                Json(ActionResponse {
                    success: false,
                    error: Some(format!("Database lookup failed: {}", e)),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                })
            })?;
            let Some(row) = row_opt else {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("SILO stake position not found.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            };
            let status: String = row.get("status");
            let is_matured: bool = row.try_get("is_matured").unwrap_or(false);
            let cooldown_ends_opt: Option<chrono::DateTime<chrono::Utc>> = row.try_get("cooldown_ends_at").ok();
            if status != "COOLDOWN" || !is_matured {
                let _ = tx_db.rollback().await;
                let unlock_label = cooldown_ends_opt
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| "7 days after initiating cooldown".to_string());
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some(format!(
                        "COOLDOWN_LOCK_ACTIVE: 7-day unbonding cooldown is active until {}.",
                        unlock_label
                    )),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let amount_staked: f64 = row.get("amount_staked");
            let token_ticker: String = row.get("token_ticker");
            sqlx::query("DELETE FROM silo_staking_positions WHERE stake_id = $1")
                .bind(stake_uuid)
                .execute(&mut *tx_db)
                .await
                .map_err(|e| {
                    Json(ActionResponse {
                        success: false,
                        error: Some(format!("Failed to finalize unstake: {}", e)),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    })
                })?;
            let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
            let _: () = redis::cmd("HINCRBYFLOAT")
                .arg(&user_ledger_key)
                .arg(&token_ticker)
                .arg(amount_staked)
                .query_async(&mut redis_conn)
                .await
                .map_err(|e| {
                    Json(ActionResponse {
                        success: false,
                        error: Some(format!("Redis credit failed during SILO claim: {}", e)),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    })
                })?;
            let _ = tx_db.commit().await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: None,
                signed_psbt_hex: None,
                data: Some(json!({
                    "stakeId": stake_uuid.to_string(),
                    "claimedAmount": amount_staked,
                    "ticker": token_ticker
                })),
            }));
        },
        "GET_SILO_STAKING" => {
            let rows = sqlx::query(
                r#"
                SELECT stake_id, token_ticker, amount_staked, status, tx_hash,
                       cooldown_initiated_at, cooldown_ends_at, created_at,
                       (cooldown_ends_at IS NOT NULL AND CURRENT_TIMESTAMP >= cooldown_ends_at) AS is_matured
                FROM silo_staking_positions
                WHERE wallet_address = $1 OR wallet_address = $2
                ORDER BY created_at DESC
                "#,
            )
            .bind(&master_identity)
            .bind(&clean_wallet)
            .fetch_all(&mut *tx_db)
            .await
            .unwrap_or_default();
            let _ = tx_db.rollback().await;
            let mut positions = Vec::new();
            let mut active_staked_total = 0.0;
            let mut cooldown_staked_total = 0.0;
            for r in rows {
                let sid: Uuid = r.get("stake_id");
                let ticker: String = r.get("token_ticker");
                let amt: f64 = r.get("amount_staked");
                let st: String = r.get("status");
                let tx_h: Option<String> = r.try_get("tx_hash").ok();
                let cd_init: Option<chrono::DateTime<chrono::Utc>> = r.try_get("cooldown_initiated_at").ok();
                let cd_end: Option<chrono::DateTime<chrono::Utc>> = r.try_get("cooldown_ends_at").ok();
                let created: Option<chrono::DateTime<chrono::Utc>> = r.try_get("created_at").ok();
                let matured: bool = r.try_get("is_matured").unwrap_or(false);
                if st == "ACTIVE" {
                    active_staked_total += amt;
                } else {
                    cooldown_staked_total += amt;
                }
                positions.push(json!({
                    "stakeId": sid.to_string(),
                    "ticker": ticker,
                    "amountStaked": amt,
                    "status": st,
                    "txHash": tx_h,
                    "cooldownInitiatedAt": cd_init.map(|d| d.to_rfc3339()),
                    "cooldownEndsAt": cd_end.map(|d| d.to_rfc3339()),
                    "createdAt": created.map(|d| d.to_rfc3339()),
                    "isMatured": matured
                }));
            }
            let tier_info = crate::sor::get_silo_staking_fee_cap(&pool, &clean_wallet, &master_identity).await;
            let (fee_rate_cap, tier_label, combined_staked) = tier_info.unwrap_or((
                0.015,
                "Standard Tier (1.50% Fee)".to_string(),
                active_staked_total,
            ));
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: None,
                signed_psbt_hex: None,
                data: Some(json!({
                    "ecosystemTicker": crate::sor::resolve_ecosystem_ticker(),
                    "activeStaked": active_staked_total,
                    "cooldownStaked": cooldown_staked_total,
                    "combinedEligibleStaked": combined_staked,
                    "feeRateCap": fee_rate_cap,
                    "tierLabel": tier_label,
                    "positions": positions
                })),
            }));
        },
        "UPDATE_TAX_FORTRESS" => {
            let existing_tf = state.get("taxFortress").cloned().unwrap_or_else(|| json!({}));
            let escrow_active = req
                .payload
                .get("escrowActive")
                .and_then(|v| v.as_bool())
                .or_else(|| existing_tf.get("escrowActive").and_then(|v| v.as_bool()))
                .unwrap_or(false);
            let raw_rate: f64 = req
                .payload
                .get("withholdingRate")
                .or_else(|| req.payload.get("effectiveTaxRate"))
                .and_then(|v| v.as_f64())
                .or_else(|| existing_tf.get("withholdingRate").and_then(|v| v.as_f64()))
                .unwrap_or(15.0_f64);
            let normalized_rate_pct: f64 = if raw_rate > 0.0_f64 && raw_rate < 1.0_f64 {
                (raw_rate * 100.0_f64).clamp(0.0_f64, 50.0_f64)
            } else {
                raw_rate.clamp(0.0_f64, 50.0_f64)
            };
            let country_code = req
                .payload
                .get("countryCode")
                .and_then(|v| v.as_str())
                .or_else(|| existing_tf.get("countryCode").and_then(|v| v.as_str()))
                .unwrap_or("US")
                .trim()
                .to_uppercase();
            let state_region = req
                .payload
                .get("stateRegion")
                .and_then(|v| v.as_str())
                .or_else(|| existing_tf.get("stateRegion").and_then(|v| v.as_str()))
                .unwrap_or("TX")
                .trim()
                .to_uppercase();
            let jurisdiction_code = req
                .payload
                .get("jurisdictionCode")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_uppercase())
                .unwrap_or_else(|| format!("{}-{}", country_code, state_region));
            let entity_type = req
                .payload
                .get("entityType")
                .and_then(|v| v.as_str())
                .or_else(|| existing_tf.get("entityType").and_then(|v| v.as_str()))
                .unwrap_or("LLC")
                .trim()
                .to_uppercase();
            let filing_status = req
                .payload
                .get("filingStatus")
                .and_then(|v| v.as_str())
                .or_else(|| existing_tf.get("filingStatus").and_then(|v| v.as_str()))
                .unwrap_or("SINGLE")
                .trim()
                .to_uppercase();
            let default_maturity = "2027-01-15";
            let raw_maturity = req
                .payload
                .get("maturityDate")
                .and_then(|v| v.as_str())
                .or_else(|| existing_tf.get("maturityDate").and_then(|v| v.as_str()))
                .unwrap_or(default_maturity)
                .trim();
            let maturity_date = if raw_maturity.is_empty()
                || raw_maturity == "2027-04-15"
                || raw_maturity == "2027-03-15"
            {
                default_maturity.to_string()
            } else {
                raw_maturity.to_string()
            };
            let rounded_rate: f64 = (normalized_rate_pct * 100.0_f64).round() / 100.0_f64;
            state["taxFortress"] = json!({
                "escrowActive": escrow_active,
                "withholdingRate": rounded_rate,
                "jurisdictionCode": jurisdiction_code,
                "countryCode": country_code,
                "stateRegion": state_region,
                "entityType": entity_type,
                "filingStatus": filing_status,
                "maturityDate": maturity_date,
                "accountingMethod": "PASSIVE_HIFO_NO_WASH",
                "lockDurationDays": 0,
                "isUnlocked": true,
                "updatedAt": chrono::Utc::now().to_rfc3339()
            });
            let _ = sqlx::query(
                "UPDATE liquidity_providers SET lock_duration_days = 0, unlock_date = CURRENT_TIMESTAMP WHERE (wallet_address = $1 OR wallet_address = $2) AND pool_pair = 'KAS/USDC'"
            )
            .bind(&master_identity)
            .bind(&clean_wallet)
            .execute(&mut *tx_db)
            .await;
            let _ = sqlx::query(
                r#"
                INSERT INTO entity_kyc
                (wallet_address, legal_name, entity_type, tax_id_hash, business_address, country_code, state_region, filing_status, effective_tax_rate, verification_status, verified_at)
                VALUES ($1, 'ZERO_PII_SOVEREIGN', $2, 'ZERO_PII_LOCAL_ONLY', 'ZERO_PII_LOCAL_ONLY', $3, $4, $5, $6, 'verified', CURRENT_TIMESTAMP)
                ON CONFLICT (wallet_address) DO UPDATE SET
                    legal_name = 'ZERO_PII_SOVEREIGN',
                    entity_type = EXCLUDED.entity_type,
                    tax_id_hash = 'ZERO_PII_LOCAL_ONLY',
                    business_address = 'ZERO_PII_LOCAL_ONLY',
                    country_code = EXCLUDED.country_code,
                    state_region = EXCLUDED.state_region,
                    filing_status = EXCLUDED.filing_status,
                    effective_tax_rate = EXCLUDED.effective_tax_rate,
                    verification_status = 'verified',
                    verified_at = CURRENT_TIMESTAMP
                "#
            )
            .bind(&master_identity)
            .bind(&entity_type)
            .bind(&country_code)
            .bind(&state_region)
            .bind(&filing_status)
            .bind(rounded_rate)
            .execute(&mut *tx_db)
            .await;
        },
        "UNLOCK_TAX_ESCROW_LP" => {
            if let Some(tf_obj) = state.get_mut("taxFortress").and_then(|v| v.as_object_mut()) {
                tf_obj.insert("escrowActive".to_string(), json!(false));
                tf_obj.insert("lockDurationDays".to_string(), json!(0));
                tf_obj.insert("isUnlocked".to_string(), json!(true));
                tf_obj.insert("maturityDate".to_string(), json!("2027-01-15"));
                tf_obj.insert("updatedAt".to_string(), json!(chrono::Utc::now().to_rfc3339()));
            } else {
                state["taxFortress"] = json!({
                    "escrowActive": false,
                    "withholdingRate": 15.0,
                    "jurisdictionCode": "US-TX",
                    "countryCode": "US",
                    "stateRegion": "TX",
                    "entityType": "LLC",
                    "filingStatus": "SINGLE",
                    "maturityDate": "2027-01-15",
                    "accountingMethod": "PASSIVE_HIFO_NO_WASH",
                    "lockDurationDays": 0,
                    "isUnlocked": true,
                    "updatedAt": chrono::Utc::now().to_rfc3339()
                });
            }
            let escrow_lps = sqlx::query(
                "SELECT lp_id, staked_asset_a, staked_asset_b FROM liquidity_providers WHERE (wallet_address = $1 OR wallet_address = $2) AND pool_pair = 'KAS/USDC'"
            )
            .bind(&master_identity)
            .bind(&clean_wallet)
            .fetch_all(&mut *tx_db)
            .await
            .unwrap_or_default();
            let mut withdrawn_kas = 0.0_f64;
            let mut withdrawn_usdc = 0.0_f64;
            for lp_row in &escrow_lps {
                let lp_id: Uuid = lp_row.get("lp_id");
                let sa: f64 = lp_row
                    .try_get::<f64, _>("staked_asset_a")
                    .unwrap_or(0.0_f64)
                    .max(0.0_f64);
                let sb: f64 = lp_row
                    .try_get::<f64, _>("staked_asset_b")
                    .unwrap_or(0.0_f64)
                    .max(0.0_f64);
                withdrawn_kas += sa;
                withdrawn_usdc += sb;
                let _ = sqlx::query("DELETE FROM liquidity_providers WHERE lp_id = $1")
                    .bind(lp_id)
                    .execute(&mut *tx_db)
                    .await;
            }
            if withdrawn_kas > 0.0 || withdrawn_usdc > 0.0 {
                let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
                let mut pipe = redis::pipe();
                if withdrawn_kas > 0.0 {
                    pipe.cmd("HINCRBYFLOAT").arg(&user_ledger_key).arg("KAS").arg(withdrawn_kas).ignore();
                }
                if withdrawn_usdc > 0.0 {
                    pipe.cmd("HINCRBYFLOAT").arg(&user_ledger_key).arg("USDC").arg(withdrawn_usdc).ignore();
                }
                let _: Result<(), _> = pipe.query_async(&mut redis_conn).await;
            }
            let _ = sqlx::query(
                "INSERT INTO user_command_centers (wallet_address, layout_state, last_updated)
                 VALUES ($1, $2, CURRENT_TIMESTAMP)
                 ON CONFLICT (wallet_address) DO UPDATE SET layout_state = EXCLUDED.layout_state, last_updated = CURRENT_TIMESTAMP"
            )
            .bind(&master_identity)
            .bind(&state)
            .execute(&mut *tx_db)
            .await;
            let _ = tx_db.commit().await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: None,
                signed_psbt_hex: None,
                data: Some(json!({
                    "escrowActive": false,
                    "isUnlocked": true,
                    "withdrawnKas": withdrawn_kas,
                    "withdrawnUsdc": withdrawn_usdc,
                    "message": format!(
                        "Tax Escrow Auto-LP unlocked and withdrawn (+{:.4} KAS, +{:.2} USDC credited to your personal ledger).",
                        withdrawn_kas, withdrawn_usdc
                    )
                })),
            }));
        },
        "WITHDRAW_SYNTHETIC_ASSET" => {
            let destination = req.payload
                .get("destination")
                .or_else(|| req.payload.get("destinationAddress"))
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let amount = req.payload
                .get("amount")
                .and_then(|a| a.as_f64().or_else(|| a.as_str().and_then(|s| s.parse::<f64>().ok())))
                .unwrap_or(0.0);
            let asset = req.payload
                .get("asset")
                .and_then(|a| a.as_str())
                .unwrap_or("KAS")
                .trim()
                .to_uppercase();
            if destination.is_empty() || amount <= 0.0 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("Missing destination address or valid withdrawal amount.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
            let debit_res: (i32, String) = redis::cmd("EVAL")
                .arg(LUA_ATOMIC_DEBIT_SINGLE)
                .arg(1)
                .arg(&user_ledger_key)
                .arg(&asset)
                .arg(amount)
                .query_async(&mut redis_conn)
                .await
                .unwrap_or((0, "0".to_string()));
            if debit_res.0 == 0 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some(format!("Insufficient {} balance in Batch Settlement Queue / Treasury Ledger.", asset)),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let from_unassigned = debit_res.1.parse::<f64>().unwrap_or(0.0);
            if from_unassigned > 1e-9 {
                let _ = sqlx::query(
                    "UPDATE yield_reservoirs SET streaming_balance_kas = GREATEST(0.0, streaming_balance_kas - $1), last_updated = CURRENT_TIMESTAMP WHERE LOWER(REPLACE(TRIM(wallet_address), 'kaspa:', '')) = $2 OR wallet_address = $3"
                )
                .bind(from_unassigned)
                .bind(&clean_wallet)
                .bind(&master_identity)
                .execute(&mut *tx_db)
                .await;
            }
            let spot_price = get_spot_usd(&mut redis_conn, &asset).await;
            let (tx_id, dispatch_status, explorer_url) = dispatch_or_queue_multi_chain_l1(
                &mut tx_db,
                &mut redis_conn,
                &master_identity,
                &clean_wallet,
                &destination,
                &asset,
                amount,
                spot_price,
                "ledger_withdrawal",
            )
            .await;
            let _ = tx_db.commit().await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: Some(tx_id.clone()),
                signed_psbt_hex: None,
                data: Some(json!({
                    "txHash": tx_id,
                    "status": dispatch_status,
                    "explorerUrl": explorer_url,
                    "asset": asset,
                    "amount": amount,
                    "destination": destination
                })),
            }));
        },
        "DISPATCH_OTC_UTXOS" => {
            let destination = req.payload.get("destination").and_then(|d| d.as_str()).unwrap_or("");
            let amount = req.payload.get("amount").and_then(|a| a.as_f64()).unwrap_or(0.0);
            let asset = req.payload.get("asset").and_then(|a| a.as_str()).unwrap_or("KAS").to_uppercase();
            if destination.is_empty() || amount <= 0.0 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("Missing destination or valid amount for OTC dispatch.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            if asset == "KAS" {
                let idemp_key = format!(
                    "OTC-DISPATCH-{}-{:.4}-{}",
                    destination,
                    amount,
                    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() / 30
                );
                let payouts_vec = vec![(destination.to_string(), amount)];
                match crate::sor::execute_idempotent_mass_physical_settlement(&pool, &idemp_key, &payouts_vec).await {
                    Ok(tx_id) => {
                        let _ = tx_db.commit().await;
                        return Ok(Json(ActionResponse {
                            success: true,
                            error: None,
                            transaction_id: Some(tx_id),
                            signed_psbt_hex: None,
                            data: None,
                        }));
                    }
                    Err(_) => {
                        let spot_price = get_spot_usd(&mut redis_conn, "KAS").await;
                        let (tx_id, status, explorer_url) = dispatch_or_queue_multi_chain_l1(
                            &mut tx_db,
                            &mut redis_conn,
                            &master_identity,
                            &clean_wallet,
                            destination,
                            "KAS",
                            amount,
                            spot_price,
                            "otc_dispatch",
                        )
                        .await;
                        let _ = tx_db.commit().await;
                        return Ok(Json(ActionResponse {
                            success: true,
                            error: None,
                            transaction_id: Some(tx_id),
                            signed_psbt_hex: None,
                            data: Some(json!({ "status": status, "explorerUrl": explorer_url })),
                        }));
                    }
                }
            } else {
                let spot_price = get_spot_usd(&mut redis_conn, &asset).await;
                let (tx_id, status, explorer_url) = dispatch_or_queue_multi_chain_l1(
                    &mut tx_db,
                    &mut redis_conn,
                    &master_identity,
                    &clean_wallet,
                    destination,
                    &asset,
                    amount,
                    spot_price,
                    "otc_dispatch",
                )
                .await;
                let _ = tx_db.commit().await;
                return Ok(Json(ActionResponse {
                    success: true,
                    error: None,
                    transaction_id: Some(tx_id),
                    signed_psbt_hex: None,
                    data: Some(json!({ "status": status, "explorerUrl": explorer_url })),
                }));
            }
        },
        "STAKE_LP" => {
            let lock_days = req.payload.get("lockDurationDays").and_then(|d| d.as_i64()).unwrap_or(0) as i32;
            if lock_days != 0 && lock_days != 30 && lock_days != 90 && lock_days != 365 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("Invalid lock duration. Permitted periods: 0 (Flexible), 30, 90, or 365 days.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let raw_pair = req.payload.get("poolPair").and_then(|p| p.as_str()).unwrap_or("KAS/USDC");
            let amount_a: f64 = req.payload.get("amountA").and_then(|a| a.as_f64()).unwrap_or(0.0_f64);
            let amount_b: f64 = req.payload.get("amountB").and_then(|b| b.as_f64()).unwrap_or(0.0_f64);
            let eco_ticker = crate::sor::resolve_ecosystem_ticker();
            let mut reserves_map: HashMap<String, f64> = HashMap::new();
            let mut weights_map: HashMap<String, f64> = HashMap::new();
            let mut secondary_order: Vec<String> = Vec::new();
            if let Some(sec_arr) = req.payload.get("secondaryAssets").and_then(|v| v.as_array()) {
                if !sec_arr.is_empty() && amount_a > 0.0_f64 {
                    reserves_map.insert("KAS".to_string(), amount_a);
                    weights_map.insert("KAS".to_string(), 0.50_f64);
                    let mut raw_sec_weights: Vec<(String, f64, f64)> = Vec::new();
                    for item in sec_arr {
                        let tick = item
                            .get("ticker")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .trim()
                            .to_uppercase();
                        let amt: f64 = item.get("amount").and_then(|v| v.as_f64()).unwrap_or(0.0_f64);
                        let w_pct: f64 = item
                            .get("weightPct")
                            .or_else(|| item.get("weight"))
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0_f64);
                        if !tick.is_empty() && tick != "KAS" && amt > 0.0_f64 {
                            raw_sec_weights.push((tick, w_pct.max(0.0_f64), amt));
                        }
                    }
                    let w_sum: f64 = raw_sec_weights.iter().map(|(_, w, _)| *w).sum();
                    let n_sec = raw_sec_weights.len();
                    for (t, w, amt) in raw_sec_weights {
                        let norm_w: f64 = if w_sum > 0.0_f64 {
                            (w / w_sum) * 0.50_f64
                        } else if n_sec > 0 {
                            0.50_f64 / (n_sec as f64)
                        } else {
                            0.50_f64
                        };
                        secondary_order.push(t.clone());
                        reserves_map.insert(t.clone(), amt);
                        weights_map.insert(t, norm_w);
                    }
                }
            }
            if reserves_map.is_empty() {
                if let (Some(r_obj), Some(w_obj)) = (
                    req.payload.get("reserves").and_then(|v| v.as_object()),
                    req.payload.get("weights").and_then(|v| v.as_object()),
                ) {
                    for (k, v) in r_obj {
                        let clean = k.trim().to_uppercase();
                        if let Some(amt) = v.as_f64() {
                            if amt > 0.0_f64 {
                                reserves_map.insert(clean.clone(), amt);
                                if clean != "KAS" {
                                    secondary_order.push(clean);
                                }
                            }
                        }
                    }
                    weights_map.insert("KAS".to_string(), 0.50_f64);
                    let mut sec_w_sum: f64 = 0.0_f64;
                    for sec in &secondary_order {
                        let w: f64 = w_obj
                            .get(sec)
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0_f64)
                            .max(0.0_f64);
                        sec_w_sum += w;
                    }
                    let n_sec = secondary_order.len();
                    for sec in &secondary_order {
                        let raw_w: f64 = w_obj
                            .get(sec)
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0_f64)
                            .max(0.0_f64);
                        let norm_w: f64 = if sec_w_sum > 0.0_f64 {
                            (raw_w / sec_w_sum) * 0.50_f64
                        } else if n_sec > 0 {
                            0.50_f64 / (n_sec as f64)
                        } else {
                            0.50_f64
                        };
                        weights_map.insert(sec.clone(), norm_w);
                    }
                }
            }
            if reserves_map.is_empty() {
                let pair_parts: Vec<String> = raw_pair
                    .split('/')
                    .map(|s| s.trim().to_uppercase())
                    .filter(|s| !s.is_empty())
                    .collect();
                let asset_a = pair_parts.first().cloned().unwrap_or_else(|| "KAS".to_string());
                let asset_b = pair_parts.get(1).cloned().unwrap_or_else(|| "USDC".to_string());
                if asset_a != "KAS" || amount_a <= 0.0_f64 || amount_b <= 0.0_f64 {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse {
                        success: false,
                        error: Some("Liquidity Plant staking requires KAS anchored at 50% with positive amounts.".to_string()),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                }
                reserves_map.insert("KAS".to_string(), amount_a);
                reserves_map.insert(asset_b.clone(), amount_b);
                weights_map.insert("KAS".to_string(), 0.50_f64);
                weights_map.insert(asset_b.clone(), 0.50_f64);
                secondary_order.push(asset_b);
            }
            let kas_amount: f64 = reserves_map.get("KAS").copied().unwrap_or(0.0_f64);
            if kas_amount <= 0.0_f64 || secondary_order.is_empty() {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("Liquidity Plant requires 50% KAS and at least 1 secondary asset.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            for sec_ticker in &secondary_order {
                let is_eligible = crate::oracle::is_oracle_supported_asset(sec_ticker)
                    || *sec_ticker == eco_ticker;
                if *sec_ticker == "KAS" || !is_eligible {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse {
                        success: false,
                        error: Some(format!(
                            "UNSUPPORTED_LP_ASSET: Liquidity Plant asset {} is not backed by a verified 7-Node or Pyth Hermes oracle feed.",
                            sec_ticker
                        )),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                }
            }
            let kas_usd: f64 = get_spot_usd(&mut redis_conn, "KAS").await;
            if kas_usd <= 0.0_f64 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some("ORACLE_HALT: Live KAS/USDC spot feed is required to provision Liquidity Plants.".to_string()),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let mut total_stake_usd: f64 = kas_amount * kas_usd;
            let mut secondary_total_b: f64 = 0.0_f64;
            for (idx, sec_ticker) in secondary_order.iter().enumerate() {
                let sec_amt: f64 = reserves_map.get(sec_ticker).copied().unwrap_or(0.0_f64);
                let sec_usd: f64 = get_spot_usd(&mut redis_conn, sec_ticker).await;
                if sec_usd <= 0.0_f64 && *sec_ticker != eco_ticker {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse {
                        success: false,
                        error: Some(format!(
                            "ORACLE_HALT: Live oracle spot feed for {} is currently unavailable.",
                            sec_ticker
                        )),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                }
                total_stake_usd += sec_amt * sec_usd;
                if secondary_order.len() == 1 || idx == 0 {
                    secondary_total_b = if secondary_order.len() == 1 {
                        sec_amt
                    } else {
                        secondary_total_b + (sec_amt * sec_usd)
                    };
                } else {
                    secondary_total_b += sec_amt * sec_usd;
                }
            }
            let min_position_usd = crate::sor::get_min_dark_pool_position_usd();
            if total_stake_usd < min_position_usd {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some(format!(
                        "ANTI_DUST_GUARD: Liquidity Plant stake value (${:.2} USD) is below the minimum position floor (${:.2} USD).",
                        total_stake_usd, min_position_usd
                    )),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
            let mut eval_cmd = redis::cmd("EVAL");
            eval_cmd
                .arg(LUA_ATOMIC_DEBIT_MULTI_LP)
                .arg(1)
                .arg(&user_ledger_key)
                .arg(reserves_map.len());
            for (asset_tick, req_amt) in &reserves_map {
                eval_cmd.arg(asset_tick).arg(*req_amt);
            }
            let debit_res: (i32, String, String) = eval_cmd
                .query_async(&mut redis_conn)
                .await
                .unwrap_or((0, "0".to_string(), "REDIS_EVAL_ERR".to_string()));
            if debit_res.0 == 0 {
                let _ = tx_db.rollback().await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some(format!(
                        "Insufficient {} balance in Treasury Ledger to provision Liquidity Plant.",
                        debit_res.2
                    )),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let from_unassigned = debit_res.1.parse::<f64>().unwrap_or(0.0);
            if from_unassigned > 1e-9 {
                let _ = sqlx::query(
                    "UPDATE yield_reservoirs SET streaming_balance_kas = GREATEST(0.0, streaming_balance_kas - $1), last_updated = CURRENT_TIMESTAMP WHERE LOWER(REPLACE(TRIM(wallet_address), 'kaspa:', '')) = $2 OR wallet_address = $3"
                )
                .bind(from_unassigned)
                .bind(&clean_wallet)
                .bind(&master_identity)
                .execute(&mut *tx_db)
                .await;
            }
            let mut full_tickers = vec!["KAS".to_string()];
            full_tickers.extend(secondary_order.clone());
            let normalized_pair = full_tickers.join("/");
            let weights_json_val = serde_json::to_value(&weights_map).unwrap_or_else(|_| json!({}));
            let reserves_json_val = serde_json::to_value(&reserves_map).unwrap_or_else(|_| json!({}));
            let invariant_k = crate::sor::compute_constant_mean_invariant(&reserves_map, &weights_map);
            let n_total = full_tickers.len();
            let internal_pairs_count = (n_total * n_total.saturating_sub(1)) / 2;
            let insert_res = if lock_days == 0 {
                sqlx::query(
                    r#"
                    INSERT INTO liquidity_providers
                    (wallet_address, pool_pair, staked_asset_a, staked_asset_b, weights_json, reserves_json, lock_duration_days, unlock_date)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
                    "#
                )
                .bind(&master_identity)
                .bind(&normalized_pair)
                .bind(kas_amount)
                .bind(secondary_total_b)
                .bind(&weights_json_val)
                .bind(&reserves_json_val)
                .bind(lock_days)
                .execute(&mut *tx_db)
                .await
            } else {
                sqlx::query(
                    r#"
                    INSERT INTO liquidity_providers
                    (wallet_address, pool_pair, staked_asset_a, staked_asset_b, weights_json, reserves_json, lock_duration_days, unlock_date)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP + make_interval(days => $7))
                    "#
                )
                .bind(&master_identity)
                .bind(&normalized_pair)
                .bind(kas_amount)
                .bind(secondary_total_b)
                .bind(&weights_json_val)
                .bind(&reserves_json_val)
                .bind(lock_days)
                .execute(&mut *tx_db)
                .await
            };
            if let Err(e) = insert_res {
                let _ = tx_db.rollback().await;
                let mut refund_pipe = redis::pipe();
                for (asset_tick, req_amt) in &reserves_map {
                    refund_pipe.cmd("HINCRBYFLOAT").arg(&user_ledger_key).arg(asset_tick).arg(*req_amt).ignore();
                }
                let _: Result<(), _> = refund_pipe.query_async(&mut redis_conn).await;
                return Err(Json(ActionResponse {
                    success: false,
                    error: Some(format!("Database execution error during Liquidity Plant staking: {}", e)),
                    transaction_id: None,
                    signed_psbt_hex: None,
                    data: None,
                }));
            }
            let _ = tx_db.commit().await;
            return Ok(Json(ActionResponse {
                success: true,
                error: None,
                transaction_id: None,
                signed_psbt_hex: None,
                data: Some(json!({
                    "poolPair": normalized_pair,
                    "weights": weights_json_val,
                    "reserves": reserves_json_val,
                    "invariantK": invariant_k,
                    "internalPairsCount": internal_pairs_count
                })),
            }));
        },
        "GET_LP_POSITIONS" => {
            let has_tax_escrow_configured = state.get("taxFortress").is_some();
            let positions = sqlx::query(
                r#"
                SELECT
                    lp_id,
                    pool_pair,
                    staked_asset_a,
                    staked_asset_b,
                    weights_json,
                    reserves_json,
                    lock_duration_days,
                    unlock_date,
                    created_at,
                    (CURRENT_TIMESTAMP >= unlock_date OR lock_duration_days <= 0) AS is_unlocked
                FROM liquidity_providers
                WHERE wallet_address = $1 OR wallet_address = $2
                ORDER BY created_at DESC
                "#
            )
            .bind(&master_identity)
            .bind(&clean_wallet)
            .fetch_all(&mut *tx_db)
            .await;
            let _ = tx_db.rollback().await;
            match positions {
                Ok(rows) => {
                    let list: Vec<Value> = rows.into_iter().map(|r| {
                        let lp_id: Uuid = r.get("lp_id");
                        let pool_pair: String = r.get("pool_pair");
                        let staked_a: f64 = r.get("staked_asset_a");
                        let staked_b: f64 = r.get("staked_asset_b");
                        let mut lock_days: i32 = r.get("lock_duration_days");
                        let unlock_date: Option<chrono::DateTime<chrono::Utc>> = r.try_get("unlock_date").ok();
                        let created_at: Option<chrono::DateTime<chrono::Utc>> = r.try_get("created_at").ok();
                        let mut is_unlocked: bool = r.try_get("is_unlocked").unwrap_or(true);
                        if has_tax_escrow_configured && pool_pair == "KAS/USDC" {
                            lock_days = 0;
                            is_unlocked = true;
                        }
                        let mut weights_val: Value = r.try_get("weights_json").unwrap_or_else(|_| json!({}));
                        let mut reserves_val: Value = r.try_get("reserves_json").unwrap_or_else(|_| json!({}));
                        let parts: Vec<String> = pool_pair.split('/').map(|s| s.trim().to_uppercase()).collect();
                        if weights_val.as_object().map(|m| m.is_empty()).unwrap_or(true) {
                            let mut w_map = serde_json::Map::new();
                            w_map.insert("KAS".to_string(), json!(0.50_f64));
                            let sec_count = parts.len().saturating_sub(1).max(1);
                            for sec in parts.iter().skip(1) {
                                w_map.insert(sec.clone(), json!(0.50_f64 / (sec_count as f64)));
                            }
                            weights_val = Value::Object(w_map);
                        }
                        if reserves_val.as_object().map(|m| m.is_empty()).unwrap_or(true) {
                            let mut r_map = serde_json::Map::new();
                            r_map.insert("KAS".to_string(), json!(staked_a));
                            if let Some(sec) = parts.get(1) {
                                r_map.insert(sec.clone(), json!(staked_b));
                            }
                            reserves_val = Value::Object(r_map);
                        }
                        let mut r_hash: HashMap<String, f64> = HashMap::new();
                        let mut w_hash: HashMap<String, f64> = HashMap::new();
                        if let Some(obj) = reserves_val.as_object() {
                            for (k, v) in obj {
                                if let Some(f) = v.as_f64() {
                                    r_hash.insert(k.clone(), f);
                                }
                            }
                        }
                        if let Some(obj) = weights_val.as_object() {
                            for (k, v) in obj {
                                if let Some(f) = v.as_f64() {
                                    w_hash.insert(k.clone(), f);
                                }
                            }
                        }
                        let invariant_k = crate::sor::compute_constant_mean_invariant(&r_hash, &w_hash);
                        let n_assets = parts.len().max(2);
                        let internal_pairs_count = (n_assets * (n_assets - 1)) / 2;
                        let multiplier = match lock_days {
                            d if d >= 365 => 2.5,
                            d if d >= 90 => 1.5,
                            d if d >= 30 => 1.2,
                            _ => 1.0,
                        };
                        let weighted_tvl = staked_a * multiplier;
                        json!({
                            "lpId": lp_id.to_string(),
                            "poolPair": pool_pair,
                            "stakedAssetA": staked_a,
                            "stakedAssetB": staked_b,
                            "weights": weights_val,
                            "reserves": reserves_val,
                            "invariantK": invariant_k,
                            "internalPairsCount": internal_pairs_count,
                            "isMultiAssetPlant": parts.len() > 2,
                            "lockDurationDays": lock_days,
                            "unlockDate": unlock_date.map(|d| d.to_rfc3339()),
                            "createdAt": created_at.map(|d| d.to_rfc3339()),
                            "isUnlocked": is_unlocked,
                            "multiplier": multiplier,
                            "weightedTvl": weighted_tvl
                        })
                    }).collect();
                    return Ok(Json(ActionResponse {
                        success: true,
                        error: None,
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: Some(json!(list)),
                    }));
                },
                Err(e) => {
                    return Err(Json(ActionResponse {
                        success: false,
                        error: Some(format!("Database error fetching LP positions: {}", e)),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                }
            }
        },
        "WITHDRAW_LP" => {
            let lp_id_str = req.payload.get("lpId").and_then(|id| id.as_str()).unwrap_or("");
            let lp_uuid = match Uuid::from_str(lp_id_str) {
                Ok(u) => u,
                Err(_) => {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse {
                        success: false,
                        error: Some("Invalid LP identifier format".to_string()),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                }
            };
            let has_tax_escrow_configured = state.get("taxFortress").is_some();
            let row = sqlx::query(
                r#"
                SELECT
                    lp_id,
                    pool_pair,
                    staked_asset_a,
                    staked_asset_b,
                    reserves_json,
                    lock_duration_days,
                    unlock_date,
                    (CURRENT_TIMESTAMP >= unlock_date OR lock_duration_days <= 0) AS is_unlocked
                FROM liquidity_providers
                WHERE lp_id = $1 AND (wallet_address = $2 OR wallet_address = $3)
                FOR UPDATE
                "#
            )
            .bind(lp_uuid)
            .bind(&master_identity)
            .bind(&clean_wallet)
            .fetch_optional(&mut *tx_db)
            .await;
            match row {
                Ok(Some(record)) => {
                    let pool_pair: String = record.get("pool_pair");
                    let is_unlocked_db: bool = record.try_get("is_unlocked").unwrap_or(false);
                    let is_tax_escrow_pair = has_tax_escrow_configured && pool_pair == "KAS/USDC";
                    let is_unlocked = is_unlocked_db || is_tax_escrow_pair;
                    let unlock_date: Option<chrono::DateTime<chrono::Utc>> = record.try_get("unlock_date").ok();
                    if !is_unlocked {
                        let unlock_str = unlock_date.map(|d| d.to_rfc3339()).unwrap_or_else(|| "Unknown".to_string());
                        let _ = tx_db.rollback().await;
                        return Err(Json(ActionResponse {
                            success: false,
                            error: Some(format!(
                                "EARLY_WITHDRAWAL_FORBIDDEN: Capital is timelocked until {}. Protocol-enforced supply shock active.",
                                unlock_str
                            )),
                            transaction_id: None,
                            signed_psbt_hex: None,
                            data: None,
                        }));
                    }
                    let rec_lp_id: Uuid = record.get("lp_id");
                    let staked_a: f64 = record.get("staked_asset_a");
                    let staked_b: f64 = record.get("staked_asset_b");
                    let reserves_val: Value = record.try_get("reserves_json").unwrap_or_else(|_| json!({}));
                    let del_res = sqlx::query("DELETE FROM liquidity_providers WHERE lp_id = $1")
                        .bind(rec_lp_id)
                        .execute(&mut *tx_db)
                        .await;
                    if let Err(e) = del_res {
                        let _ = tx_db.rollback().await;
                        return Err(Json(ActionResponse {
                            success: false,
                            error: Some(format!("Failed to execute LP withdrawal: {}", e)),
                            transaction_id: None,
                            signed_psbt_hex: None,
                            data: None,
                        }));
                    }
                    let mut credits: Vec<(String, f64)> = Vec::new();
                    if let Some(obj) = reserves_val.as_object() {
                        for (k, v) in obj {
                            if let Some(amt) = v.as_f64() {
                                if amt > 0.0 {
                                    credits.push((k.trim().to_uppercase(), amt));
                                }
                            }
                        }
                    }
                    if credits.is_empty() {
                        let pair_parts: Vec<&str> = pool_pair.split('/').collect();
                        let asset_a = pair_parts.first().copied().unwrap_or("KAS").to_uppercase();
                        let asset_b = pair_parts.get(1).copied().unwrap_or("USDC").to_uppercase();
                        credits.push((asset_a, staked_a));
                        credits.push((asset_b, staked_b));
                    }
                    let user_ledger_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
                    let mut pipe = redis::pipe();
                    pipe.atomic();
                    for (asset_tick, amt) in &credits {
                        pipe.cmd("HINCRBYFLOAT").arg(&user_ledger_key).arg(asset_tick).arg(*amt).ignore();
                    }
                    if let Err(e) = pipe.query_async::<_, ()>(&mut redis_conn).await {
                        let _ = tx_db.rollback().await;
                        return Err(Json(ActionResponse {
                            success: false,
                            error: Some(format!("Redis ledger credit failed during LP withdrawal (position preserved): {}", e)),
                            transaction_id: None,
                            signed_psbt_hex: None,
                            data: None,
                        }));
                    }
                    if let Err(e) = tx_db.commit().await {
                        let mut revert_pipe = redis::pipe();
                        revert_pipe.atomic();
                        for (asset_tick, amt) in &credits {
                            revert_pipe.cmd("HINCRBYFLOAT").arg(&user_ledger_key).arg(asset_tick).arg(-(*amt)).ignore();
                        }
                        let _: Result<(), _> = revert_pipe.query_async(&mut redis_conn).await;
                        return Err(Json(ActionResponse {
                            success: false,
                            error: Some(format!("Database commit failed during LP withdrawal: {}", e)),
                            transaction_id: None,
                            signed_psbt_hex: None,
                            data: None,
                        }));
                    }
                    return Ok(Json(ActionResponse {
                        success: true,
                        error: None,
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                },
                Ok(None) => {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse {
                        success: false,
                        error: Some("LP position not found or ownership mismatch".to_string()),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                },
                Err(e) => {
                    let _ = tx_db.rollback().await;
                    return Err(Json(ActionResponse {
                        success: false,
                        error: Some(format!("Database error querying LP record: {}", e)),
                        transaction_id: None,
                        signed_psbt_hex: None,
                        data: None,
                    }));
                }
            }
        },
        _ => {}
    }
    let save_res = sqlx::query(
        "INSERT INTO user_command_centers (wallet_address, layout_state, last_updated)
         VALUES ($1, $2, CURRENT_TIMESTAMP)
         ON CONFLICT (wallet_address) DO UPDATE SET layout_state = EXCLUDED.layout_state, last_updated = CURRENT_TIMESTAMP"
    )
    .bind(&master_identity)
    .bind(&state)
    .execute(&mut *tx_db)
    .await;
    if let Err(e) = save_res {
        let _ = tx_db.rollback().await;
        return Err(Json(ActionResponse { success: false, error: Some(e.to_string()), transaction_id: None, signed_psbt_hex: None, data: None }));
    }
    let _ = sqlx::query("DELETE FROM user_command_centers WHERE wallet_address = $1")
        .bind(&clean_wallet)
        .execute(&mut *tx_db)
        .await;
    let _ = tx_db.commit().await;
    let update_payload = json!({
        "layout_state_update": true,
        "wallet": master_identity,
        "state": state
    });
    let _: () = redis::cmd("PUBLISH")
        .arg("telemetry:updates")
        .arg(update_payload.to_string())
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(());
    Ok(Json(ActionResponse {
        success: true,
        error: None,
        transaction_id: None,
        signed_psbt_hex: None,
        data: Some(state),
    }))
}