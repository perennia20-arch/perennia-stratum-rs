use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const KASPA_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
pub const KASPA_ADDR_VERSION_P2PK_SCHNORR: u8 = 0x00;
pub const KASPA_ADDR_VERSION_P2SH: u8 = 0x08;
pub const CANONICAL_GENESIS_ANCHOR_EPOCH_SEC: i64 = 1_767_225_600;

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
        let start = i * 8;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&block[start..start + 8]);
        m[i] = u64::from_le_bytes(bytes);
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

fn blake2b_hash(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = BLAKE2B_IV;
    let key_len = key.len().min(64);
    h[0] ^= 0x01010000 ^ ((key_len as u64) << 8) ^ 32;

    let mut buffer = Vec::with_capacity(if key_len > 0 { 128 + data.len() } else { data.len() });
    if key_len > 0 {
        let mut key_block = [0u8; 128];
        key_block[..key_len].copy_from_slice(&key[..key_len]);
        buffer.extend_from_slice(&key_block);
    }
    buffer.extend_from_slice(data);

    let mut t: u128 = 0;
    if buffer.is_empty() {
        let empty_block = [0u8; 128];
        blake2b_compress(&mut h, &empty_block, 0, true);
    } else {
        let chunks = buffer.chunks(128);
        let num_chunks = chunks.len();
        for (idx, chunk) in chunks.enumerate() {
            t += chunk.len() as u128;
            let mut block = [0u8; 128];
            block[..chunk.len()].copy_from_slice(chunk);
            blake2b_compress(&mut h, &block, t, idx + 1 == num_chunks);
        }
    }

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}

pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    blake2b_hash(&[], data)
}

pub fn blake2b_256_keyed(key: &[u8], data: &[u8]) -> [u8; 32] {
    blake2b_hash(key, data)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KCC20State {
    pub amount: u64,
    pub owner_hex: String,
    pub owner_scheme: u8,
    pub borrow_scheme: u8,
    pub borrow_guard_hex: String,
    pub extension_commitment_hex: String,
    pub packed_state_hex: String,
    pub state_root_hex: String,
    pub covenant_id_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SilverScriptCompilation {
    pub contract_name: String,
    pub ticker: String,
    pub token_standard: String,
    pub label: String,
    pub beneficiary_address: String,
    pub beneficiary_pubkey_hex: String,
    pub cliff_days: i64,
    pub cliff_timestamp: i64,
    pub linear_days: i64,
    pub total_allocation: f64,
    pub silverscript_source: String,
    pub redeem_script_hex: String,
    pub script_hash_hex: String,
    pub covenant_address: String,
    pub covenant_spk_hex: String,
    pub kcc20_state: KCC20State,
}

pub fn kaspa_polymod(values: &[u8]) -> u64 {
    let mut c: u64 = 1;
    for &v in values {
        let c0 = c >> 35;
        c = ((c & 0x07ffffffff) << 5) ^ (v as u64);
        if (c0 & 1) != 0 {
            c ^= 0x98f2bc8e61;
        }
        if (c0 & 2) != 0 {
            c ^= 0x79b76d99e2;
        }
        if (c0 & 4) != 0 {
            c ^= 0xf33e5fb3c4;
        }
        if (c0 & 8) != 0 {
            c ^= 0xae2eabe2a8;
        }
        if (c0 & 16) != 0 {
            c ^= 0x1e4f43e470;
        }
    }
    c ^ 1
}

pub fn encode_kaspa_bech32m_address(version: u8, hash32: &[u8; 32]) -> String {
    let prefix = b"kaspa";
    let mut prefix_values: Vec<u8> = prefix.iter().map(|b| b & 31).collect();
    prefix_values.push(0);

    let mut raw_payload = Vec::with_capacity(33);
    raw_payload.push(version);
    raw_payload.extend_from_slice(hash32);

    let mut payload5: Vec<u8> = Vec::with_capacity(54);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for byte in raw_payload {
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
    let polymod = kaspa_polymod(&mod_input);

    let mut out = String::with_capacity(68);
    out.push_str("kaspa:");
    for &idx in &payload5 {
        out.push(KASPA_CHARSET[idx as usize] as char);
    }
    for i in 0..8 {
        let idx = ((polymod >> (5 * (7 - i))) & 31) as usize;
        out.push(KASPA_CHARSET[idx] as char);
    }
    out
}

pub fn decode_kaspa_address_payload(address: &str) -> Option<(u8, [u8; 32])> {
    let trimmed = address.trim().to_lowercase();
    let payload_str = trimmed.strip_prefix("kaspa:").unwrap_or(&trimmed);
    if payload_str.len() < 10 {
        return None;
    }
    let data_part = &payload_str[..payload_str.len().saturating_sub(8)];
    let mut words = Vec::with_capacity(data_part.len());
    for ch in data_part.bytes() {
        let pos = KASPA_CHARSET.iter().position(|&c| c == ch)?;
        words.push(pos as u8);
    }
    let mut decoded = Vec::with_capacity(34);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for w in words {
        acc = (acc << 5) | (w as u32);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            decoded.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if decoded.len() < 33 {
        return None;
    }
    let version = decoded[0];
    let mut hash32 = [0u8; 32];
    hash32.copy_from_slice(&decoded[1..33]);
    Some((version, hash32))
}

pub fn build_kcc20_state_commitment(
    ticker: &str,
    amount_base_units: u64,
    owner_bytes: &[u8; 32],
    owner_scheme: u8,
    borrow_scheme: u8,
    borrow_guard_bytes: &[u8; 32],
    charter_sha256_hex: Option<&str>,
) -> KCC20State {
    let clean_ticker = ticker.trim().to_uppercase();
    let ext_seed = format!(
        "{}:{}",
        clean_ticker,
        charter_sha256_hex.unwrap_or("PERENNIA_KCC20_CHARTER_V1")
    );
    let extension32 = blake2b_256(ext_seed.as_bytes());

    let mut packed = Vec::with_capacity(106);
    packed.extend_from_slice(&amount_base_units.to_le_bytes());
    packed.extend_from_slice(owner_bytes);
    packed.push(owner_scheme);
    packed.push(borrow_scheme);
    packed.extend_from_slice(borrow_guard_bytes);
    packed.extend_from_slice(&extension32);

    let state_root = blake2b_256_keyed(b"KCC20StateCommitment", &packed);
    let mut cov_preimage = Vec::with_capacity(16 + state_root.len());
    cov_preimage.extend_from_slice(format!("KCC-20:{}:", clean_ticker).as_bytes());
    cov_preimage.extend_from_slice(&state_root);
    let covenant_id = blake2b_256(&cov_preimage);

    KCC20State {
        amount: amount_base_units,
        owner_hex: hex::encode(owner_bytes),
        owner_scheme,
        borrow_scheme,
        borrow_guard_hex: hex::encode(borrow_guard_bytes),
        extension_commitment_hex: hex::encode(extension32),
        packed_state_hex: hex::encode(&packed),
        state_root_hex: hex::encode(state_root),
        covenant_id_hex: hex::encode(covenant_id),
    }
}

pub fn compile_silverscript_proof_of_lock_vault(
    ticker: &str,
    token_standard: &str,
    label: &str,
    beneficiary_address: &str,
    total_allocation: f64,
    cliff_days: i64,
    linear_days: i64,
    charter_sha256_hex: Option<&str>,
) -> SilverScriptCompilation {
    let clean_ticker = ticker.trim().to_uppercase();
    let clean_standard = if token_standard.trim().eq_ignore_ascii_case("KCC-20") {
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
    let cliff_timestamp = CANONICAL_GENESIS_ANCHOR_EPOCH_SEC + clamped_cliff * 86_400;

    let (owner_scheme, beneficiary_pubkey) =
        if let Some((ver, hash)) = decode_kaspa_address_payload(beneficiary_address) {
            (ver, hash)
        } else {
            let fallback = blake2b_256(
                format!("PERENNIA_BENEFICIARY:{}", beneficiary_address.trim()).as_bytes(),
            );
            (KASPA_ADDR_VERSION_P2PK_SCHNORR, fallback)
        };

    let normalized_beneficiary =
        encode_kaspa_bech32m_address(owner_scheme, &beneficiary_pubkey);
    let beneficiary_pubkey_hex = hex::encode(beneficiary_pubkey);
    let alloc_int = total_allocation.max(0.0).round() as u64;

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
             // beneficiary     = 0x{}\n\
             // cliffTimestamp  = {} ({}d cliff)\n\
             // linearDays      = {} ({}d linear vesting)\n\
             // totalAllocation = {} {}\n\
             entrypoint function unlockTranche(sig beneficiarySig, int currentEpochTs, int claimAmount) {{\n\
                 require(checkSig(beneficiarySig, beneficiary));\n\
                 require(tx.time >= cliffTimestamp);\n\
                 require(currentEpochTs >= cliffTimestamp);\n\
                 int elapsedSeconds = currentEpochTs - cliffTimestamp;\n\
                 int linearDurationSeconds = linearDays * 86400;\n\
                 int maxVested = totalAllocation;\n\
                 if (linearDurationSeconds > 0 && elapsedSeconds < linearDurationSeconds) {{\n\
                     maxVested = (totalAllocation * elapsedSeconds) / linearDurationSeconds;\n\
                 }}\n\
                 require(claimAmount > 0 && claimAmount <= maxVested);\n\
                 bytes32 expectedSpk = new ScriptPublicKeyP2PK(beneficiary);\n\
                 require(tx.outputs[0].scriptPublicKey == expectedSpk);\n\
             }}\n\
         }}",
        clean_standard,
        clean_ticker,
        clean_label,
        beneficiary_pubkey_hex,
        cliff_timestamp,
        clamped_cliff,
        clamped_linear,
        clamped_linear,
        alloc_int,
        clean_ticker
    );

    let ast_digest = blake2b_256(silverscript_source.as_bytes());
    let mut redeem_script = Vec::with_capacity(98);
    redeem_script.push(0x20);
    redeem_script.extend_from_slice(&beneficiary_pubkey);
    redeem_script.extend_from_slice(&[0xac, 0x08]);
    redeem_script.extend_from_slice(&(cliff_timestamp as u64).to_le_bytes());
    redeem_script.extend_from_slice(&[0xb1, 0x75, 0x08]);
    redeem_script.extend_from_slice(&(clamped_linear as u64).to_le_bytes());
    redeem_script.extend_from_slice(&[0x75, 0x08]);
    redeem_script.extend_from_slice(&alloc_int.to_le_bytes());
    redeem_script.extend_from_slice(&[0x75, 0x20]);
    redeem_script.extend_from_slice(&ast_digest);
    redeem_script.extend_from_slice(&[0x75, 0x51]);

    let script_hash = blake2b_256(&redeem_script);
    let script_hash_hex = hex::encode(script_hash);
    let covenant_address =
        encode_kaspa_bech32m_address(KASPA_ADDR_VERSION_P2SH, &script_hash);
    let covenant_spk_hex = format!("a9{}87", script_hash_hex);

    let is_timelocked = clamped_cliff > 0 || clamped_linear > 0;
    let base_units = alloc_int.saturating_mul(100_000_000);
    let kcc20_state = build_kcc20_state_commitment(
        &clean_ticker,
        base_units,
        &beneficiary_pubkey,
        owner_scheme,
        if is_timelocked { 0x01 } else { 0x00 },
        &script_hash,
        charter_sha256_hex,
    );

    SilverScriptCompilation {
        contract_name: "ProofOfLockVault".to_string(),
        ticker: clean_ticker,
        token_standard: clean_standard,
        label: clean_label,
        beneficiary_address: normalized_beneficiary,
        beneficiary_pubkey_hex,
        cliff_days: clamped_cliff,
        cliff_timestamp,
        linear_days: clamped_linear,
        total_allocation,
        silverscript_source,
        redeem_script_hex: hex::encode(redeem_script),
        script_hash_hex,
        covenant_address,
        covenant_spk_hex,
        kcc20_state,
    }
}

pub fn silverscript_compilation_to_json(comp: &SilverScriptCompilation) -> Value {
    serde_json::to_value(comp).unwrap_or_else(|_| json!({}))
}