use anyhow::{Context, Result};
use rand::RngCore;
use secp256k1::{Keypair, Message, SecretKey, SECP256K1};

pub const KASPA_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
pub const KASPA_ADDR_VERSION_P2PK_SCHNORR: u8 = 0x00;

fn kaspa_polymod(values: &[u8]) -> u64 {
    let mut c: u64 = 1;
    for &d in values {
        let c0 = c >> 35;
        c = ((c & 0x07ffffffff) << 5) ^ (d as u64);
        if (c0 & 0x01) != 0 { c ^= 0x98f2bc8e61; }
        if (c0 & 0x02) != 0 { c ^= 0x79b76d99e2; }
        if (c0 & 0x04) != 0 { c ^= 0xf33e5fb3c4; }
        if (c0 & 0x08) != 0 { c ^= 0xae2eabe2a8; }
        if (c0 & 0x10) != 0 { c ^= 0x1e4f43e470; }
    }
    c ^ 1
}

pub fn encode_kaspa_bech32m_address(version: u8, payload32: &[u8; 32]) -> String {
    let mut payload_u5 = Vec::with_capacity(64);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for &b in std::iter::once(&version).chain(payload32.iter()) {
        acc = (acc << 8) | (b as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            payload_u5.push(((acc >> bits) & 0x1f) as u8);
        }
    }
    if bits > 0 {
        payload_u5.push(((acc << (5 - bits)) & 0x1f) as u8);
    }

    let mut poly_input = Vec::with_capacity(6 + payload_u5.len() + 8);
    for &ch in b"kaspa" {
        poly_input.push(ch & 0x1f);
    }
    poly_input.push(0);
    poly_input.extend_from_slice(&payload_u5);
    poly_input.extend_from_slice(&[0u8; 8]);

    let checksum = kaspa_polymod(&poly_input);
    for i in 0..8 {
        payload_u5.push(((checksum >> (5 * (7 - i))) & 0x1f) as u8);
    }

    let mut out = String::with_capacity(6 + payload_u5.len());
    out.push_str("kaspa:");
    for v in payload_u5 {
        out.push(KASPA_CHARSET[v as usize] as char);
    }
    out
}

#[derive(Clone)]
pub struct SolverIdentity {
    keypair: Keypair,
    pub pubkey_hex: String,
    pub kaspa_address: String,
}

impl SolverIdentity {
    pub fn from_secret_hex(secret_hex: &str) -> Result<Self> {
        let raw = hex::decode(secret_hex.trim()).context("Invalid SOLVER_PRIVATE_KEY_HEX")?;
        let sk = SecretKey::from_slice(&raw).context("Invalid secp256k1 secret key bytes")?;
        let keypair = Keypair::from_secret_key(SECP256K1, &sk);
        let (xonly, _) = keypair.x_only_public_key();
        let pub_bytes = xonly.serialize();
        let pubkey_hex = hex::encode(pub_bytes);
        let kaspa_address = encode_kaspa_bech32m_address(KASPA_ADDR_VERSION_P2PK_SCHNORR, &pub_bytes);
        Ok(Self {
            keypair,
            pubkey_hex,
            kaspa_address,
        })
    }

    pub fn generate_fresh_secret_hex() -> String {
        loop {
            let mut buf = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            if SecretKey::from_slice(&buf).is_ok() {
                return hex::encode(buf);
            }
        }
    }

    /// Signs `blake3::hash(msg_bytes)` using deterministic BIP-340 Schnorr (64-byte / 128-hex).
    pub fn sign_blake3_message(&self, msg_bytes: &[u8]) -> String {
        let digest: [u8; 32] = *blake3::hash(msg_bytes).as_bytes();
        self.sign_digest32(&digest)
    }

    /// Signs a 32-byte digest (e.g., Kaspa TransactionSigningHash or 0x83 preimage_hash).
    pub fn sign_digest32(&self, digest32: &[u8; 32]) -> String {
        let msg = Message::from_digest(*digest32);
        let sig = SECP256K1.sign_schnorr_no_aux_rand(&msg, &self.keypair);
        hex::encode(sig.as_ref())
    }

    /// Formats canonical Kaspa P2PK Schnorr signatureScript: `[0x41, <64B sig>, 0x01]`.
    pub fn sign_kaspa_p2pk_sigscript_hex(&self, sighash32: &[u8; 32]) -> String {
        let sig_hex = self.sign_digest32(sighash32);
        format!("41{}01", sig_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::schnorr::Signature as SchnorrSignature;

    #[test]
    fn test_schnorr_identity_and_kaspa_address() {
        let sk_hex = SolverIdentity::generate_fresh_secret_hex();
        assert_eq!(sk_hex.len(), 64);
        let id = SolverIdentity::from_secret_hex(&sk_hex).expect("valid identity");
        assert!(id.kaspa_address.starts_with("kaspa:q"));
        assert_eq!(id.pubkey_hex.len(), 64);

        let challenge = b"PERENNIA_AGENT_AUTH_V1\nTestChallenge";
        let sig_hex = id.sign_blake3_message(challenge);
        assert_eq!(sig_hex.len(), 128);

        let sig = SchnorrSignature::from_slice(&hex::decode(&sig_hex).unwrap()).unwrap();
        let msg = Message::from_digest(*blake3::hash(challenge).as_bytes());
        let (xonly, _) = id.keypair.x_only_public_key();
        assert!(SECP256K1.verify_schnorr(&sig, &msg, &xonly).is_ok());
    }
}