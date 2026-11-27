use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::accounting::normalize_kaspa_prefixed;
use crate::kaspa_crypto::SolverIdentity;

#[derive(Debug, Clone)]
pub struct AgentSession {
    pub agent_key: String,
    pub key_id: String,
    pub maker_fee_bps: f64,
    pub taker_fee_bps: f64,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone)]
pub struct GatewayMarketAsset {
    #[allow(dead_code)]
    pub ticker: String,
    pub decimals: u8,
    pub oracle_usd: f64,
    #[allow(dead_code)]
    pub oracle_usd_e8: u128,
    #[allow(dead_code)]
    pub whitelisted_dark_pool: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeResp {
    challenge_id: String,
    message: String,
    challenge_blake3_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyResp {
    ok: bool,
    agent_key: String,
    key_id: String,
    expires_at_unix: String,
}

pub struct AgentGatewayClient {
    http: Client,
    base_url: String,
    identity: SolverIdentity,
    session: Option<AgentSession>,
}

impl AgentGatewayClient {
    pub fn new(base_url: String, identity: SolverIdentity) -> Result<Self> {
        let http = Client::builder()
            .user_agent("Perennia-Sovereign-Solver/0.2")
            .timeout(Duration::from_secs(8))
            .build()
            .context("Failed to initialize AgentGateway HTTP client")?;
        Ok(Self {
            http,
            base_url,
            identity,
            session: None,
        })
    }

    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub async fn ensure_authenticated(&mut self) -> Result<AgentSession> {
        let now = Self::now_unix();
        if let Some(ref s) = self.session {
            if s.expires_at_unix > now + 3600 {
                return Ok(s.clone());
            }
        }

        let chg_url = format!("{}/api/v1/agent/auth/challenge", self.base_url);
        let chg_res = self
            .http
            .post(&chg_url)
            .json(&json!({
                "walletAddress": self.identity.kaspa_address,
                "pubkeyHex": self.identity.pubkey_hex
            }))
            .send()
            .await
            .context("Mode A /auth/challenge request failed")?;

        if !chg_res.status().is_success() {
            let status = chg_res.status();
            let body = chg_res.text().await.unwrap_or_default();
            bail!("Mode A /auth/challenge rejected ({}): {}", status, body);
        }

        let chg: ChallengeResp = chg_res
            .json()
            .await
            .context("Invalid Mode A challenge JSON")?;

        let computed_blake3 = blake3::hash(chg.message.as_bytes()).to_hex().to_string();
        if computed_blake3 != chg.challenge_blake3_hex {
            bail!("Challenge Blake3 digest mismatch from Agent Gateway (fail-closed).");
        }

        let sig_hex = self.identity.sign_blake3_message(chg.message.as_bytes());

        let ver_url = format!("{}/api/v1/agent/auth/verify", self.base_url);
        let ver_res = self
            .http
            .post(&ver_url)
            .json(&json!({
                "walletAddress": self.identity.kaspa_address,
                "pubkeyHex": self.identity.pubkey_hex,
                "challengeId": chg.challenge_id,
                "signatureHex": sig_hex,
                "label": "Perennia Sovereign Solver v5 Live",
                "allowDarkPoolMaker": true,
                "maxSlippageBps": 50,
                "ttlSeconds": 2592000
            }))
            .send()
            .await
            .context("Mode A /auth/verify request failed")?;

        if !ver_res.status().is_success() {
            let status = ver_res.status();
            let body = ver_res.text().await.unwrap_or_default();
            bail!("Mode A /auth/verify rejected ({}): {}", status, body);
        }

        let ver: VerifyResp = ver_res.json().await.context("Invalid Mode A verify JSON")?;
        if !ver.ok || ver.agent_key.is_empty() {
            bail!("Mode A /auth/verify returned ok=false");
        }

        let expires_at_unix = ver.expires_at_unix.parse::<u64>().unwrap_or(now + 86_400);

        let mut sess = AgentSession {
            agent_key: ver.agent_key,
            key_id: ver.key_id,
            maker_fee_bps: 6.0,
            taker_fee_bps: 50.0,
            expires_at_unix,
        };

        if let Ok((maker_bps, taker_bps, _)) = self.fetch_markets_with_token(&sess.agent_key).await {
            sess.maker_fee_bps = maker_bps;
            sess.taker_fee_bps = taker_bps;
        }

        self.session = Some(sess.clone());
        Ok(sess)
    }

    pub async fn fetch_markets(&mut self) -> Result<(f64, f64, HashMap<String, GatewayMarketAsset>)> {
        let sess = self.ensure_authenticated().await?;
        self.fetch_markets_with_token(&sess.agent_key).await
    }

    async fn fetch_markets_with_token(
        &self,
        agent_key: &str,
    ) -> Result<(f64, f64, HashMap<String, GatewayMarketAsset>)> {
        let url = format!("{}/api/v1/agent/markets", self.base_url);
        let res = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {}", agent_key))
            .send()
            .await
            .context("GET /api/v1/agent/markets failed")?;

        if !res.status().is_success() {
            let st = res.status();
            let txt = res.text().await.unwrap_or_default();
            bail!("GET /api/v1/agent/markets HTTP {}: {}", st, txt);
        }

        let data: Value = res.json().await.context("Malformed /markets JSON")?;
        let maker_bps = data
            .pointer("/personalizedTier/effectiveDarkPoolMakerBps")
            .and_then(|v| {
                v.as_f64()
                    .or_else(|| v.as_u64().map(|u| u as f64))
                    .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
            })
            .unwrap_or(6.0);
        let taker_bps = data
            .pointer("/personalizedTier/effectiveDarkPoolTakerBps")
            .and_then(|v| {
                v.as_f64()
                    .or_else(|| v.as_u64().map(|u| u as f64))
                    .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
            })
            .unwrap_or(50.0);

        let mut map = HashMap::new();
        if let Some(arr) = data.get("assets").and_then(|v| v.as_array()) {
            for item in arr {
                let ticker = item
                    .get("ticker")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_uppercase();
                let decimals = item
                    .get("atomicDecimals")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(8) as u8;
                let usd_e8 = item
                    .get("oracleUsdE8")
                    .and_then(|v| {
                        v.as_str()
                            .and_then(|s| s.parse::<u128>().ok())
                            .or_else(|| v.as_u64().map(|u| u as u128))
                    })
                    .unwrap_or(0);
                let wl = item
                    .get("whitelistedDarkPool")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if !ticker.is_empty() && usd_e8 > 0 {
                    map.insert(
                        ticker.clone(),
                        GatewayMarketAsset {
                            ticker,
                            decimals,
                            oracle_usd: (usd_e8 as f64) / 100_000_000.0,
                            oracle_usd_e8: usd_e8,
                            whitelisted_dark_pool: wl,
                        },
                    );
                }
            }
        }
        Ok((maker_bps, taker_bps, map))
    }

    /// Queries real confirmed L1 UTXOs on the solver's dedicated Kaspa address via `/v1/utxos`.
    /// Never reads Stratum miner payout hot wallet UTXOs.
    pub async fn fetch_solver_confirmed_inventory_sompi(&self) -> Result<u128> {
        let url = format!(
            "{}/v1/utxos?address={}",
            self.base_url, self.identity.kaspa_address
        );
        let res = self
            .http
            .get(&url)
            .send()
            .await
            .context("GET /v1/utxos for dedicated solver wallet failed")?;
        if !res.status().is_success() {
            let st = res.status();
            let txt = res.text().await.unwrap_or_default();
            bail!("Solver UTXO inventory check failed HTTP {}: {}", st, txt);
        }
        let body: Value = res.json().await.context("Malformed /v1/utxos JSON")?;
        let entries = body
            .get("entries")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow::anyhow!("Malformed /v1/utxos response: missing entries array"))?;

        let mut total_sompi: u128 = 0;
        for entry in entries {
            let amt = entry
                .get("amount")
                .or_else(|| entry.get("utxoEntry").and_then(|u| u.get("amount")))
                .and_then(|v| {
                    v.as_u64()
                        .map(|n| n as u128)
                        .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u128>().ok()))
                })
                .unwrap_or(0);
            total_sompi = total_sompi.saturating_add(amt);
        }
        Ok(total_sompi)
    }

    /// Quotes a non-custodial L1 swap on Agent Gateway, checks treasury/airlock isolation,
    /// signs every input with the solver's BIP-340 Schnorr key, and broadcasts via `/execute`.
    pub async fn quote_and_execute_l1_swap(
        &mut self,
        pay_asset: &str,
        receive_asset: &str,
        amount_atomic: u128,
        master_treasury_address: &str,
        forbidden_hot_address: Option<&str>,
    ) -> Result<Value> {
        if amount_atomic == 0 {
            bail!("ZERO_LOSS_HALT: Refusing zero-amount L1 quote");
        }
        if let Some(hot) = forbidden_hot_address {
            let norm_hot = normalize_kaspa_prefixed(hot);
            if !norm_hot.is_empty() && norm_hot == self.identity.kaspa_address {
                bail!("SOLVER_ISOLATION_HALT: Solver address equals forbidden Stratum hot wallet");
            }
            if !norm_hot.is_empty() && norm_hot == normalize_kaspa_prefixed(master_treasury_address) {
                bail!("TREASURY_ISOLATION_HALT: Master treasury equals forbidden Stratum hot wallet");
            }
        }

        let sess = self.ensure_authenticated().await?;
        let quote_url = format!("{}/api/v1/agent/quote", self.base_url);
        let quote_res = self
            .http
            .post(&quote_url)
            .header("Authorization", format!("Bearer {}", sess.agent_key))
            .json(&json!({
                "payAsset": pay_asset,
                "receiveAsset": receive_asset,
                "amountAtomic": amount_atomic.to_string(),
                "executionSleeve": false,
                "treasuryFeeAddress": master_treasury_address,
                "settlementAddress": self.identity.kaspa_address
            }))
            .send()
            .await
            .context("POST /api/v1/agent/quote failed")?;

        if !quote_res.status().is_success() {
            let st = quote_res.status();
            let txt = quote_res.text().await.unwrap_or_default();
            bail!("POST /api/v1/agent/quote HTTP {}: {}", st, txt);
        }

        let quote_doc: Value = quote_res.json().await.context("Malformed /quote JSON")?;
        let quote_id = quote_doc
            .get("quoteId")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("Agent quote missing quoteId"))?;

        let sighashes = quote_doc
            .get("sighashHexPerInput")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow::anyhow!("Agent quote missing sighashHexPerInput"))?;
        if sighashes.is_empty() {
            bail!("Agent quote returned 0 sighash inputs for L1 signing");
        }

        let mut sig_scripts = Vec::with_capacity(sighashes.len());
        for sh_val in sighashes {
            let sh_hex = sh_val
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Non-string sighashHexPerInput item"))?;
            let bytes = hex::decode(sh_hex.trim())
                .context("Invalid hex in sighashHexPerInput")?;
            if bytes.len() != 32 {
                bail!("Expected 32-byte sighash digest, got {} bytes", bytes.len());
            }
            let mut digest32 = [0u8; 32];
            digest32.copy_from_slice(&bytes);
            sig_scripts.push(self.identity.sign_kaspa_p2pk_sigscript_hex(&digest32));
        }

        let exec_url = format!("{}/api/v1/agent/execute", self.base_url);
        let exec_res = self
            .http
            .post(&exec_url)
            .header("Authorization", format!("Bearer {}", sess.agent_key))
            .json(&json!({
                "quoteId": quote_id,
                "signatureScriptHexPerInput": sig_scripts
            }))
            .send()
            .await
            .context("POST /api/v1/agent/execute failed")?;

        if !exec_res.status().is_success() {
            let st = exec_res.status();
            let txt = exec_res.text().await.unwrap_or_default();
            bail!("POST /api/v1/agent/execute HTTP {}: {}", st, txt);
        }

        let exec_doc: Value = exec_res.json().await.context("Malformed /execute JSON")?;
        Ok(exec_doc)
    }
}
