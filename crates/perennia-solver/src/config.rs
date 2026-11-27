use anyhow::{bail, Context, Result};
use std::env;

#[derive(Debug, Clone)]
pub struct SolverConfig {
    pub database_url: String,
    pub redis_url: String,
    pub agent_gateway_url: String,
    pub private_key_hex: String,
    pub expected_wallet_address: Option<String>,
    pub dry_run: bool,
    pub allow_live_execution: bool,
    pub shadow_window_hours: i32,
    pub default_notional_usd: f64,
    pub max_notional_usd: f64,
    pub min_net_edge_bps: f64,
    pub kucoin_taker_bps: f64,
    pub bitget_taker_bps: f64,
    pub kraken_taker_bps: f64,
}

impl SolverConfig {
    pub fn from_env() -> Result<Self> {
        let database_url = env::var("DATABASE_URL")
            .context("CRITICAL: DATABASE_URL is required (fail-closed).")?;
        let redis_url = env::var("REDIS_URL")
            .context("CRITICAL: REDIS_URL is required (fail-closed).")?;
        let agent_gateway_url = env::var("AGENT_GATEWAY_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8002".to_string())
            .trim()
            .trim_end_matches('/')
            .to_string();

        // Dedicated solver wallet key priority: SOLVER_WALLET_PRIVATE_KEY -> SOLVER_PRIVATE_KEY_HEX.
        // Never reads Stratum hot payout signer env vars as fallback.
        let raw_pk = env::var("SOLVER_WALLET_PRIVATE_KEY")
            .or_else(|_| env::var("SOLVER_PRIVATE_KEY_HEX"))
            .unwrap_or_default();
        let trimmed_pk = raw_pk.trim();
        let private_key_hex = trimmed_pk
            .strip_prefix("0x")
            .unwrap_or(trimmed_pk)
            .to_ascii_lowercase();

        if private_key_hex.len() != 64 || !private_key_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!(
                "CRITICAL: SOLVER_WALLET_PRIVATE_KEY / SOLVER_PRIVATE_KEY_HEX must be an exact 64-char hex secp256k1 secret key."
            );
        }

        let expected_wallet_address = env::var("SOLVER_WALLET_ADDRESS")
            .or_else(|_| env::var("SOLVER_WALLET_KAS_ADDRESS"))
            .ok()
            .map(|s| crate::accounting::normalize_kaspa_prefixed(&s))
            .filter(|s| !s.is_empty());

        let raw_dry_run = env::var("SOLVER_DRY_RUN")
            .map(|v| !v.trim().eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        let raw_shadow_mode = env::var("SOLVER_SHADOW_MODE")
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let allow_live_execution = env::var("SOLVER_ALLOW_LIVE_EXECUTION")
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let dry_run = !(!raw_dry_run && allow_live_execution && !raw_shadow_mode);

        let shadow_window_hours = env::var("SOLVER_SHADOW_WINDOW_HOURS")
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
            .filter(|&h| (1..=720).contains(&h))
            .unwrap_or(48);

        let default_notional_usd = env::var("SOLVER_DEFAULT_NOTIONAL_USD")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|&v| v >= 10.0 && v.is_finite())
            .unwrap_or(250.0);

        let max_notional_usd = env::var("SOLVER_MAX_NOTIONAL_USD")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|&v| v >= default_notional_usd && v.is_finite())
            .unwrap_or(2500.0);

        let min_net_edge_bps = env::var("SOLVER_MIN_NET_EDGE_BPS")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite())
            .unwrap_or(1.0);

        let kucoin_taker_bps = env::var("KUCOIN_TAKER_BPS")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|&v| v >= 0.0 && v.is_finite())
            .unwrap_or(10.0);

        let bitget_taker_bps = env::var("BITGET_TAKER_BPS")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|&v| v >= 0.0 && v.is_finite())
            .unwrap_or(10.0);

        let kraken_taker_bps = env::var("KRAKEN_TAKER_BPS")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|&v| v >= 0.0 && v.is_finite())
            .unwrap_or(16.0);

        Ok(Self {
            database_url,
            redis_url,
            agent_gateway_url,
            private_key_hex,
            expected_wallet_address,
            dry_run,
            allow_live_execution,
            shadow_window_hours,
            default_notional_usd,
            max_notional_usd,
            min_net_edge_bps,
            kucoin_taker_bps,
            bitget_taker_bps,
            kraken_taker_bps,
        })
    }
}
