mod accounting;
mod agent_client;
mod cex_books;
mod config;
mod db;
mod kaspa_crypto;
mod strategies;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::time::Duration;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::accounting::{
    resolve_master_treasury_address_from_inputs, resolve_master_treasury_address_strict,
    validate_fresh_kas_usdc_oracle, verify_solver_isolated_from_stratum_airlock,
};
use crate::agent_client::AgentGatewayClient;
use crate::cex_books::CexOrderbookClient;
use crate::config::SolverConfig;
use crate::kaspa_crypto::SolverIdentity;
use crate::strategies::{
    evaluate_2200_epoch_pre_hedger, evaluate_cross_asset_and_rings, evaluate_sor_and_rfq_maker,
    TickContext,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Support `--gen-key` CLI helper for provisioning isolated CSPRNG BIP-340 Schnorr secret key
    if std::env::args().any(|a| a == "--gen-key") {
        println!("{}", SolverIdentity::generate_fresh_secret_hex());
        return Ok(());
    }

    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cfg = SolverConfig::from_env()?;
    let identity = SolverIdentity::from_secret_hex(&cfg.private_key_hex)?;

    if let Some(ref expected) = cfg.expected_wallet_address {
        if expected != &identity.kaspa_address {
            bail!(
                "SOLVER_CONFIG_HALT: SOLVER_WALLET_ADDRESS ({}) does not match derived solver pubkey address ({}).",
                expected,
                identity.kaspa_address
            );
        }
    }

    // Fail closed if solver wallet shares address or key material with Stratum's 5,000 KAS airlock hot wallet.
    let forbidden_hot_addr = env::var("PERENNIA_HOT_KAS_ADDRESS")
        .or_else(|_| env::var("PERENNIA_TREASURY_KAS_ADDRESS"))
        .ok();
    let forbidden_hot_sk = env::var("PERENNIA_HOT_PRIVATE_KEY")
        .or_else(|_| env::var("KASPA_HOT_PRIVATE_KEY"))
        .ok();
    verify_solver_isolated_from_stratum_airlock(
        &identity.kaspa_address,
        &cfg.private_key_hex,
        forbidden_hot_addr.as_deref(),
        forbidden_hot_sk.as_deref(),
    )?;

    // 1. Fail-closed PostgreSQL connection + schema initialization
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&cfg.database_url)
        .await
        .context("CRITICAL: Solver PostgreSQL connection failed")?;
    db::ensure_solver_schema(&pool).await?;

    let master_treasury_address = match resolve_master_treasury_address_strict() {
        Ok(addr) => addr,
        Err(_) => {
            let db_addr = db::fetch_db_treasury_kas_address(&pool).await;
            resolve_master_treasury_address_from_inputs(
                db_addr.as_deref(),
                None,
                None,
                forbidden_hot_addr.as_deref(),
            )
            .context(
                "CRITICAL: MASTER_TREASURY_ADDRESS must be configured via env or system_treasury_config and isolated from Stratum hot wallet.",
            )?
        }
    };

    info!(
        "Booting Perennia Sovereign Solver v0.2 | wallet={} | pubkey={} | masterTreasury={} | dryRun={} | allowLive={} | shadowHours={}h",
        identity.kaspa_address,
        identity.pubkey_hex,
        master_treasury_address,
        cfg.dry_run,
        cfg.allow_live_execution,
        cfg.shadow_window_hours
    );

    // 2. Fail-closed Redis connection + PING verification
    let redis_client = redis::Client::open(cfg.redis_url.as_str())
        .context("CRITICAL: Invalid Solver REDIS_URL")?;
    let mut redis_conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .context("CRITICAL: Solver Redis connection failed")?;
    let pong: String = redis::cmd("PING")
        .query_async(&mut redis_conn)
        .await
        .context("CRITICAL: Solver Redis PING failed")?;
    if pong.trim().to_uppercase() != "PONG" {
        bail!("CRITICAL: Unexpected Redis PING response: {}", pong);
    }

    // 3. Live BIP-340 Schnorr Mode A Auth Handshake against Perennia Agent Gateway
    let mut gateway = AgentGatewayClient::new(cfg.agent_gateway_url.clone(), identity.clone())?;
    let auth_sess = gateway.ensure_authenticated().await?;
    info!(
        "[MODE A AUTH VERIFIED] keyId={} | makerFeeBps={} | takerFeeBps={}",
        auth_sess.key_id, auth_sess.maker_fee_bps, auth_sess.taker_fee_bps
    );

    // 4. Register solver session in PostgreSQL
    let session_id = db::create_shadow_session(
        &pool,
        &identity.kaspa_address,
        &identity.pubkey_hex,
        &auth_sess.key_id,
        cfg.dry_run,
        cfg.shadow_window_hours,
    )
    .await?;
    if cfg.dry_run {
        info!(
            "[SHADOW SESSION ARMED] sessionId={} | {}h P&L tracking active in solver_pnl_ledger",
            session_id, cfg.shadow_window_hours
        );
    } else {
        info!(
            "[LIVE SOLVER ARMED] sessionId={} | sovereign fee-capturing execution enabled -> treasury={}",
            session_id, master_treasury_address
        );
    }

    let cex_books = CexOrderbookClient::new(&cfg);
    let mut startup_drill_done = false;
    let mut interval = tokio::time::interval(Duration::from_secs(10));

    loop {
        interval.tick().await;

        let (maker_bps, taker_bps, markets) = match gateway.fetch_markets().await {
            Ok(m) => m,
            Err(e) => {
                warn!("[FAIL-CLOSED TICK] Agent Gateway /markets unavailable: {}", e);
                continue;
            }
        };

        let (usdc_raw, usdt_raw, kas_raw, kas_pttl_ms): (
            Option<String>,
            Option<String>,
            Option<String>,
            i64,
        ) = redis::pipe()
            .cmd("GET")
            .arg("oracle:spot:USDC_USD")
            .cmd("GET")
            .arg("oracle:spot:USDT_USD")
            .cmd("GET")
            .arg("oracle:spot:KAS_USDC")
            .cmd("PTTL")
            .arg("oracle:spot:KAS_USDC")
            .query_async(&mut redis_conn)
            .await
            .unwrap_or((None, None, None, -2));

        let usdc_usd = usdc_raw
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|&v| v > 0.99 && v < 1.01)
            .unwrap_or(1.0);
        let usdt_usd = match usdt_raw.and_then(|s| s.parse::<f64>().ok()) {
            Some(v) if v > 0.99 && v < 1.01 => v,
            _ => {
                warn!(
                    "[FAIL-CLOSED TICK] Live USDT_USD parity unavailable or outside [0.99, 1.01] band."
                );
                continue;
            }
        };
        let (kas_usd_e8, kas_usd) =
            match validate_fresh_kas_usdc_oracle(kas_raw.as_deref(), kas_pttl_ms) {
                Ok(v) => v,
                Err(e) => {
                    warn!("[FAIL-CLOSED 503 ORACLE_HALT] {}", e);
                    continue;
                }
            };

        let solver_inventory_sompi = match gateway.fetch_solver_confirmed_inventory_sompi().await {
            Ok(sompi) => sompi,
            Err(e) => {
                warn!("[FAIL-CLOSED INVENTORY CHECK] {}", e);
                continue;
            }
        };

        let books = cex_books.fetch_all_core_books(usdt_usd).await;
        if books.get("KAS").map(|v| v.is_empty()).unwrap_or(true) {
            warn!(
                "[FAIL-CLOSED TICK] Zero live KAS CEX L2 orderbooks returned (KuCoin/Bitget/Kraken)."
            );
            continue;
        }

        let five_min_bucket = Utc::now().timestamp() / 300;
        let mut ctx = TickContext {
            cfg: &cfg,
            identity: &identity,
            pool: &pool,
            gateway: &mut gateway,
            session_id,
            maker_fee_bps: maker_bps,
            taker_fee_bps: taker_bps,
            markets: &markets,
            books: &books,
            kas_usd,
            kas_usd_e8,
            usdc_usd,
            usdt_usd,
            solver_inventory_sompi,
            master_treasury_address: &master_treasury_address,
            forbidden_hot_address: forbidden_hot_addr.as_deref(),
            five_min_bucket,
        };

        let mut eval_count: i64 = 0;
        match evaluate_sor_and_rfq_maker(&mut ctx, &mut redis_conn).await {
            Ok(n) => eval_count += n,
            Err(e) => warn!("SOR/RFQ Maker cycle error: {}", e),
        }
        match evaluate_cross_asset_and_rings(&ctx, &mut redis_conn).await {
            Ok(n) => eval_count += n,
            Err(e) => warn!("Cross-Asset Ring cycle error: {}", e),
        }
        match evaluate_2200_epoch_pre_hedger(&ctx, &mut redis_conn, !startup_drill_done).await {
            Ok(n) => {
                if n > 0 {
                    startup_drill_done = true;
                }
                eval_count += n;
            }
            Err(e) => warn!("22:00 UTC Pre-Hedger cycle error: {}", e),
        }

        let _ = db::heartbeat_session(&pool, session_id, eval_count).await;
    }
}
