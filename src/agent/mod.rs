// src/agent/mod.rs

pub mod auth;
pub mod dark_pool;
pub mod handlers;
pub mod locks_and_limits;
pub mod mcp;
pub mod solvency;
pub mod types;
pub mod verifier;

use axum::{
    extract::{Request, State},
    http::HeaderMap,
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use serde_json::json;
use sqlx::{PgPool, Row};
use std::{env, sync::Arc, time::Duration};
use tokio::sync::{broadcast, Semaphore};

use crate::agent::types::{
    sanitize_sterile_ticker, AgentError, AgentErrorCode,
};

pub const DEFAULT_AGENT_EDGE_MAX_CONCURRENCY: usize = 1024;
pub const MARKET_PULSE_CHANNEL_CAPACITY: usize = 512;

pub const REDIS_KEY_STEERING_STATES: &str = "perennia:steering:token_states";
pub const REDIS_KEY_STEERING_WHITELIST: &str = "perennia:steering:whitelist";
pub const REDIS_KEY_BLACKLISTED_WALLETS: &str = "perennia:firewall:blacklisted_wallets";
pub const REDIS_KEY_BLACKLISTED_TOKENS: &str = "perennia:firewall:blacklisted_tokens";
pub const REDIS_KEY_BLACKLISTED_IPS: &str = "perennia:firewall:blacklisted_ips";
pub const REDIS_KEY_LP_DEPTH_CACHE: &str = "perennia:agent:lp_depth_e8";
pub const REDIS_KEY_LATEST_PULSE: &str = "perennia:agent:latest_market_pulse";
pub const REDIS_KEY_AI_INTENT_SKEW: &str = "perennia:solver:ai_intent_skew";

#[derive(Clone)]
pub struct AgentGatewayState {
    pub pg_pool: PgPool,
    pub redis_client: redis::Client,
    pub edge_semaphore: Arc<Semaphore>,
    pub pulse_tx: broadcast::Sender<String>,
    pub signing_secret: Arc<[u8; 32]>,
    pub x402_treasury_address: String,
    pub max_edge_concurrency: usize,
}

impl AgentGatewayState {
    pub async fn initialize(pg_pool: PgPool, redis_url: &str) -> anyhow::Result<Self> {
        let raw_secret = env::var("AGENT_MACAROON_SECRET")
            .or_else(|_| env::var("LEDGER_HMAC_SECRET"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        if raw_secret.len() < 32 {
            anyhow::bail!(
                "CRITICAL_SECURITY_LOCKDOWN: AGENT_MACAROON_SECRET or LEDGER_HMAC_SECRET (min 32 chars) must be configured in .env before booting Agent Gateway."
            );
        }

        let derived_key = blake3::derive_key(
            "PERENNIA_AGENT_CAPABILITY_MACAROON_V1_2026",
            raw_secret.as_bytes(),
        );

        let x402_treasury_address = crate::chronos::resolve_master_treasury_prefixed()
            .ok()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "CRITICAL_CONFIG_HALT: MASTER_TREASURY_ADDRESS / PERENNIA_MASTER_TREASURY_KAS must be configured for non-custodial settlement and x402 burst credits (isolated from Stratum hot wallet)."
                )
            })?;

        let max_edge_concurrency = env::var("AGENT_EDGE_MAX_CONCURRENCY")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&c| (64..=16_384).contains(&c))
            .unwrap_or(DEFAULT_AGENT_EDGE_MAX_CONCURRENCY);

        let redis_client = redis::Client::open(redis_url.trim()).map_err(|e| {
            anyhow::anyhow!("CRITICAL: Failed to initialize Agent Gateway Redis client: {}", e)
        })?;

        // Fail closed at boot if Redis is unreachable
        let mut boot_conn = redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                anyhow::anyhow!("CRITICAL: Agent Gateway Redis connection failed at boot: {}", e)
            })?;
        let pong: String = redis::cmd("PING")
            .query_async(&mut boot_conn)
            .await
            .map_err(|e| anyhow::anyhow!("CRITICAL: Agent Gateway Redis PING failed: {}", e))?;
        if pong.trim().to_uppercase() != "PONG" {
            anyhow::bail!("CRITICAL: Unexpected Redis PING response: {}", pong);
        }

        ensure_agent_schema(&pg_pool).await?;
        sync_shared_state_to_redis(&pg_pool, &mut boot_conn).await?;

        let (pulse_tx, _) = broadcast::channel(MARKET_PULSE_CHANNEL_CAPACITY);

        let state = Self {
            pg_pool,
            redis_client,
            edge_semaphore: Arc::new(Semaphore::new(max_edge_concurrency)),
            pulse_tx,
            signing_secret: Arc::new(derived_key),
            x402_treasury_address,
            max_edge_concurrency,
        };

        spawn_agent_background_daemons(state.clone());

        tracing::info!(
            "🤖 [AGENT GATEWAY] Headless AI & Personal Mandate Gateway Armed (Concurrency Budget: {} permits, Stateless Blake3 Auth, x402 Ready).",
            max_edge_concurrency
        );

        Ok(state)
    }

    pub async fn get_redis_conn(&self) -> Result<redis::aio::MultiplexedConnection, AgentError> {
        self.redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!("🚨 [AGENT GATEWAY] Redis connection failure (failing closed): {}", e);
                AgentError::new(
                    AgentErrorCode::RedisUnavailable,
                    "Deterministic fail-closed halt: internal Redis state store unreachable.",
                )
            })
    }
}

pub async fn ensure_agent_schema(pool: &PgPool) -> anyhow::Result<()> {
    let ddl_statements = [
        r#"
        CREATE TABLE IF NOT EXISTS public.agent_api_keys (
            key_id VARCHAR(64) PRIMARY KEY,
            wallet_address VARCHAR(255) NOT NULL,
            clean_wallet VARCHAR(255) NOT NULL,
            agent_mode VARCHAR(16) NOT NULL CHECK (agent_mode IN ('MODE_A', 'MODE_B')),
            label VARCHAR(96) NOT NULL DEFAULT 'Sovereign Mandate',
            token_mac_blake3 VARCHAR(64) NOT NULL UNIQUE,
            pubkey_hex VARCHAR(64) NOT NULL DEFAULT '',
            whitelisted_assets TEXT[] NOT NULL DEFAULT ARRAY['KAS', 'USDC']::TEXT[],
            allow_swaps BOOLEAN NOT NULL DEFAULT TRUE,
            allow_bucket_updates BOOLEAN NOT NULL DEFAULT FALSE,
            allow_dark_pool_maker BOOLEAN NOT NULL DEFAULT FALSE,
            max_slippage_bps INTEGER NOT NULL DEFAULT 50 CHECK (max_slippage_bps >= 1 AND max_slippage_bps <= 2500),
            fee_tier_multiplier_bps INTEGER NOT NULL DEFAULT 10000 CHECK (fee_tier_multiplier_bps >= 1000 AND fee_tier_multiplier_bps <= 10000),
            cap_24h_sompi NUMERIC(39, 0) NOT NULL DEFAULT 0 CHECK (cap_24h_sompi >= 0),
            cap_24h_usd_micros NUMERIC(39, 0) NOT NULL DEFAULT 0 CHECK (cap_24h_usd_micros >= 0),
            verified_fills_count BIGINT NOT NULL DEFAULT 0 CHECK (verified_fills_count >= 0),
            cumulative_volume_usd_micros NUMERIC(39, 0) NOT NULL DEFAULT 0 CHECK (cumulative_volume_usd_micros >= 0),
            expires_at TIMESTAMP WITH TIME ZONE,
            is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
            revoked_reason VARCHAR(128),
            revoked_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_settled_at TIMESTAMP WITH TIME ZONE
        )
        "#,
        "CREATE INDEX IF NOT EXISTS idx_agent_api_keys_clean_wallet ON public.agent_api_keys (clean_wallet, is_revoked, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_agent_api_keys_wallet_prefixed ON public.agent_api_keys (wallet_address, is_revoked)",
        "CREATE INDEX IF NOT EXISTS idx_agent_api_keys_mode_active ON public.agent_api_keys (agent_mode, is_revoked)",
        r#"
        CREATE TABLE IF NOT EXISTS public.agent_execution_receipts (
            receipt_id VARCHAR(64) PRIMARY KEY,
            idempotency_key VARCHAR(128) NOT NULL UNIQUE,
            quote_id VARCHAR(64) NOT NULL UNIQUE,
            key_id VARCHAR(64) NOT NULL REFERENCES public.agent_api_keys(key_id) ON DELETE RESTRICT,
            mandate_id VARCHAR(64) NOT NULL,
            agent_mode VARCHAR(16) NOT NULL CHECK (agent_mode IN ('MODE_A', 'MODE_B')),
            wallet_address VARCHAR(255) NOT NULL,
            clean_wallet VARCHAR(255) NOT NULL,
            venue VARCHAR(32) NOT NULL CHECK (venue IN ('spot', 'dark_pool', 'dark_pool_rfq_maker')),
            pay_asset VARCHAR(16) NOT NULL CHECK (pay_asset ~ '^[A-Z0-9]{2,10}$'),
            receive_asset VARCHAR(16) NOT NULL CHECK (receive_asset ~ '^[A-Z0-9]{2,10}$'),
            amount_in_atomic NUMERIC(39, 0) NOT NULL CHECK (amount_in_atomic > 0),
            expected_out_atomic NUMERIC(39, 0) NOT NULL CHECK (expected_out_atomic > 0),
            min_amount_out_atomic NUMERIC(39, 0) NOT NULL CHECK (min_amount_out_atomic > 0),
            settled_out_atomic NUMERIC(39, 0) NOT NULL CHECK (settled_out_atomic >= min_amount_out_atomic),
            protocol_fee_atomic NUMERIC(39, 0) NOT NULL CHECK (protocol_fee_atomic >= 0),
            network_fee_sompi NUMERIC(39, 0) NOT NULL CHECK (network_fee_sompi >= 0),
            total_fee_usd_micros NUMERIC(39, 0) NOT NULL CHECK (total_fee_usd_micros >= 0),
            notional_usd_micros NUMERIC(39, 0) NOT NULL CHECK (notional_usd_micros > 0),
            pay_oracle_usd_e8 NUMERIC(39, 0) NOT NULL CHECK (pay_oracle_usd_e8 > 0),
            receive_oracle_usd_e8 NUMERIC(39, 0) NOT NULL CHECK (receive_oracle_usd_e8 > 0),
            tx_version INTEGER NOT NULL DEFAULT 1 CHECK (tx_version >= 0),
            compute_mass BIGINT NOT NULL DEFAULT 0 CHECK (compute_mass >= 0),
            storage_mass BIGINT NOT NULL DEFAULT 0 CHECK (storage_mass >= 0),
            covenant_id VARCHAR(64),
            preimage_hash VARCHAR(64) NOT NULL,
            execution_commitment_hash VARCHAR(64) NOT NULL,
            l1_txid VARCHAR(128) NOT NULL,
            hifo_disposal_lot_id UUID,
            hifo_acquisition_lot_id UUID,
            status VARCHAR(32) NOT NULL DEFAULT 'SETTLED',
            executed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "CREATE INDEX IF NOT EXISTS idx_agent_receipts_clean_wallet_time ON public.agent_execution_receipts (clean_wallet, executed_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_agent_receipts_key_time ON public.agent_execution_receipts (key_id, executed_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_agent_receipts_commitment_hash ON public.agent_execution_receipts (execution_commitment_hash)",
        r#"
        CREATE TABLE IF NOT EXISTS public.agent_x402_credits (
            payment_txid VARCHAR(128) PRIMARY KEY,
            key_id VARCHAR(64) NOT NULL REFERENCES public.agent_api_keys(key_id) ON DELETE RESTRICT,
            wallet_address VARCHAR(255) NOT NULL,
            paid_asset VARCHAR(16) NOT NULL CHECK (paid_asset ~ '^[A-Z0-9]{2,10}$'),
            paid_atomic NUMERIC(39, 0) NOT NULL CHECK (paid_atomic > 0),
            credits_granted BIGINT NOT NULL CHECK (credits_granted > 0),
            verified_daa_score BIGINT NOT NULL CHECK (verified_daa_score > 0),
            credited_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "CREATE INDEX IF NOT EXISTS idx_agent_x402_credits_key ON public.agent_x402_credits (key_id, credited_at DESC)",
        r#"
        CREATE TABLE IF NOT EXISTS public.agent_intent_signals (
            signal_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            signal_bucket TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            pay_asset VARCHAR(16) NOT NULL CHECK (pay_asset ~ '^[A-Z0-9]{2,10}$'),
            receive_asset VARCHAR(16) NOT NULL CHECK (receive_asset ~ '^[A-Z0-9]{2,10}$'),
            venue VARCHAR(32) NOT NULL,
            net_kas_delta_sompi NUMERIC(39, 0) NOT NULL DEFAULT 0,
            quote_volume_usd_micros NUMERIC(39, 0) NOT NULL DEFAULT 0,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "CREATE INDEX IF NOT EXISTS idx_agent_intent_signals_bucket ON public.agent_intent_signals (signal_bucket DESC, pay_asset, receive_asset)",
    ];

    for stmt in ddl_statements {
        sqlx::query(stmt).execute(pool).await?;
    }

    Ok(())
}

/// Synchronizes shared PostgreSQL governance, firewall, revocation, fill-concurrency,
/// and LP reserve depth tables into Redis so hot `/api/v1/agent` quote & discovery
/// calls perform zero PostgreSQL queries.
pub async fn sync_shared_state_to_redis(
    pool: &PgPool,
    redis_conn: &mut redis::aio::MultiplexedConnection,
) -> anyhow::Result<()> {
    // 1. Sync Token Steering Matrix -> perennia:steering:token_states & perennia:steering:whitelist
    let steering_rows = sqlx::query(
        r#"
        SELECT ticker, steering_state, is_whitelisted
        FROM token_steering_matrix
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut pipe = redis::pipe();
    pipe.cmd("DEL").arg(REDIS_KEY_STEERING_WHITELIST).ignore();

    let mut whitelisted_count = 0usize;
    for row in steering_rows {
        let raw_ticker: String = row.try_get("ticker").unwrap_or_default();
        let Ok(ticker) = sanitize_sterile_ticker(&raw_ticker) else {
            continue;
        };
        let state_str: String = row
            .try_get::<String, _>("steering_state")
            .unwrap_or_else(|_| "AUTO_BALANCE".to_string())
            .trim()
            .to_uppercase();
        let is_wl: bool = row.try_get("is_whitelisted").unwrap_or(false);

        pipe.cmd("HSET")
            .arg(REDIS_KEY_STEERING_STATES)
            .arg(&ticker)
            .arg(&state_str)
            .ignore();

        if state_str == "BLACKLISTED" {
            pipe.cmd("SADD")
                .arg(REDIS_KEY_BLACKLISTED_TOKENS)
                .arg(&ticker)
                .ignore();
        } else if is_wl && state_str != "PASS_THROUGH" {
            pipe.cmd("SADD")
                .arg(REDIS_KEY_STEERING_WHITELIST)
                .arg(&ticker)
                .ignore();
            whitelisted_count += 1;
        }
    }

    if whitelisted_count == 0 {
        for default_tick in ["KAS", "USDC", "USDT", "BTC", "ETH", "SOL", "SILO"] {
            pipe.cmd("SADD")
                .arg(REDIS_KEY_STEERING_WHITELIST)
                .arg(default_tick)
                .ignore();
            pipe.cmd("HSET")
                .arg(REDIS_KEY_STEERING_STATES)
                .arg(default_tick)
                .arg("AUTO_BALANCE")
                .ignore();
        }
    }

    // 2. Sync active Security Firewall Blacklist entries
    let fw_rows = sqlx::query(
        r#"
        SELECT entity_type, target_value
        FROM security_firewall_blacklist
        WHERE active = TRUE
        "#,
    )
    .fetch_all(pool)
    .await?;

    for row in fw_rows {
        let entity_type: String = row
            .try_get::<String, _>("entity_type")
            .unwrap_or_default()
            .trim()
            .to_uppercase();
        let target: String = row
            .try_get::<String, _>("target_value")
            .unwrap_or_default()
            .trim()
            .to_string();
        if target.is_empty() {
            continue;
        }
        match entity_type.as_str() {
            "WALLET" => {
                let clean = target.to_lowercase().replace("kaspa:", "").trim().to_string();
                let prefixed = format!("kaspa:{}", clean);
                pipe.cmd("SADD")
                    .arg(REDIS_KEY_BLACKLISTED_WALLETS)
                    .arg(&clean)
                    .ignore();
                pipe.cmd("SADD")
                    .arg(REDIS_KEY_BLACKLISTED_WALLETS)
                    .arg(&prefixed)
                    .ignore();
            }
            "TOKEN" => {
                if let Ok(tick) = sanitize_sterile_ticker(&target) {
                    pipe.cmd("SADD")
                        .arg(REDIS_KEY_BLACKLISTED_TOKENS)
                        .arg(&tick)
                        .ignore();
                }
            }
            "IP" => {
                pipe.cmd("SADD")
                    .arg(REDIS_KEY_BLACKLISTED_IPS)
                    .arg(&target)
                    .ignore();
            }
            _ => {}
        }
    }

    // 3. Sync revoked Agent Keys & historical verified fills per wallet/key
    let key_rows = sqlx::query(
        r#"
        SELECT key_id, clean_wallet, is_revoked, verified_fills_count,
               cumulative_volume_usd_micros::TEXT AS vol_usd_micros
        FROM agent_api_keys
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut wallet_fills_acc: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();

    for row in key_rows {
        let key_id: String = row.try_get("key_id").unwrap_or_default();
        let clean_wallet: String = row.try_get("clean_wallet").unwrap_or_default();
        let is_revoked: bool = row.try_get("is_revoked").unwrap_or(false);
        let fills: i64 = row.try_get("verified_fills_count").unwrap_or(0).max(0);
        let vol_str: String = row
            .try_get("vol_usd_micros")
            .unwrap_or_else(|_| "0".to_string());

        if !key_id.is_empty() {
            if is_revoked {
                pipe.cmd("SET")
                    .arg(format!("perennia:agent:revoked:{}", key_id))
                    .arg("1")
                    .ignore();
            }
            pipe.cmd("SET")
                .arg(format!("perennia:agent:key_fills:{}", key_id))
                .arg(fills as u64)
                .ignore();
            pipe.cmd("SET")
                .arg(format!("perennia:agent:key_vol_usd_micros:{}", key_id))
                .arg(&vol_str)
                .ignore();
        }
        if !clean_wallet.is_empty() && fills > 0 {
            let entry = wallet_fills_acc.entry(clean_wallet).or_insert(0);
            *entry = entry.saturating_add(fills as u64);
        }
    }

    for (clean_w, total_fills) in wallet_fills_acc {
        pipe.cmd("SET")
            .arg(format!("perennia:agent:wallet_fills:{}", clean_w))
            .arg(total_fills)
            .ignore();
    }

    // 4. Sync integer E8 LP reserves per pair into Redis Hash (`perennia:agent:lp_depth_e8`)
    let lp_rows = sqlx::query(
        r#"
        SELECT pool_pair,
               TRUNC(GREATEST(COALESCE(SUM(staked_asset_a), 0), 0) * 100000000)::NUMERIC(39, 0)::TEXT AS reserve_a_e8,
               TRUNC(GREATEST(COALESCE(SUM(staked_asset_b), 0), 0) * 100000000)::NUMERIC(39, 0)::TEXT AS reserve_b_e8
        FROM liquidity_providers
        GROUP BY pool_pair
        "#,
    )
    .fetch_all(pool)
    .await?;

    pipe.cmd("DEL").arg(REDIS_KEY_LP_DEPTH_CACHE).ignore();
    for row in lp_rows {
        let raw_pair: String = row.try_get("pool_pair").unwrap_or_default();
        let parts: Vec<&str> = raw_pair.split('/').collect();
        if parts.len() != 2 {
            continue;
        }
        let (Ok(asset_a), Ok(asset_b)) = (
            sanitize_sterile_ticker(parts[0]),
            sanitize_sterile_ticker(parts[1]),
        ) else {
            continue;
        };
        let res_a: String = row
            .try_get("reserve_a_e8")
            .unwrap_or_else(|_| "0".to_string());
        let res_b: String = row
            .try_get("reserve_b_e8")
            .unwrap_or_else(|_| "0".to_string());
        let pair_key = format!("{}/{}", asset_a, asset_b);
        let payload = json!({
            "pair": pair_key,
            "assetA": asset_a,
            "assetB": asset_b,
            "reserveAE8": res_a,
            "reserveBE8": res_b
        });
        pipe.cmd("HSET")
            .arg(REDIS_KEY_LP_DEPTH_CACHE)
            .arg(&pair_key)
            .arg(payload.to_string())
            .ignore();
    }

    // 5. Sync system_treasury_config outflow breaker into Redis
    let sys_cfg = crate::chronos::load_system_treasury_config(pool).await;
    if let Ok(serialized_cfg) = serde_json::to_string(&sys_cfg) {
        pipe.cmd("SET")
            .arg("perennia:treasury:system_config")
            .arg(serialized_cfg)
            .ignore();
    }

    pipe.query_async::<_, ()>(redis_conn).await?;
    Ok(())
}

fn spawn_agent_background_daemons(state: AgentGatewayState) {
    // Daemon 1: 1-second Cache-Only Market-Pulse Streamer + 15-second LP/Governance Cache Sync
    let pulse_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let mut tick: u64 = 0;
        loop {
            interval.tick().await;
            tick = tick.wrapping_add(1);

            let Ok(mut conn) = pulse_state.get_redis_conn().await else {
                continue;
            };

            if tick % 15 == 0 {
                if let Err(e) = sync_shared_state_to_redis(&pulse_state.pg_pool, &mut conn).await {
                    tracing::warn!("⚠️ [AGENT GATEWAY] Periodic Redis state sync warning: {}", e);
                }
            }

            if let Ok(pulse_val) = solvency::build_cached_market_pulse_snapshot(&mut conn).await {
                let serialized = pulse_val.to_string();
                let _: redis::RedisResult<()> = redis::cmd("SETEX")
                    .arg(REDIS_KEY_LATEST_PULSE)
                    .arg(10u64)
                    .arg(&serialized)
                    .query_async(&mut conn)
                    .await;
                let _ = pulse_state.pulse_tx.send(serialized);
            }
        }
    });

    // Daemon 2: Rolling 60-Second Global Agent Anomaly Auto-Breaker
    let anomaly_state = state;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            if let Err(e) = locks_and_limits::evaluate_rolling_60s_anomaly_window(&anomaly_state).await {
                tracing::warn!("⚠️ [AGENT ANOMALY MONITOR] Evaluation warning: {}", e.message);
            }
        }
    });
}

pub fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(forwarded) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = forwarded.split(',').next() {
            let trimmed = first.trim();
            if !trimmed.is_empty() && trimmed.len() <= 64 {
                return trimmed.to_string();
            }
        }
    }
    if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let trimmed = real_ip.trim();
        if !trimmed.is_empty() && trimmed.len() <= 64 {
            return trimmed.to_string();
        }
    }
    "127.0.0.1".to_string()
}

/// Independent Edge Semaphore, IP Firewall & Global Agent Circuit-Breaker Guard.
/// Isolates `/api/v1/agent/...` from SvelteKit (`:3000`) and protects `perennia-node`.
async fn agent_edge_guard(
    State(state): State<AgentGatewayState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, AgentError> {
    let _permit = state
        .edge_semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::EdgeCapacityExceeded,
                "Agent Gateway concurrency budget saturated; retry with exponential backoff or subscribe to /api/v1/agent/stream.",
            )
        })?;

    let mut conn = state.get_redis_conn().await?;

    let client_ip = extract_client_ip(&headers);
    let ip_blacklisted: i32 = redis::cmd("SISMEMBER")
        .arg(REDIS_KEY_BLACKLISTED_IPS)
        .arg(&client_ip)
        .query_async(&mut conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to verify IP firewall state in Redis; failing closed.",
            )
        })?;

    if ip_blacklisted == 1 {
        return Err(AgentError::new(
            AgentErrorCode::FirewallBlacklisted,
            "Client IP is blocked by the Perennia Security Firewall.",
        ));
    }

    locks_and_limits::check_global_agent_circuit_breaker(&mut conn).await?;

    let mut response = next.run(request).await;
    let resp_headers = response.headers_mut();
    resp_headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    resp_headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );

    Ok(response)
}

async fn internal_mandate_auth_guard(
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, AgentError> {
    auth::verify_internal_service_bearer(&headers)?;
    Ok(next.run(request).await)
}

pub fn agent_public_router(state: AgentGatewayState) -> Router {
    Router::new()
        .route(
            "/api/v1/agent/auth/challenge",
            post(auth::handle_mode_a_challenge),
        )
        .route(
            "/api/v1/agent/auth/verify",
            post(auth::handle_mode_a_verify),
        )
        .route(
            "/api/v1/agent/auth/x402/claim",
            post(locks_and_limits::handle_x402_credit_claim),
        )
        .route("/api/v1/agent/markets", get(handlers::handle_get_markets))
        .route("/api/v1/agent/alpha", get(handlers::handle_get_alpha))
        .route("/api/v1/agent/quote", post(handlers::handle_post_quote))
        .route("/api/v1/agent/execute", post(handlers::handle_post_execute))
        .route(
            "/api/v1/agent/chronos/rfq",
            get(dark_pool::handle_get_chronos_rfq),
        )
        .route(
            "/api/v1/agent/chronos/bid",
            post(dark_pool::handle_post_chronos_bid),
        )
        .route(
            "/api/v1/agent/chronos/zktls-unlock",
            post(dark_pool::handle_post_chronos_zktls_unlock),
        )
        .route(
            "/api/v1/agent/me/telemetry",
            get(handlers::handle_get_me_telemetry),
        )
        .route(
            "/api/v1/agent/me/buckets",
            get(handlers::handle_get_me_buckets).post(handlers::handle_post_me_buckets),
        )
        .route("/api/v1/agent/stream", get(handlers::handle_agent_stream))
        .route(
            "/api/v1/agent/mcp",
            get(mcp::handle_mcp_get).post(mcp::handle_mcp_post),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            agent_edge_guard,
        ))
        .with_state(state)
}

pub fn agent_internal_router(state: AgentGatewayState) -> Router {
    Router::new()
        .route(
            "/v1/internal/agent/mandates",
            get(auth::handle_internal_list_mandates)
                .post(auth::handle_internal_create_mandate)
                .delete(auth::handle_internal_revoke_mandate),
        )
        .route(
            "/v1/internal/agent/circuit-breaker",
            post(locks_and_limits::handle_internal_circuit_breaker_toggle),
        )
        .route_layer(middleware::from_fn(internal_mandate_auth_guard))
        .with_state(state)
}