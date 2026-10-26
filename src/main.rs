mod config;
mod stratum_tcp;
mod telemetry;
mod kaspad_client;
mod job_manager;
mod diff_engine;
mod oracle;
mod sor;
mod chronos;
mod state_api;
mod admin_api;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use axum::{
    extract::{Query, Request},
    http::{StatusCode, HeaderMap},
    middleware::{self, Next},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool};
use job_manager::JobManager;

pub async fn ensure_database_schema(pool: &PgPool) -> anyhow::Result<()> {
    tracing::info!("🛡️ Running Idempotent PostgreSQL Schema Bootstrapper...");
    let ddl_statements = [
        r#"
        CREATE TABLE IF NOT EXISTS user_command_centers (
            wallet_address VARCHAR(255) PRIMARY KEY,
            layout_state JSONB NOT NULL DEFAULT '{}'::jsonb,
            last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS yield_reservoirs (
            wallet_address VARCHAR(255) PRIMARY KEY,
            streaming_balance_kas DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            total_yield_kas DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            lp_tokens JSONB DEFAULT '{}'::jsonb,
            last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        ALTER TABLE yield_reservoirs ADD COLUMN IF NOT EXISTS lp_tokens JSONB DEFAULT '{}'::jsonb
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS network_blocks (
            block_hash VARCHAR(255) PRIMARY KEY,
            worker_id VARCHAR(255) NOT NULL,
            nonce BIGINT NOT NULL,
            network_diff DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            reward_sompi BIGINT NOT NULL DEFAULT 0,
            reward_kas DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            is_orphaned BOOLEAN DEFAULT FALSE,
            discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        ALTER TABLE network_blocks ADD COLUMN IF NOT EXISTS reward_sompi BIGINT NOT NULL DEFAULT 0
        "#,
        r#"
        ALTER TABLE network_blocks ADD COLUMN IF NOT EXISTS reward_kas DOUBLE PRECISION NOT NULL DEFAULT 0.0
        "#,
        r#"
        ALTER TABLE network_blocks ADD COLUMN IF NOT EXISTS is_orphaned BOOLEAN DEFAULT FALSE
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS liquidity_providers (
            lp_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            wallet_address VARCHAR(255) NOT NULL,
            pool_pair VARCHAR(120) NOT NULL,
            staked_asset_a DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            staked_asset_b DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            weights_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            reserves_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            lock_duration_days INTEGER NOT NULL DEFAULT 0,
            unlock_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            last_yield_distribution TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        ALTER TABLE liquidity_providers ALTER COLUMN pool_pair TYPE VARCHAR(120)
        "#,
        r#"
        ALTER TABLE liquidity_providers ADD COLUMN IF NOT EXISTS weights_json JSONB NOT NULL DEFAULT '{}'::jsonb
        "#,
        r#"
        ALTER TABLE liquidity_providers ADD COLUMN IF NOT EXISTS reserves_json JSONB NOT NULL DEFAULT '{}'::jsonb
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_lp_wallet_pair ON liquidity_providers (wallet_address, pool_pair)
        "#,
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
        r#"
        CREATE INDEX IF NOT EXISTS idx_silo_staking_wallet ON silo_staking_positions (wallet_address, status)
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS yield_distributions (
            distribution_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            pool_pair VARCHAR(120) NOT NULL,
            total_fees_distributed_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            distributed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        ALTER TABLE yield_distributions ALTER COLUMN pool_pair TYPE VARCHAR(120)
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS pending_transactions (
            tx_id VARCHAR(255) PRIMARY KEY,
            wallet_address VARCHAR(255) NOT NULL,
            amount_kas DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            action_type VARCHAR(80) NOT NULL DEFAULT 'SOVEREIGN_TRANSFER',
            status VARCHAR(40) NOT NULL DEFAULT 'PENDING',
            block_daa BIGINT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        ALTER TABLE pending_transactions ADD COLUMN IF NOT EXISTS block_daa BIGINT
        "#,
        r#"
        ALTER TABLE pending_transactions ADD COLUMN IF NOT EXISTS status VARCHAR(40) NOT NULL DEFAULT 'PENDING'
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS tax_ledger_events (
            event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            wallet_address VARCHAR(255) NOT NULL,
            asset_ticker VARCHAR(32) NOT NULL,
            event_type VARCHAR(64) NOT NULL,
            gross_proceeds_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            amount_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            spot_price_at_execution DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            tx_hash VARCHAR(255),
            payout_address VARCHAR(255),
            recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        ALTER TABLE tax_ledger_events ADD COLUMN IF NOT EXISTS tx_hash VARCHAR(255)
        "#,
        r#"
        ALTER TABLE tax_ledger_events ADD COLUMN IF NOT EXISTS payout_address VARCHAR(255)
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_tax_ledger_wallet_recorded ON tax_ledger_events (wallet_address, recorded_at DESC)
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS l1_payout_queue (
            payout_id VARCHAR(80) PRIMARY KEY,
            wallet_address VARCHAR(255) NOT NULL,
            destination_address VARCHAR(255) NOT NULL,
            asset_ticker VARCHAR(32) NOT NULL,
            network VARCHAR(32) NOT NULL,
            amount_tokens DOUBLE PRECISION NOT NULL,
            gross_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            spot_price DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            source_type VARCHAR(40) NOT NULL DEFAULT 'ledger_withdrawal',
            tx_hash VARCHAR(255),
            explorer_url TEXT,
            queue_reason TEXT,
            status VARCHAR(40) NOT NULL DEFAULT 'QUEUED_FOR_L1_DISPATCH',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_l1_payout_wallet ON l1_payout_queue (wallet_address, created_at DESC)
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS p2p_orders (
            id VARCHAR(50) PRIMARY KEY,
            seller VARCHAR(255) NOT NULL,
            sell_token VARCHAR(20) NOT NULL,
            sell_amount DOUBLE PRECISION NOT NULL,
            buy_token VARCHAR(20) NOT NULL,
            buy_amount DOUBLE PRECISION NOT NULL,
            rate VARCHAR(50) NOT NULL,
            seller_psbt TEXT,
            status VARCHAR(20) DEFAULT 'open',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS whitelisted_wallets (
            wallet_address VARCHAR(255) PRIMARY KEY,
            label VARCHAR(255) DEFAULT 'Sovereign Miner',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS fiat_payout_queue (
            payout_id VARCHAR(80) PRIMARY KEY,
            wallet_address VARCHAR(255) NOT NULL,
            source_type VARCHAR(40) NOT NULL,
            source_asset VARCHAR(20) NOT NULL,
            amount_crypto DOUBLE PRECISION NOT NULL,
            gross_usd DOUBLE PRECISION NOT NULL,
            fee_usd DOUBLE PRECISION NOT NULL,
            net_fiat_usd DOUBLE PRECISION NOT NULL,
            payout_method VARCHAR(20) NOT NULL,
            bank_last4 VARCHAR(10) NOT NULL,
            tx_id VARCHAR(255),
            trace_id VARCHAR(128),
            status VARCHAR(40) DEFAULT 'QUEUED_FOR_TREASURY_DISPATCH',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        ALTER TABLE fiat_payout_queue ADD COLUMN IF NOT EXISTS trace_id VARCHAR(128)
        "#,
        r#"
        ALTER TABLE fiat_payout_queue ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_fiat_payout_wallet ON fiat_payout_queue (wallet_address, created_at DESC)
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS fiat_bank_rails (
            wallet_address VARCHAR(255) PRIMARY KEY,
            bank_label VARCHAR(128) NOT NULL DEFAULT 'Primary Operating Account',
            account_type VARCHAR(32) NOT NULL DEFAULT 'CHECKING',
            payout_method VARCHAR(20) NOT NULL DEFAULT 'ACH',
            bank_last4 VARCHAR(10) NOT NULL,
            encrypted_rail_payload TEXT NOT NULL,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS fiat_onramp_orders (
            order_id VARCHAR(80) PRIMARY KEY,
            wallet_address VARCHAR(255) NOT NULL,
            payment_rail VARCHAR(40) NOT NULL DEFAULT 'SOVEREIGN_WIRE_ACH',
            settlement_target VARCHAR(32) NOT NULL DEFAULT 'LEDGER_KAS',
            fiat_amount_usd DOUBLE PRECISION NOT NULL,
            fee_usd DOUBLE PRECISION NOT NULL,
            net_usd_converted DOUBLE PRECISION NOT NULL,
            locked_spot_price DOUBLE PRECISION NOT NULL,
            estimated_kas DOUBLE PRECISION NOT NULL,
            delivered_kas DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            wire_memo VARCHAR(80) NOT NULL,
            tx_hash VARCHAR(255),
            status VARCHAR(40) NOT NULL DEFAULT 'AWAITING_WIRE_RECEIPT',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_fiat_onramp_wallet ON fiat_onramp_orders (wallet_address, created_at DESC)
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS rwa_oracle_feeds (
            id SERIAL PRIMARY KEY,
            ticker VARCHAR(32) NOT NULL,
            asset_class VARCHAR(40) NOT NULL DEFAULT 'RWA',
            price_usd DOUBLE PRECISION NOT NULL,
            change_24h_pct DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            oracle_source VARCHAR(40) NOT NULL DEFAULT 'PYTH_HERMES',
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        ALTER TABLE rwa_oracle_feeds ADD COLUMN IF NOT EXISTS change_24h_pct DOUBLE PRECISION NOT NULL DEFAULT 0.0
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_rwa_oracle_ticker_updated ON rwa_oracle_feeds (ticker, updated_at DESC)
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS worker_profiles (
            worker_identity VARCHAR(255) PRIMARY KEY,
            wallet_address VARCHAR(255) NOT NULL,
            worker_name VARCHAR(128) NOT NULL DEFAULT 'Rig',
            hashrate_ths DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            valid_shares BIGINT NOT NULL DEFAULT 0,
            rejected_shares BIGINT NOT NULL DEFAULT 0,
            acceptance_pct DOUBLE PRECISION NOT NULL DEFAULT 100.0,
            blocks_found BIGINT NOT NULL DEFAULT 0,
            last_share_ts BIGINT NOT NULL DEFAULT 0,
            status VARCHAR(32) NOT NULL DEFAULT 'online',
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS wallet_address VARCHAR(255) NOT NULL DEFAULT ''
        "#,
        r#"
        ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS worker_name VARCHAR(128) NOT NULL DEFAULT 'Rig'
        "#,
        r#"
        ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS hashrate_ths DOUBLE PRECISION NOT NULL DEFAULT 0.0
        "#,
        r#"
        ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS valid_shares BIGINT NOT NULL DEFAULT 0
        "#,
        r#"
        ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS rejected_shares BIGINT NOT NULL DEFAULT 0
        "#,
        r#"
        ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS acceptance_pct DOUBLE PRECISION NOT NULL DEFAULT 100.0
        "#,
        r#"
        ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS blocks_found BIGINT NOT NULL DEFAULT 0
        "#,
        r#"
        ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS last_share_ts BIGINT NOT NULL DEFAULT 0
        "#,
        r#"
        ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS status VARCHAR(32) NOT NULL DEFAULT 'online'
        "#,
        r#"
        ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS entity_kyc (
            wallet_address VARCHAR(255) PRIMARY KEY,
            legal_name VARCHAR(255) NOT NULL DEFAULT 'ZERO_PII_SOVEREIGN',
            entity_type VARCHAR(64) NOT NULL DEFAULT 'LLC',
            tax_id_hash TEXT NOT NULL DEFAULT 'ZERO_PII_LOCAL_ONLY',
            bank_data_hash TEXT,
            business_address TEXT NOT NULL DEFAULT 'ZERO_PII_LOCAL_ONLY',
            country_code VARCHAR(16) NOT NULL DEFAULT 'US',
            state_region VARCHAR(64) NOT NULL DEFAULT 'TX',
            filing_status VARCHAR(64) NOT NULL DEFAULT 'SINGLE',
            effective_tax_rate DOUBLE PRECISION NOT NULL DEFAULT 15.0,
            verification_status VARCHAR(40) DEFAULT 'verified',
            verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        ALTER TABLE entity_kyc ADD COLUMN IF NOT EXISTS country_code VARCHAR(16) NOT NULL DEFAULT 'US'
        "#,
        r#"
        ALTER TABLE entity_kyc ADD COLUMN IF NOT EXISTS state_region VARCHAR(64) NOT NULL DEFAULT 'TX'
        "#,
        r#"
        ALTER TABLE entity_kyc ADD COLUMN IF NOT EXISTS filing_status VARCHAR(64) NOT NULL DEFAULT 'SINGLE'
        "#,
        r#"
        ALTER TABLE entity_kyc ADD COLUMN IF NOT EXISTS effective_tax_rate DOUBLE PRECISION NOT NULL DEFAULT 15.0
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS micro_shares (
            share_id BIGSERIAL PRIMARY KEY,
            worker_identity VARCHAR(255) NOT NULL,
            difficulty DOUBLE PRECISION NOT NULL DEFAULT 1.0,
            is_valid BOOLEAN NOT NULL DEFAULT TRUE,
            recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
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
            lock_tx_hash VARCHAR(255),
            status VARCHAR(32) NOT NULL DEFAULT 'LOCKED',
            last_bell_unlocked_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS idx_forge_vesting_ticker ON forge_vesting_schedules (token_ticker, status)
        "#,
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
            anchor_tx_hash VARCHAR(255),
            last_bell_processed_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
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
    ];
    for stmt in ddl_statements {
        if let Err(e) = sqlx::query(stmt).execute(pool).await {
            tracing::warn!("Schema bootstrapper statement notice: {}", e);
        }
    }
    tracing::info!("✅ PostgreSQL Schema Bootstrapper Verified (21 Core & Forge v5 Tables Ready).");
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn internal_auth_guard(
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let internal_token = std::env::var("INTERNAL_ADMIN_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let admin_key = std::env::var("PERENNIA_ADMIN_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let has_configured_secret = internal_token.is_some() || admin_key.is_some();
    let enforce_strict = std::env::var("ENFORCE_INTERNAL_AUTH")
        .ok()
        .map(|v| !v.trim().eq_ignore_ascii_case("false"))
        .unwrap_or(has_configured_secret);
    if enforce_strict && has_configured_secret {
        let provided = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let mut authorized = false;
        if let Some(ref tok) = internal_token {
            let expected = format!("Bearer {}", tok);
            if constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
                authorized = true;
            }
        }
        if !authorized {
            if let Some(ref key) = admin_key {
                let expected = format!("Bearer {}", key);
                if constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
                    authorized = true;
                }
            }
        }
        if !authorized {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "UNAUTHORIZED_INTERNAL_RPC" })),
            ));
        }
    }
    Ok(next.run(request).await)
}

async fn handle_get_balance(
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let raw_address = params
        .get("address")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Missing address query parameter." })),
            )
        })?;
    let clean_addr = raw_address.replace("kaspa:", "");
    let formatted_addr = format!("kaspa:{}", clean_addr);
    let rest_url = std::env::var("KASPA_REST_URL")
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .unwrap_or_else(|_| "https://api.kaspa.org".to_string());
    let endpoint = format!("{}/addresses/{}/balance", rest_url, formatted_addr);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let response = client.get(&endpoint).send().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": format!("Upstream node balance query failed: {}", e) })),
        )
    })?;
    if !response.status().is_success() {
        let err_body = response.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": format!("Node rejected balance lookup: {}", err_body) })),
        ));
    }
    let data: Value = response.json().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Invalid JSON from upstream node: {}", e) })),
        )
    })?;
    let sompi = data
        .get("balance")
        .and_then(|v| {
            v.as_f64()
                .or_else(|| v.as_u64().map(|u| u as f64))
                .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
        })
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Malformed balance payload from node." })),
            )
        })?;
    let balance_kas = sompi / 100_000_000.0;
    Ok(Json(json!({
        "balance": balance_kas,
        "balanceKas": balance_kas
    })))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to init tracing");
    tracing::info!("Booting Perennia Core Engine (Hybrid Mainnet + Stratum)...");
    let config = Arc::new(config::StratumConfig::load("config.yaml")?);
    tracing::info!("Targeted Treasury Wallet: {}", config.mining_address);
    tracing::info!("Initializing PostgreSQL Pool...");
    let db_url = std::env::var("DATABASE_URL").expect("CRITICAL: DATABASE_URL environment variable is required.");
    let redis_url = std::env::var("REDIS_URL").expect("CRITICAL: REDIS_URL environment variable is required.");
    let pool = PgPoolOptions::new()
        .max_connections(50)
        .connect(&db_url)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to connect to PostgreSQL (Ensure DB is running): {}", e);
            panic!("Database connection required for routing dependencies: {}", e);
        });
    ensure_database_schema(&pool).await?;
    let (daa_tx, _) = tokio::sync::broadcast::channel::<u64>(100);
    let (utxo_tx, _) = tokio::sync::broadcast::channel::<kaspad_client::protowire::UtxosChangedNotificationMessage>(1000);
    let pool_chronos = pool.clone();
    tokio::spawn(async move {
        chronos::start_chronos_daemon(pool_chronos).await;
    });
    let pool_watcher = pool.clone();
    let daa_rx = daa_tx.subscribe();
    let utxo_rx = utxo_tx.subscribe();
    tokio::spawn(async move {
        chronos::start_mempool_watcher_daemon(pool_watcher, daa_rx, utxo_rx).await;
    });
    let utxo_rx_cons = utxo_tx.subscribe();
    tokio::spawn(async move {
        chronos::start_utxo_consolidation_daemon(utxo_rx_cons).await;
    });
    if let Ok(redis_client_netting) = redis::Client::open(redis_url.clone()) {
        let pool_netting = pool.clone();
        tokio::spawn(async move {
            chronos::start_delta_netting_engine(redis_client_netting, pool_netting).await;
        });
    }
    telemetry::init_telemetry();
    let prom_port = config.prom_port.clone();
    tokio::spawn(async move {
        telemetry::start_prometheus_exporter(prom_port).await;
    });
    let (valid_share_tx, valid_share_rx) = mpsc::channel::<(String, f64, bool)>(10000);
    tokio::spawn(async move {
        telemetry::start_accounting_engine(valid_share_rx).await;
    });
    tokio::spawn(async move {
        oracle::start_oracle_daemon().await;
    });
    tokio::spawn(async move {
        oracle::start_spot_pricing_daemon().await;
    });
    let pool_pyth = pool.clone();
    tokio::spawn(async move {
        oracle::start_pyth_rwa_oracle_daemon(pool_pyth).await;
    });
    let (job_manager_arc, _job_rx, block_submit_rx) = JobManager::new();
    let config_clone = config.clone();
    let jm_clone = job_manager_arc.clone();
    let daa_tx_clone = daa_tx.clone();
    let utxo_tx_clone = utxo_tx.clone();
    let share_tx_kaspad = valid_share_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = kaspad_client::start_kaspad_client(
            config_clone,
            jm_clone,
            block_submit_rx,
            share_tx_kaspad,
            daa_tx_clone,
            utxo_tx_clone,
        ).await {
            tracing::error!("Kaspa gRPC Connection Fatal Error: {}", e);
        }
    });
    let protected_routes = Router::new()
        .route("/v1/sor/execute", post(sor::handle_sor_execute))
        .route("/v1/state/action", post(state_api::handle_state_action))
        .route_layer(middleware::from_fn(internal_auth_guard));
    let app = Router::new()
        .route("/v1/balance", get(handle_get_balance))
        .merge(protected_routes)
        .merge(admin_api::admin_routes())
        .with_state(pool.clone());
    let bind_host = std::env::var("RUST_BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8002".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_host).await?;
    tokio::spawn(async move {
        tracing::info!("🚀 Axum HTTP Server bound instantly on {} (SOR, State, Balance & Admin API Armed)", bind_host);
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("Axum Server Error: {}", e);
        }
    });
    let cfg_t1 = config.clone();
    let jm_t1 = job_manager_arc.clone();
    let tx_t1 = valid_share_tx.clone();
    let pool_t1 = pool.clone();
    tokio::spawn(async move {
        if let Err(e) = stratum_tcp::start_stratum_server(cfg_t1, jm_t1, tx_t1, pool_t1, 6551, 1.0, 0).await {
            tracing::error!("Tier 1 (GPU) failed: {}", e);
        }
    });
    let cfg_t2 = config.clone();
    let jm_t2 = job_manager_arc.clone();
    let tx_t2 = valid_share_tx.clone();
    let pool_t2 = pool.clone();
    tokio::spawn(async move {
        if let Err(e) = stratum_tcp::start_stratum_server(cfg_t2, jm_t2, tx_t2, pool_t2, 6552, 256.0, 2500).await {
            tracing::error!("Tier 2 (Home ASICs) failed: {}", e);
        }
    });
    let cfg_t3 = config.clone();
    let jm_t3 = job_manager_arc.clone();
    let tx_t3 = valid_share_tx.clone();
    let pool_t3 = pool.clone();
    stratum_tcp::start_stratum_server(cfg_t3, jm_t3, tx_t3, pool_t3, 6553, 1024.0, 3000).await?;
    Ok(())
}