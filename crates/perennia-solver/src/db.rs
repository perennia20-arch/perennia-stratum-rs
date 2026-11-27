use anyhow::Result;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PnlEntryRecord {
    pub strategy: String,
    pub execution_status: String,
    pub dry_run: bool,
    pub pair: String,
    pub perennia_side: String,
    pub cex_venue: String,
    pub cex_order_type: String,
    pub notional_usd: f64,
    pub base_amount: f64,
    pub perennia_exec_price_usd: f64,
    pub cex_vwap_price_usd: f64,
    pub gross_edge_bps: f64,
    pub perennia_fee_bps: f64,
    pub cex_fee_bps: f64,
    pub l1_gas_usd: f64,
    pub slippage_bps: f64,
    pub net_edge_bps: f64,
    pub gross_pnl_usd: f64,
    pub total_costs_usd: f64,
    pub net_pnl_usd: f64,
    pub schnorr_intent_sig: String,
    pub source_ref: String,
    pub metadata_json: Value,
}

pub async fn ensure_solver_schema(pool: &PgPool) -> Result<()> {
    let stmts = [
        r#"
        CREATE TABLE IF NOT EXISTS public.solver_shadow_sessions (
            session_id UUID PRIMARY KEY,
            solver_wallet VARCHAR(255) NOT NULL,
            pubkey_hex VARCHAR(64) NOT NULL,
            agent_key_id VARCHAR(64) NOT NULL,
            dry_run BOOLEAN NOT NULL DEFAULT TRUE,
            shadow_window_hours INTEGER NOT NULL DEFAULT 48,
            started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            shadow_ends_at TIMESTAMPTZ NOT NULL,
            last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            ticks_completed BIGINT NOT NULL DEFAULT 0,
            opportunities_evaluated BIGINT NOT NULL DEFAULT 0,
            profitable_signals_logged BIGINT NOT NULL DEFAULT 0,
            cumulative_net_pnl_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0
        )
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS public.solver_pnl_ledger (
            entry_id UUID PRIMARY KEY,
            session_id UUID NOT NULL REFERENCES public.solver_shadow_sessions(session_id) ON DELETE CASCADE,
            strategy VARCHAR(48) NOT NULL,
            execution_status VARCHAR(32) NOT NULL,
            dry_run BOOLEAN NOT NULL,
            pair VARCHAR(32) NOT NULL,
            perennia_side VARCHAR(48) NOT NULL,
            cex_venue VARCHAR(32) NOT NULL,
            cex_order_type VARCHAR(32) NOT NULL,
            notional_usd DOUBLE PRECISION NOT NULL,
            base_amount DOUBLE PRECISION NOT NULL,
            perennia_exec_price_usd DOUBLE PRECISION NOT NULL,
            cex_vwap_price_usd DOUBLE PRECISION NOT NULL,
            gross_edge_bps DOUBLE PRECISION NOT NULL,
            perennia_fee_bps DOUBLE PRECISION NOT NULL,
            cex_fee_bps DOUBLE PRECISION NOT NULL,
            l1_gas_usd DOUBLE PRECISION NOT NULL,
            slippage_bps DOUBLE PRECISION NOT NULL,
            net_edge_bps DOUBLE PRECISION NOT NULL,
            gross_pnl_usd DOUBLE PRECISION NOT NULL,
            total_costs_usd DOUBLE PRECISION NOT NULL,
            net_pnl_usd DOUBLE PRECISION NOT NULL,
            schnorr_intent_sig VARCHAR(128) NOT NULL,
            source_ref VARCHAR(128) NOT NULL,
            metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (session_id, strategy, source_ref)
        )
        "#,
        "CREATE INDEX IF NOT EXISTS idx_solver_pnl_recorded ON public.solver_pnl_ledger (recorded_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_solver_pnl_strategy_status ON public.solver_pnl_ledger (strategy, execution_status, recorded_at DESC)",
        r#"
        CREATE TABLE IF NOT EXISTS public.solver_epoch_prehedge_runs (
            run_id UUID PRIMARY KEY,
            session_id UUID NOT NULL REFERENCES public.solver_shadow_sessions(session_id) ON DELETE CASCADE,
            epoch_bell_ts BIGINT NOT NULL,
            seconds_until_bell BIGINT NOT NULL,
            run_mode VARCHAR(32) NOT NULL,
            dry_run BOOLEAN NOT NULL,
            total_pending_kas DOUBLE PRECISION NOT NULL,
            total_uncovered_kas DOUBLE PRECISION NOT NULL,
            kas_maker_sell_venue VARCHAR(32) NOT NULL,
            kas_maker_sell_price_usd DOUBLE PRECISION NOT NULL,
            projected_spread_saved_usd DOUBLE PRECISION NOT NULL,
            clearing_target VARCHAR(48) NOT NULL,
            legs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
            recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (session_id, epoch_bell_ts, run_mode)
        )
        "#,
    ];

    for s in stmts {
        sqlx::query(s).execute(pool).await?;
    }
    Ok(())
}

pub async fn create_shadow_session(
    pool: &PgPool,
    solver_wallet: &str,
    pubkey_hex: &str,
    agent_key_id: &str,
    dry_run: bool,
    shadow_window_hours: i32,
) -> Result<Uuid> {
    let session_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO public.solver_shadow_sessions (
            session_id, solver_wallet, pubkey_hex, agent_key_id, dry_run,
            shadow_window_hours, shadow_ends_at
        ) VALUES (
            $1, $2, $3, $4, $5,
            $6, CURRENT_TIMESTAMP + ($6::TEXT || ' hours')::INTERVAL
        )
        "#,
    )
    .bind(session_id)
    .bind(solver_wallet)
    .bind(pubkey_hex)
    .bind(agent_key_id)
    .bind(dry_run)
    .bind(shadow_window_hours)
    .execute(pool)
    .await?;
    Ok(session_id)
}

pub async fn record_pnl_entry(
    pool: &PgPool,
    session_id: Uuid,
    rec: &PnlEntryRecord,
) -> Result<bool> {
    let entry_id = Uuid::new_v4();
    let res = sqlx::query(
        r#"
        INSERT INTO public.solver_pnl_ledger (
            entry_id, session_id, strategy, execution_status, dry_run,
            pair, perennia_side, cex_venue, cex_order_type,
            notional_usd, base_amount, perennia_exec_price_usd, cex_vwap_price_usd,
            gross_edge_bps, perennia_fee_bps, cex_fee_bps, l1_gas_usd,
            slippage_bps, net_edge_bps, gross_pnl_usd, total_costs_usd, net_pnl_usd,
            schnorr_intent_sig, source_ref, metadata_json
        ) VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8, $9,
            $10, $11, $12, $13,
            $14, $15, $16, $17,
            $18, $19, $20, $21, $22,
            $23, $24, $25
        )
        ON CONFLICT (session_id, strategy, source_ref) DO NOTHING
        "#,
    )
    .bind(entry_id)
    .bind(session_id)
    .bind(&rec.strategy)
    .bind(&rec.execution_status)
    .bind(rec.dry_run)
    .bind(&rec.pair)
    .bind(&rec.perennia_side)
    .bind(&rec.cex_venue)
    .bind(&rec.cex_order_type)
    .bind(rec.notional_usd)
    .bind(rec.base_amount)
    .bind(rec.perennia_exec_price_usd)
    .bind(rec.cex_vwap_price_usd)
    .bind(rec.gross_edge_bps)
    .bind(rec.perennia_fee_bps)
    .bind(rec.cex_fee_bps)
    .bind(rec.l1_gas_usd)
    .bind(rec.slippage_bps)
    .bind(rec.net_edge_bps)
    .bind(rec.gross_pnl_usd)
    .bind(rec.total_costs_usd)
    .bind(rec.net_pnl_usd)
    .bind(&rec.schnorr_intent_sig)
    .bind(&rec.source_ref)
    .bind(&rec.metadata_json)
    .execute(pool)
    .await?;

    let inserted = res.rows_affected() > 0;
    if inserted && (rec.execution_status == "SHADOW_FILLED" || rec.execution_status == "LIVE_SETTLED") {
        sqlx::query(
            r#"
            UPDATE public.solver_shadow_sessions
            SET profitable_signals_logged = profitable_signals_logged + 1,
                cumulative_net_pnl_usd = cumulative_net_pnl_usd + $2,
                last_heartbeat_at = CURRENT_TIMESTAMP
            WHERE session_id = $1
            "#,
        )
        .bind(session_id)
        .bind(rec.net_pnl_usd)
        .execute(pool)
        .await?;
    }
    Ok(inserted)
}

#[allow(clippy::too_many_arguments)]
pub async fn record_prehedge_run(
    pool: &PgPool,
    session_id: Uuid,
    epoch_bell_ts: i64,
    seconds_until_bell: i64,
    run_mode: &str,
    dry_run: bool,
    total_pending_kas: f64,
    total_uncovered_kas: f64,
    kas_maker_sell_venue: &str,
    kas_maker_sell_price_usd: f64,
    projected_spread_saved_usd: f64,
    legs_json: &Value,
) -> Result<bool> {
    let run_id = Uuid::new_v4();
    let res = sqlx::query(
        r#"
        INSERT INTO public.solver_epoch_prehedge_runs (
            run_id, session_id, epoch_bell_ts, seconds_until_bell, run_mode, dry_run,
            total_pending_kas, total_uncovered_kas, kas_maker_sell_venue,
            kas_maker_sell_price_usd, projected_spread_saved_usd,
            clearing_target, legs_json
        ) VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9,
            $10, $11,
            '100_PCT_INTERNAL_DARK_POOL_CROSSED', $12
        )
        ON CONFLICT (session_id, epoch_bell_ts, run_mode) DO NOTHING
        "#,
    )
    .bind(run_id)
    .bind(session_id)
    .bind(epoch_bell_ts)
    .bind(seconds_until_bell)
    .bind(run_mode)
    .bind(dry_run)
    .bind(total_pending_kas)
    .bind(total_uncovered_kas)
    .bind(kas_maker_sell_venue)
    .bind(kas_maker_sell_price_usd)
    .bind(projected_spread_saved_usd)
    .bind(legs_json)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn record_solver_tax_event(
    pool: &PgPool,
    wallet_address: &str,
    asset_ticker: &str,
    event_type: &str,
    gross_usd_micros: u128,
    amount_sompi: u128,
    spot_price_e8: u128,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO public.tax_ledger_events (
            wallet_address, asset_ticker, event_type,
            gross_proceeds_usd, amount_tokens, spot_price_at_execution
        ) VALUES (
            $1, $2, $3,
            ($4::NUMERIC / 1000000.0)::DOUBLE PRECISION,
            ($5::NUMERIC / 100000000.0)::DOUBLE PRECISION,
            ($6::NUMERIC / 100000000.0)::DOUBLE PRECISION
        )
        "#,
    )
    .bind(wallet_address)
    .bind(asset_ticker)
    .bind(event_type)
    .bind(gross_usd_micros.to_string())
    .bind(amount_sompi.to_string())
    .bind(spot_price_e8.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn fetch_db_treasury_kas_address(pool: &PgPool) -> Option<String> {
    use sqlx::Row;
    let row = sqlx::query(
        r#"
        SELECT COALESCE(
            NULLIF(TRIM(house_revenue_kas_address), ''),
            NULLIF(TRIM(cold_kas_address), '')
        ) AS addr
        FROM system_treasury_config
        WHERE config_id = 'PRIMARY'
        LIMIT 1
        "#,
    )
    .fetch_optional(pool)
    .await
    .ok()??;
    row.try_get::<Option<String>, _>("addr")
        .ok()
        .flatten()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub async fn heartbeat_session(
    pool: &PgPool,
    session_id: Uuid,
    eval_delta: i64,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE public.solver_shadow_sessions
        SET ticks_completed = ticks_completed + 1,
            opportunities_evaluated = opportunities_evaluated + $2,
            last_heartbeat_at = CURRENT_TIMESTAMP
        WHERE session_id = $1
        "#,
    )
    .bind(session_id)
    .bind(eval_delta)
    .execute(pool)
    .await?;
    Ok(())
}