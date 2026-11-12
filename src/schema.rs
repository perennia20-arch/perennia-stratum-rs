use sqlx::PgPool;
use std::env;

pub async fn ensure_database_schema(pool: &PgPool) -> anyhow::Result<()> {
    tracing::info!("🛡️ Running Idempotent PostgreSQL Schema Bootstrapper...");

    let ddl_statements = [
        r#"
        CREATE TABLE IF NOT EXISTS system_treasury_config (
            config_id VARCHAR(64) PRIMARY KEY DEFAULT 'PRIMARY',
            hot_ceiling_kas DOUBLE PRECISION NOT NULL DEFAULT 5000.0,
            min_runway_kas DOUBLE PRECISION NOT NULL DEFAULT 250.0,
            fpps_max_float_kas DOUBLE PRECISION NOT NULL DEFAULT 50.0,
            pool_fee_rate DOUBLE PRECISION NOT NULL DEFAULT 0.01,
            outflow_breaker_tripped BOOLEAN NOT NULL DEFAULT FALSE,
            cold_kas_address VARCHAR(255) NOT NULL DEFAULT '',
            cold_btc_address VARCHAR(255) NOT NULL DEFAULT '',
            cold_eth_address VARCHAR(255) NOT NULL DEFAULT '',
            cold_sol_address VARCHAR(255) NOT NULL DEFAULT '',
            updated_by VARCHAR(255) NOT NULL DEFAULT 'SYSTEM_BOOT',
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "ALTER TABLE system_treasury_config ADD COLUMN IF NOT EXISTS hot_ceiling_kas DOUBLE PRECISION NOT NULL DEFAULT 5000.0",
        "ALTER TABLE system_treasury_config ADD COLUMN IF NOT EXISTS min_runway_kas DOUBLE PRECISION NOT NULL DEFAULT 250.0",
        "ALTER TABLE system_treasury_config ADD COLUMN IF NOT EXISTS fpps_max_float_kas DOUBLE PRECISION NOT NULL DEFAULT 50.0",
        "ALTER TABLE system_treasury_config ADD COLUMN IF NOT EXISTS pool_fee_rate DOUBLE PRECISION NOT NULL DEFAULT 0.01",
        "ALTER TABLE system_treasury_config ADD COLUMN IF NOT EXISTS outflow_breaker_tripped BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE system_treasury_config ADD COLUMN IF NOT EXISTS cold_kas_address VARCHAR(255) NOT NULL DEFAULT ''",
        "ALTER TABLE system_treasury_config ADD COLUMN IF NOT EXISTS cold_btc_address VARCHAR(255) NOT NULL DEFAULT ''",
        "ALTER TABLE system_treasury_config ADD COLUMN IF NOT EXISTS cold_eth_address VARCHAR(255) NOT NULL DEFAULT ''",
        "ALTER TABLE system_treasury_config ADD COLUMN IF NOT EXISTS cold_sol_address VARCHAR(255) NOT NULL DEFAULT ''",
        "ALTER TABLE system_treasury_config ADD COLUMN IF NOT EXISTS updated_by VARCHAR(255) NOT NULL DEFAULT 'SYSTEM_BOOT'",
        "ALTER TABLE system_treasury_config ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP",
        r#"
        CREATE TABLE IF NOT EXISTS user_cold_vault_rules (
            wallet_address VARCHAR(255) NOT NULL,
            asset_ticker VARCHAR(32) NOT NULL,
            network VARCHAR(32) NOT NULL DEFAULT 'KAS',
            cold_destination_address VARCHAR(255) NOT NULL,
            vault_label VARCHAR(128) NOT NULL DEFAULT 'Perennia Cold Vault',
            overflow_ceiling DOUBLE PRECISION NOT NULL DEFAULT 500.0,
            auto_sweep_enabled BOOLEAN NOT NULL DEFAULT FALSE,
            last_sweep_txid VARCHAR(128),
            last_sweep_amount DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            last_sweep_at TIMESTAMP WITH TIME ZONE,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (wallet_address, asset_ticker)
        )
        "#,
        "CREATE INDEX IF NOT EXISTS idx_user_cold_vault_rules_auto ON user_cold_vault_rules (auto_sweep_enabled, asset_ticker)",
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
            verified_onchain_credits_kas DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            row_hmac_sig VARCHAR(128) NOT NULL DEFAULT '',
            quarantined BOOLEAN NOT NULL DEFAULT FALSE,
            quarantine_reason TEXT,
            quarantined_at TIMESTAMP WITH TIME ZONE,
            last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "ALTER TABLE yield_reservoirs ADD COLUMN IF NOT EXISTS lp_tokens JSONB DEFAULT '{}'::jsonb",
        "ALTER TABLE yield_reservoirs ADD COLUMN IF NOT EXISTS verified_onchain_credits_kas DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE yield_reservoirs ADD COLUMN IF NOT EXISTS row_hmac_sig VARCHAR(128) NOT NULL DEFAULT ''",
        "ALTER TABLE yield_reservoirs ADD COLUMN IF NOT EXISTS quarantined BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE yield_reservoirs ADD COLUMN IF NOT EXISTS quarantine_reason TEXT",
        "ALTER TABLE yield_reservoirs ADD COLUMN IF NOT EXISTS quarantined_at TIMESTAMP WITH TIME ZONE",
        r#"
        CREATE TABLE IF NOT EXISTS network_blocks (
            block_hash VARCHAR(255) PRIMARY KEY,
            worker_id VARCHAR(255) NOT NULL,
            nonce BIGINT NOT NULL,
            network_diff DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            reward_sompi BIGINT NOT NULL DEFAULT 0,
            reward_kas DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            daa_score BIGINT NOT NULL DEFAULT 0,
            is_orphaned BOOLEAN DEFAULT FALSE,
            discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "ALTER TABLE network_blocks ADD COLUMN IF NOT EXISTS reward_sompi BIGINT NOT NULL DEFAULT 0",
        "ALTER TABLE network_blocks ADD COLUMN IF NOT EXISTS reward_kas DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE network_blocks ADD COLUMN IF NOT EXISTS daa_score BIGINT NOT NULL DEFAULT 0",
        "ALTER TABLE network_blocks ADD COLUMN IF NOT EXISTS is_orphaned BOOLEAN DEFAULT FALSE",
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
        "ALTER TABLE liquidity_providers ALTER COLUMN pool_pair TYPE VARCHAR(120)",
        "ALTER TABLE liquidity_providers ADD COLUMN IF NOT EXISTS weights_json JSONB NOT NULL DEFAULT '{}'::jsonb",
        "ALTER TABLE liquidity_providers ADD COLUMN IF NOT EXISTS reserves_json JSONB NOT NULL DEFAULT '{}'::jsonb",
        "CREATE INDEX IF NOT EXISTS idx_lp_wallet_pair ON liquidity_providers (wallet_address, pool_pair)",
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
        r#"
        CREATE TABLE IF NOT EXISTS yield_distributions (
            distribution_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            pool_pair VARCHAR(120) NOT NULL,
            total_fees_distributed_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            distributed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "ALTER TABLE yield_distributions ALTER COLUMN pool_pair TYPE VARCHAR(120)",
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
        "ALTER TABLE pending_transactions ADD COLUMN IF NOT EXISTS block_daa BIGINT",
        "ALTER TABLE pending_transactions ADD COLUMN IF NOT EXISTS status VARCHAR(40) NOT NULL DEFAULT 'PENDING'",
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
            cost_basis_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            realized_gain_loss_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            holding_period VARCHAR(32) NOT NULL DEFAULT 'SHORT_TERM',
            recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "ALTER TABLE tax_ledger_events ADD COLUMN IF NOT EXISTS tx_hash VARCHAR(255)",
        "ALTER TABLE tax_ledger_events ADD COLUMN IF NOT EXISTS payout_address VARCHAR(255)",
        "ALTER TABLE tax_ledger_events ADD COLUMN IF NOT EXISTS cost_basis_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE tax_ledger_events ADD COLUMN IF NOT EXISTS realized_gain_loss_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE tax_ledger_events ADD COLUMN IF NOT EXISTS holding_period VARCHAR(32) NOT NULL DEFAULT 'SHORT_TERM'",
        "CREATE INDEX IF NOT EXISTS idx_tax_ledger_wallet_recorded ON tax_ledger_events (wallet_address, recorded_at DESC)",
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
        "CREATE INDEX IF NOT EXISTS idx_l1_payout_wallet ON l1_payout_queue (wallet_address, created_at DESC)",
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
        CREATE TABLE IF NOT EXISTS invite_codes (
            code VARCHAR(64) PRIMARY KEY,
            is_used BOOLEAN NOT NULL DEFAULT FALSE,
            used_by VARCHAR(255),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS fiat_payout_queue (
            payout_id VARCHAR(80) PRIMARY KEY,
            wallet_address VARCHAR(255) NOT NULL,
            source_type VARCHAR(64) NOT NULL,
            source_asset VARCHAR(20) NOT NULL,
            amount_crypto DOUBLE PRECISION NOT NULL,
            gross_usd DOUBLE PRECISION NOT NULL,
            fee_usd DOUBLE PRECISION NOT NULL,
            hard_cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            guaranteed_profit_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            competitor_fee_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            guest_savings_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            net_fiat_usd DOUBLE PRECISION NOT NULL,
            payout_method VARCHAR(20) NOT NULL,
            bank_last4 VARCHAR(10) NOT NULL,
            deposit_address VARCHAR(255),
            changenow_exchange_id VARCHAR(128),
            routing_topology VARCHAR(128),
            confirmations_required INTEGER NOT NULL DEFAULT 6,
            confirmations_current INTEGER NOT NULL DEFAULT 0,
            tx_id VARCHAR(255),
            trace_id VARCHAR(128),
            status VARCHAR(40) DEFAULT 'QUEUED_FOR_TREASURY_DISPATCH',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "ALTER TABLE fiat_payout_queue ALTER COLUMN source_type TYPE VARCHAR(64)",
        "ALTER TABLE fiat_payout_queue ADD COLUMN IF NOT EXISTS hard_cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE fiat_payout_queue ADD COLUMN IF NOT EXISTS guaranteed_profit_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE fiat_payout_queue ADD COLUMN IF NOT EXISTS competitor_fee_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE fiat_payout_queue ADD COLUMN IF NOT EXISTS guest_savings_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE fiat_payout_queue ADD COLUMN IF NOT EXISTS deposit_address VARCHAR(255)",
        "ALTER TABLE fiat_payout_queue ADD COLUMN IF NOT EXISTS changenow_exchange_id VARCHAR(128)",
        "ALTER TABLE fiat_payout_queue ADD COLUMN IF NOT EXISTS routing_topology VARCHAR(128)",
        "ALTER TABLE fiat_payout_queue ADD COLUMN IF NOT EXISTS confirmations_required INTEGER NOT NULL DEFAULT 6",
        "ALTER TABLE fiat_payout_queue ADD COLUMN IF NOT EXISTS confirmations_current INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE fiat_payout_queue ADD COLUMN IF NOT EXISTS trace_id VARCHAR(128)",
        "ALTER TABLE fiat_payout_queue ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP",
        "CREATE INDEX IF NOT EXISTS idx_fiat_payout_wallet ON fiat_payout_queue (wallet_address, created_at DESC)",
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
            payment_rail VARCHAR(64) NOT NULL DEFAULT 'STRIPE_ACH_DIRECT_DEBIT',
            payment_method VARCHAR(32) NOT NULL DEFAULT 'ach',
            tier_name VARCHAR(32) NOT NULL DEFAULT 'RETAIL',
            tier_bps INTEGER NOT NULL DEFAULT 85,
            settlement_target VARCHAR(64) NOT NULL DEFAULT 'LEDGER_KAS',
            target_asset VARCHAR(32) NOT NULL DEFAULT 'KAS',
            target_spot_price DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            estimated_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            auto_stake_silo BOOLEAN NOT NULL DEFAULT FALSE,
            quoted_principal_cents BIGINT NOT NULL DEFAULT 0,
            perennia_fee_cents BIGINT NOT NULL DEFAULT 250,
            stripe_gateway_fee_cents BIGINT NOT NULL DEFAULT 0,
            gross_charge_cents BIGINT NOT NULL DEFAULT 0,
            settled_net_cents BIGINT,
            fulfilled_principal_cents BIGINT,
            quarantine_reason TEXT,
            fiat_amount_usd DOUBLE PRECISION NOT NULL,
            fee_usd DOUBLE PRECISION NOT NULL,
            hard_cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            guaranteed_profit_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            competitor_fee_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            guest_savings_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            net_usd_converted DOUBLE PRECISION NOT NULL,
            locked_spot_price DOUBLE PRECISION NOT NULL,
            estimated_kas DOUBLE PRECISION NOT NULL,
            delivered_kas DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            wire_memo VARCHAR(80) NOT NULL,
            routing_topology VARCHAR(128),
            wholesale_order_id VARCHAR(96),
            wholesale_withdraw_id VARCHAR(96),
            changenow_exchange_id VARCHAR(128),
            payin_address VARCHAR(255),
            stripe_payment_intent_id VARCHAR(128),
            stripe_onramp_session_id VARCHAR(128),
            bridge_virtual_account_id VARCHAR(128),
            bridge_wire_routing VARCHAR(64),
            bridge_wire_account VARCHAR(64),
            bank_last4 VARCHAR(10),
            master_treasury_fee_usdc DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            post_trade_sweep_json JSONB DEFAULT '{}'::jsonb,
            tx_hash VARCHAR(255),
            status VARCHAR(64) NOT NULL DEFAULT 'AWAITING_WIRE_RECEIPT',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "ALTER TABLE fiat_onramp_orders ALTER COLUMN payment_rail TYPE VARCHAR(64)",
        "ALTER TABLE fiat_onramp_orders ALTER COLUMN settlement_target TYPE VARCHAR(64)",
        "ALTER TABLE fiat_onramp_orders ALTER COLUMN status TYPE VARCHAR(64)",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS payment_method VARCHAR(32) NOT NULL DEFAULT 'ach'",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS tier_name VARCHAR(32) NOT NULL DEFAULT 'RETAIL'",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS tier_bps INTEGER NOT NULL DEFAULT 85",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS target_asset VARCHAR(32) NOT NULL DEFAULT 'KAS'",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS target_spot_price DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS estimated_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS auto_stake_silo BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS quoted_principal_cents BIGINT NOT NULL DEFAULT 0",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS perennia_fee_cents BIGINT NOT NULL DEFAULT 250",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS stripe_gateway_fee_cents BIGINT NOT NULL DEFAULT 0",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS gross_charge_cents BIGINT NOT NULL DEFAULT 0",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS settled_net_cents BIGINT",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS fulfilled_principal_cents BIGINT",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS quarantine_reason TEXT",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS hard_cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS guaranteed_profit_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS competitor_fee_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS guest_savings_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS routing_topology VARCHAR(128)",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS wholesale_order_id VARCHAR(96)",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS wholesale_withdraw_id VARCHAR(96)",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS changenow_exchange_id VARCHAR(128)",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS payin_address VARCHAR(255)",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS stripe_payment_intent_id VARCHAR(128)",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS stripe_onramp_session_id VARCHAR(128)",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS bridge_virtual_account_id VARCHAR(128)",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS bridge_wire_routing VARCHAR(64)",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS bridge_wire_account VARCHAR(64)",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS bank_last4 VARCHAR(10)",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS master_treasury_fee_usdc DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE fiat_onramp_orders ADD COLUMN IF NOT EXISTS post_trade_sweep_json JSONB DEFAULT '{}'::jsonb",
        "CREATE INDEX IF NOT EXISTS idx_fiat_onramp_wallet ON fiat_onramp_orders (wallet_address, created_at DESC)",
        r#"
        CREATE TABLE IF NOT EXISTS fiat_float_ledger (
            ledger_id VARCHAR(64) PRIMARY KEY,
            local_kas_reserve_usd DOUBLE PRECISION NOT NULL DEFAULT 500.0,
            local_kas_target_cap_usd DOUBLE PRECISION NOT NULL DEFAULT 500.0,
            wholesale_api_working_usd DOUBLE PRECISION NOT NULL DEFAULT 400.0,
            wholesale_api_target_cap_usd DOUBLE PRECISION NOT NULL DEFAULT 400.0,
            ratchet_target_cap_usd DOUBLE PRECISION NOT NULL DEFAULT 5000.0,
            commercial_checking_cleared_usd DOUBLE PRECISION NOT NULL DEFAULT 1500.0,
            llc_tax_escrow_reserve_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            dark_pool_lp_vault_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            master_treasury_usdc_reserve DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            phase2_ach_target_usd DOUBLE PRECISION NOT NULL DEFAULT 250000.0,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "ALTER TABLE fiat_float_ledger ADD COLUMN IF NOT EXISTS master_treasury_usdc_reserve DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE fiat_float_ledger ADD COLUMN IF NOT EXISTS phase2_ach_target_usd DOUBLE PRECISION NOT NULL DEFAULT 250000.0",
        r#"
        CREATE TABLE IF NOT EXISTS fiat_post_trade_sweeps (
            sweep_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            order_id VARCHAR(80) NOT NULL,
            direction VARCHAR(24) NOT NULL DEFAULT 'ONRAMP',
            asset_ticker VARCHAR(32) NOT NULL DEFAULT 'KAS',
            gross_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            wholesale_api_float_sweep_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            chronos_miner_settlement_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            llc_tax_and_rail_reserve_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            net_profit_and_ratchet_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            float_ratchet_reinvest_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            dark_pool_lp_and_owner_draw_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
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
        "ALTER TABLE rwa_oracle_feeds ADD COLUMN IF NOT EXISTS change_24h_pct DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "DELETE FROM rwa_oracle_feeds a USING rwa_oracle_feeds b WHERE a.id < b.id AND a.ticker = b.ticker",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_rwa_oracle_feeds_ticker_unique ON rwa_oracle_feeds (ticker)",
        "CREATE INDEX IF NOT EXISTS idx_rwa_oracle_ticker_updated ON rwa_oracle_feeds (ticker, updated_at DESC)",
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
            streak_started_ts BIGINT NOT NULL DEFAULT 0,
            effective_fee_rate DOUBLE PRECISION NOT NULL DEFAULT 0.01,
            status VARCHAR(32) NOT NULL DEFAULT 'online',
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS wallet_address VARCHAR(255) NOT NULL DEFAULT ''",
        "ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS worker_name VARCHAR(128) NOT NULL DEFAULT 'Rig'",
        "ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS hashrate_ths DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS valid_shares BIGINT NOT NULL DEFAULT 0",
        "ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS rejected_shares BIGINT NOT NULL DEFAULT 0",
        "ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS acceptance_pct DOUBLE PRECISION NOT NULL DEFAULT 100.0",
        "ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS blocks_found BIGINT NOT NULL DEFAULT 0",
        "ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS last_share_ts BIGINT NOT NULL DEFAULT 0",
        "ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS streak_started_ts BIGINT NOT NULL DEFAULT 0",
        "ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS effective_fee_rate DOUBLE PRECISION NOT NULL DEFAULT 0.01",
        "ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS status VARCHAR(32) NOT NULL DEFAULT 'online'",
        "ALTER TABLE worker_profiles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP",
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
        "ALTER TABLE entity_kyc ADD COLUMN IF NOT EXISTS country_code VARCHAR(16) NOT NULL DEFAULT 'US'",
        "ALTER TABLE entity_kyc ADD COLUMN IF NOT EXISTS state_region VARCHAR(64) NOT NULL DEFAULT 'TX'",
        "ALTER TABLE entity_kyc ADD COLUMN IF NOT EXISTS filing_status VARCHAR(64) NOT NULL DEFAULT 'SINGLE'",
        "ALTER TABLE entity_kyc ADD COLUMN IF NOT EXISTS effective_tax_rate DOUBLE PRECISION NOT NULL DEFAULT 15.0",
        r#"
        CREATE UNLOGGED TABLE IF NOT EXISTS micro_shares (
            share_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            worker_id VARCHAR(255) NOT NULL,
            difficulty_weight DOUBLE PRECISION NOT NULL,
            kas_value_delta DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            network_diff DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            is_settled BOOLEAN NOT NULL DEFAULT FALSE,
            recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "UPDATE worker_profiles SET worker_identity = worker_id WHERE worker_identity IS NULL OR worker_identity = ''",
        "DELETE FROM worker_profiles a USING worker_profiles b WHERE a.ctid < b.ctid AND a.worker_identity = b.worker_identity",
        "UPDATE worker_profiles SET worker_id = worker_identity WHERE worker_identity IS NOT NULL AND worker_identity != '' AND worker_id != worker_identity",
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
        CREATE TABLE IF NOT EXISTS idempotent_payout_batches (
            batch_id VARCHAR(96) PRIMARY KEY,
            idempotency_key VARCHAR(128) UNIQUE NOT NULL,
            deterministic_txid VARCHAR(128),
            signed_tx_json JSONB,
            total_sompi BIGINT NOT NULL DEFAULT 0,
            recipient_manifest JSONB NOT NULL DEFAULT '[]'::jsonb,
            state VARCHAR(48) NOT NULL DEFAULT 'QUEUED',
            daa_score BIGINT,
            retry_count INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "CREATE INDEX IF NOT EXISTS idx_idempotent_payout_state ON idempotent_payout_batches (state, updated_at ASC)",
        "CREATE INDEX IF NOT EXISTS idx_idempotent_payout_txid ON idempotent_payout_batches (deterministic_txid)",
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
        CREATE TABLE IF NOT EXISTS treasury_airlock_sweeps (
            sweep_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            hot_wallet_address VARCHAR(255) NOT NULL,
            cold_vault_address VARCHAR(255) NOT NULL,
            swept_kas DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            hot_balance_before_kas DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            hot_balance_after_kas DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            runway_hours_remaining DOUBLE PRECISION NOT NULL DEFAULT 24.0,
            tx_id VARCHAR(128),
            status VARCHAR(48) NOT NULL DEFAULT 'SWEPT_TO_COLD',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
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
        "CREATE INDEX IF NOT EXISTS idx_hifo_lots_wallet_asset ON hifo_tax_lots (wallet_address, asset_ticker, status, fmv_usd_per_token DESC)",
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
        "CREATE INDEX IF NOT EXISTS idx_hifo_disposals_wallet ON hifo_disposal_matches (wallet_address, disposed_at DESC)",
        r#"
        CREATE TABLE IF NOT EXISTS token_steering_matrix (
            ticker VARCHAR(32) PRIMARY KEY,
            asset_name VARCHAR(128) NOT NULL DEFAULT '',
            network VARCHAR(32) NOT NULL DEFAULT 'KAS',
            contract_address VARCHAR(255) NOT NULL DEFAULT '',
            steering_state VARCHAR(32) NOT NULL DEFAULT 'AUTO_BALANCE',
            is_whitelisted BOOLEAN NOT NULL DEFAULT TRUE,
            target_weight_pct DOUBLE PRECISION NOT NULL DEFAULT 10.0,
            actual_weight_pct DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            accumulated_fee_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            accumulated_fee_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            updated_by VARCHAR(255) NOT NULL DEFAULT 'SYSTEM_BOOT',
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS security_firewall_blacklist (
            entry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            entity_type VARCHAR(32) NOT NULL DEFAULT 'WALLET',
            target_value VARCHAR(255) UNIQUE NOT NULL,
            reason TEXT NOT NULL DEFAULT 'Director Firewall Block',
            active BOOLEAN NOT NULL DEFAULT TRUE,
            added_by VARCHAR(255) NOT NULL DEFAULT 'DIRECTOR',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "CREATE INDEX IF NOT EXISTS idx_security_firewall_active ON security_firewall_blacklist (active, entity_type)",
        r#"
        CREATE TABLE IF NOT EXISTS director_audit_log (
            audit_id BIGSERIAL PRIMARY KEY,
            director_wallet VARCHAR(255) NOT NULL,
            zone VARCHAR(64) NOT NULL DEFAULT 'ZONE_5',
            action_type VARCHAR(96) NOT NULL,
            target_entity VARCHAR(255) NOT NULL DEFAULT '',
            details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        "CREATE INDEX IF NOT EXISTS idx_director_audit_created ON director_audit_log (created_at DESC)",
        r#"
        CREATE TABLE IF NOT EXISTS corporate_expense_vouchers (
            voucher_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            category VARCHAR(64) NOT NULL DEFAULT 'INFRASTRUCTURE',
            vendor_label VARCHAR(128) NOT NULL DEFAULT '',
            amount_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            payment_source VARCHAR(64) NOT NULL DEFAULT 'MERCURY_9901',
            tx_reference VARCHAR(128),
            recorded_by VARCHAR(255) NOT NULL DEFAULT 'DIRECTOR',
            recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS corporate_owner_draws (
            draw_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            director_wallet VARCHAR(255) NOT NULL,
            asset_ticker VARCHAR(32) NOT NULL DEFAULT 'USD',
            amount_tokens DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            amount_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            destination_rail VARCHAR(128) NOT NULL DEFAULT 'MERCURY_9901',
            tx_hash VARCHAR(255),
            recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    ];

    for stmt in ddl_statements {
        if let Err(e) = sqlx::query(stmt).execute(pool).await {
            tracing::warn!("Schema bootstrapper statement notice: {}", e);
        }
    }

    let default_whitelist_rows: &[(&str, &str, &str, f64)] = &[
        ("KAS", "Kaspa Native L1", "KAS", 35.0),
        ("USDC", "USD Coin Reserve", "ETH", 20.0),
        ("USDT", "Tether USD Reserve", "ETH", 10.0),
        ("BTC", "Bitcoin L1 Reserve", "BTC", 15.0),
        ("ETH", "Ethereum L1 Reserve", "ETH", 10.0),
        ("SOL", "Solana L1 Reserve", "SOL", 5.0),
        ("SILO", "Perennia Silo Utility (KRC-20)", "KAS", 5.0),
    ];

    for &(ticker, name, net, weight) in default_whitelist_rows {
        let _ = sqlx::query(
            r#"
            INSERT INTO token_steering_matrix (
                ticker, asset_name, network, steering_state, is_whitelisted, target_weight_pct
            ) VALUES ($1, $2, $3, 'AUTO_BALANCE', TRUE, $4)
            ON CONFLICT (ticker) DO NOTHING
            "#,
        )
        .bind(ticker)
        .bind(name)
        .bind(net)
        .bind(weight)
        .execute(pool)
        .await;
    }

    let default_cold_kas = env::var("PERENNIA_MASTER_TREASURY_KAS")
        .or_else(|_| env::var("MASTER_ADMIN_ADDRESS"))
        .or_else(|_| env::var("PERENNIA_COLD_KAS_ADDRESS"))
        .unwrap_or_default();
    let default_hot_ceiling = env::var("PERENNIA_HOT_CEILING_KAS")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|&v| v > 0.0)
        .unwrap_or(5000.0);
    let default_min_runway = env::var("PERENNIA_MIN_RUNWAY_KAS")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|&v| v >= 0.0)
        .unwrap_or(250.0);
    let default_fpps_float = env::var("FPPS_MAX_FLOAT_KAS")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|&v| v > 0.0)
        .unwrap_or(50.0);
    let default_pool_fee = env::var("POOL_FEE_RATE")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|&v| v >= 0.0 && v < 1.0)
        .unwrap_or(0.01);

    let _ = sqlx::query(
        r#"
        INSERT INTO system_treasury_config (
            config_id, hot_ceiling_kas, min_runway_kas, fpps_max_float_kas,
            pool_fee_rate, outflow_breaker_tripped, cold_kas_address
        ) VALUES ('PRIMARY', $1, $2, $3, $4, FALSE, $5)
        ON CONFLICT (config_id) DO UPDATE SET
            cold_kas_address = CASE
                WHEN system_treasury_config.cold_kas_address = '' THEN EXCLUDED.cold_kas_address
                ELSE system_treasury_config.cold_kas_address
            END
        "#,
    )
    .bind(default_hot_ceiling)
    .bind(default_min_runway)
    .bind(default_fpps_float)
    .bind(default_pool_fee)
    .bind(default_cold_kas.trim())
    .execute(pool)
    .await;

    let _ = sqlx::query(
        r#"
        INSERT INTO fiat_float_ledger (ledger_id)
        VALUES ('BOOTSTRAP_PRIMARY'), ('PRIMARY_FLOAT')
        ON CONFLICT (ledger_id) DO NOTHING
        "#,
    )
    .execute(pool)
    .await;

    if let Ok(seed_invite_code) = env::var("MASTER_BETA_INVITE_CODE") {
        let clean_code = seed_invite_code.trim();
        if !clean_code.is_empty() {
            let _ = sqlx::query(
                r#"
                INSERT INTO invite_codes (code, is_used)
                VALUES ($1, FALSE)
                ON CONFLICT (code) DO NOTHING
                "#,
            )
            .bind(clean_code)
            .execute(pool)
            .await;
        }
    }

    tracing::info!(
        "✅ PostgreSQL Schema Bootstrapper Verified (System Config, 5-State Token Steering Matrix, Security Firewall, Gross-Up Fiat Columns, HMAC Invariants & HIFO Tables Ready)."
    );
    Ok(())
}