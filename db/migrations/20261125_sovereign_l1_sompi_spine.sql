-- ==============================================================================
-- PERENNIA LLC: SOVEREIGN L1 SETTLEMENT, VAULT LOCKS & SOMPI SPINE MIGRATION
-- File: db/migrations/20261125_sovereign_l1_sompi_spine.sql
-- Invariants:
--   1. Zero synthetic or custodial multi-asset IOUs in PostgreSQL.
--   2. Strict integer atomic accounting: NUMERIC(39, 0) / BIGINT sompi & bps.
--   3. 1,000-block DAA coinbase maturity gating & SERIALIZABLE outbox state.
-- ==============================================================================

-- 1. Mechanical Stratum Mature Accruals (0 -> 25 KAS Stage 1 Flush Floor)
CREATE TABLE IF NOT EXISTS public.stratum_mature_accruals (
    clean_wallet VARCHAR(255) PRIMARY KEY,
    wallet_address VARCHAR(255) NOT NULL,
    immature_sompi NUMERIC(39, 0) NOT NULL DEFAULT 0 CHECK (immature_sompi >= 0),
    unpaid_mature_sompi NUMERIC(39, 0) NOT NULL DEFAULT 0 CHECK (unpaid_mature_sompi >= 0),
    lifetime_flushed_sompi NUMERIC(39, 0) NOT NULL DEFAULT 0 CHECK (lifetime_flushed_sompi >= 0),
    lifetime_pool_fee_sompi NUMERIC(39, 0) NOT NULL DEFAULT 0 CHECK (lifetime_pool_fee_sompi >= 0),
    pool_fee_bps INTEGER NOT NULL DEFAULT 100 CHECK (pool_fee_bps >= 50 AND pool_fee_bps <= 200),
    active_vault_id VARCHAR(64),
    last_maturity_daa BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_stratum_mature_accruals_unpaid
    ON public.stratum_mature_accruals (unpaid_mature_sompi DESC, updated_at ASC);

-- 2. SERIALIZABLE Idempotent Epoch Payout Outbox
--    outbox_key = blake3(epoch_id || "|" || clean_wallet || "|" || vault_id)
CREATE TABLE IF NOT EXISTS public.epoch_payout_outbox (
    outbox_key VARCHAR(64) PRIMARY KEY,
    epoch_id VARCHAR(64) NOT NULL,
    wallet_address VARCHAR(255) NOT NULL,
    clean_wallet VARCHAR(255) NOT NULL,
    vault_id VARCHAR(64) NOT NULL,
    destination_address VARCHAR(255) NOT NULL,
    destination_spk_hex TEXT NOT NULL,
    house_revenue_address VARCHAR(255) NOT NULL DEFAULT '',
    payout_sompi NUMERIC(39, 0) NOT NULL CHECK (payout_sompi > 0),
    house_fee_sompi NUMERIC(39, 0) NOT NULL DEFAULT 0 CHECK (house_fee_sompi >= 0),
    network_fee_sompi NUMERIC(39, 0) NOT NULL DEFAULT 0 CHECK (network_fee_sompi >= 0),
    kip21_subnetwork_id VARCHAR(40) NOT NULL DEFAULT '0000000000000000000000000000000000000000',
    kip20_covenant_id VARCHAR(64),
    state VARCHAR(24) NOT NULL DEFAULT 'CREATED' CHECK (
        state IN ('CREATED', 'SIGNING', 'BROADCAST', 'CONFIRMED', 'HALTED_INSOLVENT', 'FAILED')
    ),
    unsigned_pskt_json JSONB,
    signed_tx_json JSONB,
    txid VARCHAR(64),
    broadcast_daa BIGINT,
    confirmed_daa BIGINT,
    confirmed_blue_score BIGINT,
    retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_epoch_payout_outbox_state
    ON public.epoch_payout_outbox (state, updated_at ASC);

CREATE INDEX IF NOT EXISTS idx_epoch_payout_outbox_wallet
    ON public.epoch_payout_outbox (clean_wallet, created_at DESC);

-- 3. Public Non-Custodial L1 Vault Locks & Maker Plants (SilverScript + KIP-17/20/21)
CREATE TABLE IF NOT EXISTS public.vault_locks (
    vault_id VARCHAR(64) PRIMARY KEY,
    wallet_address VARCHAR(255) NOT NULL,
    clean_wallet VARCHAR(255) NOT NULL,
    vault_kind VARCHAR(32) NOT NULL DEFAULT 'MINER_SILO' CHECK (
        vault_kind IN ('MINER_SILO', 'STANDALONE_WALLET_SILO', 'MAKER_PLANT')
    ),
    kip20_covenant_id VARCHAR(64) UNIQUE NOT NULL,
    kip21_subnetwork_id VARCHAR(40) NOT NULL,
    covenant_address VARCHAR(255) NOT NULL,
    covenant_spk_hex TEXT NOT NULL,
    redeem_script_hex TEXT NOT NULL,
    silverscript_source TEXT NOT NULL DEFAULT '',
    owner_pubkey_hex VARCHAR(64) NOT NULL,
    chronos_trigger_pubkey_hex VARCHAR(64) NOT NULL DEFAULT '',
    target_asset VARCHAR(16) NOT NULL DEFAULT 'KAS',
    target_network VARCHAR(24) NOT NULL DEFAULT 'KAS',
    destination_address VARCHAR(255) NOT NULL,
    refund_kaspa_address VARCHAR(255) NOT NULL,
    threshold_sompi NUMERIC(39, 0) NOT NULL DEFAULT 2500000000 CHECK (threshold_sompi > 0),
    fee_bps INTEGER NOT NULL DEFAULT 50 CHECK (fee_bps >= 0 AND fee_bps <= 1000),
    maker_spread_bps INTEGER NOT NULL DEFAULT 0 CHECK (maker_spread_bps >= 0 AND maker_spread_bps <= 1000),
    kcc20_token_ticker VARCHAR(16),
    kcc20_lineage_root VARCHAR(64),
    onchain_utxo_txid VARCHAR(64),
    onchain_utxo_vout INTEGER,
    confirmed_utxo_sompi NUMERIC(39, 0) NOT NULL DEFAULT 0 CHECK (confirmed_utxo_sompi >= 0),
    confirmed_daa_score BIGINT NOT NULL DEFAULT 0,
    status VARCHAR(24) NOT NULL DEFAULT 'FILLING' CHECK (
        status IN ('FILLING', 'THRESHOLD_MET', 'LOCKED_IN_AUCTION', 'SETTLED', 'USER_CANCELLED')
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vault_locks_wallet_status
    ON public.vault_locks (clean_wallet, status);

CREATE INDEX IF NOT EXISTS idx_vault_locks_status_asset
    ON public.vault_locks (status, target_asset);

-- 4. Sequential 4-Valve Thermostat Routing Priorities
CREATE TABLE IF NOT EXISTS public.thermostat_valves (
    valve_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address VARCHAR(255) NOT NULL,
    clean_wallet VARCHAR(255) NOT NULL,
    priority_order SMALLINT NOT NULL CHECK (priority_order BETWEEN 1 AND 4),
    valve_type VARCHAR(36) NOT NULL CHECK (
        valve_type IN (
            'VALVE_1_ELECTRIC_BILL',
            'VALVE_2_AGENT_X402_FLOOR',
            'VALVE_3_JIT_VISA_CEILING',
            'VALVE_4_TANGEM_COLD_OR_PLANT'
        )
    ),
    target_asset VARCHAR(16) NOT NULL,
    target_network VARCHAR(24) NOT NULL,
    destination_address VARCHAR(255) NOT NULL,
    target_cap_sompi NUMERIC(39, 0) NOT NULL DEFAULT 0 CHECK (target_cap_sompi >= 0),
    target_cap_usd_micros NUMERIC(39, 0) NOT NULL DEFAULT 0 CHECK (target_cap_usd_micros >= 0),
    filled_epoch_sompi NUMERIC(39, 0) NOT NULL DEFAULT 0 CHECK (filled_epoch_sompi >= 0),
    filled_epoch_usd_micros NUMERIC(39, 0) NOT NULL DEFAULT 0 CHECK (filled_epoch_usd_micros >= 0),
    external_rail_ref VARCHAR(128),
    zktls_biller_commitment_hex VARCHAR(64),
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (clean_wallet, priority_order)
);

CREATE INDEX IF NOT EXISTS idx_thermostat_valves_wallet
    ON public.thermostat_valves (clean_wallet, priority_order ASC);

-- 5. Immutable On-Chain Settlement Receipts
CREATE TABLE IF NOT EXISTS public.settlement_receipts (
    receipt_id VARCHAR(64) PRIMARY KEY,
    outbox_key VARCHAR(64) REFERENCES public.epoch_payout_outbox(outbox_key) ON DELETE RESTRICT,
    epoch_id VARCHAR(64) NOT NULL,
    wallet_address VARCHAR(255) NOT NULL,
    clean_wallet VARCHAR(255) NOT NULL,
    vault_id VARCHAR(64),
    valve_priority SMALLINT,
    settlement_tier VARCHAR(32) NOT NULL CHECK (
        settlement_tier IN (
            'STAGE1_POOL_FLUSH',
            'TIER1_COW_DARK_POOL',
            'TIER2_BOT_BATCH_HTLC',
            'TIER3_CHANGENOW_SPLIT',
            'USER_PATH_A_CANCEL',
            'ZKTLS_GUEST_BILL_PAY'
        )
    ),
    source_sompi NUMERIC(39, 0) NOT NULL CHECK (source_sompi > 0),
    house_fee_sompi NUMERIC(39, 0) NOT NULL DEFAULT 0 CHECK (house_fee_sompi >= 0),
    network_fee_sompi NUMERIC(39, 0) NOT NULL DEFAULT 0 CHECK (network_fee_sompi >= 0),
    target_asset VARCHAR(16) NOT NULL,
    target_network VARCHAR(24) NOT NULL,
    settled_atomic NUMERIC(39, 0) NOT NULL CHECK (settled_atomic >= 0),
    oracle_kas_usd_e8 NUMERIC(39, 0) NOT NULL DEFAULT 0 CHECK (oracle_kas_usd_e8 >= 0),
    kaspa_l1_txid VARCHAR(64) NOT NULL,
    destination_txid VARCHAR(128),
    htlc_hashlock_sha256 VARCHAR(64),
    groth16_0x20_proof_hash VARCHAR(64),
    changenow_exchange_id VARCHAR(128),
    confirmed_daa_score BIGINT NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'CONFIRMED',
    settled_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_settlement_receipts_wallet
    ON public.settlement_receipts (clean_wallet, settled_at DESC);

CREATE INDEX IF NOT EXISTS idx_settlement_receipts_txid
    ON public.settlement_receipts (kaspa_l1_txid);

-- 6. 30-Second Solvency Circuit Breaker Audit Log
CREATE TABLE IF NOT EXISTS public.solvency_circuit_events (
    event_id BIGSERIAL PRIMARY KEY,
    unpaid_mature_sompi NUMERIC(39, 0) NOT NULL,
    inflight_outbox_sompi NUMERIC(39, 0) NOT NULL,
    confirmed_pool_vault_utxo_sompi NUMERIC(39, 0) NOT NULL,
    deficit_sompi NUMERIC(39, 0) NOT NULL,
    virtual_daa_score BIGINT NOT NULL DEFAULT 0,
    trigger_reason TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_solvency_circuit_events_time
    ON public.solvency_circuit_events (recorded_at DESC);

-- 7. Integer Sompi & 1,000-DAA Maturity Columns on Existing Tables
ALTER TABLE public.network_blocks
    ADD COLUMN IF NOT EXISTS is_mature BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE public.network_blocks
    ADD COLUMN IF NOT EXISTS matured_at_daa BIGINT;
ALTER TABLE public.network_blocks
    ADD COLUMN IF NOT EXISTS pool_fee_sompi BIGINT NOT NULL DEFAULT 0;
ALTER TABLE public.network_blocks
    ADD COLUMN IF NOT EXISTS miner_net_sompi BIGINT NOT NULL DEFAULT 0;
ALTER TABLE public.network_blocks
    ADD COLUMN IF NOT EXISTS flushed_to_accruals BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_network_blocks_maturity
    ON public.network_blocks (is_mature, is_orphaned, daa_score);

ALTER TABLE public.micro_shares
    ADD COLUMN IF NOT EXISTS sompi_delta BIGINT NOT NULL DEFAULT 0;
ALTER TABLE public.micro_shares
    ADD COLUMN IF NOT EXISTS pool_fee_sompi BIGINT NOT NULL DEFAULT 0;
ALTER TABLE public.micro_shares
    ADD COLUMN IF NOT EXISTS block_daa_score BIGINT NOT NULL DEFAULT 0;

ALTER TABLE public.system_treasury_config
    ADD COLUMN IF NOT EXISTS hot_ceiling_sompi BIGINT NOT NULL DEFAULT 500000000000;
ALTER TABLE public.system_treasury_config
    ADD COLUMN IF NOT EXISTS min_runway_sompi BIGINT NOT NULL DEFAULT 25000000000;
ALTER TABLE public.system_treasury_config
    ADD COLUMN IF NOT EXISTS fpps_max_float_sompi BIGINT NOT NULL DEFAULT 5000000000;
ALTER TABLE public.system_treasury_config
    ADD COLUMN IF NOT EXISTS pool_fee_bps INTEGER NOT NULL DEFAULT 100;
ALTER TABLE public.system_treasury_config
    ADD COLUMN IF NOT EXISTS house_revenue_kas_address VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE public.system_treasury_config
    ADD COLUMN IF NOT EXISTS solvency_breaker_tripped BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE public.system_treasury_config
    ADD COLUMN IF NOT EXISTS solvency_deficit_sompi NUMERIC(39, 0) NOT NULL DEFAULT 0;

ALTER TABLE public.silo_staking_positions
    ADD COLUMN IF NOT EXISTS amount_staked_atomic NUMERIC(39, 0) NOT NULL DEFAULT 0;
ALTER TABLE public.silo_staking_positions
    ADD COLUMN IF NOT EXISTS kcc20_covenant_id VARCHAR(64) NOT NULL DEFAULT '';

ALTER TABLE public.user_cold_vault_rules
    ADD COLUMN IF NOT EXISTS overflow_ceiling_sompi NUMERIC(39, 0) NOT NULL DEFAULT 50000000000;

ALTER TABLE public.worker_profiles
    ADD COLUMN IF NOT EXISTS effective_fee_bps INTEGER NOT NULL DEFAULT 100;

-- 8. Retire Synthetic Multi-Asset IOUs inside yield_reservoirs
UPDATE public.yield_reservoirs
SET lp_tokens = '{}'::jsonb,
    streaming_balance_kas = 0,
    verified_onchain_credits_kas = 0
WHERE COALESCE(lp_tokens, '{}'::jsonb) <> '{}'::jsonb
   OR streaming_balance_kas <> 0
   OR verified_onchain_credits_kas <> 0;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_yield_reservoirs_zero_synthetic_ious'
    ) THEN
        ALTER TABLE public.yield_reservoirs
            ADD CONSTRAINT chk_yield_reservoirs_zero_synthetic_ious
            CHECK (COALESCE(lp_tokens, '{}'::jsonb) = '{}'::jsonb);
    END IF;
END $$;
