<file path="db/schema.sql">
-- ==============================================================================
-- PERENNIA LLC: SOVEREIGN WRITE-AHEAD LOG (WAL) & REAL-TIME LEDGER SCHEMA
-- Deployment Environment: Bare-Metal Ubuntu PostgreSQL 16+
-- Architecture: High-Velocity BRIN Indexing & L1 Block Ledger
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Sovereign tracking of bare-metal hardware identities
CREATE TABLE IF NOT EXISTS worker_profiles (
    worker_id VARCHAR(255) PRIMARY KEY,
    wallet_address VARCHAR(255) NOT NULL,
    device_profile VARCHAR(100) NOT NULL DEFAULT 'unknown',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Continuous Fluidity: Real-time balance streaming for active smart contract polling
CREATE TABLE IF NOT EXISTS yield_reservoirs (
    wallet_address VARCHAR(255) PRIMARY KEY,
    streaming_balance_kas DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    total_yield_kas DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. UNLOGGED WAL: Millions of sub-second micro-shares map directly here from the Redis Oracle
CREATE UNLOGGED TABLE IF NOT EXISTS micro_shares (
    share_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    worker_id VARCHAR(255) NOT NULL,
    difficulty_weight DOUBLE PRECISION NOT NULL,
    kas_value_delta DOUBLE PRECISION NOT NULL,
    network_diff DOUBLE PRECISION NOT NULL,
    is_settled BOOLEAN NOT NULL DEFAULT false,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. The L1 Block Ledger: Persistent tracking of global Kaspa network discoveries
CREATE TABLE IF NOT EXISTS network_blocks (
    block_hash VARCHAR(64) PRIMARY KEY,
    worker_id VARCHAR(255) NOT NULL,
    nonce BIGINT NOT NULL,
    network_diff DOUBLE PRECISION NOT NULL,
    is_orphaned BOOLEAN DEFAULT false,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ==============================================================================
-- FINANCIAL COMPLIANCE: 1099-DA TAX FORTRESS INTEGRATION
-- ==============================================================================

-- 5. KYC & Entity Resolution (1099-DA Compliance Pipeline)
CREATE TABLE IF NOT EXISTS entity_kyc (
    wallet_address VARCHAR(255) PRIMARY KEY REFERENCES yield_reservoirs(wallet_address),
    legal_name VARCHAR(255) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    tax_id_hash VARCHAR(255) NOT NULL, -- Encrypted/Hashed TIN
    business_address TEXT NOT NULL,
    verification_status VARCHAR(50) DEFAULT 'pending',
    verified_at TIMESTAMP WITH TIME ZONE
);

-- 6. Gross Proceeds & Cost Basis Ledger (U.S. Broker Regs)
CREATE TABLE IF NOT EXISTS tax_ledger_events (
    event_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    wallet_address VARCHAR(255) NOT NULL REFERENCES yield_reservoirs(wallet_address),
    asset_ticker VARCHAR(20) NOT NULL,
    event_type VARCHAR(50) NOT NULL, -- 'YIELD', 'SWAP', 'LIQUIDATION'
    gross_proceeds_usd DOUBLE PRECISION NOT NULL,
    cost_basis_usd DOUBLE PRECISION DEFAULT 0.0, -- Future proofing for mandatory 2026 reporting
    amount_tokens DOUBLE PRECISION NOT NULL,
    spot_price_at_execution DOUBLE PRECISION NOT NULL,
    transaction_hash VARCHAR(255),
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ==============================================================================
-- HIGH-PERFORMANCE INDEXING MATRIX
-- ==============================================================================

-- B-Tree Indexes for exact-match lookups
CREATE INDEX IF NOT EXISTS idx_micro_shares_worker ON micro_shares(worker_id);
CREATE INDEX IF NOT EXISTS idx_micro_shares_settlement ON micro_shares(is_settled);
CREATE INDEX IF NOT EXISTS idx_network_blocks_worker ON network_blocks(worker_id);
CREATE INDEX IF NOT EXISTS idx_network_blocks_time ON network_blocks(discovered_at DESC);

-- Tax ledger optimized indexing for rapid 1099-DA compilation mapping
CREATE INDEX IF NOT EXISTS idx_tax_ledger_wallet ON tax_ledger_events(wallet_address, recorded_at);

-- Drop legacy B-Tree for time-series if it exists from Phase 1
DROP INDEX IF EXISTS idx_micro_shares_recorded;

-- BRIN (Block Range Index) for hyper-optimized append-only time-series data
CREATE INDEX IF NOT EXISTS idx_micro_shares_recorded_brin 
ON micro_shares USING brin (recorded_at) WITH (pages_per_range = 128);
</file>