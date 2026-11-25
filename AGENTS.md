# AGENTS.md — `perennia-v5-backend` (`perennia-stratum-rs`)

Multi-tier Kaspa Stratum mining pool, Smart Order Router (SOR) & internal Dark Pool, 22:00 UTC epoch settlement engine, fiat rails, HIFO tax accounting, and non-custodial Headless AI Agent / MCP Gateway backed by PostgreSQL and Redis.

- **HTTP API**: Axum server on `:8002` (`RUST_BIND_ADDRESS`), plus optional dedicated Agent Edge listener (`AGENT_BIND_ADDRESS`).
- **Telemetry**: Prometheus `/metrics` exporter on `:8081`.
- **Stratum TCP Tiers**: `6551` (GPU), `6552` (Home ASIC), `6553` (Whale ASIC).

---

## 1. Module Map & Database Schema Map

### Rust Module Map

| Area | Files | Responsibility |
| :--- | :--- | :--- |
| **Boot, Config & Schema** | `build.rs`, `src/main.rs`, `src/config.rs`, `src/schema.rs` | `tonic-build` protobuf compilation, `config.yaml` (`StratumConfig`) loading, PostgreSQL/Redis initialization, daemon spawning, Axum router assembly, and idempotent startup DDL (`ensure_database_schema`). |
| **Stratum, Kaspa RPC & Telemetry** | `src/stratum_tcp/mod.rs`, `src/job_manager/mod.rs`, `src/diff_engine/mod.rs`, `src/kaspad_client/mod.rs`, `src/telemetry/mod.rs` | Stratum TCP sessions, 16-bit `extranonce1` allocation, `vardiff`, IP strike/ban shield, block template caching, `kaspa-pow` share verification, `kaspad` bidirectional gRPC client, Prometheus metrics, and miner loyalty fee decay. |
| **Oracles, Routing, Settlement & L1 Execution** | `src/oracle.rs`, `src/sor.rs`, `src/chronos.rs` (`src/chronos/daemons.rs`, `src/chronos/netting.rs`, `src/chronos/forge_bell.rs`), `src/kaspa_tx.rs`, `src/l1_dispatcher.rs`, `src/silverscript.rs`, `src/hifo.rs` | Multi-exchange spot oracle + Pyth Hermes RWA feeds, Smart Order Router, 10s delta netting & 22:00 UTC epoch settlement (anti-sandwich slicer, Forge daily unlocks/emissions, airlock sweeps, mempool finality), Kaspa mass math & unsigned PSBT builder, `secp256k1` Schnorr batch signing, SilverScript/KCC-20 covenants, and HIFO tax lot matching. |
| **State, Fiat & Admin HTTP APIs** | `src/state_api.rs`, `src/forge_queries.rs`, `src/fiat_rails.rs`, `src/admin_api.rs` | Command center state actions, Forge tokenomics queries, Stripe/Bridge/Mercury fiat on/off-ramps & corporate ledgers, and protected `/v1/admin/*` governance/inspection endpoints. |
| **Headless AI Agent & MCP Gateway** | `src/agent/mod.rs`, `src/agent/auth.rs`, `src/agent/handlers.rs`, `src/agent/dark_pool.rs`, `src/agent/solvency.rs`, `src/agent/verifier.rs`, `src/agent/locks_and_limits.rs`, `src/agent/mcp.rs`, `src/agent/types.rs` | Edge semaphore & IP firewall, Blake3 macaroon auth (`MODE_A` Schnorr challenge & `MODE_B` mandates), quote/execute/stream handlers, Redis Maker RFQ Dark Pool matching, zero-float `u128` solvency math, UTXO/preimage verification, UTXO locks, `x402` burst credits, 60s anomaly auto-breakers, and sterilized JSON-RPC MCP server (`/api/v1/agent/mcp`). |

### PostgreSQL Schema Map

Defined across `src/schema.rs`, `db/schema.sql`, `db/migrations/20261121_agent_gateway.sql`, and `live-db-schema.sql`:

| Domain | Tables |
| :--- | :--- |
| **Mining & L1 Finality** | `worker_profiles`, `micro_shares` *(unlogged)*, `network_blocks`, `pending_transactions` |
| **Balances, UI & DeFi** | `yield_reservoirs`, `user_command_centers`, `user_treasury_preferences`, `liquidity_providers`, `yield_distributions`, `silo_staking_positions`, `p2p_orders`, `epoch_staging_buffers`, `fba_epoch_clearing_history` |
| **Treasury, Payouts & Oracles** | `system_treasury_config`, `l1_payout_queue`, `idempotent_payout_batches`, `treasury_airlock_sweeps`, `user_cold_vault_rules`, `client_cold_vault_registry`, `rwa_oracle_feeds` |
| **Fiat & Corporate** | `fiat_bank_rails`, `fiat_onramp_orders`, `fiat_payout_queue`, `fiat_float_ledger`, `fiat_post_trade_sweeps`, `corporate_expense_vouchers`, `corporate_owner_draws`, `corporate_outflow_ledger` |
| **Tax & Compliance** | `entity_kyc`, `hifo_tax_lots`, `hifo_disposal_matches`, `tax_ledger_events` |
| **Forge Tokenomics** | `forge_monetary_policies`, `forge_mineable_vaults`, `forge_vesting_schedules` |
| **Security & Governance** | `token_steering_matrix`, `security_firewall_blacklist`, `director_audit_log`, `whitelisted_wallets`, `invite_codes` |
| **AI Agent Gateway** | `agent_api_keys`, `agent_execution_receipts`, `agent_x402_credits` |

---

## 2. Strict Engineering Invariants

1. **Non-Custodial L1 Architecture Only**
   - Zero synthetic or custodial user balances in PostgreSQL or Redis.
   - All funds and settlements must be anchored to verifiable L1 UTXOs/transactions and non-custodial signing flows. Do not introduce or extend custodial ledger balance patterns.
2. **Strict Integer Math**
   - Use `u64` / `u128` atomic units (sompi, micro-USD, `E8` integer scales, `NUMERIC(39, 0)` in PostgreSQL, stringified `U128Str` on JSON boundaries) and integer basis points (`bps`).
   - Zero `f64` or `DOUBLE PRECISION` for currency, token, fee, or reserve accounting.
3. **"A Fail Is a Fail"**
   - Fail closed with explicit errors (e.g., `503` or typed error codes) whenever upstream nodes, Redis, or oracles are unavailable or stale.
   - Zero mock data, zero simulated telemetry, and zero hardcoded fallback prices or balances in production code.
4. **Compiler Verification Gate**
   - Always run `cargo check` after code edits and fix all compiler errors and warnings before finishing a batch.

---

## 3. Cross-Repo SvelteKit Frontend Contract (`perennia-frontend` -> `:8002`)

Upstream routes on `:8002` expected by `perennia-frontend`:

| Route | Handler Module | Auth Guard |
| :--- | :--- | :--- |
| `POST /v1/state/action` | `src/state_api.rs` | `internal_auth_guard` |
| `POST /v1/sor/execute` | `src/sor.rs` | `internal_auth_guard` |
| `GET /v1/balance` | `src/main.rs` | Public (kaspad gRPC / REST proxy) |
| `POST /v1/broadcast` | `src/main.rs` | Public (signed L1 tx broadcast) |
| `GET\|POST /v1/admin/shield` | `src/admin_api.rs` | Internal admin bearer auth |
| `GET /v1/admin/db/:table` | `src/admin_api.rs` | Internal admin bearer auth |
| `POST /v1/admin/epoch-bell` | `src/admin_api.rs` | Internal admin bearer auth |
| `POST\|DELETE /v1/admin/whitelist` *(+ `GET`)* | `src/admin_api.rs` | Internal admin bearer auth |
| `GET\|POST\|DELETE /v1/internal/agent/mandates` | `src/agent/auth.rs` *(via `src/agent/mod.rs`)* | `internal_mandate_auth_guard` |

> **Contract Change Flagging Rule:** Any backend change that alters the request parameters, headers, status codes, or JSON response shape of any route listed above **MUST be flagged clearly** in the response/commit notes so `perennia-frontend` can be updated in lockstep.
