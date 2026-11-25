# Perennia Backend JSON API Contract Reference (`perennia-stratum-rs` — Sovereign L1 Batches 1–3)

This reference documents the HTTP/JSON contracts exposed by `perennia-stratum-rs` on `:8002` (`RUST_BIND_ADDRESS`) for **`perennia-frontend`** and headless AI Solver bots (`/api/v1/agent/chronos/*`), reflecting all Sovereign L1 Batches 1–3 changes on branch `feat/sovereign-l1-settlement`.

---

## Global Conventions & Guards

1. **Integer Atomic Representation (`U128Str`)**
   - `u128` currency/quantity/threshold values (`sompi`, `usdMicros`, `E8` oracle prices, token atomic amounts) are serialized/accepted as decimal strings (`U128Str` / JSON string) to preserve precision across JavaScript (`Number.MAX_SAFE_INTEGER` boundaries).
   - `1 KAS = 100_000_000 sompi` (`1e8`), `1 USD = 1_000_000 usdMicros` (`1e6`), `1 USD` oracle price = `100_000_000 E8` (`ORACLE_USD_E8_SCALE`). Fee rates use integer basis points (`bps`, `10_000 bps = 100%`).
2. **Auth Guards**
   - **`internal_auth_guard`** ([main.rs](file:///home/perennia/perennia-v5-backend/src/main.rs#L50-L105)): Unless `ENFORCE_INTERNAL_AUTH=false`, requires `Authorization: Bearer <INTERNAL_ADMIN_TOKEN | PERENNIA_ADMIN_KEY>` in constant time. Missing env secret fails closed (`503 SERVICE_UNAVAILABLE`); invalid/missing bearer returns `401 UNAUTHORIZED` (`{ "error": "UNAUTHORIZED_INTERNAL_RPC" }`).
   - **`verify_internal_admin_headers`** ([admin_api.rs](file:///home/perennia/perennia-v5-backend/src/admin_api.rs#L77-L130)): Always requires `Authorization: Bearer <INTERNAL_ADMIN_TOKEN | PERENNIA_ADMIN_KEY>`.
   - **`internal_mandate_auth_guard`** ([agent/auth.rs](file:///home/perennia/perennia-v5-backend/src/agent/auth.rs)): Requires `Authorization: Bearer <AGENT_INTERNAL_SERVICE_SECRET | INTERNAL_ADMIN_TOKEN>` (validated via `verify_internal_service_bearer`).
   - **`agent_edge_guard` + Blake3 Macaroon Auth** ([agent/mod.rs](file:///home/perennia/perennia-v5-backend/src/agent/mod.rs), [agent/auth.rs](file:///home/perennia/perennia-v5-backend/src/agent/auth.rs#L284)): Agent public routes require `Authorization: Bearer agk_<key>` or `X-Agent-Key: agk_<key>`. Mutating Chronos endpoints additionally enforce a single-use 60s Redis replay nonce (`X-Agent-Nonce` header or body `nonce`, `16..=128` chars matching `[A-Za-z0-9_-]`).

---

## Contract Change Summary for `perennia-frontend` (`AGENTS.md` §3)

> [!IMPORTANT]
> Update `perennia-frontend` in lockstep for the following breaking/additive changes introduced across Batches 1–3:
> 1. **`POST /v1/sor/execute`** (`src/sor.rs`): Replaced synthetic `yield_reservoirs`/float execution with non-custodial L1 routing (`L1_COW_ATOMIC_PSKT`, `CROSS_CHAIN_OPSHA256_HTLC`, `TIER3_CHANGENOW_SPLIT_PSKT`, `CROSS_CHAIN_DEPOSIT_INTENT`). All monetary/atomic response fields are now stringified integers (`amountInAtomic`, `protocolFeeAtomic`, `networkFeeSompi`, `estimatedOutputAtomic`, `minOutputAtomic`, `grossUsdMicros`, `netUsdMicros`, `payOracleUsdE8`, `receiveOracleUsdE8`, `kasOracleUsdE8`, plus `feeBps`, `pskt`, `htlcCovenant`, `formattedUtxos`). Oracle outage fails closed with `503`.
> 2. **`POST /v1/state/action`** (`src/state_api.rs`): Retired synthetic balance/staking claims (`CLAIM_PENDING_SECTOR_KAS`, `STAKE_LP`, `WITHDRAW_LP`, `STAKE_SILO`, `CLAIM_UNSTAKED_SILO` now return `422 UNPROCESSABLE_ENTITY` with `error: "NON_CUSTODIAL_L1_ONLY..."`). Added Sovereign L1 actions: `GET_VAULT_LOCKS`, `REGISTER_VAULT_LOCK`, `BUILD_VAULT_CANCEL_PSKT`, `GET_THERMOSTAT_VALVES`, `UPSERT_THERMOSTAT_VALVES`, `GET_MATURE_ACCRUAL_AND_OUTBOX`, `GET_SETTLEMENT_RECEIPTS`, and `GET_SOLVENCY_PROOF`. Allocation percentage updated to integer `allocationBps`.
> 3. **`GET /v1/admin/db/:table`** (`src/admin_api.rs`): Removed `yield_reservoirs` from the allowlist (`400 BAD_REQUEST`); added `stratum_mature_accruals`, `epoch_payout_outbox`, `vault_locks`, `thermostat_valves`, `settlement_receipts`, and `solvency_circuit_events`.
> 4. **`POST /v1/admin/epoch-bell`** (`src/admin_api.rs`): `epochTelemetry` now returns the 3-tier waterfall structure (`tier1CowCross`, `tier2BotBatchHtlc`, `tier3ChangeNowSplit`, `timestampUtc`).

---

## Part 1: `:8002` Frontend Upstream Contract (`perennia-frontend`)

### 1. `POST /v1/state/action`

- **Handler:** [`handle_state_action`](file:///home/perennia/perennia-v5-backend/src/state_api.rs#L510-L2353)
- **Guard:** `internal_auth_guard`
- **Request Body (`StateActionRequest`):**
  ```json
  {
    "wallet": "kaspa:q...",
    "action": "GET_VAULT_LOCKS",
    "payload": {}
  }
  ```

#### Sovereign L1 Actions (Batches 1–3)

| Action | Request `payload` | Response `200 OK` (`{ "success": true, "data": ... }`) / Notes |
| :--- | :--- | :--- |
| `GET_VAULT_LOCKS` | `{}` | `data.vaults[]`: `{ vaultId, walletAddress, vaultKind ("MINER_SILO" \| "STANDALONE_WALLET_SILO" \| "MAKER_PLANT"), kip20CovenantId, kip21SubnetworkId, covenantAddress, covenantSpkHex, redeemScriptHex, ownerPubkeyHex, chronosTriggerPubkeyHex, targetAsset, targetNetwork, destinationAddress, refundKaspaAddress, thresholdSompi, feeBps, makerSpreadBps, kcc20TokenTicker, kcc20LineageRoot, confirmedUtxoSompi, liveUtxoSompi, liveUtxoCount, liveUtxoError, confirmedDaaScore, status, updatedAt }` |
| `REGISTER_VAULT_LOCK` | `{ vaultKind?, targetAsset?, targetNetwork?, destinationAddress?, refundKaspaAddress?, thresholdSompi?, feeBps?, makerSpreadBps?, kcc20TokenTicker?, kcc20LineageRoot? }` | Registers SilverScript v1.0 (`KIP-17` / `KIP-20` / `KIP-21`) dual-path P2SH vault covenant (`400` on invalid Bech32m/params) and returns vault metadata (`covenantAddress`, `covenantSpkHex`, `redeemScriptHex`, `kip20CovenantId`, `kip21SubnetworkId`, `silverscriptSource`). |
| `BUILD_VAULT_CANCEL_PSKT` | `{ vaultId }` | Builds unsigned `Transaction v1` Path A (24/7 owner cancellation) spend (`data`: `{ vaultId, spendPath: "PATH_A_24_7_USER_SOVEREIGNTY", pskt: { version: 1, subnetworkId, lockTime: 0, inputs, outputs, payload }, feeBreakdown: { totalInputSompi, refundOutputSompi, networkFeeSompi, effectiveMass, storageMass, computeGrams } }`). |
| `GET_THERMOSTAT_VALVES` | `{}` | `data.valves[]`: `{ valveId, priorityOrder (1..4), valveType ("VALVE_1_ELECTRIC_BILL" \| "VALVE_2_AGENT_X402_FLOOR" \| "VALVE_3_JIT_VISA_CEILING" \| "VALVE_4_TANGEM_COLD_OR_PLANT"), targetAsset, targetNetwork, destinationAddress, targetCapSompi, targetCapUsdMicros, filledEpochSompi, filledEpochUsdMicros, externalRailRef, zktlsBillerCommitmentHex, isEnabled, updatedAt }` |
| `UPSERT_THERMOSTAT_VALVES` | `{ valves: [...] }` or single `{ priorityOrder: 1..4, valveType?, targetAsset?, targetNetwork?, destinationAddress, targetCapSompi?, targetCapUsdMicros?, externalRailRef?, zktlsBillerCommitmentHex?, isEnabled? }` | Upserts 4-Valve priority thermostat policy (`400` on invalid priority/type/Bech32m). |
| `GET_MATURE_ACCRUAL_AND_OUTBOX` | `{}` | `data`: `{ accrual: { immatureSompi, unpaidMatureSompi, lifetimeFlushedSompi, lifetimePoolFeeSompi, poolFeeBps, activeVaultId, lastMaturityDaa, stage1FlushFloorSompi ("2500000000"), updatedAt }, outbox: [{ outboxKey, epochId, vaultId, destinationAddress, payoutSompi, houseFeeSompi, networkFeeSompi, state, txid, broadcastDaa, confirmedDaa, retryCount, lastError, createdAt, updatedAt }] }` |
| `GET_SETTLEMENT_RECEIPTS` | `{}` | `data.receipts[]`: `{ receiptId, outboxKey, epochId, vaultId, valvePriority, settlementTier, sourceSompi, houseFeeSompi, networkFeeSompi, targetAsset, targetNetwork, settledAtomic, oracleKasUsdE8, kaspaL1Txid, destinationTxid, htlcHashlockSha256, groth160x20ProofHash, changenowExchangeId, confirmedDaaScore, status, settledAt }` |
| `GET_SOLVENCY_PROOF` | `{}` | Returns 30s solvency invariant snapshot from `evaluate_pool_solvency_invariant` (`503 SERVICE_UNAVAILABLE` if node/DB offline). |

#### Command Center, Config, Loyalty & Retired Actions

- **Command Center:** `GET_STATE`, `SYNC_LAYOUT`, `ADD_WORKER`, `DELETE_WORKER`, `RENAME_WORKER`, `ADD_SECTOR`, `DELETE_SECTOR`, `RENAME_SECTOR`, `REORDER_SECTORS`, `UPDATE_SECTOR_ALLOCATION` (reads `allocationBps` `0..=10_000` or legacy integer `allocationPercentage * 100`), `UPDATE_SETTLEMENT`, `ADD_CUSTOM_TOKEN`, `REMOVE_CUSTOM_TOKEN` -> `{ "success": true, "data": <layout_state> }`.
- **Telemetry / Staking / Config:** `GET_MINER_LOYALTY`, `GET_LIVE_BUCKET_THRESHOLDS` (`503` if oracle offline), `GET_LP_POSITIONS` (`stakedAssetAE8`, `stakedAssetBE8`, `multiplierBps`, `weightedTvlE8`), `GET_SILO_STAKING` (`activeStakedAtomic`, `cooldownStakedAtomic`, `feeRateBps`, `tierLabel`, `minerLoyalty`, `positions`), `INITIATE_SILO_COOLDOWN`, `GET_SYSTEM_TREASURY_CONFIG`, `UPDATE_SYSTEM_TREASURY_CONFIG`, `GET_USER_COLD_VAULT_RULES` | `GET_COLD_VAULT_AIRLOCK`, `SAVE_USER_COLD_VAULT_RULE`, `DELETE_USER_COLD_VAULT_RULE`, `SWEEP_TOKEN_TO_COLD_VAULT_NOW`, `TRIGGER_EPOCH_BELL` | `FORCE_EPOCH_BELL`, `GET_HIFO_TAX_LOTS`, `GET_FORGE_TOKENOMICS`, `DEPLOY_FORGE_TOKENOMICS` | `REGISTER_FORGE_TOKENOMICS` | `RETROACTIVE_FORGE_UPGRADE`, `CLAIM_VESTED_TRANCHE`, `COMPILE_SILVERSCRIPT_VAULT` | `COMPILE_SILVERSCRIPT_COVENANT`, `RETRY_L1_PAYOUT`, `WHITELIST_WALLET`.
- **Retired Custodial Actions (`422 UNPROCESSABLE_ENTITY`):** `CLAIM_PENDING_SECTOR_KAS`, `STAKE_LP`, `WITHDRAW_LP`, `STAKE_SILO`, `CLAIM_UNSTAKED_SILO` all fail closed with `{ "success": false, "error": "NON_CUSTODIAL_L1_ONLY: ..." }`.

---

### 2. `POST /v1/sor/execute`

- **Handler:** [`handle_sor_execute`](file:///home/perennia/perennia-v5-backend/src/sor.rs)
- **Guard:** `internal_auth_guard`
- **Request Body (`SorExecuteRequest`):**
  ```json
  {
    "wallet": "kaspa:q...",
    "payAsset": "KAS",
    "receiveAsset": "USDC",
    "targetNetwork": "BASE",
    "amountAtomic": "2500000000",
    "minOutputAtomic": "1000000",
    "slippageBps": 50,
    "destinationAddress": "0x...",
    "refundKaspaAddress": "kaspa:q...",
    "utxos": [],
    "htlcSha256HashlockHex": "<optional 64-char hex>",
    "counterpartyPubkeyHex": "<optional 64-char hex>"
  }
  ```
  - `amount` (decimal string or JSON number) is accepted as fallback if `amountAtomic` is omitted, parsed strictly to `u128` atomic units.
- **Success Response (`200 OK`):**
  ```json
  {
    "success": true,
    "transactionUuid": "uuid-v4",
    "routeType": "L1_COW_ATOMIC_PSKT | CROSS_CHAIN_OPSHA256_HTLC | TIER3_CHANGENOW_SPLIT_PSKT | CROSS_CHAIN_DEPOSIT_INTENT",
    "payAsset": "KAS",
    "receiveAsset": "USDC",
    "targetNetwork": "BASE",
    "amountInAtomic": "2500000000",
    "protocolFeeAtomic": "12500000",
    "networkFeeSompi": "20400",
    "estimatedOutputAtomic": "...",
    "minOutputAtomic": "...",
    "feeBps": 50,
    "feeTierLabel": "50 bps Dark Pool CoW Major Tier",
    "grossUsdMicros": "...",
    "netUsdMicros": "...",
    "payOracleUsdE8": "...",
    "receiveOracleUsdE8": "...",
    "kasOracleUsdE8": "...",
    "refundKaspaAddress": "kaspa:q...",
    "tokenSteering": {
      "allowed": true,
      "rejectReason": null,
      "payState": "...",
      "receiveState": "...",
      "allowDarkPoolInternalClearing": true,
      "feeLegs": [{ "asset": "KAS", "shareRatio": 1.0 }],
      "explanation": "..."
    },
    "pskt": {},
    "htlcCovenant": {},
    "formattedUtxos": []
  }
  ```
- **Errors:** `400 BAD_REQUEST` (invalid wallet/asset/amount/destination/hashlock/pubkey), `403 FORBIDDEN` (steering firewall block / `0x21` / blacklisted), `422 UNPROCESSABLE_ENTITY` (dust/UTXO deficit / zero output), `503 SERVICE_UNAVAILABLE` (fail-closed oracle/subsystem pause).

---

### 3. `GET /v1/balance` (and `GET /v1/utxos`)

- **Handlers:** [`handle_get_balance`](file:///home/perennia/perennia-v5-backend/src/main.rs#L107-L178), [`handle_get_utxos`](file:///home/perennia/perennia-v5-backend/src/main.rs#L180-L234)
- **Guard:** Public (CORS enabled)
- **Query:** `?address=kaspa:q...` (missing `address` -> `400 BAD_REQUEST`)
- **`GET /v1/balance` Response (`200 OK`):**
  ```json
  { "balance": 12.5, "balanceKas": 12.5, "source": "kaspad_grpc | rest_fallback" }
  ```
- **`GET /v1/utxos` Response (`200 OK`):**
  ```json
  { "entries": [ ... ], "source": "kaspad_grpc | rest_fallback" }
  ```
- **Errors:** `502 BAD_GATEWAY` on upstream node failure.

---

### 4. `POST /v1/broadcast`

- **Handler:** [`handle_post_broadcast`](file:///home/perennia/perennia-v5-backend/src/main.rs#L236-L302)
- **Guard:** Public (CORS enabled)
- **Request Body:** Signed Kaspa transaction JSON (`{ ... }` or `{ "transaction": { ... } }`).
- **Response (`200 OK`):**
  ```json
  { "success": true, "transactionId": "<64-hex txid>", "source": "kaspad_grpc | rest_fallback" }
  ```
- **Errors:** `422 UNPROCESSABLE_ENTITY` (node rejected tx), `502 BAD_GATEWAY` (network failure).

---

### 5. `GET | POST /v1/admin/shield`

- **Handlers:** [`get_shield_status`](file:///home/perennia/perennia-v5-backend/src/admin_api.rs#L433-L473), [`modify_shield_ip`](file:///home/perennia/perennia-v5-backend/src/admin_api.rs#L475-L541)
- **Guard:** `verify_internal_admin_headers`
- **`GET` Response (`200 OK`):** `{ "bannedIps": [{ "ip", "elapsedSeconds", "remainingSeconds" }], "count": N, "activeStrikeCounters": [{ "key", "strikes", "maxStrikes" }], "maxConsecutiveStrikes": N }`
- **`POST` Request (`ShieldActionReq`):** `{ "ip": "1.2.3.4", "action": "BAN" | "UNBAN" | "REMOVE" }` (`action` defaults to `"BAN"`).
- **`POST` Response (`200 OK`):** `{ "success": true, "action": "BANNED" | "UNBANNED", "ip": "1.2.3.4" }`.

---

### 6. `GET /v1/admin/db/:table`

- **Handler:** [`get_table_data`](file:///home/perennia/perennia-v5-backend/src/admin_api.rs#L357-L431)
- **Guard:** `verify_internal_admin_headers`
- **Path `:table` Allowlist:**
  - **Sovereign L1 Tables (Added in Batch 3):** `stratum_mature_accruals`, `epoch_payout_outbox`, `vault_locks`, `thermostat_valves`, `settlement_receipts`, `solvency_circuit_events`
  - **Retained Tables:** `system_treasury_config`, `user_cold_vault_rules`, `worker_profiles`, `micro_shares`, `network_blocks`, `user_command_centers`, `entity_kyc`, `tax_ledger_events`, `liquidity_providers`, `silo_staking_positions`, `yield_distributions`, `pending_transactions`, `whitelisted_wallets`, `p2p_orders`, `fiat_payout_queue`, `fiat_bank_rails`, `fiat_onramp_orders`, `fiat_float_ledger`, `fiat_post_trade_sweeps`, `l1_payout_queue`, `rwa_oracle_feeds`, `forge_vesting_schedules`, `forge_monetary_policies`, `forge_mineable_vaults`, `idempotent_payout_batches`, `client_cold_vault_registry`, `treasury_airlock_sweeps`, `hifo_tax_lots`, `hifo_disposal_matches`, `token_steering_matrix`, `security_firewall_blacklist`, `director_audit_log`, `corporate_expense_vouchers`, `corporate_owner_draws`, `agent_api_keys`, `agent_execution_receipts`, `agent_x402_credits`
  - **Removed:** `yield_reservoirs` (returns `400 BAD_REQUEST`)
- **Response (`200 OK`):** `Array<Object>` (up to 5,000 rows ordered by column 1 descending).

---

### 7. `POST /v1/admin/epoch-bell`

- **Handler:** [`handle_force_epoch_bell`](file:///home/perennia/perennia-v5-backend/src/admin_api.rs#L339-L355)
- **Guard:** `verify_internal_admin_headers`
- **Request Body:** Empty / `{}`
- **Response (`200 OK`):**
  ```json
  {
    "success": true,
    "action": "FORCE_EPOCH_BELL",
    "epochTelemetry": {
      "epochId": "2026-11-25",
      "kasUsdE8": "...",
      "tier1CowCross": { ... },
      "tier2BotBatchHtlc": { ... },
      "tier3ChangeNowSplit": { ... },
      "timestampUtc": "..."
    }
  }
  ```

---

### 8. `GET | POST | DELETE /v1/admin/whitelist`

- **Handlers:** [`get_whitelisted_wallets`](file:///home/perennia/perennia-v5-backend/src/admin_api.rs#L543-L561), [`add_whitelisted_wallet`](file:///home/perennia/perennia-v5-backend/src/admin_api.rs#L563-L595), [`remove_whitelisted_wallet`](file:///home/perennia/perennia-v5-backend/src/admin_api.rs#L597-L613)
- **Guard:** `verify_internal_admin_headers`
- **`GET` Response (`200 OK`):** `{ "wallets": [...] }`
- **`POST` Request (`WhitelistReq`):** `{ "wallet": "kaspa:q...", "label": "optional" }` -> `200 OK` `{ "success": true, "wallet": "kaspa:..." }` (`400` if wallet `< 55` chars cleanly).
- **`DELETE` Request (`WhitelistReq`):** `{ "wallet": "kaspa:q..." }` -> deletes from `whitelisted_wallets`.

---

### 9. `GET | POST | DELETE /v1/internal/agent/mandates`

- **Handlers:** [`handle_internal_list_mandates`](file:///home/perennia/perennia-v5-backend/src/agent/auth.rs#L903-L1048), [`handle_internal_create_mandate`](file:///home/perennia/perennia-v5-backend/src/agent/auth.rs#L1050-L1243), [`handle_internal_revoke_mandate`](file:///home/perennia/perennia-v5-backend/src/agent/auth.rs#L1245-L1349)
- **Guard:** `internal_mandate_auth_guard`
- **`GET ?wallet=kaspa:q...` Response (`200 OK`):**
  ```json
  {
    "ok": true,
    "walletAddress": "kaspa:...",
    "mandates": [{ "keyId", "mode", "label", "whitelistedAssets", "allowSwaps", "allowBucketUpdates", "allowDarkPoolMaker", "maxSlippageBps", "feeTierMultiplierBps", "cap24hSompi", "cap24hUsdMicros", "spent24hSompi", "spent24hUsdMicros", "verifiedFillsCount", "cumulativeVolumeUsdMicros", "isRevoked", "isExpired", "revokedReason", "expiresAt", "createdAt", "lastSettledAt" }],
    "liveFills": [{ "receiptId", "quoteId", "keyId", "venue", "payAsset", "receiveAsset", "amountInAtomic", "settledOutAtomic", "totalFeeUsdMicros", "notionalUsdMicros", "executionCommitmentHash", "l1Txid", "status", "dryRun": false, "executedAt" }],
    "dryRunLogs": [ ... ]
  }
  ```
- **`POST` Request (`InternalCreateMandateRequest`):**
  ```json
  {
    "walletAddress": "kaspa:q...",
    "pubkeyHex": "<optional 64-hex>",
    "label": "Personal DCA Bot",
    "whitelistedAssets": ["KAS", "USDC"],
    "allowSwaps": true,
    "allowBucketUpdates": false,
    "maxSlippageBps": 50,
    "cap24hSompi": "25000000000",
    "cap24hUsdMicros": "1000000000",
    "expiresInHours": 720
  }
  ```
  - **Response (`201 CREATED`):** `{ "ok": true, "secretDisplayedOnce": true, "agentKey": "agk_...", "mandate": { "keyId", "mode": "MODE_B", "label", "walletAddress", "whitelistedAssets", "allowSwaps", "allowBucketUpdates", "maxSlippageBps", "feeTierMultiplierBps", "cap24hSompi", "cap24hUsdMicros", "expiresAt", "createdAt" } }`.
- **`DELETE` Request (`InternalRevokeMandateRequest`):** `{ "walletAddress": "kaspa:q...", "keyId": "mdk_...", "revokeAllForWallet": false }`
  - **Response (`200 OK`):** `{ "ok": true, "walletAddress": "kaspa:...", "revokedKeyIds": [...], "releasedActiveLocks": "0", "revokedAt": "..." }`.

---

## Part 2: Headless AI Solver Bot Contract (`/api/v1/agent/chronos/*`)

Registered in [agent/mod.rs](file:///home/perennia/perennia-v5-backend/src/agent/mod.rs) under `agent_public_router` behind `agent_edge_guard` (optional dedicated `AGENT_BIND_ADDRESS` or `:8002`).

### Agent Error Envelope (`AgentError`)

All errors return JSON:
```json
{
  "ok": false,
  "isError": true,
  "error": "SOLVENCY_FLOOR_VIOLATION | PREIMAGE_MISMATCH | INVALID_SIGNATURE_OR_SCRIPT | FORBIDDEN_MODE | IDEMPOTENCY_CONFLICT | QUOTE_EXPIRED_OR_NOT_FOUND | NODE_UNAVAILABLE | REDIS_UNAVAILABLE | DATABASE_UNAVAILABLE | INVALID_INPUT",
  "message": "Human-readable fail-closed error reason"
}
```

### 1. `GET /api/v1/agent/chronos/rfq`

- **Handler:** [`handle_get_chronos_rfq`](file:///home/perennia/perennia-v5-backend/src/agent/dark_pool.rs#L970-L1003)
- **Headers:** `Authorization: Bearer agk_...` (or `X-Agent-Key`)
- **Behavior:** Reads anonymized `21:58 UTC` batch manifests from Redis (`perennia:chronos:rfq:batches`), stripping `vaultIds` so bots receive zero miner identity leakage.
- **Response (`200 OK`):**
  ```json
  {
    "success": true,
    "keyId": "agk_...",
    "batches": [
      {
        "batchId": "...",
        "epochId": "2026-11-25",
        "targetAsset": "USDC",
        "targetNetwork": "BASE",
        "grossKasSompi": "25000000000",
        "changenowNetFloorAtomic": "2495000000",
        "closesAtUnix": 1795643970,
        "createdAtUnix": 1795643880
      }
    ]
  }
  ```

### 2. `POST /api/v1/agent/chronos/bid`

- **Handler:** [`handle_post_chronos_bid`](file:///home/perennia/perennia-v5-backend/src/agent/dark_pool.rs#L1007-L1175)
- **Requirements & Consensus Checks:**
  1. Authenticated `MODE_A` key with `allowDarkPoolMaker == true` (otherwise `403 FORBIDDEN_MODE`).
  2. Single-use 60s Redis replay nonce via `X-Agent-Nonce` header or `nonce` field (`16..=128` `[A-Za-z0-9_-]`; replay returns `IDEMPOTENCY_CONFLICT`).
  3. Batch exists and `now_secs <= manifest.closesAtUnix`.
  4. **Price Floor:** `solverNetMinerPayoutAtomic >= changenowNetFloorAtomic + 10 bps` (integer ceiling math; otherwise `SOLVENCY_FLOOR_VIOLATION`).
  5. **Dark Pool House Fee:** `houseFeeBps` must satisfy `50 <= houseFeeBps <= 75` (defaults to `50` if omitted).
  6. **Confirmed On-Chain `PerenniaBatchHTLC` Lock Verification:**
     - `disperseChain` `"BASE"` or `"ARB"` -> `eth_getTransactionReceipt` against configured `BASE_RPC_URL`/`ARB_RPC_URL` + expected contract `BASE_BATCH_HTLC_CONTRACT`/`ARB_BATCH_HTLC_CONTRACT`, requiring `status == "0x1"` and log emission containing `sha256HashlockHex`.
     - `disperseChain` `"SOL"` -> `getTransaction` against `SOLANA_RPC_URL` + `SOL_BATCH_HTLC_PROGRAM`, requiring `meta.err == null` and logs binding program + `sha256HashlockHex`.
  7. **Strict Improvement:** `solverNetMinerPayoutAtomic` must strictly exceed any existing winning bid (`IDEMPOTENCY_CONFLICT` on tie/lower bid).
- **Request Body (`ChronosBatchBidRequest`):**
  ```json
  {
    "batchId": "...",
    "nonce": "bot-nonce-0123456789abcdef",
    "solverNetMinerPayoutAtomic": "2500000000",
    "houseFeeBps": 50,
    "sha256HashlockHex": "<64-char hex>",
    "solverKaspaPubkeyHex": "<64-char x-only hex>",
    "disperseChain": "BASE",
    "disperseLockTxid": "0x...",
    "disperseContractAddress": "0x..."
  }
  ```
- **Response (`200 OK`):**
  ```json
  {
    "success": true,
    "status": "WINNING_BID_VERIFIED",
    "bid": {
      "batchId": "...",
      "solverKeyId": "...",
      "solverWallet": "kaspa:...",
      "solverNetMinerPayoutAtomic": "2500000000",
      "minRequiredAtomic": "...",
      "houseFeeBps": 50,
      "houseFeeSompi": "...",
      "sha256HashlockHex": "...",
      "solverKaspaPubkeyHex": "...",
      "disperseChain": "BASE",
      "disperseLockTxid": "0x...",
      "disperseContractAddress": "0x...",
      "verifiedAtUnix": 1795643900
    },
    "kaspaHtlcPreview": {
      "covenantAddress": "kaspa:p...",
      "covenantSpkHex": "...",
      "redeemScriptHex": "...",
      "sha256HashlockHex": "...",
      "refundDaaScore": "..."
    }
  }
  ```

### 3. `POST /api/v1/agent/chronos/zktls-unlock`

- **Handler:** [`handle_post_chronos_zktls_unlock`](file:///home/perennia/perennia-v5-backend/src/agent/dark_pool.rs#L1179-L1344)
- **Requirements & ZK Guardrails:**
  1. Authenticated Agent key + 60s replay nonce (`X-Agent-Nonce` or `nonce`).
  2. **`OpZkPrecompile` Tag Check:** `zkPrecompileTag` MUST equal `32` (`0x20` Groth16). Tag `33` (`0x21` deprecated RISC Zero recursion) and all other tags are hard-rejected (`INVALID_SIGNATURE_OR_SCRIPT` / `ZK_PRECOMPILE_BANNED`).
  3. `groth16ProofHex` must decode to `>= 128` bytes (`2` compressed `G1` + `1` `G2` points).
  4. Matches `billerCommitmentHex` (64-hex) against enabled `VALVE_1_ELECTRIC_BILL` row in `thermostat_valves` and enforces `filled_epoch_usd_micros + paidInvoiceUsdMicros <= target_cap_usd_micros`.
- **Request Body (`ChronosZkTlsUnlockRequest`):**
  ```json
  {
    "vaultId": "...",
    "minerWallet": "kaspa:q...",
    "zkPrecompileTag": 32,
    "groth16ProofHex": "<>=256 hex chars>",
    "billerCommitmentHex": "<64-char hex>",
    "paidInvoiceUsdMicros": "150000000",
    "billerReceiptRef": "util-inv-20261125-001",
    "nonce": "zktls-nonce-0123456789abcdef"
  }
  ```
- **Response (`200 OK`):**
  ```json
  {
    "success": true,
    "receiptId": "ZKTLS-<24-hex>",
    "vaultId": "...",
    "zkPrecompileTag": "0x20",
    "groth160x20ProofHash": "<64-char blake3 hex>",
    "paidInvoiceUsdMicros": "150000000",
    "status": "ZKTLS_GUEST_BILL_PAY_CONFIRMED"
  }
  ```
