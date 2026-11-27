use chrono::{Timelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sqlx::{PgPool, Row};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const COW_HOUSE_SPREAD_MIN_BPS: u16 = 50;
pub const COW_HOUSE_SPREAD_MAX_BPS: u16 = 100;
pub const TIER2_DARK_POOL_MIN_FEE_BPS: u16 = 50;
pub const TIER2_DARK_POOL_MAX_FEE_BPS: u16 = 75;
pub const TIER2_MIN_IMPROVEMENT_BPS: u16 = 10;
pub const DEFAULT_HTLC_DAA_REFUND_DELTA: u64 = 36_000;

pub const REDIS_KEY_CHRONOS_RFQ_BATCHES: &str = "perennia:chronos:rfq:batches";
pub const REDIS_KEY_CHRONOS_WINNING_BID_PREFIX: &str = "perennia:chronos:rfq:winning_bid:";
pub const REDIS_CHANNEL_CHRONOS_RFQ_EVENTS: &str = "perennia:chronos:rfq:events";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KaspaOpSha256HtlcCovenant {
    pub p2sh_address: String,
    pub p2sh_spk_hex: String,
    pub redeem_script_hex: String,
    pub sha256_hashlock_hex: String,
    pub claim_pubkey_hex: String,
    pub refund_pubkey_hex: String,
    pub refund_daa_lock: u64,
    pub sig_op_count: u8,
}

/// Builds clean-stack Kaspa `OpSHA256` P2SH HTLC bytecode:
/// `OpIf OpSHA256 <32B hashlock> OpEqualVerify <32B claim_pubkey> OpCheckSig OpElse <8B refund_daa_le> OpCheckLockTimeVerify OpDrop <32B refund_pubkey> OpCheckSig OpEndIf`
pub fn build_kaspa_opsha256_htlc_covenant(
    sha256_hashlock: &[u8; 32],
    claim_pubkey: &[u8; 32],
    refund_pubkey: &[u8; 32],
    refund_daa_lock: u64,
) -> KaspaOpSha256HtlcCovenant {
    let mut redeem = Vec::with_capacity(115);
    redeem.push(0x63); // OP_IF (claim with SHA-256 preimage)
    redeem.push(0xa8); // OP_SHA256
    redeem.push(0x20); // OP_DATA_32
    redeem.extend_from_slice(sha256_hashlock);
    redeem.push(0x88); // OP_EQUALVERIFY
    redeem.push(0x20); // OP_DATA_32
    redeem.extend_from_slice(claim_pubkey);
    redeem.push(0xac); // OP_CHECKSIG
    redeem.push(0x67); // OP_ELSE (refund after DAA maturity locktime)
    redeem.push(0x08); // OP_DATA_8
    redeem.extend_from_slice(&refund_daa_lock.to_le_bytes());
    redeem.push(0xb0); // OP_CHECKLOCKTIMEVERIFY
    redeem.push(0x75); // OP_DROP
    redeem.push(0x20); // OP_DATA_32
    redeem.extend_from_slice(refund_pubkey);
    redeem.push(0xac); // OP_CHECKSIG
    redeem.push(0x68); // OP_ENDIF

    let script_hash = crate::state_api::blake2b_256(&redeem);
    let p2sh_address = crate::state_api::encode_kaspa_bech32m_address(
        crate::state_api::KASPA_ADDR_VERSION_P2SH,
        &script_hash,
    );
    let p2sh_spk_hex = format!("a9{}87", hex::encode(script_hash));
    KaspaOpSha256HtlcCovenant {
        p2sh_address,
        p2sh_spk_hex,
        redeem_script_hex: hex::encode(&redeem),
        sha256_hashlock_hex: hex::encode(sha256_hashlock),
        claim_pubkey_hex: hex::encode(claim_pubkey),
        refund_pubkey_hex: hex::encode(refund_pubkey),
        refund_daa_lock,
        sig_op_count: 2,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThermostatValveRule {
    pub priority_order: u8,
    pub valve_type: String,
    pub target_asset: String,
    pub target_network: String,
    pub destination_address: String,
    pub target_cap_sompi: u128,
    pub target_cap_usd_micros: u128,
    pub filled_epoch_sompi: u128,
    pub filled_epoch_usd_micros: u128,
    pub zktls_biller_commitment_hex: Option<String>,
    pub is_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThermostatValveAllocation {
    pub priority_order: u8,
    pub valve_type: String,
    pub target_asset: String,
    pub target_network: String,
    pub destination_address: String,
    pub allocated_sompi: u128,
    pub zktls_biller_commitment_hex: Option<String>,
}

/// Sequential 4-Valve Thermostat Router:
/// `Valve 1: Electric Bill` -> `Valve 2: AI Agent x402 Floor` -> `Valve 3: JIT Visa Spend Ceiling` -> `Valve 4: Tangem Cold / Plant Sweep`.
pub fn route_sompi_across_thermostat_valves(
    available_sompi: u128,
    kas_usd_e8: u128,
    valves: &[ThermostatValveRule],
) -> Vec<ThermostatValveAllocation> {
    let mut ordered: Vec<&ThermostatValveRule> =
        valves.iter().filter(|v| v.is_enabled).collect();
    ordered.sort_by_key(|v| v.priority_order);

    let mut remaining = available_sompi;
    let mut allocations = Vec::with_capacity(ordered.len());

    for v in ordered {
        if remaining == 0 {
            break;
        }
        let capacity_sompi = if v.target_cap_sompi > 0 {
            v.target_cap_sompi.saturating_sub(v.filled_epoch_sompi)
        } else if v.target_cap_usd_micros > 0 && kas_usd_e8 > 0 {
            let rem_usd_micros = v
                .target_cap_usd_micros
                .saturating_sub(v.filled_epoch_usd_micros);
            // (usd_micros * 1e-6) / (kas_usd_e8 * 1e-8) * 1e8 = usd_micros * 1e10 / kas_usd_e8
            rem_usd_micros.saturating_mul(10_000_000_000) / kas_usd_e8
        } else if v.priority_order == 4 || v.valve_type == "VALVE_4_TANGEM_COLD_OR_PLANT" {
            remaining
        } else {
            0
        };

        let take = remaining.min(capacity_sompi);
        if take > 0 {
            remaining = remaining.saturating_sub(take);
            allocations.push(ThermostatValveAllocation {
                priority_order: v.priority_order,
                valve_type: v.valve_type.clone(),
                target_asset: v.target_asset.trim().to_uppercase(),
                target_network: v.target_network.trim().to_uppercase(),
                destination_address: v.destination_address.trim().to_string(),
                allocated_sompi: take,
                zktls_biller_commitment_hex: v.zktls_biller_commitment_hex.clone(),
            });
        }
    }
    allocations
}

pub async fn evaluate_wallet_thermostat_route(
    pool: &PgPool,
    clean_wallet: &str,
    available_sompi: u128,
    kas_usd_e8: u128,
) -> Vec<ThermostatValveAllocation> {
    let rows = sqlx::query(
        r#"
        SELECT priority_order, valve_type, target_asset, target_network, destination_address,
               target_cap_sompi::NUMERIC(39,0)::TEXT AS target_cap_sompi,
               target_cap_usd_micros::NUMERIC(39,0)::TEXT AS target_cap_usd_micros,
               filled_epoch_sompi::NUMERIC(39,0)::TEXT AS filled_epoch_sompi,
               filled_epoch_usd_micros::NUMERIC(39,0)::TEXT AS filled_epoch_usd_micros,
               zktls_biller_commitment_hex, is_enabled
        FROM thermostat_valves
        WHERE clean_wallet = $1 AND is_enabled = TRUE
        ORDER BY priority_order ASC
        "#,
    )
    .bind(clean_wallet)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let rules: Vec<ThermostatValveRule> = rows
        .into_iter()
        .map(|r| ThermostatValveRule {
            priority_order: r.try_get::<i16, _>("priority_order").unwrap_or(4) as u8,
            valve_type: r.try_get("valve_type").unwrap_or_default(),
            target_asset: r.try_get("target_asset").unwrap_or_else(|_| "KAS".to_string()),
            target_network: r.try_get("target_network").unwrap_or_else(|_| "KAS".to_string()),
            destination_address: r.try_get("destination_address").unwrap_or_default(),
            target_cap_sompi: r
                .try_get::<String, _>("target_cap_sompi")
                .ok()
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(0),
            target_cap_usd_micros: r
                .try_get::<String, _>("target_cap_usd_micros")
                .ok()
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(0),
            filled_epoch_sompi: r
                .try_get::<String, _>("filled_epoch_sompi")
                .ok()
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(0),
            filled_epoch_usd_micros: r
                .try_get::<String, _>("filled_epoch_usd_micros")
                .ok()
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(0),
            zktls_biller_commitment_hex: r
                .try_get::<Option<String>, _>("zktls_biller_commitment_hex")
                .ok()
                .flatten(),
            is_enabled: r.try_get::<bool, _>("is_enabled").unwrap_or(true),
        })
        .collect();

    route_sompi_across_thermostat_valves(available_sompi, kas_usd_e8, &rules)
}

/// Hard Tier 2 Batch Auction Invariants:
/// 1. `solver_net_miner_payout_atomic >= ceil(changenow_net_floor_atomic * (10_000 + 10) / 10_000)` (`+10 bps`)
/// 2. `50 <= house_fee_bps <= 75`, skimming exact `sompi` to Perennia House Revenue.
pub fn verify_tier2_solver_bid_invariants(
    changenow_net_floor_atomic: u128,
    solver_net_miner_payout_atomic: u128,
    gross_vault_sompi: u128,
    house_fee_bps: u16,
) -> Result<(u128, u128), String> {
    if !(TIER2_DARK_POOL_MIN_FEE_BPS..=TIER2_DARK_POOL_MAX_FEE_BPS).contains(&house_fee_bps) {
        return Err(format!(
            "TIER2_FEE_OUT_OF_BOUNDS: house_fee_bps={} must be between {} and {} bps.",
            house_fee_bps, TIER2_DARK_POOL_MIN_FEE_BPS, TIER2_DARK_POOL_MAX_FEE_BPS
        ));
    }
    if changenow_net_floor_atomic == 0 || gross_vault_sompi == 0 {
        return Err("TIER2_INVALID_AMOUNTS: floor and gross vault sompi must be > 0.".to_string());
    }
    let min_required_atomic = (changenow_net_floor_atomic
        .saturating_mul(10_000 + TIER2_MIN_IMPROVEMENT_BPS as u128)
        + 9_999)
        / 10_000;
    if solver_net_miner_payout_atomic < min_required_atomic {
        return Err(format!(
            "SOLVER_BID_BELOW_RESERVE_FLOOR: bid {} < minimum {} (ChangeNOW floor {} + {} bps).",
            solver_net_miner_payout_atomic,
            min_required_atomic,
            changenow_net_floor_atomic,
            TIER2_MIN_IMPROVEMENT_BPS
        ));
    }
    let house_fee_sompi = gross_vault_sompi.saturating_mul(house_fee_bps as u128) / 10_000;
    Ok((min_required_atomic, house_fee_sompi))
}

fn asset_decimals_for_target(ticker: &str) -> u8 {
    match ticker.trim().to_uppercase().as_str() {
        "USDC" | "USDT" | "KUSDT" | "USD" | "XRP" | "TRX" | "ADA" => 6,
        "SOL" | "SUI" | "TON" => 9,
        "ETH" | "ARB" | "BASE" | "POL" | "AVAX" | "LINK" => 18,
        _ => 8,
    }
}

pub async fn start_delta_netting_engine(redis_client: redis::Client, pool: PgPool) {
    tracing::info!(
        "⚡ [CHRONOS NETTING] Sovereign L1 4-Valve Thermostat, Tier 1/2/3 Dark Pool & RFQ Engine Armed."
    );
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    let mut last_tier12_day: Option<u32> = None;
    let mut last_tier2_close_day: Option<u32> = None;

    loop {
        interval.tick().await;
        let now = Utc::now();
        let ordinal_day = now.format("%j").to_string().parse::<u32>().unwrap_or(0);
        let epoch_id = now.format("%Y-%m-%d").to_string();

        // 21:58:00 UTC -> Tier 1 P2P CoW Cross + Publish Tier 2 Solver RFQ Batch Manifests
        if now.hour() == 21
            && now.minute() == 58
            && last_tier12_day != Some(ordinal_day)
        {
            last_tier12_day = Some(ordinal_day);
            if let Ok(kas_e8) = crate::state_api::resolve_strict_spot_price_e8(&pool, "KAS").await {
                let _ = execute_tier1_cow_dark_pool_cross(&pool, &epoch_id, kas_e8).await;
                if let Ok(mut conn) = redis_client.get_multiplexed_async_connection().await {
                    let _ = publish_tier2_chronos_rfq_batches(&pool, &mut conn, &epoch_id, kas_e8)
                        .await;
                }
            } else {
                tracing::warn!("⚠️ [21:58 UTC] Live KAS oracle offline; failing closed on Tier 1/2 window.");
            }
        }

        // 21:59:30 UTC -> Close Solver Auction & Lock Winning OpSHA256 HTLCs
        if now.hour() == 21
            && now.minute() == 59
            && now.second() >= 30
            && last_tier2_close_day != Some(ordinal_day)
        {
            last_tier2_close_day = Some(ordinal_day);
            if let Ok(mut conn) = redis_client.get_multiplexed_async_connection().await {
                let _ =
                    finalize_tier2_chronos_auction_and_lock_htlcs(&pool, &mut conn, &epoch_id)
                        .await;
            }
        }

        if let Err(e) = run_delta_netting_cycle(&redis_client, &pool).await {
            tracing::warn!("⚠️ [CHRONOS NETTING] Cycle warning: {}", e);
        }
    }
}

pub async fn publish_live_epoch_bucket_telemetry(
    pool: &PgPool,
    _legacy_kas_spot: f64,
) -> anyhow::Result<Value> {
    let kas_usd_e8 = crate::state_api::resolve_strict_spot_price_e8(pool, "KAS")
        .await
        .map_err(|e| anyhow::anyhow!("ORACLE_HALT: {}", e))?;

    let vault_rows = sqlx::query(
        r#"
        SELECT target_asset, target_network, clean_wallet,
               confirmed_utxo_sompi::NUMERIC(39,0)::TEXT AS confirmed_utxo_sompi,
               status
        FROM vault_locks
        WHERE status IN ('FILLING', 'THRESHOLD_MET', 'LOCKED_IN_AUCTION')
        "#,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut sompi_by_asset: BTreeMap<String, u128> = BTreeMap::new();
    let mut ready_sompi_by_asset: BTreeMap<String, u128> = BTreeMap::new();
    let mut wallets_by_asset: HashMap<String, std::collections::HashSet<String>> = HashMap::new();

    for r in vault_rows {
        let asset = r
            .try_get::<String, _>("target_asset")
            .unwrap_or_else(|_| "KAS".to_string())
            .trim()
            .to_uppercase();
        if asset.is_empty() || asset == "KAS" {
            continue;
        }
        let sompi = r
            .try_get::<String, _>("confirmed_utxo_sompi")
            .ok()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        let status: String = r.try_get("status").unwrap_or_default();
        let wallet: String = r.try_get("clean_wallet").unwrap_or_default();

        *sompi_by_asset.entry(asset.clone()).or_insert(0) += sompi;
        if status == "THRESHOLD_MET" || status == "LOCKED_IN_AUCTION" {
            *ready_sompi_by_asset.entry(asset.clone()).or_insert(0) += sompi;
        }
        if !wallet.is_empty() {
            wallets_by_asset.entry(asset).or_default().insert(wallet);
        }
    }

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (current_epoch_bell_ts, next_epoch_bell_ts, seconds_remaining) =
        crate::chronos::compute_jerusalem_epoch_window(now_secs);

    let mut buckets_map = Map::new();
    for (asset, pending_sompi) in sompi_by_asset {
        let floor_sompi = crate::fiat_rails::resolve_live_profitable_vault_floor_sompi(
            pool, &asset, None,
        )
        .await
        .ok()
        .map(|v| v as u128);
        let ready_sompi = ready_sompi_by_asset.get(&asset).copied().unwrap_or(0);
        let pending_usd_micros = pending_sompi.saturating_mul(kas_usd_e8) / 10_000_000_000;
        let participants = wallets_by_asset.get(&asset).map(|s| s.len()).unwrap_or(0);
        let status = if floor_sompi.map(|f| pending_sompi >= f).unwrap_or(false) {
            "READY_FOR_BELL"
        } else if pending_sompi > 0 {
            "FILLING"
        } else {
            "IDLE"
        };

        buckets_map.insert(
            asset.clone(),
            json!({
                "asset": asset,
                "pendingSompi": pending_sompi.to_string(),
                "readySompi": ready_sompi.to_string(),
                "pendingUsdMicros": pending_usd_micros.to_string(),
                "minProfitableSompi": floor_sompi.map(|f| f.to_string()),
                "participantCount": participants,
                "status": status,
                "lastClearedAt": current_epoch_bell_ts
            }),
        );
    }

    let epoch_state = json!({
        "anchorUtcHour": 22,
        "anchorLabel": "22:00 UTC Three-Tier Sovereign Settlement",
        "kasSpotUsdE8": kas_usd_e8.to_string(),
        "currentEpochBellTs": current_epoch_bell_ts,
        "nextEpochBellTs": next_epoch_bell_ts,
        "secondsRemaining": seconds_remaining,
        "updatedAt": now_secs,
        "buckets": Value::Object(buckets_map)
    });

    if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let serialized = epoch_state.to_string();
                let _: redis::RedisResult<()> = redis::cmd("SET")
                    .arg("perennia:settlement:epoch_telemetry")
                    .arg(&serialized)
                    .query_async(&mut conn)
                    .await;
                let sse_msg = json!({
                    "epoch_telemetry_update": true,
                    "epoch": epoch_state
                });
                let _: redis::RedisResult<()> = redis::cmd("PUBLISH")
                    .arg("telemetry:updates")
                    .arg(sse_msg.to_string())
                    .query_async(&mut conn)
                    .await;
            }
        }
    }

    Ok(epoch_state)
}

#[allow(dead_code)]
pub async fn sweep_layered_buckets_on_anchor_order(
    pool: &PgPool,
    target_asset: &str,
    _anchor_kas_volume: f64,
    _kas_spot_usd: f64,
    _target_spot_usd: f64,
) -> anyhow::Result<Value> {
    let clean_target = target_asset.trim().to_uppercase();
    let epoch_id = Utc::now().format("ANCHOR-%Y%m%d-%H%M").to_string();
    let kas_e8 = crate::state_api::resolve_strict_spot_price_e8(pool, "KAS")
        .await
        .map_err(|e| anyhow::anyhow!("ORACLE_HALT: {}", e))?;
    let cow_res = execute_tier1_cow_dark_pool_cross(pool, &epoch_id, kas_e8)
        .await
        .unwrap_or_else(|e| json!({ "error": e, "matchedCount": 0 }));
    Ok(json!({
        "targetAsset": clean_target,
        "tier1CowCross": cow_res
    }))
}

/// Tier 1 (`21:58:00 UTC`): Matches `THRESHOLD_MET` Miner `KAS` sell vaults against opposing Buy-KAS
/// Standalone Wallet Silos / Maker Plants at uniform mid-market `ORACLE_USD_E8`, skimming `50–100 bps`.
pub async fn execute_tier1_cow_dark_pool_cross(
    pool: &PgPool,
    epoch_id: &str,
    kas_usd_e8: u128,
) -> Result<Value, String> {
    if kas_usd_e8 == 0 {
        return Err("ORACLE_HALT: kas_usd_e8 must be > 0.".to_string());
    }
    let sys_cfg = crate::chronos::load_system_treasury_config(pool).await;
    if sys_cfg.outflow_breaker_tripped || sys_cfg.solvency_breaker_tripped {
        return Err("TIER1_HALTED: Circuit breaker is tripped.".to_string());
    }
    let house_revenue_address = crate::chronos::resolve_house_revenue_kas_address(&sys_cfg)
        .unwrap_or_else(|| sys_cfg.cold_kas_address.clone());

    let sell_rows = sqlx::query(
        r#"
        SELECT vault_id, wallet_address, clean_wallet, owner_pubkey_hex,
               covenant_address, target_asset, target_network, destination_address,
               confirmed_utxo_sompi::NUMERIC(39,0)::TEXT AS confirmed_utxo_sompi, fee_bps
        FROM vault_locks
        WHERE status = 'THRESHOLD_MET'
          AND vault_kind IN ('MINER_SILO', 'STANDALONE_WALLET_SILO')
          AND UPPER(target_asset) <> 'KAS'
        ORDER BY updated_at ASC
        LIMIT 50
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("Tier 1 sell vault query failed: {}", e))?;

    let buy_rows = sqlx::query(
        r#"
        SELECT vault_id, wallet_address, clean_wallet, owner_pubkey_hex,
               covenant_address, destination_address, refund_kaspa_address,
               confirmed_utxo_sompi::NUMERIC(39,0)::TEXT AS confirmed_utxo_sompi
        FROM vault_locks
        WHERE status = 'THRESHOLD_MET'
          AND vault_kind IN ('STANDALONE_WALLET_SILO', 'MAKER_PLANT')
          AND UPPER(target_asset) = 'KAS'
        ORDER BY updated_at ASC
        LIMIT 50
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("Tier 1 buy vault query failed: {}", e))?;

    if sell_rows.is_empty() || buy_rows.is_empty() {
        return Ok(json!({ "matchedPairs": 0, "crossedSompi": "0", "houseFeeSompi": "0" }));
    }

    let v_daa = crate::kaspad_client::get_virtual_daa_score_grpc()
        .await
        .unwrap_or(0);
    let mut buy_idx = 0usize;
    let mut matched_pairs = 0usize;
    let mut total_crossed_sompi: u128 = 0;
    let mut total_house_fee_sompi: u128 = 0;

    for s_row in sell_rows {
        if buy_idx >= buy_rows.len() {
            break;
        }
        let s_vault_id: String = s_row.try_get("vault_id").unwrap_or_default();
        let s_wallet: String = s_row.try_get("wallet_address").unwrap_or_default();
        let s_clean: String = s_row.try_get("clean_wallet").unwrap_or_default();
        let s_cov_addr: String = s_row.try_get("covenant_address").unwrap_or_default();
        let s_owner_pub: String = s_row.try_get("owner_pubkey_hex").unwrap_or_default();
        let mut target_asset: String = s_row.try_get("target_asset").unwrap_or_default();
        let mut target_network: String = s_row.try_get("target_network").unwrap_or_default();
        let mut dest_address: String = s_row.try_get("destination_address").unwrap_or_default();
        let s_utxo_sompi: u128 = s_row
            .try_get::<String, _>("confirmed_utxo_sompi")
            .ok()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        if s_utxo_sompi == 0 {
            continue;
        }

        // Apply 4-Valve sequential Thermostat prioritization when configured
        let valve_allocs =
            evaluate_wallet_thermostat_route(pool, &s_clean, s_utxo_sompi, kas_usd_e8).await;
        if let Some(first_valve) = valve_allocs.first() {
            if !first_valve.target_asset.is_empty() && first_valve.target_asset != "KAS" {
                target_asset = first_valve.target_asset.clone();
                target_network = first_valve.target_network.clone();
                if !first_valve.destination_address.is_empty() {
                    dest_address = first_valve.destination_address.clone();
                }
            }
        }
        let _ = s_cov_addr;

        let fee_bps = s_row
            .try_get::<i32, _>("fee_bps")
            .unwrap_or(COW_HOUSE_SPREAD_MIN_BPS as i32)
            .clamp(COW_HOUSE_SPREAD_MIN_BPS as i32, COW_HOUSE_SPREAD_MAX_BPS as i32)
            as u128;

        let b_row = &buy_rows[buy_idx];
        let b_vault_id: String = b_row.try_get("vault_id").unwrap_or_default();
        let b_clean: String = b_row.try_get("clean_wallet").unwrap_or_default();
        let b_dest: String = b_row.try_get("destination_address").unwrap_or_default();
        let b_pub_hex: String = b_row.try_get("owner_pubkey_hex").unwrap_or_default();
        let b_utxo_sompi: u128 = b_row
            .try_get::<String, _>("confirmed_utxo_sompi")
            .ok()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        if s_clean == b_clean || b_utxo_sompi < s_utxo_sompi / 2 {
            buy_idx += 1;
            continue;
        }

        let target_usd_e8 =
            match crate::state_api::resolve_strict_spot_price_e8(pool, &target_asset).await {
                Ok(p) if p > 0 => p,
                _ => continue,
            };

        let house_fee_sompi = s_utxo_sompi.saturating_mul(fee_bps) / 10_000;
        let net_sompi = s_utxo_sompi.saturating_sub(house_fee_sompi);
        let settled_atomic = (net_sompi.saturating_mul(kas_usd_e8)
            / target_usd_e8.max(1))
            .saturating_mul(10u128.pow(asset_decimals_for_target(&target_asset) as u32))
            / 100_000_000;

        let hashlock_digest = blake3::hash(
            format!("COW1:{}:{}:{}:{}", epoch_id, s_vault_id, b_vault_id, v_daa).as_bytes(),
        );
        let mut hashlock_arr = [0u8; 32];
        hashlock_arr.copy_from_slice(hashlock_digest.as_bytes());

        let mut claim_pk = [0u8; 32];
        if let Ok(bytes) = hex::decode(&b_pub_hex) {
            if bytes.len() >= 32 {
                claim_pk.copy_from_slice(&bytes[..32]);
            }
        }
        let mut refund_pk = [0u8; 32];
        if let Ok(bytes) = hex::decode(&s_owner_pub) {
            if bytes.len() >= 32 {
                refund_pk.copy_from_slice(&bytes[..32]);
            }
        }
        let htlc = build_kaspa_opsha256_htlc_covenant(
            &hashlock_arr,
            &claim_pk,
            &refund_pk,
            v_daa.saturating_add(DEFAULT_HTLC_DAA_REFUND_DELTA),
        );

        let l1_dest = if target_asset == "KUSDT" {
            b_dest.as_str()
        } else {
            htlc.p2sh_address.as_str()
        };
        let Ok(payin_u64) = u64::try_from(net_sompi.min(u64::MAX as u128)) else {
            continue;
        };
        let Ok(fee_u64) = u64::try_from(house_fee_sompi.min(u64::MAX as u128)) else {
            continue;
        };
        if let Ok((txid, net_fee)) = crate::state_api::execute_path_b_vault_split_tx(
            pool,
            &s_vault_id,
            l1_dest,
            payin_u64,
            &house_revenue_address,
            fee_u64,
        )
        .await
        {
            let _ = sqlx::query(
                "UPDATE vault_locks SET status = 'SETTLED', updated_at = CURRENT_TIMESTAMP WHERE vault_id IN ($1, $2)",
            )
            .bind(&s_vault_id)
            .bind(&b_vault_id)
            .execute(pool)
            .await;

            let receipt_id = format!("COW1-{}", &htlc.sha256_hashlock_hex[..24]);
            let _ = sqlx::query(
                r#"
                INSERT INTO settlement_receipts (
                    receipt_id, epoch_id, wallet_address, clean_wallet, vault_id,
                    settlement_tier, source_sompi, house_fee_sompi, network_fee_sompi,
                    target_asset, target_network, settled_atomic, oracle_kas_usd_e8,
                    kaspa_l1_txid, htlc_hashlock_sha256, confirmed_daa_score, status
                ) VALUES (
                    $1, $2, $3, $4, $5,
                    'TIER1_COW_DARK_POOL', $6::NUMERIC(39,0), $7::NUMERIC(39,0), $8::NUMERIC(39,0),
                    $9, $10, $11::NUMERIC(39,0), $12::NUMERIC(39,0),
                    $13, $14, $15, 'CONFIRMED'
                )
                ON CONFLICT (receipt_id) DO NOTHING
                "#,
            )
            .bind(&receipt_id)
            .bind(epoch_id)
            .bind(&s_wallet)
            .bind(&s_clean)
            .bind(&s_vault_id)
            .bind(s_utxo_sompi.to_string())
            .bind(house_fee_sompi.to_string())
            .bind(net_fee.to_string())
            .bind(&target_asset)
            .bind(&target_network)
            .bind(settled_atomic.to_string())
            .bind(kas_usd_e8.to_string())
            .bind(&txid)
            .bind(&htlc.sha256_hashlock_hex)
            .bind(v_daa as i64)
            .execute(pool)
            .await;

            let _ = dest_address;
            matched_pairs += 1;
            total_crossed_sompi = total_crossed_sompi.saturating_add(s_utxo_sompi);
            total_house_fee_sompi = total_house_fee_sompi.saturating_add(house_fee_sompi);
            buy_idx += 1;
        }
    }

    Ok(json!({
        "matchedPairs": matched_pairs,
        "crossedSompi": total_crossed_sompi.to_string(),
        "houseFeeSompi": total_house_fee_sompi.to_string()
    }))
}

/// Tier 2 (`21:58:00 UTC`): Publishes anonymized batch manifests + live ChangeNOW net reserve floor
/// on `/api/v1/agent/chronos/rfq` (`perennia:chronos:rfq:batches`).
pub async fn publish_tier2_chronos_rfq_batches(
    pool: &PgPool,
    redis_conn: &mut redis::aio::MultiplexedConnection,
    epoch_id: &str,
    kas_usd_e8: u128,
) -> Result<Value, String> {
    let rows = sqlx::query(
        r#"
        SELECT vault_id, clean_wallet, target_asset, target_network,
               destination_address,
               confirmed_utxo_sompi::NUMERIC(39,0)::TEXT AS confirmed_utxo_sompi
        FROM vault_locks
        WHERE status = 'THRESHOLD_MET'
          AND UPPER(target_asset) <> 'KAS'
        ORDER BY updated_at ASC
        LIMIT 200
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("Failed querying THRESHOLD_MET vaults for Tier 2 RFQ: {}", e))?;

    if rows.is_empty() {
        return Ok(json!({ "batchesPublished": 0, "vaultsLocked": 0 }));
    }

    #[derive(Clone)]
    struct VaultSlice {
        vault_id: String,
        clean_wallet: String,
        sompi: u128,
    }

    let mut grouped: BTreeMap<(String, String), Vec<VaultSlice>> = BTreeMap::new();
    for r in rows {
        let vault_id: String = r.try_get("vault_id").unwrap_or_default();
        let clean_wallet: String = r.try_get("clean_wallet").unwrap_or_default();
        let asset = r
            .try_get::<String, _>("target_asset")
            .unwrap_or_else(|_| "USDC".to_string())
            .trim()
            .to_uppercase();
        let network = r
            .try_get::<String, _>("target_network")
            .unwrap_or_else(|_| "SOL".to_string())
            .trim()
            .to_uppercase();
        let sompi = r
            .try_get::<String, _>("confirmed_utxo_sompi")
            .ok()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        if vault_id.is_empty() || sompi == 0 {
            continue;
        }
        grouped
            .entry((asset, network))
            .or_default()
            .push(VaultSlice {
                vault_id,
                clean_wallet,
                sompi,
            });
    }

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let closes_at_unix = now_secs.saturating_add(90);
    let mut batches_published = 0usize;
    let mut total_vaults_locked = 0usize;

    let _: redis::RedisResult<i64> = redis::cmd("DEL")
        .arg(REDIS_KEY_CHRONOS_RFQ_BATCHES)
        .query_async(redis_conn)
        .await;

    for ((asset, network), slices) in grouped {
        let gross_kas_sompi: u128 = slices.iter().map(|s| s.sompi).sum();
        let fee_bps = TIER2_DARK_POOL_MIN_FEE_BPS;
        let house_fee_sompi = gross_kas_sompi.saturating_mul(fee_bps as u128) / 10_000;
        let net_solver_kas_sompi = gross_kas_sompi.saturating_sub(house_fee_sompi);

        // Compute live ChangeNOW net post-fee Reserve Floor in target atomic units (zero fallback!)
        let Ok(target_usd_e8) = crate::state_api::resolve_strict_spot_price_e8(pool, &asset).await
        else {
            continue;
        };
        if target_usd_e8 == 0 {
            continue;
        }
        let cn_est_f64 = crate::fiat_rails::fetch_changenow_estimated_amount(
            "KAS",
            &format!("{}-{}", asset, network),
            (net_solver_kas_sompi as f64) / 100_000_000.0,
        )
        .await
        .ok()
        .filter(|v| v.is_finite() && *v > 0.0);

        let dec_scale = 10u128.pow(asset_decimals_for_target(&asset) as u32);
        let oracle_net_atomic =
            (net_solver_kas_sompi.saturating_mul(kas_usd_e8) / target_usd_e8).saturating_mul(dec_scale)
                / 100_000_000;
        let cn_floor_atomic = cn_est_f64
            .map(|v| (v * (dec_scale as f64)).floor() as u128)
            .unwrap_or(oracle_net_atomic)
            .max(1);
        let min_winning_bid_atomic = (cn_floor_atomic
            .saturating_mul(10_000 + TIER2_MIN_IMPROVEMENT_BPS as u128)
            + 9_999)
            / 10_000;

        let batch_id = format!(
            "CHRONOS-{}-{}-{}",
            epoch_id,
            asset,
            network
        );
        let mut slice_commitments = Vec::with_capacity(slices.len());
        let mut vault_ids = Vec::with_capacity(slices.len());

        for s in &slices {
            vault_ids.push(s.vault_id.clone());
            let commitment = blake3::hash(
                format!("SLICE:{}:{}:{}", epoch_id, s.vault_id, s.clean_wallet).as_bytes(),
            )
            .to_hex()
            .to_string();
            slice_commitments.push(json!({
                "sliceCommitment": commitment,
                "sompi": s.sompi.to_string()
            }));
            let _ = sqlx::query(
                "UPDATE vault_locks SET status = 'LOCKED_IN_AUCTION', updated_at = CURRENT_TIMESTAMP WHERE vault_id = $1 AND status = 'THRESHOLD_MET'",
            )
            .bind(&s.vault_id)
            .execute(pool)
            .await;
            total_vaults_locked += 1;
        }

        let manifest = json!({
            "batchId": batch_id,
            "epochId": epoch_id,
            "targetAsset": asset,
            "targetNetwork": network,
            "vaultCount": slices.len(),
            "vaultIds": vault_ids,
            "grossKasSompi": gross_kas_sompi.to_string(),
            "houseDarkPoolFeeBps": fee_bps,
            "houseFeeSompi": house_fee_sompi.to_string(),
            "netSolverKasSompi": net_solver_kas_sompi.to_string(),
            "changenowNetFloorAtomic": cn_floor_atomic.to_string(),
            "minSolverNetPayoutAtomic": min_winning_bid_atomic.to_string(),
            "daaTimelockDelta": DEFAULT_HTLC_DAA_REFUND_DELTA,
            "sliceCommitments": slice_commitments,
            "closesAtUnix": closes_at_unix
        });

        let _: redis::RedisResult<i64> = redis::cmd("HSET")
            .arg(REDIS_KEY_CHRONOS_RFQ_BATCHES)
            .arg(&batch_id)
            .arg(manifest.to_string())
            .query_async(redis_conn)
            .await;
        let _: redis::RedisResult<i64> = redis::cmd("PUBLISH")
            .arg(REDIS_CHANNEL_CHRONOS_RFQ_EVENTS)
            .arg(manifest.to_string())
            .query_async(redis_conn)
            .await;
        batches_published += 1;
    }

    Ok(json!({
        "batchesPublished": batches_published,
        "vaultsLocked": total_vaults_locked
    }))
}

/// Tier 2 Close (`21:59:30 UTC`): Consumes winning solver bids with verified `PerenniaBatchHTLC`
/// locks on Base/Solana/Arbitrum, locks pooled `KAS` into Kaspa `OpSHA256` P2SH HTLCs + skims `50–75 bps`
/// to House Revenue, and releases unbid vaults back to `THRESHOLD_MET` for Tier 3.
pub async fn finalize_tier2_chronos_auction_and_lock_htlcs(
    pool: &PgPool,
    redis_conn: &mut redis::aio::MultiplexedConnection,
    epoch_id: &str,
) -> Result<Value, String> {
    let sys_cfg = crate::chronos::load_system_treasury_config(pool).await;
    if sys_cfg.outflow_breaker_tripped || sys_cfg.solvency_breaker_tripped {
        return Err("TIER2_FINALIZE_HALTED: Circuit breaker tripped.".to_string());
    }
    let house_revenue_address = crate::chronos::resolve_house_revenue_kas_address(&sys_cfg)
        .unwrap_or_else(|| sys_cfg.cold_kas_address.clone());

    let batch_map: HashMap<String, String> = redis::cmd("HGETALL")
        .arg(REDIS_KEY_CHRONOS_RFQ_BATCHES)
        .query_async(redis_conn)
        .await
        .unwrap_or_default();

    let v_daa = crate::kaspad_client::get_virtual_daa_score_grpc()
        .await
        .unwrap_or(0);
    let kas_usd_e8 = crate::state_api::resolve_strict_spot_price_e8(pool, "KAS")
        .await
        .unwrap_or(0);

    let mut settled_batches = 0usize;
    let mut released_vaults = 0usize;

    for (batch_id, manifest_raw) in batch_map {
        let Ok(manifest) = serde_json::from_str::<Value>(&manifest_raw) else {
            continue;
        };
        let vault_ids: Vec<String> = manifest
            .get("vaultIds")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let target_asset = manifest
            .get("targetAsset")
            .and_then(|v| v.as_str())
            .unwrap_or("USDC")
            .to_string();
        let target_network = manifest
            .get("targetNetwork")
            .and_then(|v| v.as_str())
            .unwrap_or("BASE")
            .to_string();

        let bid_key = format!("{}{}", REDIS_KEY_CHRONOS_WINNING_BID_PREFIX, batch_id);
        let bid_raw_opt: Option<String> = redis::cmd("GET")
            .arg(&bid_key)
            .query_async(redis_conn)
            .await
            .ok()
            .flatten();

        let Some(bid_raw) = bid_raw_opt else {
            for vid in &vault_ids {
                let _ = sqlx::query(
                    "UPDATE vault_locks SET status = 'THRESHOLD_MET', updated_at = CURRENT_TIMESTAMP WHERE vault_id = $1 AND status = 'LOCKED_IN_AUCTION'",
                )
                .bind(vid)
                .execute(pool)
                .await;
                released_vaults += 1;
            }
            continue;
        };

        let Ok(bid) = serde_json::from_str::<Value>(&bid_raw) else {
            continue;
        };
        let hashlock_hex = bid
            .get("sha256HashlockHex")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let solver_pk_hex = bid
            .get("solverKaspaPubkeyHex")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let disperse_txid = bid
            .get("disperseLockTxid")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let fee_bps = bid
            .get("houseFeeBps")
            .and_then(|v| v.as_u64())
            .unwrap_or(50) as u128;
        let total_bid_out_atomic = bid
            .get("solverNetMinerPayoutAtomic")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);

        let Ok(hl_bytes) = hex::decode(hashlock_hex) else {
            continue;
        };
        let Ok(spk_bytes) = hex::decode(solver_pk_hex) else {
            continue;
        };
        if hl_bytes.len() != 32 || spk_bytes.len() != 32 {
            continue;
        }
        let mut hl_arr = [0u8; 32];
        hl_arr.copy_from_slice(&hl_bytes);
        let mut claim_arr = [0u8; 32];
        claim_arr.copy_from_slice(&spk_bytes);

        let total_batch_sompi: u128 = manifest
            .get("grossKasSompi")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(1)
            .max(1);

        let mut batch_ok = false;
        for vid in &vault_ids {
            let Ok(Some(v_row)) = sqlx::query(
                "SELECT wallet_address, clean_wallet, owner_pubkey_hex, confirmed_utxo_sompi::NUMERIC(39,0)::TEXT AS confirmed_utxo_sompi FROM vault_locks WHERE vault_id = $1 LIMIT 1",
            )
            .bind(vid)
            .fetch_optional(pool)
            .await
            else {
                continue;
            };
            let v_wallet: String = v_row.try_get("wallet_address").unwrap_or_default();
            let v_clean: String = v_row.try_get("clean_wallet").unwrap_or_default();
            let v_owner_pk: String = v_row.try_get("owner_pubkey_hex").unwrap_or_default();
            let v_sompi: u128 = v_row
                .try_get::<String, _>("confirmed_utxo_sompi")
                .ok()
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(0);
            if v_sompi == 0 {
                continue;
            }
            let mut ref_arr = [0u8; 32];
            if let Ok(b) = hex::decode(&v_owner_pk) {
                if b.len() >= 32 {
                    ref_arr.copy_from_slice(&b[..32]);
                }
            }
            let htlc = build_kaspa_opsha256_htlc_covenant(
                &hl_arr,
                &claim_arr,
                &ref_arr,
                v_daa.saturating_add(DEFAULT_HTLC_DAA_REFUND_DELTA),
            );
            let house_fee_sompi = v_sompi.saturating_mul(fee_bps) / 10_000;
            let net_htlc_sompi = v_sompi.saturating_sub(house_fee_sompi);
            if let (Ok(pay_u64), Ok(fee_u64)) = (u64::try_from(net_htlc_sompi), u64::try_from(house_fee_sompi)) {
                if let Ok((kaspa_txid, net_fee)) = crate::state_api::execute_path_b_vault_split_tx(
                    pool,
                    vid,
                    &htlc.p2sh_address,
                    pay_u64,
                    &house_revenue_address,
                    fee_u64,
                )
                .await
                {
                    let _ = sqlx::query(
                        "UPDATE vault_locks SET status = 'SETTLED', updated_at = CURRENT_TIMESTAMP WHERE vault_id = $1",
                    )
                    .bind(vid)
                    .execute(pool)
                    .await;
                    let proportional_out =
                        total_bid_out_atomic.saturating_mul(v_sompi) / total_batch_sompi;
                    let receipt_id = format!("BOT2-{}-{}", &vid[..10.min(vid.len())], &hashlock_hex[..10]);
                    let _ = sqlx::query(
                        r#"
                        INSERT INTO settlement_receipts (
                            receipt_id, epoch_id, wallet_address, clean_wallet, vault_id,
                            settlement_tier, source_sompi, house_fee_sompi, network_fee_sompi,
                            target_asset, target_network, settled_atomic, oracle_kas_usd_e8,
                            kaspa_l1_txid, destination_txid, htlc_hashlock_sha256,
                            confirmed_daa_score, status
                        ) VALUES (
                            $1, $2, $3, $4, $5,
                            'TIER2_BOT_BATCH_HTLC', $6::NUMERIC(39,0), $7::NUMERIC(39,0), $8::NUMERIC(39,0),
                            $9, $10, $11::NUMERIC(39,0), $12::NUMERIC(39,0),
                            $13, $14, $15, $16, 'CONFIRMED'
                        )
                        ON CONFLICT (receipt_id) DO NOTHING
                        "#,
                    )
                    .bind(&receipt_id)
                    .bind(epoch_id)
                    .bind(&v_wallet)
                    .bind(&v_clean)
                    .bind(vid)
                    .bind(v_sompi.to_string())
                    .bind(house_fee_sompi.to_string())
                    .bind(net_fee.to_string())
                    .bind(&target_asset)
                    .bind(&target_network)
                    .bind(proportional_out.to_string())
                    .bind(kas_usd_e8.to_string())
                    .bind(&kaspa_txid)
                    .bind(disperse_txid)
                    .bind(hashlock_hex)
                    .bind(v_daa as i64)
                    .execute(pool)
                    .await;
                    batch_ok = true;
                }
            }
        }
        if batch_ok {
            settled_batches += 1;
        }
    }

    Ok(json!({
        "settledBatches": settled_batches,
        "releasedVaultsToTier3": released_vaults
    }))
}

pub async fn run_delta_netting_cycle(
    redis_client: &redis::Client,
    pool: &PgPool,
) -> anyhow::Result<Value> {
    let mut redis_conn = redis_client.get_multiplexed_async_connection().await?;
    let epoch_state = publish_live_epoch_bucket_telemetry(pool, 0.0).await?;
    let rfq_count: i64 = redis::cmd("HLEN")
        .arg(REDIS_KEY_CHRONOS_RFQ_BATCHES)
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(0);
    Ok(json!({
        "mode": "SOVEREIGN_L1_VAULT_NETTING",
        "activeRfqBatches": rfq_count,
        "epoch": epoch_state,
        "completedAtMs": Utc::now().timestamp_millis()
    }))
}

/// Full 22:00 UTC Three-Tier Chronos Waterfall Entrypoint:
/// Tier 1 (P2P CoW Cross) -> Tier 2 (Verified AI Bot Batch HTLCs) -> Tier 3 (Non-Custodial ChangeNOW v2 Split).
pub async fn execute_epoch_delta_netting_and_lp_compounding(
    pool: &PgPool,
) -> anyhow::Result<Value> {
    let kas_usd_e8 = crate::state_api::resolve_strict_spot_price_e8(pool, "KAS")
        .await
        .map_err(|e| anyhow::anyhow!("Epoch waterfall aborted (fail-closed): {}", e))?;
    let epoch_id = Utc::now().format("%Y-%m-%d").to_string();

    let tier1 = execute_tier1_cow_dark_pool_cross(pool, &epoch_id, kas_usd_e8)
        .await
        .unwrap_or_else(|e| json!({ "error": e }));

    let tier2 = if let Ok(redis_url) = env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url.trim()) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                finalize_tier2_chronos_auction_and_lock_htlcs(pool, &mut conn, &epoch_id)
                    .await
                    .unwrap_or_else(|e| json!({ "error": e }))
            } else {
                json!({ "skipped": "redis_unavailable" })
            }
        } else {
            json!({ "skipped": "invalid_redis_url" })
        }
    } else {
        json!({ "skipped": "redis_url_missing" })
    };

    let tier3 = crate::fiat_rails::execute_tier3_changenow_vault_fallback(pool, &epoch_id)
        .await
        .unwrap_or_else(|e| json!({ "error": e }));

    let epoch_telemetry = publish_live_epoch_bucket_telemetry(pool, 0.0)
        .await
        .unwrap_or_else(|_| json!({}));

    Ok(json!({
        "epochId": epoch_id,
        "kasSpotUsdE8": kas_usd_e8.to_string(),
        "tier1CowCross": tier1,
        "tier2BotBatchHtlc": tier2,
        "tier3ChangeNowSplit": tier3,
        "epochTelemetry": epoch_telemetry,
        "settledAt": Utc::now().to_rfc3339()
    }))
}
