use lazy_static::lazy_static;
use prometheus::{Encoder, GaugeVec, IntCounterVec, Opts, Registry, TextEncoder};
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const KASPA_DIFF_CONSTANT_U128: u128 = 4_294_967_296;
const KASPA_DIFF_CONSTANT_F64: f64 = 4_294_967_296.0;
const DEFAULT_COINBASE_MATURITY_DAA: i64 = 1_000;

pub const BASE_POOL_FEE_BPS: u16 = 100;
pub const MIN_POOL_FEE_BPS: u16 = 50;
pub const MAX_POOL_FEE_BPS: u16 = 200;
pub const WEEKLY_FEE_DECAY_BPS: u16 = 5;
pub const SECONDS_PER_WEEK: u64 = 604_800;
pub const DISCONNECT_GRACE_WINDOW_SECS: u64 = 7_200;
pub const DISCONNECT_GRACE_WINDOW_MS: u64 = 7_200_000;
pub const MAINTENANCE_SHIELD_GRACE_WINDOW_SECS: u64 = 86_400;
pub const MAINTENANCE_SHIELD_GRACE_WINDOW_MS: u64 = 86_400_000;
pub const MINER_PERK_SWAP_FEE_FLOOR_BPS: u16 = 10;
pub const STAGE1_FLUSH_FLOOR_SOMPI: u128 = 2_500_000_000;

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref WORKER_HASHRATE: GaugeVec = GaugeVec::new(
        Opts::new(
            "ks_worker_hashrate",
            "Strictly verified unsimulated hashrate per worker in TH/s"
        ),
        &["worker"]
    )
    .expect("Metric setup failed");
    pub static ref WORKER_SHARES: IntCounterVec = IntCounterVec::new(
        Opts::new(
            "ks_worker_shares",
            "Cryptographically validated shares per worker"
        ),
        &["worker", "type"]
    )
    .expect("Metric setup failed");
}

pub fn init_telemetry() {
    REGISTRY.register(Box::new(WORKER_HASHRATE.clone())).unwrap();
    REGISTRY.register(Box::new(WORKER_SHARES.clone())).unwrap();
}

pub fn compute_miner_loyalty_fee_bps(
    streak_started_ms: u64,
    now_ms: u64,
    configured_base_fee_bps: u16,
) -> (u64, u16) {
    let base_bps = configured_base_fee_bps.clamp(MIN_POOL_FEE_BPS, MAX_POOL_FEE_BPS);
    if streak_started_ms == 0 || now_ms <= streak_started_ms {
        return (0, base_bps);
    }
    let elapsed_secs = now_ms.saturating_sub(streak_started_ms) / 1000;
    let consecutive_weeks = elapsed_secs / SECONDS_PER_WEEK;
    let discount_bps = consecutive_weeks
        .saturating_mul(WEEKLY_FEE_DECAY_BPS as u64)
        .min(u16::MAX as u64) as u16;
    let effective_bps = base_bps.saturating_sub(discount_bps).max(MIN_POOL_FEE_BPS);
    (consecutive_weeks, effective_bps)
}

pub async fn start_prometheus_exporter(_bind_addr: String) {
    let addr = "0.0.0.0:8081";
    let listener = TcpListener::bind(addr)
        .await
        .expect("Failed to bind Prometheus port");
    tracing::info!(
        "📊 Zero-Simulation Telemetry exporter natively active on http://{}/metrics",
        addr
    );
    loop {
        if let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                let _ = socket.read(&mut buf).await;
                let mut buffer = vec![];
                let encoder = TextEncoder::new();
                let metric_families = REGISTRY.gather();
                encoder.encode(&metric_families, &mut buffer).unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                    buffer.len(),
                    String::from_utf8_lossy(&buffer)
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    }
}

struct WorkerState {
    last_share_ts: u64,
    streak_started_ts: u64,
    effective_fee_bps: u16,
    share_history: VecDeque<(u64, f64)>,
    shares_contributed: f64,
    valid_share_count: u64,
    rejected_share_count: u64,
    blocks_found: u64,
    unflushed_difficulty: f64,
    unflushed_blocks: u64,
}

#[derive(Clone)]
struct WorkerDbSnapshot {
    full_identity: String,
    wallet_address: String,
    worker_name: String,
    hashrate_ths: f64,
    valid_shares: i64,
    rejected_shares: i64,
    acceptance_pct: f64,
    blocks_found: i64,
    last_share_ts: i64,
    streak_started_ts: i64,
    effective_fee_bps: u16,
    status: String,
}

struct PendingMicroShare {
    worker_id: String,
    difficulty_weight: f64,
    network_diff: f64,
    sompi_delta: i64,
    pool_fee_sompi: i64,
    block_daa_score: i64,
    is_settled: bool,
}

struct WalletAccrualDelta {
    prefixed_wallet: String,
    miner_net_sompi: u128,
    pool_fee_sompi: u128,
    pool_fee_bps: u16,
}

fn normalize_timestamp_ms(raw_ts: i64, fallback_ms: u64) -> u64 {
    if raw_ts <= 0 {
        return fallback_ms;
    }
    let val = raw_ts as u64;
    if val < 10_000_000_000 {
        val.saturating_mul(1000)
    } else {
        val
    }
}

pub async fn start_accounting_engine(mut valid_share_rx: mpsc::Receiver<(String, f64, bool)>) {
    tracing::info!(
        "🏦 Sovereign L1 Sompi Accounting, Loyalty Decay (100->50 bps) & 1,000-DAA Maturity Engine Booted..."
    );
    let redis_url = env::var("REDIS_URL")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = redis::Client::open(redis_url).expect("Redis connection failed");
    let mut redis_conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("❌ CRITICAL: Could not connect to Redis for Accounting! {}", e);
            return;
        }
    };
    let pg_url = env::var("DATABASE_URL")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "postgres://postgres:password@127.0.0.1:5432/perennia".to_string());
    let pg_pool = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&pg_url)
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!("❌ CRITICAL: Failed to connect to Postgres! {}", e);
            return;
        }
    };

    let pool_fee_bps: u16 = env::var("POOL_FEE_BPS")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|&v| (MIN_POOL_FEE_BPS..=MAX_POOL_FEE_BPS).contains(&v))
        .unwrap_or(BASE_POOL_FEE_BPS);
    let coinbase_maturity_daa: i64 = env::var("COINBASE_MATURITY_DAA")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|&v| v >= 100)
        .unwrap_or(DEFAULT_COINBASE_MATURITY_DAA);
    let corp_kas_clean = crate::chronos::resolve_master_treasury_address();
    let mut flush_interval = tokio::time::interval(Duration::from_millis(1000));
    let mut worker_states: HashMap<String, WorkerState> = HashMap::new();
    let mut maintenance_grace_shield_active = false;
    let mut blacklisted_wallets_cache: HashSet<String> = HashSet::new();
    let mut blacklisted_workers_cache: HashSet<String> = HashSet::new();

    let boot_now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    if let Ok(existing_workers) = sqlx::query(
        r#"
        SELECT COALESCE(NULLIF(worker_identity, ''), worker_id) AS worker_identity,
               valid_shares, rejected_shares, blocks_found,
               last_share_ts, COALESCE(streak_started_ts, 0) AS streak_started_ts
        FROM worker_profiles
        WHERE last_share_ts > 0
        "#,
    )
    .fetch_all(&pg_pool)
    .await
    {
        for r in existing_workers {
            let id: String = r.try_get("worker_identity").unwrap_or_default();
            if id.is_empty() {
                continue;
            }
            let raw_last_ts: i64 = r.try_get("last_share_ts").unwrap_or(0);
            let last_ms = normalize_timestamp_ms(raw_last_ts, boot_now_ms);
            if boot_now_ms.saturating_sub(last_ms) <= MAINTENANCE_SHIELD_GRACE_WINDOW_MS {
                let raw_streak_ts: i64 = r.try_get("streak_started_ts").unwrap_or(raw_last_ts);
                let streak_ms = normalize_timestamp_ms(raw_streak_ts, last_ms);
                let (_, eff_bps) =
                    compute_miner_loyalty_fee_bps(streak_ms, boot_now_ms, pool_fee_bps);
                let valid_sh = r.try_get::<i64, _>("valid_shares").unwrap_or(0).max(0) as u64;
                let rej_sh = r.try_get::<i64, _>("rejected_shares").unwrap_or(0).max(0) as u64;
                let blks = r.try_get::<i64, _>("blocks_found").unwrap_or(0).max(0) as u64;
                worker_states.insert(
                    id,
                    WorkerState {
                        last_share_ts: last_ms,
                        streak_started_ts: streak_ms,
                        effective_fee_bps: eff_bps,
                        share_history: VecDeque::new(),
                        shares_contributed: valid_sh as f64,
                        valid_share_count: valid_sh,
                        rejected_share_count: rej_sh,
                        blocks_found: blks,
                        unflushed_difficulty: 0.0,
                        unflushed_blocks: 0,
                    },
                );
            }
        }
    }

    let mut cached_l1_blocks_won_sompi: u128 = 0;
    let mut cached_immature_blocks_sompi: u128 = 0;
    let mut cached_total_blocks_count: i64 = 0;
    let mut cached_unpaid_mature_sompi: u128 = 0;
    let mut cached_immature_accruals_sompi: u128 = 0;
    let mut tick_counter: u64 = 0;
    let mut pending_micro_shares: Vec<PendingMicroShare> = Vec::new();

    loop {
        tokio::select! {
            Some((full_worker_name, difficulty, is_network_block)) = valid_share_rx.recv() => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                let active_grace_ms = if maintenance_grace_shield_active {
                    MAINTENANCE_SHIELD_GRACE_WINDOW_MS
                } else {
                    DISCONNECT_GRACE_WINDOW_MS
                };
                let state = worker_states.entry(full_worker_name.clone()).or_insert_with(|| WorkerState {
                    last_share_ts: now,
                    streak_started_ts: now,
                    effective_fee_bps: pool_fee_bps,
                    share_history: VecDeque::new(),
                    shares_contributed: 0.0,
                    valid_share_count: 0,
                    rejected_share_count: 0,
                    blocks_found: 0,
                    unflushed_difficulty: 0.0,
                    unflushed_blocks: 0,
                });
                if difficulty > 0.0 {
                    if !maintenance_grace_shield_active
                        && (now.saturating_sub(state.last_share_ts) > active_grace_ms
                            || state.streak_started_ts == 0)
                    {
                        state.streak_started_ts = now;
                    } else if state.streak_started_ts == 0 {
                        state.streak_started_ts = now;
                    }
                    let (_, eff_bps) = compute_miner_loyalty_fee_bps(
                        state.streak_started_ts,
                        now,
                        pool_fee_bps,
                    );
                    state.effective_fee_bps = eff_bps;
                    state.share_history.push_back((now, difficulty));
                    state.last_share_ts = now;
                    state.shares_contributed += difficulty;
                    state.valid_share_count += 1;
                    state.unflushed_difficulty += difficulty;
                    WORKER_SHARES.with_label_values(&[&full_worker_name, "valid"]).inc_by(difficulty as u64);
                } else if difficulty < 0.0 {
                    state.rejected_share_count += 1;
                    WORKER_SHARES.with_label_values(&[&full_worker_name, "rejected"]).inc();
                }
                if is_network_block {
                    state.blocks_found += 1;
                    state.unflushed_blocks += 1;
                    WORKER_SHARES.with_label_values(&[&full_worker_name, "block"]).inc();
                }
            }
            _ = flush_interval.tick() => {
                tick_counter = tick_counter.wrapping_add(1);
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                let now_secs = now / 1000;

                if tick_counter % 5 == 1 {
                    let shield_str: Option<String> = redis::cmd("GET")
                        .arg("perennia:stratum:maintenance_grace_shield")
                        .query_async(&mut redis_conn)
                        .await
                        .unwrap_or(None);
                    maintenance_grace_shield_active = shield_str
                        .map(|s| s.trim() == "1" || s.trim().eq_ignore_ascii_case("true"))
                        .unwrap_or(false);

                    if let Ok(blk_wallets) = redis::cmd("SMEMBERS")
                        .arg("perennia:firewall:blacklisted_wallets")
                        .query_async::<_, Vec<String>>(&mut redis_conn)
                        .await
                    {
                        blacklisted_wallets_cache = blk_wallets
                            .into_iter()
                            .map(|w| w.trim().to_lowercase().replace("kaspa:", ""))
                            .collect();
                    }
                    if let Ok(blk_workers) = redis::cmd("SMEMBERS")
                        .arg("perennia:firewall:blacklisted_workers")
                        .query_async::<_, Vec<String>>(&mut redis_conn)
                        .await
                    {
                        blacklisted_workers_cache = blk_workers
                            .into_iter()
                            .map(|w| w.trim().to_lowercase())
                            .collect();
                    }
                }

                let active_grace_window_ms = if maintenance_grace_shield_active {
                    MAINTENANCE_SHIELD_GRACE_WINDOW_MS
                } else {
                    DISCONNECT_GRACE_WINDOW_MS
                };
                let active_grace_window_secs = if maintenance_grace_shield_active {
                    MAINTENANCE_SHIELD_GRACE_WINDOW_SECS
                } else {
                    DISCONNECT_GRACE_WINDOW_SECS
                };

                let net_diff_str: Option<String> = redis::cmd("GET")
                    .arg("pool:network_diff")
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(None);
                let net_diff = net_diff_str
                    .and_then(|s| s.parse::<f64>().ok())
                    .filter(|&v| v.is_finite() && v > 0.0)
                    .unwrap_or(0.0);
                let net_diff_e6 = if net_diff > 0.0 {
                    (net_diff * 1_000_000.0).round().max(1.0) as u128
                } else {
                    0
                };

                let reward_sompi_str: Option<String> = redis::cmd("GET")
                    .arg("pool:block_reward_sompi")
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(None);
                let block_reward_sompi = reward_sompi_str
                    .and_then(|s| s.trim().parse::<u128>().ok())
                    .unwrap_or(0);

                let virtual_daa_str: Option<String> = redis::cmd("GET")
                    .arg("pool:virtual_daa_score")
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(None);
                let current_virtual_daa = virtual_daa_str
                    .and_then(|s| s.trim().parse::<i64>().ok())
                    .unwrap_or(0);

                // Strictly DAA-gated 1,000-block coinbase maturity (zero wall-clock timer fallback)
                if tick_counter % 5 == 1 {
                    if let Ok(row) = sqlx::query(
                        r#"
                        SELECT
                            COUNT(*)::BIGINT AS total_blocks_count,
                            COALESCE(SUM(CASE
                                WHEN $1 > 0
                                 AND COALESCE(daa_score, 0) > 0
                                 AND ($1 - COALESCE(daa_score, 0)) >= $2
                                THEN reward_sompi
                                ELSE 0
                            END), 0)::NUMERIC(39, 0)::TEXT AS matured_blocks_sompi,
                            COALESCE(SUM(CASE
                                WHEN NOT (
                                    $1 > 0
                                    AND COALESCE(daa_score, 0) > 0
                                    AND ($1 - COALESCE(daa_score, 0)) >= $2
                                )
                                THEN reward_sompi
                                ELSE 0
                            END), 0)::NUMERIC(39, 0)::TEXT AS immature_blocks_sompi
                        FROM network_blocks
                        WHERE COALESCE(is_orphaned, FALSE) = FALSE
                        "#,
                    )
                    .bind(current_virtual_daa)
                    .bind(coinbase_maturity_daa)
                    .fetch_one(&pg_pool)
                    .await
                    {
                        cached_total_blocks_count =
                            row.try_get::<i64, _>("total_blocks_count").unwrap_or(0);
                        cached_l1_blocks_won_sompi = row
                            .try_get::<String, _>("matured_blocks_sompi")
                            .ok()
                            .and_then(|s| s.trim().parse::<u128>().ok())
                            .unwrap_or(0);
                        cached_immature_blocks_sompi = row
                            .try_get::<String, _>("immature_blocks_sompi")
                            .ok()
                            .and_then(|s| s.trim().parse::<u128>().ok())
                            .unwrap_or(0);
                    }

                    if let Ok(acc_row) = sqlx::query(
                        r#"
                        SELECT
                            COALESCE(SUM(unpaid_mature_sompi), 0)::NUMERIC(39, 0)::TEXT AS unpaid_mature,
                            COALESCE(SUM(immature_sompi), 0)::NUMERIC(39, 0)::TEXT AS immature_accrual
                        FROM stratum_mature_accruals
                        "#,
                    )
                    .fetch_one(&pg_pool)
                    .await
                    {
                        cached_unpaid_mature_sompi = acc_row
                            .try_get::<String, _>("unpaid_mature")
                            .ok()
                            .and_then(|s| s.trim().parse::<u128>().ok())
                            .unwrap_or(0);
                        cached_immature_accruals_sompi = acc_row
                            .try_get::<String, _>("immature_accrual")
                            .ok()
                            .and_then(|s| s.trim().parse::<u128>().ok())
                            .unwrap_or(0);
                    }
                }

                let epoch_telemetry_raw: Option<String> = redis::cmd("GET")
                    .arg("perennia:settlement:epoch_telemetry")
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(None);
                let mut epoch_telemetry_val: Value = epoch_telemetry_raw
                    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                    .unwrap_or_else(|| json!({}));
                let (current_epoch_bell_ts, next_epoch_bell_ts, seconds_remaining) =
                    crate::chronos::compute_jerusalem_epoch_window(now_secs);
                if let Some(obj) = epoch_telemetry_val.as_object_mut() {
                    obj.insert("anchorUtcHour".to_string(), json!(22));
                    obj.insert(
                        "anchorLabel".to_string(),
                        json!("22:00 UTC Global Settlement"),
                    );
                    obj.insert("currentEpochBellTs".to_string(), json!(current_epoch_bell_ts));
                    obj.insert("nextEpochBellTs".to_string(), json!(next_epoch_bell_ts));
                    obj.insert("secondsRemaining".to_string(), json!(seconds_remaining));
                }

                let can_calculate_yields = net_diff_e6 > 0 && block_reward_sompi > 0;
                let mut pipeline = redis::pipe();
                let mut total_hashrate = 0.0;
                let mut workers_array = Vec::new();
                let mut keys_to_remove = Vec::new();
                let mut accruals_by_wallet: HashMap<String, WalletAccrualDelta> = HashMap::new();
                let mut wallet_hashrate_ths_map: HashMap<String, f64> = HashMap::new();
                let mut wallet_best_loyalty_map: HashMap<String, (u64, u64, u16, bool, u64)> =
                    HashMap::new();
                let mut db_worker_snapshots: Vec<WorkerDbSnapshot> = Vec::new();
                let cutoff_300s = now.saturating_sub(300_000);
                let cutoff_60s = now.saturating_sub(60_000);

                if !worker_states.is_empty() {
                    for (full_worker, state) in worker_states.iter_mut() {
                        let dt_idle_ms = now.saturating_sub(state.last_share_ts);
                        let dt_idle = (dt_idle_ms as f64) / 1000.0;
                        while let Some(&(ts, _)) = state.share_history.front() {
                            if ts < cutoff_300s {
                                state.share_history.pop_front();
                            } else {
                                break;
                            }
                        }
                        let mut work_60s = 0.0;
                        let mut work_300s = 0.0;
                        let mut oldest_ts = now;
                        for &(ts, diff) in state.share_history.iter() {
                            let work = diff * KASPA_DIFF_CONSTANT_F64;
                            work_300s += work;
                            if ts >= cutoff_60s {
                                work_60s += work;
                            }
                            if ts < oldest_ts {
                                oldest_ts = ts;
                            }
                        }
                        let elapsed_total = (((now - oldest_ts) as f64) / 1000.0).max(1.0);
                        let elapsed_60s = elapsed_total.min(60.0).max(1.0);
                        let hr_300s = work_300s / elapsed_total;
                        let hr_60s = work_60s / elapsed_60s;
                        let current_hashrate = if state.share_history.is_empty() {
                            0.0
                        } else {
                            (hr_60s * 0.4) + (hr_300s * 0.6)
                        };
                        let is_online = current_hashrate > 0.0 || dt_idle < 60.0;
                        let within_grace_window =
                            maintenance_grace_shield_active || dt_idle_ms <= active_grace_window_ms;
                        let total_attempts = state.valid_share_count + state.rejected_share_count;
                        let acceptance_pct = if total_attempts > 0 {
                            ((state.valid_share_count as f64 / total_attempts as f64) * 100.0)
                                .clamp(0.0, 100.0)
                        } else {
                            100.0
                        };
                        let parts: Vec<&str> = full_worker.split('.').collect();
                        let wallet_address = if !parts.is_empty() {
                            parts[0]
                        } else {
                            full_worker.as_str()
                        };
                        let worker_name = if parts.len() > 1 {
                            parts[1..].join(".")
                        } else {
                            full_worker.to_string()
                        };
                        let clean_wallet = wallet_address
                            .to_lowercase()
                            .replace("kaspa:", "")
                            .trim()
                            .to_string();

                        let is_blacklisted = blacklisted_wallets_cache.contains(&clean_wallet)
                            || blacklisted_workers_cache.contains(&full_worker.to_lowercase())
                            || blacklisted_workers_cache.contains(&worker_name.to_lowercase());
                        if is_blacklisted {
                            state.unflushed_difficulty = 0.0;
                            continue;
                        }

                        if !is_online && !within_grace_window {
                            keys_to_remove.push(full_worker.clone());
                            state.streak_started_ts = 0;
                            state.effective_fee_bps = pool_fee_bps;
                            WORKER_HASHRATE.with_label_values(&[full_worker]).set(0.0);
                            pipeline
                                .cmd("SET")
                                .arg(format!("worker:{}:hashrate", full_worker))
                                .arg(0.0)
                                .ignore();
                            pipeline
                                .cmd("SREM")
                                .arg("pool:workers")
                                .arg(full_worker.clone())
                                .ignore();
                            db_worker_snapshots.push(WorkerDbSnapshot {
                                full_identity: full_worker.clone(),
                                wallet_address: wallet_address.to_string(),
                                worker_name,
                                hashrate_ths: 0.0,
                                valid_shares: state.valid_share_count as i64,
                                rejected_shares: state.rejected_share_count as i64,
                                acceptance_pct,
                                blocks_found: state.blocks_found as i64,
                                last_share_ts: state.last_share_ts as i64,
                                streak_started_ts: 0,
                                effective_fee_bps: pool_fee_bps,
                                status: "offline".to_string(),
                            });
                        } else if !is_online && within_grace_window {
                            let (consecutive_weeks, eff_fee_bps) = compute_miner_loyalty_fee_bps(
                                state.streak_started_ts,
                                now,
                                pool_fee_bps,
                            );
                            state.effective_fee_bps = eff_fee_bps;
                            let grace_remaining_secs = if maintenance_grace_shield_active {
                                active_grace_window_secs
                            } else {
                                active_grace_window_secs.saturating_sub(dt_idle_ms / 1000)
                            };
                            WORKER_HASHRATE.with_label_values(&[full_worker]).set(0.0);
                            pipeline
                                .cmd("SET")
                                .arg(format!("worker:{}:hashrate", full_worker))
                                .arg(0.0)
                                .ignore();
                            pipeline
                                .cmd("SET")
                                .arg(format!("worker:{}:effective_fee_bps", full_worker))
                                .arg(eff_fee_bps)
                                .ignore();
                            pipeline
                                .cmd("SET")
                                .arg(format!("worker:{}:streak_started_ts", full_worker))
                                .arg(state.streak_started_ts)
                                .ignore();
                            let entry = wallet_best_loyalty_map.entry(clean_wallet.clone()).or_insert((
                                state.streak_started_ts,
                                consecutive_weeks,
                                eff_fee_bps,
                                false,
                                grace_remaining_secs,
                            ));
                            if eff_fee_bps < entry.2
                                || (state.streak_started_ts > 0 && state.streak_started_ts < entry.0)
                            {
                                *entry = (
                                    state.streak_started_ts,
                                    consecutive_weeks,
                                    eff_fee_bps,
                                    entry.3,
                                    grace_remaining_secs.max(entry.4),
                                );
                            }
                            db_worker_snapshots.push(WorkerDbSnapshot {
                                full_identity: full_worker.clone(),
                                wallet_address: wallet_address.to_string(),
                                worker_name,
                                hashrate_ths: 0.0,
                                valid_shares: state.valid_share_count as i64,
                                rejected_shares: state.rejected_share_count as i64,
                                acceptance_pct,
                                blocks_found: state.blocks_found as i64,
                                last_share_ts: state.last_share_ts as i64,
                                streak_started_ts: state.streak_started_ts as i64,
                                effective_fee_bps: eff_fee_bps,
                                status: "grace_period".to_string(),
                            });
                        } else {
                            if state.streak_started_ts == 0 {
                                state.streak_started_ts = now;
                            }
                            let (consecutive_weeks, eff_fee_bps) = compute_miner_loyalty_fee_bps(
                                state.streak_started_ts,
                                now,
                                pool_fee_bps,
                            );
                            state.effective_fee_bps = eff_fee_bps;
                            let grace_remaining_secs = active_grace_window_secs;
                            let entry = wallet_best_loyalty_map.entry(clean_wallet.clone()).or_insert((
                                state.streak_started_ts,
                                consecutive_weeks,
                                eff_fee_bps,
                                true,
                                grace_remaining_secs,
                            ));
                            entry.3 = true;
                            entry.4 = active_grace_window_secs;
                            if eff_fee_bps <= entry.2 {
                                entry.0 = state.streak_started_ts;
                                entry.1 = consecutive_weeks;
                                entry.2 = eff_fee_bps;
                            }
                            total_hashrate += current_hashrate;
                            *wallet_hashrate_ths_map.entry(clean_wallet.clone()).or_insert(0.0) +=
                                current_hashrate / 1e12;
                            WORKER_HASHRATE
                                .with_label_values(&[full_worker])
                                .set(current_hashrate / 1e12);
                            pipeline
                                .cmd("SET")
                                .arg(format!("worker:{}:hashrate", full_worker))
                                .arg(current_hashrate)
                                .ignore();
                            pipeline
                                .cmd("SET")
                                .arg(format!("worker:{}:blocks", full_worker))
                                .arg(state.blocks_found)
                                .ignore();
                            pipeline
                                .cmd("SET")
                                .arg(format!("worker:{}:shares", full_worker))
                                .arg(state.shares_contributed as u64)
                                .ignore();
                            pipeline
                                .cmd("SET")
                                .arg(format!("worker:{}:valid_shares", full_worker))
                                .arg(state.valid_share_count)
                                .ignore();
                            pipeline
                                .cmd("SET")
                                .arg(format!("worker:{}:rejected_shares", full_worker))
                                .arg(state.rejected_share_count)
                                .ignore();
                            pipeline
                                .cmd("SET")
                                .arg(format!("worker:{}:acceptance_pct", full_worker))
                                .arg(acceptance_pct)
                                .ignore();
                            pipeline
                                .cmd("SET")
                                .arg(format!("worker:{}:last_share_ts", full_worker))
                                .arg(state.last_share_ts)
                                .ignore();
                            pipeline
                                .cmd("SET")
                                .arg(format!("worker:{}:streak_started_ts", full_worker))
                                .arg(state.streak_started_ts)
                                .ignore();
                            pipeline
                                .cmd("SET")
                                .arg(format!("worker:{}:effective_fee_bps", full_worker))
                                .arg(eff_fee_bps)
                                .ignore();
                            pipeline
                                .cmd("SADD")
                                .arg("pool:workers")
                                .arg(full_worker.clone())
                                .ignore();

                            if can_calculate_yields && state.unflushed_difficulty > 0.0 {
                                let is_house_anchor =
                                    !corp_kas_clean.is_empty() && clean_wallet == corp_kas_clean;
                                let diff_e6 =
                                    (state.unflushed_difficulty * 1_000_000.0).round().max(0.0)
                                        as u128;
                                let gross_sompi = crate::agent::solvency::mul_div_floor_u128(
                                    diff_e6.saturating_mul(KASPA_DIFF_CONSTANT_U128),
                                    block_reward_sompi,
                                    net_diff_e6.saturating_mul(2),
                                )
                                .unwrap_or(0);
                                let share_fee_sompi = if is_house_anchor {
                                    0
                                } else {
                                    gross_sompi.saturating_mul(eff_fee_bps as u128) / 10_000
                                };
                                let miner_net_sompi = gross_sompi.saturating_sub(share_fee_sompi);

                                pending_micro_shares.push(PendingMicroShare {
                                    worker_id: full_worker.clone(),
                                    difficulty_weight: state.unflushed_difficulty,
                                    network_diff: net_diff,
                                    sompi_delta: miner_net_sompi.min(i64::MAX as u128) as i64,
                                    pool_fee_sompi: share_fee_sompi.min(i64::MAX as u128) as i64,
                                    block_daa_score: current_virtual_daa,
                                    is_settled: miner_net_sompi > 0,
                                });

                                if (miner_net_sompi > 0 || share_fee_sompi > 0)
                                    && !clean_wallet.is_empty()
                                {
                                    let prefixed = if wallet_address.starts_with("kaspa:") {
                                        wallet_address.to_string()
                                    } else {
                                        format!("kaspa:{}", clean_wallet)
                                    };
                                    let acc = accruals_by_wallet
                                        .entry(clean_wallet.clone())
                                        .or_insert_with(|| WalletAccrualDelta {
                                            prefixed_wallet: prefixed,
                                            miner_net_sompi: 0,
                                            pool_fee_sompi: 0,
                                            pool_fee_bps: eff_fee_bps,
                                        });
                                    acc.miner_net_sompi =
                                        acc.miner_net_sompi.saturating_add(miner_net_sompi);
                                    acc.pool_fee_sompi =
                                        acc.pool_fee_sompi.saturating_add(share_fee_sompi);
                                    acc.pool_fee_bps = eff_fee_bps.min(acc.pool_fee_bps);
                                }
                                state.unflushed_difficulty = 0.0;
                            }
                            if state.unflushed_blocks > 0 {
                                state.unflushed_blocks = 0;
                            }
                            db_worker_snapshots.push(WorkerDbSnapshot {
                                full_identity: full_worker.clone(),
                                wallet_address: wallet_address.to_string(),
                                worker_name: worker_name.clone(),
                                hashrate_ths: current_hashrate / 1e12,
                                valid_shares: state.valid_share_count as i64,
                                rejected_shares: state.rejected_share_count as i64,
                                acceptance_pct,
                                blocks_found: state.blocks_found as i64,
                                last_share_ts: state.last_share_ts as i64,
                                streak_started_ts: state.streak_started_ts as i64,
                                effective_fee_bps: eff_fee_bps,
                                status: "online".to_string(),
                            });
                            workers_array.push(json!({
                                "fullIdentity": full_worker,
                                "walletAddress": wallet_address,
                                "name": worker_name,
                                "trackingRate": current_hashrate,
                                "sharesContributed": state.shares_contributed,
                                "validShares": state.valid_share_count,
                                "rejectedShares": state.rejected_share_count,
                                "acceptancePct": acceptance_pct,
                                "lastShareTimestamp": state.last_share_ts,
                                "streakStartedTs": state.streak_started_ts,
                                "consecutiveWeeks": consecutive_weeks,
                                "effectiveFeeBps": eff_fee_bps,
                                "graceWindowSecsRemaining": grace_remaining_secs,
                                "maintenanceGraceShieldActive": maintenance_grace_shield_active,
                                "swapFeeFloorBps": MINER_PERK_SWAP_FEE_FLOOR_BPS,
                                "blocksFound": state.blocks_found,
                                "status": "online"
                            }));
                        }
                    }
                    for key in keys_to_remove {
                        worker_states.remove(&key);
                    }
                }

                for (clean_w, (streak_ms, weeks, eff_fee_bps, is_actively_online, grace_rem_secs)) in
                    &wallet_best_loyalty_map
                {
                    if clean_w.is_empty() {
                        continue;
                    }
                    let ttl_secs = (*grace_rem_secs).max(60);
                    let loyalty_payload = json!({
                        "wallet": format!("kaspa:{}", clean_w),
                        "activeMiner": true,
                        "isOnline": *is_actively_online,
                        "inGraceWindow": !*is_actively_online,
                        "maintenanceGraceShieldActive": maintenance_grace_shield_active,
                        "streakStartedTs": *streak_ms,
                        "consecutiveWeeks": *weeks,
                        "effectivePoolFeeBps": *eff_fee_bps,
                        "unlockedSwapFeeFloorBps": MINER_PERK_SWAP_FEE_FLOOR_BPS,
                        "graceWindowSecsRemaining": *grace_rem_secs,
                        "updatedAt": now_secs
                    });
                    pipeline
                        .cmd("SETEX")
                        .arg(format!("perennia:miner:loyalty:{}", clean_w))
                        .arg(ttl_secs)
                        .arg(loyalty_payload.to_string())
                        .ignore();
                }

                // Persist deterministic immature sompi accruals into stratum_mature_accruals
                // (promoted to unpaid_mature_sompi strictly on 1,000-DAA coinbase maturity)
                if !accruals_by_wallet.is_empty() {
                    let pool_acc = pg_pool.clone();
                    tokio::spawn(async move {
                        for (clean_w, delta) in accruals_by_wallet {
                            if let Err(e) = sqlx::query(
                                r#"
                                INSERT INTO stratum_mature_accruals (
                                    clean_wallet, wallet_address, immature_sompi,
                                    lifetime_pool_fee_sompi, pool_fee_bps, updated_at
                                ) VALUES ($1, $2, $3::NUMERIC(39, 0), $4::NUMERIC(39, 0), $5, CURRENT_TIMESTAMP)
                                ON CONFLICT (clean_wallet) DO UPDATE SET
                                    wallet_address = EXCLUDED.wallet_address,
                                    immature_sompi = stratum_mature_accruals.immature_sompi + EXCLUDED.immature_sompi,
                                    lifetime_pool_fee_sompi = stratum_mature_accruals.lifetime_pool_fee_sompi + EXCLUDED.lifetime_pool_fee_sompi,
                                    pool_fee_bps = EXCLUDED.pool_fee_bps,
                                    updated_at = CURRENT_TIMESTAMP
                                "#,
                            )
                            .bind(&clean_w)
                            .bind(&delta.prefixed_wallet)
                            .bind(delta.miner_net_sompi.to_string())
                            .bind(delta.pool_fee_sompi.to_string())
                            .bind(delta.pool_fee_bps as i32)
                            .execute(&pool_acc)
                            .await
                            {
                                tracing::error!("stratum_mature_accruals upsert failed: {}", e);
                            }
                        }
                    });
                }

                if tick_counter % 15 == 0 {
                    let global_point = json!({
                        "ts": now_secs,
                        "hashrateThs": total_hashrate / 1e12
                    });
                    pipeline
                        .cmd("RPUSH")
                        .arg("perennia:hashrate:history:global")
                        .arg(global_point.to_string())
                        .ignore();
                    pipeline
                        .cmd("LTRIM")
                        .arg("perennia:hashrate:history:global")
                        .arg(-2880)
                        .arg(-1)
                        .ignore();
                    for (w_clean, w_ths) in &wallet_hashrate_ths_map {
                        let w_point = json!({
                            "ts": now_secs,
                            "hashrateThs": *w_ths
                        });
                        let w_key = format!("perennia:hashrate:history:{}", w_clean);
                        pipeline
                            .cmd("RPUSH")
                            .arg(&w_key)
                            .arg(w_point.to_string())
                            .ignore();
                        pipeline.cmd("LTRIM").arg(&w_key).arg(-2880).arg(-1).ignore();
                    }
                }

                if !pending_micro_shares.is_empty() {
                    let batch = std::mem::take(&mut pending_micro_shares);
                    let mut w_ids = Vec::with_capacity(batch.len());
                    let mut diffs = Vec::with_capacity(batch.len());
                    let mut legacy_zeros = Vec::with_capacity(batch.len());
                    let mut ndiffs = Vec::with_capacity(batch.len());
                    let mut settled = Vec::with_capacity(batch.len());
                    let mut sompis = Vec::with_capacity(batch.len());
                    let mut fees = Vec::with_capacity(batch.len());
                    let mut daas = Vec::with_capacity(batch.len());
                    for item in batch {
                        w_ids.push(item.worker_id);
                        diffs.push(item.difficulty_weight);
                        legacy_zeros.push(0.0_f64);
                        ndiffs.push(item.network_diff);
                        settled.push(item.is_settled);
                        sompis.push(item.sompi_delta);
                        fees.push(item.pool_fee_sompi);
                        daas.push(item.block_daa_score);
                    }
                    let pool_ms = pg_pool.clone();
                    let prune = tick_counter % 300 == 0;
                    tokio::spawn(async move {
                        if let Err(e) = sqlx::query(
                            r#"
                            INSERT INTO micro_shares (
                                worker_id, difficulty_weight, kas_value_delta,
                                network_diff, is_settled, sompi_delta, pool_fee_sompi, block_daa_score
                            )
                            SELECT * FROM UNNEST(
                                $1::text[], $2::float8[], $3::float8[],
                                $4::float8[], $5::bool[], $6::bigint[], $7::bigint[], $8::bigint[]
                            )
                            "#,
                        )
                        .bind(&w_ids)
                        .bind(&diffs)
                        .bind(&legacy_zeros)
                        .bind(&ndiffs)
                        .bind(&settled)
                        .bind(&sompis)
                        .bind(&fees)
                        .bind(&daas)
                        .execute(&pool_ms)
                        .await
                        {
                            tracing::error!("micro_shares insert failed: {}", e);
                        }
                        if prune {
                            let _ = sqlx::query(
                                "DELETE FROM micro_shares WHERE recorded_at < CURRENT_TIMESTAMP - INTERVAL '24 hours'",
                            )
                            .execute(&pool_ms)
                            .await;
                        }
                    });
                }

                if tick_counter % 5 == 0 && !db_worker_snapshots.is_empty() {
                    let pool_bg = pg_pool.clone();
                    tokio::spawn(async move {
                        for snap in db_worker_snapshots {
                            let port_pub =
                                crate::stratum_tcp::resolve_worker_public_port(&snap.full_identity);
                            let dev_prof = match port_pub {
                                3331 => "GPU_TIER_1",
                                3333 => "INDUSTRIAL_ASIC_TIER_3",
                                _ => "HOME_ASIC_TIER_2",
                            };
                            let wn = snap.worker_name.to_lowercase();
                            let hw = if wn.contains("ks7") {
                                "IceRiver KS7 Lite"
                            } else if wn.contains("ultra") {
                                "IceRiver KS0 Ultra"
                            } else if wn.contains("pro") {
                                "IceRiver KS0 Pro"
                            } else if wn.contains("ks0") {
                                "IceRiver KS0"
                            } else {
                                "IceRiver KS"
                            };
                            let raw_hr = snap.hashrate_ths * 1e12;
                            if let Err(e) = sqlx::query(
                                "INSERT INTO worker_profiles (worker_id, worker_identity, wallet_address, device_profile, hardware_model, worker_name, hashrate_ths, current_hashrate, stratum_port, valid_shares, rejected_shares, acceptance_pct, blocks_found, last_share_ts, streak_started_ts, effective_fee_bps, status, updated_at, last_seen) VALUES ($1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) ON CONFLICT (worker_id) DO UPDATE SET worker_identity = EXCLUDED.worker_identity, wallet_address = EXCLUDED.wallet_address, device_profile = EXCLUDED.device_profile, hardware_model = EXCLUDED.hardware_model, worker_name = EXCLUDED.worker_name, hashrate_ths = EXCLUDED.hashrate_ths, current_hashrate = EXCLUDED.current_hashrate, stratum_port = EXCLUDED.stratum_port, valid_shares = EXCLUDED.valid_shares, rejected_shares = EXCLUDED.rejected_shares, acceptance_pct = EXCLUDED.acceptance_pct, blocks_found = EXCLUDED.blocks_found, last_share_ts = EXCLUDED.last_share_ts, streak_started_ts = EXCLUDED.streak_started_ts, effective_fee_bps = EXCLUDED.effective_fee_bps, status = EXCLUDED.status, updated_at = CURRENT_TIMESTAMP, last_seen = CASE WHEN EXCLUDED.status = 'online' THEN CURRENT_TIMESTAMP ELSE worker_profiles.last_seen END",
                            )
                            .bind(&snap.full_identity)
                            .bind(&snap.wallet_address)
                            .bind(dev_prof)
                            .bind(hw)
                            .bind(&snap.worker_name)
                            .bind(snap.hashrate_ths)
                            .bind(raw_hr)
                            .bind(port_pub)
                            .bind(snap.valid_shares)
                            .bind(snap.rejected_shares)
                            .bind(snap.acceptance_pct)
                            .bind(snap.blocks_found)
                            .bind(snap.last_share_ts)
                            .bind(snap.streak_started_ts)
                            .bind(snap.effective_fee_bps as i32)
                            .bind(&snap.status)
                            .execute(&pool_bg)
                            .await
                            {
                                tracing::error!("worker_profiles upsert failed: {}", e);
                            }
                        }
                    });
                }

                let total_blocks_sompi =
                    cached_l1_blocks_won_sompi.saturating_add(cached_immature_blocks_sompi);
                let earned_pool_fee_sompi =
                    total_blocks_sompi.saturating_mul(pool_fee_bps as u128) / 10_000;
                let miner_blocks_sompi = total_blocks_sompi.saturating_sub(earned_pool_fee_sompi);

                let solvency_telemetry = json!({
                    "totalBlocksWonCount": cached_total_blocks_count,
                    "l1BlocksWonSompi": cached_l1_blocks_won_sompi.to_string(),
                    "immatureBlocksSompi": cached_immature_blocks_sompi.to_string(),
                    "totalBlocksRewardSompi": total_blocks_sompi.to_string(),
                    "earnedPoolFeeSompi": earned_pool_fee_sompi.to_string(),
                    "minerBlocksNetSompi": miner_blocks_sompi.to_string(),
                    "unpaidMatureSompi": cached_unpaid_mature_sompi.to_string(),
                    "immatureAccrualsSompi": cached_immature_accruals_sompi.to_string(),
                    "stage1FlushFloorSompi": STAGE1_FLUSH_FLOOR_SOMPI.to_string(),
                    "poolFeeBps": pool_fee_bps,
                    "coinbaseMaturityDaa": coinbase_maturity_daa,
                    "maintenanceGraceShieldActive": maintenance_grace_shield_active,
                    "updatedAt": now_secs
                });
                pipeline
                    .cmd("SET")
                    .arg("perennia:pool:fpps_solvency")
                    .arg(solvency_telemetry.to_string())
                    .ignore();
                pipeline
                    .cmd("SET")
                    .arg("pool:hashrate")
                    .arg(total_hashrate)
                    .ignore();
                let telemetry_payload = json!({
                    "totalHashrate": total_hashrate,
                    "networkDifficulty": net_diff,
                    "blockRewardSompi": block_reward_sompi.to_string(),
                    "virtualDaaScore": current_virtual_daa,
                    "workers": workers_array,
                    "epoch": epoch_telemetry_val,
                    "fppsSolvency": solvency_telemetry
                });
                pipeline
                    .cmd("SET")
                    .arg("perennia:telemetry")
                    .arg(telemetry_payload.to_string())
                    .ignore();
                pipeline
                    .cmd("XADD")
                    .arg("telemetry:stream")
                    .arg("MAXLEN")
                    .arg("~")
                    .arg(100)
                    .arg("*")
                    .arg("payload")
                    .arg(telemetry_payload.to_string())
                    .ignore();
                pipeline
                    .cmd("PUBLISH")
                    .arg("telemetry:updates")
                    .arg(telemetry_payload.to_string())
                    .ignore();

                if let Err(e) = pipeline.query_async::<_, ()>(&mut redis_conn).await {
                    tracing::error!("🚨 CRITICAL REDIS TELEMETRY FAILURE: {}", e);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    if let Ok(new_conn) = redis_client.get_multiplexed_async_connection().await {
                        redis_conn = new_conn;
                    }
                }
            }
        }
    }
}
