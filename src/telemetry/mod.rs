use prometheus::{GaugeVec, IntCounterVec, Opts, Registry, TextEncoder, Encoder};
use lazy_static::lazy_static;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use std::collections::{HashMap, HashSet, VecDeque};
use serde_json::{json, Value};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::env;
use sqlx::Row;

const KASPA_DIFF_CONSTANT: f64 = 4_294_967_296.0;
const DEFAULT_FPPS_MAX_HOUSE_FLOAT_KAS: f64 = 50.0;
const DEFAULT_COINBASE_MATURITY_DAA: i64 = 1_000;
const LAYOUT_CACHE_TTL: Duration = Duration::from_secs(5);

pub const BASE_POOL_FEE_RATE: f64 = 0.01;
pub const MIN_POOL_FEE_RATE: f64 = 0.005;
pub const WEEKLY_FEE_DECAY_RATE: f64 = 0.0005;
pub const SECONDS_PER_WEEK: u64 = 604_800;
pub const DISCONNECT_GRACE_WINDOW_SECS: u64 = 7_200;
pub const DISCONNECT_GRACE_WINDOW_MS: u64 = 7_200_000;
pub const MAINTENANCE_SHIELD_GRACE_WINDOW_SECS: u64 = 86_400;
pub const MAINTENANCE_SHIELD_GRACE_WINDOW_MS: u64 = 86_400_000;
pub const MINER_PERK_SWAP_FEE_FLOOR_RATE: f64 = 0.001;

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref WORKER_HASHRATE: GaugeVec = GaugeVec::new(
        Opts::new("ks_worker_hashrate", "Strictly verified unsimulated hashrate per worker in TH/s"),
        &["worker"]
    ).expect("Metric setup failed");
    pub static ref WORKER_SHARES: IntCounterVec = IntCounterVec::new(
        Opts::new("ks_worker_shares", "Cryptographically validated shares per worker"),
        &["worker", "type"]
    ).expect("Metric setup failed");
}

pub fn init_telemetry() {
    REGISTRY.register(Box::new(WORKER_HASHRATE.clone())).unwrap();
    REGISTRY.register(Box::new(WORKER_SHARES.clone())).unwrap();
}

pub fn compute_miner_loyalty_fee_rate(
    streak_started_ms: u64,
    now_ms: u64,
    configured_base_fee_rate: f64,
) -> (u64, f64) {
    let base_rate = configured_base_fee_rate.clamp(MIN_POOL_FEE_RATE, 0.05);
    if streak_started_ms == 0 || now_ms <= streak_started_ms {
        return (0, base_rate);
    }
    let elapsed_secs = now_ms.saturating_sub(streak_started_ms) / 1000;
    let consecutive_weeks = elapsed_secs / SECONDS_PER_WEEK;
    let discount = (consecutive_weeks as f64) * WEEKLY_FEE_DECAY_RATE;
    let effective_rate = (base_rate - discount).max(MIN_POOL_FEE_RATE);
    let rounded_rate = (effective_rate * 100_000.0).round() / 100_000.0;
    (consecutive_weeks, rounded_rate)
}

pub async fn start_prometheus_exporter(_bind_addr: String) {
    let addr = "0.0.0.0:8081";
    let listener = TcpListener::bind(addr).await.expect("Failed to bind Prometheus port");
    tracing::info!("📊 Zero-Simulation Telemetry exporter natively active on http://{}/metrics", addr);
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
    effective_fee_rate: f64,
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
    effective_fee_rate: f64,
    status: String,
}

struct CachedSectorLayout {
    layout_state: Value,
    fetched_at: Instant,
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
    tracing::info!("🏦 Institutional Accounting, Miner Loyalty Decay (1.0% -> 0.5%, 2h Grace + Maintenance Shield) & Elastic Solvency-Gated FPPS Engine Booted...");
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
            tracing::error!("❌ CRITICAL: Failed to connect to Postgres! Yield splitting will fail. {}", e);
            return;
        }
    };
    let pool_fee_rate: f64 = env::var("POOL_FEE_RATE")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|&v| v >= MIN_POOL_FEE_RATE && v < 1.0)
        .unwrap_or(BASE_POOL_FEE_RATE);
    let max_house_float_kas: f64 = env::var("FPPS_MAX_FLOAT_KAS")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|&v| v > 0.0)
        .unwrap_or(DEFAULT_FPPS_MAX_HOUSE_FLOAT_KAS);
    let coinbase_maturity_daa: i64 = env::var("COINBASE_MATURITY_DAA")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|&v| v >= 100)
        .unwrap_or(DEFAULT_COINBASE_MATURITY_DAA);
    let corp_kas_clean = crate::chronos::resolve_master_treasury_address();
    let mut flush_interval = tokio::time::interval(Duration::from_millis(1000));
    let mut worker_states: HashMap<String, WorkerState> = HashMap::new();
    let mut sector_layout_cache: HashMap<String, CachedSectorLayout> = HashMap::new();
    let mut maintenance_grace_shield_active = false;
    let mut blacklisted_wallets_cache: HashSet<String> = HashSet::new();
    let mut blacklisted_workers_cache: HashSet<String> = HashSet::new();

    let boot_now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    if let Ok(existing_workers) = sqlx::query(
        r#"
        SELECT worker_identity, valid_shares, rejected_shares, blocks_found,
               last_share_ts, COALESCE(streak_started_ts, 0) AS streak_started_ts,
               COALESCE(effective_fee_rate, 0.01) AS effective_fee_rate
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
                let (_, eff_fee) =
                    compute_miner_loyalty_fee_rate(streak_ms, boot_now_ms, pool_fee_rate);
                let valid_sh = r.try_get::<i64, _>("valid_shares").unwrap_or(0).max(0) as u64;
                let rej_sh = r.try_get::<i64, _>("rejected_shares").unwrap_or(0).max(0) as u64;
                let blks = r.try_get::<i64, _>("blocks_found").unwrap_or(0).max(0) as u64;
                worker_states.insert(
                    id,
                    WorkerState {
                        last_share_ts: last_ms,
                        streak_started_ts: streak_ms,
                        effective_fee_rate: eff_fee,
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

    let mut cached_l1_blocks_won_kas: f64 = 0.0;
    let mut cached_immature_blocks_kas: f64 = 0.0;
    let mut cached_total_blocks_count: i64 = 0;
    let mut tick_counter: u64 = 0;

    loop {
        tokio::select! {
            Some((full_worker_name, difficulty, is_network_block)) = valid_share_rx.recv() => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
                let active_grace_ms = if maintenance_grace_shield_active {
                    MAINTENANCE_SHIELD_GRACE_WINDOW_MS
                } else {
                    DISCONNECT_GRACE_WINDOW_MS
                };
                let state = worker_states.entry(full_worker_name.clone()).or_insert_with(|| WorkerState {
                    last_share_ts: now,
                    streak_started_ts: now,
                    effective_fee_rate: pool_fee_rate,
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
                    let (_, eff_rate) = compute_miner_loyalty_fee_rate(
                        state.streak_started_ts,
                        now,
                        pool_fee_rate,
                    );
                    state.effective_fee_rate = eff_rate;
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
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
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
                    .filter(|&v| v > 0.0)
                    .unwrap_or(0.0);
                let reward_str: Option<String> = redis::cmd("GET")
                    .arg("pool:block_reward")
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(None);
                let block_reward = reward_str
                    .and_then(|s| s.parse::<f64>().ok())
                    .filter(|&v| v > 0.0)
                    .unwrap_or(0.0);
                let virtual_daa_str: Option<String> = redis::cmd("GET")
                    .arg("pool:virtual_daa_score")
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(None);
                let current_virtual_daa = virtual_daa_str
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);

                if tick_counter % 5 == 1 {
                    if let Ok(row) = sqlx::query(
                        r#"
                        SELECT
                            COUNT(*)::BIGINT AS total_blocks_count,
                            COALESCE(SUM(CASE
                                WHEN (
                                    ($1 > $2 AND COALESCE(daa_score, 0) > 0 AND ($1 - COALESCE(daa_score, 0)) >= $2)
                                    OR (COALESCE(daa_score, 0) = 0 AND discovered_at <= CURRENT_TIMESTAMP - INTERVAL '120 seconds')
                                    OR ($1 <= $2 AND discovered_at <= CURRENT_TIMESTAMP - INTERVAL '120 seconds')
                                ) THEN reward_kas
                                ELSE 0.0
                            END), 0.0) AS matured_blocks_kas,
                            COALESCE(SUM(CASE
                                WHEN NOT (
                                    ($1 > $2 AND COALESCE(daa_score, 0) > 0 AND ($1 - COALESCE(daa_score, 0)) >= $2)
                                    OR (COALESCE(daa_score, 0) = 0 AND discovered_at <= CURRENT_TIMESTAMP - INTERVAL '120 seconds')
                                    OR ($1 <= $2 AND discovered_at <= CURRENT_TIMESTAMP - INTERVAL '120 seconds')
                                ) THEN reward_kas
                                ELSE 0.0
                            END), 0.0) AS immature_blocks_kas
                        FROM network_blocks
                        WHERE COALESCE(is_orphaned, false) = false
                        "#
                    )
                    .bind(current_virtual_daa)
                    .bind(coinbase_maturity_daa)
                    .fetch_one(&pg_pool)
                    .await
                    {
                        cached_total_blocks_count = row.try_get::<i64, _>("total_blocks_count").unwrap_or(0);
                        cached_l1_blocks_won_kas = row.try_get::<f64, _>("matured_blocks_kas").unwrap_or(0.0).max(0.0);
                        cached_immature_blocks_kas = row.try_get::<f64, _>("immature_blocks_kas").unwrap_or(0.0).max(0.0);
                    }
                }
                if tick_counter % 60 == 0 {
                    sector_layout_cache.retain(|_, entry| entry.fetched_at.elapsed() < Duration::from_secs(60));
                }
                let ext_streamed_str: Option<String> = redis::cmd("GET")
                    .arg("perennia:pool:external_streamed_kas")
                    .query_async(&mut redis_conn)
                    .await
                    .unwrap_or(None);
                let mut total_external_streamed_kas = ext_streamed_str
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0)
                    .max(0.0);
                let total_solvency_ceiling_kas = cached_l1_blocks_won_kas + max_house_float_kas;
                let mut available_headroom_kas = (total_solvency_ceiling_kas - total_external_streamed_kas).max(0.0);
                let soft_knee_kas = (max_house_float_kas * 0.50).max(1.0);
                let elastic_streaming_factor = if available_headroom_kas >= soft_knee_kas {
                    1.0
                } else {
                    (available_headroom_kas / soft_knee_kas).clamp(0.0, 1.0)
                };
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
                    obj.insert("anchorLabel".to_string(), json!("22:00 UTC Global Settlement"));
                    obj.insert("currentEpochBellTs".to_string(), json!(current_epoch_bell_ts));
                    obj.insert("nextEpochBellTs".to_string(), json!(next_epoch_bell_ts));
                    obj.insert("secondsRemaining".to_string(), json!(seconds_remaining));
                }
                let can_calculate_yields = net_diff > 0.0 && block_reward > 0.0;
                let mut pipeline = redis::pipe();
                let mut total_hashrate = 0.0;
                let mut workers_array = Vec::new();
                let mut keys_to_remove = Vec::new();
                let mut yield_updates_to_publish = Vec::new();
                let mut streamed_kas_by_wallet: HashMap<String, f64> = HashMap::new();
                let mut wallet_hashrate_ths_map: HashMap<String, f64> = HashMap::new();
                let mut wallet_best_loyalty_map: HashMap<String, (u64, u64, f64, bool, u64)> = HashMap::new();
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
                            let work = diff * KASPA_DIFF_CONSTANT;
                            work_300s += work;
                            if ts >= cutoff_60s {
                                work_60s += work;
                            }
                            if ts < oldest_ts {
                                oldest_ts = ts;
                            }
                        }
                        let mut elapsed_total = ((now - oldest_ts) as f64) / 1000.0;
                        if elapsed_total < 1.0 {
                            elapsed_total = 1.0;
                        }
                        let mut elapsed_60s = elapsed_total.min(60.0);
                        if elapsed_60s < 1.0 {
                            elapsed_60s = 1.0;
                        }
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
                            ((state.valid_share_count as f64 / total_attempts as f64) * 100.0).clamp(0.0, 100.0)
                        } else {
                            100.0
                        };
                        let parts: Vec<&str> = full_worker.split('.').collect();
                        let wallet_address = if !parts.is_empty() { parts[0] } else { full_worker.as_str() };
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
                            // 2-hour disconnect grace window expired -> reset streak & evict
                            keys_to_remove.push(full_worker.clone());
                            state.streak_started_ts = 0;
                            state.effective_fee_rate = pool_fee_rate;
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
                                effective_fee_rate: pool_fee_rate,
                                status: "offline".to_string(),
                            });
                        } else if !is_online && within_grace_window {
                            let (consecutive_weeks, eff_fee_rate) = compute_miner_loyalty_fee_rate(
                                state.streak_started_ts,
                                now,
                                pool_fee_rate,
                            );
                            state.effective_fee_rate = eff_fee_rate;
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
                                .arg(format!("worker:{}:effective_fee_rate", full_worker))
                                .arg(eff_fee_rate)
                                .ignore();
                            pipeline
                                .cmd("SET")
                                .arg(format!("worker:{}:streak_started_ts", full_worker))
                                .arg(state.streak_started_ts)
                                .ignore();
                            let entry = wallet_best_loyalty_map.entry(clean_wallet.clone()).or_insert((
                                state.streak_started_ts,
                                consecutive_weeks,
                                eff_fee_rate,
                                false,
                                grace_remaining_secs,
                            ));
                            if eff_fee_rate < entry.2 || (state.streak_started_ts > 0 && state.streak_started_ts < entry.0) {
                                *entry = (
                                    state.streak_started_ts,
                                    consecutive_weeks,
                                    eff_fee_rate,
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
                                effective_fee_rate: eff_fee_rate,
                                status: "grace_period".to_string(),
                            });
                        } else {
                            if state.streak_started_ts == 0 {
                                state.streak_started_ts = now;
                            }
                            let (consecutive_weeks, eff_fee_rate) = compute_miner_loyalty_fee_rate(
                                state.streak_started_ts,
                                now,
                                pool_fee_rate,
                            );
                            state.effective_fee_rate = eff_fee_rate;
                            let grace_remaining_secs = active_grace_window_secs;
                            let entry = wallet_best_loyalty_map.entry(clean_wallet.clone()).or_insert((
                                state.streak_started_ts,
                                consecutive_weeks,
                                eff_fee_rate,
                                true,
                                grace_remaining_secs,
                            ));
                            entry.3 = true;
                            entry.4 = active_grace_window_secs;
                            if eff_fee_rate <= entry.2 {
                                entry.0 = state.streak_started_ts;
                                entry.1 = consecutive_weeks;
                                entry.2 = eff_fee_rate;
                            }
                            total_hashrate += current_hashrate;
                            *wallet_hashrate_ths_map.entry(clean_wallet.clone()).or_insert(0.0) += current_hashrate / 1e12;
                            WORKER_HASHRATE.with_label_values(&[full_worker]).set(current_hashrate / 1e12);
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
                                .arg(format!("worker:{}:effective_fee_rate", full_worker))
                                .arg(eff_fee_rate)
                                .ignore();
                            pipeline
                                .cmd("SADD")
                                .arg("pool:workers")
                                .arg(full_worker.clone())
                                .ignore();
                            if can_calculate_yields && state.unflushed_difficulty > 0.0 {
                                let is_house_anchor = !corp_kas_clean.is_empty() && clean_wallet == corp_kas_clean;
                                let work_hashes = state.unflushed_difficulty * KASPA_DIFF_CONSTANT;
                                let expected_block_hashes = net_diff * 2.0;
                                let gross_kas_yield = (work_hashes * block_reward) / expected_block_hashes;
                                let pool_fee_kas = if is_house_anchor {
                                    0.0
                                } else {
                                    gross_kas_yield * eff_fee_rate
                                };
                                let theoretical_net_kas_yield = (gross_kas_yield - pool_fee_kas).max(0.0);
                                let streamed_kas_now = if is_house_anchor {
                                    theoretical_net_kas_yield
                                } else {
                                    let deferred_key = format!("worker:{}:deferred_yield_kas", full_worker);
                                    let deferred_str: Option<String> = redis::cmd("GET")
                                        .arg(&deferred_key)
                                        .query_async(&mut redis_conn)
                                        .await
                                        .unwrap_or(None);
                                    let existing_deferred = deferred_str
                                        .and_then(|s| s.parse::<f64>().ok())
                                        .unwrap_or(0.0)
                                        .max(0.0);
                                    let deferred_release = if elastic_streaming_factor >= 0.99 && existing_deferred > 0.0 {
                                        (existing_deferred * 0.10).min(available_headroom_kas * 0.25)
                                    } else {
                                        0.0
                                    };
                                    let target_stream = (theoretical_net_kas_yield * elastic_streaming_factor) + deferred_release;
                                    let actual_stream = target_stream.min(available_headroom_kas * 0.50).max(0.0);
                                    let newly_deferred = (theoretical_net_kas_yield - (actual_stream - deferred_release)).max(0.0);
                                    let next_deferred = (existing_deferred - deferred_release + newly_deferred).max(0.0);
                                    pipeline.cmd("SET").arg(&deferred_key).arg(next_deferred).ignore();
                                    if actual_stream > 0.0 {
                                        available_headroom_kas = (available_headroom_kas - actual_stream).max(0.0);
                                        total_external_streamed_kas += actual_stream;
                                        pipeline
                                            .cmd("INCRBYFLOAT")
                                            .arg("perennia:pool:external_streamed_kas")
                                            .arg(actual_stream)
                                            .ignore();
                                    }
                                    actual_stream
                                };
                                if streamed_kas_now > 0.0 {
                                    pipeline
                                        .cmd("INCRBYFLOAT")
                                        .arg(format!("worker:{}:unpaid_yield", full_worker))
                                        .arg(streamed_kas_now)
                                        .ignore();
                                    *streamed_kas_by_wallet.entry(clean_wallet).or_insert(0.0) += streamed_kas_now;
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
                                effective_fee_rate: eff_fee_rate,
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
                                "effectiveFeeRate": eff_fee_rate,
                                "effectiveFeePct": (eff_fee_rate * 10000.0).round() / 100.0,
                                "graceWindowSecsRemaining": grace_remaining_secs,
                                "maintenanceGraceShieldActive": maintenance_grace_shield_active,
                                "swapFeeFloorPct": 0.10,
                                "blocksFound": state.blocks_found,
                                "status": "online"
                            }));
                        }
                    }
                    for key in keys_to_remove {
                        worker_states.remove(&key);
                    }
                }
                for (clean_w, (streak_ms, weeks, eff_fee_rate, is_actively_online, grace_rem_secs)) in &wallet_best_loyalty_map {
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
                        "effectivePoolFeeRate": *eff_fee_rate,
                        "effectivePoolFeePct": (*eff_fee_rate * 10000.0).round() / 100.0,
                        "unlockedSwapFeeFloorRate": MINER_PERK_SWAP_FEE_FLOOR_RATE,
                        "unlockedSwapFeeFloorPct": 0.10,
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
                for (clean_wallet, wallet_streamed_kas) in streamed_kas_by_wallet {
                    if wallet_streamed_kas <= 0.0 {
                        continue;
                    }
                    let prefixed_wallet = format!("kaspa:{}", clean_wallet);
                    let needs_db_refresh = match sector_layout_cache.get(&clean_wallet) {
                        Some(cached) => cached.fetched_at.elapsed() >= LAYOUT_CACHE_TTL,
                        None => true,
                    };
                    if needs_db_refresh {
                        if let Ok(Some(row)) = sqlx::query(
                            "SELECT layout_state FROM user_command_centers WHERE wallet_address = $1 OR wallet_address = $2 LIMIT 1"
                        )
                        .bind(&prefixed_wallet)
                        .bind(&clean_wallet)
                        .fetch_optional(&pg_pool)
                        .await
                        {
                            if let Ok(layout_state) = row.try_get::<Value, _>("layout_state") {
                                sector_layout_cache.insert(
                                    clean_wallet.clone(),
                                    CachedSectorLayout {
                                        layout_state,
                                        fetched_at: Instant::now(),
                                    },
                                );
                            }
                        }
                    }
                    let mut allocated_pct_sum = 0.0_f64;
                    if let Some(cached) = sector_layout_cache.get_mut(&clean_wallet) {
                        if let Some(sectors_array) = cached
                            .layout_state
                            .get_mut("sectors")
                            .and_then(|s| s.as_array_mut())
                        {
                            for sector in sectors_array.iter_mut() {
                                if let Some(pct) = sector.get("allocationPercentage").and_then(|v| v.as_f64()) {
                                    let clamped_pct = pct.clamp(0.0, 100.0);
                                    allocated_pct_sum += clamped_pct;
                                    let projected_micro_yield = wallet_streamed_kas * (clamped_pct / 100.0);
                                    let current_pending = sector.get("pendingKaspa").and_then(|v| v.as_f64()).unwrap_or(0.0);
                                    sector["pendingKaspa"] = json!(current_pending + projected_micro_yield);
                                }
                            }
                            if let Some(sectors_val) = cached.layout_state.get("sectors") {
                                yield_updates_to_publish.push(json!({
                                    "wallet": clean_wallet,
                                    "yield_update": true,
                                    "sectors": sectors_val
                                }));
                            }
                        }
                        let layout_to_save = cached.layout_state.clone();
                        let pool_layout = pg_pool.clone();
                        let pref_w = prefixed_wallet.clone();
                        tokio::spawn(async move {
                            let _ = sqlx::query(
                                "UPDATE user_command_centers SET layout_state = $2, last_updated = CURRENT_TIMESTAMP WHERE wallet_address = $1"
                            )
                            .bind(&pref_w)
                            .bind(&layout_to_save)
                            .execute(&pool_layout)
                            .await;
                        });
                    }
                    let unallocated_ratio = ((100.0 - allocated_pct_sum).max(0.0) / 100.0).clamp(0.0, 1.0);
                    let unassigned_kas_delta = wallet_streamed_kas * unallocated_ratio;
                    if unassigned_kas_delta > 0.0 {
                        let _ = crate::chronos::upsert_signed_yield_reservoir_kas(
                            &pg_pool,
                            &prefixed_wallet,
                            unassigned_kas_delta,
                            unassigned_kas_delta,
                            unassigned_kas_delta,
                        )
                        .await;
                        pipeline
                            .cmd("HINCRBYFLOAT")
                            .arg(format!("dev:sor:treasury:balances:{}", clean_wallet))
                            .arg("Unassigned KAS")
                            .arg(unassigned_kas_delta)
                            .ignore();
                    }
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
                        pipeline.cmd("RPUSH").arg(&w_key).arg(w_point.to_string()).ignore();
                        pipeline.cmd("LTRIM").arg(&w_key).arg(-2880).arg(-1).ignore();
                    }
                }
                if tick_counter % 30 == 0 && !db_worker_snapshots.is_empty() {
                    let pool_bg = pg_pool.clone();
                    tokio::spawn(async move {
                        for snap in db_worker_snapshots {
                            let _ = sqlx::query(
                                r#"
                                INSERT INTO worker_profiles
                                (worker_identity, wallet_address, worker_name, hashrate_ths, valid_shares, rejected_shares, acceptance_pct, blocks_found, last_share_ts, streak_started_ts, effective_fee_rate, status, updated_at)
                                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, CURRENT_TIMESTAMP)
                                ON CONFLICT (worker_identity) DO UPDATE SET
                                    wallet_address = EXCLUDED.wallet_address,
                                    worker_name = EXCLUDED.worker_name,
                                    hashrate_ths = EXCLUDED.hashrate_ths,
                                    valid_shares = EXCLUDED.valid_shares,
                                    rejected_shares = EXCLUDED.rejected_shares,
                                    acceptance_pct = EXCLUDED.acceptance_pct,
                                    blocks_found = EXCLUDED.blocks_found,
                                    last_share_ts = EXCLUDED.last_share_ts,
                                    streak_started_ts = EXCLUDED.streak_started_ts,
                                    effective_fee_rate = EXCLUDED.effective_fee_rate,
                                    status = EXCLUDED.status,
                                    updated_at = CURRENT_TIMESTAMP
                                "#
                            )
                            .bind(&snap.full_identity)
                            .bind(&snap.wallet_address)
                            .bind(&snap.worker_name)
                            .bind(snap.hashrate_ths)
                            .bind(snap.valid_shares)
                            .bind(snap.rejected_shares)
                            .bind(snap.acceptance_pct)
                            .bind(snap.blocks_found)
                            .bind(snap.last_share_ts)
                            .bind(snap.streak_started_ts)
                            .bind(snap.effective_fee_rate)
                            .bind(&snap.status)
                            .execute(&pool_bg)
                            .await;
                        }
                    });
                }
                let total_blocks_kas = cached_l1_blocks_won_kas + cached_immature_blocks_kas;
                let earned_pool_fee_kas = total_blocks_kas * pool_fee_rate;
                let custodial_miner_blocks_kas = total_blocks_kas * (1.0 - pool_fee_rate);
                pipeline
                    .cmd("SET")
                    .arg("perennia:fees:batch_accumulated:KAS")
                    .arg(earned_pool_fee_kas)
                    .ignore();
                let solvency_telemetry = json!({
                    "maxHouseFloatKas": max_house_float_kas,
                    "totalBlocksWonCount": cached_total_blocks_count,
                    "l1BlocksWonKas": cached_l1_blocks_won_kas,
                    "immatureBlocksKas": cached_immature_blocks_kas,
                    "totalBlocksRewardKas": total_blocks_kas,
                    "earnedPoolFeeKas": earned_pool_fee_kas,
                    "custodialMinerObligationKas": custodial_miner_blocks_kas,
                    "coinbaseMaturityDaa": coinbase_maturity_daa,
                    "solvencyCeilingKas": total_solvency_ceiling_kas,
                    "externalStreamedKas": total_external_streamed_kas,
                    "availableHeadroomKas": available_headroom_kas,
                    "elasticStreamingFactor": elastic_streaming_factor,
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
                    "blockRewardKas": block_reward,
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
                for update in yield_updates_to_publish {
                    pipeline
                        .cmd("PUBLISH")
                        .arg("telemetry:updates")
                        .arg(update.to_string())
                        .ignore();
                }
                if let Err(e) = pipeline.query_async::<_, ()>(&mut redis_conn).await {
                    tracing::error!("🚨 CRITICAL LEDGER FAILURE: {}", e);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    if let Ok(new_conn) = redis_client.get_multiplexed_async_connection().await {
                        redis_conn = new_conn;
                    }
                }
            }
        }
    }
}