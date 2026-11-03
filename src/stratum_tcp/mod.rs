use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::{FramedRead, LinesCodec, LinesCodecError};
use tokio_stream::StreamExt;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, Duration};
use crate::config::StratumConfig;
use crate::job_manager::{JobManager, PendingBlockSubmission, StratumJob, difficulty_from_bits};
use std::net::{Ipv4Addr, Ipv6Addr};
use lazy_static::lazy_static;
use dashmap::{DashMap, DashSet};
use sqlx::PgPool;

pub const MAX_CONSECUTIVE_STRIKES: u32 = 10;
pub const BAN_DURATION_SECS: u64 = 600;
const SOCKET_WINDOW_SECS: u64 = 10;
const MAX_MESSAGES_PER_WINDOW: u32 = 250;
const VARDIFF_GRACE_WINDOW_SECS: u64 = 15;
const ASIC_WARMUP_GRACE_SECS: u64 = 180;
const HAPROXY_HEALTHCHECK_SENTINEL: &str = "haproxy-healthcheck";

lazy_static! {
    pub static ref BANNED_IPS: DashMap<String, Instant> = DashMap::new();
    pub static ref STRIKE_COUNTERS: DashMap<String, u32> = DashMap::new();
    pub static ref ACTIVE_EXTRANONCES: DashSet<u16> = DashSet::new();
}

static WORKER_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

struct ExtranonceGuard {
    slot: u16,
}

impl ExtranonceGuard {
    fn allocate() -> anyhow::Result<Self> {
        for _ in 0..u16::MAX {
            let raw = WORKER_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
            let candidate = ((raw % (u16::MAX as u64)) as u16).max(1);
            if ACTIVE_EXTRANONCES.insert(candidate) {
                return Ok(Self { slot: candidate });
            }
        }
        anyhow::bail!("All 65,535 16-bit extranonce1 slots are currently in use")
    }

    fn to_hex(&self) -> String {
        format!("{:04x}", self.slot)
    }
}

impl Drop for ExtranonceGuard {
    fn drop(&mut self) {
        ACTIVE_EXTRANONCES.remove(&self.slot);
    }
}

#[derive(Deserialize, Debug)]
pub struct RpcRequest {
    pub id: Option<serde_json::Value>,
    pub method: Option<String>,
    pub params: Option<Vec<serde_json::Value>>,
}

fn clamp_to_power_of_2(diff: f64) -> u64 {
    if diff <= 1.0 {
        return 1;
    }
    let next_pow = diff.log2().round() as u32;
    2u64.pow(next_pow)
}

fn is_valid_kaspa_wallet(clean_wallet: &str) -> bool {
    if clean_wallet.len() < 55 || clean_wallet.len() > 75 {
        return false;
    }
    const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    clean_wallet.chars().all(|c| CHARSET.contains(c))
}

fn is_exempt_local_or_lan_ip(ip: &str) -> bool {
    let clean = ip.trim().to_lowercase();
    clean == "127.0.0.1"
        || clean == "::1"
        || clean == "localhost"
        || clean == HAPROXY_HEALTHCHECK_SENTINEL
        || clean.starts_with("127.")
        || clean.starts_with("192.168.")
        || clean.starts_with("10.")
        || clean.starts_with("172.16.")
        || clean.starts_with("172.17.")
        || clean.starts_with("172.18.")
        || clean.starts_with("172.19.")
        || clean.starts_with("172.2")
        || clean.starts_with("172.30.")
        || clean.starts_with("172.31.")
        || clean.starts_with("::ffff:127.")
        || clean.starts_with("::ffff:192.168.")
        || clean.starts_with("::ffff:10.")
}

fn is_benign_disconnect_io_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::TimedOut
    )
}

fn record_socket_strike(peer_ip: &str, worker_identity: &str, reason: &str) -> (u32, bool) {
    let is_local_exempt = is_exempt_local_or_lan_ip(peer_ip);
    let current_ip_strikes = if is_local_exempt {
        0
    } else {
        let mut ip_entry = STRIKE_COUNTERS.entry(peer_ip.to_string()).or_insert(0);
        *ip_entry = ip_entry.saturating_add(1);
        *ip_entry
    };

    let mut worker_strikes = 0u32;
    if !worker_identity.is_empty() {
        let worker_key = format!("worker:{}", worker_identity);
        let mut w_entry = STRIKE_COUNTERS.entry(worker_key).or_insert(0);
        *w_entry = w_entry.saturating_add(1);
        worker_strikes = *w_entry;
    }

    let effective_strikes = current_ip_strikes.max(worker_strikes);
    tracing::warn!(
        "⚠️ [STRATUM SHIELD STRIKE {}/{}] IP: {} | Worker: {} | Reason: {}",
        effective_strikes,
        MAX_CONSECUTIVE_STRIKES,
        peer_ip,
        if worker_identity.is_empty() { "unauthenticated" } else { worker_identity },
        reason
    );

    if effective_strikes >= MAX_CONSECUTIVE_STRIKES {
        STRIKE_COUNTERS.remove(peer_ip);
        if !worker_identity.is_empty() {
            STRIKE_COUNTERS.remove(&format!("worker:{}", worker_identity));
        }
        if is_local_exempt {
            tracing::warn!(
                "🛡️ [STRATUM SHIELD] Worker {} on local/LAN endpoint {} hit {} strikes ({}). Resetting worker connection without banning local proxy IP.",
                if worker_identity.is_empty() { "unauthenticated" } else { worker_identity },
                peer_ip,
                effective_strikes,
                reason
            );
            return (effective_strikes, true);
        }
        BANNED_IPS.insert(peer_ip.to_string(), Instant::now());
        tracing::error!(
            "🔨 [10-STRIKE BAN HAMMER] IP {} (Worker: {}) banned in memory for {}s ({}). Zero DB queries executed.",
            peer_ip,
            if worker_identity.is_empty() { "unauthenticated" } else { worker_identity },
            BAN_DURATION_SECS,
            reason
        );
        return (effective_strikes, true);
    }
    (effective_strikes, false)
}

fn reset_socket_strikes(peer_ip: &str, worker_identity: &str) {
    STRIKE_COUNTERS.remove(peer_ip);
    if !worker_identity.is_empty() {
        STRIKE_COUNTERS.remove(&format!("worker:{}", worker_identity));
    }
}

async fn read_proxy_v2_or_direct(socket: &mut TcpStream, fallback_ip: &str) -> anyhow::Result<String> {
    let mut peek_buf = [0u8; 12];
    const V2_SIG: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
    let is_proxy_v2 = match tokio::time::timeout(Duration::from_secs(3), socket.peek(&mut peek_buf)).await {
        Ok(Ok(n)) if n >= 12 && &peek_buf == V2_SIG => true,
        Ok(Ok(n)) if n > 0 && n < 12 && &peek_buf[..n] == &V2_SIG[..n] => {
            tokio::time::sleep(Duration::from_millis(25)).await;
            matches!(
                tokio::time::timeout(Duration::from_secs(1), socket.peek(&mut peek_buf)).await,
                Ok(Ok(n2)) if n2 >= 12 && &peek_buf == V2_SIG
            )
        }
        Ok(Ok(n)) if n > 0 => false,
        _ => anyhow::bail!("Timeout or EOF reading initial Stratum stream"),
    };
    if !is_proxy_v2 {
        let strict_proxy = std::env::var("STRICT_PROXY_V2")
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if strict_proxy {
            anyhow::bail!("Invalid PROXY protocol v2 signature. Direct connections are forbidden.");
        }
        return Ok(fallback_ip.to_string());
    }
    let mut sig_buf = [0u8; 16];
    tokio::time::timeout(Duration::from_secs(3), socket.read_exact(&mut sig_buf)).await??;
    let ver_cmd = sig_buf[12];
    let fam = sig_buf[13];
    let len = u16::from_be_bytes([sig_buf[14], sig_buf[15]]) as usize;
    if len > 536 {
        anyhow::bail!("PROXY v2 header too large");
    }
    let mut addr_buf = vec![0u8; len];
    if len > 0 {
        tokio::time::timeout(Duration::from_secs(3), socket.read_exact(&mut addr_buf)).await??;
    }
    if (ver_cmd & 0x0F) == 0x00 && fam == 0x00 {
        return Ok(HAPROXY_HEALTHCHECK_SENTINEL.to_string());
    }
    let peer_ip = match fam {
        0x11 | 0x12 if len >= 12 => {
            let ip = Ipv4Addr::new(addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]);
            ip.to_string()
        }
        0x21 | 0x22 if len >= 36 => {
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&addr_buf[0..16]);
            let ip = Ipv6Addr::from(ip_bytes);
            if let Some(v4) = ip.to_ipv4_mapped() {
                v4.to_string()
            } else {
                ip.to_string()
            }
        }
        _ => fallback_ip.to_string(),
    };
    Ok(peer_ip)
}

pub async fn start_stratum_server(
    config: Arc<StratumConfig>,
    job_manager: Arc<JobManager>,
    valid_share_tx: mpsc::Sender<(String, f64, bool)>,
    pg_pool: PgPool,
    port: u16,
    difficulty: f64,
    throttle_ms: u64,
) -> anyhow::Result<()> {
    let bind_addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&bind_addr).await?;
    let connection_limit = Arc::new(Semaphore::new(5000));
    tracing::info!(
        "🛡️ STRATUM TIER ACTIVE ON {} (Diff: {}, Throttle: {}ms, 10-Strike Shield Armed)",
        bind_addr,
        difficulty,
        throttle_ms
    );
    loop {
        let permit = connection_limit.clone().acquire_owned().await?;
        let (socket, addr) = listener.accept().await?;
        tracing::debug!("🔌 [{}] Hardware connection established to Tier Port {}", addr.ip(), port);
        let config_clone = config.clone();
        let job_manager_clone = job_manager.clone();
        let share_tx_clone = valid_share_tx.clone();
        let pool_clone = pg_pool.clone();
        let haproxy_ip = addr.ip().to_string();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_worker_connection(
                socket,
                haproxy_ip.clone(),
                config_clone,
                job_manager_clone,
                share_tx_clone,
                pool_clone,
                difficulty,
                throttle_ms,
            )
            .await
            {
                let err_str = e.to_string();
                if err_str.contains("Timeout or EOF reading")
                    || err_str.contains("Connection reset by peer")
                    || err_str.contains("os error 104")
                    || err_str.contains("Client closed connection")
                {
                    tracing::debug!("Socket closed from {}: {}", haproxy_ip, err_str);
                } else {
                    tracing::warn!("⚠️ Worker disconnected: {}", err_str);
                }
            }
        });
    }
}

async fn handle_worker_connection(
    mut socket: TcpStream,
    haproxy_ip: String,
    config: Arc<StratumConfig>,
    job_manager: Arc<JobManager>,
    valid_share_tx: mpsc::Sender<(String, f64, bool)>,
    pg_pool: PgPool,
    difficulty: f64,
    throttle_ms: u64,
) -> anyhow::Result<()> {
    socket.set_nodelay(true)?;
    let mut peer_addr = read_proxy_v2_or_direct(&mut socket, &haproxy_ip).await?;
    if peer_addr == HAPROXY_HEALTHCHECK_SENTINEL {
        return Ok(());
    }
    if is_exempt_local_or_lan_ip(&peer_addr) {
        BANNED_IPS.remove(&peer_addr);
        STRIKE_COUNTERS.remove(&peer_addr);
    } else if let Some(banned_time) = BANNED_IPS.get(&peer_addr) {
        if banned_time.elapsed() < Duration::from_secs(BAN_DURATION_SECS) {
            tracing::warn!("🛡️ [DDoS SHIELD] Dropping connection from BANNED IP: {}", peer_addr);
            anyhow::bail!("IP is temporarily banned due to 10 consecutive invalid payloads or shares.");
        } else {
            drop(banned_time);
            BANNED_IPS.remove(&peer_addr);
            STRIKE_COUNTERS.remove(&peer_addr);
        }
    }

    let mut job_rx = job_manager.job_tx.subscribe();
    let _extranonce_guard = ExtranonceGuard::allocate()?;
    let extranonce1 = _extranonce_guard.to_hex();
    let initial_tier_diff = clamp_to_power_of_2(difficulty);
    let tier_floor_diff = (initial_tier_diff / 4).max(clamp_to_power_of_2(config.min_share_diff));
    let mut current_diff = initial_tier_diff;
    let mut prev_diff = current_diff;
    let mut last_diff_change_time = Instant::now();
    let connected_at = Instant::now();
    let mut has_submitted_first_share = false;

    let (read_half, mut write_half) = socket.into_split();
    let mut reader = FramedRead::new(read_half, LinesCodec::new_with_max_length(4096));
    let mut handshake_state = 0;
    let mut current_worker_name = String::new();
    let mut share_count = 0;
    let mut last_vardiff_retarget = Instant::now();
    let target_shares_per_min = config.shares_per_min as f64;
    let closed_beta_mode = std::env::var("CLOSED_BETA_MODE")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut window_start = Instant::now();
    let mut window_msg_count: u32 = 0;

    while handshake_state < 2 {
        let line_timeout = tokio::time::timeout(Duration::from_secs(15), reader.next()).await;
        let line_res = match line_timeout {
            Ok(res) => res,
            Err(_) => anyhow::bail!("EOF - Handshake timeout (Slowloris / Inactive Client Mitigation)"),
        };
        if line_res.is_none() {
            anyhow::bail!("EOF - Client closed connection during handshake");
        }
        let payload_str = match line_res.unwrap() {
            Ok(s) => s,
            Err(LinesCodecError::Io(io_err)) if is_benign_disconnect_io_error(&io_err) => {
                anyhow::bail!("Connection reset by peer during handshake: {}", io_err);
            }
            Err(e) => {
                let (_, banned) = record_socket_strike(
                    &peer_addr,
                    &current_worker_name,
                    &format!("Oversized or non-UTF8 line during handshake ({})", e),
                );
                if banned {
                    anyhow::bail!("10-Strike Ban Hammer triggered during handshake: {}", e);
                }
                anyhow::bail!("Client Payload Violation: {}", e);
            }
        };
        if window_start.elapsed() >= Duration::from_secs(SOCKET_WINDOW_SECS) {
            window_start = Instant::now();
            window_msg_count = 0;
        }
        window_msg_count += 1;
        if window_msg_count > MAX_MESSAGES_PER_WINDOW {
            let (_, banned) = record_socket_strike(&peer_addr, &current_worker_name, "Handshake socket rate-limit exceeded");
            if banned {
                anyhow::bail!("10-Strike Ban Hammer: Socket flood during handshake.");
            }
            continue;
        }
        let trimmed = payload_str.trim_matches('\0').trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("PROXY ") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 3 && parts[1] != "UNKNOWN" {
                peer_addr = parts[2].to_string();
            }
            continue;
        }
        tracing::debug!("⬇️ [RX | {}] {}", peer_addr, trimmed);
        match serde_json::from_str::<RpcRequest>(trimmed) {
            Ok(req) => {
                let method = req.method.unwrap_or_else(|| "unknown".to_string());
                let req_id = req.id.clone().unwrap_or(serde_json::Value::Null);

                if method == "mining.subscribe" {
                    let sub_json = json!({
                        "id": req_id,
                        "result": [true, "EthereumStratum/1.0.0"],
                        "error": null
                    });
                    let mut response = sub_json.to_string();
                    response.push('\n');
                    write_half.write_all(response.as_bytes()).await?;
                    let en_json = json!({
                        "id": null,
                        "method": "mining.set_extranonce",
                        "params": [extranonce1.clone(), 6]
                    });
                    let mut en_resp = en_json.to_string();
                    en_resp.push('\n');
                    write_half.write_all(en_resp.as_bytes()).await?;
                    if handshake_state < 1 {
                        handshake_state = 1;
                    }
                } else if method == "mining.extranonce.subscribe" {
                    let en_sub_json = json!({
                        "id": req_id,
                        "result": true,
                        "error": null
                    });
                    let mut response = en_sub_json.to_string();
                    response.push('\n');
                    write_half.write_all(response.as_bytes()).await?;
                } else if method == "mining.configure" || method == "mining.multi_version" {
                    let cfg_json = json!({
                        "id": req_id,
                        "result": {},
                        "error": null
                    });
                    let mut response = cfg_json.to_string();
                    response.push('\n');
                    write_half.write_all(response.as_bytes()).await?;
                } else if method == "mining.authorize" {
                    if handshake_state == 0 {
                        let en_json = json!({
                            "id": null,
                            "method": "mining.set_extranonce",
                            "params": [extranonce1.clone(), 6]
                        });
                        let mut en_resp = en_json.to_string();
                        en_resp.push('\n');
                        write_half.write_all(en_resp.as_bytes()).await?;
                    }
                    let mut authorized_ok = false;
                    if let Some(ref params) = req.params {
                        if !params.is_empty() {
                            let mut auth_name = match &params[0] {
                                serde_json::Value::String(s) => s.clone(),
                                v => v.to_string(),
                            }
                            .replace('"', "")
                            .replace('\0', "")
                            .trim()
                            .to_string();
                            if !auth_name.is_empty() {
                                if !auth_name.starts_with("kaspa:") {
                                    auth_name = format!("kaspa:{}", auth_name);
                                }
                                let parts: Vec<&str> = auth_name.split('.').collect();
                                let wallet = if !parts.is_empty() { parts[0] } else { auth_name.as_str() };
                                let clean_wallet = wallet.to_lowercase().replace("kaspa:", "").trim().to_string();
                                let prefixed_wallet = format!("kaspa:{}", clean_wallet);
                                if !is_valid_kaspa_wallet(&clean_wallet) {
                                    let _ = record_socket_strike(&peer_addr, &auth_name, "Malformed Kaspa Bech32m wallet address in mining.authorize");
                                    tracing::warn!(
                                        "🔒 [AUTH REJECTED] Malformed Kaspa wallet address from {}: {}",
                                        peer_addr,
                                        auth_name
                                    );
                                    anyhow::bail!("Invalid Kaspa wallet address format.");
                                }
                                if closed_beta_mode {
                                    let is_authorized: Option<i32> = sqlx::query_scalar(
                                        r#"
                                        SELECT 1 FROM whitelisted_wallets WHERE wallet_address = $1 OR wallet_address = $2
                                        UNION
                                        SELECT 1 FROM user_command_centers WHERE wallet_address = $1 OR wallet_address = $2
                                        LIMIT 1
                                        "#,
                                    )
                                    .bind(&clean_wallet)
                                    .bind(&prefixed_wallet)
                                    .fetch_optional(&pg_pool)
                                    .await?;
                                    if is_authorized.is_none() {
                                        let _ = record_socket_strike(&peer_addr, &auth_name, "Unauthorized wallet in Closed Beta");
                                        tracing::warn!(
                                            "🔒 [AUTH REJECTED] Unregistered wallet attempt in Closed Beta from {}: {}",
                                            peer_addr,
                                            auth_name
                                        );
                                        anyhow::bail!("Unregistered wallet. Connection dropped immediately.");
                                    }
                                }
                                current_worker_name = auth_name.clone();
                                authorized_ok = true;
                                reset_socket_strikes(&peer_addr, &current_worker_name);
                                tracing::info!(
                                    "🔑 [{}] Authorized Worker Identity: {} (Extranonce1: {}, Diff: {})",
                                    peer_addr,
                                    current_worker_name,
                                    extranonce1,
                                    current_diff
                                );
                                let pool_bg = pg_pool.clone();
                                let prefixed_bg = prefixed_wallet.clone();
                                tokio::spawn(async move {
                                    let default_state = serde_json::json!({
                                        "workers": [],
                                        "sectors": [{
                                            "id": "DEFAULT-SILO",
                                            "name": "Native L1 Silo",
                                            "allocationPercentage": 100.0,
                                            "routeMode": "hold",
                                            "settlementConfig": {
                                                "targetAsset": {
                                                    "ticker": "KAS",
                                                    "name": "Kaspa",
                                                    "assetClass": "Native L1",
                                                    "spotPrice": 0.0,
                                                    "theme": { "hex": "#18C6A5", "pastel": "#99f6e4" }
                                                },
                                                "payoutAddress": prefixed_bg,
                                                "autoPayout": true,
                                                "mode": "threshold",
                                                "threshold": 50.0,
                                                "appointmentDate": "",
                                                "appointmentTime": "17:00"
                                            },
                                            "pendingKaspa": 0.0,
                                            "width": 12
                                        }],
                                        "manualLps": [],
                                        "systemMode": "base"
                                    });
                                    let _ = sqlx::query("INSERT INTO user_command_centers (wallet_address, layout_state, last_updated) VALUES ($1, $2, CURRENT_TIMESTAMP) ON CONFLICT DO NOTHING")
                                        .bind(prefixed_bg)
                                        .bind(default_state)
                                        .execute(&pool_bg)
                                        .await;
                                });
                            }
                        }
                    }
                    if !authorized_ok {
                        let (_, banned) = record_socket_strike(&peer_addr, &current_worker_name, "Empty params in mining.authorize");
                        if banned {
                            anyhow::bail!("10-Strike Ban Hammer: Empty mining.authorize params.");
                        }
                    } else {
                        let auth_json = json!({
                            "id": req_id,
                            "result": true,
                            "error": null
                        });
                        let mut response = auth_json.to_string();
                        response.push('\n');
                        write_half.write_all(response.as_bytes()).await?;
                        handshake_state = 2;
                    }
                } else {
                    let ack_json = json!({
                        "id": req_id,
                        "result": true,
                        "error": null
                    });
                    let mut response = ack_json.to_string();
                    response.push('\n');
                    write_half.write_all(response.as_bytes()).await?;
                }
            }
            Err(_) => {
                let (_, banned) = record_socket_strike(
                    &peer_addr,
                    &current_worker_name,
                    "Malformed JSON-RPC payload during handshake",
                );
                if banned {
                    anyhow::bail!("10-Strike Ban Hammer: Malformed JSON-RPC flood during handshake.");
                }
            }
        }
    }

    let initial_job = loop {
        if let Ok(cache) = job_manager.cached_job.read() {
            if let Some(job) = &*cache {
                break job.clone();
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let diff_json = json!({
        "id": null,
        "method": "mining.set_difficulty",
        "params": [current_diff]
    });
    let mut diff_msg = diff_json.to_string();
    diff_msg.push('\n');
    write_half.write_all(diff_msg.as_bytes()).await?;
    write_half.write_all(&initial_job[..]).await?;
    if !initial_job.ends_with(b"\n") {
        write_half.write_all(b"\n").await?;
    }

    let safe_throttle = if throttle_ms == 0 { 10 } else { throttle_ms };
    let mut throttle_interval = tokio::time::interval(Duration::from_millis(safe_throttle));
    throttle_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut vardiff_interval = tokio::time::interval(Duration::from_secs(30));
    let mut pending_job: Option<StratumJob> = None;
    let mut last_dispatched_job_id = String::new();

    loop {
        tokio::select! {
            job_res = job_rx.recv() => {
                match job_res {
                    Ok(job) => {
                        pending_job = Some(job);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        tracing::warn!("⚠️ [{}] Job receiver lagged, gracefully skipping block...", peer_addr);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::error!("❌ [{}] Internal channel closed.", peer_addr);
                        return Ok(());
                    }
                }
            }
            _ = throttle_interval.tick() => {
                if let Some(job) = pending_job.take() {
                    if job.job_id != last_dispatched_job_id {
                        last_dispatched_job_id = job.job_id.clone();
                        let payload = job.payload;
                        if write_half.write_all(&payload[..]).await.is_err() {
                            anyhow::bail!("Write failed - Client disconnected");
                        }
                        if !payload.ends_with(b"\n") {
                            if write_half.write_all(b"\n").await.is_err() {
                                anyhow::bail!("Write failed - Client disconnected");
                            }
                        }
                    }
                }
            }
            _ = vardiff_interval.tick() => {
                if config.var_diff && last_vardiff_retarget.elapsed().as_secs() >= 60 {
                    if !has_submitted_first_share && connected_at.elapsed().as_secs() < ASIC_WARMUP_GRACE_SECS {
                        last_vardiff_retarget = Instant::now();
                        continue;
                    }
                    let elapsed_mins = last_vardiff_retarget.elapsed().as_secs_f64() / 60.0;
                    let shares_per_min = share_count as f64 / elapsed_mins;
                    let mut new_diff = current_diff;
                    if shares_per_min < target_shares_per_min * 0.5 {
                        new_diff = (current_diff / 2).max(tier_floor_diff);
                    } else if shares_per_min > target_shares_per_min * 2.0 {
                        new_diff = current_diff * 2;
                    }
                    if new_diff != current_diff {
                        prev_diff = current_diff;
                        current_diff = new_diff;
                        last_diff_change_time = Instant::now();
                        let retarget_json = json!({
                            "id": null,
                            "method": "mining.set_difficulty",
                            "params": [current_diff]
                        });
                        let mut retarget_msg = retarget_json.to_string();
                        retarget_msg.push('\n');
                        if write_half.write_all(retarget_msg.as_bytes()).await.is_err() {
                            anyhow::bail!("Write failed - Client disconnected");
                        }
                        tracing::info!("🔄 Auto-Diff Adjusted for {} -> New Diff: {}", current_worker_name, current_diff);
                    }
                    share_count = 0;
                    last_vardiff_retarget = Instant::now();
                }
            }
            line_timeout = tokio::time::timeout(Duration::from_secs(600), reader.next()) => {
                let line_res = match line_timeout {
                    Ok(res) => res,
                    Err(_) => anyhow::bail!("EOF - Miner inactive timeout (No shares submitted in 600s)"),
                };
                if line_res.is_none() {
                    anyhow::bail!("EOF - Client closed connection");
                }
                let payload_str = match line_res.unwrap() {
                    Ok(s) => s,
                    Err(LinesCodecError::Io(io_err)) if is_benign_disconnect_io_error(&io_err) => {
                        anyhow::bail!("Connection reset by peer: {}", io_err);
                    }
                    Err(e) => {
                        let (_, banned) = record_socket_strike(&peer_addr, &current_worker_name, "Line codec max length violation");
                        if banned {
                            anyhow::bail!("10-Strike Ban Hammer: Oversized payload flood ({})", e);
                        }
                        anyhow::bail!("Client Payload Violation: {}", e);
                    }
                };
                if window_start.elapsed() >= Duration::from_secs(SOCKET_WINDOW_SECS) {
                    window_start = Instant::now();
                    window_msg_count = 0;
                }
                window_msg_count += 1;
                if window_msg_count > MAX_MESSAGES_PER_WINDOW {
                    let (_, banned) = record_socket_strike(&peer_addr, &current_worker_name, "Socket RPC rate-limit exceeded (>250 msgs/10s)");
                    if banned {
                        anyhow::bail!("10-Strike Ban Hammer: Socket rate-limit exceeded.");
                    }
                    continue;
                }
                let trimmed = payload_str.trim_matches('\0').trim();
                if trimmed.is_empty() {
                    continue;
                }
                match serde_json::from_str::<RpcRequest>(trimmed) {
                    Ok(req) => {
                        let method = req.method.unwrap_or_else(|| "unknown".to_string());
                        let req_id = req.id.clone().unwrap_or(serde_json::Value::Null);
                        if method == "mining.submit" {
                            let Some(ref params) = req.params else {
                                let (_, banned) = record_socket_strike(&peer_addr, &current_worker_name, "Missing params in mining.submit");
                                if banned {
                                    anyhow::bail!("10-Strike Ban Hammer: Missing params in mining.submit.");
                                }
                                continue;
                            };
                            if params.len() < 3 {
                                let (_, banned) = record_socket_strike(&peer_addr, &current_worker_name, "Insufficient params in mining.submit");
                                if banned {
                                    anyhow::bail!("10-Strike Ban Hammer: Malformed mining.submit parameter array.");
                                }
                                continue;
                            }
                            let mut req_worker = match &params[0] {
                                serde_json::Value::String(s) => s.clone(),
                                v => v.to_string(),
                            }
                            .replace('"', "")
                            .replace('\0', "")
                            .trim()
                            .to_string();
                            if !req_worker.is_empty() && !req_worker.starts_with("kaspa:") {
                                req_worker = format!("kaspa:{}", req_worker);
                            }
                            let active_identity = if !req_worker.is_empty() {
                                req_worker.clone()
                            } else if !current_worker_name.is_empty() {
                                current_worker_name.clone()
                            } else {
                                "kaspa:unknown".to_string()
                            };
                            let job_id = match &params[1] {
                                serde_json::Value::String(s) => s.clone(),
                                v => v.to_string(),
                            }
                            .replace('"', "")
                            .replace('\0', "")
                            .trim()
                            .to_lowercase();
                            let nonce_str = match &params[2] {
                                serde_json::Value::String(s) => s.clone(),
                                v => v.to_string(),
                            }
                            .replace('"', "")
                            .replace('\0', "")
                            .trim()
                            .to_string();
                            let clean_nonce = nonce_str.trim_start_matches("0x");
                            let Ok(parsed_base_nonce) = u64::from_str_radix(clean_nonce, 16) else {
                                let (_, banned) = record_socket_strike(&peer_addr, &active_identity, "Non-hexadecimal nonce in mining.submit");
                                let err_reply = json!({
                                    "id": req_id,
                                    "result": false,
                                    "error": [20, "Malformed hex nonce", null]
                                });
                                let mut resp = err_reply.to_string();
                                resp.push('\n');
                                let _ = write_half.write_all(resp.as_bytes()).await;
                                if banned {
                                    anyhow::bail!("10-Strike Ban Hammer: Malformed hex nonce spam.");
                                }
                                continue;
                            };
                            let mut nonce: u64 = parsed_base_nonce;
                            if clean_nonce.len() <= 12 {
                                let full_nonce_hex = format!("{}{:0>12}", extranonce1, clean_nonce);
                                nonce = u64::from_str_radix(&full_nonce_hex, 16).unwrap_or(nonce);
                            }
                            let mut is_accepted = false;
                            let mut err_msg = serde_json::Value::Null;
                            let mut should_ban_disconnect = false;
                            if let Some(job_entry) = job_manager.active_jobs.get(&job_id) {
                                let active_job = job_entry.value().clone();
                                drop(job_entry);
                                if !job_manager.register_submission(&job_id, nonce) {
                                    tracing::debug!(
                                        "⚠ [{}] Duplicate share packet ignored | Worker: {} | Job: {} | Nonce: {:016x}",
                                        peer_addr,
                                        active_identity,
                                        job_id,
                                        nonce
                                    );
                                    let _ = valid_share_tx.try_send((active_identity.clone(), -1.0, false));
                                    err_msg = json!([22, "Duplicate share", null]);
                                } else {
                                    let consensus_header = active_job.header;
                                    let mut rpc_block = active_job.block;
                                    let actual_network_diff = if active_job.network_diff > 0.0 {
                                        active_job.network_diff
                                    } else {
                                        difficulty_from_bits(consensus_header.bits)
                                    };
                                    let reward_sompi = if active_job.reward_sompi > 0 {
                                        active_job.reward_sompi
                                    } else {
                                        job_manager.get_latest_reward_sompi()
                                    };
                                    let (mut is_valid_share, is_network_block) = crate::diff_engine::verify_share(
                                        &consensus_header,
                                        nonce,
                                        current_diff as f64,
                                    );
                                    let mut credited_diff = current_diff as f64;
                                    if !is_valid_share
                                        && prev_diff < current_diff
                                        && last_diff_change_time.elapsed() < Duration::from_secs(VARDIFF_GRACE_WINDOW_SECS)
                                    {
                                        let (valid_at_prev, _) = crate::diff_engine::verify_share(
                                            &consensus_header,
                                            nonce,
                                            prev_diff as f64,
                                        );
                                        if valid_at_prev {
                                            is_valid_share = true;
                                            credited_diff = prev_diff as f64;
                                        }
                                    }
                                    if is_network_block {
                                        let mut final_header = consensus_header.clone();
                                        final_header.nonce = nonce;
                                        let block_hash = kaspa_consensus_core::hashing::header::hash(&final_header).to_string();
                                        has_submitted_first_share = true;
                                        share_count += 1;
                                        let _ = valid_share_tx.try_send((active_identity.clone(), credited_diff, false));
                                        is_accepted = true;
                                        reset_socket_strikes(&peer_addr, &active_identity);
                                        if job_manager.register_block_hash(&block_hash) {
                                            tracing::info!(
                                                "💎💎💎 [{}] CANDIDATE NETWORK BLOCK ACQUIRED! Hash: {} | Nonce: {:016x} | NetDiff: {:.2}",
                                                peer_addr,
                                                block_hash,
                                                nonce,
                                                actual_network_diff
                                            );
                                            if let Some(ref mut rpc_header) = rpc_block.header {
                                                rpc_header.nonce = nonce;
                                            }
                                            let submission = PendingBlockSubmission {
                                                block: rpc_block,
                                                block_hash,
                                                worker: active_identity.clone(),
                                                nonce,
                                                network_diff: actual_network_diff,
                                                reward_sompi,
                                            };
                                            let _ = job_manager.block_submit_tx.try_send(submission);
                                        } else {
                                            tracing::warn!(
                                                "⚠ [{}] Duplicate candidate block hash {} suppressed.",
                                                peer_addr,
                                                block_hash
                                            );
                                        }
                                    } else if is_valid_share {
                                        tracing::debug!(
                                            "✅ [{}] TIER SHARE ACCEPTED | Worker: {} | Job: {} | Diff: {}",
                                            peer_addr,
                                            active_identity,
                                            job_id,
                                            credited_diff
                                        );
                                        has_submitted_first_share = true;
                                        share_count += 1;
                                        let _ = valid_share_tx.try_send((active_identity.clone(), credited_diff, false));
                                        is_accepted = true;
                                        reset_socket_strikes(&peer_addr, &active_identity);
                                    } else {
                                        tracing::warn!("🚫 [{}] INVALID SHARE | Worker: {}", peer_addr, active_identity);
                                        let _ = valid_share_tx.try_send((active_identity.clone(), -1.0, false));
                                        err_msg = json!([20, "Invalid share", null]);
                                        let (_, banned) = record_socket_strike(&peer_addr, &active_identity, "Invalid PoW share");
                                        should_ban_disconnect = banned;
                                    }
                                }
                            } else {
                                tracing::debug!("⏳ [{}] Stale job share ignored (10 BPS rotation): {}", peer_addr, job_id);
                                let _ = valid_share_tx.try_send((active_identity.clone(), -1.0, false));
                                err_msg = json!([21, "Stale job", null]);
                            }
                            let submit_reply = if is_accepted {
                                json!({
                                    "id": req_id,
                                    "result": true,
                                    "error": null
                                })
                            } else {
                                json!({
                                    "id": req_id,
                                    "result": false,
                                    "error": err_msg
                                })
                            };
                            let mut response = submit_reply.to_string();
                            response.push('\n');
                            if write_half.write_all(response.as_bytes()).await.is_err() {
                                anyhow::bail!("Write failed - Client disconnected");
                            }
                            if should_ban_disconnect {
                                anyhow::bail!(
                                    "Disconnecting worker {} ({}): 10 consecutive invalid shares.",
                                    active_identity,
                                    peer_addr
                                );
                            }
                        } else {
                            let catch_json = json!({
                                "id": req_id,
                                "result": true,
                                "error": null
                            });
                            let mut response = catch_json.to_string();
                            response.push('\n');
                            if write_half.write_all(response.as_bytes()).await.is_err() {
                                anyhow::bail!("Write failed - Client disconnected");
                            }
                        }
                    }
                    Err(_) => {
                        let (_, banned) = record_socket_strike(
                            &peer_addr,
                            &current_worker_name,
                            "Malformed JSON-RPC payload on Stratum socket",
                        );
                        if banned {
                            anyhow::bail!("10-Strike Ban Hammer: Malformed JSON-RPC flood.");
                        }
                    }
                }
            }
        }
    }
}