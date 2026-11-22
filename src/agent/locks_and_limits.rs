// src/agent/locks_and_limits.rs

use axum::{
    extract::State,
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    agent::{
        auth::authenticate_agent_request,
        types::{
            validate_hex_64, AgentCapabilityClaims, AgentError, AgentErrorCode, AgentMode,
            StoredAgentQuote, U128Str, UtxoLaneHealth, X402PaymentChallenge,
            DUST_UTXO_THRESHOLD_SOMPI,
        },
        AgentGatewayState,
    },
    silverscript::decode_kaspa_address_payload,
};

pub const REDIS_KEY_AGENT_CIRCUIT_BREAKER: &str = "perennia:agent:circuit_breaker";

/// 0.05 KAS (5,000,000 sompi) or $0.05 USDC (50,000 micro-USDC) unlocks 100 burst calls.
pub const X402_SOMPI_PER_BURST_PACK: u128 = 5_000_000;
pub const X402_USDC_MICROS_PER_BURST_PACK: u128 = 50_000;
pub const X402_CREDITS_PER_BURST_PACK: u64 = 100;
pub const MIN_X402_DAA_CONFIRMATIONS: u64 = 10;

/// Default 60-second aggregate anomaly auto-breaker thresholds.
const DEFAULT_MAX_60S_OUTFLOW_USD_MICROS: u128 = 250_000_000_000; // $250,000 / 60s
const DEFAULT_MAX_60S_SLIPPAGE_SPIKES: u64 = 25;

const LUA_DYNAMIC_RATE_LIMIT_AND_X402: &str = r#"
local rpm_key = KEYS[1]
local q15_key = KEYS[2]
local f15_key = KEYS[3]
local x402_key = KEYS[4]
local vol_key = KEYS[5]

local is_quote = tonumber(ARGV[1])
local base_rpm = tonumber(ARGV[2])

local q_win = tonumber(redis.call('GET', q15_key) or '0')
local f_win = tonumber(redis.call('GET', f15_key) or '0')
local vol_str = redis.call('GET', vol_key) or '0'
local vol_len = string.len(vol_str)

-- Scale RPM upward with verified historical USD micro-volume:
-- >= $100,000 (12+ digits): 240 RPM
-- >= $10,000  (11 digits):  120 RPM
-- >= $1,000   (10 digits):   60 RPM
local scaled_rpm = base_rpm
if vol_len >= 12 then
    scaled_rpm = math.max(scaled_rpm, 240)
elseif vol_len == 11 then
    scaled_rpm = math.max(scaled_rpm, 120)
elseif vol_len == 10 then
    scaled_rpm = math.max(scaled_rpm, 60)
end

local ratio_bps = 10000
if q_win > 0 then
    ratio_bps = math.floor((f_win * 10000) / q_win)
end

-- Throttle parasitic quote scrapers (<5% fill ratio after >=10 quotes in 15m window) back to floor
if q_win >= 10 and ratio_bps < 500 then
    scaled_rpm = math.min(base_rpm, 6)
elseif q_win >= 20 and ratio_bps < 1500 then
    scaled_rpm = base_rpm
end

local cur_rpm = redis.call('INCR', rpm_key)
if cur_rpm == 1 then
    redis.call('EXPIRE', rpm_key, 60)
end

local used_x402 = 0
if cur_rpm > scaled_rpm then
    local credits = tonumber(redis.call('GET', x402_key) or '0')
    if credits > 0 then
        redis.call('DECR', x402_key)
        used_x402 = 1
    else
        redis.call('DECR', rpm_key)
        return {0, cur_rpm - 1, scaled_rpm, q_win, f_win, ratio_bps, 0}
    end
end

if is_quote == 1 then
    local next_q = redis.call('INCR', q15_key)
    if next_q == 1 then
        redis.call('EXPIRE', q15_key, 900)
    end
    q_win = next_q
    ratio_bps = math.floor((f_win * 10000) / q_win)
end

local rem_credits = tonumber(redis.call('GET', x402_key) or '0')
return {1, cur_rpm, scaled_rpm, q_win, f_win, ratio_bps, used_x402, rem_credits}
"#;

const LUA_PROGRESSIVE_FAULT_COOLDOWN: &str = r#"
local strike_key = KEYS[1]
local wallet_cd_key = KEYS[2]
local has_key_cd = tonumber(ARGV[1])

local strikes = redis.call('INCR', strike_key)
if strikes == 1 then
    redis.call('EXPIRE', strike_key, 86400)
end

local ban_secs = 10
if strikes == 2 then
    ban_secs = 60
elseif strikes >= 3 then
    ban_secs = 3600
end

redis.call('SET', wallet_cd_key, ARGV[2], 'EX', ban_secs)
if has_key_cd == 1 then
    redis.call('SET', KEYS[3], ARGV[2], 'EX', ban_secs)
end

return {strikes, ban_secs}
"#;

/// Exact base-10 `u128` arithmetic + UTXO outpoint semaphore + concurrency cap + Mandate 24h check.
const LUA_ACQUIRE_QUOTE_AND_UTXO_LOCKS: &str = r#"
local function norm_u128(s)
    if not s or s == '' then return '0' end
    local stripped = string.gsub(s, '^0+', '')
    if stripped == '' then return '0' end
    return stripped
end

local function cmp_u128(a, b)
    a = norm_u128(a)
    b = norm_u128(b)
    local la = string.len(a)
    local lb = string.len(b)
    if la ~= lb then
        if la < lb then return -1 else return 1 end
    end
    if a == b then return 0 end
    if a < b then return -1 else return 1 end
end

local function add_u128(a, b)
    a = norm_u128(a)
    b = norm_u128(b)
    local ia = string.len(a)
    local ib = string.len(b)
    local carry = 0
    local out = {}
    while ia > 0 or ib > 0 or carry > 0 do
        local da = 0
        local db = 0
        if ia > 0 then
            da = string.byte(a, ia) - 48
            ia = ia - 1
        end
        if ib > 0 then
            db = string.byte(b, ib) - 48
            ib = ib - 1
        end
        local s = da + db + carry
        carry = math.floor(s / 10)
        table.insert(out, 1, string.char((s % 10) + 48))
    end
    return norm_u128(table.concat(out))
end

local wallet_quotes_zset = KEYS[1]
local key_quotes_set = KEYS[2]
local quote_key = KEYS[3]

local quote_id = ARGV[1]
local quote_json = ARGV[2]
local now_ms = tonumber(ARGV[3])
local expires_ms = tonumber(ARGV[4])
local ttl_ms = tonumber(ARGV[5])
local max_conc = tonumber(ARGV[6])
local cap_sompi = ARGV[7]
local cap_usd = ARGV[8]
local delta_sompi = ARGV[9]
local delta_usd = ARGV[10]
local key_id = ARGV[11]
local cur_hour = tonumber(ARGV[12])
local num_utxos = tonumber(ARGV[13])

redis.call('ZREMRANGEBYSCORE', wallet_quotes_zset, '-inf', now_ms - 1)
local active_count = redis.call('ZCARD', wallet_quotes_zset)
if active_count >= max_conc then
    return {'ERR_CONCURRENCY_CAP', tostring(active_count), tostring(max_conc)}
end

-- Pre-check Mandate 24h rolling spend cap across last 24 hourly buckets
local spent_sompi = '0'
local spent_usd = '0'
for h = cur_hour - 23, cur_hour do
    local s_val = redis.call('GET', 'perennia:agent:spend_sompi:' .. key_id .. ':' .. tostring(h))
    if s_val then spent_sompi = add_u128(spent_sompi, s_val) end
    local u_val = redis.call('GET', 'perennia:agent:spend_usd:' .. key_id .. ':' .. tostring(h))
    if u_val then spent_usd = add_u128(spent_usd, u_val) end
end

if cmp_u128(cap_sompi, '0') > 0 and cmp_u128(add_u128(spent_sompi, delta_sompi), cap_sompi) > 0 then
    return {'ERR_CAP_SOMPI', spent_sompi, cap_sompi}
end
if cmp_u128(cap_usd, '0') > 0 and cmp_u128(add_u128(spent_usd, delta_usd), cap_usd) > 0 then
    return {'ERR_CAP_USD', spent_usd, cap_usd}
end

for i = 1, num_utxos do
    local u_key = KEYS[3 + i]
    local existing = redis.call('GET', u_key)
    if existing and existing ~= quote_id then
        return {'ERR_UTXO_LOCKED', u_key}
    end
end

for i = 1, num_utxos do
    local u_key = KEYS[3 + i]
    redis.call('SET', u_key, quote_id, 'PX', ttl_ms)
end

redis.call('SET', quote_key, quote_json, 'PX', ttl_ms)
redis.call('ZADD', wallet_quotes_zset, expires_ms, quote_id)
redis.call('PEXPIRE', wallet_quotes_zset, math.max(ttl_ms + 30000, 60000))
redis.call('SADD', key_quotes_set, quote_id)
redis.call('PEXPIRE', key_quotes_set, math.max(ttl_ms + 30000, 60000))

return {'OK', tostring(active_count + 1)}
"#;

/// Single atomic Redis Lua script executed on `/api/v1/agent/execute` to consume `quote_id`,
/// verify UTXO outpoint locks, enforce rolling 24h Mandate spend caps in exact `u128`,
/// and claim the `idempotency_key` lock in one atomic step.
const LUA_CONSUME_QUOTE_UTXOS_AND_MANDATE_ATOMIC: &str = r#"
local function norm_u128(s)
    if not s or s == '' then return '0' end
    local stripped = string.gsub(s, '^0+', '')
    if stripped == '' then return '0' end
    return stripped
end

local function cmp_u128(a, b)
    a = norm_u128(a)
    b = norm_u128(b)
    local la = string.len(a)
    local lb = string.len(b)
    if la ~= lb then
        if la < lb then return -1 else return 1 end
    end
    if a == b then return 0 end
    if a < b then return -1 else return 1 end
end

local function add_u128(a, b)
    a = norm_u128(a)
    b = norm_u128(b)
    local ia = string.len(a)
    local ib = string.len(b)
    local carry = 0
    local out = {}
    while ia > 0 or ib > 0 or carry > 0 do
        local da = 0
        local db = 0
        if ia > 0 then
            da = string.byte(a, ia) - 48
            ia = ia - 1
        end
        if ib > 0 then
            db = string.byte(b, ib) - 48
            ib = ib - 1
        end
        local s = da + db + carry
        carry = math.floor(s / 10)
        table.insert(out, 1, string.char((s % 10) + 48))
    end
    return norm_u128(table.concat(out))
end

local idemp_key = KEYS[1]
local revoked_key = KEYS[2]
local quote_key = KEYS[3]
local wallet_quotes_zset = KEYS[4]
local key_quotes_set = KEYS[5]

local expected_key_id = ARGV[1]
local quote_id = ARGV[2]
local now_ms = tonumber(ARGV[3])
local cur_hour = tonumber(ARGV[4])
local cap_sompi = ARGV[5]
local cap_usd = ARGV[6]

local idemp_state = redis.call('GET', idemp_key)
if idemp_state then
    if string.sub(idemp_state, 1, 8) == 'SETTLED:' then
        return {'IDEMPOTENT_REPLAY', string.sub(idemp_state, 9)}
    end
    return {'ERR_IDEMPOTENCY_IN_FLIGHT'}
end

if redis.call('GET', revoked_key) == '1' then
    return {'ERR_KEY_REVOKED'}
end

local quote_raw = redis.call('GET', quote_key)
if not quote_raw then
    return {'ERR_QUOTE_EXPIRED'}
end

local quote = cjson.decode(quote_raw)
if quote['keyId'] ~= expected_key_id then
    return {'ERR_KEY_MISMATCH'}
end
if tonumber(quote['expiresAtMs']) < now_ms then
    redis.call('DEL', quote_key)
    redis.call('ZREM', wallet_quotes_zset, quote_id)
    redis.call('SREM', key_quotes_set, quote_id)
    return {'ERR_QUOTE_EXPIRED'}
end

local outpoints = quote['lockedOutpoints'] or {}
for idx, out_str in ipairs(outpoints) do
    local lock_k = 'perennia:agent:utxo_lock:' .. out_str
    local cur_holder = redis.call('GET', lock_k)
    if cur_holder ~= quote_id then
        return {'ERR_UTXO_LOCK_LOST', out_str}
    end
end

local delta_sompi = tostring(quote['spendSompiEquiv'] or '0')
local delta_usd = tostring(quote['notionalUsdMicros'] or '0')

local spent_sompi = '0'
local spent_usd = '0'
for h = cur_hour - 23, cur_hour do
    local s_val = redis.call('GET', 'perennia:agent:spend_sompi:' .. expected_key_id .. ':' .. tostring(h))
    if s_val then spent_sompi = add_u128(spent_sompi, s_val) end
    local u_val = redis.call('GET', 'perennia:agent:spend_usd:' .. expected_key_id .. ':' .. tostring(h))
    if u_val then spent_usd = add_u128(spent_usd, u_val) end
end

local next_total_sompi = add_u128(spent_sompi, delta_sompi)
local next_total_usd = add_u128(spent_usd, delta_usd)

if cmp_u128(cap_sompi, '0') > 0 and cmp_u128(next_total_sompi, cap_sompi) > 0 then
    return {'ERR_CAP_SOMPI', spent_sompi, cap_sompi}
end
if cmp_u128(cap_usd, '0') > 0 and cmp_u128(next_total_usd, cap_usd) > 0 then
    return {'ERR_CAP_USD', spent_usd, cap_usd}
end

-- Atomically consume quote, hold outpoints in BROADCASTING guard for 15s, increment 24h bucket, set IN_FLIGHT
redis.call('DEL', quote_key)
redis.call('ZREM', wallet_quotes_zset, quote_id)
redis.call('SREM', key_quotes_set, quote_id)

for idx, out_str in ipairs(outpoints) do
    local lock_k = 'perennia:agent:utxo_lock:' .. out_str
    redis.call('SET', lock_k, 'BROADCASTING:' .. quote_id, 'PX', 15000)
end

local cur_s_key = 'perennia:agent:spend_sompi:' .. expected_key_id .. ':' .. tostring(cur_hour)
local cur_u_key = 'perennia:agent:spend_usd:' .. expected_key_id .. ':' .. tostring(cur_hour)

local cur_bucket_s = redis.call('GET', cur_s_key) or '0'
local cur_bucket_u = redis.call('GET', cur_u_key) or '0'

redis.call('SET', cur_s_key, add_u128(cur_bucket_s, delta_sompi), 'EX', 90000)
redis.call('SET', cur_u_key, add_u128(cur_bucket_u, delta_usd), 'EX', 90000)
redis.call('SET', idemp_key, 'IN_FLIGHT', 'EX', 120)

return {'OK', quote_raw, next_total_sompi, next_total_usd, tostring(cur_hour)}
"#;

const LUA_ROLLBACK_FAILED_EXECUTION: &str = r#"
local function norm_u128(s)
    if not s or s == '' then return '0' end
    local stripped = string.gsub(s, '^0+', '')
    if stripped == '' then return '0' end
    return stripped
end

local function cmp_u128(a, b)
    a = norm_u128(a)
    b = norm_u128(b)
    if string.len(a) ~= string.len(b) then
        if string.len(a) < string.len(b) then return -1 else return 1 end
    end
    if a == b then return 0 end
    if a < b then return -1 else return 1 end
end

local function sub_clamped_u128(a, b)
    a = norm_u128(a)
    b = norm_u128(b)
    if cmp_u128(a, b) <= 0 then return '0' end
    local ia = string.len(a)
    local ib = string.len(b)
    local borrow = 0
    local out = {}
    while ia > 0 do
        local da = (string.byte(a, ia) - 48) - borrow
        ia = ia - 1
        local db = 0
        if ib > 0 then
            db = string.byte(b, ib) - 48
            ib = ib - 1
        end
        if da < db then
            da = da + 10
            borrow = 1
        else
            borrow = 0
        end
        table.insert(out, 1, string.char((da - db) + 48))
    end
    return norm_u128(table.concat(out))
end

local idemp_key = KEYS[1]
local cur_s_key = KEYS[2]
local cur_u_key = KEYS[3]

local quote_id = ARGV[1]
local delta_sompi = ARGV[2]
local delta_usd = ARGV[3]
local num_utxos = tonumber(ARGV[4])

if redis.call('GET', idemp_key) == 'IN_FLIGHT' then
    redis.call('DEL', idemp_key)
end

local cur_s = redis.call('GET', cur_s_key)
if cur_s then
    redis.call('SET', cur_s_key, sub_clamped_u128(cur_s, delta_sompi), 'KEEPTTL')
end

local cur_u = redis.call('GET', cur_u_key)
if cur_u then
    redis.call('SET', cur_u_key, sub_clamped_u128(cur_u, delta_usd), 'KEEPTTL')
end

local expected_bcast = 'BROADCASTING:' .. quote_id
for i = 1, num_utxos do
    local u_key = KEYS[3 + i]
    if redis.call('GET', u_key) == expected_bcast then
        redis.call('DEL', u_key)
    end
end

return 1
"#;

const LUA_FINALIZE_SETTLED_METRICS: &str = r#"
local function norm_u128(s)
    if not s or s == '' then return '0' end
    local stripped = string.gsub(s, '^0+', '')
    if stripped == '' then return '0' end
    return stripped
end

local function add_u128(a, b)
    a = norm_u128(a)
    b = norm_u128(b)
    local ia = string.len(a)
    local ib = string.len(b)
    local carry = 0
    local out = {}
    while ia > 0 or ib > 0 or carry > 0 do
        local da = 0
        local db = 0
        if ia > 0 then
            da = string.byte(a, ia) - 48
            ia = ia - 1
        end
        if ib > 0 then
            db = string.byte(b, ib) - 48
            ib = ib - 1
        end
        local s = da + db + carry
        carry = math.floor(s / 10)
        table.insert(out, 1, string.char((s % 10) + 48))
    end
    return norm_u128(table.concat(out))
end

local idemp_key = KEYS[1]
local wallet_fills_key = KEYS[2]
local key_fills_key = KEYS[3]
local f15_key = KEYS[4]
local key_vol_key = KEYS[5]
local anomaly_outflow_key = KEYS[6]

local settled_payload = ARGV[1]
local notional_usd_micros = ARGV[2]

redis.call('SET', idemp_key, 'SETTLED:' .. settled_payload, 'EX', 86400)
redis.call('INCR', wallet_fills_key)
redis.call('INCR', key_fills_key)

local f15 = redis.call('INCR', f15_key)
if f15 == 1 then
    redis.call('EXPIRE', f15_key, 900)
end

local prev_vol = redis.call('GET', key_vol_key) or '0'
redis.call('SET', key_vol_key, add_u128(prev_vol, notional_usd_micros))

local prev_anom = redis.call('GET', anomaly_outflow_key) or '0'
redis.call('SET', anomaly_outflow_key, add_u128(prev_anom, notional_usd_micros), 'EX', 120)

return 1
"#;

const LUA_RELEASE_ALL_LOCKS_FOR_KEY: &str = r#"
local key_quotes_set = KEYS[1]
local wallet_quotes_zset = KEYS[2]

local quote_ids = redis.call('SMEMBERS', key_quotes_set)
local released = 0

for _, qid in ipairs(quote_ids) do
    local q_key = 'perennia:agent:quote:' .. qid
    local raw = redis.call('GET', q_key)
    if raw then
        local decoded = cjson.decode(raw)
        local outs = decoded['lockedOutpoints'] or {}
        for _, out_str in ipairs(outs) do
            local lk = 'perennia:agent:utxo_lock:' .. out_str
            if redis.call('GET', lk) == qid then
                redis.call('DEL', lk)
            end
        end
        local rfq_pair = decoded['rfqPairKey']
        if rfq_pair then
            redis.call('ZREM', rfq_pair, qid)
        end
        redis.call('DEL', q_key)
        released = released + 1
    end
    redis.call('ZREM', wallet_quotes_zset, qid)
end

redis.call('DEL', key_quotes_set)
return released
"#;

#[inline]
pub fn redis_key_revoked(key_id: &str) -> String {
    format!("perennia:agent:revoked:{}", key_id)
}

#[inline]
pub fn redis_key_key_cooldown(key_id: &str) -> String {
    format!("perennia:agent:cooldown:key:{}", key_id)
}

#[inline]
pub fn redis_key_wallet_cooldown(clean_wallet: &str) -> String {
    format!("perennia:agent:cooldown:wallet:{}", clean_wallet)
}

#[inline]
pub fn compute_max_concurrent_quotes(historical_verified_fills: u64) -> u32 {
    match historical_verified_fills {
        0 => 1,
        1..=4 => 2,
        5..=19 => 4,
        20..=99 => 6,
        _ => 8,
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitVerdict {
    pub current_rpm: u64,
    pub rpm_limit: u64,
    pub rolling_quotes_15m: u64,
    pub rolling_fills_15m: u64,
    pub quote_to_fill_ratio_bps: u64,
    pub consumed_x402_credit: bool,
    pub remaining_x402_credits: u64,
}

pub enum ConsumedQuoteOutcome {
    Fresh {
        quote: Box<StoredAgentQuote>,
        spent_24h_sompi: u128,
        spent_24h_usd_micros: u128,
        consumed_hour_bucket: u64,
    },
    IdempotentReplay(Value),
}

pub async fn check_global_agent_circuit_breaker(
    redis_conn: &mut redis::aio::MultiplexedConnection,
) -> Result<(), AgentError> {
    let (cb_val, sys_cfg_raw): (Option<String>, Option<String>) = redis::pipe()
        .cmd("GET")
        .arg(REDIS_KEY_AGENT_CIRCUIT_BREAKER)
        .cmd("GET")
        .arg("perennia:treasury:system_config")
        .query_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to read Global Agent Circuit Breaker from Redis; failing closed.",
            )
        })?;

    if let Some(reason) = cb_val {
        let trimmed = reason.trim();
        if !trimmed.is_empty() && trimmed != "0" && !trimmed.eq_ignore_ascii_case("false") {
            return Err(AgentError::new(
                AgentErrorCode::CircuitBreakerTripped,
                format!(
                    "AGENT_CIRCUIT_BREAKER_TRIPPED: /api/v1/agent paused ({}). Human UI remains unaffected.",
                    trimmed
                ),
            ));
        }
    }

    if let Some(cfg_str) = sys_cfg_raw {
        if let Ok(parsed) = serde_json::from_str::<Value>(&cfg_str) {
            if parsed
                .get("outflowBreakerTripped")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                return Err(AgentError::new(
                    AgentErrorCode::CircuitBreakerTripped,
                    "SYSTEM_OUTFLOW_BREAKER_TRIPPED: Director has paused automated outflows.",
                ));
            }
        }
    }

    Ok(())
}

/// Evaluates rolling 60-second aggregate outflow and post-jitter slippage/divergence spikes.
/// Automatically trips `perennia:agent:circuit_breaker` if thresholds are breached.
pub async fn evaluate_rolling_60s_anomaly_window(
    state: &AgentGatewayState,
) -> Result<(), AgentError> {
    let mut conn = state.get_redis_conn().await?;

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let cur_b10 = now_secs / 10;

    let max_outflow_usd_micros: u128 = env::var("AGENT_ANOMALY_MAX_60S_OUTFLOW_USD_MICROS")
        .ok()
        .and_then(|s| s.trim().parse::<u128>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(DEFAULT_MAX_60S_OUTFLOW_USD_MICROS);

    let max_slippage_spikes: u64 = env::var("AGENT_ANOMALY_MAX_60S_SLIPPAGE_SPIKES")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(DEFAULT_MAX_60S_SLIPPAGE_SPIKES);

    let mut pipe = redis::pipe();
    for b in cur_b10.saturating_sub(5)..=cur_b10 {
        pipe.cmd("GET")
            .arg(format!("perennia:agent:anomaly:outflow_usd_micros:{}", b));
        pipe.cmd("GET")
            .arg(format!("perennia:agent:anomaly:slip_spikes:{}", b));
    }

    let raw_vals: Vec<Option<String>> = pipe.query_async(&mut conn).await.map_err(|_| {
        AgentError::new(
            AgentErrorCode::RedisUnavailable,
            "Redis unavailable during rolling 60s anomaly check.",
        )
    })?;

    let mut agg_outflow_usd_micros: u128 = 0;
    let mut agg_slip_spikes: u64 = 0;

    for (idx, item) in raw_vals.into_iter().enumerate() {
        if let Some(val_str) = item {
            if idx % 2 == 0 {
                if let Ok(v) = val_str.trim().parse::<u128>() {
                    agg_outflow_usd_micros = agg_outflow_usd_micros.saturating_add(v);
                }
            } else if let Ok(v) = val_str.trim().parse::<u64>() {
                agg_slip_spikes = agg_slip_spikes.saturating_add(v);
            }
        }
    }

    if agg_outflow_usd_micros > max_outflow_usd_micros {
        let reason = format!(
            "AUTO_BREAKER_60S_OUTFLOW_SPIKE: {} usd_micros exceeded {} ceiling",
            agg_outflow_usd_micros, max_outflow_usd_micros
        );
        tracing::error!("🚨 [AGENT AUTO-BREAKER] {}", reason);
        let _: redis::RedisResult<()> = redis::cmd("SETEX")
            .arg(REDIS_KEY_AGENT_CIRCUIT_BREAKER)
            .arg(300u64)
            .arg(&reason)
            .query_async(&mut conn)
            .await;
    } else if agg_slip_spikes >= max_slippage_spikes {
        let reason = format!(
            "AUTO_BREAKER_60S_SLIPPAGE_SPIKE: {} post-jitter halts exceeded {} ceiling",
            agg_slip_spikes, max_slippage_spikes
        );
        tracing::error!("🚨 [AGENT AUTO-BREAKER] {}", reason);
        let _: redis::RedisResult<()> = redis::cmd("SETEX")
            .arg(REDIS_KEY_AGENT_CIRCUIT_BREAKER)
            .arg(300u64)
            .arg(&reason)
            .query_async(&mut conn)
            .await;
    }

    Ok(())
}

pub async fn record_slippage_or_divergence_spike(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    now_secs: u64,
) {
    let bucket = now_secs / 10;
    let key = format!("perennia:agent:anomaly:slip_spikes:{}", bucket);
    let _: redis::RedisResult<()> = redis::pipe()
        .cmd("INCR")
        .arg(&key)
        .ignore()
        .cmd("EXPIRE")
        .arg(&key)
        .arg(120u64)
        .ignore()
        .query_async(redis_conn)
        .await;
}

/// Applies progressive Redis cooldown bans (`10s -> 60s -> 3600s`) scoped strictly to adversarial faults.
pub async fn record_adversarial_fault(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    key_id_opt: Option<&str>,
    clean_wallet: &str,
    fault_reason: &str,
) -> Result<u64, AgentError> {
    let strike_key = format!("perennia:agent:fault_strikes:{}", clean_wallet);
    let wallet_cd_key = redis_key_wallet_cooldown(clean_wallet);

    let script = redis::Script::new(LUA_PROGRESSIVE_FAULT_COOLDOWN);
    let mut inv = script.prepare_invoke();
    inv.key(&strike_key).key(&wallet_cd_key);

    let has_key = if let Some(kid) = key_id_opt {
        inv.key(redis_key_key_cooldown(kid));
        1u8
    } else {
        inv.key("perennia:agent:cooldown:key:_none");
        0u8
    };

    let (strikes, ban_secs): (u64, u64) = inv
        .arg(has_key)
        .arg(fault_reason)
        .invoke_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to record adversarial fault strike in Redis.",
            )
        })?;

    tracing::warn!(
        "🛡️ [AGENT FAULT COOLDOWN] Wallet: kaspa:{} | Key: {:?} | Strike #{} | Ban: {}s | Reason: {}",
        clean_wallet,
        key_id_opt,
        strikes,
        ban_secs,
        fault_reason
    );

    Ok(ban_secs)
}

/// Enforces dynamic Quote-to-Fill rate limiting per Agent Key.
/// Unfilled quotes degrade the rolling ratio and throttle quote scrapers back to baseline,
/// returning a machine-readable HTTP `402 Payment Required` (`x402`) burst-credit challenge.
pub async fn enforce_dynamic_rate_limit(
    state: &AgentGatewayState,
    redis_conn: &mut redis::aio::MultiplexedConnection,
    claims: &AgentCapabilityClaims,
    is_quote_call: bool,
) -> Result<RateLimitVerdict, AgentError> {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let minute_bucket = now_secs / 60;
    let window_15m = now_secs / 900;

    let base_rpm: u64 = match (claims.mode, is_quote_call) {
        (AgentMode::ModeA, true) => 12,
        (AgentMode::ModeA, false) => 30,
        (AgentMode::ModeB, true) => 20,
        (AgentMode::ModeB, false) => 45,
    };

    let rpm_key = format!("perennia:agent:rl:rpm:{}:{}", claims.key_id, minute_bucket);
    let q15_key = format!("perennia:agent:rl:q15:{}:{}", claims.key_id, window_15m);
    let f15_key = format!("perennia:agent:rl:f15:{}:{}", claims.key_id, window_15m);
    let x402_key = format!("perennia:agent:x402_credits:{}", claims.key_id);
    let vol_key = format!("perennia:agent:key_vol_usd_micros:{}", claims.key_id);

    let res: Vec<u64> = redis::Script::new(LUA_DYNAMIC_RATE_LIMIT_AND_X402)
        .key(&rpm_key)
        .key(&q15_key)
        .key(&f15_key)
        .key(&x402_key)
        .key(&vol_key)
        .arg(if is_quote_call { 1u8 } else { 0u8 })
        .arg(base_rpm)
        .invoke_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Redis unavailable during dynamic rate-limit evaluation.",
            )
        })?;

    let allowed = res.first().copied().unwrap_or(0) == 1;
    let current_rpm = res.get(1).copied().unwrap_or(0);
    let rpm_limit = res.get(2).copied().unwrap_or(base_rpm);
    let q_win = res.get(3).copied().unwrap_or(0);
    let f_win = res.get(4).copied().unwrap_or(0);
    let ratio_bps = res.get(5).copied().unwrap_or(10_000);
    let used_x402 = res.get(6).copied().unwrap_or(0) == 1;
    let rem_credits = res.get(7).copied().unwrap_or(0);

    if !allowed {
        let challenge = X402PaymentChallenge {
            protocol: "x402/perennia-v1".to_string(),
            key_id: claims.key_id.clone(),
            rolling_quotes_window: q_win,
            rolling_fills_window: f_win,
            quote_to_fill_ratio_bps: ratio_bps,
            current_rpm_limit: rpm_limit,
            treasury_kaspa_address: state.x402_treasury_address.clone(),
            sompi_per_burst_pack: U128Str(X402_SOMPI_PER_BURST_PACK),
            usdc_micros_per_burst_pack: U128Str(X402_USDC_MICROS_PER_BURST_PACK),
            credits_per_burst_pack: X402_CREDITS_PER_BURST_PACK,
            claim_endpoint: "/api/v1/agent/auth/x402/claim".to_string(),
            challenge_memo: format!("X402:{}", claims.key_id),
        };
        return Err(AgentError::with_x402(
            challenge,
            "Dynamic quote-to-fill rate limit reached; execute fills to scale organic RPM or top up x402 burst credits.",
        ));
    }

    Ok(RateLimitVerdict {
        current_rpm,
        rpm_limit,
        rolling_quotes_15m: q_win,
        rolling_fills_15m: f_win,
        quote_to_fill_ratio_bps: ratio_bps,
        consumed_x402_credit: used_x402,
        remaining_x402_credits: rem_credits,
    })
}

pub async fn resolve_wallet_concurrency_limit(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    clean_wallet: &str,
) -> Result<(u64, u32), AgentError> {
    let fills_str: Option<String> = redis::cmd("GET")
        .arg(format!("perennia:agent:wallet_fills:{}", clean_wallet))
        .query_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Redis unavailable while resolving wallet fill concurrency tier.",
            )
        })?;

    let fills = fills_str
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    Ok((fills, compute_max_concurrent_quotes(fills)))
}

pub async fn read_rolling_24h_spend(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    key_id: &str,
    now_secs: u64,
) -> Result<(u128, u128), AgentError> {
    let cur_hour = now_secs / 3_600;
    let mut pipe = redis::pipe();
    for h in cur_hour.saturating_sub(23)..=cur_hour {
        pipe.cmd("GET")
            .arg(format!("perennia:agent:spend_sompi:{}:{}", key_id, h));
        pipe.cmd("GET")
            .arg(format!("perennia:agent:spend_usd:{}:{}", key_id, h));
    }

    let vals: Vec<Option<String>> = pipe.query_async(redis_conn).await.map_err(|_| {
        AgentError::new(
            AgentErrorCode::RedisUnavailable,
            "Failed to read rolling 24h Mandate spend counters from Redis.",
        )
    })?;

    let mut total_sompi: u128 = 0;
    let mut total_usd_micros: u128 = 0;

    for (idx, item) in vals.into_iter().enumerate() {
        if let Some(raw) = item {
            if let Ok(parsed) = raw.trim().parse::<u128>() {
                if idx % 2 == 0 {
                    total_sompi = total_sompi.saturating_add(parsed);
                } else {
                    total_usd_micros = total_usd_micros.saturating_add(parsed);
                }
            }
        }
    }

    Ok((total_sompi, total_usd_micros))
}

pub async fn check_mandate_24h_headroom_readonly(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    claims: &AgentCapabilityClaims,
    delta_sompi: u128,
    delta_usd_micros: u128,
    now_secs: u64,
) -> Result<(u128, u128), AgentError> {
    let (spent_sompi, spent_usd) =
        read_rolling_24h_spend(redis_conn, &claims.key_id, now_secs).await?;

    let next_sompi = spent_sompi.checked_add(delta_sompi).ok_or_else(|| {
        AgentError::new(
            AgentErrorCode::MandateViolation,
            "24h sompi spend arithmetic overflow.",
        )
    })?;
    let next_usd = spent_usd.checked_add(delta_usd_micros).ok_or_else(|| {
        AgentError::new(
            AgentErrorCode::MandateViolation,
            "24h USD micro spend arithmetic overflow.",
        )
    })?;

    if claims.cap_24h_sompi.as_u128() > 0 && next_sompi > claims.cap_24h_sompi.as_u128() {
        return Err(AgentError::new(
            AgentErrorCode::MandateViolation,
            format!(
                "Mandate 24h KAS cap exceeded: spent {} + requested {} > {} sompi cap.",
                spent_sompi, delta_sompi, claims.cap_24h_sompi
            ),
        ));
    }

    if claims.cap_24h_usd_micros.as_u128() > 0 && next_usd > claims.cap_24h_usd_micros.as_u128() {
        return Err(AgentError::new(
            AgentErrorCode::MandateViolation,
            format!(
                "Mandate 24h USD cap exceeded: spent {} + requested {} > {} micro-USD cap.",
                spent_usd, delta_usd_micros, claims.cap_24h_usd_micros
            ),
        ));
    }

    Ok((spent_sompi, spent_usd))
}

pub async fn acquire_quote_and_utxo_locks(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    claims: &AgentCapabilityClaims,
    stored_quote: &StoredAgentQuote,
    max_concurrent_quotes: u32,
) -> Result<u32, AgentError> {
    let wallet_quotes_zset =
        format!("perennia:agent:wallet_active_quotes:{}", claims.clean_wallet);
    let key_quotes_set = format!("perennia:agent:key_active_quotes:{}", claims.key_id);
    let quote_redis_key = format!("perennia:agent:quote:{}", stored_quote.quote_id);

    let quote_json = serde_json::to_string(stored_quote).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            "Failed to serialize deterministic quote state.",
        )
    })?;

    let ttl_ms = stored_quote.ttl_secs.saturating_mul(1_000).max(1_000);
    let cur_hour = (stored_quote.created_at_ms / 1_000) / 3_600;

    let script = redis::Script::new(LUA_ACQUIRE_QUOTE_AND_UTXO_LOCKS);
    let mut inv = script.prepare_invoke();
    inv.key(&wallet_quotes_zset)
        .key(&key_quotes_set)
        .key(&quote_redis_key);

    for out_str in &stored_quote.locked_outpoints {
        inv.key(format!("perennia:agent:utxo_lock:{}", out_str));
    }

    let resp: Vec<String> = inv
        .arg(&stored_quote.quote_id)
        .arg(&quote_json)
        .arg(stored_quote.created_at_ms)
        .arg(stored_quote.expires_at_ms)
        .arg(ttl_ms)
        .arg(max_concurrent_quotes)
        .arg(claims.cap_24h_sompi.to_string())
        .arg(claims.cap_24h_usd_micros.to_string())
        .arg(stored_quote.spend_sompi_equiv.to_string())
        .arg(stored_quote.notional_usd_micros.to_string())
        .arg(&claims.key_id)
        .arg(cur_hour)
        .arg(stored_quote.locked_outpoints.len())
        .invoke_async(redis_conn)
        .await
        .map_err(|e| {
            tracing::error!("🚨 [AGENT LUA LOCK] Redis Lua error: {}", e);
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to execute atomic UTXO & quote lock script in Redis.",
            )
        })?;

    match resp.first().map(|s| s.as_str()) {
        Some("OK") => {
            let active = resp
                .get(1)
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(1);
            Ok(active)
        }
        Some("ERR_CONCURRENCY_CAP") => Err(AgentError::new(
            AgentErrorCode::ConcurrencyCapReached,
            format!(
                "Fill-earned concurrency limit reached ({}/{} active locked quotes). Settle active quotes to unlock up to 8 parallel UTXO lanes.",
                resp.get(1).cloned().unwrap_or_default(),
                max_concurrent_quotes
            ),
        )),
        Some("ERR_UTXO_LOCKED") => Err(AgentError::new(
            AgentErrorCode::UtxoContentionLocked,
            format!(
                "Requested UTXO outpoint is already locked by an in-flight quote ({}). Split wallet into 4-8 non-overlapping UTXO lanes.",
                resp.get(1).cloned().unwrap_or_default()
            ),
        )),
        Some("ERR_CAP_SOMPI") => Err(AgentError::new(
            AgentErrorCode::MandateViolation,
            format!(
                "Rolling 24h KAS Mandate cap exceeded (spent {} sompi of {} sompi ceiling).",
                resp.get(1).cloned().unwrap_or_default(),
                resp.get(2).cloned().unwrap_or_default()
            ),
        )),
        Some("ERR_CAP_USD") => Err(AgentError::new(
            AgentErrorCode::MandateViolation,
            format!(
                "Rolling 24h USD Mandate cap exceeded (spent {} micro-USD of {} micro-USD ceiling).",
                resp.get(1).cloned().unwrap_or_default(),
                resp.get(2).cloned().unwrap_or_default()
            ),
        )),
        _ => Err(AgentError::new(
            AgentErrorCode::RedisUnavailable,
            "Unexpected response from atomic quote lock script.",
        )),
    }
}

pub async fn consume_quote_utxos_and_mandate_cap_atomic(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    claims: &AgentCapabilityClaims,
    quote_id: &str,
    idempotency_key: &str,
    now_ms: u64,
) -> Result<ConsumedQuoteOutcome, AgentError> {
    let idemp_redis_key = format!(
        "perennia:agent:idemp:{}:{}",
        claims.clean_wallet, idempotency_key
    );
    let revoked_key = redis_key_revoked(&claims.key_id);
    let quote_key = format!("perennia:agent:quote:{}", quote_id);
    let wallet_quotes_zset =
        format!("perennia:agent:wallet_active_quotes:{}", claims.clean_wallet);
    let key_quotes_set = format!("perennia:agent:key_active_quotes:{}", claims.key_id);
    let cur_hour = (now_ms / 1_000) / 3_600;

    let resp: Vec<String> = redis::Script::new(LUA_CONSUME_QUOTE_UTXOS_AND_MANDATE_ATOMIC)
        .key(&idemp_redis_key)
        .key(&revoked_key)
        .key(&quote_key)
        .key(&wallet_quotes_zset)
        .key(&key_quotes_set)
        .arg(&claims.key_id)
        .arg(quote_id)
        .arg(now_ms)
        .arg(cur_hour)
        .arg(claims.cap_24h_sompi.to_string())
        .arg(claims.cap_24h_usd_micros.to_string())
        .invoke_async(redis_conn)
        .await
        .map_err(|e| {
            tracing::error!("🚨 [AGENT EXECUTE LUA] Redis Lua error: {}", e);
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to execute atomic quote & Mandate consumption in Redis.",
            )
        })?;

    match resp.first().map(|s| s.as_str()) {
        Some("IDEMPOTENT_REPLAY") => {
            let raw_receipt = resp.get(1).cloned().unwrap_or_else(|| "{}".to_string());
            let parsed: Value = serde_json::from_str(&raw_receipt).map_err(|_| {
                AgentError::new(
                    AgentErrorCode::RedisUnavailable,
                    "Stored idempotent receipt JSON was unreadable.",
                )
            })?;
            Ok(ConsumedQuoteOutcome::IdempotentReplay(parsed))
        }
        Some("ERR_IDEMPOTENCY_IN_FLIGHT") => Err(AgentError::new(
            AgentErrorCode::IdempotencyConflict,
            "An execution with this idempotencyKey is currently IN_FLIGHT.",
        )),
        Some("ERR_KEY_REVOKED") => Err(AgentError::new(
            AgentErrorCode::KeyRevoked,
            "Agent capability key was revoked via Kill Switch before broadcast.",
        )),
        Some("ERR_QUOTE_EXPIRED") => Err(AgentError::new(
            AgentErrorCode::QuoteExpiredOrNotFound,
            "Quote expired or was already consumed (5s Taker TTL enforced).",
        )),
        Some("ERR_KEY_MISMATCH") => {
            let ban_secs = record_adversarial_fault(
                redis_conn,
                Some(&claims.key_id),
                &claims.clean_wallet,
                "CROSS_KEY_QUOTE_HIJACK_ATTEMPT",
            )
            .await?;
            Err(AgentError::with_cooldown(
                ban_secs,
                "Quote belongs to a different Agent Key; fault cooldown applied.",
            ))
        }
        Some("ERR_UTXO_LOCK_LOST") => Err(AgentError::new(
            AgentErrorCode::UtxoContentionLocked,
            format!(
                "UTXO outpoint lock expired or was superseded ({}). Request a fresh quote.",
                resp.get(1).cloned().unwrap_or_default()
            ),
        )),
        Some("ERR_CAP_SOMPI") => Err(AgentError::new(
            AgentErrorCode::MandateViolation,
            format!(
                "Rolling 24h KAS Mandate cap exceeded (spent {} of {} sompi).",
                resp.get(1).cloned().unwrap_or_default(),
                resp.get(2).cloned().unwrap_or_default()
            ),
        )),
        Some("ERR_CAP_USD") => Err(AgentError::new(
            AgentErrorCode::MandateViolation,
            format!(
                "Rolling 24h USD Mandate cap exceeded (spent {} of {} micro-USD).",
                resp.get(1).cloned().unwrap_or_default(),
                resp.get(2).cloned().unwrap_or_default()
            ),
        )),
        Some("OK") => {
            let raw_quote = resp.get(1).ok_or_else(|| {
                AgentError::new(
                    AgentErrorCode::RedisUnavailable,
                    "Missing quote payload from atomic Lua script.",
                )
            })?;
            let quote: StoredAgentQuote = serde_json::from_str(raw_quote).map_err(|_| {
                AgentError::new(
                    AgentErrorCode::RedisUnavailable,
                    "Failed to decode StoredAgentQuote from Redis.",
                )
            })?;
            let spent_s = resp
                .get(2)
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(0);
            let spent_u = resp
                .get(3)
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(0);
            let bucket_h = resp
                .get(4)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(cur_hour);

            Ok(ConsumedQuoteOutcome::Fresh {
                quote: Box::new(quote),
                spent_24h_sompi: spent_s,
                spent_24h_usd_micros: spent_u,
                consumed_hour_bucket: bucket_h,
            })
        }
        _ => Err(AgentError::new(
            AgentErrorCode::RedisUnavailable,
            "Unexpected response from atomic quote consumption script.",
        )),
    }
}

pub async fn rollback_consumed_mandate_on_failure(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    claims: &AgentCapabilityClaims,
    quote: &StoredAgentQuote,
    idempotency_key: &str,
    consumed_hour_bucket: u64,
) -> Result<(), AgentError> {
    let idemp_redis_key = format!(
        "perennia:agent:idemp:{}:{}",
        claims.clean_wallet, idempotency_key
    );
    let cur_s_key = format!(
        "perennia:agent:spend_sompi:{}:{}",
        claims.key_id, consumed_hour_bucket
    );
    let cur_u_key = format!(
        "perennia:agent:spend_usd:{}:{}",
        claims.key_id, consumed_hour_bucket
    );

    let script = redis::Script::new(LUA_ROLLBACK_FAILED_EXECUTION);
    let mut inv = script.prepare_invoke();
    inv.key(&idemp_redis_key).key(&cur_s_key).key(&cur_u_key);

    for out_str in &quote.locked_outpoints {
        inv.key(format!("perennia:agent:utxo_lock:{}", out_str));
    }

    let _: i32 = inv
        .arg(&quote.quote_id)
        .arg(quote.spend_sompi_equiv.to_string())
        .arg(quote.notional_usd_micros.to_string())
        .arg(quote.locked_outpoints.len())
        .invoke_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to roll back Mandate spend counters after aborted execution.",
            )
        })?;

    Ok(())
}

pub async fn finalize_settled_execution_metrics(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    claims: &AgentCapabilityClaims,
    idempotency_key: &str,
    notional_usd_micros: u128,
    receipt_json: &Value,
    now_secs: u64,
) -> Result<(), AgentError> {
    let idemp_redis_key = format!(
        "perennia:agent:idemp:{}:{}",
        claims.clean_wallet, idempotency_key
    );
    let wallet_fills_key = format!("perennia:agent:wallet_fills:{}", claims.clean_wallet);
    let key_fills_key = format!("perennia:agent:key_fills:{}", claims.key_id);
    let window_15m = now_secs / 900;
    let f15_key = format!("perennia:agent:rl:f15:{}:{}", claims.key_id, window_15m);
    let key_vol_key = format!("perennia:agent:key_vol_usd_micros:{}", claims.key_id);
    let anomaly_bucket = now_secs / 10;
    let anomaly_outflow_key = format!(
        "perennia:agent:anomaly:outflow_usd_micros:{}",
        anomaly_bucket
    );

    let serialized_receipt = serde_json::to_string(receipt_json).unwrap_or_else(|_| "{}".to_string());

    let _: i32 = redis::Script::new(LUA_FINALIZE_SETTLED_METRICS)
        .key(&idemp_redis_key)
        .key(&wallet_fills_key)
        .key(&key_fills_key)
        .key(&f15_key)
        .key(&key_vol_key)
        .key(&anomaly_outflow_key)
        .arg(serialized_receipt)
        .arg(notional_usd_micros.to_string())
        .invoke_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to finalize settled Agent metrics in Redis.",
            )
        })?;

    Ok(())
}

pub async fn release_all_locks_for_key(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    key_id: &str,
    clean_wallet: &str,
) -> Result<u64, AgentError> {
    let key_quotes_set = format!("perennia:agent:key_active_quotes:{}", key_id);
    let wallet_quotes_zset = format!("perennia:agent:wallet_active_quotes:{}", clean_wallet);

    let released: u64 = redis::Script::new(LUA_RELEASE_ALL_LOCKS_FOR_KEY)
        .key(&key_quotes_set)
        .key(&wallet_quotes_zset)
        .invoke_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to release active locks during Kill Switch revocation.",
            )
        })?;

    Ok(released)
}

/// Computes wallet UTXO parallel lane health (targeting 4–8 clean confirmed UTXO lanes).
pub async fn inspect_utxo_lane_health(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    clean_wallet: &str,
    raw_utxos: &[Value],
    virtual_daa_score: u64,
) -> Result<UtxoLaneHealth, AgentError> {
    let (_, max_concurrent_quotes) =
        resolve_wallet_concurrency_limit(redis_conn, clean_wallet).await?;

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let wallet_quotes_zset = format!("perennia:agent:wallet_active_quotes:{}", clean_wallet);

    let (_, active_wallet_quotes): (u64, u32) = redis::pipe()
        .cmd("ZREMRANGEBYSCORE")
        .arg(&wallet_quotes_zset)
        .arg("-inf")
        .arg(now_ms.saturating_sub(1))
        .cmd("ZCARD")
        .arg(&wallet_quotes_zset)
        .query_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to inspect active wallet quote lanes in Redis.",
            )
        })?;

    let mut total_utxo_count: u32 = 0;
    let mut confirmed_clean_lanes: u32 = 0;
    let mut dust_utxo_count: u32 = 0;
    let mut candidate_outpoints: Vec<String> = Vec::new();

    for entry in raw_utxos {
        let txid = entry
            .get("outpoint")
            .and_then(|o| o.get("transactionId"))
            .or_else(|| entry.get("transactionId"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if txid.len() != 64 {
            continue;
        }
        let vout = entry
            .get("outpoint")
            .and_then(|o| o.get("index"))
            .or_else(|| entry.get("index"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let amt_sompi = entry
            .get("utxoEntry")
            .and_then(|u| u.get("amount"))
            .or_else(|| entry.get("amount"))
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            })
            .unwrap_or(0);
        let block_daa = entry
            .get("utxoEntry")
            .and_then(|u| u.get("blockDaaScore"))
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            })
            .unwrap_or(0);
        let is_coinbase = entry
            .get("utxoEntry")
            .and_then(|u| u.get("isCoinbase"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        total_utxo_count = total_utxo_count.saturating_add(1);
        candidate_outpoints.push(format!("perennia:agent:utxo_lock:{}:{}", txid.to_ascii_lowercase(), vout));

        if amt_sompi < DUST_UTXO_THRESHOLD_SOMPI {
            dust_utxo_count = dust_utxo_count.saturating_add(1);
        } else {
            let min_daa_depth = if is_coinbase { 100 } else { 10 };
            let confirmed = virtual_daa_score > 0
                && block_daa > 0
                && virtual_daa_score.saturating_sub(block_daa) >= min_daa_depth;
            if confirmed {
                confirmed_clean_lanes = confirmed_clean_lanes.saturating_add(1);
            }
        }
    }

    let locked_outpoint_count: u32 = if candidate_outpoints.is_empty() {
        0
    } else {
        let mut pipe = redis::pipe();
        for lk in &candidate_outpoints {
            pipe.cmd("EXISTS").arg(lk);
        }
        let flags: Vec<u32> = pipe.query_async(redis_conn).await.unwrap_or_default();
        flags.into_iter().sum()
    };

    let lane_status = if confirmed_clean_lanes == 0 {
        "NO_CONFIRMED_LANES".to_string()
    } else if confirmed_clean_lanes == 1 {
        "SINGLE_UTXO_CONTENTION_RISK".to_string()
    } else if dust_utxo_count > 16 {
        "DUST_BLOAT_COMPACTION_RECOMMENDED".to_string()
    } else if (4..=8).contains(&confirmed_clean_lanes) {
        "OPTIMAL_PARALLEL_LANES".to_string()
    } else if confirmed_clean_lanes < 4 {
        "SUBOPTIMAL_SPLIT_TO_4_8_LANES".to_string()
    } else {
        "HEALTHY_MULTI_LANE".to_string()
    };

    Ok(UtxoLaneHealth {
        total_utxo_count,
        confirmed_clean_lanes,
        dust_utxo_count,
        locked_outpoint_count,
        active_wallet_quotes,
        max_concurrent_quotes,
        recommended_target_lanes_min: 4,
        recommended_target_lanes_max: 8,
        lane_status,
    })
}

// ============================================================================
// x402 ON-CHAIN BURST CREDIT CLAIM & DIRECTOR CIRCUIT-BREAKER ENDPOINTS
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402CreditClaimRequest {
    pub payment_txid: String,
    #[serde(default)]
    pub vout: Option<u32>,
}

/// Verifies a confirmed Kaspa L1 payment UTXO on `state.x402_treasury_address` via `kaspad` gRPC
/// and atomically grants `x402` burst credits (`100` calls per `5,000,000` sompi) with SQL replay protection.
pub async fn handle_x402_credit_claim(
    State(state): State<AgentGatewayState>,
    headers: HeaderMap,
    Json(req): Json<X402CreditClaimRequest>,
) -> Result<Json<Value>, AgentError> {
    let mut conn = state.get_redis_conn().await?;
    let claims = authenticate_agent_request(&state, &headers, &mut conn).await?;
    let payment_txid = validate_hex_64(&req.payment_txid, "paymentTxid")?;

    let virtual_daa_str: Option<String> = redis::cmd("GET")
        .arg("pool:virtual_daa_score")
        .query_async(&mut conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to read virtual DAA score from Redis.",
            )
        })?;
    let virtual_daa = virtual_daa_str
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&d| d > 0)
        .ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::NodeUnavailable,
                "kaspad virtual DAA score unavailable; failing closed.",
            )
        })?;

    let treasury_utxos =
        crate::kaspad_client::get_utxos_by_address_grpc(&state.x402_treasury_address)
            .await
            .map_err(|_| {
                AgentError::new(
                    AgentErrorCode::NodeUnavailable,
                    "kaspad gRPC unavailable while verifying x402 payment UTXO.",
                )
            })?;

    let (_, expected_hash32) = decode_kaspa_address_payload(&state.x402_treasury_address)
        .ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::NodeUnavailable,
                "Configured x402 treasury address failed Bech32m decode.",
            )
        })?;
    let expected_p2pk_spk = format!("20{}ac", hex::encode(expected_hash32));

    let mut verified_sompi: u128 = 0;
    let mut verified_daa: u64 = 0;

    for entry in treasury_utxos {
        let txid = entry
            .get("outpoint")
            .and_then(|o| o.get("transactionId"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if txid != payment_txid {
            continue;
        }
        let idx = entry
            .get("outpoint")
            .and_then(|o| o.get("index"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        if let Some(req_vout) = req.vout {
            if idx != req_vout {
                continue;
            }
        }
        let spk_hex = entry
            .get("utxoEntry")
            .and_then(|u| u.get("scriptPublicKey"))
            .and_then(|s| s.get("scriptPublicKey"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if spk_hex != expected_p2pk_spk {
            continue;
        }
        let block_daa = entry
            .get("utxoEntry")
            .and_then(|u| u.get("blockDaaScore"))
            .and_then(|v| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            .unwrap_or(0);
        if block_daa == 0 || virtual_daa.saturating_sub(block_daa) < MIN_X402_DAA_CONFIRMATIONS {
            return Err(AgentError::new(
                AgentErrorCode::UnconfirmedParentUtxo,
                format!(
                    "x402 payment UTXO requires at least {} DAA confirmations (current depth: {}).",
                    MIN_X402_DAA_CONFIRMATIONS,
                    virtual_daa.saturating_sub(block_daa)
                ),
            ));
        }
        let amt = entry
            .get("utxoEntry")
            .and_then(|u| u.get("amount"))
            .and_then(|v| v.as_str().and_then(|s| s.parse::<u128>().ok()))
            .unwrap_or(0);
        verified_sompi = verified_sompi.saturating_add(amt);
        verified_daa = block_daa;
    }

    if verified_sompi < X402_SOMPI_PER_BURST_PACK {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            format!(
                "Verified x402 payment on {} is {} sompi (minimum {} sompi required per burst pack).",
                state.x402_treasury_address, verified_sompi, X402_SOMPI_PER_BURST_PACK
            ),
        ));
    }

    let packs = (verified_sompi / X402_SOMPI_PER_BURST_PACK).min(10_000) as u64;
    let credits_granted = packs.saturating_mul(X402_CREDITS_PER_BURST_PACK);

    let insert_res = sqlx::query(
        r#"
        INSERT INTO agent_x402_credits (
            payment_txid, key_id, wallet_address, paid_asset,
            paid_atomic, credits_granted, verified_daa_score
        ) VALUES ($1, $2, $3, 'KAS', $4::NUMERIC(39, 0), $5, $6)
        "#,
    )
    .bind(&payment_txid)
    .bind(&claims.key_id)
    .bind(&claims.prefixed_wallet)
    .bind(verified_sompi.to_string())
    .bind(credits_granted as i64)
    .bind(verified_daa as i64)
    .execute(&state.pg_pool)
    .await;

    if insert_res.is_err() {
        return Err(AgentError::new(
            AgentErrorCode::IdempotencyConflict,
            "paymentTxid was already claimed or database rejected replay.",
        ));
    }

    let total_credits: u64 = redis::cmd("INCRBY")
        .arg(format!("perennia:agent:x402_credits:{}", claims.key_id))
        .arg(credits_granted)
        .query_async(&mut conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to credit x402 burst balance in Redis.",
            )
        })?;

    Ok(Json(json!({
        "ok": true,
        "keyId": claims.key_id,
        "paymentTxid": payment_txid,
        "verifiedSompi": verified_sompi.to_string(),
        "creditsGranted": credits_granted.to_string(),
        "totalAvailableCredits": total_credits.to_string()
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InternalCircuitBreakerRequest {
    pub paused: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

pub async fn handle_internal_circuit_breaker_toggle(
    State(state): State<AgentGatewayState>,
    Json(req): Json<InternalCircuitBreakerRequest>,
) -> Result<Json<Value>, AgentError> {
    let mut conn = state.get_redis_conn().await?;

    if req.paused {
        let reason = req
            .reason
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("MANUAL_DIRECTOR_PAUSE");
        if let Some(ttl) = req.ttl_seconds.filter(|&t| t > 0) {
            redis::cmd("SETEX")
                .arg(REDIS_KEY_AGENT_CIRCUIT_BREAKER)
                .arg(ttl)
                .arg(reason)
                .query_async::<_, ()>(&mut conn)
                .await
                .map_err(|_| {
                    AgentError::new(
                        AgentErrorCode::RedisUnavailable,
                        "Failed to set Agent circuit breaker in Redis.",
                    )
                })?;
        } else {
            redis::cmd("SET")
                .arg(REDIS_KEY_AGENT_CIRCUIT_BREAKER)
                .arg(reason)
                .query_async::<_, ()>(&mut conn)
                .await
                .map_err(|_| {
                    AgentError::new(
                        AgentErrorCode::RedisUnavailable,
                        "Failed to set Agent circuit breaker in Redis.",
                    )
                })?;
        }
        Ok(Json(json!({
            "ok": true,
            "agentCircuitBreakerPaused": true,
            "reason": reason
        })))
    } else {
        redis::cmd("DEL")
            .arg(REDIS_KEY_AGENT_CIRCUIT_BREAKER)
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|_| {
                AgentError::new(
                    AgentErrorCode::RedisUnavailable,
                    "Failed to clear Agent circuit breaker in Redis.",
                )
            })?;
        Ok(Json(json!({
            "ok": true,
            "agentCircuitBreakerPaused": false
        })))
    }
}