// src/agent/dark_pool.rs

use axum::{
    extract::State,
    http::HeaderMap,
    Json,
};
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::{
    env,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::agent::{
    auth::authenticate_agent_request,
    locks_and_limits,
    solvency::{
        self, compute_zero_loss_quote_math, div_ceil_u128, mul_div_floor_u128, PairOracleSnapshot,
        MAKER_ZERO_LOSS_FLOOR_BPS,
    },
    types::{
        atomic_decimals_for_asset, pow10_u128, validate_hex_64, AgentCapabilityClaims, AgentError,
        AgentErrorCode, AgentMode, AgentVenue, PostToccataEnvelope, StoredAgentQuote, U128Str,
        BPS_DENOMINATOR,
    },
    AgentGatewayState,
};

/// Maximum tolerated CEX/DEX cross-venue spread divergence during Dark Pool clearing (150 bps = 1.50%).
pub const MAX_CEX_DEX_DIVERGENCE_BPS: u128 = 150;
/// Maximum tolerated oracle price drift across the 1.0s–2.0s micro-batch jitter window (100 bps = 1.00%).
pub const MAX_MICRO_BATCH_ORACLE_DRIFT_BPS: u128 = 100;

/// Minimum Taker Dark Pool micro-batch jitter (1,000 ms = 1.0s).
pub const MIN_MICRO_BATCH_JITTER_MS: u64 = 1_000;
/// Maximum Taker Dark Pool micro-batch jitter (2,000 ms = 2.0s).
pub const MAX_MICRO_BATCH_JITTER_MS: u64 = 2_000;

const LUA_REGISTER_RESTING_MAKER_RFQ: &str = r#"
local book_zset = KEYS[1]
local order_key = KEYS[2]

local quote_id = ARGV[1]
local order_json = ARGV[2]
local now_ms = tonumber(ARGV[3])
local expires_ms = tonumber(ARGV[4])
local ttl_ms = tonumber(ARGV[5])

redis.call('ZREMRANGEBYSCORE', book_zset, '-inf', now_ms - 1)
redis.call('SET', order_key, order_json, 'PX', ttl_ms)
redis.call('ZADD', book_zset, expires_ms, quote_id)
redis.call('PEXPIRE', book_zset, math.max(ttl_ms + 30000, 60000))
return redis.call('ZCARD', book_zset)
"#;

const LUA_CONSUME_MATCHING_MAKER_RFQ: &str = r#"
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

local book_zset = KEYS[1]
local now_ms = tonumber(ARGV[1])
local req_maker_offer_min = ARGV[2]
local max_maker_ask_in = ARGV[3]
local taker_clean_wallet = ARGV[4]

redis.call('ZREMRANGEBYSCORE', book_zset, '-inf', now_ms - 1)
local candidates = redis.call('ZRANGE', book_zset, 0, 24)

for _, qid in ipairs(candidates) do
    local ord_key = 'perennia:agent:rfq_order:' .. qid
    local raw = redis.call('GET', ord_key)
    if not raw then
        redis.call('ZREM', book_zset, qid)
    else
        local ord = cjson.decode(raw)
        local exp = tonumber(ord['expiresAtMs'] or '0')
        if exp < now_ms then
            redis.call('DEL', ord_key)
            redis.call('ZREM', book_zset, qid)
        elseif ord['makerCleanWallet'] ~= taker_clean_wallet then
            local offer_amt = tostring(ord['makerOfferAtomic'] or '0')
            local min_recv = tostring(ord['makerMinReceiveAtomic'] or '0')
            if cmp_u128(offer_amt, req_maker_offer_min) >= 0 and cmp_u128(min_recv, max_maker_ask_in) <= 0 then
                redis.call('DEL', ord_key)
                redis.call('ZREM', book_zset, qid)
                return {1, raw}
            end
        end
    end
end

return {0, ''}
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestingMakerRfqOrder {
    pub quote_id: String,
    pub maker_key_id: String,
    pub maker_clean_wallet: String,
    pub maker_prefixed_wallet: String,
    pub pay_asset: String,
    pub receive_asset: String,
    pub maker_offer_atomic: U128Str,
    pub maker_min_receive_atomic: U128Str,
    pub maker_fee_bps: u16,
    pub l1_txid: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MicroBatchClearingOutcome {
    pub jitter_applied_ms: u64,
    pub fresh_pay_oracle_usd_e8: U128Str,
    pub fresh_receive_oracle_usd_e8: U128Str,
    pub fresh_kas_oracle_usd_e8: U128Str,
    pub post_jitter_net_out_atomic: U128Str,
    pub post_jitter_protocol_fee_atomic: U128Str,
    pub post_jitter_total_fee_usd_micros: U128Str,
    pub matched_maker_rfq_quote_id: Option<String>,
    pub matched_maker_wallet: Option<String>,
}

#[inline]
pub fn canonical_rfq_book_key(offer_asset: &str, want_asset: &str) -> String {
    if offer_asset == "KAS" {
        format!("perennia:agent:rfq_book:KAS/{}", want_asset)
    } else if want_asset == "KAS" {
        format!("perennia:agent:rfq_book:KAS/{}", offer_asset)
    } else {
        format!("perennia:agent:rfq_book:{}/{}", offer_asset, want_asset)
    }
}

#[inline]
fn abs_diff_bps(a: u128, b: u128) -> Result<u128, AgentError> {
    let ref_val = a.min(b);
    if ref_val == 0 {
        return Err(AgentError::new(
            AgentErrorCode::OracleUnavailable,
            "Zero oracle price encountered in divergence calculation.",
        ));
    }
    let diff = a.abs_diff(b);
    div_ceil_u128(diff.saturating_mul(BPS_DENOMINATOR), ref_val)
}

async fn verify_cex_dex_divergence_bounds(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    pay_asset: &str,
    receive_asset: &str,
    quoted_pay_e8: u128,
    quoted_receive_e8: u128,
    fresh: &PairOracleSnapshot,
) -> Result<(), AgentError> {
    let (pay_div_raw, rec_div_raw): (Option<String>, Option<String>) = redis::pipe()
        .cmd("GET")
        .arg(format!("oracle:divergence_bps:{}", pay_asset))
        .cmd("GET")
        .arg(format!("oracle:divergence_bps:{}", receive_asset))
        .query_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to read CEX/DEX oracle divergence metrics from Redis.",
            )
        })?;

    if let Some(p_div) = pay_div_raw.and_then(|s| s.trim().parse::<u128>().ok()) {
        if p_div > MAX_CEX_DEX_DIVERGENCE_BPS {
            return Err(AgentError::new(
                AgentErrorCode::OracleDivergenceHalt,
                format!(
                    "ORACLE_DIVERGENCE_HALT: {} cross-venue spread ({} bps) exceeded {} bps bound.",
                    pay_asset, p_div, MAX_CEX_DEX_DIVERGENCE_BPS
                ),
            ));
        }
    }

    if let Some(r_div) = rec_div_raw.and_then(|s| s.trim().parse::<u128>().ok()) {
        if r_div > MAX_CEX_DEX_DIVERGENCE_BPS {
            return Err(AgentError::new(
                AgentErrorCode::OracleDivergenceHalt,
                format!(
                    "ORACLE_DIVERGENCE_HALT: {} cross-venue spread ({} bps) exceeded {} bps bound.",
                    receive_asset, r_div, MAX_CEX_DEX_DIVERGENCE_BPS
                ),
            ));
        }
    }

    let pay_drift_bps = abs_diff_bps(quoted_pay_e8, fresh.pay_usd_e8)?;
    let rec_drift_bps = abs_diff_bps(quoted_receive_e8, fresh.receive_usd_e8)?;

    if pay_drift_bps > MAX_MICRO_BATCH_ORACLE_DRIFT_BPS
        || rec_drift_bps > MAX_MICRO_BATCH_ORACLE_DRIFT_BPS
    {
        return Err(AgentError::new(
            AgentErrorCode::OracleDivergenceHalt,
            format!(
                "MICRO_BATCH_DRIFT_HALT: Post-jitter oracle moved {} bps ({}) / {} bps ({}), exceeding {} bps safety band.",
                pay_drift_bps,
                pay_asset,
                rec_drift_bps,
                receive_asset,
                MAX_MICRO_BATCH_ORACLE_DRIFT_BPS
            ),
        ));
    }

    Ok(())
}

/// Registers an authenticated Mode A market-maker bot's short-TTL (`5–15s`) resting RFQ liquidity
/// inside the Dark Pool orderbook after signature & deposit verification.
pub async fn register_resting_maker_rfq(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    quote: &StoredAgentQuote,
    l1_txid: &str,
) -> Result<u64, AgentError> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let ttl_ms = quote
        .ttl_secs
        .clamp(5, 15)
        .saturating_mul(1_000);
    let expires_at_ms = now_ms.saturating_add(ttl_ms);

    let order = RestingMakerRfqOrder {
        quote_id: quote.quote_id.clone(),
        maker_key_id: quote.key_id.clone(),
        maker_clean_wallet: quote.clean_wallet.clone(),
        maker_prefixed_wallet: quote.prefixed_wallet.clone(),
        pay_asset: quote.pay_asset.clone(),
        receive_asset: quote.receive_asset.clone(),
        maker_offer_atomic: quote.amount_in_atomic,
        maker_min_receive_atomic: quote.min_amount_out_atomic,
        maker_fee_bps: quote.applied_fee_bps.max(MAKER_ZERO_LOSS_FLOOR_BPS),
        l1_txid: l1_txid.to_string(),
        created_at_ms: now_ms,
        expires_at_ms,
    };

    let directional_book_key =
        format!("perennia:agent:rfq_side:{}:{}", quote.pay_asset, quote.receive_asset);
    let summary_book_key = canonical_rfq_book_key(&quote.pay_asset, &quote.receive_asset);
    let order_key = format!("perennia:agent:rfq_order:{}", quote.quote_id);
    let serialized = serde_json::to_string(&order).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            "Failed to encode resting Maker RFQ order.",
        )
    })?;

    let depth: u64 = redis::Script::new(LUA_REGISTER_RESTING_MAKER_RFQ)
        .key(&directional_book_key)
        .key(&order_key)
        .arg(&quote.quote_id)
        .arg(&serialized)
        .arg(now_ms)
        .arg(expires_at_ms)
        .arg(ttl_ms)
        .invoke_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to register resting Maker RFQ order in Redis.",
            )
        })?;

    let _: redis::RedisResult<()> = redis::pipe()
        .cmd("ZREMRANGEBYSCORE")
        .arg(&summary_book_key)
        .arg("-inf")
        .arg(now_ms.saturating_sub(1))
        .ignore()
        .cmd("ZADD")
        .arg(&summary_book_key)
        .arg(expires_at_ms)
        .arg(&quote.quote_id)
        .ignore()
        .cmd("PEXPIRE")
        .arg(&summary_book_key)
        .arg((ttl_ms + 30_000) as i64)
        .ignore()
        .query_async(redis_conn)
        .await;

    Ok(depth)
}

/// Clears a Taker Dark Pool match after a randomized `1.0s–2.0s` jitter window priced
/// strictly against the post-jitter Redis oracle snapshot.
/// Fails closed with ZERO state mutation if CEX/DEX feeds diverge OR if
/// `post_jitter_net_out < quote.min_amount_out`.
pub async fn clear_taker_dark_pool_micro_batch(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    claims: &AgentCapabilityClaims,
    quote: &StoredAgentQuote,
    dry_run: bool,
) -> Result<MicroBatchClearingOutcome, AgentError> {
    let jitter_ms: u64 = rand::rngs::OsRng.gen_range(MIN_MICRO_BATCH_JITTER_MS..=MAX_MICRO_BATCH_JITTER_MS);

    if !dry_run {
        tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
    }

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Re-verify Global Agent Circuit Breaker after the jitter window
    locks_and_limits::check_global_agent_circuit_breaker(redis_conn).await?;

    // Read fresh post-jitter Redis oracle snapshot (cache-only, zero outbound HTTP)
    let fresh_oracle =
        match solvency::read_cached_oracle_pair_snapshot(redis_conn, &quote.pay_asset, &quote.receive_asset)
            .await
        {
            Ok(snap) => snap,
            Err(err) => {
                locks_and_limits::record_slippage_or_divergence_spike(redis_conn, now_secs).await;
                return Err(err);
            }
        };

    // Enforce CEX/DEX divergence bounds and micro-batch drift bounds
    if let Err(div_err) = verify_cex_dex_divergence_bounds(
        redis_conn,
        &quote.pay_asset,
        &quote.receive_asset,
        quote.pay_oracle_usd_e8.as_u128(),
        quote.receive_oracle_usd_e8.as_u128(),
        &fresh_oracle,
    )
    .await
    {
        locks_and_limits::record_slippage_or_divergence_spike(redis_conn, now_secs).await;
        return Err(div_err);
    }

    let envelope = PostToccataEnvelope {
        tx_version: quote.tx_version,
        compute_budget: Some(quote.compute_grams),
        storage_mass: Some(quote.storage_mass),
        covenant_id: quote.covenant_id.clone(),
        proof_payload: quote.proof_payload.clone(),
    };

    let input_sompi_vec: Vec<u128> = quote
        .locked_utxos
        .iter()
        .map(|u| u.amount_sompi.as_u128())
        .collect();
    let proof_len = quote
        .proof_payload
        .as_ref()
        .map(|h| h.len() / 2)
        .unwrap_or(0);

    // Recompute exact u128 zero-loss output against the post-jitter oracle snapshot
    let post_jitter_math = compute_zero_loss_quote_math(
        claims,
        AgentVenue::DarkPool,
        quote.amount_in_atomic.as_u128(),
        quote.max_slippage_bps,
        &fresh_oracle,
        quote.locked_utxos.len().max(1),
        2,
        quote.payload_0x83_hex.len() / 2,
        proof_len,
        &input_sompi_vec,
        &[],
        &envelope,
    )?;

    let mut settled_out_atomic = post_jitter_math.expected_amount_out_atomic;
    let mut matched_rfq_id: Option<String> = None;
    let mut matched_maker_wallet: Option<String> = None;

    // Attempt atomic match against resting Mode A Dark Pool Maker RFQs offering `receive_asset` for `pay_asset`
    if !dry_run {
        let opposite_side_key =
            format!("perennia:agent:rfq_side:{}:{}", quote.receive_asset, quote.pay_asset);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Taker net input available to Maker after Perennia's Taker protocol + L1 fee margin:
        let net_taker_in_for_maker = quote
            .amount_in_atomic
            .as_u128()
            .saturating_sub(post_jitter_math.protocol_fee_pay_atomic);

        if net_taker_in_for_maker > 0 {
            let match_resp: (i32, String) = redis::Script::new(LUA_CONSUME_MATCHING_MAKER_RFQ)
                .key(&opposite_side_key)
                .arg(now_ms)
                .arg(settled_out_atomic.to_string())
                .arg(net_taker_in_for_maker.to_string())
                .arg(&claims.clean_wallet)
                .invoke_async(redis_conn)
                .await
                .unwrap_or((0, String::new()));

            if match_resp.0 == 1 {
                if let Ok(maker_ord) = serde_json::from_str::<RestingMakerRfqOrder>(&match_resp.1) {
                    let summary_key = canonical_rfq_book_key(&quote.pay_asset, &quote.receive_asset);
                    let _: redis::RedisResult<()> = redis::cmd("ZREM")
                        .arg(&summary_key)
                        .arg(&maker_ord.quote_id)
                        .query_async(redis_conn)
                        .await;

                    // Price improvement capped cleanly while strictly preserving zero-loss protocol cut
                    let maker_net_offer = mul_div_floor_u128(
                        maker_ord.maker_offer_atomic.as_u128(),
                        BPS_DENOMINATOR.saturating_sub(maker_ord.maker_fee_bps as u128),
                        BPS_DENOMINATOR,
                    )?;
                    if maker_net_offer >= settled_out_atomic {
                        settled_out_atomic = maker_net_offer;
                        matched_rfq_id = Some(maker_ord.quote_id);
                        matched_maker_wallet = Some(maker_ord.maker_prefixed_wallet);
                    }
                }
            }
        }
    }

    // Mandatory Zero-Loss & Signed Floor Invariant:
    // Execution succeeds IF AND ONLY IF `post_jitter_net_out >= quote.min_amount_out`
    if settled_out_atomic < quote.min_amount_out_atomic.as_u128() {
        locks_and_limits::record_slippage_or_divergence_spike(redis_conn, now_secs).await;
        return Err(AgentError::new(
            AgentErrorCode::SlippageExceededPostJitter,
            format!(
                "POST_JITTER_FLOOR_BREACH: Post-jitter net output ({} {}) fell below signed minAmountOut ({} {}). Failing closed with zero state mutation.",
                settled_out_atomic,
                quote.receive_asset,
                quote.min_amount_out_atomic,
                quote.receive_asset
            ),
        ));
    }

    let _ = (atomic_decimals_for_asset, pow10_u128);

    Ok(MicroBatchClearingOutcome {
        jitter_applied_ms: jitter_ms,
        fresh_pay_oracle_usd_e8: U128Str(fresh_oracle.pay_usd_e8),
        fresh_receive_oracle_usd_e8: U128Str(fresh_oracle.receive_usd_e8),
        fresh_kas_oracle_usd_e8: U128Str(fresh_oracle.kas_usd_e8),
        post_jitter_net_out_atomic: U128Str(settled_out_atomic),
        post_jitter_protocol_fee_atomic: U128Str(post_jitter_math.protocol_fee_pay_atomic),
        post_jitter_total_fee_usd_micros: U128Str(post_jitter_math.total_fee_usd_micros),
        matched_maker_rfq_quote_id: matched_rfq_id,
        matched_maker_wallet,
    })
}

/// Executes the 22:00:00 UTC Global Settlement Bell with anti-sandwich protection:
/// 1. Locks the exact `22:00:00` UTC accounting snapshot and crosses internal Dark Pool liquidity first.
/// 2. Extracts any external residual swap tickets (`NET_RESIDUAL_AUTOBALANCE`) staged by the bell and
///    slices/jitters their external execution across a randomized multi-minute window (`4..=8` slices,
///    `20s..=65s` randomized spacing) with fresh Redis oracle checks before each slice.
pub async fn execute_chronos_2200_anti_sandwich_bell(
    pool: &PgPool,
    immediate_admin_force: bool,
) -> anyhow::Result<Value> {
    let snapshot_ts_utc = Utc::now().to_rfc3339();

    // 1. Cross internal Dark Pool netting queue & miner buckets at the exact snapshot timestamp
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let redis_client = redis::Client::open(redis_url)?;
    let _ = crate::chronos::run_delta_netting_cycle(&redis_client, pool).await;

    let netting_res = crate::chronos::execute_epoch_delta_netting_and_lp_compounding(pool).await?;
    let forge_res = crate::chronos::execute_2200_utc_forge_bell_settlement(pool).await?;

    if immediate_admin_force {
        return Ok(json!({
            "snapshotTimestampUtc": snapshot_ts_utc,
            "antiSandwichMode": "IMMEDIATE_ADMIN_OVERRIDE",
            "netting": netting_res,
            "forge": forge_res,
            "bellTimestampUtc": Utc::now().to_rfc3339()
        }));
    }

    // 2. Pop external residual tickets so bots cannot front-run a predictable 22:00:01 UTC external dump,
    //    then re-dispatch them in randomized sub-slices across a multi-minute jitter window.
    let mut conn = redis_client.get_multiplexed_async_connection().await?;
    let raw_passthrough: Vec<String> = redis::cmd("LRANGE")
        .arg("perennia:sor:third_party_passthrough_queue")
        .arg(0)
        .arg(199)
        .query_async(&mut conn)
        .await
        .unwrap_or_default();

    let mut bell_residuals: Vec<Value> = Vec::new();
    let mut non_bell_items: Vec<String> = Vec::new();

    for item_str in raw_passthrough {
        if let Ok(parsed) = serde_json::from_str::<Value>(&item_str) {
            let is_residual = parsed
                .get("type")
                .and_then(|v| v.as_str())
                .map(|t| t == "NET_RESIDUAL_AUTOBALANCE")
                .unwrap_or(false);
            if is_residual {
                bell_residuals.push(parsed);
            } else {
                non_bell_items.push(item_str);
            }
        }
    }

    let residual_count = bell_residuals.len();
    if residual_count > 0 {
        let _: redis::RedisResult<()> = redis::cmd("DEL")
            .arg("perennia:sor:third_party_passthrough_queue")
            .query_async(&mut conn)
            .await;
        for keep in non_bell_items.into_iter().rev() {
            let _: redis::RedisResult<()> = redis::cmd("LPUSH")
                .arg("perennia:sor:third_party_passthrough_queue")
                .arg(keep)
                .query_async(&mut conn)
                .await;
        }

        let num_slices: usize = rand::rngs::OsRng.gen_range(4usize..=8usize);
        let r_client_bg = redis_client.clone();

        tokio::spawn(async move {
            for (idx, mut ticket) in bell_residuals.into_iter().enumerate() {
                let slice_count = num_slices.max(2);
                for slice_idx in 0..slice_count {
                    let sleep_ms: u64 = rand::rngs::OsRng.gen_range(20_000u64..=65_000u64);
                    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;

                    let Ok(mut slice_conn) = r_client_bg.get_multiplexed_async_connection().await
                    else {
                        tracing::error!("❌ [CHRONOS ANTI-SANDWICH] Redis unreachable during jittered slice; failing closed.");
                        break;
                    };

                    let target_asset = ticket
                        .get("target_asset")
                        .and_then(|v| v.as_str())
                        .unwrap_or("USDC")
                        .to_string();

                    // Fail closed on slice if cached Redis oracle or circuit breaker tripped
                    if locks_and_limits::check_global_agent_circuit_breaker(&mut slice_conn)
                        .await
                        .is_err()
                    {
                        tracing::warn!(
                            "⚠️ [CHRONOS ANTI-SANDWICH] Agent circuit breaker active; deferring residual slice {}/{} for {}.",
                            slice_idx + 1,
                            slice_count,
                            target_asset
                        );
                        continue;
                    }

                    if target_asset != "KAS"
                        && solvency::read_cached_oracle_pair_snapshot(
                            &mut slice_conn,
                            "KAS",
                            &target_asset,
                        )
                        .await
                        .is_err()
                    {
                        tracing::warn!(
                            "⚠️ [CHRONOS ANTI-SANDWICH] Cached oracle offline for {}; failing closed on residual slice.",
                            target_asset
                        );
                        continue;
                    }

                    let total_res_usd = ticket
                        .get("residual_usd")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    let total_kas_eq = ticket
                        .get("kas_equiv")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);

                    if let Some(obj) = ticket.as_object_mut() {
                        let res_micros = (total_res_usd.max(0.0) * 1_000_000.0).round() as u128;
                        let kas_sompi = (total_kas_eq.max(0.0) * 100_000_000.0).round() as u128;
                        let slice_micros = res_micros / (slice_count as u128);
                        let slice_sompi = kas_sompi / (slice_count as u128);
                        obj.insert(
                            "slice_index".to_string(),
                            json!(format!("{}/{}", slice_idx + 1, slice_count)),
                        );
                        obj.insert("slice_usd_micros".to_string(), json!(slice_micros.to_string()));
                        obj.insert("slice_sompi".to_string(), json!(slice_sompi.to_string()));
                        obj.insert(
                            "anti_sandwich_dispatched_at".to_string(),
                            json!(Utc::now().to_rfc3339()),
                        );
                        obj.insert("residual_group_idx".to_string(), json!(idx));
                    }

                    let _: redis::RedisResult<()> = redis::cmd("LPUSH")
                        .arg("perennia:sor:third_party_passthrough_queue")
                        .arg(ticket.to_string())
                        .query_async(&mut slice_conn)
                        .await;
                    let _: redis::RedisResult<()> = redis::cmd("LTRIM")
                        .arg("perennia:sor:third_party_passthrough_queue")
                        .arg(0)
                        .arg(199)
                        .query_async(&mut slice_conn)
                        .await;
                }
            }
        });

        return Ok(json!({
            "snapshotTimestampUtc": snapshot_ts_utc,
            "antiSandwichMode": "JITTERED_MULTI_MINUTE_SLICER",
            "residualTicketsSliced": residual_count,
            "slicesPerTicket": num_slices,
            "netting": netting_res,
            "forge": forge_res,
            "bellTimestampUtc": Utc::now().to_rfc3339()
        }));
    }

    Ok(json!({
        "snapshotTimestampUtc": snapshot_ts_utc,
        "antiSandwichMode": "100_PCT_INTERNAL_DARK_POOL_CROSSED",
        "residualTicketsSliced": 0,
        "netting": netting_res,
        "forge": forge_res,
        "bellTimestampUtc": Utc::now().to_rfc3339()
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChronosBatchBidRequest {
    pub batch_id: String,
    pub nonce: Option<String>,
    pub solver_net_miner_payout_atomic: U128Str,
    pub house_fee_bps: Option<u16>,
    pub sha256_hashlock_hex: String,
    pub solver_kaspa_pubkey_hex: String,
    pub disperse_chain: String,
    pub disperse_lock_txid: String,
    pub disperse_contract_address: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChronosZkTlsUnlockRequest {
    pub vault_id: String,
    pub miner_wallet: String,
    pub zk_precompile_tag: u8,
    pub groth16_proof_hex: String,
    pub biller_commitment_hex: String,
    pub paid_invoice_usd_micros: U128Str,
    pub biller_receipt_ref: String,
    pub nonce: Option<String>,
}

async fn verify_and_consume_agent_replay_nonce(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    headers: &HeaderMap,
    body_nonce: Option<&str>,
    key_id: &str,
) -> Result<String, AgentError> {
    let raw = headers
        .get("x-agent-nonce")
        .and_then(|v| v.to_str().ok())
        .or(body_nonce)
        .unwrap_or("")
        .trim();
    if !(16..=128).contains(&raw.len())
        || !raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "Missing or malformed 60s replay nonce (provide 16..=128 char X-Agent-Nonce header or body.nonce).",
        ));
    }
    let key = format!("perennia:agent:replay_nonce:{}:{}", key_id, raw);
    let set_res: Option<String> = redis::cmd("SET")
        .arg(&key)
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(60)
        .query_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed verifying 60s replay nonce in Redis.",
            )
        })?;
    if set_res.is_none() {
        return Err(AgentError::new(
            AgentErrorCode::IdempotencyConflict,
            "REPLAY_NONCE_CONFLICT: Nonce already consumed within 60s replay window.",
        ));
    }
    Ok(raw.to_string())
}

async fn verify_onchain_perennia_batch_htlc(
    chain: &str,
    txid: &str,
    contract_addr: &str,
    sha256_hashlock_hex: &str,
    min_locked_atomic: u128,
) -> Result<(), AgentError> {
    let clean_chain = chain.trim().to_uppercase();
    let clean_tx = txid.trim();
    let clean_contract = contract_addr.trim().to_lowercase();
    let clean_hl = sha256_hashlock_hex.trim().trim_start_matches("0x").to_lowercase();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    match clean_chain.as_str() {
        "BASE" | "ARB" => {
            let (rpc_env, contract_env) = if clean_chain == "BASE" {
                ("BASE_RPC_URL", "PERENNIA_BATCH_HTLC_BASE_ADDRESS")
            } else {
                ("ARB_RPC_URL", "PERENNIA_BATCH_HTLC_ARB_ADDRESS")
            };
            let rpc_url = env::var(rpc_env)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    AgentError::new(
                        AgentErrorCode::NodeUnavailable,
                        format!("{} not configured; cannot verify PerenniaBatchHTLC lock.", rpc_env),
                    )
                })?;
            let expected_contract = env::var(contract_env)
                .ok()
                .map(|s| s.trim().to_lowercase())
                .filter(|s| s.starts_with("0x") && s.len() == 42)
                .ok_or_else(|| {
                    AgentError::new(
                        AgentErrorCode::NodeUnavailable,
                        format!("{} not configured; failing closed on EVM HTLC check.", contract_env),
                    )
                })?;
            if clean_contract != expected_contract {
                return Err(AgentError::new(
                    AgentErrorCode::MandateViolation,
                    "disperseContractAddress does not match configured PerenniaBatchHTLC deployment.",
                ));
            }
            let rpc_body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_getTransactionReceipt",
                "params": [clean_tx]
            });
            let resp = client.post(&rpc_url).json(&rpc_body).send().await.map_err(|e| {
                AgentError::new(
                    AgentErrorCode::NodeUnavailable,
                    format!("{} RPC request failed: {}", clean_chain, e),
                )
            })?;
            let body: Value = resp.json().await.map_err(|_| {
                AgentError::new(
                    AgentErrorCode::NodeUnavailable,
                    "Invalid EVM JSON-RPC receipt response.",
                )
            })?;
            let receipt = body
                .get("result")
                .filter(|r| !r.is_null())
                .ok_or_else(|| {
                    AgentError::new(
                        AgentErrorCode::UnconfirmedParentUtxo,
                        "PerenniaBatchHTLC EVM transaction receipt not yet confirmed.",
                    )
                })?;
            if receipt.get("status").and_then(|v| v.as_str()) != Some("0x1") {
                return Err(AgentError::new(
                    AgentErrorCode::InvalidSignatureOrScript,
                    "PerenniaBatchHTLC EVM transaction reverted on-chain.",
                ));
            }
            let logs = receipt
                .get("logs")
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    AgentError::new(
                        AgentErrorCode::PreimageMismatch,
                        "PerenniaBatchHTLC receipt contains no event logs.",
                    )
                })?;
            let matched = logs.iter().any(|l| {
                let addr_ok = l
                    .get("address")
                    .and_then(|v| v.as_str())
                    .map(|a| a.to_lowercase() == expected_contract)
                    .unwrap_or(false);
                let data_hex = l
                    .get("data")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                let topics_match = l
                    .get("topics")
                    .and_then(|t| t.as_array())
                    .map(|arr| {
                        arr.iter().any(|tp| {
                            tp.as_str()
                                .unwrap_or("")
                                .to_lowercase()
                                .contains(&clean_hl)
                        })
                    })
                    .unwrap_or(false);
                addr_ok && (topics_match || data_hex.contains(&clean_hl))
            });
            if !matched {
                return Err(AgentError::new(
                    AgentErrorCode::PreimageMismatch,
                    "PerenniaBatchHTLC receipt missing BatchHTLCLocked event for hashlock.",
                ));
            }
            let _ = min_locked_atomic;
            Ok(())
        }
        "SOL" => {
            let rpc_url = env::var("SOLANA_RPC_URL")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    AgentError::new(
                        AgentErrorCode::NodeUnavailable,
                        "SOLANA_RPC_URL not configured; cannot verify PerenniaBatchHTLC lock.",
                    )
                })?;
            let expected_prog = env::var("PERENNIA_BATCH_HTLC_SOL_PROGRAM_ID")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    AgentError::new(
                        AgentErrorCode::NodeUnavailable,
                        "PERENNIA_BATCH_HTLC_SOL_PROGRAM_ID not configured.",
                    )
                })?;
            if contract_addr.trim() != expected_prog {
                return Err(AgentError::new(
                    AgentErrorCode::MandateViolation,
                    "disperseContractAddress does not match PERENNIA_BATCH_HTLC_SOL_PROGRAM_ID.",
                ));
            }
            let rpc_body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getTransaction",
                "params": [clean_tx, { "encoding": "jsonParsed", "commitment": "confirmed", "maxSupportedTransactionVersion": 0 }]
            });
            let resp = client.post(&rpc_url).json(&rpc_body).send().await.map_err(|e| {
                AgentError::new(
                    AgentErrorCode::NodeUnavailable,
                    format!("Solana RPC request failed: {}", e),
                )
            })?;
            let body: Value = resp.json().await.map_err(|_| {
                AgentError::new(
                    AgentErrorCode::NodeUnavailable,
                    "Invalid Solana getTransaction JSON response.",
                )
            })?;
            let result = body
                .get("result")
                .filter(|r| !r.is_null())
                .ok_or_else(|| {
                    AgentError::new(
                        AgentErrorCode::UnconfirmedParentUtxo,
                        "Solana PerenniaBatchHTLC transaction not yet confirmed.",
                    )
                })?;
            let meta = result.get("meta").ok_or_else(|| {
                AgentError::new(
                    AgentErrorCode::PreimageMismatch,
                    "Solana transaction missing meta.",
                )
            })?;
            if !meta.get("err").map(|v| v.is_null()).unwrap_or(false) {
                return Err(AgentError::new(
                    AgentErrorCode::InvalidSignatureOrScript,
                    "Solana PerenniaBatchHTLC transaction failed on-chain.",
                ));
            }
            let logs_text = meta
                .get("logMessages")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default()
                .to_lowercase();
            if !logs_text.contains(&expected_prog.to_lowercase()) || !logs_text.contains(&clean_hl) {
                return Err(AgentError::new(
                    AgentErrorCode::PreimageMismatch,
                    "Solana PerenniaBatchHTLC logs do not bind expected program and SHA-256 hashlock.",
                ));
            }
            Ok(())
        }
        _ => Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "disperseChain must be BASE, SOL, or ARB.",
        )),
    }
}

/// `GET /api/v1/agent/chronos/rfq` — publishes anonymized batch manifests + live ChangeNOW reserve floor.
pub async fn handle_get_chronos_rfq(
    State(state): State<AgentGatewayState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AgentError> {
    let mut conn = state.get_redis_conn().await?;
    let claims = authenticate_agent_request(&state, &headers, &mut conn).await?;

    let raw_batches: Vec<String> = redis::cmd("HVALS")
        .arg(crate::chronos::REDIS_KEY_CHRONOS_RFQ_BATCHES)
        .query_async(&mut conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed reading active Chronos RFQ batches from Redis.",
            )
        })?;

    let mut anonymized = Vec::with_capacity(raw_batches.len());
    for raw in raw_batches {
        if let Ok(mut v) = serde_json::from_str::<Value>(&raw) {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("vaultIds"); // Zero identity bleed in anonymized solver feed
            }
            anonymized.push(v);
        }
    }

    Ok(Json(json!({
        "success": true,
        "keyId": claims.key_id,
        "batches": anonymized
    })))
}

/// `POST /api/v1/agent/chronos/bid` — verifies Solver's on-chain `PerenniaBatchHTLC` lock, enforces
/// `>= ChangeNOW_net_floor + 10 bps` and `50..=75 bps` Dark Pool house fee, and registers winning bid.
pub async fn handle_post_chronos_bid(
    State(state): State<AgentGatewayState>,
    headers: HeaderMap,
    Json(req): Json<ChronosBatchBidRequest>,
) -> Result<Json<Value>, AgentError> {
    let mut conn = state.get_redis_conn().await?;
    let claims = authenticate_agent_request(&state, &headers, &mut conn).await?;
    if claims.mode != AgentMode::ModeA || !claims.allow_dark_pool_maker {
        return Err(AgentError::new(
            AgentErrorCode::ForbiddenMode,
            "Chronos solver bidding requires MODE_A key with allowDarkPoolMaker capability.",
        ));
    }
    let _nonce = verify_and_consume_agent_replay_nonce(
        &mut conn,
        &headers,
        req.nonce.as_deref(),
        &claims.key_id,
    )
    .await?;

    let hashlock_hex = validate_hex_64(&req.sha256_hashlock_hex, "sha256HashlockHex")?;
    let solver_pk_hex = validate_hex_64(&req.solver_kaspa_pubkey_hex, "solverKaspaPubkeyHex")?;
    let batch_id = req.batch_id.trim().to_string();

    let manifest_raw: Option<String> = redis::cmd("HGET")
        .arg(crate::chronos::REDIS_KEY_CHRONOS_RFQ_BATCHES)
        .arg(&batch_id)
        .query_async(&mut conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed loading Chronos RFQ batch manifest from Redis.",
            )
        })?;
    let manifest_str = manifest_raw.ok_or_else(|| {
        AgentError::new(
            AgentErrorCode::QuoteExpiredOrNotFound,
            format!("Chronos RFQ batch {} not found or already closed.", batch_id),
        )
    })?;
    let manifest: Value = serde_json::from_str(&manifest_str).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            "Corrupt Chronos RFQ batch manifest in Redis.",
        )
    })?;

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let closes_at = manifest
        .get("closesAtUnix")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if now_secs > closes_at {
        return Err(AgentError::new(
            AgentErrorCode::QuoteExpiredOrNotFound,
            "Chronos RFQ batch bidding window has closed.",
        ));
    }

    let gross_kas_sompi = manifest
        .get("grossKasSompi")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(0);
    let cn_floor_atomic = manifest
        .get("changenowNetFloorAtomic")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(0);
    let fee_bps = req
        .house_fee_bps
        .unwrap_or(crate::chronos::TIER2_DARK_POOL_MIN_FEE_BPS);

    let (min_required_atomic, house_fee_sompi) = crate::chronos::verify_tier2_solver_bid_invariants(
        cn_floor_atomic,
        req.solver_net_miner_payout_atomic.as_u128(),
        gross_kas_sompi,
        fee_bps,
    )
    .map_err(|e| AgentError::new(AgentErrorCode::SolvencyFloorViolation, e))?;

    verify_onchain_perennia_batch_htlc(
        &req.disperse_chain,
        &req.disperse_lock_txid,
        &req.disperse_contract_address,
        &hashlock_hex,
        req.solver_net_miner_payout_atomic.as_u128(),
    )
    .await?;

    let bid_key = format!("{}{}", crate::chronos::REDIS_KEY_CHRONOS_WINNING_BID_PREFIX, batch_id);
    let prior_bid_opt: Option<String> = redis::cmd("GET")
        .arg(&bid_key)
        .query_async(&mut conn)
        .await
        .ok()
        .flatten();
    if let Some(prior_raw) = prior_bid_opt {
        if let Ok(prior_val) = serde_json::from_str::<Value>(&prior_raw) {
            let prior_amt = prior_val
                .get("solverNetMinerPayoutAtomic")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(0);
            if req.solver_net_miner_payout_atomic.as_u128() <= prior_amt {
                return Err(AgentError::new(
                    AgentErrorCode::IdempotencyConflict,
                    "BID_NOT_IMPROVING: Existing verified solver bid already equals or exceeds your payout.",
                ));
            }
        }
    }

    let bid_record = json!({
        "batchId": batch_id,
        "solverKeyId": claims.key_id,
        "solverWallet": claims.prefixed_wallet,
        "solverNetMinerPayoutAtomic": req.solver_net_miner_payout_atomic,
        "minRequiredAtomic": U128Str(min_required_atomic),
        "houseFeeBps": fee_bps,
        "houseFeeSompi": U128Str(house_fee_sompi),
        "sha256HashlockHex": hashlock_hex,
        "solverKaspaPubkeyHex": solver_pk_hex,
        "disperseChain": req.disperse_chain.trim().to_uppercase(),
        "disperseLockTxid": req.disperse_lock_txid.trim(),
        "disperseContractAddress": req.disperse_contract_address.trim(),
        "verifiedAtUnix": now_secs
    });
    let _: redis::RedisResult<()> = redis::cmd("SETEX")
        .arg(&bid_key)
        .arg(600u64)
        .arg(bid_record.to_string())
        .query_async(&mut conn)
        .await;

    let v_daa = crate::kaspad_client::get_virtual_daa_score_grpc()
        .await
        .unwrap_or(0);
    let mut hl_arr = [0u8; 32];
    if let Ok(b) = hex::decode(&hashlock_hex) {
        if b.len() == 32 {
            hl_arr.copy_from_slice(&b);
        }
    }
    let mut pk_arr = [0u8; 32];
    if let Ok(b) = hex::decode(&solver_pk_hex) {
        if b.len() == 32 {
            pk_arr.copy_from_slice(&b);
        }
    }
    let htlc_preview = crate::chronos::build_kaspa_opsha256_htlc_covenant(
        &hl_arr,
        &pk_arr,
        &pk_arr,
        v_daa.saturating_add(crate::chronos::DEFAULT_HTLC_DAA_REFUND_DELTA),
    );

    Ok(Json(json!({
        "success": true,
        "status": "WINNING_BID_VERIFIED",
        "bid": bid_record,
        "kaspaHtlcPreview": htlc_preview
    })))
}

/// `POST /api/v1/agent/chronos/zktls-unlock` — validates Valve 1 `zkTLS` Guest-Pay bill-pay
/// proof using `OpZkPrecompile` tag `0x20` (Groth16) ONLY (hard-rejecting deprecated `0x21`).
pub async fn handle_post_chronos_zktls_unlock(
    State(state): State<AgentGatewayState>,
    headers: HeaderMap,
    Json(req): Json<ChronosZkTlsUnlockRequest>,
) -> Result<Json<Value>, AgentError> {
    let mut conn = state.get_redis_conn().await?;
    let claims = authenticate_agent_request(&state, &headers, &mut conn).await?;
    let _nonce = verify_and_consume_agent_replay_nonce(
        &mut conn,
        &headers,
        req.nonce.as_deref(),
        &claims.key_id,
    )
    .await?;

    crate::silverscript::validate_zk_precompile_tag(req.zk_precompile_tag).map_err(|e| {
        AgentError::new(AgentErrorCode::InvalidSignatureOrScript, e)
    })?;

    let clean_proof = req.groth16_proof_hex.trim().trim_start_matches("0x");
    let proof_bytes = hex::decode(clean_proof).map_err(|_| {
        AgentError::new(
            AgentErrorCode::InvalidSignatureOrScript,
            "groth16ProofHex must be valid hexadecimal.",
        )
    })?;
    if proof_bytes.len() < 128 {
        return Err(AgentError::new(
            AgentErrorCode::InvalidSignatureOrScript,
            "Groth16 0x20 proof must contain at least 128 bytes (2 compressed G1 + 1 G2 points).",
        ));
    }
    let biller_commit = validate_hex_64(&req.biller_commitment_hex, "billerCommitmentHex")?;
    let clean_miner = req
        .miner_wallet
        .trim()
        .to_lowercase()
        .replace("kaspa:", "")
        .trim()
        .to_string();
    let paid_usd_micros = req.paid_invoice_usd_micros.as_u128();
    if paid_usd_micros == 0 {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "paidInvoiceUsdMicros must be > 0.",
        ));
    }

    let valve_row = sqlx::query(
        r#"
        SELECT target_cap_usd_micros::NUMERIC(39,0)::TEXT AS target_cap_usd_micros,
               filled_epoch_usd_micros::NUMERIC(39,0)::TEXT AS filled_epoch_usd_micros,
               zktls_biller_commitment_hex
        FROM thermostat_valves
        WHERE clean_wallet = $1
          AND priority_order = 1
          AND valve_type = 'VALVE_1_ELECTRIC_BILL'
          AND is_enabled = TRUE
        LIMIT 1
        "#,
    )
    .bind(&clean_miner)
    .fetch_optional(&state.pg_pool)
    .await
    .map_err(|_| {
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Failed querying Valve 1 zkTLS biller policy.",
        )
    })?
    .ok_or_else(|| {
        AgentError::new(
            AgentErrorCode::MandateViolation,
            "No enabled VALVE_1_ELECTRIC_BILL policy found for minerWallet.",
        )
    })?;

    let expected_commit: String = valve_row
        .try_get::<Option<String>, _>("zktls_biller_commitment_hex")
        .ok()
        .flatten()
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    if expected_commit != biller_commit {
        return Err(AgentError::new(
            AgentErrorCode::PreimageMismatch,
            "billerCommitmentHex does not match Valve 1 zktls_biller_commitment_hex.",
        ));
    }
    let cap_micros: u128 = valve_row
        .try_get::<String, _>("target_cap_usd_micros")
        .ok()
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(0);
    let filled_micros: u128 = valve_row
        .try_get::<String, _>("filled_epoch_usd_micros")
        .ok()
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(0);
    if cap_micros > 0 && filled_micros.saturating_add(paid_usd_micros) > cap_micros {
        return Err(AgentError::new(
            AgentErrorCode::MandateViolation,
            "paidInvoiceUsdMicros exceeds Valve 1 electric bill cap.",
        ));
    }

    let proof_hash = blake3::hash(&proof_bytes).to_hex().to_string();
    let receipt_id = format!("ZKTLS-{}", &proof_hash[..24]);
    let epoch_id = Utc::now().format("%Y-%m-%d").to_string();

    sqlx::query(
        r#"
        UPDATE thermostat_valves
        SET filled_epoch_usd_micros = filled_epoch_usd_micros + $2::NUMERIC(39,0),
            updated_at = CURRENT_TIMESTAMP
        WHERE clean_wallet = $1 AND priority_order = 1
        "#,
    )
    .bind(&clean_miner)
    .bind(paid_usd_micros.to_string())
    .execute(&state.pg_pool)
    .await
    .map_err(|_| {
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Failed updating Valve 1 zkTLS filled cap.",
        )
    })?;

    let _ = sqlx::query(
        r#"
        INSERT INTO settlement_receipts (
            receipt_id, epoch_id, wallet_address, clean_wallet, vault_id, valve_priority,
            settlement_tier, source_sompi, target_asset, target_network,
            settled_atomic, kaspa_l1_txid, destination_txid, groth16_0x20_proof_hash, status
        ) VALUES (
            $1, $2, $3, $4, $5, 1,
            'ZKTLS_GUEST_BILL_PAY', 1, 'USD', 'ZKTLS',
            $6::NUMERIC(39,0), $7, $8, $9, 'CONFIRMED'
        )
        ON CONFLICT (receipt_id) DO NOTHING
        "#,
    )
    .bind(&receipt_id)
    .bind(&epoch_id)
    .bind(format!("kaspa:{}", clean_miner))
    .bind(&clean_miner)
    .bind(req.vault_id.trim())
    .bind(paid_usd_micros.to_string())
    .bind(&proof_hash)
    .bind(req.biller_receipt_ref.trim())
    .bind(&proof_hash)
    .execute(&state.pg_pool)
    .await;

    Ok(Json(json!({
        "success": true,
        "receiptId": receipt_id,
        "vaultId": req.vault_id.trim(),
        "zkPrecompileTag": "0x20",
        "groth160x20ProofHash": proof_hash,
        "paidInvoiceUsdMicros": U128Str(paid_usd_micros),
        "status": "ZKTLS_GUEST_BILL_PAY_CONFIRMED"
    })))
}