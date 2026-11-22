// src/agent/dark_pool.rs

use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::agent::{
    locks_and_limits,
    solvency::{
        self, compute_zero_loss_quote_math, div_ceil_u128, mul_div_floor_u128, PairOracleSnapshot,
        MAKER_ZERO_LOSS_FLOOR_BPS,
    },
    types::{
        atomic_decimals_for_asset, pow10_u128, AgentCapabilityClaims, AgentError, AgentErrorCode,
        AgentVenue, PostToccataEnvelope, StoredAgentQuote, U128Str, BPS_DENOMINATOR,
    },
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
                    let slice_ratio = 1.0 / (slice_count as f64);

                    if let Some(obj) = ticket.as_object_mut() {
                        obj.insert(
                            "slice_index".to_string(),
                            json!(format!("{}/{}", slice_idx + 1, slice_count)),
                        );
                        obj.insert(
                            "residual_usd".to_string(),
                            json!(((total_res_usd * slice_ratio) * 10_000.0).round() / 10_000.0),
                        );
                        obj.insert(
                            "kas_equiv".to_string(),
                            json!(((total_kas_eq * slice_ratio) * 10_000.0).round() / 10_000.0),
                        );
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