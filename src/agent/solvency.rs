// src/agent/solvency.rs

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    agent::{
        types::{
            atomic_decimals_for_asset, pow10_u128, sanitize_sterile_ticker, AgentCapabilityClaims,
            AgentError, AgentErrorCode, AgentMode, AgentVenue, PostToccataEnvelope, U128Str,
            BPS_DENOMINATOR, MIN_AGENT_NOTIONAL_USD_MICROS, ORACLE_USD_E8_SCALE, SOMPI_PER_KAS,
            USD_MICROS_SCALE,
        },
        REDIS_KEY_BLACKLISTED_TOKENS, REDIS_KEY_LP_DEPTH_CACHE, REDIS_KEY_STEERING_STATES,
        REDIS_KEY_STEERING_WHITELIST,
    },
    sor::kaspa_tx::{BASE_COMPUTE_MASS, MASS_PER_INPUT, MASS_PER_OUTPUT, STORAGE_MASS_PARAMETER},
};

/// Post-Toccata Kaspa Transaction v1 consensus minimum fee: 100 sompi per mass unit.
pub const POST_TOCCATA_CONSENSUS_SOMPI_PER_GRAM: u128 = 100;
/// Relay safety fee rate matching `src/kaspa_tx.rs` (`110 sompi/gram`, strictly >= v1 floor).
pub const RELAY_SAFE_SOMPI_PER_GRAM: u128 = 110;

/// Hard zero-loss protocol profit floor on standard Taker swaps (10 bps = 0.10%).
pub const TAKER_ZERO_LOSS_FLOOR_BPS: u16 = 10;
/// Hard zero-loss protocol profit floor on resting Mode A Dark Pool Maker RFQs (2 bps = 0.02%).
pub const MAKER_ZERO_LOSS_FLOOR_BPS: u16 = 2;
/// Base Dark Pool Maker RFQ fee before loyalty/SILO multiplier (6 bps = 0.06%).
pub const DARK_POOL_MAKER_BASE_BPS: u16 = 6;
/// Buy-KAS inbound Taker base fee (20 bps = 0.20%).
pub const BUY_KAS_TAKER_BASE_BPS: u16 = 20;
/// Wholesale ($2,500+ notional) Taker base fee (25 bps = 0.25%).
pub const WHOLESALE_TAKER_BASE_BPS: u16 = 25;
/// Dark Pool whitelisted major pair Taker base fee (50 bps = 0.50%).
pub const DARK_POOL_MAJOR_TAKER_BASE_BPS: u16 = 50;
/// External pass-through Taker base fee (85 bps = 0.85%).
pub const PASS_THROUGH_TAKER_BASE_BPS: u16 = 85;

/// Minimum guaranteed protocol margin per Taker swap ($0.01 = 10,000 micro-USD).
pub const MIN_TAKER_PROTOCOL_FEE_USD_MICROS: u128 = 10_000;
/// Minimum guaranteed protocol margin per Maker RFQ fill ($0.002 = 2,000 micro-USD).
pub const MIN_MAKER_PROTOCOL_FEE_USD_MICROS: u128 = 2_000;

/// Maximum tolerated USD deviation for bridged/native stablecoins (`±50 bps` = `$0.9950`..=`$1.0050`).
pub const STABLECOIN_PARITY_MIN_E8: u128 = 99_500_000;
pub const STABLECOIN_PARITY_MAX_E8: u128 = 100_500_000;

const WHOLESALE_VOLUME_THRESHOLD_USD_MICROS: u128 = 2_500_000_000; // $2,500.00

// ============================================================================
// EXACT 256-BIT INTERMEDIATE INTEGER ARITHMETIC (ZERO FLOATING-POINT)
// ============================================================================

#[inline]
pub fn div_ceil_u128(num: u128, denom: u128) -> Result<u128, AgentError> {
    if denom == 0 {
        return Err(AgentError::new(
            AgentErrorCode::SolvencyFloorViolation,
            "Division by zero in u128 solvency math.",
        ));
    }
    let q = num / denom;
    let r = num % denom;
    if r > 0 {
        q.checked_add(1).ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::SolvencyFloorViolation,
                "u128 ceiling division overflow.",
            )
        })
    } else {
        Ok(q)
    }
}

fn u256_mul(a: u128, b: u128) -> [u64; 4] {
    let a0 = a as u64 as u128;
    let a1 = (a >> 64) as u64 as u128;
    let b0 = b as u64 as u128;
    let b1 = (b >> 64) as u64 as u128;

    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;

    let w0 = p00 as u64;
    let carry1 = p00 >> 64;

    let mid1 = carry1 + (p01 as u64 as u128) + (p10 as u64 as u128);
    let w1 = mid1 as u64;

    let carry2 = (mid1 >> 64) + (p01 >> 64) + (p10 >> 64) + (p11 as u64 as u128);
    let w2 = carry2 as u64;

    let carry3 = (carry2 >> 64) + (p11 >> 64);
    let w3 = carry3 as u64;

    [w0, w1, w2, w3]
}

fn u256_div_rem(num: [u64; 4], denom: u128) -> Option<(u128, u128)> {
    if denom == 0 {
        return None;
    }
    let hi: u128 = ((num[3] as u128) << 64) | (num[2] as u128);
    let lo: u128 = ((num[1] as u128) << 64) | (num[0] as u128);

    if hi == 0 {
        return Some((lo / denom, lo % denom));
    }
    if hi >= denom {
        return None;
    }

    let mut rem = hi;
    let mut quot: u128 = 0;

    for bit in (0..128).rev() {
        let carry = (rem >> 127) != 0;
        let next_bit = (lo >> bit) & 1;
        let shifted = (rem << 1) | next_bit;
        if carry || shifted >= denom {
            rem = shifted.wrapping_sub(denom);
            quot |= 1u128 << bit;
        } else {
            rem = shifted;
        }
    }

    Some((quot, rem))
}

/// Computes `floor((a * b) / denom)` using exact 256-bit intermediate integer math.
pub fn mul_div_floor_u128(a: u128, b: u128, denom: u128) -> Result<u128, AgentError> {
    let prod = u256_mul(a, b);
    let (q, _) = u256_div_rem(prod, denom).ok_or_else(|| {
        AgentError::new(
            AgentErrorCode::SolvencyFloorViolation,
            "Overflow or zero denominator in mul_div_floor_u128.",
        )
    })?;
    Ok(q)
}

/// Computes `ceil((a * b) / denom)` using exact 256-bit intermediate integer math.
pub fn mul_div_ceil_u128(a: u128, b: u128, denom: u128) -> Result<u128, AgentError> {
    let prod = u256_mul(a, b);
    let (q, rem) = u256_div_rem(prod, denom).ok_or_else(|| {
        AgentError::new(
            AgentErrorCode::SolvencyFloorViolation,
            "Overflow or zero denominator in mul_div_ceil_u128.",
        )
    })?;
    if rem > 0 {
        q.checked_add(1).ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::SolvencyFloorViolation,
                "u128 overflow rounding fee upward in mul_div_ceil_u128.",
            )
        })
    } else {
        Ok(q)
    }
}

/// Parses an ASCII decimal string (e.g. Redis oracle snapshot `"0.152841"` or `"92150.25"`)
/// directly into an exact `u128` integer scaled by `10^decimals` with ZERO floating-point casts.
pub fn parse_decimal_str_to_u128_scaled(raw: &str, decimals: u8) -> Result<u128, AgentError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with('-') || trimmed.starts_with('+') {
        return Err(AgentError::new(
            AgentErrorCode::OracleUnavailable,
            "Malformed or non-positive decimal string in cached state.",
        ));
    }

    let scale = pow10_u128(decimals)?;
    let mut parts = trimmed.split('.');
    let int_str = parts.next().unwrap_or("");
    let frac_str_opt = parts.next();
    if parts.next().is_some() {
        return Err(AgentError::new(
            AgentErrorCode::OracleUnavailable,
            "Decimal string contains multiple '.' separators.",
        ));
    }

    if int_str.is_empty() || !int_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AgentError::new(
            AgentErrorCode::OracleUnavailable,
            "Invalid integer digits in cached decimal string.",
        ));
    }

    let int_val = int_str.parse::<u128>().map_err(|_| {
        AgentError::new(
            AgentErrorCode::OracleUnavailable,
            "Integer overflow parsing cached decimal string.",
        )
    })?;

    let mut scaled_total = int_val.checked_mul(scale).ok_or_else(|| {
        AgentError::new(
            AgentErrorCode::OracleUnavailable,
            "Scaled integer overflow parsing cached decimal string.",
        )
    })?;

    if let Some(frac_str) = frac_str_opt {
        if !frac_str.is_empty() && !frac_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(AgentError::new(
                AgentErrorCode::OracleUnavailable,
                "Invalid fractional digits in cached decimal string.",
            ));
        }

        let dec_usize = decimals as usize;
        if dec_usize > 0 && !frac_str.is_empty() {
            let take_len = frac_str.len().min(dec_usize);
            let prefix = &frac_str[..take_len];
            let mut frac_val = prefix.parse::<u128>().map_err(|_| {
                AgentError::new(
                    AgentErrorCode::OracleUnavailable,
                    "Fractional parse error in cached decimal string.",
                )
            })?;
            let pad_pow = (dec_usize - take_len) as u32;
            if pad_pow > 0 {
                frac_val = frac_val.saturating_mul(10u128.pow(pad_pow));
            }
            // Round half-up on next digit if precision exceeds `decimals`
            if frac_str.len() > dec_usize {
                let next_digit = frac_str.as_bytes()[dec_usize] - b'0';
                if next_digit >= 5 {
                    frac_val = frac_val.saturating_add(1);
                }
            }
            scaled_total = scaled_total.checked_add(frac_val).ok_or_else(|| {
                AgentError::new(
                    AgentErrorCode::OracleUnavailable,
                    "Overflow adding fractional digits in cached decimal string.",
                )
            })?;
        }
    }

    Ok(scaled_total)
}

/// Formats an exact `u128` atomic balance into a fixed-point decimal string without `f64`.
pub fn format_u128_scaled_to_decimal_str(amount: u128, decimals: u8) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let scale = 10u128.pow(decimals as u32);
    let int_part = amount / scale;
    let frac_part = amount % scale;
    format!(
        "{}.{:0>width$}",
        int_part,
        frac_part,
        width = decimals as usize
    )
}

// ============================================================================
// POST-TOCCATA TRANSACTION v1 MASS & STORAGE MASS FEE ENGINE
// ============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostToccataFeeBreakdown {
    pub tx_version: u16,
    pub compute_grams: u64,
    pub tx_bytes: u64,
    pub bandwidth_mass: u64,
    pub storage_mass: u64,
    pub effective_mass: u64,
    pub consensus_v1_floor_sompi: u128,
    pub required_network_fee_sompi: u128,
}

/// Computes exact KIP-9 storage mass in pure integer `u128` math (matching `src/kaspa_tx.rs`).
pub fn compute_kip9_storage_mass_exact(
    input_amounts_sompi: &[u128],
    output_amounts_sompi: &[u128],
) -> u64 {
    if input_amounts_sompi.is_empty() || output_amounts_sompi.is_empty() {
        return 0;
    }
    let param = STORAGE_MASS_PARAMETER as u128;

    let mut harmonic_outs: u128 = 0;
    for &out_amt in output_amounts_sompi {
        let term = if out_amt > 0 {
            div_ceil_u128(param, out_amt).unwrap_or(param)
        } else {
            param
        };
        harmonic_outs = harmonic_outs.saturating_add(term);
    }

    let mut sum_ins: u128 = 0;
    for &in_amt in input_amounts_sompi {
        sum_ins = sum_ins.saturating_add(in_amt);
    }

    let num_ins = input_amounts_sompi.len() as u128;
    let mean_ins = sum_ins / num_ins.max(1);
    if mean_ins == 0 {
        return harmonic_outs.min(u64::MAX as u128) as u64;
    }

    let arithmetic_ins = num_ins.saturating_mul(param / mean_ins);
    harmonic_outs
        .saturating_sub(arithmetic_ins)
        .min(u64::MAX as u128) as u64
}

/// Enforces Kaspa post-Toccata Transaction v1 fee floors:
/// `consensus_v1_floor_sompi = 100 sompi * max(compute_grams, 2 * tx_bytes)` (and `>= 100 * storage_mass`),
/// while pricing Perennia unsigned payloads at `110 sompi * effective_mass` so node relay never rejects.
pub fn calculate_post_toccata_v1_mass_and_fee(
    num_inputs: usize,
    num_outputs: usize,
    payload_bytes_len: usize,
    proof_bytes_len: usize,
    input_amounts_sompi: &[u128],
    output_amounts_sompi: &[u128],
    envelope: &PostToccataEnvelope,
) -> PostToccataFeeBreakdown {
    let safe_inputs = num_inputs.max(1) as u64;
    let safe_outputs = num_outputs.max(1) as u64;
    let extra_bytes = (payload_bytes_len.saturating_add(proof_bytes_len)) as u64;

    let raw_compute_grams = BASE_COMPUTE_MASS
        .saturating_add(safe_inputs.saturating_mul(MASS_PER_INPUT))
        .saturating_add(safe_outputs.saturating_mul(MASS_PER_OUTPUT))
        .saturating_add(extra_bytes);

    let compute_grams = match envelope.compute_budget {
        Some(budget) if budget > raw_compute_grams => budget,
        _ => raw_compute_grams,
    };

    // Exact conservative serialized wire byte estimate for Kaspa Transaction v1
    let tx_bytes = 64u64
        .saturating_add(safe_inputs.saturating_mul(118))
        .saturating_add(safe_outputs.saturating_mul(46))
        .saturating_add(extra_bytes);

    let bandwidth_mass = tx_bytes.saturating_mul(2);

    let kip9_storage = compute_kip9_storage_mass_exact(input_amounts_sompi, output_amounts_sompi);
    let storage_mass = match envelope.storage_mass {
        Some(explicit_sm) if explicit_sm > kip9_storage => explicit_sm,
        _ => kip9_storage,
    };

    let compute_or_bw = compute_grams.max(bandwidth_mass);
    let effective_mass = compute_or_bw.max(storage_mass);

    let consensus_v1_floor_sompi =
        POST_TOCCATA_CONSENSUS_SOMPI_PER_GRAM.saturating_mul(effective_mass as u128);
    let relay_safe_fee_sompi = RELAY_SAFE_SOMPI_PER_GRAM.saturating_mul(effective_mass as u128);

    PostToccataFeeBreakdown {
        tx_version: envelope.tx_version.max(1),
        compute_grams,
        tx_bytes,
        bandwidth_mass,
        storage_mass,
        effective_mass,
        consensus_v1_floor_sompi,
        required_network_fee_sompi: relay_safe_fee_sompi.max(consensus_v1_floor_sompi),
    }
}

// ============================================================================
// CACHE-ONLY REDIS ORACLE, DEPEG CIRCUIT BREAKER & STEERING SNAPSHOTS
// ============================================================================

#[inline]
pub fn is_bridged_or_fiat_stablecoin(ticker: &str) -> bool {
    matches!(ticker, "USDC" | "USDT" | "USD")
}

#[derive(Debug, Clone)]
pub struct PairOracleSnapshot {
    pub pay_asset: String,
    pub receive_asset: String,
    pub pay_usd_e8: u128,
    pub receive_usd_e8: u128,
    pub kas_usd_e8: u128,
    pub pay_steering_state: String,
    pub receive_steering_state: String,
    pub allow_dark_pool: bool,
    pub dark_pool_paused: bool,
    pub external_dex_paused: bool,
}

async fn read_single_cached_asset_usd_e8(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    ticker: &str,
    is_pay_side: bool,
) -> Result<u128, AgentError> {
    if ticker == "USD" {
        return Ok(ORACLE_USD_E8_SCALE);
    }

    if is_bridged_or_fiat_stablecoin(ticker) {
        let (depeg_flag, parity_raw, spot_usdc_raw): (
            Option<String>,
            Option<String>,
            Option<String>,
        ) = redis::pipe()
            .cmd("GET")
            .arg(format!("oracle:depeg_halt:{}", ticker))
            .cmd("GET")
            .arg(format!("oracle:spot:{}_USD", ticker))
            .cmd("GET")
            .arg(format!("oracle:spot:{}_USDC", ticker))
            .query_async(redis_conn)
            .await
            .map_err(|_| {
                AgentError::new(
                    AgentErrorCode::RedisUnavailable,
                    "Redis unavailable while checking stablecoin depeg circuit breaker.",
                )
            })?;

        if let Some(flag) = depeg_flag {
            let trimmed = flag.trim();
            if trimmed == "1" || trimmed.eq_ignore_ascii_case("true") {
                return Err(AgentError::new(
                    AgentErrorCode::StablecoinDepegHalt,
                    format!(
                        "STABLECOIN_DEPEG_HALT: {} deviated from $1.00 parity; automated swaps halted.",
                        ticker
                    ),
                ));
            }
        }

        if let Some(p_str) = parity_raw {
            let parity_e8 = parse_decimal_str_to_u128_scaled(&p_str, 8)?;
            if !(STABLECOIN_PARITY_MIN_E8..=STABLECOIN_PARITY_MAX_E8).contains(&parity_e8) {
                return Err(AgentError::new(
                    AgentErrorCode::StablecoinDepegHalt,
                    format!(
                        "STABLECOIN_DEPEG_HALT: {} parity {} E8 breached [$0.9950, $1.0050] band.",
                        ticker, parity_e8
                    ),
                ));
            }
            // Zero-loss conservative stablecoin valuation:
            // Never credit > $1.00 on inbound stablecoin; never value < $1.00 on outbound stablecoin.
            return Ok(if is_pay_side {
                parity_e8.min(ORACLE_USD_E8_SCALE)
            } else {
                parity_e8.max(ORACLE_USD_E8_SCALE)
            });
        }

        let fallback_str = spot_usdc_raw.ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::OracleUnavailable,
                format!("Cached oracle feed for {} is offline; failing closed.", ticker),
            )
        })?;
        let parsed = parse_decimal_str_to_u128_scaled(&fallback_str, 8)?;
        if !(STABLECOIN_PARITY_MIN_E8..=STABLECOIN_PARITY_MAX_E8).contains(&parsed) {
            return Err(AgentError::new(
                AgentErrorCode::StablecoinDepegHalt,
                format!("STABLECOIN_DEPEG_HALT: {} cached feed out of $1.00 bounds.", ticker),
            ));
        }
        return Ok(ORACLE_USD_E8_SCALE);
    }

    let raw_spot: Option<String> = redis::cmd("GET")
        .arg(format!("oracle:spot:{}_USDC", ticker))
        .query_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Redis unavailable while reading cached oracle price.",
            )
        })?;

    if let Some(spot_str) = raw_spot {
        let price_e8 = parse_decimal_str_to_u128_scaled(&spot_str, 8)?;
        if price_e8 == 0 {
            return Err(AgentError::new(
                AgentErrorCode::OracleUnavailable,
                format!("Cached oracle price for {} is zero; failing closed.", ticker),
            ));
        }
        return Ok(price_e8);
    }

    // SILO deterministic Kaspa ecosystem ratio (`KAS / 23.809524`, i.e. `KAS * 42_000 / 1_000_000`)
    // derived strictly from live cached `oracle:spot:KAS_USDC` (never hardcoded USD!)
    if ticker == "SILO" {
        let kas_raw: Option<String> = redis::cmd("GET")
            .arg("oracle:spot:KAS_USDC")
            .query_async(redis_conn)
            .await
            .map_err(|_| {
                AgentError::new(
                    AgentErrorCode::RedisUnavailable,
                    "Redis unavailable while reading KAS anchor for SILO.",
                )
            })?;
        if let Some(kas_str) = kas_raw {
            let kas_e8 = parse_decimal_str_to_u128_scaled(&kas_str, 8)?;
            if kas_e8 > 0 {
                let silo_e8 = if is_pay_side {
                    mul_div_floor_u128(kas_e8, 42_000, 1_000_000)?
                } else {
                    mul_div_ceil_u128(kas_e8, 42_000, 1_000_000)?
                };
                if silo_e8 > 0 {
                    return Ok(silo_e8);
                }
            }
        }
    }

    Err(AgentError::new(
        AgentErrorCode::OracleUnavailable,
        format!(
            "ORACLE_HALT: Cached Redis price oracle:spot:{}_USDC expired or offline. Failing closed.",
            ticker
        ),
    ))
}

/// Reads cached prices, token steering states, firewall token sets, and subsystem kill switches
/// strictly from Redis with zero PostgreSQL or outbound HTTP calls.
pub async fn read_cached_oracle_pair_snapshot(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    pay_asset: &str,
    receive_asset: &str,
) -> Result<PairOracleSnapshot, AgentError> {
    let p_tick = sanitize_sterile_ticker(pay_asset)?;
    let r_tick = sanitize_sterile_ticker(receive_asset)?;

    if p_tick == r_tick {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "payAsset and receiveAsset must be distinct tickers.",
        ));
    }

    let (blk_p, blk_r, p_state_opt, r_state_opt, dp_kill, ext_kill): (
        i32,
        i32,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = redis::pipe()
        .cmd("SISMEMBER")
        .arg(REDIS_KEY_BLACKLISTED_TOKENS)
        .arg(&p_tick)
        .cmd("SISMEMBER")
        .arg(REDIS_KEY_BLACKLISTED_TOKENS)
        .arg(&r_tick)
        .cmd("HGET")
        .arg(REDIS_KEY_STEERING_STATES)
        .arg(&p_tick)
        .cmd("HGET")
        .arg(REDIS_KEY_STEERING_STATES)
        .arg(&r_tick)
        .cmd("GET")
        .arg("perennia:killswitch:dark_pool")
        .cmd("GET")
        .arg("perennia:killswitch:external_dex")
        .query_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to read token steering and firewall state from Redis.",
            )
        })?;

    if blk_p == 1 || blk_r == 1 {
        let blocked = if blk_p == 1 { &p_tick } else { &r_tick };
        return Err(AgentError::new(
            AgentErrorCode::FirewallBlacklisted,
            format!("Token {} is blocked by the Perennia Security Firewall.", blocked),
        ));
    }

    let pay_state = p_state_opt
        .map(|s| s.trim().to_ascii_uppercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "PASS_THROUGH".to_string());
    let receive_state = r_state_opt
        .map(|s| s.trim().to_ascii_uppercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "PASS_THROUGH".to_string());

    if pay_state == "BLACKLISTED" || receive_state == "BLACKLISTED" {
        return Err(AgentError::new(
            AgentErrorCode::FirewallBlacklisted,
            "Requested pair contains a BLACKLISTED token in the Steering Matrix.",
        ));
    }

    let dark_pool_paused = dp_kill
        .map(|v| v.trim() == "1" || v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let external_dex_paused = ext_kill
        .map(|v| v.trim() == "1" || v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let allow_dark_pool =
        !dark_pool_paused && pay_state != "PASS_THROUGH" && receive_state != "PASS_THROUGH";

    if !allow_dark_pool && external_dex_paused {
        return Err(AgentError::new(
            AgentErrorCode::CircuitBreakerTripped,
            "SUBSYSTEM_PAUSED: External routing and/or Dark Pool clearing are paused by Director kill-switch.",
        ));
    }

    let pay_usd_e8 = read_single_cached_asset_usd_e8(redis_conn, &p_tick, true).await?;
    let receive_usd_e8 = read_single_cached_asset_usd_e8(redis_conn, &r_tick, false).await?;
    let kas_usd_e8 = if p_tick == "KAS" {
        pay_usd_e8
    } else if r_tick == "KAS" {
        receive_usd_e8
    } else {
        read_single_cached_asset_usd_e8(redis_conn, "KAS", true).await?
    };

    Ok(PairOracleSnapshot {
        pay_asset: p_tick,
        receive_asset: r_tick,
        pay_usd_e8,
        receive_usd_e8,
        kas_usd_e8,
        pay_steering_state: pay_state,
        receive_steering_state: receive_state,
        allow_dark_pool,
        dark_pool_paused,
        external_dex_paused,
    })
}

// ============================================================================
// ZERO-LOSS DETERMINISTIC QUOTE MATH (ALL FEES CEIL-ROUNDED IN u128)
// ============================================================================

#[derive(Debug, Clone)]
pub struct SolvencyQuoteMath {
    pub pay_decimals: u8,
    pub receive_decimals: u8,
    pub notional_usd_micros: u128,
    pub spend_sompi_equiv: u128,
    pub applied_fee_bps: u16,
    pub protocol_fee_usd_micros: u128,
    pub protocol_fee_pay_atomic: u128,
    pub l1_network_fee_sompi: u128,
    pub l1_network_fee_usd_micros: u128,
    pub external_gas_and_slip_usd_micros: u128,
    pub total_fee_usd_micros: u128,
    pub net_value_usd_micros: u128,
    pub expected_amount_out_atomic: u128,
    pub min_amount_out_atomic: u128,
    pub mass_breakdown: PostToccataFeeBreakdown,
}

fn non_kaspa_chain_gas_cover_usd_micros(ticker: &str) -> u128 {
    match ticker {
        "KAS" | "SILO" | "NACHO" | "BEDRCK" | "PERX" | "KASPY" | "KASPER" | "KANGO" | "GHOAD"
        | "KEKE" => 0,
        "BTC" => 650_000, // $0.65
        "ETH" | "USDC" | "USDT" | "XAU" | "XAG" | "USTB" => 250_000, // $0.25
        "SOL" | "ARB" | "BASE" | "POL" | "AVAX" | "SUI" | "XRP" | "DOGE" | "TRX" | "TON"
        | "ADA" | "LINK" | "LTC" | "ZEC" => 25_000, // $0.025
        _ => 150_000,     // $0.15 conservative cover
    }
}

/// Computes exact `u128` fees (strictly rounded UP via `mul_div_ceil_u128`) and net outputs
/// (strictly rounded DOWN via `mul_div_floor_u128`), guaranteeing Perennia never subsidizes
/// a single sompi or micro-USD of L1 mass, bridge gas, or slippage.
pub fn compute_zero_loss_quote_math(
    claims: &AgentCapabilityClaims,
    venue: AgentVenue,
    amount_in_atomic: u128,
    requested_slippage_bps: u16,
    oracle: &PairOracleSnapshot,
    num_inputs: usize,
    num_outputs: usize,
    payload_bytes_len: usize,
    proof_bytes_len: usize,
    input_amounts_sompi: &[u128],
    output_amounts_sompi: &[u128],
    envelope: &PostToccataEnvelope,
) -> Result<SolvencyQuoteMath, AgentError> {
    if amount_in_atomic == 0 {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "amountIn must be greater than zero.",
        ));
    }

    if requested_slippage_bps == 0 || requested_slippage_bps > claims.max_slippage_bps {
        return Err(AgentError::new(
            AgentErrorCode::MandateViolation,
            format!(
                "maxSlippageBps ({}) must be in 1..={} permitted by capability key.",
                requested_slippage_bps, claims.max_slippage_bps
            ),
        ));
    }

    if venue == AgentVenue::DarkPoolRfqMaker {
        if claims.mode != AgentMode::ModeA || !claims.allow_dark_pool_maker {
            return Err(AgentError::new(
                AgentErrorCode::ForbiddenMode,
                "dark_pool_rfq_maker venue requires an authenticated Mode A Maker capability key.",
            ));
        }
    }

    if (venue == AgentVenue::DarkPool || venue == AgentVenue::DarkPoolRfqMaker)
        && !oracle.allow_dark_pool
    {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "Dark Pool clearing is unavailable for PASS_THROUGH pairs or while Dark Pool is paused.",
        ));
    }

    let pay_decimals = atomic_decimals_for_asset(&oracle.pay_asset);
    let receive_decimals = atomic_decimals_for_asset(&oracle.receive_asset);
    let pay_unit_scale = pow10_u128(pay_decimals)?;
    let receive_unit_scale = pow10_u128(receive_decimals)?;

    // Convert atomic input -> USD micros (1 USD = 10^6; oracle is 10^8 -> divide by 100 * pay_unit_scale)
    let usd_denom = pay_unit_scale.checked_mul(100).ok_or_else(|| {
        AgentError::new(
            AgentErrorCode::SolvencyFloorViolation,
            "Pay unit denominator overflow.",
        )
    })?;
    let notional_usd_micros = mul_div_floor_u128(amount_in_atomic, oracle.pay_usd_e8, usd_denom)?;

    if notional_usd_micros < MIN_AGENT_NOTIONAL_USD_MICROS {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            format!(
                "ANTI_DUST_FLOOR: Minimum bot swap notional is {} micro-USD ($1.00); submitted {} micro-USD.",
                MIN_AGENT_NOTIONAL_USD_MICROS, notional_usd_micros
            ),
        ));
    }

    // KAS sompi equivalent for rolling 24h Mandate spend cap (ceil-rounded so caps cannot be shaved)
    let spend_sompi_equiv = if oracle.pay_asset == "KAS" {
        amount_in_atomic
    } else {
        // notional_usd_micros (10^6) -> sompi (10^8) at kas_usd_e8 (10^8):
        // sompi = notional_usd_micros * 10^10 / kas_usd_e8
        mul_div_ceil_u128(notional_usd_micros, 10_000_000_000u128, oracle.kas_usd_e8)?
    };

    // 1. Post-Toccata Kaspa Transaction v1 L1 mass & storage mass fee (ceil-rounded into USD micros)
    let mass_breakdown = calculate_post_toccata_v1_mass_and_fee(
        num_inputs,
        num_outputs,
        payload_bytes_len,
        proof_bytes_len,
        input_amounts_sompi,
        output_amounts_sompi,
        envelope,
    );
    let l1_network_fee_sompi = mass_breakdown.required_network_fee_sompi;
    let l1_network_fee_usd_micros = mul_div_ceil_u128(
        l1_network_fee_sompi,
        oracle.kas_usd_e8,
        10_000_000_000u128,
    )?;

    // 2. Multi-chain gas + external pass-through slippage cover (strictly ceil-rounded)
    let is_external_route = venue == AgentVenue::Spot && !oracle.allow_dark_pool;
    let mut external_gas_and_slip_usd_micros: u128 = 0;
    if venue != AgentVenue::DarkPoolRfqMaker {
        let chain_gas = non_kaspa_chain_gas_cover_usd_micros(&oracle.pay_asset)
            .saturating_add(non_kaspa_chain_gas_cover_usd_micros(&oracle.receive_asset));
        if is_external_route {
            let ext_slip = mul_div_ceil_u128(notional_usd_micros, 15, BPS_DENOMINATOR)?; // 15 bps cover
            external_gas_and_slip_usd_micros = chain_gas.saturating_add(ext_slip);
        } else if notional_usd_micros < 25_000_000 {
            // Internal Dark Pool ledger/LP cross caps modeled external bridge amortizer on sub-$25 fills
            let cap_amortizer = mul_div_ceil_u128(notional_usd_micros, 100, BPS_DENOMINATOR)?;
            external_gas_and_slip_usd_micros = chain_gas.min(cap_amortizer);
        } else {
            external_gas_and_slip_usd_micros = chain_gas;
        }
    }

    // 3. Asymmetric Maker vs. Taker Protocol Fee Margin (with loyalty scalar clamped to zero-loss floor)
    let (base_bps, floor_bps, min_fee_usd_micros) = match venue {
        AgentVenue::DarkPoolRfqMaker => (
            DARK_POOL_MAKER_BASE_BPS,
            MAKER_ZERO_LOSS_FLOOR_BPS,
            MIN_MAKER_PROTOCOL_FEE_USD_MICROS,
        ),
        AgentVenue::DarkPool | AgentVenue::Spot => {
            let raw_taker_bps = if oracle.receive_asset == "KAS" && oracle.pay_asset != "USD" {
                BUY_KAS_TAKER_BASE_BPS
            } else if notional_usd_micros >= WHOLESALE_VOLUME_THRESHOLD_USD_MICROS {
                WHOLESALE_TAKER_BASE_BPS
            } else if oracle.allow_dark_pool {
                DARK_POOL_MAJOR_TAKER_BASE_BPS
            } else {
                PASS_THROUGH_TAKER_BASE_BPS
            };
            (
                raw_taker_bps,
                TAKER_ZERO_LOSS_FLOOR_BPS,
                MIN_TAKER_PROTOCOL_FEE_USD_MICROS,
            )
        }
    };

    let scalar_bps = claims.fee_tier_multiplier_bps.clamp(1_000, 10_000) as u128;
    let scaled_bps = div_ceil_u128((base_bps as u128).saturating_mul(scalar_bps), BPS_DENOMINATOR)?
        .max(floor_bps as u128) as u16;

    let raw_protocol_fee_usd_micros =
        mul_div_ceil_u128(notional_usd_micros, scaled_bps as u128, BPS_DENOMINATOR)?;
    let protocol_fee_usd_micros = raw_protocol_fee_usd_micros.max(min_fee_usd_micros);

    // Convert protocol fee into pay_asset atomic units (strictly ceil-rounded)
    let protocol_fee_pay_atomic =
        mul_div_ceil_u128(protocol_fee_usd_micros, usd_denom, oracle.pay_usd_e8)?;

    let total_fee_usd_micros = protocol_fee_usd_micros
        .checked_add(l1_network_fee_usd_micros)
        .and_then(|v| v.checked_add(external_gas_and_slip_usd_micros))
        .ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::SolvencyFloorViolation,
                "Total fee USD micros overflow.",
            )
        })?;

    if total_fee_usd_micros >= notional_usd_micros {
        return Err(AgentError::new(
            AgentErrorCode::SolvencyFloorViolation,
            format!(
                "ZERO_LOSS_INVARIANT_HALT: Total execution cost + fee ({} micro-USD) exceeds input notional ({} micro-USD).",
                total_fee_usd_micros, notional_usd_micros
            ),
        ));
    }

    let net_value_usd_micros = notional_usd_micros - total_fee_usd_micros;

    // Convert net_value_usd_micros -> receive_asset atomic units (strictly floor-rounded!)
    // atomic_out = floor((net_value_usd_micros * receive_unit_scale * 100) / receive_usd_e8)
    let out_scale_100 = receive_unit_scale.checked_mul(100).ok_or_else(|| {
        AgentError::new(
            AgentErrorCode::SolvencyFloorViolation,
            "Receive unit scale overflow.",
        )
    })?;
    let expected_amount_out_atomic =
        mul_div_floor_u128(net_value_usd_micros, out_scale_100, oracle.receive_usd_e8)?;

    if expected_amount_out_atomic == 0 {
        return Err(AgentError::new(
            AgentErrorCode::SolvencyFloorViolation,
            "ZERO_LOSS_INVARIANT_HALT: Net output rounded to 0 atomic units after full fee deduction.",
        ));
    }

    let retain_bps = BPS_DENOMINATOR.saturating_sub(requested_slippage_bps as u128);
    let min_amount_out_atomic =
        mul_div_floor_u128(expected_amount_out_atomic, retain_bps, BPS_DENOMINATOR)?;

    if min_amount_out_atomic == 0 {
        return Err(AgentError::new(
            AgentErrorCode::SolvencyFloorViolation,
            "minAmountOut rounded to 0 atomic units; increase swap size.",
        ));
    }

    Ok(SolvencyQuoteMath {
        pay_decimals,
        receive_decimals,
        notional_usd_micros,
        spend_sompi_equiv,
        applied_fee_bps: scaled_bps,
        protocol_fee_usd_micros,
        protocol_fee_pay_atomic,
        l1_network_fee_sompi,
        l1_network_fee_usd_micros,
        external_gas_and_slip_usd_micros,
        total_fee_usd_micros,
        net_value_usd_micros,
        expected_amount_out_atomic,
        min_amount_out_atomic,
        mass_breakdown,
    })
}

/// Builds a sterile, prompt-injection-safe market discovery & pulse snapshot strictly from Redis.
pub async fn build_cached_market_pulse_snapshot(
    redis_conn: &mut redis::aio::MultiplexedConnection,
) -> Result<Value, AgentError> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let (
        supported_raw,
        whitelist_members,
        blacklisted_tokens,
        steering_map,
        lp_depth_map,
        dp_kill,
        ext_kill,
    ): (
        Option<String>,
        Vec<String>,
        Vec<String>,
        HashMap<String, String>,
        HashMap<String, String>,
        Option<String>,
        Option<String>,
    ) = redis::pipe()
        .cmd("GET")
        .arg("oracle:spot:supported_assets")
        .cmd("SMEMBERS")
        .arg(REDIS_KEY_STEERING_WHITELIST)
        .cmd("SMEMBERS")
        .arg(REDIS_KEY_BLACKLISTED_TOKENS)
        .cmd("HGETALL")
        .arg(REDIS_KEY_STEERING_STATES)
        .cmd("HGETALL")
        .arg(REDIS_KEY_LP_DEPTH_CACHE)
        .cmd("GET")
        .arg("perennia:killswitch:dark_pool")
        .cmd("GET")
        .arg("perennia:killswitch:external_dex")
        .query_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to read market pulse governance snapshot from Redis.",
            )
        })?;

    let (
        usdc_depeg,
        usdt_depeg,
        usdc_usd_raw,
        usdt_usd_raw,
        virtual_daa_raw,
        node_sync_raw,
        reward_sompi_raw,
    ): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = redis::pipe()
        .cmd("GET")
        .arg("oracle:depeg_halt:USDC")
        .cmd("GET")
        .arg("oracle:depeg_halt:USDT")
        .cmd("GET")
        .arg("oracle:spot:USDC_USD")
        .cmd("GET")
        .arg("oracle:spot:USDT_USD")
        .cmd("GET")
        .arg("pool:virtual_daa_score")
        .cmd("GET")
        .arg("perennia:node:sync_status")
        .cmd("GET")
        .arg("pool:block_reward_sompi")
        .query_async(redis_conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to read market pulse consensus snapshot from Redis.",
            )
        })?;

    let blacklist_set: HashSet<String> = blacklisted_tokens
        .into_iter()
        .filter_map(|t| sanitize_sterile_ticker(&t).ok())
        .collect();
    let whitelist_set: HashSet<String> = whitelist_members
        .into_iter()
        .filter_map(|t| sanitize_sterile_ticker(&t).ok())
        .collect();

    let mut tickers: Vec<String> = supported_raw
        .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .unwrap_or_else(|| {
            vec![
                "KAS".to_string(),
                "USDC".to_string(),
                "USDT".to_string(),
                "BTC".to_string(),
                "ETH".to_string(),
                "SOL".to_string(),
                "SILO".to_string(),
            ]
        })
        .into_iter()
        .filter_map(|t| sanitize_sterile_ticker(&t).ok())
        .filter(|t| !blacklist_set.contains(t) && t != "USD")
        .collect();

    if !tickers.iter().any(|t| t == "SILO") && !blacklist_set.contains("SILO") {
        tickers.push("SILO".to_string());
    }
    tickers.sort();
    tickers.dedup();

    let mut spot_pipe = redis::pipe();
    for tick in &tickers {
        spot_pipe.cmd("GET").arg(format!("oracle:spot:{}_USDC", tick));
    }
    let raw_spots: Vec<Option<String>> = spot_pipe.query_async(redis_conn).await.map_err(|_| {
        AgentError::new(
            AgentErrorCode::RedisUnavailable,
            "Failed to pipeline cached oracle spot feeds.",
        )
    })?;

    let mut price_e8_map: HashMap<String, u128> = HashMap::new();
    for (tick, raw_opt) in tickers.iter().zip(raw_spots.into_iter()) {
        if let Some(s) = raw_opt {
            if let Ok(p_e8) = parse_decimal_str_to_u128_scaled(&s, 8) {
                if p_e8 > 0 {
                    price_e8_map.insert(tick.clone(), p_e8);
                }
            }
        }
    }
    if !price_e8_map.contains_key("SILO") {
        if let Some(&kas_e8) = price_e8_map.get("KAS") {
            if let Ok(silo_e8) = mul_div_floor_u128(kas_e8, 42_000, 1_000_000) {
                if silo_e8 > 0 {
                    price_e8_map.insert("SILO".to_string(), silo_e8);
                }
            }
        }
    }

    let usdc_parity_e8 = usdc_usd_raw
        .as_deref()
        .and_then(|s| parse_decimal_str_to_u128_scaled(s, 8).ok())
        .unwrap_or(ORACLE_USD_E8_SCALE);
    let usdt_parity_e8 = usdt_usd_raw
        .as_deref()
        .and_then(|s| parse_decimal_str_to_u128_scaled(s, 8).ok())
        .unwrap_or(ORACLE_USD_E8_SCALE);

    let usdc_halted = usdc_depeg
        .as_deref()
        .map(|s| s.trim() == "1" || s.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        || !(STABLECOIN_PARITY_MIN_E8..=STABLECOIN_PARITY_MAX_E8).contains(&usdc_parity_e8);

    let usdt_halted = usdt_depeg
        .as_deref()
        .map(|s| s.trim() == "1" || s.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        || !(STABLECOIN_PARITY_MIN_E8..=STABLECOIN_PARITY_MAX_E8).contains(&usdt_parity_e8);

    let dark_pool_paused = dp_kill
        .as_deref()
        .map(|s| s.trim() == "1" || s.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let external_dex_paused = ext_kill
        .as_deref()
        .map(|s| s.trim() == "1" || s.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    // Query resting Dark Pool RFQ depth summaries for active KAS/{QUOTE} pairs
    let mut rfq_pipe = redis::pipe();
    let mut candidate_pairs: Vec<(String, String, String)> = Vec::new();
    for quote_tick in &tickers {
        if quote_tick == "KAS" {
            continue;
        }
        let pair_id = format!("KAS/{}", quote_tick);
        rfq_pipe
            .cmd("ZCOUNT")
            .arg(format!("perennia:agent:rfq_book:{}", pair_id))
            .arg(now_ms)
            .arg("+inf");
        candidate_pairs.push(("KAS".to_string(), quote_tick.clone(), pair_id));
    }
    let rfq_counts: Vec<u64> = rfq_pipe.query_async(redis_conn).await.unwrap_or_default();

    let kas_e8 = price_e8_map.get("KAS").copied().unwrap_or(0);
    let mut pairs_out: Vec<Value> = Vec::with_capacity(candidate_pairs.len());

    for (idx, (base, quote, pair_id)) in candidate_pairs.into_iter().enumerate() {
        let Some(&quote_e8) = price_e8_map.get(&quote) else {
            continue;
        };
        if kas_e8 == 0 || quote_e8 == 0 {
            continue;
        }

        // Midpoint rate of 1 KAS in `quote` scaled by 10^8: floor((kas_e8 * 10^8) / quote_e8)
        let midpoint_rate_e8 =
            mul_div_floor_u128(kas_e8, ORACLE_USD_E8_SCALE, quote_e8).unwrap_or(0);

        let quote_state = steering_map
            .get(&quote)
            .map(|s| s.trim().to_ascii_uppercase())
            .unwrap_or_else(|| "PASS_THROUGH".to_string());
        if quote_state == "BLACKLISTED" {
            continue;
        }

        let is_whitelisted_dp = whitelist_set.contains(&quote) && quote_state != "PASS_THROUGH";
        let asset_standard = match quote.as_str() {
            "SILO" | "NACHO" | "BEDRCK" | "PERX" | "KASPY" | "KASPER" | "KANGO" | "GHOAD"
            | "KEKE" => "KRC20_OR_KCC20",
            "USDC" | "USDT" => "STABLECOIN",
            "SPY" | "QQQ" | "NVDA" | "AAPL" | "TSLA" | "AMD" | "TSM" | "AVGO" | "XLE" | "XAU"
            | "XAG" | "USTB" => "RWA_SYNTHETIC",
            _ => "MULTI_CHAIN_L1",
        };

        let (reserve_kas_e8, reserve_quote_e8) = lp_depth_map
            .get(&pair_id)
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .map(|v| {
                (
                    v.get("reserveAE8")
                        .and_then(|x| x.as_str())
                        .unwrap_or("0")
                        .to_string(),
                    v.get("reserveBE8")
                        .and_then(|x| x.as_str())
                        .unwrap_or("0")
                        .to_string(),
                )
            })
            .unwrap_or_else(|| ("0".to_string(), "0".to_string()));

        let pair_depeg_halted =
            (quote == "USDC" && usdc_halted) || (quote == "USDT" && usdt_halted);
        let taker_bps = if is_whitelisted_dp {
            DARK_POOL_MAJOR_TAKER_BASE_BPS
        } else {
            PASS_THROUGH_TAKER_BASE_BPS
        };
        let active_rfq_orders = rfq_counts.get(idx).copied().unwrap_or(0);

        pairs_out.push(json!({
            "pair": pair_id,
            "baseAsset": base,
            "quoteAsset": quote,
            "assetStandard": asset_standard,
            "baseDecimals": atomic_decimals_for_asset("KAS"),
            "quoteDecimals": atomic_decimals_for_asset(&quote),
            "baseOracleUsdE8": U128Str(kas_e8),
            "quoteOracleUsdE8": U128Str(quote_e8),
            "darkPoolMidpointRateE8": U128Str(midpoint_rate_e8),
            "poolReserveBaseE8": reserve_kas_e8,
            "poolReserveQuoteE8": reserve_quote_e8,
            "restingRfqCount": active_rfq_orders.to_string(),
            "darkPoolEligible": is_whitelisted_dp && !dark_pool_paused && !pair_depeg_halted,
            "depegHalted": pair_depeg_halted,
            "makerFeeBaseBps": DARK_POOL_MAKER_BASE_BPS,
            "makerZeroLossFloorBps": MAKER_ZERO_LOSS_FLOOR_BPS,
            "takerFeeBaseBps": taker_bps,
            "takerBuyKasBps": BUY_KAS_TAKER_BASE_BPS,
            "takerWholesaleBps": WHOLESALE_TAKER_BASE_BPS,
            "takerZeroLossFloorBps": TAKER_ZERO_LOSS_FLOOR_BPS
        }));
    }

    let mut assets_out: Vec<Value> = Vec::with_capacity(price_e8_map.len());
    for tick in &tickers {
        if let Some(&p_e8) = price_e8_map.get(tick) {
            assets_out.push(json!({
                "ticker": tick,
                "atomicDecimals": atomic_decimals_for_asset(tick),
                "oracleUsdE8": U128Str(p_e8),
                "whitelistedDarkPool": whitelist_set.contains(tick)
            }));
        }
    }

    let node_online = node_sync_raw
        .as_deref()
        .map(|s| s.trim().eq_ignore_ascii_case("online"))
        .unwrap_or(false);
    let virtual_daa = virtual_daa_raw
        .as_deref()
        .and_then(|s| s.trim().parse::<u128>().ok())
        .unwrap_or(0);
    let block_reward_sompi = reward_sompi_raw
        .as_deref()
        .and_then(|s| s.trim().parse::<u128>().ok())
        .unwrap_or(0);

    let _ = SOMPI_PER_KAS;
    let _ = USD_MICROS_SCALE;

    Ok(json!({
        "ok": true,
        "snapshotTimestampMs": now_ms.to_string(),
        "nodeConsensus": {
            "kaspadOnline": node_online,
            "virtualDaaScore": U128Str(virtual_daa),
            "blockSubsidySompi": U128Str(block_reward_sompi),
            "postToccataMinSompiPerGram": U128Str(POST_TOCCATA_CONSENSUS_SOMPI_PER_GRAM),
            "relaySafeSompiPerGram": U128Str(RELAY_SAFE_SOMPI_PER_GRAM)
        },
        "circuitBreakers": {
            "kasOracleOnline": kas_e8 > 0,
            "darkPoolPaused": dark_pool_paused,
            "externalDexPaused": external_dex_paused,
            "usdcParityUsdE8": U128Str(usdc_parity_e8),
            "usdcDepegHalted": usdc_halted,
            "usdtParityUsdE8": U128Str(usdt_parity_e8),
            "usdtDepegHalted": usdt_halted,
            "minSwapNotionalUsdMicros": U128Str(MIN_AGENT_NOTIONAL_USD_MICROS)
        },
        "assets": assets_out,
        "markets": pairs_out
    }))
}