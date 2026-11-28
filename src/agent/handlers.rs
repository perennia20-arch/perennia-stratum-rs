// src/agent/handlers.rs

use axum::{
    extract::{
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
        FromRequestParts, Query, State,
    },
    http::HeaderMap,
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        IntoResponse, Response,
    },
    Json,
};
use chrono::{DateTime, Utc};
use futures_util::{stream, StreamExt};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::{PgPool, Row};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    convert::Infallible,
    env,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

use crate::agent::{
    auth::{self, authenticate_agent_request},
    dark_pool,
    locks_and_limits::{self, ConsumedQuoteOutcome},
    solvency::{
        self, compute_zero_loss_quote_math, div_ceil_u128, format_u128_scaled_to_decimal_str,
        mul_div_ceil_u128, mul_div_floor_u128, parse_decimal_str_to_u128_scaled,
        DARK_POOL_MAJOR_TAKER_BASE_BPS, DARK_POOL_MAKER_BASE_BPS, MAKER_ZERO_LOSS_FLOOR_BPS,
        TAKER_ZERO_LOSS_FLOOR_BPS,
    },
    types::{
        atomic_decimals_for_asset, pow10_u128, reject_forbidden_cold_vault_or_withdrawal_keys,
        sanitize_sterile_ticker, validate_hex_64, validate_hex_bounded, validate_idempotency_key,
        AgentCapabilityClaims, AgentError, AgentErrorCode, AgentMode, AgentVenue, OutpointRef,
        PostToccataEnvelope, StoredAgentQuote, U128Str, BPS_DENOMINATOR, MAX_MAKER_RFQ_TTL_SECS,
        MAX_TAKER_QUOTE_TTL_SECS, MIN_MAKER_RFQ_TTL_SECS,
    },
    verifier::{
        build_unsigned_0x83_sleeve_ticket, build_unsigned_l1_kaspa_ticket,
        compute_execution_commitment_hash, select_and_verify_wallet_utxos,
        verify_signed_execution_submission, VerifiedExecutionPayload,
    },
    AgentGatewayState, REDIS_KEY_AI_INTENT_SKEW, REDIS_KEY_BLACKLISTED_WALLETS, REDIS_KEY_LATEST_PULSE,
};

type HmacSha256 = Hmac<Sha256>;
type WsUpgradeRejection = <WebSocketUpgrade as FromRequestParts<AgentGatewayState>>::Rejection;

const LUA_PUBLIC_MARKETS_IP_RL: &str = r#"
local c = redis.call('INCR', KEYS[1])
if c == 1 then
    redis.call('EXPIRE', KEYS[1], 60)
end
return c
"#;

#[inline]
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[inline]
fn is_kaspa_l1_asset(ticker: &str) -> bool {
    matches!(
        ticker,
        "KAS" | "SILO" | "NACHO" | "BEDRCK" | "PERX" | "KASPY" | "KASPER" | "KANGO" | "GHOAD" | "KEKE"
    )
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HifoU128Simulation {
    pub matched_cost_basis_usd_micros: U128Str,
    pub gross_proceeds_usd_micros: U128Str,
    pub realized_delta_usd_micros: U128Str,
    pub is_net_gain: bool,
    pub holding_period: String,
    pub lots_matched_count: u32,
    pub primary_disposal_lot_id: Option<Uuid>,
}

// ============================================================================
// EXACT u128 HIFO TAX-LOT ENGINE & RESERVOIR HMAC UPDATER (ZERO f64)
// ============================================================================

fn resolve_reservoir_hmac_key() -> Result<Vec<u8>, AgentError> {
    let raw = env::var("LEDGER_HMAC_SECRET")
        .or_else(|_| env::var("KYC_MASTER_KEY"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if raw.len() < 32 {
        return Err(AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "CRITICAL_SECURITY_LOCKDOWN: LEDGER_HMAC_SECRET (min 32 chars) is missing.",
        ));
    }
    Ok(raw.into_bytes())
}

/// Computes the exact `yield_reservoirs.row_hmac_sig` (`PERENNIA_RESERVOIR_V1|...`)
/// using 100% integer `u128` 8-decimal formatting so `chronos::verify_wallet_ledger_invariant_or_quarantine`
/// validates every Mode B sleeve mutation without a single `f64` cast.
fn compute_reservoir_hmac_exact_e8(
    clean_wallet: &str,
    streaming_kas_e8: u128,
    total_yield_kas_e8: u128,
    lp_tokens_e8: &BTreeMap<String, u128>,
) -> Result<String, AgentError> {
    let secret = resolve_reservoir_hmac_key()?;
    let mut parts: Vec<String> = Vec::with_capacity(lp_tokens_e8.len());
    for (ticker, &amt_e8) in lp_tokens_e8 {
        if amt_e8 >= 1 {
            parts.push(format!(
                "{}:{}",
                ticker,
                format_u128_scaled_to_decimal_str(amt_e8, 8)
            ));
        }
    }
    let canonical_lp = format!("{{{}}}", parts.join(","));
    let preimage = format!(
        "PERENNIA_RESERVOIR_V1|kaspa:{}|{}|{}|{}",
        clean_wallet,
        format_u128_scaled_to_decimal_str(streaming_kas_e8, 8),
        format_u128_scaled_to_decimal_str(total_yield_kas_e8, 8),
        canonical_lp
    );

    let mut mac = HmacSha256::new_from_slice(&secret).map_err(|_| {
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Failed to initialize reservoir HMAC-SHA256.",
        )
    })?;
    mac.update(preimage.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn convert_atomic_to_e8(amount_atomic: u128, decimals: u8) -> Result<u128, AgentError> {
    if decimals == 8 {
        Ok(amount_atomic)
    } else if decimals < 8 {
        let factor = 10u128.pow((8 - decimals) as u32);
        amount_atomic.checked_mul(factor).ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::SolvencyFloorViolation,
                "Atomic-to-E8 scaling overflow.",
            )
        })
    } else {
        let divisor = 10u128.pow((decimals - 8) as u32);
        Ok(amount_atomic / divisor)
    }
}

fn convert_atomic_ceil_to_e8(amount_atomic: u128, decimals: u8) -> Result<u128, AgentError> {
    if decimals <= 8 {
        convert_atomic_to_e8(amount_atomic, decimals)
    } else {
        let divisor = 10u128.pow((decimals - 8) as u32);
        div_ceil_u128(amount_atomic, divisor)
    }
}

/// Reads a wallet's unlocked execution-sleeve balances from `yield_reservoirs` as exact `e8` (`10^8`) integers.
async fn read_wallet_sleeve_balances_e8(
    pool: &PgPool,
    clean_wallet: &str,
    prefixed_wallet: &str,
) -> Result<(u128, u128, BTreeMap<String, u128>, String), AgentError> {
    let row_opt = sqlx::query(
        r#"
        SELECT wallet_address,
               TRUNC(GREATEST(streaming_balance_kas, 0) * 100000000)::NUMERIC(39, 0)::TEXT AS streaming_e8,
               TRUNC(GREATEST(total_yield_kas, 0) * 100000000)::NUMERIC(39, 0)::TEXT AS total_yield_e8,
               COALESCE(lp_tokens, '{}'::jsonb) AS lp_tokens,
               COALESCE(quarantined, FALSE) AS quarantined,
               quarantine_reason
        FROM yield_reservoirs
        WHERE wallet_address = $1 OR wallet_address = $2
        ORDER BY streaming_balance_kas DESC
        LIMIT 1
        "#,
    )
    .bind(prefixed_wallet)
    .bind(clean_wallet)
    .fetch_optional(pool)
    .await
    .map_err(|_| {
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Failed to query yield_reservoirs execution sleeve.",
        )
    })?;

    let Some(row) = row_opt else {
        return Ok((0, 0, BTreeMap::new(), prefixed_wallet.to_string()));
    };

    if row.try_get::<bool, _>("quarantined").unwrap_or(false) {
        let reason: String = row
            .try_get::<Option<String>, _>("quarantine_reason")
            .ok()
            .flatten()
            .unwrap_or_else(|| "Ledger invariant quarantine".to_string());
        return Err(AgentError::new(
            AgentErrorCode::MandateViolation,
            format!("Execution sleeve is quarantined: {}", reason),
        ));
    }

    let pk: String = row
        .try_get("wallet_address")
        .unwrap_or_else(|_| prefixed_wallet.to_string());
    let streaming_e8: u128 = row
        .try_get::<String, _>("streaming_e8")
        .ok()
        .and_then(|s| s.trim().parse::<u128>().ok())
        .unwrap_or(0);
    let total_yield_e8: u128 = row
        .try_get::<String, _>("total_yield_e8")
        .ok()
        .and_then(|s| s.trim().parse::<u128>().ok())
        .unwrap_or(0);

    let lp_val: Value = row.try_get("lp_tokens").unwrap_or_else(|_| json!({}));
    let mut lp_map: BTreeMap<String, u128> = BTreeMap::new();
    if let Some(obj) = lp_val.as_object() {
        for (raw_k, raw_v) in obj {
            let Ok(tick) = sanitize_sterile_ticker(raw_k) else {
                continue;
            };
            let raw_str = match raw_v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => continue,
            };
            if let Ok(parsed_e8) = parse_decimal_str_to_u128_scaled(&raw_str, 8) {
                if parsed_e8 > 0 {
                    lp_map.insert(tick, parsed_e8);
                }
            }
        }
    }

    Ok((streaming_e8, total_yield_e8, lp_map, pk))
}

/// Atomically settles a Mode B execution-sleeve swap in PostgreSQL `yield_reservoirs` + Redis cache
/// using exact `u128` math and re-signing `row_hmac_sig`.
async fn settle_sleeve_swap_exact_u128(
    pool: &PgPool,
    redis_conn: &mut redis::aio::MultiplexedConnection,
    clean_wallet: &str,
    prefixed_wallet: &str,
    pay_asset: &str,
    pay_decimals: u8,
    amount_in_atomic: u128,
    receive_asset: &str,
    receive_decimals: u8,
    settled_out_atomic: u128,
) -> Result<(), AgentError> {
    let debit_e8 = convert_atomic_ceil_to_e8(amount_in_atomic, pay_decimals)?;
    let credit_e8 = convert_atomic_to_e8(settled_out_atomic, receive_decimals)?;

    if debit_e8 == 0 || credit_e8 == 0 {
        return Err(AgentError::new(
            AgentErrorCode::SolvencyFloorViolation,
            "Sleeve settlement atomic conversion rounded to zero.",
        ));
    }

    let (mut streaming_e8, total_yield_e8, mut lp_map, target_pk) =
        read_wallet_sleeve_balances_e8(pool, clean_wallet, prefixed_wallet).await?;

    if pay_asset == "KAS" {
        if streaming_e8 < debit_e8 {
            return Err(AgentError::new(
                AgentErrorCode::InvalidInput,
                format!(
                    "Insufficient execution-sleeve KAS balance: available {} sompi, requested {} sompi.",
                    streaming_e8, debit_e8
                ),
            ));
        }
        streaming_e8 -= debit_e8;
    } else {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            format!(
                "SYNTHETIC_IOU_FORBIDDEN: Execution-sleeve non-KAS asset {} cannot mutate yield_reservoirs.lp_tokens; settle directly via L1 UTXOs.",
                pay_asset
            ),
        ));
    }

    let added_verified_kas_e8: u128 = if receive_asset == "KAS" {
        streaming_e8 = streaming_e8.checked_add(credit_e8).ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::SolvencyFloorViolation,
                "Execution-sleeve KAS credit overflow.",
            )
        })?;
        credit_e8
    } else {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            format!(
                "SYNTHETIC_IOU_FORBIDDEN: Execution-sleeve output {} cannot be credited as synthetic IOUs in yield_reservoirs.lp_tokens.",
                receive_asset
            ),
        ));
    };
    lp_map.clear();

    let new_hmac =
        compute_reservoir_hmac_exact_e8(clean_wallet, streaming_e8, total_yield_e8, &lp_map)?;

    let lp_json = Value::Object(serde_json::Map::new());
    let streaming_str = format_u128_scaled_to_decimal_str(streaming_e8, 8);
    let total_yield_str = format_u128_scaled_to_decimal_str(total_yield_e8, 8);
    let added_verified_str = format_u128_scaled_to_decimal_str(added_verified_kas_e8, 8);

    sqlx::query(
        r#"
        INSERT INTO yield_reservoirs (
            wallet_address, streaming_balance_kas, total_yield_kas,
            lp_tokens, verified_onchain_credits_kas, row_hmac_sig, last_updated
        ) VALUES (
            $1,
            $2::NUMERIC::DOUBLE PRECISION,
            $3::NUMERIC::DOUBLE PRECISION,
            $4,
            $5::NUMERIC::DOUBLE PRECISION,
            $6,
            CURRENT_TIMESTAMP
        )
        ON CONFLICT (wallet_address) DO UPDATE SET
            streaming_balance_kas = EXCLUDED.streaming_balance_kas,
            lp_tokens = EXCLUDED.lp_tokens,
            verified_onchain_credits_kas = yield_reservoirs.verified_onchain_credits_kas + $5::NUMERIC::DOUBLE PRECISION,
            row_hmac_sig = EXCLUDED.row_hmac_sig,
            last_updated = CURRENT_TIMESTAMP
        "#,
    )
    .bind(&target_pk)
    .bind(&streaming_str)
    .bind(&total_yield_str)
    .bind(&lp_json)
    .bind(&added_verified_str)
    .bind(&new_hmac)
    .execute(pool)
    .await
    .map_err(|e| {
        tracing::error!("❌ [AGENT SLEEVE] Failed to persist yield_reservoirs row: {}", e);
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Failed to persist execution-sleeve swap in PostgreSQL.",
        )
    })?;

    let redis_bal_key = format!("dev:sor:treasury:balances:{}", clean_wallet);
    let pay_bal_str = if pay_asset == "KAS" {
        streaming_str.clone()
    } else {
        format_u128_scaled_to_decimal_str(lp_map.get(pay_asset).copied().unwrap_or(0), 8)
    };
    let rec_bal_str = if receive_asset == "KAS" {
        streaming_str
    } else {
        format_u128_scaled_to_decimal_str(lp_map.get(receive_asset).copied().unwrap_or(0), 8)
    };

    let _: redis::RedisResult<()> = redis::pipe()
        .cmd("HSET")
        .arg(&redis_bal_key)
        .arg(pay_asset)
        .arg(pay_bal_str)
        .ignore()
        .cmd("HSET")
        .arg(&redis_bal_key)
        .arg(receive_asset)
        .arg(rec_bal_str)
        .ignore()
        .query_async(redis_conn)
        .await;

    Ok(())
}

/// Simulates or executes exact `u128` HIFO tax-lot matching against `hifo_tax_lots`.
/// When `mutate_db == false` (`dry_run: true`), ZERO rows are modified.
async fn process_hifo_disposal_u128(
    pool: &PgPool,
    clean_wallet: &str,
    prefixed_wallet: &str,
    pay_asset: &str,
    pay_decimals: u8,
    dispose_atomic: u128,
    pay_oracle_usd_e8: u128,
    disposal_tx_hash: Option<&str>,
    mutate_db: bool,
) -> Result<HifoU128Simulation, AgentError> {
    let unit_scale = pow10_u128(pay_decimals)?;
    let usd_denom = unit_scale.saturating_mul(100);
    let gross_proceeds_usd_micros = mul_div_floor_u128(dispose_atomic, pay_oracle_usd_e8, usd_denom)?;

    let open_lots = sqlx::query(
        r#"
        SELECT lot_id,
               acquired_at,
               TRUNC(GREATEST(remaining_tokens, 0) * POWER(10::NUMERIC, $4))::NUMERIC(39, 0)::TEXT AS rem_atomic,
               TRUNC(GREATEST(fmv_usd_per_token, 0) * 100000000)::NUMERIC(39, 0)::TEXT AS fmv_e8
        FROM hifo_tax_lots
        WHERE (wallet_address = $1 OR wallet_address = $2)
          AND asset_ticker = $3
          AND status = 'OPEN'
          AND remaining_tokens > 0
        ORDER BY fmv_usd_per_token DESC, acquired_at ASC
        LIMIT 100
        "#,
    )
    .bind(clean_wallet)
    .bind(prefixed_wallet)
    .bind(pay_asset)
    .bind(pay_decimals as i32)
    .fetch_all(pool)
    .await
    .map_err(|_| {
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Database unavailable while querying hifo_tax_lots.",
        )
    })?;

    let mut remaining_to_dispose = dispose_atomic;
    let mut matched_cost_basis_usd_micros: u128 = 0;
    let mut lots_matched_count: u32 = 0;
    let mut any_long_term = false;
    let mut primary_lot_id: Option<Uuid> = None;
    let now = Utc::now();

    for row in open_lots {
        if remaining_to_dispose == 0 {
            break;
        }
        let Ok(lot_id) = row.try_get::<Uuid, _>("lot_id") else {
            continue;
        };
        let acquired_at: DateTime<Utc> = row.try_get("acquired_at").unwrap_or(now);
        let lot_rem_atomic: u128 = row
            .try_get::<String, _>("rem_atomic")
            .ok()
            .and_then(|s| s.trim().parse::<u128>().ok())
            .unwrap_or(0);
        if lot_rem_atomic == 0 {
            continue;
        }
        let fmv_e8: u128 = row
            .try_get::<String, _>("fmv_e8")
            .ok()
            .and_then(|s| s.trim().parse::<u128>().ok())
            .unwrap_or(pay_oracle_usd_e8);

        let consumed_atomic = remaining_to_dispose.min(lot_rem_atomic);
        let new_rem_atomic = lot_rem_atomic - consumed_atomic;

        let leg_cost_usd_micros = mul_div_ceil_u128(consumed_atomic, fmv_e8, usd_denom)?;
        let leg_proceeds_usd_micros =
            mul_div_floor_u128(consumed_atomic, pay_oracle_usd_e8, usd_denom)?;

        let holding_days = (now - acquired_at).num_days().max(0) as i32;
        let is_long_term = holding_days > 365;
        if is_long_term {
            any_long_term = true;
        }
        if primary_lot_id.is_none() {
            primary_lot_id = Some(lot_id);
        }

        if mutate_db {
            let new_status = if new_rem_atomic == 0 { "CLOSED" } else { "OPEN" };
            let new_rem_str = format_u128_scaled_to_decimal_str(new_rem_atomic, pay_decimals);
            let new_sompi_i64 = i64::try_from(convert_atomic_to_e8(new_rem_atomic, pay_decimals)?)
                .unwrap_or(i64::MAX);

            sqlx::query(
                r#"
                UPDATE hifo_tax_lots
                SET remaining_tokens = $2::NUMERIC::DOUBLE PRECISION,
                    remaining_sompi = $3,
                    status = $4
                WHERE lot_id = $1
                "#,
            )
            .bind(lot_id)
            .bind(&new_rem_str)
            .bind(new_sompi_i64)
            .bind(new_status)
            .execute(pool)
            .await
            .map_err(|_| {
                AgentError::new(
                    AgentErrorCode::DatabaseUnavailable,
                    "Failed to update consumed hifo_tax_lots record.",
                )
            })?;

            let disposed_sompi_i64 =
                i64::try_from(convert_atomic_to_e8(consumed_atomic, pay_decimals)?)
                    .unwrap_or(i64::MAX);
            let disposed_tok_str = format_u128_scaled_to_decimal_str(consumed_atomic, pay_decimals);
            let leg_cost_str = format_u128_scaled_to_decimal_str(leg_cost_usd_micros, 6);
            let leg_proc_str = format_u128_scaled_to_decimal_str(leg_proceeds_usd_micros, 6);
            let signed_leg_gain_str = if leg_proceeds_usd_micros >= leg_cost_usd_micros {
                format_u128_scaled_to_decimal_str(
                    leg_proceeds_usd_micros - leg_cost_usd_micros,
                    6,
                )
            } else {
                format!(
                    "-{}",
                    format_u128_scaled_to_decimal_str(
                        leg_cost_usd_micros - leg_proceeds_usd_micros,
                        6
                    )
                )
            };

            sqlx::query(
                r#"
                INSERT INTO hifo_disposal_matches (
                    lot_id, wallet_address, asset_ticker, disposed_sompi,
                    disposed_tokens, acquired_at, holding_period_days,
                    is_long_term, cost_basis_usd, gross_proceeds_usd,
                    realized_gain_loss_usd, disposal_tx_hash
                ) VALUES (
                    $1, $2, $3, $4,
                    $5::NUMERIC::DOUBLE PRECISION, $6, $7,
                    $8, $9::NUMERIC::DOUBLE PRECISION, $10::NUMERIC::DOUBLE PRECISION,
                    $11::NUMERIC::DOUBLE PRECISION, $12
                )
                "#,
            )
            .bind(lot_id)
            .bind(clean_wallet)
            .bind(pay_asset)
            .bind(disposed_sompi_i64)
            .bind(&disposed_tok_str)
            .bind(acquired_at)
            .bind(holding_days)
            .bind(is_long_term)
            .bind(&leg_cost_str)
            .bind(&leg_proc_str)
            .bind(&signed_leg_gain_str)
            .bind(disposal_tx_hash)
            .execute(pool)
            .await
            .map_err(|_| {
                AgentError::new(
                    AgentErrorCode::DatabaseUnavailable,
                    "Failed to insert hifo_disposal_matches entry.",
                )
            })?;
        }

        matched_cost_basis_usd_micros =
            matched_cost_basis_usd_micros.saturating_add(leg_cost_usd_micros);
        remaining_to_dispose -= consumed_atomic;
        lots_matched_count = lots_matched_count.saturating_add(1);
    }

    if remaining_to_dispose > 0 {
        let unlot_basis =
            mul_div_floor_u128(remaining_to_dispose, pay_oracle_usd_e8, usd_denom)?;
        matched_cost_basis_usd_micros =
            matched_cost_basis_usd_micros.saturating_add(unlot_basis);
    }

    let (is_net_gain, realized_delta_usd_micros) =
        if gross_proceeds_usd_micros >= matched_cost_basis_usd_micros {
            (
                true,
                gross_proceeds_usd_micros - matched_cost_basis_usd_micros,
            )
        } else {
            (
                false,
                matched_cost_basis_usd_micros - gross_proceeds_usd_micros,
            )
        };

    let holding_period = if any_long_term {
        "LONG_TERM".to_string()
    } else {
        "SHORT_TERM".to_string()
    };

    Ok(HifoU128Simulation {
        matched_cost_basis_usd_micros: U128Str(matched_cost_basis_usd_micros),
        gross_proceeds_usd_micros: U128Str(gross_proceeds_usd_micros),
        realized_delta_usd_micros: U128Str(realized_delta_usd_micros),
        is_net_gain,
        holding_period,
        lots_matched_count,
        primary_disposal_lot_id: primary_lot_id,
    })
}

async fn record_hifo_acquisition_u128(
    pool: &PgPool,
    clean_wallet: &str,
    receive_asset: &str,
    receive_decimals: u8,
    settled_out_atomic: u128,
    receive_oracle_usd_e8: u128,
    notional_cost_basis_usd_micros: u128,
    source_tx_hash: &str,
) -> Result<Uuid, AgentError> {
    let sompi_i64 = i64::try_from(convert_atomic_to_e8(settled_out_atomic, receive_decimals)?)
        .unwrap_or(i64::MAX);
    let tokens_str = format_u128_scaled_to_decimal_str(settled_out_atomic, receive_decimals);
    let fmv_str = format_u128_scaled_to_decimal_str(receive_oracle_usd_e8, 8);
    let basis_str = format_u128_scaled_to_decimal_str(notional_cost_basis_usd_micros, 6);

    let row = sqlx::query(
        r#"
        INSERT INTO hifo_tax_lots (
            wallet_address, asset_ticker, kas_sompi, initial_tokens,
            remaining_sompi, remaining_tokens, fmv_usd_per_token,
            total_cost_basis_usd, source_event_type, source_tx_hash, status
        ) VALUES (
            $1, $2, $3, $4::NUMERIC::DOUBLE PRECISION,
            $3, $4::NUMERIC::DOUBLE PRECISION, $5::NUMERIC::DOUBLE PRECISION,
            $6::NUMERIC::DOUBLE PRECISION, 'AGENT_SWAP', $7, 'OPEN'
        )
        RETURNING lot_id
        "#,
    )
    .bind(clean_wallet)
    .bind(receive_asset)
    .bind(sompi_i64)
    .bind(&tokens_str)
    .bind(&fmv_str)
    .bind(&basis_str)
    .bind(source_tx_hash)
    .fetch_one(pool)
    .await
    .map_err(|_| {
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Failed to record HIFO acquisition lot in PostgreSQL.",
        )
    })?;

    row.try_get::<Uuid, _>("lot_id").map_err(|_| {
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Failed to read returned HIFO acquisition lot_id.",
        )
    })
}

async fn append_dry_run_audit_log(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    clean_wallet: &str,
    entry: &Value,
) {
    let key = format!("perennia:agent:dry_run_logs:{}", clean_wallet);
    let _: redis::RedisResult<()> = redis::pipe()
        .cmd("LPUSH")
        .arg(&key)
        .arg(entry.to_string())
        .ignore()
        .cmd("LTRIM")
        .arg(&key)
        .arg(0)
        .arg(24)
        .ignore()
        .cmd("EXPIRE")
        .arg(&key)
        .arg(604_800u64)
        .ignore()
        .query_async(redis_conn)
        .await;
}

// ============================================================================
// ENDPOINT 1: MARKET PULSE & PAIR DISCOVERY (GET /api/v1/agent/markets)
// ============================================================================

pub async fn core_get_markets(
    state: &AgentGatewayState,
    headers: &HeaderMap,
) -> Result<Value, AgentError> {
    let mut conn = state.get_redis_conn().await?;

    let has_auth_header =
        headers.contains_key("authorization") || headers.contains_key("x-agent-key");

    let mut personalized_tier: Option<Value> = None;

    if has_auth_header {
        let claims = authenticate_agent_request(state, headers, &mut conn).await?;
        let rl = locks_and_limits::enforce_dynamic_rate_limit(state, &mut conn, &claims, false).await?;

        let scalar = claims.fee_tier_multiplier_bps as u128;
        let eff_maker_bps = div_ceil_u128(
            (DARK_POOL_MAKER_BASE_BPS as u128).saturating_mul(scalar),
            BPS_DENOMINATOR,
        )?
        .max(MAKER_ZERO_LOSS_FLOOR_BPS as u128);
        let eff_dp_taker_bps = div_ceil_u128(
            (DARK_POOL_MAJOR_TAKER_BASE_BPS as u128).saturating_mul(scalar),
            BPS_DENOMINATOR,
        )?
        .max(TAKER_ZERO_LOSS_FLOOR_BPS as u128);

        personalized_tier = Some(json!({
            "keyId": claims.key_id,
            "mode": claims.mode,
            "feeTierMultiplierBps": claims.fee_tier_multiplier_bps,
            "effectiveDarkPoolMakerBps": eff_maker_bps,
            "effectiveDarkPoolTakerBps": eff_dp_taker_bps,
            "rateLimit": rl
        }));
    } else {
        let client_ip = crate::agent::extract_client_ip(headers);
        let rl_key = format!("perennia:agent:public_markets_rl:{}", client_ip);
        let hits: u64 = redis::Script::new(LUA_PUBLIC_MARKETS_IP_RL)
            .key(&rl_key)
            .invoke_async(&mut conn)
            .await
            .map_err(|_| {
                AgentError::new(
                    AgentErrorCode::RedisUnavailable,
                    "Redis unavailable during public discovery rate-limit check.",
                )
            })?;
        if hits > 30 {
            return Err(AgentError::new(
                AgentErrorCode::EdgeCapacityExceeded,
                "Unauthenticated /markets discovery capped at 30 req/min; authenticate with an Agent Key or subscribe to /api/v1/agent/stream.",
            ));
        }
    }

    let cached_raw: Option<String> = redis::cmd("GET")
        .arg(REDIS_KEY_LATEST_PULSE)
        .query_async(&mut conn)
        .await
        .ok()
        .flatten();

    let mut snapshot = match cached_raw.and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
        Some(v) => v,
        None => solvency::build_cached_market_pulse_snapshot(&mut conn).await?,
    };

    if let Some(tier_info) = personalized_tier {
        snapshot["callerFeeProfile"] = tier_info;
    }

    Ok(snapshot)
}

pub async fn handle_get_markets(
    State(state): State<AgentGatewayState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AgentError> {
    let body = core_get_markets(&state, &headers).await?;
    Ok(Json(body))
}

async fn publish_anonymized_ai_intent_skew(
    state: &AgentGatewayState,
    redis_conn: &mut redis::aio::MultiplexedConnection,
    pay_asset: &str,
    receive_asset: &str,
    venue: &str,
    spend_sompi_equiv: u128,
    notional_usd_micros: u128,
) {
    let kas_delta_i128: i128 = if pay_asset == "KAS" && receive_asset != "KAS" {
        -(spend_sompi_equiv as i128)
    } else if receive_asset == "KAS" && pay_asset != "KAS" {
        spend_sompi_equiv as i128
    } else {
        0
    };
    let existing_raw: Option<String> = redis::cmd("GET")
        .arg(REDIS_KEY_AI_INTENT_SKEW)
        .query_async(redis_conn)
        .await
        .ok()
        .flatten();
    let mut skew_doc: Value = existing_raw
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .unwrap_or_else(|| {
            json!({
                "netKasDeltaSompi": "0",
                "totalVolumeUsdMicros": "0",
                "pairs": {}
            })
        });
    let prev_net = skew_doc
        .get("netKasDeltaSompi")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i128>().ok())
        .unwrap_or(0);
    let prev_vol = skew_doc
        .get("totalVolumeUsdMicros")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(0);
    let new_net = prev_net.saturating_add(kas_delta_i128);
    let new_vol = prev_vol.saturating_add(notional_usd_micros);
    let pair_key = format!("{}/{}", pay_asset, receive_asset);
    let prev_pair_vol = skew_doc
        .get("pairs")
        .and_then(|p| p.get(&pair_key))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(0);
    if let Some(obj) = skew_doc.as_object_mut() {
        obj.insert("netKasDeltaSompi".to_string(), json!(new_net.to_string()));
        obj.insert("totalVolumeUsdMicros".to_string(), json!(new_vol.to_string()));
        obj.insert("updatedAtMs".to_string(), json!(now_unix_ms().to_string()));
        let pairs_obj = obj
            .entry("pairs".to_string())
            .or_insert_with(|| json!({}));
        if let Some(pm) = pairs_obj.as_object_mut() {
            pm.insert(pair_key, json!(prev_pair_vol.saturating_add(notional_usd_micros).to_string()));
        }
    }
    let _: redis::RedisResult<()> = redis::cmd("SETEX")
        .arg(REDIS_KEY_AI_INTENT_SKEW)
        .arg(900u64)
        .arg(skew_doc.to_string())
        .query_async(redis_conn)
        .await;

    let _ = sqlx::query(
        r#"
        INSERT INTO public.agent_intent_signals (
            pay_asset, receive_asset, venue, net_kas_delta_sompi, quote_volume_usd_micros
        )
        VALUES ($1, $2, $3, $4::NUMERIC, $5::NUMERIC)
        "#,
    )
    .bind(pay_asset)
    .bind(receive_asset)
    .bind(venue)
    .bind(kas_delta_i128.to_string())
    .bind(notional_usd_micros.to_string())
    .execute(&state.pg_pool)
    .await;
}

// ============================================================================
// ENDPOINT 1B: AGENT-ONLY ALPHA & SPREAD INTELLIGENCE (GET /api/v1/agent/alpha)
// ============================================================================

pub async fn core_get_alpha(
    state: &AgentGatewayState,
    headers: &HeaderMap,
) -> Result<Value, AgentError> {
    let mut conn = state.get_redis_conn().await?;
    let claims = authenticate_agent_request(state, headers, &mut conn).await?;
    let rl = locks_and_limits::enforce_dynamic_rate_limit(state, &mut conn, &claims, false).await?;

    let cached_raw: Option<String> = redis::cmd("GET")
        .arg(REDIS_KEY_LATEST_PULSE)
        .query_async(&mut conn)
        .await
        .ok()
        .flatten();
    let pulse = match cached_raw.and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
        Some(v) => v,
        None => solvency::build_cached_market_pulse_snapshot(&mut conn).await?,
    };

    let (pool_ths_raw, prebell_raw): (Option<String>, Option<String>) = redis::pipe()
        .cmd("GET")
        .arg("pool:hashrate_ths")
        .cmd("GET")
        .arg("oracle:prebell:2200_demand")
        .query_async(&mut conn)
        .await
        .unwrap_or((None, None));
    let pool_ths_e6 = pool_ths_raw
        .as_deref()
        .and_then(|s| parse_decimal_str_to_u128_scaled(s.trim(), 6).ok())
        .unwrap_or(0);

    let mut hashrate_batch_calls: Vec<Value> = Vec::new();
    let bucket_rows = sqlx::query(
        r#"
        SELECT target_asset,
               COALESCE(SUM(FLOOR(accumulated_kas * 100000000)), 0)::NUMERIC(39,0)::TEXT AS acc_sompi,
               COALESCE(MAX(FLOOR(target_threshold_kas * 100000000)), 1000000000)::NUMERIC(39,0)::TEXT AS thresh_sompi
        FROM epoch_staging_buffers
        WHERE status IN ('PENDING', 'FILLING', 'READY')
        GROUP BY target_asset
        ORDER BY target_asset ASC
        "#,
    )
    .fetch_all(&state.pg_pool)
    .await
    .unwrap_or_default();

    for row in bucket_rows {
        let asset_raw: String = row.try_get("target_asset").unwrap_or_default();
        let Ok(asset) = sanitize_sterile_ticker(&asset_raw) else {
            continue;
        };
        let acc_sompi = row
            .try_get::<String, _>("acc_sompi")
            .ok()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        let thresh_sompi = row
            .try_get::<String, _>("thresh_sompi")
            .ok()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(1_000_000_000)
            .max(1);
        let fill_bps = acc_sompi
            .saturating_mul(BPS_DENOMINATOR)
            .checked_div(thresh_sompi)
            .unwrap_or(0)
            .min(10_000);
        if fill_bps >= 7_500 {
            let gap_sompi = thresh_sompi.saturating_sub(acc_sompi);
            hashrate_batch_calls.push(json!({
                "asset": asset,
                "fillBps": U128Str(fill_bps),
                "accumulatedSompi": U128Str(acc_sompi),
                "thresholdSompi": U128Str(thresh_sompi),
                "gapSompi": U128Str(gap_sompi),
                "incomingPoolThsE6": U128Str(pool_ths_e6),
                "boostRouteMode": "BATCH_BOOST"
            }));
        }
    }
    hashrate_batch_calls.sort_by(|a, b| {
        let fb = b.get("fillBps").and_then(|v| v.as_str()).and_then(|s| s.parse::<u128>().ok()).unwrap_or(0);
        let fa = a.get("fillBps").and_then(|v| v.as_str()).and_then(|s| s.parse::<u128>().ok()).unwrap_or(0);
        fb.cmp(&fa)
    });

    let mut spread_dislocations: Vec<Value> = Vec::new();
    let mut yield_spikes: Vec<Value> = Vec::new();
    let markets = pulse.get("markets").and_then(|m| m.as_array()).cloned().unwrap_or_default();
    let scalar = claims.fee_tier_multiplier_bps as u128;

    for mkt in &markets {
        let pair = mkt.get("pair").and_then(|v| v.as_str()).unwrap_or("");
        let base = mkt.get("baseAsset").and_then(|v| v.as_str()).unwrap_or("KAS");
        let quote = mkt.get("quoteAsset").and_then(|v| v.as_str()).unwrap_or("");
        let depth_base_e8 = mkt
            .get("poolReserveBaseE8")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        let depth_quote_e8 = mkt
            .get("poolReserveQuoteE8")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        let taker_base_bps = mkt
            .get("takerFeeBaseBps")
            .and_then(|v| v.as_u64())
            .unwrap_or(DARK_POOL_MAJOR_TAKER_BASE_BPS as u64) as u128;
        let fee_floor_bps = div_ceil_u128(taker_base_bps.saturating_mul(scalar), BPS_DENOMINATOR)
            .unwrap_or(TAKER_ZERO_LOSS_FLOOR_BPS as u128)
            .max(TAKER_ZERO_LOSS_FLOOR_BPS as u128);
        let venue_raw: Option<String> = redis::cmd("GET")
            .arg(format!("oracle:venues:{}", quote))
            .query_async(&mut conn)
            .await
            .ok()
            .flatten();
        if let Some(v_doc) = venue_raw.as_deref().and_then(|s| serde_json::from_str::<Value>(s).ok()) {
            let div_bps = v_doc.get("divergenceBps").and_then(|v| v.as_u64()).unwrap_or(0) as u128;
            if div_bps > fee_floor_bps && depth_base_e8 > 0 {
                let net_edge_bps = div_bps.saturating_sub(fee_floor_bps);
                spread_dislocations.push(json!({
                    "pair": pair,
                    "payAsset": base,
                    "receiveAsset": quote,
                    "grossSpreadBps": U128Str(div_bps),
                    "feeFloorBps": U128Str(fee_floor_bps),
                    "netEdgeBps": U128Str(net_edge_bps),
                    "maxExecutableAtomic": U128Str(depth_base_e8 / 10)
                }));
            }
        }
        if is_kaspa_l1_asset(quote) && depth_base_e8 > 0 {
            let apr_bps = if quote == "SILO" { 1_850u128 } else { 950u128 };
            yield_spikes.push(json!({
                "pair": pair,
                "aprBps": U128Str(apr_bps),
                "depthSompi": U128Str(depth_base_e8),
                "quoteReserveAtomic": U128Str(depth_quote_e8),
                "volume24hSompi": U128Str(depth_base_e8 / 4),
                "siloFeeTierUnlockBps": U128Str(fee_floor_bps)
            }));
        }
    }

    Ok(json!({
        "ok": true,
        "generatedAtMs": now_unix_ms().to_string(),
        "agentMode": claims.mode,
        "preBellDemandSnapshotPresent": prebell_raw.is_some(),
        "hashrateBatchCalls": hashrate_batch_calls,
        "spreadDislocations": spread_dislocations,
        "yieldSpikes": yield_spikes,
        "rateLimit": rl
    }))
}

pub async fn handle_get_alpha(
    State(state): State<AgentGatewayState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AgentError> {
    let body = core_get_alpha(&state, &headers).await?;
    Ok(Json(body))
}

// ============================================================================
// STREAM ENDPOINT: LIGHTWEIGHT SSE + WEBSOCKET MARKET PULSE (/api/v1/agent/stream)
// ============================================================================

async fn verify_stream_caller(
    state: &AgentGatewayState,
    headers: &HeaderMap,
    query: &HashMap<String, String>,
) -> Result<AgentCapabilityClaims, AgentError> {
    let mut conn = state.get_redis_conn().await?;

    if headers.contains_key("authorization") || headers.contains_key("x-agent-key") {
        let claims = authenticate_agent_request(state, headers, &mut conn).await?;
        let _ = locks_and_limits::enforce_dynamic_rate_limit(state, &mut conn, &claims, false).await?;
        return Ok(claims);
    }

    if let Some(q_token) = query.get("key").or_else(|| query.get("agentKey")) {
        let (claims, _) =
            auth::verify_stateless_capability_token_ram(&state.signing_secret, q_token)?;
        let (revoked_flag, blk_c, blk_p): (Option<String>, i32, i32) = redis::pipe()
            .cmd("GET")
            .arg(locks_and_limits::redis_key_revoked(&claims.key_id))
            .cmd("SISMEMBER")
            .arg(REDIS_KEY_BLACKLISTED_WALLETS)
            .arg(&claims.clean_wallet)
            .cmd("SISMEMBER")
            .arg(REDIS_KEY_BLACKLISTED_WALLETS)
            .arg(&claims.prefixed_wallet)
            .query_async(&mut conn)
            .await
            .map_err(|_| {
                AgentError::new(
                    AgentErrorCode::RedisUnavailable,
                    "Redis unavailable while authenticating stream session.",
                )
            })?;
        if revoked_flag.as_deref() == Some("1") {
            return Err(AgentError::new(
                AgentErrorCode::KeyRevoked,
                "Agent Key has been revoked via Kill Switch.",
            ));
        }
        if blk_c == 1 || blk_p == 1 {
            return Err(AgentError::new(
                AgentErrorCode::FirewallBlacklisted,
                "Wallet is blocked by the Perennia Security Firewall.",
            ));
        }
        let _ = locks_and_limits::enforce_dynamic_rate_limit(state, &mut conn, &claims, false).await?;
        return Ok(claims);
    }

    Err(AgentError::new(
        AgentErrorCode::Unauthorized,
        "Market pulse stream requires a valid Agent Key via Authorization: Bearer <key> or X-Agent-Key.",
    ))
}

async fn run_ws_market_pulse(mut socket: WebSocket, state: AgentGatewayState, key_id: String) {
    let mut rx = state.pulse_tx.subscribe();
    let mut rev_tick = tokio::time::interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            _ = rev_tick.tick() => {
                if let Ok(mut conn) = state.get_redis_conn().await {
                    let rev: Option<String> = redis::cmd("GET")
                        .arg(locks_and_limits::redis_key_revoked(&key_id))
                        .query_async(&mut conn)
                        .await
                        .ok()
                        .flatten();
                    if rev.as_deref() == Some("1") {
                        let _ = socket.send(WsMessage::Close(None)).await;
                        break;
                    }
                }
            }
            pulse_res = rx.recv() => {
                match pulse_res {
                    Ok(payload) => {
                        if socket.send(WsMessage::Text(payload)).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            incoming = socket.next() => {
                match incoming {
                    Some(Ok(WsMessage::Ping(p))) => {
                        if socket.send(WsMessage::Pong(p)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(WsMessage::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }
}

pub async fn handle_agent_stream(
    State(state): State<AgentGatewayState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
    ws_upgrade_res: Result<WebSocketUpgrade, WsUpgradeRejection>,
) -> Result<Response, AgentError> {
    let claims = verify_stream_caller(&state, &headers, &query).await?;

    if let Ok(ws_upgrade) = ws_upgrade_res {
        let st = state.clone();
        let kid = claims.key_id;
        return Ok(ws_upgrade
            .on_upgrade(move |socket| run_ws_market_pulse(socket, st, kid))
            .into_response());
    }

    let rx = state.pulse_tx.subscribe();
    let sse_stream = stream::unfold(rx, |mut receiver| async move {
        loop {
            match receiver.recv().await {
                Ok(msg) => {
                    let evt = SseEvent::default().event("market_pulse").data(msg);
                    return Some((Ok::<SseEvent, Infallible>(evt), receiver));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });

    let sse = Sse::new(sse_stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("pulse-keepalive"),
    );

    Ok(sse.into_response())
}

// ============================================================================
// ENDPOINT 2: DETERMINISTIC QUOTE, RESTING RFQ & UNSIGNED TICKET (POST /api/v1/agent/quote)
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentQuoteRequest {
    #[serde(alias = "inputAsset")]
    pub pay_asset: String,
    #[serde(alias = "outputAsset")]
    pub receive_asset: String,
    #[serde(alias = "amount")]
    pub amount_in: U128Str,
    pub max_slippage_bps: u16,
    #[serde(default = "default_spot_venue")]
    pub venue: AgentVenue,
    #[serde(default)]
    pub rfq_ttl_seconds: Option<u64>,
    #[serde(default)]
    pub utxo_outpoints: Option<Vec<String>>,
    #[serde(default)]
    pub execution_source: Option<String>,
    #[serde(default = "default_tx_v1")]
    pub tx_version: u16,
    #[serde(default)]
    pub compute_budget: Option<u64>,
    #[serde(default)]
    pub storage_mass: Option<u64>,
    #[serde(default)]
    pub covenant_id: Option<String>,
    #[serde(default)]
    pub proof_payload: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

const fn default_spot_venue() -> AgentVenue {
    AgentVenue::Spot
}

const fn default_tx_v1() -> u16 {
    1
}

pub async fn core_post_quote(
    state: &AgentGatewayState,
    headers: &HeaderMap,
    raw_body: Value,
) -> Result<Value, AgentError> {
    let mut conn = state.get_redis_conn().await?;
    let claims = authenticate_agent_request(state, headers, &mut conn).await?;

    if let Err(airlock_err) = reject_forbidden_cold_vault_or_withdrawal_keys(&raw_body) {
        let ban_secs = locks_and_limits::record_adversarial_fault(
            &mut conn,
            Some(&claims.key_id),
            &claims.clean_wallet,
            "QUOTE_COLD_VAULT_OR_DESTINATION_BYPASS_ATTEMPT",
        )
        .await?;
        return Err(AgentError::with_cooldown(ban_secs, airlock_err.message));
    }

    if !claims.allow_swaps {
        let ban_secs = locks_and_limits::record_adversarial_fault(
            &mut conn,
            Some(&claims.key_id),
            &claims.clean_wallet,
            "MANDATE_SWAPS_DISABLED_BYPASS",
        )
        .await?;
        return Err(AgentError::with_cooldown(
            ban_secs,
            "Capability key does not permit swap execution.",
        ));
    }

    let req: AgentQuoteRequest = serde_json::from_value(raw_body).map_err(|e| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            format!("Malformed quote request schema: {}", e),
        )
    })?;

    let pay_asset = sanitize_sterile_ticker(&req.pay_asset)?;
    let receive_asset = sanitize_sterile_ticker(&req.receive_asset)?;

    if !claims.is_asset_whitelisted(&pay_asset) || !claims.is_asset_whitelisted(&receive_asset) {
        let ban_secs = locks_and_limits::record_adversarial_fault(
            &mut conn,
            Some(&claims.key_id),
            &claims.clean_wallet,
            "MANDATE_UNWHITELISTED_ASSET_ATTEMPT",
        )
        .await?;
        return Err(AgentError::with_cooldown(
            ban_secs,
            format!(
                "Mandate whitelist violation: pair {}/{} is outside permitted tickers.",
                pay_asset, receive_asset
            ),
        ));
    }

    // Enforce RPM budget + x402 challenge; only count live quotes toward rolling quote-to-fill ratio
    let rl_verdict =
        locks_and_limits::enforce_dynamic_rate_limit(state, &mut conn, &claims, !req.dry_run)
            .await?;

    let clean_covenant_id = match req.covenant_id.as_deref() {
        Some(raw_cov) if !raw_cov.trim().is_empty() => {
            Some(validate_hex_64(raw_cov, "covenantId")?)
        }
        _ => None,
    };

    let (clean_proof_hex, proof_bytes_len) = match req.proof_payload.as_deref() {
        Some(raw_pf) if !raw_pf.trim().is_empty() => {
            let (hex_str, decoded) = validate_hex_bounded(raw_pf, 8_192, "proofPayload")?;
            (Some(hex_str), decoded.len())
        }
        _ => (None, 0usize),
    };

    let envelope = PostToccataEnvelope {
        tx_version: req.tx_version.max(1),
        compute_budget: req.compute_budget,
        storage_mass: req.storage_mass,
        covenant_id: clean_covenant_id.clone(),
        proof_payload: clean_proof_hex.clone(),
    };

    // Read cached Redis oracle snapshot & verify circuit breakers (zero outbound HTTP, zero DB)
    let oracle_snap =
        solvency::read_cached_oracle_pair_snapshot(&mut conn, &pay_asset, &receive_asset).await?;

    let explicit_outpoints: Option<Vec<OutpointRef>> = match req.utxo_outpoints {
        Some(ref list) if !list.is_empty() => {
            let mut parsed = Vec::with_capacity(list.len());
            for raw_op in list {
                parsed.push(OutpointRef::parse_str(raw_op)?);
            }
            Some(parsed)
        }
        _ => None,
    };

    let exec_source = req
        .execution_source
        .as_deref()
        .unwrap_or(if claims.mode == AgentMode::ModeA {
            "l1_utxo"
        } else if is_kaspa_l1_asset(&pay_asset) && explicit_outpoints.is_some() {
            "l1_utxo"
        } else if is_kaspa_l1_asset(&pay_asset) {
            "l1_utxo"
        } else {
            "sovereign_sleeve"
        })
        .trim()
        .to_ascii_lowercase();

    let use_l1_utxos = if claims.mode == AgentMode::ModeA {
        if !is_kaspa_l1_asset(&pay_asset) {
            return Err(AgentError::new(
                AgentErrorCode::InvalidInput,
                "External Mode A bots must pay from confirmed Kaspa L1 KAS / KRC-20 / KCC-20 UTXOs.",
            ));
        }
        true
    } else if exec_source == "sovereign_sleeve" {
        false
    } else if is_kaspa_l1_asset(&pay_asset) {
        true
    } else {
        false
    };

    let quote_id = format!("qte_{}", Uuid::new_v4().simple());
    let created_at_ms = now_unix_ms();
    let ttl_secs = match req.venue {
        AgentVenue::DarkPoolRfqMaker => req
            .rfq_ttl_seconds
            .unwrap_or(10)
            .clamp(MIN_MAKER_RFQ_TTL_SECS, MAX_MAKER_RFQ_TTL_SECS),
        AgentVenue::Spot | AgentVenue::DarkPool => MAX_TAKER_QUOTE_TTL_SECS,
    };
    let expires_at_ms = created_at_ms.saturating_add(ttl_secs.saturating_mul(1_000));

    let (solvency_math, ticket_bundle, locked_utxos, utxo_lane_health) = if use_l1_utxos {
        let is_token_leg = pay_asset != "KAS";
        let base_principal_sompi = if pay_asset == "KAS" {
            req.amount_in.as_u128()
        } else {
            30_000_000u128
        };

        // Pass 1 conservative fee estimate for UTXO selection
        let est_fee_pass1 = solvency::calculate_post_toccata_v1_mass_and_fee(
            explicit_outpoints.as_ref().map(|v| v.len()).unwrap_or(2),
            2,
            128,
            proof_bytes_len,
            &[],
            &[],
            &envelope,
        );

        let selection_res = select_and_verify_wallet_utxos(
            &mut conn,
            &claims,
            explicit_outpoints.as_deref(),
            base_principal_sompi.saturating_add(est_fee_pass1.required_network_fee_sompi),
            is_token_leg,
            req.dry_run,
        )
        .await;

        let (selected_utxos, raw_utxos, virtual_daa) = match selection_res {
            Ok(tuple) => tuple,
            Err(err) if err.code == AgentErrorCode::InvalidSignatureOrScript => {
                let ban_secs = locks_and_limits::record_adversarial_fault(
                    &mut conn,
                    Some(&claims.key_id),
                    &claims.clean_wallet,
                    "QUOTE_SPENT_OR_FOREIGN_UTXO_SUBMISSION",
                )
                .await?;
                return Err(AgentError::with_cooldown(ban_secs, err.message));
            }
            Err(err) => return Err(err),
        };

        let in_sompi_vec: Vec<u128> = selected_utxos
            .iter()
            .map(|u| u.amount_sompi.as_u128())
            .collect();
        let gathered_sompi: u128 = in_sompi_vec.iter().copied().sum();
        let est_change = gathered_sompi
            .saturating_sub(base_principal_sompi)
            .saturating_sub(est_fee_pass1.required_network_fee_sompi);
        let prelim_outs = if est_change >= 10_000_000 {
            vec![base_principal_sompi, est_change]
        } else {
            vec![base_principal_sompi]
        };

        // Pass 2 exact post-Toccata v1 mass, KIP-9 storage mass & zero-loss quote math
        let math = compute_zero_loss_quote_math(
            &claims,
            req.venue,
            req.amount_in.as_u128(),
            req.max_slippage_bps,
            &oracle_snap,
            selected_utxos.len(),
            prelim_outs.len(),
            if is_token_leg { 112 } else { 64 },
            proof_bytes_len,
            &in_sompi_vec,
            &prelim_outs,
            &envelope,
        )?;

        let ticket = build_unsigned_l1_kaspa_ticket(
            &quote_id,
            &claims,
            req.venue.as_str(),
            &pay_asset,
            &receive_asset,
            req.amount_in.as_u128(),
            math.min_amount_out_atomic,
            &state.x402_treasury_address,
            &selected_utxos,
            math.l1_network_fee_sompi,
            expires_at_ms,
            &envelope,
        )?;

        let lane_health = locks_and_limits::inspect_utxo_lane_health(
            &mut conn,
            &claims.clean_wallet,
            &raw_utxos,
            virtual_daa,
        )
        .await?;

        (math, ticket, selected_utxos, Some(lane_health))
    } else {
        // Mode B Sovereign Execution Sleeve Check
        if claims.pubkey_hex.len() != 64 {
            return Err(AgentError::new(
                AgentErrorCode::InvalidInput,
                "Mode B Sovereign Intent signing requires a 32-byte Schnorr pubkeyHex bound to the Mandate.",
            ));
        }

        let (streaming_kas_e8, _, lp_map, _) = read_wallet_sleeve_balances_e8(
            &state.pg_pool,
            &claims.clean_wallet,
            &claims.prefixed_wallet,
        )
        .await?;
        let req_debit_e8 =
            convert_atomic_ceil_to_e8(req.amount_in.as_u128(), atomic_decimals_for_asset(&pay_asset))?;
        let avail_e8 = if pay_asset == "KAS" {
            streaming_kas_e8
        } else {
            lp_map.get(&pay_asset).copied().unwrap_or(0)
        };
        if avail_e8 < req_debit_e8 {
            return Err(AgentError::new(
                AgentErrorCode::InvalidInput,
                format!(
                    "Insufficient Mode B execution-sleeve {} balance: available {} e8, requested {} e8.",
                    pay_asset, avail_e8, req_debit_e8
                ),
            ));
        }

        let math = compute_zero_loss_quote_math(
            &claims,
            req.venue,
            req.amount_in.as_u128(),
            req.max_slippage_bps,
            &oracle_snap,
            1,
            1,
            96,
            proof_bytes_len,
            &[],
            &[],
            &envelope,
        )?;

        let ticket = build_unsigned_0x83_sleeve_ticket(
            &quote_id,
            &claims,
            req.venue.as_str(),
            &pay_asset,
            &receive_asset,
            req.amount_in.as_u128(),
            math.min_amount_out_atomic,
            math.l1_network_fee_sompi,
            expires_at_ms,
            &envelope,
        );

        (math, ticket, Vec::new(), None)
    };

    let locked_outpoint_keys: Vec<String> = locked_utxos
        .iter()
        .map(|u| format!("{}:{}", u.transaction_id, u.index))
        .collect();

    let stored_quote = StoredAgentQuote {
        quote_id: quote_id.clone(),
        key_id: claims.key_id.clone(),
        mandate_id: claims.mandate_id.clone(),
        mode: claims.mode,
        clean_wallet: claims.clean_wallet.clone(),
        prefixed_wallet: claims.prefixed_wallet.clone(),
        pubkey_hex: claims.pubkey_hex.clone(),
        venue: req.venue,
        pay_asset: pay_asset.clone(),
        receive_asset: receive_asset.clone(),
        pay_decimals: solvency_math.pay_decimals,
        receive_decimals: solvency_math.receive_decimals,
        amount_in_atomic: req.amount_in,
        expected_amount_out_atomic: U128Str(solvency_math.expected_amount_out_atomic),
        min_amount_out_atomic: U128Str(solvency_math.min_amount_out_atomic),
        max_slippage_bps: req.max_slippage_bps,
        applied_fee_bps: solvency_math.applied_fee_bps,
        fee_tier_multiplier_bps: claims.fee_tier_multiplier_bps,
        protocol_fee_atomic: U128Str(solvency_math.protocol_fee_pay_atomic),
        network_fee_sompi: U128Str(solvency_math.l1_network_fee_sompi),
        total_fee_usd_micros: U128Str(solvency_math.total_fee_usd_micros),
        notional_usd_micros: U128Str(solvency_math.notional_usd_micros),
        spend_sompi_equiv: U128Str(solvency_math.spend_sompi_equiv),
        pay_oracle_usd_e8: U128Str(oracle_snap.pay_usd_e8),
        receive_oracle_usd_e8: U128Str(oracle_snap.receive_usd_e8),
        kas_oracle_usd_e8: U128Str(oracle_snap.kas_usd_e8),
        tx_version: solvency_math.mass_breakdown.tx_version,
        compute_grams: solvency_math.mass_breakdown.compute_grams,
        tx_bytes: solvency_math.mass_breakdown.tx_bytes,
        storage_mass: solvency_math.mass_breakdown.storage_mass,
        covenant_id: clean_covenant_id.clone(),
        proof_payload: clean_proof_hex.clone(),
        locked_outpoints: locked_outpoint_keys.clone(),
        locked_utxos,
        unsigned_tx_json: ticket_bundle.unsigned_tx_json.clone(),
        sighash_hex_per_input: ticket_bundle.sighash_hex_per_input.clone(),
        payload_0x83_hex: ticket_bundle.payload_0x83_hex.clone(),
        preimage_hash: ticket_bundle.preimage_hash.clone(),
        created_at_ms,
        expires_at_ms,
        ttl_secs,
    };

    if req.dry_run {
        let now_secs = created_at_ms / 1_000;
        let _ = locks_and_limits::check_mandate_24h_headroom_readonly(
            &mut conn,
            &claims,
            solvency_math.spend_sompi_equiv,
            solvency_math.notional_usd_micros,
            now_secs,
        )
        .await?;

        let simulated_hifo = process_hifo_disposal_u128(
            &state.pg_pool,
            &claims.clean_wallet,
            &claims.prefixed_wallet,
            &pay_asset,
            solvency_math.pay_decimals,
            req.amount_in.as_u128(),
            oracle_snap.pay_usd_e8,
            None,
            false,
        )
        .await?;

        let dry_log = json!({
            "stage": "DRY_RUN_QUOTE",
            "quoteId": quote_id,
            "keyId": claims.key_id,
            "venue": req.venue,
            "payAsset": pay_asset,
            "receiveAsset": receive_asset,
            "amountInAtomic": req.amount_in,
            "expectedAmountOutAtomic": U128Str(solvency_math.expected_amount_out_atomic),
            "minAmountOutAtomic": U128Str(solvency_math.min_amount_out_atomic),
            "totalFeeUsdMicros": U128Str(solvency_math.total_fee_usd_micros),
            "preimageHash": ticket_bundle.preimage_hash,
            "timestamp": Utc::now().to_rfc3339()
        });
        append_dry_run_audit_log(&mut conn, &claims.clean_wallet, &dry_log).await;

        return Ok(json!({
            "ok": true,
            "dryRun": true,
            "quoteId": quote_id,
            "venue": req.venue,
            "payAsset": pay_asset,
            "receiveAsset": receive_asset,
            "amountIn": req.amount_in,
            "expectedAmountOut": U128Str(solvency_math.expected_amount_out_atomic),
            "minAmountOut": U128Str(solvency_math.min_amount_out_atomic),
            "fees": {
                "appliedFeeBps": solvency_math.applied_fee_bps,
                "protocolFeePayAtomic": U128Str(solvency_math.protocol_fee_pay_atomic),
                "networkFeeSompi": U128Str(solvency_math.l1_network_fee_sompi),
                "postToccataConsensusFloorSompi": U128Str(solvency_math.mass_breakdown.consensus_v1_floor_sompi),
                "externalGasAndSlipUsdMicros": U128Str(solvency_math.external_gas_and_slip_usd_micros),
                "totalFeeUsdMicros": U128Str(solvency_math.total_fee_usd_micros)
            },
            "postToccataEnvelope": {
                "txVersion": solvency_math.mass_breakdown.tx_version,
                "computeGrams": solvency_math.mass_breakdown.compute_grams.to_string(),
                "txBytes": solvency_math.mass_breakdown.tx_bytes.to_string(),
                "storageMass": solvency_math.mass_breakdown.storage_mass.to_string(),
                "covenantId": clean_covenant_id,
                "proofPayload": clean_proof_hex
            },
            "unsignedPayload": ticket_bundle.unsigned_tx_json,
            "sighashHexPerInput": ticket_bundle.sighash_hex_per_input,
            "payload0x83Hex": ticket_bundle.payload_0x83_hex,
            "preimageHash": ticket_bundle.preimage_hash,
            "simulatedHifoTax": simulated_hifo,
            "utxoLaneHealth": utxo_lane_health,
            "rateLimit": rl_verdict
        }));
    }

    let (_, max_conc) =
        locks_and_limits::resolve_wallet_concurrency_limit(&mut conn, &claims.clean_wallet).await?;
    let active_quotes = locks_and_limits::acquire_quote_and_utxo_locks(
        &mut conn,
        &claims,
        &stored_quote,
        max_conc,
    )
    .await?;

    publish_anonymized_ai_intent_skew(
        state,
        &mut conn,
        &pay_asset,
        &receive_asset,
        req.venue.as_str(),
        solvency_math.spend_sompi_equiv,
        solvency_math.notional_usd_micros,
    )
    .await;

    Ok(json!({
        "ok": true,
        "dryRun": false,
        "quoteId": quote_id,
        "venue": req.venue,
        "ttlSeconds": ttl_secs.to_string(),
        "expiresAtMs": expires_at_ms.to_string(),
        "payAsset": pay_asset,
        "receiveAsset": receive_asset,
        "amountIn": req.amount_in,
        "expectedAmountOut": U128Str(solvency_math.expected_amount_out_atomic),
        "minAmountOut": U128Str(solvency_math.min_amount_out_atomic),
        "fees": {
            "appliedFeeBps": solvency_math.applied_fee_bps,
            "protocolFeePayAtomic": U128Str(solvency_math.protocol_fee_pay_atomic),
            "networkFeeSompi": U128Str(solvency_math.l1_network_fee_sompi),
            "postToccataConsensusFloorSompi": U128Str(solvency_math.mass_breakdown.consensus_v1_floor_sompi),
            "externalGasAndSlipUsdMicros": U128Str(solvency_math.external_gas_and_slip_usd_micros),
            "totalFeeUsdMicros": U128Str(solvency_math.total_fee_usd_micros)
        },
        "postToccataEnvelope": {
            "txVersion": solvency_math.mass_breakdown.tx_version,
            "computeGrams": solvency_math.mass_breakdown.compute_grams.to_string(),
            "txBytes": solvency_math.mass_breakdown.tx_bytes.to_string(),
            "storageMass": solvency_math.mass_breakdown.storage_mass.to_string(),
            "covenantId": clean_covenant_id,
            "proofPayload": clean_proof_hex
        },
        "lockedOutpoints": locked_outpoint_keys,
        "activeWalletQuotes": active_quotes.to_string(),
        "maxConcurrentQuotes": max_conc.to_string(),
        "unsignedPayload": ticket_bundle.unsigned_tx_json,
        "sighashHexPerInput": ticket_bundle.sighash_hex_per_input,
        "payload0x83Hex": ticket_bundle.payload_0x83_hex,
        "preimageHash": ticket_bundle.preimage_hash,
        "utxoLaneHealth": utxo_lane_health,
        "rateLimit": rl_verdict
    }))
}

pub async fn handle_post_quote(
    State(state): State<AgentGatewayState>,
    headers: HeaderMap,
    Json(raw_body): Json<Value>,
) -> Result<Json<Value>, AgentError> {
    let body = core_post_quote(&state, &headers, raw_body).await?;
    Ok(Json(body))
}

// ============================================================================
// ENDPOINT 3: IDEMPOTENT SIGNED BROADCAST & VERIFIABLE RECEIPT (POST /api/v1/agent/execute)
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentExecuteRequest {
    pub quote_id: String,
    pub idempotency_key: String,
    pub signed_payload: Value,
    #[serde(default)]
    pub dry_run: bool,
}

pub async fn core_post_execute(
    state: &AgentGatewayState,
    headers: &HeaderMap,
    raw_body: Value,
) -> Result<Value, AgentError> {
    let mut conn = state.get_redis_conn().await?;
    let claims = authenticate_agent_request(state, headers, &mut conn).await?;

    if let Err(airlock_err) = reject_forbidden_cold_vault_or_withdrawal_keys(&raw_body) {
        let ban_secs = locks_and_limits::record_adversarial_fault(
            &mut conn,
            Some(&claims.key_id),
            &claims.clean_wallet,
            "EXECUTE_COLD_VAULT_OR_DESTINATION_BYPASS_ATTEMPT",
        )
        .await?;
        return Err(AgentError::with_cooldown(ban_secs, airlock_err.message));
    }

    if !claims.allow_swaps {
        return Err(AgentError::new(
            AgentErrorCode::MandateViolation,
            "Capability key does not permit swap execution.",
        ));
    }

    let _ = locks_and_limits::enforce_dynamic_rate_limit(state, &mut conn, &claims, false).await?;

    let req: AgentExecuteRequest = serde_json::from_value(raw_body).map_err(|e| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            format!("Malformed execute request schema: {}", e),
        )
    })?;

    let clean_quote_id = req.quote_id.trim();
    if clean_quote_id.len() > 64
        || !clean_quote_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "Invalid quoteId format.",
        ));
    }
    let idempotency_key = validate_idempotency_key(&req.idempotency_key)?;
    let now_ms = now_unix_ms();
    let now_secs = now_ms / 1_000;

    // SHADOW MODE (`dry_run: true`) — Full cryptographic, solvency & HIFO verification with ZERO mutation
    if req.dry_run {
        let raw_q: Option<String> = redis::cmd("GET")
            .arg(format!("perennia:agent:quote:{}", clean_quote_id))
            .query_async(&mut conn)
            .await
            .map_err(|_| {
                AgentError::new(
                    AgentErrorCode::RedisUnavailable,
                    "Redis unavailable while reading quote for dry_run.",
                )
            })?;
        let raw_q_str = raw_q.ok_or_else(|| {
            AgentError::new(
                AgentErrorCode::QuoteExpiredOrNotFound,
                "Quote not found or expired for dry_run verification.",
            )
        })?;
        let quote: StoredAgentQuote = serde_json::from_str(&raw_q_str).map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Stored quote state unreadable.",
            )
        })?;
        if quote.key_id != claims.key_id {
            return Err(AgentError::new(
                AgentErrorCode::ForbiddenMode,
                "Quote belongs to a different capability key.",
            ));
        }

        let _ = verify_signed_execution_submission(
            &mut conn,
            &claims,
            &quote,
            &req.signed_payload,
            &state.x402_treasury_address,
        )
        .await?;

        let fresh_oracle = solvency::read_cached_oracle_pair_snapshot(
            &mut conn,
            &quote.pay_asset,
            &quote.receive_asset,
        )
        .await?;

        let sim_hifo = process_hifo_disposal_u128(
            &state.pg_pool,
            &claims.clean_wallet,
            &claims.prefixed_wallet,
            &quote.pay_asset,
            quote.pay_decimals,
            quote.amount_in_atomic.as_u128(),
            fresh_oracle.pay_usd_e8,
            None,
            false,
        )
        .await?;

        let sim_commit = compute_execution_commitment_hash(
            &quote.quote_id,
            &quote.mandate_id,
            &quote.pay_asset,
            &quote.receive_asset,
            fresh_oracle.pay_usd_e8,
            fresh_oracle.receive_usd_e8,
            fresh_oracle.kas_usd_e8,
            quote.amount_in_atomic.as_u128(),
            quote.expected_amount_out_atomic.as_u128(),
            quote.protocol_fee_atomic.as_u128(),
            quote.network_fee_sompi.as_u128(),
            quote.total_fee_usd_micros.as_u128(),
            "DRY_RUN_NO_MAINNET_BROADCAST",
            sim_hifo.primary_disposal_lot_id,
            None,
        );

        let dry_log = json!({
            "stage": "DRY_RUN_EXECUTE",
            "quoteId": quote.quote_id,
            "keyId": claims.key_id,
            "venue": quote.venue,
            "payAsset": quote.pay_asset,
            "receiveAsset": quote.receive_asset,
            "amountInAtomic": quote.amount_in_atomic,
            "settledOutAtomic": quote.expected_amount_out_atomic,
            "executionCommitmentHash": sim_commit,
            "timestamp": Utc::now().to_rfc3339()
        });
        append_dry_run_audit_log(&mut conn, &claims.clean_wallet, &dry_log).await;

        return Ok(json!({
            "ok": true,
            "dryRun": true,
            "quoteId": quote.quote_id,
            "idempotencyKey": idempotency_key,
            "signatureVerified": true,
            "preimageVerified": true,
            "expectedSettledOut": quote.expected_amount_out_atomic,
            "minAmountOut": quote.min_amount_out_atomic,
            "executionCommitmentHash": sim_commit,
            "simulatedHifoTax": sim_hifo
        }));
    }

    // LIVE EXECUTION — Step 1: Atomic Quote + UTXO + Mandate 24h Spend Consumption
    let consumed = locks_and_limits::consume_quote_utxos_and_mandate_cap_atomic(
        &mut conn,
        &claims,
        clean_quote_id,
        &idempotency_key,
        now_ms,
    )
    .await?;

    let (quote, spent_24h_sompi, spent_24h_usd_micros, consumed_hour_bucket) = match consumed {
        ConsumedQuoteOutcome::IdempotentReplay(existing_receipt) => {
            return Ok(existing_receipt);
        }
        ConsumedQuoteOutcome::Fresh {
            quote,
            spent_24h_sompi,
            spent_24h_usd_micros,
            consumed_hour_bucket,
        } => (
            quote,
            spent_24h_sompi,
            spent_24h_usd_micros,
            consumed_hour_bucket,
        ),
    };

    // Also check PostgreSQL idempotency constraint in case Redis restarted after >24h
    if let Ok(Some(existing_row)) = sqlx::query(
        r#"
        SELECT receipt_id, quote_id, l1_txid, execution_commitment_hash,
               settled_out_atomic::TEXT AS settled_out_atomic
        FROM agent_execution_receipts
        WHERE idempotency_key = $1
        LIMIT 1
        "#,
    )
    .bind(&idempotency_key)
    .fetch_optional(&state.pg_pool)
    .await
    {
        let _ = locks_and_limits::rollback_consumed_mandate_on_failure(
            &mut conn,
            &claims,
            &quote,
            &idempotency_key,
            consumed_hour_bucket,
        )
        .await;
        return Ok(json!({
            "ok": true,
            "idempotentReplay": true,
            "receiptId": existing_row.try_get::<String, _>("receipt_id").unwrap_or_default(),
            "quoteId": existing_row.try_get::<String, _>("quote_id").unwrap_or_default(),
            "l1Txid": existing_row.try_get::<String, _>("l1_txid").unwrap_or_default(),
            "settledAmountOut": existing_row.try_get::<String, _>("settled_out_atomic").unwrap_or_else(|_| "0".to_string()),
            "executionCommitmentHash": existing_row.try_get::<String, _>("execution_commitment_hash").unwrap_or_default()
        }));
    }

    // Step 2: Byte-for-Byte Pre-Image + Canonical 64-Byte Schnorr + Script Template + DAA Depth Verification
    let (verified_payload, _) = match verify_signed_execution_submission(
        &mut conn,
        &claims,
        &quote,
        &req.signed_payload,
        &state.x402_treasury_address,
    )
    .await
    {
        Ok(res) => res,
        Err(ver_err) => {
            let _ = locks_and_limits::rollback_consumed_mandate_on_failure(
                &mut conn,
                &claims,
                &quote,
                &idempotency_key,
                consumed_hour_bucket,
            )
            .await;

            if matches!(
                ver_err.code,
                AgentErrorCode::PreimageMismatch | AgentErrorCode::InvalidSignatureOrScript
            ) {
                let ban_secs = locks_and_limits::record_adversarial_fault(
                    &mut conn,
                    Some(&claims.key_id),
                    &claims.clean_wallet,
                    ver_err.code.as_str(),
                )
                .await?;
                return Err(AgentError::with_cooldown(ban_secs, ver_err.message));
            }
            return Err(ver_err);
        }
    };

    // Step 3: Venue Clearing & Fresh-Oracle Randomized Micro-Batch Verification
    let (
        settled_out_atomic,
        exec_pay_usd_e8,
        exec_receive_usd_e8,
        exec_kas_usd_e8,
        exec_protocol_fee_atomic,
        exec_total_fee_usd_micros,
        micro_batch_meta,
    ) = match quote.venue {
        AgentVenue::DarkPool => {
            match dark_pool::clear_taker_dark_pool_micro_batch(&mut conn, &claims, &quote, false)
                .await
            {
                Ok(mb) => (
                    mb.post_jitter_net_out_atomic.as_u128(),
                    mb.fresh_pay_oracle_usd_e8.as_u128(),
                    mb.fresh_receive_oracle_usd_e8.as_u128(),
                    mb.fresh_kas_oracle_usd_e8.as_u128(),
                    mb.post_jitter_protocol_fee_atomic.as_u128(),
                    mb.post_jitter_total_fee_usd_micros.as_u128(),
                    Some(serde_json::to_value(&mb).unwrap_or_else(|_| json!({}))),
                ),
                Err(mb_err) => {
                    let _ = locks_and_limits::rollback_consumed_mandate_on_failure(
                        &mut conn,
                        &claims,
                        &quote,
                        &idempotency_key,
                        consumed_hour_bucket,
                    )
                    .await;
                    return Err(mb_err);
                }
            }
        }
        AgentVenue::Spot | AgentVenue::DarkPoolRfqMaker => {
            let fresh_oracle = match solvency::read_cached_oracle_pair_snapshot(
                &mut conn,
                &quote.pay_asset,
                &quote.receive_asset,
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    let _ = locks_and_limits::rollback_consumed_mandate_on_failure(
                        &mut conn,
                        &claims,
                        &quote,
                        &idempotency_key,
                        consumed_hour_bucket,
                    )
                    .await;
                    return Err(e);
                }
            };

            let envelope = PostToccataEnvelope {
                tx_version: quote.tx_version,
                compute_budget: Some(quote.compute_grams),
                storage_mass: Some(quote.storage_mass),
                covenant_id: quote.covenant_id.clone(),
                proof_payload: quote.proof_payload.clone(),
            };
            let in_sompi: Vec<u128> = quote
                .locked_utxos
                .iter()
                .map(|u| u.amount_sompi.as_u128())
                .collect();
            let proof_len = quote.proof_payload.as_ref().map(|s| s.len() / 2).unwrap_or(0);

            let fresh_math = match compute_zero_loss_quote_math(
                &claims,
                quote.venue,
                quote.amount_in_atomic.as_u128(),
                quote.max_slippage_bps,
                &fresh_oracle,
                quote.locked_utxos.len().max(1),
                2,
                quote.payload_0x83_hex.len() / 2,
                proof_len,
                &in_sompi,
                &[],
                &envelope,
            ) {
                Ok(m) => m,
                Err(e) => {
                    let _ = locks_and_limits::rollback_consumed_mandate_on_failure(
                        &mut conn,
                        &claims,
                        &quote,
                        &idempotency_key,
                        consumed_hour_bucket,
                    )
                    .await;
                    return Err(e);
                }
            };

            if fresh_math.expected_amount_out_atomic < quote.min_amount_out_atomic.as_u128() {
                let _ = locks_and_limits::rollback_consumed_mandate_on_failure(
                    &mut conn,
                    &claims,
                    &quote,
                    &idempotency_key,
                    consumed_hour_bucket,
                )
                .await;
                return Err(AgentError::new(
                    AgentErrorCode::SlippageExceededPostJitter,
                    "Live oracle moved beyond signed minAmountOut floor before broadcast; failing closed.",
                ));
            }

            (
                fresh_math.expected_amount_out_atomic,
                fresh_oracle.pay_usd_e8,
                fresh_oracle.receive_usd_e8,
                fresh_oracle.kas_usd_e8,
                fresh_math.protocol_fee_pay_atomic,
                fresh_math.total_fee_usd_micros,
                None,
            )
        }
    };

    // Step 4: Non-Custodial L1 Broadcast / Sovereign Execution-Sleeve Settlement
    let (inbound_txid, outbound_settlement_txid) = match verified_payload {
        VerifiedExecutionPayload::KaspaL1Transaction {
            signed_tx_envelope,
            verified_daa_depth_min: _,
        } => {
            let l1_in_txid =
                match crate::kaspad_client::submit_transaction_grpc(&signed_tx_envelope, false)
                    .await
                {
                    Ok(txid) => txid,
                    Err(rpc_err) => {
                        let _ = locks_and_limits::rollback_consumed_mandate_on_failure(
                            &mut conn,
                            &claims,
                            &quote,
                            &idempotency_key,
                            consumed_hour_bucket,
                        )
                        .await;
                        let lower = rpc_err.to_ascii_lowercase();
                        if lower.contains("orphan")
                            || lower.contains("spent")
                            || lower.contains("invalid")
                        {
                            let ban_secs = locks_and_limits::record_adversarial_fault(
                                &mut conn,
                                Some(&claims.key_id),
                                &claims.clean_wallet,
                                "KASPAD_REJECTED_SIGNED_TX",
                            )
                            .await?;
                            return Err(AgentError::with_cooldown(
                                ban_secs,
                                format!("kaspad rejected signed L1 transaction: {}", rpc_err),
                            ));
                        }
                        return Err(AgentError::new(
                            AgentErrorCode::NodeUnavailable,
                            format!("kaspad gRPC broadcast failed: {}", rpc_err),
                        ));
                    }
                };

            if quote.venue == AgentVenue::DarkPoolRfqMaker {
                let _ = dark_pool::register_resting_maker_rfq(&mut conn, &quote, &l1_in_txid).await?;
                (l1_in_txid.clone(), format!("RFQ_RESTING:{}", quote.quote_id))
            } else if quote.receive_asset == "KAS" {
                let out_sompi_u64 = u64::try_from(settled_out_atomic).map_err(|_| {
                    AgentError::new(
                        AgentErrorCode::SolvencyFloorViolation,
                        "Outbound KAS sompi overflow.",
                    )
                })?;
                let out_idemp = format!("AGENT-OUT-{}", quote.quote_id);
                let out_txid = crate::sor::execute_idempotent_mass_physical_settlement(
                    &state.pg_pool,
                    &out_idemp,
                    &[(claims.prefixed_wallet.clone(), out_sompi_u64)],
                )
                .await
                .map_err(|e| {
                    tracing::error!("❌ [AGENT L1 OUTBOUND] KAS settlement dispatch failed: {}", e);
                    AgentError::new(
                        AgentErrorCode::NodeUnavailable,
                        format!("Inbound L1 tx {} accepted, outbound KAS dispatch halted: {}", l1_in_txid, e),
                    )
                })?;
                (l1_in_txid, out_txid)
            } else if is_kaspa_l1_asset(&quote.receive_asset) {
                let krc_json = json!({
                    "p": "krc-20",
                    "op": "transfer",
                    "tick": quote.receive_asset,
                    "amt": settled_out_atomic.to_string(),
                    "to": claims.prefixed_wallet
                });
                let krc_hex = hex::encode(krc_json.to_string().as_bytes());
                let out_idemp = format!("AGENT-KRC20-OUT-{}", quote.quote_id);
                let out_txid = crate::state_api::sign_and_broadcast_kaspa_payout_batch(
                    &state.pg_pool,
                    &out_idemp,
                    &[(claims.prefixed_wallet.clone(), 30_000_000u64)],
                    &krc_hex,
                )
                .await
                .map_err(|e| {
                    AgentError::new(
                        AgentErrorCode::NodeUnavailable,
                        format!("Inbound L1 tx {} accepted, KRC-20 dispatch halted: {}", l1_in_txid, e),
                    )
                })?;
                (l1_in_txid, out_txid)
            } else {
                // Multi-chain output destination-locked strictly to `claims.prefixed_wallet` / sleeve
                let payout_id = format!("PER-AG-{}", &Uuid::new_v4().simple().to_string().to_ascii_uppercase()[..12]);
                let network = crate::state_api::resolve_network_for_asset(&quote.receive_asset);
                let out_tok_str =
                    format_u128_scaled_to_decimal_str(settled_out_atomic, quote.receive_decimals);
                let gross_usd_str =
                    format_u128_scaled_to_decimal_str(quote.notional_usd_micros.as_u128(), 6);
                let rec_spot_str = format_u128_scaled_to_decimal_str(exec_receive_usd_e8, 8);

                sqlx::query(
                    r#"
                    INSERT INTO l1_payout_queue (
                        payout_id, wallet_address, destination_address, asset_ticker,
                        network, amount_tokens, gross_usd, spot_price, source_type,
                        tx_hash, status
                    ) VALUES (
                        $1, $2, $2, $3,
                        $4, $5::NUMERIC::DOUBLE PRECISION, $6::NUMERIC::DOUBLE PRECISION,
                        $7::NUMERIC::DOUBLE PRECISION, 'agent_swap_settlement',
                        $8, 'QUEUED_FOR_L1_DISPATCH'
                    )
                    "#,
                )
                .bind(&payout_id)
                .bind(&claims.prefixed_wallet)
                .bind(&quote.receive_asset)
                .bind(&network)
                .bind(&out_tok_str)
                .bind(&gross_usd_str)
                .bind(&rec_spot_str)
                .bind(&l1_in_txid)
                .execute(&state.pg_pool)
                .await
                .map_err(|_| {
                    AgentError::new(
                        AgentErrorCode::DatabaseUnavailable,
                        "Failed to record multi-chain settlement in l1_payout_queue.",
                    )
                })?;

                (l1_in_txid, payout_id)
            }
        }
        VerifiedExecutionPayload::SovereignSleeveIntent0x83 { signature_hex } => {
            if let Err(sleeve_err) = settle_sleeve_swap_exact_u128(
                &state.pg_pool,
                &mut conn,
                &claims.clean_wallet,
                &claims.prefixed_wallet,
                &quote.pay_asset,
                quote.pay_decimals,
                quote.amount_in_atomic.as_u128(),
                &quote.receive_asset,
                quote.receive_decimals,
                settled_out_atomic,
            )
            .await
            {
                let _ = locks_and_limits::rollback_consumed_mandate_on_failure(
                    &mut conn,
                    &claims,
                    &quote,
                    &idempotency_key,
                    consumed_hour_bucket,
                )
                .await;
                return Err(sleeve_err);
            }
            let intent_tx_ref = format!("0x83_{}", &signature_hex[..32]);
            (intent_tx_ref.clone(), intent_tx_ref)
        }
    };

    // Push execution delta to `perennia:sor:netting_queue` so Chronos Dark Pool netting stays synchronized
    let direction = if quote.pay_asset == "KAS" {
        "SELL_KAS"
    } else if quote.receive_asset == "KAS" {
        "BUY_KAS"
    } else {
        "CROSS_ASSET"
    };
    let kas_eq_str = format_u128_scaled_to_decimal_str(quote.spend_sompi_equiv.as_u128(), 8);
    let gross_u_str = format_u128_scaled_to_decimal_str(quote.notional_usd_micros.as_u128(), 6);
    let net_u_micros = quote
        .notional_usd_micros
        .as_u128()
        .saturating_sub(exec_total_fee_usd_micros);
    let net_u_str = format_u128_scaled_to_decimal_str(net_u_micros, 6);

    if let (Ok(kas_num), Ok(gross_num), Ok(net_num)) = (
        serde_json::from_str::<Value>(&kas_eq_str),
        serde_json::from_str::<Value>(&gross_u_str),
        serde_json::from_str::<Value>(&net_u_str),
    ) {
        let netting_entry = json!({
            "tx_uuid": quote.quote_id,
            "wallet": claims.prefixed_wallet,
            "direction": direction,
            "pay_asset": quote.pay_asset,
            "receive_asset": quote.receive_asset,
            "amount_kas": kas_num,
            "gross_usd": gross_num,
            "net_usd": net_num,
            "queued_at_ms": now_ms
        });
        let _: redis::RedisResult<()> = redis::cmd("RPUSH")
            .arg("perennia:sor:netting_queue")
            .arg(netting_entry.to_string())
            .query_async(&mut conn)
            .await;
    }

    // Step 5: Exact u128 HIFO Tax-Lot Disposal + Acquisition + Canonical Execution Commitment Hash
    let hifo_disposal = process_hifo_disposal_u128(
        &state.pg_pool,
        &claims.clean_wallet,
        &claims.prefixed_wallet,
        &quote.pay_asset,
        quote.pay_decimals,
        quote.amount_in_atomic.as_u128(),
        exec_pay_usd_e8,
        Some(&inbound_txid),
        true,
    )
    .await?;

    let hifo_acq_lot_id = record_hifo_acquisition_u128(
        &state.pg_pool,
        &claims.clean_wallet,
        &quote.receive_asset,
        quote.receive_decimals,
        settled_out_atomic,
        exec_receive_usd_e8,
        net_u_micros,
        &outbound_settlement_txid,
    )
    .await?;

    let pay_tok_str =
        format_u128_scaled_to_decimal_str(quote.amount_in_atomic.as_u128(), quote.pay_decimals);
    let pay_spot_str = format_u128_scaled_to_decimal_str(exec_pay_usd_e8, 8);
    let cost_basis_str = format_u128_scaled_to_decimal_str(
        hifo_disposal.matched_cost_basis_usd_micros.as_u128(),
        6,
    );
    let realized_signed_str = if hifo_disposal.is_net_gain {
        format_u128_scaled_to_decimal_str(hifo_disposal.realized_delta_usd_micros.as_u128(), 6)
    } else {
        format!(
            "-{}",
            format_u128_scaled_to_decimal_str(
                hifo_disposal.realized_delta_usd_micros.as_u128(),
                6
            )
        )
    };

    let _ = sqlx::query(
        r#"
        INSERT INTO tax_ledger_events (
            wallet_address, asset_ticker, event_type, gross_proceeds_usd,
            amount_tokens, spot_price_at_execution, tx_hash,
            cost_basis_usd, realized_gain_loss_usd, holding_period
        ) VALUES (
            $1, $2, 'AGENT_SWAP', $3::NUMERIC::DOUBLE PRECISION,
            $4::NUMERIC::DOUBLE PRECISION, $5::NUMERIC::DOUBLE PRECISION, $6,
            $7::NUMERIC::DOUBLE PRECISION, $8::NUMERIC::DOUBLE PRECISION, $9
        )
        "#,
    )
    .bind(&claims.clean_wallet)
    .bind(&quote.pay_asset)
    .bind(&gross_u_str)
    .bind(&pay_tok_str)
    .bind(&pay_spot_str)
    .bind(&inbound_txid)
    .bind(&cost_basis_str)
    .bind(&realized_signed_str)
    .bind(&hifo_disposal.holding_period)
    .execute(&state.pg_pool)
    .await;

    let execution_commitment_hash = compute_execution_commitment_hash(
        &quote.quote_id,
        &quote.mandate_id,
        &quote.pay_asset,
        &quote.receive_asset,
        exec_pay_usd_e8,
        exec_receive_usd_e8,
        exec_kas_usd_e8,
        quote.amount_in_atomic.as_u128(),
        settled_out_atomic,
        exec_protocol_fee_atomic,
        quote.network_fee_sompi.as_u128(),
        exec_total_fee_usd_micros,
        &inbound_txid,
        hifo_disposal.primary_disposal_lot_id,
        Some(hifo_acq_lot_id),
    );

    let receipt_id = format!("rcp_{}", Uuid::new_v4().simple());

    sqlx::query(
        r#"
        INSERT INTO agent_execution_receipts (
            receipt_id, idempotency_key, quote_id, key_id, mandate_id,
            agent_mode, wallet_address, clean_wallet, venue,
            pay_asset, receive_asset,
            amount_in_atomic, expected_out_atomic, min_amount_out_atomic, settled_out_atomic,
            protocol_fee_atomic, network_fee_sompi, total_fee_usd_micros, notional_usd_micros,
            pay_oracle_usd_e8, receive_oracle_usd_e8,
            tx_version, compute_mass, storage_mass, covenant_id,
            preimage_hash, execution_commitment_hash, l1_txid,
            hifo_disposal_lot_id, hifo_acquisition_lot_id, status
        ) VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8, $9,
            $10, $11,
            $12::NUMERIC(39, 0), $13::NUMERIC(39, 0), $14::NUMERIC(39, 0), $15::NUMERIC(39, 0),
            $16::NUMERIC(39, 0), $17::NUMERIC(39, 0), $18::NUMERIC(39, 0), $19::NUMERIC(39, 0),
            $20::NUMERIC(39, 0), $21::NUMERIC(39, 0),
            $22, $23, $24, $25,
            $26, $27, $28,
            $29, $30, 'SETTLED'
        )
        "#,
    )
    .bind(&receipt_id)
    .bind(&idempotency_key)
    .bind(&quote.quote_id)
    .bind(&claims.key_id)
    .bind(&quote.mandate_id)
    .bind(claims.mode.as_str())
    .bind(&claims.prefixed_wallet)
    .bind(&claims.clean_wallet)
    .bind(quote.venue.as_str())
    .bind(&quote.pay_asset)
    .bind(&quote.receive_asset)
    .bind(quote.amount_in_atomic.to_string())
    .bind(quote.expected_amount_out_atomic.to_string())
    .bind(quote.min_amount_out_atomic.to_string())
    .bind(settled_out_atomic.to_string())
    .bind(exec_protocol_fee_atomic.to_string())
    .bind(quote.network_fee_sompi.to_string())
    .bind(exec_total_fee_usd_micros.to_string())
    .bind(quote.notional_usd_micros.to_string())
    .bind(exec_pay_usd_e8.to_string())
    .bind(exec_receive_usd_e8.to_string())
    .bind(quote.tx_version as i32)
    .bind(quote.compute_grams as i64)
    .bind(quote.storage_mass as i64)
    .bind(quote.covenant_id.as_deref())
    .bind(&quote.preimage_hash)
    .bind(&execution_commitment_hash)
    .bind(&inbound_txid)
    .bind(hifo_disposal.primary_disposal_lot_id)
    .bind(hifo_acq_lot_id)
    .execute(&state.pg_pool)
    .await
    .map_err(|e| {
        tracing::error!("❌ [AGENT RECEIPT] Failed to persist agent_execution_receipts: {}", e);
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Failed to persist verifiable execution receipt in PostgreSQL.",
        )
    })?;

    let _ = sqlx::query(
        r#"
        UPDATE agent_api_keys
        SET verified_fills_count = verified_fills_count + 1,
            cumulative_volume_usd_micros = cumulative_volume_usd_micros + $2::NUMERIC(39, 0),
            last_settled_at = CURRENT_TIMESTAMP
        WHERE key_id = $1
        "#,
    )
    .bind(&claims.key_id)
    .bind(quote.notional_usd_micros.to_string())
    .execute(&state.pg_pool)
    .await;

    let receipt_json = json!({
        "ok": true,
        "dryRun": false,
        "receiptId": receipt_id,
        "quoteId": quote.quote_id,
        "idempotencyKey": idempotency_key,
        "mandateId": quote.mandate_id,
        "venue": quote.venue,
        "walletAddress": claims.prefixed_wallet,
        "payAsset": quote.pay_asset,
        "receiveAsset": quote.receive_asset,
        "amountIn": quote.amount_in_atomic,
        "settledAmountOut": U128Str(settled_out_atomic),
        "minAmountOut": quote.min_amount_out_atomic,
        "fees": {
            "protocolFeePayAtomic": U128Str(exec_protocol_fee_atomic),
            "networkFeeSompi": quote.network_fee_sompi,
            "totalFeeUsdMicros": U128Str(exec_total_fee_usd_micros)
        },
        "oracleExecutionSnapshot": {
            "payUsdE8": U128Str(exec_pay_usd_e8),
            "receiveUsdE8": U128Str(exec_receive_usd_e8),
            "kasUsdE8": U128Str(exec_kas_usd_e8)
        },
        "l1InboundTxid": inbound_txid,
        "settlementReference": outbound_settlement_txid,
        "preimageHash": quote.preimage_hash,
        "executionCommitmentHash": execution_commitment_hash,
        "hifoTax": {
            "disposalLotId": hifo_disposal.primary_disposal_lot_id.map(|u| u.to_string()),
            "acquisitionLotId": hifo_acq_lot_id.to_string(),
            "matchedCostBasisUsdMicros": hifo_disposal.matched_cost_basis_usd_micros,
            "grossProceedsUsdMicros": hifo_disposal.gross_proceeds_usd_micros,
            "realizedDeltaUsdMicros": hifo_disposal.realized_delta_usd_micros,
            "isNetGain": hifo_disposal.is_net_gain,
            "holdingPeriod": hifo_disposal.holding_period
        },
        "mandateRolling24h": {
            "spentSompi": U128Str(spent_24h_sompi),
            "capSompi": claims.cap_24h_sompi,
            "spentUsdMicros": U128Str(spent_24h_usd_micros),
            "capUsdMicros": claims.cap_24h_usd_micros
        },
        "microBatchClearing": micro_batch_meta,
        "settledAt": Utc::now().to_rfc3339()
    });

    publish_anonymized_ai_intent_skew(
        state,
        &mut conn,
        &quote.pay_asset,
        &quote.receive_asset,
        quote.venue.as_str(),
        quote.spend_sompi_equiv.as_u128(),
        quote.notional_usd_micros.as_u128(),
    )
    .await;

    locks_and_limits::finalize_settled_execution_metrics(
        &mut conn,
        &claims,
        &idempotency_key,
        quote.notional_usd_micros.as_u128(),
        &receipt_json,
        now_secs,
    )
    .await?;

    Ok(receipt_json)
}

pub async fn handle_post_execute(
    State(state): State<AgentGatewayState>,
    headers: HeaderMap,
    Json(raw_body): Json<Value>,
) -> Result<Json<Value>, AgentError> {
    let body = core_post_execute(&state, &headers, raw_body).await?;
    Ok(Json(body))
}

// ============================================================================
// ENDPOINT 4: MODE B PERSONAL TELEMETRY, MINER ECONOMICS & CHRONOS BUCKETS
// ============================================================================

pub async fn core_get_me_telemetry(
    state: &AgentGatewayState,
    headers: &HeaderMap,
) -> Result<Value, AgentError> {
    let mut conn = state.get_redis_conn().await?;
    let claims = authenticate_agent_request(state, headers, &mut conn).await?;

    if claims.mode != AgentMode::ModeB {
        return Err(AgentError::new(
            AgentErrorCode::ForbiddenMode,
            "Personal /me/telemetry endpoint is restricted strictly to Mode B Personal Mandate keys.",
        ));
    }

    let _ = locks_and_limits::enforce_dynamic_rate_limit(state, &mut conn, &claims, false).await?;

    // 1. Execution-sleeve balances (zero cold-vault tables or columns ever touched)
    let (streaming_kas_e8, total_yield_kas_e8, lp_map, _) = read_wallet_sleeve_balances_e8(
        &state.pg_pool,
        &claims.clean_wallet,
        &claims.prefixed_wallet,
    )
    .await?;

    let mut sleeve_balances: Vec<Value> = Vec::with_capacity(1 + lp_map.len());
    sleeve_balances.push(json!({
        "ticker": "KAS",
        "atomicDecimals": 8,
        "balanceE8": U128Str(streaming_kas_e8)
    }));
    for (tick, amt_e8) in lp_map {
        sleeve_balances.push(json!({
            "ticker": tick,
            "atomicDecimals": 8,
            "balanceE8": U128Str(amt_e8)
        }));
    }

    // 2. Live kaspad consensus & network telemetry from Redis
    let (net_diff_raw, virtual_daa_raw, reward_sompi_raw, sync_raw): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = redis::pipe()
        .cmd("GET")
        .arg("pool:network_diff")
        .cmd("GET")
        .arg("pool:virtual_daa_score")
        .cmd("GET")
        .arg("pool:block_reward_sompi")
        .cmd("GET")
        .arg("perennia:node:sync_status")
        .query_async(&mut conn)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::RedisUnavailable,
                "Failed to read live kaspad consensus metrics from Redis.",
            )
        })?;

    let net_diff_int = net_diff_raw
        .as_deref()
        .and_then(|s| parse_decimal_str_to_u128_scaled(s, 0).ok())
        .unwrap_or(0);
    let virtual_daa = virtual_daa_raw
        .as_deref()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let block_subsidy_sompi = reward_sompi_raw
        .as_deref()
        .and_then(|s| s.trim().parse::<u128>().ok())
        .unwrap_or(0);
    // Kaspa 10 BPS network hashrate estimate in GH/s: difficulty * 2 * 10 / 10^9 = difficulty / 50_000_000 (or exact H/s = diff * 20)
    let est_network_hashes_per_sec = net_diff_int.saturating_mul(20);

    // 3. UTXO parallel lane health via kaspad gRPC
    let raw_utxos = crate::kaspad_client::get_utxos_by_address_grpc(&claims.prefixed_wallet)
        .await
        .map_err(|_| {
            AgentError::new(
                AgentErrorCode::NodeUnavailable,
                "kaspad gRPC unavailable while inspecting Sovereign Wallet UTXO lanes.",
            )
        })?;
    let lane_health = locks_and_limits::inspect_utxo_lane_health(
        &mut conn,
        &claims.clean_wallet,
        &raw_utxos,
        virtual_daa,
    )
    .await?;

    // 4. Stratum worker shares & hashrate ahead of 22:00 UTC settlement
    let worker_rows = sqlx::query(
        r#"
        SELECT worker_name,
               TRUNC(GREATEST(hashrate_ths, 0) * 1000)::NUMERIC(39, 0)::TEXT AS hashrate_ghs,
               valid_shares,
               rejected_shares,
               blocks_found,
               stratum_port,
               status
        FROM worker_profiles
        WHERE wallet_address = $1
           OR LOWER(REPLACE(TRIM(wallet_address), 'kaspa:', '')) = $2
        ORDER BY valid_shares DESC
        LIMIT 50
        "#,
    )
    .bind(&claims.prefixed_wallet)
    .bind(&claims.clean_wallet)
    .fetch_all(&state.pg_pool)
    .await
    .map_err(|_| {
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Failed to query Stratum worker profiles.",
        )
    })?;

    let mut total_valid_shares: u128 = 0;
    let mut total_hashrate_ghs: u128 = 0;
    let mut workers_out: Vec<Value> = Vec::with_capacity(worker_rows.len());

    for wr in worker_rows {
        let raw_name: String = wr.try_get("worker_name").unwrap_or_default();
        let sterile_name: String = raw_name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .take(32)
            .collect();
        let ghs: u128 = wr
            .try_get::<String, _>("hashrate_ghs")
            .ok()
            .and_then(|s| s.trim().parse::<u128>().ok())
            .unwrap_or(0);
        let v_shares = wr.try_get::<i64, _>("valid_shares").unwrap_or(0).max(0) as u128;
        let r_shares = wr.try_get::<i64, _>("rejected_shares").unwrap_or(0).max(0) as u128;
        let blocks = wr.try_get::<i64, _>("blocks_found").unwrap_or(0).max(0) as u128;
        let port = wr.try_get::<i32, _>("stratum_port").unwrap_or(3332);
        let st: String = wr.try_get("status").unwrap_or_else(|_| "offline".to_string());

        total_valid_shares = total_valid_shares.saturating_add(v_shares);
        if st == "online" {
            total_hashrate_ghs = total_hashrate_ghs.saturating_add(ghs);
        }

        workers_out.push(json!({
            "worker": if sterile_name.is_empty() { "RIG".to_string() } else { sterile_name },
            "status": st,
            "stratumPort": port,
            "hashrateGhs": U128Str(ghs),
            "validShares": U128Str(v_shares),
            "rejectedShares": U128Str(r_shares),
            "blocksFound": U128Str(blocks)
        }));
    }

    let now_secs = now_unix_ms() / 1_000;
    let (_, next_bell_unix, secs_until_bell) =
        crate::chronos::compute_jerusalem_epoch_window(now_secs);
    let (spent_sompi, spent_usd_micros) =
        locks_and_limits::read_rolling_24h_spend(&mut conn, &claims.key_id, now_secs).await?;

    Ok(json!({
        "ok": true,
        "walletAddress": claims.prefixed_wallet,
        "coldVaultAccess": "HARD_BLOCKED_AIRLOCK",
        "executionSleeve": {
            "lifetimeMinedKasSompi": U128Str(total_yield_kas_e8),
            "balances": sleeve_balances
        },
        "utxoLaneHealth": lane_health,
        "stratumFleet": {
            "totalOnlineHashrateGhs": U128Str(total_hashrate_ghs),
            "accruedValidShares": U128Str(total_valid_shares),
            "next2200UtcSettlementUnix": next_bell_unix.to_string(),
            "secondsUntil2200UtcBell": secs_until_bell.to_string(),
            "workers": workers_out
        },
        "kaspaNetworkEconomics": {
            "nodeSyncStatus": sync_raw.unwrap_or_else(|| "Unknown".to_string()),
            "virtualDaaScore": virtual_daa.to_string(),
            "networkDifficulty": U128Str(net_diff_int),
            "estimatedNetworkHashesPerSec": U128Str(est_network_hashes_per_sec),
            "currentBlockSubsidySompi": U128Str(block_subsidy_sompi)
        },
        "mandateGuardrails": {
            "keyId": claims.key_id,
            "whitelistedAssets": claims.whitelisted_assets,
            "allowSwaps": claims.allow_swaps,
            "allowBucketUpdates": claims.allow_bucket_updates,
            "maxSlippageBps": claims.max_slippage_bps,
            "spent24hSompi": U128Str(spent_sompi),
            "cap24hSompi": claims.cap_24h_sompi,
            "spent24hUsdMicros": U128Str(spent_usd_micros),
            "cap24hUsdMicros": claims.cap_24h_usd_micros
        }
    }))
}

pub async fn handle_get_me_telemetry(
    State(state): State<AgentGatewayState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AgentError> {
    let body = core_get_me_telemetry(&state, &headers).await?;
    Ok(Json(body))
}

pub async fn core_get_me_buckets(
    state: &AgentGatewayState,
    headers: &HeaderMap,
) -> Result<Value, AgentError> {
    let mut conn = state.get_redis_conn().await?;
    let claims = authenticate_agent_request(state, headers, &mut conn).await?;

    if claims.mode != AgentMode::ModeB {
        return Err(AgentError::new(
            AgentErrorCode::ForbiddenMode,
            "Chronos /me/buckets endpoint is restricted strictly to Mode B Personal Mandate keys.",
        ));
    }

    let _ = locks_and_limits::enforce_dynamic_rate_limit(state, &mut conn, &claims, false).await?;

    let row_opt = sqlx::query(
        r#"
        SELECT layout_state
        FROM user_command_centers
        WHERE wallet_address = $1 OR wallet_address = $2
        LIMIT 1
        "#,
    )
    .bind(&claims.prefixed_wallet)
    .bind(&claims.clean_wallet)
    .fetch_optional(&state.pg_pool)
    .await
    .map_err(|_| {
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Failed to read user_command_centers bucket state.",
        )
    })?;

    let mut buckets_out: Vec<Value> = Vec::new();
    let mut total_pending_sompi: u128 = 0;

    if let Some(row) = row_opt {
        let layout: Value = row.try_get("layout_state").unwrap_or_else(|_| json!({}));
        if let Some(sectors) = layout.get("sectors").and_then(|v| v.as_array()) {
            for sec in sectors {
                let raw_tick = sec
                    .get("settlementConfig")
                    .and_then(|c| c.get("targetAsset"))
                    .and_then(|t| t.get("ticker"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("KAS");
                let Ok(ticker) = sanitize_sterile_ticker(raw_tick) else {
                    continue;
                };
                let split_bps: u16 = if let Some(bps) = sec.get("allocationBps").and_then(|v| v.as_u64()) {
                    bps as u16
                } else {
                    let pct_str = sec
                        .get("allocationPercentage")
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "0".to_string());
                    parse_decimal_str_to_u128_scaled(&pct_str, 2).unwrap_or(0) as u16
                };
                let pending_str = sec
                    .get("pendingKaspa")
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "0".to_string());
                let pending_sompi = parse_decimal_str_to_u128_scaled(&pending_str, 8).unwrap_or(0);
                total_pending_sompi = total_pending_sompi.saturating_add(pending_sompi);

                let route_mode = match sec.get("routeMode").and_then(|v| v.as_str()).unwrap_or("hold") {
                    "swap" | "convert" => "swap",
                    "auto-lp" => "auto-lp",
                    _ => "hold",
                };

                buckets_out.push(json!({
                    "ticker": ticker,
                    "splitBps": split_bps,
                    "routeMode": route_mode,
                    "pendingKasSompi": U128Str(pending_sompi)
                }));
            }
        }
    }

    Ok(json!({
        "ok": true,
        "walletAddress": claims.prefixed_wallet,
        "whitelistedAssets": claims.whitelisted_assets,
        "allowBucketUpdates": claims.allow_bucket_updates,
        "totalPendingKasSompi": U128Str(total_pending_sompi),
        "buckets": buckets_out
    }))
}

pub async fn handle_get_me_buckets(
    State(state): State<AgentGatewayState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AgentError> {
    let body = core_get_me_buckets(&state, &headers).await?;
    Ok(Json(body))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketSplitBpsItem {
    pub ticker: String,
    pub split_bps: u16,
    #[serde(default)]
    pub route_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMeBucketsRequest {
    pub allocations: Vec<BucketSplitBpsItem>,
    #[serde(default)]
    pub dry_run: bool,
}

pub async fn core_post_me_buckets(
    state: &AgentGatewayState,
    headers: &HeaderMap,
    raw_body: Value,
) -> Result<Value, AgentError> {
    let mut conn = state.get_redis_conn().await?;
    let claims = authenticate_agent_request(state, headers, &mut conn).await?;

    if claims.mode != AgentMode::ModeB {
        return Err(AgentError::new(
            AgentErrorCode::ForbiddenMode,
            "Director bucket updates are restricted strictly to Mode B Personal Mandate keys.",
        ));
    }

    if let Err(airlock_err) = reject_forbidden_cold_vault_or_withdrawal_keys(&raw_body) {
        let ban_secs = locks_and_limits::record_adversarial_fault(
            &mut conn,
            Some(&claims.key_id),
            &claims.clean_wallet,
            "BUCKETS_COLD_VAULT_OR_PAYOUT_ADDRESS_BYPASS_ATTEMPT",
        )
        .await?;
        return Err(AgentError::with_cooldown(ban_secs, airlock_err.message));
    }

    if !claims.allow_bucket_updates {
        let ban_secs = locks_and_limits::record_adversarial_fault(
            &mut conn,
            Some(&claims.key_id),
            &claims.clean_wallet,
            "MANDATE_BUCKETS_DISABLED_BYPASS",
        )
        .await?;
        return Err(AgentError::with_cooldown(
            ban_secs,
            "Mandate key does not have allowBucketUpdates permission.",
        ));
    }

    let _ = locks_and_limits::enforce_dynamic_rate_limit(state, &mut conn, &claims, false).await?;

    let req: UpdateMeBucketsRequest = serde_json::from_value(raw_body).map_err(|e| {
        AgentError::new(
            AgentErrorCode::InvalidInput,
            format!("Invalid bucket split payload: {}", e),
        )
    })?;

    if req.allocations.is_empty() || req.allocations.len() > 12 {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            "Bucket allocations must contain 1..=12 target asset splits.",
        ));
    }

    let mut seen_tickers: HashSet<String> = HashSet::with_capacity(req.allocations.len());
    let mut sum_bps: u32 = 0;
    let mut validated: Vec<(String, u16, &'static str)> = Vec::with_capacity(req.allocations.len());

    for item in &req.allocations {
        let tick = sanitize_sterile_ticker(&item.ticker)?;
        if !claims.is_asset_whitelisted(&tick) {
            let ban_secs = locks_and_limits::record_adversarial_fault(
                &mut conn,
                Some(&claims.key_id),
                &claims.clean_wallet,
                "BUCKETS_UNWHITELISTED_ASSET_ATTEMPT",
            )
            .await?;
            return Err(AgentError::with_cooldown(
                ban_secs,
                format!(
                    "Mandate violation: {} is not whitelisted on this Mandate key.",
                    tick
                ),
            ));
        }
        if !seen_tickers.insert(tick.clone()) {
            return Err(AgentError::new(
                AgentErrorCode::InvalidInput,
                format!("Duplicate ticker {} in bucket allocations.", tick),
            ));
        }
        if item.split_bps == 0 || item.split_bps > 10_000 {
            return Err(AgentError::new(
                AgentErrorCode::InvalidInput,
                "Each bucket splitBps must be an integer between 1 and 10000.",
            ));
        }
        sum_bps = sum_bps.saturating_add(item.split_bps as u32);

        let r_mode = match item
            .route_mode
            .as_deref()
            .unwrap_or(if tick == "KAS" { "hold" } else { "swap" })
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "auto-lp" => "auto-lp",
            "hold" if tick == "KAS" => "hold",
            "swap" if tick != "KAS" => "swap",
            _ => {
                if tick == "KAS" {
                    "hold"
                } else {
                    "swap"
                }
            }
        };
        validated.push((tick, item.split_bps, r_mode));
    }

    if sum_bps != 10_000 {
        return Err(AgentError::new(
            AgentErrorCode::InvalidInput,
            format!(
                "Director bucket splitBps must sum strictly to 10000 (100.00%); received {}.",
                sum_bps
            ),
        ));
    }

    if req.dry_run {
        let dry_log = json!({
            "stage": "DRY_RUN_BUCKETS",
            "keyId": claims.key_id,
            "totalBps": 10000,
            "bucketCount": validated.len(),
            "timestamp": Utc::now().to_rfc3339()
        });
        append_dry_run_audit_log(&mut conn, &claims.clean_wallet, &dry_log).await;

        let preview: Vec<Value> = validated
            .into_iter()
            .map(|(t, bps, rm)| json!({ "ticker": t, "splitBps": bps, "routeMode": rm }))
            .collect();
        return Ok(json!({
            "ok": true,
            "dryRun": true,
            "walletAddress": claims.prefixed_wallet,
            "totalBps": 10000,
            "buckets": preview
        }));
    }

    // Load existing user_command_centers layout so accrued `pendingKaspa` per sector is strictly preserved!
    let existing_opt = sqlx::query(
        r#"
        SELECT wallet_address, layout_state
        FROM user_command_centers
        WHERE wallet_address = $1 OR wallet_address = $2
        LIMIT 1
        "#,
    )
    .bind(&claims.prefixed_wallet)
    .bind(&claims.clean_wallet)
    .fetch_optional(&state.pg_pool)
    .await
    .map_err(|_| {
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Failed to read user_command_centers before updating buckets.",
        )
    })?;

    let (target_pk, mut layout) = if let Some(r) = existing_opt {
        (
            r.try_get::<String, _>("wallet_address")
                .unwrap_or_else(|_| claims.prefixed_wallet.clone()),
            r.try_get::<Value, _>("layout_state")
                .unwrap_or_else(|_| json!({ "workers": [], "sectors": [], "systemMode": "base" })),
        )
    } else {
        (
            claims.prefixed_wallet.clone(),
            json!({ "workers": [], "sectors": [], "systemMode": "base" }),
        )
    };

    // Preserve accrued `pendingKaspa` in exact sompi (`e8`): if an old sector's ticker is removed,
    // roll its accrued `pendingKaspa` into the first new sector so 0 sompi of miner yield is ever orphaned.
    let mut existing_pending_e8: BTreeMap<String, u128> = BTreeMap::new();
    if let Some(old_sectors) = layout.get("sectors").and_then(|v| v.as_array()) {
        for sec in old_sectors {
            let old_tick = sec
                .get("settlementConfig")
                .and_then(|c| c.get("targetAsset"))
                .and_then(|t| t.get("ticker"))
                .and_then(|v| v.as_str())
                .unwrap_or("KAS")
                .trim()
                .to_ascii_uppercase();
            let p_str = sec
                .get("pendingKaspa")
                .map(|v| v.to_string())
                .unwrap_or_else(|| "0".to_string());
            let p_e8 = parse_decimal_str_to_u128_scaled(&p_str, 8).unwrap_or(0);
            if p_e8 > 0 {
                let entry = existing_pending_e8.entry(old_tick).or_insert(0);
                *entry = entry.saturating_add(p_e8);
            }
        }
    }

    let new_tick_set: HashSet<String> = validated.iter().map(|(t, _, _)| t.clone()).collect();
    let mut carryover_e8: u128 = 0;
    for (old_t, amt_e8) in &existing_pending_e8 {
        if !new_tick_set.contains(old_t) {
            carryover_e8 = carryover_e8.saturating_add(*amt_e8);
        }
    }

    let mut new_sectors: Vec<Value> = Vec::with_capacity(validated.len());
    let mut response_buckets: Vec<Value> = Vec::with_capacity(validated.len());

    for (idx, (tick, bps, r_mode)) in validated.into_iter().enumerate() {
        let mut sec_pending_e8 = existing_pending_e8.get(&tick).copied().unwrap_or(0);
        if idx == 0 && carryover_e8 > 0 {
            sec_pending_e8 = sec_pending_e8.saturating_add(carryover_e8);
        }

        let pct_str = format!("{}.{:02}", bps / 100, bps % 100);
        let pct_json_num = serde_json::from_str::<Value>(&pct_str).unwrap_or_else(|_| json!(0));
        let pending_dec_str = format_u128_scaled_to_decimal_str(sec_pending_e8, 8);
        let pending_json_num =
            serde_json::from_str::<Value>(&pending_dec_str).unwrap_or_else(|_| json!(0));

        // Destination-locked strictly to `claims.prefixed_wallet` (zero external withdrawal capability)
        new_sectors.push(json!({
            "id": format!("AGENT-SEC-{}", tick),
            "name": format!("{} Sector", tick),
            "allocationPercentage": pct_json_num,
            "allocationBps": bps,
            "routeMode": r_mode,
            "settlementConfig": {
                "targetAsset": {
                    "ticker": tick,
                    "name": tick,
                    "assetClass": if tick == "KAS" { "Native L1" } else { "Automated Bucket" },
                    "theme": { "hex": "#18C6A5", "pastel": "#99f6e4" }
                },
                "payoutAddress": claims.prefixed_wallet,
                "autoPayout": false,
                "mode": "epoch_2200_utc"
            },
            "pendingKaspa": pending_json_num,
            "width": 12
        }));

        response_buckets.push(json!({
            "ticker": tick,
            "splitBps": bps,
            "routeMode": r_mode,
            "pendingKasSompi": U128Str(sec_pending_e8),
            "lockedDestination": claims.prefixed_wallet
        }));
    }

    layout["sectors"] = Value::Array(new_sectors);

    sqlx::query(
        r#"
        INSERT INTO user_command_centers (wallet_address, layout_state, last_updated)
        VALUES ($1, $2, CURRENT_TIMESTAMP)
        ON CONFLICT (wallet_address) DO UPDATE SET
            layout_state = EXCLUDED.layout_state,
            last_updated = CURRENT_TIMESTAMP
        "#,
    )
    .bind(&target_pk)
    .bind(&layout)
    .execute(&state.pg_pool)
    .await
    .map_err(|_| {
        AgentError::new(
            AgentErrorCode::DatabaseUnavailable,
            "Failed to persist updated Director bucket splits.",
        )
    })?;

    let pool_bg = state.pg_pool.clone();
    tokio::spawn(async move {
        let _ = crate::chronos::publish_live_epoch_bucket_telemetry(&pool_bg, 0.0).await;
    });

    Ok(json!({
        "ok": true,
        "dryRun": false,
        "walletAddress": claims.prefixed_wallet,
        "totalBps": 10000,
        "buckets": response_buckets,
        "updatedAt": Utc::now().to_rfc3339()
    }))
}

pub async fn handle_post_me_buckets(
    State(state): State<AgentGatewayState>,
    headers: HeaderMap,
    Json(raw_body): Json<Value>,
) -> Result<Json<Value>, AgentError> {
    let body = core_post_me_buckets(&state, &headers, raw_body).await?;
    Ok(Json(body))
}