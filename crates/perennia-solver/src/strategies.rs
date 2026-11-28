use anyhow::Result;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

use crate::accounting::{
    compute_lp_pair_sompi_split, compute_protocol_sompi_split, mul_div_floor_u128,
    split_inventory_and_external_overflow, SOMPI_PER_KAS,
};
use crate::agent_client::{AgentGatewayClient, GatewayMarketAsset};
use crate::cex_books::{
    best_buy_vwap, best_post_only_maker_buy, best_post_only_maker_sell, best_sell_vwap,
    VenueOrderBook,
};
use crate::config::SolverConfig;
use crate::db::{record_pnl_entry, record_prehedge_run, record_solver_tax_event, PnlEntryRecord};
use crate::kaspa_crypto::SolverIdentity;

const STANDARD_L1_GAS_KAS: f64 = 0.0033;
const KRC20_REVEAL_GAS_KAS: f64 = 0.0065;
const MAX_GATEWAY_DIVERGENCE_BPS: u64 = 150;
const BUY_KAS_INBOUND_TAKER_BPS: f64 = 20.0;

pub struct TickContext<'a> {
    pub cfg: &'a SolverConfig,
    pub identity: &'a SolverIdentity,
    pub pool: &'a PgPool,
    pub gateway: &'a mut AgentGatewayClient,
    pub session_id: Uuid,
    pub maker_fee_bps: f64,
    pub taker_fee_bps: f64,
    pub markets: &'a HashMap<String, GatewayMarketAsset>,
    pub books: &'a HashMap<String, Vec<VenueOrderBook>>,
    pub kas_usd: f64,
    pub kas_usd_e8: u128,
    pub usdc_usd: f64,
    pub usdt_usd: f64,
    pub solver_inventory_sompi: u128,
    pub master_treasury_address: &'a str,
    pub forbidden_hot_address: Option<&'a str>,
    pub five_min_bucket: i64,
}

fn sign_shadow_intent(
    identity: &SolverIdentity,
    strategy: &str,
    pair: &str,
    notional: f64,
    source_ref: &str,
) -> String {
    let payload = format!(
        "PERENNIA_SOLVER_SHADOW_V1|{}|{}|{:.4}|{}",
        strategy, pair, notional, source_ref
    );
    identity.sign_blake3_message(payload.as_bytes())
}

/// 1. 10-Second SOR Batch & Dark Pool RFQ Maker (pure u128 sompi accounting + live L1 settlement / external overflow)
pub async fn evaluate_sor_and_rfq_maker(
    ctx: &mut TickContext<'_>,
    redis_conn: &mut redis::aio::MultiplexedConnection,
) -> Result<i64> {
    let mut evaluated: i64 = 0;
    let l1_gas_usd = STANDARD_L1_GAS_KAS * ctx.kas_usd;
    let mut remaining_inventory_sompi = ctx.solver_inventory_sompi;

    let (netting_items, passthrough_items): (Vec<String>, Vec<String>) = redis::pipe()
        .cmd("LRANGE").arg("perennia:sor:netting_queue").arg(0).arg(49)
        .cmd("LRANGE").arg("perennia:sor:third_party_passthrough_queue").arg(0).arg(24)
        .query_async(redis_conn)
        .await
        .unwrap_or_default();

    for raw in netting_items.iter().chain(passthrough_items.iter()) {
        let Ok(ord) = serde_json::from_str::<Value>(raw) else { continue };
        if ord.get("solverOverflowRouted").and_then(|v| v.as_bool()) == Some(true) {
            continue;
        }
        evaluated += 1;

        let is_residual = ord.get("type").and_then(|v| v.as_str()) == Some("NET_RESIDUAL_AUTOBALANCE");
        let (pair, perennia_side, kas_qty, notional_usd, src_ref) = if is_residual {
            let target = ord.get("target_asset").and_then(|v| v.as_str()).unwrap_or("USDC").to_uppercase();
            let action = ord.get("rebalance_action").and_then(|v| v.as_str()).unwrap_or("BUY_DEFICIT_WITH_KAS");
            let res_usd = ord.get("residual_usd").and_then(|v| v.as_f64()).unwrap_or(0.0).min(ctx.cfg.max_notional_usd);
            let batch_id = ord.get("batch_id").and_then(|v| v.as_str()).unwrap_or("RES");
            let slice_idx = ord.get("slice_index").and_then(|v| v.as_str()).unwrap_or("1/1");
            if res_usd < 5.0 { continue; }
            (format!("KAS/{}", target), action.to_string(), res_usd / ctx.kas_usd, res_usd, format!("PT_{}_{}_{}", batch_id, target, slice_idx))
        } else {
            let dir = ord.get("direction").and_then(|v| v.as_str()).unwrap_or("SELL_KAS");
            let amt_kas = ord.get("amount_kas").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let gross_u = ord.get("gross_usd").and_then(|v| v.as_f64()).unwrap_or(amt_kas * ctx.kas_usd).min(ctx.cfg.max_notional_usd);
            if gross_u < 5.0 { continue; }
            let hash_ref = &blake3::hash(raw.as_bytes()).to_hex().to_string()[..16];
            ("KAS/USDC".to_string(), format!("ABSORB_{}", dir), gross_u / ctx.kas_usd, gross_u, format!("NQ_{}", hash_ref))
        };

        // Pure integer u128 sompi calculation & deterministic fee split verification
        let requested_sompi = ord
            .get("amount_sompi")
            .and_then(|v| {
                v.as_u64()
                    .map(|u| u as u128)
                    .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u128>().ok()))
            })
            .unwrap_or_else(|| {
                let micro_usd = ((notional_usd * 1_000_000.0).round() as u128).max(1);
                mul_div_floor_u128(micro_usd, SOMPI_PER_KAS * 100, ctx.kas_usd_e8).unwrap_or(0)
            });
        if requested_sompi == 0 {
            continue;
        }
        let lp_tier_opt = ord
            .get("lpFeeTierBps")
            .and_then(|v| v.as_u64())
            .and_then(|u| u16::try_from(u).ok());
        let (lp_fee_sompi, treasury_fee_sompi, net_in_sompi) = if let Some(tier_bps) = lp_tier_opt {
            match compute_lp_pair_sompi_split(requested_sompi, tier_bps) {
                Ok(s) => (s.lp_fee_sompi, s.treasury_fee_sompi, s.net_out_sompi),
                Err(_) => continue,
            }
        } else {
            let fee_bps = (ctx.maker_fee_bps.round() as u16).max(6);
            match compute_protocol_sompi_split(requested_sompi, fee_bps) {
                Ok(s) => (0u128, s.treasury_fee_sompi, s.net_out_sompi),
                Err(_) => continue,
            }
        };

        let Some(kas_books) = ctx.books.get("KAS") else { continue };
        let captured_taker_spread_bps = 45.0_f64;
        let quote_opt = if perennia_side.contains("SELL_KAS") || perennia_side.contains("BUY_DEFICIT_WITH_KAS") {
            best_sell_vwap(kas_books, kas_qty).map(|vwap| {
                let perennia_buy_px = ctx.kas_usd * (1.0 - captured_taker_spread_bps / 10_000.0);
                let gross_bps = ((vwap.vwap_price_usd - perennia_buy_px) / perennia_buy_px) * 10_000.0;
                (perennia_buy_px, vwap, gross_bps)
            })
        } else {
            best_buy_vwap(kas_books, kas_qty).map(|vwap| {
                let perennia_sell_px = ctx.kas_usd * (1.0 + captured_taker_spread_bps / 10_000.0);
                let gross_bps = ((perennia_sell_px - vwap.vwap_price_usd) / vwap.vwap_price_usd) * 10_000.0;
                (perennia_sell_px, vwap, gross_bps)
            })
        };

        if let Some((perennia_px, vwap, gross_edge_bps)) = quote_opt {
            let l1_bps = (l1_gas_usd / notional_usd) * 10_000.0;
            let net_edge_bps = gross_edge_bps - ctx.maker_fee_bps - vwap.venue_fee_bps - l1_bps;
            let gross_pnl = notional_usd * (gross_edge_bps / 10_000.0);
            let costs_usd = notional_usd * ((ctx.maker_fee_bps + vwap.venue_fee_bps) / 10_000.0) + l1_gas_usd;
            let net_pnl = gross_pnl - costs_usd;
            let is_prof = net_edge_bps >= ctx.cfg.min_net_edge_bps && net_pnl > 0.0;

            let mut exec_txid: Option<String> = None;
            let mut exec_receipt_id: Option<String> = None;
            let mut exec_err: Option<String> = None;
            let inv_split = split_inventory_and_external_overflow(requested_sompi, remaining_inventory_sompi);

            let status: String = if !is_prof {
                if ctx.cfg.dry_run {
                    "SHADOW_SKIPPED_UNPROFITABLE".to_string()
                } else {
                    "LIVE_SKIPPED_UNPROFITABLE".to_string()
                }
            } else if ctx.cfg.dry_run {
                "SHADOW_FILLED".to_string()
            } else {
                // Live Fee-Capturing Execution: internalize up to verified solver UTXOs and route excess cleanly to external overflow
                if inv_split.external_overflow_sompi > 0 {
                    let overflow_payload = json!({
                        "type": "EXTERNAL_OVERFLOW_PASSTHROUGH",
                        "solverOverflowRouted": true,
                        "sourceRef": src_ref,
                        "pair": pair,
                        "requestedSompi": requested_sompi.to_string(),
                        "internalizedSompi": inv_split.internalized_sompi.to_string(),
                        "overflowSompi": inv_split.external_overflow_sompi.to_string(),
                        "masterTreasuryAddress": ctx.master_treasury_address
                    });
                    let _ = redis::cmd("RPUSH")
                        .arg("perennia:sor:third_party_passthrough_queue")
                        .arg(overflow_payload.to_string())
                        .query_async::<_, i64>(redis_conn)
                        .await;
                }

                if inv_split.internalized_sompi > 0 {
                    match ctx
                        .gateway
                        .quote_and_execute_l1_swap(
                            "KAS",
                            "USDC",
                            inv_split.internalized_sompi,
                            ctx.master_treasury_address,
                            ctx.forbidden_hot_address,
                        )
                        .await
                    {
                        Ok(res) => {
                            remaining_inventory_sompi = remaining_inventory_sompi
                                .saturating_sub(inv_split.internalized_sompi);
                            exec_txid = res
                                .get("l1Txid")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            exec_receipt_id = res
                                .get("receiptId")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            let gross_micros = mul_div_floor_u128(
                                inv_split.internalized_sompi,
                                ctx.kas_usd_e8,
                                SOMPI_PER_KAS * 100,
                            )
                            .unwrap_or(0);
                            let _ = record_solver_tax_event(
                                ctx.pool,
                                &ctx.identity.kaspa_address,
                                "KAS",
                                "SOLVER_LIVE_L1_SETTLEMENT",
                                gross_micros,
                                inv_split.internalized_sompi,
                                ctx.kas_usd_e8,
                            )
                            .await;
                            "LIVE_SETTLED".to_string()
                        }
                        Err(e) => {
                            exec_err = Some(e.to_string());
                            "LIVE_EXECUTION_FAILED".to_string()
                        }
                    }
                } else {
                    "LIVE_OVERFLOW_EXTERNAL".to_string()
                }
            };

            let sig = sign_shadow_intent(ctx.identity, "SOR_10S_BATCH_MAKER", &pair, notional_usd, &src_ref);
            let _ = record_pnl_entry(ctx.pool, ctx.session_id, &PnlEntryRecord {
                strategy: "SOR_10S_BATCH_MAKER".to_string(),
                execution_status: status,
                dry_run: ctx.cfg.dry_run,
                pair,
                perennia_side,
                cex_venue: vwap.venue,
                cex_order_type: "IOC_TAKER".to_string(),
                notional_usd,
                base_amount: kas_qty,
                perennia_exec_price_usd: perennia_px,
                cex_vwap_price_usd: vwap.vwap_price_usd,
                gross_edge_bps,
                perennia_fee_bps: ctx.maker_fee_bps,
                cex_fee_bps: vwap.venue_fee_bps,
                l1_gas_usd,
                slippage_bps: vwap.slippage_bps,
                net_edge_bps,
                gross_pnl_usd: gross_pnl,
                total_costs_usd: costs_usd,
                net_pnl_usd: net_pnl,
                schnorr_intent_sig: sig,
                source_ref: src_ref,
                metadata_json: json!({
                    "queueOrigin": if is_residual { "passthrough" } else { "netting_queue" },
                    "requestedSompi": requested_sompi.to_string(),
                    "internalizedSompi": inv_split.internalized_sompi.to_string(),
                    "externalOverflowSompi": inv_split.external_overflow_sompi.to_string(),
                    "lpFeeSompi": lp_fee_sompi.to_string(),
                    "treasuryFeeSompi": treasury_fee_sompi.to_string(),
                    "netInSompi": net_in_sompi.to_string(),
                    "masterTreasuryAddress": ctx.master_treasury_address,
                    "l1Txid": exec_txid,
                    "receiptId": exec_receipt_id,
                    "error": exec_err
                }),
            }).await;
        }
    }

    let (_, rfq_keys): (u64, Vec<String>) = redis::cmd("SCAN")
        .arg(0u64).arg("MATCH").arg("perennia:agent:rfq_side:*").arg("COUNT").arg(100u64)
        .query_async(redis_conn).await.unwrap_or((0, Vec::new()));

    for side_key in rfq_keys {
        let quote_ids: Vec<String> = redis::cmd("ZRANGE").arg(&side_key).arg(0).arg(15).query_async(redis_conn).await.unwrap_or_default();
        for qid in quote_ids {
            let ord_raw: Option<String> = redis::cmd("GET").arg(format!("perennia:agent:rfq_order:{}", qid)).query_async(redis_conn).await.unwrap_or(None);
            let Some(ord_str) = ord_raw else { continue };
            let Ok(rfq) = serde_json::from_str::<Value>(&ord_str) else { continue };
            evaluated += 1;

            let pay_asset = rfq.get("payAsset").and_then(|v| v.as_str()).unwrap_or("");
            let rec_asset = rfq.get("receiveAsset").and_then(|v| v.as_str()).unwrap_or("");
            let offer_atomic = rfq.get("makerOfferAtomic").and_then(|v| v.as_str()).and_then(|s| s.parse::<u128>().ok()).unwrap_or(0);
            let min_rec_atomic = rfq.get("makerMinReceiveAtomic").and_then(|v| v.as_str()).and_then(|s| s.parse::<u128>().ok()).unwrap_or(0);
            if offer_atomic == 0 || min_rec_atomic == 0 { continue; }
            let Some(pay_mkt) = ctx.markets.get(pay_asset) else { continue };
            let Some(rec_mkt) = ctx.markets.get(rec_asset) else { continue };
            let offer_units = (offer_atomic as f64) / 10f64.powi(pay_mkt.decimals as i32);
            let req_units = (min_rec_atomic as f64) / 10f64.powi(rec_mkt.decimals as i32);

            if pay_asset == "KAS" && (rec_asset == "USDC" || rec_asset == "USDT") {
                if let Some(kas_books) = ctx.books.get("KAS") {
                    if let Some(vwap) = best_sell_vwap(kas_books, offer_units) {
                        let implied_maker_px = req_units / offer_units;
                        let notional = offer_units * vwap.vwap_price_usd;
                        let gross_bps = ((vwap.vwap_price_usd - implied_maker_px) / implied_maker_px) * 10_000.0;
                        let buy_kas_bps = BUY_KAS_INBOUND_TAKER_BPS.min(ctx.taker_fee_bps);
                        let l1_bps = (l1_gas_usd / notional.max(1.0)) * 10_000.0;
                        let net_bps = gross_bps - buy_kas_bps - vwap.venue_fee_bps - l1_bps;
                        let gross_pnl = notional * (gross_bps / 10_000.0);
                        let costs = notional * ((buy_kas_bps + vwap.venue_fee_bps) / 10_000.0) + l1_gas_usd;
                        let net_pnl = gross_pnl - costs;
                        let filled_label = if ctx.cfg.dry_run { "SHADOW_FILLED" } else { "LIVE_SIGNAL_QUEUED" };
                        let skipped_label = if ctx.cfg.dry_run { "SHADOW_SKIPPED_UNPROFITABLE" } else { "LIVE_SKIPPED_UNPROFITABLE" };
                        let status = if net_bps >= ctx.cfg.min_net_edge_bps && net_pnl > 0.0 { filled_label } else { skipped_label };
                        let sig = sign_shadow_intent(ctx.identity, "DARK_POOL_RFQ_CROSS", "KAS/USDC", notional, &qid);
                        let _ = record_pnl_entry(ctx.pool, ctx.session_id, &PnlEntryRecord {
                            strategy: "DARK_POOL_RFQ_CROSS".to_string(),
                            execution_status: status.to_string(),
                            dry_run: ctx.cfg.dry_run,
                            pair: format!("{}/{}", pay_asset, rec_asset),
                            perennia_side: "CROSS_RESTING_MAKER_RFQ".to_string(),
                            cex_venue: vwap.venue,
                            cex_order_type: "IOC_TAKER".to_string(),
                            notional_usd: notional,
                            base_amount: offer_units,
                            perennia_exec_price_usd: implied_maker_px,
                            cex_vwap_price_usd: vwap.vwap_price_usd,
                            gross_edge_bps: gross_bps,
                            perennia_fee_bps: buy_kas_bps,
                            cex_fee_bps: vwap.venue_fee_bps,
                            l1_gas_usd,
                            slippage_bps: vwap.slippage_bps,
                            net_edge_bps: net_bps,
                            gross_pnl_usd: gross_pnl,
                            total_costs_usd: costs,
                            net_pnl_usd: net_pnl,
                            schnorr_intent_sig: sig,
                            source_ref: format!("RFQ_{}", qid),
                            metadata_json: json!({ "rfqSideKey": side_key }),
                        }).await;
                    }
                }
            }
        }
    }

    if let Some(kas_books) = ctx.books.get("KAS") {
        let kas_qty = ctx.cfg.default_notional_usd / ctx.kas_usd;
        if let Some(vwap) = best_sell_vwap(kas_books, kas_qty) {
            evaluated += 1;
            let maker_bid_px = ctx.kas_usd * (1.0 - 0.0028);
            let gross_bps = ((vwap.vwap_price_usd - maker_bid_px) / maker_bid_px) * 10_000.0;
            let l1_bps = (l1_gas_usd / ctx.cfg.default_notional_usd) * 10_000.0;
            let net_bps = gross_bps - ctx.maker_fee_bps - vwap.venue_fee_bps - l1_bps;
            let gross_pnl = ctx.cfg.default_notional_usd * (gross_bps / 10_000.0);
            let costs = ctx.cfg.default_notional_usd * ((ctx.maker_fee_bps + vwap.venue_fee_bps) / 10_000.0) + l1_gas_usd;
            let net_pnl = gross_pnl - costs;
            let src_ref = format!("STANDING_MAKER_KAS_USDC_{}", ctx.five_min_bucket);
            let sig = sign_shadow_intent(ctx.identity, "SOR_10S_BATCH_MAKER", "KAS/USDC", ctx.cfg.default_notional_usd, &src_ref);
            let _ = record_pnl_entry(ctx.pool, ctx.session_id, &PnlEntryRecord {
                strategy: "SOR_10S_BATCH_MAKER".to_string(),
                execution_status: "SHADOW_QUOTE_BENCHMARK".to_string(),
                dry_run: ctx.cfg.dry_run,
                pair: "KAS/USDC".to_string(),
                perennia_side: "RESTING_RFQ_MAKER_BID".to_string(),
                cex_venue: vwap.venue,
                cex_order_type: "IOC_TAKER".to_string(),
                notional_usd: ctx.cfg.default_notional_usd,
                base_amount: kas_qty,
                perennia_exec_price_usd: maker_bid_px,
                cex_vwap_price_usd: vwap.vwap_price_usd,
                gross_edge_bps: gross_bps,
                perennia_fee_bps: ctx.maker_fee_bps,
                cex_fee_bps: vwap.venue_fee_bps,
                l1_gas_usd,
                slippage_bps: vwap.slippage_bps,
                net_edge_bps: net_bps,
                gross_pnl_usd: gross_pnl,
                total_costs_usd: costs,
                net_pnl_usd: net_pnl,
                schnorr_intent_sig: sig,
                source_ref: src_ref,
                metadata_json: json!({ "l2DepthLevels": 100, "topBidUsd": vwap.top_of_book_usd }),
            }).await;
        }
    }

    Ok(evaluated)
}

/// 2. Cross-Asset Differential & Ring Engine (Strict Taker fees + 5m shadow fill deduplication)
pub async fn evaluate_cross_asset_and_rings(
    ctx: &TickContext<'_>,
    redis_conn: &mut redis::aio::MultiplexedConnection,
) -> Result<i64> {
    let mut evaluated: i64 = 0;
    let notional = ctx.cfg.default_notional_usd;
    let l1_gas_usd = STANDARD_L1_GAS_KAS * ctx.kas_usd;

    let (usdc_halt, usdt_halt): (Option<String>, Option<String>) = redis::pipe()
        .cmd("GET").arg("oracle:depeg_halt:USDC")
        .cmd("GET").arg("oracle:depeg_halt:USDT")
        .query_async(redis_conn).await.unwrap_or((None, None));

    if usdc_halt.as_deref() == Some("1") || usdt_halt.as_deref() == Some("1") {
        let src_ref = format!("DEPEG_HALT_{}", ctx.five_min_bucket);
        let sig = sign_shadow_intent(ctx.identity, "STABLE_PARITY_BASIS", "USDC/USDT", notional, &src_ref);
        let _ = record_pnl_entry(ctx.pool, ctx.session_id, &PnlEntryRecord {
            strategy: "STABLE_PARITY_BASIS".to_string(),
            execution_status: "SHADOW_HALTED_RISK".to_string(),
            dry_run: ctx.cfg.dry_run,
            pair: "USDC/USDT".to_string(),
            perennia_side: "HALT_DEPEG_BREAKER".to_string(),
            cex_venue: "none".to_string(),
            cex_order_type: "NONE".to_string(),
            notional_usd: 0.0,
            base_amount: 0.0,
            perennia_exec_price_usd: ctx.usdc_usd,
            cex_vwap_price_usd: ctx.usdt_usd,
            gross_edge_bps: 0.0,
            perennia_fee_bps: 0.0,
            cex_fee_bps: 0.0,
            l1_gas_usd: 0.0,
            slippage_bps: 0.0,
            net_edge_bps: 0.0,
            gross_pnl_usd: 0.0,
            total_costs_usd: 0.0,
            net_pnl_usd: 0.0,
            schnorr_intent_sig: sig,
            source_ref: src_ref,
            metadata_json: json!({ "usdcHalt": usdc_halt, "usdtHalt": usdt_halt }),
        }).await;
    } else if let Some(usdc_books) = ctx.books.get("USDC") {
        evaluated += 1;
        let perennia_ratio = ctx.usdc_usd / ctx.usdt_usd.max(0.99);
        if let (Some(sell_q), Some(buy_q)) = (best_sell_vwap(usdc_books, notional), best_buy_vwap(usdc_books, notional)) {
            let sell_cex_edge_bps = ((sell_q.vwap_price_usd / ctx.usdt_usd) - perennia_ratio) * 10_000.0;
            let buy_cex_edge_bps = (perennia_ratio - (buy_q.vwap_price_usd / ctx.usdt_usd)) * 10_000.0;
            let (side, vwap, gross_bps) = if sell_cex_edge_bps >= buy_cex_edge_bps {
                ("BUY_PERENNIA_USDC_SELL_CEX", sell_q, sell_cex_edge_bps)
            } else {
                ("SELL_PERENNIA_USDC_BUY_CEX", buy_q, buy_cex_edge_bps)
            };
            let perennia_leg_bps = ctx.taker_fee_bps; // Strict 50 bps Taker on uncrossed USDC/USDT swap
            let l1_bps = (l1_gas_usd / notional) * 10_000.0;
            let net_bps = gross_bps - perennia_leg_bps - vwap.venue_fee_bps - l1_bps;
            let gross_pnl = notional * (gross_bps / 10_000.0);
            let costs = notional * ((perennia_leg_bps + vwap.venue_fee_bps) / 10_000.0) + l1_gas_usd;
            let net_pnl = gross_pnl - costs;
            let is_prof = net_bps >= ctx.cfg.min_net_edge_bps && net_pnl > 0.0;
            let src_ref = if is_prof { format!("PARITY_FILL_{}", ctx.five_min_bucket) } else { format!("PARITY_BENCH_{}", ctx.five_min_bucket) };
            let filled_label = if ctx.cfg.dry_run { "SHADOW_FILLED" } else { "LIVE_SIGNAL_QUEUED" };
            let skipped_label = if ctx.cfg.dry_run { "SHADOW_SKIPPED_UNPROFITABLE" } else { "LIVE_SKIPPED_UNPROFITABLE" };
            let status = if is_prof { filled_label } else { skipped_label };
            let sig = sign_shadow_intent(ctx.identity, "STABLE_PARITY_BASIS", "USDC/USDT", notional, &src_ref);
            let _ = record_pnl_entry(ctx.pool, ctx.session_id, &PnlEntryRecord {
                strategy: "STABLE_PARITY_BASIS".to_string(),
                execution_status: status.to_string(),
                dry_run: ctx.cfg.dry_run,
                pair: "USDC/USDT".to_string(),
                perennia_side: side.to_string(),
                cex_venue: vwap.venue,
                cex_order_type: "IOC_TAKER".to_string(),
                notional_usd: notional,
                base_amount: notional,
                perennia_exec_price_usd: ctx.usdc_usd,
                cex_vwap_price_usd: vwap.vwap_price_usd,
                gross_edge_bps: gross_bps,
                perennia_fee_bps: perennia_leg_bps,
                cex_fee_bps: vwap.venue_fee_bps,
                l1_gas_usd,
                slippage_bps: vwap.slippage_bps,
                net_edge_bps: net_bps,
                gross_pnl_usd: gross_pnl,
                total_costs_usd: costs,
                net_pnl_usd: net_pnl,
                schnorr_intent_sig: sig,
                source_ref: src_ref,
                metadata_json: json!({ "usdcUsd": ctx.usdc_usd, "usdtUsd": ctx.usdt_usd }),
            }).await;
        }
    }

    for asset in ["KAS", "BTC", "ETH", "SOL"] {
        let venue_raw: Option<String> = redis::cmd("GET").arg(format!("oracle:venues:{}", asset)).query_async(redis_conn).await.unwrap_or(None);
        let Some(venue_str) = venue_raw else { continue };
        let Ok(v_doc) = serde_json::from_str::<Value>(&venue_str) else { continue };
        let div_bps = v_doc.get("divergenceBps").and_then(|v| v.as_u64()).unwrap_or(0);
        if div_bps > MAX_GATEWAY_DIVERGENCE_BPS { continue; }
        let median_usd = v_doc.get("medianUsd").and_then(|v| v.as_f64()).or_else(|| ctx.markets.get(asset).map(|m| m.oracle_usd)).unwrap_or(0.0);
        if median_usd <= 0.0 { continue; }
        let Some(asset_books) = ctx.books.get(asset) else { continue };
        let base_qty = notional / median_usd;
        evaluated += 1;

        let sell_cand = best_sell_vwap(asset_books, base_qty).map(|q| {
            let g_bps = ((q.vwap_price_usd - median_usd) / median_usd) * 10_000.0;
            ("BUY_PERENNIA_MEDIAN_SELL_CEX", q, g_bps)
        });
        let buy_cand = best_buy_vwap(asset_books, base_qty).map(|q| {
            let g_bps = ((median_usd - q.vwap_price_usd) / q.vwap_price_usd) * 10_000.0;
            ("SELL_PERENNIA_MEDIAN_BUY_CEX", q, g_bps)
        });

        let chosen = match (sell_cand, buy_cand) {
            (Some(s), Some(b)) => if s.2 >= b.2 { Some(s) } else { Some(b) },
            (Some(s), None) => Some(s),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        if let Some((side, vwap, gross_bps)) = chosen {
            let perennia_leg_bps = if asset == "KAS" && side == "BUY_PERENNIA_MEDIAN_SELL_CEX" {
                BUY_KAS_INBOUND_TAKER_BPS.min(ctx.taker_fee_bps) // 20 bps inbound Buy-KAS Taker tier
            } else {
                ctx.taker_fee_bps // 50 bps standard Dark Pool Taker tier
            };
            let l1_bps = (l1_gas_usd / notional) * 10_000.0;
            let net_bps = gross_bps - perennia_leg_bps - vwap.venue_fee_bps - l1_bps;
            let gross_pnl = notional * (gross_bps / 10_000.0);
            let costs = notional * ((perennia_leg_bps + vwap.venue_fee_bps) / 10_000.0) + l1_gas_usd;
            let net_pnl = gross_pnl - costs;
            let is_prof = net_bps >= ctx.cfg.min_net_edge_bps && net_pnl > 0.0;
            let src_ref = if is_prof { format!("DISP_{}_FILL_{}", asset, ctx.five_min_bucket) } else { format!("DISP_{}_BENCH_{}", asset, ctx.five_min_bucket) };
            let filled_label = if ctx.cfg.dry_run { "SHADOW_FILLED" } else { "LIVE_SIGNAL_QUEUED" };
            let skipped_label = if ctx.cfg.dry_run { "SHADOW_SKIPPED_UNPROFITABLE" } else { "LIVE_SKIPPED_UNPROFITABLE" };
            let status = if is_prof { filled_label } else { skipped_label };
            let pair = format!("{}/USDC", asset);
            let sig = sign_shadow_intent(ctx.identity, "VENUE_DISPERSION_RING", &pair, notional, &src_ref);
            let _ = record_pnl_entry(ctx.pool, ctx.session_id, &PnlEntryRecord {
                strategy: "VENUE_DISPERSION_RING".to_string(),
                execution_status: status.to_string(),
                dry_run: ctx.cfg.dry_run,
                pair,
                perennia_side: side.to_string(),
                cex_venue: vwap.venue,
                cex_order_type: "IOC_TAKER".to_string(),
                notional_usd: notional,
                base_amount: base_qty,
                perennia_exec_price_usd: median_usd,
                cex_vwap_price_usd: vwap.vwap_price_usd,
                gross_edge_bps: gross_bps,
                perennia_fee_bps: perennia_leg_bps,
                cex_fee_bps: vwap.venue_fee_bps,
                l1_gas_usd,
                slippage_bps: vwap.slippage_bps,
                net_edge_bps: net_bps,
                gross_pnl_usd: gross_pnl,
                total_costs_usd: costs,
                net_pnl_usd: net_pnl,
                schnorr_intent_sig: sig,
                source_ref: src_ref,
                metadata_json: json!({ "oracleDivergenceBps": div_bps }),
            }).await;
        }
    }

    let krc_gas_usd = KRC20_REVEAL_GAS_KAS * ctx.kas_usd;
    let krc_notional = (notional * 0.4).max(25.0);
    for krc in ["SILO", "NACHO"] {
        let v_raw: Option<String> = redis::cmd("GET").arg(format!("oracle:venues:{}", krc)).query_async(redis_conn).await.unwrap_or(None);
        let Some(v_str) = v_raw else { continue };
        let Ok(v_doc) = serde_json::from_str::<Value>(&v_str) else { continue };
        let median_usd = v_doc.get("medianUsd").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let Some(venues_map) = v_doc.get("venues").and_then(|v| v.as_object()) else { continue };
        if median_usd <= 0.0 || venues_map.is_empty() { continue; }

        let mut max_venue: Option<(String, f64)> = None;
        let mut min_venue: Option<(String, f64)> = None;
        for (v_name, v_info) in venues_map {
            if v_name == "coingecko" || v_name == "yahoo" || v_name == "kasfyi" { continue; }
            let sp = v_info.get("spotUsd").and_then(|x| x.as_f64()).unwrap_or(0.0);
            if sp > 0.0 {
                if max_venue.as_ref().map(|(_, m)| sp > *m).unwrap_or(true) { max_venue = Some((v_name.clone(), sp)); }
                if min_venue.as_ref().map(|(_, m)| sp < *m).unwrap_or(true) { min_venue = Some((v_name.clone(), sp)); }
            }
        }

        let best_krc_leg = match (max_venue, min_venue) {
            (Some((hi_v, hi_p)), Some((lo_v, lo_p))) => {
                evaluated += 1;
                let sell_ext_bps = ((hi_p - median_usd) / median_usd) * 10_000.0;
                let buy_ext_bps = ((median_usd - lo_p) / lo_p) * 10_000.0;
                if sell_ext_bps >= buy_ext_bps { Some(("BUY_PERENNIA_KRC20_SELL_VENUE", hi_v, hi_p, sell_ext_bps)) }
                else { Some(("SELL_PERENNIA_KRC20_BUY_VENUE", lo_v, lo_p, buy_ext_bps)) }
            }
            _ => None,
        };

        if let Some((side, v_name, v_px, gross_bps)) = best_krc_leg {
            let div_bps = v_doc.get("divergenceBps").and_then(|v| v.as_u64()).unwrap_or(0);
            if div_bps > MAX_GATEWAY_DIVERGENCE_BPS { continue; }
            let venue_fee_bps = 20.0;
            let est_slip_bps = 15.0;
            let l1_bps = (krc_gas_usd / krc_notional) * 10_000.0;
            let net_bps = gross_bps - ctx.taker_fee_bps - venue_fee_bps - est_slip_bps - l1_bps;
            let gross_pnl = krc_notional * (gross_bps / 10_000.0);
            let costs = krc_notional * ((ctx.taker_fee_bps + venue_fee_bps + est_slip_bps) / 10_000.0) + krc_gas_usd;
            let net_pnl = gross_pnl - costs;
            let is_prof = net_bps >= ctx.cfg.min_net_edge_bps && net_pnl > 0.0;
            let src_ref = if is_prof { format!("KRC20_{}_FILL_{}", krc, ctx.five_min_bucket) } else { format!("KRC20_{}_BENCH_{}", krc, ctx.five_min_bucket) };
            let filled_label = if ctx.cfg.dry_run { "SHADOW_FILLED" } else { "LIVE_SIGNAL_QUEUED" };
            let skipped_label = if ctx.cfg.dry_run { "SHADOW_SKIPPED_UNPROFITABLE" } else { "LIVE_SKIPPED_UNPROFITABLE" };
            let status = if is_prof { filled_label } else { skipped_label };
            let pair = format!("{}/KAS", krc);
            let sig = sign_shadow_intent(ctx.identity, "KRC20_SPREAD_ARB", &pair, krc_notional, &src_ref);
            let _ = record_pnl_entry(ctx.pool, ctx.session_id, &PnlEntryRecord {
                strategy: "KRC20_SPREAD_ARB".to_string(),
                execution_status: status.to_string(),
                dry_run: ctx.cfg.dry_run,
                pair,
                perennia_side: side.to_string(),
                cex_venue: v_name,
                cex_order_type: "LIMIT_IOC".to_string(),
                notional_usd: krc_notional,
                base_amount: krc_notional / median_usd,
                perennia_exec_price_usd: median_usd,
                cex_vwap_price_usd: v_px,
                gross_edge_bps: gross_bps,
                perennia_fee_bps: ctx.taker_fee_bps,
                cex_fee_bps: venue_fee_bps,
                l1_gas_usd: krc_gas_usd,
                slippage_bps: est_slip_bps,
                net_edge_bps: net_bps,
                gross_pnl_usd: gross_pnl,
                total_costs_usd: costs,
                net_pnl_usd: net_pnl,
                schnorr_intent_sig: sig,
                source_ref: src_ref,
                metadata_json: json!({ "krc20CarrierKas": 0.30, "venueCount": venues_map.len() }),
            }).await;
        }
    }

    Ok(evaluated)
}

/// Applies anonymized AI agent directional skew conservatively (`±max_shift_bps` cap, default <= 2500 bps)
/// so the Chronos 22:00 UTC pre-hedger can pre-stage Dark Pool counter-liquidity without front-running quotes.
pub fn apply_ai_intent_skew_sompi(
    base_kas_sompi: u128,
    net_kas_skew_sompi: i128,
    max_shift_bps: u16,
) -> (u128, i128) {
    if base_kas_sompi == 0 || net_kas_skew_sompi == 0 || max_shift_bps == 0 {
        return (base_kas_sompi, 0);
    }
    let capped_bps = (max_shift_bps as u128).min(2_500);
    let max_delta = base_kas_sompi.saturating_mul(capped_bps) / 10_000;
    let abs_skew = net_kas_skew_sompi.unsigned_abs();
    let bounded_delta = abs_skew.min(max_delta);
    if net_kas_skew_sompi > 0 {
        // Net AI KAS buy demand -> reduce pre-hedge sell sizing up to bound
        let adjusted = base_kas_sompi.saturating_sub(bounded_delta).max(1);
        (adjusted, -(bounded_delta as i128))
    } else {
        // Net AI KAS sell pressure -> expand pre-hedge absorption within bound
        let adjusted = base_kas_sompi.saturating_add(bounded_delta);
        (adjusted, bounded_delta as i128)
    }
}

/// 3. 21:55 -> 22:00 UTC Epoch Pre-Hedger (0 bps Post-Only Maker Pre-Sourcing)
pub async fn evaluate_2200_epoch_pre_hedger(
    ctx: &TickContext<'_>,
    redis_conn: &mut redis::aio::MultiplexedConnection,
    startup_readiness_drill: bool,
) -> Result<i64> {
    let (pb_raw, ai_skew_raw): (Option<String>, Option<String>) = redis::pipe()
        .cmd("GET").arg("oracle:prebell:2200_demand")
        .cmd("GET").arg("perennia:solver:ai_intent_skew")
        .query_async(redis_conn)
        .await
        .unwrap_or((None, None));
    let Some(pb_str) = pb_raw else { return Ok(0); };
    let Ok(pb) = serde_json::from_str::<Value>(&pb_str) else { return Ok(0); };

    let next_bell_ts = pb.get("nextEpochBellTs").and_then(|v| v.as_i64()).unwrap_or(0);
    let secs_until_bell = pb.get("secondsUntilBell").and_then(|v| v.as_i64()).unwrap_or(86_400);
    let in_window = pb.get("inPreHedgeWindow").and_then(|v| v.as_bool()).unwrap_or(false);
    let total_pending_kas = pb.get("totalPendingKas").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let total_uncovered_kas = pb.get("totalUncoveredKas").and_then(|v| v.as_f64()).unwrap_or(0.0);

    if !in_window && !startup_readiness_drill { return Ok(0); }
    let Some(kas_books) = ctx.books.get("KAS") else { return Ok(0); };

    let run_mode = if in_window {
        let minute_slot = ((300 - secs_until_bell.clamp(0, 300)) / 60) + 1;
        format!("LIVE_WINDOW_TRANCHE_{}", minute_slot.clamp(1, 5))
    } else {
        "STARTUP_READINESS_AUDIT".to_string()
    };

    let base_target_kas = if total_uncovered_kas > 1.0 { total_uncovered_kas / 5.0 }
        else if total_pending_kas > 1.0 { total_pending_kas / 5.0 }
        else { ctx.cfg.default_notional_usd / ctx.kas_usd };

    let ai_net_kas_delta_sompi = ai_skew_raw
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.get("netKasDeltaSompi").and_then(|x| x.as_str()).map(|s| s.to_string()))
        .and_then(|s| s.parse::<i128>().ok())
        .unwrap_or(0);
    let base_kas_sompi = ((base_target_kas * (SOMPI_PER_KAS as f64)).round() as u128).max(1);
    let (adjusted_kas_sompi, applied_skew_delta_sompi) =
        apply_ai_intent_skew_sompi(base_kas_sompi, ai_net_kas_delta_sompi, 2_000);
    let target_kas_for_sizing = (adjusted_kas_sompi as f64) / (SOMPI_PER_KAS as f64);

    let Some(kas_maker_sell) = best_post_only_maker_sell(kas_books, target_kas_for_sizing) else { return Ok(0); };

    let mut legs = Vec::new();
    if let Some(demands) = pb.get("demands").and_then(|v| v.as_array()) {
        for d in demands {
            let t_asset = d.get("targetAsset").and_then(|v| v.as_str()).unwrap_or("USDC");
            let p_kas = d.get("pendingKas").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let est_tok = d.get("estimatedTargetTokens").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let maker_buy_venue = if t_asset == "USDC" || t_asset == "USDT" || t_asset == "USD" {
                Some(("direct_quote_proceeds".to_string(), 1.0))
            } else {
                ctx.books.get(t_asset).and_then(|b| best_post_only_maker_buy(b, (est_tok / 5.0).max(0.0001))).map(|q| (q.venue, q.vwap_price_usd))
            };
            legs.push(json!({
                "targetAsset": t_asset,
                "pendingKas": p_kas,
                "estimatedTargetTokens": est_tok,
                "postOnlyMakerFeeBps": 0,
                "targetBuyVenue": maker_buy_venue.as_ref().map(|x| &x.0),
                "targetMakerBuyUsd": maker_buy_venue.as_ref().map(|x| x.1)
            }));
        }
    }

    let hedge_notional_usd = target_kas_for_sizing * kas_maker_sell.vwap_price_usd;
    let avoided_passthrough_bps = 50.0_f64;
    let l1_gas_usd = STANDARD_L1_GAS_KAS * ctx.kas_usd;
    let net_saved_bps = avoided_passthrough_bps - ctx.maker_fee_bps - ((l1_gas_usd / hedge_notional_usd.max(1.0)) * 10_000.0);
    let projected_saved_usd = (hedge_notional_usd * (net_saved_bps / 10_000.0)).max(0.0);

    let inserted = record_prehedge_run(
        ctx.pool, ctx.session_id, next_bell_ts, secs_until_bell, &run_mode, ctx.cfg.dry_run,
        total_pending_kas, total_uncovered_kas, &kas_maker_sell.venue, kas_maker_sell.vwap_price_usd,
        projected_saved_usd, &Value::Array(legs),
    ).await?;

    if inserted {
        let active_label = if ctx.cfg.dry_run { "SHADOW_FILLED" } else { "LIVE_PREBELL_ARMED" };
        let readiness_label = if ctx.cfg.dry_run { "SHADOW_PREBELL_READINESS" } else { "LIVE_PREBELL_READINESS" };
        let exec_status = if in_window && total_pending_kas > 0.0 && projected_saved_usd > 0.0 { active_label } else { readiness_label };
        let src_ref = format!("EPOCH_{}_{}", next_bell_ts, run_mode);
        let sig = sign_shadow_intent(ctx.identity, "CHRONOS_2200_PRE_HEDGER", "KAS/EPOCH_BASKET", hedge_notional_usd, &src_ref);
        let _ = record_pnl_entry(ctx.pool, ctx.session_id, &PnlEntryRecord {
            strategy: "CHRONOS_2200_PRE_HEDGER".to_string(),
            execution_status: exec_status.to_string(),
            dry_run: ctx.cfg.dry_run,
            pair: "KAS/EPOCH_BASKET".to_string(),
            perennia_side: format!("POST_ONLY_PRE_HEDGE_{}", run_mode),
            cex_venue: kas_maker_sell.venue,
            cex_order_type: "POST_ONLY_MAKER_0BPS".to_string(),
            notional_usd: hedge_notional_usd,
            base_amount: target_kas_for_sizing,
            perennia_exec_price_usd: ctx.kas_usd,
            cex_vwap_price_usd: kas_maker_sell.vwap_price_usd,
            gross_edge_bps: avoided_passthrough_bps,
            perennia_fee_bps: ctx.maker_fee_bps,
            cex_fee_bps: 0.0,
            l1_gas_usd,
            slippage_bps: 0.0,
            net_edge_bps: net_saved_bps,
            gross_pnl_usd: hedge_notional_usd * (avoided_passthrough_bps / 10_000.0),
            total_costs_usd: hedge_notional_usd * (ctx.maker_fee_bps / 10_000.0) + l1_gas_usd,
            net_pnl_usd: projected_saved_usd,
            schnorr_intent_sig: sig,
            source_ref: src_ref,
            metadata_json: json!({
                "nextEpochBellTs": next_bell_ts,
                "secondsUntilBell": secs_until_bell,
                "aiIntentSkewKasDeltaSompi": applied_skew_delta_sompi.to_string(),
                "clearingTarget": "100_PCT_INTERNAL_DARK_POOL_CROSSED"
            }),
        }).await;
    }

    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::apply_ai_intent_skew_sompi;

    #[test]
    fn ai_intent_skew_caps_prehedge_adjustment_and_preserves_direction() {
        let base = 1_000_000_000_000u128; // 10,000 KAS
        let (adj_buy, delta_buy) = apply_ai_intent_skew_sompi(base, 500_000_000_000, 2_000);
        assert_eq!(adj_buy, 800_000_000_000);
        assert_eq!(delta_buy, -200_000_000_000);

        let (adj_sell, delta_sell) = apply_ai_intent_skew_sompi(base, -50_000_000_000, 2_000);
        assert_eq!(adj_sell, 1_050_000_000_000);
        assert_eq!(delta_sell, 50_000_000_000);

        let (adj_zero, delta_zero) = apply_ai_intent_skew_sompi(base, 0, 2_000);
        assert_eq!(adj_zero, base);
        assert_eq!(delta_zero, 0);
    }
}