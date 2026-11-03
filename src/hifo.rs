use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HifoDisposalSummary {
    pub disposed_tokens: f64,
    pub gross_proceeds_usd: f64,
    pub matched_cost_basis_usd: f64,
    pub realized_gain_loss_usd: f64,
    pub holding_period: String,
    pub lots_consumed: usize,
}

pub async fn record_hifo_acquisition_lot(
    pool: &PgPool,
    wallet_address: &str,
    asset_ticker: &str,
    amount_tokens: f64,
    fmv_usd_per_token: f64,
    source_event_type: &str,
    source_tx_hash: Option<&str>,
) -> anyhow::Result<Uuid> {
    let clean_ticker = asset_ticker.trim().to_uppercase();
    let sompi = (amount_tokens.max(0.0) * 100_000_000.0).round() as i64;
    let total_basis = (amount_tokens * fmv_usd_per_token).max(0.0);

    let row = sqlx::query(
        r#"
        INSERT INTO hifo_tax_lots (
            wallet_address, asset_ticker, kas_sompi, initial_tokens,
            remaining_sompi, remaining_tokens, fmv_usd_per_token,
            total_cost_basis_usd, source_event_type, source_tx_hash, status
        ) VALUES ($1, $2, $3, $4, $3, $4, $5, $6, $7, $8, 'OPEN')
        RETURNING lot_id
        "#,
    )
    .bind(wallet_address)
    .bind(&clean_ticker)
    .bind(sompi)
    .bind(amount_tokens)
    .bind(fmv_usd_per_token)
    .bind(total_basis)
    .bind(source_event_type)
    .bind(source_tx_hash)
    .fetch_one(pool)
    .await?;

    let lot_id: Uuid = row.try_get("lot_id")?;
    Ok(lot_id)
}

pub async fn match_and_consume_hifo_lots(
    pool: &PgPool,
    wallet_address: &str,
    asset_ticker: &str,
    dispose_tokens: f64,
    execution_spot_usd: f64,
    disposal_tx_hash: Option<&str>,
) -> anyhow::Result<HifoDisposalSummary> {
    let clean_ticker = asset_ticker.trim().to_uppercase();
    let mut remaining_to_dispose = dispose_tokens.max(0.0);
    let gross_proceeds_total = remaining_to_dispose * execution_spot_usd;

    let open_lots = sqlx::query(
        r#"
        SELECT lot_id, acquired_at, remaining_tokens, fmv_usd_per_token
        FROM hifo_tax_lots
        WHERE wallet_address = $1
          AND asset_ticker = $2
          AND status = 'OPEN'
          AND remaining_tokens > 0
        ORDER BY fmv_usd_per_token DESC, acquired_at ASC
        "#,
    )
    .bind(wallet_address)
    .bind(&clean_ticker)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut matched_cost_basis_usd = 0.0_f64;
    let mut lots_consumed = 0usize;
    let mut any_long_term = false;
    let now = Utc::now();

    for lot in open_lots {
        if remaining_to_dispose <= 1e-9 {
            break;
        }
        let lot_id: Uuid = match lot.try_get("lot_id") {
            Ok(id) => id,
            Err(_) => continue,
        };
        let acquired_at: chrono::DateTime<Utc> = lot.try_get("acquired_at").unwrap_or(now);
        let lot_rem: f64 = lot.try_get("remaining_tokens").unwrap_or(0.0);
        let fmv_per_tok: f64 = lot.try_get("fmv_usd_per_token").unwrap_or(execution_spot_usd);

        let consumed = remaining_to_dispose.min(lot_rem);
        if consumed <= 0.0 {
            continue;
        }

        let new_rem = (lot_rem - consumed).max(0.0);
        let new_sompi = (new_rem * 100_000_000.0).round() as i64;
        let new_status = if new_rem <= 1e-8 { "CLOSED" } else { "OPEN" };

        let _ = sqlx::query(
            r#"
            UPDATE hifo_tax_lots
            SET remaining_tokens = $2,
                remaining_sompi = $3,
                status = $4
            WHERE lot_id = $1
            "#,
        )
        .bind(lot_id)
        .bind(new_rem)
        .bind(new_sompi)
        .bind(new_status)
        .execute(pool)
        .await;

        let leg_cost_basis = consumed * fmv_per_tok;
        let leg_proceeds = consumed * execution_spot_usd;
        let leg_gain = leg_proceeds - leg_cost_basis;
        let holding_days = (now - acquired_at).num_days().max(0) as i32;
        let is_long_term = holding_days > 365;
        if is_long_term {
            any_long_term = true;
        }

        let disposed_sompi = (consumed * 100_000_000.0).round() as i64;
        let _ = sqlx::query(
            r#"
            INSERT INTO hifo_disposal_matches (
                lot_id, wallet_address, asset_ticker, disposed_sompi,
                disposed_tokens, acquired_at, holding_period_days,
                is_long_term, cost_basis_usd, gross_proceeds_usd,
                realized_gain_loss_usd, disposal_tx_hash
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
        )
        .bind(lot_id)
        .bind(wallet_address)
        .bind(&clean_ticker)
        .bind(disposed_sompi)
        .bind(consumed)
        .bind(acquired_at)
        .bind(holding_days)
        .bind(is_long_term)
        .bind(leg_cost_basis)
        .bind(leg_proceeds)
        .bind(leg_gain)
        .bind(disposal_tx_hash)
        .execute(pool)
        .await;

        matched_cost_basis_usd += leg_cost_basis;
        remaining_to_dispose -= consumed;
        lots_consumed += 1;
    }

    if remaining_to_dispose > 1e-8 {
        matched_cost_basis_usd += remaining_to_dispose * execution_spot_usd;
    }

    let realized_gain_loss_usd = gross_proceeds_total - matched_cost_basis_usd;
    let holding_period = if any_long_term {
        "LONG_TERM".to_string()
    } else {
        "SHORT_TERM".to_string()
    };

    Ok(HifoDisposalSummary {
        disposed_tokens: dispose_tokens,
        gross_proceeds_usd: gross_proceeds_total,
        matched_cost_basis_usd,
        realized_gain_loss_usd,
        holding_period,
        lots_consumed,
    })
}