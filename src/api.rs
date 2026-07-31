// src/api.rs

use axum::{
    extract::State,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;
use crate::omnichain::router::SmartOrderRouter;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SwapRequest {
    pub wallet: String,
    pub pay_asset: String,
    pub receive_asset: String,
    pub amount: f64,
    pub slippage_tolerance: f64,
}

pub async fn sor_lock_handler(
    State(sor): State<Arc<SmartOrderRouter>>,
    Json(payload): Json<SwapRequest>,
) -> impl IntoResponse {
    let lock_result = sor.request_route_lock(
        &payload.wallet,
        &payload.pay_asset,
        &payload.receive_asset,
        payload.amount,
        payload.slippage_tolerance,
    ).await;

    match lock_result {
        Ok((lock_id, executed_rate)) => {
            match sor.provider.execute_rebalance(&payload.wallet, &payload.pay_asset, &payload.receive_asset, payload.amount).await {
                Ok(tx_hash) => {
                    axum::Json(serde_json::json!({
                        "transaction_uuid": tx_hash,
                        "executed_rate": executed_rate
                    })).into_response()
                }
                Err(e) => {
                    (
                        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                        axum::Json(serde_json::json!({ "error": e.to_string() }))
                    ).into_response()
                }
            }
        }
        Err(e) => {
            (
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                axum::Json(serde_json::json!({ "error": e.to_string() }))
            ).into_response()
        }
    }
}