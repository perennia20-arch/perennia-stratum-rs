// src/state_api.rs
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::env;

#[derive(Deserialize, Debug)]
pub struct StateActionReq {
    pub wallet: String,
    pub action: String,
    pub payload: Value,
}

#[derive(Serialize)]
pub struct ActionResponse {
    pub success: bool,
    pub error: Option<String>,
}

pub async fn handle_state_action(
    State(pool): State<PgPool>,
    Json(req): Json<StateActionReq>,
) -> Result<Json<ActionResponse>, Json<ActionResponse>> {
    
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = match redis::Client::open(redis_url) {
        Ok(c) => c,
        Err(e) => return Err(Json(ActionResponse { success: false, error: Some(e.to_string()) })),
    };
    let mut redis_conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => return Err(Json(ActionResponse { success: false, error: Some(e.to_string()) })),
    };

    // Strictly enforce the kaspa: prefix for all database indexing
    let clean_wallet = req.wallet.to_lowercase().replace("kaspa:", "").trim().to_string();
    let master_identity = format!("kaspa:{}", clean_wallet);

    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => return Err(Json(ActionResponse { success: false, error: Some(e.to_string()) })),
    };

    // ⚡ THE FIX: Use fetch_all to prevent the SQL driver from crashing if a ghost row exists
    let rows = sqlx::query!(
        "SELECT layout_state FROM user_command_centers WHERE wallet_address = $1 OR wallet_address = $2",
        master_identity,
        clean_wallet
    )
    .fetch_all(&mut *tx)
    .await;

    let mut state: Value = json!({"workers": [], "sectors": [], "manualLps": [], "systemMode": "base"});
    
    if let Ok(results) = rows {
        for r in results {
            state = r.layout_state;
            // If we find a profile that actually has configured sectors, we prioritize it
            if state.get("sectors").and_then(|s| s.as_array()).map(|a| a.len()).unwrap_or(0) > 0 {
                break;
            }
        }
    }

    match req.action.as_str() {
        "ADD_WORKER" => {
            if let Some(workers) = state.get_mut("workers").and_then(|w| w.as_array_mut()) {
                let new_id = req.payload.get("id").and_then(|i| i.as_str()).unwrap_or("");
                let exists = workers.iter().any(|w| w.get("id").and_then(|i| i.as_str()).unwrap_or("") == new_id);
                if !exists {
                    workers.push(req.payload.clone());
                }
            } else {
                state["workers"] = json!([req.payload.clone()]);
            }
        },
        "DELETE_WORKER" => {
            if let Some(id) = req.payload.get("id").and_then(|i| i.as_str()) {
                if let Some(workers) = state.get_mut("workers").and_then(|w| w.as_array_mut()) {
                    workers.retain(|w| w.get("id").and_then(|i| i.as_str()).unwrap_or("") != id);
                }
            }
        },
        "RENAME_WORKER" => {
            if let (Some(id), Some(name), Some(wallet_worker)) = (
                req.payload.get("id").and_then(|i| i.as_str()),
                req.payload.get("name").and_then(|n| n.as_str()),
                req.payload.get("walletWorker").and_then(|w| w.as_str())
            ) {
                if let Some(workers) = state.get_mut("workers").and_then(|w| w.as_array_mut()) {
                    for w in workers.iter_mut() {
                        if w.get("id").and_then(|i| i.as_str()).unwrap_or("") == id {
                            w["name"] = json!(name);
                            w["walletWorker"] = json!(wallet_worker);
                        }
                    }
                }
            }
        },
        "ADD_SECTOR" => {
            let new_pct = req.payload.get("allocationPercentage").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let mut total_pct = new_pct;

            if let Some(sectors) = state.get("sectors").and_then(|s| s.as_array()) {
                for sec in sectors {
                    total_pct += sec.get("allocationPercentage").and_then(|v| v.as_f64()).unwrap_or(0.0);
                }
            }

            if total_pct > 100.001 {
                let _ = tx.rollback().await;
                return Err(Json(ActionResponse { success: false, error: Some("Total sector allocation cannot exceed 100%".to_string()) }));
            }

            if let Some(sectors) = state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                sectors.push(req.payload.clone());
            } else {
                state["sectors"] = json!([req.payload.clone()]);
            }
        },
        "DELETE_SECTOR" => {
            if let Some(id) = req.payload.get("id").and_then(|i| i.as_str()) {
                if let Some(sectors) = state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                    sectors.retain(|s| s.get("id").and_then(|i| i.as_str()).unwrap_or("") != id);
                }
            }
        },
        "RENAME_SECTOR" => {
            if let (Some(id), Some(name)) = (
                req.payload.get("id").and_then(|i| i.as_str()),
                req.payload.get("name").and_then(|n| n.as_str())
            ) {
                if let Some(sectors) = state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                    for sec in sectors.iter_mut() {
                        if sec.get("id").and_then(|i| i.as_str()).unwrap_or("") == id {
                            sec["name"] = json!(name);
                        }
                    }
                }
            }
        },
        "UPDATE_SECTOR_ALLOCATION" => {
            if let (Some(id), Some(new_pct)) = (
                req.payload.get("id").and_then(|i| i.as_str()),
                req.payload.get("allocationPercentage").and_then(|p| p.as_f64())
            ) {
                let mut total_pct = new_pct;
                if let Some(sectors) = state.get("sectors").and_then(|s| s.as_array()) {
                    for sec in sectors {
                        if sec.get("id").and_then(|i| i.as_str()).unwrap_or("") != id {
                            total_pct += sec.get("allocationPercentage").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        }
                    }
                }

                if total_pct > 100.001 {
                    let _ = tx.rollback().await;
                    return Err(Json(ActionResponse { success: false, error: Some("Total sector allocation cannot exceed 100%".to_string()) }));
                }

                if let Some(sectors) = state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                    for sec in sectors.iter_mut() {
                        if sec.get("id").and_then(|i| i.as_str()).unwrap_or("") == id {
                            sec["allocationPercentage"] = json!(new_pct);
                        }
                    }
                }
            }
        },
        "UPDATE_SETTLEMENT" => {
            if let (Some(id), Some(config)) = (
                req.payload.get("id").and_then(|i| i.as_str()),
                req.payload.get("config")
            ) {
                if let Some(sectors) = state.get_mut("sectors").and_then(|s| s.as_array_mut()) {
                    for sec in sectors.iter_mut() {
                        if sec.get("id").and_then(|i| i.as_str()).unwrap_or("") == id {
                            sec["settlementConfig"] = config.clone();
                        }
                    }
                }
            }
        },
        "REORDER_SECTORS" => {
            if let Some(new_array) = req.payload.as_array() {
                state["sectors"] = json!(new_array);
            }
        },
        "ADD_MANUAL_LP" => {
            if let Some(pos) = req.payload.get("position") {
                if let Some(lps) = state.get_mut("manualLps").and_then(|l| l.as_array_mut()) {
                    lps.push(pos.clone());
                } else {
                    state["manualLps"] = json!([pos.clone()]);
                }
            }
        },
        "SYSTEM_MODE" => {
            if let Some(mode) = req.payload.get("mode").and_then(|m| m.as_str()) {
                state["systemMode"] = json!(mode);
            }
        },
        "UPDATE_TAX_FORTRESS" => {
            if let Some(active) = req.payload.get("escrowActive").and_then(|a| a.as_bool()) {
                if let Some(tf) = state.get_mut("taxFortress").and_then(|t| t.as_object_mut()) {
                    tf.insert("escrowActive".to_string(), json!(active));
                } else {
                    state["taxFortress"] = json!({ "escrowActive": active });
                }
            }
        }
        _ => {}
    }

    // Always save to the master_identity (kaspa: prefix) to unify the profiles
    let save_res = sqlx::query!(
        "INSERT INTO user_command_centers (wallet_address, layout_state, last_updated) 
         VALUES ($1, $2, CURRENT_TIMESTAMP) 
         ON CONFLICT (wallet_address) DO UPDATE SET layout_state = EXCLUDED.layout_state, last_updated = CURRENT_TIMESTAMP",
        master_identity,
        state
    )
    .execute(&mut *tx)
    .await;

    if let Err(e) = save_res {
        let _ = tx.rollback().await;
        return Err(Json(ActionResponse { success: false, error: Some(e.to_string()) }));
    }

    // Erase the ghost row from the database so it never crashes the parser again
    let _ = sqlx::query!("DELETE FROM user_command_centers WHERE wallet_address = $1", clean_wallet).execute(&mut *tx).await;

    let _ = tx.commit().await;

    let update_payload = json!({
        "layout_state_update": true,
        "wallet": master_identity,
        "state": state
    });

    let _: () = redis::cmd("PUBLISH")
        .arg("telemetry:updates")
        .arg(update_payload.to_string())
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(());

    Ok(Json(ActionResponse { success: true, error: None }))
}