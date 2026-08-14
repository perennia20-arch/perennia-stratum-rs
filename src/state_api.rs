use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;

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
    let redis_client = match redis::Client::open("redis://127.0.0.1/") {
        Ok(c) => c,
        Err(e) => return Err(Json(ActionResponse { success: false, error: Some(e.to_string()) })),
    };
    let mut redis_conn = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => return Err(Json(ActionResponse { success: false, error: Some(e.to_string()) })),
    };

    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => return Err(Json(ActionResponse { success: false, error: Some(e.to_string()) })),
    };

    let row = sqlx::query!(
        "SELECT layout_state FROM user_command_centers WHERE wallet_address = $1 FOR UPDATE",
        req.wallet
    )
    .fetch_optional(&mut *tx)
    .await;

    let mut state: Value = match row {
        Ok(Some(r)) => r.layout_state,
        _ => json!({"workers": [], "silos": [], "plants": [], "manualLps": [], "systemMode": "base"}),
    };

    match req.action.as_str() {
        "ADD_WORKER" => {
            if let Some(workers) = state.get_mut("workers").and_then(|w| w.as_array_mut()) {
                workers.push(req.payload.clone());
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
        "ASSIGN_WORKER_TO_SILO" => {
            if let Some(worker_id) = req.payload.get("workerId").and_then(|i| i.as_str()) {
                let silo_id = req.payload.get("siloId").unwrap_or(&Value::Null).clone();
                if let Some(workers) = state.get_mut("workers").and_then(|w| w.as_array_mut()) {
                    for w in workers.iter_mut() {
                        if w.get("id").and_then(|i| i.as_str()).unwrap_or("") == worker_id {
                            w["assignedSiloId"] = silo_id.clone();
                        }
                    }
                }
            }
        },
        "ADD_SILO" => {
            if let Some(silos) = state.get_mut("silos").and_then(|s| s.as_array_mut()) {
                silos.push(req.payload.clone());
            } else {
                state["silos"] = json!([req.payload.clone()]);
            }
        },
        "DELETE_SILO" => {
            if let Some(id) = req.payload.get("id").and_then(|i| i.as_str()) {
                if let Some(workers) = state.get_mut("workers").and_then(|w| w.as_array_mut()) {
                    for w in workers.iter_mut() {
                        if w.get("assignedSiloId").and_then(|i| i.as_str()).unwrap_or("") == id {
                            w["assignedSiloId"] = Value::Null;
                        }
                    }
                }
                if let Some(silos) = state.get_mut("silos").and_then(|s| s.as_array_mut()) {
                    silos.retain(|s| s.get("id").and_then(|i| i.as_str()).unwrap_or("") != id);
                }
            }
        },
        "RENAME_SILO" => {
            if let (Some(id), Some(name)) = (req.payload.get("id").and_then(|i| i.as_str()), req.payload.get("name").and_then(|n| n.as_str())) {
                if let Some(silos) = state.get_mut("silos").and_then(|s| s.as_array_mut()) {
                    for s in silos.iter_mut() {
                        if s.get("id").and_then(|i| i.as_str()).unwrap_or("") == id {
                            s["name"] = json!(name);
                        }
                    }
                }
            }
        },
        "RESIZE_SILO" => {
            if let (Some(id), Some(width)) = (req.payload.get("id").and_then(|i| i.as_str()), req.payload.get("width").and_then(|n| n.as_i64())) {
                if let Some(silos) = state.get_mut("silos").and_then(|s| s.as_array_mut()) {
                    for s in silos.iter_mut() {
                        if s.get("id").and_then(|i| i.as_str()).unwrap_or("") == id {
                            s["width"] = json!(width);
                        }
                    }
                }
            }
        },
        "UPDATE_SETTLEMENT" => {
            if let Some(id) = req.payload.get("id").and_then(|i| i.as_str()) {
                if let Some(config) = req.payload.get("config") {
                    if let Some(silos) = state.get_mut("silos").and_then(|s| s.as_array_mut()) {
                        for s in silos.iter_mut() {
                            if s.get("id").and_then(|i| i.as_str()).unwrap_or("") == id {
                                s["settlementConfig"] = config.clone();
                            }
                        }
                    }
                }
            }
        },
        "ADD_PLANT" => {
            if let Some(plants) = state.get_mut("plants").and_then(|p| p.as_array_mut()) {
                plants.push(req.payload.clone());
            } else {
                state["plants"] = json!([req.payload.clone()]);
            }
        },
        "DELETE_PLANT" => {
            if let Some(id) = req.payload.get("id").and_then(|i| i.as_str()) {
                if let Some(silos) = state.get_mut("silos").and_then(|s| s.as_array_mut()) {
                    for s in silos.iter_mut() {
                        if s.get("assignedPlantId").and_then(|i| i.as_str()).unwrap_or("") == id {
                            s["assignedPlantId"] = Value::Null;
                        }
                    }
                }
                if let Some(plants) = state.get_mut("plants").and_then(|p| p.as_array_mut()) {
                    plants.retain(|p| p.get("id").and_then(|i| i.as_str()).unwrap_or("") != id);
                }
            }
        },
        "UPDATE_PLANT_PARAMS" => {
            if let Some(id) = req.payload.get("id").and_then(|i| i.as_str()) {
                if let Some(plants) = state.get_mut("plants").and_then(|p| p.as_array_mut()) {
                    for p in plants.iter_mut() {
                        if p.get("id").and_then(|i| i.as_str()).unwrap_or("") == id {
                            if let Some(ac) = req.payload.get("autoCompound") { p["autoCompound"] = ac.clone(); }
                            if let Some(ld) = req.payload.get("liquidityDeposit") { p["liquidityDeposit"] = ld.clone(); }
                            if let Some(apr) = req.payload.get("currentApr") { p["currentApr"] = apr.clone(); }
                        }
                    }
                }
            }
        },
        "ASSIGN_SILO_TO_PLANT" => {
            if let Some(silo_id) = req.payload.get("siloId").and_then(|i| i.as_str()) {
                let plant_id = req.payload.get("plantId").unwrap_or(&Value::Null).clone();
                
                if !plant_id.is_null() {
                    let mut current_silo_count = 0;
                    if let Some(silos) = state.get("silos").and_then(|s| s.as_array()) {
                        for s in silos {
                            if s.get("assignedPlantId").unwrap_or(&Value::Null) == &plant_id {
                                current_silo_count += 1;
                            }
                        }
                    }
                    if current_silo_count >= 2 {
                        let _ = tx.rollback().await;
                        return Err(Json(ActionResponse { success: false, error: Some("Synthesis Failed: A Plant can only hold exactly 2 Silos.".to_string()) }));
                    }
                }

                if let Some(silos) = state.get_mut("silos").and_then(|s| s.as_array_mut()) {
                    for s in silos.iter_mut() {
                        if s.get("id").and_then(|i| i.as_str()).unwrap_or("") == silo_id {
                            s["assignedPlantId"] = plant_id.clone();
                        }
                    }
                }
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

    let save_res = sqlx::query!(
        "INSERT INTO user_command_centers (wallet_address, layout_state, last_updated) 
         VALUES ($1, $2, CURRENT_TIMESTAMP) 
         ON CONFLICT (wallet_address) DO UPDATE SET layout_state = EXCLUDED.layout_state, last_updated = CURRENT_TIMESTAMP",
        req.wallet,
        state
    )
    .execute(&mut *tx)
    .await;

    if let Err(e) = save_res {
        let _ = tx.rollback().await;
        return Err(Json(ActionResponse { success: false, error: Some(e.to_string()) }));
    }

    let _ = tx.commit().await;

    let update_payload = json!({
        "layout_state_update": true,
        "wallet": req.wallet,
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