// src/agent/mcp.rs

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::agent::{
    handlers,
    types::{AgentError, AgentErrorCode},
    AgentGatewayState,
};

pub const JSON_SCHEMA_DRAFT_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";
pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

const TOOL_MARKETS: &str = "perennia_get_markets";
const TOOL_QUOTE: &str = "perennia_quote_swap";
const TOOL_EXECUTE: &str = "perennia_execute_swap";
const TOOL_ME_CONTROL: &str = "perennia_me_telemetry_and_buckets";

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcErrorObj {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[inline]
fn is_valid_mcp_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Recursively strips control characters and untrusted markup from all string leaves
/// returned through `/api/v1/agent/mcp` to guarantee sterile machine-safe outputs.
pub fn sterilize_mcp_value(val: Value) -> Value {
    match val {
        Value::String(s) => {
            let mut out = String::with_capacity(s.len());
            for ch in s.chars() {
                if (ch.is_ascii_graphic() || ch == ' ') && ch != '<' && ch != '>' && ch != '`' {
                    out.push(ch);
                }
            }
            Value::String(out)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(sterilize_mcp_value).collect()),
        Value::Object(map) => {
            let mut clean_map = Map::with_capacity(map.len());
            for (k, v) in map {
                let clean_k: String = k
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '/' || *c == '$')
                    .take(96)
                    .collect();
                if !clean_k.is_empty() {
                    clean_map.insert(clean_k, sterilize_mcp_value(v));
                }
            }
            Value::Object(clean_map)
        }
        other => other,
    }
}

fn u128_string_schema(description: &str) -> Value {
    json!({
        "type": "string",
        "pattern": "^[0-9]{1,39}$",
        "description": description
    })
}

fn sterile_ticker_schema(description: &str) -> Value {
    json!({
        "type": "string",
        "pattern": "^[A-Z0-9]{2,10}$",
        "description": description
    })
}

pub fn build_mcp_tools_manifest() -> Vec<Value> {
    let tools = vec![
        json!({
            "name": TOOL_MARKETS,
            "description": "Read Perennia cached multi-chain, KAS, KRC-20, and KCC-20 market pulse, Dark Pool midpoints, resting RFQ counts, asymmetric Maker/Taker bps, and stablecoin $1.00 depeg circuit-breaker flags.",
            "annotations": {
                "title": "Perennia Market Pulse & Pair Discovery",
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false
            },
            "inputSchema": {
                "$schema": JSON_SCHEMA_DRAFT_2020_12,
                "type": "object",
                "additionalProperties": false,
                "properties": {}
            },
            "outputSchema": {
                "$schema": JSON_SCHEMA_DRAFT_2020_12,
                "type": "object",
                "required": ["ok", "snapshotTimestampMs", "nodeConsensus", "circuitBreakers", "assets", "markets"],
                "properties": {
                    "ok": { "type": "boolean" },
                    "snapshotTimestampMs": u128_string_schema("Unix timestamp in milliseconds."),
                    "nodeConsensus": {
                        "type": "object",
                        "required": ["kaspadOnline", "virtualDaaScore", "blockSubsidySompi", "postToccataMinSompiPerGram", "relaySafeSompiPerGram"],
                        "properties": {
                            "kaspadOnline": { "type": "boolean" },
                            "virtualDaaScore": u128_string_schema("Current kaspad virtual DAA score."),
                            "blockSubsidySompi": u128_string_schema("Current block subsidy in sompi."),
                            "postToccataMinSompiPerGram": u128_string_schema("Post-Toccata Transaction v1 consensus minimum sompi/gram (100)."),
                            "relaySafeSompiPerGram": u128_string_schema("Perennia relay-safe sompi/gram (110).")
                        }
                    },
                    "circuitBreakers": {
                        "type": "object",
                        "required": ["kasOracleOnline", "darkPoolPaused", "externalDexPaused", "usdcParityUsdE8", "usdcDepegHalted", "usdtParityUsdE8", "usdtDepegHalted", "minSwapNotionalUsdMicros"],
                        "properties": {
                            "kasOracleOnline": { "type": "boolean" },
                            "darkPoolPaused": { "type": "boolean" },
                            "externalDexPaused": { "type": "boolean" },
                            "usdcParityUsdE8": u128_string_schema("Live USDC/USD parity scaled by 10^8."),
                            "usdcDepegHalted": { "type": "boolean" },
                            "usdtParityUsdE8": u128_string_schema("Live USDT/USD parity scaled by 10^8."),
                            "usdtDepegHalted": { "type": "boolean" },
                            "minSwapNotionalUsdMicros": u128_string_schema("Minimum swap notional in micro-USD (1000000 = $1.00).")
                        }
                    },
                    "assets": { "type": "array", "items": { "type": "object" } },
                    "markets": { "type": "array", "items": { "type": "object" } }
                }
            }
        }),
        json!({
            "name": TOOL_QUOTE,
            "description": "Request a zero-loss u128 swap quote or resting Dark Pool Maker RFQ, lock non-overlapping Kaspa UTXO outpoints in Redis (5s Taker max TTL; 5-15s Maker RFQ), and receive an unsigned Kaspa Transaction v1 or 0x83 payload plus Blake3 preimageHash.",
            "annotations": {
                "title": "Perennia Deterministic Quote & Unsigned Ticket",
                "readOnlyHint": false,
                "destructiveHint": false,
                "idempotentHint": false,
                "openWorldHint": false
            },
            "inputSchema": {
                "$schema": JSON_SCHEMA_DRAFT_2020_12,
                "type": "object",
                "additionalProperties": false,
                "required": ["payAsset", "receiveAsset", "amountIn", "maxSlippageBps"],
                "properties": {
                    "payAsset": sterile_ticker_schema("Input asset ticker matching ^[A-Z0-9]{2,10}$."),
                    "receiveAsset": sterile_ticker_schema("Output asset ticker matching ^[A-Z0-9]{2,10}$."),
                    "amountIn": u128_string_schema("Exact integer atomic input units as a base-10 u128 string."),
                    "maxSlippageBps": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 2500,
                        "description": "Maximum slippage tolerance in integer basis points."
                    },
                    "venue": {
                        "type": "string",
                        "enum": ["spot", "dark_pool", "dark_pool_rfq_maker"],
                        "default": "spot"
                    },
                    "rfqTtlSeconds": {
                        "type": "integer",
                        "minimum": 5,
                        "maximum": 15,
                        "description": "Resting TTL in seconds for dark_pool_rfq_maker quotes (5..=15)."
                    },
                    "utxoOutpoints": {
                        "type": "array",
                        "maxItems": 32,
                        "items": {
                            "type": "string",
                            "pattern": "^[0-9a-fA-F]{64}:[0-9]{1,5}$"
                        },
                        "description": "Optional explicit confirmed Kaspa UTXO outpoints (txid:vout) for parallel lane execution."
                    },
                    "executionSource": {
                        "type": "string",
                        "enum": ["l1_utxo", "sovereign_sleeve"]
                    },
                    "txVersion": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 2,
                        "default": 1
                    },
                    "computeBudget": {
                        "type": "integer",
                        "minimum": 200
                    },
                    "storageMass": {
                        "type": "integer",
                        "minimum": 0
                    },
                    "covenantId": {
                        "type": "string",
                        "pattern": "^[0-9a-fA-F]{64}$"
                    },
                    "proofPayload": {
                        "type": "string",
                        "pattern": "^([0-9a-fA-F]{2}){0,8192}$"
                    },
                    "dryRun": {
                        "type": "boolean",
                        "default": false,
                        "description": "When true, runs real Redis oracle, post-Toccata mass, Mandate, and HIFO simulation without locking UTXOs."
                    }
                }
            },
            "outputSchema": {
                "$schema": JSON_SCHEMA_DRAFT_2020_12,
                "type": "object",
                "required": ["ok", "dryRun", "quoteId", "venue", "payAsset", "receiveAsset", "amountIn", "expectedAmountOut", "minAmountOut", "fees", "unsignedPayload", "payload0x83Hex", "preimageHash"],
                "properties": {
                    "ok": { "type": "boolean" },
                    "dryRun": { "type": "boolean" },
                    "quoteId": { "type": "string" },
                    "venue": { "type": "string", "enum": ["spot", "dark_pool", "dark_pool_rfq_maker"] },
                    "payAsset": sterile_ticker_schema("Quoted input ticker."),
                    "receiveAsset": sterile_ticker_schema("Quoted output ticker."),
                    "amountIn": u128_string_schema("Quoted atomic input."),
                    "expectedAmountOut": u128_string_schema("Expected net atomic output after all ceil-rounded fees."),
                    "minAmountOut": u128_string_schema("Signed minimum guaranteed net atomic output floor."),
                    "fees": { "type": "object" },
                    "postToccataEnvelope": { "type": "object" },
                    "unsignedPayload": { "type": "object" },
                    "sighashHexPerInput": { "type": "array", "items": { "type": "string" } },
                    "payload0x83Hex": { "type": "string" },
                    "preimageHash": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
                }
            }
        }),
        json!({
            "name": TOOL_EXECUTE,
            "description": "Broadcast a locally signed Kaspa Transaction v1 or 0x83 Sovereign Intent idempotently. Atomically consumes quote + UTXO locks + 24h Mandate spend cap, verifies byte-for-byte preimageHash and 64-byte Schnorr signatures, clears L1/Dark Pool, and returns a Blake3 executionCommitmentHash.",
            "annotations": {
                "title": "Perennia Idempotent Signed Broadcast & Receipt",
                "readOnlyHint": false,
                "destructiveHint": true,
                "idempotentHint": true,
                "openWorldHint": true
            },
            "inputSchema": {
                "$schema": JSON_SCHEMA_DRAFT_2020_12,
                "type": "object",
                "additionalProperties": false,
                "required": ["quoteId", "idempotencyKey", "signedPayload"],
                "properties": {
                    "quoteId": {
                        "type": "string",
                        "pattern": "^[A-Za-z0-9_]{4,64}$"
                    },
                    "idempotencyKey": {
                        "type": "string",
                        "pattern": "^[A-Za-z0-9_-]{8,128}$"
                    },
                    "signedPayload": {
                        "type": "object",
                        "description": "Locally signed transaction or 0x83 intent matching the exact quoted unsignedPayload skeleton."
                    },
                    "dryRun": {
                        "type": "boolean",
                        "default": false,
                        "description": "When true, verifies preimageHash, Schnorr signatures, and HIFO output without broadcasting or mutating state."
                    }
                }
            },
            "outputSchema": {
                "$schema": JSON_SCHEMA_DRAFT_2020_12,
                "type": "object",
                "required": ["ok", "quoteId", "idempotencyKey", "executionCommitmentHash"],
                "properties": {
                    "ok": { "type": "boolean" },
                    "dryRun": { "type": "boolean" },
                    "receiptId": { "type": "string" },
                    "quoteId": { "type": "string" },
                    "idempotencyKey": { "type": "string" },
                    "settledAmountOut": u128_string_schema("Final settled atomic output (>= minAmountOut)."),
                    "l1InboundTxid": { "type": "string" },
                    "executionCommitmentHash": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                    "hifoTax": { "type": "object" }
                }
            }
        }),
        json!({
            "name": TOOL_ME_CONTROL,
            "description": "Mode B Personal Mandate Only: Read Sovereign execution-sleeve balances, UTXO parallel lane health, Stratum worker shares, and live kaspad difficulty/block subsidy, or update 22:00 UTC Director mining bucket integer basis points summing strictly to 10000 across human-whitelisted tickers. Cold-vault addresses are hard-blocked.",
            "annotations": {
                "title": "Perennia Mode B Telemetry & Chronos Bucket Control",
                "readOnlyHint": false,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false
            },
            "inputSchema": {
                "$schema": JSON_SCHEMA_DRAFT_2020_12,
                "type": "object",
                "additionalProperties": false,
                "required": ["operation"],
                "properties": {
                    "operation": {
                        "type": "string",
                        "enum": ["get_telemetry", "get_buckets", "update_buckets"]
                    },
                    "allocations": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 12,
                        "items": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["ticker", "splitBps"],
                            "properties": {
                                "ticker": sterile_ticker_schema("Human-whitelisted target ticker."),
                                "splitBps": {
                                    "type": "integer",
                                    "minimum": 1,
                                    "maximum": 10000
                                },
                                "routeMode": {
                                    "type": "string",
                                    "enum": ["hold", "swap", "auto-lp"]
                                }
                            }
                        }
                    },
                    "dryRun": {
                        "type": "boolean",
                        "default": false
                    }
                }
            },
            "outputSchema": {
                "$schema": JSON_SCHEMA_DRAFT_2020_12,
                "type": "object",
                "required": ["ok", "walletAddress"],
                "properties": {
                    "ok": { "type": "boolean" },
                    "walletAddress": { "type": "string" },
                    "executionSleeve": { "type": "object" },
                    "utxoLaneHealth": { "type": "object" },
                    "stratumFleet": { "type": "object" },
                    "kaspaNetworkEconomics": { "type": "object" },
                    "buckets": { "type": "array", "items": { "type": "object" } }
                }
            }
        }),
    ];

    for t in &tools {
        let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
        debug_assert!(is_valid_mcp_tool_name(name));
    }

    tools
}

fn jsonrpc_success(id: Value, result: Value) -> Json<Value> {
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    }))
}

fn jsonrpc_error(id: Value, code: i32, message: impl Into<String>, data: Option<Value>) -> Json<Value> {
    let err = JsonRpcErrorObj {
        code,
        message: message.into(),
        data,
    };
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": err
    }))
}

fn format_mcp_tool_result(payload: Value, is_error: bool) -> Value {
    let sterile_payload = sterilize_mcp_value(payload);
    let serialized_text =
        serde_json::to_string(&sterile_payload).unwrap_or_else(|_| "{}".to_string());
    json!({
        "isError": is_error,
        "structuredContent": sterile_payload,
        "content": [
            {
                "type": "text",
                "text": serialized_text
            }
        ]
    })
}

/// HTTP `GET /api/v1/agent/mcp` — Returns the sterile MCP server manifest and JSON Schema `2020-12` tools.
pub async fn handle_mcp_get(
    State(_state): State<AgentGatewayState>,
) -> Result<Json<Value>, AgentError> {
    let tools = build_mcp_tools_manifest();
    Ok(Json(json!({
        "ok": true,
        "protocol": "mcp",
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "jsonSchemaDialect": JSON_SCHEMA_DRAFT_2020_12,
        "serverInfo": {
            "name": "perennia-agent-gateway",
            "version": "1.0.0"
        },
        "capabilities": {
            "tools": {
                "listChanged": false
            }
        },
        "invariants": {
            "nonCustodial": true,
            "integerMath": "u128_base10_strings_only",
            "takerMaxQuoteTtlSeconds": "5",
            "makerRfqTtlSeconds": "5..=15",
            "rateLimitOverflowProtocol": "x402"
        },
        "tools": tools
    })))
}

/// HTTP `POST /api/v1/agent/mcp` — JSON-RPC 2.0 / MCP dispatcher (`initialize`, `ping`, `tools/list`, `tools/call`).
pub async fn handle_mcp_post(
    State(state): State<AgentGatewayState>,
    headers: HeaderMap,
    Json(raw_rpc): Json<Value>,
) -> Response {
    let req: JsonRpcRequest = match serde_json::from_value(raw_rpc) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::OK,
                jsonrpc_error(
                    Value::Null,
                    -32700,
                    format!("Invalid JSON-RPC 2.0 request envelope: {}", e),
                    None,
                ),
            )
                .into_response();
        }
    };

    let req_id = req.id.clone().unwrap_or(Value::Null);

    if req.jsonrpc != "2.0" {
        return (
            StatusCode::OK,
            jsonrpc_error(req_id, -32600, "jsonrpc field must equal '2.0'.", None),
        )
            .into_response();
    }

    match req.method.as_str() {
        "notifications/initialized" | "notifications/cancelled" => {
            if req.id.is_none() {
                return StatusCode::ACCEPTED.into_response();
            }
            (StatusCode::OK, jsonrpc_success(req_id, json!({}))).into_response()
        }
        "ping" => (StatusCode::OK, jsonrpc_success(req_id, json!({}))).into_response(),
        "initialize" => {
            let init_res = json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {
                        "listChanged": false
                    }
                },
                "serverInfo": {
                    "name": "perennia-agent-gateway",
                    "version": "1.0.0"
                },
                "instructions": "Perennia non-custodial Agent Gateway. Pass stateless capability key in Authorization: Bearer <key> or X-Agent-Key. All amounts, prices, and fees are exact base-10 u128 strings. Sign quoted unsignedPayload locally and submit via perennia_execute_swap within TTL."
            });
            (StatusCode::OK, jsonrpc_success(req_id, init_res)).into_response()
        }
        "tools/list" => {
            let list_res = json!({
                "tools": build_mcp_tools_manifest()
            });
            (StatusCode::OK, jsonrpc_success(req_id, list_res)).into_response()
        }
        "tools/call" => {
            let Some(params_obj) = req.params.as_ref().and_then(|p| p.as_object()) else {
                return (
                    StatusCode::OK,
                    jsonrpc_error(req_id, -32602, "tools/call requires a params object.", None),
                )
                    .into_response();
            };

            let tool_name = params_obj
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();

            if !is_valid_mcp_tool_name(tool_name) {
                return (
                    StatusCode::OK,
                    jsonrpc_error(
                        req_id,
                        -32602,
                        "Tool name must match sterile pattern ^[A-Za-z0-9_-]{1,64}$.",
                        None,
                    ),
                )
                    .into_response();
            }

            let mut effective_headers = headers.clone();
            if !effective_headers.contains_key("authorization")
                && !effective_headers.contains_key("x-agent-key")
            {
                if let Some(meta_key) = params_obj
                    .get("_meta")
                    .and_then(|m| m.get("agentKey"))
                    .and_then(|v| v.as_str())
                {
                    if let Ok(hv) = HeaderValue::from_str(meta_key.trim()) {
                        effective_headers.insert("x-agent-key", hv);
                    }
                }
            }

            let args = params_obj
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));

            let exec_outcome: Result<Value, AgentError> = match tool_name {
                TOOL_MARKETS => handlers::core_get_markets(&state, &effective_headers).await,
                TOOL_QUOTE => handlers::core_post_quote(&state, &effective_headers, args).await,
                TOOL_EXECUTE => {
                    handlers::core_post_execute(&state, &effective_headers, args).await
                }
                TOOL_ME_CONTROL => {
                    let op = args
                        .get("operation")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    match op {
                        "get_telemetry" => {
                            handlers::core_get_me_telemetry(&state, &effective_headers).await
                        }
                        "get_buckets" => {
                            handlers::core_get_me_buckets(&state, &effective_headers).await
                        }
                        "update_buckets" => {
                            let mut forward_body = json!({
                                "allocations": args.get("allocations").cloned().unwrap_or_else(|| json!([])),
                                "dryRun": args.get("dryRun").and_then(|v| v.as_bool()).unwrap_or(false)
                            });
                            if let Some(obj) = args.as_object() {
                                for (k, v) in obj {
                                    if k != "operation"
                                        && k != "allocations"
                                        && k != "dryRun"
                                        {
                                        if let Some(f_obj) = forward_body.as_object_mut() {
                                            f_obj.insert(k.clone(), v.clone());
                                        }
                                    }
                                }
                            }
                            handlers::core_post_me_buckets(&state, &effective_headers, forward_body)
                                .await
                        }
                        _ => Err(AgentError::new(
                            AgentErrorCode::InvalidInput,
                            "operation must be one of: get_telemetry, get_buckets, update_buckets.",
                        )),
                    }
                }
                _ => {
                    return (
                        StatusCode::OK,
                        jsonrpc_error(
                            req_id,
                            -32602,
                            format!("Unknown Perennia MCP tool: {}", tool_name),
                            None,
                        ),
                    )
                        .into_response();
                }
            };

            match exec_outcome {
                Ok(data) => {
                    let tool_res = format_mcp_tool_result(data, false);
                    (StatusCode::OK, jsonrpc_success(req_id, tool_res)).into_response()
                }
                Err(agent_err) => {
                    let err_body = agent_err.to_json_body();
                    let tool_err_res = format_mcp_tool_result(err_body, true);
                    (StatusCode::OK, jsonrpc_success(req_id, tool_err_res)).into_response()
                }
            }
        }
        _ => (
            StatusCode::OK,
            jsonrpc_error(
                req_id,
                -32601,
                format!("Unsupported MCP JSON-RPC method: {}", req.method),
                None,
            ),
        )
            .into_response(),
    }
}