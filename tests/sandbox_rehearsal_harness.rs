#[allow(dead_code, unused_imports)]
#[path = "../src/schema.rs"]
pub mod schema;

#[allow(dead_code, unused_imports)]
pub mod kaspad_client {
    use serde_json::Value;

    pub mod protowire {
        tonic::include_proto!("protowire");
    }

    pub fn resolve_local_first_grpc_endpoints() -> Vec<String> {
        vec!["grpc://127.0.0.1:16110".to_string()]
    }

    pub async fn get_utxos_by_address_grpc(_address: &str) -> Result<Vec<Value>, String> {
        Err("GRPC_TEST_STUB".to_string())
    }

    pub async fn submit_transaction_grpc(
        _rpc_tx: &Value,
        _allow_orphan: bool,
    ) -> Result<String, String> {
        Err("GRPC_TEST_STUB".to_string())
    }

    pub async fn get_balance_by_address_grpc(_address: &str) -> Result<f64, String> {
        Ok(0.0)
    }
}

#[allow(dead_code, unused_imports)]
pub mod oracle {
    pub fn register_dynamic_oracle_ticker(_ticker: &str) {}
}

#[allow(dead_code, unused_imports)]
#[path = "../src/sor.rs"]
pub mod sor;

#[allow(dead_code, unused_imports)]
#[path = "../src/chronos.rs"]
pub mod chronos;

#[allow(dead_code, unused_imports)]
#[path = "../src/l1_dispatcher.rs"]
pub mod l1_dispatcher;

#[allow(dead_code, unused_imports)]
#[path = "../src/state_api.rs"]
pub mod state_api;

#[allow(dead_code, unused_imports)]
#[path = "../src/fiat_rails.rs"]
pub mod fiat_rails;

use serde_json::json;

#[test]
fn rehearsal_1_verify_900_onramp_basket_cost_plus_math() {
    let kas_500 = fiat_rails::calculate_onramp_cost_plus_quote(
        "KAS",
        500.0,
        0.15,
        "SOVEREIGN_WIRE_ACH",
        "L1_SELF_CUSTODY",
        false,
        false,
    );
    assert_eq!(kas_500.quoted_guest_fee_usd, 10.0);
    assert_eq!(kas_500.hard_execution_and_repar_cost_usd, 1.0);
    assert_eq!(kas_500.guaranteed_net_profit_usd, 9.0);
    assert_eq!(kas_500.guest_net_usd, 490.0);
    assert_eq!(kas_500.competitor_fee_usd, 17.0);
    assert_eq!(kas_500.guest_savings_vs_competitor_usd, 7.0);
    assert!(!kas_500.circuit_breaker_tripped);

    let btc_100 = fiat_rails::calculate_onramp_cost_plus_quote(
        "BTC",
        100.0,
        90_000.0,
        "SOVEREIGN_WIRE_ACH",
        "L1_SELF_CUSTODY",
        false,
        false,
    );
    assert_eq!(btc_100.quoted_guest_fee_usd, 7.0);
    assert_eq!(btc_100.hard_execution_and_repar_cost_usd, 4.0);
    assert_eq!(btc_100.guaranteed_net_profit_usd, 3.0);
    assert_eq!(btc_100.guest_net_usd, 93.0);
    assert_eq!(btc_100.competitor_fee_usd, 9.0);
    assert_eq!(btc_100.guest_savings_vs_competitor_usd, 2.0);
    assert!(!btc_100.circuit_breaker_tripped);

    let eth_100 = fiat_rails::calculate_onramp_cost_plus_quote(
        "ETH",
        100.0,
        3_000.0,
        "SOVEREIGN_WIRE_ACH",
        "L1_SELF_CUSTODY",
        false,
        false,
    );
    assert_eq!(eth_100.quoted_guest_fee_usd, 3.0);
    assert_eq!(eth_100.hard_execution_and_repar_cost_usd, 1.5);
    assert_eq!(eth_100.guaranteed_net_profit_usd, 1.5);
    assert_eq!(eth_100.guest_net_usd, 97.0);
    assert_eq!(eth_100.competitor_fee_usd, 6.0);

    let sol_100 = fiat_rails::calculate_onramp_cost_plus_quote(
        "SOL",
        100.0,
        180.0,
        "SOVEREIGN_WIRE_ACH",
        "L1_SELF_CUSTODY",
        false,
        false,
    );
    assert_eq!(sol_100.quoted_guest_fee_usd, 3.0);
    assert_eq!(sol_100.hard_execution_and_repar_cost_usd, 1.5);
    assert_eq!(sol_100.guaranteed_net_profit_usd, 1.5);
    assert_eq!(sol_100.guest_net_usd, 97.0);
    assert_eq!(sol_100.competitor_fee_usd, 6.0);

    let usdc_100 = fiat_rails::calculate_onramp_cost_plus_quote(
        "USDC",
        100.0,
        1.0,
        "SOVEREIGN_WIRE_ACH",
        "L1_SELF_CUSTODY",
        false,
        false,
    );
    assert_eq!(usdc_100.quoted_guest_fee_usd, 2.0);
    assert_eq!(usdc_100.hard_execution_and_repar_cost_usd, 0.35);
    assert_eq!(usdc_100.guaranteed_net_profit_usd, 1.65);
    assert_eq!(usdc_100.guest_net_usd, 98.0);
    assert_eq!(usdc_100.competitor_fee_usd, 5.0);

    let total_gross = kas_500.gross_usd
        + btc_100.gross_usd
        + eth_100.gross_usd
        + sol_100.gross_usd
        + usdc_100.gross_usd;
    let total_fee = kas_500.quoted_guest_fee_usd
        + btc_100.quoted_guest_fee_usd
        + eth_100.quoted_guest_fee_usd
        + sol_100.quoted_guest_fee_usd
        + usdc_100.quoted_guest_fee_usd;
    let total_net = kas_500.guest_net_usd
        + btc_100.guest_net_usd
        + eth_100.guest_net_usd
        + sol_100.guest_net_usd
        + usdc_100.guest_net_usd;

    assert_eq!(total_gross, 900.0);
    assert_eq!(total_fee, 25.0);
    assert_eq!(total_net, 875.0);
}

#[test]
fn rehearsal_2_verify_3300_offramp_volume_and_post_trade_4_bucket_split() {
    let kas_500 = fiat_rails::calculate_offramp_cost_plus_quote("KAS", 500.0, 0.15, "ACH");
    let btc_100 = fiat_rails::calculate_offramp_cost_plus_quote("BTC", 100.0, 90_000.0, "ACH");
    let eth_200 = fiat_rails::calculate_offramp_cost_plus_quote("ETH", 200.0, 3_000.0, "ACH");
    let whale_2500 = fiat_rails::calculate_offramp_cost_plus_quote("BTC", 2500.0, 90_000.0, "WIRE");

    assert_eq!(kas_500.quoted_guest_fee_usd, 9.0);
    assert_eq!(kas_500.guest_net_usd, 491.0);

    assert_eq!(btc_100.quoted_guest_fee_usd, 3.0);
    assert_eq!(btc_100.guest_net_usd, 97.0);

    assert_eq!(eth_200.quoted_guest_fee_usd, 5.0);
    assert_eq!(eth_200.guest_net_usd, 195.0);

    assert_eq!(whale_2500.quoted_guest_fee_usd, 30.0);
    assert_eq!(whale_2500.guest_net_usd, 2470.0);

    let total_offramp_gross =
        kas_500.gross_usd + btc_100.gross_usd + eth_200.gross_usd + whale_2500.gross_usd;
    let total_offramp_fee = kas_500.quoted_guest_fee_usd
        + btc_100.quoted_guest_fee_usd
        + eth_200.quoted_guest_fee_usd
        + whale_2500.quoted_guest_fee_usd;
    assert_eq!(total_offramp_gross, 3300.0);
    assert_eq!(total_offramp_fee, 47.0);

    let split = fiat_rails::compute_post_trade_usd_allocation(1_000.0);
    assert_eq!(split.wholesale_api_float_sweep_usd, 485.0);
    assert_eq!(split.chronos_miner_settlement_usd, 490.0);
    assert_eq!(split.llc_tax_and_rail_reserve_usd, 7.0);
    assert_eq!(split.net_profit_and_ratchet_usd, 18.0);
}

#[test]
fn rehearsal_3_verify_fail_closed_oracle_circuit_breaker_and_reservoir_hmac() {
    let tripped_onramp = fiat_rails::calculate_onramp_cost_plus_quote(
        "BTC",
        100.0,
        0.0,
        "SOVEREIGN_WIRE_ACH",
        "L1_SELF_CUSTODY",
        false,
        false,
    );
    assert!(tripped_onramp.circuit_breaker_tripped);
    assert!(tripped_onramp
        .circuit_breaker_reason
        .unwrap_or_default()
        .contains("CIRCUIT_BREAKER_TRIPPED"));

    let tripped_offramp =
        fiat_rails::calculate_offramp_cost_plus_quote("ETH", 200.0, 0.0, "ACH");
    assert!(tripped_offramp.circuit_breaker_tripped);

    std::env::set_var(
        "LEDGER_HMAC_SECRET",
        "perennia_unit_test_hmac_secret_key_32_bytes_minimum_length",
    );
    let wallet = "kaspa:qrsmsx90uctxg3lnjra64vad98kwuhq7xxhk0f7q5g245tyerxznj2lvwe0hx";
    let lp_json = json!({ "USDC": 125.5, "SILO": 1000.0 });
    let sig_a = chronos::compute_reservoir_hmac(wallet, 250.0, 500.0, &lp_json)
        .expect("HMAC computation should succeed with 32+ char secret");
    let sig_b = chronos::compute_reservoir_hmac(wallet, 250.0, 500.0, &lp_json)
        .expect("Deterministic HMAC must match");
    let sig_tampered = chronos::compute_reservoir_hmac(wallet, 9999.0, 500.0, &lp_json)
        .expect("Tampered balance produces distinct HMAC");

    assert_eq!(sig_a, sig_b);
    assert_ne!(sig_a, sig_tampered);
}
