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

    pub async fn get_balance_by_address_grpc(_address: &str) -> Result<u64, String> {
        Ok(0)
    }

    pub async fn get_virtual_daa_score_grpc() -> Result<u64, String> {
        Ok(100_000_000)
    }

    pub async fn get_fee_estimate_sompi_per_gram_grpc() -> Result<u64, String> {
        Ok(110)
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
    assert!(chronos::compute_reservoir_hmac(wallet, 250.0, 500.0, &lp_json).is_err());
}

#[test]
fn rehearsal_4_verify_batch2_toccata_vault_zk_guard_and_changenow_split() {
    assert_eq!(state_api::validate_zk_precompile_tag(0x20), Ok(0x20));
    assert!(state_api::validate_zk_precompile_tag(0x21).is_err());
    assert!(state_api::validate_zk_precompile_tag(0x99).is_err());

    let owner = "kaspa:qrsmsx90uctxg3lnjra64vad98kwuhq7xxhk0f7q5g245tyerxznj2lvwe0hx";
    let (_, owner_hash) = state_api::decode_kaspa_address_payload(owner).unwrap();
    let trigger_pk = state_api::blake2b_256(b"PERENNIA_CHRONOS_TRIGGER_V1");
    let owner_spk = format!("20{}ac", hex::encode(owner_hash));

    let spec = state_api::VaultLockCovenantSpec {
        vault_kind: state_api::VaultLockKind::MinerSilo,
        owner_kaspa_address: owner.to_string(),
        chronos_trigger_pubkey: trigger_pk,
        destination_spk_hex: owner_spk.clone(),
        house_revenue_spk_hex: owner_spk,
        refund_kaspa_address: owner.to_string(),
        threshold_sompi: 2_500_000_000,
        fee_bps: 50,
        maker_spread_bps: 0,
        target_asset: "USDC".to_string(),
        target_network: "SOL".to_string(),
        kcc20_ticker: Some("SILO".to_string()),
        kcc20_amount_atomic: Some(100_000_000),
        zk_precompile_tag: Some(0x20),
    };
    let compiled = state_api::compile_toccata_vault_lock_covenant(&spec).unwrap();
    assert!(compiled.covenant_address.starts_with("kaspa:"));
    assert!(compiled.covenant_spk_hex.starts_with("a9"));
    assert!(compiled.covenant_spk_hex.ends_with("87"));
    assert_eq!(compiled.sig_op_count, 2);
    assert_eq!(compiled.kip20_covenant_id.len(), 64);

    let (payin_sompi, house_fee_sompi) =
        fiat_rails::compute_tier3_changenow_sompi_split(10_000_000_000, 300_000, 50).unwrap();
    assert_eq!(house_fee_sompi, 50_000_000);
    assert_eq!(payin_sompi, 9_949_700_000);
    assert_eq!(payin_sompi + house_fee_sompi + 300_000, 10_000_000_000);
}

#[test]
fn rehearsal_5_verify_batch3_cow_htlc_tier2_bid_invariants_and_zktls_0x20() {
    let hl = [0x11u8; 32];
    let claim_pk = [0x22u8; 32];
    let refund_pk = [0x33u8; 32];
    let htlc = chronos::build_kaspa_opsha256_htlc_covenant(&hl, &claim_pk, &refund_pk, 123_456_789);
    let script_bytes = hex::decode(&htlc.redeem_script_hex).unwrap();
    assert!(htlc.p2sh_address.starts_with("kaspa:"));
    assert!(htlc.p2sh_spk_hex.starts_with("a9"));
    assert!(htlc.p2sh_spk_hex.ends_with("87"));
    assert_eq!(htlc.sig_op_count, 2);
    // Exact OpIf OpSHA256 ... OpElse <daa> OpCheckLockTimeVerify OpDrop ... OpEndIf
    assert_eq!(script_bytes[0], 0x63);
    assert_eq!(script_bytes[1], 0xa8);
    assert!(script_bytes.windows(3).any(|w| w == [0xb0, 0x75, 0x20]));
    assert_eq!(*script_bytes.last().unwrap(), 0x68);

    // Tier 2 Solver Bid Invariants: must beat ChangeNOW floor by >= 10 bps, house fee 50..=75 bps
    assert!(chronos::verify_tier2_solver_bid_invariants(
        100_000_000,
        100_050_000, // only +5 bps
        100_000_000_000,
        50,
    )
    .is_err());
    assert!(chronos::verify_tier2_solver_bid_invariants(
        100_000_000,
        100_200_000,
        100_000_000_000,
        49, // below 50 bps
    )
    .is_err());
    let (min_req, house_fee) = chronos::verify_tier2_solver_bid_invariants(
        100_000_000,
        100_150_000, // +15 bps
        100_000_000_000,
        60, // 0.60%
    )
    .unwrap();
    assert_eq!(min_req, 100_100_000);
    assert_eq!(house_fee, 600_000_000);

    // Sequential 4-Valve Thermostat Conservation
    let valves = vec![
        chronos::ThermostatValveRule {
            priority_order: 2,
            valve_type: "VALVE_2_AGENT_X402_FLOOR".to_string(),
            target_asset: "USDC".to_string(),
            target_network: "BASE".to_string(),
            destination_address: "0xagent".to_string(),
            target_cap_sompi: 2_000_000_000,
            target_cap_usd_micros: 0,
            filled_epoch_sompi: 0,
            filled_epoch_usd_micros: 0,
            zktls_biller_commitment_hex: None,
            is_enabled: true,
        },
        chronos::ThermostatValveRule {
            priority_order: 1,
            valve_type: "VALVE_1_ELECTRIC_BILL".to_string(),
            target_asset: "USD".to_string(),
            target_network: "ZKTLS".to_string(),
            destination_address: "biller_1".to_string(),
            target_cap_sompi: 3_000_000_000,
            target_cap_usd_micros: 0,
            filled_epoch_sompi: 500_000_000,
            filled_epoch_usd_micros: 0,
            zktls_biller_commitment_hex: Some("aa".repeat(32)),
            is_enabled: true,
        },
        chronos::ThermostatValveRule {
            priority_order: 4,
            valve_type: "VALVE_4_TANGEM_COLD_OR_PLANT".to_string(),
            target_asset: "KAS".to_string(),
            target_network: "KAS".to_string(),
            destination_address: "kaspa:cold".to_string(),
            target_cap_sompi: 0,
            target_cap_usd_micros: 0,
            filled_epoch_sompi: 0,
            filled_epoch_usd_micros: 0,
            zktls_biller_commitment_hex: None,
            is_enabled: true,
        },
    ];
    let allocs = chronos::route_sompi_across_thermostat_valves(10_000_000_000, 15_000_000, &valves);
    assert_eq!(allocs.len(), 3);
    assert_eq!(allocs[0].priority_order, 1);
    assert_eq!(allocs[0].allocated_sompi, 2_500_000_000);
    assert_eq!(allocs[1].priority_order, 2);
    assert_eq!(allocs[1].allocated_sompi, 2_000_000_000);
    assert_eq!(allocs[2].priority_order, 4);
    assert_eq!(allocs[2].allocated_sompi, 5_500_000_000);
    assert_eq!(
        allocs.iter().map(|a| a.allocated_sompi).sum::<u128>(),
        10_000_000_000
    );

    assert_eq!(state_api::validate_zk_precompile_tag(0x20), Ok(0x20));
    assert!(state_api::validate_zk_precompile_tag(0x21).is_err());
}

#[test]
fn lp_pair_80_20_splits_treasury_routing_and_airlock_isolation_invariants() {
    // 1. Verify exact 80/20 sompi splits across 30, 100, and 250 bps with deterministic dust
    for tier_bps in [30u16, 100u16, 250u16] {
        for amount_in in [10_000u128, 100_003u128, 999_999_997u128, 50_000_000_000u128] {
            let split = sor::compute_lp_pair_sompi_split(amount_in, tier_bps).unwrap();
            assert_eq!(
                split.amount_in,
                split.net_out + split.lp_fee + split.treasury_fee
            );
            assert!(split.treasury_fee >= split.total_fee / 5);
        }
    }
    assert!(sor::compute_lp_pair_sompi_split(100_000_000, 75).is_err());

    // 2. Direct swap / BOOST exact protocol fee conservation & overflow partitioning
    let proto = sor::compute_protocol_sompi_split(250_000_000_005, 50).unwrap();
    assert_eq!(proto.amount_in, proto.net_out + proto.treasury_fee);

    let overflow = sor::split_solver_inventory_and_overflow(600_000_000_000, 150_000_000_000);
    assert_eq!(overflow.internalized_atomic, 150_000_000_000);
    assert_eq!(overflow.external_overflow_atomic, 450_000_000_000);
    assert_eq!(
        overflow.internalized_atomic + overflow.external_overflow_atomic,
        600_000_000_000
    );

    // 3. Stratum 5,000 KAS airlock isolation guard
    assert_eq!(chronos::STRATUM_HOT_AIRLOCK_CEILING_SOMPI, 500_000_000_000);
    let hot_addr = "kaspa:qrsmsx90uctxg3lnjra64vad98kwuhq7xxhk0f7q5g245tyerxznj2lvwe0hx".to_string();
    let solver_addr = chronos::build_kaspa_opsha256_htlc_covenant(
        &[0x42u8; 32],
        &[0x43u8; 32],
        &[0x44u8; 32],
        200_000_000,
    )
    .p2sh_address;
    std::env::set_var("PERENNIA_HOT_KAS_ADDRESS", &hot_addr);
    std::env::set_var("PERENNIA_HOT_PRIVATE_KEY", &"11".repeat(32));
    std::env::set_var("SOLVER_WALLET_PRIVATE_KEY", &"22".repeat(32));

    assert!(chronos::verify_solver_wallet_isolated_from_stratum_airlock(&solver_addr).is_ok());
    assert!(chronos::verify_solver_wallet_isolated_from_stratum_airlock(&hot_addr).is_err());

    std::env::set_var("SOLVER_WALLET_PRIVATE_KEY", &"11".repeat(32));
    assert!(chronos::verify_solver_wallet_isolated_from_stratum_airlock(&solver_addr).is_err());

    std::env::remove_var("PERENNIA_HOT_KAS_ADDRESS");
    std::env::remove_var("PERENNIA_HOT_PRIVATE_KEY");
    std::env::remove_var("SOLVER_WALLET_PRIVATE_KEY");
}
