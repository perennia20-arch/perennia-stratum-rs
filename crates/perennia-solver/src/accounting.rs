use anyhow::{bail, Result};
use std::env;

/// Stratum miner payout hot wallet ceiling (5,000 KAS in sompi).
/// Sovereign solver liquidity MUST remain strictly isolated from this hot airlock.
pub const STRATUM_HOT_AIRLOCK_CEILING_SOMPI: u128 = 500_000_000_000;
pub const SOMPI_PER_KAS: u128 = 100_000_000;
pub const ALLOWED_LP_FEE_TIERS_BPS: [u16; 3] = [30, 100, 250];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LpPairSompiSplit {
    pub amount_in_sompi: u128,
    pub fee_bps: u16,
    pub total_fee_sompi: u128,
    pub lp_fee_sompi: u128,
    pub treasury_fee_sompi: u128,
    pub net_out_sompi: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolSompiSplit {
    pub amount_in_sompi: u128,
    pub fee_bps: u16,
    pub treasury_fee_sompi: u128,
    pub net_out_sompi: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryOverflowSplit {
    pub internalized_sompi: u128,
    pub external_overflow_sompi: u128,
}

/// Exact 256-bit intermediate `(a * b) / denom` returning `(quotient, remainder)` in pure `u128`.
pub fn mul_div_rem_u128(a: u128, b: u128, denom: u128) -> Result<(u128, u128)> {
    if denom == 0 {
        bail!("ARITHMETIC_HALT: Division by zero in u128 mul_div.");
    }
    if a == 0 || b == 0 {
        return Ok((0, 0));
    }
    if let Some(prod) = a.checked_mul(b) {
        return Ok((prod / denom, prod % denom));
    }
    let a_lo = a & 0xFFFF_FFFF_FFFF_FFFF;
    let a_hi = a >> 64;
    let b_lo = b & 0xFFFF_FFFF_FFFF_FFFF;
    let b_hi = b >> 64;

    let p0 = a_lo * b_lo;
    let p1 = a_lo * b_hi;
    let p2 = a_hi * b_lo;
    let p3 = a_hi * b_hi;

    let mid = (p0 >> 64) + (p1 & 0xFFFF_FFFF_FFFF_FFFF) + (p2 & 0xFFFF_FFFF_FFFF_FFFF);
    let lo = (p0 & 0xFFFF_FFFF_FFFF_FFFF) | (mid << 64);
    let hi = p3 + (p1 >> 64) + (p2 >> 64) + (mid >> 64);

    if hi >= denom {
        bail!("ARITHMETIC_HALT: Quotient overflows u128.");
    }

    let mut q: u128 = 0;
    let mut rem_lo: u128 = 0;
    let mut rem_hi: u128 = 0;
    for bit_idx in (0..256).rev() {
        rem_hi = (rem_hi << 1) | (rem_lo >> 127);
        let in_bit = if bit_idx >= 128 {
            (hi >> (bit_idx - 128)) & 1
        } else {
            (lo >> bit_idx) & 1
        };
        rem_lo = (rem_lo << 1) | in_bit;
        if rem_hi > 0 || rem_lo >= denom {
            let (new_lo, borrow) = rem_lo.overflowing_sub(denom);
            rem_lo = new_lo;
            if borrow {
                rem_hi -= 1;
            }
            if bit_idx < 128 {
                q |= 1u128 << bit_idx;
            }
        }
    }
    Ok((q, rem_lo))
}

pub fn mul_div_floor_u128(a: u128, b: u128, denom: u128) -> Result<u128> {
    Ok(mul_div_rem_u128(a, b, denom)?.0)
}

pub fn mul_div_ceil_u128(a: u128, b: u128, denom: u128) -> Result<u128> {
    let (q, rem) = mul_div_rem_u128(a, b, denom)?;
    if rem > 0 {
        q.checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("ARITHMETIC_HALT: Ceil quotient overflows u128."))
    } else {
        Ok(q)
    }
}

pub fn parse_decimal_to_scaled_u128(raw: &str, decimals: u8) -> Result<u128> {
    let s = raw.trim();
    if s.is_empty() || s.starts_with('-') {
        bail!("Invalid unsigned decimal string: {}", raw);
    }
    let mut parts = s.split('.');
    let int_part = parts.next().unwrap_or("");
    let frac_part = parts.next().unwrap_or("");
    if parts.next().is_some() {
        bail!("Malformed decimal string with extra dot: {}", raw);
    }
    let int_val: u128 = if int_part.is_empty() {
        0
    } else {
        int_part.parse()?
    };
    let dec = decimals as usize;
    let mut frac_digits = frac_part.as_bytes().to_vec();
    if frac_digits.iter().any(|b| !b.is_ascii_digit()) {
        bail!("Non-digit in decimal fraction: {}", raw);
    }
    if frac_digits.len() > dec {
        frac_digits.truncate(dec);
    }
    while frac_digits.len() < dec {
        frac_digits.push(b'0');
    }
    let frac_str = String::from_utf8(frac_digits)?;
    let frac_val: u128 = if frac_str.is_empty() {
        0
    } else {
        frac_str.parse()?
    };
    let scale = 10u128.pow(decimals as u32);
    int_val
        .checked_mul(scale)
        .and_then(|v| v.checked_add(frac_val))
        .ok_or_else(|| anyhow::anyhow!("Decimal scaled u128 overflow"))
}

/// Deterministic 80/20 Liquidity Pair sompi fee split across tier fees (30, 100, or 250 bps).
/// Assigns odd integer remainder deterministically to `treasury_fee_sompi` and asserts
/// `amount_in_sompi == net_out_sompi + lp_fee_sompi + treasury_fee_sompi`.
pub fn compute_lp_pair_sompi_split(
    amount_in_sompi: u128,
    fee_tier_bps: u16,
) -> Result<LpPairSompiSplit> {
    if !ALLOWED_LP_FEE_TIERS_BPS.contains(&fee_tier_bps) {
        bail!(
            "INVALID_LP_FEE_TIER: Expected 30, 100, or 250 bps; got {}.",
            fee_tier_bps
        );
    }
    if amount_in_sompi == 0 {
        bail!("ZERO_LOSS_INVARIANT_VIOLATION: amount_in_sompi must be > 0.");
    }
    let total_fee_sompi = mul_div_ceil_u128(amount_in_sompi, fee_tier_bps as u128, 10_000)?;
    let net_out_sompi = amount_in_sompi
        .checked_sub(total_fee_sompi)
        .filter(|&v| v > 0)
        .ok_or_else(|| {
            anyhow::anyhow!("ZERO_LOSS_INVARIANT_VIOLATION: Net swap output after fee is 0.")
        })?;
    let lp_fee_sompi = mul_div_floor_u128(total_fee_sompi, 80, 100)?;
    let treasury_fee_sompi = total_fee_sompi.saturating_sub(lp_fee_sompi);
    assert_eq!(
        amount_in_sompi,
        net_out_sompi + lp_fee_sompi + treasury_fee_sompi
    );
    Ok(LpPairSompiSplit {
        amount_in_sompi,
        fee_bps: fee_tier_bps,
        total_fee_sompi,
        lp_fee_sompi,
        treasury_fee_sompi,
        net_out_sompi,
    })
}

/// Exact integer protocol fee deduction for Direct SWAP / BOOST settlements.
pub fn compute_protocol_sompi_split(
    amount_in_sompi: u128,
    fee_bps: u16,
) -> Result<ProtocolSompiSplit> {
    if amount_in_sompi == 0 {
        bail!("ZERO_LOSS_INVARIANT_VIOLATION: amount_in_sompi must be > 0.");
    }
    let treasury_fee_sompi = mul_div_ceil_u128(amount_in_sompi, fee_bps as u128, 10_000)?;
    let net_out_sompi = amount_in_sompi
        .checked_sub(treasury_fee_sompi)
        .filter(|&v| v > 0)
        .ok_or_else(|| {
            anyhow::anyhow!("ZERO_LOSS_INVARIANT_VIOLATION: Net protocol swap output is 0.")
        })?;
    assert_eq!(amount_in_sompi, net_out_sompi + treasury_fee_sompi);
    Ok(ProtocolSompiSplit {
        amount_in_sompi,
        fee_bps,
        treasury_fee_sompi,
        net_out_sompi,
    })
}

pub fn normalize_kaspa_prefixed(raw: &str) -> String {
    let clean = raw
        .trim()
        .to_lowercase()
        .replace("kaspa:", "")
        .trim()
        .to_string();
    if clean.is_empty() {
        String::new()
    } else {
        format!("kaspa:{}", clean)
    }
}

pub fn resolve_master_treasury_address_from_inputs(
    master_treasury_env: Option<&str>,
    perennia_master_env: Option<&str>,
    master_admin_env: Option<&str>,
    forbidden_stratum_hot_addr: Option<&str>,
) -> Result<String> {
    let raw = master_treasury_env
        .or(perennia_master_env)
        .or(master_admin_env)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "TREASURY_CONFIG_HALT: MASTER_TREASURY_ADDRESS / PERENNIA_MASTER_TREASURY_KAS is unconfigured."
            )
        })?;
    let normalized = normalize_kaspa_prefixed(raw);
    let body = normalized.trim_start_matches("kaspa:");
    if body.len() < 55 || !(body.starts_with('q') || body.starts_with('p')) {
        bail!("TREASURY_CONFIG_HALT: Invalid Bech32m kaspa: master treasury address.");
    }
    if let Some(hot_raw) = forbidden_stratum_hot_addr {
        let hot_norm = normalize_kaspa_prefixed(hot_raw);
        if !hot_norm.is_empty() && normalized == hot_norm {
            bail!(
                "TREASURY_ISOLATION_HALT: MASTER_TREASURY_ADDRESS cannot equal Stratum miner payout hot wallet (hotCeilingSompi={}).",
                STRATUM_HOT_AIRLOCK_CEILING_SOMPI
            );
        }
    }
    Ok(normalized)
}

pub fn resolve_master_treasury_address_strict() -> Result<String> {
    let mt = env::var("MASTER_TREASURY_ADDRESS").ok();
    let pmt = env::var("PERENNIA_MASTER_TREASURY_KAS").ok();
    let ma = env::var("MASTER_ADMIN_ADDRESS").ok();
    let hot = env::var("PERENNIA_HOT_KAS_ADDRESS")
        .or_else(|_| env::var("PERENNIA_TREASURY_KAS_ADDRESS"))
        .ok();
    resolve_master_treasury_address_from_inputs(
        mt.as_deref(),
        pmt.as_deref(),
        ma.as_deref(),
        hot.as_deref(),
    )
}

pub fn verify_solver_isolated_from_stratum_airlock(
    solver_address: &str,
    solver_sk_hex: &str,
    forbidden_stratum_hot_addr: Option<&str>,
    forbidden_stratum_hot_sk_hex: Option<&str>,
) -> Result<()> {
    let norm_solver = normalize_kaspa_prefixed(solver_address);
    let body = norm_solver.trim_start_matches("kaspa:");
    if body.len() < 55 || !(body.starts_with('q') || body.starts_with('p')) {
        bail!("SOLVER_ISOLATION_HALT: Invalid solver kaspa: address.");
    }
    if let Some(hot_addr) = forbidden_stratum_hot_addr {
        let norm_hot = normalize_kaspa_prefixed(hot_addr);
        if !norm_hot.is_empty() && norm_solver == norm_hot {
            bail!(
                "SOLVER_ISOLATION_HALT: Solver wallet {} collides with Stratum miner payout hot wallet (hotCeilingSompi={}).",
                norm_solver,
                STRATUM_HOT_AIRLOCK_CEILING_SOMPI
            );
        }
    }
    if let Some(hot_sk) = forbidden_stratum_hot_sk_hex {
        let clean_hot_sk = hot_sk.trim().strip_prefix("0x").unwrap_or(hot_sk.trim()).to_ascii_lowercase();
        let clean_solver_sk = solver_sk_hex
            .trim()
            .strip_prefix("0x")
            .unwrap_or(solver_sk_hex.trim())
            .to_ascii_lowercase();
        if !clean_hot_sk.is_empty() && clean_hot_sk == clean_solver_sk {
            bail!(
                "SOLVER_ISOLATION_HALT: Solver key shares private key material with Stratum hot payout wallet (hotCeilingSompi={}).",
                STRATUM_HOT_AIRLOCK_CEILING_SOMPI
            );
        }
    }
    Ok(())
}

/// Fail-closed 503 oracle guard for `oracle:spot:KAS_USDC`: requires present value, `pttl_ms > 0`, and positive price.
pub fn validate_fresh_kas_usdc_oracle(
    spot_opt: Option<&str>,
    pttl_ms: i64,
) -> Result<(u128, f64)> {
    let spot_str = spot_opt.ok_or_else(|| {
        anyhow::anyhow!("503 ORACLE_HALT: Redis oracle:spot:KAS_USDC missing (fail-closed).")
    })?;
    if pttl_ms <= 0 {
        bail!(
            "503 ORACLE_HALT: Redis oracle:spot:KAS_USDC stale or missing TTL (pttl_ms={}).",
            pttl_ms
        );
    }
    let e8 = parse_decimal_to_scaled_u128(spot_str, 8)?;
    if e8 == 0 {
        bail!("503 ORACLE_HALT: Redis oracle:spot:KAS_USDC resolved to 0.");
    }
    Ok((e8, (e8 as f64) / 100_000_000.0))
}

/// Splits an order across verified on-chain solver inventory and external overflow routing.
pub fn split_inventory_and_external_overflow(
    requested_sompi: u128,
    solver_inventory_sompi: u128,
) -> InventoryOverflowSplit {
    let internalized_sompi = solver_inventory_sompi.min(requested_sompi);
    let external_overflow_sompi = requested_sompi.saturating_sub(internalized_sompi);
    assert_eq!(
        requested_sompi,
        internalized_sompi + external_overflow_sompi
    );
    InventoryOverflowSplit {
        internalized_sompi,
        external_overflow_sompi,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lp_pair_splits_80_20_with_deterministic_dust_and_zero_loss() {
        for tier in [30u16, 100u16, 250u16] {
            for amount in [10_000u128, 100_001u128, 555_555_557u128, 50_000_000_000u128] {
                let s = compute_lp_pair_sompi_split(amount, tier).unwrap();
                assert_eq!(
                    s.amount_in_sompi,
                    s.net_out_sompi + s.lp_fee_sompi + s.treasury_fee_sompi
                );
                assert_eq!(s.total_fee_sompi, s.lp_fee_sompi + s.treasury_fee_sompi);
                assert!(s.lp_fee_sompi <= (s.total_fee_sompi * 80) / 100);
                assert!(s.treasury_fee_sompi >= s.total_fee_sompi / 5);
            }
        }
        assert!(compute_lp_pair_sompi_split(100_000_000, 50).is_err());
    }

    #[test]
    fn protocol_split_and_treasury_routing_guard() {
        let p = compute_protocol_sompi_split(10_000_000_003, 50).unwrap();
        assert_eq!(p.amount_in_sompi, p.net_out_sompi + p.treasury_fee_sompi);

        let valid_treasury =
            "kaspa:qp00000000000000000000000000000000000000000000000000000000000";
        let stratum_hot =
            "kaspa:qr11111111111111111111111111111111111111111111111111111111111";

        let resolved = resolve_master_treasury_address_from_inputs(
            Some(valid_treasury),
            None,
            None,
            Some(stratum_hot),
        )
        .unwrap();
        assert_eq!(resolved, valid_treasury);

        assert!(resolve_master_treasury_address_from_inputs(
            Some(stratum_hot),
            None,
            None,
            Some(stratum_hot)
        )
        .is_err());
        assert!(resolve_master_treasury_address_from_inputs(None, None, None, None).is_err());
    }

    #[test]
    fn stratum_airlock_isolation_and_oracle_and_overflow_guards() {
        let solver_addr =
            "kaspa:qp22222222222222222222222222222222222222222222222222222222222";
        let hot_addr =
            "kaspa:qr11111111111111111111111111111111111111111111111111111111111";

        assert!(verify_solver_isolated_from_stratum_airlock(
            solver_addr,
            "11".repeat(32).as_str(),
            Some(hot_addr),
            Some("22".repeat(32).as_str())
        )
        .is_ok());

        // Colliding address with Stratum 5,000 KAS airlock must fail closed
        assert!(verify_solver_isolated_from_stratum_airlock(
            hot_addr,
            "11".repeat(32).as_str(),
            Some(hot_addr),
            Some("22".repeat(32).as_str())
        )
        .is_err());

        // Colliding private key material must fail closed
        assert!(verify_solver_isolated_from_stratum_airlock(
            solver_addr,
            "aa".repeat(32).as_str(),
            Some(hot_addr),
            Some("aa".repeat(32).as_str())
        )
        .is_err());

        // Fresh vs stale/missing KAS_USDC oracle checks
        let (e8, px) = validate_fresh_kas_usdc_oracle(Some("0.14500000"), 12_000).unwrap();
        assert_eq!(e8, 14_500_000);
        assert!((px - 0.145).abs() < 1e-9);
        assert!(validate_fresh_kas_usdc_oracle(Some("0.145"), 0).is_err());
        assert!(validate_fresh_kas_usdc_oracle(Some("0.145"), -1).is_err());
        assert!(validate_fresh_kas_usdc_oracle(None, 10_000).is_err());
        assert!(validate_fresh_kas_usdc_oracle(Some("0"), 10_000).is_err());

        // Inventory + external overflow split
        let ov = split_inventory_and_external_overflow(600_000_000_000, 125_000_000_000);
        assert_eq!(ov.internalized_sompi, 125_000_000_000);
        assert_eq!(ov.external_overflow_sompi, 475_000_000_000);
        assert_eq!(ov.internalized_sompi + ov.external_overflow_sompi, 600_000_000_000);
    }
}
