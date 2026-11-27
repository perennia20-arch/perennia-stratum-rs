use kaspa_consensus_core::header::Header;
use kaspa_math::Uint256;
use kaspa_pow::State;

const STRATUM_DIFF1_DIVISOR: u64 = 4_294_967_296;

pub fn verify_share(header: &Header, nonce: u64, min_share_diff: f64) -> (bool, bool) {
    let mut testing_header = header.clone();
    testing_header.nonce = nonce;
    let state = State::new(&testing_header);
    let (is_network_block, pow_hash) = state.check_pow(nonce);
    let clamped = if min_share_diff.is_finite() && min_share_diff > 0.0 { min_share_diff } else { 1.0 };
    let pool_target = if clamped >= 1.0 {
        let diff1 = Uint256::MAX / Uint256::from(STRATUM_DIFF1_DIVISOR);
        diff1 / Uint256::from(clamped.round().max(1.0) as u64)
    } else {
        let scaled = ((STRATUM_DIFF1_DIVISOR as f64) * clamped).round().max(1.0) as u64;
        Uint256::MAX / Uint256::from(scaled)
    };
    (pow_hash <= pool_target, is_network_block)
}
