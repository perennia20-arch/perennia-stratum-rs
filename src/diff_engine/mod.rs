use kaspa_consensus_core::header::Header;
use kaspa_pow::State;
use kaspa_math::Uint256;

/// Validates incoming shares against both pool and network targets using native kHeavyHash.
pub fn verify_share(header: &Header, nonce: u64, min_share_diff: f64) -> (bool, bool) {
    let mut testing_header = header.clone();
    testing_header.nonce = nonce;

    // ⚡ Execute official cSHAKE-256 + HeavyHash matrix operations
    let state = State::new(&testing_header);
    
    // check_pow natively returns whether it met the Network Target, AND the actual Uint256 hash
    let (is_network_block, pow_hash) = state.check_pow(nonce);

    // Compute the absolute pool target threshold based on maximum space configuration
    let max_target = Uint256::MAX;
    let pool_target = if min_share_diff <= 1.0 {
        max_target
    } else {
        // Use standard From implementation for bulletproof compilation
        max_target / Uint256::from(min_share_diff as u64)
    };

    // A share is cryptographically valid if its hash value falls beneath the pool target space
    let is_valid_pool_share = pow_hash <= pool_target;

    (is_valid_pool_share, is_network_block)
}