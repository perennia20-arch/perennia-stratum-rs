// src/omnichain/mod.rs

pub mod mock;
pub mod live;
pub mod provider;
pub mod router;
pub mod scripts;
pub mod liquidity_poller;

use std::env;

pub use mock::MockFaucetProvider;
pub use live::LiveChainProvider;
pub use provider::{SorError, SorProvider};
pub use scripts::SilverscriptCompiler; // ⚡ Export the new Compiler

/// Bootstraps the dependency injection layer.
/// Dynamically links the active provider based on execution environment.
pub async fn initialize_provider() -> Box<dyn SorProvider> {
    let mode = env::var("NETWORK_MODE").unwrap_or_else(|_| "dev".to_string());

    if mode == "testnet-12" {
        let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let cfg = deadpool_redis::Config::from_url(redis_url);
        let pool = cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1)).unwrap();
        
        // Bind to Kaspa Testnet-12 public REST / gRPC
        Box::new(LiveChainProvider::new(pool, "https://api.kaspatest.org".to_string()).await)
    } else if mode == "mainnet" {
        panic!("LiveChainProvider not yet implemented for mainnet.");
    } else {
        // Default to the localized zero-allocation Mock Engine for dev
        Box::new(MockFaucetProvider::new().await)
    }
}