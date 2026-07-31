// src/omnichain/provider.rs

use async_trait::async_trait;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SorError {
    #[error("Redis state fault: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("Pool connection error: {0}")]
    PoolError(String),

    #[error("Insufficient liquidity constraints for asset: {0}")]
    InsufficientLiquidity(String),

    #[error("Slippage tolerance violated during route locking")]
    SlippageViolation,

    #[error("Transaction broadcasting failure: {0}")]
    BroadcastFailure(String),
}

#[async_trait]
pub trait SorProvider: Send + Sync {
    async fn fetch_liquidity(&self, pair: &str) -> Result<f64, SorError>;

    async fn execute_rebalance(
        &self,
        wallet: &str,
        src_asset: &str,
        dst_asset: &str,
        amount: f64,
    ) -> Result<String, SorError>;

    async fn trigger_faucet(&self, asset: &str, amount: f64) -> Result<(), SorError>;

    async fn get_treasury_balance(&self, wallet: &str, asset: &str) -> Result<f64, SorError>;
}