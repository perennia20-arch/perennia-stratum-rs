use async_trait::async_trait;
use deadpool_redis::{Config, Pool, Runtime};
use rand::Rng;
use redis::AsyncCommands;
use std::env;
use std::time::Duration;

use super::provider::{SorError, SorProvider};

pub struct MockFaucetProvider {
    pool: Pool,
    namespace: String,
}

impl MockFaucetProvider {
    pub async fn new() -> Self {
        // ⚡ Dynamically load network target to survive subnet lease changes
        let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let cfg = Config::from_url(redis_url);

        let pool = cfg
            .create_pool(Some(Runtime::Tokio1))
            .expect("CRITICAL: FAILED TO BIND TO REDIS MULTIPLEXER POOL");

        Self {
            pool,
            namespace: "dev:sor:treasury".to_string(),
        }
    }
}

#[async_trait]
impl SorProvider for MockFaucetProvider {
    async fn fetch_liquidity(&self, pair: &str) -> Result<f64, SorError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| SorError::PoolError(e.to_string()))?;

        let depth_key = format!("dev:sor:depth:{}", pair);

        let raw_depth: Option<f64> = conn.get(&depth_key).await?;
        let mut base_depth = raw_depth.unwrap_or(500_000.0);

        let mut rng = rand::thread_rng();
        let jitter = rng.gen_range(-0.015..=0.015);
        base_depth *= 1.0 + jitter;

        Ok(base_depth)
    }

    async fn execute_rebalance(
        &self,
        wallet: &str,
        src_asset: &str,
        dst_asset: &str,
        amount: f64,
    ) -> Result<String, SorError> {
        tokio::time::sleep(Duration::from_millis(1200)).await;

        let available_balance = self.get_treasury_balance(wallet, src_asset).await?;
        if available_balance < amount {
            return Err(SorError::InsufficientLiquidity(src_asset.to_string()));
        }

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| SorError::PoolError(e.to_string()))?;

        let balance_key = format!("{}:balances:{}", self.namespace, wallet);

        let mut pipe = redis::pipe();
        pipe.atomic()
            .cmd("HINCRBYFLOAT")
            .arg(&balance_key)
            .arg(src_asset)
            .arg(-amount)
            .cmd("HINCRBYFLOAT")
            .arg(&balance_key)
            .arg(dst_asset)
            .arg(amount);

        let _: () = pipe.query_async(&mut *conn).await?;

        let mut rng = rand::thread_rng();
        let mock_entropy: String = (0..56)
            .map(|_| format!("{:01x}", rng.gen_range(0..16)))
            .collect();
        let tx_hash = format!("mock_tx_{}", mock_entropy);

        Ok(tx_hash)
    }

    async fn trigger_faucet(&self, asset: &str, amount: f64) -> Result<(), SorError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| SorError::PoolError(e.to_string()))?;

        let balance_key = format!("{}:balances:admin", self.namespace);

        let _: () = redis::cmd("HINCRBYFLOAT")
            .arg(&balance_key)
            .arg(asset)
            .arg(amount)
            .query_async(&mut *conn)
            .await?;

        Ok(())
    }

    async fn get_treasury_balance(&self, wallet: &str, asset: &str) -> Result<f64, SorError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| SorError::PoolError(e.to_string()))?;

        let balance_key = format!("{}:balances:{}", self.namespace, wallet);

        let balance: Option<f64> = conn.hget(&balance_key, asset).await?;

        Ok(balance.unwrap_or(0.0))
    }
}