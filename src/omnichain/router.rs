// src/omnichain/router.rs

use deadpool_redis::Pool;
use redis::AsyncCommands;
use std::sync::Arc;
use uuid::Uuid;

use super::provider::{SorError, SorProvider};

pub struct SmartOrderRouter {
    pub provider: Arc<Box<dyn SorProvider>>,
    pub pool: Pool,
}

impl SmartOrderRouter {
    pub fn new(provider: Arc<Box<dyn SorProvider>>, pool: Pool) -> Self {
        Self { provider, pool }
    }

    pub async fn request_route_lock(
        &self,
        _user_id: &str, 
        src_asset: &str,
        dst_asset: &str,
        amount: f64,
        max_slippage: f64,
    ) -> Result<(String, f64), SorError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| SorError::PoolError(e.to_string()))?;

        let pair = format!("{}_{}", src_asset.to_uppercase(), dst_asset.to_uppercase());
        let depth_key = format!("dev:sor:depth:{}", pair);
        
        let current_depth: Option<f64> = conn.get(&depth_key).await.map_err(SorError::Redis)?;
        let depth = current_depth.unwrap_or(500_000.0);

        // 1. Hard Liquidity Constraint
        if depth < amount {
            return Err(SorError::InsufficientLiquidity(pair));
        }

        // 2. Volatility & Slippage Constraint
        let impact = amount / depth;
        if impact > max_slippage {
            return Err(SorError::SlippageViolation);
        }

        // 3. Ephemeral Mutual Exclusion (Mutex) Lock
        let lock_id = Uuid::new_v4().to_string();
        let lock_key = format!("dev:sor:lock:{}", lock_id);
        let ttl_seconds = 15;

        let acquired: bool = redis::cmd("SET")
            .arg(&lock_key)
            .arg("LOCKED")
            .arg("EX")
            .arg(ttl_seconds)
            .arg("NX")
            .query_async(&mut conn)
            .await
            .map_err(SorError::Redis)?;

        if !acquired {
            return Err(SorError::BroadcastFailure("Route lock collision. Try again.".into()));
        }

        Ok((lock_id, impact))
    }
}