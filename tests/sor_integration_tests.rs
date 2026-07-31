// tests/sor_integration_tests.rs

use std::sync::Arc;
use deadpool_redis::{Config, Runtime};
use redis::AsyncCommands;

use perennia_stratum_rs::omnichain::{
    router::SmartOrderRouter,
    provider::{SorProvider, SorError},
    MockFaucetProvider,
};

/// Bootstraps a clean, isolated routing environment for each test
async fn setup_test_environment() -> (Arc<SmartOrderRouter>, deadpool_redis::Pool) {
    // Target the local test Redis instance
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let cfg = Config::from_url(redis_url);
    let pool = cfg.create_pool(Some(Runtime::Tokio1)).expect("Failed to bind Redis test pool");

    let provider = Arc::new(Box::new(MockFaucetProvider::new().await) as Box<dyn SorProvider>);
    let router = Arc::new(SmartOrderRouter::new(provider, pool.clone()));

    // ⚡ Clear the test namespace to prevent cross-test contamination
    let mut conn = pool.get().await.unwrap();
    let _: () = redis::cmd("FLUSHDB").query_async(&mut conn).await.unwrap();

    (router, pool)
}

#[tokio::test]
async fn test_sor_route_lock_success() {
    let (router, pool) = setup_test_environment().await;
    let mut conn = pool.get().await.unwrap();

    // Seed Kasplex mock depth
    let _: () = redis::cmd("SET")
        .arg("dev:sor:depth:KAS_USDC")
        .arg(500_000.0)
        .query_async(&mut conn)
        .await
        .unwrap();

    let result = router.request_route_lock(
        "admin",
        "KAS",
        "USDC",
        5_000.0, // Requested swap volume
        0.05,    // 5% Max slippage tolerance
    ).await;

    assert!(result.is_ok(), "Route lock should succeed under safe parameters");
    let (lock_id, impact) = result.unwrap();
    
    assert_eq!(impact, 0.01, "Mathematical impact should be exactly 1% (5k / 500k)");
    
    // Verify the ephemeral mutex was successfully placed in the cache
    let lock_exists: bool = redis::cmd("EXISTS")
        .arg(format!("dev:sor:lock:{}", lock_id))
        .query_async(&mut conn)
        .await
        .unwrap();
        
    assert!(lock_exists, "Ephemeral route lock must exist in Redis");
}

#[tokio::test]
async fn test_sor_insufficient_liquidity() {
    let (router, pool) = setup_test_environment().await;
    let mut conn = pool.get().await.unwrap();

    // Simulate a heavily drained KRC-20 pool
    let _: () = redis::cmd("SET")
        .arg("dev:sor:depth:KAS_NACHO")
        .arg(1_000.0)
        .query_async(&mut conn)
        .await
        .unwrap();

    let result = router.request_route_lock("admin", "KAS", "NACHO", 5_000.0, 0.10).await;

    assert!(
        matches!(result, Err(SorError::InsufficientLiquidity(_))),
        "Router must aggressively reject requests exceeding the available pool depth"
    );
}

#[tokio::test]
async fn test_sor_slippage_violation() {
    let (router, pool) = setup_test_environment().await;
    let mut conn = pool.get().await.unwrap();

    let _: () = redis::cmd("SET")
        .arg("dev:sor:depth:KAS_KASPER")
        .arg(100_000.0)
        .query_async(&mut conn)
        .await
        .unwrap();

    // 5,000 swap on 100,000 depth = 5% impact. Tolerance is locked at 2%.
    let result = router.request_route_lock("admin", "KAS", "KASPER", 5_000.0, 0.02).await;

    assert!(
        matches!(result, Err(SorError::SlippageViolation)), 
        "Router must reject due to strict slippage bounds"
    );
}

#[tokio::test]
async fn test_sor_route_busy_collision() {
    let (router, pool) = setup_test_environment().await;
    let mut conn = pool.get().await.unwrap();

    let depth_key = "dev:sor:depth:KAS_BTC";
    let _: () = redis::cmd("SET").arg(depth_key).arg(1_000_000.0).query_async(&mut conn).await.unwrap();

    // Bypass the UUID generator to intentionally force a collision state
    let lock_key = "dev:sor:lock:STATIC_COLLISION_UUID";

    // Call 1: Mutex Acquisition
    let res1: Vec<String> = router.script
        .key(depth_key).key(lock_key)
        .arg(1000.0).arg(0.05).arg(10)
        .invoke_async(&mut conn).await.unwrap();
    
    assert_eq!(res1[0], "ok", "First lock must succeed");

    // Call 2: Concurrent Mutex Collision (e.g., SYN Flood / Double Spend Attempt)
    let res2: Vec<String> = router.script
        .key(depth_key).key(lock_key)
        .arg(1000.0).arg(0.05).arg(10)
        .invoke_async(&mut conn).await.unwrap();

    assert_eq!(res2[0], "err");
    assert_eq!(res2[1], "ROUTE_BUSY", "The Lua script must enforce atomic mutual exclusion and bounce the second request");
}

#[tokio::test]
async fn test_sor_atomic_rebalance() {
    let (router, _pool) = setup_test_environment().await;

    // 1. Seed the internal Tier 1 Treasury
    router.provider.trigger_faucet("KAS", 10_000.0).await.unwrap();

    let pre_balance = router.provider.get_treasury_balance("admin", "KAS").await.unwrap();
    assert_eq!(pre_balance, 10_000.0);

    // 2. Execute the Waterfall Swap (KAS -> USDC)
    let tx_hash = router.provider.execute_rebalance("admin", "KAS", "USDC", 1_500.0).await.unwrap();
    assert!(tx_hash.starts_with("mock_tx_"), "Must return the synthetic transaction payload");

    // 3. Verify Atomic Settlement
    let post_kas = router.provider.get_treasury_balance("admin", "KAS").await.unwrap();
    let post_usdc = router.provider.get_treasury_balance("admin", "USDC").await.unwrap();

    assert_eq!(post_kas, 8_500.0, "KAS leg must decrement exactly");
    assert_eq!(post_usdc, 1_500.0, "USDC leg must increment exactly");
}