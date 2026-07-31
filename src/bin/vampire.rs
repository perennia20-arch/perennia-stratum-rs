// src/bin/vampire.rs

use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncBufReadExt, BufReader};
use serde_json::json;
use std::time::Duration;
use rand::Rng;
use std::sync::Arc;
use tokio::sync::Semaphore;

const TARGET_PORT: u16 = 5552; // Tier 2: Home ASICs
const CONCURRENT_WORKERS: usize = 4500; // Pushing right up against the 5000 connection limit
const SHARES_PER_SECOND: u64 = 8; // Aggressive erratic firing rate

#[tokio::main]
async fn main() {
    println!("🧛 BOOTING VAMPIRE LOAD-TESTER...");
    println!("Targeting Port: {}", TARGET_PORT);
    println!("Deploying {} Concurrent Worker Threads...", CONCURRENT_WORKERS);

    let semaphore = Arc::new(Semaphore::new(CONCURRENT_WORKERS));
    let mut handles = vec![];

    for i in 0..CONCURRENT_WORKERS {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let worker_name = format!("kaspa:q_vampire_wallet.vamp_rig_{:04}", i);

        handles.push(tokio::spawn(async move {
            if let Err(_e) = simulate_asic_worker(worker_name.clone(), TARGET_PORT).await {
                // Silently ignore connection drops to focus on server survival metrics
            }
            drop(permit);
        }));

        // Micro-jitter to prevent localhost TCP port exhaustion during the initial handshake
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    println!("🦇 ALL VAMPIRES DEPLOYED. WATCH THE SERVER FOR VARDIFF RETARGETING...");
    
    for handle in handles {
        let _ = handle.await;
    }
}

async fn simulate_asic_worker(worker_name: String, port: u16) -> anyhow::Result<()> {
    let stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    // ==========================================
    // 1. Subscribe Phase
    // ==========================================
    let sub_req = json!({
        "id": 1,
        "method": "mining.subscribe",
        "params": ["VampireMiner/1.0"]
    }).to_string() + "\n";
    write_half.write_all(sub_req.as_bytes()).await?;
    
    reader.read_line(&mut line).await?;
    line.clear();
    reader.read_line(&mut line).await?; // Catch extranonce injection
    line.clear();

    // ==========================================
    // 2. Authorize Phase
    // ==========================================
    let auth_req = json!({
        "id": 2,
        "method": "mining.authorize",
        "params": [worker_name, "password"]
    }).to_string() + "\n";
    write_half.write_all(auth_req.as_bytes()).await?;
    
    reader.read_line(&mut line).await?;
    line.clear();

    let mut current_job = String::from("vampire_dummy_job");
    let mut current_diff = 256.0;

    // ==========================================
    // 3. Execution & Retargeting Loop
    // ==========================================
    loop {
        tokio::select! {
            // Asynchronously read incoming server messages (Jobs and VarDiff adjustments)
            res = reader.read_line(&mut line) => {
                if res? == 0 { break; }
                if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line) {
                    if msg["method"] == "mining.notify" {
                        if let Some(params) = msg["params"].as_array() {
                            if let Some(job_id) = params[0].as_str() {
                                current_job = job_id.to_string();
                            }
                        }
                    } else if msg["method"] == "mining.set_difficulty" {
                        if let Some(params) = msg["params"].as_array() {
                            if let Some(new_diff) = params[0].as_f64() {
                                current_diff = new_diff;
                                println!("🔄 VARDIFF RETARGET OBSERVED: {} -> New Diff: {}", worker_name, current_diff);
                            }
                        }
                    }
                }
                line.clear();
            }

            // Rapid-fire mock share submission decoupled from actual hashing (Vampire Attack)
            _ = tokio::time::sleep(Duration::from_millis(1000 / SHARES_PER_SECOND)) => {
                let mock_nonce = format!("{:016x}", rand::thread_rng().gen::<u64>());
                let submit_req = json!({
                    "id": 4,
                    "method": "mining.submit",
                    "params": [worker_name, current_job, mock_nonce]
                }).to_string() + "\n";
                
                if write_half.write_all(submit_req.as_bytes()).await.is_err() {
                    break;
                }
            }
        }
    }

    Ok(())
}