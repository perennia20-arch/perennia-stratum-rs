// src/job_manager/mod.rs

use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use bytes::Bytes;
use crate::kaspad_client::protowire::RpcBlock;
use serde_json::json;
use dashmap::{DashMap, DashSet};

use kaspa_hashes::Hash;
use kaspa_consensus_core::header::Header;
use kaspa_math::Uint192; 
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, Duration};
use std::fmt::Write;

static JOB_COUNTER: AtomicU64 = AtomicU64::new(1);

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct StratumJob {
    pub job_id: String,
    pub payload: Arc<Bytes>,
}

#[derive(Clone, Debug)]
pub struct ActiveJob {
    pub header: Header,
    pub block: RpcBlock,
    pub network_diff: f64,
    pub reward_sompi: u64,
}

#[derive(Clone, Debug)]
pub struct PendingBlockSubmission {
    pub block: RpcBlock,
    pub block_hash: String,
    pub worker: String,
    pub nonce: u64,
    pub network_diff: f64,
    pub reward_sompi: u64,
}

/// Computes the exact Kaspa consensus difficulty from the block header's compact `bits` field
/// matching kaspad's `get_difficulty_ratio` against maximum target `0x207fffff`.
pub fn difficulty_from_bits(bits: u32) -> f64 {
    let exponent = (bits >> 24) as i32;
    let mantissa = (bits & 0x00ff_ffff) as f64;
    if mantissa <= 0.0 {
        return 0.0;
    }
    (0x007f_ffff as f64 / mantissa) * 2.0_f64.powi(8 * (0x20 - exponent))
}

/// Extracts the consensus block reward in sompi from a block's coinbase transaction.
/// Uses the exact 8-byte little-endian chromatic subsidy encoded in bytes [8..16] of the
/// Kaspa coinbase payload, or the single-block coinbase output when fees are included.
pub fn extract_coinbase_reward_sompi(block: &RpcBlock) -> u64 {
    if let Some(coinbase_tx) = block.transactions.first() {
        let mut payload_subsidy_sompi = 0u64;
        if !coinbase_tx.payload.is_empty() {
            if let Ok(payload_bytes) = hex::decode(&coinbase_tx.payload) {
                if payload_bytes.len() >= 16 {
                    let mut subsidy_bytes = [0u8; 8];
                    subsidy_bytes.copy_from_slice(&payload_bytes[8..16]);
                    payload_subsidy_sompi = u64::from_le_bytes(subsidy_bytes);
                }
            }
        }

        if coinbase_tx.outputs.len() == 1 {
            let single_output = coinbase_tx.outputs[0].amount;
            if payload_subsidy_sompi > 0 {
                // If the single output represents a single block's subsidy + tx fees (not a multi-block mergeset sum)
                if single_output >= payload_subsidy_sompi && single_output < payload_subsidy_sompi.saturating_mul(2) {
                    return single_output;
                }
                return payload_subsidy_sompi;
            }
            return single_output;
        }

        if payload_subsidy_sompi > 0 {
            return payload_subsidy_sompi;
        }
    }
    0
}

pub struct JobManager {
    pub job_tx: broadcast::Sender<StratumJob>,
    pub active_jobs: DashMap<String, ActiveJob>,
    pub submitted_nonces: DashMap<String, DashSet<u64>>,
    pub submitted_blocks: DashMap<String, Instant>,
    pub block_submit_tx: mpsc::Sender<PendingBlockSubmission>,
    pub job_timestamps: DashMap<String, Instant>,
    pub cached_job: RwLock<Option<Arc<Bytes>>>,
    pub latest_network_diff_bits: AtomicU64,
    pub latest_reward_sompi: AtomicU64,
}

impl JobManager {
    pub fn new() -> (Arc<Self>, broadcast::Receiver<StratumJob>, mpsc::Receiver<PendingBlockSubmission>) {
        let (job_tx, job_rx) = broadcast::channel(1024);
        let (block_submit_tx, block_submit_rx) = mpsc::channel(100);
        
        let manager = Arc::new(Self { 
            job_tx,
            active_jobs: DashMap::new(),
            submitted_nonces: DashMap::new(),
            submitted_blocks: DashMap::new(),
            job_timestamps: DashMap::new(),
            block_submit_tx,
            cached_job: RwLock::new(None),
            latest_network_diff_bits: AtomicU64::new(0.0_f64.to_bits()),
            latest_reward_sompi: AtomicU64::new(0),
        });

        let gc_manager = manager.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            loop {
                interval.tick().await;
                let now = Instant::now();
                let mut stale_keys = Vec::new();

                for entry in gc_manager.job_timestamps.iter() {
                    if now.duration_since(*entry.value()) > Duration::from_secs(300) {
                        stale_keys.push(entry.key().clone());
                    }
                }

                let active_count = gc_manager.active_jobs.len();
                if stale_keys.len() >= active_count && active_count > 0 {
                    stale_keys.sort_by_key(|k| gc_manager.job_timestamps.get(k).map(|v| *v).unwrap_or(now));
                    stale_keys.pop(); 
                }

                for key in stale_keys {
                    gc_manager.active_jobs.remove(&key);
                    gc_manager.submitted_nonces.remove(&key);
                    gc_manager.job_timestamps.remove(&key);
                }

                let mut stale_blocks = Vec::new();
                for entry in gc_manager.submitted_blocks.iter() {
                    if now.duration_since(*entry.value()) > Duration::from_secs(600) {
                        stale_blocks.push(entry.key().clone());
                    }
                }
                for bh in stale_blocks {
                    gc_manager.submitted_blocks.remove(&bh);
                }
            }
        });

        (manager, job_rx, block_submit_rx)
    }

    pub fn update_latest_network_diff(&self, diff: f64) {
        if diff > 0.0 {
            self.latest_network_diff_bits.store(diff.to_bits(), Ordering::Relaxed);
        }
    }

    pub fn get_latest_network_diff(&self) -> f64 {
        f64::from_bits(self.latest_network_diff_bits.load(Ordering::Relaxed))
    }

    pub fn update_latest_reward_sompi(&self, reward_sompi: u64) {
        if reward_sompi > 0 {
            self.latest_reward_sompi.store(reward_sompi, Ordering::Relaxed);
        }
    }

    pub fn get_latest_reward_sompi(&self) -> u64 {
        self.latest_reward_sompi.load(Ordering::Relaxed)
    }

    /// Atomically records a `(job_id, nonce)` submission. Returns `true` if the submission is new,
    /// or `false` if this exact `(job_id, nonce)` was already processed.
    pub fn register_submission(&self, job_id: &str, nonce: u64) -> bool {
        let set = self.submitted_nonces.entry(job_id.to_string()).or_insert_with(DashSet::new);
        set.insert(nonce)
    }

    /// Atomically records a candidate `block_hash`. Returns `true` if this block hash has not yet
    /// been submitted to the node.
    pub fn register_block_hash(&self, block_hash: &str) -> bool {
        if self.submitted_blocks.contains_key(block_hash) {
            return false;
        }
        self.submitted_blocks.insert(block_hash.to_string(), Instant::now()).is_none()
    }

    pub fn process_new_block(&self, block: RpcBlock) -> (f64, u64) {
        if let Some(rpc_header) = &block.header {
            let unique_id = JOB_COUNTER.fetch_add(1, Ordering::SeqCst);
            
            // Strictly numerical job ID to prevent IceRiver parser panics
            let job_id = format!("{:04}", unique_id % 10000); 

            let hash_merkle_root = Hash::from_str(&rpc_header.hash_merkle_root).expect("Invalid hash_merkle_root");
            let accepted_id_merkle_root = Hash::from_str(&rpc_header.accepted_id_merkle_root).expect("Invalid accepted_id_merkle_root");
            let utxo_commitment = Hash::from_str(&rpc_header.utxo_commitment).expect("Invalid utxo_commitment");
            let pruning_point = Hash::from_str(&rpc_header.pruning_point).expect("Invalid pruning_point");
            let blue_work = Uint192::from_hex(&rpc_header.blue_work).expect("Invalid blue_work string");

            let mut parents_by_level = vec![];
            for level in &rpc_header.parents {
                let level_hashes: Vec<Hash> = level.parent_hashes.iter()
                    .map(|h| Hash::from_str(h).expect("Invalid parent hash from node"))
                    .collect();
                parents_by_level.push(level_hashes);
            }

            let consensus_header = Header::new_finalized(
                rpc_header.version as u16,
                parents_by_level.try_into().expect("DAG Parent Compression Failed"),
                hash_merkle_root,
                accepted_id_merkle_root,
                utxo_commitment,
                rpc_header.timestamp as u64,
                rpc_header.bits,
                rpc_header.nonce,
                rpc_header.daa_score,
                blue_work,                
                rpc_header.blue_score,   
                pruning_point,
            );

            // Resolve per-block Kaspa network difficulty from template verbose_data or header.bits
            let template_diff = block
                .verbose_data
                .as_ref()
                .map(|v| v.difficulty)
                .filter(|&d| d > 0.0)
                .unwrap_or_else(|| difficulty_from_bits(rpc_header.bits));

            let network_diff = if template_diff > 0.0 {
                self.update_latest_network_diff(template_diff);
                template_diff
            } else {
                self.get_latest_network_diff()
            };

            let coinbase_reward_sompi = extract_coinbase_reward_sompi(&block);
            let reward_sompi = if self.get_latest_reward_sompi() > 0 {
                self.get_latest_reward_sompi()
            } else {
                coinbase_reward_sompi
            };

            // Reset nonce deduplication set for this recycled job_id slot before inserting the new job
            self.submitted_nonces.insert(job_id.clone(), DashSet::new());
            self.active_jobs.insert(
                job_id.clone(),
                ActiveJob {
                    header: consensus_header.clone(),
                    block: block.clone(),
                    network_diff,
                    reward_sompi,
                },
            );
            self.job_timestamps.insert(job_id.clone(), Instant::now()); 

            let pre_pow_hash = kaspa_consensus_core::hashing::header::hash_override_nonce_time(
                &consensus_header, 
                0, 
                0
            );
            let hb = pre_pow_hash.as_bytes();

            let mut large_job_param = String::with_capacity(80);
            
            for b in hb {
                write!(&mut large_job_param, "{:02x}", b).unwrap();
            }
            
            let ts = rpc_header.timestamp as u64;
            let ts_bytes = ts.to_le_bytes();
            for b in &ts_bytes {
                write!(&mut large_job_param, "{:02x}", b).unwrap();
            }

            let notify_payload = json!({
                "id": null,
                "method": "mining.notify",
                "params": [
                    job_id,
                    large_job_param,
                    true // Required flag for IceRiver ASICs
                ]
            });

            let mut json_payload = notify_payload.to_string();
            json_payload.push('\n');

            let bytes_payload = Arc::new(Bytes::from(json_payload));

            if let Ok(mut cache) = self.cached_job.write() {
                *cache = Some(Arc::clone(&bytes_payload));
            }

            let stratum_job = StratumJob {
                job_id: job_id.clone(),
                payload: bytes_payload,
            };

            let _ = self.job_tx.send(stratum_job);
            return (network_diff, coinbase_reward_sompi);
        }
        (self.get_latest_network_diff(), self.get_latest_reward_sompi())
    }
}