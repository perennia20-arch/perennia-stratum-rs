use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use bytes::Bytes;
use crate::kaspad_client::protowire::RpcBlock;
use serde_json::json;
use dashmap::DashMap;

use kaspa_hashes::Hash;
use kaspa_consensus_core::header::Header;
use kaspa_math::Uint192; 
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, Duration};
use std::fmt::Write; // ⚡ REQUIRED TO BUILD THE 80-CHAR ICERIVER HEX STRING

static JOB_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct StratumJob {
    pub job_id: String,
    pub payload: Arc<Bytes>,
}

pub struct JobManager {
    pub job_tx: broadcast::Sender<StratumJob>,
    pub active_jobs: DashMap<String, (Header, RpcBlock)>,
    pub block_submit_tx: mpsc::Sender<RpcBlock>,
    pub job_timestamps: DashMap<String, Instant>,
    pub cached_job: RwLock<Option<Arc<Bytes>>>, 
}

impl JobManager {
    pub fn new() -> (Arc<Self>, broadcast::Receiver<StratumJob>, mpsc::Receiver<RpcBlock>) {
        let (job_tx, job_rx) = broadcast::channel(1024);
        let (block_submit_tx, block_submit_rx) = mpsc::channel(100);
        
        let manager = Arc::new(Self { 
            job_tx,
            active_jobs: DashMap::new(),
            job_timestamps: DashMap::new(),
            block_submit_tx,
            cached_job: RwLock::new(None),
        });

        let gc_manager = manager.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            loop {
                interval.tick().await;
                let now = Instant::now();
                let mut stale_keys = Vec::new();

                for entry in gc_manager.job_timestamps.iter() {
                    if now.duration_since(*entry.value()) > Duration::from_secs(120) {
                        stale_keys.push(entry.key().clone());
                    }
                }

                for key in stale_keys {
                    gc_manager.active_jobs.remove(&key);
                    gc_manager.job_timestamps.remove(&key);
                }
            }
        });

        (manager, job_rx, block_submit_rx)
    }

    pub fn process_new_block(&self, block: RpcBlock) {
        if let Some(rpc_header) = &block.header {
            let unique_id = JOB_COUNTER.fetch_add(1, Ordering::SeqCst);
            let job_id = format!("{:04x}", unique_id & 0xFFFF); 

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

            self.active_jobs.insert(job_id.clone(), (consensus_header.clone(), block.clone()));
            self.job_timestamps.insert(job_id.clone(), Instant::now()); 

            // 1. EXACT BRIDGE CRYPTOGRAPHY: Hash the state with Time = 0 and Nonce = 0
            let pre_pow_hash = kaspa_consensus_core::hashing::header::hash_override_nonce_time(
                &consensus_header, 
                0, 
                0
            );
            let hb = pre_pow_hash.as_bytes();

            // 2. THE BIG JOB STRING: IceRiver demands a single 80-char hex string (32-byte Hash + 8-byte LE Timestamp)
            let mut large_job_param = String::with_capacity(80);
            
            for b in hb {
                write!(&mut large_job_param, "{:02x}", b).unwrap();
            }
            
            let ts = rpc_header.timestamp as u64;
            let ts_bytes = ts.to_le_bytes();
            for b in &ts_bytes {
                write!(&mut large_job_param, "{:02x}", b).unwrap();
            }

            // 3. THE ICERIVER PAYLOAD: Exactly two elements in the array. No booleans, no integer arrays!
            let notify_payload = json!({
                "id": null,
                "method": "mining.notify",
                "params": [
                    job_id,
                    large_job_param
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
        }
    }
}