use serde::Deserialize;
use std::fs;
use anyhow::{Context, Result};

#[derive(Debug, Deserialize, Clone)]
pub struct StratumConfig {
    pub stratum_port: String,
    pub kaspad_address: String,
    pub mining_address: String,
    pub starting_diff: f64,
    pub min_share_diff: f64,
    pub var_diff: bool,
    pub shares_per_min: u32,
    pub extranonce_size: usize,
    pub prom_port: String,
    pub print_stats: bool,
}

impl StratumConfig {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file at {}", path))?;
        
        let config: StratumConfig = serde_yaml::from_str(&content)
            .context("Failed to parse YAML configuration")?;
            
        if config.extranonce_size != 2 {
            anyhow::bail!("FATAL ARCHITECTURE RULE: extranonce_size MUST be exactly 2.");
        }
            
        Ok(config)
    }
}