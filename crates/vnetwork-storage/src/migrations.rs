use crate::transactions::atomic_write_json;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use vnetwork_types::*;

pub const INITIAL_MIGRATION_SQL: &str = include_str!("../migrations/0001_initial.sql");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationRecord {
    pub version: u32,
    pub name: String,
    pub checksum: String,
    pub applied_at_ms: u64,
}

pub fn run_migrations(data_dir: &Path, now_ms: u64) -> VResult<Vec<MigrationRecord>> {
    fs::create_dir_all(data_dir).map_err(|e| VNetworkError::Storage(e.to_string()))?;
    let migrations_path = data_dir.join("migrations.json");
    let mut records: Vec<MigrationRecord> = if migrations_path.exists() {
        let raw = fs::read_to_string(&migrations_path)
            .map_err(|e| VNetworkError::Storage(e.to_string()))?;
        serde_json::from_str(&raw).map_err(|e| VNetworkError::Storage(e.to_string()))?
    } else {
        Vec::new()
    };

    let checksum = blake3_hex(INITIAL_MIGRATION_SQL.as_bytes());
    if !records.iter().any(|r| r.version == 1) {
        records.push(MigrationRecord {
            version: 1,
            name: "0001_initial.sql".to_string(),
            checksum,
            applied_at_ms: now_ms,
        });
        atomic_write_json(&migrations_path, &records)?;
    }

    Ok(records)
}
