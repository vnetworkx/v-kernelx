use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use vnetwork_sdk::ClientIdentity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliState {
    pub endpoint: String,
    pub network_id: Option<String>,
    pub identity: Option<ClientIdentity>,
    pub nonce: u64,
}

impl Default for CliState {
    fn default() -> Self {
        Self {
            endpoint: std::env::var("VNETWORK_ENDPOINT")
                .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string()),
            network_id: None,
            identity: None,
            nonce: 1,
        }
    }
}

pub fn cli_state_path() -> PathBuf {
    let dir = std::env::var("VNETWORK_CLI_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".vnetwork"))
                .unwrap_or_else(|_| PathBuf::from(".vnetwork"))
        });
    dir.join("cli.json")
}

pub fn load_cli_state() -> CliState {
    let path = cli_state_path();
    if path.exists() {
        if let Ok(raw) = fs::read_to_string(&path) {
            if let Ok(s) = serde_json::from_str::<CliState>(&raw) {
                return s;
            }
        }
    }
    CliState::default()
}

pub fn save_cli_state(state: &CliState) -> Result<(), Box<dyn std::error::Error>> {
    let path = cli_state_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(state)?;
    fs::write(path, json)?;
    Ok(())
}
