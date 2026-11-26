use crate::config::load_cli_state;
use vnetwork_sdk::{ClientIdentity, VectorNetworkClient};

pub async fn run_participation_status() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_cli_state();
    let id = state
        .identity
        .ok_or("no local identity found; run `vn identity create` first")?;
    let client = VectorNetworkClient::new(&state.endpoint, id);
    let val = client.participant_status().await?;
    println!("{}", serde_json::to_string_pretty(&val)?);
    Ok(())
}

pub async fn run_network_info() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_cli_state();
    let id = state
        .identity
        .unwrap_or_else(|| ClientIdentity::generate("vn-info"));
    let client = VectorNetworkClient::new(&state.endpoint, id);
    let val = client.get_json("/v1/network/info").await?;
    println!("{}", serde_json::to_string_pretty(&val)?);
    Ok(())
}

pub async fn run_ledger_verify() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_cli_state();
    let id = state
        .identity
        .unwrap_or_else(|| ClientIdentity::generate("vn-ledger"));
    let client = VectorNetworkClient::new(&state.endpoint, id);
    let val = client.get_json("/v1/ledger/proofs").await?;
    println!("{}", serde_json::to_string_pretty(&val)?);
    Ok(())
}
