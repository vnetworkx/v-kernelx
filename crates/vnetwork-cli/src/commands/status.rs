use crate::config::load_cli_state;
use vnetwork_sdk::{ClientIdentity, VectorNetworkClient};

pub async fn run_participation_status() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_cli_state()?;
    let meta = state
        .identity_metadata
        .ok_or("no local identity found; run `vn identity create` first")?;
    let client = VectorNetworkClient::new(&state.endpoint, ClientIdentity::generate("vn-read"));
    let val = client
        .get_json(&format!("/v1/participants/{}/scope", meta.participant_id))
        .await?;
    println!("{}", serde_json::to_string_pretty(&val)?);
    Ok(())
}

pub async fn run_network_info() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_cli_state()?;
    let client = VectorNetworkClient::new(&state.endpoint, ClientIdentity::generate("vn-info"));
    let val = client.get_json("/v1/network/info").await?;
    println!("{}", serde_json::to_string_pretty(&val)?);
    Ok(())
}

pub async fn run_ledger_verify() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_cli_state()?;
    let client = VectorNetworkClient::new(&state.endpoint, ClientIdentity::generate("vn-ledger"));
    let val = client.get_json("/v1/ledger/proofs").await?;
    println!("{}", serde_json::to_string_pretty(&val)?);
    Ok(())
}

pub async fn run_ledger_replay() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_cli_state()?;
    let client = VectorNetworkClient::new(&state.endpoint, ClientIdentity::generate("vn-replay"));
    let val = client.verify_ledger_replay().await?;
    println!("{}", serde_json::to_string_pretty(&val)?);
    Ok(())
}
