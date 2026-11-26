use crate::config::load_cli_state;
use vnetwork_sdk::{ClientIdentity, VectorNetworkClient};

pub async fn run_tx_status(tx_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let state = load_cli_state();
    let id = state
        .identity
        .unwrap_or_else(|| ClientIdentity::generate("vn-tx"));
    let client = VectorNetworkClient::new(&state.endpoint, id);
    let val = client
        .get_json(&format!("/v1/transactions/{tx_id}"))
        .await?;
    println!("{}", serde_json::to_string_pretty(&val)?);
    Ok(())
}
