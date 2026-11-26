use crate::config::load_cli_state;
use vnetwork_sdk::{ClientIdentity, VectorNetworkClient};

pub async fn run_node_status() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_cli_state()?;
    let client = VectorNetworkClient::new(&state.endpoint, ClientIdentity::generate("vn-node"));
    let val = client.get_json("/v1/nodes").await?;
    println!("{}", serde_json::to_string_pretty(&val)?);
    Ok(())
}
