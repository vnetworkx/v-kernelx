use crate::config::load_cli_state;
use vnetwork_sdk::{ClientIdentity, VectorNetworkClient};

pub async fn run_query(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let state = load_cli_state()?;
    let client = VectorNetworkClient::new(&state.endpoint, ClientIdentity::generate("vn-query"));
    let val = client.get_json(path).await?;
    println!("{}", serde_json::to_string_pretty(&val)?);
    Ok(())
}

pub async fn run_reconstruct(kind: &str, id_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let state = load_cli_state()?;
    let client =
        VectorNetworkClient::new(&state.endpoint, ClientIdentity::generate("vn-reconstruct"));
    let val = client.verify_reconstruction(kind, id_str).await?;
    println!("{}", serde_json::to_string_pretty(&val)?);
    Ok(())
}
