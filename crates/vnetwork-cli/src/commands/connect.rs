use crate::config::{load_cli_state, save_cli_state};
use vnetwork_sdk::{ClientIdentity, VectorNetworkClient};

pub async fn run_connect(
    network: Option<String>,
    endpoint: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = load_cli_state();
    if let Some(ep) = endpoint {
        state.endpoint = ep;
    }
    let id = state
        .identity
        .clone()
        .unwrap_or_else(|| ClientIdentity::generate("vn-cli-temp"));
    let mut client = VectorNetworkClient::new(&state.endpoint, id);
    if let Some(n) = &network {
        client = client.with_expected_network(n);
    }
    let info = client.connect().await?;
    state.network_id = Some(info.network_id.clone());
    save_cli_state(&state)?;
    println!("{}", serde_json::to_string_pretty(&info.raw)?);
    Ok(())
}
