use crate::config::{load_cli_state, save_cli_state};
use std::path::PathBuf;
use vnetwork_sdk::VectorNetworkClient;

pub async fn run_program_submit(file: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = load_cli_state();
    let id = state
        .identity
        .clone()
        .ok_or("no local identity; run `vn identity create` and `vn join` first")?;
    let mut client = VectorNetworkClient::new(&state.endpoint, id);
    client.set_nonce(state.nonce);
    if let Some(net) = &state.network_id {
        client = client.with_expected_network(net);
    }
    let sub = client.submit_vx_file(&file).await?;
    state.nonce = client.next_nonce();
    save_cli_state(&state)?;
    println!("{}", serde_json::to_string_pretty(&sub)?);
    Ok(())
}
