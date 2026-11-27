use crate::config::{load_cli_identity, load_cli_state, save_cli_state};
use std::path::PathBuf;
use vnetwork_sdk::VectorNetworkClient;

pub async fn run_program_submit(
    file: PathBuf,
    passphrase: Option<&str>,
    allow_plaintext_fallback: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = load_cli_state()?;
    let id = load_cli_identity(&state, passphrase, allow_plaintext_fallback)?;
    let mut client = VectorNetworkClient::new(&state.endpoint, id);
    client.set_nonce(state.nonce);
    if let Some(net) = &state.network_id {
        client = client.with_expected_network(net);
    }
    // Reserve and persist the nonce before sending the signed request. A timeout
    // may occur after the node commits it; saving only after a successful response
    // would then reuse a consumed nonce on the next CLI invocation.
    state.nonce = state
        .nonce
        .checked_add(1)
        .ok_or("CLI request nonce exhausted")?;
    save_cli_state(&state)?;
    let sub = client.submit_vx_file(&file).await?;
    println!("{}", serde_json::to_string_pretty(&sub)?);
    Ok(())
}
