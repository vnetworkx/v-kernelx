use crate::config::{load_cli_state, save_cli_state, store_cli_identity};
use vnetwork_sdk::ClientIdentity;

pub fn run_identity_create(
    name: Option<String>,
    passphrase: Option<&str>,
    allow_plaintext_fallback: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = load_cli_state()?;
    let id = ClientIdentity::generate(name.unwrap_or_else(|| "vn-participant".to_string()));
    store_cli_identity(&mut state, &id, passphrase, allow_plaintext_fallback)?;
    state.nonce = 1;
    save_cli_state(&state)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&state.identity_metadata)?
    );
    Ok(())
}

pub fn run_identity_show() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_cli_state()?;
    let meta = state
        .identity_metadata
        .ok_or("no identity created yet; run `vn identity create`")?;
    println!("{}", serde_json::to_string_pretty(&meta)?);
    Ok(())
}
