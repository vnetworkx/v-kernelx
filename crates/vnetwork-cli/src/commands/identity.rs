use crate::config::{load_cli_state, save_cli_state};
use vnetwork_sdk::ClientIdentity;

pub fn run_identity_create(name: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = load_cli_state();
    let id = ClientIdentity::generate(name.unwrap_or_else(|| "vn-participant".to_string()));
    let summary = serde_json::json!({
        "participant_id": id.participant_id,
        "participant_pubkey": id.participant_key.public_key_hex,
        "node_id": id.node_id,
        "node_pubkey": id.node_key.public_key_hex,
        "display_name": id.display_name,
    });
    state.identity = Some(id);
    state.nonce = 1;
    save_cli_state(&state)?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

pub fn run_identity_show() -> Result<(), Box<dyn std::error::Error>> {
    let state = load_cli_state();
    let id = state
        .identity
        .ok_or("no identity created yet; run `vn identity create`")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "participant_id": id.participant_id,
            "participant_pubkey": id.participant_key.public_key_hex,
            "node_id": id.node_id,
            "node_pubkey": id.node_key.public_key_hex,
            "display_name": id.display_name,
        }))?
    );
    Ok(())
}
