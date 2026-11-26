use crate::config::{load_cli_identity, load_cli_state, save_cli_state};
use std::path::PathBuf;
use vnetwork_sdk::VectorNetworkClient;
use vnetwork_types::ParticipationLevel;

pub async fn run_join(
    scopes: Vec<String>,
    auth_file: Option<PathBuf>,
    passphrase: Option<&str>,
    allow_plaintext_fallback: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = load_cli_state()?;
    let id = load_cli_identity(&state, passphrase, allow_plaintext_fallback)?;
    let mut parsed_scopes = Vec::new();
    for s in scopes {
        for part in s.split(',') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            let lvl = ParticipationLevel::parse(trimmed).ok_or_else(|| {
                format!(
                    "invalid participation scope `{trimmed}`; expected NETWORK, SPACE, REGION, WALLET, or TOKEN"
                )
            })?;
            parsed_scopes.push(lvl);
        }
    }
    if parsed_scopes.is_empty() {
        parsed_scopes = vec![ParticipationLevel::Network];
    }
    let scope_authorizations: Vec<serde_json::Value> = if let Some(path) = auth_file {
        let raw = std::fs::read_to_string(&path)?;
        serde_json::from_str(&raw)?
    } else {
        Vec::new()
    };
    let mut client = VectorNetworkClient::new(&state.endpoint, id);
    if let Some(net) = &state.network_id {
        client = client.with_expected_network(net);
    }
    let res = client
        .join_with_authorizations(parsed_scopes, scope_authorizations)
        .await?;
    save_cli_state(&state)?;
    println!("{}", serde_json::to_string_pretty(&res)?);
    Ok(())
}
