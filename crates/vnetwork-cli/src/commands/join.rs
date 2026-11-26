use crate::config::{load_cli_state, save_cli_state};
use vnetwork_sdk::VectorNetworkClient;
use vnetwork_types::ParticipationLevel;

pub async fn run_join(scopes: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let state = load_cli_state();
    let id = state
        .identity
        .clone()
        .ok_or("no local identity found; run `vn identity create` first")?;
    let mut parsed_scopes = Vec::new();
    for s in scopes {
        for part in s.split(',') {
            if let Some(lvl) = ParticipationLevel::parse(part) {
                parsed_scopes.push(lvl);
            }
        }
    }
    if parsed_scopes.is_empty() {
        parsed_scopes = vec![
            ParticipationLevel::Network,
            ParticipationLevel::Space,
            ParticipationLevel::Region,
            ParticipationLevel::Wallet,
            ParticipationLevel::Token,
        ];
    }
    let mut client = VectorNetworkClient::new(&state.endpoint, id);
    if let Some(net) = &state.network_id {
        client = client.with_expected_network(net);
    }
    let res = client.join(parsed_scopes).await?;
    save_cli_state(&state)?;
    println!("{}", serde_json::to_string_pretty(&res)?);
    Ok(())
}
