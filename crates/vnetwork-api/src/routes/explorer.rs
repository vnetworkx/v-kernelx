use crate::state::ApiAppState;
use axum::extract::State;
use axum::Json;

pub async fn explorer_network(State(app): State<ApiAppState>) -> Json<serde_json::Value> {
    let state = app.backend.state_snapshot().await;
    let status = app.backend.network_status().await;
    let consensus = app.backend.consensus_status().await;
    let peers = app.backend.list_peers_and_nodes().await;
    let spaces: Vec<_> = state.spaces.values().collect();
    let regions: Vec<_> = state.regions.values().collect();
    let wallets: Vec<_> = state.wallets.values().collect();
    let tokens: Vec<_> = state.tokens.values().collect();
    let balances: Vec<_> = state.balances.values().collect();
    let contracts: Vec<_> = state.contracts.values().collect();
    let loans: Vec<_> = state.loans.values().collect();
    let programs: Vec<_> = state.programs.values().collect();
    let certificates: Vec<_> = state.certificates.values().collect();

    Json(serde_json::json!({
        "status": status,
        "consensus": consensus,
        "peers": peers,
        "spaces": spaces,
        "regions": regions,
        "wallets": wallets,
        "tokens": tokens,
        "balances": balances,
        "contracts": contracts,
        "loans": loans,
        "programs": programs,
        "events": state.events,
        "certificates": certificates,
        "state_root": state.compute_state_root().unwrap_or_default(),
        "replay_hash": state.compute_replay_hash(),
    }))
}
