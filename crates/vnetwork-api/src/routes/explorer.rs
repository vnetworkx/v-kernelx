use crate::state::ApiAppState;
use axum::extract::State;
use axum::Json;
use std::collections::BTreeMap;
use vnetwork_core::supply::compute_token_supply_breakdown;

pub async fn explorer_network(State(app): State<ApiAppState>) -> Json<serde_json::Value> {
    let state = app.backend.state_snapshot().await;
    let health = app.backend.health_report().await;
    let info = app.backend.network_info().await;
    let status = app.backend.network_status().await;
    let consensus = app.backend.consensus_status().await;
    let peers = app.backend.list_peers_and_nodes().await;
    let proofs = app.backend.verify_ledger_proofs().await.ok();
    let replay = app.backend.verify_replay().await.ok();
    let equivocations = app.backend.list_equivocations().await;

    let spaces: Vec<_> = state.spaces.values().collect();
    let regions: Vec<_> = state.regions.values().collect();
    let wallets: Vec<_> = state.wallets.values().collect();
    let tokens: Vec<_> = state.tokens.values().collect();
    let balances: Vec<_> = state.balances.values().collect();
    let contracts: Vec<_> = state.contracts.values().collect();
    let loans: Vec<_> = state.loans.values().collect();
    let programs: Vec<_> = state.programs.values().collect();
    let certificates: Vec<_> = state.certificates.values().collect();

    let mut supply_breakdowns = BTreeMap::new();
    for token in &tokens {
        if let Ok(b) = compute_token_supply_breakdown(&state, &token.token_id) {
            supply_breakdowns.insert(token.token_id.clone(), b);
        }
    }

    Json(serde_json::json!({
        "health": health,
        "network_info": info,
        "status": status,
        "consensus": consensus,
        "equivocations": equivocations,
        "peers": peers,
        "proofs": proofs,
        "replay": replay,
        "storage_engine": "vnetwork-wal-json",
        "drain_policy": state.drain_policy,
        "spaces": spaces,
        "regions": regions,
        "wallets": wallets,
        "tokens": tokens,
        "balances": balances,
        "supply_breakdowns": supply_breakdowns,
        "contracts": contracts,
        "loans": loans,
        "programs": programs,
        "events": state.events,
        "event_history_root": state.event_history_root,
        "certificates": certificates,
        "state_root": state.compute_state_root().unwrap_or_default(),
        "replay_hash": state.compute_replay_hash(),
    }))
}
