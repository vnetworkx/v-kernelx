use crate::transactions::atomic_write_json;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use vnetwork_core::state::NetworkLedgerState;
use vnetwork_types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityCounts {
    pub spaces: usize,
    pub regions: usize,
    pub wallets: usize,
    pub tokens: usize,
    pub contracts: usize,
    pub loans: usize,
    pub participants: usize,
    pub nodes: usize,
    pub events: usize,
    pub certificates: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageIndex {
    pub network_id: String,
    pub height: u64,
    pub state_root: String,
    pub counts: EntityCounts,
    pub token_symbols: BTreeMap<String, String>,
    pub space_regions: BTreeMap<String, Vec<String>>,
    pub region_wallets: BTreeMap<String, Vec<String>>,
}

pub fn build_entity_index(state: &NetworkLedgerState) -> VResult<StorageIndex> {
    let mut token_symbols = BTreeMap::new();
    for t in state.tokens.values() {
        token_symbols.insert(t.symbol.clone(), t.token_id.clone());
    }
    let mut space_regions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for r in state.regions.values() {
        space_regions
            .entry(r.space_id.clone())
            .or_default()
            .push(r.region_id.clone());
    }
    let mut region_wallets: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for w in state.wallets.values() {
        region_wallets
            .entry(w.region_id.clone())
            .or_default()
            .push(w.wallet_id.clone());
    }
    Ok(StorageIndex {
        network_id: state.network_id.clone(),
        height: state.height,
        state_root: state.compute_state_root()?,
        counts: EntityCounts {
            spaces: state.spaces.len(),
            regions: state.regions.len(),
            wallets: state.wallets.len(),
            tokens: state.tokens.len(),
            contracts: state.contracts.len(),
            loans: state.loans.len(),
            participants: state.participants.len(),
            nodes: state.nodes.len(),
            events: state.events.len(),
            certificates: state.certificates.len(),
        },
        token_symbols,
        space_regions,
        region_wallets,
    })
}

pub fn persist_entity_index(data_dir: &Path, state: &NetworkLedgerState) -> VResult<StorageIndex> {
    let idx = build_entity_index(state)?;
    atomic_write_json(&data_dir.join("indexes.json"), &idx)?;
    Ok(idx)
}
