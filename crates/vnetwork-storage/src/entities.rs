use crate::indexes::{build_entity_index, StorageIndex};
use vnetwork_core::state::NetworkLedgerState;
use vnetwork_types::*;

pub fn summarize_persisted_entities(state: &NetworkLedgerState) -> VResult<StorageIndex> {
    build_entity_index(state)
}
