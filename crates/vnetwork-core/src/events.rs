use crate::state::NetworkLedgerState;
use vnetwork_types::*;

pub fn verify_event_chain(events: &[LedgerEvent]) -> VResult<bool> {
    let mut prev_hash: Option<String> = None;
    for (idx, ev) in events.iter().enumerate() {
        let expected_seq = (idx as u64) + 1;
        if ev.sequence != expected_seq {
            return Err(VNetworkError::Validation(format!(
                "event sequence gap at index {idx}: expected {expected_seq}, got {}",
                ev.sequence
            )));
        }
        if !ev.verify_hashes()? {
            return Err(VNetworkError::Validation(format!(
                "event hash integrity check failed for {}",
                ev.event_id
            )));
        }
        if let Some(prev) = &prev_hash {
            if !ev.parent_hashes.contains(prev) {
                return Err(VNetworkError::Validation(format!(
                    "event {} missing expected parent hash {prev}",
                    ev.event_id
                )));
            }
        }
        prev_hash = Some(ev.event_hash.clone());
    }
    Ok(true)
}

pub fn events_for_entity<'a>(
    state: &'a NetworkLedgerState,
    entity_kind: Option<&str>,
    entity_id: &str,
) -> Vec<&'a LedgerEvent> {
    state
        .events
        .iter()
        .filter(|e| {
            let kind_ok = entity_kind.is_none_or(|k| e.entity_kind == k);
            kind_ok && e.entity_id == entity_id
        })
        .collect()
}
