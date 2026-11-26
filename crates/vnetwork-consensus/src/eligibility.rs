use crate::membership::ValidatorMembership;
use vnetwork_types::*;

pub fn verify_proposer_eligibility(
    membership: &ValidatorMembership,
    validator_id: &str,
) -> VResult<ConsensusValidator> {
    let v = membership.get(validator_id).ok_or_else(|| {
        VNetworkError::Consensus(format!(
            "proposer `{validator_id}` is not in validator set"
        ))
    })?;
    if !v.active || v.weight == 0 {
        return Err(VNetworkError::Consensus(format!(
            "validator `{validator_id}` is not active or has zero weight"
        )));
    }
    let _ = v.canonical_pubkey_bytes()?;
    Ok(v.clone())
}

pub fn verify_node_cannot_self_promote_validator(node: &NodeRecord) -> VResult<()> {
    if node.validator_eligible && node.node_kind != NodeKind::ValidatorNode {
        return Err(VNetworkError::Authorization(
            "non-validator node cannot claim validator eligibility".to_string(),
        ));
    }
    Ok(())
}
