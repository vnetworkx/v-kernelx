use vnetwork_consensus::{sign_consensus_vote, QuorumTracker, ValidatorMembership};
use vnetwork_types::*;

#[test]
fn test_bft_supermajority_quorum_and_equivocation() {
    let keys: Vec<KeypairMaterial> = (0..4).map(|_| KeypairMaterial::generate("validator")).collect();
    let validators: Vec<ConsensusValidator> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| ConsensusValidator {
            validator_id: format!("val_{}", i + 1),
            node_id: format!("nod_val_{}", i + 1),
            validator_pubkey_hex: k.public_key_hex.clone(),
            weight: 100,
            active: true,
            joined_epoch: 1,
        })
        .collect();

    let membership = ValidatorMembership::new(validators.clone(), 6667);
    assert_eq!(membership.total_active_weight(), 400);
    // ceil(400 * 6667 / 10000) = 267 -> 3 validators (weight 300) required; 2 (200) insufficient!
    assert_eq!(membership.required_weight(), 267);

    let mut proposal = ConsensusProposal {
        proposal_id: "prop_test_1".to_string(),
        network_id: "vnetwork-devnet-1".to_string(),
        height: 1,
        round: 1,
        epoch: 1,
        proposer_validator_id: "val_1".to_string(),
        pre_state_root: "pre".to_string(),
        post_state_root: "post".to_string(),
        events: vec![],
        program_id: None,
        tx_id: None,
        program_source_bundle: None,
        nonce_binding: None,
        timestamp_ms: 1_000,
        proposer_signature: String::new(),
    };
    proposal.proposer_signature = keys[0]
        .sign(&proposal.canonical_signing_bytes().unwrap())
        .unwrap();

    let mut tracker = QuorumTracker::new();
    tracker.register_proposal(proposal.clone());

    let v1 = sign_consensus_vote(&proposal, &validators[0], &keys[0], true, 1_001).unwrap();
    let v2 = sign_consensus_vote(&proposal, &validators[1], &keys[1], true, 1_002).unwrap();
    let v3 = sign_consensus_vote(&proposal, &validators[2], &keys[2], true, 1_003).unwrap();

    assert!(tracker.record_vote(&membership, v1, 1_001).unwrap().is_none());
    // 2/4 = 200 < 267 -> still no QC
    assert!(tracker.record_vote(&membership, v2, 1_002).unwrap().is_none());
    // 3/4 = 300 >= 267 -> QC formed!
    let qc = tracker.record_vote(&membership, v3, 1_003).unwrap().expect("3/4 should form QC");
    assert_eq!(qc.approving_weight, 300);
    assert_eq!(qc.votes.len(), 3);

    // Equivocation test: validator 1 voting on a different proposal at same height/round triggers equivocation
    let mut conflicting_prop = proposal.clone();
    conflicting_prop.proposal_id = "prop_conflict".to_string();
    let bad_vote = sign_consensus_vote(&conflicting_prop, &validators[0], &keys[0], true, 1_004).unwrap();
    let eq_err = tracker.record_vote(&membership, bad_vote, 1_004).unwrap_err();
    assert!(eq_err.to_string().contains("equivocation"));
    assert_eq!(tracker.equivocations().len(), 1);
}
