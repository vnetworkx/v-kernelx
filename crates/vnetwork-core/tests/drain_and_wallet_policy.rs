use vnetwork_core::drain::compute_scope_drain;
use vnetwork_core::engine::ProtocolEngine;
use vnetwork_core::identity::{
    canonical_join_signing_bytes, JoinNetworkRequest, SignedScopeAuthorization,
};
use vnetwork_core::loans::apply_execute_loan;
use vnetwork_core::state::GenesisConfig;
use vnetwork_core::supply::verify_token_supply_conservation;
use vnetwork_types::*;

fn single_val_qc(
    prop: &ConsensusProposal,
    val_kp: &KeypairMaterial,
    _qc_id: &str,
    ts: u64,
) -> QuorumCertificate {
    let mut vote = ConsensusVote {
        proposal_id: prop.proposal_id.clone(),
        proposal_digest: prop.proposal_digest.clone(),
        network_id: prop.network_id.clone(),
        genesis_commitment: prop.genesis_commitment.clone(),
        protocol_version: prop.protocol_version.clone(),
        height: prop.height,
        round: prop.round,
        epoch: prop.epoch,
        validator_set_hash: prop.validator_set_hash.clone(),
        consensus_parameters_hash: prop.consensus_parameters_hash.clone(),
        parent_commitment: prop.parent_commitment.clone(),
        pre_state_root: prop.pre_state_root.clone(),
        post_state_root: prop.post_state_root.clone(),
        operation_scope: prop.operation_scope.clone(),
        vote_phase: VotePhase::Commit,
        validator_id: "val_1".to_string(),
        validator_pubkey_hex: val_kp.public_key_hex.clone(),
        approve: true,
        timestamp_ms: ts,
        signature: String::new(),
    };
    vote.signature = val_kp
        .sign(&vote.canonical_signing_bytes().unwrap())
        .unwrap();
    let mut qc = QuorumCertificate {
        certificate_id: String::new(),
        proposal_id: prop.proposal_id.clone(),
        proposal_digest: prop.proposal_digest.clone(),
        network_id: prop.network_id.clone(),
        genesis_commitment: prop.genesis_commitment.clone(),
        protocol_version: prop.protocol_version.clone(),
        height: prop.height,
        round: prop.round,
        epoch: prop.epoch,
        validator_set_hash: prop.validator_set_hash.clone(),
        consensus_parameters_hash: prop.consensus_parameters_hash.clone(),
        parent_commitment: prop.parent_commitment.clone(),
        pre_state_root: prop.pre_state_root.clone(),
        post_state_root: prop.post_state_root.clone(),
        operation_scope: prop.operation_scope.clone(),
        vote_phase: VotePhase::Commit,
        ordered_event_ids: prop.ordered_event_ids(),
        event_hashes: prop.ordered_event_hashes(),
        total_weight: 100,
        approving_weight: 100,
        quorum_threshold_bps: DEFAULT_BFT_QUORUM_BPS,
        votes: vec![vote],
        finalized_at_ms: ts,
    };
    qc.finalize_certificate_id().unwrap();
    qc
}

fn sign_operation(
    actor: &KeypairMaterial,
    network_id: &str,
    nonce: u64,
    request_id: &str,
    ts: u64,
    op: &NetworkOperation,
) -> SignedRequestEnvelope {
    let payload_hash = blake3_hex(&canonical_json_bytes(op).unwrap());
    let mut env = SignedRequestEnvelope {
        actor_pubkey: actor.public_key_hex.clone(),
        network_id: network_id.to_string(),
        request_id: request_id.to_string(),
        nonce,
        timestamp_ms: ts,
        payload_hash,
        signature: String::new(),
    };
    let signing_bytes = SignedRequestEnvelope::canonical_signing_bytes(
        network_id,
        request_id,
        &actor.public_key_hex,
        nonce,
        ts,
        &env.payload_hash,
    )
    .unwrap();
    env.signature = actor.sign(&signing_bytes).unwrap();
    env
}

fn bootstrap_engine(policy: DrainPolicy) -> (ProtocolEngine, KeypairMaterial, KeypairMaterial) {
    let val_kp = KeypairMaterial::generate("validator");
    let genesis = GenesisConfig::for_profile(
        NetworkProfile::Development,
        "vector-devnet-1",
        "Drain Test",
        vec![ConsensusValidator {
            validator_id: "val_1".to_string(),
            node_id: "nod_val_1".to_string(),
            validator_pubkey_hex: val_kp.public_key_hex.clone(),
            weight: 100,
            active: true,
            joined_epoch: 1,
        }],
    )
    .with_drain_policy(policy);
    let mut engine = ProtocolEngine::new(genesis);

    let actor_kp = KeypairMaterial::generate("participant");
    let node_kp = KeypairMaterial::generate("node");
    let ch = engine.issue_challenge(100);
    // Genesis bootstrap grants only explicit Network governance. Further
    // Space/Region/Wallet/Token scopes must be delegated by their authorized
    // owners after those entities exist.
    let scopes = vec![ParticipationLevel::Network];
    let join_bytes = canonical_join_signing_bytes(
        &ch,
        &actor_kp.public_key_hex,
        &node_kp.public_key_hex,
        &scopes,
    )
    .unwrap();
    let mut auth = SignedScopeAuthorization {
        target_participant_pubkey: actor_kp.public_key_hex.clone(),
        grantor_pubkey: val_kp.public_key_hex.clone(),
        scopes: vec![ParticipationLevel::Network],
        target_id: None,
        expires_at_ms: None,
        authorization_basis: "genesis_governance".to_string(),
        signature: String::new(),
    };
    auth.signature = val_kp
        .sign(&auth.canonical_signing_bytes("vector-devnet-1").unwrap())
        .unwrap();

    let (_, _, prop, _) = engine
        .stage_participant_join(
            &JoinNetworkRequest {
                challenge_id: ch.challenge_id,
                participant_pubkey: actor_kp.public_key_hex.clone(),
                node_pubkey: node_kp.public_key_hex.clone(),
                display_name: "drain-tester".to_string(),
                node_kind: NodeKind::FullNode,
                requested_scopes: scopes,
                advertised_addresses: vec![],
                participant_signature: actor_kp.sign(&join_bytes).unwrap(),
                node_signature: node_kp.sign(&join_bytes).unwrap(),
                scope_authorizations: vec![auth],
            },
            "val_1",
            |b| val_kp.sign(b),
            101,
        )
        .unwrap();
    let qc = single_val_qc(&prop, &val_kp, "qc_join", 102);
    engine.commit_proposal_with_qc(&prop, &qc, 102).unwrap();
    (engine, val_kp, actor_kp)
}

#[test]
fn test_scope_drain_unconfigured_fails_closed_and_hierarchy_derives_exact_rates() {
    let w_a = WalletEntity {
        wallet_id: "wal_a".to_string(),
        name: "A".to_string(),
        region_id: "reg_1".to_string(),
        space_id: "spc_1".to_string(),
        ghost: false,
        owner_pubkey: "00".repeat(32),
        authorized_keys: Default::default(),
        approval_threshold: 1,
        receive_policy: WalletReceivePolicy::Open,
        created_at_ms: 1,
        version: 1,
    };
    let mut w_b_same_reg = w_a.clone();
    w_b_same_reg.wallet_id = "wal_b".to_string();

    let mut w_c_diff_reg = w_a.clone();
    w_c_diff_reg.wallet_id = "wal_c".to_string();
    w_c_diff_reg.region_id = "reg_2".to_string();

    let mut w_d_diff_spc = w_a.clone();
    w_d_diff_spc.wallet_id = "wal_d".to_string();
    w_d_diff_spc.region_id = "reg_3".to_string();
    w_d_diff_spc.space_id = "spc_2".to_string();

    // Unconfigured policy MUST fail closed (never invent default 200 bps)
    let unconfigured = DrainPolicy::unconfigured();
    assert!(compute_scope_drain(&unconfigured, &w_a, &w_b_same_reg, 10_000).is_err());

    let policy = DrainPolicy::new(
        ScopeDrainRate::ConfiguredBps(0),
        ScopeDrainRate::ConfiguredBps(10),
        ScopeDrainRate::ConfiguredBps(50),
        ScopeDrainRate::ConfiguredBps(150),
    )
    .unwrap();

    let (s0, bps0, fee0, net0) = compute_scope_drain(&policy, &w_a, &w_a, 10_000).unwrap();
    assert_eq!(
        (s0, bps0, fee0, net0),
        (TransferScope::SameWallet, 0, 0, 10_000)
    );

    let (s1, bps1, fee1, net1) = compute_scope_drain(&policy, &w_a, &w_b_same_reg, 10_000).unwrap();
    assert_eq!(
        (s1, bps1, fee1, net1),
        (TransferScope::DifferentWalletsSameRegion, 10, 10, 9_990)
    );

    let (s2, bps2, fee2, net2) = compute_scope_drain(&policy, &w_a, &w_c_diff_reg, 10_000).unwrap();
    assert_eq!(
        (s2, bps2, fee2, net2),
        (TransferScope::DifferentRegionsSameSpace, 50, 50, 9_950)
    );

    let (s3, bps3, fee3, net3) = compute_scope_drain(&policy, &w_a, &w_d_diff_spc, 10_000).unwrap();
    assert_eq!(
        (s3, bps3, fee3, net3),
        (TransferScope::DifferentSpaces, 150, 150, 9_850)
    );
}

#[test]
fn test_wallet_receive_policy_blocks_frozen_and_unlisted_senders() {
    let policy = DrainPolicy::new(
        ScopeDrainRate::ConfiguredBps(0),
        ScopeDrainRate::ConfiguredBps(25),
        ScopeDrainRate::ConfiguredBps(50),
        ScopeDrainRate::ConfiguredBps(150),
    )
    .unwrap();
    let (mut engine, val_kp, actor_kp) = bootstrap_engine(policy);

    let commit_op = |engine: &mut ProtocolEngine, nonce: u64, op: NetworkOperation| -> String {
        let env = sign_operation(
            &actor_kp,
            "vector-devnet-1",
            nonce,
            &format!("req_{nonce}"),
            200 + nonce,
            &op,
        );
        let b = engine
            .stage_signed_operation(&env, &op, "val_1", |bytes| val_kp.sign(bytes), 200 + nonce)
            .unwrap();
        let qc = single_val_qc(&b.proposal, &val_kp, &format!("qc_{nonce}"), 200 + nonce);
        engine
            .commit_proposal_with_qc(&b.proposal, &qc, 200 + nonce)
            .unwrap();
        b.created_entities
            .first()
            .map(|e| e.id.clone())
            .unwrap_or_default()
    };

    let spc_id = commit_op(
        &mut engine,
        1,
        NetworkOperation::CreateSpace {
            name: "PolicySpace".to_string(),
            visibility: "public".to_string(),
            ghost: false,
        },
    );
    // Network governance explicitly delegates the first Space scope before
    // the participant creates a Region within that space.
    commit_op(
        &mut engine,
        2,
        NetworkOperation::GrantParticipantScope {
            target_participant_id: derive_participant_id(&actor_kp.public_key_hex),
            level: "SPACE".to_string(),
            target_id: Some(spc_id.clone()),
            expires_at_ms: None,
        },
    );
    let reg_id = commit_op(
        &mut engine,
        3,
        NetworkOperation::CreateRegion {
            space_id: spc_id,
            name: "PolicyRegion".to_string(),
            prefix: Some("POL".to_string()),
            title: None,
            visibility: "public".to_string(),
            section: 1,
            ghost: false,
        },
    );
    let w_a = commit_op(
        &mut engine,
        4,
        NetworkOperation::CreateWallet {
            region_id: reg_id.clone(),
            name: "SenderWallet".to_string(),
            ghost: false,
            approval_threshold: None,
        },
    );
    let w_b = commit_op(
        &mut engine,
        5,
        NetworkOperation::CreateWallet {
            region_id: reg_id,
            name: "ReceiverWallet".to_string(),
            ghost: false,
            approval_threshold: None,
        },
    );
    let tok_id = commit_op(
        &mut engine,
        6,
        NetworkOperation::CreateToken {
            wallet_id: w_a.clone(),
            name: "Policy Token".to_string(),
            symbol: "PTOK".to_string(),
            initial_supply: 20_000,
            max_supply: 20_000,
            unlimited_supply: false,
            auth_ratio_au: 100,
            energy: 10,
            drain_bps: 0,
            purpose: "policy-test".to_string(),
            external_monetary_value: "None".to_string(),
            ghost: false,
        },
    );

    // Freeze receiver wallet -> transfer MUST fail
    commit_op(
        &mut engine,
        7,
        NetworkOperation::UpdateWalletReceivePolicy {
            wallet_id: w_b.clone(),
            mode: "FROZEN".to_string(),
            allowed_senders: vec![],
        },
    );
    let frozen_xfer = NetworkOperation::TransferToken {
        token_id: tok_id.clone(),
        from_wallet_id: w_a.clone(),
        to_wallet_id: w_b.clone(),
        amount: 1_000,
        cosignatures: vec![],
    };
    let env_f = sign_operation(
        &actor_kp,
        "vector-devnet-1",
        8,
        "req_frozen",
        300,
        &frozen_xfer,
    );
    assert!(engine
        .stage_signed_operation(&env_f, &frozen_xfer, "val_1", |b| val_kp.sign(b), 300)
        .is_err());

    // Restrict receiver wallet to an unrelated sender -> transfer from w_a MUST fail
    commit_op(
        &mut engine,
        8,
        NetworkOperation::UpdateWalletReceivePolicy {
            wallet_id: w_b.clone(),
            mode: "RESTRICTED".to_string(),
            allowed_senders: vec!["wal_unrelated".to_string()],
        },
    );
    let env_r = sign_operation(
        &actor_kp,
        "vector-devnet-1",
        9,
        "req_restricted",
        301,
        &frozen_xfer,
    );
    assert!(engine
        .stage_signed_operation(&env_r, &frozen_xfer, "val_1", |b| val_kp.sign(b), 301)
        .is_err());

    // Allow w_a -> transfer succeeds and deducts exact scope drain (25 bps of 1000 = 2)
    commit_op(
        &mut engine,
        9,
        NetworkOperation::UpdateWalletReceivePolicy {
            wallet_id: w_b.clone(),
            mode: "RESTRICTED".to_string(),
            allowed_senders: vec![w_a.clone()],
        },
    );
    commit_op(&mut engine, 10, frozen_xfer);
    assert_eq!(
        engine
            .state
            .get_balance(&tok_id, &w_b)
            .unwrap()
            .vector
            .token,
        998
    );
    assert!(verify_token_supply_conservation(&engine.state, &tok_id).unwrap());

    // Collateralized loan fund + repay uses protocol settlement transfer without Send permission issues
    let loan_id = commit_op(
        &mut engine,
        11,
        NetworkOperation::CreateLoan {
            name: "SettlementLoan".to_string(),
            token_id: tok_id.clone(),
            lender_wallet_id: w_a,
            borrower_wallet_id: w_b,
            principal: 500,
            collateral: 200,
            interest_bps: 0,
            maturity_at_ms: None,
        },
    );
    apply_execute_loan(
        &mut engine.state,
        &loan_id,
        "fund",
        500,
        &actor_kp.public_key_hex,
        500,
    )
    .unwrap();
    apply_execute_loan(
        &mut engine.state,
        &loan_id,
        "repay",
        500,
        &actor_kp.public_key_hex,
        501,
    )
    .unwrap();
    assert!(verify_token_supply_conservation(&engine.state, &tok_id).unwrap());
}
