use std::collections::BTreeMap;
use vnetwork_core::contracts::{apply_create_contract, apply_execute_contract};
use vnetwork_core::engine::ProtocolEngine;
use vnetwork_core::ghost::inspect_ghost_entities;
use vnetwork_core::identity::{
    canonical_join_signing_bytes, JoinNetworkRequest, SignedScopeAuthorization,
};
use vnetwork_core::ledger::build_ledger_proof_report;
use vnetwork_core::loans::apply_execute_loan;
use vnetwork_core::replay::apply_event_to_state;
use vnetwork_core::state::GenesisConfig;
use vnetwork_core::supply::verify_token_supply_conservation;
use vnetwork_core::token::{
    apply_adjust_non_transferable_dimensions, canonical_transfer_approval_bytes,
};
use vnetwork_core::wallet::canonical_wallet_pop_bytes;
use vnetwork_types::*;

fn sign_qc(prop: &ConsensusProposal, val_kp: &KeypairMaterial, ts: u64) -> QuorumCertificate {
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

fn sign_envelope(
    actor: &KeypairMaterial,
    network_id: &str,
    nonce: u64,
    req_id: &str,
    ts: u64,
    op: &NetworkOperation,
) -> SignedRequestEnvelope {
    let payload_hash = blake3_hex(&canonical_json_bytes(op).unwrap());
    let mut env = SignedRequestEnvelope {
        actor_pubkey: actor.public_key_hex.clone(),
        network_id: network_id.to_string(),
        request_id: req_id.to_string(),
        nonce,
        timestamp_ms: ts,
        payload_hash,
        signature: String::new(),
    };
    let signing_bytes = SignedRequestEnvelope::canonical_signing_bytes(
        network_id,
        req_id,
        &actor.public_key_hex,
        nonce,
        ts,
        &env.payload_hash,
    )
    .unwrap();
    env.signature = actor.sign(&signing_bytes).unwrap();
    env
}

fn commit_operation(
    engine: &mut ProtocolEngine,
    validator: &KeypairMaterial,
    actor: &KeypairMaterial,
    nonce: &mut u64,
    timestamp_ms: &mut u64,
    request_prefix: &str,
    operation: NetworkOperation,
) -> String {
    let current_nonce = *nonce;
    let current_timestamp = *timestamp_ms;
    *nonce = current_nonce.checked_add(1).expect("test nonce overflow");
    *timestamp_ms = current_timestamp
        .checked_add(1)
        .expect("test timestamp overflow");

    let request_id = format!("{request_prefix}_{current_nonce}");
    let envelope = sign_envelope(
        actor,
        "vector-devnet-invariants",
        current_nonce,
        &request_id,
        current_timestamp,
        &operation,
    );
    let staged = engine
        .stage_signed_operation(
            &envelope,
            &operation,
            "val_1",
            |bytes| validator.sign(bytes),
            current_timestamp,
        )
        .expect("signed test operation should stage");
    let certificate = sign_qc(&staged.proposal, validator, current_timestamp);
    engine
        .commit_proposal_with_qc(&staged.proposal, &certificate, current_timestamp)
        .expect("signed test operation should commit");
    staged
        .created_entities
        .first()
        .map(|entity| entity.id.clone())
        .unwrap_or_default()
}

fn setup_test_engine() -> (ProtocolEngine, KeypairMaterial, KeypairMaterial) {
    let val_kp = KeypairMaterial::generate("validator");
    let policy = DrainPolicy::new(
        ScopeDrainRate::ConfiguredBps(0),
        ScopeDrainRate::ConfiguredBps(10),
        ScopeDrainRate::ConfiguredBps(50),
        ScopeDrainRate::ConfiguredBps(200),
    )
    .unwrap();
    let genesis = GenesisConfig::for_profile(
        NetworkProfile::Development,
        "vector-devnet-invariants",
        "Invariant Test Network",
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

    let owner_kp = KeypairMaterial::generate("owner");
    let node_kp = KeypairMaterial::generate("owner-node");
    let ch = engine.issue_challenge(100);
    let scopes = vec![
        ParticipationLevel::Network,
        ParticipationLevel::Space,
        ParticipationLevel::Region,
        ParticipationLevel::Wallet,
        ParticipationLevel::Token,
    ];
    let join_bytes = canonical_join_signing_bytes(
        &ch,
        &owner_kp.public_key_hex,
        &node_kp.public_key_hex,
        &scopes,
    )
    .unwrap();
    let mut auth = SignedScopeAuthorization {
        target_participant_pubkey: owner_kp.public_key_hex.clone(),
        grantor_pubkey: val_kp.public_key_hex.clone(),
        scopes: vec![
            ParticipationLevel::Space,
            ParticipationLevel::Region,
            ParticipationLevel::Wallet,
            ParticipationLevel::Token,
        ],
        target_id: None,
        expires_at_ms: None,
        authorization_basis: "genesis_test".to_string(),
        signature: String::new(),
    };
    auth.signature = val_kp
        .sign(
            &auth
                .canonical_signing_bytes("vector-devnet-invariants")
                .unwrap(),
        )
        .unwrap();

    let (_, _, prop, _) = engine
        .stage_participant_join(
            &JoinNetworkRequest {
                challenge_id: ch.challenge_id,
                participant_pubkey: owner_kp.public_key_hex.clone(),
                node_pubkey: node_kp.public_key_hex.clone(),
                display_name: "owner".to_string(),
                node_kind: NodeKind::FullNode,
                requested_scopes: scopes,
                advertised_addresses: vec![],
                participant_signature: owner_kp.sign(&join_bytes).unwrap(),
                node_signature: node_kp.sign(&join_bytes).unwrap(),
                scope_authorizations: vec![auth],
            },
            "val_1",
            |b| val_kp.sign(b),
            101,
        )
        .unwrap();
    let qc = sign_qc(&prop, &val_kp, 102);
    engine.commit_proposal_with_qc(&prop, &qc, 102).unwrap();
    (engine, val_kp, owner_kp)
}

#[test]
fn test_genesis_commitment_covers_all_consensus_critical_fields() {
    let v1 = KeypairMaterial::generate("v1");
    let v2 = KeypairMaterial::generate("v2");
    let base = GenesisConfig::for_profile(
        NetworkProfile::Testnet,
        "vector-testnet-1",
        "Vector Testnet",
        vec![
            ConsensusValidator {
                validator_id: "val_1".to_string(),
                node_id: "nod_1".to_string(),
                validator_pubkey_hex: v1.public_key_hex.clone(),
                weight: 100,
                active: true,
                joined_epoch: 1,
            },
            ConsensusValidator {
                validator_id: "val_2".to_string(),
                node_id: "nod_2".to_string(),
                validator_pubkey_hex: v2.public_key_hex.clone(),
                weight: 100,
                active: true,
                joined_epoch: 1,
            },
        ],
    );
    let h_base = base.commitment_hash().unwrap();

    let mut diff_quorum = base.clone();
    diff_quorum.consensus_parameters.quorum_threshold_bps = 7_500;
    assert_ne!(diff_quorum.commitment_hash().unwrap(), h_base);

    let mut diff_fault = base.clone();
    diff_fault.consensus_parameters.validator_fault_assumption = "BFT_CUSTOM_QUORUM".to_string();
    assert_ne!(diff_fault.commitment_hash().unwrap(), h_base);

    let mut diff_weight = base.clone();
    diff_weight.initial_validators[0].weight = 200;
    assert_ne!(diff_weight.commitment_hash().unwrap(), h_base);

    let mut diff_drain = base.clone();
    diff_drain.drain_policy = DrainPolicy::new(
        ScopeDrainRate::ConfiguredBps(0),
        ScopeDrainRate::ConfiguredBps(10),
        ScopeDrainRate::ConfiguredBps(20),
        ScopeDrainRate::ConfiguredBps(50),
    )
    .unwrap();
    assert_ne!(diff_drain.commitment_hash().unwrap(), h_base);

    let mut diff_atlas = base.clone();
    diff_atlas.allow_bootstrap_atlas = true;
    assert_ne!(diff_atlas.commitment_hash().unwrap(), h_base);

    let mut diff_epoch = base.clone();
    diff_epoch.genesis_epoch = 2;
    assert_ne!(diff_epoch.commitment_hash().unwrap(), h_base);
}

#[test]
fn test_3d_token_vector_transfer_only_and_cross_space_atomicity() {
    let (mut engine, val_kp, owner_kp) = setup_test_engine();
    let mut nonce = 1u64;
    let mut ts = 201u64;

    let s1 = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        NetworkOperation::CreateSpace {
            name: "SpaceA".to_string(),
            visibility: "public".to_string(),
            ghost: false,
        },
    );
    let s2 = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        NetworkOperation::CreateSpace {
            name: "SpaceB".to_string(),
            visibility: "public".to_string(),
            ghost: false,
        },
    );
    let r1 = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        NetworkOperation::CreateRegion {
            space_id: s1,
            name: "RegA".to_string(),
            prefix: Some("REGA".to_string()),
            title: None,
            visibility: "public".to_string(),
            section: 1,
            ghost: false,
        },
    );
    let r2 = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        NetworkOperation::CreateRegion {
            space_id: s2,
            name: "RegB".to_string(),
            prefix: Some("REGB".to_string()),
            title: None,
            visibility: "public".to_string(),
            section: 1,
            ghost: false,
        },
    );
    let w1 = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        NetworkOperation::CreateWallet {
            region_id: r1,
            name: "WA".to_string(),
            ghost: false,
            approval_threshold: None,
        },
    );
    let w2 = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        NetworkOperation::CreateWallet {
            region_id: r2,
            name: "WB".to_string(),
            ghost: false,
            approval_threshold: None,
        },
    );
    let tok = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        NetworkOperation::CreateToken {
            wallet_id: w1.clone(),
            name: "Cross Token".to_string(),
            symbol: "XTOK".to_string(),
            initial_supply: 50_000,
            max_supply: 50_000,
            unlimited_supply: false,
            auth_ratio_au: 777,
            energy: 42,
            drain_bps: 0,
            purpose: "test".to_string(),
            external_monetary_value: "None".to_string(),
            ghost: false,
        },
    );

    // Cross-Space transfer (200 bps drain on 1_000 = 20 fee, 980 credited)
    commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        NetworkOperation::TransferToken {
            token_id: tok.clone(),
            from_wallet_id: w1.clone(),
            to_wallet_id: w2.clone(),
            amount: 1_000,
            cosignatures: vec![],
        },
    );

    let bal_from = engine.state.get_balance(&tok, &w1).unwrap();
    let bal_to = engine.state.get_balance(&tok, &w2).unwrap();
    assert_eq!(bal_from.vector.token, 49_000);
    assert_eq!(bal_from.vector.auth_ratio_au, 777);
    assert_eq!(bal_from.vector.energy, 42);
    assert_eq!(bal_to.vector.token, 980);
    assert_eq!(bal_to.vector.auth_ratio_au, 0);
    assert_eq!(bal_to.vector.energy, 0);
    assert!(verify_token_supply_conservation(&engine.state, &tok).unwrap());

    // Direct TokenVector invariant check rejects modifying au/energy during transfer
    let tampered = TokenVector::new(980, 1, 0);
    assert!(TokenVector::verify_transfer_invariant(
        &TokenVector::new(50_000, 777, 42),
        &bal_from.vector,
        &TokenVector::zero(),
        &tampered,
    )
    .is_err());

    // Failed cross-space transfer leaves debit AND credit untouched (atomic)
    let over_transfer = NetworkOperation::TransferToken {
        token_id: tok.clone(),
        from_wallet_id: w1.clone(),
        to_wallet_id: w2.clone(),
        amount: 99_999,
        cosignatures: vec![],
    };
    let bad_env = sign_envelope(
        &owner_kp,
        "vector-devnet-invariants",
        9,
        "req_over",
        209,
        &over_transfer,
    );
    assert!(engine
        .stage_signed_operation(&bad_env, &over_transfer, "val_1", |b| val_kp.sign(b), 209)
        .is_err());
    assert_eq!(
        engine.state.get_balance(&tok, &w1).unwrap().vector.token,
        49_000
    );
    assert_eq!(
        engine.state.get_balance(&tok, &w2).unwrap().vector.token,
        980
    );

    // Replay equivalence & entity reconstruction verify deterministically
    let replay = engine.verify_replay().unwrap();
    assert!(replay.valid);
    let rec = engine.reconstruct_entity("token", &tok).unwrap();
    assert!(rec.verified);
}

#[test]
fn test_wallet_pop_replay_expiry_revocation_multisig_and_ghost_isolation() {
    let (mut engine, val_kp, owner_kp) = setup_test_engine();
    let mut nonce = 1u64;
    let mut ts = 500u64;

    let s = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        NetworkOperation::CreateSpace {
            name: "AuthSpace".to_string(),
            visibility: "public".to_string(),
            ghost: false,
        },
    );
    let r = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        NetworkOperation::CreateRegion {
            space_id: s,
            name: "AuthRegion".to_string(),
            prefix: Some("AUT".to_string()),
            title: None,
            visibility: "public".to_string(),
            section: 1,
            ghost: false,
        },
    );
    // Multisig wallet requiring 2 approvals
    let w_ms = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        NetworkOperation::CreateWallet {
            region_id: r.clone(),
            name: "Multisig".to_string(),
            ghost: false,
            approval_threshold: Some(2),
        },
    );
    let w_dst = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        NetworkOperation::CreateWallet {
            region_id: r,
            name: "Dest".to_string(),
            ghost: false,
            approval_threshold: Some(1),
        },
    );
    let tok = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        NetworkOperation::CreateToken {
            wallet_id: w_ms.clone(),
            name: "SecToken".to_string(),
            symbol: "SEC".to_string(),
            initial_supply: 10_000,
            max_supply: 10_000,
            unlimited_supply: false,
            auth_ratio_au: 500,
            energy: 10,
            drain_bps: 0,
            purpose: "sec".to_string(),
            external_monetary_value: "None".to_string(),
            ghost: false,
        },
    );

    // Authorize limited signer with PoP, max_amount_per_op=100, expiry=2_000, allowed_token=[tok]
    let signer_kp = KeypairMaterial::generate("signer");
    let pop_bytes = canonical_wallet_pop_bytes(
        "vector-devnet-invariants",
        &w_ms,
        &derive_participant_id(&owner_kp.public_key_hex),
        &signer_kp.public_key_hex,
        "wallet_key_authorization",
        "pop-nonce-1",
        Some(2_000),
        PROTOCOL_VERSION,
    )
    .unwrap();
    let pop_sig = signer_kp.sign(&pop_bytes).unwrap();
    let auth_op = NetworkOperation::AuthorizeWalletKey {
        wallet_id: w_ms.clone(),
        authorized_pubkey: signer_kp.public_key_hex.clone(),
        role: "signer".to_string(),
        permissions: vec!["send".to_string()],
        allowed_token_ids: vec![tok.clone()],
        max_amount_per_op: Some(100),
        expires_at_ms: Some(2_000),
        pop_nonce: Some("pop-nonce-1".to_string()),
        pop_signature: Some(pop_sig.clone()),
        participant_identity: Some(derive_participant_id(&owner_kp.public_key_hex)),
    };
    commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        auth_op.clone(),
    );

    // Reusing same PoP nonce MUST fail
    let env_dup = sign_envelope(
        &owner_kp,
        "vector-devnet-invariants",
        nonce,
        "req_pop_dup",
        ts,
        &auth_op,
    );
    assert!(engine
        .stage_signed_operation(&env_dup, &auth_op, "val_1", |b| val_kp.sign(b), ts)
        .is_err());

    // Transfer without 2nd cosigner fails multisig threshold
    let xfer_small = NetworkOperation::TransferToken {
        token_id: tok.clone(),
        from_wallet_id: w_ms.clone(),
        to_wallet_id: w_dst.clone(),
        amount: 50,
        cosignatures: vec![],
    };
    let env_no_cosig = sign_envelope(
        &owner_kp,
        "vector-devnet-invariants",
        nonce,
        "req_no_cosig",
        ts,
        &xfer_small,
    );
    assert!(engine
        .stage_signed_operation(&env_no_cosig, &xfer_small, "val_1", |b| val_kp.sign(b), ts)
        .is_err());

    // Cosign with signer_kp -> succeeds when within limit and expiry
    let approval_bytes = canonical_transfer_approval_bytes(
        "vector-devnet-invariants",
        PROTOCOL_VERSION,
        &tok,
        &w_ms,
        &w_dst,
        50,
    )
    .unwrap();
    let cosig_hex = signer_kp.sign(&approval_bytes).unwrap();
    let xfer_cosigned = NetworkOperation::TransferToken {
        token_id: tok.clone(),
        from_wallet_id: w_ms.clone(),
        to_wallet_id: w_dst.clone(),
        amount: 50,
        cosignatures: vec![(signer_kp.public_key_hex.clone(), cosig_hex.clone())],
    };
    commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        xfer_cosigned.clone(),
    );
    assert_eq!(
        engine.state.get_balance(&tok, &w_dst).unwrap().vector.token,
        50
    );

    // Same cosigner AFTER expiry (ts=2_500 >= 2_000) MUST fail
    let env_exp = sign_envelope(
        &owner_kp,
        "vector-devnet-invariants",
        nonce,
        "req_expired_cosig",
        2_500,
        &xfer_cosigned,
    );
    assert!(engine
        .stage_signed_operation(&env_exp, &xfer_cosigned, "val_1", |b| val_kp.sign(b), 2_500)
        .is_err());

    // Cosign exceeding max_amount_per_op (101 > 100) MUST fail before expiry too
    let ab_over = canonical_transfer_approval_bytes(
        "vector-devnet-invariants",
        PROTOCOL_VERSION,
        &tok,
        &w_ms,
        &w_dst,
        101,
    )
    .unwrap();
    let xfer_over_lim = NetworkOperation::TransferToken {
        token_id: tok.clone(),
        from_wallet_id: w_ms.clone(),
        to_wallet_id: w_dst.clone(),
        amount: 101,
        cosignatures: vec![(
            signer_kp.public_key_hex.clone(),
            signer_kp.sign(&ab_over).unwrap(),
        )],
    };
    let env_lim = sign_envelope(
        &owner_kp,
        "vector-devnet-invariants",
        nonce,
        "req_over_lim",
        600,
        &xfer_over_lim,
    );
    assert!(engine
        .stage_signed_operation(&env_lim, &xfer_over_lim, "val_1", |b| val_kp.sign(b), 600)
        .is_err());

    // Revoking signer key blocks further cosigning
    commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        NetworkOperation::RevokeWalletKey {
            wallet_id: w_ms.clone(),
            target_pubkey: signer_kp.public_key_hex.clone(),
        },
    );
    let env_rev = sign_envelope(
        &owner_kp,
        "vector-devnet-invariants",
        nonce,
        "req_revoked",
        601,
        &xfer_cosigned,
    );
    assert!(engine
        .stage_signed_operation(&env_rev, &xfer_cosigned, "val_1", |b| val_kp.sign(b), 601)
        .is_err());

    // Unjoined actor cannot create a Ghost Space or Entity
    let outsider = KeypairMaterial::generate("outsider");
    let ghost_op = NetworkOperation::CreateSpace {
        name: "GhostRogue".to_string(),
        visibility: "private".to_string(),
        ghost: true,
    };
    let env_ghost = sign_envelope(
        &outsider,
        "vector-devnet-invariants",
        1,
        "req_ghost_outsider",
        602,
        &ghost_op,
    );
    assert!(engine
        .stage_signed_operation(&env_ghost, &ghost_op, "val_1", |b| val_kp.sign(b), 602)
        .is_err());

    // A loan that has already matured cannot be funded retroactively.
    let expired_loan_id = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        NetworkOperation::CreateLoan {
            name: "ExpiredUnfundedLoan".to_string(),
            token_id: tok.clone(),
            lender_wallet_id: w_ms.clone(),
            borrower_wallet_id: w_dst.clone(),
            principal: 50,
            collateral: 1,
            interest_bps: 0,
            maturity_at_ms: Some(650),
        },
    );
    assert!(apply_execute_loan(
        &mut engine.state,
        &expired_loan_id,
        "fund",
        50,
        &owner_kp.public_key_hex,
        650,
    )
    .is_err());
    assert_eq!(
        engine.state.loans.get(&expired_loan_id).unwrap().status,
        LoanStatus::Created
    );
    let (cancelled, _) = apply_execute_loan(
        &mut engine.state,
        &expired_loan_id,
        "cancel",
        0,
        &owner_kp.public_key_hex,
        651,
    )
    .unwrap();
    assert_eq!(cancelled.status, LoanStatus::Cancelled);
    assert_eq!(cancelled.collateral_locked, 0);
    assert!(verify_token_supply_conservation(&engine.state, &tok).unwrap());

    // Loan collateral maturity enforcement
    let loan_id = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "req",
        NetworkOperation::CreateLoan {
            name: "TimedLoan".to_string(),
            token_id: tok.clone(),
            lender_wallet_id: w_ms.clone(),
            borrower_wallet_id: w_dst.clone(),
            principal: 100,
            collateral: 20,
            interest_bps: 500,
            maturity_at_ms: Some(10_000),
        },
    );
    apply_execute_loan(
        &mut engine.state,
        &loan_id,
        "fund",
        100,
        &owner_kp.public_key_hex,
        700,
    )
    .unwrap();
    // Further facility draws stop at maturity, even while the loan remains Active.
    assert!(apply_execute_loan(
        &mut engine.state,
        &loan_id,
        "draw",
        10,
        &owner_kp.public_key_hex,
        10_000
    )
    .is_err());
    // Liquidation requires the explicit default transition, both before and at maturity.
    assert!(apply_execute_loan(
        &mut engine.state,
        &loan_id,
        "liquidate",
        0,
        &owner_kp.public_key_hex,
        9_999
    )
    .is_err());
    assert!(apply_execute_loan(
        &mut engine.state,
        &loan_id,
        "liquidate",
        0,
        &owner_kp.public_key_hex,
        10_000
    )
    .is_err());
    apply_execute_loan(
        &mut engine.state,
        &loan_id,
        "default",
        0,
        &owner_kp.public_key_hex,
        10_000,
    )
    .unwrap();
    let (liq_loan, _) = apply_execute_loan(
        &mut engine.state,
        &loan_id,
        "liquidate",
        0,
        &owner_kp.public_key_hex,
        10_001,
    )
    .unwrap();
    assert_eq!(liq_loan.status, LoanStatus::Liquidated);
    assert_eq!(liq_loan.collateral_locked, 0);
    assert!(verify_token_supply_conservation(&engine.state, &tok).unwrap());
}

#[test]
fn test_validator_cannot_bypass_app_authorization_or_mutate_token_dimensions() {
    let (mut engine, val_kp, owner_kp) = setup_test_engine();
    let mut nonce = 1u64;
    let mut ts = 1_000u64;

    let s = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "vreq",
        NetworkOperation::CreateSpace {
            name: "AuthIsoSpace".to_string(),
            visibility: "public".to_string(),
            ghost: false,
        },
    );
    let r = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "vreq",
        NetworkOperation::CreateRegion {
            space_id: s.clone(),
            name: "AuthIsoRegion".to_string(),
            prefix: Some("ISO".to_string()),
            title: None,
            visibility: "public".to_string(),
            section: 1,
            ghost: false,
        },
    );
    // Policy-derived initial_region_auth_ratio_bps defaults to 0 (never hardcoded 1_000)
    assert_eq!(engine.state.regions.get(&r).unwrap().auth_ratio_bps, 0);

    let w = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "vreq",
        NetworkOperation::CreateWallet {
            region_id: r,
            name: "OwnerVault".to_string(),
            ghost: false,
            approval_threshold: None,
        },
    );
    let tok = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "vreq",
        NetworkOperation::CreateToken {
            wallet_id: w.clone(),
            name: "IsoToken".to_string(),
            symbol: "ISOT".to_string(),
            initial_supply: 5_000,
            max_supply: 5_000,
            unlimited_supply: false,
            auth_ratio_au: 200,
            energy: 10,
            drain_bps: 0,
            purpose: "isolation".to_string(),
            external_monetary_value: "None".to_string(),
            ghost: false,
        },
    );

    // Validator is NOT token authority and MUST be rejected adjusting dimensions
    let dim_err = apply_adjust_non_transferable_dimensions(
        &mut engine.state,
        &tok,
        &w,
        Some(9_999),
        None,
        "validator override attempt",
        &val_kp.public_key_hex,
        1_100,
    )
    .unwrap_err();
    assert!(matches!(dim_err, VNetworkError::Authorization(_)));

    // Validator cannot create entities in owner's space without explicit participant Space scope
    let unauth_region = NetworkOperation::CreateRegion {
        space_id: s,
        name: "ValidatorInjected".to_string(),
        prefix: Some("VI".to_string()),
        title: None,
        visibility: "public".to_string(),
        section: 2,
        ghost: false,
    };
    let env_val = sign_envelope(
        &val_kp,
        "vector-devnet-invariants",
        1,
        "req_val_bypass",
        1_101,
        &unauth_region,
    );
    assert!(engine
        .stage_signed_operation(&env_val, &unauth_region, "val_1", |b| val_kp.sign(b), 1_101)
        .is_err());
}

#[test]
fn test_contract_state_and_escrow_execution_and_loan_draw_maturity_guards() {
    let (mut engine, val_kp, owner_kp) = setup_test_engine();
    let mut nonce = 1u64;
    let mut ts = 2_000u64;

    let s = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "creq",
        NetworkOperation::CreateSpace {
            name: "ExecSpace".to_string(),
            visibility: "public".to_string(),
            ghost: false,
        },
    );
    let r = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "creq",
        NetworkOperation::CreateRegion {
            space_id: s,
            name: "ExecReg".to_string(),
            prefix: Some("EXR".to_string()),
            title: None,
            visibility: "public".to_string(),
            section: 1,
            ghost: false,
        },
    );
    let w_a = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "creq",
        NetworkOperation::CreateWallet {
            region_id: r.clone(),
            name: "LenderW".to_string(),
            ghost: false,
            approval_threshold: None,
        },
    );
    let w_b = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "creq",
        NetworkOperation::CreateWallet {
            region_id: r.clone(),
            name: "BorrowerW".to_string(),
            ghost: false,
            approval_threshold: None,
        },
    );
    let tok = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "creq",
        NetworkOperation::CreateToken {
            wallet_id: w_a.clone(),
            name: "ExecToken".to_string(),
            symbol: "EXEC".to_string(),
            initial_supply: 20_000,
            max_supply: 20_000,
            unlimited_supply: false,
            auth_ratio_au: 400,
            energy: 25,
            drain_bps: 0,
            purpose: "contracts".to_string(),
            external_monetary_value: "None".to_string(),
            ghost: false,
        },
    );
    commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "creq",
        NetworkOperation::TransferToken {
            token_id: tok.clone(),
            from_wallet_id: w_a.clone(),
            to_wallet_id: w_b.clone(),
            amount: 2_000,
            cosignatures: vec![],
        },
    );

    // Reject nondeterministic rules on contract creation
    let mut bad_rules = BTreeMap::new();
    bad_rules.insert(
        "http_call".to_string(),
        serde_json::json!("https://example.com"),
    );
    assert!(apply_create_contract(
        &mut engine.state,
        "BadContract",
        Some(&r),
        bad_rules,
        vec![],
        &owner_kp.public_key_hex,
        2_050,
    )
    .is_err());

    // Create deterministic escrow contract + execute deposit & payout
    let mut rules = BTreeMap::new();
    rules.insert("token".to_string(), serde_json::json!(tok.clone()));
    rules.insert("max_amount_per_op".to_string(), serde_json::json!(5_000));
    rules.insert(
        "initial_state".to_string(),
        serde_json::json!({ "counter": "0" }),
    );
    let contract_id = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "creq",
        NetworkOperation::CreateContract {
            name: "EscrowVault".to_string(),
            region_id: Some(r),
            rules: serde_json::Value::Object(rules.into_iter().collect()),
            actions: vec![
                serde_json::json!({ "name": "deposit" }),
                serde_json::json!({ "name": "release" }),
                serde_json::json!({ "name": "increment" }),
            ],
        },
    );

    commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "creq",
        NetworkOperation::ExecuteContract {
            contract_id: contract_id.clone(),
            action: "deposit".to_string(),
            args: serde_json::json!({ "token": tok.clone(), "from_wallet": w_a.clone(), "amount": 1_500 }),
        },
    );
    assert_eq!(
        engine
            .state
            .contracts
            .get(&contract_id)
            .unwrap()
            .escrow_balances
            .get(&tok)
            .copied(),
        Some(1_500)
    );

    // Excessive release fails atomically leaving escrow & wallet balances intact
    assert!(apply_execute_contract(
        &mut engine.state,
        &contract_id,
        "release",
        serde_json::json!({ "token": tok.clone(), "to_wallet": w_b.clone(), "amount": 9_999 }),
        &owner_kp.public_key_hex,
        2_060,
    )
    .is_err());
    assert_eq!(
        engine
            .state
            .contracts
            .get(&contract_id)
            .unwrap()
            .escrow_balances
            .get(&tok)
            .copied(),
        Some(1_500)
    );

    commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "creq",
        NetworkOperation::ExecuteContract {
            contract_id: contract_id.clone(),
            action: "release".to_string(),
            args: serde_json::json!({ "token": tok.clone(), "to_wallet": w_b.clone(), "amount": 500 }),
        },
    );
    commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "creq",
        NetworkOperation::ExecuteContract {
            contract_id: contract_id.clone(),
            action: "increment".to_string(),
            args: serde_json::json!({ "key": "counter", "delta": 3 }),
        },
    );
    assert_eq!(
        engine
            .state
            .contracts
            .get(&contract_id)
            .unwrap()
            .state_data
            .get("counter")
            .unwrap(),
        "3"
    );
    assert_eq!(
        engine
            .state
            .contracts
            .get(&contract_id)
            .unwrap()
            .escrow_balances
            .get(&tok)
            .copied(),
        Some(1_000)
    );
    assert!(verify_token_supply_conservation(&engine.state, &tok).unwrap());

    // Closing a contract must not wrap the sum of its escrow records.
    let mut overflow_contract_state = engine.state.clone();
    let (mut overflow_contract, _) = apply_create_contract(
        &mut overflow_contract_state,
        "EscrowOverflowClose",
        None,
        BTreeMap::new(),
        vec![serde_json::json!({ "name": "close" })],
        &owner_kp.public_key_hex,
        2_064,
    )
    .unwrap();
    overflow_contract
        .escrow_balances
        .insert("token-a".to_string(), u128::MAX);
    overflow_contract
        .escrow_balances
        .insert("token-b".to_string(), 1);
    overflow_contract_state.contracts.insert(
        overflow_contract.contract_id.clone(),
        overflow_contract.clone(),
    );
    let overflow_state_before = overflow_contract_state.clone();
    assert!(matches!(
        apply_execute_contract(
            &mut overflow_contract_state,
            &overflow_contract.contract_id,
            "close",
            serde_json::json!({}),
            &owner_kp.public_key_hex,
            2_065,
        ),
        Err(VNetworkError::Validation(_))
    ));
    assert_eq!(overflow_contract_state, overflow_state_before);

    // A contract requiring AuthRatio cannot bypass the gate by omitting its Region.
    let mut no_region_rules = BTreeMap::new();
    no_region_rules.insert("min_auth_ratio_bps".to_string(), serde_json::json!(5_000));
    let mut contract_probe_state = engine.state.clone();
    let (ungated_contract, _) = apply_create_contract(
        &mut contract_probe_state,
        "UngatedAuthRatioContract",
        None,
        no_region_rules,
        vec![serde_json::json!({ "name": "increment" })],
        &owner_kp.public_key_hex,
        2_065,
    )
    .unwrap();
    assert!(apply_execute_contract(
        &mut contract_probe_state,
        &ungated_contract.contract_id,
        "increment",
        serde_json::json!({ "key": "counter", "delta": 1 }),
        &owner_kp.public_key_hex,
        2_066,
    )
    .is_err());
    assert_eq!(
        contract_probe_state
            .contracts
            .get(&ungated_contract.contract_id)
            .unwrap()
            .execution_count,
        0,
    );

    // Loan with missing maturity CANNOT liquidate unless defaulted, and partial draw <= principal
    let no_mat_loan = commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "creq",
        NetworkOperation::CreateLoan {
            name: "NoMatLoan".to_string(),
            token_id: tok.clone(),
            lender_wallet_id: w_a.clone(),
            borrower_wallet_id: w_b.clone(),
            principal: 1_000,
            collateral: 100,
            interest_bps: 1000,
            maturity_at_ms: None,
        },
    );
    commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "creq",
        NetworkOperation::ExecuteLoan {
            loan_id: no_mat_loan.clone(),
            action: "draw".to_string(),
            amount: 400,
        },
    );
    assert_eq!(
        engine
            .state
            .loans
            .get(&no_mat_loan)
            .unwrap()
            .disbursed_amount,
        400
    );
    // Drawing more than remaining facility (600) MUST fail
    assert!(apply_execute_loan(
        &mut engine.state,
        &no_mat_loan,
        "draw",
        700,
        &owner_kp.public_key_hex,
        2_070
    )
    .is_err());
    // Liquidation without maturity MUST fail
    assert!(apply_execute_loan(
        &mut engine.state,
        &no_mat_loan,
        "liquidate",
        0,
        &owner_kp.public_key_hex,
        2_071
    )
    .is_err());
    // Repay based on actual disbursement (400 + 10% = 440) settles & releases collateral
    commit_operation(
        &mut engine,
        &val_kp,
        &owner_kp,
        &mut nonce,
        &mut ts,
        "creq",
        NetworkOperation::ExecuteLoan {
            loan_id: no_mat_loan.clone(),
            action: "repay".to_string(),
            amount: 440,
        },
    );
    let settled = engine.state.loans.get(&no_mat_loan).unwrap();
    assert_eq!(settled.status, LoanStatus::Repaid);
    assert_eq!(settled.collateral_locked, 0);
    assert_eq!(settled.repayment_history.len(), 1);
    assert!(engine.verify_replay().unwrap().valid);

    // Proof report includes hierarchical commitments & ghost inspection
    let report = build_ledger_proof_report(&engine.state).unwrap();
    assert!(!report.hierarchy_commitments.network_commitment.is_empty());
    assert!(report
        .hierarchy_commitments
        .token_commitments
        .contains_key(&tok));
    let ghost_info = inspect_ghost_entities(&engine.state).unwrap();
    assert_eq!(ghost_info.total_ghost_entities, 0);

    // Replay rejects tampered unknown event operations fail-closed
    let mut bad_ev = engine.state.events.last().unwrap().clone();
    bad_ev.operation = "UNKNOWN_ROGUE_OP".to_string();
    let mut cloned_state = engine.state.clone();
    assert!(apply_event_to_state(&mut cloned_state, &bad_ev).is_err());
}
