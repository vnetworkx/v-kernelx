use crate::authorization::{validate_signed_envelope, verify_non_replay};
use crate::consensus_gate::commit_verified_proposal;
use crate::identity::{issue_participant_challenge, verify_and_register_participant, JoinNetworkRequest};
use crate::language::{
    build_program_submission, compile_vx_source, execute_compiled_program_staged,
    SubmitProgramRequest,
};
use crate::ledger::{build_verified_ledger_proof_report, LedgerProofReport};
use crate::reconstruction::{reconstruct_entity, ReconstructionReport};
use crate::replay::{verify_replay_equivalence, ReplayVerificationReport};
use crate::snapshot::create_snapshot;
use crate::state::{GenesisConfig, NetworkLedgerState, StateSnapshot, TransactionReceipt};
use crate::transition::apply_network_operation_with_genesis;
use std::path::Path;
use vnetwork_types::*;

#[derive(Debug, Clone)]
pub struct StagedProposalBundle {
    pub proposal: ConsensusProposal,
    pub program_submission: Option<ProgramSubmission>,
    pub tx_receipt: TransactionReceipt,
    pub created_entities: Vec<CreatedEntitySummary>,
    pub outputs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ProtocolEngine {
    pub genesis: GenesisConfig,
    pub state: NetworkLedgerState,
    pub validators: Vec<ConsensusValidator>,
}

impl ProtocolEngine {
    pub fn try_new(genesis: GenesisConfig) -> VResult<Self> {
        let validators = genesis.initial_validators.clone();
        let state = NetworkLedgerState::try_new(&genesis)?;
        Ok(Self {
            genesis,
            state,
            validators,
        })
    }

    pub fn new(genesis: GenesisConfig) -> Self {
        Self::try_new(genesis).expect("invalid GenesisConfig passed to ProtocolEngine::new")
    }

    pub fn from_restored(genesis: GenesisConfig, state: NetworkLedgerState) -> Self {
        let validators = if state.validators.is_empty() {
            genesis.initial_validators.clone()
        } else {
            state.validators.clone()
        };
        Self {
            genesis,
            state,
            validators,
        }
    }

    pub fn validator_set_hash(&self) -> VResult<String> {
        validate_validator_set(&self.validators)
    }

    pub fn issue_challenge(&mut self, timestamp_ms: u64) -> ParticipantChallenge {
        issue_participant_challenge(&mut self.state, timestamp_ms)
    }

    pub fn stage_participant_join(
        &mut self,
        req: &JoinNetworkRequest,
        proposer_validator_id: &str,
        proposer_signing_fn: impl FnOnce(&[u8]) -> VResult<String>,
        timestamp_ms: u64,
    ) -> VResult<(ParticipantRecord, NodeRecord, ConsensusProposal, TransactionReceipt)> {
        let mut staged = self.state.clone();
        let pre_root = staged.compute_state_root()?;
        let parent_commitment = self.state.expected_parent_commitment();
        let next_height = self
            .state
            .height
            .checked_add(1)
            .ok_or_else(|| VNetworkError::Validation("height overflow".to_string()))?;
        let vset_hash = self.validator_set_hash()?;
        let (participant, node, event) =
            verify_and_register_participant(&mut staged, req, timestamp_ms)?;
        staged.height = next_height;
        let post_root = staged.compute_state_root()?;
        let tx_id = format!(
            "tx_join_{}",
            &blake3_hex(format!("{}:{}", participant.participant_id, timestamp_ms).as_bytes())[..20]
        );

        let mut proposal = ConsensusProposal {
            proposal_id: String::new(),
            proposal_version: PROPOSAL_VERSION,
            network_id: self.state.network_id.clone(),
            genesis_commitment: self.state.genesis_commitment.clone(),
            protocol_version: self.state.protocol_version.clone(),
            height: next_height,
            round: 1,
            epoch: self.state.validator_epoch,
            validator_set_hash: vset_hash,
            consensus_parameters_hash: self.state.consensus_parameters_hash.clone(),
            proposer_validator_id: proposer_validator_id.to_string(),
            parent_commitment,
            pre_state_root: pre_root,
            post_state_root: post_root.clone(),
            proposal_digest: String::new(),
            operation_scope: "PARTICIPANT_JOIN".to_string(),
            events: vec![event.clone()],
            program_id: None,
            tx_id: Some(tx_id.clone()),
            program_source_bundle: None,
            nonce_binding: None,
            execution_params: std::collections::BTreeMap::new(),
            timestamp_ms,
            proposer_signature: String::new(),
        };
        proposal.finalize_digest_and_id()?;
        let bytes = proposal.canonical_signing_bytes()?;
        proposal.proposer_signature = proposer_signing_fn(&bytes)?;

        let receipt = TransactionReceipt {
            tx_id: tx_id.clone(),
            request_id: req.challenge_id.clone(),
            actor_pubkey: req.participant_pubkey.clone(),
            operation: "PARTICIPANT_JOIN".to_string(),
            status: ProgramLifecycleStatus::AwaitingConsensus,
            event_ids: vec![event.event_id],
            certificate_id: None,
            state_root: post_root,
            error: None,
            timestamp_ms,
        };
        self.state.challenges.remove(&req.challenge_id);
        self.state.transactions.insert(tx_id, receipt.clone());

        Ok((participant, node, proposal, receipt))
    }

    pub fn stage_program_submission(
        &mut self,
        req: &SubmitProgramRequest,
        fs_base_dir: Option<&Path>,
        proposer_validator_id: &str,
        proposer_signing_fn: impl FnOnce(&[u8]) -> VResult<String>,
        timestamp_ms: u64,
    ) -> VResult<Result<StagedProposalBundle, ProgramSubmission>> {
        // 1. Authenticate submitter signature and replay guard
        req.verify_signature()?;
        verify_non_replay(
            &self.state,
            &req.request_id,
            &req.actor_pubkey,
            req.nonce,
            &req.network_id,
        )?;

        // 2. Compile via real VectorSpace Rust frontend
        let compiled = match compile_vx_source(
            &req.source_bytes,
            &req.file_name,
            &req.modules,
            fs_base_dir,
        ) {
            Ok(c) => c,
            Err(err) => {
                let mut sub = build_program_submission(
                    req,
                    None,
                    ProgramLifecycleStatus::Failed,
                    timestamp_ms,
                );
                sub.error_message = Some(err.to_string());
                self.state.programs.insert(sub.program_id.clone(), sub.clone());
                return Ok(Err(sub));
            }
        };

        let mut sub = build_program_submission(
            req,
            Some(&compiled),
            ProgramLifecycleStatus::Compiled,
            timestamp_ms,
        );

        // 3. Staged atomic execution on cloned state (zero partial state on failure)
        let exec = match execute_compiled_program_staged(
            &self.state,
            &self.genesis,
            &compiled,
            &req.actor_pubkey,
            timestamp_ms,
            Some((req.actor_pubkey.as_str(), req.request_id.as_str(), req.nonce)),
        ) {
            Ok(ok) => ok,
            Err(fail) => {
                sub.status = fail.lifecycle_status;
                sub.failed_operation_index = Some(fail.failed_operation_index);
                sub.error_message = Some(fail.error.to_string());
                sub.final_state_root = Some(self.state.compute_state_root()?);
                self.state.programs.insert(sub.program_id.clone(), sub.clone());
                return Ok(Err(sub));
            }
        };

        sub.status = ProgramLifecycleStatus::AwaitingConsensus;
        sub.resulting_event_ids = exec
            .generated_events
            .iter()
            .map(|e| e.event_id.clone())
            .collect();
        sub.created_entities = exec.created_entities.clone();
        sub.outputs = exec.outputs.clone();
        sub.final_state_root = Some(exec.post_state_root.clone());

        let next_height = self
            .state
            .height
            .checked_add(1)
            .ok_or_else(|| VNetworkError::Validation("height overflow".to_string()))?;
        let parent_commitment = self.state.expected_parent_commitment();
        let tx_id = sub.program_id.clone();
        let vset_hash = self.validator_set_hash()?;

        let bundle = ProgramSourceBundle {
            file_name: req.file_name.clone(),
            source_bytes: req.source_bytes.clone(),
            source_hash: sub.source_hash.clone(),
            compiled_program_hash: compiled.program_hash.clone(),
            resolved_module_sources: req.modules.clone(),
            language_version: compiled.language_version.clone(),
            compiler_version: compiled.compiler_version.clone(),
            execution_params: req.execution_params.clone(),
        };

        let mut proposal = ConsensusProposal {
            proposal_id: String::new(),
            proposal_version: PROPOSAL_VERSION,
            network_id: self.state.network_id.clone(),
            genesis_commitment: self.state.genesis_commitment.clone(),
            protocol_version: self.state.protocol_version.clone(),
            height: next_height,
            round: 1,
            epoch: self.state.validator_epoch,
            validator_set_hash: vset_hash,
            consensus_parameters_hash: self.state.consensus_parameters_hash.clone(),
            proposer_validator_id: proposer_validator_id.to_string(),
            parent_commitment,
            pre_state_root: exec.pre_state_root,
            post_state_root: exec.post_state_root.clone(),
            proposal_digest: String::new(),
            operation_scope: format!("VX_PROGRAM:{}", req.file_name),
            events: exec.generated_events,
            program_id: Some(sub.program_id.clone()),
            tx_id: Some(tx_id.clone()),
            program_source_bundle: Some(bundle),
            nonce_binding: Some((
                req.actor_pubkey.clone(),
                req.request_id.clone(),
                req.nonce,
            )),
            execution_params: req.execution_params.clone(),
            timestamp_ms,
            proposer_signature: String::new(),
        };
        proposal.finalize_digest_and_id()?;
        let bytes = proposal.canonical_signing_bytes()?;
        proposal.proposer_signature = proposer_signing_fn(&bytes)?;

        let receipt = TransactionReceipt {
            tx_id: tx_id.clone(),
            request_id: req.request_id.clone(),
            actor_pubkey: req.actor_pubkey.clone(),
            operation: format!("VX_PROGRAM:{}", req.file_name),
            status: ProgramLifecycleStatus::AwaitingConsensus,
            event_ids: sub.resulting_event_ids.clone(),
            certificate_id: None,
            state_root: exec.post_state_root,
            error: None,
            timestamp_ms,
        };

        self.state.programs.insert(sub.program_id.clone(), sub.clone());
        self.state.transactions.insert(tx_id, receipt.clone());

        Ok(Ok(StagedProposalBundle {
            proposal,
            program_submission: Some(sub),
            tx_receipt: receipt,
            created_entities: exec.created_entities,
            outputs: exec.outputs,
        }))
    }

    pub fn stage_signed_operation(
        &mut self,
        envelope: &SignedRequestEnvelope,
        op: &NetworkOperation,
        proposer_validator_id: &str,
        proposer_signing_fn: impl FnOnce(&[u8]) -> VResult<String>,
        timestamp_ms: u64,
    ) -> VResult<StagedProposalBundle> {
        validate_signed_envelope(&self.state, envelope)?;
        let actual_hash = blake3_hex(&canonical_json_bytes(op)?);
        if actual_hash != envelope.payload_hash {
            return Err(VNetworkError::Signature(format!(
                "envelope payload_hash `{}` does not match canonical operation hash `{actual_hash}`",
                envelope.payload_hash
            )));
        }

        let mut staged = self.state.clone();
        let pre_root = staged.compute_state_root()?;
        let parent_commitment = self.state.expected_parent_commitment();
        let next_height = self
            .state
            .height
            .checked_add(1)
            .ok_or_else(|| VNetworkError::Validation("height overflow".to_string()))?;
        let vset_hash = self.validator_set_hash()?;
        let mut outcome = apply_network_operation_with_genesis(
            &mut staged,
            &self.genesis,
            op,
            &envelope.actor_pubkey,
            timestamp_ms,
        )?;
        let nonce_event = crate::authorization::commit_request_nonce_event(
            &mut staged,
            &envelope.request_id,
            &envelope.actor_pubkey,
            envelope.nonce,
            timestamp_ms,
        )?;
        outcome.events.push(nonce_event);
        staged.height = next_height;
        let post_root = staged.compute_state_root()?;
        let tx_id = format!(
            "tx_{}",
            &blake3_hex(format!("{}:{}", envelope.request_id, post_root).as_bytes())[..20]
        );
        let op_scope = serde_json::to_value(op)
            .map_err(|e| VNetworkError::Serialization(e.to_string()))?
            .get("op")
            .and_then(|s| s.as_str())
            .ok_or_else(|| VNetworkError::Serialization("missing op discriminator".to_string()))?
            .to_string();

        let mut proposal = ConsensusProposal {
            proposal_id: String::new(),
            proposal_version: PROPOSAL_VERSION,
            network_id: self.state.network_id.clone(),
            genesis_commitment: self.state.genesis_commitment.clone(),
            protocol_version: self.state.protocol_version.clone(),
            height: next_height,
            round: 1,
            epoch: self.state.validator_epoch,
            validator_set_hash: vset_hash,
            consensus_parameters_hash: self.state.consensus_parameters_hash.clone(),
            proposer_validator_id: proposer_validator_id.to_string(),
            parent_commitment,
            pre_state_root: pre_root,
            post_state_root: post_root.clone(),
            proposal_digest: String::new(),
            operation_scope: op_scope,
            events: outcome.events.clone(),
            program_id: None,
            tx_id: Some(tx_id.clone()),
            program_source_bundle: None,
            nonce_binding: Some((
                envelope.actor_pubkey.clone(),
                envelope.request_id.clone(),
                envelope.nonce,
            )),
            execution_params: std::collections::BTreeMap::new(),
            timestamp_ms,
            proposer_signature: String::new(),
        };
        proposal.finalize_digest_and_id()?;
        let bytes = proposal.canonical_signing_bytes()?;
        proposal.proposer_signature = proposer_signing_fn(&bytes)?;

        let receipt = TransactionReceipt {
            tx_id: tx_id.clone(),
            request_id: envelope.request_id.clone(),
            actor_pubkey: envelope.actor_pubkey.clone(),
            operation: op_scope,
            status: ProgramLifecycleStatus::AwaitingConsensus,
            event_ids: outcome.events.iter().map(|e| e.event_id.clone()).collect(),
            certificate_id: None,
            state_root: post_root,
            error: None,
            timestamp_ms,
        };

        self.state.transactions.insert(tx_id, receipt.clone());

        Ok(StagedProposalBundle {
            proposal,
            program_submission: None,
            tx_receipt: receipt,
            created_entities: outcome.created_entities,
            outputs: outcome.outputs,
        })
    }

    pub fn commit_proposal_with_qc(
        &mut self,
        proposal: &ConsensusProposal,
        qc: &QuorumCertificate,
        timestamp_ms: u64,
    ) -> VResult<String> {
        let post_root =
            commit_verified_proposal(&mut self.state, proposal, qc, &self.validators)?;

        if let Some(pid) = &proposal.program_id {
            if let Some(sub) = self.state.programs.get_mut(pid) {
                sub.status = ProgramLifecycleStatus::Committed;
                sub.consensus_certificate = Some(qc.clone());
                sub.final_state_root = Some(post_root.clone());
                sub.updated_at_ms = timestamp_ms;
            } else if let Some(bundle) = &proposal.program_source_bundle {
                let (actor_pubkey, request_id, nonce) = proposal
                    .nonce_binding
                    .clone()
                    .ok_or_else(|| VNetworkError::Consensus("committed program proposal missing nonce_binding".to_string()))?;
                let imported_modules: Vec<ModuleCommitment> = bundle
                    .resolved_module_sources
                    .iter()
                    .map(|(path, src)| ModuleCommitment {
                        path: path.clone(),
                        blake3_hash: blake3_hex(src.as_bytes()),
                    })
                    .collect();
                let sub = ProgramSubmission {
                    program_id: pid.clone(),
                    file_name: bundle.file_name.clone(),
                    file_kind: if bundle.file_name.ends_with(".vdx") {
                        "vdx".to_string()
                    } else {
                        "vx".to_string()
                    },
                    source_bytes: bundle.source_bytes.clone(),
                    source_hash: bundle.source_hash.clone(),
                    language_version: bundle.language_version.clone(),
                    compiler_version: bundle.compiler_version.clone(),
                    imported_modules,
                    resolved_module_sources: bundle.resolved_module_sources.clone(),
                    compiled_program_hash: bundle.compiled_program_hash.clone(),
                    protocol_version: self.state.protocol_version.clone(),
                    network_id: self.state.network_id.clone(),
                    submitter_participant_id: derive_participant_id(&actor_pubkey),
                    submitter_pubkey: actor_pubkey,
                    request_id,
                    nonce,
                    signature: String::new(),
                    execution_params: bundle.execution_params.clone(),
                    status: ProgramLifecycleStatus::Committed,
                    failed_operation_index: None,
                    error_message: None,
                    resulting_event_ids: proposal.events.iter().map(|e| e.event_id.clone()).collect(),
                    consensus_certificate: Some(qc.clone()),
                    final_state_root: Some(post_root.clone()),
                    created_entities: Vec::new(),
                    outputs: Vec::new(),
                    submitted_at_ms: proposal.timestamp_ms,
                    updated_at_ms: timestamp_ms,
                };
                self.state.programs.insert(pid.clone(), sub);
            }
        }
        if let Some(tid) = &proposal.tx_id {
            if let Some(tx) = self.state.transactions.get_mut(tid) {
                tx.status = ProgramLifecycleStatus::Committed;
                tx.certificate_id = Some(qc.certificate_id.clone());
                tx.state_root = post_root.clone();
            } else {
                let (actor_pubkey, request_id, _) = proposal
                    .nonce_binding
                    .clone()
                    .unwrap_or_else(|| {
                        let ev_actor = proposal
                            .events
                            .first()
                            .map(|e| e.actor.clone())
                            .unwrap_or_default();
                        (ev_actor, proposal.proposal_id.clone(), 0)
                    });
                let op_label = proposal
                    .program_source_bundle
                    .as_ref()
                    .map(|b| format!("VX_PROGRAM:{}", b.file_name))
                    .or_else(|| proposal.events.first().map(|e| e.operation.clone()))
                    .unwrap_or_else(|| "OPERATION".to_string());
                self.state.transactions.insert(
                    tid.clone(),
                    TransactionReceipt {
                        tx_id: tid.clone(),
                        request_id,
                        actor_pubkey,
                        operation: op_label,
                        status: ProgramLifecycleStatus::Committed,
                        event_ids: proposal.events.iter().map(|e| e.event_id.clone()).collect(),
                        certificate_id: Some(qc.certificate_id.clone()),
                        state_root: post_root.clone(),
                        error: None,
                        timestamp_ms: proposal.timestamp_ms,
                    },
                );
            }
        }
        Ok(post_root)
    }

    pub fn reconstruct_entity(
        &self,
        entity_kind: &str,
        entity_id_or_name: &str,
    ) -> VResult<ReconstructionReport> {
        reconstruct_entity(&self.state, &self.genesis, entity_kind, entity_id_or_name)
    }

    pub fn verify_replay(&self) -> VResult<ReplayVerificationReport> {
        verify_replay_equivalence(&self.state, &self.genesis)
    }

    pub fn proof_report(&self) -> VResult<LedgerProofReport> {
        build_verified_ledger_proof_report(&self.state, Some(&self.genesis))
    }

    pub fn snapshot(&mut self, timestamp_ms: u64) -> VResult<StateSnapshot> {
        create_snapshot(&mut self.state, timestamp_ms)
    }
}
