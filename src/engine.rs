use crate::certification::certify_state;
use crate::consensus::{accept_record, ConsensusPolicy};
use crate::drain::apply_drain;
use crate::error::KernelXError;
use crate::origin::create_origin_vector;
use crate::projection::project_vector;
use crate::query::{get_vector, list_records, list_vectors};
use crate::record::{make_record_id, OperationKind, VectorRecordV1};
use crate::reconstruction::SettlementOutcome;
use crate::reconstruction::reconstruct_vector;
use crate::state::{now_ms, VectorStateV1};
use crate::storage::{MemoryStore, StateStore};
use crate::transfer::{transfer_components, transfer_record};
use crate::validation::validate_state;

#[derive(Clone)]
pub struct KernelEngine<S: StateStore> {
    pub store: S,
    pub consensus: ConsensusPolicy,
}

impl KernelEngine<MemoryStore> {
    pub fn new() -> Self {
        Self {
            store: MemoryStore::default(),
            consensus: ConsensusPolicy::default(),
        }
    }
}

impl<S: StateStore> KernelEngine<S> {
    pub fn with_store(store: S) -> Self {
        Self {
            store,
            consensus: ConsensusPolicy::default(),
        }
    }

    pub fn certify(&mut self, vector_id: &str) -> Result<VectorStateV1, KernelXError> {
        let state = self
            .store
            .get_state(vector_id)?
            .ok_or(KernelXError::VectorNotFound)?;
        let mut updated = state.clone();
        updated.certification = certify_state(&state, true, true);
        updated.updated_at_ms = now_ms();
        updated.version += 1;
        self.store.put_state(updated.clone())?;
        let record = VectorRecordV1::new(
            make_record_id("certify", vector_id),
            vector_id.to_string(),
            Some(state),
            updated.clone(),
            OperationKind::Certify,
            serde_json::json!({}),
        );
        if accept_record(&record, &self.consensus) {
            self.store.put_record(record)?;
        }
        Ok(updated)
    }

    pub fn origin_create(
        &mut self,
        vector_id: impl Into<String>,
        owner_pubkey: impl Into<String>,
        space_id: impl Into<String>,
        components: Vec<u128>,
        seed: impl Into<String>,
        nonce: u64,
        difficulty: u32,
    ) -> Result<VectorStateV1, KernelXError> {
        let mut state = create_origin_vector(
            vector_id,
            owner_pubkey,
            space_id,
            components,
            seed,
            nonce,
            difficulty,
        )?;
        validate_state(&state)?;
        state.certification = certify_state(&state, true, true);
        self.store.put_state(state.clone())?;
        let record = VectorRecordV1::new(
            make_record_id("origin", &state.vector_id),
            state.vector_id.clone(),
            None,
            state.clone(),
            OperationKind::OriginCreate,
            serde_json::json!({ "difficulty": difficulty }),
        );
        if accept_record(&record, &self.consensus) {
            self.store.put_record(record)?;
        }
        Ok(state)
    }

    pub fn transfer(
        &mut self,
        from_id: &str,
        to_id: &str,
        amount: Vec<u128>,
    ) -> Result<(VectorStateV1, VectorStateV1), KernelXError> {
        let from = self.store.get_state(from_id)?.ok_or(KernelXError::VectorNotFound)?;
        let to = self.store.get_state(to_id)?.ok_or(KernelXError::VectorNotFound)?;
        let before_from = from.clone();
        let before_to = to.clone();
        let (mut after_from, mut after_to) = transfer_components(from, to, amount.clone())?;
        after_from.certification = certify_state(&after_from, true, true);
        after_to.certification = certify_state(&after_to, true, true);
        self.store.put_state(after_from.clone())?;
        self.store.put_state(after_to.clone())?;
        let (mut sender_record, mut receiver_record) =
            transfer_record(before_from, before_to, after_from.clone(), after_to.clone(), amount);
        sender_record.certification = after_from.certification.clone();
        receiver_record.certification = after_to.certification.clone();
        if accept_record(&sender_record, &self.consensus) {
            self.store.put_record(sender_record)?;
        }
        if accept_record(&receiver_record, &self.consensus) {
            self.store.put_record(receiver_record)?;
        }
        Ok((after_from, after_to))
    }

    pub fn drain(&mut self, vector_id: &str, basis_points: u16) -> Result<VectorStateV1, KernelXError> {
        let mut state = self.store.get_state(vector_id)?.ok_or(KernelXError::VectorNotFound)?;
        let (drained, remaining) = apply_drain(&state.components, basis_points, state.certification.auth_ratio, state.certification.threshold)?;
        state.components = remaining;
        state.certification = certify_state(&state, true, true);
        state.updated_at_ms = now_ms();
        state.version += 1;
        self.store.put_state(state.clone())?;
        let record = VectorRecordV1::new(
            make_record_id("drain", vector_id),
            vector_id.to_string(),
            None,
            state.clone(),
            OperationKind::Drain,
            serde_json::json!({ "basis_points": basis_points, "drained": drained }),
        );
        if accept_record(&record, &self.consensus) {
            self.store.put_record(record)?;
        }
        Ok(state)
    }

    pub fn project(
        &mut self,
        vector_id: &str,
        projected_components: Vec<u128>,
        escrow_id: impl Into<String>,
    ) -> Result<VectorStateV1, KernelXError> {
        let state = self.store.get_state(vector_id)?.ok_or(KernelXError::VectorNotFound)?;
        let before = state.clone();
        let mut after = project_vector(state, projected_components.clone(), escrow_id)?;
        after.certification = certify_state(&after, true, true);
        self.store.put_state(after.clone())?;
        let record = VectorRecordV1::new(
            make_record_id("project", vector_id),
            vector_id.to_string(),
            Some(before),
            after.clone(),
            OperationKind::Project,
            serde_json::json!({ "projected_components": projected_components }),
        );
        if accept_record(&record, &self.consensus) {
            self.store.put_record(record)?;
        }
        Ok(after)
    }

    pub fn reconstruct(
        &mut self,
        vector_id: &str,
        outcome: SettlementOutcome,
    ) -> Result<VectorStateV1, KernelXError> {
        let state = self.store.get_state(vector_id)?.ok_or(KernelXError::VectorNotFound)?;
        let before = state.clone();
        let mut after = reconstruct_vector(state, outcome)?;
        after.certification = certify_state(&after, true, true);
        self.store.put_state(after.clone())?;
        let record = VectorRecordV1::new(
            make_record_id("reconstruct", vector_id),
            vector_id.to_string(),
            Some(before),
            after.clone(),
            OperationKind::Reconstruct,
            serde_json::json!({}),
        );
        if accept_record(&record, &self.consensus) {
            self.store.put_record(record)?;
        }
        Ok(after)
    }

    pub fn query_vector(&self, vector_id: &str) -> Result<Option<VectorStateV1>, KernelXError> {
        get_vector(&self.store, vector_id)
    }

    pub fn query_vectors(&self) -> Result<Vec<VectorStateV1>, KernelXError> {
        list_vectors(&self.store)
    }

    pub fn query_records(&self) -> Result<Vec<VectorRecordV1>, KernelXError> {
        list_records(&self.store)
    }
}
