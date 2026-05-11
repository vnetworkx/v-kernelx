use crate::error::KernelXError;
use crate::record::VectorRecordV1;
use crate::state::VectorStateV1;
use crate::storage::StateStore;

pub fn get_vector<S: StateStore>(store: &S, vector_id: &str) -> Result<Option<VectorStateV1>, KernelXError> {
    store.get_state(vector_id)
}

pub fn list_vectors<S: StateStore>(store: &S) -> Result<Vec<VectorStateV1>, KernelXError> {
    store.list_states()
}

pub fn get_record<S: StateStore>(store: &S, record_id: &str) -> Result<Option<VectorRecordV1>, KernelXError> {
    store.get_record(record_id)
}

pub fn list_records<S: StateStore>(store: &S) -> Result<Vec<VectorRecordV1>, KernelXError> {
    store.list_records()
}
