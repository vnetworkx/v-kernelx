use crate::error::KernelXError;
use crate::record::VectorRecordV1;
use crate::state::VectorStateV1;
use std::collections::BTreeMap;

pub trait StateStore {
    fn put_state(&mut self, state: VectorStateV1) -> Result<(), KernelXError>;
    fn get_state(&self, vector_id: &str) -> Result<Option<VectorStateV1>, KernelXError>;
    fn list_states(&self) -> Result<Vec<VectorStateV1>, KernelXError>;
    fn put_record(&mut self, record: VectorRecordV1) -> Result<(), KernelXError>;
    fn get_record(&self, record_id: &str) -> Result<Option<VectorRecordV1>, KernelXError>;
    fn list_records(&self) -> Result<Vec<VectorRecordV1>, KernelXError>;
}

#[derive(Clone, Default)]
pub struct MemoryStore {
    states: BTreeMap<String, VectorStateV1>,
    records: BTreeMap<String, VectorRecordV1>,
}

impl StateStore for MemoryStore {
    fn put_state(&mut self, state: VectorStateV1) -> Result<(), KernelXError> {
        self.states.insert(state.vector_id.clone(), state);
        Ok(())
    }

    fn get_state(&self, vector_id: &str) -> Result<Option<VectorStateV1>, KernelXError> {
        Ok(self.states.get(vector_id).cloned())
    }

    fn list_states(&self) -> Result<Vec<VectorStateV1>, KernelXError> {
        Ok(self.states.values().cloned().collect())
    }

    fn put_record(&mut self, record: VectorRecordV1) -> Result<(), KernelXError> {
        self.records.insert(record.record_id.clone(), record);
        Ok(())
    }

    fn get_record(&self, record_id: &str) -> Result<Option<VectorRecordV1>, KernelXError> {
        Ok(self.records.get(record_id).cloned())
    }

    fn list_records(&self) -> Result<Vec<VectorRecordV1>, KernelXError> {
        Ok(self.records.values().cloned().collect())
    }
}
