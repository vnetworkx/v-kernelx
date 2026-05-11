use crate::error::KernelXError;
use crate::sdk::VectorKernel;
use crate::state::VectorStateV1;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimulationReport {
    pub vectors: Vec<VectorStateV1>,
    pub records: usize,
}

pub struct SimulationHarness {
    pub kernel: VectorKernel,
}

impl SimulationHarness {
    pub fn new() -> Self {
        Self {
            kernel: VectorKernel::new(),
        }
    }

    pub fn basic_flow(&mut self) -> Result<SimulationReport, KernelXError> {
        let wallet_a = self.kernel.wallet();
        let wallet_b = self.kernel.wallet();
        self.kernel.origin_create("v-a", wallet_a.public_key_hex(), "space-1", vec![1000, 2000], "seed-a", 1, 1)?;
        self.kernel.origin_create("v-b", wallet_b.public_key_hex(), "space-1", vec![50, 75], "seed-b", 2, 1)?;
        self.kernel.transfer("v-a", "v-b", vec![250, 250])?;
        self.kernel.drain("v-a", 100)?;
        self.kernel.project("v-b", vec![10, 10], "escrow-1")?;
        let vectors = self.kernel.engine.query_vectors()?;
        let records = self.kernel.engine.query_records()?.len();
        Ok(SimulationReport { vectors, records })
    }
}
