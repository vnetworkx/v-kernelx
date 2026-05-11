use crate::error::KernelXError;
use crate::origin::find_valid_nonce;
use crate::reconstruction::SettlementOutcome;
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

        let seed_a = "seed-a";
        let seed_b = "seed-b";
        let nonce_a = find_valid_nonce(seed_a, 1, 1_000_000).ok_or(KernelXError::OriginRejected)?;
        let nonce_b = find_valid_nonce(seed_b, 1, 1_000_000).ok_or(KernelXError::OriginRejected)?;

        self.kernel.origin_create("v-a", wallet_a.public_key_hex(), "space-1", vec![1000, 2000], seed_a, nonce_a, 1)?;
        self.kernel.origin_create("v-b", wallet_b.public_key_hex(), "space-1", vec![50, 75], seed_b, nonce_b, 1)?;
        self.kernel.transfer("v-a", "v-b", vec![250, 250])?;
        self.kernel.drain("v-a", 100)?;
        self.kernel.project("v-b", vec![10, 10], "escrow-1")?;
        self.kernel.reconstruct(
            "v-b",
            SettlementOutcome {
                outcome_tag: "settled".to_string(),
                gains: vec![2, 1],
                losses: vec![0, 0],
            },
        )?;
        let vectors = self.kernel.engine.query_vectors()?;
        let records = self.kernel.engine.query_records()?.len();
        Ok(SimulationReport { vectors, records })
    }
}
