use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochState {
    pub current_epoch: u64,
    pub blocks_per_epoch: u64,
    pub epoch_start_height: u64,
}

impl Default for EpochState {
    fn default() -> Self {
        Self {
            current_epoch: 1,
            blocks_per_epoch: 100,
            epoch_start_height: 0,
        }
    }
}

impl EpochState {
    pub fn epoch_for_height(&self, height: u64) -> u64 {
        if self.blocks_per_epoch == 0 {
            1
        } else {
            (height / self.blocks_per_epoch) + 1
        }
    }
}
