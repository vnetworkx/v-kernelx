use crate::error::{VNetworkError, VResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Amount(pub u128);

impl Amount {
    pub fn checked_add(self, rhs: Self) -> VResult<Self> {
        self.0
            .checked_add(rhs.0)
            .map(Amount)
            .ok_or_else(|| VNetworkError::Validation("amount overflow".to_string()))
    }

    pub fn checked_sub(self, rhs: Self) -> VResult<Self> {
        self.0
            .checked_sub(rhs.0)
            .map(Amount)
            .ok_or_else(|| VNetworkError::InsufficientBalance("insufficient amount".to_string()))
    }
}
