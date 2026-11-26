use crate::error::{VNetworkError, VResult};
use serde::{Deserialize, Serialize};

pub const TOKEN_VECTOR_DIMENSIONS: usize = 3;

/// Canonical 3-dimensional Token vector:
/// - Dimension 0: `token` (transferable value unit)
/// - Dimension 1: `authratio_au` (non-transferable certification / authority ratio in AU)
/// - Dimension 2: `energy` (non-transferable protocol energy capacity)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenVector {
    pub token: u128,
    pub auth_ratio_au: u128,
    pub energy: u128,
}

impl TokenVector {
    pub fn new(token: u128, auth_ratio_au: u128, energy: u128) -> Self {
        Self {
            token,
            auth_ratio_au,
            energy,
        }
    }

    pub fn from_slice(components: &[u128]) -> VResult<Self> {
        if components.len() != TOKEN_VECTOR_DIMENSIONS {
            return Err(VNetworkError::DimensionInvariant(format!(
                "token vector must have exactly 3 dimensions [token, authratio(au), energy], got {}",
                components.len()
            )));
        }
        Ok(Self {
            token: components[0],
            auth_ratio_au: components[1],
            energy: components[2],
        })
    }

    pub fn as_array(&self) -> [u128; 3] {
        [self.token, self.auth_ratio_au, self.energy]
    }

    /// Only dimension 0 (`token`) is transferable. `auth_ratio_au` and `energy` NEVER move across wallets.
    pub fn verify_transfer_invariant(
        before_from: &TokenVector,
        after_from: &TokenVector,
        before_to: &TokenVector,
        after_to: &TokenVector,
    ) -> VResult<()> {
        if before_from.auth_ratio_au != after_from.auth_ratio_au
            || before_to.auth_ratio_au != after_to.auth_ratio_au
        {
            return Err(VNetworkError::DimensionInvariant(
                "AuthRatio (dimension 1) is non-transferable and cannot change during transfer"
                    .to_string(),
            ));
        }
        if before_from.energy != after_from.energy || before_to.energy != after_to.energy {
            return Err(VNetworkError::DimensionInvariant(
                "Energy (dimension 2) is non-transferable and cannot change during transfer"
                    .to_string(),
            ));
        }
        Ok(())
    }
}
