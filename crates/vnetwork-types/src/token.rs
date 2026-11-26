use crate::error::{VNetworkError, VResult};
use serde::{Deserialize, Serialize};

pub const TOKEN_VECTOR_DIMENSIONS: usize = 3;
pub const TOKEN_SCHEMA_VERSION: u16 = 3;

/// Canonical 3-dimensional Token vector:
/// - Dimension 0: `token` (transferable value unit)
/// - Dimension 1: `auth_ratio_au` (non-transferable certification / authority ratio in AU)
/// - Dimension 2: `energy` (non-transferable protocol energy capacity)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenVector {
    pub token: u128,
    pub auth_ratio_au: u128,
    pub energy: u128,
}

impl TokenVector {
    pub fn zero() -> Self {
        Self {
            token: 0,
            auth_ratio_au: 0,
            energy: 0,
        }
    }

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

    /// Explicit migration helper for legacy 2D `[token, energy]` records into 3D v3 vectors.
    /// Never invoked silently during regular execution or parsing.
    pub fn migrate_legacy_2d(components: &[u128], initial_auth_ratio_au: u128) -> VResult<Self> {
        if components.len() != 2 {
            return Err(VNetworkError::DimensionInvariant(format!(
                "legacy 2D migration requires exactly 2 dimensions, got {}",
                components.len()
            )));
        }
        Ok(Self {
            token: components[0],
            auth_ratio_au: initial_auth_ratio_au,
            energy: components[1],
        })
    }

    pub fn as_array(&self) -> [u128; 3] {
        [self.token, self.auth_ratio_au, self.energy]
    }

    pub fn checked_add_token(self, amount: u128) -> VResult<Self> {
        let token = self
            .token
            .checked_add(amount)
            .ok_or_else(|| VNetworkError::Validation("token balance overflow".to_string()))?;
        Ok(Self { token, ..self })
    }

    pub fn checked_sub_token(self, amount: u128) -> VResult<Self> {
        let token = self.token.checked_sub(amount).ok_or_else(|| {
            VNetworkError::InsufficientBalance(format!(
                "insufficient token balance: available {}, required {}",
                self.token, amount
            ))
        })?;
        Ok(Self { token, ..self })
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransferScope {
    SameWallet,
    DifferentWalletsSameRegion,
    DifferentRegionsSameSpace,
    DifferentSpaces,
}

impl TransferScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransferScope::SameWallet => "SAME_WALLET",
            TransferScope::DifferentWalletsSameRegion => "DIFFERENT_WALLETS_SAME_REGION",
            TransferScope::DifferentRegionsSameSpace => "DIFFERENT_REGIONS_SAME_SPACE",
            TransferScope::DifferentSpaces => "DIFFERENT_SPACES",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "bps", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScopeDrainRate {
    Unconfigured,
    ConfiguredBps(u16),
}

impl Default for ScopeDrainRate {
    fn default() -> Self {
        Self::Unconfigured
    }
}

impl ScopeDrainRate {
    pub fn validate(&self) -> VResult<()> {
        if let ScopeDrainRate::ConfiguredBps(bps) = self {
            if *bps > 10_000 {
                return Err(VNetworkError::Validation(format!(
                    "drain rate bps `{bps}` exceeds maximum 10000"
                )));
            }
        }
        Ok(())
    }
}

pub const DRAIN_POLICY_VERSION: u16 = 1;

fn default_drain_policy_version() -> u16 {
    DRAIN_POLICY_VERSION
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainPolicy {
    #[serde(default = "default_drain_policy_version")]
    pub policy_version: u16,
    #[serde(default)]
    pub same_wallet: ScopeDrainRate,
    #[serde(default)]
    pub different_wallets_same_region: ScopeDrainRate,
    #[serde(default)]
    pub different_regions_same_space: ScopeDrainRate,
    #[serde(default)]
    pub different_spaces: ScopeDrainRate,
}

impl Default for DrainPolicy {
    fn default() -> Self {
        Self::unconfigured()
    }
}

impl DrainPolicy {
    pub fn unconfigured() -> Self {
        Self {
            policy_version: DRAIN_POLICY_VERSION,
            same_wallet: ScopeDrainRate::Unconfigured,
            different_wallets_same_region: ScopeDrainRate::Unconfigured,
            different_regions_same_space: ScopeDrainRate::Unconfigured,
            different_spaces: ScopeDrainRate::Unconfigured,
        }
    }

    pub fn new(
        same_wallet: ScopeDrainRate,
        different_wallets_same_region: ScopeDrainRate,
        different_regions_same_space: ScopeDrainRate,
        different_spaces: ScopeDrainRate,
    ) -> VResult<Self> {
        same_wallet.validate()?;
        different_wallets_same_region.validate()?;
        different_regions_same_space.validate()?;
        different_spaces.validate()?;
        Ok(Self {
            policy_version: DRAIN_POLICY_VERSION,
            same_wallet,
            different_wallets_same_region,
            different_regions_same_space,
            different_spaces,
        })
    }

    pub fn validate(&self) -> VResult<()> {
        if self.policy_version != DRAIN_POLICY_VERSION {
            return Err(VNetworkError::Validation(format!(
                "unsupported drain policy version {}",
                self.policy_version
            )));
        }
        self.same_wallet.validate()?;
        self.different_wallets_same_region.validate()?;
        self.different_regions_same_space.validate()?;
        self.different_spaces.validate()?;
        Ok(())
    }

    pub fn rate_for_scope(&self, scope: TransferScope) -> VResult<u16> {
        self.validate()?;
        let rate = match scope {
            TransferScope::SameWallet => self.same_wallet,
            TransferScope::DifferentWalletsSameRegion => self.different_wallets_same_region,
            TransferScope::DifferentRegionsSameSpace => self.different_regions_same_space,
            TransferScope::DifferentSpaces => self.different_spaces,
        };
        match rate {
            ScopeDrainRate::ConfiguredBps(bps) => Ok(bps),
            ScopeDrainRate::Unconfigured => Err(VNetworkError::Validation(format!(
                "drain rate for transfer scope `{}` is UNCONFIGURED; refusing transfer (fail-closed)",
                scope.as_str()
            ))),
        }
    }

    pub fn compute_drain(&self, scope: TransferScope, amount: u128) -> VResult<(u16, u128, u128)> {
        if amount == 0 {
            return Err(VNetworkError::Validation(
                "transfer amount must be positive".to_string(),
            ));
        }
        let bps = self.rate_for_scope(scope)?;
        let fee = amount
            .checked_mul(bps as u128)
            .ok_or_else(|| VNetworkError::Validation("drain fee overflow".to_string()))?
            / 10_000;
        let net = amount
            .checked_sub(fee)
            .ok_or_else(|| VNetworkError::Validation("drain net underflow".to_string()))?;
        Ok((bps, fee, net))
    }
}

