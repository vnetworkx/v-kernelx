use crate::error::KernelXError;
use serde::{Deserialize, Serialize};

pub const DEFAULT_TRANSFER_DRAIN_BPS: u16 = 200; // 2.00% base drain, halved to 1.00% when certified

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DrainRewardDistribution {
    pub effective_bps: u16,
    pub total_fee: Vec<u128>,
    pub net_received: Vec<u128>,
    pub region_creator_reward: Vec<u128>,
    pub wallet_creator_reward: Vec<u128>,
    pub token_creator_reward: Vec<u128>,
    pub network_reward: Vec<u128>,
}

pub fn apply_drain(
    amounts: &[u128],
    basis_points: u16,
    auth_ratio: u16,
    threshold: u16,
) -> Result<(Vec<u128>, Vec<u128>), KernelXError> {
    if basis_points > 10_000 {
        return Err(KernelXError::Rejected(
            "drain basis points must be <= 10000".to_string(),
        ));
    }

    let discount = if auth_ratio >= threshold {
        basis_points / 2
    } else {
        basis_points
    };

    let mut drained = Vec::with_capacity(amounts.len());
    let mut remaining = Vec::with_capacity(amounts.len());

    for amount in amounts {
        let fee = amount.saturating_mul(discount as u128) / 10_000u128;
        drained.push(fee);
        remaining.push(amount.saturating_sub(fee));
    }

    Ok((drained, remaining))
}

/// Applies drain fees on multidimensional transfer components and splits fees equally
/// across region creator, wallet creator, token/vector creator, and the network pool
/// with zero rounding leakage (net_received + sum(rewards) == amount).
pub fn apply_transfer_drain(
    amounts: &[u128],
    basis_points: u16,
    auth_ratio: u16,
    threshold: u16,
) -> Result<DrainRewardDistribution, KernelXError> {
    if basis_points > 10_000 {
        return Err(KernelXError::Rejected(
            "drain basis points must be <= 10000".to_string(),
        ));
    }

    let effective_bps = if auth_ratio >= threshold {
        basis_points / 2
    } else {
        basis_points
    };

    let (total_fee, net_received) = apply_drain(amounts, basis_points, auth_ratio, threshold)?;

    let mut region_creator_reward = Vec::with_capacity(amounts.len());
    let mut wallet_creator_reward = Vec::with_capacity(amounts.len());
    let mut token_creator_reward = Vec::with_capacity(amounts.len());
    let mut network_reward = Vec::with_capacity(amounts.len());

    for fee in &total_fee {
        let quarter = fee / 4;
        let rem = fee.saturating_sub(quarter.saturating_mul(3));
        region_creator_reward.push(quarter);
        wallet_creator_reward.push(quarter);
        token_creator_reward.push(quarter);
        network_reward.push(rem);
    }

    Ok(DrainRewardDistribution {
        effective_bps,
        total_fee,
        net_received,
        region_creator_reward,
        wallet_creator_reward,
        token_creator_reward,
        network_reward,
    })
}
