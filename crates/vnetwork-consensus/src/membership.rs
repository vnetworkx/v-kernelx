use std::collections::BTreeMap;
use vnetwork_types::*;

#[derive(Debug, Clone)]
pub struct ValidatorMembership {
    validators: BTreeMap<String, ConsensusValidator>,
    quorum_threshold_bps: u16,
}

impl ValidatorMembership {
    pub fn try_new(
        validators: Vec<ConsensusValidator>,
        quorum_threshold_bps: u16,
    ) -> VResult<Self> {
        validate_validator_set(&validators)?;
        if quorum_threshold_bps < DEFAULT_BFT_QUORUM_BPS || quorum_threshold_bps > 10_000 {
            return Err(VNetworkError::Consensus(format!(
                "invalid quorum_threshold_bps `{quorum_threshold_bps}`; must be within [{DEFAULT_BFT_QUORUM_BPS}..=10000]"
            )));
        }
        let mut map = BTreeMap::new();
        for v in validators {
            map.insert(v.validator_id.clone(), v);
        }
        Ok(Self {
            validators: map,
            quorum_threshold_bps,
        })
    }

    pub fn new(validators: Vec<ConsensusValidator>, quorum_threshold_bps: u16) -> Self {
        Self::try_new(validators, quorum_threshold_bps)
            .expect("invalid validator membership configuration")
    }

    pub fn validator_set_hash(&self) -> VResult<String> {
        validate_validator_set(&self.all_validators())
    }

    pub fn active_validators(&self) -> Vec<ConsensusValidator> {
        self.validators
            .values()
            .filter(|v| v.active)
            .cloned()
            .collect()
    }

    pub fn all_validators(&self) -> Vec<ConsensusValidator> {
        self.validators.values().cloned().collect()
    }

    pub fn get(&self, validator_id: &str) -> Option<&ConsensusValidator> {
        self.validators.get(validator_id)
    }

    pub fn get_by_pubkey(&self, pubkey_hex: &str) -> Option<&ConsensusValidator> {
        let Ok(target_bytes) = canonical_ed25519_pubkey_bytes(pubkey_hex) else {
            return None;
        };
        self.validators.values().find(|v| {
            canonical_ed25519_pubkey_bytes(&v.validator_pubkey_hex)
                .map_or(false, |b| b == target_bytes)
        })
    }

    pub fn total_active_weight(&self) -> u64 {
        self.validators
            .values()
            .filter(|v| v.active)
            .map(|v| v.weight)
            .sum()
    }

    pub fn quorum_threshold_bps(&self) -> u16 {
        self.quorum_threshold_bps
    }

    pub fn required_weight(&self) -> u64 {
        let total = self.total_active_weight() as u128;
        let bps = self.quorum_threshold_bps as u128;
        ((total * bps + 9_999) / 10_000) as u64
    }

    pub fn upsert_validator(&mut self, validator: ConsensusValidator) -> VResult<()> {
        let mut next = self.validators.clone();
        next.insert(validator.validator_id.clone(), validator);
        let list: Vec<ConsensusValidator> = next.values().cloned().collect();
        validate_validator_set(&list)?;
        self.validators = next;
        Ok(())
    }

    pub fn deactivate_validator(&mut self, validator_id: &str) -> VResult<()> {
        let mut next = self.validators.clone();
        let v = next.get_mut(validator_id).ok_or_else(|| {
            VNetworkError::NotFound(format!("validator `{validator_id}`"))
        })?;
        v.active = false;
        let list: Vec<ConsensusValidator> = next.values().cloned().collect();
        validate_validator_set(&list)?;
        self.validators = next;
        Ok(())
    }
}
