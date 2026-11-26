use std::collections::BTreeMap;
use vnetwork_types::*;

#[derive(Debug, Clone)]
pub struct ValidatorMembership {
    validators: BTreeMap<String, ConsensusValidator>,
    quorum_threshold_bps: u16,
}

impl ValidatorMembership {
    pub fn new(validators: Vec<ConsensusValidator>, quorum_threshold_bps: u16) -> Self {
        let mut map = BTreeMap::new();
        for v in validators {
            map.insert(v.validator_id.clone(), v);
        }
        Self {
            validators: map,
            quorum_threshold_bps: quorum_threshold_bps.max(DEFAULT_BFT_QUORUM_BPS),
        }
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
        self.validators
            .values()
            .find(|v| v.validator_pubkey_hex == pubkey_hex)
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

    pub fn upsert_validator(&mut self, validator: ConsensusValidator) {
        self.validators
            .insert(validator.validator_id.clone(), validator);
    }

    pub fn deactivate_validator(&mut self, validator_id: &str) {
        if let Some(v) = self.validators.get_mut(validator_id) {
            v.active = false;
        }
    }
}
