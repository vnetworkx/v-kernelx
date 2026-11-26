use std::collections::BTreeMap;
use vnetwork_types::*;

#[derive(Debug, Clone)]
pub struct ValidatorMembership {
    validators: BTreeMap<String, ConsensusValidator>,
    consensus_parameters: NetworkConsensusParameters,
}

impl ValidatorMembership {
    pub fn try_new(
        validators: Vec<ConsensusValidator>,
        quorum_threshold_bps: u16,
    ) -> VResult<Self> {
        let params = NetworkConsensusParameters::with_quorum_threshold_bps(quorum_threshold_bps)?;
        Self::try_new_with_parameters(validators, params)
    }

    pub fn try_new_with_parameters(
        validators: Vec<ConsensusValidator>,
        consensus_parameters: NetworkConsensusParameters,
    ) -> VResult<Self> {
        validate_validator_set(&validators)?;
        consensus_parameters.validate()?;
        let mut map = BTreeMap::new();
        for v in validators {
            map.insert(v.validator_id.clone(), v);
        }
        Ok(Self {
            validators: map,
            consensus_parameters,
        })
    }

    pub fn validator_set_hash(&self) -> VResult<String> {
        validate_validator_set(&self.all_validators())
    }

    pub fn consensus_parameters(&self) -> &NetworkConsensusParameters {
        &self.consensus_parameters
    }

    pub fn consensus_parameters_hash(&self) -> VResult<String> {
        self.consensus_parameters.parameters_hash()
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

    pub fn total_active_weight(&self) -> VResult<u64> {
        self.validators
            .values()
            .filter(|v| v.active)
            .try_fold(0u64, |acc, v| acc.checked_add(v.weight))
            .ok_or_else(|| VNetworkError::Consensus("active validator weight overflow".to_string()))
    }

    pub fn quorum_threshold_bps(&self) -> u16 {
        self.consensus_parameters.quorum_threshold_bps
    }

    pub fn required_weight(&self) -> VResult<u64> {
        let total = self.total_active_weight()? as u128;
        let bps = self.consensus_parameters.quorum_threshold_bps as u128;
        let weighted = total
            .checked_mul(bps)
            .and_then(|v| v.checked_add(9_999))
            .map(|v| v / 10_000)
            .ok_or_else(|| VNetworkError::Consensus("required quorum weight overflow".to_string()))?;
        u64::try_from(weighted)
            .map_err(|_| VNetworkError::Consensus("required quorum weight exceeds u64".to_string()))
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
