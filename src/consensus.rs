use crate::record::VectorRecordV1;

#[derive(Clone, Debug)]
pub struct ConsensusPolicy {
    pub min_auth_ratio: u16,
    pub require_certified: bool,
}

impl Default for ConsensusPolicy {
    fn default() -> Self {
        Self {
            min_auth_ratio: 700,
            require_certified: true,
        }
    }
}

pub fn accept_record(record: &VectorRecordV1, policy: &ConsensusPolicy) -> bool {
    if policy.require_certified && !record.certification.certified {
        return false;
    }
    record.certification.auth_ratio >= policy.min_auth_ratio
}
