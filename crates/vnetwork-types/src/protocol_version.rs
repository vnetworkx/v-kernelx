use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: &str = "vector-network/1.0.0";
pub const LANGUAGE_VERSION: &str = "v-langx/1.2.0";
pub const COMPILER_VERSION: &str = "vectorspace-compiler/1.2.0";
pub const PROPOSAL_VERSION: u16 = 1;
pub const CHECKPOINT_VERSION: u16 = 1;

// Explicit cryptographic domain separation tags
pub const DOM_PROPOSAL_DIGEST_V1: &str = "vnetwork/proposal-digest/v1";
pub const DOM_PROPOSAL_SIGN_V1: &str = "vnetwork/proposal-sign/v1";
pub const DOM_VOTE_SIGN_V1: &str = "vnetwork/consensus-vote/v1";
pub const DOM_QC_V1: &str = "vnetwork/quorum-certificate/v1";
pub const DOM_CHECKPOINT_V1: &str = "vnetwork/certified-checkpoint/v1";
pub const DOM_EVENT_HISTORY_V1: &str = "vnetwork/event-history/v1";
pub const DOM_VALIDATOR_EPOCH_V1: &str = "vnetwork/validator-epoch/v1";
pub const DOM_EPOCH_TRANSITION_V1: &str = "vnetwork/epoch-transition/v1";
pub const DOM_CONSENSUS_PARAMS_V1: &str = "vnetwork/consensus-params/v1";
pub const DOM_KEY_ENVELOPE_V1: &str = "vnetwork/key-envelope/v1";
pub const DOM_EQUIVOCATION_RECORD_V1: &str = "vnetwork/equivocation-record/v1";
pub const DOM_EQUIVOCATION_INCIDENT_V1: &str = "vnetwork/equivocation-incident/v1";
pub const DOM_TRANSFER_APPROVAL_V1: &str = "vnetwork/transfer-approval/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationStatus {
    Verified,
    Unverified,
    Invalid,
    Unknown,
    Pending,
}

impl Default for VerificationStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NetworkProfile {
    Development,
    Testnet,
    Production,
}

impl NetworkProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkProfile::Development => "DEVELOPMENT",
            NetworkProfile::Testnet => "TESTNET",
            NetworkProfile::Production => "PRODUCTION",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "DEVELOPMENT" | "DEV" => Some(Self::Development),
            "TESTNET" | "TEST" => Some(Self::Testnet),
            "PRODUCTION" | "MAINNET" | "PROD" => Some(Self::Production),
            _ => None,
        }
    }

    pub fn default_network_id(&self) -> &'static str {
        match self {
            NetworkProfile::Development => "vector-devnet-1",
            NetworkProfile::Testnet => "vector-testnet-1",
            NetworkProfile::Production => "vector-main",
        }
    }

    pub fn allows_dev_atlas_fixture(&self) -> bool {
        matches!(self, NetworkProfile::Development | NetworkProfile::Testnet)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolCompatibility {
    pub protocol_version: String,
    pub language_version: String,
    pub compiler_version: String,
    pub network_id: String,
    pub profile: NetworkProfile,
}
