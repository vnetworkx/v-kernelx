use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: &str = "vector-network/1.0.0";
pub const LANGUAGE_VERSION: &str = "v-langx/1.2.0";
pub const COMPILER_VERSION: &str = "vectorspace-compiler/1.2.0";

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
            "DEVELOPMENT" | "DEV" => Some(NetworkProfile::Development),
            "TESTNET" | "TEST" => Some(NetworkProfile::Testnet),
            "PRODUCTION" | "MAINNET" | "PROD" => Some(NetworkProfile::Production),
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
