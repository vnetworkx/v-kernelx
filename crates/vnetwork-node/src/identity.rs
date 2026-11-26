use libp2p::identity as p2p_id;
use std::fs;
use std::path::Path;
use vnetwork_types::*;

#[derive(Debug, Clone)]
pub struct NodeIdentity {
    pub node_keypair: KeypairMaterial,
    pub node_id: String,
    pub libp2p_keypair: p2p_id::Keypair,
    pub libp2p_peer_id: libp2p::PeerId,
    pub validator_keypair: Option<KeypairMaterial>,
    pub validator_id: Option<String>,
}

impl NodeIdentity {
    pub fn load_or_create(
        node_key_path: &Path,
        validator_key_path: Option<&Path>,
        explicit_validator_id: Option<&str>,
        enable_validator: bool,
    ) -> VResult<Self> {
        let node_keypair = load_or_generate_key(node_key_path, "node")?;
        let node_id = derive_node_id(&node_keypair.public_key_hex);
        let libp2p_keypair = to_libp2p_ed25519(&node_keypair)?;
        let libp2p_peer_id = libp2p::PeerId::from(libp2p_keypair.public());

        let (validator_keypair, validator_id) = if enable_validator {
            let vpath = validator_key_path.map(|p| p.to_path_buf()).unwrap_or_else(|| {
                node_key_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join("validator.key.json")
            });
            let vkp = load_or_generate_key(&vpath, "validator")?;
            if vkp.public_key_hex == node_keypair.public_key_hex {
                return Err(VNetworkError::Authorization(
                    "validator key must remain distinct from node identity key".to_string(),
                ));
            }
            let vid = explicit_validator_id
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("val_{}", &vkp.public_key_hex[..16]));
            (Some(vkp), Some(vid))
        } else {
            (None, None)
        };

        Ok(Self {
            node_keypair,
            node_id,
            libp2p_keypair,
            libp2p_peer_id,
            validator_keypair,
            validator_id,
        })
    }
}

pub fn load_or_generate_key(path: &Path, role: &str) -> VResult<KeypairMaterial> {
    if path.exists() {
        let raw = fs::read_to_string(path)
            .map_err(|e| VNetworkError::Storage(format!("read key {:?} failed: {e}", path)))?;
        let kp: KeypairMaterial = serde_json::from_str(&raw)
            .map_err(|e| VNetworkError::Serialization(format!("parse key {:?} failed: {e}", path)))?;
        return Ok(kp);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| VNetworkError::Storage(format!("create key dir failed: {e}")))?;
    }
    let kp = KeypairMaterial::generate(role);
    let json = serde_json::to_vec_pretty(&kp)
        .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
    fs::write(path, json)
        .map_err(|e| VNetworkError::Storage(format!("write key {:?} failed: {e}", path)))?;
    Ok(kp)
}

pub fn to_libp2p_ed25519(kp: &KeypairMaterial) -> VResult<p2p_id::Keypair> {
    let mut sk_bytes = hex::decode(&kp.private_key_hex)
        .map_err(|_| VNetworkError::Signature("invalid node private key hex".to_string()))?;
    p2p_id::Keypair::ed25519_from_bytes(&mut sk_bytes)
        .map_err(|e| VNetworkError::Signature(format!("libp2p ed25519 key error: {e}")))
}
