use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use vnetwork_sdk::{ClientIdentity, ClientIdentityMetadata, EncryptedClientIdentity};
use vnetwork_types::{KeyKdfParams, KeypairMaterial};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyPlaintextCliIdentity {
    pub display_name: String,
    pub participant_id: String,
    pub node_id: String,
    pub participant_key: KeypairMaterial,
    pub node_key: KeypairMaterial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliState {
    pub endpoint: String,
    pub network_id: Option<String>,
    #[serde(default)]
    pub identity_metadata: Option<ClientIdentityMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_identity: Option<EncryptedClientIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_plaintext_identity: Option<LegacyPlaintextCliIdentity>,
    pub nonce: u64,
}

impl Default for CliState {
    fn default() -> Self {
        Self {
            endpoint: std::env::var("VNETWORK_ENDPOINT")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "http://127.0.0.1:8080".to_string()),
            network_id: None,
            identity_metadata: None,
            encrypted_identity: None,
            legacy_plaintext_identity: None,
            nonce: 1,
        }
    }
}

pub fn cli_state_path() -> PathBuf {
    let dir = std::env::var("VNETWORK_CLI_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".vnetwork"))
                .unwrap_or_else(|_| PathBuf::from(".vnetwork"))
        });
    dir.join("cli.json")
}

pub fn resolve_cli_passphrase(
    cli_passphrase: Option<&str>,
    passphrase_file: Option<&Path>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if let Some(p) = cli_passphrase {
        if !p.is_empty() {
            return Ok(Some(p.to_string()));
        }
    }
    if let Some(path) = passphrase_file {
        let content = fs::read_to_string(path)?;
        let trimmed = content.trim_end_matches(&['\r', '\n'][..]).to_string();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed));
        }
    }
    for env_name in ["VNETWORK_CLI_PASSPHRASE", "NETWORK_KEY_PASSPHRASE"] {
        if let Ok(val) = std::env::var(env_name) {
            if !val.is_empty() {
                return Ok(Some(val));
            }
        }
    }
    Ok(None)
}

pub fn store_cli_identity(
    state: &mut CliState,
    identity: &ClientIdentity,
    passphrase: Option<&str>,
    allow_plaintext_fallback: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    state.legacy_plaintext_identity = None;
    if let Some(pass) = passphrase {
        let encrypted = identity.encrypt_envelopes(pass, Some(KeyKdfParams::default()))?;
        state.identity_metadata = Some(identity.metadata("encrypted-argon2id-aes256gcm"));
        state.encrypted_identity = Some(encrypted);
        return Ok(());
    }
    if allow_plaintext_fallback {
        let (p_kp, n_kp) = identity.export_legacy_plaintext_keypairs_unsafe();
        state.identity_metadata = Some(identity.metadata("explicit-plaintext-fallback"));
        state.encrypted_identity = None;
        state.legacy_plaintext_identity = Some(LegacyPlaintextCliIdentity {
            display_name: identity.display_name.clone(),
            participant_id: identity.participant_id.clone(),
            node_id: identity.node_id.clone(),
            participant_key: p_kp,
            node_key: n_kp,
        });
        return Ok(());
    }
    Err("refusing to persist CLI identity without encryption passphrase; set VNETWORK_CLI_PASSPHRASE / NETWORK_KEY_PASSPHRASE or pass --passphrase / --passphrase-file (or explicit --allow-plaintext-key-fallback for dev)".into())
}

pub fn load_cli_identity(
    state: &CliState,
    passphrase: Option<&str>,
    allow_plaintext_fallback: bool,
) -> Result<ClientIdentity, Box<dyn std::error::Error>> {
    if let Some(enc) = &state.encrypted_identity {
        let pass = passphrase.ok_or(
            "encrypted CLI identity requires passphrase via --passphrase, --passphrase-file, VNETWORK_CLI_PASSPHRASE, or NETWORK_KEY_PASSPHRASE",
        )?;
        return Ok(ClientIdentity::from_envelopes(enc, pass)?);
    }
    if let Some(legacy) = &state.legacy_plaintext_identity {
        if !allow_plaintext_fallback {
            return Err("refusing to load unencrypted CLI identity without explicit --allow-plaintext-key-fallback".into());
        }
        return Ok(ClientIdentity::from_legacy_plaintext_keypairs_unsafe(
            &legacy.display_name,
            &legacy.participant_key,
            &legacy.node_key,
        )?);
    }
    Err("no local identity found; run `vn identity create` first".into())
}

pub fn load_cli_state() -> Result<CliState, Box<dyn std::error::Error>> {
    let path = cli_state_path();
    if !path.exists() {
        return Ok(CliState::default());
    }
    let raw = fs::read_to_string(&path)?;
    let val: serde_json::Value = serde_json::from_str(&raw)?;
    if val.get("identity").is_some() && val.get("encrypted_identity").is_none() {
        return Err(
            "legacy plaintext `identity` field detected in cli.json; remove it or recreate identity with `vn identity create`"
                .into(),
        );
    }
    Ok(serde_json::from_value::<CliState>(val)?)
}

pub fn save_cli_state(state: &CliState) -> Result<(), Box<dyn std::error::Error>> {
    let path = cli_state_path();
    let parent = path.parent().ok_or("invalid cli state path")?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }

    let json = serde_json::to_vec_pretty(state)?;
    let tmp_path = path.with_file_name("cli.json.enc.tmp");
    let mut file = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(&tmp_path)?
        }
        #[cfg(not(unix))]
        {
            fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp_path)?
        }
    };
    file.write_all(&json)?;
    file.sync_all()?;
    drop(file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&tmp_path, &path)?;
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_identity_requires_passphrase_by_default_and_roundtrips_encrypted() {
        let mut state = CliState::default();
        let id = ClientIdentity::generate("cli-unit");
        let err = store_cli_identity(&mut state, &id, None, false).unwrap_err();
        assert!(err.to_string().contains("passphrase"));

        store_cli_identity(&mut state, &id, Some("cli-strong-pass-!"), false).unwrap();
        assert!(state.encrypted_identity.is_some());
        assert!(state.legacy_plaintext_identity.is_none());

        assert!(load_cli_identity(&state, None, false).is_err());
        assert!(load_cli_identity(&state, Some("wrong-pass"), false).is_err());
        let loaded = load_cli_identity(&state, Some("cli-strong-pass-!"), false).unwrap();
        assert_eq!(loaded.participant_id, id.participant_id);
        assert_eq!(loaded.node_id, id.node_id);
    }

    #[test]
    fn cli_plaintext_fallback_requires_explicit_opt_in_to_load() {
        let mut state = CliState::default();
        let id = ClientIdentity::generate("cli-plain");
        store_cli_identity(&mut state, &id, None, true).unwrap();
        assert!(state.legacy_plaintext_identity.is_some());
        assert!(load_cli_identity(&state, None, false).is_err());
        let loaded = load_cli_identity(&state, None, true).unwrap();
        assert_eq!(loaded.participant_id, id.participant_id);
    }
}
