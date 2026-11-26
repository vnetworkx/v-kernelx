use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use v_langx::compiler::CompiledProgram;
use vnetwork_types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitProgramRequest {
    pub file_name: String,
    pub source_bytes: String,
    #[serde(default)]
    pub modules: BTreeMap<String, String>,
    pub actor_pubkey: String,
    pub network_id: String,
    pub request_id: String,
    pub nonce: u64,
    pub signature: String,
    #[serde(default)]
    pub execution_params: BTreeMap<String, serde_json::Value>,
}

impl SubmitProgramRequest {
    pub fn file_kind(&self) -> &'static str {
        if self.file_name.ends_with(".vdx") {
            "vdx"
        } else {
            "vx"
        }
    }

    pub fn canonical_signing_bytes(&self) -> VResult<Vec<u8>> {
        let source_hash = blake3_hex(self.source_bytes.as_bytes());
        let mut module_hashes = BTreeMap::new();
        for (path, src) in &self.modules {
            module_hashes.insert(path.clone(), blake3_hex(src.as_bytes()));
        }
        let obj = serde_json::json!({
            "actor_pubkey": self.actor_pubkey,
            "compiler_version": v_langx::compiler::COMPILER_VERSION,
            "execution_params": self.execution_params,
            "file_kind": self.file_kind(),
            "file_name": self.file_name,
            "language_version": v_langx::compiler::LANGUAGE_VERSION,
            "module_hashes": module_hashes,
            "network_id": self.network_id,
            "nonce": self.nonce,
            "protocol_version": PROTOCOL_VERSION,
            "request_id": self.request_id,
            "source_hash": source_hash,
        });
        canonical_json_bytes(&obj)
    }

    pub fn verify_signature(&self) -> VResult<()> {
        let bytes = self.canonical_signing_bytes()?;
        verify_ed25519(&self.actor_pubkey, &bytes, &self.signature)
    }
}

pub fn build_program_submission(
    req: &SubmitProgramRequest,
    compiled: Option<&CompiledProgram>,
    status: ProgramLifecycleStatus,
    timestamp_ms: u64,
) -> ProgramSubmission {
    let source_hash = blake3_hex(req.source_bytes.as_bytes());
    let program_id = derive_program_id(&source_hash, &req.actor_pubkey, req.nonce);
    let participant_id = derive_participant_id(&req.actor_pubkey);
    let file_kind = req.file_kind().to_string();

    let (lang_ver, comp_ver, imported, compiled_hash) = match compiled {
        Some(c) => (
            c.language_version.clone(),
            c.compiler_version.clone(),
            c.imported_modules
                .iter()
                .map(|m| ModuleCommitment {
                    path: m.path.clone(),
                    blake3_hash: m.blake3_hash.clone(),
                })
                .collect(),
            c.program_hash.clone(),
        ),
        None => (
            v_langx::compiler::LANGUAGE_VERSION.to_string(),
            v_langx::compiler::COMPILER_VERSION.to_string(),
            Vec::new(),
            String::new(),
        ),
    };

    ProgramSubmission {
        program_id,
        file_name: req.file_name.clone(),
        file_kind,
        source_bytes: req.source_bytes.clone(),
        source_hash,
        language_version: lang_ver,
        compiler_version: comp_ver,
        imported_modules: imported,
        resolved_module_sources: req.modules.clone(),
        compiled_program_hash: compiled_hash,
        protocol_version: PROTOCOL_VERSION.to_string(),
        network_id: req.network_id.clone(),
        submitter_participant_id: participant_id,
        submitter_pubkey: req.actor_pubkey.clone(),
        request_id: req.request_id.clone(),
        nonce: req.nonce,
        signature: req.signature.clone(),
        execution_params: req.execution_params.clone(),
        status,
        failed_operation_index: None,
        error_message: None,
        resulting_event_ids: Vec::new(),
        consensus_certificate: None,
        final_state_root: None,
        created_entities: Vec::new(),
        outputs: Vec::new(),
        submitted_at_ms: timestamp_ms,
        updated_at_ms: timestamp_ms,
    }
}
