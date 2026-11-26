use crate::language::adapter::compile_vx_source;
use crate::language::program::execute_compiled_program_staged;
use crate::state::{GenesisConfig, NetworkLedgerState};
use std::collections::BTreeMap;
use vnetwork_types::*;

/// Independently recompiles source bytes + verified module bundle and re-executes
/// against `state` to confirm proposal integrity before a validator votes.
pub fn validator_verify_program_bundle(
    state: &NetworkLedgerState,
    genesis: &GenesisConfig,
    bundle: &ProgramSourceBundle,
    proposal: &ConsensusProposal,
    actor_pubkey: &str,
) -> VResult<()> {
    let actual_source_hash = blake3_hex(bundle.source_bytes.as_bytes());
    if actual_source_hash != bundle.source_hash {
        return Err(VNetworkError::Consensus(format!(
            "program source hash mismatch: expected {}, got {actual_source_hash}",
            bundle.source_hash
        )));
    }

    let compiled = compile_vx_source(
        &bundle.source_bytes,
        &bundle.file_name,
        &bundle.resolved_module_sources,
        None,
    )?;

    if compiled.program_hash != bundle.compiled_program_hash {
        return Err(VNetworkError::Consensus(format!(
            "compiled program hash mismatch during validator verification: expected {}, got {}",
            bundle.compiled_program_hash, compiled.program_hash
        )));
    }

    let staged = execute_compiled_program_staged(
        state,
        genesis,
        &compiled,
        actor_pubkey,
        proposal.timestamp_ms,
    )
    .map_err(|pf| {
        VNetworkError::Consensus(format!(
            "validator re-execution failed at op {}: {}",
            pf.failed_operation_index, pf.error
        ))
    })?;

    if staged.post_state_root != proposal.post_state_root {
        return Err(VNetworkError::Consensus(format!(
            "validator re-execution post_state_root `{}` != proposal `{}`",
            staged.post_state_root, proposal.post_state_root
        )));
    }
    Ok(())
}

pub fn collect_module_commitments(
    inline_modules: &BTreeMap<String, String>,
) -> Vec<ModuleCommitment> {
    inline_modules
        .iter()
        .map(|(path, src)| ModuleCommitment {
            path: path.clone(),
            blake3_hash: blake3_hex(src.as_bytes()),
        })
        .collect()
}
