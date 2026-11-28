use crate::language::adapter::compile_vx_source;
use crate::language::program::execute_compiled_program_staged;
use crate::language::submission::SubmitProgramRequest;
use crate::state::{GenesisConfig, NetworkLedgerState};
use std::collections::BTreeMap;
use vnetwork_types::*;

/// Independently recompiles source bytes + verified module bundle and re-executes
/// against `state`, authenticating actor, versions, execution params, and exact event commitments.
pub fn validator_verify_program_bundle(
    state: &NetworkLedgerState,
    genesis: &GenesisConfig,
    bundle: &ProgramSourceBundle,
    proposal: &ConsensusProposal,
    actor_pubkey: &str,
) -> VResult<()> {
    let (bound_actor, bound_request_id, bound_nonce) =
        proposal.nonce_binding.as_ref().ok_or_else(|| {
            VNetworkError::Consensus(
                "program proposal missing mandatory nonce_binding actor commitment".to_string(),
            )
        })?;
    if bound_actor != actor_pubkey {
        return Err(VNetworkError::Authorization(format!(
            "program actor_pubkey `{actor_pubkey}` does not match proposal nonce_binding `{bound_actor}`"
        )));
    }

    let submitter_signature = bundle.submitter_signature.as_ref().ok_or_else(|| {
        VNetworkError::Authorization(
            "program proposal is missing the submitter's authenticated signature".to_string(),
        )
    })?;
    let signed_request = SubmitProgramRequest {
        file_name: bundle.file_name.clone(),
        source_bytes: bundle.source_bytes.clone(),
        modules: bundle.resolved_module_sources.clone(),
        actor_pubkey: bound_actor.clone(),
        network_id: state.network_id.clone(),
        request_id: bound_request_id.clone(),
        nonce: *bound_nonce,
        signature: submitter_signature.clone(),
        execution_params: bundle.execution_params.clone(),
    };
    signed_request.verify_signature()?;

    let expected_program_id = derive_program_id(&bundle.source_hash, actor_pubkey, *bound_nonce);
    if proposal.program_id.as_deref() != Some(expected_program_id.as_str())
        || proposal.tx_id.as_deref() != Some(expected_program_id.as_str())
        || proposal.operation_scope != format!("VX_PROGRAM:{}", bundle.file_name)
    {
        return Err(VNetworkError::Consensus(
            "program proposal identity/scope does not match the signed submission".to_string(),
        ));
    }
    if bundle.language_version != v_langx::compiler::LANGUAGE_VERSION
        || bundle.compiler_version != v_langx::compiler::COMPILER_VERSION
    {
        return Err(VNetworkError::Consensus(format!(
            "program bundle language/compiler version mismatch: got {}/{}",
            bundle.language_version, bundle.compiler_version
        )));
    }
    if proposal.execution_params != bundle.execution_params {
        return Err(VNetworkError::Consensus(
            "proposal execution_params diverge from program source bundle".to_string(),
        ));
    }

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

    if compiled.language_version != bundle.language_version
        || compiled.compiler_version != bundle.compiler_version
    {
        return Err(VNetworkError::Consensus(
            "compiled language/compiler version differs from bundle metadata".to_string(),
        ));
    }
    if compiled.program_hash != bundle.compiled_program_hash {
        return Err(VNetworkError::Consensus(format!(
            "compiled program hash mismatch during validator verification: expected {}, got {}",
            bundle.compiled_program_hash, compiled.program_hash
        )));
    }

    let nonce_ref = proposal
        .nonce_binding
        .as_ref()
        .map(|(a, r, n)| (a.as_str(), r.as_str(), *n));

    let staged = execute_compiled_program_staged(
        state,
        genesis,
        &compiled,
        actor_pubkey,
        proposal.timestamp_ms,
        nonce_ref,
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

    let staged_event_ids: Vec<String> = staged
        .generated_events
        .iter()
        .map(|e| e.event_id.clone())
        .collect();
    let staged_event_hashes: Vec<String> = staged
        .generated_events
        .iter()
        .map(|e| e.event_hash.clone())
        .collect();
    if staged_event_ids != proposal.ordered_event_ids()
        || staged_event_hashes != proposal.ordered_event_hashes()
    {
        return Err(VNetworkError::Consensus(
            "validator re-execution generated event IDs/hashes diverge from proposal".to_string(),
        ));
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
