use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::collections::BTreeMap;
use vnetwork_core::language::compile_vx_source;
use vnetwork_types::{blake3_hex, canonical_json_string, KeypairMaterial};

#[pyfunction]
fn blake3_digest_hex(data: &[u8]) -> String {
    blake3_hex(data)
}

#[pyfunction]
fn generate_keypair_json(role: &str) -> PyResult<String> {
    let kp = KeypairMaterial::generate(role);
    canonical_json_string(&kp).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
#[pyo3(signature = (source, file_name="program.vx", modules_json=None))]
fn compile_vx_json(
    source: &str,
    file_name: &str,
    modules_json: Option<&str>,
) -> PyResult<String> {
    let modules: BTreeMap<String, String> = match modules_json {
        Some(raw) => serde_json::from_str(raw)
            .map_err(|e| PyValueError::new_err(format!("invalid modules JSON: {e}")))?,
        None => BTreeMap::new(),
    };
    let compiled = compile_vx_source(source, file_name, &modules, None)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    canonical_json_string(&compiled).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pymodule]
fn vnetwork_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(blake3_digest_hex, m)?)?;
    m.add_function(wrap_pyfunction!(generate_keypair_json, m)?)?;
    m.add_function(wrap_pyfunction!(compile_vx_json, m)?)?;
    Ok(())
}
