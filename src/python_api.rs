use crate::engine::KernelEngine;
use crate::reconstruction::SettlementOutcome;
use crate::region::{RegionCreateRequest, RegionVisibility};
use crate::storage::MemoryStore;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyDict, PyList, PyTuple};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

fn to_json<T: Serialize>(value: &T) -> PyResult<String> {
    serde_json::to_string(value).map_err(|err| PyValueError::new_err(err.to_string()))
}

fn map_err<E: ToString>(err: E) -> PyErr {
    PyValueError::new_err(err.to_string())
}

fn parse_region_visibility(value: &str) -> PyResult<RegionVisibility> {
    match value.trim().to_ascii_lowercase().as_str() {
        "public" => Ok(RegionVisibility::Public),
        "private" => Ok(RegionVisibility::Private),
        other => Err(PyValueError::new_err(format!(
            "invalid region visibility: {other}"
        ))),
    }
}

fn json_value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn metadata_from_json(value: Option<Value>) -> PyResult<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let Some(value) = value else {
        return Ok(out);
    };

    let Some(map) = value.as_object() else {
        return Err(PyValueError::new_err(
            "metadata must be a JSON object / Python dict",
        ));
    };

    for (k, v) in map {
        out.insert(k.clone(), json_value_to_string(v));
    }

    Ok(out)
}

fn py_any_to_json_value(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    if obj.is_none() {
        return Ok(Value::Null);
    }

    if obj.is_instance_of::<PyBool>() {
        return Ok(Value::Bool(obj.extract::<bool>()?));
    }

    if let Ok(s) = obj.extract::<String>() {
        return Ok(Value::String(s));
    }

    if let Ok(i) = obj.extract::<i64>() {
        return Ok(Value::Number(i.into()));
    }

    if let Ok(u) = obj.extract::<u64>() {
        return Ok(Value::Number(u.into()));
    }

    if let Ok(f) = obj.extract::<f64>() {
        return serde_json::Number::from_f64(f)
            .map(Value::Number)
            .ok_or_else(|| PyValueError::new_err("non-finite float not supported"));
    }

    if let Ok(dict) = obj.cast::<PyDict>() {
        let mut map = serde_json::Map::new();
        for (k, v) in dict.iter() {
            let key = k.extract::<String>()?;
            map.insert(key, py_any_to_json_value(&v)?);
        }
        return Ok(Value::Object(map));
    }

    if let Ok(list) = obj.cast::<PyList>() {
        let mut out = Vec::with_capacity(list.len());
        for item in list.iter() {
            out.push(py_any_to_json_value(&item)?);
        }
        return Ok(Value::Array(out));
    }

    if let Ok(tuple) = obj.cast::<PyTuple>() {
        let mut out = Vec::with_capacity(tuple.len());
        for item in tuple.iter() {
            out.push(py_any_to_json_value(&item)?);
        }
        return Ok(Value::Array(out));
    }

    Err(PyValueError::new_err(
        "region request must be a JSON-safe Python object",
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CreateRegionRequestInput {
    region_name: String,
    actor_public_key: String,
    trigger_event_hash: String,
    creation_proof: String,
    visibility: String,
    section: u64,
    request_signature: String,
    region_prefix: Option<String>,
    suggested_title: Option<String>,
    access_key: Option<String>,
    metadata: Option<Value>,
}

fn create_region_input_from_any(request: &Bound<'_, PyAny>) -> PyResult<CreateRegionRequestInput> {
    let value = if let Ok(raw_json) = request.extract::<String>() {
        serde_json::from_str::<Value>(&raw_json).map_err(|e| {
            PyValueError::new_err(format!(
                "create_region expected a dict/object or valid JSON string: {e}"
            ))
        })?
    } else {
        py_any_to_json_value(request)?
    };

    serde_json::from_value(value).map_err(map_err)
}

#[pyclass(unsendable)]
pub struct PyKernelEngine {
    inner: KernelEngine<MemoryStore>,
}

impl Default for PyKernelEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[pymethods]
impl PyKernelEngine {
    #[new]
    pub fn new() -> Self {
        Self {
            inner: KernelEngine::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn origin_create(
        &mut self,
        vector_id: String,
        owner_pubkey: String,
        space_id: String,
        components: Vec<u128>,
        seed: String,
        nonce: u64,
        difficulty: u32,
    ) -> PyResult<String> {
        let state = self
            .inner
            .origin_create(
                vector_id,
                owner_pubkey,
                space_id,
                components,
                seed,
                nonce,
                difficulty,
            )
            .map_err(map_err)?;

        to_json(&state)
    }

    pub fn certify(&mut self, vector_id: String) -> PyResult<String> {
        let state = self.inner.certify(&vector_id).map_err(map_err)?;
        to_json(&state)
    }

    pub fn transfer(
        &mut self,
        from_id: String,
        to_id: String,
        amount: Vec<u128>,
    ) -> PyResult<String> {
        let result = self
            .inner
            .transfer(&from_id, &to_id, amount)
            .map_err(map_err)?;

        to_json(&result)
    }

    pub fn drain(&mut self, vector_id: String, basis_points: u16) -> PyResult<String> {
        let state = self
            .inner
            .drain(&vector_id, basis_points)
            .map_err(map_err)?;
        to_json(&state)
    }

    pub fn project(
        &mut self,
        vector_id: String,
        projected_components: Vec<u128>,
        escrow_id: String,
    ) -> PyResult<String> {
        let state = self
            .inner
            .project(&vector_id, projected_components, escrow_id)
            .map_err(map_err)?;

        to_json(&state)
    }

    pub fn reconstruct(
        &mut self,
        vector_id: String,
        outcome_tag: String,
        gains: Vec<u128>,
        losses: Vec<u128>,
    ) -> PyResult<String> {
        let outcome = SettlementOutcome {
            outcome_tag,
            gains,
            losses,
        };

        let state = self
            .inner
            .reconstruct(&vector_id, outcome)
            .map_err(map_err)?;

        to_json(&state)
    }

    pub fn create_region(&mut self, request: &Bound<'_, PyAny>) -> PyResult<String> {
        let input = create_region_input_from_any(request)?;

        let request = RegionCreateRequest {
            region_name: input.region_name,
            region_prefix: input.region_prefix,
            suggested_title: input.suggested_title,
            visibility: parse_region_visibility(&input.visibility)?,
            section: input.section,
            trigger_event_hash: input.trigger_event_hash,
            creation_proof: input.creation_proof,
            access_key: input.access_key,
            metadata: metadata_from_json(input.metadata)?,
            request_signature: input.request_signature,
        };

        let state = self
            .inner
            .create_region(request, input.actor_public_key)
            .map_err(map_err)?;

        to_json(&state)
    }

    pub fn query_region(&self, region_id: String) -> PyResult<String> {
        let result = self.inner.query_region(&region_id).map_err(map_err)?;
        to_json(&result)
    }

    pub fn query_region_by_name(
        &self,
        region_name: String,
        region_prefix: Option<String>,
    ) -> PyResult<String> {
        let result = self
            .inner
            .query_region_by_name(&region_name, region_prefix.as_deref())
            .map_err(map_err)?;
        to_json(&result)
    }

    pub fn query_regions(&self) -> PyResult<String> {
        let result = self.inner.query_regions().map_err(map_err)?;
        to_json(&result)
    }

    pub fn resolve_region_id(
        &self,
        region_name: String,
        region_prefix: Option<String>,
    ) -> PyResult<String> {
        let result = self
            .inner
            .resolve_region_id(&region_name, region_prefix.as_deref())
            .map_err(map_err)?;
        to_json(&result)
    }

    pub fn region_exists(
        &self,
        region_name: String,
        region_prefix: Option<String>,
    ) -> PyResult<String> {
        let result = self
            .inner
            .region_exists(&region_name, region_prefix.as_deref())
            .map_err(map_err)?;
        to_json(&result)
    }

    pub fn authorize_region(
        &self,
        region_id: String,
        access_key: Option<String>,
    ) -> PyResult<String> {
        let result = self
            .inner
            .authorize_region(&region_id, access_key.as_deref())
            .map_err(map_err)?;
        to_json(&result)
    }

    pub fn query_vector(&self, vector_id: String) -> PyResult<String> {
        let result = self.inner.query_vector(&vector_id).map_err(map_err)?;
        to_json(&result)
    }

    pub fn query_vectors(&self) -> PyResult<String> {
        let result = self.inner.query_vectors().map_err(map_err)?;
        to_json(&result)
    }

    pub fn query_records(&self) -> PyResult<String> {
        let result = self.inner.query_records().map_err(map_err)?;
        to_json(&result)
    }

    pub fn query_event_by_hash(&self, event_hash: String) -> PyResult<String> {
        let result = self
            .inner
            .query_event_by_hash(&event_hash)
            .map_err(map_err)?;

        to_json(&result)
    }

    pub fn replay_canonical_history(&self) -> PyResult<String> {
        let result = self.inner.replay_canonical_history().map_err(map_err)?;

        to_json(&result)
    }

    pub fn current_state_root(&self) -> PyResult<String> {
        let result = self.inner.current_state_root().map_err(map_err)?;
        to_json(&result)
    }

    pub fn metrics(&self) -> PyResult<String> {
        let result = self.inner.metrics().map_err(map_err)?;
        to_json(&result)
    }
}