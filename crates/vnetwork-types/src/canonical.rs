use crate::error::{VNetworkError, VResult};
use serde::Serialize;
use std::collections::BTreeMap;

pub fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub fn canonical_json_bytes<T: Serialize>(value: &T) -> VResult<Vec<u8>> {
    let val = serde_json::to_value(value)
        .map_err(|e| VNetworkError::Serialization(format!("json value error: {e}")))?;
    let sorted = sort_json_value(val);
    serde_json::to_vec(&sorted)
        .map_err(|e| VNetworkError::Serialization(format!("canonical json encode error: {e}")))
}

pub fn canonical_json_string<T: Serialize>(value: &T) -> VResult<String> {
    let bytes = canonical_json_bytes(value)?;
    String::from_utf8(bytes)
        .map_err(|e| VNetworkError::Serialization(format!("utf8 canonical error: {e}")))
}

pub fn sort_json_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut btree = BTreeMap::new();
            for (k, v) in map {
                btree.insert(k, sort_json_value(v));
            }
            let mut out = serde_json::Map::new();
            for (k, v) in btree {
                out.insert(k, v);
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(sort_json_value).collect())
        }
        other => other,
    }
}
