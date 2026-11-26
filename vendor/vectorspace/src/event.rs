use crate::ast::{VectorType};
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub eid: String,
    pub parent_hashes: Vec<String>,
    pub region_id: String,
    pub entity_id: String,
    pub v_before: Vec<u128>,
    pub v_after: Vec<u128>,
    pub operation: String,
    pub params: String,
    pub auth_ratio: String,
    pub certified: bool,
    pub actor_pk: String,
    pub proof: String,
    pub logical_clock: u64,
    pub timestamp: u64,
    pub signature: String,
    pub event_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryRecord {
    pub query: String,
    pub result: String,
}

pub fn canonical_join(parts: &[String]) -> String {
    let mut out = String::new();
    for (idx, part) in parts.iter().enumerate() {
        if idx > 0 {
            out.push('|');
        }
        out.push_str(part);
    }
    out
}

pub fn vector_to_string(v: &[u128]) -> String {
    let mut s = String::from("(");
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str(&x.to_string());
    }
    s.push(')');
    s
}

pub fn type_to_string(ty: VectorType) -> &'static str {
    ty.as_str()
}

pub fn fnv1a_128(input: &str) -> String {
    let mut hash: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    let prime: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;
    for byte in input.as_bytes() {
        hash ^= *byte as u128;
        hash = hash.wrapping_mul(prime);
    }
    format!("{hash:032x}")
}

pub fn derive_signature(event_hash: &str, actor_pk: &str, logical_clock: u64) -> String {
    fnv1a_128(&format!("{event_hash}:{actor_pk}:{logical_clock}"))
}

pub fn derive_timestamp(logical_clock: u64) -> u64 {
    1_700_000_000 + logical_clock
}

pub fn canonical_event_payload(
    eid: &str,
    parent_hashes: &[String],
    region_id: &str,
    entity_id: &str,
    v_before: &[u128],
    v_after: &[u128],
    operation: &str,
    params: &str,
    auth_ratio: &str,
    certified: bool,
    actor_pk: &str,
    proof: &str,
    logical_clock: u64,
    timestamp: u64,
    signature: &str,
) -> String {
    let mut parts = vec![
        format!("eid={eid}"),
        format!("parents={}", canonical_join(parent_hashes)),
        format!("region_id={region_id}"),
        format!("entity_id={entity_id}"),
        format!("v_before={}", vector_to_string(v_before)),
        format!("v_after={}", vector_to_string(v_after)),
        format!("operation={operation}"),
        format!("params={params}"),
        format!("auth_ratio={auth_ratio}"),
        format!("certified={certified}"),
        format!("actor_pk={actor_pk}"),
        format!("proof={proof}"),
        format!("logical_clock={logical_clock}"),
        format!("timestamp={timestamp}"),
        format!("signature={signature}"),
    ];
    parts.sort();
    parts.join("\n")
}

pub fn derive_event_hash(payload: &str) -> String {
    fnv1a_128(payload)
}

impl Display for Event {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Event({}, op={}, entity={}, hash={})",
            self.eid, self.operation, self.entity_id, self.event_hash
        )
    }
}
