use crate::engine::KernelEngine;
use crate::error::KernelXError;
use crate::reconstruction::SettlementOutcome;
use crate::storage::StateStore;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Opcode {
    OriginCreate,
    Transfer,
    Drain,
    Project,
    Reconstruct,
    Certify,
    Query,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Instruction {
    pub opcode: Opcode,
    pub params: Value,
}

pub fn parse_script(script: &str) -> Result<Vec<Instruction>, KernelXError> {
    let mut out = Vec::new();
    for raw in script.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, ' ');
        let opcode_str = parts.next().unwrap_or_default().to_uppercase();
        let params = parts.next().unwrap_or("{}");
        let opcode = match opcode_str.as_str() {
            "ORIGIN" | "ORIGIN_CREATE" => Opcode::OriginCreate,
            "TRANSFER" => Opcode::Transfer,
            "DRAIN" => Opcode::Drain,
            "PROJECT" => Opcode::Project,
            "RECONSTRUCT" => Opcode::Reconstruct,
            "CERTIFY" => Opcode::Certify,
            "QUERY" => Opcode::Query,
            _ => return Err(KernelXError::Rejected(format!("unknown opcode: {}", opcode_str))),
        };
        let params: Value = serde_json::from_str(params)
            .map_err(|e| KernelXError::Rejected(format!("invalid params json: {e}")))?;
        out.push(Instruction { opcode, params });
    }
    Ok(out)
}

pub fn execute_script<S: StateStore>(
    engine: &mut KernelEngine<S>,
    script: &str,
) -> Result<Vec<String>, KernelXError> {
    let instructions = parse_script(script)?;
    let mut results = Vec::new();
    for ins in instructions {
        let result = match ins.opcode {
            Opcode::OriginCreate => {
                let vector_id = ins.params["vector_id"].as_str().unwrap_or("vector").to_string();
                let owner_pubkey = ins.params["owner_pubkey"].as_str().unwrap_or("").to_string();
                let space_id = ins.params["space_id"].as_str().unwrap_or("default").to_string();
                let components = ins.params["components"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|v| v.as_u64().unwrap_or(0) as u128)
                    .collect();
                let seed = ins.params["seed"].as_str().unwrap_or("").to_string();
                let nonce = ins.params["nonce"].as_u64().unwrap_or(0);
                let difficulty = ins.params["difficulty"].as_u64().unwrap_or(1) as u32;
                let state = engine.origin_create(vector_id, owner_pubkey, space_id, components, seed, nonce, difficulty)?;
                format!("origin:{}", state.vector_id)
            }
            Opcode::Transfer => {
                let from_id = ins.params["from"].as_str().unwrap_or("");
                let to_id = ins.params["to"].as_str().unwrap_or("");
                let amount = ins.params["amount"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|v| v.as_u64().unwrap_or(0) as u128)
                    .collect();
                let (a, b) = engine.transfer(from_id, to_id, amount)?;
                format!("transfer:{}->{}:{}|{}", from_id, to_id, a.magnitude(), b.magnitude())
            }
            Opcode::Drain => {
                let vector_id = ins.params["vector_id"].as_str().unwrap_or("");
                let basis_points = ins.params["basis_points"].as_u64().unwrap_or(0) as u16;
                let state = engine.drain(vector_id, basis_points)?;
                format!("drain:{}", state.vector_id)
            }
            Opcode::Project => {
                let vector_id = ins.params["vector_id"].as_str().unwrap_or("");
                let projected_components = ins.params["projected_components"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|v| v.as_u64().unwrap_or(0) as u128)
                    .collect();
                let escrow_id = ins.params["escrow_id"].as_str().unwrap_or("escrow");
                let state = engine.project(vector_id, projected_components, escrow_id.to_string())?;
                format!("project:{}", state.vector_id)
            }
            Opcode::Reconstruct => {
                let vector_id = ins.params["vector_id"].as_str().unwrap_or("");
                let gains = ins.params["gains"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|v| v.as_u64().unwrap_or(0) as u128)
                    .collect();
                let losses = ins.params["losses"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|v| v.as_u64().unwrap_or(0) as u128)
                    .collect();
                let outcome = SettlementOutcome {
                    outcome_tag: ins.params["outcome_tag"].as_str().unwrap_or("settled").to_string(),
                    gains,
                    losses,
                };
                let state = engine.reconstruct(vector_id, outcome)?;
                format!("reconstruct:{}", state.vector_id)
            }
            Opcode::Certify => {
                let vector_id = ins.params["vector_id"].as_str().unwrap_or("");
                let state = engine.certify(vector_id)?;
                format!("certify:{}:{}", state.vector_id, state.certification.auth_ratio)
            }
            Opcode::Query => {
                let vector_id = ins.params["vector_id"].as_str().unwrap_or("");
                let state = engine.query_vector(vector_id)?;
                serde_json::to_string(&state).unwrap_or_else(|_| "null".to_string())
            }
        };
        results.push(result);
    }
    Ok(results)
}
