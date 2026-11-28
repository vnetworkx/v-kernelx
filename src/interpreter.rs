use crate::engine::KernelEngine;
use crate::error::KernelXError;
use crate::reconstruction::SettlementOutcome;
use crate::storage::KernelStore;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Opcode {
    OriginCreate,
    Transport,
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
            "TRANSPORT" => Opcode::Transport,
            "TRANSFER" => Opcode::Transfer,
            "DRAIN" => Opcode::Drain,
            "PROJECT" => Opcode::Project,
            "RECONSTRUCT" => Opcode::Reconstruct,
            "CERTIFY" => Opcode::Certify,
            "QUERY" => Opcode::Query,
            _ => {
                return Err(KernelXError::Rejected(format!(
                    "unknown opcode: {}",
                    opcode_str
                )))
            }
        };

        let params: Value = serde_json::from_str(params)
            .map_err(|e| KernelXError::Rejected(format!("invalid params json: {e}")))?;

        out.push(Instruction { opcode, params });
    }

    Ok(out)
}

fn param_str<'a>(params: &'a Value, keys: &[&str], default: &'a str) -> &'a str {
    for key in keys {
        if let Some(s) = params.get(*key).and_then(|v| v.as_str()) {
            return s;
        }
    }
    default
}

fn param_u64(params: &Value, keys: &[&str], default: u64) -> u64 {
    for key in keys {
        if let Some(v) = params.get(*key).and_then(|v| v.as_u64()) {
            return v;
        }
    }
    default
}

fn param_u16(params: &Value, keys: &[&str], default: u16) -> u16 {
    for key in keys {
        if let Some(v) = params.get(*key).and_then(|v| v.as_u64()) {
            return v as u16;
        }
    }
    default
}

fn param_u128_vec(params: &Value, keys: &[&str]) -> Vec<u128> {
    for key in keys {
        if let Some(arr) = params.get(*key).and_then(|v| v.as_array()) {
            return arr
                .iter()
                .map(|v| {
                    if let Some(n) = v.as_u64() {
                        n as u128
                    } else if let Some(s) = v.as_str() {
                        s.parse::<u128>().unwrap_or(0)
                    } else {
                        0
                    }
                })
                .collect();
        }
    }
    Vec::new()
}

pub fn execute_script<S: KernelStore>(
    engine: &mut KernelEngine<S>,
    script: &str,
) -> Result<Vec<String>, KernelXError> {
    let instructions = parse_script(script)?;
    let mut results = Vec::new();

    for ins in instructions {
        let result = match ins.opcode {
            Opcode::OriginCreate => {
                let vector_id =
                    param_str(&ins.params, &["vector_id", "vectorId"], "vector").to_string();
                let owner_pubkey =
                    param_str(&ins.params, &["owner_pubkey", "ownerPubkey"], "").to_string();
                let space_id =
                    param_str(&ins.params, &["space_id", "spaceId"], "default").to_string();
                let components = param_u128_vec(&ins.params, &["components"]);
                let seed = param_str(&ins.params, &["seed"], "").to_string();
                let nonce = param_u64(&ins.params, &["nonce"], 0);
                let difficulty = param_u64(&ins.params, &["difficulty"], 1) as u32;

                let state = engine.origin_create(
                    vector_id,
                    owner_pubkey,
                    space_id,
                    components,
                    seed,
                    nonce,
                    difficulty,
                )?;
                format!("origin:{}", state.vector_id)
            }
            Opcode::Transport => {
                let from_id = param_str(&ins.params, &["from", "from_reserve_id"], "");
                let to_id = param_str(&ins.params, &["to", "to_id"], "");
                let amount = param_u128_vec(&ins.params, &["amount"]);

                let (a, b) = engine.transport(from_id, to_id, amount)?;
                format!(
                    "transport:{}->{}:{}|{}",
                    from_id,
                    to_id,
                    a.magnitude(),
                    b.magnitude()
                )
            }
            Opcode::Transfer => {
                let from_id = param_str(&ins.params, &["from"], "");
                let to_id = param_str(&ins.params, &["to"], "");
                let amount = param_u128_vec(&ins.params, &["amount"]);
                let drain_bps = param_u16(
                    &ins.params,
                    &["drain_bps", "basis_points", "basisPoints"],
                    0,
                );

                if drain_bps > 0 {
                    let (a, b, dist) =
                        engine.transfer_with_drain(from_id, to_id, amount, drain_bps)?;
                    format!(
                        "transfer:{}->{}:{}|{} (drain_bps={})",
                        from_id,
                        to_id,
                        a.magnitude(),
                        b.magnitude(),
                        dist.effective_bps
                    )
                } else {
                    let (a, b) = engine.transfer(from_id, to_id, amount)?;
                    format!(
                        "transfer:{}->{}:{}|{}",
                        from_id,
                        to_id,
                        a.magnitude(),
                        b.magnitude()
                    )
                }
            }
            Opcode::Drain => {
                let vector_id = param_str(&ins.params, &["vector_id", "vectorId"], "");
                let basis_points = param_u16(&ins.params, &["basis_points", "basisPoints"], 0);

                let state = engine.drain(vector_id, basis_points)?;
                format!("drain:{}", state.vector_id)
            }
            Opcode::Project => {
                let vector_id = param_str(&ins.params, &["vector_id", "vectorId"], "");
                let projected_components = param_u128_vec(
                    &ins.params,
                    &["projected_components", "projectedComponents"],
                );
                let escrow_id = param_str(&ins.params, &["escrow_id", "escrowId"], "escrow");

                let state =
                    engine.project(vector_id, projected_components, escrow_id.to_string())?;
                format!("project:{}", state.vector_id)
            }
            Opcode::Reconstruct => {
                let vector_id = param_str(&ins.params, &["vector_id", "vectorId"], "");
                let gains = param_u128_vec(&ins.params, &["gains"]);
                let losses = param_u128_vec(&ins.params, &["losses"]);

                let outcome = SettlementOutcome {
                    outcome_tag: param_str(&ins.params, &["outcome_tag", "outcomeTag"], "settled")
                        .to_string(),
                    gains,
                    losses,
                };

                let state = engine.reconstruct(vector_id, outcome)?;
                format!("reconstruct:{}", state.vector_id)
            }
            Opcode::Certify => {
                let vector_id = param_str(&ins.params, &["vector_id", "vectorId"], "");
                let state = engine.certify(vector_id)?;
                format!(
                    "certify:{}:{}",
                    state.vector_id, state.certification.auth_ratio
                )
            }
            Opcode::Query => {
                let vector_id = param_str(&ins.params, &["vector_id", "vectorId"], "");
                let state = engine.query_vector(vector_id)?;
                serde_json::to_string(&state).unwrap_or_else(|_| "null".to_string())
            }
        };

        results.push(result);
    }

    Ok(results)
}
