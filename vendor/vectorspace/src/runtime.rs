use crate::compiler::compile_program;
use crate::error::{RuntimeError, RuntimeErrorKind};
use crate::kernel::{execute_kernel_op, KernelOp};
use crate::parser::parse;
use crate::state::NetworkState;
use crate::ast::*;

#[derive(Debug, Clone)]
pub struct ExecutionReport {
    pub outputs: Vec<String>,
    pub events: Vec<String>,
    pub final_state: NetworkState,
}

#[derive(Debug, Clone)]
pub struct Runtime {
    pub state: NetworkState,
}

impl Runtime {
    pub fn new() -> Self {
        Self { state: NetworkState::new() }
    }

    pub fn parse(&self, source: &str) -> Result<Program, RuntimeError> {
        parse(source).map_err(|e| RuntimeError::new(RuntimeErrorKind::Parse(crate::error::ParseErrorKind::Message(e.to_string()))))
    }

    pub fn compile(&self, program: &Program) -> Result<Vec<KernelOp>, RuntimeError> {
        Ok(compile_program(program)?.ops)
    }

    pub fn execute_program(&mut self, program: &Program) -> Result<ExecutionReport, RuntimeError> {
        let ops = self.compile(program)?;
        self.execute_ops(ops)
    }

    pub fn execute_source(&mut self, source: &str) -> Result<ExecutionReport, RuntimeError> {
        let program = self.parse(source)?;
        self.execute_program(&program)
    }

    pub fn execute_ops(&mut self, ops: Vec<KernelOp>) -> Result<ExecutionReport, RuntimeError> {
        let mut outputs = Vec::new();
        let mut event_hashes = Vec::new();

        for op in ops {
            match op {
                KernelOp::Query { expr } => {
                    let resolved = self.resolve_query(&expr)?;
                    outputs.push(format!("{expr} => {resolved}"));
                }
                KernelOp::Record { expr } => {
                    let resolved = self.resolve_record(&expr)?;
                    outputs.push(format!("{expr} => {resolved}"));
                }
                other => {
                    let result = execute_kernel_op(&mut self.state, other)?;
                    if let Some(out) = result.output {
                        outputs.push(out);
                    }
                    if let Some(record) = result.record {
                        event_hashes.push(record.event_hash.clone());
                    }
                }
            }
        }

        Ok(ExecutionReport {
            outputs,
            events: event_hashes,
            final_state: self.state.clone(),
        })
    }

    pub fn resolve_query(&self, expr: &str) -> Result<String, RuntimeError> {
        let parts: Vec<&str> = expr.split('.').collect();
        if parts.is_empty() {
            return Err(RuntimeError::new(RuntimeErrorKind::InvalidOperation("empty query".to_string())));
        }
        let head = parts[0];
        let tail = &parts[1..];

        if let Some(vector) = self.state.vectors.get(head) {
            return Ok(resolve_vector_query(vector, tail));
        }
        if let Some(wallet) = self.state.wallets.get(head) {
            return Ok(resolve_wallet_query(wallet, tail));
        }
        if let Some(proj) = self.state.projections.get(head) {
            return Ok(resolve_projection_query(proj, tail));
        }
        if let Some(contract) = self.state.contracts.get(head) {
            return Ok(format!("contract {} with {} actions", contract.name, contract.actions.len()));
        }
        Err(RuntimeError::new(RuntimeErrorKind::UnknownSymbol(head.to_string())))
    }

    pub fn resolve_record(&self, expr: &str) -> Result<String, RuntimeError> {
        let query = expr.trim();
        if query == "last" || query == "last_event" {
            if let Some(event) = self.state.events.last() {
                return Ok(format!("{event}"));
            }
            return Err(RuntimeError::new(RuntimeErrorKind::RecordMissing(query.to_string())));
        }
        if let Some(event) = self.state.events.iter().find(|event| event.eid == query || event.event_hash == query) {
            return Ok(format!("{event}"));
        }
        Err(RuntimeError::new(RuntimeErrorKind::RecordMissing(query.to_string())))
    }
}

fn resolve_vector_query(vector: &crate::state::VectorState, tail: &[&str]) -> String {
    match tail {
        [] => format!(
            "{}:{} {} certification={:?} auth_ratio={}",
            vector.name,
            vector.vector_type.as_str(),
            crate::event::vector_to_string(&vector.components),
            vector.certification,
            vector.auth_ratio
        ),
        ["vector"] => crate::event::vector_to_string(&vector.components),
        ["type"] => vector.vector_type.as_str().to_string(),
        ["magnitude"] => vector.magnitude().to_string(),
        ["certification"] => format!("{:?}", vector.certification),
        ["auth_ratio"] => vector.auth_ratio.clone(),
        ["owner"] => vector.owner.clone().unwrap_or_else(|| "unbound".to_string()),
        _ => format!(
            "{}:{} {}",
            vector.name,
            vector.vector_type.as_str(),
            crate::event::vector_to_string(&vector.components)
        ),
    }
}

fn resolve_wallet_query(wallet: &crate::state::WalletState, tail: &[&str]) -> String {
    match tail {
        [] => format!("wallet {} = {}", wallet.name, wallet.public_key),
        ["pk"] => wallet.public_key.clone(),
        _ => format!("wallet {} = {}", wallet.name, wallet.public_key),
    }
}

fn resolve_projection_query(proj: &crate::state::ProjectionState, tail: &[&str]) -> String {
    match tail {
        [] => format!("projection {} from {}", proj.projection_id, proj.source),
        ["status"] => {
            if proj.consumed {
                "consumed".to_string()
            } else {
                "active".to_string()
            }
        }
        ["environment"] => proj.environment.clone(),
        ["policy"] => proj.policy.clone().unwrap_or_else(|| "none".to_string()),
        ["locked"] => crate::event::vector_to_string(&proj.locked),
        _ => format!("projection {} from {}", proj.projection_id, proj.source),
    }
}

pub fn render_query_output(query: &str, value: &str) -> String {
    format!("{query} => {value}")
}
