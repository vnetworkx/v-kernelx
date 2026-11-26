use crate::ast::*;
use crate::error::{Diagnostic, RuntimeError, RuntimeErrorKind, Span};
use crate::kernel::KernelOp;
use crate::parser::parse;
use crate::semantic::{validate_program_semantics, SymbolTable};
use crate::value::{Context, Value};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const LANGUAGE_VERSION: &str = "v-langx/1.2.0";
pub const COMPILER_VERSION: &str = "vectorspace-compiler/1.2.0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerConfig {
    pub certification_threshold: String,
}

impl Default for CompilerConfig {
    fn default() -> Self {
        Self {
            certification_threshold: "0.8000".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilationUnit {
    pub ops: Vec<KernelOp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedModuleRef {
    pub path: String,
    pub blake3_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledOp {
    pub index: usize,
    pub op_kind: String,
    pub params: serde_json::Value,
    pub required_scope: String,
    pub span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledProgram {
    pub language_version: String,
    pub compiler_version: String,
    pub file_name: String,
    pub file_kind: String,
    pub source_hash: String,
    pub imported_modules: Vec<ImportedModuleRef>,
    pub ops: Vec<CompiledOp>,
    pub program_hash: String,
    pub diagnostics: Vec<Diagnostic>,
}

pub trait ModuleResolver {
    fn resolve(&self, path: &str) -> Result<String, RuntimeError>;
}

#[derive(Debug, Default, Clone)]
pub struct InMemoryModuleResolver {
    pub modules: BTreeMap<String, String>,
}

impl InMemoryModuleResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, path: impl Into<String>, source: impl Into<String>) {
        self.modules.insert(path.into(), source.into());
    }
}

impl ModuleResolver for InMemoryModuleResolver {
    fn resolve(&self, path: &str) -> Result<String, RuntimeError> {
        self.modules.get(path).cloned().ok_or_else(|| {
            RuntimeError::new(RuntimeErrorKind::ImportError(format!(
                "module `{path}` not found"
            )))
        })
    }
}

#[derive(Debug, Clone)]
pub struct FilesystemModuleResolver {
    pub base_dir: std::path::PathBuf,
}

impl FilesystemModuleResolver {
    pub fn new(base_dir: impl AsRef<Path>) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_path_buf(),
        }
    }
}

impl ModuleResolver for FilesystemModuleResolver {
    fn resolve(&self, path: &str) -> Result<String, RuntimeError> {
        let candidate = Path::new(path);
        if candidate.is_absolute() || path.contains("..") {
            return Err(RuntimeError::new(RuntimeErrorKind::ImportError(format!(
                "unsafe module import path `{path}`"
            ))));
        }
        let full = self.base_dir.join(candidate);
        std::fs::read_to_string(&full).map_err(|e| {
            RuntimeError::new(RuntimeErrorKind::ImportError(format!(
                "failed to read module `{path}`: {e}"
            )))
        })
    }
}

pub fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub fn expr_to_string(expr: &Expr) -> String {
    match expr {
        Expr::Integer(v) => v.to_string(),
        Expr::Bool(b) => b.to_string(),
        Expr::String(v) => v.clone(),
        Expr::Ident(v) => v.clone(),
        Expr::Path(parts) => parts.join("."),
        Expr::VectorLiteral(vals) => {
            let inner: Vec<String> = vals.iter().map(|v| v.to_string()).collect();
            format!("({})", inner.join(", "))
        }
        Expr::Call { callee, args } => {
            let mut out = String::new();
            out.push_str(callee);
            out.push('(');
            for (idx, arg) in args.iter().enumerate() {
                if idx > 0 {
                    out.push_str(", ");
                }
                if let Some(name) = &arg.name {
                    out.push_str(name);
                    out.push('=');
                    out.push_str(&expr_to_string(&arg.value));
                } else {
                    out.push_str(&expr_to_string(&arg.value));
                }
            }
            out.push(')');
            out
        }
        Expr::Group(inner) => expr_to_string(inner),
    }
}

pub fn expr_to_json(expr: &Expr) -> serde_json::Value {
    match expr {
        Expr::Integer(v) => {
            if let Ok(n) = u64::try_from(*v) {
                serde_json::json!(n)
            } else {
                serde_json::json!(v.to_string())
            }
        }
        Expr::Bool(b) => serde_json::json!(b),
        Expr::String(s) => serde_json::json!(s),
        Expr::Ident(s) => serde_json::json!(s),
        Expr::Path(parts) => serde_json::json!(parts.join(".")),
        Expr::VectorLiteral(vals) => {
            serde_json::json!(vals.iter().map(|v| v.to_string()).collect::<Vec<_>>())
        }
        Expr::Call { callee, args } => {
            let mut map = serde_json::Map::new();
            for (idx, arg) in args.iter().enumerate() {
                let k = arg.name.clone().unwrap_or_else(|| format!("arg_{idx}"));
                map.insert(k, expr_to_json(&arg.value));
            }
            serde_json::json!({ "callee": callee, "args": map })
        }
        Expr::Group(inner) => expr_to_json(inner),
    }
}

pub fn fields_to_json(fields: &[PropertyField]) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    let mut sorted: Vec<&PropertyField> = fields.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    for f in sorted {
        map.insert(f.name.clone(), expr_to_json(&f.value));
    }
    serde_json::Value::Object(map)
}

pub fn eval_int(expr: &Expr, env: &BTreeMap<String, u128>) -> Result<u128, RuntimeError> {
    match expr {
        Expr::Integer(v) => Ok(*v),
        Expr::Ident(name) => env
            .get(name)
            .copied()
            .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::UnknownSymbol(name.clone()))),
        Expr::Group(inner) => eval_int(inner, env),
        other => Err(RuntimeError::new(RuntimeErrorKind::InvalidOperation(
            format!("expected integer expression, found {other:?}"),
        ))),
    }
}

pub fn eval_context(expr: &ContextExpr) -> Context {
    let mut context = Context::new();
    for arg in &expr.args {
        if let Some(name) = &arg.name {
            context.fields.insert(name.clone(), value_from_expr(&arg.value));
        }
    }
    context
}

pub fn value_from_expr(expr: &Expr) -> Value {
    match expr {
        Expr::Integer(v) => Value::Int(*v),
        Expr::Bool(b) => Value::Bool(*b),
        Expr::String(v) => Value::String(v.clone()),
        Expr::Ident(v) => Value::String(v.clone()),
        Expr::Path(parts) => Value::Path(parts.clone()),
        Expr::VectorLiteral(vals) => Value::Vector(vals.clone()),
        Expr::Call { callee, args } => {
            let mut map = BTreeMap::new();
            for arg in args {
                if let Some(name) = &arg.name {
                    map.insert(name.clone(), value_from_expr(&arg.value));
                }
            }
            let mut out = BTreeMap::new();
            out.insert("callee".to_string(), Value::String(callee.clone()));
            out.insert("args".to_string(), Value::Map(map));
            Value::Map(out)
        }
        Expr::Group(inner) => value_from_expr(inner),
    }
}

pub fn compile_program(program: &Program) -> Result<CompilationUnit, RuntimeError> {
    let mut ops = Vec::new();
    let mut projection_seq: u64 = 0;
    for statement in &program.statements {
        match statement {
            Statement::VectorDecl(v) => ops.push(KernelOp::CreateVector {
                name: v.name.clone(),
                vector_type: v.vector_type,
                components: v.components.clone(),
            }),
            Statement::WalletDecl(w) => ops.push(KernelOp::BindWallet {
                name: w.name.clone(),
                public_key: w.public_key.clone(),
            }),
            Statement::Certify(c) => {
                let ctx = eval_context(&c.context);
                let mut context_text = String::from("ctx(");
                for (idx, (k, v)) in ctx.fields.iter().enumerate() {
                    if idx > 0 {
                        context_text.push_str(", ");
                    }
                    context_text.push_str(k);
                    context_text.push('=');
                    context_text.push_str(&format!("{v:?}"));
                }
                context_text.push(')');

                let ratio = compute_auth_ratio(&ctx);
                let certified = ratio.parse::<f64>().unwrap_or(0.0) >= 0.8000;
                ops.push(KernelOp::Certify {
                    target: c.target.clone(),
                    context: context_text,
                    auth_ratio: ratio,
                    certified,
                });
            }
            Statement::Transfer(t) => {
                let env = BTreeMap::new();
                let amount = eval_int(&t.amount, &env)?;
                let drain = t
                    .drain
                    .as_ref()
                    .map(|expr| eval_int(expr, &env))
                    .transpose()?
                    .unwrap_or(0);
                let policy = t.policy.as_ref().map(expr_to_string);
                ops.push(KernelOp::Transfer {
                    source: t.source.clone(),
                    destination: t.destination.clone(),
                    amount,
                    drain,
                    policy,
                });
            }
            Statement::Drain(d) => {
                let env = BTreeMap::new();
                let amount = eval_int(&d.amount, &env)?;
                ops.push(KernelOp::Drain {
                    target: d.target.clone(),
                    amount,
                });
            }
            Statement::Project(p) => {
                let env = BTreeMap::new();
                let amount = eval_int(&p.amount, &env)?;
                let policy = p.policy.as_ref().map(expr_to_string);
                projection_seq = projection_seq.saturating_add(1);
                let projection_id = format!("proj_{:03}", projection_seq);
                ops.push(KernelOp::Project {
                    source: p.source.clone(),
                    environment: p.environment.clone(),
                    amount,
                    policy,
                    projection_id,
                });
            }
            Statement::Reconstruct(r) => {
                ops.push(KernelOp::Reconstruct {
                    target: r.target.clone(),
                    projection_id: r.projection_id.clone().unwrap_or_else(|| "history".to_string()),
                });
            }
            Statement::Query(q) => {
                ops.push(KernelOp::Query {
                    expr: expr_to_string(&q.expr),
                });
            }
            Statement::Record(r) => {
                ops.push(KernelOp::Record {
                    expr: expr_to_string(&r.expr),
                });
            }
            Statement::Contract(c) => {
                let actions = c
                    .actions
                    .iter()
                    .map(|a| format_action(&a.name, &a.args))
                    .collect();
                ops.push(KernelOp::Contract {
                    name: c.name.clone(),
                    actions,
                });
            }
            // Network statements compile via compile_source_with_imports into CompiledOp
            _ => {}
        }
    }
    Ok(CompilationUnit { ops })
}

fn format_action(name: &str, args: &[NamedArg]) -> String {
    let mut text = name.to_string();
    text.push('(');
    for (idx, arg) in args.iter().enumerate() {
        if idx > 0 {
            text.push_str(", ");
        }
        if let Some(n) = &arg.name {
            text.push_str(n);
            text.push('=');
            text.push_str(&expr_to_string(&arg.value));
        } else {
            text.push_str(&expr_to_string(&arg.value));
        }
    }
    text.push(')');
    text
}

pub fn compile_source_with_imports(
    source: &str,
    file_name: &str,
    resolver: &dyn ModuleResolver,
) -> Result<CompiledProgram, RuntimeError> {
    let file_kind = SourceFileKind::from_filename(file_name);
    let source_hash = blake3_hex(source.as_bytes());
    let mut visited = BTreeSet::new();
    visited.insert(file_name.to_string());
    let mut imported_modules = Vec::new();
    let mut table = SymbolTable::new();
    let mut ops = Vec::new();

    compile_unit_recursive(
        source,
        file_kind,
        resolver,
        &mut visited,
        &mut imported_modules,
        &mut table,
        &mut ops,
        false,
    )?;

    imported_modules.sort_by(|a, b| a.path.cmp(&b.path));
    imported_modules.dedup();

    let canonical_payload = serde_json::json!({
        "language_version": LANGUAGE_VERSION,
        "compiler_version": COMPILER_VERSION,
        "file_kind": file_kind.as_str(),
        "source_hash": source_hash,
        "imported_modules": imported_modules,
        "ops": ops,
    });
    let canonical_bytes = serde_json::to_vec(&canonical_payload).map_err(|e| {
        RuntimeError::new(RuntimeErrorKind::InvalidOperation(format!(
            "compiled program serialization error: {e}"
        )))
    })?;
    let program_hash = blake3_hex(&canonical_bytes);

    Ok(CompiledProgram {
        language_version: LANGUAGE_VERSION.to_string(),
        compiler_version: COMPILER_VERSION.to_string(),
        file_name: file_name.to_string(),
        file_kind: file_kind.as_str().to_string(),
        source_hash,
        imported_modules,
        ops,
        program_hash,
        diagnostics: table.diagnostics,
    })
}

#[allow(clippy::too_many_arguments)]
fn compile_unit_recursive(
    source: &str,
    file_kind: SourceFileKind,
    resolver: &dyn ModuleResolver,
    visited: &mut BTreeSet<String>,
    imported_modules: &mut Vec<ImportedModuleRef>,
    table: &mut SymbolTable,
    ops: &mut Vec<CompiledOp>,
    is_imported_module: bool,
) -> Result<(), RuntimeError> {
    let program = parse(source)?;
    validate_program_semantics(&program, file_kind, table)?;

    for stmt in &program.statements {
        if let Statement::Import(imp) = stmt {
            if !visited.insert(imp.path.clone()) {
                return Err(RuntimeError::with_span(
                    RuntimeErrorKind::ImportError(format!(
                        "cyclic or duplicate module import `{}`",
                        imp.path
                    )),
                    imp.span,
                ));
            }
            let mod_src = resolver.resolve(&imp.path)?;
            let mod_hash = blake3_hex(mod_src.as_bytes());
            if let Some(expected) = &imp.expected_hash {
                if !expected.eq_ignore_ascii_case(&mod_hash) {
                    return Err(RuntimeError::with_span(
                        RuntimeErrorKind::ImportError(format!(
                            "module `{}` content hash mismatch: expected {}, actual {}",
                            imp.path, expected, mod_hash
                        )),
                        imp.span,
                    ));
                }
            }
            imported_modules.push(ImportedModuleRef {
                path: imp.path.clone(),
                blake3_hash: mod_hash,
            });
            let mod_kind = SourceFileKind::from_filename(&imp.path);
            compile_unit_recursive(
                &mod_src,
                mod_kind,
                resolver,
                visited,
                imported_modules,
                table,
                ops,
                true,
            )?;
            continue;
        }

        if let Some(op) = compile_statement_to_op(stmt, ops.len(), is_imported_module)? {
            ops.push(op);
        }
    }

    Ok(())
}

fn compile_statement_to_op(
    stmt: &Statement,
    index: usize,
    _is_imported_module: bool,
) -> Result<Option<CompiledOp>, RuntimeError> {
    let op = match stmt {
        Statement::Import(_) => return Ok(None),
        Statement::NetworkConnect(n) => CompiledOp {
            index,
            op_kind: if n.target_only {
                "NETWORK_TARGET"
            } else {
                "NETWORK_CONNECT"
            }
            .to_string(),
            params: serde_json::json!({ "network_id": n.network_id }),
            required_scope: "NETWORK".to_string(),
            span: Some(n.span),
        },
        Statement::ParticipantJoin(p) => {
            let ctx = p.context.as_ref().map(|c| {
                c.args
                    .iter()
                    .filter_map(|a| a.name.as_ref().map(|k| (k.clone(), expr_to_json(&a.value))))
                    .collect::<serde_json::Map<String, serde_json::Value>>()
            });
            CompiledOp {
                index,
                op_kind: "PARTICIPANT_JOIN".to_string(),
                params: serde_json::json!({
                    "name": p.name,
                    "scopes": p.scopes,
                    "context": ctx,
                }),
                required_scope: "NETWORK".to_string(),
                span: Some(p.span),
            }
        }
        Statement::SpaceCreate(s) => CompiledOp {
            index,
            op_kind: "SPACE_CREATE".to_string(),
            params: serde_json::json!({
                "space_name": s.name,
                "ghost": s.ghost,
                "fields": fields_to_json(&s.fields),
            }),
            required_scope: "NETWORK".to_string(),
            span: Some(s.span),
        },
        Statement::RegionCreate(r) => CompiledOp {
            index,
            op_kind: "REGION_CREATE".to_string(),
            params: serde_json::json!({
                "region_symbol": r.name,
                "space": r.space,
                "ghost": r.ghost,
                "fields": fields_to_json(&r.fields),
            }),
            required_scope: "SPACE".to_string(),
            span: Some(r.span),
        },
        Statement::WalletCreate(w) => CompiledOp {
            index,
            op_kind: "WALLET_CREATE".to_string(),
            params: serde_json::json!({
                "wallet_symbol": w.name,
                "region": w.region,
                "ghost": w.ghost,
                "fields": fields_to_json(&w.fields),
            }),
            required_scope: "REGION".to_string(),
            span: Some(w.span),
        },
        Statement::WalletAuthorize(a) => CompiledOp {
            index,
            op_kind: "WALLET_AUTHORIZE".to_string(),
            params: serde_json::json!({
                "wallet": a.wallet,
                "public_key": expr_to_json(&a.public_key),
                "role": a.role,
            }),
            required_scope: "WALLET".to_string(),
            span: Some(a.span),
        },
        Statement::TokenCreate(t) => CompiledOp {
            index,
            op_kind: "TOKEN_CREATE".to_string(),
            params: serde_json::json!({
                "token_symbol": t.name,
                "wallet": t.wallet,
                "ghost": t.ghost,
                "fields": fields_to_json(&t.fields),
            }),
            required_scope: "WALLET".to_string(),
            span: Some(t.span),
        },
        Statement::VectorDecl(v) => CompiledOp {
            index,
            op_kind: "VECTOR_CREATE".to_string(),
            params: serde_json::json!({
                "name": v.name,
                "vector_type": v.vector_type.as_str(),
                "components": v.components.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
            }),
            required_scope: "WALLET".to_string(),
            span: None,
        },
        Statement::WalletDecl(w) => CompiledOp {
            index,
            op_kind: "WALLET_BIND".to_string(),
            params: serde_json::json!({
                "name": w.name,
                "public_key": w.public_key,
            }),
            required_scope: "WALLET".to_string(),
            span: None,
        },
        Statement::Certify(c) => {
            let ctx = eval_context(&c.context);
            let ratio = compute_auth_ratio(&ctx);
            let certified = ratio.parse::<f64>().unwrap_or(0.0) >= 0.8000;
            CompiledOp {
                index,
                op_kind: "CERTIFY".to_string(),
                params: serde_json::json!({
                    "target": c.target,
                    "auth_ratio": ratio,
                    "certified": certified,
                }),
                required_scope: "REGION".to_string(),
                span: None,
            }
        }
        Statement::Transfer(t) => CompiledOp {
            index,
            op_kind: "TOKEN_TRANSFER".to_string(),
            params: serde_json::json!({
                "token": t.token,
                "from": t.source,
                "to": t.destination,
                "amount": expr_to_string(&t.amount),
                "drain": t.drain.as_ref().map(expr_to_string),
                "policy": t.policy.as_ref().map(expr_to_string),
            }),
            required_scope: "TOKEN".to_string(),
            span: None,
        },
        Statement::Receive(r) => CompiledOp {
            index,
            op_kind: "TOKEN_RECEIVE".to_string(),
            params: serde_json::json!({
                "token": r.token,
                "wallet": r.wallet,
                "source": r.source,
                "amount": expr_to_string(&r.amount),
            }),
            required_scope: "TOKEN".to_string(),
            span: Some(r.span),
        },
        Statement::Drain(d) => CompiledOp {
            index,
            op_kind: "TOKEN_DRAIN".to_string(),
            params: serde_json::json!({
                "target": d.target,
                "wallet": d.wallet,
                "amount": expr_to_string(&d.amount),
                "policy": d.policy.as_ref().map(expr_to_string),
            }),
            required_scope: "TOKEN".to_string(),
            span: None,
        },
        Statement::Project(p) => CompiledOp {
            index,
            op_kind: "PROJECT".to_string(),
            params: serde_json::json!({
                "source": p.source,
                "environment": p.environment,
                "amount": expr_to_string(&p.amount),
                "policy": p.policy.as_ref().map(expr_to_string),
            }),
            required_scope: "WALLET".to_string(),
            span: None,
        },
        Statement::Reconstruct(r) => CompiledOp {
            index,
            op_kind: "RECONSTRUCT".to_string(),
            params: serde_json::json!({
                "target": r.target,
                "projection_id": r.projection_id,
            }),
            required_scope: "NETWORK".to_string(),
            span: None,
        },
        Statement::Query(q) => CompiledOp {
            index,
            op_kind: "QUERY".to_string(),
            params: serde_json::json!({ "expr": expr_to_string(&q.expr) }),
            required_scope: "NETWORK".to_string(),
            span: None,
        },
        Statement::History(h) => CompiledOp {
            index,
            op_kind: "HISTORY_INSPECT".to_string(),
            params: serde_json::json!({ "expr": expr_to_string(&h.expr) }),
            required_scope: "NETWORK".to_string(),
            span: Some(h.span),
        },
        Statement::VerifyProof(v) => CompiledOp {
            index,
            op_kind: "PROOF_VERIFY".to_string(),
            params: serde_json::json!({ "expr": expr_to_string(&v.expr) }),
            required_scope: "NETWORK".to_string(),
            span: Some(v.span),
        },
        Statement::Record(r) => CompiledOp {
            index,
            op_kind: "EVENT_RECORD".to_string(),
            params: serde_json::json!({ "expr": expr_to_string(&r.expr) }),
            required_scope: "WALLET".to_string(),
            span: None,
        },
        Statement::Contract(c) => {
            let actions: Vec<serde_json::Value> = c
                .actions
                .iter()
                .map(|a| {
                    let mut args = serde_json::Map::new();
                    for (idx, arg) in a.args.iter().enumerate() {
                        let k = arg.name.clone().unwrap_or_else(|| format!("arg_{idx}"));
                        args.insert(k, expr_to_json(&arg.value));
                    }
                    serde_json::json!({ "name": a.name, "args": args })
                })
                .collect();
            CompiledOp {
                index,
                op_kind: "CONTRACT_CREATE".to_string(),
                params: serde_json::json!({
                    "name": c.name,
                    "actions": actions,
                    "fields": fields_to_json(&c.fields),
                }),
                required_scope: "REGION".to_string(),
                span: None,
            }
        }
        Statement::ContractExecute(ce) => {
            let mut args = serde_json::Map::new();
            for (idx, arg) in ce.args.iter().enumerate() {
                let k = arg.name.clone().unwrap_or_else(|| format!("arg_{idx}"));
                args.insert(k, expr_to_json(&arg.value));
            }
            CompiledOp {
                index,
                op_kind: "CONTRACT_EXECUTE".to_string(),
                params: serde_json::json!({
                    "contract": ce.contract,
                    "action": ce.action,
                    "args": args,
                }),
                required_scope: "WALLET".to_string(),
                span: Some(ce.span),
            }
        }
        Statement::LoanCreate(l) => CompiledOp {
            index,
            op_kind: "LOAN_CREATE".to_string(),
            params: serde_json::json!({
                "name": l.name,
                "fields": fields_to_json(&l.fields),
            }),
            required_scope: "WALLET".to_string(),
            span: Some(l.span),
        },
        Statement::LoanExecute(le) => {
            let mut args = serde_json::Map::new();
            for (idx, arg) in le.args.iter().enumerate() {
                let k = arg.name.clone().unwrap_or_else(|| format!("arg_{idx}"));
                args.insert(k, expr_to_json(&arg.value));
            }
            CompiledOp {
                index,
                op_kind: "LOAN_EXECUTE".to_string(),
                params: serde_json::json!({
                    "loan": le.loan,
                    "action": le.action,
                    "args": args,
                }),
                required_scope: "WALLET".to_string(),
                span: Some(le.span),
            }
        }
    };
    Ok(Some(op))
}

fn compute_auth_ratio(ctx: &Context) -> String {
    let mut am = 1.0f64;
    let mut ac = 1.0f64;
    let mut ao = 1.0f64;
    let mut ap = 1.0f64;
    if let Some(Value::String(op)) = ctx.get("op") {
        if op.trim().is_empty() {
            ap = 0.0;
        }
    } else {
        ap = 0.75;
    }
    if let Some(Value::String(space)) = ctx.get("space") {
        if space.trim().is_empty() {
            ac = 0.5;
        }
    }
    if let Some(Value::String(risk)) = ctx.get("risk") {
        if risk == "high" {
            ao = 0.8;
        }
    }
    if ctx.fields.is_empty() {
        am = 0.5;
        ac = 0.5;
        ao = 0.5;
        ap = 0.5;
    }
    let ratio = 0.35 * am + 0.25 * ac + 0.25 * ao + 0.15 * ap;
    format!("{ratio:.4}")
}
