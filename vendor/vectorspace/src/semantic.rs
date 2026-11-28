use crate::ast::*;
use crate::error::{Diagnostic, DiagnosticLevel, RuntimeError, RuntimeErrorKind, Span};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolKind {
    Space,
    Region,
    Wallet,
    Token,
    Vector,
    Contract,
    Loan,
    Participant,
}

#[derive(Debug, Clone)]
pub struct SymbolTable {
    pub symbols: BTreeMap<String, SymbolKind>,
    pub token_dimensions: BTreeMap<String, usize>,
    pub diagnostics: Vec<Diagnostic>,
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            symbols: BTreeMap::new(),
            token_dimensions: BTreeMap::new(),
            diagnostics: Vec::new(),
        }
    }

    pub fn declare(
        &mut self,
        name: &str,
        kind: SymbolKind,
        span: Option<Span>,
    ) -> Result<(), RuntimeError> {
        if let Some(existing) = self.symbols.get(name) {
            if *existing != kind {
                return Err(RuntimeError {
                    span,
                    kind: RuntimeErrorKind::DuplicateSymbol(name.to_string()),
                });
            }
            self.diagnostics.push(Diagnostic {
                level: DiagnosticLevel::Warning,
                code: "W_REDECLARED".to_string(),
                message: format!("symbol `{name}` redeclared in current program"),
                span,
            });
        }
        self.symbols.insert(name.to_string(), kind);
        Ok(())
    }
}

pub fn field_map(fields: &[PropertyField]) -> BTreeMap<String, &Expr> {
    let mut map = BTreeMap::new();
    for f in fields {
        map.insert(f.name.clone(), &f.value);
    }
    map
}

pub fn validate_program_semantics(
    program: &Program,
    file_kind: SourceFileKind,
    table: &mut SymbolTable,
) -> Result<(), RuntimeError> {
    for stmt in &program.statements {
        if file_kind == SourceFileKind::Vdx {
            match stmt {
                Statement::Transfer(_)
                | Statement::Receive(_)
                | Statement::Drain(_)
                | Statement::Project(_)
                | Statement::Reconstruct(_)
                | Statement::ContractExecute(_)
                | Statement::LoanExecute(_)
                | Statement::NetworkConnect(_)
                | Statement::ParticipantJoin(_) => {
                    return Err(RuntimeError::new(RuntimeErrorKind::Validation(
                        ".vdx declaration modules may only contain declarations, imports, contracts, and policies".to_string(),
                    )));
                }
                _ => {}
            }
        }

        match stmt {
            Statement::Import(_) => {}
            Statement::NetworkConnect(n) => {
                if n.network_id.trim().is_empty() {
                    return Err(RuntimeError::with_span(
                        RuntimeErrorKind::Validation("network_id cannot be empty".to_string()),
                        n.span,
                    ));
                }
            }
            Statement::ParticipantJoin(p) => {
                if p.name.trim().is_empty() {
                    return Err(RuntimeError::with_span(
                        RuntimeErrorKind::Validation("participant name cannot be empty".to_string()),
                        p.span,
                    ));
                }
                for scope in &p.scopes {
                    let norm = scope.trim().to_ascii_uppercase();
                    if !matches!(
                        norm.as_str(),
                        "NETWORK" | "SPACE" | "REGION" | "WALLET" | "TOKEN"
                    ) {
                        return Err(RuntimeError::with_span(
                            RuntimeErrorKind::PermissionDenied(format!(
                                "invalid participation scope `{scope}`"
                            )),
                            p.span,
                        ));
                    }
                }
                table.declare(&p.name, SymbolKind::Participant, Some(p.span))?;
            }
            Statement::SpaceCreate(s) => {
                if s.name.trim().is_empty() {
                    return Err(RuntimeError::with_span(
                        RuntimeErrorKind::Validation("space name cannot be empty".to_string()),
                        s.span,
                    ));
                }
                let fields = field_map(&s.fields);
                if let Some(vis) = fields.get("visibility") {
                    validate_visibility(vis, s.span)?;
                }
                table.declare(&s.name, SymbolKind::Space, Some(s.span))?;
            }
            Statement::RegionCreate(r) => {
                if r.name.trim().is_empty() || (!r.ghost && r.space.trim().is_empty()) {
                    return Err(RuntimeError::with_span(
                        RuntimeErrorKind::Validation(
                            "region name cannot be empty, and non-ghost regions require a parent space"
                                .to_string(),
                        ),
                        r.span,
                    ));
                }
                let fields = field_map(&r.fields);
                if let Some(vis) = fields.get("visibility") {
                    validate_visibility(vis, r.span)?;
                }
                table.declare(&r.name, SymbolKind::Region, Some(r.span))?;
            }
            Statement::WalletCreate(w) => {
                if w.name.trim().is_empty() || (!w.ghost && w.region.trim().is_empty()) {
                    return Err(RuntimeError::with_span(
                        RuntimeErrorKind::Validation(
                            "wallet name cannot be empty, and non-ghost wallets require a parent region"
                                .to_string(),
                        ),
                        w.span,
                    ));
                }
                table.declare(&w.name, SymbolKind::Wallet, Some(w.span))?;
            }
            Statement::WalletAuthorize(a) => {
                if a.wallet.trim().is_empty() {
                    return Err(RuntimeError::with_span(
                        RuntimeErrorKind::Validation("wallet target cannot be empty".to_string()),
                        a.span,
                    ));
                }
            }
            Statement::TokenCreate(t) => {
                if t.name.trim().is_empty() || (!t.ghost && t.wallet.trim().is_empty()) {
                    return Err(RuntimeError::with_span(
                        RuntimeErrorKind::Validation(
                            "token name cannot be empty, and non-ghost tokens require a parent wallet"
                                .to_string(),
                        ),
                        t.span,
                    ));
                }
                let fields = field_map(&t.fields);
                if let Some(dims) = fields.get("dimensions") {
                    match dims {
                        Expr::Integer(3) => {}
                        Expr::Integer(other) => {
                            return Err(RuntimeError::with_span(
                                RuntimeErrorKind::TypeMismatch {
                                    expected: "3 ([token, authratio(au), energy])".to_string(),
                                    found: format!("{other}"),
                                },
                                t.span,
                            ));
                        }
                        other => {
                            return Err(RuntimeError::with_span(
                                RuntimeErrorKind::TypeMismatch {
                                    expected: "integer 3".to_string(),
                                    found: format!("{other:?}"),
                                },
                                t.span,
                            ));
                        }
                    }
                }
                if let Some(vec_expr) = fields.get("vector") {
                    match vec_expr {
                        Expr::VectorLiteral(vals) if vals.len() == 3 => {}
                        Expr::VectorLiteral(vals) => {
                            return Err(RuntimeError::with_span(
                                RuntimeErrorKind::TypeMismatch {
                                    expected: "3-dimensional vector [token, authratio(au), energy]".to_string(),
                                    found: format!("{}-dimensional vector", vals.len()),
                                },
                                t.span,
                            ));
                        }
                        other => {
                            return Err(RuntimeError::with_span(
                                RuntimeErrorKind::TypeMismatch {
                                    expected: "3-element vector literal".to_string(),
                                    found: format!("{other:?}"),
                                },
                                t.span,
                            ));
                        }
                    }
                }
                table.declare(&t.name, SymbolKind::Token, Some(t.span))?;
                table.token_dimensions.insert(t.name.clone(), 3);
            }
            Statement::VectorDecl(v) => {
                if v.components.is_empty() {
                    return Err(RuntimeError::new(RuntimeErrorKind::Validation(format!(
                        "vector `{}` must have at least one component",
                        v.name
                    ))));
                }
                table.declare(&v.name, SymbolKind::Vector, None)?;
            }
            Statement::WalletDecl(w) => {
                table.declare(&w.name, SymbolKind::Wallet, None)?;
            }
            Statement::Transfer(t) => {
                if t.drain.is_some() {
                    return Err(RuntimeError::new(RuntimeErrorKind::InvalidOperation(
                        "sender-supplied `drain` override on `transfer` is forbidden; transfer drain rate is strictly protocol-determined from transfer scope".to_string(),
                    )));
                }
                match &t.amount {
                    Expr::Integer(n) if *n > 0 => {}
                    Expr::Integer(0) => {
                        return Err(RuntimeError::new(RuntimeErrorKind::Validation(
                            "transfer amount must be positive".to_string(),
                        )));
                    }
                    Expr::VectorLiteral(_) => {
                        return Err(RuntimeError::new(RuntimeErrorKind::ImmutableViolation(
                            "ordinary token transfer cannot directly mutate multidimensional [token, authratio, energy] components; only Token amount is transferable".to_string(),
                        )));
                    }
                    _ => {}
                }
                if let Some(policy) = &t.policy {
                    let p = format!("{policy:?}").to_ascii_lowercase();
                    if p.contains("authratio") || p.contains("energy") {
                        return Err(RuntimeError::new(RuntimeErrorKind::ImmutableViolation(
                            "transfer cannot target AuthRatio or Energy dimensions".to_string(),
                        )));
                    }
                }
            }
            Statement::Receive(r) => {
                if let Expr::Integer(0) = r.amount {
                    return Err(RuntimeError::with_span(
                        RuntimeErrorKind::Validation("receive amount must be positive".to_string()),
                        r.span,
                    ));
                }
            }
            Statement::Drain(d) => {
                if let Expr::Integer(0) = d.amount {
                    return Err(RuntimeError::new(RuntimeErrorKind::Validation(
                        "drain amount must be positive".to_string(),
                    )));
                }
            }
            Statement::Contract(c) => {
                table.declare(&c.name, SymbolKind::Contract, None)?;
            }
            Statement::ContractExecute(ce) => {
                if ce.contract.trim().is_empty() || ce.action.trim().is_empty() {
                    return Err(RuntimeError::with_span(
                        RuntimeErrorKind::Validation(
                            "contract and action names cannot be empty".to_string(),
                        ),
                        ce.span,
                    ));
                }
            }
            Statement::LoanCreate(l) => {
                let fields = field_map(&l.fields);
                if let Some(Expr::Integer(0)) = fields.get("principal") {
                    return Err(RuntimeError::with_span(
                        RuntimeErrorKind::Validation("loan principal must be positive".to_string()),
                        l.span,
                    ));
                }
                table.declare(&l.name, SymbolKind::Loan, Some(l.span))?;
            }
            Statement::LoanExecute(le) => {
                let act = le.action.trim().to_ascii_lowercase();
                if !matches!(act.as_str(), "draw" | "repay" | "liquidate" | "fund" | "settle") {
                    return Err(RuntimeError::with_span(
                        RuntimeErrorKind::InvalidOperation(format!(
                            "unsupported loan action `{}`",
                            le.action
                        )),
                        le.span,
                    ));
                }
            }
            Statement::Certify(_)
            | Statement::Project(_)
            | Statement::Reconstruct(_)
            | Statement::Query(_)
            | Statement::History(_)
            | Statement::VerifyProof(_)
            | Statement::Record(_) => {}
        }
    }

    let _ = BTreeSet::<String>::new();
    Ok(())
}

fn validate_visibility(expr: &Expr, span: Span) -> Result<(), RuntimeError> {
    match expr {
        Expr::Ident(s) | Expr::String(s) => {
            let norm = s.trim().to_ascii_lowercase();
            if norm == "public" || norm == "private" {
                Ok(())
            } else {
                Err(RuntimeError::with_span(
                    RuntimeErrorKind::Validation(format!(
                        "visibility must be `public` or `private`, got `{s}`"
                    )),
                    span,
                ))
            }
        }
        other => Err(RuntimeError::with_span(
            RuntimeErrorKind::TypeMismatch {
                expected: "public | private".to_string(),
                found: format!("{other:?}"),
            },
            span,
        )),
    }
}
