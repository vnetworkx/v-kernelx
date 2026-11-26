use crate::error::Span;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceFileKind {
    Vx,
    Vdx,
}

impl SourceFileKind {
    pub fn from_filename(name: &str) -> Self {
        if name.trim().to_ascii_lowercase().ends_with(".vdx") {
            Self::Vdx
        } else {
            Self::Vx
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vx => "vx",
            Self::Vdx => "vdx",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    pub statements: Vec<Statement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Statement {
    Import(ImportStmt),
    NetworkConnect(NetworkConnectStmt),
    ParticipantJoin(ParticipantJoinStmt),
    SpaceCreate(SpaceCreateStmt),
    RegionCreate(RegionCreateStmt),
    WalletCreate(WalletCreateStmt),
    WalletAuthorize(WalletAuthorizeStmt),
    TokenCreate(TokenCreateStmt),
    VectorDecl(VectorDecl),
    WalletDecl(WalletDecl),
    Certify(CertifyStmt),
    Transfer(TransferStmt),
    Receive(ReceiveStmt),
    Drain(DrainStmt),
    Project(ProjectStmt),
    Reconstruct(ReconstructStmt),
    Query(QueryStmt),
    History(HistoryStmt),
    VerifyProof(VerifyProofStmt),
    Record(RecordStmt),
    Contract(ContractDecl),
    ContractExecute(ContractExecuteStmt),
    LoanCreate(LoanCreateStmt),
    LoanExecute(LoanExecuteStmt),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportStmt {
    pub path: String,
    pub hash_algorithm: Option<String>,
    pub expected_hash: Option<String>,
    pub alias: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConnectStmt {
    pub network_id: String,
    pub target_only: bool,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantJoinStmt {
    pub name: String,
    pub scopes: Vec<String>,
    pub context: Option<ContextExpr>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyField {
    pub name: String,
    pub value: Expr,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceCreateStmt {
    pub name: String,
    pub ghost: bool,
    pub fields: Vec<PropertyField>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionCreateStmt {
    pub name: String,
    pub space: String,
    pub ghost: bool,
    pub fields: Vec<PropertyField>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletCreateStmt {
    pub name: String,
    pub region: String,
    pub ghost: bool,
    pub context: Option<ContextExpr>,
    pub fields: Vec<PropertyField>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletAuthorizeStmt {
    pub wallet: String,
    pub public_key: Expr,
    pub role: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenCreateStmt {
    pub name: String,
    pub wallet: String,
    pub ghost: bool,
    pub fields: Vec<PropertyField>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorDecl {
    pub name: String,
    pub vector_type: VectorType,
    pub components: Vec<u128>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletDecl {
    pub name: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertifyStmt {
    pub target: String,
    pub context: ContextExpr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferStmt {
    pub token: Option<String>,
    pub source: String,
    pub destination: String,
    pub amount: Expr,
    pub drain: Option<Expr>,
    pub policy: Option<Expr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiveStmt {
    pub token: String,
    pub wallet: String,
    pub source: String,
    pub amount: Expr,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainStmt {
    pub target: String,
    pub wallet: Option<String>,
    pub amount: Expr,
    pub policy: Option<Expr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectStmt {
    pub source: String,
    pub environment: String,
    pub amount: Expr,
    pub policy: Option<Expr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconstructStmt {
    pub target: String,
    pub projection_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryStmt {
    pub expr: Expr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryStmt {
    pub expr: Expr,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyProofStmt {
    pub expr: Expr,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordStmt {
    pub expr: Expr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractDecl {
    pub name: String,
    pub actions: Vec<ContractAction>,
    pub fields: Vec<PropertyField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAction {
    pub name: String,
    pub args: Vec<NamedArg>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractExecuteStmt {
    pub contract: String,
    pub action: String,
    pub args: Vec<NamedArg>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoanCreateStmt {
    pub name: String,
    pub fields: Vec<PropertyField>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoanExecuteStmt {
    pub loan: String,
    pub action: String,
    pub args: Vec<NamedArg>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedArg {
    pub name: Option<String>,
    pub value: Expr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expr {
    Integer(u128),
    Bool(bool),
    String(String),
    Ident(String),
    Path(Vec<String>),
    VectorLiteral(Vec<u128>),
    Call { callee: String, args: Vec<NamedArg> },
    Group(Box<Expr>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextExpr {
    pub args: Vec<NamedArg>,
}

impl ContextExpr {
    pub fn new(args: Vec<NamedArg>) -> Self {
        Self { args }
    }

    pub fn get(&self, key: &str) -> Option<&Expr> {
        self.args.iter().find_map(|arg| match &arg.name {
            Some(name) if name == key => Some(&arg.value),
            _ => None,
        })
    }

    pub fn as_map(&self) -> BTreeMap<String, Expr> {
        let mut out = BTreeMap::new();
        for arg in &self.args {
            if let Some(name) = &arg.name {
                out.insert(name.clone(), arg.value.clone());
            }
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VectorType {
    Position,
    Free,
    Bound,
    Unit,
    Zero,
    Spatial,
}

impl VectorType {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "position" => Some(Self::Position),
            "free" => Some(Self::Free),
            "bound" => Some(Self::Bound),
            "unit" => Some(Self::Unit),
            "zero" => Some(Self::Zero),
            "spatial" => Some(Self::Spatial),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Position => "position",
            Self::Free => "free",
            Self::Bound => "bound",
            Self::Unit => "unit",
            Self::Zero => "zero",
            Self::Spatial => "spatial",
        }
    }
}
