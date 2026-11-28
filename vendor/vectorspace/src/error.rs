use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub line: usize,
    pub col: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self {
            start,
            end,
            line: 1,
            col: start + 1,
        }
    }

    pub fn with_line_col(start: usize, end: usize, line: usize, col: usize) -> Self {
        Self {
            start,
            end,
            line,
            col,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticLevel {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub level: DiagnosticLevel,
    pub code: String,
    pub message: String,
    pub span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseErrorKind {
    UnexpectedEof,
    UnexpectedToken { expected: String, found: String },
    InvalidNumber(String),
    InvalidString(String),
    Message(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseError {
    pub span: Span,
    pub kind: ParseErrorKind,
}

impl ParseError {
    pub fn new(span: Span, kind: ParseErrorKind) -> Self {
        Self { span, kind }
    }
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ParseErrorKind::UnexpectedEof => {
                write!(
                    f,
                    "unexpected end of file at {}:{} ({}..{})",
                    self.span.line, self.span.col, self.span.start, self.span.end
                )
            }
            ParseErrorKind::UnexpectedToken { expected, found } => write!(
                f,
                "unexpected token `{found}` at {}:{} ({}..{}), expected {expected}",
                self.span.line, self.span.col, self.span.start, self.span.end
            ),
            ParseErrorKind::InvalidNumber(v) => {
                write!(
                    f,
                    "invalid number `{v}` at {}:{} ({}..{})",
                    self.span.line, self.span.col, self.span.start, self.span.end
                )
            }
            ParseErrorKind::InvalidString(v) => {
                write!(
                    f,
                    "invalid string `{v}` at {}:{} ({}..{})",
                    self.span.line, self.span.col, self.span.start, self.span.end
                )
            }
            ParseErrorKind::Message(msg) => write!(
                f,
                "{msg} at {}:{} ({}..{})",
                self.span.line, self.span.col, self.span.start, self.span.end
            ),
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeErrorKind {
    Parse(ParseErrorKind),
    DuplicateSymbol(String),
    UnknownSymbol(String),
    TypeMismatch { expected: String, found: String },
    Validation(String),
    PermissionDenied(String),
    ImportError(String),
    InsufficientBalance { name: String, requested: u128, available: u128 },
    CertificationFailed { name: String, ratio: String, threshold: String },
    ProjectionMissing(String),
    ProjectionConsumed(String),
    ContractMissing(String),
    RecordMissing(String),
    InvalidOperation(String),
    ImmutableViolation(String),
    ZeroNormalization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeError {
    pub span: Option<Span>,
    pub kind: RuntimeErrorKind,
}

impl RuntimeError {
    pub fn new(kind: RuntimeErrorKind) -> Self {
        Self { span: None, kind }
    }

    pub fn with_span(kind: RuntimeErrorKind, span: Span) -> Self {
        Self {
            span: Some(span),
            kind,
        }
    }

    pub fn code(&self) -> &'static str {
        match &self.kind {
            RuntimeErrorKind::Parse(_) => "E_PARSE",
            RuntimeErrorKind::DuplicateSymbol(_) => "E_DUPLICATE_SYMBOL",
            RuntimeErrorKind::UnknownSymbol(_) => "E_UNKNOWN_SYMBOL",
            RuntimeErrorKind::TypeMismatch { .. } => "E_TYPE_MISMATCH",
            RuntimeErrorKind::Validation(_) => "E_VALIDATION",
            RuntimeErrorKind::PermissionDenied(_) => "E_PERMISSION",
            RuntimeErrorKind::ImportError(_) => "E_IMPORT",
            RuntimeErrorKind::InsufficientBalance { .. } => "E_INSUFFICIENT_BALANCE",
            RuntimeErrorKind::CertificationFailed { .. } => "E_CERTIFICATION",
            RuntimeErrorKind::ProjectionMissing(_) => "E_PROJECTION_MISSING",
            RuntimeErrorKind::ProjectionConsumed(_) => "E_PROJECTION_CONSUMED",
            RuntimeErrorKind::ContractMissing(_) => "E_CONTRACT_MISSING",
            RuntimeErrorKind::RecordMissing(_) => "E_RECORD_MISSING",
            RuntimeErrorKind::InvalidOperation(_) => "E_INVALID_OPERATION",
            RuntimeErrorKind::ImmutableViolation(_) => "E_IMMUTABLE_VIOLATION",
            RuntimeErrorKind::ZeroNormalization => "E_ZERO_NORMALIZATION",
        }
    }
}

impl Display for RuntimeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(span) = self.span {
            write!(f, "[{}:{}] ", span.line, span.col)?;
        }
        match &self.kind {
            RuntimeErrorKind::Parse(k) => write!(f, "parse error: {k:?}"),
            RuntimeErrorKind::DuplicateSymbol(s) => write!(f, "duplicate symbol `{s}`"),
            RuntimeErrorKind::UnknownSymbol(s) => write!(f, "unknown symbol `{s}`"),
            RuntimeErrorKind::TypeMismatch { expected, found } => {
                write!(f, "type mismatch: expected {expected}, found {found}")
            }
            RuntimeErrorKind::Validation(msg) => write!(f, "validation failed: {msg}"),
            RuntimeErrorKind::PermissionDenied(msg) => write!(f, "permission denied: {msg}"),
            RuntimeErrorKind::ImportError(msg) => write!(f, "import error: {msg}"),
            RuntimeErrorKind::InsufficientBalance {
                name,
                requested,
                available,
            } => write!(
                f,
                "insufficient balance in `{name}`: requested {requested}, available {available}"
            ),
            RuntimeErrorKind::CertificationFailed {
                name,
                ratio,
                threshold,
            } => write!(
                f,
                "certification failed for `{name}`: ratio {ratio} below threshold {threshold}"
            ),
            RuntimeErrorKind::ProjectionMissing(id) => write!(f, "projection `{id}` not found"),
            RuntimeErrorKind::ProjectionConsumed(id) => {
                write!(f, "projection `{id}` was already consumed")
            }
            RuntimeErrorKind::ContractMissing(id) => write!(f, "contract `{id}` not found"),
            RuntimeErrorKind::RecordMissing(id) => write!(f, "record `{id}` not found"),
            RuntimeErrorKind::InvalidOperation(msg) => write!(f, "invalid operation: {msg}"),
            RuntimeErrorKind::ImmutableViolation(msg) => write!(f, "immutable violation: {msg}"),
            RuntimeErrorKind::ZeroNormalization => {
                write!(f, "normalization of the zero vector is undefined")
            }
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<ParseError> for RuntimeError {
    fn from(err: ParseError) -> Self {
        Self {
            span: Some(err.span),
            kind: RuntimeErrorKind::Parse(err.kind),
        }
    }
}
