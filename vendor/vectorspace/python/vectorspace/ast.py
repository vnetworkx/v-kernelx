from dataclasses import dataclass, field
from typing import List, Optional, Union, Dict, Any

@dataclass
class Program:
    statements: List[Any]

@dataclass
class VectorDecl:
    name: str
    vector_type: str
    components: List[int]

@dataclass
class WalletDecl:
    name: str
    public_key: str

@dataclass
class NamedArg:
    name: Optional[str]
    value: Any

@dataclass
class Expr:
    kind: str
    value: Any

@dataclass
class ContextExpr:
    args: List[NamedArg] = field(default_factory=list)

@dataclass
class CertifyStmt:
    target: str
    context: ContextExpr

@dataclass
class TransferStmt:
    source: str
    destination: str
    amount: Expr
    drain: Optional[Expr] = None
    policy: Optional[Expr] = None

@dataclass
class DrainStmt:
    target: str
    amount: Expr

@dataclass
class ProjectStmt:
    source: str
    environment: str
    amount: Expr
    policy: Optional[Expr] = None

@dataclass
class ReconstructStmt:
    target: str
    projection_id: str

@dataclass
class QueryStmt:
    expr: Expr

@dataclass
class RecordStmt:
    expr: Expr

@dataclass
class ContractAction:
    name: str
    args: List[NamedArg] = field(default_factory=list)

@dataclass
class ContractDecl:
    name: str
    actions: List[ContractAction] = field(default_factory=list)
