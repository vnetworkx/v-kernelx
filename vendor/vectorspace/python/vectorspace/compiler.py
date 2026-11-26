from __future__ import annotations
from dataclasses import dataclass
from typing import List

from .ast import *

@dataclass
class KernelOp:
    kind: str
    payload: dict

def expr_to_text(expr: Expr) -> str:
    if expr.kind == "integer":
        return str(expr.value)
    if expr.kind == "string":
        return repr(expr.value)
    if expr.kind == "path":
        return ".".join(expr.value) if isinstance(expr.value, list) else str(expr.value)
    if expr.kind == "call":
        args = []
        for arg in expr.value["args"]:
            if arg.name:
                args.append(f"{arg.name}={expr_to_text(arg.value)}")
            else:
                args.append(expr_to_text(arg.value))
        return f'{expr.value["callee"]}({", ".join(args)})'
    if expr.kind == "group":
        return f'({expr_to_text(expr.value)})'
    return str(expr.value)

def compile_program(program: Program) -> List[KernelOp]:
    ops: List[KernelOp] = []
    for stmt in program.statements:
        if isinstance(stmt, VectorDecl):
            ops.append(KernelOp("CREATE", {"name": stmt.name, "type": stmt.vector_type, "components": stmt.components}))
        elif isinstance(stmt, WalletDecl):
            ops.append(KernelOp("BIND", {"name": stmt.name, "public_key": stmt.public_key}))
        elif isinstance(stmt, CertifyStmt):
            ops.append(KernelOp("CERTIFY", {"target": stmt.target, "context": stmt.context}))
        elif isinstance(stmt, TransferStmt):
            ops.append(KernelOp("TRANSFER", {
                "source": stmt.source, "destination": stmt.destination,
                "amount": expr_to_text(stmt.amount), "drain": expr_to_text(stmt.drain) if stmt.drain else "0",
                "policy": expr_to_text(stmt.policy) if stmt.policy else None,
            }))
        elif isinstance(stmt, DrainStmt):
            ops.append(KernelOp("DRAIN", {"target": stmt.target, "amount": expr_to_text(stmt.amount)}))
        elif isinstance(stmt, ProjectStmt):
            ops.append(KernelOp("PROJECT", {"source": stmt.source, "environment": stmt.environment, "amount": expr_to_text(stmt.amount), "policy": expr_to_text(stmt.policy) if stmt.policy else None}))
        elif isinstance(stmt, ReconstructStmt):
            ops.append(KernelOp("RECONSTRUCT", {"target": stmt.target, "projection_id": stmt.projection_id}))
        elif isinstance(stmt, QueryStmt):
            ops.append(KernelOp("QUERY", {"expr": expr_to_text(stmt.expr)}))
        elif isinstance(stmt, RecordStmt):
            ops.append(KernelOp("RECORD", {"expr": expr_to_text(stmt.expr)}))
        elif isinstance(stmt, ContractDecl):
            ops.append(KernelOp("CONTRACT", {"name": stmt.name, "actions": [a.name for a in stmt.actions]}))
            for action in stmt.actions:
                ops.append(KernelOp("CONTRACT_ACTION", {"contract": stmt.name, "action": action.name, "args": [expr_to_text(a.value) for a in action.args]}))
    return ops
