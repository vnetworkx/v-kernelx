from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from .ast import *
from .compiler import compile_program
from .parser import parse

@dataclass
class Vector:
    name: str
    vector_type: str
    components: List[int]
    certification: str = "pending"

@dataclass
class Runtime:
    vectors: Dict[str, Vector] = field(default_factory=dict)
    wallets: Dict[str, str] = field(default_factory=dict)
    events: List[str] = field(default_factory=list)

    def execute_source(self, source: str):
        program = parse(source)
        return self.execute_program(program)

    def execute_program(self, program: Program):
        ops = compile_program(program)
        outputs = []
        for op in ops:
            if op.kind == "CREATE":
                self.vectors[op.payload["name"]] = Vector(op.payload["name"], op.payload["type"], op.payload["components"])
                self.events.append(f'CREATE:{op.payload["name"]}')
                outputs.append(f"created {op.payload['name']}")
            elif op.kind == "BIND":
                self.wallets[op.payload["name"]] = op.payload["public_key"]
                self.events.append(f'BIND:{op.payload["name"]}')
                outputs.append(f"wallet {op.payload['name']} bound")
            elif op.kind == "CERTIFY":
                vec = self.vectors[op.payload["target"]]
                vec.certification = "certified"
                self.events.append(f'CERTIFY:{op.payload["target"]}')
                outputs.append(f"certify {op.payload['target']} -> certified")
            elif op.kind == "TRANSFER":
                outputs.append(f"transfer {op.payload['source']}->{op.payload['destination']} amount={op.payload['amount']}")
                self.events.append("TRANSFER")
            elif op.kind == "DRAIN":
                outputs.append(f"drain {op.payload['target']} amount={op.payload['amount']}")
                self.events.append("DRAIN")
            elif op.kind == "PROJECT":
                outputs.append(f"project {op.payload['source']} -> {op.payload['environment']}")
                self.events.append("PROJECT")
            elif op.kind == "RECONSTRUCT":
                outputs.append(f"reconstruct {op.payload['target']} from {op.payload['projection_id']}")
                self.events.append("RECONSTRUCT")
            elif op.kind == "QUERY":
                outputs.append(op.payload["expr"])
            elif op.kind == "RECORD":
                outputs.append(op.payload["expr"])
            elif op.kind == "CONTRACT":
                outputs.append(f"contract {op.payload['name']} deployed")
                self.events.append(f"CONTRACT:{op.payload['name']}")
            elif op.kind == "CONTRACT_ACTION":
                outputs.append(f"contract action {op.payload['contract']}::{op.payload['action']}")
                self.events.append("CONTRACT_ACTION")
        return {"outputs": outputs, "events": list(self.events), "vectors": self.vectors}
