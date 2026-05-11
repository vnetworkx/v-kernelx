from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional
import json
import time
import hashlib

STATE_SCHEMA_V1 = "v.kernelx/VectorStateV1"

class VectorType(str, Enum):
    STANDARD = "Standard"
    ORIGIN = "Origin"
    PROJECTED = "Projected"
    ESCROW = "Escrow"
    SETTLEMENT = "Settlement"
    LOCKED = "Locked"

class VectorStatus(str, Enum):
    ACTIVE = "Active"
    PROJECTED = "Projected"
    ESCROWED = "Escrowed"
    SETTLED = "Settled"
    ARCHIVED = "Archived"

@dataclass
class CertificationState:
    certified: bool = False
    auth_ratio: int = 0
    threshold: int = 700
    last_checked_at_ms: int = 0
    reason: Optional[str] = None

@dataclass
class ProjectionState:
    escrow_id: str
    projected_components: List[int]
    settled_components: List[int] = field(default_factory=list)
    started_at_ms: int = 0
    settlement_at_ms: Optional[int] = None
    outcome_tag: Optional[str] = None

@dataclass
class OriginState:
    seed: str
    nonce: int
    difficulty: int
    proof_hash: str

@dataclass
class VectorStateV1:
    schema: str
    vector_id: str
    owner_pubkey: str
    space_id: str
    vector_type: VectorType
    status: VectorStatus
    components: List[int]
    type_metadata: Dict[str, str] = field(default_factory=dict)
    certification: CertificationState = field(default_factory=CertificationState)
    projection: Optional[ProjectionState] = None
    origin: Optional[OriginState] = None
    version: int = 1
    created_at_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    updated_at_ms: int = field(default_factory=lambda: int(time.time() * 1000))

    @staticmethod
    def new(vector_id: str, owner_pubkey: str, space_id: str, components: List[int], vector_type: VectorType) -> "VectorStateV1":
        now = int(time.time() * 1000)
        return VectorStateV1(
            schema=STATE_SCHEMA_V1,
            vector_id=vector_id,
            owner_pubkey=owner_pubkey,
            space_id=space_id,
            vector_type=vector_type,
            status=VectorStatus.ACTIVE,
            components=list(components),
            certification=CertificationState(certified=False, auth_ratio=0, threshold=700, last_checked_at_ms=now, reason="not yet certified"),
            created_at_ms=now,
            updated_at_ms=now,
        )

    def magnitude(self) -> int:
        return sum(self.components)

    def is_zero(self) -> bool:
        return all(v == 0 for v in self.components)

    def direction_shares(self):
        m = self.magnitude()
        if m == 0:
            raise ValueError("zero vector cannot be normalized")
        return [{"component_index": i, "numerator": c, "denominator": m} for i, c in enumerate(self.components)]

    def to_json(self) -> str:
        def default(o):
            if isinstance(o, Enum):
                return o.value
            if hasattr(o, "__dict__"):
                return asdict(o)
            raise TypeError(type(o))
        return json.dumps(asdict(self), default=default, sort_keys=True)

@dataclass
class VectorRecordV1:
    schema: str
    record_id: str
    vector_id: str
    before: Optional[VectorStateV1]
    after: VectorStateV1
    operation: str
    parameters: dict
    certification: CertificationState
    timestamp_ms: int
    proof: str

    @staticmethod
    def new(record_id: str, vector_id: str, before: Optional[VectorStateV1], after: VectorStateV1, operation: str, parameters: dict):
        timestamp_ms = int(time.time() * 1000)
        payload = json.dumps([record_id, vector_id, before and asdict(before), asdict(after), operation, parameters, asdict(after.certification), timestamp_ms], sort_keys=True, default=str).encode()
        proof = hashlib.sha256(payload).hexdigest()
        return VectorRecordV1("v.kernelx/VectorRecordV1", record_id, vector_id, before, after, operation, parameters, after.certification, timestamp_ms, proof)
