from __future__ import annotations
from dataclasses import asdict
from typing import Dict, List, Optional, Tuple
import hashlib
import json
import time

from .model import (
    STATE_SCHEMA_V1,
    CertificationState,
    OriginState,
    ProjectionState,
    VectorRecordV1,
    VectorStateV1,
    VectorStatus,
    VectorType,
)


def find_valid_nonce(seed: str, difficulty: int, max_attempts: int = 1_000_000) -> Optional[int]:
    if difficulty <= 0:
        return 0
    for nonce in range(max_attempts):
        proof = hashlib.sha256(f"{seed}:{nonce}".encode()).hexdigest()
        if len(proof) - len(proof.lstrip("0")) >= difficulty:
            return nonce
    return None


class VectorKernel:
    def __init__(self):
        self.states: Dict[str, VectorStateV1] = {}
        self.records: Dict[str, VectorRecordV1] = {}

    def _now(self) -> int:
        return int(time.time() * 1000)

    def _certify_state(self, state: VectorStateV1) -> CertificationState:
        auth = 1000 if state.owner_pubkey else 0
        if state.is_zero():
            auth = max(auth, 100)
        if state.schema != STATE_SCHEMA_V1 or not state.vector_id or not state.space_id:
            return CertificationState(False, 0, 700, self._now(), "invalid canonical state")
        certified = auth >= state.certification.threshold
        return CertificationState(certified, auth, state.certification.threshold, self._now(), None if certified else "below threshold")

    def create_origin(self, vector_id: str, owner_pubkey: str, space_id: str, components: List[int], seed: str, nonce: int, difficulty: int) -> VectorStateV1:
        proof = hashlib.sha256(f"{seed}:{nonce}".encode()).hexdigest()
        if len(proof) - len(proof.lstrip("0")) < difficulty:
            raise ValueError("origin proof rejected")
        state = VectorStateV1.new(vector_id, owner_pubkey, space_id, components, VectorType.ORIGIN)
        state.origin = OriginState(seed, nonce, difficulty, proof)
        state.certification = self._certify_state(state)
        self.states[vector_id] = state
        self._record(None, state, "OriginCreate", {"difficulty": difficulty})
        return state

    def transfer(self, from_id: str, to_id: str, amount: List[int]) -> Tuple[VectorStateV1, VectorStateV1]:
        sender = self.states[from_id]
        receiver = self.states[to_id]
        if len(sender.components) != len(receiver.components) or len(amount) != len(sender.components):
            raise ValueError("dimension mismatch")
        if any(a > s for a, s in zip(amount, sender.components)):
            raise ValueError("insufficient balance")
        before_from = json.loads(sender.to_json())
        before_to = json.loads(receiver.to_json())
        sender.components = [s - a for s, a in zip(sender.components, amount)]
        receiver.components = [r + a for r, a in zip(receiver.components, amount)]
        sender.certification = self._certify_state(sender)
        receiver.certification = self._certify_state(receiver)
        self.states[from_id] = sender
        self.states[to_id] = receiver
        self._record_obj(before_from, sender, "Transfer", {"direction": "out", "amount": amount})
        self._record_obj(before_to, receiver, "Transfer", {"direction": "in", "amount": amount})
        return sender, receiver

    def drain(self, vector_id: str, basis_points: int) -> VectorStateV1:
        state = self.states[vector_id]
        if basis_points > 10_000:
            raise ValueError("drain too large")
        discount = basis_points // 2 if state.certification.auth_ratio >= state.certification.threshold else basis_points
        state.components = [c - (c * discount // 10_000) for c in state.components]
        state.certification = self._certify_state(state)
        self.states[vector_id] = state
        self._record(None, state, "Drain", {"basis_points": basis_points})
        return state

    def project(self, vector_id: str, projected_components: List[int], escrow_id: str) -> VectorStateV1:
        state = self.states[vector_id]
        if len(projected_components) != len(state.components):
            raise ValueError("dimension mismatch")
        if any(p > c for p, c in zip(projected_components, state.components)):
            raise ValueError("insufficient balance")
        state.components = [c - p for c, p in zip(state.components, projected_components)]
        state.vector_type = VectorType.PROJECTED
        state.status = VectorStatus.PROJECTED
        state.projection = ProjectionState(escrow_id, list(projected_components), [], self._now(), None, None)
        state.certification = self._certify_state(state)
        self.states[vector_id] = state
        self._record(None, state, "Project", {"escrow_id": escrow_id, "projected_components": projected_components})
        return state

    def reconstruct(self, vector_id: str, gains: List[int], losses: List[int], outcome_tag: str = "settled") -> VectorStateV1:
        state = self.states[vector_id]
        if not state.projection:
            raise ValueError("missing projection")
        if len(gains) != len(losses) or len(gains) != len(state.projection.projected_components):
            raise ValueError("dimension mismatch")
        settled = []
        for principal, gain, loss in zip(state.projection.projected_components, gains, losses):
            value = principal + gain - loss
            if value < 0:
                raise ValueError("settlement rejected")
            settled.append(value)
        for idx, value in enumerate(settled):
            if idx < len(state.components):
                state.components[idx] += value
            else:
                state.components.append(value)
        state.projection.settled_components = settled
        state.projection.settlement_at_ms = self._now()
        state.projection.outcome_tag = outcome_tag
        state.vector_type = VectorType.SETTLEMENT
        state.status = VectorStatus.SETTLED
        state.certification = self._certify_state(state)
        self.states[vector_id] = state
        self._record(None, state, "Reconstruct", {"outcome_tag": outcome_tag})
        return state

    def certify(self, vector_id: str) -> VectorStateV1:
        state = self.states[vector_id]
        state.certification = self._certify_state(state)
        self.states[vector_id] = state
        self._record(None, state, "Certify", {})
        return state

    def query(self, vector_id: str) -> Optional[VectorStateV1]:
        return self.states.get(vector_id)

    def query_records(self) -> List[VectorRecordV1]:
        return list(self.records.values())

    def query_vectors(self) -> List[VectorStateV1]:
        return list(self.states.values())

    def execute_script(self, script: str) -> List[str]:
        results = []
        for raw in script.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            opcode, _, payload = line.partition(" ")
            params = json.loads(payload or "{}")
            op = opcode.upper()
            if op in {"ORIGIN", "ORIGIN_CREATE"}:
                state = self.create_origin(params["vector_id"], params["owner_pubkey"], params.get("space_id", "default"), params.get("components", []), params.get("seed", ""), params.get("nonce", 0), params.get("difficulty", 1))
                results.append(f"origin:{state.vector_id}")
            elif op == "TRANSFER":
                a, b = self.transfer(params["from"], params["to"], params["amount"])
                results.append(f"transfer:{a.vector_id}->{b.vector_id}")
            elif op == "DRAIN":
                state = self.drain(params["vector_id"], params["basis_points"])
                results.append(f"drain:{state.vector_id}")
            elif op == "PROJECT":
                state = self.project(params["vector_id"], params["projected_components"], params["escrow_id"])
                results.append(f"project:{state.vector_id}")
            elif op == "RECONSTRUCT":
                state = self.reconstruct(params["vector_id"], params.get("gains", []), params.get("losses", []), params.get("outcome_tag", "settled"))
                results.append(f"reconstruct:{state.vector_id}")
            elif op == "CERTIFY":
                state = self.certify(params["vector_id"])
                results.append(f"certify:{state.vector_id}:{state.certification.auth_ratio}")
            elif op == "QUERY":
                state = self.query(params["vector_id"])
                results.append(json.dumps(asdict(state), default=str) if state else "null")
            else:
                raise ValueError(f"unknown opcode: {opcode}")
        return results

    def _record(self, before, after: VectorStateV1, operation: str, parameters: dict):
        before_obj = before if isinstance(before, VectorStateV1) else before
        before_payload = None if before is None else json.dumps(asdict(before), sort_keys=True, default=str)
        after_payload = json.dumps(asdict(after), sort_keys=True, default=str)
        record_id = hashlib.sha256(json.dumps([after.vector_id, operation, before_payload, after_payload, parameters], sort_keys=True, default=str).encode()).hexdigest()
        record = VectorRecordV1.new(record_id, after.vector_id, before_obj, after, operation, parameters)
        self.records[record_id] = record

    def _record_obj(self, before_json, after: VectorStateV1, operation: str, parameters: dict):
        before = None
        if before_json is not None:
            before = VectorStateV1(
                schema=before_json["schema"],
                vector_id=before_json["vector_id"],
                owner_pubkey=before_json["owner_pubkey"],
                space_id=before_json["space_id"],
                vector_type=VectorType(before_json["vector_type"]),
                status=VectorStatus(before_json["status"]),
                components=list(before_json["components"]),
                type_metadata=dict(before_json.get("type_metadata", {})),
                certification=CertificationState(**before_json["certification"]),
                projection=ProjectionState(**before_json["projection"]) if before_json.get("projection") else None,
                origin=OriginState(**before_json["origin"]) if before_json.get("origin") else None,
                version=before_json["version"],
                created_at_ms=before_json["created_at_ms"],
                updated_at_ms=before_json["updated_at_ms"],
            )
        self._record(before, after, operation, parameters)
