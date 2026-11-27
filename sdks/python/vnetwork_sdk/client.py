"""Official Python client for Vector Network HTTP & WebSocket API."""

import hashlib
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .blake3 import blake3_hex
from .canonical import canonical_json_bytes
from .crypto import (
    PROTOCOL_VERSION,
    ClientIdentity,
    KeypairMaterial,
    canonical_program_submit_object,
    canonical_transfer_approval_object,
    canonical_wallet_pop_object,
)
from .ws import subscribe_events_thread

_IMPORT_RE = re.compile(
    r'^\s*import\s+"([^"]+)"(?:\s+(?:blake3|sha256)\s+"([^"]+)")?(?:\s+as\s+[A-Za-z0-9_]+)?\s*;',
    re.MULTILINE,
)


class VectorNetworkError(RuntimeError):
    pass



def _reserve_durable_nonce(
    file_path: Path,
    network_id: str,
    actor_pubkey: str,
    minimum_next_nonce: int,
    restrict_directory: bool,
) -> int:
    file_path = Path(file_path).expanduser()
    directory = file_path.parent
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if restrict_directory:
        os.chmod(directory, 0o700)
    lock_path = Path(str(file_path) + ".lock")
    lock_fd: Optional[int] = None

    for _ in range(400):
        try:
            lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            lock_data = json.dumps({"pid": os.getpid(), "created_at_ms": int(time.time() * 1000)}).encode()
            os.write(lock_fd, lock_data)
            os.fsync(lock_fd)
            break
        except FileExistsError:
            try:
                stat = lock_path.stat()
                if time.time() - stat.st_mtime > 30:
                    owner_pid: Optional[int] = None
                    try:
                        owner = json.loads(lock_path.read_text(encoding="utf-8"))
                        pid = owner.get("pid")
                        if type(pid) is int and pid > 0:
                            owner_pid = pid
                    except (OSError, ValueError, TypeError):
                        pass
                    owner_alive = False
                    if owner_pid is not None:
                        try:
                            os.kill(owner_pid, 0)
                            owner_alive = True
                        except PermissionError:
                            owner_alive = True
                        except ProcessLookupError:
                            owner_alive = False
                    if not owner_alive:
                        try:
                            lock_path.unlink()
                        except FileNotFoundError:
                            pass
                        continue
            except FileNotFoundError:
                continue
            time.sleep(0.025)

    if lock_fd is None:
        raise VectorNetworkError(
            f"Timed out acquiring durable nonce lock {lock_path}; refusing to risk nonce reuse"
        )

    try:
        current = minimum_next_nonce
        try:
            stored = json.loads(file_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            stored = None
        if stored is not None:
            if (
                not isinstance(stored, dict)
                or stored.get("version") != 1
                or stored.get("network_id") != network_id
                or stored.get("actor_pubkey") != actor_pubkey
                or type(stored.get("next_nonce")) is not int
                or stored["next_nonce"] < 1
            ):
                raise VectorNetworkError(f"Invalid or mismatched durable nonce state at {file_path}")
            current = max(current, stored["next_nonce"])

        if type(current) is not int or current < 1 or current >= (2**53 - 1):
            raise VectorNetworkError("Request nonce exhausted safe integer range")
        temp_fd, temp_name = tempfile.mkstemp(prefix=file_path.name + ".tmp-", dir=str(directory))
        try:
            os.fchmod(temp_fd, 0o600)
            with os.fdopen(temp_fd, "w", encoding="utf-8") as temp_file:
                json.dump(
                    {
                        "version": 1,
                        "network_id": network_id,
                        "actor_pubkey": actor_pubkey,
                        "next_nonce": current + 1,
                    },
                    temp_file,
                    separators=(",", ":"),
                )
                temp_file.write("\\n")
                temp_file.flush()
                os.fsync(temp_file.fileno())
            os.replace(temp_name, file_path)
            os.chmod(file_path, 0o600)
        except Exception:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
            raise
        return current
    finally:
        os.close(lock_fd)
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


class VectorNetworkClient:
    def __init__(
        self,
        base_url: str,
        identity: ClientIdentity,
        expected_network_id: Optional[str] = None,
        nonce_store_path: Optional[str] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.identity = identity
        self.expected_network_id = expected_network_id
        self.connected_network_id: Optional[str] = None
        self._nonce = 1
        self._nonce_store_path = Path(nonce_store_path).expanduser() if nonce_store_path else None

    def next_nonce(self) -> int:
        network_id = self._resolved_network_id()
        actor_pubkey = self.identity.participant_key.public_key_hex
        key = hashlib.sha256(f"{network_id}::{actor_pubkey}".encode()).hexdigest()
        use_default_store = self._nonce_store_path is None
        store_path = self._nonce_store_path or (Path.home() / ".vnetwork" / "nonces" / f"{key}.json")
        reserved = _reserve_durable_nonce(
            store_path,
            network_id,
            actor_pubkey,
            self._nonce,
            use_default_store,
        )
        self._nonce = reserved + 1
        return reserved

    def connect(self) -> Dict[str, Any]:
        info = self.get_json("/v1/network/info")
        if info.get("protocol_version") != PROTOCOL_VERSION:
            raise VectorNetworkError(
                f"Protocol mismatch: remote {info.get('protocol_version')} != {PROTOCOL_VERSION}"
            )
        net_id = info.get("network_id")
        if self.expected_network_id and net_id != self.expected_network_id:
            raise VectorNetworkError(
                f"Expected network {self.expected_network_id}, got {net_id}"
            )
        self.connected_network_id = net_id
        return info

    def _resolved_network_id(self) -> str:
        net = self.connected_network_id or self.expected_network_id
        if not net:
            raise VectorNetworkError("Client must call connect() before write operations")
        return net

    def join(
        self,
        scopes: Optional[List[str]] = None,
        scope_authorizations: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        if not self.connected_network_id:
            self.connect()
        req_scopes = scopes or ["NETWORK", "SPACE", "REGION", "WALLET", "TOKEN"]
        challenge = self.post_json("/v1/participants/challenge", {})
        msg = canonical_json_bytes(
            {
                "challenge_id": challenge["challenge_id"],
                "network_id": challenge["network_id"],
                "node_pubkey": self.identity.node_key.public_key_hex,
                "nonce": challenge["nonce"],
                "participant_pubkey": self.identity.participant_key.public_key_hex,
                "requested_scopes": req_scopes,
            }
        )
        participant_sig = self.identity.participant_key.sign(msg)
        node_sig = self.identity.node_key.sign(msg)
        return self.post_json(
            "/v1/participants/join",
            {
                "challenge_id": challenge["challenge_id"],
                "participant_pubkey": self.identity.participant_key.public_key_hex,
                "node_pubkey": self.identity.node_key.public_key_hex,
                "display_name": self.identity.display_name,
                "node_kind": "FULL_NODE",
                "requested_scopes": req_scopes,
                "advertised_addresses": [],
                "participant_signature": participant_sig,
                "node_signature": node_sig,
                "scope_authorizations": scope_authorizations or [],
            },
        )

    def participant_status(self, participant_id: Optional[str] = None) -> Dict[str, Any]:
        pid = participant_id or self.identity.participant_id
        return self.get_json(f"/v1/participants/{pid}/scope")

    def load_modules_for_source(self, source_bytes: str, base_dir: Path) -> Dict[str, str]:
        real_base = Path(base_dir).resolve(strict=True)
        modules: Dict[str, str] = {}
        queue = [source_bytes]
        max_modules = 64
        while queue:
            current = queue.pop()
            for match in _IMPORT_RE.finditer(current):
                imp = match.group(1).strip()
                imp_path = Path(imp)
                if (
                    not imp
                    or "\\" in imp
                    or imp_path.is_absolute()
                    or ".." in imp_path.parts
                ):
                    raise VectorNetworkError(f"Unsafe module import path: {imp}")
                if imp not in modules:
                    if len(modules) >= max_modules:
                        raise VectorNetworkError(
                            f"Imported module count exceeded limit ({max_modules})"
                        )
                    real_target = (real_base / imp_path).resolve(strict=True)
                    if not real_target.is_relative_to(real_base):
                        raise VectorNetworkError(
                            f"Module import path escapes base directory: {imp}"
                        )
                    content = real_target.read_text(encoding="utf-8")
                    modules[imp] = content
                    queue.append(content)
        return modules

    def compile_source(
        self, file_name: str, source_bytes: str, modules: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        return self.post_json(
            "/v1/language/compile",
            {
                "file_name": file_name,
                "source_bytes": source_bytes,
                "modules": modules or {},
            },
        )

    def submit_vx_file(
        self, path: str, execution_params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        p = Path(path).resolve()
        source_bytes = p.read_text(encoding="utf-8")
        modules = self.load_modules_for_source(source_bytes, p.parent)
        return self.submit_program(p.name, source_bytes, modules, execution_params)

    def submit_program(
        self,
        file_name: str,
        source_bytes: str,
        modules: Optional[Dict[str, str]] = None,
        execution_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not self.connected_network_id:
            self.connect()
        network_id = self._resolved_network_id()
        request_id = f"req_{uuid.uuid4().hex}"
        nonce = self.next_nonce()
        resolved_modules = modules or {}
        resolved_params = execution_params or {}
        signing_bytes = canonical_json_bytes(
            canonical_program_submit_object(
                actor_pubkey=self.identity.participant_key.public_key_hex,
                file_name=file_name,
                source_bytes=source_bytes,
                modules=resolved_modules,
                network_id=network_id,
                request_id=request_id,
                nonce=nonce,
                execution_params=resolved_params,
            )
        )
        signature = self.identity.participant_key.sign(signing_bytes)
        return self.post_json(
            "/v1/programs/submit",
            {
                "file_name": file_name,
                "source_bytes": source_bytes,
                "modules": resolved_modules,
                "actor_pubkey": self.identity.participant_key.public_key_hex,
                "network_id": network_id,
                "request_id": request_id,
                "nonce": nonce,
                "signature": signature,
                "execution_params": resolved_params,
            },
        )

    def sign_wallet_pop(
        self,
        wallet_id: str,
        participant_identity: str,
        purpose: str,
        pop_nonce: str,
        authorized_key: KeypairMaterial,
        expires_at_ms: Optional[int] = None,
    ) -> str:
        network_id = self._resolved_network_id()
        msg = canonical_json_bytes(
            canonical_wallet_pop_object(
                network_id=network_id,
                wallet_id=wallet_id,
                participant_identity=participant_identity,
                authorized_pubkey=authorized_key.public_key_hex,
                purpose=purpose,
                nonce=pop_nonce,
                expires_at_ms=expires_at_ms,
            )
        )
        return authorized_key.sign(msg)

    def sign_transfer_approval(
        self,
        token_id: str,
        from_wallet_id: str,
        to_wallet_id: str,
        amount: int,
        cosigner_key: KeypairMaterial,
    ) -> str:
        network_id = self._resolved_network_id()
        msg = canonical_json_bytes(
            canonical_transfer_approval_object(
                network_id=network_id,
                token_id=token_id,
                from_wallet_id=from_wallet_id,
                to_wallet_id=to_wallet_id,
                amount=amount,
            )
        )
        return cosigner_key.sign(msg)

    def update_wallet_receive_policy(
        self,
        wallet_id: str,
        mode: str,
        allowed_senders: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        return self.submit_operation(
            {
                "op": "UpdateWalletReceivePolicy",
                "payload": {
                    "wallet_id": wallet_id,
                    "mode": mode,
                    "allowed_senders": allowed_senders or [],
                },
            }
        )

    def submit_operation(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        if not self.connected_network_id:
            self.connect()
        network_id = self._resolved_network_id()
        request_id = f"req_{uuid.uuid4().hex}"
        nonce = self.next_nonce()
        timestamp_ms = int(time.time() * 1000)
        payload_hash = blake3_hex(canonical_json_bytes(operation))
        signing_bytes = canonical_json_bytes(
            {
                "actor_pubkey": self.identity.participant_key.public_key_hex,
                "network_id": network_id,
                "nonce": nonce,
                "payload_hash": payload_hash,
                "request_id": request_id,
                "timestamp_ms": timestamp_ms,
            }
        )
        signature = self.identity.participant_key.sign(signing_bytes)
        return self.post_json(
            "/v1/transactions",
            {
                "request_id": request_id,
                "network_id": network_id,
                "actor_pubkey": self.identity.participant_key.public_key_hex,
                "nonce": nonce,
                "timestamp_ms": timestamp_ms,
                "signature": signature,
                "operation": operation,
            },
        )

    def get_network_info(self) -> Dict[str, Any]:
        return self.get_json("/v1/network/info")

    def get_network_status(self) -> Dict[str, Any]:
        return self.get_json("/v1/network/status")

    def list_nodes(self) -> Dict[str, Any]:
        return self.get_json("/v1/nodes")

    def get_node_details(self, node_id: str) -> Dict[str, Any]:
        return self.get_json(f"/v1/nodes/{node_id}")

    def get_explorer_network(self) -> Dict[str, Any]:
        return self.get_json("/v1/explorer/network")

    def get_program(self, program_id: str) -> Dict[str, Any]:
        return self.get_json(f"/v1/programs/{program_id}")

    def get_program_status(self, program_id: str) -> Dict[str, Any]:
        return self.get_json(f"/v1/programs/{program_id}/status")

    def get_transaction(self, tx_id: str) -> Dict[str, Any]:
        return self.get_json(f"/v1/transactions/{tx_id}")

    def list_spaces(self) -> Any:
        return self.get_json("/v1/spaces")

    def list_regions(self) -> Any:
        return self.get_json("/v1/regions")

    def list_wallets(self) -> Any:
        return self.get_json("/v1/wallets")

    def get_wallet(self, wallet_id: str) -> Dict[str, Any]:
        return self.get_json(f"/v1/wallets/{wallet_id}")

    def list_tokens(self) -> Any:
        return self.get_json("/v1/tokens")

    def get_token(self, token_id: str) -> Dict[str, Any]:
        return self.get_json(f"/v1/tokens/{token_id}")

    def list_contracts(self) -> Any:
        return self.get_json("/v1/contracts")

    def get_contract(self, contract_id: str) -> Dict[str, Any]:
        return self.get_json(f"/v1/contracts/{contract_id}")

    def list_loans(self) -> Any:
        return self.get_json("/v1/loans")

    def get_loan(self, loan_id: str) -> Dict[str, Any]:
        return self.get_json(f"/v1/loans/{loan_id}")

    def create_contract(
        self,
        name: str,
        region_id: Optional[str],
        rules: Any,
        actions: List[Any],
    ) -> Dict[str, Any]:
        return self.submit_operation(
            {
                "op": "CreateContract",
                "payload": {
                    "name": name,
                    "region_id": region_id,
                    "rules": rules,
                    "actions": actions,
                },
            }
        )

    def execute_contract(
        self,
        contract_id: str,
        action: str,
        args: Any = None,
    ) -> Dict[str, Any]:
        return self.submit_operation(
            {
                "op": "ExecuteContract",
                "payload": {
                    "contract_id": contract_id,
                    "action": action,
                    "args": {} if args is None else args,
                },
            }
        )

    def create_loan(
        self,
        name: str,
        token_id: str,
        lender_wallet_id: str,
        borrower_wallet_id: str,
        principal: int,
        collateral: int,
        interest_bps: int,
        maturity_at_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        return self.submit_operation(
            {
                "op": "CreateLoan",
                "payload": {
                    "name": name,
                    "token_id": token_id,
                    "lender_wallet_id": lender_wallet_id,
                    "borrower_wallet_id": borrower_wallet_id,
                    "principal": principal,
                    "collateral": collateral,
                    "interest_bps": interest_bps,
                    "maturity_at_ms": maturity_at_ms,
                },
            }
        )

    def execute_loan(
        self,
        loan_id: str,
        action: str,
        amount: int,
    ) -> Dict[str, Any]:
        return self.submit_operation(
            {
                "op": "ExecuteLoan",
                "payload": {
                    "loan_id": loan_id,
                    "action": action,
                    "amount": amount,
                },
            }
        )

    def get_ledger_events(self) -> Any:
        return self.get_json("/v1/ledger/events")

    def get_ledger_proofs(self) -> Dict[str, Any]:
        return self.get_json("/v1/ledger/proofs")

    def verify_ledger_replay(self) -> Dict[str, Any]:
        return self.get_json("/v1/ledger/replay")

    def verify_token_supply(self, token_id: str) -> Dict[str, Any]:
        return self.get_json(f"/v1/tokens/{token_id}/supply")

    def get_consensus_status(self) -> Dict[str, Any]:
        return self.get_json("/v1/consensus/status")

    def get_equivocations(self) -> Dict[str, Any]:
        return self.get_json("/v1/consensus/equivocations")

    def verify_reconstruction(self, entity_kind: str, entity_id: str) -> Dict[str, Any]:
        return self.post_json(
            "/v1/reconstruction/verify",
            {"entity_kind": entity_kind, "entity_id": entity_id},
        )

    def subscribe_events(self, on_event: Callable[[Dict[str, Any]], None]) -> Any:
        return subscribe_events_thread(self.base_url, on_event)

    def get_json(self, path: str) -> Any:
        req = urllib.request.Request(f"{self.base_url}{path}", method="GET")
        return self._do_json(req)

    def post_json(self, path: str, payload: Any) -> Any:
        raw = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=raw,
            headers={"content-type": "application/json"},
            method="POST",
        )
        return self._do_json(req)

    def _do_json(self, req: urllib.request.Request) -> Any:
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body_txt = e.read().decode("utf-8", errors="replace")
            try:
                body = json.loads(body_txt)
                msg = body.get("error", body_txt)
            except Exception:
                msg = body_txt
            raise VectorNetworkError(f"HTTP {e.code}: {msg}") from e
