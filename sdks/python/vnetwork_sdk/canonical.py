"""Canonical JSON encoder sorting object keys recursively without whitespace."""

import json
from typing import Any


def sort_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: sort_json_value(value[k]) for k in sorted(value.keys())}
    if isinstance(value, list):
        return [sort_json_value(item) for item in value]
    return value


def canonical_json_string(value: Any) -> str:
    return json.dumps(sort_json_value(value), separators=(",", ":"), ensure_ascii=False)


def canonical_json_bytes(value: Any) -> bytes:
    return canonical_json_string(value).encode("utf-8")
