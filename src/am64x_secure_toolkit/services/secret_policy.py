from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

_SECRET_KEY_FRAGMENTS = (
    "private_key",
    "privatekey",
    "encryption_key",
    "enckey",
    "mek_value",
    "smek_value",
    "bmek_value",
    "passphrase",
    "password",
    "seed",
    "secret_value",
)


def _is_secret_field(name: str) -> bool:
    lowered = name.lower().replace("-", "_")
    return any(fragment in lowered for fragment in _SECRET_KEY_FRAGMENTS)


def sanitize_for_record(value: Any) -> Any:
    """Remove secret-bearing fields before session/report persistence.

    Public hashes/fingerprints are intentionally preserved. This sanitizer is field-name
    based so legitimate SHA-256/SHA-512 evidence is not destroyed.
    """
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if _is_secret_field(str(key)):
                out[str(key)] = "<REDACTED>"
            else:
                out[str(key)] = sanitize_for_record(item)
        return out
    if isinstance(value, list):
        return [sanitize_for_record(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_for_record(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return deepcopy(value)


def contains_unredacted_secret_field(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if _is_secret_field(str(key)):
                if not (item is None or item == "" or item is False or item == "<REDACTED>"):
                    return True
            if contains_unredacted_secret_field(item):
                return True
    elif isinstance(value, (list, tuple)):
        return any(contains_unredacted_secret_field(item) for item in value)
    return False
