"""Cryptographic and hashing utilities for evidence integrity.

Every evidence item gets a content hash so we can detect tampering or
duplicate ingestion (§8). We also support a chain-of-custody hash that
links each evidence record to its predecessor within an investigation.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_json(obj: Any) -> str:
    """Stable hash of a JSON-serializable object."""
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return sha256_text(canonical)


def chain_hash(prev_hash: str | None, payload: str) -> str:
    """Hash-chain payload with the previous hash to make tampering detectable."""
    return sha256_text(f"{prev_hash or ''}|{payload}")


def redact(s: str, keep: int = 4) -> str:
    """Redact all but the first/last few chars of a secret."""
    if len(s) <= keep * 2:
        return "*" * len(s)
    return s[:keep] + "*" * (len(s) - keep * 2) + s[-keep:]
