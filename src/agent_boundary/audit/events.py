"""Structured audit event schemas and canonical hashing utilities."""

from __future__ import annotations

import hashlib
import hmac
import json
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


GENESIS_PREV_HASH = "0" * 64


class EnforcementMode(StrEnum):
    """Explicitly distinguishes non-enforced simulation from real OS sandboxing."""

    SIMULATION = "simulation"
    OS_ENFORCED_BWRAP = "os_enforced_bwrap"


class AuditEventType(StrEnum):
    """Audit lifecycle event types."""

    SESSION_START = "SESSION_START"
    POLICY_VALIDATED = "POLICY_VALIDATED"
    ACTION_EVALUATED = "ACTION_EVALUATED"
    SANDBOX_INIT_FAILED = "SANDBOX_INIT_FAILED"
    SANDBOX_STARTED = "SANDBOX_STARTED"
    SANDBOX_FINISHED = "SANDBOX_FINISHED"
    SESSION_END = "SESSION_END"


class AuditRecord(BaseModel):
    """Single line record in an append-only JSONL audit log."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    seq: int = Field(ge=0)
    timestamp_utc: str
    session_id: str
    enforcement_mode: EnforcementMode
    event_type: AuditEventType
    payload: dict[str, Any]
    prev_hash: str = Field(min_length=64, max_length=64)
    event_hash: str = Field(min_length=64, max_length=64)
    hmac_sig: str | None = None


def canonical_json_bytes(data: dict[str, Any]) -> bytes:
    """Serialize a dictionary into canonical UTF-8 JSON bytes for deterministic hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def compute_event_hash(
    *,
    seq: int,
    timestamp_utc: str,
    session_id: str,
    enforcement_mode: str,
    event_type: str,
    payload: dict[str, Any],
    prev_hash: str,
) -> str:
    """Compute the SHA-256 hex digest over the canonical fields of an audit event."""
    envelope = {
        "enforcement_mode": enforcement_mode,
        "event_type": event_type,
        "payload": payload,
        "prev_hash": prev_hash,
        "seq": seq,
        "session_id": session_id,
        "timestamp_utc": timestamp_utc,
    }
    return hashlib.sha256(canonical_json_bytes(envelope)).hexdigest()


def compute_hmac_signature(secret_key: str, event_hash: str) -> str:
    """Compute an optional HMAC-SHA256 signature over `event_hash`."""
    return hmac.new(
        secret_key.encode("utf-8"),
        event_hash.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
