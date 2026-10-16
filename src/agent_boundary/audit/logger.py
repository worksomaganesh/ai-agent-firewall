"""Append-only hash-chained JSONL audit logger."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_boundary.audit.events import (
    GENESIS_PREV_HASH,
    AuditEventType,
    AuditRecord,
    EnforcementMode,
    compute_event_hash,
    compute_hmac_signature,
)


class AuditLogger:
    """Writes tamper-evident, hash-chained JSONL audit events."""

    def __init__(
        self,
        log_path: Path,
        session_id: str,
        enforcement_mode: EnforcementMode = EnforcementMode.SIMULATION,
        hmac_key: str | None = None,
    ) -> None:
        self.log_path = log_path
        self.session_id = session_id
        self.enforcement_mode = enforcement_mode
        self.hmac_key = (
            hmac_key if hmac_key is not None else os.environ.get("AGENT_BOUNDARY_AUDIT_KEY")
        )
        self._seq = 0
        self._last_hash = GENESIS_PREV_HASH
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        # A new logger starts a new chain. Never append seq=0 to an existing chain.
        # Exclusive creation also closes the check/create race for duplicate sessions.
        with self.log_path.open("x", encoding="utf-8"):
            pass

    @property
    def head_hash(self) -> str:
        """Return the latest `event_hash` written to the chain."""
        return self._last_hash

    @property
    def event_count(self) -> int:
        """Return the total number of events recorded so far."""
        return self._seq

    def log_event(self, event_type: AuditEventType, payload: dict[str, Any]) -> AuditRecord:
        """Append a single event to the JSONL audit log and advance the hash chain."""
        timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        event_hash = compute_event_hash(
            seq=self._seq,
            timestamp_utc=timestamp_utc,
            session_id=self.session_id,
            enforcement_mode=self.enforcement_mode.value,
            event_type=event_type.value,
            payload=payload,
            prev_hash=self._last_hash,
        )
        hmac_sig = (
            compute_hmac_signature(self.hmac_key, event_hash)
            if self.hmac_key
            else None
        )
        record = AuditRecord(
            seq=self._seq,
            timestamp_utc=timestamp_utc,
            session_id=self.session_id,
            enforcement_mode=self.enforcement_mode,
            event_type=event_type,
            payload=payload,
            prev_hash=self._last_hash,
            event_hash=event_hash,
            hmac_sig=hmac_sig,
        )
        line = record.model_dump_json() + "\n"
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()

        self._last_hash = event_hash
        self._seq += 1
        return record
