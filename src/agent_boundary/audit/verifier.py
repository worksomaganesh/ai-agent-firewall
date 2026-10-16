"""Audit log hash-chain and HMAC integrity verification engine."""

from __future__ import annotations

import hmac
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from agent_boundary.audit.events import (
    GENESIS_PREV_HASH,
    AuditRecord,
    compute_event_hash,
    compute_hmac_signature,
)


@dataclass(frozen=True)
class AuditVerificationResult:
    """Detailed outcome of verifying an `audit.jsonl` file."""

    valid: bool
    records_checked: int
    head_hash: str
    hmac_verified: bool
    head_hash_anchored: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def verify_audit_log(
    log_path: Path,
    expected_head_hash: str | None = None,
    hmac_key: str | None = None,
    require_hmac: bool = False,
) -> AuditVerificationResult:
    """Verify the cryptographic hash chain, sequence continuity, and optional HMAC of a JSONL log."""
    errors: list[str] = []
    warnings: list[str] = []
    resolved_key = hmac_key if hmac_key is not None else os.environ.get("AGENT_BOUNDARY_AUDIT_KEY")

    if not log_path.exists() or not log_path.is_file():
        return AuditVerificationResult(
            valid=False,
            records_checked=0,
            head_hash="",
            hmac_verified=False,
            head_hash_anchored=False,
            errors=[f"Audit log file not found: {log_path}"],
        )

    try:
        raw_lines = log_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        return AuditVerificationResult(
            valid=False,
            records_checked=0,
            head_hash="",
            hmac_verified=False,
            head_hash_anchored=False,
            errors=[f"Unable to read audit log {log_path}: {exc}"],
        )

    if not raw_lines:
        return AuditVerificationResult(
            valid=False,
            records_checked=0,
            head_hash="",
            hmac_verified=False,
            head_hash_anchored=False,
            errors=["Audit log file is empty (0 events)"],
        )

    expected_prev_hash = GENESIS_PREV_HASH
    last_hash = GENESIS_PREV_HASH
    hmac_checked_all = True
    records_checked = 0
    if require_hmac and not resolved_key:
        errors.append(
            "HMAC verification was required, but no key was supplied through "
            "hmac_key or AGENT_BOUNDARY_AUDIT_KEY."
        )
        hmac_checked_all = False

    for idx, line in enumerate(raw_lines):
        line_no = idx + 1
        try:
            parsed = json.loads(line)
            record = AuditRecord.model_validate(parsed)
        except (json.JSONDecodeError, ValidationError) as exc:
            errors.append(f"Line {line_no}: Malformed audit record: {exc}")
            break

        records_checked += 1
        if record.seq != idx:
            errors.append(
                f"Line {line_no}: Sequence number mismatch "
                f"(expected seq={idx}, found seq={record.seq})"
            )

        if record.prev_hash != expected_prev_hash:
            errors.append(
                f"Line {line_no} (seq={record.seq}): Broken prev_hash link "
                f"(expected {expected_prev_hash[:12]}..., found {record.prev_hash[:12]}...)"
            )

        recomputed_hash = compute_event_hash(
            seq=record.seq,
            timestamp_utc=record.timestamp_utc,
            session_id=record.session_id,
            enforcement_mode=record.enforcement_mode.value,
            event_type=record.event_type.value,
            payload=record.payload,
            prev_hash=record.prev_hash,
        )
        if recomputed_hash != record.event_hash:
            errors.append(
                f"Line {line_no} (seq={record.seq}): Event payload or metadata tampered "
                f"(recomputed hash {recomputed_hash[:12]}... != stored {record.event_hash[:12]}...)"
            )

        if require_hmac and not record.hmac_sig:
            errors.append(f"Line {line_no} (seq={record.seq}): Missing required HMAC signature")
            hmac_checked_all = False
        elif record.hmac_sig:
            if not resolved_key:
                hmac_checked_all = False
                if not require_hmac:
                    warnings.append(
                        f"Line {line_no} (seq={record.seq}): Record has hmac_sig, but no "
                        "AGENT_BOUNDARY_AUDIT_KEY was supplied to verify it."
                    )
            else:
                expected_sig = compute_hmac_signature(resolved_key, record.event_hash)
                if not hmac.compare_digest(expected_sig, record.hmac_sig):
                    errors.append(
                        f"Line {line_no} (seq={record.seq}): Invalid HMAC signature"
                    )
        else:
            hmac_checked_all = False

        expected_prev_hash = record.event_hash
        last_hash = record.event_hash

    head_anchored = False
    if expected_head_hash:
        if last_hash != expected_head_hash.strip().lower():
            errors.append(
                f"Head hash mismatch: log ends with {last_hash[:12]}..., "
                f"expected {expected_head_hash[:12]}... (possible tail truncation or re-chaining)"
            )
        else:
            head_anchored = True

    if not head_anchored and not (hmac_checked_all and resolved_key):
        warnings.append(
            "LIMITATION DISCLOSURE: Unkeyed SHA-256 hash chain verified without an external "
            "--expected-head-hash or HMAC key. While single-line edits or middle deletions break "
            "the chain, a host process with write access to the log file could recompute the entire "
            "chain from seq=0 unless anchored by --expected-head-hash or AGENT_BOUNDARY_AUDIT_KEY."
        )

    return AuditVerificationResult(
        valid=len(errors) == 0,
        records_checked=records_checked,
        head_hash=last_hash,
        hmac_verified=bool(hmac_checked_all and resolved_key and len(errors) == 0),
        head_hash_anchored=head_anchored and len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )
