"""Unit tests for one-use host-terminal approval grants."""

from __future__ import annotations

import json
from pathlib import Path

from agent_boundary.audit.events import AuditEventType, EnforcementMode
from agent_boundary.audit.logger import AuditLogger
from agent_boundary.audit.verifier import verify_audit_log
from agent_boundary.sandbox.approval import ApprovalBroker


def make_logger(tmp_path: Path) -> tuple[AuditLogger, Path]:
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path, "approval-test", EnforcementMode.OS_ENFORCED_BWRAP)
    return logger, path


def test_approval_is_exact_scope_and_one_use(tmp_path: Path) -> None:
    logger, path = make_logger(tmp_path)
    broker = ApprovalBroker(
        logger,
        ttl_seconds=10,
        tty_reader=lambda _prompt, _timeout: "APPROVE pypi.org:443",
    )
    grant = broker.request_network("pypi.org", 443, "pypi-rule", "Package download")
    assert grant is not None
    assert broker.consume(grant, "network.connect", "pypi.org:443", "pypi-rule")
    assert not broker.consume(grant, "network.connect", "pypi.org:443", "pypi-rule")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    event_types = [row["event_type"] for row in rows]
    assert AuditEventType.APPROVAL_GRANTED.value in event_types
    assert AuditEventType.APPROVAL_CONSUMED.value in event_types
    assert verify_audit_log(path).valid


def test_wrong_response_denies_and_creates_no_grant(tmp_path: Path) -> None:
    logger, path = make_logger(tmp_path)
    broker = ApprovalBroker(
        logger,
        tty_reader=lambda _prompt, _timeout: "yes",
    )
    grant = broker.request_network("pypi.org", 443, "pypi-rule", "Package download")
    assert grant is None
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert any(row["event_type"] == AuditEventType.APPROVAL_DENIED.value for row in rows)
    assert verify_audit_log(path).valid


def test_approval_expires_and_cannot_be_consumed(tmp_path: Path) -> None:
    logger, path = make_logger(tmp_path)
    now = [100.0]
    broker = ApprovalBroker(
        logger,
        ttl_seconds=5,
        tty_reader=lambda _prompt, _timeout: "APPROVE pypi.org:443",
        clock=lambda: now[0],
    )
    grant = broker.request_network("pypi.org", 443, "pypi-rule", "Package download")
    assert grant is not None
    now[0] = 106.0
    assert not broker.consume(grant, "network.connect", "pypi.org:443", "pypi-rule")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert any(row["event_type"] == AuditEventType.APPROVAL_EXPIRED.value for row in rows)
    assert verify_audit_log(path).valid


def test_approval_cannot_be_reused_for_another_target_or_rule(tmp_path: Path) -> None:
    logger, _path = make_logger(tmp_path)
    broker = ApprovalBroker(
        logger,
        tty_reader=lambda _prompt, _timeout: "APPROVE pypi.org:443",
    )
    grant = broker.request_network("pypi.org", 443, "pypi-rule", "Package download")
    assert grant is not None
    assert not broker.consume(grant, "network.connect", "evil.example:443", "pypi-rule")
    grant2 = broker.request_network("pypi.org", 443, "pypi-rule", "Package download")
    assert grant2 is not None
    assert not broker.consume(grant2, "network.connect", "pypi.org:443", "other-rule")
