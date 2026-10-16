"""Adversarial tests for the reusable mediated-action policy gate."""

from __future__ import annotations

import json
import re
from pathlib import Path

from agent_boundary.audit.events import AuditEventType, EnforcementMode
from agent_boundary.audit.logger import AuditLogger
from agent_boundary.audit.verifier import verify_audit_log
from agent_boundary.policy.engine import ActionRequest
from agent_boundary.policy.parser import load_policy
from agent_boundary.policy.schema import Decision
from agent_boundary.sandbox.approval import ApprovalBroker
from agent_boundary.sandbox.guard import GuardedActionGate

POLICY_PATH = Path(__file__).resolve().parents[1] / "policies" / "strict-default.yaml"


def setup_gate(
    tmp_path: Path,
    response: str | None = None,
) -> tuple[GuardedActionGate, Path]:
    audit_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit_path, "guard-gate-test", EnforcementMode.OS_ENFORCED_BWRAP)
    broker = None
    if response is not None:
        broker = ApprovalBroker(logger, tty_reader=lambda _prompt, _timeout: response)
    return GuardedActionGate(load_policy(POLICY_PATH), logger, broker), audit_path


def approval_response(prompt: str, _timeout: float) -> str | None:
    match = re.search(r"Type exactly '([^']+)'", prompt)
    return f"APPROVE {match.group(1).removeprefix('APPROVE ')}" if match else None


def setup_approving_gate(tmp_path: Path) -> tuple[GuardedActionGate, Path]:
    audit_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit_path, "guard-gate-test", EnforcementMode.OS_ENFORCED_BWRAP)
    broker = ApprovalBroker(logger, tty_reader=approval_response)
    return GuardedActionGate(load_policy(POLICY_PATH), logger, broker), audit_path


def read_audit(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_denied_action_is_never_authorized_and_audited(tmp_path: Path) -> None:
    gate, audit = setup_approving_gate(tmp_path)
    result = gate.authorize(
        ActionRequest(category="command", operation="exec", target="sudo id", action_id="deny-1")
    )
    assert not result.allowed
    assert result.decision is Decision.DENY
    events = read_audit(audit)
    assert any(e["event_type"] == AuditEventType.ACTION_EVALUATED.value for e in events)
    assert events[-1]["payload"]["enforced_decision"] == "deny"
    assert verify_audit_log(audit).valid


def test_approval_required_without_broker_fails_closed(tmp_path: Path) -> None:
    gate, audit = setup_gate(tmp_path)
    result = gate.authorize(
        ActionRequest(category="filesystem", operation="write",
                      target="/workspace/.github/workflows/deploy.yml", action_id="approval-1")
    )
    assert not result.allowed
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert "no host-terminal approval broker" in result.reason
    assert verify_audit_log(audit).valid


def test_approved_filesystem_action_uses_host_broker_and_audits_consumption(tmp_path: Path) -> None:
    gate, audit = setup_approving_gate(tmp_path)
    result = gate.authorize(
        ActionRequest(category="filesystem", operation="write",
                      target="/workspace/.github/workflows/deploy.yml", action_id="approval-2")
    )
    assert result.allowed
    assert result.approval_used
    events = read_audit(audit)
    kinds = [e["event_type"] for e in events]
    assert AuditEventType.APPROVAL_REQUESTED.value in kinds
    assert AuditEventType.APPROVAL_GRANTED.value in kinds
    assert AuditEventType.APPROVAL_CONSUMED.value in kinds
    assert events[-1]["payload"]["enforced_decision"] == "allow"
    assert verify_audit_log(audit).valid


def test_approved_command_is_scoped_to_exact_command_target(tmp_path: Path) -> None:
    gate, audit = setup_approving_gate(tmp_path)
    result = gate.authorize(
        ActionRequest(category="command", operation="exec",
                      target="git push origin main", action_id="command-1")
    )
    assert result.allowed and result.approval_used
    grant = next(e for e in read_audit(audit) if e["event_type"] == AuditEventType.APPROVAL_GRANTED.value)
    assert grant["payload"]["target"] == "git push origin main"
    assert verify_audit_log(audit).valid


def test_action_gate_never_executes_denied_action(tmp_path: Path) -> None:
    gate, _audit = setup_approving_gate(tmp_path)
    called = False

    def operation() -> str:
        nonlocal called
        called = True
        return "ran"

    result = gate.authorize(
        ActionRequest(category="command", operation="exec", target="sudo rm -rf /", action_id="deny-2")
    )
    if result.allowed:
        operation()
    assert not called



def test_target_state_change_while_prompt_is_open_revokes_approval(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit_path, "guard-state-test", EnforcementMode.OS_ENFORCED_BWRAP)
    state = ["inode=10;sha256=before"]
    prompts: list[str] = []

    def reader(prompt: str, _timeout: float) -> str | None:
        prompts.append(prompt)
        match = re.search(r"Type exactly '([^']+)'", prompt)
        state[0] = "inode=11;sha256=attacker-replaced"
        return match.group(1) if match else None

    broker = ApprovalBroker(logger, tty_reader=reader)
    gate = GuardedActionGate(load_policy(POLICY_PATH), logger, broker)
    result = gate.authorize(
        ActionRequest(category="filesystem", operation="write",
                      target="/workspace/.github/workflows/deploy.yml", action_id="state-race-1"),
        target_state_provider=lambda: state[0],
    )
    assert not result.allowed
    assert "target state changed" in result.reason
    assert prompts
    events = read_audit(audit_path)
    assert any(
        event["event_type"] == AuditEventType.APPROVAL_DENIED.value
        for event in events
    )
    assert verify_audit_log(audit_path).valid


def test_perform_never_calls_operation_after_policy_denial(tmp_path: Path) -> None:
    gate, _audit = setup_approving_gate(tmp_path)
    calls: list[str] = []
    result, value = gate.perform(
        ActionRequest(category="command", operation="exec", target="sudo id", action_id="perform-deny"),
        lambda: calls.append("executed") or "unsafe",
    )
    assert not result.allowed
    assert value is None
    assert calls == []


def test_perform_calls_mediated_callback_after_explicit_approval(tmp_path: Path) -> None:
    gate, audit = setup_approving_gate(tmp_path)
    calls: list[str] = []
    result, value = gate.perform(
        ActionRequest(category="filesystem", operation="write",
                      target="/workspace/.github/workflows/deploy.yml", action_id="perform-allow"),
        lambda: calls.append("executed") or "completed",
    )
    assert result.allowed and result.approval_used
    assert value == "completed"
    assert calls == ["executed"]
    assert verify_audit_log(audit).valid
