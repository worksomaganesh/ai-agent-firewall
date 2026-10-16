"""Tests for the concrete policy-gated staged-workspace file adapter."""

from __future__ import annotations

import json
import re
from pathlib import Path

from agent_boundary.audit.events import AuditEventType, EnforcementMode
from agent_boundary.audit.logger import AuditLogger
from agent_boundary.audit.verifier import verify_audit_log
from agent_boundary.policy.parser import load_policy
from agent_boundary.sandbox.approval import ApprovalBroker
from agent_boundary.sandbox.guard import GuardedActionGate
from agent_boundary.sandbox.workspace_tools import GuardedWorkspaceTools

POLICY_PATH = Path(__file__).resolve().parents[1] / "policies" / "strict-default.yaml"


def make_tools(
    tmp_path: Path,
    *,
    approve: bool = False,
    reader_override=None,
) -> tuple[GuardedWorkspaceTools, Path]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    audit_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit_path, "workspace-tools-test", EnforcementMode.OS_ENFORCED_BWRAP)
    broker = None
    if approve:
        def reader(prompt: str, _timeout: float) -> str | None:
            match = re.search(r"Type exactly '([^']+)'", prompt)
            return match.group(1) if match else None
        broker = ApprovalBroker(logger, tty_reader=reader_override or reader)
    gate = GuardedActionGate(load_policy(POLICY_PATH), logger, broker, workspace_override="/workspace")
    return GuardedWorkspaceTools(workspace, gate), audit_path


def test_guarded_read_and_write_operate_on_workspace_files_only(tmp_path: Path) -> None:
    tools, audit = make_tools(tmp_path)
    (tmp_path / "workspace" / "app.py").write_text("old\n", encoding="utf-8")

    read_result, text = tools.read_text("app.py")
    assert read_result.allowed
    assert text == "old\n"

    write_result = tools.write_text("app.py", "new\n")
    assert write_result.allowed
    assert (tmp_path / "workspace" / "app.py").read_text(encoding="utf-8") == "new\n"
    assert verify_audit_log(audit).valid


def test_guarded_file_tools_deny_secret_reads_and_unsafe_paths(tmp_path: Path) -> None:
    tools, audit = make_tools(tmp_path)
    (tmp_path / "workspace" / ".env").write_text("TOKEN=do-not-read\n", encoding="utf-8")

    result, value = tools.read_text(".env")
    assert not result.allowed
    assert value is None

    try:
        tools.read_text("../outside.txt")
    except ValueError as exc:
        assert "safe relative paths" in str(exc)
    else:
        raise AssertionError("Path traversal must be rejected before policy evaluation")
    assert verify_audit_log(audit).valid


def test_delete_requires_host_approval_and_preserves_audit(tmp_path: Path) -> None:
    tools, audit = make_tools(tmp_path, approve=True)
    target = tmp_path / "workspace" / "notes.txt"
    target.write_text("remove only after approval\n", encoding="utf-8")

    result = tools.delete_file("notes.txt")
    assert result.allowed and result.approval_used
    assert not target.exists()
    events = [json.loads(line)["event_type"] for line in audit.read_text(encoding="utf-8").splitlines()]
    assert AuditEventType.APPROVAL_GRANTED.value in events
    assert AuditEventType.APPROVAL_CONSUMED.value in events
    assert verify_audit_log(audit).valid


def test_workspace_tool_revokes_approval_if_file_changes_during_prompt(tmp_path: Path) -> None:
    target_holder: list[Path] = []

    def malicious_timing_reader(prompt: str, _timeout: float) -> str | None:
        match = re.search(r"Type exactly '([^']+)'", prompt)
        target_holder[0].write_text("replacement during approval\n", encoding="utf-8")
        return match.group(1) if match else None

    tools, audit = make_tools(tmp_path, approve=True, reader_override=malicious_timing_reader)
    target = tmp_path / "workspace" / "notes.txt"
    target.write_text("original content\n", encoding="utf-8")
    target_holder.append(target)

    result = tools.delete_file("notes.txt")
    assert not result.allowed
    assert "target state changed" in result.reason
    assert target.read_text(encoding="utf-8") == "replacement during approval\n"
    assert verify_audit_log(audit).valid


def test_workspace_tool_refuses_symlink_targets(tmp_path: Path) -> None:
    tools, _audit = make_tools(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n", encoding="utf-8")
    (tmp_path / "workspace" / "link.txt").symlink_to(outside)

    try:
        tools.read_text("link.txt")
    except ValueError as exc:
        assert "Symlink paths" in str(exc)
    else:
        raise AssertionError("Symlink targets must be refused")
    assert outside.read_text(encoding="utf-8") == "secret\n"
