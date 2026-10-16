"""Regression tests for Phase 1 audit and workspace-safety edge cases."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_boundary.audit.events import AuditEventType, EnforcementMode
from agent_boundary.audit.logger import AuditLogger
from agent_boundary.audit.verifier import verify_audit_log
from agent_boundary.policy.engine import PolicyEngine
from agent_boundary.policy.parser import load_policy
from agent_boundary.simulator import load_scenario, run_simulation

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "strict-default.yaml"
SCENARIO_PATH = ROOT / "scenarios" / "mock-agent-attack-suite.json"


def test_require_hmac_fails_when_key_is_missing(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(
        log_path=log_path,
        session_id="hmac-regression",
        enforcement_mode=EnforcementMode.SIMULATION,
        hmac_key="test-only-key",
    )
    logger.log_event(AuditEventType.SESSION_START, {"case": "signed"})

    result = verify_audit_log(log_path, require_hmac=True)
    assert result.valid is False
    assert result.hmac_verified is False
    assert any("no key was supplied" in error for error in result.errors)


def test_audit_logger_refuses_to_append_a_new_chain_to_existing_file(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path, "first-session")
    logger.log_event(AuditEventType.SESSION_START, {"case": "first"})
    original = log_path.read_text(encoding="utf-8")

    with pytest.raises(FileExistsError):
        AuditLogger(log_path, "second-session")

    assert log_path.read_text(encoding="utf-8") == original


def test_simulation_never_deletes_existing_audit_evidence(tmp_path: Path) -> None:
    out_dir = tmp_path / "existing-session"
    out_dir.mkdir()
    audit_path = out_dir / "audit.jsonl"
    audit_path.write_text("preserve-this-evidence\n", encoding="utf-8")

    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        run_simulation(
            policy=load_policy(POLICY_PATH),
            scenario=load_scenario(SCENARIO_PATH),
            output_dir=out_dir,
        )

    assert audit_path.read_text(encoding="utf-8") == "preserve-this-evidence\n"


def test_workspace_override_must_be_absolute() -> None:
    policy = load_policy(POLICY_PATH)
    with pytest.raises(ValueError, match="absolute path"):
        PolicyEngine(policy, workspace_override="relative/workspace")


def test_verifier_handles_invalid_utf8_as_failed_verification(tmp_path: Path) -> None:
    audit_path = tmp_path / "invalid-utf8.jsonl"
    audit_path.write_bytes(b"\xff\xfe\x00")
    result = verify_audit_log(audit_path)

    assert result.valid is False
    assert result.records_checked == 0
    assert any("Unable to read audit log" in error for error in result.errors)
