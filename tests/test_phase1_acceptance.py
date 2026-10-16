"""Automated Phase 1 acceptance test suite covering P1-T1 through P1-T6."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_boundary.audit.events import AuditEventType, EnforcementMode
from agent_boundary.audit.logger import AuditLogger
from agent_boundary.audit.verifier import verify_audit_log
from agent_boundary.cli import app
from agent_boundary.exit_codes import ExitCode
from agent_boundary.policy.engine import ActionRequest, PolicyEngine
from agent_boundary.policy.parser import PolicyValidationError, load_policy, load_policy_from_text
from agent_boundary.policy.schema import Decision
from agent_boundary.simulator import load_scenario, run_simulation

runner = CliRunner()

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = REPO_ROOT / "policies" / "strict-default.yaml"
DEFAULT_SCENARIO_PATH = REPO_ROOT / "scenarios" / "mock-agent-attack-suite.json"


def test_cli_version_and_help() -> None:
    """Verify CLI exposes version and help information cleanly."""
    ver_res = runner.invoke(app, ["--version"])
    assert ver_res.exit_code == ExitCode.OK
    assert "agent-boundary version 0.1.0" in ver_res.stdout

    help_res = runner.invoke(app, ["--help"])
    assert help_res.exit_code == ExitCode.OK
    assert "validate-policy" in help_res.stdout
    assert "simulate" in help_res.stdout
    assert "verify-audit" in help_res.stdout


def test_p1_t1_unknown_policy_fields_and_duplicate_keys_fail_closed(tmp_path: Path) -> None:
    """P1-T1: Unknown keys, invalid schema versions, and duplicate YAML keys must fail closed."""
    unknown_field_yaml = """
schema_version: "1.0"
policy_id: "bad-policy"
description: "Contains an unknown field"
allow_all_network: true
"""
    with pytest.raises(PolicyValidationError, match="Extra inputs are not permitted"):
        load_policy_from_text(unknown_field_yaml)

    bad_version_yaml = """
schema_version: "2.0"
policy_id: "bad-version"
description: "Unsupported version"
"""
    with pytest.raises(PolicyValidationError):
        load_policy_from_text(bad_version_yaml)

    duplicate_key_yaml = """
schema_version: "1.0"
policy_id: "dup-key"
policy_id: "overwritten-key"
description: "Duplicate key test"
"""
    with pytest.raises(PolicyValidationError, match="Duplicate YAML key 'policy_id'"):
        load_policy_from_text(duplicate_key_yaml)

    bad_file = tmp_path / "invalid.yaml"
    bad_file.write_text(unknown_field_yaml, encoding="utf-8")
    cli_res = runner.invoke(app, ["validate-policy", str(bad_file)])
    assert cli_res.exit_code == ExitCode.CONFIG_OR_POLICY_ERROR


def test_p1_t2_deny_overrides_allow_and_require_approval() -> None:
    """P1-T2: Explicit DENY rules must override both REQUIRE_APPROVAL and ALLOW rules."""
    policy = load_policy(DEFAULT_POLICY_PATH)
    engine = PolicyEngine(policy)

    for target in ["/workspace/.env", "/workspace/.env.local", "/workspace/nested/.env.prod"]:
        res = engine.evaluate(
            ActionRequest(category="filesystem", operation="read", target=target)
        )
        assert res.decision is Decision.DENY
        assert res.matched_rule_id == "deny-dotenv-secrets"
        assert "allow-workspace-read-write" in res.matched_rules

    del_res = engine.evaluate(
        ActionRequest(category="filesystem", operation="delete", target="/workspace/.env")
    )
    assert del_res.decision is Decision.DENY
    assert del_res.matched_rule_id == "deny-dotenv-secrets"

    wf_res = engine.evaluate(
        ActionRequest(
            category="filesystem",
            operation="write",
            target="/workspace/.github/workflows/release.yml",
        )
    )
    assert wf_res.decision is Decision.REQUIRE_APPROVAL
    assert wf_res.matched_rule_id == "approve-ci-workflow-edits"


def test_p1_t3_default_deny_on_unmatched_and_unknown_actions() -> None:
    """P1-T3: Unmatched targets and unknown categories/operations must fail closed (DENY)."""
    policy = load_policy(DEFAULT_POLICY_PATH)
    engine = PolicyEngine(policy)

    res_cat = engine.evaluate(
        ActionRequest(category="kernel_module", operation="load", target="evil.ko")
    )
    assert res_cat.decision is Decision.DENY
    assert res_cat.matched_rule_id == "default-deny-unknown-category"

    res_op = engine.evaluate(
        ActionRequest(category="filesystem", operation="chmod_suid", target="/workspace/app.py")
    )
    assert res_op.decision is Decision.DENY
    assert res_op.matched_rule_id == "default-deny-unknown-file-op"

    res_net = engine.evaluate(
        ActionRequest(category="network", operation="connect", target="unlisted.example.org:443")
    )
    assert res_net.decision is Decision.DENY
    assert res_net.matched_rule_id == "default-deny"

    res_cmd = engine.evaluate(
        ActionRequest(category="command", operation="exec", target="curl https://example.com")
    )
    assert res_cmd.decision is Decision.DENY
    assert res_cmd.matched_rule_id == "default-deny"


def test_p1_t4_path_traversal_and_symlink_escape_denied() -> None:
    """P1-T4: Dot-segment path traversal and symlinks pointing outside workspace must be denied."""
    policy = load_policy(DEFAULT_POLICY_PATH)
    engine = PolicyEngine(policy)

    traversal_res = engine.evaluate(
        ActionRequest(
            category="filesystem",
            operation="read",
            target="/workspace/src/../../etc/passwd",
        )
    )
    assert traversal_res.decision is Decision.DENY
    assert traversal_res.escaped_workspace is True
    assert traversal_res.normalized_target == "/etc/passwd"
    assert traversal_res.matched_rule_id == "boundary-workspace-escape"

    symlink_res = engine.evaluate(
        ActionRequest(
            category="filesystem",
            operation="read",
            target="/workspace/README_link.md",
            symlink_target="/home/user/.ssh/id_rsa",
        )
    )
    assert symlink_res.decision is Decision.DENY
    assert symlink_res.escaped_workspace is True
    assert symlink_res.normalized_target == "/home/user/.ssh/id_rsa"
    assert symlink_res.matched_rule_id == "boundary-workspace-escape"


def test_p1_t5_audit_log_tamper_detection(tmp_path: Path) -> None:
    """P1-T5: Modifying a payload, deleting a line, or truncating the tail must fail verification."""
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(
        log_path=log_path,
        session_id="ab-sim-test123",
        enforcement_mode=EnforcementMode.SIMULATION,
        hmac_key="super-secret-test-key",
    )
    for i in range(5):
        logger.log_event(AuditEventType.ACTION_EVALUATED, {"step": i, "decision": "allow"})

    head_hash = logger.head_hash

    ok_res = verify_audit_log(
        log_path,
        expected_head_hash=head_hash,
        hmac_key="super-secret-test-key",
        require_hmac=True,
    )
    assert ok_res.valid is True
    assert ok_res.records_checked == 5
    assert ok_res.hmac_verified is True
    assert ok_res.head_hash_anchored is True

    original_lines = log_path.read_text(encoding="utf-8").splitlines()

    mutated_lines = list(original_lines)
    rec2 = json.loads(mutated_lines[2])
    rec2["payload"]["decision"] = "deny"
    mutated_lines[2] = json.dumps(rec2)
    tampered_mutate = tmp_path / "audit_mutated.jsonl"
    tampered_mutate.write_text("\n".join(mutated_lines) + "\n", encoding="utf-8")

    res_mutate = verify_audit_log(tampered_mutate)
    assert res_mutate.valid is False
    assert any("seq=2" in err for err in res_mutate.errors)

    deleted_lines = original_lines[:3] + original_lines[4:]
    tampered_delete = tmp_path / "audit_deleted.jsonl"
    tampered_delete.write_text("\n".join(deleted_lines) + "\n", encoding="utf-8")

    res_delete = verify_audit_log(tampered_delete)
    assert res_delete.valid is False
    assert any("Sequence number mismatch" in err for err in res_delete.errors)

    truncated_lines = original_lines[:4]
    tampered_trunc = tmp_path / "audit_truncated.jsonl"
    tampered_trunc.write_text("\n".join(truncated_lines) + "\n", encoding="utf-8")

    res_trunc = verify_audit_log(tampered_trunc, expected_head_hash=head_hash)
    assert res_trunc.valid is False
    assert any("Head hash mismatch" in err for err in res_trunc.errors)


def test_p1_t6_simulation_mode_honesty_and_report_generation(tmp_path: Path) -> None:
    """P1-T6: Simulation mode must pass all scenario expectations and prominently disclose simulation status."""
    policy = load_policy(DEFAULT_POLICY_PATH)
    scenario = load_scenario(DEFAULT_SCENARIO_PATH)
    out_dir = tmp_path / "sim-session"

    summary = run_simulation(policy=policy, scenario=scenario, output_dir=out_dir)
    assert summary.total_steps == 9
    assert summary.expectation_mismatches == []
    assert summary.allow_count == 2
    assert summary.require_approval_count == 1
    assert summary.deny_count == 6

    report_text = summary.report_path.read_text(encoding="utf-8")
    assert "[SIMULATION MODE — NO OS ENFORCEMENT]" in report_text
    assert "no Linux kernel namespace, Bubblewrap mount, Seccomp-BPF filter" in report_text

    cli_out_dir = tmp_path / "cli-sim-session"
    cli_res = runner.invoke(
        app,
        [
            "simulate",
            "--policy",
            str(DEFAULT_POLICY_PATH),
            "--scenario",
            str(DEFAULT_SCENARIO_PATH),
            "--output-dir",
            str(cli_out_dir),
        ],
    )
    assert cli_res.exit_code == ExitCode.OK
    assert "[SIMULATION MODE — NO OS ENFORCEMENT]" in cli_res.stdout
