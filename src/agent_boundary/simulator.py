"""Deterministic local mock-agent simulation runner for Phase 1 testing."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agent_boundary.audit.events import AuditEventType, EnforcementMode
from agent_boundary.audit.logger import AuditLogger
from agent_boundary.audit.report import generate_session_report
from agent_boundary.policy.engine import ActionRequest, EvaluationResult, PolicyEngine
from agent_boundary.policy.schema import Decision, PolicyDocument


class SimulatedStep(BaseModel):
    """A single deterministic mock-agent action inside a scenario file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    category: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    target: str
    symlink_target: str | None = None
    expected_decision: Decision | None = None


class SimulationScenario(BaseModel):
    """A deterministic collection of mock-agent steps (no LLM API calls required)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    workspace_root: str = "/workspace"
    steps: list[SimulatedStep] = Field(min_length=1)


@dataclass(frozen=True)
class SimulationRunSummary:
    """Summary returned after running a mock-agent simulation scenario."""

    session_id: str
    session_dir: Path
    audit_log_path: Path
    report_path: Path
    head_hash: str
    total_steps: int
    allow_count: int
    require_approval_count: int
    deny_count: int
    expectation_mismatches: list[str]
    results: list[tuple[SimulatedStep, EvaluationResult]]


def load_scenario(path: Path) -> SimulationScenario:
    """Load and validate a deterministic JSON mock-agent scenario."""
    if not path.exists() or not path.is_file():
        raise ValueError(f"Scenario file not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return SimulationScenario.model_validate(raw)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise ValueError(f"Invalid simulation scenario file {path}: {exc}") from exc


def run_simulation(
    policy: PolicyDocument,
    scenario: SimulationScenario,
    output_dir: Path,
    hmac_key: str | None = None,
) -> SimulationRunSummary:
    """Execute a deterministic policy simulation, writing `audit.jsonl` and `session_report.md`."""
    output_dir.mkdir(parents=True, exist_ok=True)
    session_id = f"ab-sim-{uuid.uuid4().hex[:12]}"
    audit_path = output_dir / "audit.jsonl"
    if audit_path.exists():
        audit_path.unlink()

    logger = AuditLogger(
        log_path=audit_path,
        session_id=session_id,
        enforcement_mode=EnforcementMode.SIMULATION,
        hmac_key=hmac_key,
    )
    engine = PolicyEngine(policy=policy, workspace_override=scenario.workspace_root)

    logger.log_event(
        AuditEventType.SESSION_START,
        {
            "banner": "SIMULATION MODE — NO OS ENFORCEMENT",
            "policy_id": policy.policy_id,
            "scenario_id": scenario.scenario_id,
            "workspace_root": engine.workspace_root,
        },
    )
    logger.log_event(
        AuditEventType.POLICY_VALIDATED,
        {
            "policy_id": policy.policy_id,
            "schema_version": policy.schema_version,
            "default_decision": policy.default_decision.value,
        },
    )

    allow_count = 0
    approval_count = 0
    deny_count = 0
    mismatches: list[str] = []
    step_results: list[tuple[SimulatedStep, EvaluationResult]] = []

    for step in scenario.steps:
        req = ActionRequest(
            action_id=step.action_id,
            actor="mock-agent",
            category=step.category,
            operation=step.operation,
            target=step.target,
            symlink_target=step.symlink_target,
        )
        res = engine.evaluate(req)
        step_results.append((step, res))

        if res.decision is Decision.ALLOW:
            allow_count += 1
        elif res.decision is Decision.REQUIRE_APPROVAL:
            approval_count += 1
        else:
            deny_count += 1

        if step.expected_decision is not None and res.decision is not step.expected_decision:
            mismatches.append(
                f"Step '{step.action_id}': expected {step.expected_decision.value}, "
                f"got {res.decision.value} (rule={res.matched_rule_id})"
            )

        logger.log_event(
            AuditEventType.ACTION_EVALUATED,
            {
                "action_id": step.action_id,
                "actor": req.actor,
                "category": step.category,
                "decision": res.decision.value,
                "description": step.description,
                "enforced_by": "simulation_policy_engine_only",
                "escaped_workspace": res.escaped_workspace,
                "matched_rule_id": res.matched_rule_id,
                "matched_rules": res.matched_rules,
                "normalized_target": res.normalized_target,
                "operation": step.operation,
                "reason": res.reason,
                "symlink_target": step.symlink_target,
                "target": step.target,
            },
        )

    logger.log_event(
        AuditEventType.SESSION_END,
        {
            "allow_count": allow_count,
            "deny_count": deny_count,
            "expectation_mismatches": mismatches,
            "require_approval_count": approval_count,
            "total_steps": len(scenario.steps),
        },
    )

    report_md = generate_session_report(output_dir)
    report_path = output_dir / "session_report.md"
    report_path.write_text(report_md, encoding="utf-8")

    return SimulationRunSummary(
        session_id=session_id,
        session_dir=output_dir,
        audit_log_path=audit_path,
        report_path=report_path,
        head_hash=logger.head_hash,
        total_steps=len(scenario.steps),
        allow_count=allow_count,
        require_approval_count=approval_count,
        deny_count=deny_count,
        expectation_mismatches=mismatches,
        results=step_results,
    )
