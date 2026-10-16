"""Session report generator with explicit enforcement vs. simulation disclosure."""

from __future__ import annotations

import json
from pathlib import Path

from agent_boundary.audit.events import AuditEventType, AuditRecord, EnforcementMode
from agent_boundary.audit.verifier import verify_audit_log


def generate_session_report(session_dir: Path) -> str:
    """Build a human-readable Markdown report from a session directory's `audit.jsonl`."""
    audit_path = session_dir / "audit.jsonl"
    verification = verify_audit_log(audit_path)

    records: list[AuditRecord] = []
    if audit_path.exists():
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(AuditRecord.model_validate(json.loads(line)))

    session_id = records[0].session_id if records else "unknown"
    mode = records[0].enforcement_mode if records else EnforcementMode.SIMULATION

    allow_count = 0
    approval_count = 0
    deny_count = 0
    action_rows: list[str] = []

    for rec in records:
        if rec.event_type is AuditEventType.ACTION_EVALUATED:
            p = rec.payload
            decision = str(p.get("decision", "deny"))
            if decision == "allow":
                allow_count += 1
            elif decision == "require_approval":
                approval_count += 1
            else:
                deny_count += 1

            action_rows.append(
                f"| `{rec.seq}` | `{p.get('category')}:{p.get('operation')}` | "
                f"`{p.get('target')}` | `{p.get('normalized_target')}` | "
                f"**{decision.upper()}** | `{p.get('matched_rule_id')}` | "
                f"`{p.get('enforced_by')}` |"
            )

    banner = (
        "> **[SIMULATION MODE — NO OS ENFORCEMENT]**\n"
        "> This session executed in **Phase 1 Policy Simulation Mode**. Policy decisions were "
        "evaluated deterministically and recorded to the hash-chained audit log, but **no Linux "
        "kernel namespace, Bubblewrap mount, Seccomp-BPF filter, or network proxy was active**."
        if mode is EnforcementMode.SIMULATION
        else "> **[OS ENFORCEMENT ACTIVE — BUBBLEWRAP SANDBOX]**"
    )

    integrity_status = "PASSED" if verification.valid else "FAILED (TAMPERED OR CORRUPTED)"
    table_body = "\n".join(action_rows) if action_rows else "| - | - | - | - | - | - | - |"

    report_lines = [
        f"# agent-boundary Session Report (`{session_id}`)",
        "",
        banner,
        "",
        "## 1. Session Summary",
        "",
        f"- **Session ID**: `{session_id}`",
        f"- **Enforcement Mode**: `{mode.value}`",
        f"- **Audit Records Checked**: `{verification.records_checked}`",
        f"- **Audit Chain Integrity**: **{integrity_status}**",
        f"- **Final Audit Head Hash**: `{verification.head_hash}`",
        f"- **Decision Counts**: `{allow_count}` Allowed, `{approval_count}` Require-Approval, `{deny_count}` Denied",
        "",
        "## 2. Evaluated Actions & Decisions",
        "",
        "| Seq | Action | Requested Target | Normalized Target | Decision | Matched Rule | Enforcement Layer |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        table_body,
        "",
        "## 3. Telemetry & Security Limitations Disclosure",
        "",
        "- **Policy Precedence Guarantee**: Explicit `deny` rules always override `require_approval` and `allow` rules. Unmatched targets fail closed (`default-deny`).",
        "- **Simulation vs. OS Isolation**: In `simulation` mode, actions are evaluated against the policy model without spawning an isolated container or masking host files.",
        "- **Audit Hash Chain Boundary**: Each event is linked via `SHA-256(seq | prev_hash | canonical_payload)`. To protect against full-chain recomputation by a host script, supply `AGENT_BOUNDARY_AUDIT_KEY` (HMAC-SHA256) or record the Final Audit Head Hash above in an external receipt.",
        "",
    ]
    return "\n".join(report_lines)
