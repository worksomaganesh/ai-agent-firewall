"""Reusable fail-closed policy gate for mediated command and tool actions.

This gate protects only actions explicitly routed through it. It is not a syscall
monitor and does not intercept arbitrary filesystem operations by an agent process.
Kernel sandbox controls remain the enforcement boundary for raw process activity.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from agent_boundary.audit.events import AuditEventType
from agent_boundary.audit.logger import AuditLogger
from agent_boundary.policy.engine import ActionRequest, EvaluationResult, PolicyEngine
from agent_boundary.policy.schema import Decision, PolicyDocument
from agent_boundary.sandbox.approval import ApprovalBroker


@dataclass(frozen=True)
class GuardResult:
    """Outcome of evaluating and, where required, approving one mediated action."""

    allowed: bool
    decision: Decision
    action: ActionRequest
    normalized_target: str
    rule_id: str
    reason: str
    approval_used: bool = False


class GuardedActionGate:
    """Evaluate tool/command actions with explicit approval and immediate revalidation."""

    def __init__(
        self,
        policy: PolicyDocument,
        audit_logger: AuditLogger,
        approval_broker: ApprovalBroker | None = None,
        workspace_override: str | None = None,
    ) -> None:
        self.engine = PolicyEngine(policy, workspace_override=workspace_override)
        self.audit_logger = audit_logger
        self.approval_broker = approval_broker

    @staticmethod
    def _approval_phrase(request: ActionRequest, target: str, rule_id: str) -> str:
        payload = json.dumps(
            {
                "action_id": request.action_id,
                "category": request.category,
                "operation": request.operation,
                "target": target,
                "rule_id": rule_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.sha256(payload).hexdigest()[:16]
        return f"APPROVE {request.category}.{request.operation} {digest}"

    def _audit(self, request: ActionRequest, result: EvaluationResult, allowed: bool, reason: str) -> None:
        self.audit_logger.log_event(
            AuditEventType.ACTION_EVALUATED,
            {
                "action_id": request.action_id,
                "actor": request.actor,
                "category": request.category,
                "operation": request.operation,
                "target": result.normalized_target,
                "policy_decision": result.decision.value,
                "enforced_decision": "allow" if allowed else "deny",
                "rule_id": result.matched_rule_id,
                "reason": reason[:300],
                "approval_required": result.decision is Decision.REQUIRE_APPROVAL,
            },
        )

    def authorize(self, request: ActionRequest) -> GuardResult:
        """Return an explicit allow/deny result; no action is executed by this method."""
        result = self.engine.evaluate(request)
        if result.decision is Decision.DENY:
            self._audit(request, result, False, result.reason)
            return GuardResult(
                False, result.decision, request, result.normalized_target,
                result.matched_rule_id, result.reason,
            )

        if result.decision is Decision.ALLOW:
            self._audit(request, result, True, result.reason)
            return GuardResult(
                True, result.decision, request, result.normalized_target,
                result.matched_rule_id, result.reason,
            )

        if self.approval_broker is None:
            reason = "Approval required but no host-terminal approval broker is configured"
            self._audit(request, result, False, reason)
            return GuardResult(
                False, result.decision, request, result.normalized_target,
                result.matched_rule_id, reason,
            )

        action_name = f"{request.category}.{request.operation}"
        phrase = self._approval_phrase(request, result.normalized_target, result.matched_rule_id)
        grant = self.approval_broker.request_action(
            action=action_name,
            target=result.normalized_target,
            rule_id=result.matched_rule_id,
            reason=result.reason,
            confirmation_phrase=phrase,
            display_target=result.normalized_target,
        )
        if grant is None:
            reason = "Host operator did not approve the exact action"
            self._audit(request, result, False, reason)
            return GuardResult(
                False, result.decision, request, result.normalized_target,
                result.matched_rule_id, reason,
            )

        # Re-evaluate immediately before the caller performs the mediated action.
        current = self.engine.evaluate(request)
        if (
            current.decision is not Decision.REQUIRE_APPROVAL
            or current.matched_rule_id != result.matched_rule_id
            or current.normalized_target != result.normalized_target
        ):
            self.approval_broker.revoke(grant)
            reason = "Policy decision, rule, or normalized target changed after approval"
            self._audit(request, current, False, reason)
            return GuardResult(
                False, current.decision, request, current.normalized_target,
                current.matched_rule_id, reason,
            )

        consumed = self.approval_broker.consume(
            grant, action_name, current.normalized_target, current.matched_rule_id
        )
        if not consumed:
            reason = "Approval expired, was consumed, or did not match the exact action"
            self._audit(request, current, False, reason)
            return GuardResult(
                False, current.decision, request, current.normalized_target,
                current.matched_rule_id, reason,
            )

        self._audit(request, current, True, "Explicit one-use host approval consumed")
        return GuardResult(
            True, current.decision, request, current.normalized_target,
            current.matched_rule_id, "Explicit one-use host approval consumed",
            approval_used=True,
        )
