"""Deterministic policy evaluation engine with path normalization and precedence guarantees."""

from __future__ import annotations

import fnmatch
import posixpath
import shlex
from dataclasses import dataclass, field

from agent_boundary.policy.schema import (
    ActionCategory,
    CommandRule,
    Decision,
    FileOperation,
    FilesystemRule,
    NetworkRule,
    PolicyDocument,
)


@dataclass(frozen=True)
class ActionRequest:
    """Normalized representation of an action requested by an agent."""

    category: str
    operation: str
    target: str
    symlink_target: str | None = None
    actor: str = "agent"
    action_id: str = "act-0"


@dataclass(frozen=True)
class EvaluationResult:
    """Deterministic output of the policy engine for a single ActionRequest."""

    decision: Decision
    matched_rule_id: str
    reason: str
    normalized_target: str
    matched_rules: list[str] = field(default_factory=list)
    escaped_workspace: bool = False


def normalize_workspace_path(
    raw_target: str,
    workspace_root: str,
    symlink_target: str | None = None,
) -> tuple[str, bool]:
    """Normalize a requested filesystem path and check whether it stays inside workspace_root.

    If `symlink_target` is provided (simulating or inspecting a symlink on disk),
    both the lexical path and the resolved symlink target are checked against
    `workspace_root`.
    """
    norm_ws = posixpath.normpath(workspace_root)
    if not norm_ws.startswith("/"):
        norm_ws = "/" + norm_ws

    candidate = raw_target.strip()
    if not candidate.startswith("/"):
        candidate = posixpath.join(norm_ws, candidate)
    norm_lexical = posixpath.normpath(candidate)

    if symlink_target:
        sym = symlink_target.strip()
        if not sym.startswith("/"):
            sym_base = posixpath.dirname(norm_lexical)
            sym = posixpath.join(sym_base, sym)
        norm_effective = posixpath.normpath(sym)
    else:
        norm_effective = norm_lexical

    inside_lexical = norm_lexical == norm_ws or norm_lexical.startswith(norm_ws + "/")
    inside_effective = norm_effective == norm_ws or norm_effective.startswith(norm_ws + "/")
    escaped = not (inside_lexical and inside_effective)
    return norm_effective, escaped


def _glob_matches_path(norm_path: str, workspace_root: str, pattern: str) -> bool:
    """Match a normalized absolute path against a policy glob pattern.

    Supports both workspace-relative globs (e.g., `**/.env*`, `.git/hooks/**`, `src/**`)
    and absolute globs (`/workspace/**`, `/etc/**`). Handles leading `**/` so that
    `**/.env*` matches both `/workspace/.env` and `/workspace/sub/.env.local`.
    """
    norm_ws = posixpath.normpath(workspace_root)
    rel_path: str | None = None
    if norm_path == norm_ws:
        rel_path = "."
    elif norm_path.startswith(norm_ws + "/"):
        rel_path = norm_path[len(norm_ws) + 1 :]

    candidates = [norm_path]
    if rel_path is not None:
        candidates.append(rel_path)

    patterns_to_try = [pattern]
    if pattern.startswith("**/"):
        patterns_to_try.append(pattern[3:])
    if pattern.startswith("/workspace/") and norm_ws != "/workspace":
        patterns_to_try.append(norm_ws + pattern[len("/workspace") :])

    for cand in candidates:
        for pat in patterns_to_try:
            if fnmatch.fnmatchcase(cand, pat):
                return True
            if pat.endswith("/**") and cand == pat[:-3]:
                return True
    return False


class PolicyEngine:
    """Evaluates ActionRequests against a validated PolicyDocument."""

    def __init__(self, policy: PolicyDocument, workspace_override: str | None = None) -> None:
        self.policy = policy
        selected_root = workspace_override if workspace_override is not None else policy.workspace_root
        if not selected_root.startswith("/"):
            raise ValueError("Workspace root must be an absolute path")
        self.workspace_root = posixpath.normpath(selected_root)

    def evaluate(self, request: ActionRequest) -> EvaluationResult:
        """Evaluate an action request using strict Deny > Require-Approval > Allow > Default-Deny."""
        try:
            category = ActionCategory(request.category)
        except ValueError:
            return EvaluationResult(
                decision=Decision.DENY,
                matched_rule_id="default-deny-unknown-category",
                reason=f"Unknown action category '{request.category}'; fail-closed default deny",
                normalized_target=request.target,
            )

        if category is ActionCategory.FILESYSTEM:
            return self._evaluate_filesystem(request)
        if category is ActionCategory.COMMAND:
            return self._evaluate_command(request)
        if category is ActionCategory.NETWORK:
            return self._evaluate_network(request)

        return EvaluationResult(
            decision=Decision.DENY,
            matched_rule_id="default-deny",
            reason="Unhandled action category; fail-closed default deny",
            normalized_target=request.target,
        )

    def _evaluate_filesystem(self, request: ActionRequest) -> EvaluationResult:
        try:
            op = FileOperation(request.operation)
        except ValueError:
            return EvaluationResult(
                decision=Decision.DENY,
                matched_rule_id="default-deny-unknown-file-op",
                reason=f"Unknown filesystem operation '{request.operation}'; fail-closed default deny",
                normalized_target=request.target,
            )

        norm_target, escaped = normalize_workspace_path(
            request.target, self.workspace_root, request.symlink_target
        )

        deny_matches = self._match_fs_rules(self.policy.filesystem.deny, op, norm_target)
        approval_matches = self._match_fs_rules(
            self.policy.filesystem.require_approval, op, norm_target
        )
        allow_matches = self._match_fs_rules(self.policy.filesystem.allow, op, norm_target)
        all_matched_ids = [r.id for r in (*deny_matches, *approval_matches, *allow_matches)]

        # 1. Explicit DENY rules always take highest precedence
        if deny_matches:
            first = deny_matches[0]
            return EvaluationResult(
                decision=Decision.DENY,
                matched_rule_id=first.id,
                reason=first.reason,
                normalized_target=norm_target,
                matched_rules=all_matched_ids,
                escaped_workspace=escaped,
            )

        # 2. Hard workspace boundary enforcement: any path outside workspace_root is denied
        if escaped:
            return EvaluationResult(
                decision=Decision.DENY,
                matched_rule_id="boundary-workspace-escape",
                reason=(
                    f"Target '{request.target}' resolves to '{norm_target}', "
                    f"outside workspace boundary '{self.workspace_root}'"
                ),
                normalized_target=norm_target,
                matched_rules=all_matched_ids,
                escaped_workspace=True,
            )

        # 3. REQUIRE_APPROVAL overrides ALLOW
        if approval_matches:
            first = approval_matches[0]
            return EvaluationResult(
                decision=Decision.REQUIRE_APPROVAL,
                matched_rule_id=first.id,
                reason=first.reason,
                normalized_target=norm_target,
                matched_rules=all_matched_ids,
                escaped_workspace=False,
            )

        # 4. Explicit ALLOW
        if allow_matches:
            first = allow_matches[0]
            return EvaluationResult(
                decision=Decision.ALLOW,
                matched_rule_id=first.id,
                reason=first.reason,
                normalized_target=norm_target,
                matched_rules=all_matched_ids,
                escaped_workspace=False,
            )

        # 5. Default-Deny fallback
        return EvaluationResult(
            decision=Decision.DENY,
            matched_rule_id="default-deny",
            reason=f"No filesystem rule matched '{norm_target}' for operation '{op.value}'",
            normalized_target=norm_target,
            matched_rules=[],
            escaped_workspace=escaped,
        )

    def _match_fs_rules(
        self,
        rules: list[FilesystemRule],
        op: FileOperation,
        norm_target: str,
    ) -> list[FilesystemRule]:
        matched: list[FilesystemRule] = []
        for rule in rules:
            if op not in rule.operations:
                continue
            if any(_glob_matches_path(norm_target, self.workspace_root, pat) for pat in rule.paths):
                matched.append(rule)
        return matched

    def _evaluate_command(self, request: ActionRequest) -> EvaluationResult:
        if request.operation != "exec":
            return EvaluationResult(
                decision=Decision.DENY,
                matched_rule_id="default-deny-unknown-command-op",
                reason=f"Unknown command operation '{request.operation}'; expected 'exec'",
                normalized_target=request.target,
            )

        raw_cmd = request.target.strip()
        if not raw_cmd:
            return EvaluationResult(
                decision=Decision.DENY,
                matched_rule_id="default-deny-empty-command",
                reason="Empty command string is denied",
                normalized_target="",
            )

        try:
            tokens = shlex.split(raw_cmd)
        except ValueError as exc:
            return EvaluationResult(
                decision=Decision.DENY,
                matched_rule_id="default-deny-malformed-command",
                reason=f"Malformed command quoting ({exc}); fail-closed deny",
                normalized_target=raw_cmd,
            )

        executable = posixpath.basename(tokens[0])
        args_str = " ".join(tokens[1:])
        norm_cmd = " ".join(tokens)

        deny_matches = self._match_cmd_rules(
            self.policy.commands.deny, executable, tokens[0], args_str, norm_cmd
        )
        approval_matches = self._match_cmd_rules(
            self.policy.commands.require_approval, executable, tokens[0], args_str, norm_cmd
        )
        allow_matches = self._match_cmd_rules(
            self.policy.commands.allow, executable, tokens[0], args_str, norm_cmd
        )
        all_matched_ids = [r.id for r in (*deny_matches, *approval_matches, *allow_matches)]

        if deny_matches:
            first = deny_matches[0]
            return EvaluationResult(
                decision=Decision.DENY,
                matched_rule_id=first.id,
                reason=first.reason,
                normalized_target=norm_cmd,
                matched_rules=all_matched_ids,
            )
        if approval_matches:
            first = approval_matches[0]
            return EvaluationResult(
                decision=Decision.REQUIRE_APPROVAL,
                matched_rule_id=first.id,
                reason=first.reason,
                normalized_target=norm_cmd,
                matched_rules=all_matched_ids,
            )
        if allow_matches:
            first = allow_matches[0]
            return EvaluationResult(
                decision=Decision.ALLOW,
                matched_rule_id=first.id,
                reason=first.reason,
                normalized_target=norm_cmd,
                matched_rules=all_matched_ids,
            )

        return EvaluationResult(
            decision=Decision.DENY,
            matched_rule_id="default-deny",
            reason=f"No command rule matched executable '{executable}'",
            normalized_target=norm_cmd,
            matched_rules=[],
        )

    def _match_cmd_rules(
        self,
        rules: list[CommandRule],
        executable_base: str,
        executable_raw: str,
        args_str: str,
        full_cmd: str,
    ) -> list[CommandRule]:
        matched: list[CommandRule] = []
        for rule in rules:
            exec_ok = any(
                fnmatch.fnmatchcase(executable_base, pat)
                or fnmatch.fnmatchcase(executable_raw, pat)
                for pat in rule.executables
            )
            if not exec_ok:
                continue
            if not rule.arg_patterns:
                matched.append(rule)
                continue
            if any(
                fnmatch.fnmatchcase(args_str, pat) or fnmatch.fnmatchcase(full_cmd, pat)
                for pat in rule.arg_patterns
            ):
                matched.append(rule)
        return matched

    def _evaluate_network(self, request: ActionRequest) -> EvaluationResult:
        if request.operation != "connect":
            return EvaluationResult(
                decision=Decision.DENY,
                matched_rule_id="default-deny-unknown-network-op",
                reason=f"Unknown network operation '{request.operation}'; expected 'connect'",
                normalized_target=request.target,
            )

        host, port, parse_err = self._parse_host_port(request.target)
        if parse_err or port is None:
            return EvaluationResult(
                decision=Decision.DENY,
                matched_rule_id="default-deny-malformed-network-target",
                reason=parse_err or "Invalid host:port target",
                normalized_target=request.target,
            )

        norm_target = f"{host}:{port}"
        deny_matches = self._match_net_rules(self.policy.network.deny, host, port)
        approval_matches = self._match_net_rules(self.policy.network.require_approval, host, port)
        allow_matches = self._match_net_rules(self.policy.network.allow, host, port)
        all_matched_ids = [r.id for r in (*deny_matches, *approval_matches, *allow_matches)]

        if deny_matches:
            first = deny_matches[0]
            return EvaluationResult(
                decision=Decision.DENY,
                matched_rule_id=first.id,
                reason=first.reason,
                normalized_target=norm_target,
                matched_rules=all_matched_ids,
            )
        if approval_matches:
            first = approval_matches[0]
            return EvaluationResult(
                decision=Decision.REQUIRE_APPROVAL,
                matched_rule_id=first.id,
                reason=first.reason,
                normalized_target=norm_target,
                matched_rules=all_matched_ids,
            )
        if allow_matches:
            first = allow_matches[0]
            return EvaluationResult(
                decision=Decision.ALLOW,
                matched_rule_id=first.id,
                reason=first.reason,
                normalized_target=norm_target,
                matched_rules=all_matched_ids,
            )

        return EvaluationResult(
            decision=Decision.DENY,
            matched_rule_id="default-deny",
            reason=f"No network rule matched destination '{norm_target}'",
            normalized_target=norm_target,
            matched_rules=[],
        )

    @staticmethod
    def _parse_host_port(target: str) -> tuple[str, int | None, str | None]:
        cleaned = target.strip().lower()
        if ":" not in cleaned:
            return cleaned, None, f"Network target '{target}' must specify 'host:port'"
        host, port_str = cleaned.rsplit(":", 1)
        if not host:
            return "", None, "Network target host cannot be empty"
        try:
            port = int(port_str)
        except ValueError:
            return host, None, f"Invalid port '{port_str}' in network target '{target}'"
        if port < 1 or port > 65535:
            return host, None, f"Port {port} out of valid range 1..65535"
        return host, port, None

    @staticmethod
    def _match_net_rules(rules: list[NetworkRule], host: str, port: int) -> list[NetworkRule]:
        matched: list[NetworkRule] = []
        for rule in rules:
            if port not in rule.ports:
                continue
            if any(fnmatch.fnmatchcase(host, pat.lower()) for pat in rule.hosts):
                matched.append(rule)
        return matched
