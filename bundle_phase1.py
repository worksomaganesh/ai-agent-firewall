#!/usr/bin/env python3
"""Generate ai-agent-firewall-phase1.zip and optionally extract into engineering-os."""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

BASE_DIR = "builds/ai-agent-firewall"

FILES: dict[str, str] = {
    f"{BASE_DIR}/.gitignore": r'''# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# Virtual environments
.venv/
venv/
ENV/

# Packaging and build artifacts
build/
dist/
*.egg-info/
.eggs/

# Tool caches and test artifacts
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage
htmlcov/
artifacts/
''',
    f"{BASE_DIR}/pyproject.toml": r'''[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "agent-boundary"
version = "0.1.0"
description = "Linux-first local security supervisor and policy firewall for AI coding agents"
readme = "README.md"
requires-python = ">=3.11"
license = { text = "MIT" }
authors = [
    { name = "Doddi Yashwanth Soma Ganesh" }
]
dependencies = [
    "pydantic>=2.7.0,<3.0.0",
    "PyYAML>=6.0.1,<7.0.0",
    "typer>=0.12.0,<1.0.0",
    "rich>=13.7.0,<14.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.2.0,<9.0.0",
    "pytest-cov>=5.0.0,<6.0.0",
    "mypy>=1.10.0,<2.0.0",
    "ruff>=0.5.0,<1.0.0",
    "types-PyYAML>=6.0.12",
]

[project.scripts]
agent-boundary = "agent_boundary.cli:app"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v --strict-markers"

[tool.mypy]
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_configs = true
mypy_path = "src"

[tool.ruff]
target-version = "py311"
line-length = 100
''',
    f"{BASE_DIR}/src/agent_boundary/__init__.py": r'''"""agent-boundary: External security policy and isolation supervisor for AI coding agents."""

__all__ = ["__version__"]

__version__ = "0.1.0"
''',
    f"{BASE_DIR}/src/agent_boundary/exit_codes.py": r'''"""Deterministic process exit codes for agent-boundary CLI."""

from enum import IntEnum


class ExitCode(IntEnum):
    """Standardized exit codes for scripting and CI assertions."""

    OK = 0
    CONFIG_OR_POLICY_ERROR = 2
    AUDIT_TAMPER_DETECTED = 76
    POLICY_DENIED = 77
    SANDBOX_FAILURE = 78
''',
    f"{BASE_DIR}/src/agent_boundary/policy/__init__.py": r'''"""Policy schema, safe YAML parser, and deterministic evaluation engine."""
''',
    f"{BASE_DIR}/src/agent_boundary/policy/schema.py": r'''"""Strict, versioned policy schemas with fail-closed validation."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Decision(StrEnum):
    """Deterministic policy decisions ordered by security precedence."""

    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    ALLOW = "allow"


class ActionCategory(StrEnum):
    """Supported categories of agent actions."""

    FILESYSTEM = "filesystem"
    COMMAND = "command"
    NETWORK = "network"


class FileOperation(StrEnum):
    """Supported filesystem operations."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"


class FilesystemRule(BaseModel):
    """A single filesystem access rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, pattern=r"^[a-zA-Z0-9_-]+$")
    operations: list[FileOperation] = Field(min_length=1)
    paths: list[str] = Field(min_length=1)
    reason: str = Field(min_length=1)

    @field_validator("paths")
    @classmethod
    def validate_non_empty_paths(cls, v: list[str]) -> list[str]:
        for pattern in v:
            if not pattern or not pattern.strip():
                raise ValueError("Filesystem path glob cannot be empty or whitespace")
        return v


class CommandRule(BaseModel):
    """A single process/command execution rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, pattern=r"^[a-zA-Z0-9_-]+$")
    executables: list[str] = Field(min_length=1)
    arg_patterns: list[str] = Field(default_factory=list)
    reason: str = Field(min_length=1)


class NetworkRule(BaseModel):
    """A single outbound network access rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, pattern=r"^[a-zA-Z0-9_-]+$")
    hosts: list[str] = Field(min_length=1)
    ports: list[int] = Field(min_length=1)
    reason: str = Field(min_length=1)

    @field_validator("ports")
    @classmethod
    def validate_port_range(cls, v: list[int]) -> list[int]:
        for port in v:
            if port < 1 or port > 65535:
                raise ValueError(f"Port {port} out of valid range 1..65535")
        return v


class FilesystemPolicySection(BaseModel):
    """Filesystem rules grouped by decision tier."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    deny: list[FilesystemRule] = Field(default_factory=list)
    require_approval: list[FilesystemRule] = Field(default_factory=list)
    allow: list[FilesystemRule] = Field(default_factory=list)


class CommandPolicySection(BaseModel):
    """Command rules grouped by decision tier."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    deny: list[CommandRule] = Field(default_factory=list)
    require_approval: list[CommandRule] = Field(default_factory=list)
    allow: list[CommandRule] = Field(default_factory=list)


class NetworkPolicySection(BaseModel):
    """Network rules grouped by decision tier."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    deny: list[NetworkRule] = Field(default_factory=list)
    require_approval: list[NetworkRule] = Field(default_factory=list)
    allow: list[NetworkRule] = Field(default_factory=list)


class PolicyDocument(BaseModel):
    """Top-level versioned policy specification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    policy_id: str = Field(min_length=1, pattern=r"^[a-zA-Z0-9_-]+$")
    description: str = Field(min_length=1)
    workspace_root: str = Field(default="/workspace", min_length=1)
    default_decision: Literal[Decision.DENY] = Decision.DENY
    filesystem: FilesystemPolicySection = Field(default_factory=FilesystemPolicySection)
    commands: CommandPolicySection = Field(default_factory=CommandPolicySection)
    network: NetworkPolicySection = Field(default_factory=NetworkPolicySection)

    @field_validator("workspace_root")
    @classmethod
    def validate_absolute_workspace_root(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("workspace_root in policy must be an absolute path starting with '/'")
        return v
''',
    f"{BASE_DIR}/src/agent_boundary/policy/parser.py": r'''"""Fail-closed YAML policy loader that rejects duplicate keys and unknown fields."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from agent_boundary.policy.schema import PolicyDocument


class PolicyValidationError(Exception):
    """Raised when a policy file cannot be parsed or fails strict schema validation."""


class UniqueKeySafeLoader(yaml.SafeLoader):
    """Custom YAML SafeLoader that raises an error on duplicate mapping keys.

    Standard PyYAML silently overwrites duplicate keys, which in a security
    policy could silently replace an earlier `deny:` block with a later one.
    """

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise PolicyValidationError(
                    f"Duplicate YAML key '{key}' detected at line {key_node.start_mark.line + 1}"
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def load_policy_from_text(raw_yaml: str) -> PolicyDocument:
    """Parse and strictly validate a YAML policy string."""
    try:
        data = yaml.load(raw_yaml, Loader=UniqueKeySafeLoader)
    except yaml.YAMLError as exc:
        raise PolicyValidationError(f"Invalid YAML syntax: {exc}") from exc

    if not isinstance(data, dict):
        raise PolicyValidationError("Policy root must be a YAML mapping/object")

    try:
        doc = PolicyDocument.model_validate(data)
    except ValidationError as exc:
        raise PolicyValidationError(f"Policy schema validation failed:\n{exc}") from exc

    _verify_unique_rule_ids(doc)
    return doc


def load_policy(path: Path) -> PolicyDocument:
    """Read, parse, and validate a policy file from disk."""
    if not path.exists() or not path.is_file():
        raise PolicyValidationError(f"Policy file not found: {path}")
    try:
        raw_yaml = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyValidationError(f"Failed to read policy file {path}: {exc}") from exc
    return load_policy_from_text(raw_yaml)


def _verify_unique_rule_ids(doc: PolicyDocument) -> None:
    """Ensure every rule ID across the entire policy document is unique."""
    seen: set[str] = set()
    all_rules = [
        *doc.filesystem.deny,
        *doc.filesystem.require_approval,
        *doc.filesystem.allow,
        *doc.commands.deny,
        *doc.commands.require_approval,
        *doc.commands.allow,
        *doc.network.deny,
        *doc.network.require_approval,
        *doc.network.allow,
    ]
    for rule in all_rules:
        if rule.id in seen:
            raise PolicyValidationError(f"Duplicate rule id '{rule.id}' in policy document")
        seen.add(rule.id)
''',
    f"{BASE_DIR}/src/agent_boundary/policy/engine.py": r'''"""Deterministic policy evaluation engine with path normalization and precedence guarantees."""

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
        self.workspace_root = posixpath.normpath(workspace_override or policy.workspace_root)

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
''',
    f"{BASE_DIR}/src/agent_boundary/audit/__init__.py": r'''"""Tamper-evident JSONL audit logging, verification, and session reporting."""
''',
    f"{BASE_DIR}/src/agent_boundary/audit/events.py": r'''"""Structured audit event schemas and canonical hashing utilities."""

from __future__ import annotations

import hashlib
import hmac
import json
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


GENESIS_PREV_HASH = "0" * 64


class EnforcementMode(StrEnum):
    """Explicitly distinguishes non-enforced simulation from real OS sandboxing."""

    SIMULATION = "simulation"
    OS_ENFORCED_BWRAP = "os_enforced_bwrap"


class AuditEventType(StrEnum):
    """Audit lifecycle event types."""

    SESSION_START = "SESSION_START"
    POLICY_VALIDATED = "POLICY_VALIDATED"
    ACTION_EVALUATED = "ACTION_EVALUATED"
    SESSION_END = "SESSION_END"


class AuditRecord(BaseModel):
    """Single line record in an append-only JSONL audit log."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    seq: int = Field(ge=0)
    timestamp_utc: str
    session_id: str
    enforcement_mode: EnforcementMode
    event_type: AuditEventType
    payload: dict[str, Any]
    prev_hash: str = Field(min_length=64, max_length=64)
    event_hash: str = Field(min_length=64, max_length=64)
    hmac_sig: str | None = None


def canonical_json_bytes(data: dict[str, Any]) -> bytes:
    """Serialize a dictionary into canonical UTF-8 JSON bytes for deterministic hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def compute_event_hash(
    *,
    seq: int,
    timestamp_utc: str,
    session_id: str,
    enforcement_mode: str,
    event_type: str,
    payload: dict[str, Any],
    prev_hash: str,
) -> str:
    """Compute the SHA-256 hex digest over the canonical fields of an audit event."""
    envelope = {
        "enforcement_mode": enforcement_mode,
        "event_type": event_type,
        "payload": payload,
        "prev_hash": prev_hash,
        "seq": seq,
        "session_id": session_id,
        "timestamp_utc": timestamp_utc,
    }
    return hashlib.sha256(canonical_json_bytes(envelope)).hexdigest()


def compute_hmac_signature(secret_key: str, event_hash: str) -> str:
    """Compute an optional HMAC-SHA256 signature over `event_hash`."""
    return hmac.new(
        secret_key.encode("utf-8"),
        event_hash.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
''',
    f"{BASE_DIR}/src/agent_boundary/audit/logger.py": r'''"""Append-only hash-chained JSONL audit logger."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_boundary.audit.events import (
    GENESIS_PREV_HASH,
    AuditEventType,
    AuditRecord,
    EnforcementMode,
    compute_event_hash,
    compute_hmac_signature,
)


class AuditLogger:
    """Writes tamper-evident, hash-chained JSONL audit events."""

    def __init__(
        self,
        log_path: Path,
        session_id: str,
        enforcement_mode: EnforcementMode = EnforcementMode.SIMULATION,
        hmac_key: str | None = None,
    ) -> None:
        self.log_path = log_path
        self.session_id = session_id
        self.enforcement_mode = enforcement_mode
        self.hmac_key = (
            hmac_key if hmac_key is not None else os.environ.get("AGENT_BOUNDARY_AUDIT_KEY")
        )
        self._seq = 0
        self._last_hash = GENESIS_PREV_HASH
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def head_hash(self) -> str:
        """Return the latest `event_hash` written to the chain."""
        return self._last_hash

    @property
    def event_count(self) -> int:
        """Return the total number of events recorded so far."""
        return self._seq

    def log_event(self, event_type: AuditEventType, payload: dict[str, Any]) -> AuditRecord:
        """Append a single event to the JSONL audit log and advance the hash chain."""
        timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        event_hash = compute_event_hash(
            seq=self._seq,
            timestamp_utc=timestamp_utc,
            session_id=self.session_id,
            enforcement_mode=self.enforcement_mode.value,
            event_type=event_type.value,
            payload=payload,
            prev_hash=self._last_hash,
        )
        hmac_sig = (
            compute_hmac_signature(self.hmac_key, event_hash)
            if self.hmac_key
            else None
        )
        record = AuditRecord(
            seq=self._seq,
            timestamp_utc=timestamp_utc,
            session_id=self.session_id,
            enforcement_mode=self.enforcement_mode,
            event_type=event_type,
            payload=payload,
            prev_hash=self._last_hash,
            event_hash=event_hash,
            hmac_sig=hmac_sig,
        )
        line = record.model_dump_json() + "\n"
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()

        self._last_hash = event_hash
        self._seq += 1
        return record
''',
    f"{BASE_DIR}/src/agent_boundary/audit/verifier.py": r'''"""Audit log hash-chain and HMAC integrity verification engine."""

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

    raw_lines = log_path.read_text(encoding="utf-8").splitlines()
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

    for idx, line in enumerate(raw_lines):
        line_no = idx + 1
        try:
            parsed = json.loads(line)
            record = AuditRecord.model_validate(parsed)
        except (json.JSONDecodeError, ValidationError) as exc:
            errors.append(f"Line {line_no}: Malformed audit record: {exc}")
            break

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
        records_checked=len(raw_lines),
        head_hash=last_hash,
        hmac_verified=bool(hmac_checked_all and resolved_key and len(errors) == 0),
        head_hash_anchored=head_anchored and len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )
''',
    f"{BASE_DIR}/src/agent_boundary/audit/report.py": r'''"""Session report generator with explicit enforcement vs. simulation disclosure."""

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
''',
    f"{BASE_DIR}/src/agent_boundary/simulator.py": r'''"""Deterministic local mock-agent simulation runner for Phase 1 testing."""

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
''',
    f"{BASE_DIR}/src/agent_boundary/cli.py": r'''"""Command-line interface for agent-boundary (Phase 1 Core Control Plane)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from agent_boundary import __version__
from agent_boundary.audit.report import generate_session_report
from agent_boundary.audit.verifier import verify_audit_log
from agent_boundary.exit_codes import ExitCode
from agent_boundary.policy.engine import ActionRequest, PolicyEngine
from agent_boundary.policy.parser import PolicyValidationError, load_policy
from agent_boundary.policy.schema import Decision
from agent_boundary.simulator import load_scenario, run_simulation

app = typer.Typer(
    name="agent-boundary",
    help=(
        "Linux-first security supervisor and policy firewall for AI coding agents. "
        "(Phase 1: Policy Validation, Simulation, and Tamper-Evident Audit Core)"
    ),
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"agent-boundary version {__version__}")
        raise typer.Exit(code=int(ExitCode.OK))


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-V",
            help="Show agent-boundary version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """agent-boundary CLI root callback."""


@app.command("validate-policy")
def validate_policy_cmd(
    policy_path: Annotated[Path, typer.Argument(help="Path to YAML policy file.")],
) -> None:
    """Validate a policy file against the strict v1.0 schema (fails closed on unknown fields)."""
    try:
        doc = load_policy(policy_path)
    except PolicyValidationError as exc:
        console.print(f"[bold red]POLICY VALIDATION FAILED:[/bold red] {exc}")
        raise typer.Exit(code=int(ExitCode.CONFIG_OR_POLICY_ERROR)) from exc

    fs_count = (
        len(doc.filesystem.deny)
        + len(doc.filesystem.require_approval)
        + len(doc.filesystem.allow)
    )
    cmd_count = (
        len(doc.commands.deny) + len(doc.commands.require_approval) + len(doc.commands.allow)
    )
    net_count = len(doc.network.deny) + len(doc.network.require_approval) + len(doc.network.allow)

    console.print(
        f"[bold green]VALID POLICY:[/bold green] id='{doc.policy_id}' "
        f"(schema_version={doc.schema_version}, default={doc.default_decision.value}, "
        f"rules: filesystem={fs_count}, commands={cmd_count}, network={net_count})"
    )


@app.command("evaluate")
def evaluate_cmd(
    policy: Annotated[Path, typer.Option("--policy", "-p", help="Path to YAML policy file.")],
    category: Annotated[
        str, typer.Option("--category", "-c", help="Action category: filesystem|command|network.")
    ],
    operation: Annotated[
        str,
        typer.Option(
            "--operation", "-o", help="Operation: read|write|delete|execute|exec|connect."
        ),
    ],
    target: Annotated[
        str, typer.Option("--target", "-t", help="Target path, command, or host:port.")
    ],
    workspace: Annotated[
        str | None, typer.Option("--workspace", "-w", help="Override workspace root path.")
    ] = None,
    symlink_target: Annotated[
        str | None,
        typer.Option("--symlink-target", help="Optional resolved symlink target path."),
    ] = None,
) -> None:
    """Evaluate a single agent action deterministically against a policy (no OS execution)."""
    try:
        doc = load_policy(policy)
    except PolicyValidationError as exc:
        console.print(f"[bold red]POLICY ERROR:[/bold red] {exc}")
        raise typer.Exit(code=int(ExitCode.CONFIG_OR_POLICY_ERROR)) from exc

    engine = PolicyEngine(doc, workspace_override=workspace)
    result = engine.evaluate(
        ActionRequest(
            category=category,
            operation=operation,
            target=target,
            symlink_target=symlink_target,
        )
    )

    console.print(
        f"[bold yellow][POLICY EVALUATION ONLY — NO OS EXECUTION][/bold yellow]\n"
        f"Decision: [bold]{result.decision.value.upper()}[/bold]\n"
        f"Matched Rule: {result.matched_rule_id}\n"
        f"Normalized Target: {result.normalized_target}\n"
        f"Reason: {result.reason}"
    )
    if result.decision is not Decision.ALLOW:
        raise typer.Exit(code=int(ExitCode.POLICY_DENIED))


@app.command("simulate")
def simulate_cmd(
    policy: Annotated[Path, typer.Option("--policy", "-p", help="Path to YAML policy file.")],
    scenario: Annotated[
        Path, typer.Option("--scenario", "-s", help="Path to JSON simulation scenario.")
    ],
    output_dir: Annotated[
        Path, typer.Option("--output-dir", "-d", help="Directory for audit.jsonl and report.")
    ],
) -> None:
    """Run a deterministic mock-agent scenario in clearly labelled Simulation Mode."""
    try:
        doc = load_policy(policy)
    except PolicyValidationError as exc:
        console.print(f"[bold red]POLICY ERROR:[/bold red] {exc}")
        raise typer.Exit(code=int(ExitCode.CONFIG_OR_POLICY_ERROR)) from exc

    try:
        scen = load_scenario(scenario)
    except ValueError as exc:
        console.print(f"[bold red]SCENARIO ERROR:[/bold red] {exc}")
        raise typer.Exit(code=int(ExitCode.CONFIG_OR_POLICY_ERROR)) from exc

    summary = run_simulation(policy=doc, scenario=scen, output_dir=output_dir)

    console.print(
        "[bold yellow]====================================================================[/bold yellow]"
    )
    console.print(
        "[bold yellow][SIMULATION MODE — NO OS ENFORCEMENT][/bold yellow] "
        "Evaluating policy logic & audit chain only."
    )
    console.print(
        "[bold yellow]====================================================================[/bold yellow]"
    )

    table = Table(title=f"Simulation Session: {summary.session_id}")
    table.add_column("Step ID")
    table.add_column("Action")
    table.add_column("Target")
    table.add_column("Normalized Target")
    table.add_column("Decision")
    table.add_column("Rule ID")

    for step, res in summary.results:
        table.add_row(
            step.action_id,
            f"{step.category}:{step.operation}",
            step.target,
            res.normalized_target,
            res.decision.value.upper(),
            res.matched_rule_id,
        )

    console.print(table)
    console.print(f"Audit Log: [bold]{summary.audit_log_path}[/bold]")
    console.print(f"Report:    [bold]{summary.report_path}[/bold]")
    console.print(f"Head Hash: [bold]{summary.head_hash}[/bold]")

    if summary.expectation_mismatches:
        console.print("[bold red]Expectation Mismatches Detected:[/bold red]")
        for mismatch in summary.expectation_mismatches:
            console.print(f"  - {mismatch}")
        raise typer.Exit(code=int(ExitCode.POLICY_DENIED))


@app.command("verify-audit")
def verify_audit_cmd(
    audit_path: Annotated[Path, typer.Argument(help="Path to audit.jsonl file.")],
    expected_head_hash: Annotated[
        str | None,
        typer.Option(
            "--expected-head-hash",
            help="Expected final event_hash to detect truncation/re-chaining.",
        ),
    ] = None,
    require_hmac: Annotated[
        bool,
        typer.Option(
            "--require-hmac", help="Require every record to carry a valid HMAC signature."
        ),
    ] = False,
) -> None:
    """Verify hash-chain continuity and tamper evidence of an audit.jsonl log."""
    res = verify_audit_log(
        log_path=audit_path,
        expected_head_hash=expected_head_hash,
        require_hmac=require_hmac,
    )
    for warning in res.warnings:
        console.print(f"[yellow]WARNING:[/yellow] {warning}")

    if not res.valid:
        console.print(f"[bold red]AUDIT VERIFICATION FAILED ({audit_path}):[/bold red]")
        for err in res.errors:
            console.print(f"  - {err}")
        raise typer.Exit(code=int(ExitCode.AUDIT_TAMPER_DETECTED))

    console.print(
        f"[bold green]AUDIT VERIFIED:[/bold green] {res.records_checked} events intact "
        f"(head_hash={res.head_hash}, hmac_verified={res.hmac_verified}, "
        f"head_anchored={res.head_hash_anchored})"
    )


@app.command("report")
def report_cmd(
    session_dir: Annotated[
        Path, typer.Argument(help="Session directory containing audit.jsonl.")
    ],
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Optional path to write Markdown report.")
    ] = None,
) -> None:
    """Generate a human-readable Markdown report from a session directory."""
    audit_file = session_dir / "audit.jsonl"
    if not audit_file.exists():
        console.print(f"[bold red]ERROR:[/bold red] No audit.jsonl found in {session_dir}")
        raise typer.Exit(code=int(ExitCode.CONFIG_OR_POLICY_ERROR))

    report_md = generate_session_report(session_dir)
    if output is not None:
        output.write_text(report_md, encoding="utf-8")
        console.print(f"Report written to {output}")
    else:
        console.print(report_md)


if __name__ == "__main__":
    app()
''',
    f"{BASE_DIR}/policies/strict-default.yaml": r'''schema_version: "1.0"
policy_id: "strict-local-dev"
description: "Fail-closed default policy for local AI coding agent sessions."
workspace_root: "/workspace"
default_decision: "deny"

filesystem:
  deny:
    - id: "deny-dotenv-secrets"
      operations: ["read", "write", "delete", "execute"]
      paths:
        - "**/.env"
        - "**/.env.*"
        - "**/*.pem"
        - "**/*.key"
      reason: "Protect environment secrets and private keys inside workspace."
    - id: "deny-git-hooks-persistence"
      operations: ["write", "delete", "execute"]
      paths:
        - ".git/hooks/**"
        - ".git/config"
      reason: "Prevent sandbox escape or persistence via host git hooks and config."
  require_approval:
    - id: "approve-ci-workflow-edits"
      operations: ["write", "delete"]
      paths:
        - ".github/workflows/**"
        - "pyproject.toml"
      reason: "Modifying CI workflows or build dependencies requires human approval."
    - id: "approve-workspace-file-delete"
      operations: ["delete"]
      paths:
        - "/workspace/**"
      reason: "Deleting workspace files requires explicit human approval."
  allow:
    - id: "allow-workspace-read-write"
      operations: ["read", "write"]
      paths:
        - "/workspace/**"
      reason: "Permit reading and editing regular source files inside the workspace."

commands:
  deny:
    - id: "deny-privilege-escalation-and-raw-net"
      executables: ["sudo", "su", "pkexec", "nc", "ncat", "socat", "mount", "umount"]
      reason: "Privilege escalation and raw socket utilities are strictly prohibited."
    - id: "deny-destructive-git-push-force"
      executables: ["git"]
      arg_patterns: ["*push*--force*", "*push*-f*"]
      reason: "Force-pushing git history is prohibited."
  require_approval:
    - id: "approve-git-push-and-reset"
      executables: ["git"]
      arg_patterns: ["push*", "reset*--hard*"]
      reason: "Pushing commits or hard-resetting the repository requires human approval."
    - id: "approve-package-installs"
      executables: ["pip", "pip3", "uv", "npm", "pnpm"]
      arg_patterns: ["install*", "add*"]
      reason: "Installing external packages requires human approval."
  allow:
    - id: "allow-safe-dev-test-tools"
      executables: ["pytest", "ruff", "mypy", "git"]
      arg_patterns: ["status*", "diff*", "log*", "-v*", "--version*"]
      reason: "Permit standard read-only git inspection and local test runners."

network:
  deny:
    - id: "deny-metadata-and-localhost"
      hosts: ["169.254.169.254", "localhost", "127.*"]
      ports: [80, 443, 8080, 22, 5432, 6379]
      reason: "Block cloud metadata service and host loopback services."
  require_approval:
    - id: "approve-package-registries"
      hosts: ["pypi.org", "files.pythonhosted.org"]
      ports: [443]
      reason: "Connecting to package registries requires human approval."
  allow:
    - id: "allow-llm-inference-apis"
      hosts: ["api.anthropic.com", "generativelanguage.googleapis.com"]
      ports: [443]
      reason: "Allow outbound HTTPS to configured LLM API endpoints."
''',
    f"{BASE_DIR}/scenarios/mock-agent-attack-suite.json": r'''{
  "scenario_id": "phase1-attack-and-normal-suite",
  "description": "Deterministic mock-agent scenario testing normal actions, prompt-injected secret reads, path traversal, symlink escape, and unauthorized network calls.",
  "workspace_root": "/workspace",
  "steps": [
    {
      "action_id": "step-1-normal-read",
      "description": "Agent reads an allowed Python source file inside the workspace.",
      "category": "filesystem",
      "operation": "read",
      "target": "/workspace/src/app.py",
      "expected_decision": "allow"
    },
    {
      "action_id": "step-2-dotenv-secret-read",
      "description": "Prompt-injected agent attempts to read root .env file (matches both allow /workspace/** and deny **/.env).",
      "category": "filesystem",
      "operation": "read",
      "target": "/workspace/.env",
      "expected_decision": "deny"
    },
    {
      "action_id": "step-3-nested-dotenv-read",
      "description": "Agent attempts to read nested config/.env.production file.",
      "category": "filesystem",
      "operation": "read",
      "target": "config/.env.production",
      "expected_decision": "deny"
    },
    {
      "action_id": "step-4-path-traversal-ssh",
      "description": "Agent attempts relative path traversal outside workspace to read host SSH private key.",
      "category": "filesystem",
      "operation": "read",
      "target": "/workspace/src/../../home/user/.ssh/id_ed25519",
      "expected_decision": "deny"
    },
    {
      "action_id": "step-5-symlink-escape",
      "description": "Agent reads an in-workspace symlink that points outside the workspace to /etc/shadow.",
      "category": "filesystem",
      "operation": "read",
      "target": "/workspace/docs/innocent_link.md",
      "symlink_target": "/etc/shadow",
      "expected_decision": "deny"
    },
    {
      "action_id": "step-6-git-hook-persistence",
      "description": "Agent attempts to write a malicious pre-commit hook inside .git/hooks/pre-commit.",
      "category": "filesystem",
      "operation": "write",
      "target": "/workspace/.git/hooks/pre-commit",
      "expected_decision": "deny"
    },
    {
      "action_id": "step-7-ci-workflow-modification",
      "description": "Agent attempts to modify a GitHub Actions workflow (should require human approval).",
      "category": "filesystem",
      "operation": "write",
      "target": "/workspace/.github/workflows/ci.yml",
      "expected_decision": "require_approval"
    },
    {
      "action_id": "step-8-unauthorized-exfiltration-host",
      "description": "Agent attempts to exfiltrate data to an unlisted external host evil.example.com:443.",
      "category": "network",
      "operation": "connect",
      "target": "evil.example.com:443",
      "expected_decision": "deny"
    },
    {
      "action_id": "step-9-allowed-llm-api",
      "description": "Agent connects to allowed Gemini API endpoint on port 443.",
      "category": "network",
      "operation": "connect",
      "target": "generativelanguage.googleapis.com:443",
      "expected_decision": "allow"
    }
  ]
}
''',
    f"{BASE_DIR}/tests/__init__.py": r'''"""Test suite package for agent-boundary."""
''',
    f"{BASE_DIR}/tests/test_phase1_acceptance.py": r'''"""Automated Phase 1 acceptance test suite covering P1-T1 through P1-T6."""

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
''',
}


def build_zip(zip_path: Path, extract_to: Path | None = None) -> None:
    """Write all Phase 1 files into a .zip archive and optionally unpack them."""
    with zipfile.ZipFile(zip_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel_path, content in FILES.items():
            zf.writestr(rel_path, content.lstrip("\n"))

    print(f"[OK] Created zip archive: {zip_path.resolve()} ({len(FILES)} files)")

    if extract_to is not None:
        for rel_path, content in FILES.items():
            dest = extract_to / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content.lstrip("\n"), encoding="utf-8")
        # Ensure README.md exists for setuptools if unpacking into a fresh directory outside engineering-os
        readme_path = extract_to / BASE_DIR / "README.md"
        if not readme_path.exists():
            readme_path.write_text(
                "# AI Agent Firewall (`agent-boundary`)\n\nPhase 1 core control plane.\n",
                encoding="utf-8",
            )
            print(f"[INFO] Created placeholder {readme_path} (no existing README.md found)")
        else:
            print(f"[SAFE] Preserved existing {readme_path} untouched")
        print(f"[OK] Extracted {len(FILES)} Phase 1 files into: {(extract_to / BASE_DIR).resolve()}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build ai-agent-firewall-phase1.zip and optionally extract into engineering-os."
    )
    parser.add_argument(
        "--zip-out",
        type=Path,
        default=Path("ai-agent-firewall-phase1.zip"),
        help="Output path for the generated .zip file.",
    )
    parser.add_argument(
        "--extract-root",
        type=Path,
        default=None,
        help="Optional root of your engineering-os repository to unpack files directly.",
    )
    args = parser.parse_args()
    build_zip(args.zip_out, args.extract_root)


if __name__ == "__main__":
    main()
