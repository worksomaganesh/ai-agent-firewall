"""Strict, versioned policy schemas with fail-closed validation."""

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
