"""Deterministic process exit codes for agent-boundary CLI."""

from enum import IntEnum


class ExitCode(IntEnum):
    """Standardized exit codes for scripting and CI assertions."""

    OK = 0
    CONFIG_OR_POLICY_ERROR = 2
    AUDIT_TAMPER_DETECTED = 76
    POLICY_DENIED = 77
    SANDBOX_FAILURE = 78
    SANDBOX_TIMEOUT = 124
