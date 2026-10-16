"""Host-terminal, action-scoped, one-time approval grants."""

from __future__ import annotations

import os
import select
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Callable

from agent_boundary.audit.events import AuditEventType
from agent_boundary.audit.logger import AuditLogger


@dataclass(frozen=True)
class ApprovalGrant:
    """Opaque in-memory grant bound to one operation, exact target, and policy rule."""

    grant_id: str
    action: str
    target: str
    rule_id: str
    expires_at: float


class ApprovalBroker:
    """Request explicit approval on the host's controlling terminal, never child stdin.

    Grants are memory-only, one-use, target-specific, rule-specific, and expire
    quickly. A missing TTY, timeout, unexpected response, expired grant, or scope
    mismatch is always a denial.
    """

    def __init__(
        self,
        audit_logger: AuditLogger,
        ttl_seconds: float = 30.0,
        tty_reader: Callable[[str, float], str | None] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 1.0 <= ttl_seconds <= 120.0:
            raise ValueError("Approval TTL must be between 1 and 120 seconds")
        self.audit_logger = audit_logger
        self.ttl_seconds = ttl_seconds
        self._tty_reader = tty_reader or self._read_host_tty
        self._clock = clock
        self._prompt_lock = threading.Lock()
        self._grant_lock = threading.Lock()
        self._grants: dict[str, ApprovalGrant] = {}

    @staticmethod
    def _read_host_tty(prompt: str, timeout_seconds: float) -> str | None:
        """Read one line from /dev/tty with a hard timeout, independent of agent stdin."""
        fd: int | None = None
        try:
            fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
            os.write(fd, prompt.encode("utf-8", errors="replace"))
            ready, _, _ = select.select([fd], [], [], timeout_seconds)
            if not ready:
                return None
            data = os.read(fd, 512)
            if not data:
                return None
            return data.decode("utf-8", errors="replace").splitlines()[0].strip()
        except (OSError, ValueError, IndexError):
            return None
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

    @staticmethod
    def _format_target(host: str, port: int) -> str:
        return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"

    def request_network(
        self,
        host: str,
        port: int,
        rule_id: str,
        reason: str,
    ) -> ApprovalGrant | None:
        """Prompt for approval of precisely one network.connect action."""
        target = self._format_target(host, port)
        action = "network.connect"
        self.audit_logger.log_event(
            AuditEventType.APPROVAL_REQUESTED,
            {
                "action": action,
                "target": target,
                "rule_id": rule_id,
                "ttl_seconds": self.ttl_seconds,
                "prompt_channel": "host_controlling_terminal",
            },
        )
        prompt = (
            "\n[agent-boundary approval required]\n"
            f"Action: {action}\nDestination: {target}\nPolicy rule: {rule_id}\n"
            f"Reason: {reason[:240]}\n"
            f"This approves ONE connection to this exact destination for at most {self.ttl_seconds:g}s.\n"
            f"Type exactly 'APPROVE {target}' to allow, or anything else to deny: "
        )
        try:
            with self._prompt_lock:
                response = self._tty_reader(prompt, self.ttl_seconds)
        except (OSError, RuntimeError, ValueError):
            response = None

        if response != f"APPROVE {target}":
            self.audit_logger.log_event(
                AuditEventType.APPROVAL_DENIED,
                {
                    "action": action,
                    "target": target,
                    "rule_id": rule_id,
                    "reason": "No exact approval response from host terminal",
                },
            )
            return None

        grant = ApprovalGrant(
            grant_id=uuid.uuid4().hex,
            action=action,
            target=target,
            rule_id=rule_id,
            expires_at=self._clock() + self.ttl_seconds,
        )
        with self._grant_lock:
            self._grants[grant.grant_id] = grant
        self.audit_logger.log_event(
            AuditEventType.APPROVAL_GRANTED,
            {
                "grant_id": grant.grant_id,
                "action": grant.action,
                "target": grant.target,
                "rule_id": grant.rule_id,
                "expires_in_seconds": self.ttl_seconds,
                "uses": 1,
            },
        )
        return grant

    def consume(self, grant: ApprovalGrant, action: str, target: str, rule_id: str) -> bool:
        """Consume a grant exactly once after policy revalidation and before connecting."""
        with self._grant_lock:
            stored = self._grants.get(grant.grant_id)
            if stored != grant:
                return False
            if self._clock() >= stored.expires_at:
                self._grants.pop(grant.grant_id, None)
                outcome = "expired"
            elif (stored.action, stored.target, stored.rule_id) != (action, target, rule_id):
                self._grants.pop(grant.grant_id, None)
                outcome = "scope_mismatch"
            else:
                self._grants.pop(grant.grant_id, None)
                outcome = "consumed"

        if outcome == "consumed":
            self.audit_logger.log_event(
                AuditEventType.APPROVAL_CONSUMED,
                {
                    "grant_id": grant.grant_id,
                    "action": action,
                    "target": target,
                    "rule_id": rule_id,
                    "uses_remaining": 0,
                },
            )
            return True

        event_type = (
            AuditEventType.APPROVAL_EXPIRED
            if outcome == "expired"
            else AuditEventType.APPROVAL_DENIED
        )
        self.audit_logger.log_event(
            event_type,
            {
                "grant_id": grant.grant_id,
                "action": action,
                "target": target,
                "rule_id": rule_id,
                "reason": "Approval expired" if outcome == "expired" else "Approval scope mismatch",
            },
        )
        return False

    def revoke(self, grant: ApprovalGrant) -> None:
        """Remove an unused grant when policy revalidation fails."""
        with self._grant_lock:
            self._grants.pop(grant.grant_id, None)
