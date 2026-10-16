"""Unit/integration tests for live network policy enforcement."""
from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

from agent_boundary.audit.events import EnforcementMode
from agent_boundary.audit.logger import AuditLogger
from agent_boundary.audit.verifier import verify_audit_log
from agent_boundary.policy.parser import load_policy
from agent_boundary.policy.schema import Decision, NetworkPolicySection, NetworkRule, PolicyDocument
from agent_boundary.sandbox.proxy import PolicyEnforcingProxy

ROOT = Path(__file__).resolve().parents[1]


def policy_allowing_example() -> PolicyDocument:
    return PolicyDocument(
        schema_version="1.0",
        policy_id="proxy-test",
        description="Allow one destination for proxy unit tests",
        workspace_root="/workspace",
        default_decision=Decision.DENY,
        network=NetworkPolicySection(
            allow=[
                NetworkRule(
                    id="allow-example",
                    hosts=["example.com"],
                    ports=[443],
                    reason="Allow example.com only in this test",
                )
            ]
        ),
    )


def request(proxy: PolicyEnforcingProxy, payload: bytes) -> tuple[socket.socket, bytes]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(3)
    client.connect(str(proxy.socket_path))
    client.sendall(payload)
    return client, client.recv(4096)


def test_unmatched_host_denied_before_dns_and_audited(tmp_path: Path) -> None:
    policy = load_policy(ROOT / "policies" / "strict-default.yaml")
    audit = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit, "deny-test", EnforcementMode.OS_ENFORCED_BWRAP)
    proxy = PolicyEnforcingProxy(
        tmp_path / "private" / "proxy.sock",
        policy,
        logger,
        resolver=lambda *_: (_ for _ in ()).throw(AssertionError("Denied host must not resolve")),
    )
    proxy.start()
    try:
        client, response = request(
            proxy,
            b"CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n",
        )
        client.close()
        assert response.startswith(b"HTTP/1.1 403 Forbidden")
    finally:
        proxy.stop()
    records = [json.loads(line) for line in audit.read_text().splitlines()]
    event = next(row for row in records if row["event_type"] == "NETWORK_REQUEST")
    assert event["payload"]["policy_decision"] == "deny"
    assert event["payload"]["enforced_decision"] == "deny"
    assert verify_audit_log(audit).valid


def test_require_approval_fails_closed_without_broker(tmp_path: Path) -> None:
    policy = load_policy(ROOT / "policies" / "strict-default.yaml")
    audit = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit, "approval-test", EnforcementMode.OS_ENFORCED_BWRAP)
    proxy = PolicyEnforcingProxy(tmp_path / "private" / "proxy.sock", policy, logger)
    proxy.start()
    try:
        client, response = request(
            proxy,
            b"CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\n\r\n",
        )
        client.close()
        assert response.startswith(b"HTTP/1.1 403 Forbidden")
    finally:
        proxy.stop()
    event = next(
        json.loads(line) for line in audit.read_text().splitlines()
        if json.loads(line)["event_type"] == "NETWORK_REQUEST"
    )
    assert event["payload"]["policy_decision"] == "require_approval"
    assert event["payload"]["enforced_decision"] == "deny"


def test_allowlisted_public_connect_uses_checked_address(tmp_path: Path) -> None:
    policy = policy_allowing_example()
    audit = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit, "allow-test", EnforcementMode.OS_ENFORCED_BWRAP)
    upstream, peer = socket.socketpair()
    received: list[bytes] = []
    peer_done = threading.Event()

    def peer_worker() -> None:
        try:
            peer.settimeout(3)
            received.append(peer.recv(64))
            peer.sendall(b"mock-upstream-response")
            peer_done.set()
        finally:
            peer.close()

    thread = threading.Thread(target=peer_worker, daemon=True)
    thread.start()
    proxy = PolicyEnforcingProxy(
        tmp_path / "private" / "proxy.sock",
        policy,
        logger,
        resolver=lambda host, port: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", port))
        ],
        connector=lambda _address: upstream,
    )
    proxy.start()
    try:
        client, response = request(
            proxy,
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        )
        assert response.startswith(b"HTTP/1.1 200 Connection Established")
        client.sendall(b"test-payload")
        assert client.recv(64) == b"mock-upstream-response"
        client.close()
        assert peer_done.wait(3)
    finally:
        proxy.stop()
        upstream.close()
        thread.join(timeout=3)
    assert received == [b"test-payload"]
    rows = [json.loads(line) for line in audit.read_text().splitlines()]
    event = next(row for row in rows if row["event_type"] == "NETWORK_REQUEST")
    assert event["payload"]["policy_decision"] == "allow"
    assert event["payload"]["enforced_decision"] == "allow"
    assert verify_audit_log(audit).valid


def test_allowlisted_host_resolving_to_private_ip_is_denied(tmp_path: Path) -> None:
    policy = policy_allowing_example()
    audit = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit, "private-ip-test", EnforcementMode.OS_ENFORCED_BWRAP)
    connector_called = False

    def connector(_address: tuple) -> socket.socket:
        nonlocal connector_called
        connector_called = True
        raise AssertionError("Must not connect to private IP")

    proxy = PolicyEnforcingProxy(
        tmp_path / "private" / "proxy.sock",
        policy,
        logger,
        resolver=lambda _host, port: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port))
        ],
        connector=connector,
    )
    proxy.start()
    try:
        client, response = request(
            proxy,
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        )
        client.close()
        assert response.startswith(b"HTTP/1.1 403 Forbidden")
    finally:
        proxy.stop()
    assert not connector_called
    rows = [json.loads(line) for line in audit.read_text().splitlines()]
    event = next(row for row in rows if row["event_type"] == "NETWORK_REQUEST")
    assert event["payload"]["policy_decision"] == "allow"
    assert event["payload"]["enforced_decision"] == "deny"
    assert verify_audit_log(audit).valid
