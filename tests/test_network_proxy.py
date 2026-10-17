"""Unit/integration tests for live network policy enforcement."""
from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

from agent_boundary.audit.events import AuditEventType, EnforcementMode
from agent_boundary.audit.logger import AuditLogger
from agent_boundary.audit.verifier import verify_audit_log
from agent_boundary.policy.parser import load_policy
from agent_boundary.policy.schema import Decision, NetworkPolicySection, NetworkRule, PolicyDocument
from agent_boundary.sandbox.proxy import PolicyEnforcingProxy
from agent_boundary.sandbox.approval import ApprovalBroker

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



def test_required_approval_is_prompted_consumed_and_audited(tmp_path: Path) -> None:
    policy = PolicyDocument(
        schema_version="1.0",
        policy_id="proxy-approval-test",
        description="Require exact human approval for package index",
        workspace_root="/workspace",
        default_decision=Decision.DENY,
        network=NetworkPolicySection(
            require_approval=[
                NetworkRule(
                    id="approve-pypi",
                    hosts=["pypi.org"],
                    ports=[443],
                    reason="Package index access needs explicit approval",
                )
            ]
        ),
    )
    audit = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit, "proxy-approval-test", EnforcementMode.OS_ENFORCED_BWRAP)
    prompts: list[str] = []
    broker = ApprovalBroker(
        logger,
        ttl_seconds=10,
        tty_reader=lambda prompt, _timeout: (
            prompts.append(prompt) or "APPROVE pypi.org:443"
        ),
    )
    connector_called = False

    def connector(_address: tuple) -> socket.socket:
        nonlocal connector_called
        connector_called = True
        raise OSError("expected mocked upstream failure")

    proxy = PolicyEnforcingProxy(
        tmp_path / "private" / "proxy.sock",
        policy,
        logger,
        resolver=lambda _host, port: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", port))
        ],
        connector=connector,
        approval_broker=broker,
    )
    proxy.start()
    try:
        client, response = request(
            proxy,
            b"CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\n\r\n",
        )
        client.close()
    finally:
        proxy.stop()

    assert prompts and "host terminal" in prompts[0]
    assert connector_called
    assert response.startswith(b"HTTP/1.1 502 Bad Gateway")
    rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    types = [row["event_type"] for row in rows]
    assert AuditEventType.APPROVAL_GRANTED.value in types
    assert AuditEventType.APPROVAL_CONSUMED.value in types
    network_event = next(row for row in rows if row["event_type"] == "NETWORK_REQUEST")
    assert network_event["payload"]["policy_decision"] == "require_approval"
    assert network_event["payload"]["enforced_decision"] == "allow"
    assert verify_audit_log(audit).valid


def test_mixed_public_and_private_dns_answers_are_denied(tmp_path: Path) -> None:
    policy = policy_allowing_example()
    audit = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit, "mixed-dns-test", EnforcementMode.OS_ENFORCED_BWRAP)
    connector_called = False

    def connector(_address: tuple) -> socket.socket:
        nonlocal connector_called
        connector_called = True
        raise AssertionError("Must not connect when any DNS answer is private")

    proxy = PolicyEnforcingProxy(
        tmp_path / "private" / "proxy.sock", policy, logger,
        resolver=lambda _host, port: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", port)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.8", port)),
        ],
        connector=connector,
    )
    proxy.start()
    try:
        client, response = request(proxy, b"CONNECT example.com:443 HTTP/1.1\\r\\nHost: example.com:443\\r\\n\\r\\n")
        client.close()
        assert response.startswith(b"HTTP/1.1 403 Forbidden")
    finally:
        proxy.stop()
    assert not connector_called
    records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    event = next(row for row in records if row["event_type"] == "NETWORK_REQUEST")
    assert event["payload"]["enforced_decision"] == "deny"
    assert verify_audit_log(audit).valid


def test_ipv4_mapped_ipv6_loopback_dns_answer_is_denied(tmp_path: Path) -> None:
    policy = policy_allowing_example()
    audit = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit, "mapped-ip-test", EnforcementMode.OS_ENFORCED_BWRAP)
    connector_called = False

    def connector(_address: tuple) -> socket.socket:
        nonlocal connector_called
        connector_called = True
        raise AssertionError("Must not connect to mapped loopback")

    proxy = PolicyEnforcingProxy(
        tmp_path / "private" / "proxy.sock", policy, logger,
        resolver=lambda _host, port: [
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::ffff:127.0.0.1", port, 0, 0))
        ],
        connector=connector,
    )
    proxy.start()
    try:
        client, response = request(proxy, b"CONNECT example.com:443 HTTP/1.1\\r\\nHost: example.com:443\\r\\n\\r\\n")
        client.close()
        assert response.startswith(b"HTTP/1.1 403 Forbidden")
    finally:
        proxy.stop()
    assert not connector_called
    assert verify_audit_log(audit).valid
