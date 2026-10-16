"""Phase 4 adversarial regression tests for proxy parsing and isolation boundaries."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from agent_boundary.audit.events import EnforcementMode
from agent_boundary.audit.logger import AuditLogger
from agent_boundary.audit.verifier import verify_audit_log
from agent_boundary.policy.parser import load_policy
from agent_boundary.sandbox.proxy import PolicyEnforcingProxy, ProxyRequestError

ROOT = Path(__file__).resolve().parents[1]


def make_proxy(tmp_path: Path, **kwargs) -> tuple[PolicyEnforcingProxy, Path]:
    audit = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit, "phase4-proxy-adversarial", EnforcementMode.OS_ENFORCED_BWRAP)
    proxy = PolicyEnforcingProxy(
        tmp_path / "private" / "proxy.sock",
        load_policy(ROOT / "policies" / "strict-default.yaml"),
        logger,
        request_timeout=0.5,
        **kwargs,
    )
    return proxy, audit


@pytest.mark.parametrize(
    "authority",
    [
        "",
        "example.com",
        "example.com:0",
        "example.com:65536",
        "example.com:nope",
        "user:pass@example.com:443",
        "example.com:443/path",
        "example.com:443?query=1",
        "example.com:443#fragment",
        "example..com:443",
        "-bad.example:443",
        "bad-.example:443",
        "a" * 254 + ".com:443",
        "example.com:443:444",
        "example.com\n:443",
        "localhost:443",
    ],
)
def test_adversarial_authorities_fail_closed(authority: str, tmp_path: Path) -> None:
    proxy, _audit = make_proxy(tmp_path)
    with pytest.raises(ProxyRequestError):
        proxy._parse_authority(authority)


@pytest.mark.parametrize(
    "headers",
    [
        "Content-Length: 2\r\nContent-Length: 2\r\n",
        "Content-Length: 2\r\nContent-Length: 3\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n",
        "Content-Length: 2\r\nTransfer-Encoding: chunked\r\n",
        " X-Folded: yes\r\n",
        "Bad Header: value\r\n",
        "X-Test: before\x00after\r\n",
    ],
)
def test_adversarial_http_framing_and_headers_rejected(headers: str, tmp_path: Path) -> None:
    proxy, _audit = make_proxy(tmp_path)
    raw = ("CONNECT example.com:443 HTTP/1.1\r\n" + headers + "\r\n").encode("iso-8859-1")
    with pytest.raises(ProxyRequestError):
        proxy._parse_headers(raw)


def test_connect_with_content_length_is_rejected_before_resolution_or_connect(tmp_path: Path) -> None:
    called = {"resolver": False, "connector": False}

    def resolver(_host: str, _port: int) -> list[tuple]:
        called["resolver"] = True
        raise AssertionError("Malformed CONNECT must not resolve DNS")

    def connector(_address: tuple) -> socket.socket:
        called["connector"] = True
        raise AssertionError("Malformed CONNECT must not open an upstream socket")

    proxy, audit = make_proxy(tmp_path, resolver=resolver, connector=connector)
    proxy.start()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(2)
    try:
        client.connect(str(proxy.socket_path))
        client.sendall(
            b"CONNECT example.com:443 HTTP/1.1\r\n"
            b"Host: example.com:443\r\n"
            b"Content-Length: 1\r\n\r\nX"
        )
        response = client.recv(4096)
    finally:
        client.close()
        proxy.stop()

    assert response.startswith(b"HTTP/1.1 400 Bad Request")
    assert called == {"resolver": False, "connector": False}
    verification = verify_audit_log(audit)
    assert verification.valid, verification.errors


def test_duplicate_host_or_authority_mismatch_never_connects(tmp_path: Path) -> None:
    called = False

    def connector(_address: tuple) -> socket.socket:
        nonlocal called
        called = True
        raise AssertionError("Mismatched authority must not connect")

    proxy, audit = make_proxy(tmp_path, connector=connector)
    proxy.start()
    responses: list[bytes] = []
    try:
        for headers in (
            b"Host: example.com:443\r\nHost: example.com:443\r\n",
            b"Host: evil.example:443\r\n",
        ):
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(2)
            try:
                client.connect(str(proxy.socket_path))
                client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\n" + headers + b"\r\n")
                responses.append(client.recv(4096))
            finally:
                client.close()
    finally:
        proxy.stop()

    assert all(response.startswith(b"HTTP/1.1 400 Bad Request") for response in responses)
    assert called is False
    assert verify_audit_log(audit).valid


def test_proxy_header_limit_rejects_overlong_header_block(tmp_path: Path) -> None:
    proxy, audit = make_proxy(tmp_path, request_timeout=0.5)
    proxy.start()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(2)
    try:
        client.connect(str(proxy.socket_path))
        header = b"X-Pad: " + b"A" * 70000 + b"\r\n\r\n"
        try:
            client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\n" + header)
        except OSError:
            pass
        response = client.recv(4096)
    finally:
        client.close()
        proxy.stop()

    assert response.startswith(b"HTTP/1.1 400 Bad Request")
    assert verify_audit_log(audit).valid


def test_audit_mutation_of_approval_chain_is_detected(tmp_path: Path) -> None:
    import json

    from agent_boundary.audit.events import AuditEventType
    from agent_boundary.sandbox.approval import ApprovalBroker

    audit = tmp_path / "approval-audit.jsonl"
    logger = AuditLogger(audit, "phase4-audit-attack", EnforcementMode.OS_ENFORCED_BWRAP)
    broker = ApprovalBroker(
        logger,
        tty_reader=lambda _prompt, _timeout: "APPROVE pypi.org:443",
    )
    grant = broker.request_network("pypi.org", 443, "pypi-rule", "Adversarial test")
    assert grant is not None
    assert broker.consume(grant, "network.connect", "pypi.org:443", "pypi-rule")
    before = verify_audit_log(audit)
    assert before.valid, before.errors

    rows = audit.read_text(encoding="utf-8").splitlines()
    record = json.loads(rows[1])
    record["payload"]["target"] = "evil.example:443"
    rows[1] = json.dumps(record)
    tampered = tmp_path / "tampered-approval-audit.jsonl"
    tampered.write_text("\n".join(rows) + "\n", encoding="utf-8")
    after = verify_audit_log(tampered)
    assert not after.valid
    assert after.errors
