"""Host-side fail-closed HTTP/HTTPS policy proxy."""

from __future__ import annotations

import ipaddress
import os
import select
import socket
import socketserver
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from agent_boundary.audit.events import AuditEventType
from agent_boundary.audit.logger import AuditLogger
from agent_boundary.sandbox.approval import ApprovalBroker, ApprovalGrant
from agent_boundary.policy.engine import ActionRequest, PolicyEngine
from agent_boundary.policy.schema import Decision, PolicyDocument

_HEADER_LIMIT = 65536
_MAX_HEADERS = 128
_RELAY_IDLE_SECONDS = 180
_LOCAL_NAMES = {"localhost", "localhost.localdomain", "metadata.google.internal"}
_LOCAL_SUFFIXES = (".localhost", ".local", ".internal")


@dataclass(frozen=True)
class _Access:
    host: str
    port: int
    policy_decision: str
    enforced_decision: str
    matched_rule_id: str
    reason: str
    addresses: tuple[tuple, ...] = ()
    approval_grant: ApprovalGrant | None = None

    @property
    def allowed(self) -> bool:
        return self.enforced_decision == Decision.ALLOW.value


class ProxyRequestError(ValueError):
    """Raised for malformed or ambiguous HTTP proxy requests."""


class PolicyEnforcingProxy:
    """Evaluate each request; host-side DNS and upstream sockets use the checked policy.

    Every resolved address must be globally routable. Private, loopback, link-local,
    reserved, and mixed public/private DNS answers are denied. TLS is passed through
    after an authorized CONNECT and is not decrypted or inspected.
    """

    def __init__(
        self,
        socket_path: Path,
        policy: PolicyDocument,
        audit_logger: AuditLogger,
        request_timeout: float = 15.0,
        resolver: Callable[[str, int], list[tuple]] | None = None,
        connector: Callable[[tuple], socket.socket] | None = None,
        approval_broker: ApprovalBroker | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.engine = PolicyEngine(policy, workspace_override="/workspace")
        self.policy = policy
        self.audit_logger = audit_logger
        self.request_timeout = request_timeout
        self._resolver_override = resolver
        self._connector_override = connector
        self.approval_broker = approval_broker or ApprovalBroker(audit_logger)
        self._ready = threading.Event()
        self._thread: threading.Thread | None = None
        self._server: socketserver.UnixStreamServer | None = None
        self._startup_error: BaseException | None = None
        self._connections: set[socket.socket] = set()
        self._connections_lock = threading.Lock()

    def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.socket_path.parent, 0o700)
        if os.path.lexists(self.socket_path):
            raise OSError(f"Proxy socket path already exists: {self.socket_path}")
        self._thread = threading.Thread(target=self._serve, name="agent-boundary-policy-proxy", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=5):
            self.stop()
            raise TimeoutError("Timed out starting the host policy proxy")
        if self._startup_error is not None:
            raise RuntimeError(f"Could not start policy proxy: {self._startup_error}") from self._startup_error
        if not self.socket_path.exists():
            self.stop()
            raise OSError("Policy proxy did not create its socket")

    def _serve(self) -> None:
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                client: socket.socket = self.request
                with owner._connections_lock:
                    owner._connections.add(client)
                try:
                    owner._handle_client(client)
                finally:
                    with owner._connections_lock:
                        owner._connections.discard(client)

        class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True
            request_queue_size = 64
            allow_reuse_address = False

        server: Server | None = None
        try:
            server = Server(str(self.socket_path), Handler, bind_and_activate=False)
            server.server_bind()
            os.chmod(self.socket_path, 0o600)
            server.server_activate()
            self._server = server
            self._ready.set()
            server.serve_forever(poll_interval=0.05)
        except BaseException as exc:
            self._startup_error = exc
            self._ready.set()
        finally:
            if server is not None:
                server.server_close()
            try:
                self.socket_path.unlink()
            except FileNotFoundError:
                pass

    def stop(self) -> None:
        server = self._server
        if server is not None and self._thread is not threading.current_thread():
            try:
                server.shutdown()
            except (OSError, RuntimeError):
                pass
        with self._connections_lock:
            active = list(self._connections)
        for conn in active:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
        if server is not None:
            try:
                server.server_close()
            except OSError:
                pass
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=5)
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass

    @staticmethod
    def _normalize_host(host: str) -> str:
        value = host.strip().rstrip(".").lower()
        if not value or any(ch.isspace() for ch in value) or "\x00" in value or "%" in value:
            raise ProxyRequestError("Destination hostname is malformed")
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            try:
                value = value.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ProxyRequestError("Destination hostname is invalid") from exc
            labels = value.split(".")
            if len(value) > 253 or len(labels) < 2 or any(
                not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                or not all(ch.isalnum() or ch == "-" for ch in label)
                for label in labels
            ):
                raise ProxyRequestError("Single-label or malformed hostname is denied")
            return value

    @classmethod
    def _parse_authority(cls, authority: str, default_port: int | None = None) -> tuple[str, int]:
        value = authority.strip()
        if not value or "@" in value or any(ch.isspace() for ch in value):
            raise ProxyRequestError("Destination authority is malformed")
        parsed = urlsplit("//" + value)
        if parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment:
            raise ProxyRequestError("Unexpected components in destination authority")
        try:
            port = parsed.port if parsed.port is not None else default_port
        except ValueError as exc:
            raise ProxyRequestError("Invalid destination port") from exc
        if parsed.hostname is None or port is None or not 1 <= port <= 65535:
            raise ProxyRequestError("A valid destination host and port are required")
        return cls._normalize_host(parsed.hostname), port

    def _resolve(self, host: str, port: int) -> list[tuple]:
        if self._resolver_override:
            return self._resolver_override(host, port)
        return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)

    @staticmethod
    def _local_name(host: str) -> bool:
        return host in _LOCAL_NAMES or any(host.endswith(suffix) for suffix in _LOCAL_SUFFIXES)

    def _authorize(self, host: str, port: int) -> _Access:
        target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        request = ActionRequest(category="network", operation="connect", target=target)
        result = self.engine.evaluate(request)
        if result.decision is Decision.DENY:
            return _Access(host, port, result.decision.value, Decision.DENY.value, result.matched_rule_id, result.reason)
        if self._local_name(host):
            return _Access(host, port, result.decision.value, Decision.DENY.value, result.matched_rule_id, "Local and metadata destinations are denied")

        grant: ApprovalGrant | None = None
        if result.decision is Decision.REQUIRE_APPROVAL:
            grant = self.approval_broker.request_network(host, port, result.matched_rule_id, result.reason)
            if grant is None:
                return _Access(host, port, result.decision.value, Decision.DENY.value, result.matched_rule_id, "Human approval was not granted; denied fail-closed")

        try:
            addresses = self._resolve(host, port)
        except (OSError, ValueError):
            if grant is not None:
                self.approval_broker.revoke(grant)
            return _Access(host, port, result.decision.value, Decision.DENY.value, result.matched_rule_id, "Destination DNS resolution failed")
        if not addresses:
            if grant is not None:
                self.approval_broker.revoke(grant)
            return _Access(host, port, result.decision.value, Decision.DENY.value, result.matched_rule_id, "Destination resolved to no addresses")
        for address in addresses:
            try:
                resolved_ip = ipaddress.ip_address(str(address[4][0]).split("%", 1)[0])
            except (IndexError, TypeError, ValueError):
                if grant is not None:
                    self.approval_broker.revoke(grant)
                return _Access(host, port, result.decision.value, Decision.DENY.value, result.matched_rule_id, "Resolver returned an invalid address")
            if not resolved_ip.is_global or resolved_ip.is_multicast or resolved_ip.is_unspecified:
                if grant is not None:
                    self.approval_broker.revoke(grant)
                return _Access(host, port, result.decision.value, Decision.DENY.value, result.matched_rule_id, "A resolved address is not globally routable; private/loopback/link-local access is denied")
        return _Access(host, port, result.decision.value, Decision.ALLOW.value, result.matched_rule_id, result.reason, tuple(addresses), grant)

    def _revalidate_before_connect(self, access: _Access) -> _Access:
        """Re-evaluate the exact request immediately before the upstream socket opens."""
        target = f"[{access.host}]:{access.port}" if ":" in access.host else f"{access.host}:{access.port}"
        result = self.engine.evaluate(ActionRequest(category="network", operation="connect", target=target))
        expected = Decision.REQUIRE_APPROVAL if access.approval_grant is not None else Decision.ALLOW
        if result.decision is not expected or result.matched_rule_id != access.matched_rule_id:
            if access.approval_grant is not None:
                self.approval_broker.revoke(access.approval_grant)
            return _Access(access.host, access.port, result.decision.value, Decision.DENY.value, result.matched_rule_id, "Policy decision or matching rule changed before connection")
        if access.approval_grant is not None:
            consumed = self.approval_broker.consume(
                access.approval_grant, "network.connect", target, result.matched_rule_id
            )
            if not consumed:
                return _Access(access.host, access.port, result.decision.value, Decision.DENY.value, result.matched_rule_id, "Approval expired, was already used, or did not match this exact action")
        return _Access(
            access.host, access.port, result.decision.value, Decision.ALLOW.value,
            result.matched_rule_id, result.reason, access.addresses,
        )

    def _audit_access(self, method: str, access: _Access) -> None:
        self.audit_logger.log_event(AuditEventType.NETWORK_REQUEST, {
            "action": "network.connect", "host": access.host, "port": access.port,
            "method": method, "policy_decision": access.policy_decision,
            "enforced_decision": access.enforced_decision, "matched_rule_id": access.matched_rule_id,
            "reason": access.reason[:400],
            "upstream_addresses": sorted({str(a[4][0]) for a in access.addresses}) if access.allowed else [],
            "approval_supported": True, "approval_used": access.policy_decision == Decision.REQUIRE_APPROVAL.value, "request_path_logged": False,
        })

    def _connect_one(self, address: tuple) -> socket.socket:
        if self._connector_override:
            return self._connector_override(address)
        family, socktype, proto, _canon, sockaddr = address
        upstream = socket.socket(family, socktype, proto)
        upstream.settimeout(self.request_timeout)
        try:
            upstream.connect(sockaddr)
            upstream.settimeout(None)
            return upstream
        except OSError:
            upstream.close()
            raise

    def _connect_upstream(self, access: _Access) -> socket.socket:
        failures: list[str] = []
        for address in access.addresses:
            try:
                return self._connect_one(address)
            except OSError as exc:
                failures.append(type(exc).__name__)
        raise OSError("All authorized upstream addresses failed: " + ", ".join(failures))

    @staticmethod
    def _read_header(client: socket.socket) -> tuple[bytes, bytes]:
        data = bytearray()
        delimiter = b"\r\n\r\n"
        while delimiter not in data:
            chunk = client.recv(8192)
            if not chunk:
                raise ProxyRequestError("Connection closed before request headers completed")
            data.extend(chunk)
            if len(data) > _HEADER_LIMIT:
                raise ProxyRequestError("Proxy request headers exceeded size limit")
        index = data.index(delimiter)
        end = index + len(delimiter)
        return bytes(data[:end]), bytes(data[end:])

    @staticmethod
    def _parse_headers(raw: bytes) -> tuple[str, str, str, list[tuple[str, str]]]:
        lines = raw.decode("iso-8859-1").split("\r\n")
        pieces = lines[0].split()
        if len(pieces) != 3:
            raise ProxyRequestError("Malformed HTTP request line")
        method, target, version = pieces
        method = method.upper()
        if not method.isascii() or not method.replace("-", "").isalnum():
            raise ProxyRequestError("Invalid method")
        if version not in {"HTTP/1.0", "HTTP/1.1"}:
            raise ProxyRequestError("Only HTTP/1.0 and HTTP/1.1 are supported")
        headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            if not line:
                break
            if line.startswith((" ", "\t")) or ":" not in line:
                raise ProxyRequestError("Malformed or folded header")
            name, value = line.split(":", 1)
            name, value = name.strip().lower(), value.strip()
            if not name or not all(ch.isalnum() or ch in "!#$%&'*+-.^_|~" for ch in name):
                raise ProxyRequestError("Malformed header name")
            if any(ch in value for ch in ("\x00", "\r", "\n")):
                raise ProxyRequestError("Malformed header value")
            headers.append((name, value))
            if len(headers) > _MAX_HEADERS:
                raise ProxyRequestError("Too many request headers")
        lengths = [value for name, value in headers if name == "content-length"]
        encodings = [value for name, value in headers if name == "transfer-encoding"]
        if lengths and (len(set(lengths)) != 1 or not lengths[0].isdigit()):
            raise ProxyRequestError("Ambiguous Content-Length")
        if lengths and encodings:
            raise ProxyRequestError("Transfer-Encoding with Content-Length is denied")
        return method, target, version, headers

    @staticmethod
    def _send_error(client: socket.socket, status: int, reason: str, message: str) -> None:
        body = (message + "\n").encode("utf-8")
        response = (
            f"HTTP/1.1 {status} {reason}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\nCache-Control: no-store\r\n\r\n"
        ).encode("ascii") + body
        try:
            client.sendall(response)
        except OSError:
            pass

    def _audit_malformed(self, method: str, error_name: str) -> None:
        self.audit_logger.log_event(AuditEventType.NETWORK_REQUEST, {
            "action": "network.connect", "host": "unparsed", "port": 0,
            "method": method[:16], "policy_decision": "deny", "enforced_decision": "deny",
            "matched_rule_id": "proxy-malformed-request", "reason": error_name[:300],
            "upstream_addresses": [], "approval_supported": False, "request_path_logged": False,
        })

    def _handle_client(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        method = "UNKNOWN"
        try:
            client.settimeout(self.request_timeout)
            raw, remainder = self._read_header(client)
            method, target, version, headers = self._parse_headers(raw)
            hosts = [value for name, value in headers if name == "host"]
            if method == "CONNECT":
                host, port = self._parse_authority(target)
                if len(hosts) > 1:
                    raise ProxyRequestError("Multiple Host headers denied")
                if hosts and self._parse_authority(hosts[0], default_port=port) != (host, port):
                    raise ProxyRequestError("CONNECT authority and Host differ")
                rewritten = b""
            else:
                uri = urlsplit(target)
                if uri.scheme.lower() != "http" or not uri.netloc:
                    raise ProxyRequestError("Use CONNECT for HTTPS; plain HTTP requires an absolute http:// URI")
                host, port = self._parse_authority(uri.netloc, default_port=80)
                if len(hosts) > 1:
                    raise ProxyRequestError("Multiple Host headers denied")
                if hosts and self._parse_authority(hosts[0], default_port=80) != (host, port):
                    raise ProxyRequestError("Absolute URI and Host differ")
                path = uri.path or "/"
                if uri.query:
                    path += "?" + uri.query
                tokens = {
                    token.strip().lower() for name, value in headers if name == "connection"
                    for token in value.split(",") if token.strip()
                }
                discard = {"connection", "proxy-connection", "proxy-authorization", "keep-alive", "te", "trailer"} | tokens
                forwarded = [(n, v) for n, v in headers if n not in discard]
                if not hosts:
                    forwarded.append(("host", uri.netloc))
                forwarded.append(("connection", "close"))
                rewritten = (f"{method} {path} {version}\r\n" + "".join(f"{n}: {v}\r\n" for n, v in forwarded) + "\r\n").encode("iso-8859-1")

            access = self._authorize(host, port)
            if access.allowed:
                access = self._revalidate_before_connect(access)
            self._audit_access(method, access)
            if not access.allowed:
                self._send_error(client, 403, "Forbidden", "Blocked by agent-boundary network policy")
                return
            try:
                upstream = self._connect_upstream(access)
            except OSError as exc:
                self.audit_logger.log_event(AuditEventType.NETWORK_CONNECTION_FAILED, {
                    "host": host, "port": port, "matched_rule_id": access.matched_rule_id,
                    "error_type": type(exc).__name__,
                    "reason": "Policy allowed destination but upstream connection failed",
                })
                self._send_error(client, 502, "Bad Gateway", "Policy-approved upstream connection failed")
                return
            client.settimeout(None)
            upstream.settimeout(None)
            if method == "CONNECT":
                client.sendall(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: agent-boundary\r\n\r\n")
                if remainder:
                    upstream.sendall(remainder)
            else:
                upstream.sendall(rewritten)
                if remainder:
                    upstream.sendall(remainder)
            self._relay(client, upstream)
        except (ProxyRequestError, OSError, ValueError, UnicodeError, socket.timeout) as exc:
            self._audit_malformed(method, type(exc).__name__)
            if isinstance(exc, ProxyRequestError):
                self._send_error(client, 400, "Bad Request", "Malformed proxy request")
        finally:
            if upstream is not None:
                try:
                    upstream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                upstream.close()

    @staticmethod
    def _relay(client: socket.socket, upstream: socket.socket) -> None:
        last_activity = time.monotonic()
        while True:
            readable, _, exceptional = select.select([client, upstream], [], [client, upstream], 1)
            if exceptional:
                return
            if not readable:
                if time.monotonic() - last_activity > _RELAY_IDLE_SECONDS:
                    return
                continue
            for source in readable:
                try:
                    data = source.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                destination = upstream if source is client else client
                try:
                    destination.sendall(data)
                except OSError:
                    return
                last_activity = time.monotonic()
