"""Property-based adversarial tests for proxy parsing and guarded path normalization."""
from __future__ import annotations
from hypothesis import given, settings, strategies as st
from agent_boundary.sandbox.proxy import PolicyEnforcingProxy, ProxyRequestError
from agent_boundary.sandbox.workspace_tools import GuardedWorkspaceTools

@settings(max_examples=500, deadline=None)
@given(authority=st.text(max_size=320))
def test_arbitrary_authorities_are_rejected_or_normalize_safely(authority: str) -> None:
    try:
        host, port = PolicyEnforcingProxy._parse_authority(authority)
    except (ProxyRequestError, ValueError, UnicodeError):
        return
    assert host and host == host.lower()
    assert not any(ch.isspace() for ch in host)
    assert "\x00" not in host and "%" not in host
    assert 1 <= port <= 65535

@settings(max_examples=500, deadline=None)
@given(host=st.text(max_size=320))
def test_accepted_host_normalization_is_idempotent(host: str) -> None:
    try:
        normalized = PolicyEnforcingProxy._normalize_host(host)
    except (ProxyRequestError, ValueError, UnicodeError):
        return
    assert normalized == PolicyEnforcingProxy._normalize_host(normalized)
    assert normalized == normalized.lower() and not normalized.endswith(".")
    assert not any(ch.isspace() for ch in normalized)

@settings(max_examples=500, deadline=None)
@given(raw=st.text(max_size=256))
def test_workspace_relative_path_never_accepts_traversal(raw: str) -> None:
    try:
        normalized = GuardedWorkspaceTools._relative_path(raw)
    except ValueError:
        return
    assert not normalized.is_absolute() and "\\" not in raw and not raw.startswith("/")
    assert all(part not in ("", ".", "..") for part in raw.split("/"))
    assert normalized.as_posix() == raw

@settings(max_examples=500, deadline=None)
@given(raw=st.binary(min_size=0, max_size=4096))
def test_arbitrary_http_header_bytes_are_rejected_or_return_safe_fields(raw: bytes) -> None:
    try:
        method, _target, version, headers = PolicyEnforcingProxy._parse_headers(raw)
    except (ProxyRequestError, ValueError, UnicodeError):
        return
    assert method.isascii() and method.replace("-", "").isalnum()
    assert version in {"HTTP/1.0", "HTTP/1.1"}
    for name, value in headers:
        assert name == name.lower() and name
        assert not any(char in value for char in ("\x00", "\r", "\n"))

@settings(max_examples=300, deadline=None)
@given(port=st.integers(min_value=-10000, max_value=100000))
def test_authority_parser_never_accepts_out_of_range_ports(port: int) -> None:
    try:
        _host, accepted_port = PolicyEnforcingProxy._parse_authority(f"example.com:{port}")
    except (ProxyRequestError, ValueError):
        return
    assert 1 <= accepted_port <= 65535
