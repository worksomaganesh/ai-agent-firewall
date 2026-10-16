"""Phase 2 unit and real Linux enforcement tests."""

from __future__ import annotations

import json
import os
import struct
import shutil
import socket
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_boundary.cli import app
from agent_boundary.audit.verifier import verify_audit_log
from agent_boundary.sandbox.bwrap import (
    ResourceLimits,
    SandboxError,
    _write_filter_pipe,
    build_bwrap_argv,
    parse_bwrap_version,
    preflight_bubblewrap,
    run_sandboxed,
)
from agent_boundary.sandbox.seccomp import build_seccomp_filter, supported_architecture
from agent_boundary.sandbox.snapshot import diff_snapshots, snapshot_workspace
from agent_boundary.sandbox.workspace import WorkspacePreparationError, prepare_workspace_copy

runner = CliRunner()


def test_seccomp_filter_contains_arch_guard_and_denied_syscalls() -> None:
    program = build_seccomp_filter("x86_64")
    assert len(program) % 8 == 0
    instructions = [struct.unpack("=HBBI", program[i:i + 8]) for i in range(0, len(program), 8)]
    # First instruction loads seccomp_data.arch; the next one compares it.
    assert instructions[0] == (0x20, 0, 0, 4)
    assert instructions[1][0] == 0x15
    assert instructions[1][1] == 1
    constants = {ins[3] for ins in instructions}
    assert 101 in constants  # ptrace on x86_64
    assert 165 in constants  # mount on x86_64
    assert 272 in constants  # unshare on x86_64
    assert 0x5412 in constants  # TIOCSTI
    assert instructions[-1][0] == 0x06  # final RET


def test_seccomp_rejects_unsupported_architecture() -> None:
    with pytest.raises(ValueError, match="not defined"):
        supported_architecture("mips64")


def test_bubblewrap_version_parser_and_minimum() -> None:
    assert parse_bwrap_version("bubblewrap 0.12.0") == (0, 12, 0)
    assert parse_bwrap_version("bubblewrap 1.2.3") == (1, 2, 3)
    with pytest.raises(SandboxError, match="Could not parse"):
        parse_bwrap_version("unknown build")


def test_resource_limits_reject_invalid_values() -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        ResourceLimits(timeout_seconds=0).validate()
    with pytest.raises(ValueError, match="memory_mib"):
        ResourceLimits(memory_mib=1).validate()


def test_workspace_staging_omits_secrets_and_sanitizes_git(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('safe')\n", encoding="utf-8")
    (source / ".env").write_text("API_TOKEN=never-copy-this\n", encoding="utf-8")
    (source / "deploy.pem").write_text("PRIVATE KEY MATERIAL\n", encoding="utf-8")
    (source / ".npmrc").write_text("//registry.example/:_authToken=SECRET\n", encoding="utf-8")
    git = source / ".git"
    (git / "hooks").mkdir(parents=True)
    (git / "objects" / "info").mkdir(parents=True)
    (git / "config").write_text('[remote "origin"]\n url = https://user:token@example.com/repo.git\n', encoding="utf-8")
    (git / "hooks" / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
    (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    workflows = source / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("name: CI\n", encoding="utf-8")
    (workflows / "link.yml").symlink_to("../../app.py")
    (source / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")

    destination = tmp_path / "session" / "workspace"
    result = prepare_workspace_copy(source, destination)

    assert result.secret_paths_omitted >= 3
    assert not (destination / ".env").exists()
    assert not (destination / "deploy.pem").exists()
    assert not (destination / ".npmrc").exists()
    assert "token@" not in (destination / ".git" / "config").read_text(encoding="utf-8")
    assert list((destination / ".git" / "hooks").iterdir()) == []
    assert (destination / ".github" / "workflows" / "ci.yml").is_file()
    assert not (destination / ".github" / "workflows" / "link.yml").exists()
    # Source data remains intact; staging is a copy, not a live workspace bind.
    assert "API_TOKEN=never-copy-this" in (source / ".env").read_text(encoding="utf-8")
    assert (git / "hooks" / "pre-commit").exists()


def test_workspace_staging_rejects_git_worktree_file(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / ".git").write_text("gitdir: /private/path\n", encoding="utf-8")
    with pytest.raises(WorkspacePreparationError, match="worktrees"):
        prepare_workspace_copy(source, tmp_path / "copy")


def test_snapshot_detects_changes_without_reading_git_metadata(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "file.txt").write_text("before", encoding="utf-8")
    (root / ".git").mkdir()
    (root / ".git" / "internal").write_text("ignore", encoding="utf-8")
    before = snapshot_workspace(root)
    (root / "file.txt").write_text("after", encoding="utf-8")
    (root / "new.txt").write_text("new", encoding="utf-8")
    after = snapshot_workspace(root)
    diff = diff_snapshots(before, after)

    assert "file.txt" in before
    assert ".git/internal" not in before
    assert [item["path"] for item in diff["modified"]] == ["file.txt"]
    assert [item["path"] for item in diff["added"]] == ["new.txt"]


def test_bwrap_command_uses_required_namespaces_and_no_network_exception(tmp_path: Path) -> None:
    stage = tmp_path / "stage"
    stage.mkdir()
    (stage / ".git").mkdir()
    (stage / ".git" / "hooks").mkdir()
    (stage / ".github" / "workflows").mkdir(parents=True)
    (stage / "pyproject.toml").write_text("[project]\n", encoding="utf-8")

    argv = build_bwrap_argv(
        Path("/usr/bin/bwrap"),
        stage,
        ["/bin/true"],
        seccomp_fd=9,
        status_fd=10,
    )
    assert "--unshare-user" in argv
    assert "--unshare-pid" in argv
    assert "--unshare-net" in argv
    assert "--unshare-ipc" in argv
    assert "--unshare-uts" in argv
    assert "--disable-userns" in argv
    assert "--seccomp" in argv and argv[argv.index("--seccomp") + 1] == "9"
    assert "--json-status-fd" in argv and argv[argv.index("--json-status-fd") + 1] == "10"
    assert "--share-net" not in argv
    assert [str(stage / ".git"), "/workspace/.git"] == argv[argv.index("--ro-bind", argv.index("--bind")) + 1:argv.index("--ro-bind", argv.index("--bind")) + 3]
    assert str(stage / ".github" / "workflows") in argv
    assert str(stage / "pyproject.toml") in argv


def test_preflight_failure_never_launches_target(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import agent_boundary.sandbox.bwrap as bwrap_module

    source = tmp_path / "source"
    source.mkdir()
    marker = tmp_path / "target-was-run"

    def failed_preflight() -> tuple[Path, str]:
        raise SandboxError("simulated namespace setup failure")

    monkeypatch.setattr(bwrap_module, "preflight_bubblewrap", failed_preflight)
    result = run_sandboxed(
        source,
        ["/bin/sh", "-c", f"touch {marker}"],
        output_root=tmp_path / "runs",
    )
    assert result.sandbox_started is False
    assert result.exit_code == 78
    assert not marker.exists()
    audit_path = result.session_dir / "audit.jsonl"
    log_text = audit_path.read_text(encoding="utf-8")
    assert "SANDBOX_INIT_FAILED" in log_text
    assert "target_command_started" in log_text
    assert verify_audit_log(audit_path).valid
    report = (result.session_dir / "session_report.md").read_text(encoding="utf-8")
    assert "SANDBOX NOT STARTED" in report


@pytest.mark.sandbox
def test_real_bubblewrap_isolation_and_source_workspace_preservation(tmp_path: Path) -> None:
    if shutil.which("bwrap") is None and not Path("/usr/local/bin/bwrap").exists() and not Path("/usr/bin/bwrap").exists():
        pytest.skip("Bubblewrap is not installed in this environment")
    try:
        preflight_bubblewrap()
    except SandboxError as exc:
        pytest.skip(f"Bubblewrap namespace/seccomp capability unavailable: {exc}")

    source = tmp_path / "source"
    source.mkdir()
    secret = source / ".env"
    secret.write_text("PHASE2_TEST_SECRET=not-copied\n", encoding="utf-8")
    (source / "app.py").write_text("before\n", encoding="utf-8")
    proof_file = "phase2-proof.json"
    script = (
        "import json, pathlib, socket, resource; "
        "ws=pathlib.Path('/workspace'); "
        "e={'dotenv_absent': not (ws/'.env').exists(), "
        "'host_source_path_absent': not pathlib.Path(" + repr(str(source.resolve())) + ").exists(), "
        "'nofile_limit': resource.getrlimit(resource.RLIMIT_NOFILE)[0]}; "
        "pathlib.Path('" + proof_file + "').write_text(json.dumps(e)); "
        "(ws/'app.py').write_text('after\\n'); "
        "p=socket.create_connection(('127.0.0.1',18790),timeout=3); "
        "p.sendall(b'CONNECT evil.example.com:443 HTTP/1.1\\r\\nHost: evil.example.com:443\\r\\n\\r\\n'); "
        "e['proxy_blocked']=b'403 Forbidden' in p.recv(4096); p.close(); "
        "s=socket.socket(); s.settimeout(1); "
        "exec(\"try:\\n s.connect(('1.1.1.1',443)); e['network_blocked']=False\\nexcept OSError:\\n e['network_blocked']=True\\nfinally:\\n s.close()\"); "
        "pathlib.Path('" + proof_file + "').write_text(json.dumps(e)); "
        "assert e['dotenv_absent'] and e['host_source_path_absent'] and e['network_blocked'] and e['proxy_blocked']"
    )
    result = run_sandboxed(
        source,
        ["/usr/bin/python3", "-c", script],
        output_root=tmp_path / "runs",
        limits=ResourceLimits(timeout_seconds=30, cpu_seconds=20, memory_mib=1024, file_size_mib=32, open_files=128),
    )
    assert result.sandbox_started is True
    assert result.exit_code == 0
    assert secret.read_text(encoding="utf-8") == "PHASE2_TEST_SECRET=not-copied\n"
    assert (result.workspace_copy / "app.py").read_text(encoding="utf-8") == "after\n"
    proof = json.loads((result.workspace_copy / proof_file).read_text(encoding="utf-8"))
    assert proof == {
        "dotenv_absent": True,
        "host_source_path_absent": True,
        "network_blocked": True,
        "proxy_blocked": True,
        "nofile_limit": 128,
    }
    assert result.changes["modified"] and any(item["path"] == "app.py" for item in result.changes["modified"])
    assert (result.session_dir / "diff.json").is_file()
    report = (result.session_dir / "session_report.md").read_text(encoding="utf-8")
    assert "OS SANDBOX CHILD STARTED" in report
    assert "Live Network Policy Decisions" in report
    assert "evil.example.com" in report
    assert "Outbound networking" in report
    assert verify_audit_log(result.session_dir / "audit.jsonl").valid
