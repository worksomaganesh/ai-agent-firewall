"""Fail-closed Bubblewrap runner for Linux Phase 2.

This is a constrained local runner, not yet a policy-mediated command broker.
External networking is disabled completely; there is no proxy bridge in this
increment. The host workspace is copied to a private session directory first,
so agent edits are reviewable and do not modify the original source tree.
"""

from __future__ import annotations

import json
import os
import platform
import re
import select
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from agent_boundary.audit.events import AuditEventType, EnforcementMode
from agent_boundary.audit.logger import AuditLogger
from agent_boundary.audit.report import generate_session_report
from agent_boundary.sandbox.seccomp import build_seccomp_filter
from agent_boundary.sandbox.snapshot import changed_path_count, diff_snapshots, snapshot_workspace
from agent_boundary.sandbox.workspace import StagingSummary, prepare_workspace_copy, collect_policy_write_protections
from agent_boundary.sandbox.proxy import PolicyEnforcingProxy
from agent_boundary.policy.schema import Decision, PolicyDocument


class SandboxError(RuntimeError):
    """Raised for sandbox setup errors that must stop execution before the target starts."""


@dataclass(frozen=True)
class ResourceLimits:
    """Per-session resource limits enforced through inherited Linux rlimits."""

    timeout_seconds: int = 600
    cpu_seconds: int = 600
    memory_mib: int = 4096
    file_size_mib: int = 512
    open_files: int = 1024

    def validate(self) -> None:
        if not 1 <= self.timeout_seconds <= 86400:
            raise ValueError("timeout_seconds must be in 1..86400")
        if not 1 <= self.cpu_seconds <= 86400:
            raise ValueError("cpu_seconds must be in 1..86400")
        if not 256 <= self.memory_mib <= 65536:
            raise ValueError("memory_mib must be in 256..65536")
        if not 1 <= self.file_size_mib <= 4096:
            raise ValueError("file_size_mib must be in 1..4096")
        if not 64 <= self.open_files <= 65536:
            raise ValueError("open_files must be in 64..65536")


@dataclass(frozen=True)
class SandboxRunResult:
    """Result of a Bubblewrap session and its local evidence bundle."""

    session_id: str
    session_dir: Path
    workspace_copy: Path | None
    exit_code: int
    sandbox_started: bool
    timed_out: bool
    interrupted: bool
    audit_head_hash: str
    changes: dict[str, list[dict[str, object]]]
    omitted_secrets: int
    error: str | None = None


def parse_bwrap_version(version_output: str) -> tuple[int, int, int]:
    """Extract a semantic upstream version from the output of bwrap --version."""
    match = re.search(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?!\d)", version_output)
    if not match:
        raise SandboxError(f"Could not parse Bubblewrap version output: {version_output.strip()!r}")
    return tuple(int(match.group(index)) for index in range(1, 4))


def _trusted_bwrap_binary() -> Path:
    """Find Bubblewrap only in trusted system directories, not the caller's PATH."""
    if platform.system() != "Linux":
        raise SandboxError("Real OS enforcement is supported only on Linux")
    if os.geteuid() == 0:
        raise SandboxError("Refusing to run a coding agent as root; use an unprivileged account")

    for candidate in (
        Path("/usr/local/bin/bwrap"),
        Path("/usr/bin/bwrap"),
        Path("/bin/bwrap"),
    ):
        try:
            resolved = candidate.resolve(strict=True)
            info = resolved.stat()
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
            continue
        if info.st_uid != 0 or info.st_mode & 0o022:
            continue
        if info.st_mode & stat.S_ISUID:
            continue
        return resolved

    raise SandboxError(
        "A trusted, root-owned, non-writable, non-setuid Bubblewrap binary was not found "
        "in /usr/local/bin, /usr/bin, or /bin"
    )


def _write_filter_pipe() -> int:
    """Create a pipe containing a compiled cBPF program and return its read descriptor."""
    program = build_seccomp_filter()
    read_fd, write_fd = os.pipe()
    try:
        view = memoryview(program)
        while view:
            written = os.write(write_fd, view)
            view = view[written:]
    finally:
        os.close(write_fd)
    return read_fd


def _system_mount_args() -> list[str]:
    """Mount only standard executable and shared-library trees read-only."""
    args: list[str] = ["--ro-bind", "/usr", "/usr"]
    for system_path in ("/bin", "/sbin", "/lib", "/lib64"):
        if Path(system_path).exists():
            args.extend(["--ro-bind-try", system_path, system_path])
    return args


def build_bwrap_argv(
    binary: Path,
    workspace_copy: Path,
    command: Sequence[str],
    seccomp_fd: int,
    status_fd: int | None = None,
    proxy_socket_path: Path | None = None,
    bridge_script_path: Path | None = None,
    policy: PolicyDocument | None = None,
    proxy_port: int = 18790,
) -> list[str]:
    """Construct the exact sandbox invocation without executing it."""
    if not command or any(not isinstance(arg, str) or "\x00" in arg for arg in command):
        raise ValueError("Command must be a non-empty sequence of strings without NUL bytes")
    workspace_copy = workspace_copy.resolve(strict=True)
    if not workspace_copy.is_dir():
        raise ValueError(f"Staged workspace is not a directory: {workspace_copy}")

    args = [
        str(binary),
        # Do not use --unshare-all here: that uses --unshare-user-try on some
        # Bubblewrap versions. Every required isolation namespace must succeed.
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--disable-userns",
        "--seccomp",
        str(seccomp_fd),
    ]
    if status_fd is not None:
        args.extend(["--json-status-fd", str(status_fd)])

    args.extend(_system_mount_args())
    args.extend(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"])
    args.extend(["--dir", "/workspace", "--bind", str(workspace_copy), "/workspace"])

    if (proxy_socket_path is not None) != (bridge_script_path is not None):
        raise ValueError("Proxy socket and guest bridge script must be supplied together")
    if proxy_socket_path is not None and bridge_script_path is not None:
        if not proxy_socket_path.is_socket() or not bridge_script_path.is_file():
            raise ValueError("Proxy socket or guest bridge script is missing")
        args.extend(["--dir", "/run", "--dir", "/run/agent-boundary"])
        args.extend(["--bind", str(proxy_socket_path), "/run/agent-boundary/proxy.sock"])
        args.extend(["--ro-bind", str(bridge_script_path), "/run/agent-boundary/guest_bridge.py"])

    git_dir = workspace_copy / ".git"
    if git_dir.is_dir() and not git_dir.is_symlink():
        args.extend(["--ro-bind", str(git_dir), "/workspace/.git"])

    workflows_dir = workspace_copy / ".github" / "workflows"
    if workflows_dir.is_dir() and not workflows_dir.is_symlink():
        args.extend(
            ["--ro-bind", str(workflows_dir), "/workspace/.github/workflows"]
        )

    pyproject = workspace_copy / "pyproject.toml"
    if pyproject.is_file() and not pyproject.is_symlink():
        args.extend(["--ro-bind", str(pyproject), "/workspace/pyproject.toml"])

    if policy is not None:
        protected_roots = (".git", ".github/workflows", "pyproject.toml")
        for protected in collect_policy_write_protections(workspace_copy, policy):
            rel = protected.relative_to(workspace_copy).as_posix()
            if any(rel == root or rel.startswith(root + "/") for root in protected_roots):
                continue
            args.extend(["--ro-bind", str(protected), "/workspace/" + rel])

    sandbox_command = list(command)
    if proxy_socket_path is not None and bridge_script_path is not None:
        sandbox_command = [
            "/usr/bin/python3",
            "/run/agent-boundary/guest_bridge.py",
            "--proxy-socket", "/run/agent-boundary/proxy.sock",
            "--listen-port", str(proxy_port),
            "--", *command,
        ]

    args.extend(
        [
            "--chdir",
            "/workspace",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "GIT_CONFIG_NOSYSTEM",
            "1",
            "--setenv",
            "GIT_CONFIG_GLOBAL",
            "/dev/null",
            "--setenv",
            "GIT_OPTIONAL_LOCKS",
            "0",
            "--setenv",
            "GIT_TERMINAL_PROMPT",
            "0",
            "--",
            *sandbox_command,
        ]
    )
    return args


def _apply_resource_limits(limits: ResourceLimits) -> None:
    """Apply inherited process resource caps in the subprocess pre-exec stage."""
    import resource

    cpu = limits.cpu_seconds
    address_space = limits.memory_mib * 1024 * 1024
    max_file = limits.file_size_mib * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))
    resource.setrlimit(resource.RLIMIT_FSIZE, (max_file, max_file))
    resource.setrlimit(resource.RLIMIT_NOFILE, (limits.open_files, limits.open_files))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def preflight_bubblewrap() -> tuple[Path, str]:
    """Check trusted binary/version, then probe every configured OS control."""
    binary = _trusted_bwrap_binary()
    try:
        version_result = subprocess.run(
            [str(binary), "--version"],
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=5,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SandboxError(f"Unable to query Bubblewrap version: {exc}") from exc
    version_output = (version_result.stdout + "\n" + version_result.stderr).strip()
    if version_result.returncode != 0:
        raise SandboxError(f"Bubblewrap version check failed: {version_output}")
    version = parse_bwrap_version(version_output)
    if version < (0, 12, 0):
        raise SandboxError(
            f"Bubblewrap {version[0]}.{version[1]}.{version[2]} is too old. "
            "This runner requires upstream Bubblewrap >= 0.12.0 (the release fixing "
            "CVE-2026-87766); older distro version strings are rejected conservatively."
        )

    true_binary = Path("/usr/bin/true")
    if not true_binary.exists():
        true_binary = Path("/bin/true")
    if not true_binary.exists():
        raise SandboxError("Could not find /usr/bin/true or /bin/true for the sandbox probe")

    try:
        with tempfile.TemporaryDirectory(prefix="agent-boundary-preflight-") as temp_dir:
            stage = Path(temp_dir)
            seccomp_fd = _write_filter_pipe()
            try:
                args = build_bwrap_argv(
                    binary=binary,
                    workspace_copy=stage,
                    command=[str(true_binary)],
                    seccomp_fd=seccomp_fd,
                )
                probe = subprocess.run(
                    args,
                    check=False,
                    pass_fds=(seccomp_fd,),
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=15,
                    env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C"},
                )
            finally:
                os.close(seccomp_fd)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise SandboxError(f"Bubblewrap isolation probe could not complete: {exc}") from exc

    if probe.returncode != 0:
        detail = (probe.stderr or probe.stdout or "no diagnostic output").strip()
        raise SandboxError(
            "Bubblewrap preflight failed; the requested command was not launched. "
            f"Probe returned {probe.returncode}: {detail[-2000:]}"
        )
    return binary, f"{version[0]}.{version[1]}.{version[2]}"


def _wait_for_child_started(process: subprocess.Popen[bytes], status_fd: int, timeout: float) -> bool:
    """Wait for Bubblewrap's JSON status to confirm the sandbox child actually started."""
    deadline = time.monotonic() + timeout
    buffered = bytearray()

    while time.monotonic() < deadline:
        ready, _, _ = select.select([status_fd], [], [], 0.1)
        if ready:
            try:
                chunk = os.read(status_fd, 4096)
            except OSError:
                return False
            if not chunk:
                return False
            buffered.extend(chunk)
            while b"\n" in buffered:
                line, _, rest = buffered.partition(b"\n")
                buffered = bytearray(rest)
                try:
                    status = json.loads(line.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError):
                    continue
                if isinstance(status, dict) and "child-pid" in status:
                    return True
        if process.poll() is not None and not ready:
            return False

    return False


def _write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _extend_report(session_dir: Path, changes: dict[str, list[dict[str, object]]], result: dict[str, object]) -> None:
    """Append truthful Phase 2 execution and workspace-change details."""
    report_path = session_dir / "session_report.md"
    try:
        current = report_path.read_text(encoding="utf-8")
    except OSError:
        current = "# agent-boundary Session Report\n"
    changed_count = changed_path_count(changes)
    lines = [
        "",
        "## 5. Phase 2 OS Sandbox Details",
        "",
        f"- Sandbox child started: **{result.get('sandbox_started')}**",
        f"- Command exit code: **{result.get('exit_code')}**",
        f"- Timed out: **{result.get('timed_out')}**",
        "- Host workspace modified by this runner: **No** (the command used the private staged copy)",
        "- Outbound networking: direct TCP/UDP/DNS sockets are blocked by the private network namespace; HTTP/HTTPS proxy requests are evaluated by the host policy proxy over a mounted UNIX socket",
        "- Network require-approval rules fail closed until the Phase 3 approval broker exists; HTTPS payloads remain opaque after an allowed CONNECT",
        "- Environment: host environment variables and credentials are not forwarded; the guest bridge supplies minimal environment variables and local proxy settings",
        "- Workspace policy status: deny-read paths are omitted during staging; write-deny and require-approval targets are mounted read-only where supported",
        f"- Paths omitted by filesystem policy: {result.get('policy_paths_omitted', 0)}",
        f"- Changed staged paths: **{changed_count}**",
        "",
        "## 6. Private Workspace Copy Changes",
        "",
        "| Change | Path |",
        "|---|---|",
    ]
    for kind in ("added", "modified", "deleted"):
        for item in changes[kind][:100]:
            lines.append(f"| {kind} | {item.get('path', '')} |")
    if changed_count == 0:
        lines.append("| none | - |")
    if changed_count > 300:
        lines.extend(["", f"Only the first 100 items per category are listed here; {changed_count} total changes are recorded in diff.json."])
    lines.extend(
        [
            "",
            "The staged workspace is retained under the session directory for inspection. Changes are not automatically copied back to the original workspace.",
            "",
        ]
    )
    report_path.write_text(current.rstrip() + "\n" + "\n".join(lines), encoding="utf-8")
    report_path.chmod(0o600)


def run_sandboxed(
    workspace: Path,
    command: Sequence[str],
    output_root: Path | None = None,
    limits: ResourceLimits | None = None,
    policy: PolicyDocument | None = None,
) -> SandboxRunResult:
    """Run a command inside Bubblewrap, recording evidence and retaining a private copy.

    The caller's source workspace is only read. A sanitized private copy is used
    as /workspace; OS setup failures return before the requested command starts.
    """
    limits = limits or ResourceLimits()
    limits.validate()
    source = workspace.expanduser().resolve(strict=True)
    if not source.is_dir():
        raise ValueError(f"Workspace is not a directory: {source}")
    if source == Path("/") or source == Path.home().expanduser().resolve():
        raise ValueError("Choose a project directory rather than the filesystem root or home directory")

    argv = tuple(command)
    if not argv or any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in argv):
        raise ValueError("Supply a non-empty command after --; arguments must be non-empty strings")

    if output_root is None:
        output_root = Path.home() / ".local" / "state" / "agent-boundary" / "runs"
    output_root = output_root.expanduser().resolve()
    if output_root == source or output_root.is_relative_to(source):
        raise ValueError("Output root must be outside the source workspace")
    output_root.mkdir(parents=True, exist_ok=True, mode=0o700)

    session_id = f"ab-run-{uuid.uuid4().hex[:12]}"
    session_dir = output_root / session_id
    session_dir.mkdir(mode=0o700)
    workspace_copy = session_dir / "workspace"
    audit_path = session_dir / "audit.jsonl"
    logger = AuditLogger(
        log_path=audit_path,
        session_id=session_id,
        enforcement_mode=EnforcementMode.OS_ENFORCED_BWRAP,
    )
    logger.log_event(
        AuditEventType.SESSION_START,
        {
            "session_kind": "bubblewrap_run",
            "workspace_name": source.name,
            "command_name": Path(argv[0]).name,
            "argument_count": len(argv),
            "network_mode": "isolated_net_namespace_with_policy_proxy",
            "policy_id": policy.policy_id if policy else "implicit-default-deny",
        },
    )

    sandbox_started = False
    timed_out = False
    interrupted = False
    exit_code = int(ExitCodeForSandbox.FAILURE)
    error: str | None = None
    staging: StagingSummary | None = None
    changes: dict[str, list[dict[str, object]]] = {"added": [], "modified": [], "deleted": []}
    bwrap_version: str | None = None
    pre_manifest: dict[str, dict[str, object]] = {}
    post_manifest: dict[str, dict[str, object]] = {}
    proxy_server: PolicyEnforcingProxy | None = None
    proxy_directory: Path | None = None

    try:
        binary, bwrap_version = preflight_bubblewrap()
        staging = prepare_workspace_copy(source, workspace_copy, policy=policy)
        pre_manifest = snapshot_workspace(workspace_copy)
        _write_json(session_dir / "baseline-manifest.json", pre_manifest)

        proxy_directory = Path(tempfile.mkdtemp(prefix="abp-", dir="/tmp"))
        proxy_directory.chmod(0o700)
        proxy_socket_path = proxy_directory / "proxy.sock"
        bridge_script_path = proxy_directory / "guest_bridge.py"
        shutil.copyfile(Path(__file__).with_name("guest_bridge.py"), bridge_script_path)
        bridge_script_path.chmod(0o400)
        if policy is None:
            proxy_policy = PolicyDocument(
                schema_version="1.0",
                policy_id="implicit-default-deny",
                description="No policy supplied; all outbound network access is denied.",
                workspace_root="/workspace",
                default_decision=Decision.DENY,
            )
        else:
            proxy_policy = policy
        proxy_server = PolicyEnforcingProxy(proxy_socket_path, proxy_policy, logger)
        proxy_server.start()

        seccomp_fd = _write_filter_pipe()
        status_read, status_write = os.pipe()
        process: subprocess.Popen[bytes] | None = None
        try:
            run_args = build_bwrap_argv(
                binary=binary,
                workspace_copy=workspace_copy,
                command=argv,
                seccomp_fd=seccomp_fd,
                status_fd=status_write,
                proxy_socket_path=proxy_socket_path,
                bridge_script_path=bridge_script_path,
                policy=policy,
            )
            process = subprocess.Popen(
                run_args,
                pass_fds=(seccomp_fd, status_write),
                preexec_fn=lambda: _apply_resource_limits(limits),
            )
        except (OSError, ValueError) as exc:
            error = f"Unable to start Bubblewrap: {exc}"
            logger.log_event(
                AuditEventType.SANDBOX_INIT_FAILED,
                {"phase": "process_creation", "reason": error, "target_command_started": False},
            )
        finally:
            os.close(seccomp_fd)
            os.close(status_write)

        if process is not None:
            try:
                sandbox_started = _wait_for_child_started(process, status_read, timeout=15)
                if not sandbox_started:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
                    error = (
                        "Bubblewrap did not confirm that the target child started; "
                        "the command is treated as not executed"
                    )
                    logger.log_event(
                        AuditEventType.SANDBOX_INIT_FAILED,
                        {
                            "phase": "sandbox_startup",
                            "reason": error,
                            "bwrap_exit_code": process.returncode,
                            "target_command_started": False,
                        },
                    )
                else:
                    logger.log_event(
                        AuditEventType.SANDBOX_STARTED,
                        {
                            "backend": "bubblewrap",
                            "version": bwrap_version,
                            "namespaces": ["user", "pid", "net", "ipc", "uts"],
                            "seccomp_filter": "architecture_checked_denylist",
                            "workspace_copy": "read_write_private_copy",
                            "git_metadata": "read_only",
                            "network": "private_net_namespace_plus_host_policy_proxy",
                            "policy_id": proxy_policy.policy_id,
                            "proxy_socket": "mounted_unix_socket",
                            "environment": "cleared_and_minimal",
                        },
                    )
                    try:
                        exit_code = process.wait(timeout=limits.timeout_seconds)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        process.kill()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            pass
                        exit_code = 124
                        error = f"Command exceeded wall-clock timeout of {limits.timeout_seconds} seconds"
                    except KeyboardInterrupt:
                        interrupted = True
                        process.kill()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            pass
                        exit_code = 130
                        error = "Interrupted by operator"
                    if process.returncode is not None and not timed_out and not interrupted:
                        exit_code = int(process.returncode)
                    logger.log_event(
                        AuditEventType.SANDBOX_FINISHED,
                        {
                            "exit_code": exit_code,
                            "timed_out": timed_out,
                            "interrupted": interrupted,
                            "target_command_started": True,
                        },
                    )
            finally:
                os.close(status_read)
        else:
            os.close(status_read)

        if workspace_copy.exists():
            post_manifest = snapshot_workspace(workspace_copy)
            _write_json(session_dir / "final-manifest.json", post_manifest)
            changes = diff_snapshots(pre_manifest, post_manifest)
            _write_json(session_dir / "diff.json", changes)
    except (SandboxError, OSError, ValueError, RuntimeError) as exc:
        error = str(exc)
        if not sandbox_started:
            logger.log_event(
                AuditEventType.SANDBOX_INIT_FAILED,
                {
                    "phase": "preflight_or_workspace_setup",
                    "reason": error,
                    "target_command_started": False,
                },
            )
        exit_code = int(ExitCodeForSandbox.FAILURE)
    finally:
        if proxy_server is not None:
            try:
                proxy_server.stop()
            except (OSError, RuntimeError, TimeoutError):
                pass
        if proxy_directory is not None:
            shutil.rmtree(proxy_directory, ignore_errors=True)
        logger.log_event(
            AuditEventType.SESSION_END,
            {
                "sandbox_started": sandbox_started,
                "exit_code": exit_code,
                "timed_out": timed_out,
                "interrupted": interrupted,
                "error": error,
                "changed_path_count": changed_path_count(changes),
                "secret_paths_omitted": staging.secret_paths_omitted if staging else 0,
            },
        )
        try:
            base_report = generate_session_report(session_dir)
            report_path = session_dir / "session_report.md"
            report_path.write_text(base_report, encoding="utf-8")
            _extend_report(
                session_dir,
                changes,
                {
                    "sandbox_started": sandbox_started,
                    "exit_code": exit_code,
                    "timed_out": timed_out,
                    "policy_paths_omitted": staging.policy_paths_omitted if staging else 0,
                },
            )
        except (OSError, ValueError, RuntimeError) as report_error:
            if error is None:
                error = f"Could not finalize session report: {report_error}"
        summary = {
            "session_id": session_id,
            "enforcement_mode": EnforcementMode.OS_ENFORCED_BWRAP.value,
            "sandbox_started": sandbox_started,
            "command_name": Path(argv[0]).name,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "interrupted": interrupted,
            "bwrap_version": bwrap_version,
            "workspace_copy": str(workspace_copy) if workspace_copy.exists() else None,
            "source_workspace_modified": False,
            "secret_paths_omitted": staging.secret_paths_omitted if staging else 0,
            "metadata_paths_omitted": staging.metadata_paths_omitted if staging else 0,
            "special_files_omitted": staging.special_files_omitted if staging else 0,
            "policy_paths_omitted": staging.policy_paths_omitted if staging else 0,
            "network_proxy_enabled": proxy_server is not None,
            "changed_path_count": changed_path_count(changes),
            "audit_head_hash": logger.head_hash,
            "error": error,
        }
        try:
            _write_json(session_dir / "session-summary.json", summary)
        except OSError:
            pass

    return SandboxRunResult(
        session_id=session_id,
        session_dir=session_dir,
        workspace_copy=workspace_copy if workspace_copy.exists() else None,
        exit_code=exit_code,
        sandbox_started=sandbox_started,
        timed_out=timed_out,
        interrupted=interrupted,
        audit_head_hash=logger.head_hash,
        changes=changes,
        omitted_secrets=staging.secret_paths_omitted if staging else 0,
        error=error,
    )


# Kept separate so the sandbox module does not import CLI presentation concerns.
class ExitCodeForSandbox:
    FAILURE = 78
