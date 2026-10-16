"""Concrete policy-gated file tools for trusted adapters operating on a staged workspace.

These helpers are for mediated tool integrations. They are not a replacement for
Bubblewrap mounts: raw syscalls made by an arbitrary child process do not pass
through this Python API.
"""

from __future__ import annotations

import hashlib
import os
import stat
import uuid
from pathlib import Path, PurePosixPath
from typing import Callable

from agent_boundary.policy.engine import ActionRequest
from agent_boundary.sandbox.guard import GuardResult, GuardedActionGate


class GuardedWorkspaceTools:
    """Read, write and delete regular files only through a GuardedActionGate."""

    def __init__(self, workspace_root: Path, gate: GuardedActionGate) -> None:
        self.root = workspace_root.expanduser().resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("Workspace root must be an existing directory")
        self.gate = gate

    @staticmethod
    def _relative_path(relative_path: str) -> PurePosixPath:
        rel = PurePosixPath(relative_path)
        if (
            not relative_path
            or rel.is_absolute()
            or "\\" in relative_path
            or any(part in ("", ".", "..") for part in relative_path.split("/"))
        ):
            raise ValueError("File tool paths must be safe relative paths inside the workspace")
        return rel

    def _path(self, relative_path: str, *, allow_missing_leaf: bool = False) -> Path:
        rel = self._relative_path(relative_path)
        current = self.root
        parts = rel.parts
        for index, part in enumerate(parts):
            current = current / part
            try:
                mode = current.lstat().st_mode
            except FileNotFoundError:
                if allow_missing_leaf and index == len(parts) - 1:
                    break
                raise
            if stat.S_ISLNK(mode):
                raise ValueError(f"Symlink paths are not supported by guarded file tools: {relative_path}")
            if index < len(parts) - 1 and not stat.S_ISDIR(mode):
                raise ValueError(f"Parent path is not a directory: {relative_path}")
        if not current.resolve(strict=False).is_relative_to(self.root):
            raise ValueError("Path escapes staged workspace")
        return current

    @staticmethod
    def _fingerprint(path: Path) -> str:
        try:
            before = path.lstat()
        except FileNotFoundError:
            return "missing"
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Guarded file tools support regular files only")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino, opened.st_mode) != (before.st_dev, before.st_ino, before.st_mode):
                raise RuntimeError("Target changed while opening for fingerprint")
            digest = hashlib.sha256()
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            after = os.fstat(fd)
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ):
                raise RuntimeError("Target changed while fingerprinting")
            return ":".join(
                str(value)
                for value in (
                    after.st_dev, after.st_ino, after.st_mode, after.st_size,
                    after.st_mtime_ns, digest.hexdigest(),
                )
            )
        finally:
            os.close(fd)

    def _request(self, operation: str, relative_path: str) -> ActionRequest:
        self._relative_path(relative_path)
        return ActionRequest(
            category="filesystem",
            operation=operation,
            target="/workspace/" + relative_path,
            action_id=f"fs-{uuid.uuid4().hex}",
            actor="guarded_workspace_tool",
        )

    def read_text(self, relative_path: str, encoding: str = "utf-8") -> tuple[GuardResult, str | None]:
        path = self._path(relative_path)
        expected = [self._fingerprint(path)]

        def state_provider() -> str:
            expected[0] = self._fingerprint(self._path(relative_path))
            return expected[0]

        def operation() -> str:
            current = self._path(relative_path)
            if self._fingerprint(current) != expected[0]:
                raise RuntimeError("File changed after policy/approval check; read refused")
            fd = os.open(current, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            try:
                opened = os.fstat(fd)
                with os.fdopen(os.dup(fd), "rb") as stream:
                    raw = stream.read()
                after = os.fstat(fd)
                if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
                ):
                    raise RuntimeError("File changed during read; refusing to return potentially inconsistent content")
                if self._fingerprint(current) != expected[0]:
                    raise RuntimeError("File changed during read; refusing to return potentially inconsistent content")
                return raw.decode(encoding)
            finally:
                os.close(fd)

        result, value = self.gate.perform(
            self._request("read", relative_path), operation, target_state_provider=state_provider
        )
        return result, value

    def write_text(
        self, relative_path: str, content: str, encoding: str = "utf-8"
    ) -> GuardResult:
        path = self._path(relative_path, allow_missing_leaf=True)
        expected = [self._fingerprint(path)]

        def state_provider() -> str:
            expected[0] = self._fingerprint(self._path(relative_path, allow_missing_leaf=True))
            return expected[0]

        def operation() -> str:
            current = self._path(relative_path, allow_missing_leaf=True)
            if self._fingerprint(current) != expected[0]:
                raise RuntimeError("File changed after policy/approval check; write refused")
            flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            if expected[0] == "missing":
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(current, flags, 0o600)
            try:
                if expected[0] != "missing":
                    before = os.fstat(fd)
                    if self._fingerprint(current) != expected[0]:
                        raise RuntimeError("File changed while opening for write")
                    digest = hashlib.sha256()
                    while True:
                        chunk = os.read(fd, 1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                    if digest.hexdigest() != expected[0].split(":")[-1]:
                        raise RuntimeError("File content changed while opening for write")
                    os.lseek(fd, 0, os.SEEK_SET)
                    os.ftruncate(fd, 0)
                payload = content.encode(encoding)
                view = memoryview(payload)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
                return "written"
            finally:
                os.close(fd)

        result, _value = self.gate.perform(
            self._request("write", relative_path), operation, target_state_provider=state_provider
        )
        return result

    def delete_file(self, relative_path: str) -> GuardResult:
        """Delete one regular file by first moving it to a private same-directory quarantine."""
        path = self._path(relative_path)
        expected = [self._fingerprint(path)]

        def state_provider() -> str:
            expected[0] = self._fingerprint(self._path(relative_path))
            return expected[0]

        def operation() -> str:
            current = self._path(relative_path)
            if self._fingerprint(current) != expected[0]:
                raise RuntimeError("File changed after policy/approval check; delete refused")
            quarantine = current.with_name(f".agent-boundary-delete-{uuid.uuid4().hex}")
            os.rename(current, quarantine)
            try:
                if self._fingerprint(quarantine) != expected[0]:
                    if not current.exists():
                        os.rename(quarantine, current)
                    raise RuntimeError("Moved target did not match approved file state; delete refused")
                quarantine.unlink()
            except Exception:
                if quarantine.exists() and not current.exists():
                    os.rename(quarantine, current)
                raise
            return "deleted"

        result, _value = self.gate.perform(
            self._request("delete", relative_path), operation, target_state_provider=state_provider
        )
        return result
