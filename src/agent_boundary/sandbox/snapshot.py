"""Metadata-only workspace snapshots and change summaries."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any


def snapshot_workspace(root: Path) -> dict[str, dict[str, Any]]:
    """Snapshot file metadata and content hashes without following symlinks.

    Git metadata is excluded because Phase 2 mounts the copied .git directory
    read-only. Special files are recorded by type but are never opened.
    """
    root = root.resolve(strict=True)
    result: dict[str, dict[str, Any]] = {}

    for current_dir, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_dir)
        safe_dirs: list[str] = []
        names = sorted(set(dirnames + filenames))
        for name in names:
            entry = current / name
            rel = entry.relative_to(root).as_posix()
            if rel == ".git" or rel.startswith(".git/"):
                continue
            try:
                metadata = entry.lstat()
            except OSError as exc:
                raise OSError(f"Unable to snapshot workspace entry {rel!r}: {exc}") from exc

            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISLNK(metadata.st_mode):
                result[rel] = {
                    "type": "symlink",
                    "mode": mode,
                    "target": os.readlink(entry),
                }
            elif stat.S_ISDIR(metadata.st_mode):
                result[rel] = {"type": "directory", "mode": mode}
                if name in dirnames:
                    safe_dirs.append(name)
            elif stat.S_ISREG(metadata.st_mode):
                digest = hashlib.sha256()
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(entry, flags)
                try:
                    opened = os.fstat(fd)
                    if not stat.S_ISREG(opened.st_mode):
                        raise OSError(f"Workspace entry changed type during snapshot: {rel!r}")
                    with os.fdopen(fd, "rb", closefd=False) as handle:
                        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                            digest.update(chunk)
                finally:
                    os.close(fd)
                result[rel] = {
                    "type": "file",
                    "mode": mode,
                    "size": metadata.st_size,
                    "sha256": digest.hexdigest(),
                }
            else:
                result[rel] = {"type": "special", "mode": mode}

        dirnames[:] = safe_dirs

    return dict(sorted(result.items()))


def diff_snapshots(
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Compare snapshots and classify added, deleted, and changed workspace entries."""
    added: list[dict[str, Any]] = []
    deleted: list[dict[str, Any]] = []
    modified: list[dict[str, Any]] = []

    for path in sorted(after.keys() - before.keys()):
        added.append({"path": path, "after": after[path]})
    for path in sorted(before.keys() - after.keys()):
        deleted.append({"path": path, "before": before[path]})
    for path in sorted(before.keys() & after.keys()):
        if before[path] != after[path]:
            modified.append({"path": path, "before": before[path], "after": after[path]})

    return {"added": added, "modified": modified, "deleted": deleted}


def changed_path_count(diff: dict[str, list[dict[str, Any]]]) -> int:
    """Return total count of added, modified, and deleted entries."""
    return sum(len(diff[key]) for key in ("added", "modified", "deleted"))
