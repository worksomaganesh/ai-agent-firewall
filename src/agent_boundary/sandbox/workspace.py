"""Create a reviewable private workspace copy with known secret material omitted."""

from __future__ import annotations

import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path


class WorkspacePreparationError(ValueError):
    """Raised when a workspace cannot be staged without unsafe ambiguity."""


@dataclass(frozen=True)
class StagingSummary:
    """Counts of paths excluded while preparing a private sandbox workspace."""

    secret_paths_omitted: int
    metadata_paths_omitted: int
    special_files_omitted: int


_SECRET_NAMES = {
    ".netrc",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "credentials",
    "credentials.json",
    "token",
    "token.json",
}
_SECRET_DIRS = {".ssh", ".aws", ".gnupg", ".kube", ".secrets"}
_SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".p8")
_STANDARD_GIT_CONFIG = (
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    "\tfilemode = true\n"
    "\tbare = false\n"
    "\tlogallrefupdates = true\n"
)


def _remove_path(path: Path) -> None:
    """Remove a path from the copied workspace without following symlinks."""
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if stat.S_ISDIR(mode) and not stat.S_ISLNK(mode):
        shutil.rmtree(path)
    else:
        path.unlink()


def _is_sensitive_file_name(name: str) -> bool:
    folded = name.casefold()
    return (
        folded.startswith(".env")
        or folded in _SECRET_NAMES
        or folded.endswith(_SECRET_SUFFIXES)
    )


def _is_sensitive_directory_name(name: str) -> bool:
    return name.casefold() in _SECRET_DIRS


def prepare_workspace_copy(source: Path, destination: Path) -> StagingSummary:
    """Copy source to destination while omitting common credentials and host hooks.

    Symlinks are copied as links, never dereferenced. The original source tree is
    never modified. A normal .git directory is retained with a synthetic config
    and empty hooks directory; worktrees whose .git is a file are rejected.
    """
    source = source.expanduser().resolve(strict=True)
    if not source.is_dir():
        raise WorkspacePreparationError(f"Workspace is not a directory: {source}")
    if source == Path("/") or source == Path.home().expanduser().resolve():
        raise WorkspacePreparationError(
            "Refusing to stage the filesystem root or home directory; choose a project directory"
        )

    source_git = source / ".git"
    if source_git.is_symlink() or (os.path.lexists(source_git) and not source_git.is_dir()):
        raise WorkspacePreparationError(
            "Git worktrees and .git file indirections are not supported by this Phase 2 runner"
        )
    if (source_git / "commondir").exists():
        raise WorkspacePreparationError(
            "Linked Git worktrees are not supported by this Phase 2 runner"
        )

    if destination.exists() or destination.is_symlink():
        raise WorkspacePreparationError(f"Staging destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    counters = {"secrets": 0, "metadata": 0, "special": 0}

    def ignore(directory: str, names: list[str]) -> set[str]:
        current = Path(directory).relative_to(source)
        ignored: set[str] = set()
        for name in names:
            relative = current / name
            parts = relative.parts
            entry = Path(directory) / name
            try:
                entry_mode = entry.lstat().st_mode
            except OSError:
                ignored.add(name)
                counters["special"] += 1
                continue

            if _is_sensitive_file_name(name) or _is_sensitive_directory_name(name):
                ignored.add(name)
                counters["secrets"] += 1
                continue

            if relative in (Path(".git/config"), Path(".git/config.worktree")):
                ignored.add(name)
                counters["metadata"] += 1
                continue
            if relative == Path(".git/hooks"):
                ignored.add(name)
                counters["metadata"] += 1
                continue
            if relative == Path(".git/objects/info/alternates"):
                ignored.add(name)
                counters["metadata"] += 1
                continue
            if name == ".git" and current != Path("."):
                ignored.add(name)
                counters["metadata"] += 1
                continue

            if not (stat.S_ISDIR(entry_mode) or stat.S_ISREG(entry_mode) or stat.S_ISLNK(entry_mode)):
                ignored.add(name)
                counters["special"] += 1
                continue

            # Do not accidentally traverse nested repository metadata.
            if ".git" in parts and parts[0] != ".git":
                ignored.add(name)
                counters["metadata"] += 1

        return ignored

    try:
        shutil.copytree(source, destination, symlinks=True, ignore=ignore)
    except (OSError, shutil.Error) as exc:
        raise WorkspacePreparationError(f"Could not safely stage workspace: {exc}") from exc

    # A minimal config avoids copying remote URLs, credential helpers, URL rewrites,
    # includes, or custom hooks paths from the source repository.
    staged_git = destination / ".git"
    if staged_git.is_dir() and not staged_git.is_symlink():
        config_path = staged_git / "config"
        _remove_path(config_path)
        config_path.write_text(_STANDARD_GIT_CONFIG, encoding="utf-8")
        config_path.chmod(0o444)

        hooks_path = staged_git / "hooks"
        _remove_path(hooks_path)
        hooks_path.mkdir(mode=0o555, parents=True)

        alternates = staged_git / "objects" / "info" / "alternates"
        _remove_path(alternates)

    # Always construct a real, protected workflows directory. This avoids mounting
    # over a source-controlled symlink during sandbox setup.
    github_dir = destination / ".github"
    if github_dir.is_symlink() or (github_dir.exists() and not github_dir.is_dir()):
        _remove_path(github_dir)
    github_dir.mkdir(exist_ok=True)
    workflows_dir = github_dir / "workflows"
    if workflows_dir.is_symlink() or (workflows_dir.exists() and not workflows_dir.is_dir()):
        _remove_path(workflows_dir)
    workflows_dir.mkdir(exist_ok=True)

    # Symlink entries inside workflows could point outside that protected subtree.
    # Drop them in the staging copy before it is ever used as a bind-mount source.
    for current_dir, dirnames, filenames in os.walk(workflows_dir, topdown=True, followlinks=False):
        current = Path(current_dir)
        for name in list(dirnames):
            path = current / name
            if path.is_symlink():
                path.unlink()
                dirnames.remove(name)
                counters["metadata"] += 1
        for name in filenames:
            path = current / name
            if path.is_symlink():
                path.unlink()
                counters["metadata"] += 1

    pyproject = destination / "pyproject.toml"
    if pyproject.is_symlink() or (pyproject.exists() and not pyproject.is_file()):
        _remove_path(pyproject)
        pyproject.write_text("", encoding="utf-8")
        pyproject.chmod(0o444)
        counters["metadata"] += 1

    return StagingSummary(
        secret_paths_omitted=counters["secrets"],
        metadata_paths_omitted=counters["metadata"],
        special_files_omitted=counters["special"],
    )
