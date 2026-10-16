"""Tests for safe Phase 3 session review and staged-copy cleanup."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agent_boundary.cli import app

runner = CliRunner()


def make_session(root: Path) -> Path:
    session = root / "ab-run-test"
    session.mkdir()
    (session / "audit.jsonl").write_text("audit evidence\n", encoding="utf-8")
    (session / "session-summary.json").write_text(
        json.dumps({"session_id": "ab-run-test", "sandbox_started": True, "exit_code": 0}),
        encoding="utf-8",
    )
    (session / "diff.json").write_text(
        json.dumps(
            {
                "added": [{"path": "new.py", "after": {"type": "file"}}],
                "modified": [{"path": "app.py", "before": {}, "after": {}}],
                "deleted": [],
            }
        ),
        encoding="utf-8",
    )
    (session / "workspace").mkdir()
    (session / "workspace" / "app.py").write_text("staged change\n", encoding="utf-8")
    (session / "workspace" / "new.py").write_text("new staged file\n", encoding="utf-8")
    (session / "session_report.md").write_text("report\n", encoding="utf-8")
    (session / "baseline-manifest.json").write_text("{}\n", encoding="utf-8")
    (session / "final-manifest.json").write_text("{}\n", encoding="utf-8")
    return session


def test_review_session_lists_paths_without_copying_changes(tmp_path: Path) -> None:
    session = make_session(tmp_path)
    result = runner.invoke(app, ["review-session", str(session)])
    assert result.exit_code == 0, result.output
    assert "new.py" in result.output
    assert "app.py" in result.output
    assert (session / "workspace" / "app.py").read_text(encoding="utf-8") == "staged change\n"


def test_discard_requires_explicit_confirmation_and_preserves_evidence(tmp_path: Path) -> None:
    session = make_session(tmp_path)
    refused = runner.invoke(app, ["discard-workspace-copy", str(session)])
    assert refused.exit_code != 0
    assert (session / "workspace").is_dir()

    result = runner.invoke(app, ["discard-workspace-copy", str(session), "--yes"])
    assert result.exit_code == 0, result.output
    assert not (session / "workspace").exists()
    assert (session / "audit.jsonl").is_file()
    assert (session / "session_report.md").is_file()
    assert (session / "diff.json").is_file()
    assert (session / "baseline-manifest.json").is_file()
    assert (session / "final-manifest.json").is_file()



def test_export_reviewed_changes_copies_only_changed_files_without_overwrite(tmp_path: Path) -> None:
    session = make_session(tmp_path)
    destination = tmp_path / "review-export"
    result = runner.invoke(app, ["export-reviewed-changes", str(session), str(destination)])
    assert result.exit_code == 0, result.output
    assert (destination / "app.py").read_text(encoding="utf-8") == "staged change\n"
    assert (destination / "new.py").read_text(encoding="utf-8") == "new staged file\n"
    assert (destination / "app.py").stat().st_mode & 0o777 == 0o600
    assert (session / "workspace" / "app.py").read_text(encoding="utf-8") == "staged change\n"

    second = runner.invoke(app, ["export-reviewed-changes", str(session), str(destination)])
    assert second.exit_code != 0
    assert (destination / "app.py").read_text(encoding="utf-8") == "staged change\n"


def test_export_reviewed_changes_rejects_path_traversal(tmp_path: Path) -> None:
    session = make_session(tmp_path)
    diff_path = session / "diff.json"
    diff = json.loads(diff_path.read_text(encoding="utf-8"))
    diff["added"] = [{"path": "../outside.txt", "after": {"type": "file"}}]
    diff_path.write_text(json.dumps(diff), encoding="utf-8")
    destination = tmp_path / "review-export"
    result = runner.invoke(app, ["export-reviewed-changes", str(session), str(destination)])
    assert result.exit_code != 0
    assert not (tmp_path / "outside.txt").exists()


def test_export_reviewed_changes_rejects_symlink_sources(tmp_path: Path) -> None:
    session = make_session(tmp_path)
    external = tmp_path / "outside-secret.txt"
    external.write_text("do not export", encoding="utf-8")
    (session / "workspace" / "link.py").symlink_to(external)
    diff_path = session / "diff.json"
    diff = json.loads(diff_path.read_text(encoding="utf-8"))
    diff["added"] = [{"path": "link.py", "after": {"type": "file"}}]
    diff_path.write_text(json.dumps(diff), encoding="utf-8")
    destination = tmp_path / "review-export"
    result = runner.invoke(app, ["export-reviewed-changes", str(session), str(destination)])
    assert result.exit_code != 0
    assert not (destination / "link.py").exists()
