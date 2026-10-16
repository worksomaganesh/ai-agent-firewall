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
