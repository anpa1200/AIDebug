import subprocess
import sys
from pathlib import Path

from scripts import check_release_metadata

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check_release_metadata.py"


def test_release_metadata_is_consistent():
    result = subprocess.run(
        [sys.executable, str(CHECKER)],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_release_metadata_rejects_wrong_tag():
    result = subprocess.run(
        [sys.executable, str(CHECKER), "--tag", "v0.0.0"],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode != 0
    assert "does not match package version" in result.stderr


def test_release_metadata_accepts_matching_tag_for_prepared_release():
    version = check_release_metadata.config_version()
    result = subprocess.run(
        [sys.executable, str(CHECKER), "--tag", f"v{version}"],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_release_metadata_detects_unreleased_changes(tmp_path, monkeypatch):
    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\n## Unreleased\n\n- Pending change.\n\n"
        "## 1.2.0 - 2026-08-08\n\n- Released change.\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(check_release_metadata, "ROOT", tmp_path)
    assert check_release_metadata.has_unreleased_changes() is True
