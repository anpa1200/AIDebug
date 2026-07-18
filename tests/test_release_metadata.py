import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

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


def test_release_metadata_refuses_to_tag_unreleased_changes():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    result = subprocess.run(
        [sys.executable, str(CHECKER), "--tag", f"v{project['version']}"],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode != 0
    assert "still contains Unreleased changes" in result.stderr
