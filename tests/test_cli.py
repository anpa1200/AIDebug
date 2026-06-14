import subprocess
import sys


def test_main_help_runs():
    result = subprocess.run(
        [sys.executable, "main.py", "--help"],
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0
    assert "AIDebug" in result.stdout
    assert "--binary" in result.stdout


def test_session_list_without_api_key(tmp_path):
    db_path = tmp_path / "traces.db"
    result = subprocess.run(
        [sys.executable, "main.py", "--db", str(db_path), "--list-sessions"],
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0
    assert "No analysis sessions found" in result.stdout
