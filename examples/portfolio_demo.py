"""Identify a freshly generated empty ZIP through the real offline CLI."""
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="aidebug-portfolio-") as directory:
    fixture = Path(directory) / "renamed.dat"
    with zipfile.ZipFile(fixture, "w"):
        pass
    result = subprocess.run([sys.executable, str(root / "main.py"), "--identify", str(fixture), "--offline"], cwd=root, capture_output=True, text=True, check=True)
    # Preserve the actual CLI evidence rather than inventing a report.
    print(result.stdout, end="")
    data = json.loads(result.stdout)
    assert data["mime_type"] == "application/zip", data
    assert data["ai_used"] is False, data
    assert data["size"] == 22, data
    print("PASS: renamed empty ZIP identified from bytes; AI unused; sample never executed")
