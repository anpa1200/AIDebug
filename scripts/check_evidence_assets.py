#!/usr/bin/env python3
"""Verify integrity metadata for illustrative screenshots and mock outputs."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCREENSHOTS = {
    "behavioral-patterns-tab.png": (800, 363, "3e44d6fce656623c674caa318186c0d3effa4ad090a1d7f40d4f1707ef5a91b0"),
    "control-flow-graph.png": (550, 604, "48740252ad0c50192813abab3e9bf53d3394d959643b0810dc8682595bf05e4b"),
    "four-panel-tui.png": (800, 456, "9378bc38426571c94a724eb352a5e7875a7429fffe19f746f0913b7aceb44777"),
    "pattern-detection-output.png": (534, 221, "8c16eca507eb7d0d2fd05b8fd96b331b1bec738db657f596ee0953ce8910d610"),
    "tui-function-analysis.png": (800, 447, "9f0036ee08e52ac7ecaff44b0744a41af1d70e84cf325146e0d802a173856c84"),
}


def main() -> None:
    screenshot_dir = ROOT / "assets/screenshots"
    actual_files = {path.name for path in screenshot_dir.glob("*.png")}
    if actual_files != set(SCREENSHOTS):
        raise SystemExit(
            f"screenshot manifest mismatch: expected={sorted(SCREENSHOTS)}, actual={sorted(actual_files)}"
        )

    for name, (expected_width, expected_height, expected_hash) in SCREENSHOTS.items():
        data = (screenshot_dir / name).read_bytes()
        if data[:8] != b"\x89PNG\r\n\x1a\n":
            raise SystemExit(f"{name} is not a PNG")
        width, height = struct.unpack(">II", data[16:24])
        digest = hashlib.sha256(data).hexdigest()
        if (width, height) != (expected_width, expected_height) or digest != expected_hash:
            raise SystemExit(f"screenshot integrity mismatch: {name}")

    mock_dir = ROOT / "examples/mock-output"
    with (mock_dir / "aidebug-session.json").open(encoding="utf-8") as handle:
        mock_session = json.load(handle)
    if mock_session.get("_schema") != "aidebug/session/v2":
        raise SystemExit("mock JSON does not use the current AIDebug session schema")
    for key in ("binary", "session", "summary", "functions", "api_calls", "network_events", "runtime_events"):
        if key not in mock_session:
            raise SystemExit(f"mock JSON is missing the current schema field: {key}")
    if mock_session["summary"].get("mitre_techniques"):
        raise SystemExit("offline mock JSON must not claim model-generated ATT&CK conclusions")
    for name in ("aidebug-candidate.yar", "aidebug-report.html"):
        if not (mock_dir / name).read_text(encoding="utf-8").strip():
            raise SystemExit(f"empty mock output: {name}")

    print("Illustrative evidence assets match their integrity manifest.")


if __name__ == "__main__":
    main()
