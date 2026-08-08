#!/usr/bin/env python3
"""Validate required and forbidden files in AIDebug wheels and source archives."""

from __future__ import annotations

import argparse
import tarfile
import zipfile
from pathlib import Path

REQUIRED_WHEEL_SUFFIXES = {
    "analysis/data/AIDebugDecompile.java",
    "analysis/data/flirt_sigs.json",
    "debugger/active.py",
    "debugger/scripts/network_tracer.js",
    "debugger/scripts/tracer.js",
    "debugger/scripts/unpack_detector.js",
    "learning/catalog.py",
    "learning/functions.c",
    "learning/live.py",
    "learning/renderer.py",
}
REQUIRED_SDIST_SUFFIXES = {
    "CHANGELOG.md",
    "LICENSE",
    "README.md",
    "RELEASE.md",
    "SECURITY.md",
    "analysis/data/flirt_sigs.json",
    "analysis/data/AIDebugDecompile.java",
    "assets/screenshots/README.md",
    "assets/screenshots/behavioral-patterns-tab.png",
    "assets/screenshots/control-flow-graph.png",
    "assets/screenshots/four-panel-tui.png",
    "assets/screenshots/pattern-detection-output.png",
    "assets/screenshots/tui-function-analysis.png",
    "debian/tests/smoke",
    "debugger/scripts/network_tracer.js",
    "debugger/scripts/tracer.js",
    "debugger/scripts/unpack_detector.js",
    "debugger/active.py",
    "docs/release-readiness.md",
    "examples/mock-output/aidebug-candidate.yar",
    "examples/mock-output/aidebug-report.html",
    "examples/mock-output/aidebug-session.json",
    "examples/toy_c_analysis.c",
    "learning/catalog.py",
    "learning/functions.c",
    "learning/live.py",
    "learning/renderer.py",
    "requirements-ai.txt",
    "requirements-dynamic.txt",
    "requirements.txt",
    "scripts/check_distribution.py",
    "scripts/check_docs.py",
    "scripts/check_evidence_assets.py",
    "scripts/check_release_metadata.py",
    "scripts/release-readiness.sh",
}
FORBIDDEN_PARTS = {
    ".coverage",
    ".env",
    "malware1_exe_report.html",
    "traces.db",
}


def archive_names(path: Path) -> set[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return set(archive.namelist())
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            return set(archive.getnames())
    raise ValueError(f"unsupported distribution: {path}")


def validate(path: Path) -> None:
    names = archive_names(path)
    normalized = {name.removeprefix("./") for name in names}

    for name in sorted(normalized):
        parts = Path(name).parts
        forbidden_environment = any(part == ".env" or part.startswith(".env.") for part in parts)
        forbidden_suffix = name.endswith((".pyc", ".pyo", ".db", ".db-shm", ".db-wal"))
        if any(part in FORBIDDEN_PARTS for part in parts) or forbidden_environment or forbidden_suffix:
            raise ValueError(f"{path.name} contains forbidden path: {name}")
        if name.endswith("data/flirt_sigs.json") and not name.endswith("analysis/data/flirt_sigs.json"):
            raise ValueError(f"{path.name} contains a non-canonical signature database: {name}")

    if path.suffix == ".whl":
        missing = {
            suffix
            for suffix in REQUIRED_WHEEL_SUFFIXES
            if not any(name.endswith(suffix) for name in normalized)
        }
        if missing:
            raise ValueError(f"{path.name} is missing package data: {sorted(missing)}")
    else:
        missing = {
            suffix
            for suffix in REQUIRED_SDIST_SUFFIXES
            if not any(name.endswith(suffix) for name in normalized)
        }
        if missing:
            raise ValueError(f"{path.name} is missing source-release files: {sorted(missing)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("distributions", nargs="+", type=Path)
    args = parser.parse_args()
    for distribution in args.distributions:
        validate(distribution)
        print(f"Distribution content is valid: {distribution}")


if __name__ == "__main__":
    main()
