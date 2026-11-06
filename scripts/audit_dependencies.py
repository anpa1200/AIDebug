#!/usr/bin/env python3
"""Audit the installed dependency graph without creating an unpatched pip venv."""

from __future__ import annotations

import importlib.metadata
import subprocess
import sys
import tempfile
from pathlib import Path

from packaging.version import Version


def audit() -> None:
    for package, minimum in (("pip", "26.2.2"), ("certifi", "2026.10.19")):
        installed = importlib.metadata.version(package)
        if Version(installed) < Version(minimum):
            raise RuntimeError(f"{package} {installed} is below the patched TLS floor {minimum}")
    # All project extras must be installed by the caller. Exclude only our own
    # unpublished source package; every installed third-party dependency remains.
    frozen = subprocess.run(
        [
            sys.executable, "-m", "pip", "freeze", "--all",
            "--exclude", "1200km-aidebug", "--exclude", "pip",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    if not frozen.strip():
        raise RuntimeError("Refusing to audit an empty dependency snapshot")
    # Hash-bootstrapped pip has a direct_url.json, so freeze would emit a URL
    # requirement. Audit its known installed version explicitly instead.
    frozen = f"pip=={importlib.metadata.version('pip')}\n" + frozen
    with tempfile.TemporaryDirectory(prefix="aidebug-audit-") as temporary:
        requirements = Path(temporary) / "installed.txt"
        requirements.write_text(frozen, encoding="utf-8")
        # Requirement resolution in pip-audit 2.10.1 otherwise creates a venv
        # with old ensurepip certificates. These are fully resolved exact pins,
        # so disable that resolver rather than bootstrap through vulnerable TLS.
        subprocess.run(
            [
                sys.executable, "-m", "pip_audit", "--strict", "--disable-pip",
                "--no-deps", "--requirement", str(requirements),
            ],
            check=True,
        )


if __name__ == "__main__":
    audit()
