#!/usr/bin/env python3
"""Bootstrap pip's patched CA bundle before any package-index downloads.

The direct wheel URL and SHA-256 come from the Python security advisory:
https://discuss.python.org/t/109576
This script uses only the standard library and never downgrades a newer pip.
"""

from __future__ import annotations

import importlib.metadata
import re
import subprocess
import sys

MINIMUM_PIP = (26, 2, 2)
PIP_WHEEL = (
    "https://files.pythonhosted.org/packages/3f/06/"
    "3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/"
    "pip-26.2.2-py3-none-any.whl"
    "#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
)


def pip_is_safe(version: str) -> bool:
    """Accept stable releases only; unknown versions must be reviewed manually."""
    match = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?(?:\.post\d+)?(?:\+[a-zA-Z0-9.]+)?", version)
    if match is None:
        raise RuntimeError(f"Cannot verify pip version {version!r}; install a stable pip >=26.2.2")
    release = tuple(int(part or 0) for part in match.groups())
    return release >= MINIMUM_PIP


def bootstrap() -> None:
    try:
        current = importlib.metadata.version("pip")
    except importlib.metadata.PackageNotFoundError as exc:
        raise RuntimeError("pip is missing; create a venv with pip or run python -m ensurepip first") from exc
    if pip_is_safe(current):
        print(f"pip {current} already meets the patched CA-bundle floor.")
        return
    subprocess.run(
        [
            sys.executable,
            "-m", "pip",
            "--isolated",
            "--disable-pip-version-check",
            "install",
            "--no-index",
            "--no-deps",
            "--no-cache-dir",
            "--only-binary=:all:",
            "--upgrade",
            PIP_WHEEL,
        ],
        check=True,
    )
    current = importlib.metadata.version("pip")
    if not pip_is_safe(current):
        raise RuntimeError(f"pip bootstrap did not install a patched version (found {current})")
    print(f"pip {current} now meets the patched CA-bundle floor.")


if __name__ == "__main__":
    try:
        bootstrap()
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"pip bootstrap error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
