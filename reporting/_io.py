"""Small, shared helpers for safely writing generated reports."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def _restrict_permissions(fd: int, temporary_name: str) -> None:
    """Apply owner-only permissions where the host platform supports them.

    Windows does not provide POSIX mode semantics.  ``chmod`` is therefore a
    best-effort fallback there; the file also inherits the destination
    directory's ACL.
    """
    fchmod = getattr(os, "fchmod", None)
    if fchmod is not None:
        try:
            fchmod(fd, 0o600)
            return
        except OSError:
            pass
    try:
        os.chmod(temporary_name, 0o600)
    except OSError:
        if os.name != "nt":
            raise


def atomic_write_text(output_path: str | os.PathLike[str], content: str) -> str:
    """Atomically replace *output_path* with a private, UTF-8 text file.

    Report generation should never leave a truncated destination behind when a
    process is interrupted.  Creating the temporary file beside the destination
    also keeps ``os.replace`` on the same filesystem.  Replacing, rather than
    opening, the destination avoids following a pre-existing destination
    symlink.
    """
    path = Path(output_path)
    directory = path.parent
    if not directory.is_dir():
        raise FileNotFoundError(f"Report directory does not exist: {directory}")

    fd, temporary_name = tempfile.mkstemp(
        dir=directory,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    try:
        _restrict_permissions(fd, temporary_name)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

    return os.fspath(path)
