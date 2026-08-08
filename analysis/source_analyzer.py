"""Safe, bounded C-source preparation for AIDebug static analysis.

The selected source is compiled into a temporary ELF shared object. The
compiler output is never executed; it is parsed by the normal ELF pipeline and
deleted when analysis preparation finishes.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

import config

from .static_analyzer import BinaryInfo, StaticAnalyzer


class CSourceAnalyzer:
    """Compile one C translation unit to a temporary ELF analysis artifact."""

    COMPILER_CANDIDATES = ("cc", "gcc", "clang")

    def __init__(self, compiler: str | None = None, sandbox: str | None = None):
        self.compiler = compiler or self._find_compiler()
        self.sandbox = sandbox

    @classmethod
    def _find_compiler(cls) -> str:
        for candidate in cls.COMPILER_CANDIDATES:
            resolved = shutil.which(candidate)
            if resolved:
                return os.fspath(Path(resolved).resolve())
        raise RuntimeError(
            "C source analysis requires an ELF-capable C compiler "
            "(install cc, gcc, or clang)"
        )

    def analyze(self, path: str | os.PathLike[str]) -> BinaryInfo:
        source_path = Path(path).expanduser().resolve()
        if source_path.suffix.lower() != ".c":
            raise ValueError("C source analysis accepts files with the .c extension")

        source_data = self._read_source(source_path)
        source_sha256 = hashlib.sha256(source_data).hexdigest()

        with tempfile.TemporaryDirectory(prefix="aidebug-c-source-") as temp_directory:
            sandbox_source_path = Path(temp_directory) / "input.c"
            output_path = Path(temp_directory) / "compiled-source.so"
            self._write_private_file(sandbox_source_path, source_data)
            self._compile(sandbox_source_path, output_path)
            try:
                with output_path.open("rb") as compiled_file:
                    magic = compiled_file.read(4)
                if magic != b"\x7fELF":
                    raise RuntimeError(
                        "The available C compiler did not produce an ELF artifact; "
                        "C source analysis currently targets ELF"
                    )
            except OSError as exc:
                raise RuntimeError(f"Unable to inspect compiled C artifact: {exc}") from exc

            info = StaticAnalyzer().analyze(os.fspath(output_path))

        # Keep the selected source as the case identity while retaining the
        # compiled artifact hash for provenance. raw_data already contains the
        # bounded ELF bytes required by the disassembler.
        info.path = os.fspath(source_path)
        info.filename = source_path.name
        info.sha256 = source_sha256
        info.file_format = "C/ELF"
        info.analysis_origin = "C source compiled in a filesystem sandbox to temporary ELF (not executed)"
        info.compiled_sha256 = hashlib.sha256(info.raw_data).hexdigest()
        return info

    @staticmethod
    def _read_source(source_path: Path) -> bytes:
        try:
            path_stat = source_path.stat()
        except OSError as exc:
            raise ValueError(f"Unable to inspect C source path: {exc}") from exc
        if not stat.S_ISREG(path_stat.st_mode):
            raise ValueError("C source path must point to a regular file")
        if path_stat.st_size > config.MAX_C_SOURCE_SIZE_BYTES:
            raise ValueError(
                f"C source is too large ({path_stat.st_size} bytes); maximum is "
                f"{config.MAX_C_SOURCE_SIZE_BYTES} bytes"
            )

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(source_path, flags)
        except OSError as exc:
            raise ValueError(f"Unable to open C source path: {exc}") from exc
        with os.fdopen(descriptor, "rb") as source_file:
            opened_stat = os.fstat(source_file.fileno())
            if not stat.S_ISREG(opened_stat.st_mode):
                raise ValueError("C source path must point to a regular file")
            if opened_stat.st_size > config.MAX_C_SOURCE_SIZE_BYTES:
                raise ValueError(
                    f"C source is too large ({opened_stat.st_size} bytes); maximum is "
                    f"{config.MAX_C_SOURCE_SIZE_BYTES} bytes"
                )
            source_data = source_file.read(config.MAX_C_SOURCE_SIZE_BYTES + 1)

        if len(source_data) > config.MAX_C_SOURCE_SIZE_BYTES:
            raise ValueError(
                f"C source exceeds the {config.MAX_C_SOURCE_SIZE_BYTES}-byte analysis limit"
            )
        if b"\x00" in source_data:
            raise ValueError("C source contains a NUL byte and was rejected")
        return source_data

    @staticmethod
    def _write_private_file(path: Path, data: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise RuntimeError(f"Unable to prepare sandboxed C source: {exc}") from exc
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)

    def _compile(self, source_path: Path, output_path: Path) -> None:
        compiler_name = Path(self.compiler).name.lower()
        error_limit = "-ferror-limit=20" if "clang" in compiler_name else "-fmax-errors=20"
        compiler_command = [
            self.compiler,
            "-x",
            "c",
            "-std=c11",
            "-O0",
            "-g",
            "-fPIC",
            "-shared",
            "-nostartfiles",
            "-fno-inline",
            "-fno-omit-frame-pointer",
            "-fdiagnostics-color=never",
            error_limit,
            "-Wl,--build-id=none",
            "/work/input.c",
            "-o",
            "/work/compiled-source.so",
        ]
        sandbox = self.sandbox or shutil.which("bwrap")
        if not sandbox:
            raise RuntimeError(
                "C source analysis requires Bubblewrap (bwrap) so the compiler cannot "
                "read unrelated host files"
            )
        sandbox = os.fspath(Path(sandbox).resolve())
        private_tmp = PurePosixPath("/", "tmp").as_posix()
        command = [
            sandbox,
            "--die-with-parent",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--new-session",
        ]
        for host_path in ("/usr", "/bin", "/lib", "/lib64"):
            if Path(host_path).exists():
                command.extend(("--ro-bind", host_path, host_path))
        command.extend((
            "--dev",
            "/dev",
            "--tmpfs",
            # This path is a private tmpfs created inside Bubblewrap.
            private_tmp,
            "--bind",
            os.fspath(output_path.parent),
            "/work",
            "--chdir",
            "/work",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "HOME",
            "/work",
            "--setenv",
            "TMPDIR",
            # TMPDIR points to the private tmpfs above.
            private_tmp,
            "--setenv",
            "LC_ALL",
            "C",
            *compiler_command,
        ))
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": os.fspath(output_path.parent),
            "TMPDIR": os.fspath(output_path.parent),
            "LC_ALL": "C",
        }

        start_new_session = os.name != "nt"
        try:
            process = subprocess.Popen(
                command,
                cwd=os.fspath(output_path.parent),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                start_new_session=start_new_session,
            )
        except OSError as exc:
            raise RuntimeError(f"Unable to start C compiler: {exc}") from exc

        try:
            stdout, stderr = process.communicate(
                timeout=config.C_SOURCE_COMPILE_TIMEOUT_SECONDS
            )
        except subprocess.TimeoutExpired as exc:
            if start_new_session:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            process.communicate()
            raise RuntimeError(
                "C compilation exceeded the "
                f"{config.C_SOURCE_COMPILE_TIMEOUT_SECONDS:g}-second limit"
            ) from exc

        if process.returncode != 0:
            diagnostic = (stderr or stdout).decode("utf-8", errors="replace").strip()
            if len(diagnostic) > 4_000:
                diagnostic = diagnostic[:4_000] + "\n[compiler diagnostics truncated]"
            raise ValueError(
                "C compilation failed"
                + (f":\n{diagnostic}" if diagnostic else " without diagnostics")
            )
