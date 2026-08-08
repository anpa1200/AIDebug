"""Bounded integration with Ghidra's headless native-code decompiler."""
from __future__ import annotations

import os
import shutil
import signal
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import config

from .static_analyzer import BinaryInfo


class DecompilerError(RuntimeError):
    """A real decompiler backend was unavailable or failed safely."""


@dataclass(frozen=True)
class DecompiledFunction:
    address: int
    code: str
    language: str = "c"
    backend: str = "ghidra"
    warning: str = (
        "Ghidra reconstructed C-like code from machine instructions. "
        "It is not the original source; types, names, and structure still require review."
    )


class GhidraDecompiler:
    """Run one bounded Ghidra analysis and decompile selected function addresses."""

    EXECUTABLE_ENV = "AIDEBUG_GHIDRA_HEADLESS"
    EXECUTABLE_NAMES = ("analyzeHeadless",)

    def __init__(
        self,
        binary_info: BinaryInfo,
        executable: str | os.PathLike[str] | None = None,
        *,
        timeout: float | None = None,
    ):
        self.info = binary_info
        self.executable = self.find_executable(executable)
        self.timeout = timeout or config.GHIDRA_DECOMPILE_TIMEOUT_SECONDS

    @classmethod
    def find_executable(
        cls,
        explicit: str | os.PathLike[str] | None = None,
    ) -> str:
        """Resolve an executable Ghidra ``analyzeHeadless`` launcher."""
        configured = explicit or os.environ.get(cls.EXECUTABLE_ENV, "").strip()
        if configured:
            return cls._validate_executable(Path(configured).expanduser())

        for name in cls.EXECUTABLE_NAMES:
            resolved = shutil.which(name)
            if resolved:
                return cls._validate_executable(Path(resolved))

        candidates = [
            Path("/usr/share/ghidra/support/analyzeHeadless"),
            Path("/opt/ghidra/support/analyzeHeadless"),
        ]
        local_share = Path.home() / ".local" / "share"
        for parent in (local_share, Path("/opt")):
            if parent.is_dir():
                candidates.extend(sorted(parent.glob("ghidra*/support/analyzeHeadless")))
        for candidate in candidates:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return cls._validate_executable(candidate)

        raise DecompilerError(
            "Ghidra analyzeHeadless was not found. Install Ghidra and place its support/ "
            "directory on PATH, or set AIDEBUG_GHIDRA_HEADLESS to the launcher path. "
            "AIDebug will not substitute heuristic register translation for decompilation."
        )

    @staticmethod
    def _validate_executable(path: Path) -> str:
        try:
            resolved = path.resolve(strict=True)
            mode = resolved.stat().st_mode
        except OSError as exc:
            raise DecompilerError(f"Unable to inspect Ghidra launcher: {exc}") from exc
        if not stat.S_ISREG(mode) or not os.access(resolved, os.X_OK):
            raise DecompilerError(f"Ghidra launcher is not an executable regular file: {resolved}")
        return os.fspath(resolved)

    def decompile(self, addresses: list[int]) -> dict[int, DecompiledFunction]:
        selected = self._normalize_addresses(addresses)
        if not selected:
            return {}

        with tempfile.TemporaryDirectory(prefix="aidebug-ghidra-") as temp_directory:
            working = Path(temp_directory)
            sample_path = working / "sample.bin"
            address_path = working / "addresses.txt"
            output_directory = working / "decompiled"
            project_directory = working / "project"
            output_directory.mkdir(mode=0o700)
            project_directory.mkdir(mode=0o700)
            self._write_private(sample_path, bytes(self.info.raw_data))
            self._write_private(
                address_path,
                ("\n".join(f"{address:x}" for address in selected) + "\n").encode("ascii"),
            )

            script_directory = Path(__file__).resolve().parent / "data"
            script_path = script_directory / "AIDebugDecompile.java"
            if not script_path.is_file():
                raise DecompilerError(f"Bundled Ghidra decompiler script is missing: {script_path}")

            command = [
                self.executable,
                os.fspath(project_directory),
                "AIDebugProject",
                "-import",
                os.fspath(sample_path),
                "-scriptPath",
                os.fspath(script_directory),
                "-postScript",
                script_path.name,
                os.fspath(output_directory),
                os.fspath(address_path),
                str(int(self.info.image_base)),
                str(config.GHIDRA_FUNCTION_TIMEOUT_SECONDS),
                str(config.MAX_DECOMPILED_CHARS),
                "-deleteProject",
            ]
            self._run(command, working)
            return self._read_results(selected, output_directory)

    @staticmethod
    def _normalize_addresses(addresses: list[int]) -> list[int]:
        normalized = []
        seen = set()
        for address in addresses[:config.MAX_FUNCTIONS_TO_DISCOVER]:
            if isinstance(address, bool) or not isinstance(address, int) or address < 0:
                raise ValueError("Decompiler addresses must be non-negative integers")
            if address not in seen:
                normalized.append(address)
                seen.add(address)
        return normalized

    @staticmethod
    def _write_private(path: Path, data: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise DecompilerError(f"Unable to prepare Ghidra input: {exc}") from exc
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)

    def _run(self, command: list[str], working: Path) -> None:
        environment = os.environ.copy()
        environment.update({
            "HOME": os.fspath(working),
            "XDG_CACHE_HOME": os.fspath(working / "cache"),
            "XDG_CONFIG_HOME": os.fspath(working / "config"),
            "GHIDRA_JAVA_OPTIONS": f"-Duser.home={working}",
        })
        start_new_session = os.name != "nt"
        try:
            process = subprocess.Popen(
                command,
                cwd=os.fspath(working),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                start_new_session=start_new_session,
            )
        except OSError as exc:
            raise DecompilerError(f"Unable to start Ghidra: {exc}") from exc

        try:
            stdout, stderr = process.communicate(timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            if start_new_session:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            process.communicate()
            raise DecompilerError(
                f"Ghidra decompilation exceeded the {self.timeout:g}-second limit"
            ) from exc

        if process.returncode != 0:
            diagnostic = self._diagnostic(stderr or stdout)
            raise DecompilerError(
                "Ghidra headless analysis failed"
                + (f":\n{diagnostic}" if diagnostic else " without diagnostics")
            )

    def _read_results(
        self,
        addresses: list[int],
        output_directory: Path,
    ) -> dict[int, DecompiledFunction]:
        results = {}
        for address in addresses:
            result_path = output_directory / f"{address:x}.c"
            if not result_path.is_file():
                continue
            try:
                with result_path.open("r", encoding="utf-8", errors="replace") as source:
                    code = source.read(config.MAX_DECOMPILED_CHARS + 1)
            except OSError as exc:
                raise DecompilerError(f"Unable to read Ghidra output: {exc}") from exc
            code = self._safe_text(code, config.MAX_DECOMPILED_CHARS)
            if code.strip():
                results[address] = DecompiledFunction(address=address, code=code.rstrip())

        if not results:
            error_path = output_directory / "errors.log"
            error = ""
            if error_path.is_file():
                try:
                    error = self._safe_text(
                        error_path.read_text(encoding="utf-8", errors="replace"),
                        4_000,
                    ).strip()
                except OSError:
                    pass
            raise DecompilerError(
                "Ghidra completed but did not decompile any requested functions"
                + (f":\n{error}" if error else "")
            )
        return results

    @staticmethod
    def _safe_text(value: object, limit: int) -> str:
        text = str(value or "")[:limit]
        return "".join(character for character in text if character in "\n\t" or ord(character) >= 32)

    @classmethod
    def _diagnostic(cls, data: bytes) -> str:
        return cls._safe_text(data.decode("utf-8", errors="replace"), 4_000).strip()
