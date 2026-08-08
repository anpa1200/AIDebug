"""Compile and analyze trusted learning functions without executing them."""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from analysis import Disassembler, GhidraDecompiler, StaticAnalyzer
from analysis.decompiler import DecompilerError

from .catalog import Lesson


class LearningAnalysisError(RuntimeError):
    """The real learning artifact could not be compiled or analyzed."""


@dataclass(frozen=True)
class AnalyzedLesson:
    lesson: Lesson
    source: str
    assembly: str
    pseudocode: str
    function_address: int
    artifact_sha256: str
    compiler: str
    decompiler: str
    warning: str


class LiveLearningAnalyzer:
    """Build one trusted corpus and inspect one real function within it."""

    COMPILE_TIMEOUT_SECONDS = 60.0
    COMPILER_NAMES = ("cc", "gcc", "clang")

    def __init__(
        self,
        *,
        compiler: str | os.PathLike[str] | None = None,
        ghidra_headless: str | os.PathLike[str] | None = None,
        static_analyzer_factory: Callable[[], StaticAnalyzer] = StaticAnalyzer,
        disassembler_factory: Callable = Disassembler,
        decompiler_factory: Callable = GhidraDecompiler,
    ):
        self.compiler = self._find_compiler(compiler)
        self.ghidra_headless = ghidra_headless
        self._static_analyzer_factory = static_analyzer_factory
        self._disassembler_factory = disassembler_factory
        self._decompiler_factory = decompiler_factory

    def analyze(self, lesson: Lesson) -> AnalyzedLesson:
        corpus = self._read_corpus()
        source = self._extract_function_source(corpus, lesson.lesson_id)

        with tempfile.TemporaryDirectory(prefix="aidebug-learning-") as temporary:
            working = Path(temporary)
            source_path = working / "learning-functions.c"
            artifact_path = working / "learning-functions.so"
            source_path.write_text(corpus, encoding="utf-8")
            source_path.chmod(0o600)
            self._compile(source_path, artifact_path)

            info = self._static_analyzer_factory().analyze(os.fspath(artifact_path))
            if info.file_format != "ELF":
                raise LearningAnalysisError(
                    f"Learning compiler produced {info.file_format}, but an ELF artifact is required"
                )
            symbol = self._function_symbol(info, lesson.function_name)
            address = int(symbol["address"])
            disassembler = self._disassembler_factory(info)
            function = disassembler.get_function(address)
            if function is None or not function.instructions:
                raise LearningAnalysisError(
                    f"AIDebug could not disassemble compiled function {lesson.function_name}"
                )

            linear_instructions = self._decode_complete_symbol(
                info,
                disassembler,
                address,
                int(symbol.get("size", 0)),
            )
            assembly = self._render_assembly(linear_instructions)
            try:
                decompiled = self._decompiler_factory(
                    info,
                    executable=self.ghidra_headless,
                ).decompile([address]).get(address)
            except DecompilerError as exc:
                raise LearningAnalysisError(str(exc)) from exc
            if decompiled is None or not decompiled.code.strip():
                raise LearningAnalysisError(
                    f"Ghidra did not return pseudo-code for {lesson.function_name}"
                )

            return AnalyzedLesson(
                lesson=lesson,
                source=source,
                assembly=assembly,
                pseudocode=decompiled.code,
                function_address=address,
                artifact_sha256=info.sha256,
                compiler=self._compiler_identity(),
                decompiler=decompiled.backend,
                warning=decompiled.warning,
            )

    @classmethod
    def _find_compiler(cls, explicit: str | os.PathLike[str] | None) -> str:
        if explicit:
            candidate = Path(explicit).expanduser()
            try:
                resolved = candidate.resolve(strict=True)
            except OSError as exc:
                raise LearningAnalysisError(f"Unable to inspect learning compiler: {exc}") from exc
            return cls._validate_compiler(resolved)

        for name in cls.COMPILER_NAMES:
            resolved = shutil.which(name)
            if resolved:
                return cls._validate_compiler(Path(resolved).resolve())
        raise LearningAnalysisError(
            "Learning Mode requires an ELF-capable cc, gcc, or clang compiler"
        )

    @staticmethod
    def _validate_compiler(path: Path) -> str:
        try:
            mode = path.stat().st_mode
        except OSError as exc:
            raise LearningAnalysisError(f"Unable to inspect learning compiler: {exc}") from exc
        if not stat.S_ISREG(mode) or not os.access(path, os.X_OK):
            raise LearningAnalysisError(
                f"Learning compiler is not an executable regular file: {path}"
            )
        return os.fspath(path)

    @staticmethod
    def _read_corpus() -> str:
        resource = files("learning").joinpath("functions.c")
        try:
            return resource.read_text(encoding="utf-8")
        except OSError as exc:
            raise LearningAnalysisError(f"Unable to read bundled learning corpus: {exc}") from exc

    @staticmethod
    def _extract_function_source(corpus: str, lesson_id: str) -> str:
        escaped = re.escape(lesson_id)
        pattern = re.compile(
            rf"/\* AIDEBUG_LESSON_BEGIN {escaped} \*/\s*(.*?)\s*"
            rf"/\* AIDEBUG_LESSON_END {escaped} \*/",
            re.DOTALL,
        )
        match = pattern.search(corpus)
        if match is None:
            raise LearningAnalysisError(
                f"Bundled source is missing function body for lesson {lesson_id}"
            )
        return match.group(1).strip()

    def _compile(self, source_path: Path, artifact_path: Path) -> None:
        command = [
            self.compiler,
            "-std=c11",
            "-O1",
            "-g",
            "-shared",
            "-fPIC",
            "-fno-inline",
            "-fno-builtin",
            "-fno-tree-vectorize",
            "-fno-stack-protector",
            "-Wall",
            "-Wextra",
            "-Werror",
            os.fspath(source_path),
            "-o",
            os.fspath(artifact_path),
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=os.fspath(source_path.parent),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=self.COMPILE_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise LearningAnalysisError(f"Unable to compile learning corpus: {exc}") from exc
        if completed.returncode != 0:
            diagnostic = (completed.stderr or completed.stdout).decode(
                "utf-8", errors="replace"
            )[:4000]
            raise LearningAnalysisError(
                "Learning corpus compilation failed"
                + (f":\n{diagnostic.strip()}" if diagnostic.strip() else "")
            )
        try:
            artifact_stat = artifact_path.stat()
        except OSError as exc:
            raise LearningAnalysisError(f"Compiler did not create an analysis artifact: {exc}") from exc
        if not stat.S_ISREG(artifact_stat.st_mode) or artifact_stat.st_size == 0:
            raise LearningAnalysisError("Compiler produced an invalid learning artifact")

    @staticmethod
    def _function_symbol(info, function_name: str) -> dict:
        matches = [
            symbol
            for symbol in info.function_symbols
            if symbol.get("name") == function_name
        ]
        if len(matches) != 1:
            raise LearningAnalysisError(
                f"Expected one compiled symbol named {function_name}; found {len(matches)}"
            )
        return matches[0]

    @staticmethod
    def _decode_complete_symbol(info, disassembler, address: int, size: int):
        if size <= 0:
            raise LearningAnalysisError(
                f"Compiled symbol at 0x{address:x} does not provide a usable size"
            )
        for section in info.sections:
            start = int(section.virtual_address)
            end = start + len(section.data)
            if start <= address and address + size <= end:
                offset = address - start
                code = section.data[offset:offset + size]
                instructions = list(disassembler.cs.disasm(code, address))
                if instructions and sum(len(item.bytes) for item in instructions) == size:
                    return instructions
                raise LearningAnalysisError(
                    f"AIDebug did not decode the complete {size}-byte symbol at 0x{address:x}"
                )
        raise LearningAnalysisError(
            f"Compiled symbol at 0x{address:x} is outside an analyzed section"
        )

    @staticmethod
    def _render_assembly(instructions) -> str:
        lines = []
        for instruction in instructions:
            raw_bytes = getattr(instruction, "raw_bytes", None)
            if raw_bytes is None:
                raw_bytes = bytes(instruction.bytes)
            encoded = raw_bytes.hex(" ")
            operation = f"{instruction.mnemonic} {instruction.op_str}".rstrip()
            lines.append(f"0x{instruction.address:016x}  {encoded:<31}  {operation}")
        return "\n".join(lines)

    def _compiler_identity(self) -> str:
        try:
            completed = subprocess.run(
                [self.compiler, "--version"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=5,
                check=False,
            )
            first_line = completed.stdout.decode("utf-8", errors="replace").splitlines()[0]
        except (OSError, subprocess.TimeoutExpired, IndexError):
            first_line = Path(self.compiler).name
        return first_line[:300]
