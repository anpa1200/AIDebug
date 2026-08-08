"""Analyst-controlled local ELF debugging through GDB's machine interface.

This backend is intentionally separate from Frida tracing.  It executes the
selected program only after the caller explicitly chooses debug mode.
"""
from __future__ import annotations

import json
import os
import queue
import re
import shutil
import stat
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path


class ActiveDebugError(RuntimeError):
    """A bounded error from the active debugger backend."""


@dataclass(frozen=True)
class DebugStop:
    reason: str
    function: str
    address: int | None
    source: str
    line: int | None
    registers: dict[str, str] = field(default_factory=dict)
    changed_registers: dict[str, tuple[str, str]] = field(default_factory=dict)
    function_inputs: dict[str, str] = field(default_factory=dict)
    function_output: str = ""


def _decode_mi_string(value: str) -> str:
    try:
        decoded = json.loads(f'"{value}"')
    except (json.JSONDecodeError, TypeError):
        return value.replace(r'\"', '"').replace(r"\\", "\\")
    return decoded if isinstance(decoded, str) else str(decoded)


def _fields(record: str) -> dict[str, str]:
    return {
        key: _decode_mi_string(value)
        for key, value in re.findall(r'([A-Za-z0-9_-]+)="((?:\\.|[^"\\])*)"', record)
    }


class GDBMIDebugger:
    """Small synchronous GDB/MI controller with register-delta tracking."""

    def __init__(
        self,
        binary_path: str | os.PathLike[str],
        *,
        program_args: list[str] | None = None,
        executable: str | os.PathLike[str] | None = None,
        arch: str = "x86-64",
        bits: int = 64,
        os_target: str = "Linux",
        timeout: float = 15.0,
        process_factory=None,
    ):
        self.binary_path = self._validate_binary(Path(binary_path).expanduser())
        self.executable = self._find_gdb(executable)
        self.program_args = [self._bounded_arg(value) for value in (program_args or [])]
        self.arch = str(arch).lower()
        self.bits = int(bits)
        self.os_target = str(os_target).lower()
        self.timeout = max(1.0, min(float(timeout), 120.0))
        self._process_factory = process_factory or subprocess.Popen
        self._process = None
        self._records: queue.Queue[str] = queue.Queue()
        self._reader = None
        self._token = 0
        self._register_names: list[str] | None = None
        self._previous_registers: dict[str, str] = {}
        self._last_stop: DebugStop | None = None
        self._active_function = ""
        self._active_inputs: dict[str, str] = {}

    @staticmethod
    def _validate_binary(path: Path) -> str:
        try:
            resolved = path.resolve(strict=True)
            mode = resolved.stat().st_mode
        except OSError as exc:
            raise ActiveDebugError(f"Unable to inspect debug target: {exc}") from exc
        if not stat.S_ISREG(mode):
            raise ActiveDebugError(f"Debug target is not a regular file: {resolved}")
        return os.fspath(resolved)

    @staticmethod
    def _find_gdb(explicit: str | os.PathLike[str] | None) -> str:
        candidate = os.fspath(explicit) if explicit else shutil.which("gdb")
        if not candidate:
            raise ActiveDebugError("GDB was not found. Install gdb or pass --gdb PATH.")
        path = Path(candidate).expanduser()
        try:
            resolved = path.resolve(strict=True)
            mode = resolved.stat().st_mode
        except OSError as exc:
            raise ActiveDebugError(f"Unable to inspect GDB executable: {exc}") from exc
        if not stat.S_ISREG(mode) or not os.access(resolved, os.X_OK):
            raise ActiveDebugError(f"GDB path is not an executable regular file: {resolved}")
        return os.fspath(resolved)

    @staticmethod
    def _bounded_arg(value: str) -> str:
        if not isinstance(value, str) or len(value) > 4_096:
            raise ValueError("Debug arguments must be strings no longer than 4096 characters")
        if "\x00" in value or "\n" in value or "\r" in value:
            raise ValueError("Debug arguments cannot contain NUL or line breaks")
        return value

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    @property
    def last_stop(self) -> DebugStop | None:
        return self._last_stop

    def start(self) -> None:
        if self.is_running:
            return
        try:
            self._process = self._process_factory(
                [
                    self.executable,
                    "--quiet",
                    "--nx",
                    "--nh",
                    "--interpreter=mi2",
                    self.binary_path,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except OSError as exc:
            raise ActiveDebugError(f"Unable to start GDB: {exc}") from exc
        if self._process.stdin is None or self._process.stdout is None:
            raise ActiveDebugError("GDB did not provide machine-interface pipes")
        self._reader = threading.Thread(target=self._read_records, daemon=True)
        self._reader.start()
        self._command("-gdb-set pagination off")
        self._command("-gdb-set confirm off")
        self._command("-gdb-set print elements 64")
        if self.program_args:
            arguments = " ".join(json.dumps(value) for value in self.program_args)
            self._command(f"-exec-arguments {arguments}")

    def close(self) -> None:
        process = self._process
        if process is None:
            return
        if process.poll() is None:
            try:
                self._command("-gdb-exit", timeout=2.0)
            except ActiveDebugError:
                process.terminate()
                try:
                    process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2.0)
        self._process = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        del exc_type, exc, traceback
        self.close()

    def add_breakpoint(self, location: str) -> str:
        location = self._validate_location(location)
        record, _ = self._command(f"-break-insert {json.dumps(location)}")
        fields = _fields(record)
        return fields.get("number", location)

    def run(self) -> DebugStop:
        return self._control("-exec-run")

    def continue_execution(self) -> DebugStop:
        return self._control("-exec-continue")

    def step_instruction(self) -> DebugStop:
        return self._control("-exec-step-instruction")

    def next_instruction(self) -> DebugStop:
        return self._control("-exec-next-instruction")

    def finish_function(self) -> DebugStop:
        return self._control("-exec-finish")

    def registers(self) -> dict[str, str]:
        if self._register_names is None:
            record, _ = self._command("-data-list-register-names")
            match = re.search(r'register-names=\[(.*)\]', record)
            values = match.group(1) if match else ""
            self._register_names = [
                _decode_mi_string(item)
                for item in re.findall(r'"((?:\\.|[^"\\])*)"', values)
            ]
        record, _ = self._command("-data-list-register-values x")
        registers = {}
        for number, value in re.findall(
            r'\{number="(\d+)",value="((?:\\.|[^"\\])*)"\}', record
        ):
            index = int(number)
            if index < len(self._register_names) and self._register_names[index]:
                registers[self._register_names[index]] = _decode_mi_string(value)
        return registers

    def disassemble_current(self, count: int = 8) -> list[str]:
        count = max(1, min(int(count), 32))
        command = f'-interpreter-exec console {json.dumps(f"x/{count}i $pc")}'
        _, records = self._command(command)
        lines = []
        for record in records:
            if record.startswith("~\"") and record.endswith('"'):
                lines.extend(_decode_mi_string(record[2:-1]).splitlines())
        return [line for line in lines if line.strip()]

    def _control(self, command: str) -> DebugStop:
        result, records = self._command(command, wait_for_stop=True)
        stopped = next((record for record in reversed(records) if record.startswith("*stopped")), None)
        if stopped is None and result.startswith("^exit"):
            stopped = '*stopped,reason="exited"'
        if stopped is None:
            raise ActiveDebugError("GDB did not report a stopped inferior")
        stop = self._build_stop(stopped)
        self._last_stop = stop
        return stop

    def _build_stop(self, record: str) -> DebugStop:
        fields = _fields(record)
        reason = fields.get("reason", "stopped")
        function = fields.get("func", "")
        source = fields.get("fullname") or fields.get("file", "")
        address = self._parse_address(fields.get("addr"))
        line = self._parse_positive_int(fields.get("line"))
        output = fields.get("return-value") or fields.get("gdb-result-var", "")
        if reason.startswith("exited"):
            registers = {}
        else:
            registers = self.registers()
        changes = {
            name: (before, value)
            for name, value in registers.items()
            if name in self._core_registers()
            and (before := self._previous_registers.get(name)) is not None
            and before != value
        }
        current_inputs = {
            name: registers[name]
            for name in self._argument_registers()
            if name in registers
        }
        active_function = getattr(self, "_active_function", "")
        active_inputs = getattr(self, "_active_inputs", {})
        if reason == "function-finished" and active_function:
            function = active_function
            inputs = dict(active_inputs)
        else:
            if function and function != active_function:
                self._active_function = function
                self._active_inputs = dict(current_inputs)
            inputs = dict(getattr(self, "_active_inputs", {}) or current_inputs)
        if output:
            output = f"GDB return={output}"
        else:
            return_register = self._return_register()
            if reason == "function-finished" and return_register in registers:
                output = f"ABI candidate {return_register}={registers[return_register]}"
        self._previous_registers = dict(registers)
        stop = DebugStop(
            reason=reason,
            function=function,
            address=address,
            source=source,
            line=line,
            registers=registers,
            changed_registers=changes,
            function_inputs=inputs,
            function_output=output,
        )
        if reason == "function-finished":
            self._active_function = ""
            self._active_inputs = {}
        return stop

    def _argument_registers(self) -> tuple[str, ...]:
        if self.arch == "x86-64" and self.bits == 64:
            if "windows" in self.os_target:
                return ("rcx", "rdx", "r8", "r9")
            return ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
        if self.arch == "aarch64":
            return tuple(f"x{index}" for index in range(8))
        if self.arch == "arm":
            return ("r0", "r1", "r2", "r3")
        return ()

    def _return_register(self) -> str:
        if self.arch == "x86-64":
            return "rax"
        if self.arch == "x86":
            return "eax"
        if self.arch == "aarch64":
            return "x0"
        if self.arch == "arm":
            return "r0"
        return ""

    def _core_registers(self) -> set[str]:
        if self.arch == "x86-64":
            return {
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags",
            }
        if self.arch == "x86":
            return {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags"}
        if self.arch == "aarch64":
            return {*(f"x{index}" for index in range(31)), "sp", "pc", "cpsr"}
        if self.arch == "arm":
            return {*(f"r{index}" for index in range(16)), "sp", "lr", "pc", "cpsr"}
        return set(self._previous_registers)

    @staticmethod
    def _validate_location(location: str) -> str:
        if not isinstance(location, str):
            raise ValueError("Breakpoint location must be text")
        location = location.strip()
        if not location or len(location) > 512 or any(ch in location for ch in "\x00\r\n"):
            raise ValueError("Breakpoint location is empty, too long, or contains a line break")
        return location

    def _read_records(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        for line in process.stdout:
            self._records.put(line.rstrip("\r\n"))
        self._records.put("__AIDEBUG_GDB_EOF__")

    def _command(
        self,
        command: str,
        *,
        wait_for_stop: bool = False,
        timeout: float | None = None,
    ) -> tuple[str, list[str]]:
        process = self._process
        if process is None or process.poll() is not None or process.stdin is None:
            raise ActiveDebugError("GDB is not running")
        if "\n" in command or "\r" in command:
            raise ValueError("GDB/MI commands cannot contain line breaks")
        self._token += 1
        token = self._token
        try:
            process.stdin.write(f"{token}{command}\n")
            process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise ActiveDebugError(f"Unable to send a command to GDB: {exc}") from exc

        deadline = time.monotonic() + (timeout or self.timeout)
        records = []
        result = ""
        saw_running = False
        while time.monotonic() < deadline:
            remaining = max(0.01, deadline - time.monotonic())
            try:
                record = self._records.get(timeout=remaining)
            except queue.Empty:
                break
            if record == "__AIDEBUG_GDB_EOF__":
                raise ActiveDebugError("GDB exited unexpectedly")
            records.append(record)
            if record.startswith(f"{token}^"):
                result = record[len(str(token)):]
                if result.startswith("^error"):
                    message = _fields(result).get("msg", "GDB command failed")
                    raise ActiveDebugError(message)
                saw_running = result.startswith("^running")
                if not wait_for_stop or not saw_running:
                    return result, records
            if wait_for_stop and saw_running and record.startswith("*stopped"):
                return result, records
        raise ActiveDebugError(f"GDB command timed out after {timeout or self.timeout:g} seconds")

    @staticmethod
    def _parse_address(value: str | None) -> int | None:
        try:
            return int(value, 0) if value else None
        except (TypeError, ValueError, OverflowError):
            return None

    @staticmethod
    def _parse_positive_int(value: str | None) -> int | None:
        try:
            result = int(value) if value else None
        except (TypeError, ValueError, OverflowError):
            return None
        return result if result is not None and result >= 0 else None
