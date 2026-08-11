#!/usr/bin/env python3
"""
AIDebug — AI-Assisted Malware Debugger
Usage:
    python main.py --binary <path>                    # static analysis + TUI
    python main.py --binary <path> --no-tui           # CLI mode (print to stdout)
    python main.py --binary <path> --decompile         # add Ghidra C-like output
    python main.py --source <path.c> --offline         # compile to temporary ELF + analyze
    python main.py --binary <path> --pid 1234         # dynamic mode (attach Frida)
    python main.py --identify <path>                  # broad file-type identification
    python main.py --list-sessions                    # show past analysis sessions
    python main.py --history <file-or-sha256>         # show prior hash-matched analyses
    python main.py --session 1 --report               # HTML report for session 1
    python main.py --session 1 --yara                 # YARA rules for session 1
    python main.py --session 1 --json-export          # JSON export for session 1
    python main.py --session 1 --report --yara --json-export  # all three at once
"""
import argparse
import hashlib
import json
import os
import re
import sys
import threading
from pathlib import Path
from typing import Any

# Make sure we can import from project root
sys.path.insert(0, os.path.dirname(__file__))

import config

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class CLIError(RuntimeError):
    """Expected command-line failure that should not produce a traceback."""


def banner() -> None:
    print(r"""
  ___  ___ ____       _
 / _ \|_ _|  _ \  ___| |__  _   _  __ _
| | | || || | | |/ _ \ '_ \| | | |/ _` |
| |_| || || |_| |  __/ |_) | |_| | (_| |
 \__,_|___|____/ \___|_.__/ \__,_|\__, |
                                   |___/
  AI-Assisted Malware Reverse Engineering Debugger
""")


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def _terminal_text(value: Any, limit: int = 500) -> str:
    """Render untrusted values without terminal control sequences."""
    raw = str(value)[:limit]
    rendered = []
    for character in raw:
        if character.isprintable():
            rendered.append(character)
        elif ord(character) <= 0xFF:
            rendered.append(f"\\x{ord(character):02x}")
        else:
            rendered.append(f"\\u{ord(character):04x}")
    return "".join(rendered)


def _terminal_multiline_text(value: Any, limit: int = 12_000) -> str:
    """Preserve line breaks while neutralizing untrusted terminal controls."""
    raw = str(value)[:limit]
    rendered = []
    for character in raw:
        if character in "\n\t" or character.isprintable():
            rendered.append(character)
        elif ord(character) <= 0xFF:
            rendered.append(f"\\x{ord(character):02x}")
        else:
            rendered.append(f"\\u{ord(character):04x}")
    return "".join(rendered)


def _report_stem(filename: Any, session_id: int) -> str:
    """Return a short basename suitable for report files.

    A session database is user-controlled input.  Never treat its filename as a
    path when deciding where generated reports are written.
    """
    basename = Path(str(filename or "")).name
    stem = re.sub(r"[^A-Za-z0-9_-]+", "_", basename).strip("_")
    safe_session_id = re.sub(r"[^0-9]+", "", str(session_id))[:20] or "unknown"
    return f"{stem[:80] or 'analysis'}_session_{safe_session_id}"


def load_binary(path: str, *, max_functions: int | None = None):
    """Run static analysis and disassembly. Returns (binary_info, disassembler, func_addresses)."""
    from analysis import StaticAnalyzer

    print(f"[*] Loading: {_terminal_text(path)}")
    analyzer = StaticAnalyzer()
    info = analyzer.analyze(path)
    return _prepare_static_analysis(info, max_functions=max_functions)


def load_c_source(path: str, *, max_functions: int | None = None):
    """Compile C to a temporary, non-executed ELF and run static analysis."""
    from analysis import CSourceAnalyzer

    print(f"[*] Loading C source: {_terminal_text(path)}")
    print("[*] Compiling a temporary ELF analysis artifact (the artifact will not be executed)…")
    info = CSourceAnalyzer().analyze(path)
    if info.compiled_sha256:
        print(f"[*] Compiled artifact SHA-256: {info.compiled_sha256}")
    return _prepare_static_analysis(info, max_functions=max_functions)


def identify_file(path: str, *, offline: bool = False) -> int:
    """Identify an arbitrary file locally, using bounded AI metadata only as fallback."""
    from analysis import FileTypeDetector

    detector = FileTypeDetector()
    ai_identifier = None
    if not offline:
        def ai_identifier(evidence):
            analyzer = _make_analyzer(False)
            return analyzer.identify_file_type(evidence)

    result = detector.identify(path, ai_identifier=ai_identifier)
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    if result.ai_used:
        print(
            "[!] AI classification is capped at 60% confidence and requires analyst validation.",
            file=sys.stderr,
        )
    return 2 if result.is_unknown else 0


def _prepare_static_analysis(info, *, max_functions: int | None = None):
    """Describe, disassemble, and enrich an already parsed static artifact."""
    from analysis import Disassembler

    print(
        f"[*] Format   : {_terminal_text(info.file_format)} "
        f"{_terminal_text(info.arch)} {info.bits}-bit  ({_terminal_text(info.os_target)})"
    )
    print(f"[*] EntryPoint: {hex(info.entry_point)}")
    section_names = ", ".join(_terminal_text(section.name, 120) for section in info.sections)
    print(f"[*] Sections  : [{section_names}]")
    print(f"[*] Imports   : {sum(len(i.functions) for i in info.imports)} functions "
          f"from {len(info.imports)} import source(s)")
    print(f"[*] Strings   : {len(info.strings)} found")

    # Check for packing
    high_entropy = [s for s in info.sections if s.entropy > 7.0]
    if high_entropy:
        packed_names = ", ".join(_terminal_text(section.name, 120) for section in high_entropy)
        print(f"[!] Possible packing: [{packed_names}] (entropy > 7.0)")

    print("[*] Discovering functions…")
    dis = Disassembler(info)
    addresses = dis.discover_functions(max_functions=max_functions)
    cap_note = f" (discovery cap: {max_functions})" if max_functions is not None else ""
    print(f"[*] Found {len(addresses)} functions{cap_note}.")

    return info, dis, addresses


def decompile_functions(binary_info, disassembler, addresses, executable=None) -> int:
    """Attach bounded, genuine Ghidra decompiler output to discovered functions."""
    from analysis import DecompilerError, GhidraDecompiler

    selected = [
        address
        for address in addresses
        if (disassembler.get_function(address) is not None)
    ]
    print(f"[*] Decompiling {len(selected)} function(s) with Ghidra headless…")
    try:
        results = GhidraDecompiler(binary_info, executable=executable).decompile(selected)
    except DecompilerError as exc:
        raise CLIError(str(exc)) from exc

    generated = 0
    for address, result in results.items():
        function = disassembler.get_function(address)
        if not function:
            continue
        function.decompiled_code = result.code
        function.decompile_language = result.language
        function.decompile_backend = result.backend
        function.decompile_warning = result.warning
        generated += 1
    print(
        f"[*] Ghidra decompiled {generated} function(s). "
        "The reconstructed C-like output is not original source."
    )
    return generated


def write_full_decompilation(binary_info, disassembler, addresses, destination: str) -> Path:
    """Write one full-program C-like reconstruction with explicit provenance."""
    from analysis import DecompilerError
    from analysis import write_full_decompilation as write_output

    try:
        path = write_output(destination, binary_info, disassembler, addresses)
    except DecompilerError as exc:
        raise CLIError(str(exc)) from exc
    print(f"[+] Full decompilation → {_terminal_text(path)}")
    return path


def run_learning(
    topic: str,
    *,
    compiler: str | None = None,
    ghidra_headless: str | None = None,
    collection_path: str | None = None,
) -> int:
    """Compile and analyze a trusted lesson function without executing it."""
    from learning import (
        LearningAnalysisError,
        LearningCollectionError,
        LiveLearningAnalyzer,
        find_lessons,
        get_lesson,
        load_learning_collection,
        render_catalog,
        render_lesson,
    )

    try:
        collection = (
            load_learning_collection(collection_path) if collection_path else None
        )
    except LearningCollectionError as exc:
        raise CLIError(str(exc)) from exc
    normalized = (topic or "list").strip().lower()
    exact = (
        collection.get_lesson(normalized) if collection is not None else get_lesson(normalized)
    )
    if exact is not None:
        source_label = (
            os.fspath(collection.source_paths[exact.lesson_id])
            if collection is not None
            else f"learning/cases/{exact.lesson_id}.c"
        )
        origin = "external" if collection is not None else "bundled"
        print(f"[*] Compiling {origin} learning case: {_terminal_text(source_label)}")
        print("[*] The temporary ELF artifact will be analyzed and will not be executed.")
        print("[*] Recovering real machine instructions and Ghidra pseudo-code…")
        try:
            result = LiveLearningAnalyzer(
                compiler=compiler,
                ghidra_headless=ghidra_headless,
                collection=collection,
            ).analyze(exact)
        except LearningAnalysisError as exc:
            raise CLIError(str(exc)) from exc
        render_lesson(result)
        return 0
    matches = (
        collection.find_lessons(normalized)
        if collection is not None
        else find_lessons(normalized)
    )
    if not matches:
        raise CLIError(
            f"No learning lesson matches {_terminal_text(topic)!r}. "
            "Run aidebug --learn to list the catalog."
        )
    render_catalog(matches)
    return 0


def run_learning_tui(
    topic: str,
    *,
    compiler: str | None = None,
    ghidra_headless: str | None = None,
    collection_path: str | None = None,
) -> int:
    """Open real learning cases inside AIDebug's original Textual workspace."""
    from learning import (
        LearningAnalysisError,
        LearningCollectionError,
        catalog,
        find_lessons,
        get_lesson,
        load_learning_collection,
    )
    from ui import LearningModeApp

    try:
        collection = (
            load_learning_collection(collection_path) if collection_path else None
        )
    except LearningCollectionError as exc:
        raise CLIError(str(exc)) from exc
    normalized = (topic or "list").strip().lower()
    exact = (
        collection.get_lesson(normalized) if collection is not None else get_lesson(normalized)
    )
    if exact is not None:
        lessons = collection.lessons if collection is not None else catalog()
        initial_lesson_id = exact.lesson_id
    else:
        lessons = (
            collection.find_lessons(normalized)
            if collection is not None
            else find_lessons(normalized)
        )
        initial_lesson_id = lessons[0].lesson_id if len(lessons) == 1 else None
    if not lessons:
        raise CLIError(
            f"No learning lesson matches {_terminal_text(topic)!r}. "
            "Run aidebug --learn to open the complete catalog."
        )
    try:
        app = LearningModeApp(
            lessons,
            initial_lesson_id=initial_lesson_id,
            compiler=compiler,
            ghidra_headless=ghidra_headless,
            collection=collection,
        )
    except LearningAnalysisError as exc:
        raise CLIError(str(exc)) from exc
    app.run()
    return 0


# ---------------------------------------------------------------------------
# CLI (no-TUI) mode
# ---------------------------------------------------------------------------

def run_cli(binary_info, disassembler, addresses, store, session_id, analyzer):
    analyzer_name = getattr(analyzer, "display_name", config.AI_MODEL)
    print(f"\n[*] Analyzing {len(addresses)} functions with {_terminal_text(analyzer_name)}…\n")

    failures = 0
    analyzed = 0
    for addr in addresses:
        func = disassembler.get_function(addr)
        if not func or not func.instructions:
            continue

        # Check cache
        cached = store.get_cached_analysis(
            session_id,
            addr,
            cache_key=getattr(analyzer, "cache_key", None),
        )
        if cached:
            analysis = cached
            try:
                store.save_function_analysis(session_id, func, analysis)
                store.save_patterns(session_id, addr, getattr(func, "patterns", []))
            except Exception as exc:
                failures += 1
                print(
                    f"[!] Could not persist cached result for 0x{addr:08x}: "
                    f"{_terminal_text(exc)}",
                    file=sys.stderr,
                )
                continue
            print(
                f"  [cache] 0x{addr:08x}  {_terminal_text(cached.risk_badge, 20)}  "
                f"{_terminal_text(cached.suggested_name, 160)}"
            )
        else:
            print(
                f"  [new]   0x{addr:08x}  {_terminal_text(func.name, 160)}  "
                f"({len(func.instructions)} insns)…",
                end=" ",
                flush=True,
            )
            try:
                store.save_patterns(session_id, addr, getattr(func, "patterns", []))
                analysis = analyzer.analyze_function(
                    func,
                    binary_info,
                    context_id=f"session:{session_id}:function:{addr:x}",
                )
                store.save_function_analysis(session_id, func, analysis)
            except Exception as exc:
                failures += 1
                print("FAILED")
                print(
                    f"[!] Function 0x{addr:08x} failed: {_terminal_text(exc)}",
                    file=sys.stderr,
                )
                continue
            print(
                f"{_terminal_text(analysis.risk_badge, 20)}  "
                f"{_terminal_text(analysis.suggested_name, 160)}"
            )

        analyzed += 1

        if analysis.risk_level in ('HIGH', 'CRITICAL'):
            print(f"           → {_terminal_text(analysis.summary, 120)}")
            if analysis.mitre_technique:
                print(f"           → MITRE: {_terminal_text(analysis.mitre_technique, 160)}")

        if getattr(func, "decompiled_code", ""):
            language = _terminal_text(getattr(func, "decompile_language", "c"), 24)
            backend = _terminal_text(getattr(func, "decompile_backend", "ghidra"), 40)
            print(
                f"\n--- {backend} decompilation: 0x{addr:08x} ({language}-like) ---\n"
                f"{_terminal_multiline_text(func.decompiled_code, config.MAX_DECOMPILED_CHARS)}\n"
            )
            review = getattr(analysis, "decompilation_review", {})
            if isinstance(review, dict):
                status = _terminal_text(review.get("status", "NOT_AVAILABLE"), 32)
                confidence = _terminal_text(review.get("confidence", "LOW"), 16)
                print(f"[decompilation cross-check] {status} (confidence: {confidence})")
                for finding in review.get("findings", [])[:16]:
                    print(f"  - {_terminal_text(finding, 1_000)}")
                corrected = review.get("corrected_pseudocode", "")
                if corrected:
                    print(
                        "[suggested corrected pseudo-code]\n"
                        f"{_terminal_multiline_text(corrected, 8_000)}"
                    )

    # Summary
    summary = store.get_risk_summary(session_id)
    print("\n=== Risk Summary ===")
    for level in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'):
        count = summary.get(level, 0)
        if count:
            print(f"  {level:<10}: {count}")
    print(f"\n[*] Results saved to: {_terminal_text(store.db_path)}")
    if failures:
        print(
            f"[!] Analysis incomplete: {failures} function(s) failed; "
            f"{analyzed} completed or loaded from cache.",
            file=sys.stderr,
        )
    return failures == 0


# ---------------------------------------------------------------------------
# Dynamic mode
# ---------------------------------------------------------------------------

def run_dynamic(binary_info, disassembler, addresses, store, session_id,
                analyzer, pid=None, binary_path=None, frida_host=None):
    from debugger import DebugEngine

    engine = DebugEngine(
        remote_host=frida_host,
        static_image_base=binary_info.image_base,
        module_name=binary_info.filename,
    )
    failures = 0
    instrumentation_degraded = False
    analyzed_addresses: set[int] = set()
    persistence_caps: set[str] = set()
    callback_lock = threading.RLock()
    spawned_by_aidebug = pid is None
    if frida_host:
        print(f"[*] Using remote frida-server at {_terminal_text(frida_host, 300)}")
    if not engine.is_available:
        raise CLIError("Frida is not installed or unavailable; dynamic mode cannot start")

    print("[*] Dynamic mode — attaching Frida…")
    if pid:
        ok = engine.attach(pid)
        if not ok:
            raise CLIError(
                f"Failed to attach to PID {pid}. Confirm that it is running and that "
                "the analysis account has ptrace permission."
            )
        print(f"[*] Attached to PID {pid}")
    else:
        spawned_pid = engine.spawn(binary_path)
        if not spawned_pid:
            raise CLIError(
                "Failed to spawn the process. Windows PE samples on Linux must run in "
                "an isolated Windows/Wine target; attach with --pid when appropriate."
            )
        print(f"[*] Spawned PID: {spawned_pid}")
        pid = spawned_pid

    # Hook first N interesting functions
    def on_entry(snapshot):
        pass  # handled in on_exit where we have full snapshot

    def report_persistence_cap(category):
        """Notify once when bounded event retention starts dropping a category."""
        with callback_lock:
            if category in persistence_caps:
                return
            persistence_caps.add(category)
        print(
            f"[!] {category} persistence cap reached; later events remain visible "
            "live but are not stored.",
            file=sys.stderr,
        )

    def on_exit(snapshot):
        nonlocal failures
        addr = snapshot.function_address
        with callback_lock:
            if addr in analyzed_addresses:
                return
            analyzed_addresses.add(addr)
        func = disassembler.get_function(addr)
        if not func:
            return
        return_value = snapshot.return_value
        try:
            rendered_return = hex(int(return_value))
        except (TypeError, ValueError, OverflowError):
            rendered_return = _terminal_text(return_value, 80)
        print(f"  [hook] 0x{addr:08x} returned {rendered_return}")
        try:
            store.save_patterns(session_id, addr, getattr(func, "patterns", []))
            analysis = analyzer.analyze_function(
                func,
                binary_info,
                snapshot,
                context_id=f"session:{session_id}:function:{addr:x}",
            )
            store.save_function_analysis(session_id, func, analysis, snapshot)
            print(
                f"         → {_terminal_text(analysis.risk_badge, 20)} "
                f"{_terminal_text(analysis.suggested_name, 160)}"
            )
        except Exception as exc:
            with callback_lock:
                failures += 1
            print(
                f"[!] Dynamic analysis failed at 0x{addr:08x}: {_terminal_text(exc)}",
                file=sys.stderr,
            )

    hook_addresses = addresses[:config.MAX_DYNAMIC_FUNCTION_HOOKS]
    print(f"[*] Hooking {len(hook_addresses)} functions…")
    installed_hooks = 0
    for addr in hook_addresses:
        try:
            engine.hook_function(addr, on_entry=on_entry, on_exit=on_exit)
            installed_hooks += 1
        except Exception as exc:
            failures += 1
            print(f"[!] Hook 0x{addr:08x} failed: {_terminal_text(exc)}", file=sys.stderr)
    if installed_hooks:
        print(f"[*] Installed {installed_hooks} function hook(s).")
    else:
        print(
            "[!] No function hooks were installed; dynamic evidence is tracer-only.",
            file=sys.stderr,
        )

    # Load API tracer
    def on_api_call(call):
        nonlocal failures
        if not isinstance(call, dict):
            return
        try:
            arguments = call.get("args") if isinstance(call.get("args"), list) else []
            persisted = store.save_api_call(
                session_id,
                call.get("module", ""),
                call.get("function", ""),
                arguments,
                call.get("retval", ""),
            )
            if persisted is False:
                report_persistence_cap("API event")
            module = _terminal_text(call.get("module", ""), 160)
            function = _terminal_text(call.get("function", ""), 160)
            print(f"  [api] {module}!{function}({_terminal_text(arguments[:2], 300)})")
        except Exception as exc:
            with callback_lock:
                failures += 1
            print(f"[!] API event persistence failed: {_terminal_text(exc)}", file=sys.stderr)

    def on_network_event(event):
        nonlocal failures
        if not isinstance(event, dict):
            return
        try:
            if store.save_network_event(session_id, event) is False:
                report_persistence_cap("network event")
            destination = event.get("url") or (
                f"{event.get('ip', '')}:{event.get('port', 0)}"
                if event.get("ip")
                else "?"
            )
            print(
                f"  [net] {_terminal_text(event.get('event', ''), 64)} "
                f"{_terminal_text(event.get('function', ''), 160)} "
                f"→ {_terminal_text(destination, 300)} "
                f"({_terminal_text(event.get('size', 0), 32)} bytes)"
            )
        except Exception as exc:
            with callback_lock:
                failures += 1
            print(f"[!] Network event persistence failed: {_terminal_text(exc)}", file=sys.stderr)

    def on_protection_transition(event):
        nonlocal failures
        if not isinstance(event, dict):
            return
        try:
            if store.save_runtime_event(session_id, event) is False:
                report_persistence_cap("runtime event")
            print(
                "  [memory] executable protection transition "
                f"region={_terminal_text(event.get('address', ''), 80)} "
                f"size={_terminal_text(event.get('size', 0), 32)} "
                f"entry-point-candidate="
                f"{_terminal_text(event.get('entry_point_candidate', ''), 80)} "
                "(heuristic evidence only)"
            )
        except Exception as exc:
            with callback_lock:
                failures += 1
            print(f"[!] Runtime event persistence failed: {_terminal_text(exc)}", file=sys.stderr)

    tracer_loaders = (
        ("API", "api", lambda: engine.load_api_tracer(on_call=on_api_call)),
        ("network", "network", lambda: engine.load_network_tracer(on_event=on_network_event)),
        (
            "protection-transition",
            "protection",
            lambda: engine.load_unpack_detector(on_unpack=on_protection_transition),
        ),
    )
    active_tracers = []
    for label, status_key, loader in tracer_loaders:
        try:
            status = loader()
            if not isinstance(status, dict):
                status = engine.get_instrumentation_status().get(status_key, {})
            if not status.get("ready"):
                raise RuntimeError("script did not confirm readiness")
            count = status.get("installed_count", 0)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise RuntimeError("script reported an invalid hook count")
            active_tracers.append((label, count))
        except Exception as exc:
            failures += 1
            print(
                f"[!] {label} tracer setup failed: {_terminal_text(exc)}",
                file=sys.stderr,
            )
    for label, installed_count in active_tracers:
        if installed_count:
            print(f"[*] {label} tracer active with {installed_count} hook(s) installed.")
        else:
            print(
                f"[*] {label} tracer observer active; 0 hooks are currently installed "
                "and matching modules may load later."
            )

    if spawned_by_aidebug:
        if not engine.resume():
            engine.detach()
            raise CLIError("Failed to resume the instrumented process")
        print("[*] Process resumed. Press Ctrl+C to stop.")
    else:
        print("[*] Instrumentation active. Press Ctrl+C to stop.")
    try:
        import time
        while engine.is_attached:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        status_snapshot = engine.get_instrumentation_status()
        instrumentation_degraded = any(
            bool(status.get("fatal") or status.get("errors"))
            for status in status_snapshot.values()
            if isinstance(status, dict)
        )
        for tracer, status in sorted(status_snapshot.items()):
            if not isinstance(status, dict) or not status.get("errors"):
                continue
            print(
                f"[!] {_terminal_text(tracer, 80)} instrumentation reported "
                f"{len(status['errors'])} error(s); dynamic evidence may be incomplete.",
                file=sys.stderr,
            )
        engine.detach()
        print(f"\n[*] Detached. Results saved to {_terminal_text(store.db_path)}")
    return failures == 0 and not instrumentation_degraded


# ---------------------------------------------------------------------------
# Active local debugger mode
# ---------------------------------------------------------------------------

def _print_debug_stop(stop, debugger) -> None:
    address = f"0x{stop.address:x}" if stop.address is not None else "?"
    function = stop.function or "unknown"
    location = ""
    if stop.source:
        location = f"  {stop.source}"
        if stop.line is not None:
            location += f":{stop.line}"
    print(f"\n[stop] {stop.reason} at {function} ({address}){location}")
    if stop.function_inputs:
        values = ", ".join(f"{name}={value}" for name, value in stop.function_inputs.items())
        print(f"[input candidates] {values}")
    if stop.function_output:
        print(f"[function output] {stop.function_output}")
    if stop.changed_registers:
        print("[register changes]")
        for name, (before, after) in sorted(stop.changed_registers.items()):
            print(f"  {name:<8} {before} → {after}")
    instructions = debugger.disassemble_current() if stop.registers else []
    if instructions:
        print("[next instructions]")
        for instruction in instructions:
            print(f"  {_terminal_text(instruction, 500)}")


def _print_registers(registers: dict[str, str]) -> None:
    if not registers:
        print("(registers unavailable: the inferior is not stopped)")
        return
    for name, value in sorted(registers.items()):
        print(f"  {name:<12} {_terminal_text(value, 256)}")


def _run_debug_command(command: str, debugger) -> bool:
    """Run one analyst command. Return False when the session should close."""
    command = command.strip()
    if not command:
        return True
    operation, _, argument = command.partition(" ")
    operation = operation.lower()
    if operation in {"q", "quit", "exit"}:
        return False
    if operation in {"c", "continue"}:
        _print_debug_stop(debugger.continue_execution(), debugger)
    elif operation in {"s", "step", "stepi"}:
        _print_debug_stop(debugger.step_instruction(), debugger)
    elif operation in {"n", "next", "nexti"}:
        _print_debug_stop(debugger.next_instruction(), debugger)
    elif operation in {"f", "finish"}:
        _print_debug_stop(debugger.finish_function(), debugger)
    elif operation in {"r", "regs", "registers"}:
        _print_registers(debugger.registers())
    elif operation in {"changes", "diff"}:
        stop = debugger.last_stop
        if stop is None or not stop.changed_registers:
            print("(no register changes captured yet)")
        else:
            for name, (before, after) in sorted(stop.changed_registers.items()):
                print(f"  {name:<12} {before} → {after}")
    elif operation in {"io", "inputs", "outputs"}:
        stop = debugger.last_stop
        if stop is None:
            print("(no stopped function context yet)")
        else:
            print("Function input candidates:")
            _print_registers(stop.function_inputs)
            print(f"Function output: {stop.function_output or '(not captured yet)'}")
    elif operation in {"d", "disasm", "disassemble"}:
        for instruction in debugger.disassemble_current(16):
            print(f"  {_terminal_text(instruction, 500)}")
    elif operation in {"b", "break", "breakpoint"}:
        if not argument.strip():
            raise CLIError("break requires a symbol or address")
        number = debugger.add_breakpoint(argument.strip())
        print(f"[breakpoint] {number}: {_terminal_text(argument.strip(), 512)}")
    elif operation in {"h", "help", "?"}:
        print(
            "Commands: break LOCATION, continue, step, next, finish, registers, "
            "changes, io, disassemble, quit"
        )
    else:
        raise CLIError(f"Unknown debug command: {_terminal_text(operation)}")
    return True


def run_active_debug(
    binary_info,
    binary_path: str,
    *,
    breakpoints: list[str] | None = None,
    program_args: list[str] | None = None,
    commands: list[str] | None = None,
    gdb_path: str | None = None,
) -> bool:
    """Run an explicit analyst-controlled GDB/MI session for a local ELF."""
    from debugger import ActiveDebugError, GDBMIDebugger

    if not str(binary_info.file_format).upper().startswith("ELF"):
        raise CLIError(
            "Active GDB mode currently supports local ELF targets. "
            "Use --mode dynamic with Frida for PE/remote targets."
        )
    selected_breakpoints = list(breakpoints or ["main"])
    print("[!] ACTIVE DEBUG MODE EXECUTES THE SELECTED ELF. Use an isolated lab target.")
    try:
        with GDBMIDebugger(
            binary_path,
            program_args=program_args,
            executable=gdb_path,
            arch=binary_info.arch,
            bits=binary_info.bits,
            os_target=binary_info.os_target,
        ) as debugger:
            for location in selected_breakpoints:
                number = debugger.add_breakpoint(location)
                print(f"[*] Breakpoint {number}: {_terminal_text(location, 512)}")
            _print_debug_stop(debugger.run(), debugger)

            if commands:
                for command in commands:
                    print(f"\n(aidebug-db) {_terminal_text(command, 512)}")
                    if not _run_debug_command(command, debugger):
                        break
                return True

            if not sys.stdin.isatty():
                raise CLIError(
                    "Interactive debug mode requires a terminal. Use repeatable "
                    "--debug-command options for non-interactive operation."
                )
            print(
                "[*] Commands: break, continue, step, next, finish, registers, "
                "changes, io, disassemble, quit"
            )
            while True:
                try:
                    command = input("(aidebug-db) ")
                except EOFError:
                    break
                try:
                    if not _run_debug_command(command, debugger):
                        break
                except (ActiveDebugError, CLIError, ValueError) as exc:
                    print(f"[!] {_terminal_text(exc)}", file=sys.stderr)
            return True
    except ActiveDebugError as exc:
        raise CLIError(str(exc)) from exc


# ---------------------------------------------------------------------------
# TUI mode
# ---------------------------------------------------------------------------

def run_tui(
    binary_info,
    disassembler,
    addresses,
    store,
    session_id,
    analyzer,
    *,
    allow_bulk_analysis=False,
    max_bulk_functions=25,
    prior_sessions=None,
):
    from ui import AIDebugApp

    app = AIDebugApp(
        binary_info=binary_info,
        disassembler=disassembler,
        ai_analyzer=analyzer,
        trace_store=store,
        session_id=session_id,
        function_addresses=addresses,
        allow_bulk_analysis=allow_bulk_analysis,
        max_bulk_functions=max_bulk_functions,
        prior_sessions=prior_sessions,
    )
    app.run()


# ---------------------------------------------------------------------------
# Session listing
# ---------------------------------------------------------------------------

def list_sessions(store):
    sessions = store.list_sessions()
    if not sessions:
        print("No analysis sessions found.")
        return
    print(f"\n{'ID':>4}  {'File':<26}  {'Arch':<10}  {'Status':<11}  {'Created'}")
    print("-" * 86)
    for s in sessions:
        session_id = s.get("id", "?")
        filename = _terminal_text(s.get("filename", ""), 26)
        arch = _terminal_text(s.get("arch", ""), 10)
        status = _terminal_text(s.get("status") or "legacy", 11)
        created_at = _terminal_text(s.get("created_at", ""), 30)
        print(
            f"{str(session_id):>4}  {filename:<26}  {arch:<10}  "
            f"{status:<11}  {created_at}"
        )


def _history_sha256(value: str) -> str:
    """Resolve an existing file or a literal SHA-256 into a normalized hash."""
    candidate = Path(value).expanduser()
    if candidate.exists():
        if not candidate.is_file():
            raise CLIError(f"history target is not a regular file: {_terminal_text(value)}")
        if not os.access(candidate, os.R_OK):
            raise CLIError(f"history target is not readable: {_terminal_text(value)}")
        digest = hashlib.sha256()
        try:
            with candidate.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError as exc:
            raise CLIError(f"could not hash history target: {exc}") from exc
        return digest.hexdigest()

    normalized = str(value).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise CLIError("--history requires an existing file or a full 64-character SHA-256")
    return normalized


def _stored_analysis_data(trace: dict) -> dict:
    try:
        value = json.loads(trace.get("ai_analysis_json") or "{}")
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def show_hash_history(store, value: str) -> list:
    """Print persisted sessions and AI findings for a sample path or SHA-256."""
    sha256 = _history_sha256(value)
    sessions = store.find_sessions_by_sha256(sha256)
    print(f"[*] Analysis history for SHA-256: {sha256}")
    print(f"[*] Local database: {_terminal_text(store.db_path, 8_192)}")
    if not sessions:
        print("No previous analysis sessions found for this hash.")
        return []

    print(f"[+] Found {len(sessions)} previous analysis session(s).")
    for session in sessions:
        session_id = session.get("id", "?")
        status = _terminal_text(session.get("status") or "legacy", 32)
        mode = _terminal_text(session.get("analysis_mode") or "unknown", 32)
        analyzer = _terminal_text(session.get("analyzer") or "unknown", 80)
        created = _terminal_text(session.get("created_at") or "unknown", 40)
        completed = _terminal_text(session.get("completed_at") or "not recorded", 40)
        print(
            f"\nSession {session_id}  |  {status}  |  {mode}  |  {created}"
            f"\n  Analyzer: {analyzer}"
            f"\n  Completed: {completed}"
            f"\n  Stored evidence: {session.get('function_count', 0)} functions, "
            f"{session.get('pattern_count', 0)} patterns, "
            f"{session.get('api_call_count', 0)} API calls, "
            f"{session.get('network_event_count', 0)} network events, "
            f"{session.get('runtime_event_count', 0)} runtime events"
            f"\n  Risk: CRITICAL={session.get('critical_count', 0)} "
            f"HIGH={session.get('high_count', 0)} "
            f"MEDIUM={session.get('medium_count', 0)} "
            f"LOW={session.get('low_count', 0)}"
        )
        traces = store.get_all_traces(int(session_id))
        for trace in traces:
            ai = _stored_analysis_data(trace)
            address = trace.get("address", 0)
            try:
                address_text = f"0x{int(address):x}"
            except (TypeError, ValueError, OverflowError):
                address_text = "unknown"
            name = _terminal_text(
                ai.get("suggested_name") or trace.get("name") or "unknown",
                100,
            )
            risk = _terminal_text(trace.get("risk_level") or "UNKNOWN", 20)
            summary = _terminal_text(ai.get("summary") or "No stored summary", 240)
            mitre = _terminal_text(
                ai.get("mitre_technique") or trace.get("mitre_technique") or "",
                100,
            )
            suffix = f" | {mitre}" if mitre else ""
            print(f"    {address_text:<18} [{risk:<8}] {name}{suffix}")
            print(f"      {summary}")
        print(
            f"  Export every stored field: aidebug --session {session_id} "
            "--json-export --out-dir reports/"
        )
    return sessions


def print_prior_analysis_notice(store, sha256: str, sessions: list) -> None:
    """Explain automatic hash recovery when a known sample is opened again."""
    if not sessions:
        return
    latest = sessions[0]
    print(
        f"[+] Recognized SHA-256 {sha256}: {len(sessions)} prior session(s) found "
        f"in {_terminal_text(store.db_path, 8_192)}."
    )
    print(
        f"[*] Latest prior session: {latest.get('id')} "
        f"({latest.get('created_at') or 'unknown date'}, "
        f"{latest.get('ai_function_count', 0)} stored function analyses)."
    )
    print(
        "[*] Compatible function results will be restored automatically. "
        "Open the History tab or run aidebug --history <file-or-sha256>."
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def run_reports(store, session_id: int, out_dir: str,
                do_html=False, do_yara=False, do_json=False,
                allow_remote_yara=False, max_yara_functions=None):
    session = store.get_session(session_id)
    if not session:
        print(f"[!] Session {session_id} not found.", file=sys.stderr)
        return False

    traces    = store.get_all_traces(session_id)
    api_calls = store.get_api_calls(session_id)
    network_events = store.get_network_events(session_id)
    runtime_events = store.get_runtime_events(session_id)
    patterns = store.get_patterns(session_id)

    stem = _report_stem(session.get("filename"), session_id)
    output_directory = Path(out_dir).expanduser()
    output_directory.mkdir(parents=True, exist_ok=True)
    if not output_directory.is_dir():
        raise CLIError(f"Report output is not a directory: {_terminal_text(out_dir)}")

    print(f"[*] Session {session_id}: {_terminal_text(session.get('filename'), 240)}  "
          f"({len(traces)} functions analyzed)")

    completed = True

    if do_html:
        try:
            from reporting.html_report import HTMLReporter

            path = output_directory / f"{stem}_report.html"
            HTMLReporter().generate(session, traces, path, store=store)
            print(f"[+] HTML report   → {_terminal_text(path)}")
        except Exception as exc:
            completed = False
            print(f"[!] HTML report failed: {_terminal_text(exc)}", file=sys.stderr)

    if do_yara:
        try:
            from reporting.yara_generator import YaraGenerator

            path = output_directory / f"{stem}.yar"
            _, count = YaraGenerator(allow_remote=allow_remote_yara).generate(
                session,
                traces,
                path,
                max_rules=max_yara_functions,
            )
            print(f"[+] YARA rules    → {_terminal_text(path)}  ({count} rules)")
        except Exception as exc:
            completed = False
            print(f"[!] YARA generation failed: {_terminal_text(exc)}", file=sys.stderr)

    if do_json:
        try:
            from reporting.json_export import JSONExporter

            path = output_directory / f"{stem}_export.json"
            JSONExporter().export(
                session,
                traces,
                api_calls,
                path,
                network_events=network_events,
                runtime_events=runtime_events,
                patterns=patterns,
            )
            print(f"[+] JSON export   → {_terminal_text(path)}")
        except Exception as exc:
            completed = False
            print(f"[!] JSON export failed: {_terminal_text(exc)}", file=sys.stderr)

    return completed


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

DEFAULT_MAX_FUNCTIONS = 25


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AIDebug — AI-Assisted Malware Reverse Engineering Debugger"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"AIDebug {config.APP_VERSION}",
    )
    parser.add_argument("--binary",         help="Path to binary (PE or ELF)")
    parser.add_argument(
        "--identify",
        metavar="PATH",
        help=(
            "Identify an arbitrary file by signature and container structure; if unknown, "
            "a configured AI provider receives only bounded header metadata unless --offline"
        ),
    )
    parser.add_argument(
        "--source",
        metavar="PATH.c",
        help="Path to C source; compile to a temporary, non-executed ELF for static analysis",
    )
    parser.add_argument("--mode",           choices=["static", "dynamic", "debug"], default="static",
                        help="Analysis mode: static, Frida dynamic tracing, or active local ELF debug")
    parser.add_argument("--pid",            type=_positive_int, help="PID to attach (dynamic mode)")
    parser.add_argument("--frida-host",     default=None,
                        help="Remote frida-server host[:port] (e.g. 192.168.56.101 or 192.168.56.101:27042). "
                             "Use this to attach to a VM/sandbox while keeping API traffic on the host.")
    parser.add_argument("--no-tui",         action="store_true", help="CLI output, no TUI")
    parser.add_argument(
        "--decompile",
        action="store_true",
        help=(
            "Decompile discovered functions with Ghidra headless into bounded C-like output"
        ),
    )
    parser.add_argument(
        "--decompile-all",
        metavar="FILE.c",
        help=(
            "Decompile every discovered function with Ghidra and write one combined "
            "C-like reconstruction; implies --decompile"
        ),
    )
    parser.add_argument(
        "--ghidra-headless",
        metavar="PATH",
        help=(
            "Path to Ghidra support/analyzeHeadless; otherwise use "
            "AIDEBUG_GHIDRA_HEADLESS or automatic discovery"
        ),
    )
    parser.add_argument(
        "--breakpoint",
        action="append",
        default=[],
        metavar="LOCATION",
        help="Initial symbol/address breakpoint for --mode debug; repeatable (default: main)",
    )
    parser.add_argument(
        "--debug-arg",
        action="append",
        default=[],
        metavar="VALUE",
        help="Argument passed to the debug target; repeatable",
    )
    parser.add_argument(
        "--debug-command",
        action="append",
        default=[],
        metavar="COMMAND",
        help="Non-interactive debugger command; repeatable",
    )
    parser.add_argument("--gdb", metavar="PATH", help="Path to GDB for --mode debug")
    parser.add_argument(
        "--learn",
        nargs="?",
        const="list",
        metavar="TOPIC",
        help="Open real learning cases in the main GUI (add --no-tui for text output)",
    )
    parser.add_argument(
        "--learning-compiler",
        metavar="PATH",
        help="ELF-capable compiler used for --learn (default: cc, gcc, or clang)",
    )
    parser.add_argument(
        "--learning-collection",
        metavar="DIR",
        help=(
            "Load external C learning cases from DIR; expects case_common.h and "
            "optional collection.json"
        ),
    )
    parser.add_argument("--list-sessions",  action="store_true", help="List past sessions")
    parser.add_argument(
        "--history",
        metavar="FILE_OR_SHA256",
        help="Show all persisted analysis sessions matching a file or SHA-256",
    )
    parser.add_argument("--session",        type=_positive_int, help="Session ID for reporting commands")
    parser.add_argument("--report",         action="store_true", help="Generate HTML report")
    parser.add_argument(
        "--yara",
        action="store_true",
        help="Generate analyst-review YARA candidates (HIGH/CRITICAL)",
    )
    parser.add_argument(
        "--json-export",
        action="store_true",
        help="Export versioned AIDebug JSON for custom SIEM/SOAR adapters",
    )
    parser.add_argument("--out-dir",        default=".", help="Output directory for reports (default: current dir)")
    parser.add_argument(
        "--offline",
        "--no-ai",
        action="store_true",
        help="Keep analysis local; use deterministic patterns and never call a remote AI",
    )
    parser.add_argument(
        "--max-functions",
        type=_positive_int,
        default=DEFAULT_MAX_FUNCTIONS,
        metavar="N",
        help=(
            f"Maximum functions in one bulk analysis or YARA ruleset "
            f"(default: {DEFAULT_MAX_FUNCTIONS}); "
            f"dynamic instrumentation is additionally capped at {config.MAX_DYNAMIC_FUNCTION_HOOKS}"
        ),
    )
    parser.add_argument(
        "--accept-ai-cost",
        action="store_true",
        help="Acknowledge that bulk remote analysis sends data and can incur API charges",
    )
    parser.add_argument("--db",             default=config.DB_PATH,
                        help=f"SQLite DB path (default: {config.DB_PATH})")
    return parser


def _validate_args(args, parser: argparse.ArgumentParser) -> None:
    wants_report = args.report or args.yara or args.json_export
    identify = getattr(args, "identify", None)
    selected_input = args.binary or args.source
    decompile = getattr(args, "decompile", None)
    decompile_all = getattr(args, "decompile_all", None)
    ghidra_headless = getattr(args, "ghidra_headless", None)
    learn = getattr(args, "learn", None)
    learning_compiler = getattr(args, "learning_compiler", None)
    learning_collection = getattr(args, "learning_collection", None)
    history = getattr(args, "history", None)
    debug_options = bool(
        getattr(args, "breakpoint", [])
        or getattr(args, "debug_arg", [])
        or getattr(args, "debug_command", [])
        or getattr(args, "gdb", None)
    )
    if identify:
        conflicting = (
            selected_input
            or learn is not None
            or args.list_sessions
            or args.session
            or wants_report
            or args.mode != "static"
            or args.pid
            or args.frida_host
            or args.no_tui
            or args.out_dir != "."
            or args.db != config.DB_PATH
            or decompile
            or decompile_all
            or ghidra_headless
            or history
            or debug_options
        )
        if conflicting:
            parser.error("--identify cannot be combined with analysis, debug, or reporting options")
        input_path = Path(identify).expanduser()
        if not input_path.exists():
            parser.error(f"file not found: {_terminal_text(identify)}")
        if not input_path.is_file():
            parser.error(f"file is not a regular file: {_terminal_text(identify)}")
        if not os.access(input_path, os.R_OK):
            parser.error(f"file is not readable: {_terminal_text(identify)}")
        return
    if learn is not None:
        conflicting = (
            selected_input
            or args.list_sessions
            or args.session
            or wants_report
            or args.mode != "static"
            or args.pid
            or args.frida_host
            or args.offline
            or args.accept_ai_cost
            or args.out_dir != "."
            or args.db != config.DB_PATH
            or decompile
            or decompile_all
            or history
            or debug_options
        )
        if conflicting:
            parser.error("--learn cannot be combined with analysis, debug, or reporting options")
        return
    if learning_compiler or learning_collection:
        option = "--learning-compiler" if learning_compiler else "--learning-collection"
        parser.error(f"{option} requires --learn")
    if args.binary and args.source:
        parser.error("--binary and --source are mutually exclusive")
    if args.offline and args.accept_ai_cost:
        parser.error("--offline cannot be combined with --accept-ai-cost")
    if args.max_functions > config.MAX_FUNCTIONS_TO_DISCOVER:
        parser.error(
            f"--max-functions cannot exceed the discovery limit "
            f"({config.MAX_FUNCTIONS_TO_DISCOVER})"
        )

    if history:
        conflicting = (
            selected_input
            or args.list_sessions
            or args.session
            or wants_report
            or args.mode != "static"
            or args.pid
            or args.frida_host
            or args.no_tui
            or args.offline
            or args.accept_ai_cost
            or args.out_dir != "."
            or decompile
            or decompile_all
            or ghidra_headless
            or debug_options
        )
        if conflicting:
            parser.error("--history cannot be combined with analysis, debug, or reporting options")
        return

    if args.list_sessions:
        conflicting = (
            args.binary
            or args.source
            or args.session
            or wants_report
            or args.mode != "static"
            or args.pid
            or args.frida_host
            or args.no_tui
            or args.offline
            or args.accept_ai_cost
            or args.out_dir != "."
            or decompile
            or decompile_all
            or ghidra_headless
            or debug_options
        )
        if conflicting:
            parser.error("--list-sessions cannot be combined with analysis or reporting options")
        return

    if args.session and not wants_report:
        parser.error("--session requires --report, --yara, or --json-export")
    if args.no_tui and not selected_input:
        parser.error("--no-tui applies only to file analysis")
    if decompile and not selected_input:
        parser.error("--decompile requires --binary or --source")
    if decompile_all and not selected_input:
        parser.error("--decompile-all requires --binary or --source")
    if ghidra_headless and not (decompile or decompile_all):
        parser.error("--ghidra-headless requires --decompile or --decompile-all")
    if selected_input and args.session:
        parser.error("--session selects an existing session and cannot be combined with file analysis")
    if (args.pid or args.frida_host) and args.mode != "dynamic":
        parser.error("--pid and --frida-host require --mode dynamic")
    if debug_options and args.mode != "debug":
        parser.error("--breakpoint, --debug-arg, --debug-command, and --gdb require --mode debug")
    if args.source and args.mode == "dynamic":
        parser.error("--source supports static analysis only; compiled source is never executed")
    if args.mode == "dynamic" and not args.binary:
        parser.error("--mode dynamic requires --binary")
    if args.mode == "debug" and not args.binary:
        parser.error("--mode debug requires --binary")
    if args.mode == "debug" and wants_report:
        parser.error("--mode debug cannot be combined with reporting commands")
    if args.source and args.yara:
        parser.error(
            "--yara is unavailable for C source because analysis uses a temporary compiled artifact"
        )
    if args.out_dir != "." and not wants_report:
        parser.error("--out-dir requires --report, --yara, or --json-export")
    if args.accept_ai_cost and not selected_input and not args.yara:
        parser.error("--accept-ai-cost has no effect without file analysis or --yara")

    if not selected_input and not wants_report:
        parser.error(
            "choose --binary, --source, --identify, --learn, --history, --list-sessions, "
            "or a reporting command"
        )

    if selected_input:
        input_kind = "source" if args.source else "binary"
        input_path = Path(selected_input).expanduser()
        if not input_path.exists():
            parser.error(f"{input_kind} not found: {_terminal_text(selected_input)}")
        if not input_path.is_file():
            parser.error(f"{input_kind} is not a regular file: {_terminal_text(selected_input)}")
        if not os.access(input_path, os.R_OK):
            parser.error(f"{input_kind} is not readable: {_terminal_text(selected_input)}")
        if args.source and input_path.suffix.lower() != ".c":
            parser.error("--source accepts files with the .c extension")

        is_bulk = args.mode == "dynamic" or args.no_tui or wants_report
        llm_settings = None
        if not args.offline:
            try:
                llm_settings = config.resolve_llm_settings()
            except ValueError as exc:
                parser.error(str(exc))
        # Preserve the cost boundary even before credentials are configured.
        # Only an explicitly resolved local provider bypasses acknowledgement.
        uses_billable_remote = not args.offline and not bool(
            llm_settings and llm_settings.get("is_local")
        )
        if is_bulk and uses_billable_remote and not args.accept_ai_cost:
            parser.error(
                "bulk remote analysis requires --accept-ai-cost; use --offline "
                "to keep all analysis local"
            )


def _make_analyzer(offline: bool):
    from analysis import AIAnalyzer, OfflineAnalyzer

    if offline:
        print("[*] Offline mode: no sample data will be sent to a remote AI service.")
        return OfflineAnalyzer()
    try:
        settings = config.resolve_llm_settings()
    except ValueError as exc:
        raise CLIError(str(exc)) from exc
    if settings is None:
        raise CLIError(
            "No LLM provider is configured. Add one API key to AIDebug's .env, "
            "configure OLLAMA_BASE_URL for a local model, or use --offline."
        )
    return AIAnalyzer(
        provider=settings["provider"],
        model=settings["model"],
        api_key=settings["api_key"],
        base_url=settings["base_url"],
    )


def _execute(args) -> int:
    from storage import TraceStore

    store = None
    active_session_id = None
    session_finished = False
    try:
        identify_argument = getattr(args, "identify", None)
        if identify_argument:
            return identify_file(
                os.fspath(Path(identify_argument).expanduser()),
                offline=bool(args.offline),
            )
        if getattr(args, "learn", None) is not None:
            runner = run_learning if args.no_tui else run_learning_tui
            return runner(
                args.learn,
                compiler=getattr(args, "learning_compiler", None),
                ghidra_headless=getattr(args, "ghidra_headless", None),
                collection_path=getattr(args, "learning_collection", None),
            )

        wants_report = args.report or args.yara or args.json_export
        analyzer = None
        prepared_binary = None
        source_argument = getattr(args, "source", None)
        selected_input = args.binary or source_argument
        if selected_input:
            if args.mode != "debug":
                analyzer = _make_analyzer(args.offline)
            bulk_analysis = args.mode == "dynamic" or args.no_tui or wants_report
            discovery_limit = args.max_functions if bulk_analysis else None
            if getattr(args, "decompile_all", None):
                discovery_limit = None
            if args.mode == "dynamic":
                discovery_limit = min(
                    args.max_functions,
                    config.MAX_DYNAMIC_FUNCTION_HOOKS,
                )
            if source_argument:
                prepared_binary = load_c_source(
                    os.fspath(Path(source_argument).expanduser()),
                    max_functions=discovery_limit,
                )
            else:
                prepared_binary = load_binary(
                    os.fspath(Path(args.binary).expanduser()),
                    max_functions=discovery_limit,
                )

        if prepared_binary is not None:
            binary_info, disassembler, addresses = prepared_binary
            wants_decompilation = bool(
                getattr(args, "decompile", False)
                or getattr(args, "decompile_all", None)
            )
            if wants_decompilation:
                decompile_functions(
                    binary_info,
                    disassembler,
                    addresses,
                    getattr(args, "ghidra_headless", None),
                )
            if getattr(args, "decompile_all", None):
                write_full_decompilation(
                    binary_info,
                    disassembler,
                    addresses,
                    args.decompile_all,
                )
            if args.mode == "debug":
                return 0 if run_active_debug(
                    binary_info,
                    args.binary,
                    breakpoints=args.breakpoint,
                    program_args=args.debug_arg,
                    commands=args.debug_command,
                    gdb_path=args.gdb,
                ) else 1

        store = TraceStore(args.db)

        if getattr(args, "history", None):
            show_hash_history(store, args.history)
            return 0

        if args.list_sessions:
            list_sessions(store)
            return 0

        # Reporting only (no binary) works against a stored session.  YARA is
        # deterministic unless the caller explicitly acknowledges remote use.
        if wants_report and not selected_input:
            session_id = args.session
            if session_id is None:
                sessions = store.list_sessions()
                if not sessions:
                    raise CLIError("No sessions found. Run an analysis first.")
                session_id = sessions[0]["id"]
                print(f"[*] Auto-selected most recent session: {session_id}")
            completed = run_reports(
                store,
                session_id,
                args.out_dir,
                do_html=args.report,
                do_yara=args.yara,
                do_json=args.json_export,
                allow_remote_yara=args.accept_ai_cost and not args.offline,
                max_yara_functions=args.max_functions,
            )
            return 0 if completed else 1

        if analyzer is None or prepared_binary is None:
            raise CLIError("File analysis was not initialized")
        binary_info, disassembler, addresses = prepared_binary
        prior_sessions = store.find_sessions_by_sha256(binary_info.sha256)
        analyzer_name = getattr(analyzer, "display_name", analyzer.__class__.__name__)
        session_id = store.create_session(
            binary_info,
            mode=args.mode,
            analyzer=analyzer_name,
        )
        active_session_id = session_id
        print(f"[*] Session ID: {session_id}")
        print_prior_analysis_notice(store, binary_info.sha256, prior_sessions)

        completed = True
        if args.mode == "dynamic":
            selected = addresses[:config.MAX_DYNAMIC_FUNCTION_HOOKS]
            print(
                f"[*] Dynamic analysis limit: {len(selected)} function(s) "
                f"(requested cap: {args.max_functions}; instrumentation cap: "
                f"{config.MAX_DYNAMIC_FUNCTION_HOOKS})."
            )
            completed = run_dynamic(
                binary_info,
                disassembler,
                selected,
                store,
                session_id,
                analyzer,
                pid=args.pid,
                binary_path=args.binary,
                frida_host=args.frida_host,
            )
        elif args.no_tui or wants_report:
            selected = addresses[:args.max_functions]
            remote_label = "remote AI requests" if not args.offline else "local deterministic analysis"
            print(
                f"[*] Bulk preflight: {len(selected)} function(s), configured cap "
                f"{args.max_functions}; {remote_label}."
            )
            completed = run_cli(
                binary_info,
                disassembler,
                selected,
                store,
                session_id,
                analyzer,
            )
        else:
            run_tui(
                binary_info,
                disassembler,
                addresses,
                store,
                session_id,
                analyzer,
                allow_bulk_analysis=args.offline or args.accept_ai_cost,
                max_bulk_functions=args.max_functions,
                prior_sessions=prior_sessions,
            )

        store.finish_session(session_id, "completed" if completed else "failed")
        session_finished = True

        if wants_report:
            print()
            reports_completed = run_reports(
                store,
                session_id,
                args.out_dir,
                do_html=args.report,
                do_yara=args.yara,
                do_json=args.json_export,
                allow_remote_yara=args.accept_ai_cost and not args.offline,
                max_yara_functions=args.max_functions,
            )
            completed = completed and reports_completed

        return 0 if completed else 1
    except BaseException as exc:
        if store is not None and active_session_id is not None and not session_finished:
            status = "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed"
            try:
                store.finish_session(active_session_id, status)
            except Exception as finish_error:
                print(
                    "[!] Could not persist final session status: "
                    f"{_terminal_text(finish_error)}",
                    file=sys.stderr,
                )
        raise
    finally:
        if store is not None:
            store.close()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _validate_args(args, parser)
    if not getattr(args, "identify", None):
        banner()
    try:
        return _execute(args)
    except CLIError as exc:
        print(f"[!] {_terminal_text(exc)}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[!] Operation failed: {_terminal_text(exc)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
