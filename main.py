#!/usr/bin/env python3
"""
AIDebug — AI-Assisted Malware Debugger
Usage:
    python main.py --binary <path>                    # static analysis + TUI
    python main.py --binary <path> --no-tui           # CLI mode (print to stdout)
    python main.py --binary <path> --pid 1234         # dynamic mode (attach Frida)
    python main.py --list-sessions                    # show past analysis sessions
    python main.py --session 1 --report               # HTML report for session 1
    python main.py --session 1 --yara                 # YARA rules for session 1
    python main.py --session 1 --json-export          # JSON export for session 1
    python main.py --session 1 --report --yara --json-export  # all three at once
"""
import argparse
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
    from analysis import Disassembler, StaticAnalyzer

    print(f"[*] Loading: {_terminal_text(path)}")
    analyzer = StaticAnalyzer()
    info = analyzer.analyze(path)

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
    print(f"\n{'ID':>4}  {'File':<30}  {'Arch':<10}  {'Created'}")
    print("-" * 70)
    for s in sessions:
        session_id = s.get("id", "?")
        filename = _terminal_text(s.get("filename", ""), 30)
        arch = _terminal_text(s.get("arch", ""), 10)
        created_at = _terminal_text(s.get("created_at", ""), 30)
        print(f"{str(session_id):>4}  {filename:<30}  {arch:<10}  {created_at}")


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
    parser.add_argument("--mode",           choices=["static", "dynamic"], default="static",
                        help="Analysis mode (default: static)")
    parser.add_argument("--pid",            type=_positive_int, help="PID to attach (dynamic mode)")
    parser.add_argument("--frida-host",     default=None,
                        help="Remote frida-server host[:port] (e.g. 192.168.56.101 or 192.168.56.101:27042). "
                             "Use this to attach to a VM/sandbox while keeping API traffic on the host.")
    parser.add_argument("--no-tui",         action="store_true", help="CLI output, no TUI")
    parser.add_argument("--list-sessions",  action="store_true", help="List past sessions")
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
    if args.offline and args.accept_ai_cost:
        parser.error("--offline cannot be combined with --accept-ai-cost")
    if args.max_functions > config.MAX_FUNCTIONS_TO_DISCOVER:
        parser.error(
            f"--max-functions cannot exceed the discovery limit "
            f"({config.MAX_FUNCTIONS_TO_DISCOVER})"
        )

    if args.list_sessions:
        conflicting = (
            args.binary
            or args.session
            or wants_report
            or args.mode != "static"
            or args.pid
            or args.frida_host
            or args.no_tui
            or args.offline
            or args.accept_ai_cost
            or args.out_dir != "."
        )
        if conflicting:
            parser.error("--list-sessions cannot be combined with analysis or reporting options")
        return

    if args.session and not wants_report:
        parser.error("--session requires --report, --yara, or --json-export")
    if args.no_tui and not args.binary:
        parser.error("--no-tui applies only to binary analysis")
    if args.binary and args.session:
        parser.error("--session selects an existing session and cannot be combined with --binary")
    if (args.pid or args.frida_host) and args.mode != "dynamic":
        parser.error("--pid and --frida-host require --mode dynamic")
    if args.mode == "dynamic" and not args.binary:
        parser.error("--mode dynamic requires --binary")
    if args.out_dir != "." and not wants_report:
        parser.error("--out-dir requires --report, --yara, or --json-export")
    if args.accept_ai_cost and not args.binary and not args.yara:
        parser.error("--accept-ai-cost has no effect without binary analysis or --yara")

    if not args.binary and not wants_report:
        parser.error("choose --binary, --list-sessions, or a reporting command")

    if args.binary:
        binary_path = Path(args.binary).expanduser()
        if not binary_path.exists():
            parser.error(f"binary not found: {_terminal_text(args.binary)}")
        if not binary_path.is_file():
            parser.error(f"binary is not a regular file: {_terminal_text(args.binary)}")
        if not os.access(binary_path, os.R_OK):
            parser.error(f"binary is not readable: {_terminal_text(args.binary)}")

        is_bulk = args.mode == "dynamic" or args.no_tui or wants_report
        if is_bulk and not args.offline and not args.accept_ai_cost:
            parser.error(
                "bulk remote analysis requires --accept-ai-cost; use --offline "
                "to keep all analysis local"
            )


def _make_analyzer(offline: bool):
    from analysis import AIAnalyzer, OfflineAnalyzer

    if offline:
        print("[*] Offline mode: no sample data will be sent to a remote AI service.")
        return OfflineAnalyzer()
    if not config.ANTHROPIC_API_KEY:
        raise CLIError(
            "ANTHROPIC_API_KEY is not set. Export it for AI analysis or use --offline."
        )
    return AIAnalyzer()


def _execute(args) -> int:
    from storage import TraceStore

    store = None
    try:
        wants_report = args.report or args.yara or args.json_export
        analyzer = None
        prepared_binary = None
        if args.binary:
            analyzer = _make_analyzer(args.offline)
            bulk_analysis = args.mode == "dynamic" or args.no_tui or wants_report
            discovery_limit = args.max_functions if bulk_analysis else None
            if args.mode == "dynamic":
                discovery_limit = min(
                    args.max_functions,
                    config.MAX_DYNAMIC_FUNCTION_HOOKS,
                )
            prepared_binary = load_binary(
                os.fspath(Path(args.binary).expanduser()),
                max_functions=discovery_limit,
            )

        store = TraceStore(args.db)

        if args.list_sessions:
            list_sessions(store)
            return 0

        # Reporting only (no binary) works against a stored session.  YARA is
        # deterministic unless the caller explicitly acknowledges remote use.
        if wants_report and not args.binary:
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
            raise CLIError("Binary analysis was not initialized")
        binary_info, disassembler, addresses = prepared_binary
        session_id = store.create_session(binary_info)
        print(f"[*] Session ID: {session_id}")

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
            )

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
    finally:
        if store is not None:
            store.close()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _validate_args(args, parser)
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
