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
import sys

# Make sure we can import from project root
sys.path.insert(0, os.path.dirname(__file__))

import config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def banner():
    print(r"""
  ___  ___ ____       _
 / _ \|_ _|  _ \  ___| |__  _   _  __ _
| | | || || | | |/ _ \ '_ \| | | |/ _` |
| |_| || || |_| |  __/ |_) | |_| | (_| |
 \__,_|___|____/ \___|_.__/ \__,_|\__, |
                                   |___/
  AI-Assisted Malware Reverse Engineering Debugger
""")


def check_api_key():
    if not config.ANTHROPIC_API_KEY:
        print("[!] ANTHROPIC_API_KEY is not set.")
        print("    Export it before running:")
        print("      export ANTHROPIC_API_KEY=sk-ant-...")
        sys.exit(1)


def load_binary(path: str):
    """Run static analysis and disassembly. Returns (binary_info, disassembler, func_addresses)."""
    from analysis import StaticAnalyzer, Disassembler

    print(f"[*] Loading: {path}")
    analyzer = StaticAnalyzer()
    info = analyzer.analyze(path)

    print(f"[*] Format   : {info.file_format} {info.arch} {info.bits}-bit  ({info.os_target})")
    print(f"[*] EntryPoint: {hex(info.entry_point)}")
    print(f"[*] Sections  : {[s.name for s in info.sections]}")
    print(f"[*] Imports   : {sum(len(i.functions) for i in info.imports)} functions "
          f"from {len(info.imports)} DLLs")
    print(f"[*] Strings   : {len(info.strings)} found")

    # Check for packing
    high_entropy = [s for s in info.sections if s.entropy > 7.0]
    if high_entropy:
        print(f"[!] Possible packing: {[s.name for s in high_entropy]} (entropy > 7.0)")

    print(f"[*] Discovering functions…")
    dis = Disassembler(info)
    addresses = dis.discover_functions()
    print(f"[*] Found {len(addresses)} functions.")

    return info, dis, addresses


# ---------------------------------------------------------------------------
# CLI (no-TUI) mode
# ---------------------------------------------------------------------------

def run_cli(binary_info, disassembler, addresses, store, session_id):
    from analysis import AIAnalyzer

    ai = AIAnalyzer()
    print(f"\n[*] Analyzing {len(addresses)} functions with {config.AI_MODEL}…\n")

    for addr in addresses:
        func = disassembler.get_function(addr)
        if not func or not func.instructions:
            continue

        # Check cache
        cached = store.get_cached_analysis(session_id, addr)
        if cached:
            analysis = cached
            print(f"  [cache] 0x{addr:08x}  {cached.risk_badge}  {cached.suggested_name}")
        else:
            print(f"  [AI]    0x{addr:08x}  {func.name}  ({len(func.instructions)} insns)…", end=' ', flush=True)
            analysis = ai.analyze_function(func, binary_info)
            store.save_function_analysis(session_id, func, analysis)
            print(f"{analysis.risk_badge}  {analysis.suggested_name}")

        if analysis.risk_level in ('HIGH', 'CRITICAL'):
            print(f"           → {analysis.summary[:120]}")
            if analysis.mitre_technique:
                print(f"           → MITRE: {analysis.mitre_technique}")

    # Summary
    summary = store.get_risk_summary(session_id)
    print("\n=== Risk Summary ===")
    for level in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
        count = summary.get(level, 0)
        if count:
            print(f"  {level:<10}: {count}")
    print(f"\n[*] Results saved to: {config.DB_PATH}")


# ---------------------------------------------------------------------------
# Dynamic mode
# ---------------------------------------------------------------------------

def run_dynamic(binary_info, disassembler, addresses, store, session_id, pid=None, binary_path=None):
    from debugger import DebugEngine
    from analysis import AIAnalyzer

    engine = DebugEngine()
    if not engine.is_available:
        print("[!] Frida is not installed or not available. Cannot run dynamic mode.")
        sys.exit(1)

    ai = AIAnalyzer()

    print(f"[*] Dynamic mode — attaching Frida…")
    if pid:
        ok = engine.attach(pid)
        print(f"[*] Attached to PID {pid}: {ok}")
    else:
        spawned_pid = engine.spawn(binary_path)
        if not spawned_pid:
            print("[!] Failed to spawn process.")
            sys.exit(1)
        print(f"[*] Spawned PID: {spawned_pid}")
        pid = spawned_pid

    # Hook first N interesting functions
    def on_entry(snapshot):
        pass  # handled in on_exit where we have full snapshot

    def on_exit(snapshot):
        addr = snapshot.function_address
        func = disassembler.get_function(addr)
        if not func:
            return
        print(f"  [hook] 0x{addr:08x} returned {hex(snapshot.return_value)}")
        analysis = ai.analyze_function(func, binary_info, snapshot)
        store.save_function_analysis(session_id, func, analysis, snapshot)
        print(f"         → {analysis.risk_badge} {analysis.suggested_name}")

    print(f"[*] Hooking {min(50, len(addresses))} functions…")
    for addr in addresses[:50]:
        engine.hook_function(addr, on_entry=on_entry, on_exit=on_exit)

    # Load API tracer
    def on_api_call(call):
        store.save_api_call(
            session_id,
            call['module'], call['function'],
            call['args'], call['retval'],
        )
        print(f"  [api] {call['module']}!{call['function']}({call['args'][:2]})")

    engine.load_api_tracer(on_call=on_api_call)

    engine.resume()
    print(f"[*] Process resumed. Press Ctrl+C to stop.")
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        engine.detach()
        print(f"\n[*] Detached. Results saved to {config.DB_PATH}")


# ---------------------------------------------------------------------------
# TUI mode
# ---------------------------------------------------------------------------

def run_tui(binary_info, disassembler, addresses, store, session_id):
    from analysis import AIAnalyzer
    from ui import AIDebugApp

    ai = AIAnalyzer()
    app = AIDebugApp(
        binary_info=binary_info,
        disassembler=disassembler,
        ai_analyzer=ai,
        trace_store=store,
        session_id=session_id,
        function_addresses=addresses,
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
        print(f"{s['id']:>4}  {s['filename']:<30}  {s['arch']:<10}  {s['created_at']}")


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def run_reports(store, session_id: int, out_dir: str,
                do_html=False, do_yara=False, do_json=False):
    import os
    from reporting import HTMLReporter, YaraGenerator, JSONExporter

    session = store.get_session(session_id)
    if not session:
        print(f"[!] Session {session_id} not found.")
        return

    traces    = store.get_all_traces(session_id)
    api_calls = store.get_api_calls(session_id)

    stem = session.get('filename', f'session_{session_id}').replace('.', '_')
    os.makedirs(out_dir, exist_ok=True)

    print(f"[*] Session {session_id}: {session.get('filename')}  "
          f"({len(traces)} functions analyzed)")

    if do_html:
        path = os.path.join(out_dir, f"{stem}_report.html")
        HTMLReporter().generate(session, traces, path)
        print(f"[+] HTML report   → {path}")

    if do_yara:
        check_api_key()
        path = os.path.join(out_dir, f"{stem}.yar")
        _, count = YaraGenerator().generate(session, traces, path)
        print(f"[+] YARA rules    → {path}  ({count} rules)")

    if do_json:
        path = os.path.join(out_dir, f"{stem}_export.json")
        JSONExporter().export(session, traces, api_calls, path)
        print(f"[+] JSON export   → {path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    banner()

    parser = argparse.ArgumentParser(
        description="AIDebug — AI-Assisted Malware Reverse Engineering Debugger"
    )
    parser.add_argument("--binary",         help="Path to binary (PE or ELF)")
    parser.add_argument("--mode",           choices=["static", "dynamic"], default="static",
                        help="Analysis mode (default: static)")
    parser.add_argument("--pid",            type=int, help="PID to attach (dynamic mode)")
    parser.add_argument("--no-tui",         action="store_true", help="CLI output, no TUI")
    parser.add_argument("--list-sessions",  action="store_true", help="List past sessions")
    parser.add_argument("--session",        type=int, help="Session ID for reporting commands")
    parser.add_argument("--report",         action="store_true", help="Generate HTML report")
    parser.add_argument("--yara",           action="store_true", help="Generate YARA rules (HIGH/CRITICAL)")
    parser.add_argument("--json-export",    action="store_true", help="Export session as JSON for SIEM/SOAR")
    parser.add_argument("--out-dir",        default=".", help="Output directory for reports (default: current dir)")
    parser.add_argument("--db",             default=config.DB_PATH,
                        help=f"SQLite DB path (default: {config.DB_PATH})")
    args = parser.parse_args()

    from storage import TraceStore
    store = TraceStore(args.db)

    if args.list_sessions:
        list_sessions(store)
        return

    # ---- Reporting commands (work on an existing session, no binary needed) ----
    if args.report or args.yara or args.json_export:
        if not args.session:
            # Auto-pick the most recent session
            sessions = store.list_sessions()
            if not sessions:
                print("[!] No sessions found. Run an analysis first.")
                sys.exit(1)
            args.session = sessions[0]['id']
            print(f"[*] Auto-selected most recent session: {args.session}")
        run_reports(store, args.session, args.out_dir,
                    do_html=args.report, do_yara=args.yara, do_json=args.json_export)
        return

    if not args.binary:
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(args.binary):
        print(f"[!] File not found: {args.binary}")
        sys.exit(1)

    check_api_key()

    binary_info, disassembler, addresses = load_binary(args.binary)
    session_id = store.create_session(binary_info)
    print(f"[*] Session ID: {session_id}")

    if args.mode == "dynamic":
        run_dynamic(binary_info, disassembler, addresses, store, session_id,
                    pid=args.pid, binary_path=args.binary)
    elif args.no_tui:
        run_cli(binary_info, disassembler, addresses, store, session_id)
    else:
        run_tui(binary_info, disassembler, addresses, store, session_id)


if __name__ == "__main__":
    main()
