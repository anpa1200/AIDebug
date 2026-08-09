"""
AIDebug — Textual TUI
Three-panel layout: Function List | Disassembly | AI Analysis
Bottom bar: chat input for follow-up questions to the AI.
"""
from __future__ import annotations

import json
import threading

from rich.markup import escape
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    LoadingIndicator,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

import config
from analysis.cfg import CFGBuilder, CFGTextRenderer


def _display_text(value, limit: int = 8_000) -> str:
    """Keep newlines readable while neutralizing terminal control sequences."""
    rendered = []
    for character in str(value)[:limit]:
        if character in "\n\t" or character.isprintable():
            rendered.append(character)
        elif ord(character) <= 0xFF:
            rendered.append(f"\\x{ord(character):02x}")
        else:
            rendered.append(f"\\u{ord(character):04x}")
    return "".join(rendered)


def _markup_text(value, limit: int = 8_000) -> str:
    return escape(_display_text(value, limit))

# ---------------------------------------------------------------------------
# Custom messages (worker → UI thread)
# ---------------------------------------------------------------------------

class AnalysisReady(Message):
    def __init__(self, address: int, analysis) -> None:
        self.address  = address
        self.analysis = analysis
        super().__init__()


class AnalysisFailed(Message):
    def __init__(self, address: int, error: str) -> None:
        self.address = address
        self.error = error
        super().__init__()


class FollowupReady(Message):
    def __init__(self, address: int, text: str, *, failed: bool = False) -> None:
        self.address = address
        self.text = text
        self.failed = failed
        super().__init__()


class StatusUpdate(Message):
    def __init__(self, text: str) -> None:
        self.text = text
        super().__init__()


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

class AIDebugApp(App):

    TITLE = config.APP_TITLE
    CSS = """
Screen {
    background: $surface;
}

#toolbar {
    height: 1;
    background: $primary-darken-3;
    color: $text;
    padding: 0 2;
    content-align: left middle;
}

#main {
    height: 1fr;
    layout: horizontal;
}

/* ---- Left: function list ---- */
#left-panel {
    width: 28%;
    border: solid $primary-darken-2;
    padding: 0;
}

#left-title {
    background: $primary-darken-3;
    color: $text-muted;
    height: 1;
    padding: 0 1;
    text-style: bold;
}

#func-table {
    height: 1fr;
}

/* ---- Center: disassembly ---- */
#center-panel {
    width: 40%;
    border: solid $primary-darken-2;
}

#center-title {
    background: $primary-darken-3;
    color: $text-muted;
    height: 1;
    padding: 0 1;
    text-style: bold;
}

#disasm-log {
    height: 70%;
}

#reg-title {
    height: 1;
    background: $primary-darken-3;
    color: $text-muted;
    padding: 0 1;
}

#reg-view {
    height: 30%;
    overflow-y: auto;
}

/* ---- Right: AI analysis ---- */
#right-panel {
    width: 32%;
    border: solid $primary-darken-2;
}

#right-title {
    background: $primary-darken-3;
    color: $text-muted;
    height: 1;
    padding: 0 1;
    text-style: bold;
}

#ai-log {
    height: 1fr;
}

#ai-loading {
    height: 3;
    display: none;
    align: center middle;
}

/* ---- Bottom chat ---- */
#chat-bar {
    height: 3;
    border: solid $accent;
    layout: horizontal;
}

#chat-label {
    width: 8;
    content-align: center middle;
    background: $accent-darken-2;
    color: $text;
    padding: 0 1;
}

#chat-input {
    width: 1fr;
    border: none;
}

/* ---- Status bar ---- */
#status-bar {
    height: 1;
    background: $primary-darken-3;
    color: $text-muted;
    padding: 0 2;
    content-align: left middle;
}
"""

    BINDINGS = [
        Binding("q",        "quit",         "Quit",           show=True),
        Binding("ctrl+a",   "analyze_all",  "Analyze All",    show=True),
        Binding("ctrl+h",   "show_history", "History",        show=True),
        Binding("ctrl+f",   "focus_chat",   "Follow-up",       show=True),
        Binding("escape",   "blur_chat",    "Unfocus Chat",   show=False),
    ]

    # Reactive state
    _current_address: reactive[int | None] = reactive(None)
    _status: reactive[str] = reactive("")

    # ------------------------------------------------------------------
    # Init / setup
    # ------------------------------------------------------------------

    def __init__(self, binary_info, disassembler, ai_analyzer, trace_store,
                 session_id: int, function_addresses: list, *,
                 allow_bulk_analysis: bool = False,
                 max_bulk_functions: int = 25,
                 prior_sessions: list | None = None):
        super().__init__()
        self.binary_info        = binary_info
        self.disassembler       = disassembler
        self.ai_analyzer        = ai_analyzer
        self.trace_store        = trace_store
        self.session_id         = session_id
        self.function_addresses = function_addresses
        self._analyses: dict    = {}   # address -> AIAnalysis
        self._analyzing: set    = set()
        self._ai_lock = threading.RLock()
        self._followup_running = False
        self._allow_bulk_analysis = allow_bulk_analysis
        self._max_bulk_functions = max(1, max_bulk_functions)
        self._startup_warnings: list[str] = []
        self._cached_count = 0
        if prior_sessions is None:
            finder = getattr(self.trace_store, "find_sessions_by_sha256", None)
            if callable(finder):
                prior_sessions = finder(
                    self.binary_info.sha256,
                    exclude_session_id=self.session_id,
                )
        self.prior_sessions = list(prior_sessions or [])

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        info = self.binary_info
        yield Header(show_clock=True)

        # Top toolbar with binary info
        analyzer_mode = getattr(self.ai_analyzer, "display_name", config.AI_MODEL)
        if getattr(self.ai_analyzer, "remote_enabled", True):
            analyzer_mode = f"{analyzer_mode} (selection transmits evidence)"
        toolbar_text = Text(
            f" {_display_text(info.filename, 240)}  |  {_display_text(info.file_format, 40)} "
            f"{_display_text(info.arch, 40)} {info.bits}-bit  "
            f"|  {len(self.function_addresses)} functions  |  SHA256: {info.sha256[:12]}... "
            f"|  history: {len(self.prior_sessions)} prior session(s) "
            f"|  {_display_text(analyzer_mode, 160)}"
        )
        yield Static(toolbar_text, id="toolbar")

        with Horizontal(id="main"):
            # LEFT — function list
            with Vertical(id="left-panel"):
                yield Label(" FUNCTIONS ", id="left-title")
                yield DataTable(id="func-table", cursor_type="row")

            # CENTER — disassembly + registers
            with Vertical(id="center-panel"):
                yield Label(" DISASSEMBLY ", id="center-title")
                yield RichLog(id="disasm-log", highlight=True, markup=True, wrap=False)
                yield Label(" REGISTERS / SNAPSHOT ", id="reg-title")
                yield RichLog(id="reg-view", highlight=True, markup=True)

            # RIGHT — tabbed panel
            with Vertical(id="right-panel"):
                yield LoadingIndicator(id="ai-loading")
                with TabbedContent(id="right-tabs"):
                    with TabPane("AI Analysis", id="tab-ai"):
                        yield RichLog(id="ai-log", highlight=True, markup=True)
                    with TabPane("CFG", id="tab-cfg"):
                        yield RichLog(id="cfg-log", highlight=True, markup=True)
                    with TabPane("Patterns", id="tab-patterns"):
                        yield RichLog(id="patterns-log", highlight=True, markup=True)
                    with TabPane("Decompiled C", id="tab-decompile"):
                        yield RichLog(id="decompile-log", highlight=True, markup=True)
                    with TabPane("History", id="tab-history"):
                        yield RichLog(id="history-log", highlight=True, markup=True)

        # Bottom — chat bar
        with Horizontal(id="chat-bar"):
            remote_enabled = getattr(self.ai_analyzer, "remote_enabled", True)
            yield Label(" Ask AI " if remote_enabled else " Offline ", id="chat-label")
            yield Input(
                id="chat-input",
                placeholder=(
                    "Type a follow-up question…"
                    if remote_enabled
                    else "Follow-up chat is unavailable in offline mode"
                ),
                max_length=getattr(config, "MAX_AI_FOLLOWUP_CHARS", 4000),
                disabled=not remote_enabled,
            )

        # Status
        yield Static(self._status or "Ready.", id="status-bar")
        yield Footer()

    # ------------------------------------------------------------------
    # Startup
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._populate_function_table()
        self._render_history()
        if self._startup_warnings:
            self._set_status(self._startup_warnings[0])
        elif self.prior_sessions:
            self._set_status(
                f"Found {len(self.prior_sessions)} prior session(s); restored "
                f"{self._cached_count} compatible function analyses."
            )
        else:
            self._set_status(f"Loaded {len(self.function_addresses)} functions — select one to analyze.")

    def _populate_function_table(self):
        table: DataTable = self.query_one("#func-table")
        table.add_columns("Risk", "Address", "Name", "Insns")

        for addr in self.function_addresses:
            func = self.disassembler.get_function(addr)
            if not func:
                continue
            # Check if already cached in DB
            cached = self.trace_store.get_cached_analysis(
                self.session_id,
                addr,
                cache_key=getattr(self.ai_analyzer, "cache_key", None),
            )
            if cached:
                self._analyses[addr] = cached
                self._cached_count += 1
                try:
                    self.trace_store.save_function_analysis(self.session_id, func, cached)
                    self.trace_store.save_patterns(
                        self.session_id,
                        addr,
                        getattr(func, "patterns", []),
                    )
                except Exception as exc:
                    self._startup_warnings.append(
                        f"Could not persist cached result at 0x{addr:08x}: {exc}"
                    )
                badge = Text(
                    _display_text(cached.risk_badge, 20),
                    style=f"bold {self._risk_color(cached.risk_level)}",
                )
                name = Text(_display_text(cached.suggested_name, 30))
            else:
                badge = Text("[ -- ]", style="dim")
                name = Text(_display_text(func.name, 30))

            table.add_row(
                badge,
                f"0x{addr:08x}",
                name,
                str(len(func.instructions)),
                key=str(addr),
            )

    def _render_history(self) -> None:
        log: RichLog = self.query_one("#history-log")
        log.clear()
        log.write(
            f"[bold cyan]SHA-256 analysis history[/bold cyan]\n"
            f"[dim]{_markup_text(self.binary_info.sha256, 128)}[/dim]\n"
        )
        if not self.prior_sessions:
            log.write(
                "[dim]No previous sessions were found for this exact file hash. "
                "Results from this run will be retained in the local SQLite database.[/dim]"
            )
            return

        log.write(
            f"[bold green]{len(self.prior_sessions)} previous session(s) found[/bold green]\n"
            f"[dim]Database: {_markup_text(getattr(self.trace_store, 'db_path', ''), 8_192)}[/dim]\n"
        )
        for session in self.prior_sessions:
            session_id = session.get("id", "?")
            status = _markup_text(session.get("status") or "legacy", 32)
            mode = _markup_text(session.get("analysis_mode") or "unknown", 32)
            created = _markup_text(session.get("created_at") or "unknown", 64)
            analyzer = _markup_text(session.get("analyzer") or "unknown", 160)
            log.write(
                f"[bold]Session {session_id}[/bold]  [{status}]  {mode}  [dim]{created}[/dim]"
            )
            log.write(f"  Analyzer: {analyzer}")
            log.write(
                f"  Evidence: {session.get('function_count', 0)} functions; "
                f"{session.get('pattern_count', 0)} patterns; "
                f"{session.get('api_call_count', 0)} API calls; "
                f"{session.get('network_event_count', 0)} network events; "
                f"{session.get('runtime_event_count', 0)} runtime events"
            )
            log.write(
                f"  Risk: CRITICAL={session.get('critical_count', 0)} "
                f"HIGH={session.get('high_count', 0)} "
                f"MEDIUM={session.get('medium_count', 0)} "
                f"LOW={session.get('low_count', 0)}"
            )
            log.write(
                f"  [cyan]Full export:[/cyan] aidebug --session {session_id} "
                "--json-export --out-dir reports/\n"
            )

        history_reader = getattr(
            self.trace_store,
            "get_function_history_by_sha256",
            None,
        )
        findings = []
        if callable(history_reader):
            findings = history_reader(
                self.binary_info.sha256,
                exclude_session_id=self.session_id,
                limit=300,
            )
        if not findings:
            return
        log.write("[bold cyan]Previous function findings[/bold cyan]")
        for finding in findings:
            try:
                ai = json.loads(finding.get("ai_analysis_json") or "{}")
            except (json.JSONDecodeError, TypeError, ValueError):
                ai = {}
            if not isinstance(ai, dict):
                ai = {}
            try:
                address = f"0x{int(finding.get('address', 0)):x}"
            except (TypeError, ValueError, OverflowError):
                address = "unknown"
            name = ai.get("suggested_name") or finding.get("name") or "unknown"
            risk = finding.get("risk_level") or ai.get("risk_level") or "UNKNOWN"
            summary = ai.get("summary") or "No stored summary"
            log.write(
                f"  [dim]session {finding.get('session_id', '?')}[/dim] "
                f"{_markup_text(address, 32)} "
                f"[bold]{_markup_text(risk, 20)}[/bold] "
                f"{_markup_text(name, 120)}"
            )
            log.write(f"    {_markup_text(summary, 500)}")

    # ------------------------------------------------------------------
    # Function selection
    # ------------------------------------------------------------------

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        try:
            addr = int(event.row_key.value, 0)
        except (ValueError, TypeError):
            return
        self._show_function(addr)

    def _show_function(self, address: int):
        self._current_address = address
        func = self.disassembler.get_function(address)
        if not func:
            return

        self._render_disassembly(func)
        self._render_registers(None)
        self._render_cfg(func)
        self._render_patterns(func)
        self._render_decompilation(func)

        # Show cached analysis if available
        if address in self._analyses:
            context_id = self._context_id(address)
            if not self.ai_analyzer.has_context(context_id):
                try:
                    self.ai_analyzer.seed_context(
                        func,
                        self.binary_info,
                        self._analyses[address],
                        context_id=context_id,
                    )
                except Exception as exc:
                    self._set_status(f"Could not prepare follow-up context: {exc}")
            self._sync_loading_indicator()
            self._render_ai_analysis(self._analyses[address])
        else:
            self._request_ai_analysis(address)

    # ------------------------------------------------------------------
    # Disassembly panel
    # ------------------------------------------------------------------

    def _render_disassembly(self, func):
        log: RichLog = self.query_one("#disasm-log")
        log.clear()
        log.write(f"[bold cyan]Function:[/bold cyan] [yellow]{_markup_text(func.name)}[/yellow]  "
                  f"[dim]({len(func.instructions)} instructions)[/dim]\n")

        for insn in func.instructions:
            mnem = str(insn.mnemonic)
            # Color-code by mnemonic category
            if mnem in ('call', 'callq'):
                color = "yellow"
            elif mnem in ('ret', 'retn', 'retf', 'retq'):
                color = "green"
            elif mnem.startswith('j'):
                color = "magenta"
            elif mnem in ('push', 'pop'):
                color = "cyan"
            elif mnem in ('mov', 'lea', 'movsx', 'movzx'):
                color = "white"
            else:
                color = "bright_white"

            log.write(
                f"[dim]0x{insn.address:08x}[/dim]  "
                f"[{color}]{_markup_text(mnem, 64):<8}[/{color}] "
                f"[bright_white]{_markup_text(insn.op_str)}[/bright_white]"
            )

        if func.strings_referenced:
            log.write("\n[dim]── Strings referenced ──[/dim]")
            for s in func.strings_referenced:
                log.write(f'[green]  "{_markup_text(s)}"[/green]')

    # ------------------------------------------------------------------
    # Register / snapshot panel
    # ------------------------------------------------------------------

    def _render_registers(self, snapshot):
        log: RichLog = self.query_one("#reg-view")
        log.clear()
        if snapshot is None:
            log.write("[dim](No runtime snapshot — static analysis mode)[/dim]")
            return
        regs = snapshot.entry_registers
        for i, (reg, val) in enumerate(regs.items()):
            try:
                num = int(val, 0)
                val_str = f"{hex(num):>12}  ({num})"
            except (ValueError, TypeError):
                val_str = str(val)
            log.write(f"[cyan]{_markup_text(str(reg).upper(), 32):<5}[/cyan]  {_markup_text(val_str)}")
        if snapshot.entry_stack_hex:
            log.write(f"\n[dim]Stack: {_markup_text(snapshot.entry_stack_hex)}[/dim]")

    # ------------------------------------------------------------------
    # CFG panel
    # ------------------------------------------------------------------

    def _render_cfg(self, func):
        log: RichLog = self.query_one("#cfg-log")
        log.clear()
        try:
            cfg = CFGBuilder().build(func)
            text = CFGTextRenderer().render(cfg)
            log.write(Text(_display_text(text)))
        except Exception as exc:
            log.write(f"[dim]CFG unavailable: {_markup_text(exc)}[/dim]")

    # ------------------------------------------------------------------
    # Patterns panel
    # ------------------------------------------------------------------

    def _render_patterns(self, func):
        log: RichLog = self.query_one("#patterns-log")
        log.clear()
        patterns = getattr(func, 'patterns', [])
        if not patterns:
            log.write("[dim]No malware patterns detected in this function.[/dim]")
            return
        for p in patterns:
            severity = str(getattr(p, "severity", "INFO")).upper()
            severity_color = {"HIGH": "red", "MEDIUM": "yellow", "INFO": "cyan"}.get(
                severity,
                "white",
            )
            severity_badge = {"HIGH": "[HIGH]", "MEDIUM": "[MED ]", "INFO": "[INFO]"}.get(
                severity,
                "[??? ]",
            )
            log.write(
                f"[bold {severity_color}]{_markup_text(severity_badge)}[/bold {severity_color}] "
                f"[bold]{_markup_text(p.name)}[/bold]  [dim]@ 0x{p.address:08x}[/dim]"
            )
            log.write(f"  {_markup_text(p.description)}")
            if p.evidence:
                log.write(f"  [dim]Evidence: {_markup_text(p.evidence)}[/dim]")
            log.write("")

    def _render_decompilation(self, func):
        log: RichLog = self.query_one("#decompile-log")
        log.clear()
        code = getattr(func, "decompiled_code", "")
        if not code:
            log.write(
                "[dim]No Ghidra decompiler output was requested. "
                "Restart with --decompile.[/dim]"
            )
            return
        language = getattr(func, "decompile_language", "c") or "c"
        backend = getattr(func, "decompile_backend", "ghidra") or "ghidra"
        warning = getattr(func, "decompile_warning", "") or (
            "Reconstructed from machine code; not original source. "
            "Types, names, and structure require analyst review."
        )
        log.write(
            f"[bold cyan]{_markup_text(backend, 64)} decompiler output[/bold cyan] "
            f"[dim]({_markup_text(language, 32)}-like)[/dim]\n"
        )
        log.write(f"[yellow]{_markup_text(warning, 1_024)}[/yellow]\n")
        log.write(Text(_display_text(code, config.MAX_DECOMPILED_CHARS)))

    # ------------------------------------------------------------------
    # AI analysis panel
    # ------------------------------------------------------------------

    def _request_ai_analysis(self, address: int):
        if address in self._analyzing:
            self._sync_loading_indicator()
            return
        self._analyzing.add(address)

        # Show loading spinner
        self.query_one("#ai-loading").display = True
        ai_log: RichLog = self.query_one("#ai-log")
        ai_log.clear()
        ai_log.write("[dim]Analyzing function…[/dim]")

        analyzer_name = getattr(self.ai_analyzer, "display_name", "configured analyzer")
        self._set_status(f"Analyzing 0x{address:08x} with {analyzer_name}…")
        self._run_ai_worker(address)

    @work(thread=True)
    def _run_ai_worker(self, address: int):
        func     = self.disassembler.get_function(address)
        snapshot = None  # populated if dynamic mode has data

        try:
            if not func or not func.instructions:
                raise ValueError("Function has no instructions to analyze")
            with self._ai_lock:
                self.trace_store.save_patterns(
                    self.session_id,
                    address,
                    getattr(func, "patterns", []),
                )
                analysis = self.ai_analyzer.analyze_function(
                    func,
                    self.binary_info,
                    snapshot,
                    context_id=self._context_id(address),
                )
                self.trace_store.save_function_analysis(
                    self.session_id,
                    func,
                    analysis,
                    snapshot,
                )
            self.post_message(AnalysisReady(address, analysis))
        except Exception as exc:
            self.post_message(AnalysisFailed(address, str(exc)))

    def on_analysis_ready(self, event: AnalysisReady):
        self._analyzing.discard(event.address)
        self._analyses[event.address] = event.analysis
        self._sync_loading_indicator()
        if event.address == self._current_address:
            self._render_ai_analysis(event.analysis)
            self._set_status(
                f"Analysis complete: 0x{event.address:08x}  "
                f"→ {event.analysis.suggested_name}  [{event.analysis.risk_level}]"
            )
        elif self._current_address not in self._analyzing:
            self._set_status(f"Background analysis complete: 0x{event.address:08x}")
        # Update function table row with name and risk.
        self._update_table_row(event.address, event.analysis)

    def on_analysis_failed(self, event: AnalysisFailed):
        self._analyzing.discard(event.address)
        self._sync_loading_indicator()
        if event.address == self._current_address:
            log: RichLog = self.query_one("#ai-log")
            log.clear()
            log.write(
                f"[bold red]Analysis failed[/bold red]\n{_markup_text(event.error)}\n\n"
                "[dim]Select the function again to retry.[/dim]"
            )
            self._set_status(f"Analysis failed for 0x{event.address:08x}: {event.error}")
        elif self._current_address not in self._analyzing:
            self._set_status(f"Background analysis failed for 0x{event.address:08x}")

    def _render_ai_analysis(self, analysis):
        self.query_one("#ai-loading").display = False
        log: RichLog = self.query_one("#ai-log")
        log.clear()

        risk_color = self._risk_color(analysis.risk_level)
        log.write(
            f"[bold {risk_color}]{_markup_text(analysis.risk_badge)}[/bold {risk_color}]  "
            f"[bold]{_markup_text(analysis.suggested_name)}[/bold]\n"
        )

        log.write(f"[bold]Summary:[/bold]\n{_markup_text(analysis.summary)}\n")

        if analysis.mitre_technique:
            log.write(
                f"[bold]MITRE ATT&CK:[/bold] "
                f"[yellow]{_markup_text(analysis.mitre_technique)}[/yellow]\n"
            )

        if isinstance(analysis.parameters, list) and analysis.parameters:
            log.write("[bold]Parameters:[/bold]")
            for p in analysis.parameters:
                if not isinstance(p, dict):
                    continue
                log.write(
                    f"  [cyan]{_markup_text(p.get('name', '?'))}[/cyan] "
                    f"({_markup_text(p.get('type', '?'))}): "
                    f"{_markup_text(p.get('description', ''))}"
                )

        log.write(
            f"\n[bold]Return value:[/bold]\n{_markup_text(analysis.return_value)}\n"
        )

        if isinstance(analysis.behaviors, list) and analysis.behaviors:
            log.write("[bold]Behaviors:[/bold]")
            for b in analysis.behaviors:
                log.write(f"  • {_markup_text(b)}")

        if analysis.notes:
            log.write(f"\n[bold]Notes:[/bold]\n[dim]{_markup_text(analysis.notes)}[/dim]")

        review = getattr(analysis, "decompilation_review", {})
        if isinstance(review, dict) and review:
            status = review.get("status", "NOT_AVAILABLE")
            confidence = review.get("confidence", "LOW")
            log.write(
                "\n[bold]LLM decompilation cross-check:[/bold] "
                f"[cyan]{_markup_text(status, 32)}[/cyan] "
                f"[dim](confidence: {_markup_text(confidence, 16)})[/dim]"
            )
            for finding in review.get("findings", [])[:16]:
                log.write(f"  • {_markup_text(finding, 1_000)}")
            corrected = review.get("corrected_pseudocode", "")
            if corrected:
                log.write("[bold]Suggested corrected pseudo-code:[/bold]")
                log.write(Text(_display_text(corrected, 8_000)))

        log.write("\n[dim]─────────────────────────────────────[/dim]")
        if getattr(self.ai_analyzer, "remote_enabled", True):
            log.write("[dim]Type a question below to ask the AI.[/dim]")
        else:
            log.write("[dim]Offline deterministic result; follow-up chat is disabled.[/dim]")

    # ------------------------------------------------------------------
    # Chat / follow-up
    # ------------------------------------------------------------------

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "chat-input":
            return
        question = event.value.strip()
        if not question:
            return
        address = self._current_address
        if address is None:
            self._set_status("Select and analyze a function before asking a follow-up.")
            return
        if address not in self._analyses:
            self._set_status("Wait for the selected function analysis to complete.")
            return
        if self._followup_running:
            self._set_status("A follow-up request is already running.")
            return
        event.input.clear()
        event.input.disabled = True
        self._followup_running = True

        ai_log: RichLog = self.query_one("#ai-log")
        ai_log.write(f"\n[bold cyan]You:[/bold cyan] {_markup_text(question)}")
        ai_log.write("[dim]Thinking…[/dim]")
        self._set_status("Waiting for AI follow-up…")
        self._run_followup_worker(address, question)

    @work(thread=True)
    def _run_followup_worker(self, address: int, question: str):
        try:
            context_id = self._context_id(address)
            with self._ai_lock:
                if not self.ai_analyzer.has_context(context_id):
                    func = self.disassembler.get_function(address)
                    analysis = self._analyses.get(address)
                    if func and analysis:
                        self.ai_analyzer.seed_context(
                            func,
                            self.binary_info,
                            analysis,
                            context_id=context_id,
                        )
                answer = self.ai_analyzer.ask_followup(question, context_id=context_id)
            self.post_message(FollowupReady(address, answer))
        except Exception as exc:
            self.post_message(FollowupReady(address, str(exc), failed=True))

    def on_followup_ready(self, event: FollowupReady):
        self._followup_running = False
        self.query_one("#chat-input", Input).disabled = False
        if event.address == self._current_address:
            log: RichLog = self.query_one("#ai-log")
            label = "Error" if event.failed else "Assistant"
            color = "red" if event.failed else "green"
            log.write(
                f"[bold {color}]{label}:[/bold {color}] {_markup_text(event.text)}\n"
            )
        self._set_status("Follow-up failed." if event.failed else "Ready.")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_show_history(self):
        self.query_one("#right-tabs", TabbedContent).active = "tab-history"
        self._set_status(
            f"Showing {len(self.prior_sessions)} prior session(s) for this SHA-256."
        )

    def action_analyze_all(self):
        """Queue AI analysis for all functions not yet analyzed."""
        if not self._allow_bulk_analysis and getattr(self.ai_analyzer, "remote_enabled", True):
            self._set_status(
                "Bulk remote analysis is locked. Restart with --accept-ai-cost or use --offline."
            )
            return
        pending = [
            address
            for address in self.function_addresses
            if address not in self._analyses and address not in self._analyzing
        ][:self._max_bulk_functions]
        if not pending:
            self._set_status("All functions already analyzed.")
            return
        self._analyzing.update(pending)
        self._set_status(f"Queueing {len(pending)} functions for AI analysis…")
        self._run_batch_worker(pending)

    @work(thread=True)
    def _run_batch_worker(self, addresses: list):
        for i, addr in enumerate(addresses):
            func = self.disassembler.get_function(addr)
            if not func or not func.instructions:
                self.post_message(AnalysisFailed(addr, "Function has no instructions to analyze"))
                continue
            try:
                with self._ai_lock:
                    self.trace_store.save_patterns(
                        self.session_id,
                        addr,
                        getattr(func, "patterns", []),
                    )
                    analysis = self.ai_analyzer.analyze_function(
                        func,
                        self.binary_info,
                        context_id=self._context_id(addr),
                    )
                    self.trace_store.save_function_analysis(
                        self.session_id,
                        func,
                        analysis,
                    )
                self.post_message(AnalysisReady(addr, analysis))
                self.post_message(StatusUpdate(
                    f"Batch: {i+1}/{len(addresses)} — {analysis.suggested_name}"
                ))
            except Exception as exc:
                self.post_message(AnalysisFailed(addr, str(exc)))

    def action_focus_chat(self):
        self.query_one("#chat-input").focus()

    def action_blur_chat(self):
        self.query_one("#func-table").focus()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def on_status_update(self, event: StatusUpdate):
        self._set_status(event.text)

    def _set_status(self, text: str):
        try:
            bar: Static = self.query_one("#status-bar")
            bar.update(Text(f" {_display_text(text)}"))
        except Exception:
            pass

    def _update_table_row(self, address: int, analysis):
        """Refresh the function table row after analysis completes."""
        table: DataTable = self.query_one("#func-table")
        key = str(address)
        try:
            risk_color = self._risk_color(analysis.risk_level)
            badge = Text(_display_text(analysis.risk_badge, 20), style=f"bold {risk_color}")
            table.update_cell(key, "Risk", badge, update_width=False)
            table.update_cell(
                key,
                "Name",
                Text(_display_text(analysis.suggested_name, 30)),
                update_width=False,
            )
        except Exception:
            pass

    def _context_id(self, address: int) -> str:
        return f"session:{self.session_id}:function:{address:x}"

    def _sync_loading_indicator(self) -> None:
        spinner = self.query_one("#ai-loading")
        spinner.display = self._current_address in self._analyzing

    def _risk_color(self, risk_level: str) -> str:
        return {
            "LOW": "green",
            "MEDIUM": "yellow",
            "HIGH": "red",
            "CRITICAL": "bright_red",
            "UNKNOWN": "white",
        }.get(str(risk_level).upper(), "white")
