"""
AIDebug — Textual TUI
Three-panel layout: Function List | Disassembly | AI Analysis
Bottom bar: chat input for follow-up questions to the AI.
"""
from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass
from typing import Optional

from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import (
    DataTable, Footer, Header, Input, Label,
    RichLog, Static, LoadingIndicator, TabbedContent, TabPane,
)
from textual import work

from analysis.cfg import CFGBuilder, CFGTextRenderer
from analysis.pattern_detector import PatternDetector

import config


# ---------------------------------------------------------------------------
# Custom messages (worker → UI thread)
# ---------------------------------------------------------------------------

class AnalysisReady(Message):
    def __init__(self, address: int, analysis) -> None:
        self.address  = address
        self.analysis = analysis
        super().__init__()


class FollowupReady(Message):
    def __init__(self, text: str) -> None:
        self.text = text
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
        Binding("a",        "analyze_all",  "Analyze All",    show=True),
        Binding("r",        "reset_session","Reset DB",       show=False),
        Binding("ctrl+f",   "focus_search", "Search",         show=True),
        Binding("escape",   "blur_chat",    "Unfocus Chat",   show=False),
    ]

    # Reactive state
    _current_address: reactive[Optional[int]] = reactive(None)
    _status: reactive[str] = reactive("")

    # ------------------------------------------------------------------
    # Init / setup
    # ------------------------------------------------------------------

    def __init__(self, binary_info, disassembler, ai_analyzer, trace_store,
                 session_id: int, function_addresses: list):
        super().__init__()
        self.binary_info        = binary_info
        self.disassembler       = disassembler
        self.ai_analyzer        = ai_analyzer
        self.trace_store        = trace_store
        self.session_id         = session_id
        self.function_addresses = function_addresses
        self._analyses: dict    = {}   # address -> AIAnalysis
        self._analyzing: set    = set()

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        info = self.binary_info
        yield Header(show_clock=True)

        # Top toolbar with binary info
        toolbar_text = (
            f" {info.filename}  |  {info.file_format} {info.arch} {info.bits}-bit  "
            f"|  {len(self.function_addresses)} functions  |  SHA256: {info.sha256[:12]}..."
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
                    with TabPane("Network", id="tab-network"):
                        yield RichLog(id="network-log", highlight=True, markup=True)

        # Bottom — chat bar
        with Horizontal(id="chat-bar"):
            yield Label(" Ask AI ", id="chat-label")
            yield Input(id="chat-input", placeholder="Type a follow-up question…")

        # Status
        yield Static(self._status or "Ready.", id="status-bar")
        yield Footer()

    # ------------------------------------------------------------------
    # Startup
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._populate_function_table()
        self._set_status(f"Loaded {len(self.function_addresses)} functions — select one to analyze.")

    def _populate_function_table(self):
        table: DataTable = self.query_one("#func-table")
        table.add_columns("Risk", "Address", "Name", "Insns")

        for addr in self.function_addresses:
            func = self.disassembler.get_function(addr)
            if not func:
                continue
            # Check if already cached in DB
            cached = self.trace_store.get_cached_analysis(self.session_id, addr)
            if cached:
                self._analyses[addr] = cached
                badge = cached.risk_badge
                name  = cached.suggested_name
            else:
                badge = "[dim][ -- ][/dim]"
                name  = func.name

            table.add_row(
                badge,
                f"0x{addr:08x}",
                name[:30],
                str(len(func.instructions)),
                key=str(addr),
            )

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

        # Show cached analysis if available
        if address in self._analyses:
            self._render_ai_analysis(self._analyses[address])
        else:
            self._request_ai_analysis(address)

    # ------------------------------------------------------------------
    # Disassembly panel
    # ------------------------------------------------------------------

    def _render_disassembly(self, func):
        log: RichLog = self.query_one("#disasm-log")
        log.clear()
        log.write(f"[bold cyan]Function:[/bold cyan] [yellow]{func.name}[/yellow]  "
                  f"[dim]({len(func.instructions)} instructions)[/dim]\n")

        for insn in func.instructions:
            mnem = insn.mnemonic
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
                f"[{color}]{mnem:<8}[/{color}] "
                f"[bright_white]{insn.op_str}[/bright_white]"
            )

        if func.strings_referenced:
            log.write("\n[dim]── Strings referenced ──[/dim]")
            for s in func.strings_referenced:
                log.write(f'[green]  "{s}"[/green]')

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
            log.write(f"[cyan]{reg.upper():<5}[/cyan]  {val_str}")
        if snapshot.entry_stack_hex:
            log.write(f"\n[dim]Stack: {snapshot.entry_stack_hex}[/dim]")

    # ------------------------------------------------------------------
    # CFG panel
    # ------------------------------------------------------------------

    def _render_cfg(self, func):
        log: RichLog = self.query_one("#cfg-log")
        log.clear()
        try:
            cfg = CFGBuilder().build(func)
            text = CFGTextRenderer().render(cfg)
            log.write(text)
        except Exception as exc:
            log.write(f"[dim]CFG unavailable: {exc}[/dim]")

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
            log.write(
                f"[bold {p.severity_color}]{p.severity_badge}[/bold {p.severity_color}] "
                f"[bold]{p.name}[/bold]  [dim]@ 0x{p.address:08x}[/dim]"
            )
            log.write(f"  {p.description}")
            if p.evidence:
                log.write(f"  [dim]Evidence: {p.evidence}[/dim]")
            log.write("")

    # ------------------------------------------------------------------
    # Network panel (called from dynamic mode callbacks)
    # ------------------------------------------------------------------

    def append_network_event(self, event: dict):
        """Append a network event to the Network tab (thread-safe via call_from_thread)."""
        def _do():
            log: RichLog = self.query_one("#network-log")
            evt   = event.get('event', '')
            fn    = event.get('function', '')
            ip    = event.get('ip', '')
            port  = event.get('port', 0)
            size  = event.get('size', 0)
            url   = event.get('url', '')
            dest  = url or (f"{ip}:{port}" if ip else '?')
            log.write(
                f"[cyan]{evt}[/cyan] [yellow]{fn}[/yellow]  "
                f"[white]{dest}[/white]  [dim]{size} bytes[/dim]"
            )
        self.call_from_thread(_do)

    # ------------------------------------------------------------------
    # AI analysis panel
    # ------------------------------------------------------------------

    def _request_ai_analysis(self, address: int):
        if address in self._analyzing:
            return
        self._analyzing.add(address)

        # Show loading spinner
        self.query_one("#ai-loading").display = True
        ai_log: RichLog = self.query_one("#ai-log")
        ai_log.clear()
        ai_log.write("[dim]Analyzing with AI…[/dim]")

        self._set_status(f"Sending 0x{address:08x} to Claude for analysis…")
        self._run_ai_worker(address)

    @work(thread=True)
    def _run_ai_worker(self, address: int):
        func     = self.disassembler.get_function(address)
        snapshot = None  # populated if dynamic mode has data

        try:
            analysis = self.ai_analyzer.analyze_function(
                func, self.binary_info, snapshot
            )
            self._analyses[address] = analysis
            self.trace_store.save_function_analysis(
                self.session_id, func, analysis, snapshot
            )
            self.post_message(AnalysisReady(address, analysis))
        except Exception as exc:
            self.post_message(StatusUpdate(f"AI error: {exc}"))
        finally:
            self._analyzing.discard(address)

    def on_analysis_ready(self, event: AnalysisReady):
        self.query_one("#ai-loading").display = False
        if event.address == self._current_address:
            self._render_ai_analysis(event.analysis)
        # Update function table row with name and risk
        self._update_table_row(event.address, event.analysis)
        self._set_status(
            f"Analysis complete: 0x{event.address:08x}  "
            f"→ {event.analysis.suggested_name}  [{event.analysis.risk_level}]"
        )

    def _render_ai_analysis(self, analysis):
        self.query_one("#ai-loading").display = False
        log: RichLog = self.query_one("#ai-log")
        log.clear()

        risk_color = analysis.risk_color
        log.write(
            f"[bold {risk_color}]{analysis.risk_badge}[/bold {risk_color}]  "
            f"[bold]{analysis.suggested_name}[/bold]\n"
        )

        log.write(f"[bold]Summary:[/bold]\n{analysis.summary}\n")

        if analysis.mitre_technique:
            log.write(f"[bold]MITRE ATT&CK:[/bold] [yellow]{analysis.mitre_technique}[/yellow]\n")

        if analysis.parameters:
            log.write("[bold]Parameters:[/bold]")
            for p in analysis.parameters:
                log.write(f"  [cyan]{p.get('name','?')}[/cyan] ({p.get('type','?')}): {p.get('description','')}")

        log.write(f"\n[bold]Return value:[/bold]\n{analysis.return_value}\n")

        if analysis.behaviors:
            log.write("[bold]Behaviors:[/bold]")
            for b in analysis.behaviors:
                log.write(f"  • {b}")

        if analysis.notes:
            log.write(f"\n[bold]Notes:[/bold]\n[dim]{analysis.notes}[/dim]")

        log.write("\n[dim]─────────────────────────────────────[/dim]")
        log.write("[dim]Type a question below to ask the AI.[/dim]")

    # ------------------------------------------------------------------
    # Chat / follow-up
    # ------------------------------------------------------------------

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "chat-input":
            return
        question = event.value.strip()
        if not question:
            return
        event.input.clear()

        ai_log: RichLog = self.query_one("#ai-log")
        ai_log.write(f"\n[bold cyan]You:[/bold cyan] {question}")
        ai_log.write("[dim]Thinking…[/dim]")
        self._set_status("Waiting for AI follow-up…")
        self._run_followup_worker(question)

    @work(thread=True)
    def _run_followup_worker(self, question: str):
        try:
            answer = self.ai_analyzer.ask_followup(question)
            self.post_message(FollowupReady(answer))
        except Exception as exc:
            self.post_message(FollowupReady(f"[Error: {exc}]"))

    def on_followup_ready(self, event: FollowupReady):
        log: RichLog = self.query_one("#ai-log")
        log.write(f"[bold green]AI:[/bold green] {event.text}\n")
        self._set_status("Ready.")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_analyze_all(self):
        """Queue AI analysis for all functions not yet analyzed."""
        pending = [a for a in self.function_addresses if a not in self._analyses]
        if not pending:
            self._set_status("All functions already analyzed.")
            return
        self._set_status(f"Queueing {len(pending)} functions for AI analysis…")
        self._run_batch_worker(pending)

    @work(thread=True)
    def _run_batch_worker(self, addresses: list):
        for i, addr in enumerate(addresses):
            func = self.disassembler.get_function(addr)
            if not func or not func.instructions:
                continue
            try:
                analysis = self.ai_analyzer.analyze_function(func, self.binary_info)
                self._analyses[addr] = analysis
                self.trace_store.save_function_analysis(self.session_id, func, analysis)
                self.post_message(AnalysisReady(addr, analysis))
                self.post_message(StatusUpdate(
                    f"Batch: {i+1}/{len(addresses)} — {analysis.suggested_name}"
                ))
            except Exception as exc:
                self.post_message(StatusUpdate(f"Batch error at 0x{addr:08x}: {exc}"))

    def action_focus_search(self):
        self.query_one("#chat-input").focus()

    def action_blur_chat(self):
        self.query_one("#func-table").focus()

    def action_reset_session(self):
        self._set_status("DB session reset not implemented in this version.")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def on_status_update(self, event: StatusUpdate):
        self._set_status(event.text)

    def _set_status(self, text: str):
        try:
            bar: Static = self.query_one("#status-bar")
            bar.update(f" {text}")
        except Exception:
            pass

    def _update_table_row(self, address: int, analysis):
        """Refresh the function table row after analysis completes."""
        table: DataTable = self.query_one("#func-table")
        key = str(address)
        try:
            risk_color = analysis.risk_color
            badge = f"[bold {risk_color}]{analysis.risk_badge}[/bold {risk_color}]"
            func = self.disassembler.get_function(address)
            insn_count = len(func.instructions) if func else 0

            # DataTable doesn't support in-place row update — remove and re-add
            # This is a limitation we work around by tracking row positions
            # For now, we rebuild the whole table column by column is not supported;
            # just update the name via a workaround using the row key lookup
            row_index = None
            for i, row_key in enumerate(table.rows):
                if str(row_key) == key:
                    row_index = i
                    break
            if row_index is not None:
                table.update_cell(key, "Risk",    badge,                         update_width=False)
                table.update_cell(key, "Name",    analysis.suggested_name[:30],  update_width=False)
        except Exception:
            pass
