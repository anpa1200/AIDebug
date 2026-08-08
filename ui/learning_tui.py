"""AIDebug Learning Mode rendered inside the original Textual workspace."""
from __future__ import annotations

import threading

from rich.syntax import Syntax
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
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
from learning import AnalyzedLesson, Lesson, LiveLearningAnalyzer, get_lesson

from .tui import AIDebugApp, _display_text, _markup_text


class LearningReady(Message):
    """A selected real learning case finished compiling and decompiling."""

    def __init__(self, lesson_id: str, result: AnalyzedLesson) -> None:
        self.lesson_id = lesson_id
        self.result = result
        super().__init__()


class LearningFailed(Message):
    """A selected learning case could not be analyzed."""

    def __init__(self, lesson_id: str, error: str) -> None:
        self.lesson_id = lesson_id
        self.error = error
        super().__init__()


class LearningModeApp(App):
    """Use the main AIDebug layout to explore independently compiled cases."""

    TITLE = f"{config.APP_TITLE} — Learning Mode"
    CSS = AIDebugApp.CSS

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("r", "reload_lesson", "Recompile", show=True),
    ]

    def __init__(
        self,
        lessons: tuple[Lesson, ...],
        *,
        initial_lesson_id: str | None = None,
        compiler: str | None = None,
        ghidra_headless: str | None = None,
        live_analyzer: LiveLearningAnalyzer | None = None,
    ) -> None:
        super().__init__()
        self.lessons = lessons
        self.initial_lesson_id = initial_lesson_id
        self.live_analyzer = live_analyzer or LiveLearningAnalyzer(
            compiler=compiler,
            ghidra_headless=ghidra_headless,
        )
        self._results: dict[str, AnalyzedLesson] = {}
        self._analyzing: set[str] = set()
        self._current_lesson_id: str | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        compiler = _display_text(self.live_analyzer.compiler, 180)
        yield Static(
            Text(
                f" LEARNING MODE  |  {len(self.lessons)} real C cases  "
                f"|  x86-64 ELF  |  compiler: {compiler}  "
                "|  compiled artifacts are never executed"
            ),
            id="toolbar",
        )

        with Horizontal(id="main"):
            with Vertical(id="left-panel"):
                yield Label(" LEARNING CASES ", id="left-title")
                yield DataTable(id="func-table", cursor_type="row")

            with Vertical(id="center-panel"):
                yield Label(" REAL DISASSEMBLY ", id="center-title")
                yield RichLog(id="disasm-log", highlight=True, markup=True, wrap=False)
                yield Label(" ORIGINAL C SOURCE ", id="reg-title")
                yield RichLog(id="reg-view", highlight=True, markup=True, wrap=False)

            with Vertical(id="right-panel"):
                yield LoadingIndicator(id="ai-loading")
                with TabbedContent(id="right-tabs"):
                    with TabPane("Pseudo-code", id="tab-decompile"):
                        yield RichLog(id="decompile-log", highlight=True, markup=True)
                    with TabPane("Lesson", id="tab-ai"):
                        yield RichLog(id="ai-log", highlight=True, markup=True)
                    with TabPane("Build Evidence", id="tab-patterns"):
                        yield RichLog(id="patterns-log", highlight=True, markup=True)
                    with TabPane("Help", id="tab-cfg"):
                        yield RichLog(id="cfg-log", highlight=True, markup=True)

        with Horizontal(id="chat-bar"):
            yield Label(" Learn ", id="chat-label")
            yield Input(
                id="chat-input",
                placeholder="Select a real case on the left and press Enter",
                disabled=True,
            )

        yield Static("Ready.", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        self._populate_lesson_table()
        self._render_help()
        self._render_empty_state()
        if self.initial_lesson_id and get_lesson(self.initial_lesson_id):
            for row, lesson in enumerate(self.lessons):
                if lesson.lesson_id == self.initial_lesson_id:
                    self.query_one("#func-table", DataTable).move_cursor(row=row)
                    self._request_lesson(lesson.lesson_id)
                    return
        self._set_status(
            f"Loaded {len(self.lessons)} real cases — select one and press Enter."
        )

    def _populate_lesson_table(self) -> None:
        table = self.query_one("#func-table", DataTable)
        table.add_columns("ID", "Category", "Lesson")
        for lesson in self.lessons:
            table.add_row(
                Text(lesson.lesson_id, style="cyan"),
                Text(lesson.category, style="magenta"),
                Text(lesson.title),
                key=lesson.lesson_id,
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        lesson_id = str(event.row_key.value or "")
        if get_lesson(lesson_id) is not None:
            self._request_lesson(lesson_id)

    def _request_lesson(self, lesson_id: str, *, force: bool = False) -> None:
        self._current_lesson_id = lesson_id
        if not force and lesson_id in self._results:
            self._render_result(self._results[lesson_id])
            self._set_status(f"Loaded cached result for {lesson_id}. Press R to recompile.")
            return
        if lesson_id in self._analyzing:
            self._set_status(f"{lesson_id} is already being compiled and decompiled…")
            return

        lesson = get_lesson(lesson_id)
        if lesson is None:
            self._set_status(f"Unknown learning case: {lesson_id}")
            return
        self._analyzing.add(lesson_id)
        self.query_one("#ai-loading", LoadingIndicator).display = True
        self._render_loading(lesson)
        self._set_status(
            f"Compiling {lesson_id}.c, disassembling its ELF, and running Ghidra…"
        )
        threading.Thread(
            target=self._run_lesson_worker,
            args=(lesson_id,),
            name=f"aidebug-learn-{lesson_id}",
            daemon=True,
        ).start()

    def _run_lesson_worker(self, lesson_id: str) -> None:
        lesson = get_lesson(lesson_id)
        if lesson is None:
            self._post_from_worker(
                LearningFailed(lesson_id, "Learning case disappeared")
            )
            return
        try:
            result = self.live_analyzer.analyze(lesson)
        except Exception as exc:
            self._post_from_worker(LearningFailed(lesson_id, str(exc)))
            return
        self._post_from_worker(LearningReady(lesson_id, result))

    def _post_from_worker(self, message: Message) -> None:
        try:
            self.call_from_thread(self.post_message, message)
        except RuntimeError:
            # The user may close the TUI while GCC or Ghidra is still running.
            return

    def on_learning_ready(self, event: LearningReady) -> None:
        self._analyzing.discard(event.lesson_id)
        self._results[event.lesson_id] = event.result
        if event.lesson_id != self._current_lesson_id:
            return
        self.query_one("#ai-loading", LoadingIndicator).display = False
        self._render_result(event.result)
        self._set_status(
            f"Ready: {event.lesson_id} — real C, assembly, and Ghidra pseudo-code."
        )

    def on_learning_failed(self, event: LearningFailed) -> None:
        self._analyzing.discard(event.lesson_id)
        if event.lesson_id != self._current_lesson_id:
            return
        self.query_one("#ai-loading", LoadingIndicator).display = False
        error = _markup_text(event.error, 4_000)
        for selector in ("#disasm-log", "#reg-view", "#decompile-log"):
            log = self.query_one(selector, RichLog)
            log.clear()
            log.write(f"[bold red]Learning analysis failed[/bold red]\n{error}")
        self._set_status(f"Learning analysis failed for {event.lesson_id}: {event.error}")

    def _render_loading(self, lesson: Lesson) -> None:
        for selector in ("#disasm-log", "#reg-view", "#decompile-log"):
            log = self.query_one(selector, RichLog)
            log.clear()
            log.write(f"[dim]Preparing {_markup_text(lesson.lesson_id)}…[/dim]")
        self._render_lesson_details(lesson)
        evidence = self.query_one("#patterns-log", RichLog)
        evidence.clear()
        evidence.write(
            "[dim]The compiler, function address, and artifact SHA-256 will appear here.[/dim]"
        )

    def _render_result(self, result: AnalyzedLesson) -> None:
        assembly = self.query_one("#disasm-log", RichLog)
        assembly.clear()
        assembly.write(
            f"[bold cyan]{_markup_text(result.lesson.function_name)}[/bold cyan]  "
            f"[dim]@ 0x{result.function_address:x}[/dim]\n"
        )
        assembly.write(Syntax(result.assembly, "asm", theme="ansi_dark", word_wrap=False))

        source = self.query_one("#reg-view", RichLog)
        source.clear()
        source.write(f"[dim]{_markup_text(result.source_file)}[/dim]\n")
        source.write(Syntax(result.source, "c", theme="ansi_dark", word_wrap=False))

        pseudo = self.query_one("#decompile-log", RichLog)
        pseudo.clear()
        pseudo.write(
            f"[bold green]{_markup_text(result.decompiler)} reconstructed pseudo-code[/bold green]\n"
            f"[yellow]{_markup_text(result.warning, 1_024)}[/yellow]\n"
        )
        pseudo.write(Syntax(result.pseudocode, "c", theme="ansi_dark", word_wrap=True))

        self._render_lesson_details(result.lesson)
        evidence = self.query_one("#patterns-log", RichLog)
        evidence.clear()
        evidence.write(f"[bold]Source file[/bold]\n{_markup_text(result.source_file)}\n")
        evidence.write(f"[bold]Function[/bold]\n{_markup_text(result.lesson.function_name)}")
        evidence.write(f"[bold]ELF address[/bold]\n0x{result.function_address:x}")
        evidence.write(f"[bold]Compiler[/bold]\n{_markup_text(result.compiler)}")
        evidence.write(
            f"[bold]Artifact SHA-256[/bold]\n{_markup_text(result.artifact_sha256, 128)}\n"
        )
        evidence.write(
            "[bold green]Safety[/bold green]\n"
            "The selected source was compiled in a temporary directory. "
            "The resulting ELF was analyzed and never executed."
        )

    def _render_lesson_details(self, lesson: Lesson) -> None:
        details = self.query_one("#ai-log", RichLog)
        details.clear()
        details.write(
            f"[bold cyan]{_markup_text(lesson.lesson_id)}[/bold cyan]\n"
            f"[bold]{_markup_text(lesson.title)}[/bold]\n"
            f"[dim]{_markup_text(lesson.category)}[/dim]\n"
        )
        details.write(f"[bold]What it means[/bold]\n{_markup_text(lesson.explanation)}\n")
        details.write(f"[bold]Register / flag effects[/bold]\n{_markup_text(lesson.effects)}\n")
        details.write(
            f"[bold yellow]Analyst clue[/bold yellow]\n"
            f"{_markup_text(lesson.analyst_clue)}\n"
        )
        details.write(
            f"[bold red]Common misreading[/bold red]\n{_markup_text(lesson.pitfall)}"
        )

    def _render_help(self) -> None:
        help_log = self.query_one("#cfg-log", RichLog)
        help_log.clear()
        help_log.write("[bold cyan]Real Learning Mode workflow[/bold cyan]\n")
        help_log.write("1. Select a case in the left table and press Enter.")
        help_log.write("2. AIDebug compiles only that case into a temporary x86-64 ELF.")
        help_log.write("3. The center panes show real assembly and the exact original C.")
        help_log.write("4. The Pseudo-code tab shows Ghidra's independent reconstruction.")
        help_log.write("5. Press R to rebuild the selected case; press Q to quit.\n")
        help_log.write(
            "[yellow]The compiler may choose different valid instructions across versions. "
            "Treat pseudo-code types and names as hypotheses.[/yellow]"
        )

    def _render_empty_state(self) -> None:
        self.query_one("#ai-loading", LoadingIndicator).display = False
        self.query_one("#disasm-log", RichLog).write(
            "[dim]Select a learning case to generate real assembly.[/dim]"
        )
        self.query_one("#reg-view", RichLog).write(
            "[dim]The exact standalone C source will appear here.[/dim]"
        )
        self.query_one("#decompile-log", RichLog).write(
            "[dim]Ghidra pseudo-code will appear after compilation.[/dim]"
        )
        self.query_one("#ai-log", RichLog).write(
            "[dim]Lesson guidance will appear here.[/dim]"
        )
        self.query_one("#patterns-log", RichLog).write(
            "[dim]Build evidence will appear here.[/dim]"
        )

    def action_reload_lesson(self) -> None:
        if self._current_lesson_id is None:
            self._set_status("Select a learning case before recompiling.")
            return
        self._request_lesson(self._current_lesson_id, force=True)

    def _set_status(self, text: str) -> None:
        status = self.query_one("#status-bar", Static)
        status.update(Text(_display_text(text, 500)))
