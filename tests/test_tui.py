import asyncio
from types import SimpleNamespace

from textual.screen import Screen

import ui.tui as tui_module
from analysis.ai_analyzer import AIAnalysis
from analysis.disassembler import Function, Instruction
from learning import AnalyzedLesson, Lesson, catalog
from ui.hex_tui import HexViewerScreen
from ui.learning_tui import LearningModeApp
from ui.tui import AIDebugApp, AnalysisReady


class FakeDisassembler:
    def __init__(self, functions):
        self.functions = {function.address: function for function in functions}

    def get_function(self, address):
        return self.functions.get(address)


class FakeStore:
    db_path = ":memory:"

    def __init__(self, cached=None, *, history=False):
        self.analyses = []
        self.patterns = []
        self.cached = cached or {}
        self.history = history

    def get_cached_analysis(self, session_id, address, cache_key=None):
        return self.cached.get(address)

    def save_function_analysis(self, session_id, function, analysis, snapshot=None):
        self.analyses.append((session_id, function.address, analysis.suggested_name))

    def save_patterns(self, session_id, address, patterns):
        self.patterns.append((session_id, address, patterns))

    def find_sessions_by_sha256(self, sha256, *, exclude_session_id=None):
        if not self.history:
            return []
        return [{
            "id": 9,
            "status": "completed",
            "analysis_mode": "static",
            "analyzer": "Previous analyzer",
            "created_at": "2026-08-09 09:00:00",
            "function_count": 1,
            "pattern_count": 1,
            "api_call_count": 0,
            "network_event_count": 0,
            "runtime_event_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 1,
        }]

    def get_function_history_by_sha256(
        self,
        sha256,
        *,
        exclude_session_id=None,
        limit=300,
    ):
        if not self.history:
            return []
        return [{
            "session_id": 9,
            "address": 0x401000,
            "name": "previous_name",
            "risk_level": "LOW",
            "ai_analysis_json": '{"summary":"Previous AI summary"}',
        }]


class FakeAnalyzer:
    cache_key = "fake-v1"
    display_name = "Fake analyzer"

    def __init__(self, *, remote_enabled=False):
        self.remote_enabled = remote_enabled
        self.contexts = set()

    def analyze_function(self, function, binary_info, snapshot=None, context_id="default"):
        self.contexts.add(context_id)
        return _analysis(function.address, function.name)

    def has_context(self, context_id):
        return context_id in self.contexts

    def seed_context(self, function, binary_info, analysis, snapshot=None, context_id="default"):
        self.contexts.add(context_id)

    def ask_followup(self, question, context_id="default"):
        return f"answer for {context_id}: {question}"


def _function(address, name):
    function = Function(
        address=address,
        name=name,
        instructions=[
            Instruction(address, "mov", "eax, [brackets]", b"\x90"),
            Instruction(address + 1, "ret", "", b"\xc3"),
        ],
        strings_referenced=["[bold red]literal[/bold red]"],
    )
    function.decompiled_code = "int sample(void) { return 0; }"
    function.decompile_language = "c"
    function.decompile_backend = "ghidra"
    function.decompile_warning = "Not original source."
    return function


def _analysis(address, name="function"):
    return AIAnalysis(
        suggested_name=f"analysis_{address:x}",
        summary=f"Summary for {name}",
        parameters=[],
        return_value="none",
        behaviors=["deterministic"],
        mitre_technique=None,
        risk_level="LOW",
        notes="safe",
        cache_key="fake-v1",
    )


def _app(analyzer, *, allow_bulk=True, max_bulk=1, cached=False, history=False):
    functions = [
        _function(0x401000, "[bold red]first[/bold red]"),
        _function(0x402000, "second"),
    ]
    binary_info = SimpleNamespace(
        filename="[red]sample[/red].exe",
        file_format="ELF",
        arch="x86-64",
        bits=64,
        sha256="a" * 64,
        os_target="linux",
        imports=[],
        raw_data=b"\x7fELF" + bytes(5000),
    )
    cached_results = {
        function.address: _analysis(function.address, function.name)
        for function in functions
    } if cached else {}
    return AIDebugApp(
        binary_info,
        FakeDisassembler(functions),
        analyzer,
        FakeStore(cached_results, history=history),
        1,
        [function.address for function in functions],
        allow_bulk_analysis=allow_bulk,
        max_bulk_functions=max_bulk,
    )


def test_tui_headless_mount_tabs_selection_and_bounded_batch():
    async def scenario():
        app = _app(FakeAnalyzer(), max_bulk=1, cached=True, history=True)
        async with app.run_test() as pilot:
            table = app.query_one("#func-table")
            assert table.row_count == 2
            assert {pane.id for pane in app.query("TabbedContent TabPane")} == {
                "tab-ai",
                "tab-cfg",
                "tab-patterns",
                "tab-decompile",
                "tab-history",
            }
            tabs = app.query_one("#right-tabs")
            tabs.active = "tab-cfg"
            await pilot.pause()
            assert tabs.active == "tab-cfg"

            await pilot.press("ctrl+h")
            await pilot.pause()
            assert tabs.active == "tab-history"
            history = "\n".join(line.text for line in app.query_one("#history-log").lines)
            assert "Previous AI summary" in history
            assert "session 9" in history

            table.focus()
            table.move_cursor(row=1)
            await pilot.press("enter")
            await pilot.pause()
            assert app._current_address == 0x402000
            assert set(app._analyses) == {0x401000, 0x402000}
            assert not app.query_one("#ai-loading").display

            await pilot.press("ctrl+a")
            await pilot.pause()
            assert "already analyzed" in app.query_one("#status-bar").render().plain

    asyncio.run(scenario())


def test_tui_late_analysis_does_not_replace_new_selection():
    async def scenario():
        analyzer = FakeAnalyzer(remote_enabled=True)
        app = _app(analyzer)
        async with app.run_test() as pilot:
            app._current_address = 0x402000
            app._analyzing.update({0x401000, 0x402000})
            app.on_analysis_ready(AnalysisReady(0x401000, _analysis(0x401000)))
            app.on_analysis_ready(AnalysisReady(0x402000, _analysis(0x402000)))
            await pilot.pause()

            assert app._current_address == 0x402000
            assert set(app._analyses) == {0x401000, 0x402000}
            rendered = "\n".join(line.text for line in app.query_one("#ai-log").lines)
            assert "analysis_402000" in rendered
            assert "analysis_401000" not in rendered

    asyncio.run(scenario())


def test_tui_blocks_unacknowledged_remote_bulk_action():
    async def scenario():
        app = _app(FakeAnalyzer(remote_enabled=True), allow_bulk=False)
        async with app.run_test() as pilot:
            await pilot.press("ctrl+a")
            await pilot.pause()
            status = app.query_one("#status-bar").render().plain
            assert "Bulk remote analysis is locked" in status
            assert not app._analyses

    asyncio.run(scenario())


def test_tui_file_inspector_opens_hex_viewer_for_elf():
    async def scenario():
        app = _app(FakeAnalyzer())
        async with app.run_test() as pilot:
            await pilot.press("x")
            await pilot.pause()
            assert isinstance(app.screen, HexViewerScreen)
            rendered = "\n".join(
                line.text for line in app.screen.query_one("#hex-file-log").lines
            )
            assert "Whole-file hexadecimal view" in rendered
            assert "7f 45 4c 46" in rendered

    asyncio.run(scenario())


def test_tui_file_inspector_routes_pe_to_full_structure(monkeypatch):
    class FakePEAnalyzer:
        def analyze(self, binary_info):
            return object()

    class FakePEScreen(Screen):
        def __init__(self, structure):
            super().__init__()
            self.structure = structure

    monkeypatch.setattr(tui_module, "PEStructureAnalyzer", FakePEAnalyzer)
    monkeypatch.setattr(tui_module, "PEStructureScreen", FakePEScreen)

    async def scenario():
        app = _app(FakeAnalyzer())
        app.binary_info.file_format = "PE"
        async with app.run_test() as pilot:
            await pilot.press("x")
            await pilot.pause()
            assert isinstance(app.screen, FakePEScreen)

    asyncio.run(scenario())


class FakeLearningAnalyzer:
    compiler = "/usr/bin/fake-gcc"

    def analyze(self, lesson):
        return AnalyzedLesson(
            lesson=lesson,
            source_file=f"learning/cases/{lesson.lesson_id}.c",
            source=(
                '#include "case_common.h"\n\n'
                f"LEARN int {lesson.function_name}(int value) {{\n"
                "    return value;\n"
                "}\n"
            ),
            assembly="0x00001000  89 f8  mov eax, edi\n0x00001002  c3  ret",
            pseudocode=f"int {lesson.function_name}(int value) {{ return value; }}",
            function_address=0x1000,
            artifact_sha256="b" * 64,
            compiler="fake-gcc 1.0",
            decompiler="ghidra",
            warning="Reconstructed from machine code; not original source.",
        )


def test_learning_mode_uses_original_tui_layout_and_live_result_panes():
    async def scenario():
        lessons = catalog()[:2]
        app = LearningModeApp(
            lessons,
            initial_lesson_id=lessons[0].lesson_id,
            live_analyzer=FakeLearningAnalyzer(),
        )
        async with app.run_test() as pilot:
            await pilot.pause(0.2)
            assert app.query_one("#func-table").row_count == 2
            assert {pane.id for pane in app.query("TabbedContent TabPane")} == {
                "tab-ai",
                "tab-cfg",
                "tab-patterns",
                "tab-decompile",
            }
            assert app._current_lesson_id == lessons[0].lesson_id

            source = "\n".join(line.text for line in app.query_one("#reg-view").lines)
            assembly = "\n".join(line.text for line in app.query_one("#disasm-log").lines)
            pseudo = "\n".join(line.text for line in app.query_one("#decompile-log").lines)
            app.query_one("#right-tabs").active = "tab-patterns"
            await pilot.pause()
            evidence = "\n".join(line.text for line in app.query_one("#patterns-log").lines)
            assert lessons[0].function_name in source
            # Textual 0.52 clips RichLog content at the rendered pane width;
            # validate the real instruction family without depending on hidden
            # off-screen operand text surviving in its internal line buffer.
            assert "mov eax" in assembly
            assert "ret" in assembly
            assert lessons[0].function_name in pseudo
            assert "fake-gcc 1.0" in evidence

            table = app.query_one("#func-table")
            table.focus()
            table.move_cursor(row=1)
            await pilot.press("enter")
            await pilot.pause(0.2)
            assert app._current_lesson_id == lessons[1].lesson_id
            assert set(app._results) == {lesson.lesson_id for lesson in lessons}

    asyncio.run(scenario())


def test_learning_mode_uses_external_lesson_lookup_instead_of_builtin_catalog():
    async def scenario():
        lesson = Lesson(
            lesson_id="external-add",
            title="External addition",
            category="analyst collection",
            function_name="learn_external_add",
            explanation="Adds a constant.",
            effects="The result register changes.",
            analyst_clue="Compare source and assembly.",
            pitfall="Instruction selection can vary.",
        )
        app = LearningModeApp(
            (lesson,),
            initial_lesson_id=lesson.lesson_id,
            live_analyzer=FakeLearningAnalyzer(),
        )

        async with app.run_test() as pilot:
            await pilot.pause(0.2)
            assert app._current_lesson_id == "external-add"
            assert "external-add" in app._results
            assert app.query_one("#func-table").row_count == 1

    asyncio.run(scenario())
