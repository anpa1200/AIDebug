import asyncio
from types import SimpleNamespace

from analysis.ai_analyzer import AIAnalysis
from analysis.disassembler import Function, Instruction
from ui.tui import AIDebugApp, AnalysisReady


class FakeDisassembler:
    def __init__(self, functions):
        self.functions = {function.address: function for function in functions}

    def get_function(self, address):
        return self.functions.get(address)


class FakeStore:
    db_path = ":memory:"

    def __init__(self, cached=None):
        self.analyses = []
        self.patterns = []
        self.cached = cached or {}

    def get_cached_analysis(self, session_id, address, cache_key=None):
        return self.cached.get(address)

    def save_function_analysis(self, session_id, function, analysis, snapshot=None):
        self.analyses.append((session_id, function.address, analysis.suggested_name))

    def save_patterns(self, session_id, address, patterns):
        self.patterns.append((session_id, address, patterns))


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
    return Function(
        address=address,
        name=name,
        instructions=[
            Instruction(address, "mov", "eax, [brackets]", b"\x90"),
            Instruction(address + 1, "ret", "", b"\xc3"),
        ],
        strings_referenced=["[bold red]literal[/bold red]"],
    )


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


def _app(analyzer, *, allow_bulk=True, max_bulk=1, cached=False):
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
    )
    cached_results = {
        function.address: _analysis(function.address, function.name)
        for function in functions
    } if cached else {}
    return AIDebugApp(
        binary_info,
        FakeDisassembler(functions),
        analyzer,
        FakeStore(cached_results),
        1,
        [function.address for function in functions],
        allow_bulk_analysis=allow_bulk,
        max_bulk_functions=max_bulk,
    )


def test_tui_headless_mount_tabs_selection_and_bounded_batch():
    async def scenario():
        app = _app(FakeAnalyzer(), max_bulk=1, cached=True)
        async with app.run_test() as pilot:
            table = app.query_one("#func-table")
            assert table.row_count == 2
            assert {pane.id for pane in app.query("TabbedContent TabPane")} == {
                "tab-ai",
                "tab-cfg",
                "tab-patterns",
            }
            tabs = app.query_one("#right-tabs")
            tabs.active = "tab-cfg"
            await pilot.pause()
            assert tabs.active == "tab-cfg"

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
