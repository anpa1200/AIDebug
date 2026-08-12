import asyncio
import threading
from dataclasses import dataclass
from types import SimpleNamespace

from textual.app import App

from ui import StringsAnalysisScreen
from ui.strings_tui import AIStringsConsentScreen, StringsReportReady


@dataclass(frozen=True)
class FakeStringRecord:
    id: str
    value: str
    file_offset: int
    byte_length: int
    char_length: int
    encoding: str
    rva: int | None
    va: int | None
    section: str | None
    categories: tuple[str, ...]
    score: float
    reasons: tuple[str, ...]
    descriptions: tuple[str, ...]


class FakeStringAnalysis:
    complete = True

    def __init__(self, records):
        self.records = tuple(records)


class FakeAIAnalyzer:
    display_name = "Remote test provider"
    transmits_evidence = True

    def __init__(self, *, remote_enabled=True):
        self.remote_enabled = remote_enabled
        self.calls = []

    def analyze_strings(self, string_analysis, binary_info):
        self.calls.append((string_analysis, binary_info))
        return {
            "summary": "Literal [bold red]model evidence[/bold red]",
            "coverage": f"{len(string_analysis.records)}/{len(string_analysis.records)} records",
            "records_analyzed": len(string_analysis.records),
            "ioc_candidates": [{"value": "https://example.test", "confidence": "LOW"}],
        }


class StringsHarness(App):
    def __init__(self, screen):
        super().__init__()
        self.strings_screen = screen

    def on_mount(self):
        self.push_screen(self.strings_screen)


class ImmediateStringsAnalysisScreen(StringsAnalysisScreen):
    """Exercise the consent/result UI without leaving a thread worker at test teardown."""

    def _run_ai_analysis(self):
        report = self.ai_analyzer.analyze_strings(self.string_analysis, self.binary_info)
        self.on_strings_report_ready(StringsReportReady(report))


class CountingStringsAnalysisScreen(StringsAnalysisScreen):
    def __init__(self, *args, **kwargs):
        self.filter_applications = 0
        super().__init__(*args, **kwargs)

    def _apply_filters(self, *, reset_page=False):
        self.filter_applications += 1
        return super()._apply_filters(reset_page=reset_page)


def _records(count=260):
    records = []
    for index in range(count):
        hostile = index == 0
        value = (
            "[bold red]https://hostile.example/path[/bold red]"
            if hostile
            else f"sample-string-{index:03d}.dll"
        )
        categories = ("url", "suspicious") if hostile else ("dll", "file_path")
        records.append(
            FakeStringRecord(
                id=f"str-{index:04d}",
                value=value,
                file_offset=index * 16,
                byte_length=len(value),
                char_length=len(value),
                encoding="utf-16le" if index % 2 else "ascii",
                rva=0x2000 + index * 16,
                va=0x402000 + index * 16,
                section=".rdata",
                categories=categories,
                score=90.0 if hostile else float(index % 20),
                reasons=("Hostile [green]markup[/green] is inert evidence",),
                descriptions=("Candidate [blue]description[/blue]",),
            )
        )
    return records


def _screen(*, remote_enabled=True, count=260, immediate_ai=False):
    analysis = FakeStringAnalysis(_records(count))
    binary_info = SimpleNamespace(
        filename="[red]sample.exe[/red]",
        sha256="a" * 64,
        string_analysis=analysis,
    )
    analyzer = FakeAIAnalyzer(remote_enabled=remote_enabled)
    screen_type = ImmediateStringsAnalysisScreen if immediate_ai else StringsAnalysisScreen
    return screen_type(binary_info, analyzer), analyzer


def _log_text(log):
    return "\n".join(line.text for line in log.lines)


def test_strings_screen_paginates_filters_sorts_and_renders_hostile_text_safely():
    async def scenario():
        screen, _ = _screen()
        app = StringsHarness(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            table = screen.query_one("#strings-table")
            assert table.row_count == screen.PAGE_SIZE
            assert "Page 1/2" in screen.query_one("#strings-status").render().plain

            detail = _log_text(screen.query_one("#strings-detail-log"))
            assert "[bold red]https://hostile.example/path[/bold red]" in detail
            assert "[green]markup[/green]" in detail
            assert "Candidate [blue]description[/blue]" in detail

            table.focus()
            await pilot.press("pagedown")
            await pilot.pause()
            assert table.row_count == 10
            assert "Page 2/2" in screen.query_one("#strings-status").render().plain

            screen.query_one("#strings-category").value = "url"
            await pilot.pause()
            assert table.row_count == 1
            assert "1 filtered" in screen.query_one("#strings-status").render().plain

            screen.query_one("#strings-search").value = "does-not-exist"
            await asyncio.sleep(screen.FILTER_DEBOUNCE_SECONDS + 0.05)
            await pilot.pause()
            assert table.row_count == 0
            assert "No string records match" in _log_text(
                screen.query_one("#strings-detail-log")
            )

            screen.action_reset_filters()
            screen._sort_column = "score"
            screen._sort_reverse = True
            screen._apply_filters(reset_page=True)
            await pilot.pause()
            assert table.row_count == screen.PAGE_SIZE
            first = screen._page_records()[0]
            assert first.id == "str-0000"

            screen.query_one("#strings-tabs").active = "strings-tab-all"
            await pilot.pause()
            all_strings = _log_text(screen.query_one("#strings-all-log"))
            assert "at most 250 records shown" in all_strings
            assert "[bold red]https://hostile.example/path[/bold red]" in all_strings

    asyncio.run(scenario())


def test_ai_analysis_requires_confirmation_and_reports_coverage():
    async def scenario():
        screen, analyzer = _screen(count=3, immediate_ai=True)
        app = StringsHarness(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            assert analyzer.calls == []

            screen.action_analyze_with_ai()
            await pilot.pause()
            assert isinstance(app.screen, AIStringsConsentScreen)
            warning = app.screen.query_one("#strings-consent-message").render().plain
            assert "credentials" in warning
            assert "API cost" in warning
            assert "3 locally extracted records" in warning
            assert analyzer.calls == []

            await pilot.click("#strings-ai-confirm")
            await pilot.pause()

            assert len(analyzer.calls) == 1
            assert app.screen is screen
            rendered = _log_text(screen.query_one("#strings-ai-log"))
            assert "Coverage: 3/3 records" in rendered
            assert "[bold red]model evidence[/bold red]" in rendered
            assert "complete" in screen.query_one("#strings-status").render().plain.lower()

    asyncio.run(scenario())


def test_offline_mode_disables_ai_without_opening_confirmation():
    async def scenario():
        screen, analyzer = _screen(remote_enabled=False, count=2)
        app = StringsHarness(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen.action_analyze_with_ai()
            await pilot.pause()

            assert app.screen is screen
            assert analyzer.calls == []
            assert "disabled in offline mode" in screen.query_one(
                "#strings-status"
            ).render().plain
            assert "unavailable in offline mode" in _log_text(
                screen.query_one("#strings-ai-log")
            )

    asyncio.run(scenario())


def test_strings_screen_requires_prepared_analysis():
    binary_info = SimpleNamespace(filename="sample.exe")
    try:
        StringsAnalysisScreen(binary_info, FakeAIAnalyzer())
    except ValueError as exc:
        assert "String analysis is unavailable" in str(exc)
    else:
        raise AssertionError("missing string analysis should fail closed")


def test_production_ai_worker_uses_optional_shared_lock(monkeypatch):
    class TrackingLock:
        active = False
        entries = 0

        def __enter__(self):
            self.active = True
            self.entries += 1

        def __exit__(self, exc_type, exc, traceback):
            self.active = False

    lock = TrackingLock()
    analysis = FakeStringAnalysis(_records(1))
    binary_info = SimpleNamespace(filename="sample.exe", string_analysis=analysis)

    class LockCheckingAnalyzer(FakeAIAnalyzer):
        def analyze_strings(
            self,
            string_analysis,
            binary_info,
            *,
            progress_callback=None,
            cancel_requested=None,
        ):
            assert lock.active
            assert callable(progress_callback)
            assert cancel_requested is screen._ai_cancel_event
            return {"coverage": "1/1 records"}

    screen = StringsAnalysisScreen(
        binary_info,
        LockCheckingAnalyzer(),
        ai_lock=lock,
    )
    messages = []
    monkeypatch.setattr(screen, "post_message", messages.append)

    StringsAnalysisScreen._run_ai_analysis.__wrapped__(screen)

    assert lock.entries == 1
    assert len(messages) == 1
    assert isinstance(messages[0], StringsReportReady)


def test_unmount_requests_ai_cancellation_and_drops_stale_report(monkeypatch):
    class CancellationAwareAnalyzer(FakeAIAnalyzer):
        def __init__(self):
            super().__init__()
            self.started = threading.Event()
            self.finished = threading.Event()
            self.cancel_signal = None

        def analyze_strings(
            self,
            string_analysis,
            binary_info,
            *,
            progress_callback=None,
            cancel_requested=None,
        ):
            del string_analysis, binary_info, progress_callback
            self.cancel_signal = cancel_requested
            self.started.set()
            assert cancel_requested.wait(2), "screen did not propagate cancellation"
            self.finished.set()
            return {
                "coverage": {"cancelled": True, "complete": False},
                "overall_assessment": "unknown",
                "confidence": "low",
            }

    analysis = FakeStringAnalysis(_records(2))
    binary_info = SimpleNamespace(filename="sample.exe", string_analysis=analysis)
    analyzer = CancellationAwareAnalyzer()
    screen = StringsAnalysisScreen(binary_info, analyzer)
    messages = []
    monkeypatch.setattr(screen, "post_message", messages.append)
    worker = threading.Thread(
        target=StringsAnalysisScreen._run_ai_analysis.__wrapped__,
        args=(screen,),
        daemon=True,
    )

    worker.start()
    assert analyzer.started.wait(2)
    screen.on_unmount()

    assert analyzer.cancel_signal is screen._ai_cancel_event
    assert screen._ai_cancel_event.is_set()
    assert analyzer.finished.wait(2)
    worker.join(2)
    assert not worker.is_alive()
    assert messages == []
    assert not hasattr(binary_info, "string_ai_report")


def test_close_requests_ai_cancellation_before_popping_screen():
    app_state = SimpleNamespace(pop_calls=0)

    def pop_screen():
        assert screen._ai_cancel_event.is_set()
        app_state.pop_calls += 1

    app_state.pop_screen = pop_screen

    class CloseTestScreen(StringsAnalysisScreen):
        @property
        def app(self):
            return app_state

    analysis = FakeStringAnalysis(_records(1))
    binary_info = SimpleNamespace(filename="sample.exe", string_analysis=analysis)
    screen = CloseTestScreen(binary_info, FakeAIAnalyzer())
    screen._ai_running = True

    screen.action_close()

    assert screen._ai_cancel_event.is_set()
    assert app_state.pop_calls == 1


def test_large_ai_report_is_retained_but_rendered_with_hard_bounds():
    async def scenario():
        screen, _ = _screen(count=2)
        app = StringsHarness(screen)
        large_report = {
            "coverage": {
                "extracted_count": 500,
                "retained_count": 500,
                "sent_count": 500,
                "reviewed_count": 500,
                "chunks_attempted": 10,
                "chunks_total": 10,
                "complete": True,
            },
            "executive_summary": "Bounded summary",
            "overall_assessment": "suspicious",
            "confidence": "medium",
            "suspicious_findings": [
                {
                    "title": f"finding-{index}",
                    "severity": "medium",
                    "confidence": "medium",
                    "analysis": "A" * 2_000,
                    "evidence_ids": [f"str-{index:04d}"],
                }
                for index in range(100)
            ],
            "iocs": [
                {
                    "normalized_value": f"ioc-{index}.example",
                    "type": "domain",
                    "confidence": "low",
                    "context": "context",
                }
                for index in range(100)
            ],
            "capabilities": [
                {"name": f"capability-{index}", "analysis": "possible capability"}
                for index in range(100)
            ],
            "entities": [
                {
                    "canonical_name": f"entity-{index}",
                    "kind": "api",
                    "description": "general API description",
                }
                for index in range(100)
            ],
            "limitations": [f"limitation-{index}" for index in range(100)],
            "analyst_next_steps": [f"next-step-{index}" for index in range(100)],
            "annotations": [
                {"string_id": f"str-{index:04d}", "reason": f"annotation-tail-{index}"}
                for index in range(5_000)
            ],
            "relationships": [{"relationship": f"relationship-{index}"} for index in range(500)],
        }

        async with app.run_test() as pilot:
            await pilot.pause()
            screen.query_one("#strings-tabs").active = "strings-tab-ai"
            screen.on_strings_report_ready(StringsReportReady(large_report))
            await pilot.pause()

            rendered = _log_text(screen.query_one("#strings-ai-log"))
            assert screen._ai_report is large_report
            assert "Suspicious findings — showing 8 of 100" in rendered
            assert "DLL / API entities — showing 12 of 100" in rendered
            assert "Annotations:   5,000" in rendered
            assert "Relationships: 500" in rendered
            assert "DISPLAY TRUNCATED" in rendered
            assert "annotation-tail-4999" not in rendered
            assert "finding-99" not in rendered
            assert len(rendered) <= screen.AI_DISPLAY_MAX_CHARS

    asyncio.run(scenario())


def test_successful_ai_report_is_restored_when_strings_screen_reopens():
    async def scenario():
        screen, analyzer = _screen(count=2)
        binary_info = screen.binary_info
        report = {
            "coverage": "2/2 records",
            "executive_summary": "Restored bounded report",
            "overall_assessment": "unknown",
            "confidence": "low",
            "suspicious_findings": [],
            "iocs": [],
            "capabilities": [],
            "entities": [],
            "limitations": ["Static strings do not prove execution."],
            "analyst_next_steps": ["Validate with code references."],
            "annotations": [{"string_id": "str-0000"}],
            "relationships": [],
        }

        first_app = StringsHarness(screen)
        async with first_app.run_test() as pilot:
            await pilot.pause()
            screen.on_strings_report_ready(StringsReportReady(report))
            await pilot.pause()
            assert binary_info.string_ai_report is report

        reopened = StringsAnalysisScreen(binary_info, analyzer)
        second_app = StringsHarness(reopened)
        async with second_app.run_test() as pilot:
            await pilot.pause()
            reopened.query_one("#strings-tabs").active = "strings-tab-ai"
            await pilot.pause()

            rendered = _log_text(reopened.query_one("#strings-ai-log"))
            assert reopened._ai_report is report
            assert "Restored in-memory report for this loaded artifact" in rendered
            assert "Restored bounded report" in rendered
            assert "Annotations:   1" in rendered
            assert analyzer.calls == []

    asyncio.run(scenario())


def test_rapid_text_filter_changes_are_debounced_to_the_latest_values():
    async def scenario():
        analysis = FakeStringAnalysis(_records(260))
        binary_info = SimpleNamespace(filename="sample.exe", string_analysis=analysis)
        screen = CountingStringsAnalysisScreen(binary_info, FakeAIAnalyzer())
        app = StringsHarness(screen)

        async with app.run_test() as pilot:
            await pilot.pause()
            initial_applications = screen.filter_applications
            search = screen.query_one("#strings-search")
            minimum = screen.query_one("#strings-min-length")

            search.value = "sample"
            minimum.value = "10"
            await pilot.pause(0.02)
            search.value = "sample-string-2"
            minimum.value = "15"
            await pilot.pause(0.02)
            search.value = "sample-string-259.dll"
            minimum.value = "20"
            await pilot.pause(0.02)

            assert screen.filter_applications == initial_applications
            await asyncio.sleep(screen.FILTER_DEBOUNCE_SECONDS + 0.08)
            await pilot.pause()

            assert screen.filter_applications == initial_applications + 1
            assert screen.query_one("#strings-table").row_count == 1
            assert screen._page_records()[0].id == "str-0259"

    asyncio.run(scenario())
