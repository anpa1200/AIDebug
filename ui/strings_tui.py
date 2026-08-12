"""Dedicated, read-only workspace for extracted-string intelligence."""

from __future__ import annotations

import math
import threading
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from typing import Any

from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.screen import ModalScreen, Screen
from textual.timer import Timer
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    LoadingIndicator,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
)


def _display_text(value: Any, limit: int = 16_000) -> str:
    """Render attacker-controlled evidence without terminal control characters."""
    rendered: list[str] = []
    for character in str(value)[:limit]:
        if character in "\n\t" or character.isprintable():
            rendered.append(character)
        elif ord(character) <= 0xFF:
            rendered.append(f"\\x{ord(character):02x}")
        else:
            rendered.append(f"\\u{ord(character):04x}")
    return "".join(rendered)


def _field(record: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if isinstance(record, Mapping) and name in record:
            return record[name]
        if hasattr(record, name):
            return getattr(record, name)
    return default


def _label(value: Any) -> str:
    value = getattr(value, "value", value)
    return str(value) if value is not None else ""


def _values(record: Any, *names: str) -> tuple[str, ...]:
    value = _field(record, *names, default=())
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Mapping):
        return tuple(_label(item) for item in value)
    if isinstance(value, Sequence) or isinstance(value, (set, frozenset)):
        return tuple(_label(item) for item in value)
    return (_label(value),)


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


class StringsReportReady(Message):
    def __init__(self, report: Any) -> None:
        self.report = report
        super().__init__()


class StringsReportFailed(Message):
    def __init__(self, error: str) -> None:
        self.error = error
        super().__init__()


class StringsProgress(Message):
    def __init__(self, progress: Mapping[str, Any]) -> None:
        self.progress = dict(progress)
        super().__init__()


class AIStringsConsentScreen(ModalScreen[bool]):
    """Require an affirmative analyst action before any string evidence is sent."""

    CSS = """
AIStringsConsentScreen {
    align: center middle;
}

#strings-consent-box {
    width: 72;
    height: auto;
    border: thick $warning;
    background: $surface;
    padding: 1 2;
}

#strings-consent-message {
    height: auto;
    margin-bottom: 1;
}

#strings-consent-actions {
    height: 3;
    align-horizontal: right;
}

#strings-ai-cancel, #strings-ai-confirm {
    margin-left: 1;
}
"""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
        Binding("q", "cancel", "Cancel", show=False),
    ]

    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="strings-consent-box"):
            yield Label("AI STRING ANALYSIS — CONFIRM EVIDENCE TRANSFER")
            yield Static(Text(self.message), id="strings-consent-message")
            with Horizontal(id="strings-consent-actions"):
                yield Button("Cancel", id="strings-ai-cancel")
                yield Button("Analyze strings", id="strings-ai-confirm", variant="warning")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "strings-ai-confirm")

    def action_cancel(self) -> None:
        self.dismiss(False)


class StringsAnalysisScreen(Screen):
    """Paginated string records, deterministic findings, and opt-in AI review."""

    TITLE = "AIDebug — String Intelligence"
    PAGE_SIZE = 250
    AI_DISPLAY_ITEM_LIMIT = 8
    AI_DISPLAY_ENTITY_LIMIT = 12
    AI_DISPLAY_ITEM_CHARS = 1_000
    AI_DISPLAY_MAX_CHARS = 36_000
    FILTER_DEBOUNCE_SECONDS = 0.2

    CSS = """
StringsAnalysisScreen {
    background: $surface;
}

#strings-summary {
    height: 3;
    background: $primary-darken-3;
    color: $text;
    padding: 0 2;
}

#strings-filters {
    height: 3;
    layout: horizontal;
    padding: 0 1;
}

#strings-min-length {
    width: 14;
}

#strings-search {
    width: 1fr;
}

#strings-category, #strings-encoding {
    width: 24;
}

.strings-filter {
    margin-right: 1;
}

#strings-body {
    height: 1fr;
}

#strings-table {
    width: 58%;
    border: solid $primary-darken-2;
}

#strings-tabs {
    width: 42%;
    border: solid $primary-darken-2;
}

.strings-log {
    height: 1fr;
}

#strings-ai-loading {
    height: 3;
    display: none;
    align: center middle;
}

#strings-status {
    height: 1;
    background: $primary-darken-3;
    color: $text-muted;
    padding: 0 2;
}
"""

    BINDINGS = [
        Binding("escape", "close", "Back", show=True),
        Binding("q", "close", "Back", show=False),
        Binding("r", "reset_filters", "Reset filters", show=True),
        Binding("a", "analyze_with_ai", "Analyze strings with AI", show=True),
        Binding(
            "pageup", "previous_page", "Previous page", show=True, priority=True
        ),
        Binding("pagedown", "next_page", "Next page", show=True, priority=True),
        Binding("home", "first_page", "First page", show=False, priority=True),
        Binding("end", "last_page", "Last page", show=False, priority=True),
    ]

    def __init__(self, binary_info: Any, ai_analyzer: Any, *, ai_lock: Any = None) -> None:
        super().__init__()
        self.binary_info = binary_info
        self.ai_analyzer = ai_analyzer
        self.ai_lock = ai_lock
        self.string_analysis = getattr(binary_info, "string_analysis", None)
        if self.string_analysis is None:
            raise ValueError("String analysis is unavailable for this binary")
        self._records = list(getattr(self.string_analysis, "records", ()))
        self._filtered_records = list(self._records)
        self._visible_records: dict[str, Any] = {}
        self._page = 0
        self._sort_column: str | None = None
        self._sort_reverse = False
        self._filter_timer: Timer | None = None
        self._filter_revision = 0
        self._ai_running = False
        self._ai_cancel_event = threading.Event()
        self._ai_report: Any = getattr(binary_info, "string_ai_report", None)

    def compose(self) -> ComposeResult:
        filename = _display_text(getattr(self.binary_info, "filename", "<unknown>"), 240)
        omitted = _integer(getattr(self.string_analysis, "omitted_count", 0))
        scanned = _integer(getattr(self.string_analysis, "scanned_bytes", 0))
        total = _integer(getattr(self.string_analysis, "total_bytes", scanned))
        scan_state = "full scan" if scanned >= total else "partial byte scan"
        coverage = (
            scan_state
            if omitted == 0
            else f"{scan_state}; {omitted:,} candidate(s) omitted at retention cap"
        )
        yield Header(show_clock=True)
        yield Static(
            Text(f" {filename}  |  {len(self._records):,} string records  |  {coverage}"),
            id="strings-summary",
        )
        with Horizontal(id="strings-filters"):
            yield Input(
                value="0",
                placeholder="Min length",
                id="strings-min-length",
                classes="strings-filter",
                type="integer",
            )
            yield Input(
                placeholder="Search extracted values, descriptions, and reasons",
                id="strings-search",
                classes="strings-filter",
            )
            yield Select(
                self._category_options(),
                value="*",
                allow_blank=False,
                id="strings-category",
                classes="strings-filter",
            )
            yield Select(
                self._encoding_options(),
                value="*",
                allow_blank=False,
                id="strings-encoding",
                classes="strings-filter",
            )
        with Horizontal(id="strings-body"):
            yield DataTable(id="strings-table", cursor_type="row", zebra_stripes=True)
            with TabbedContent(id="strings-tabs"):
                with TabPane("Details", id="strings-tab-details"):
                    yield RichLog(
                        id="strings-detail-log", classes="strings-log", markup=False, wrap=True
                    )
                with TabPane("Category summary", id="strings-tab-summary"):
                    yield RichLog(
                        id="strings-category-log", classes="strings-log", markup=False, wrap=True
                    )
                with TabPane("All strings", id="strings-tab-all"):
                    yield RichLog(
                        id="strings-all-log", classes="strings-log", markup=False, wrap=False
                    )
                with TabPane("AI", id="strings-tab-ai"):
                    yield LoadingIndicator(id="strings-ai-loading")
                    yield RichLog(
                        id="strings-ai-log", classes="strings-log", markup=False, wrap=True
                    )
        yield Static("Preparing string records…", id="strings-status")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#strings-table", DataTable)
        table.add_column("Score", key="score", width=7)
        table.add_column("Offset", key="offset", width=13)
        table.add_column("Encoding", key="encoding", width=10)
        table.add_column("Len", key="length", width=7)
        table.add_column("Categories", key="categories", width=24)
        table.add_column("Value", key="value")
        self._apply_filters(reset_page=True)
        ai_log = self.query_one("#strings-ai-log", RichLog)
        if self._ai_report is not None:
            self._show_ai_report(self._ai_report, restored=True)
        elif getattr(self.ai_analyzer, "remote_enabled", True):
            ai_log.write(
                Text(
                    "AI analysis has not run. Press A, review the evidence-transfer warning, "
                    "and confirm explicitly. No string is sent automatically."
                )
            )
        else:
            ai_log.write(
                Text("AI string analysis is unavailable in offline mode; no evidence will leave this host.")
            )

    def _category_options(self) -> list[tuple[str, str]]:
        categories = sorted(
            {category for record in self._records for category in self._categories(record)},
            key=str.casefold,
        )
        return [("All categories", "*"), *((item, item) for item in categories)]

    def _encoding_options(self) -> list[tuple[str, str]]:
        encodings = sorted(
            {_label(_field(record, "encoding", default="unknown")) for record in self._records},
            key=str.casefold,
        )
        return [("All encodings", "*"), *((item, item) for item in encodings)]

    @staticmethod
    def _categories(record: Any) -> tuple[str, ...]:
        values = _values(record, "categories", "category")
        return values or ("uncategorized",)

    @staticmethod
    def _length(record: Any) -> int:
        value = _field(record, "char_length", "length", default=None)
        if value is None:
            value = len(str(_field(record, "value", default="")))
        return _integer(value)

    @staticmethod
    def _score(record: Any) -> float:
        value = _field(
            record,
            "score",
            "suspicion_score",
            "suspicious_score",
            default=0,
        )
        try:
            return float(value)
        except (TypeError, ValueError, OverflowError):
            return 0.0

    def _filter_settings(self) -> tuple[int, str, str | None, str | None]:
        minimum = max(0, _integer(self.query_one("#strings-min-length", Input).value))
        search = self.query_one("#strings-search", Input).value.strip()
        category_value = self.query_one("#strings-category", Select).value
        encoding_value = self.query_one("#strings-encoding", Select).value
        category = None if category_value in ("*", Select.BLANK) else str(category_value)
        encoding = None if encoding_value in ("*", Select.BLANK) else str(encoding_value)
        return minimum, search, category, encoding

    def _records_from_analysis_filter(
        self, minimum: int, search: str, category: str | None, encoding: str | None
    ) -> list[Any] | None:
        filter_method = getattr(self.string_analysis, "filter", None)
        if not callable(filter_method):
            return None
        try:
            result = filter_method(
                min_length=minimum,
                category=category,
                search=search,
                encoding=encoding,
            )
        except TypeError:
            return None
        records = getattr(result, "records", result)
        try:
            return list(records)
        except TypeError:
            return None

    def _records_from_local_filter(
        self, minimum: int, search: str, category: str | None, encoding: str | None
    ) -> list[Any]:
        needle = search.casefold()
        result = []
        for record in self._records:
            if self._length(record) < minimum:
                continue
            categories = self._categories(record)
            if category is not None and category.casefold() not in {
                value.casefold() for value in categories
            }:
                continue
            record_encoding = _label(_field(record, "encoding", default="unknown"))
            if encoding is not None and encoding.casefold() != record_encoding.casefold():
                continue
            if needle:
                searchable = "\n".join(
                    (
                        str(_field(record, "value", default="")),
                        " ".join(categories),
                        " ".join(_values(record, "reasons")),
                        " ".join(_values(record, "descriptions", "description")),
                    )
                ).casefold()
                if needle not in searchable:
                    continue
            result.append(record)
        return result

    def _apply_filters(self, *, reset_page: bool = False) -> None:
        minimum, search, category, encoding = self._filter_settings()
        records = self._records_from_analysis_filter(minimum, search, category, encoding)
        if records is None:
            records = self._records_from_local_filter(minimum, search, category, encoding)
        self._filtered_records = records
        self._sort_records()
        if reset_page:
            self._page = 0
        self._page = min(self._page, self._page_count() - 1)
        self._render_page()
        self._render_category_summary()

    def _sort_records(self) -> None:
        if self._sort_column is None:
            return
        key_functions = {
            "score": self._score,
            "offset": lambda item: _integer(_field(item, "file_offset", "offset", default=0)),
            "encoding": lambda item: _label(_field(item, "encoding", default="")).casefold(),
            "length": self._length,
            "categories": lambda item: ",".join(self._categories(item)).casefold(),
            "value": lambda item: str(_field(item, "value", default="")).casefold(),
        }
        self._filtered_records.sort(
            key=key_functions[self._sort_column], reverse=self._sort_reverse
        )

    def _page_count(self) -> int:
        return max(1, math.ceil(len(self._filtered_records) / self.PAGE_SIZE))

    def _page_records(self) -> list[Any]:
        start = self._page * self.PAGE_SIZE
        return self._filtered_records[start : start + self.PAGE_SIZE]

    def _render_page(self) -> None:
        table = self.query_one("#strings-table", DataTable)
        table.clear(columns=False)
        self._visible_records.clear()
        page_records = self._page_records()
        for index, record in enumerate(page_records):
            absolute_index = self._page * self.PAGE_SIZE + index
            row_key = str(absolute_index)
            self._visible_records[row_key] = record
            offset = _integer(_field(record, "file_offset", "offset", default=0))
            score = self._score(record)
            table.add_row(
                Text(f"{score:.1f}"),
                Text(f"0x{offset:08x}"),
                Text(_display_text(_field(record, "encoding", default="unknown"), 32)),
                Text(str(self._length(record))),
                Text(_display_text(", ".join(self._categories(record)), 120)),
                Text(_display_text(_field(record, "value", default=""), 1_000)),
                key=row_key,
            )
        self._render_all_strings(page_records)
        if page_records:
            table.move_cursor(row=0)
            self._render_details(page_records[0])
        else:
            self.query_one("#strings-detail-log", RichLog).clear()
            self.query_one("#strings-detail-log", RichLog).write(
                Text("No string records match the active filters.")
            )
        start = self._page * self.PAGE_SIZE + (1 if page_records else 0)
        end = self._page * self.PAGE_SIZE + len(page_records)
        omitted = _integer(getattr(self.string_analysis, "omitted_count", 0))
        scanned = _integer(getattr(self.string_analysis, "scanned_bytes", 0))
        total = _integer(getattr(self.string_analysis, "total_bytes", scanned))
        scan_note = "full byte scan" if scanned >= total else "partial byte scan"
        if omitted:
            scan_note += f"; {omitted:,} candidate(s) omitted at retention cap"
        self.query_one("#strings-status", Static).update(
            Text(
                f"Page {self._page + 1}/{self._page_count()} — records {start:,}–{end:,} "
                f"of {len(self._filtered_records):,} filtered / {len(self._records):,} total — "
                f"{scan_note}; click a column heading to sort."
            )
        )

    def _render_details(self, record: Any) -> None:
        log = self.query_one("#strings-detail-log", RichLog)
        log.clear()
        offset = _integer(_field(record, "file_offset", "offset", default=0))
        rva = _field(record, "rva", default=None)
        address = _field(record, "va", "virtual_address", "address", default=None)
        reasons = self._reasons(record)
        descriptions = _values(record, "descriptions", "description")
        occurrence_count = max(
            1, _integer(_field(record, "occurrence_count", default=1), default=1)
        )
        occurrence_offsets = _values(record, "occurrence_offsets")
        occurrence_addresses = _values(record, "occurrence_addresses")
        truncated = bool(_field(record, "truncated", default=False))
        lines = [
            "String record",
            f"ID            {_display_text(_field(record, 'id', 'record_id', default='unknown'), 128)}",
            f"Value         {_display_text(_field(record, 'value', default=''), 8_000)}",
            f"File offset   0x{offset:x}",
            f"RVA           {self._format_address(rva)}",
            f"VA/address    {self._format_address(address)}",
            f"Section       {_display_text(_field(record, 'section', 'section_name', default='unmapped'), 256)}",
            f"Encoding      {_display_text(_field(record, 'encoding', default='unknown'), 64)}",
            f"Confidence    {_display_text(_field(record, 'confidence', default='unknown'), 64)}",
            f"Characters    {self._length(record)}",
            f"Bytes         {_integer(_field(record, 'byte_length', default=0))}",
            f"Value preview {'truncated' if truncated else 'complete'}",
            f"Occurrences   {occurrence_count}",
            f"Shown offsets {_display_text(', '.join(self._format_offset(value) for value in occurrence_offsets) or self._format_offset(offset), 2_000)}",
            f"Shown addrs   {_display_text(', '.join(self._format_address(value) for value in occurrence_addresses) or self._format_address(address), 2_000)}",
            f"Categories    {_display_text(', '.join(self._categories(record)), 1_000)}",
            f"Score         {self._score(record):.1f}",
            "",
            "Reasons",
            *(f"- {_display_text(reason, 2_000)}" for reason in reasons),
            "",
            "Descriptions",
            *(f"- {_display_text(description, 4_000)}" for description in descriptions),
        ]
        if not reasons:
            lines.insert(lines.index("Descriptions") - 1, "- No scoring reasons were recorded.")
        if not descriptions:
            lines.append("- No deterministic description is available.")
        log.write(Text("\n".join(lines)))

    @staticmethod
    def _format_address(value: Any) -> str:
        if value in (None, ""):
            return "unmapped"
        try:
            return f"0x{int(value):x}"
        except (TypeError, ValueError, OverflowError):
            return _display_text(value, 128)

    @staticmethod
    def _format_offset(value: Any) -> str:
        try:
            return f"0x{int(value):x}"
        except (TypeError, ValueError, OverflowError):
            return _display_text(value, 128)

    @staticmethod
    def _reasons(record: Any) -> tuple[str, ...]:
        reasons = _field(record, "reasons", default=())
        if isinstance(reasons, Mapping):
            return tuple(f"{_label(key)}: {_label(value)}" for key, value in reasons.items())
        return _values(record, "reasons")

    def _render_category_summary(self) -> None:
        counts: Counter[str] = Counter()
        for record in self._filtered_records:
            counts.update(self._categories(record))
        lines = [
            "Category coverage",
            f"Filtered records: {len(self._filtered_records):,}",
            f"All records:      {len(self._records):,}",
            "",
        ]
        lines.extend(
            f"{_display_text(category, 100):<32} {count:>8,}"
            for category, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        )
        if not counts:
            lines.append("No categories match the active filters.")
        log = self.query_one("#strings-category-log", RichLog)
        log.clear()
        log.write(Text("\n".join(lines)))

    def _render_all_strings(self, records: list[Any]) -> None:
        lines = [
            f"Filtered strings — page {self._page + 1}/{self._page_count()} "
            f"(at most {self.PAGE_SIZE} records shown here)",
            "",
        ]
        for record in records:
            offset = _integer(_field(record, "file_offset", "offset", default=0))
            encoding = _display_text(_field(record, "encoding", default="unknown"), 32)
            value = _display_text(_field(record, "value", default=""), 8_000)
            lines.append(f"0x{offset:08x}  {encoding:<10}  {value}")
        if not records:
            lines.append("No string records match the active filters.")
        log = self.query_one("#strings-all-log", RichLog)
        log.clear()
        log.write(Text("\n".join(lines)))

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id in {"strings-min-length", "strings-search"}:
            self._schedule_filter_update()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id in {"strings-category", "strings-encoding"}:
            self._cancel_filter_update()
            self._apply_filters(reset_page=True)

    def _schedule_filter_update(self) -> None:
        self._cancel_filter_update()
        revision = self._filter_revision
        self._filter_timer = self.set_timer(
            self.FILTER_DEBOUNCE_SECONDS,
            lambda: self._apply_scheduled_filter(revision),
            name="strings-filter-debounce",
        )

    def _cancel_filter_update(self) -> None:
        self._filter_revision += 1
        if self._filter_timer is not None:
            self._filter_timer.stop()
            self._filter_timer = None

    def _apply_scheduled_filter(self, revision: int) -> None:
        if revision != self._filter_revision:
            return
        self._filter_timer = None
        self._apply_filters(reset_page=True)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        record = self._visible_records.get(str(event.row_key.value))
        if record is not None:
            self._render_details(record)

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        column = str(event.column_key.value)
        if column not in {"score", "offset", "encoding", "length", "categories", "value"}:
            return
        if self._sort_column == column:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_column = column
            self._sort_reverse = column in {"score", "length"}
        self._apply_filters(reset_page=True)

    def action_previous_page(self) -> None:
        if self._page > 0:
            self._page -= 1
            self._render_page()

    def action_next_page(self) -> None:
        if self._page + 1 < self._page_count():
            self._page += 1
            self._render_page()

    def action_first_page(self) -> None:
        self._page = 0
        self._render_page()

    def action_last_page(self) -> None:
        self._page = self._page_count() - 1
        self._render_page()

    def action_reset_filters(self) -> None:
        self._cancel_filter_update()
        self.query_one("#strings-min-length", Input).value = "0"
        self.query_one("#strings-search", Input).value = ""
        self.query_one("#strings-category", Select).value = "*"
        self.query_one("#strings-encoding", Select).value = "*"
        self._sort_column = None
        self._sort_reverse = False
        self._apply_filters(reset_page=True)

    def action_analyze_with_ai(self) -> None:
        tabs = self.query_one("#strings-tabs", TabbedContent)
        tabs.active = "strings-tab-ai"
        if not getattr(self.ai_analyzer, "remote_enabled", True):
            self._set_status("AI string analysis is disabled in offline mode; no evidence was sent.")
            return
        if self._ai_running:
            self._set_status("AI string analysis is already running.")
            return
        analyzer_name = _display_text(
            getattr(self.ai_analyzer, "display_name", "the configured AI provider"), 160
        )
        transmits = bool(getattr(self.ai_analyzer, "transmits_evidence", True))
        destination = (
            "All retained string records may be transmitted to a remote provider"
            if transmits
            else "All retained string records will be processed by the configured local provider"
        )
        warning = (
            f"{destination}: {analyzer_name}. Strings may contain credentials, personal data, "
            f"malware-authored prompt injection, or other secrets. Analysis covers {len(self._records):,} "
            "locally extracted records and may require many model requests (in the worst case, "
            "one chunk request per retained record plus a reducer). Remote requests can "
            "incur API cost. AIDebug treats every string as untrusted evidence, but provider retention "
            "and billing policies still apply. Continue?"
        )
        self.app.push_screen(AIStringsConsentScreen(warning), self._on_ai_consent)

    def _on_ai_consent(self, confirmed: bool | None) -> None:
        if not confirmed:
            self._set_status("AI string analysis cancelled; no evidence was sent.")
            return
        self._ai_cancel_event = threading.Event()
        self._ai_running = True
        self.query_one("#strings-ai-loading", LoadingIndicator).display = True
        ai_log = self.query_one("#strings-ai-log", RichLog)
        ai_log.clear()
        ai_log.write(
            Text(
                f"Analyzing {len(self._records):,} retained string records. "
                "The provider may receive multiple bounded batches…"
            )
        )
        self._set_status("AI string analysis running — coverage will be shown with the result.")
        self._run_ai_analysis()

    @work(thread=True)
    def _run_ai_analysis(self) -> None:
        cancel_event = self._ai_cancel_event

        def publish_progress(progress: Mapping[str, Any]) -> None:
            if not cancel_event.is_set():
                self.post_message(StringsProgress(progress))

        try:
            if self.ai_lock is None:
                report = self.ai_analyzer.analyze_strings(
                    self.string_analysis,
                    self.binary_info,
                    progress_callback=publish_progress,
                    cancel_requested=cancel_event,
                )
            else:
                with self.ai_lock:
                    report = self.ai_analyzer.analyze_strings(
                        self.string_analysis,
                        self.binary_info,
                        progress_callback=publish_progress,
                        cancel_requested=cancel_event,
                    )
        except Exception as exc:
            if not cancel_event.is_set():
                self.post_message(StringsReportFailed(_display_text(exc, 2_000)))
            return
        if not cancel_event.is_set():
            self.post_message(StringsReportReady(report))

    def on_strings_progress(self, event: StringsProgress) -> None:
        attempted = _integer(event.progress.get("chunks_attempted"), 0)
        total = _integer(event.progress.get("chunks_total"), 0)
        reviewed = _integer(event.progress.get("records_reviewed"), 0)
        self._set_status(
            f"AI string analysis running — chunks {attempted:,}/{total:,}; "
            f"validated records {reviewed:,}."
        )

    def on_strings_report_ready(self, event: StringsReportReady) -> None:
        if self._ai_cancel_event.is_set():
            return
        self._ai_running = False
        self._ai_report = event.report
        self.binary_info.string_ai_report = event.report
        self.query_one("#strings-ai-loading", LoadingIndicator).display = False
        self._show_ai_report(event.report, restored=False)

    def _show_ai_report(self, report: Any, *, restored: bool) -> None:
        rendered = self._report_mapping(report)
        processed = _integer(
            rendered.get("analyzed_record_count", rendered.get("records_analyzed", len(self._records))),
            len(self._records),
        )
        coverage = rendered.get("coverage")
        coverage_text = self._coverage_text(coverage, processed)
        log = self.query_one("#strings-ai-log", RichLog)
        log.clear()
        report_text = self._render_ai_report(rendered, coverage_text)
        if restored:
            report_text = "Restored in-memory report for this loaded artifact.\n\n" + report_text
        if len(report_text) > self.AI_DISPLAY_MAX_CHARS:
            suffix = (
                "\n\nDISPLAY TRUNCATED AT THE TUI CHARACTER CEILING — "
                "the complete report remains available in memory."
            )
            report_text = report_text[: self.AI_DISPLAY_MAX_CHARS - len(suffix)] + suffix
        log.write(Text(report_text))
        state = "restored from this loaded artifact" if restored else "complete"
        self._set_status(f"AI string analysis {state} — coverage: {coverage_text}.")

    def _render_ai_report(self, report: Mapping[str, Any], coverage_text: str) -> str:
        """Build a bounded analyst view while retaining the complete report object."""
        lines = [
            "AI string analysis",
            f"Coverage: {_display_text(coverage_text, 1_000)}",
            f"Assessment: {_display_text(report.get('overall_assessment', 'unknown'), 128)}",
            f"Confidence: {_display_text(report.get('confidence', 'unknown'), 128)}",
            "",
            "Executive summary",
            _display_text(
                report.get("executive_summary", report.get("summary", "No summary supplied.")),
                3_000,
            ),
            "",
        ]
        display_truncated = False
        sections = (
            ("Suspicious findings", "suspicious_findings", self.AI_DISPLAY_ITEM_LIMIT),
            ("IOCs", "iocs", self.AI_DISPLAY_ITEM_LIMIT),
            ("Capabilities", "capabilities", self.AI_DISPLAY_ITEM_LIMIT),
            ("DLL / API entities", "entities", self.AI_DISPLAY_ENTITY_LIMIT),
            ("Limitations", "limitations", self.AI_DISPLAY_ITEM_LIMIT),
            ("Analyst next steps", "analyst_next_steps", self.AI_DISPLAY_ITEM_LIMIT),
        )
        for title, key, limit in sections:
            values = self._report_list(report.get(key))
            shown = min(len(values), limit)
            lines.append(f"{title} — showing {shown:,} of {len(values):,}")
            for item in values[:limit]:
                lines.append(f"- {self._format_report_item(item)}")
            if not values:
                lines.append("- None reported.")
            if len(values) > limit:
                display_truncated = True
                lines.append(f"- … {len(values) - limit:,} additional item(s) retained in memory.")
            lines.append("")

        annotations = self._report_list(report.get("annotations"))
        relationships = self._report_list(report.get("relationships"))
        lines.extend(
            (
                "Full-report inventory",
                f"Annotations:   {len(annotations):,} (not expanded in the TUI)",
                f"Relationships: {len(relationships):,} (not expanded in the TUI)",
            )
        )
        if annotations or relationships:
            display_truncated = True
        if display_truncated:
            lines.extend(
                (
                    "",
                    "DISPLAY TRUNCATED — the complete validated report remains available in memory; "
                    "the TUI intentionally renders only bounded analyst highlights.",
                )
            )

        rendered = "\n".join(lines)
        if len(rendered) > self.AI_DISPLAY_MAX_CHARS:
            suffix = (
                "\n\nDISPLAY TRUNCATED AT THE TUI CHARACTER CEILING — "
                "the complete report remains available in memory."
            )
            rendered = rendered[: self.AI_DISPLAY_MAX_CHARS - len(suffix)] + suffix
        return rendered

    @staticmethod
    def _report_list(value: Any) -> list[Any]:
        if isinstance(value, list):
            return value
        if isinstance(value, tuple):
            return list(value)
        return []

    def _format_report_item(self, item: Any) -> str:
        if not isinstance(item, Mapping):
            return _display_text(item, self.AI_DISPLAY_ITEM_CHARS)
        headline = next(
            (
                item.get(key)
                for key in (
                    "title",
                    "name",
                    "canonical_name",
                    "normalized_value",
                    "string_id",
                )
                if item.get(key) not in (None, "")
            ),
            "finding",
        )
        attributes = []
        for key in ("kind", "type", "severity", "confidence", "resolution", "module"):
            value = item.get(key)
            if value not in (None, ""):
                attributes.append(f"{key}={_display_text(value, 128)}")
        evidence = item.get("evidence_ids")
        if isinstance(evidence, (list, tuple)) and evidence:
            attributes.append(
                f"evidence={','.join(_display_text(value, 128) for value in evidence[:12])}"
            )
        bodies = [
            _display_text(item.get(key), 500)
            for key in (
                "analysis",
                "context",
                "basis",
                "description",
                "security_relevance",
                "reason",
            )
            if item.get(key) not in (None, "")
        ]
        text = _display_text(headline, 256)
        if attributes:
            text += f" ({'; '.join(attributes)})"
        if bodies:
            text += f": {' | '.join(bodies)}"
        return _display_text(text, self.AI_DISPLAY_ITEM_CHARS)

    def _coverage_text(self, coverage: Any, processed: int) -> str:
        if not isinstance(coverage, Mapping):
            return (
                _display_text(coverage, 500)
                if coverage is not None
                else f"{processed:,}/{len(self._records):,} records"
            )
        extracted = _integer(coverage.get("extracted_count"), len(self._records))
        retained = _integer(coverage.get("retained_count"), len(self._records))
        sent = _integer(coverage.get("sent_count"), retained)
        reviewed = _integer(coverage.get("reviewed_count"), sent)
        attempted = _integer(coverage.get("chunks_attempted"), 0)
        total_chunks = _integer(coverage.get("chunks_total"), attempted)
        complete = bool(coverage.get("complete", False))
        state = "complete" if complete else "partial"
        return (
            f"{state}; extracted {extracted:,}, retained {retained:,}, sent {sent:,}, "
            f"reviewed {reviewed:,}; chunks {attempted:,}/{total_chunks:,}"
        )

    def on_strings_report_failed(self, event: StringsReportFailed) -> None:
        if self._ai_cancel_event.is_set():
            return
        self._ai_running = False
        self.query_one("#strings-ai-loading", LoadingIndicator).display = False
        log = self.query_one("#strings-ai-log", RichLog)
        log.clear()
        log.write(
            Text(
                "AI string analysis failed. Deterministic extraction and categories remain available.\n"
                f"Error: {event.error}"
            )
        )
        self._set_status("AI string analysis failed; local deterministic results are unchanged.")

    @staticmethod
    def _report_mapping(report: Any) -> dict[str, Any]:
        if isinstance(report, Mapping):
            return dict(report)
        to_dict = getattr(report, "to_dict", None)
        if callable(to_dict):
            value = to_dict()
            if isinstance(value, Mapping):
                return dict(value)
        if is_dataclass(report):
            return asdict(report)
        values = getattr(report, "__dict__", None)
        if isinstance(values, Mapping):
            return {key: value for key, value in values.items() if not str(key).startswith("_")}
        return {"result": str(report)}

    def _set_status(self, value: str) -> None:
        self.query_one("#strings-status", Static).update(Text(_display_text(value, 2_000)))

    def action_close(self) -> None:
        self._ai_cancel_event.set()
        self._cancel_filter_update()
        self.app.pop_screen()

    def on_unmount(self) -> None:
        self._ai_cancel_event.set()
        self._cancel_filter_update()


__all__ = ["AIStringsConsentScreen", "StringsAnalysisScreen"]
