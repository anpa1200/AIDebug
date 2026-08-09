"""Full-screen Portable Executable structure and hexadecimal workspace."""

from __future__ import annotations

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, RichLog, Static, TabbedContent, TabPane

from analysis.pe_structure import PEStructure, page_count, render_hex_page


def _safe(value, limit: int = 16_384) -> str:
    rendered = []
    for character in str(value)[:limit]:
        if character in "\n\t" or character.isprintable():
            rendered.append(character)
        elif ord(character) <= 0xFF:
            rendered.append(f"\\x{ord(character):02x}")
        else:
            rendered.append(f"\\u{ord(character):04x}")
    return escape("".join(rendered))


def _number(value: int | None) -> str:
    if value is None:
        return "—"
    return f"0x{value:x} ({value})"


def _header_value(value) -> str:
    if isinstance(value, int):
        return _number(value)
    if isinstance(value, bytes):
        return repr(value)
    return _safe(value)


class PEStructureScreen(Screen):
    """Browse all PE metadata and every byte without loading huge logs at once."""

    TITLE = "AIDebug — PE Structure"
    HEX_PAGE_SIZE = 4096
    RECORD_PAGE_SIZE = 250

    CSS = """
PEStructureScreen {
    background: $surface;
}

#pe-summary {
    height: 3;
    background: $primary-darken-3;
    color: $text;
    padding: 0 2;
}

#pe-tabs {
    height: 1fr;
}

.pe-log {
    height: 1fr;
    border: solid $primary-darken-2;
}

#pe-status {
    height: 1;
    background: $primary-darken-3;
    color: $text-muted;
    padding: 0 2;
}
"""

    BINDINGS = [
        Binding("escape", "close", "Back", show=True),
        Binding("q", "close", "Back", show=False),
        Binding("pageup", "previous_page", "Previous page", show=True),
        Binding("pagedown", "next_page", "Next page", show=True),
        Binding("home", "first_page", "First page", show=False),
        Binding("end", "last_page", "Last page", show=False),
    ]

    def __init__(self, structure: PEStructure):
        super().__init__()
        self.structure = structure
        self._pages = {"pe-hex": 0, "pe-imports": 0, "pe-exports": 0}

    def compose(self) -> ComposeResult:
        pe = self.structure
        yield Header(show_clock=True)
        yield Static(
            Text(
                f" {pe.filename}  |  PE {pe.arch} {pe.bits}-bit  |  "
                f"{pe.file_size:,} bytes  |  SHA-256 {pe.sha256[:16]}...\n"
                f" Image base 0x{pe.image_base:x}  |  Entry point 0x{pe.entry_point:x}  |  "
                f"{len(pe.sections)} sections  |  {len(pe.imports)} imports  |  "
                f"{len(pe.exports)} exports"
            ),
            id="pe-summary",
        )
        with Vertical():
            with TabbedContent(id="pe-tabs"):
                with TabPane("Overview", id="pe-overview"):
                    yield RichLog(id="pe-overview-log", classes="pe-log", markup=True, wrap=False)
                with TabPane("Hex", id="pe-hex"):
                    yield RichLog(id="pe-hex-log", classes="pe-log", markup=False, wrap=False)
                with TabPane("Headers", id="pe-headers"):
                    yield RichLog(id="pe-headers-log", classes="pe-log", markup=True, wrap=False)
                with TabPane("Sections", id="pe-sections"):
                    yield RichLog(id="pe-sections-log", classes="pe-log", markup=True, wrap=False)
                with TabPane("Directories", id="pe-directories"):
                    yield RichLog(id="pe-directories-log", classes="pe-log", markup=True, wrap=False)
                with TabPane("Imports", id="pe-imports"):
                    yield RichLog(id="pe-imports-log", classes="pe-log", markup=True, wrap=False)
                with TabPane("Exports", id="pe-exports"):
                    yield RichLog(id="pe-exports-log", classes="pe-log", markup=True, wrap=False)
        yield Static("Read-only PE evidence view.", id="pe-status")
        yield Footer()

    def on_mount(self) -> None:
        self._render_overview()
        self._render_hex()
        self._render_headers()
        self._render_sections()
        self._render_directories()
        self._render_imports()
        self._render_exports()
        self._update_status()

    def _render_overview(self) -> None:
        pe = self.structure
        log = self.query_one("#pe-overview-log", RichLog)
        log.write("[bold cyan]Portable Executable evidence[/bold cyan]")
        log.write(f"File              {_safe(pe.filename)}")
        log.write(f"SHA-256           {_safe(pe.sha256)}")
        log.write(f"Size              {pe.file_size:,} bytes")
        log.write(f"Architecture      {_safe(pe.arch)} ({pe.bits}-bit)")
        log.write(f"Image base        0x{pe.image_base:x}")
        log.write(f"Entry point       0x{pe.entry_point:x}")
        log.write(f"Headers           {len(pe.headers)} groups")
        log.write(f"Data directories  {len(pe.data_directories)}")
        log.write(f"Sections          {len(pe.sections)}")
        log.write(f"Imports           {len(pe.imports)}")
        log.write(f"Exports           {len(pe.exports)}")
        if pe.overlay_offset is None:
            log.write("Overlay           none detected")
        else:
            log.write(
                f"Overlay           offset 0x{pe.overlay_offset:x}, "
                f"{pe.overlay_size:,} bytes"
            )
        if pe.imports_truncated or pe.exports_truncated:
            log.write(
                "[yellow]A configured safety limit was reached; see the affected tab.[/yellow]"
            )
        log.write(
            "\n[dim]The Hex tab exposes the entire analyzed file in 4 KiB pages. "
            "No sample code is executed and the source path is not reopened.[/dim]"
        )

    def _render_hex(self) -> None:
        log = self.query_one("#pe-hex-log", RichLog)
        rendered, selected, total = render_hex_page(
            self.structure.raw_data,
            self._pages["pe-hex"],
            page_size=self.HEX_PAGE_SIZE,
        )
        self._pages["pe-hex"] = selected
        start = selected * self.HEX_PAGE_SIZE
        end = min(len(self.structure.raw_data), start + self.HEX_PAGE_SIZE)
        log.clear()
        log.write(
            Text(
                f"Whole-file hexadecimal view — page {selected + 1}/{total}, "
                f"offsets 0x{start:x}–0x{max(start, end - 1):x}\n"
                "OFFSET    00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  ASCII\n"
                f"{rendered}"
            )
        )

    def _render_headers(self) -> None:
        log = self.query_one("#pe-headers-log", RichLog)
        for header in self.structure.headers:
            log.write(f"[bold cyan]{_safe(header.name)}[/bold cyan]")
            log.write("File offset  Size  Field                         Value")
            for field in header.fields:
                offset = f"0x{field.file_offset:08x}" if field.file_offset is not None else "—".rjust(10)
                size = str(field.size) if field.size is not None else "—"
                log.write(
                    f"{offset}  {size:>4}  {_safe(field.name, 80):<29} "
                    f"{_header_value(field.value)}"
                )
                for flag_name in field.decoded_flags:
                    log.write(f"{'':17}  [green]↳ {_safe(flag_name, 80)}[/green]")
                if field.mitigation_clues:
                    log.write(f"{'':17}  [bold cyan]Mitigation clues[/bold cyan]")
                    for clue in field.mitigation_clues:
                        log.write(f"{'':17}  [cyan]• {_safe(clue, 160)}[/cyan]")
                    log.write(
                        f"{'':17}  [dim]Header flags are clues, not proof of "
                        "effective runtime policy.[/dim]"
                    )
            log.write("")

    def _render_sections(self) -> None:
        log = self.query_one("#pe-sections-log", RichLog)
        log.write(
            "[bold cyan]Section table[/bold cyan]\n"
            "Name       RVA        VA                 Virtual    Raw offset  Raw size  "
            "Entropy  Characteristics"
        )
        for section in self.structure.sections:
            log.write(
                f"{_safe(section.name, 64):<10} 0x{section.virtual_address:08x} "
                f"0x{self.structure.image_base + section.virtual_address:016x} "
                f"0x{section.virtual_size:08x} 0x{section.raw_offset:08x} "
                f"0x{section.raw_size:08x} {section.entropy:7.3f}  "
                f"0x{section.characteristics:08x}"
            )
        if not self.structure.sections:
            log.write("[dim]No sections were reported.[/dim]")

    def _render_directories(self) -> None:
        log = self.query_one("#pe-directories-log", RichLog)
        log.write("[bold cyan]Optional-header data directories[/bold cyan]")
        log.write("Index  Directory             RVA        Size")
        for directory in self.structure.data_directories:
            log.write(
                f"{directory.index:>5}  {_safe(directory.name, 64):<20} "
                f"0x{directory.rva:08x} 0x{directory.size:08x}"
            )
        if not self.structure.data_directories:
            log.write("[dim]No data directories were reported.[/dim]")

    def _render_imports(self) -> None:
        records = self.structure.imports
        page = self._bounded_record_page("pe-imports", len(records))
        start = page * self.RECORD_PAGE_SIZE
        selected = records[start:start + self.RECORD_PAGE_SIZE]
        total = page_count(len(records), self.RECORD_PAGE_SIZE)
        log = self.query_one("#pe-imports-log", RichLog)
        log.clear()
        log.write(
            f"[bold cyan]Imports — page {page + 1}/{total}[/bold cyan]\n"
            "Kind    IAT address         Hint  Ordinal  DLL!Symbol"
        )
        for item in selected:
            iat = f"0x{item.iat_address:016x}" if item.iat_address is not None else "—".rjust(18)
            hint = str(item.hint) if item.hint is not None else "—"
            ordinal = str(item.ordinal) if item.ordinal is not None else "—"
            log.write(
                f"{item.kind:<7} {iat} {hint:>5} {ordinal:>8}  "
                f"{_safe(item.dll, 512)}!{_safe(item.name, 512)}"
            )
        if not records:
            log.write("[dim]No imports were reported.[/dim]")
        if self.structure.imports_truncated:
            log.write(
                f"[yellow]Display model limited to {len(records):,} imports by "
                "MAX_IMPORT_FUNCTIONS.[/yellow]"
            )

    def _render_exports(self) -> None:
        records = self.structure.exports
        page = self._bounded_record_page("pe-exports", len(records))
        start = page * self.RECORD_PAGE_SIZE
        selected = records[start:start + self.RECORD_PAGE_SIZE]
        total = page_count(len(records), self.RECORD_PAGE_SIZE)
        log = self.query_one("#pe-exports-log", RichLog)
        log.clear()
        log.write(
            f"[bold cyan]Exports — page {page + 1}/{total}[/bold cyan]\n"
            "Ordinal  RVA         Address             Name / forwarder"
        )
        for item in selected:
            forwarder = f" -> {_safe(item.forwarder, 512)}" if item.forwarder else ""
            log.write(
                f"{item.ordinal:>7}  0x{item.rva:08x} 0x{item.address:016x}  "
                f"{_safe(item.name, 512)}{forwarder}"
            )
        if not records:
            log.write("[dim]No exports were reported.[/dim]")
        if self.structure.exports_truncated:
            log.write(
                f"[yellow]Display model limited to {len(records):,} exports by "
                "MAX_EXPORTS.[/yellow]"
            )

    def _active_paged_tab(self) -> str | None:
        active = self.query_one("#pe-tabs", TabbedContent).active
        return active if active in self._pages else None

    def _bounded_record_page(self, tab: str, count: int) -> int:
        selected = min(
            max(0, self._pages[tab]),
            page_count(count, self.RECORD_PAGE_SIZE) - 1,
        )
        self._pages[tab] = selected
        return selected

    def _total_pages(self, tab: str) -> int:
        if tab == "pe-hex":
            return page_count(len(self.structure.raw_data), self.HEX_PAGE_SIZE)
        if tab == "pe-imports":
            return page_count(len(self.structure.imports), self.RECORD_PAGE_SIZE)
        if tab == "pe-exports":
            return page_count(len(self.structure.exports), self.RECORD_PAGE_SIZE)
        return 1

    def _render_active_page(self, tab: str) -> None:
        if tab == "pe-hex":
            self._render_hex()
        elif tab == "pe-imports":
            self._render_imports()
        elif tab == "pe-exports":
            self._render_exports()
        self._update_status()

    def _update_status(self) -> None:
        tab = self._active_paged_tab()
        if tab is None:
            message = "Read-only PE evidence view. Select Hex, Imports, or Exports to page through data."
        else:
            page = self._pages[tab]
            total = self._total_pages(tab)
            message = (
                f"{tab.removeprefix('pe-').title()} page {page + 1}/{total} — "
                "PageUp/PageDown navigate; Home/End jump."
            )
        self.query_one("#pe-status", Static).update(Text(message))

    def action_previous_page(self) -> None:
        tab = self._active_paged_tab()
        if tab is None:
            self._update_status()
            return
        self._pages[tab] = max(0, self._pages[tab] - 1)
        self._render_active_page(tab)

    def action_next_page(self) -> None:
        tab = self._active_paged_tab()
        if tab is None:
            self._update_status()
            return
        self._pages[tab] = min(self._total_pages(tab) - 1, self._pages[tab] + 1)
        self._render_active_page(tab)

    def action_first_page(self) -> None:
        tab = self._active_paged_tab()
        if tab is not None:
            self._pages[tab] = 0
            self._render_active_page(tab)

    def action_last_page(self) -> None:
        tab = self._active_paged_tab()
        if tab is not None:
            self._pages[tab] = self._total_pages(tab) - 1
            self._render_active_page(tab)

    def action_close(self) -> None:
        self.app.pop_screen()
