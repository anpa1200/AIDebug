"""Read-only whole-file hexadecimal viewer for analyzed binaries."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, RichLog, Static, TabbedContent, TabPane

from analysis.pe_structure import page_count, render_hex_page


class HexViewerScreen(Screen):
    """Browse every byte from AIDebug's already-hashed in-memory evidence."""

    TITLE = "AIDebug — Hex Viewer"
    HEX_PAGE_SIZE = 4096

    CSS = """
HexViewerScreen {
    background: $surface;
}

#hex-summary {
    height: 3;
    background: $primary-darken-3;
    color: $text;
    padding: 0 2;
}

#hex-tabs {
    height: 1fr;
}

.hex-log {
    height: 1fr;
    border: solid $primary-darken-2;
}

#hex-status {
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

    def __init__(self, binary_info):
        super().__init__()
        raw_data = getattr(binary_info, "raw_data", b"")
        self.raw_data = bytes(raw_data)
        if not self.raw_data:
            raise ValueError("The analyzed file bytes are unavailable")
        self.filename = str(getattr(binary_info, "filename", "<unknown>"))
        self.file_format = str(getattr(binary_info, "file_format", "unknown"))
        self.arch = str(getattr(binary_info, "arch", "unknown"))
        self.bits = int(getattr(binary_info, "bits", 0) or 0)
        self.sha256 = str(getattr(binary_info, "sha256", "unknown"))
        self._page = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(
            Text(
                f" {self.filename}  |  {self.file_format} {self.arch} {self.bits}-bit  |  "
                f"{len(self.raw_data):,} bytes\n SHA-256 {self.sha256}"
            ),
            id="hex-summary",
        )
        with Vertical():
            with TabbedContent(id="hex-tabs"):
                with TabPane("Hex", id="hex-file"):
                    yield RichLog(id="hex-file-log", classes="hex-log", markup=False, wrap=False)
                with TabPane("Overview", id="hex-overview"):
                    yield RichLog(id="hex-overview-log", classes="hex-log", markup=False, wrap=False)
        yield Static("Read-only whole-file evidence view.", id="hex-status")
        yield Footer()

    def on_mount(self) -> None:
        self._render_hex()
        overview = self.query_one("#hex-overview-log", RichLog)
        overview.write(
            Text(
                "File evidence\n"
                f"File          {self.filename}\n"
                f"Format        {self.file_format}\n"
                f"Architecture  {self.arch} ({self.bits}-bit)\n"
                f"Size          {len(self.raw_data):,} bytes\n"
                f"SHA-256       {self.sha256}\n\n"
                "The viewer uses the exact in-memory bytes AIDebug hashed. "
                "It does not execute the file or reopen its source path."
            )
        )

    def _render_hex(self) -> None:
        rendered, selected, total = render_hex_page(
            self.raw_data,
            self._page,
            page_size=self.HEX_PAGE_SIZE,
        )
        self._page = selected
        start = selected * self.HEX_PAGE_SIZE
        end = min(len(self.raw_data), start + self.HEX_PAGE_SIZE)
        log = self.query_one("#hex-file-log", RichLog)
        log.clear()
        log.write(
            Text(
                f"Whole-file hexadecimal view — page {selected + 1}/{total}, "
                f"offsets 0x{start:x}–0x{max(start, end - 1):x}\n"
                "OFFSET    00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  ASCII\n"
                f"{rendered}"
            )
        )
        self.query_one("#hex-status", Static).update(
            Text(
                f"Hex page {selected + 1}/{total} — PageUp/PageDown navigate; "
                "Home/End jump."
            )
        )

    def _hex_is_active(self) -> bool:
        return self.query_one("#hex-tabs", TabbedContent).active == "hex-file"

    def action_previous_page(self) -> None:
        if self._hex_is_active():
            self._page = max(0, self._page - 1)
            self._render_hex()

    def action_next_page(self) -> None:
        if self._hex_is_active():
            self._page = min(
                page_count(len(self.raw_data), self.HEX_PAGE_SIZE) - 1,
                self._page + 1,
            )
            self._render_hex()

    def action_first_page(self) -> None:
        if self._hex_is_active():
            self._page = 0
            self._render_hex()

    def action_last_page(self) -> None:
        if self._hex_is_active():
            self._page = page_count(len(self.raw_data), self.HEX_PAGE_SIZE) - 1
            self._render_hex()

    def action_close(self) -> None:
        self.app.pop_screen()
