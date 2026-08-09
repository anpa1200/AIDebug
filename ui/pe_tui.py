"""Full-screen Portable Executable structure and hexadecimal workspace."""

from __future__ import annotations

import os
import re
from pathlib import Path

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, RichLog, Static, TabbedContent, TabPane, Tree

from analysis.pe_structure import (
    PEResourceDataRecord,
    PEResourceDirectoryRecord,
    PEStructure,
    page_count,
    render_hex_page,
)


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


def _resource_extension(record: PEResourceDataRecord) -> str:
    preview = record.preview
    if preview.startswith(b"MZ"):
        return ".exe"
    if preview.startswith(b"\x7fELF"):
        return ".elf"
    if preview.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if preview.startswith((b"\xff\xd8\xff",)):
        return ".jpg"
    if preview.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"
    if preview.startswith(b"PK\x03\x04"):
        return ".zip"
    stripped = preview.lstrip(b"\xef\xbb\xbf\x00\t\r\n ")
    if stripped.startswith((b"<?xml", b"<assembly", b"<manifest")):
        return ".xml"
    return ".bin"


def resource_filename(record: PEResourceDataRecord) -> str:
    """Build a stable, traversal-safe filename for a resource payload."""
    components = []
    for component in record.path:
        if component == "<root>":
            continue
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", component).strip("._-")
        components.append((cleaned or "unnamed")[:48])
    stem = "__".join(components)[:180] or "resource"
    identity = (record.sha256 or f"rva-{record.data_rva:08x}")[:12]
    return f"{stem}__{identity}{_resource_extension(record)}"


def resource_payload(
    structure: PEStructure,
    record: PEResourceDataRecord,
) -> bytes | None:
    """Return a complete payload only when its declared range is valid."""
    if not record.complete or record.data_file_offset is None:
        return None
    start = record.data_file_offset
    end = start + record.size
    if start < 0 or end < start or end > len(structure.raw_data):
        return None
    return structure.raw_data[start:end]


def export_resource(
    structure: PEStructure,
    record: PEResourceDataRecord,
    export_root: Path | None = None,
) -> Path:
    """Export one complete resource without overwrite or symlink following."""
    payload = resource_payload(structure, record)
    if payload is None:
        raise ValueError("The resource range is incomplete or unmapped")
    root = export_root or Path.cwd() / "aidebug-resource-exports"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise OSError("Resource export root is not a safe directory")
    sample_directory = root / structure.sha256[:16]
    sample_directory.mkdir(mode=0o700, exist_ok=True)
    if sample_directory.is_symlink() or not sample_directory.is_dir():
        raise OSError("Sample export path is not a safe directory")
    destination = sample_directory / resource_filename(record)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return destination


class ResourcePayloadScreen(Screen):
    """Open one embedded resource in a bounded, read-only hex/text viewer."""

    TITLE = "AIDebug — Resource payload"
    PAGE_SIZE = 4096

    BINDINGS = [
        Binding("escape", "close", "Back", show=True),
        Binding("q", "close", "Back", show=False),
        Binding("pageup", "previous_page", "Previous page", show=True),
        Binding("pagedown", "next_page", "Next page", show=True),
        Binding("home", "first_page", "First page", show=False),
        Binding("end", "last_page", "Last page", show=False),
    ]

    def __init__(self, structure: PEStructure, record: PEResourceDataRecord):
        super().__init__()
        self.structure = structure
        self.record = record
        self.payload = resource_payload(structure, record) or b""
        self.page = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(
            Text(
                f" {resource_filename(self.record)}  |  {len(self.payload):,} bytes  |  "
                f"SHA-256 {self.record.sha256 or 'unavailable'}"
            ),
            id="resource-summary",
        )
        yield RichLog(id="resource-payload-log", classes="pe-log", wrap=False)
        yield Static("Read-only resource evidence view.", id="resource-status")
        yield Footer()

    def on_mount(self) -> None:
        self._render_payload()

    def _render_payload(self) -> None:
        rendered, selected, total = render_hex_page(
            self.payload,
            self.page,
            page_size=self.PAGE_SIZE,
        )
        self.page = selected
        start = selected * self.PAGE_SIZE
        end = min(len(self.payload), start + self.PAGE_SIZE)
        log = self.query_one("#resource-payload-log", RichLog)
        log.clear()
        log.write(
            Text(
                f"Resource payload — page {selected + 1}/{total}, "
                f"offsets 0x{start:x}–0x{max(start, end - 1):x}\n"
                "OFFSET    00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  ASCII\n"
                f"{rendered}"
            )
        )
        chunk = self.payload[start:end]
        try:
            decoded = chunk.decode("utf-8")
        except UnicodeDecodeError:
            decoded = ""
        if decoded and all(character.isprintable() or character in "\r\n\t" for character in decoded):
            log.write(Text(f"\nUTF-8 text preview\n{decoded}"))
        self.query_one("#resource-status", Static).update(
            Text(
                f"Page {selected + 1}/{total} — PageUp/PageDown navigate; "
                "the payload is never executed."
            )
        )

    def action_previous_page(self) -> None:
        self.page = max(0, self.page - 1)
        self._render_payload()

    def action_next_page(self) -> None:
        total = page_count(len(self.payload), self.PAGE_SIZE)
        self.page = min(total - 1, self.page + 1)
        self._render_payload()

    def action_first_page(self) -> None:
        self.page = 0
        self._render_payload()

    def action_last_page(self) -> None:
        self.page = page_count(len(self.payload), self.PAGE_SIZE) - 1
        self._render_payload()

    def action_close(self) -> None:
        self.app.pop_screen()


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

#pe-resource-workspace {
    height: 1fr;
}

#pe-resource-tree {
    width: 2fr;
    height: 1fr;
    border: solid $primary-darken-2;
}

#pe-directories-log {
    width: 3fr;
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
        Binding("d", "export_resource", "Download resource", show=True),
    ]

    def __init__(self, structure: PEStructure):
        super().__init__()
        self.structure = structure
        self._pages = {
            "pe-hex": 0,
            "pe-import-descriptors": 0,
            "pe-imports": 0,
            "pe-exports": 0,
        }
        self._resource_nodes = {}

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
                with TabPane("Resources", id="pe-directories"):
                    with Horizontal(id="pe-resource-workspace"):
                        yield Tree("PE resources", id="pe-resource-tree")
                        yield RichLog(
                            id="pe-directories-log",
                            classes="pe-log",
                            markup=True,
                            wrap=False,
                        )
                with TabPane("Import descriptors", id="pe-import-descriptors"):
                    yield RichLog(
                        id="pe-import-descriptors-log",
                        classes="pe-log",
                        markup=True,
                        wrap=False,
                    )
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
        self._populate_resource_tree()
        self._render_directories()
        self._render_import_descriptors()
        self._render_imports()
        self._render_exports()
        self._update_status()

    def on_tabbed_content_tab_activated(
        self,
        event: TabbedContent.TabActivated,
    ) -> None:
        """Render paged evidence after its previously hidden pane becomes active."""
        if event.tabbed_content.id != "pe-tabs" or event.pane.id not in self._pages:
            return
        self._render_active_page(event.pane.id)

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
        log.write(f"Resource records  {len(pe.resources)}")
        log.write(f"Sections          {len(pe.sections)}")
        log.write(f"Imports           {len(pe.imports)}")
        log.write(f"Import descriptors {len(pe.import_descriptors)}")
        log.write(f"Delay descriptors {len(pe.delay_import_descriptors)}")
        log.write(f"Exports           {len(pe.exports)}")
        if pe.overlay_offset is None:
            log.write("Overlay           none detected")
        else:
            log.write(
                f"Overlay           offset 0x{pe.overlay_offset:x}, "
                f"{pe.overlay_size:,} bytes"
            )
        if pe.imports_truncated or pe.resources_truncated or pe.exports_truncated:
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
            "[bold cyan]IMAGE_SECTION_HEADER records[/bold cyan]\n"
            "[dim]Each record is 40 bytes. Raw header values and decoded flags "
            "are shown without executing the image.[/dim]"
        )
        for index, section in enumerate(self.structure.sections, start=1):
            header_offset = (
                f" at file offset 0x{section.header_offset:08x}"
                if section.header_offset is not None
                else ""
            )
            log.write(
                f"\n[bold cyan][{index}] {_safe(section.name, 64)}[/bold cyan]"
                f"[dim]{header_offset}[/dim]"
            )
            log.write("Field                         Value")
            log.write(f"Name                          {_safe(section.name, 64)}")
            log.write(f"VirtualSize                   0x{section.virtual_size:08x}")
            log.write(f"VirtualAddress (RVA)          0x{section.virtual_address:08x}")
            log.write(
                "Mapped virtual address        "
                f"0x{self.structure.image_base + section.virtual_address:016x}"
            )
            log.write(f"SizeOfRawData                 0x{section.raw_size:08x}")
            log.write(f"PointerToRawData              0x{section.raw_offset:08x}")
            log.write(
                "PointerToRelocations           "
                f"0x{section.pointer_to_relocations:08x}"
            )
            log.write(
                "PointerToLinenumbers           "
                f"0x{section.pointer_to_linenumbers:08x}"
            )
            log.write(f"NumberOfRelocations           {section.number_of_relocations}")
            log.write(f"NumberOfLinenumbers           {section.number_of_linenumbers}")
            log.write(f"Characteristics               0x{section.characteristics:08x}")
            for flag_name in section.characteristic_flags:
                log.write(f"                              [green]↳ {_safe(flag_name, 96)}[/green]")
            permissions = "".join(
                (
                    "R" if section.characteristics & 0x40000000 else "-",
                    "W" if section.characteristics & 0x80000000 else "-",
                    "X" if section.characteristics & 0x20000000 else "-",
                )
            )
            log.write(f"Memory permissions            {permissions}")
            log.write(f"Entropy                       {section.entropy:.3f} [dim](derived)[/dim]")
        if not self.structure.sections:
            log.write("[dim]No sections were reported.[/dim]")

    def _render_directories(self) -> None:
        self._render_resource_record(None)

    def _populate_resource_tree(self) -> None:
        tree = self.query_one("#pe-resource-tree", Tree)
        tree.root.set_label("PE resources")
        tree.root.expand()
        self._resource_nodes = {("<root>",): tree.root}
        for record in self.structure.resources:
            if isinstance(record, PEResourceDirectoryRecord):
                if record.path == ("<root>",):
                    tree.root.data = record
                    continue
                parent = self._resource_nodes.get(record.path[:-1], tree.root)
                node = parent.add(record.path[-1], data=record, expand=True)
                self._resource_nodes[record.path] = node
                continue
            parent = self._resource_nodes.get(record.path[:-1], tree.root)
            language = parent.add(record.path[-1], expand=True)
            self._resource_nodes[record.path] = language
            file_node = language.add(
                f"{resource_filename(record)}  ({record.size:,} bytes)",
                data=record,
            )
            self._resource_nodes[record.path + ("<data>",)] = file_node
        if not self.structure.resources:
            tree.root.add("No resource hierarchy reported", allow_expand=False)

    def _render_resource_record(
        self,
        record: PEResourceDirectoryRecord | PEResourceDataRecord | None,
    ) -> None:
        log = self.query_one("#pe-directories-log", RichLog)
        log.clear()
        log.write("[bold cyan]Optional-header data directories[/bold cyan]")
        log.write("Index  Directory             RVA        Size")
        for directory in self.structure.data_directories:
            log.write(
                f"{directory.index:>5}  {_safe(directory.name, 64):<20} "
                f"0x{directory.rva:08x} 0x{directory.size:08x}"
            )
        if not self.structure.data_directories:
            log.write("[dim]No data directories were reported.[/dim]")
        log.write(
            "\n[bold cyan]Resource explorer[/bold cyan]\n"
            "[dim]Conventional path: type → name/ID → language → data file. "
            "Select a file and press Enter to open it safely inside AIDebug; "
            "press D to download/export the exact bytes.[/dim]"
        )
        if record is None:
            if not self.structure.resources:
                log.write("[dim]No resource hierarchy was reported.[/dim]")
            else:
                data_count = sum(
                    isinstance(item, PEResourceDataRecord)
                    for item in self.structure.resources
                )
                log.write(
                    f"\n{data_count:,} resource files found. Use the explorer "
                    "on the left to inspect one."
                )
        elif isinstance(record, PEResourceDirectoryRecord):
            path = " → ".join(_safe(part, 256) for part in record.path)
            log.write(f"\n[bold cyan]Directory  {path}[/bold cyan]")
            log.write(f"Header file offset       0x{record.file_offset:08x}")
            log.write(f"Characteristics          0x{record.characteristics:08x}")
            log.write(f"TimeDateStamp            0x{record.time_date_stamp:08x}")
            log.write(f"Version                  {record.major_version}.{record.minor_version}")
            log.write(f"NumberOfNamedEntries     {record.named_entries}")
            log.write(f"NumberOfIdEntries        {record.id_entries}")
        else:
            path = " → ".join(_safe(part, 256) for part in record.path)
            log.write(f"\n[bold green]File       {resource_filename(record)}[/bold green]")
            log.write(f"Hierarchy                {path}")
            log.write(f"Data-entry file offset   0x{record.entry_file_offset:08x}")
            log.write(f"OffsetToData (RVA)       0x{record.data_rva:08x}")
            if record.data_file_offset is None:
                log.write("Data file offset         [red]unmapped / invalid[/red]")
            else:
                log.write(f"Data file offset         0x{record.data_file_offset:08x}")
            log.write(f"Size                     0x{record.size:08x} ({record.size})")
            log.write(f"CodePage                 {record.code_page}")
            log.write(f"Reserved                 0x{record.reserved:08x}")
            if record.complete:
                log.write(f"SHA-256                  {_safe(record.sha256)}")
            else:
                log.write(
                    "[yellow]Range warning            declared "
                    f"{record.size:,} bytes; only {record.available_size:,} "
                    "bytes are available in the analyzed file[/yellow]"
                )
                log.write(
                    "SHA-256                  [yellow]not computed for an "
                    "incomplete or unmapped range[/yellow]"
                )
            if record.preview:
                preview_hex = " ".join(f"{byte:02x}" for byte in record.preview)
                preview_ascii = "".join(
                    chr(byte) if 32 <= byte <= 126 else "."
                    for byte in record.preview
                )
                log.write(f"Preview (hex)            {preview_hex}")
                log.write(f"Preview (ASCII)          {_safe(preview_ascii)}")
            else:
                log.write("Preview                  [dim]empty or unavailable[/dim]")
        if self.structure.resources_truncated:
            log.write(
                "\n[yellow]Resource traversal was limited by the configured "
                "record/depth safety bounds or malformed cyclic evidence.[/yellow]"
            )

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
        if event.control.id != "pe-resource-tree":
            return
        record = event.node.data
        if isinstance(record, (PEResourceDirectoryRecord, PEResourceDataRecord)):
            self._render_resource_record(record)
        else:
            self._render_resource_record(None)

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        if event.control.id != "pe-resource-tree":
            return
        record = event.node.data
        if not isinstance(record, PEResourceDataRecord):
            return
        if resource_payload(self.structure, record) is None:
            self.query_one("#pe-status", Static).update(
                Text("Resource cannot be opened: its declared byte range is incomplete.")
            )
            return
        self.app.push_screen(ResourcePayloadScreen(self.structure, record))

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

    def _render_import_descriptors(self) -> None:
        records = self.structure.import_descriptors
        delay_records = self.structure.delay_import_descriptors
        record_count = max(len(records), len(delay_records))
        page = self._bounded_record_page("pe-import-descriptors", record_count)
        start = page * self.RECORD_PAGE_SIZE
        selected = records[start:start + self.RECORD_PAGE_SIZE]
        total = page_count(len(records), self.RECORD_PAGE_SIZE)
        log = self.query_one("#pe-import-descriptors-log", RichLog)
        log.clear()
        log.write(
            f"[bold cyan]IMAGE_IMPORT_DESCRIPTOR records — page "
            f"{page + 1}/{total}[/bold cyan]\n"
            "[dim]Each descriptor is 20 bytes. Values are RVAs unless marked "
            "as a file offset.[/dim]"
        )
        for descriptor in selected:
            if descriptor.is_zero_terminator:
                log.write(
                    f"\n[bold green][{descriptor.index}] All-zero terminator[/bold green] "
                    f"[dim]at file offset 0x{descriptor.file_offset:08x}[/dim]"
                )
            else:
                log.write(
                    f"\n[bold cyan][{descriptor.index}] "
                    f"{_safe(descriptor.dll, 512)}[/bold cyan] "
                    f"[dim]at file offset 0x{descriptor.file_offset:08x}[/dim]"
                )
            log.write(
                "OriginalFirstThunk (INT)  "
                f"0x{descriptor.original_first_thunk:08x}"
            )
            log.write(f"TimeDateStamp              0x{descriptor.time_date_stamp:08x}")
            log.write(f"ForwarderChain             0x{descriptor.forwarder_chain:08x}")
            log.write(f"Name                       0x{descriptor.name_rva:08x}")
            log.write(f"FirstThunk (IAT)           0x{descriptor.first_thunk:08x}")
        if not records:
            log.write("[dim]No standard import descriptors were reported.[/dim]")
        elif not any(item.is_zero_terminator for item in records):
            log.write(
                "\n[yellow]No all-zero terminator was confirmed within the analyzed "
                "descriptor evidence.[/yellow]"
            )
        if self.structure.import_descriptors_truncated:
            log.write(
                f"[yellow]Display model limited to {len(records):,} descriptors by "
                "MAX_IMPORT_DESCRIPTORS.[/yellow]"
            )
        self._append_delay_import_descriptors(log, delay_records, page)

    def _append_delay_import_descriptors(self, log, records, page: int) -> None:
        start = page * self.RECORD_PAGE_SIZE
        selected = records[start:start + self.RECORD_PAGE_SIZE]
        total = page_count(max(len(self.structure.import_descriptors), len(records)), self.RECORD_PAGE_SIZE)
        log.write(
            f"\n[bold cyan]IMAGE_DELAYLOAD_DESCRIPTOR records — page "
            f"{page + 1}/{total}[/bold cyan]\n"
            "[dim]Each descriptor is 32 bytes. Attribute bit 0 selects RVA "
            "rather than legacy VA fields.[/dim]"
        )
        for descriptor in selected:
            if descriptor.is_zero_terminator:
                log.write(
                    f"\n[bold green][{descriptor.index}] All-zero terminator[/bold green] "
                    f"[dim]at file offset 0x{descriptor.file_offset:08x}[/dim]"
                )
            else:
                log.write(
                    f"\n[bold cyan][{descriptor.index}] "
                    f"{_safe(descriptor.dll, 512)}[/bold cyan] "
                    f"[dim]at file offset 0x{descriptor.file_offset:08x}[/dim]"
                )
            if descriptor.is_zero_terminator:
                address_kind = "terminator (all fields zero)"
            else:
                address_kind = (
                    "RVAs (dlattrRva set)" if descriptor.uses_rvas else "legacy VAs"
                )
            log.write(
                f"Attributes / grAttrs         0x{descriptor.attributes:08x} "
                f"[cyan]{address_kind}[/cyan]"
            )
            reserved_attributes = descriptor.attributes & ~1
            if reserved_attributes:
                log.write(
                    "                              [yellow]↳ reserved attribute "
                    f"bits set: 0x{reserved_attributes:x}[/yellow]"
                )
            log.write(f"DllName / szName            0x{descriptor.dll_name:08x}")
            log.write(f"ModuleHandle / phmod        0x{descriptor.module_handle:08x}")
            log.write(
                "ImportAddressTable / pIAT    "
                f"0x{descriptor.import_address_table:08x}"
            )
            log.write(
                "ImportNameTable / pINT       "
                f"0x{descriptor.import_name_table:08x}"
            )
            log.write(
                "BoundImportAddress / pBoundIAT "
                f"0x{descriptor.bound_import_address_table:08x}"
            )
            log.write(
                "UnloadInformation / pUnloadIAT "
                f"0x{descriptor.unload_information_table:08x}"
            )
            log.write(f"TimeDateStamp / dwTimeStamp 0x{descriptor.time_date_stamp:08x}")
        if not records:
            log.write("[dim]No delay-import descriptors were reported.[/dim]")
        elif not any(item.is_zero_terminator for item in records):
            log.write(
                "\n[yellow]No all-zero delay descriptor was confirmed within the "
                "analyzed evidence.[/yellow]"
            )
        if self.structure.delay_import_descriptors_truncated:
            log.write(
                f"[yellow]Display model limited to {len(records):,} delay "
                "descriptors by MAX_DELAY_IMPORT_DESCRIPTORS.[/yellow]"
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
        if tab == "pe-import-descriptors":
            return page_count(
                max(
                    len(self.structure.import_descriptors),
                    len(self.structure.delay_import_descriptors),
                ),
                self.RECORD_PAGE_SIZE,
            )
        if tab == "pe-imports":
            return page_count(len(self.structure.imports), self.RECORD_PAGE_SIZE)
        if tab == "pe-exports":
            return page_count(len(self.structure.exports), self.RECORD_PAGE_SIZE)
        return 1

    def _render_active_page(self, tab: str) -> None:
        if tab == "pe-hex":
            self._render_hex()
        elif tab == "pe-import-descriptors":
            self._render_import_descriptors()
        elif tab == "pe-imports":
            self._render_imports()
        elif tab == "pe-exports":
            self._render_exports()
        self._update_status()

    def _update_status(self) -> None:
        tab = self._active_paged_tab()
        if tab is None:
            message = (
                "Read-only PE evidence view. In Resources: Enter opens; D downloads "
                "the selected file."
            )
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

    def action_export_resource(self) -> None:
        if self.query_one("#pe-tabs", TabbedContent).active != "pe-directories":
            self.query_one("#pe-status", Static).update(
                Text("Open the Resources tab and select a resource file first.")
            )
            return
        node = self.query_one("#pe-resource-tree", Tree).cursor_node
        record = node.data if node is not None else None
        if not isinstance(record, PEResourceDataRecord):
            self.query_one("#pe-status", Static).update(
                Text("Select a resource file—not a folder—then press D.")
            )
            return
        try:
            destination = export_resource(self.structure, record)
        except FileExistsError:
            self.query_one("#pe-status", Static).update(
                Text("Export refused: the destination already exists and was not overwritten.")
            )
        except (OSError, ValueError) as exc:
            self.query_one("#pe-status", Static).update(
                Text(f"Resource export failed: {exc}")
            )
        else:
            self.query_one("#pe-status", Static).update(
                Text(f"Resource downloaded to {destination.resolve()}")
            )

    def action_close(self) -> None:
        self.app.pop_screen()
