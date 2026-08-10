"""Full-screen Portable Executable structure and hexadecimal workspace."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, RichLog, Static, TabbedContent, TabPane, Tree

from analysis.pe_structure import (
    PEASLRAssessment,
    PEAuthenticode,
    PEBaseRelocationBlock,
    PECFGEvidence,
    PECFGTarget,
    PEDebugDirectory,
    PEDebugRecord,
    PEDotNetAssemblyReference,
    PEDotNetHeader,
    PEDotNetStream,
    PEExceptionDirectory,
    PELoadConfiguration,
    PEOverlay,
    PEResourceDataRecord,
    PEResourceDirectoryRecord,
    PERichHeader,
    PERuntimeFunction,
    PEStructure,
    PETLSCallback,
    PETLSDirectory,
    PEWinCertificate,
    page_count,
    render_hex_page,
)


@dataclass(frozen=True)
class PEExceptionPage:
    start: int
    end: int
    functions: tuple[PERuntimeFunction, ...]


@dataclass(frozen=True)
class PECFGTargetPage:
    start: int
    end: int
    targets: tuple[PECFGTarget, ...]


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


def certificate_filename(record: PEWinCertificate) -> str:
    """Build a stable filename for an embedded WIN_CERTIFICATE payload."""
    extension = {
        0x0001: ".cer",
        0x0002: ".p7b",
    }.get(record.certificate_type, ".bin")
    identity = (record.content_sha256 or f"offset-{record.file_offset:08x}")[:16]
    return f"win-certificate-{record.index:03d}-{identity}{extension}"


def certificate_payload(
    structure: PEStructure,
    record: PEWinCertificate,
) -> bytes | None:
    """Return exact bCertificate bytes only when the entry is complete."""
    if not record.complete:
        return None
    start = record.content_file_offset
    end = start + record.content_size
    if start < 0 or end < start or end > len(structure.raw_data):
        return None
    return structure.raw_data[start:end]


def export_certificate(
    structure: PEStructure,
    record: PEWinCertificate,
    export_root: Path | None = None,
) -> Path:
    """Export one embedded certificate blob without overwrite or symlink following."""
    payload = certificate_payload(structure, record)
    if payload is None:
        raise ValueError("The certificate payload is incomplete or outside the file")
    root = export_root or Path.cwd() / "aidebug-certificate-exports"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise OSError("Certificate export root is not a safe directory")
    sample_directory = root / structure.sha256[:16]
    sample_directory.mkdir(mode=0o700, exist_ok=True)
    if sample_directory.is_symlink() or not sample_directory.is_dir():
        raise OSError("Sample export path is not a safe directory")
    destination = sample_directory / certificate_filename(record)
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


def debug_payload(structure: PEStructure, record: PEDebugRecord) -> bytes | None:
    """Return exact debug data only when its declared range is complete."""
    if not record.complete or record.data_file_offset is None:
        return None
    start = record.data_file_offset
    end = start + record.size_of_data
    if start < 0 or end < start or end > len(structure.raw_data):
        return None
    return structure.raw_data[start:end]


def overlay_payload(structure: PEStructure, record: PEOverlay) -> bytes | None:
    """Return the exact overlay bytes represented by the evidence model."""
    start = record.file_offset
    end = start + record.size
    if start < 0 or end < start or end > len(structure.raw_data):
        return None
    return structure.raw_data[start:end]


def dotnet_stream_payload(
    structure: PEStructure,
    record: PEDotNetStream,
) -> bytes | None:
    """Return exact managed metadata stream bytes only when complete."""
    if not record.complete or record.file_offset is None:
        return None
    start = record.file_offset
    end = start + record.size
    if start < 0 or end < start or end > len(structure.raw_data):
        return None
    return structure.raw_data[start:end]


def _export_evidence_payload(
    structure: PEStructure,
    payload: bytes | None,
    filename: str,
    directory_name: str,
    export_root: Path | None,
) -> Path:
    if payload is None:
        raise ValueError("The evidence payload is incomplete or outside the file")
    root = export_root or Path.cwd() / directory_name
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise OSError("Evidence export root is not a safe directory")
    sample_directory = root / structure.sha256[:16]
    sample_directory.mkdir(mode=0o700, exist_ok=True)
    if sample_directory.is_symlink() or not sample_directory.is_dir():
        raise OSError("Sample export path is not a safe directory")
    destination = sample_directory / filename
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


def export_debug_payload(
    structure: PEStructure,
    record: PEDebugRecord,
    export_root: Path | None = None,
) -> Path:
    identity = (record.data_sha256 or f"offset-{record.file_offset:08x}")[:16]
    filename = f"debug-{record.index:03d}-{record.type_name.lower()}-{identity}.bin"
    return _export_evidence_payload(
        structure,
        debug_payload(structure, record),
        filename,
        "aidebug-debug-exports",
        export_root,
    )


def export_overlay(
    structure: PEStructure,
    record: PEOverlay,
    export_root: Path | None = None,
) -> Path:
    return _export_evidence_payload(
        structure,
        overlay_payload(structure, record),
        f"overlay-{record.sha256[:16]}.bin",
        "aidebug-overlay-exports",
        export_root,
    )


def export_dotnet_stream(
    structure: PEStructure,
    record: PEDotNetStream,
    export_root: Path | None = None,
) -> Path:
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", record.name).strip("._-")
    identity = (record.sha256 or f"offset-{record.metadata_offset:08x}")[:16]
    return _export_evidence_payload(
        structure,
        dotnet_stream_payload(structure, record),
        f"dotnet-stream-{record.index:02d}-{name or 'unnamed'}-{identity}.bin",
        "aidebug-dotnet-exports",
        export_root,
    )


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


class CertificatePayloadScreen(Screen):
    """Open an embedded certificate blob in a bounded read-only hex viewer."""

    TITLE = "AIDebug — Authenticode certificate payload"
    PAGE_SIZE = 4096

    BINDINGS = ResourcePayloadScreen.BINDINGS

    def __init__(self, structure: PEStructure, record: PEWinCertificate):
        super().__init__()
        self.structure = structure
        self.record = record
        self.payload = certificate_payload(structure, record) or b""
        self.page = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(
            Text(
                f" {certificate_filename(self.record)}  |  "
                f"{len(self.payload):,} bytes  |  "
                f"SHA-256 {self.record.content_sha256 or 'unavailable'}"
            ),
            id="certificate-summary",
        )
        yield RichLog(id="certificate-payload-log", classes="pe-log", wrap=False)
        yield Static("Read-only certificate evidence view.", id="certificate-status")
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
        log = self.query_one("#certificate-payload-log", RichLog)
        log.clear()
        log.write(
            Text(
                f"bCertificate payload — page {selected + 1}/{total}, "
                f"offsets 0x{start:x}–0x{max(start, end - 1):x}\n"
                "OFFSET    00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  ASCII\n"
                f"{rendered}"
            )
        )
        self.query_one("#certificate-status", Static).update(
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


class EvidencePayloadScreen(Screen):
    """Open Debug Directory or overlay bytes in a bounded read-only viewer."""

    TITLE = "AIDebug — PE evidence payload"
    PAGE_SIZE = 4096
    BINDINGS = ResourcePayloadScreen.BINDINGS

    def __init__(self, label: str, payload: bytes, sha256: str, base_offset: int):
        super().__init__()
        self.label = label
        self.payload = payload
        self.sha256 = sha256
        self.base_offset = base_offset
        self.page = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(
            Text(
                f" {self.label}  |  {len(self.payload):,} bytes  |  "
                f"file offset 0x{self.base_offset:x}  |  SHA-256 {self.sha256}"
            ),
            id="evidence-summary",
        )
        yield RichLog(id="evidence-payload-log", classes="pe-log", wrap=False)
        yield Static("Read-only PE evidence view.", id="evidence-status")
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
        log = self.query_one("#evidence-payload-log", RichLog)
        log.clear()
        log.write(
            Text(
                f"{self.label} — page {selected + 1}/{total}, payload offsets "
                f"0x{start:x}–0x{max(start, end - 1):x}, file offsets "
                f"0x{self.base_offset + start:x}–"
                f"0x{self.base_offset + max(start, end - 1):x}\n"
                "OFFSET    00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  ASCII\n"
                f"{rendered}"
            )
        )
        self.query_one("#evidence-status", Static).update(
            Text(
                f"Page {selected + 1}/{total} — PageUp/PageDown navigate; "
                "the bytes are never executed."
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
        Binding("d", "export_resource", "Download payload", show=True),
    ]

    def __init__(self, structure: PEStructure):
        super().__init__()
        self.structure = structure
        self._pages = {
            "pe-hex": 0,
            "pe-base-relocations": 0,
            "pe-import-descriptors": 0,
            "pe-imports": 0,
            "pe-exports": 0,
        }
        self._resource_nodes = {}
        self._relocation_nodes = {}
        self._relocation_root = None
        self._tls_root = None
        self._tls_callback_nodes = {}
        self._exception_root = None
        self._exception_page_nodes = {}
        self._exception_function_nodes = {}
        self._load_config_root = None
        self._cfg_root = None
        self._cfg_page_nodes = {}
        self._authenticode_root = None
        self._certificate_nodes = {}
        self._rich_header_root = None
        self._debug_root = None
        self._debug_nodes = {}
        self._overlay_root = None
        self._dotnet_root = None
        self._dotnet_stream_nodes = {}
        self._dotnet_reference_nodes = {}
        self._selected_relocation_block = None

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
                    with Horizontal(id="pe-resource-workspace"):
                        yield Tree("PE data directories", id="pe-resource-tree")
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
        log.write(f"Relocation blocks {len(pe.base_relocations)}")
        log.write(f"TLS callbacks     {len(pe.tls.callbacks) if pe.tls else 0}")
        log.write(
            f"Runtime functions {len(pe.exceptions.functions) if pe.exceptions else 0}"
        )
        log.write(
            f"Load-config fields {len(pe.load_configuration.fields) if pe.load_configuration else 0}"
        )
        log.write(
            "CFG targets       "
            f"{len(pe.load_configuration.cfg.targets) if pe.load_configuration and pe.load_configuration.cfg else 0}"
        )
        log.write(
            "WIN_CERTIFICATEs  "
            f"{len(pe.authenticode.entries) if pe.authenticode else 0}"
        )
        log.write(
            "Rich entries      "
            f"{len(pe.rich_header.entries) if pe.rich_header else 0}"
        )
        log.write(
            "Debug records     "
            f"{len(pe.debug_directory.records) if pe.debug_directory else 0}"
        )
        log.write(
            ".NET metadata     "
            f"{'present' if pe.dotnet else 'not detected'}"
        )
        if pe.dotnet is not None:
            identity = pe.dotnet.assembly.name if pe.dotnet.assembly else pe.dotnet.module_name
            log.write(f"Managed identity  {_safe(identity)}")
            log.write(f"Metadata streams  {len(pe.dotnet.streams)}")
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
            if pe.overlay is not None:
                log.write(f"Overlay SHA-256   {pe.overlay.sha256}")
                log.write(f"Overlay entropy  {pe.overlay.entropy:.3f}")
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
        tree.root.set_label("PE data directories")
        tree.root.expand()
        resource_root = tree.root.add("Resources", expand=True)
        self._resource_nodes = {("<root>",): resource_root}
        for record in self.structure.resources:
            if isinstance(record, PEResourceDirectoryRecord):
                if record.path == ("<root>",):
                    resource_root.data = record
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
            resource_root.add("No resource hierarchy reported", allow_expand=False)
        relocation_root = tree.root.add(
            "Base relocations & ASLR",
            data=self.structure.aslr,
            expand=True,
        )
        self._relocation_root = relocation_root
        self._relocation_nodes = {}
        for block in self.structure.base_relocations:
            self._relocation_nodes[block.index] = relocation_root.add(
                f"Block {block.index}: page RVA 0x{block.virtual_address:08x} "
                f"({len(block.entries):,} entries)",
                data=block,
                allow_expand=False,
            )
        if not self.structure.base_relocations:
            relocation_root.add("No parsed relocation blocks", allow_expand=False)
        self._tls_root = tree.root.add(
            "TLS data & callbacks",
            data=self.structure.tls,
            expand=True,
        )
        self._tls_callback_nodes = {}
        if self.structure.tls is None:
            self._tls_root.add("No TLS directory reported", allow_expand=False)
        elif not self.structure.tls.callbacks:
            self._tls_root.add("No TLS callbacks reported", allow_expand=False)
        else:
            for callback in self.structure.tls.callbacks:
                self._tls_callback_nodes[callback.index] = self._tls_root.add(
                    f"Callback {callback.index}: VA 0x{callback.address:016x}",
                    data=callback,
                    allow_expand=False,
                )
        self._exception_root = tree.root.add(
            "Exceptions & unwind",
            data=self.structure.exceptions,
            expand=True,
        )
        self._exception_page_nodes = {}
        self._exception_function_nodes = {}
        if self.structure.exceptions is None:
            self._exception_root.add(
                "No Exception Directory reported",
                allow_expand=False,
            )
        elif not self.structure.exceptions.functions:
            self._exception_root.add(
                "No runtime-function records parsed",
                allow_expand=False,
            )
        else:
            functions = self.structure.exceptions.functions
            for start in range(0, len(functions), self.RECORD_PAGE_SIZE):
                selected = functions[start:start + self.RECORD_PAGE_SIZE]
                end = start + len(selected) - 1
                page = PEExceptionPage(start, end, selected)
                self._exception_page_nodes[start] = self._exception_root.add(
                    f"Runtime functions {start}–{end}",
                    data=page,
                    allow_expand=True,
                )
        self._load_config_root = tree.root.add(
            "Load configuration & mitigations",
            data=self.structure.load_configuration,
            expand=True,
        )
        self._cfg_page_nodes = {}
        cfg = (
            self.structure.load_configuration.cfg
            if self.structure.load_configuration is not None
            else None
        )
        self._cfg_root = self._load_config_root.add(
            "CFG evidence",
            data=cfg,
            expand=True,
        )
        if cfg is None:
            self._cfg_root.add("No CFG evidence model", allow_expand=False)
        elif not cfg.targets:
            self._cfg_root.add("No GFIDS targets parsed", allow_expand=False)
        else:
            for start in range(0, len(cfg.targets), self.RECORD_PAGE_SIZE):
                selected = cfg.targets[start:start + self.RECORD_PAGE_SIZE]
                end = start + len(selected) - 1
                page = PECFGTargetPage(start, end, selected)
                self._cfg_page_nodes[start] = self._cfg_root.add(
                    f"GFIDS targets {start}–{end}",
                    data=page,
                    allow_expand=False,
                )
        self._authenticode_root = tree.root.add(
            "Authenticode certificates & signatures",
            data=self.structure.authenticode,
            expand=True,
        )
        self._certificate_nodes = {}
        if self.structure.authenticode is None:
            self._authenticode_root.add(
                "No embedded Certificate Table",
                allow_expand=False,
            )
        elif not self.structure.authenticode.entries:
            self._authenticode_root.add(
                "No WIN_CERTIFICATE entries parsed",
                allow_expand=False,
            )
        else:
            for entry in self.structure.authenticode.entries:
                self._certificate_nodes[entry.index] = self._authenticode_root.add(
                    f"WIN_CERTIFICATE {entry.index}: "
                    f"{entry.certificate_type_name} ({entry.content_size:,} bytes)",
                    data=entry,
                    allow_expand=False,
                )
        self._dotnet_root = tree.root.add(
            ".NET / CLR assembly",
            data=self.structure.dotnet,
            expand=True,
        )
        self._dotnet_stream_nodes = {}
        self._dotnet_reference_nodes = {}
        if self.structure.dotnet is None:
            self._dotnet_root.add("No COM Descriptor / CLR header", allow_expand=False)
        else:
            streams_root = self._dotnet_root.add("Metadata streams", expand=True)
            if not self.structure.dotnet.streams:
                streams_root.add("No metadata streams parsed", allow_expand=False)
            for stream in self.structure.dotnet.streams:
                self._dotnet_stream_nodes[stream.index] = streams_root.add(
                    f"{stream.name or '<unnamed>'} ({stream.size:,} bytes)",
                    data=stream,
                    allow_expand=False,
                )
            references_root = self._dotnet_root.add("Assembly references", expand=True)
            if not self.structure.dotnet.assembly_references:
                references_root.add("No AssemblyRef rows parsed", allow_expand=False)
            for reference in self.structure.dotnet.assembly_references:
                self._dotnet_reference_nodes[reference.index] = references_root.add(
                    f"{reference.name}, Version={reference.version}",
                    data=reference,
                    allow_expand=False,
                )
        self._rich_header_root = tree.root.add(
            "Rich header",
            data=self.structure.rich_header,
            expand=True,
        )
        if self.structure.rich_header is None:
            self._rich_header_root.add("No decoded Rich header", allow_expand=False)
        self._debug_root = tree.root.add(
            "Debug data & CodeView",
            data=self.structure.debug_directory,
            expand=True,
        )
        self._debug_nodes = {}
        if self.structure.debug_directory is None:
            self._debug_root.add("No Debug Directory reported", allow_expand=False)
        elif not self.structure.debug_directory.records:
            self._debug_root.add("No debug records parsed", allow_expand=False)
        else:
            for debug_record in self.structure.debug_directory.records:
                detail = (
                    f" — {_safe(debug_record.pdb_path, 80)}"
                    if debug_record.pdb_path
                    else ""
                )
                self._debug_nodes[debug_record.index] = self._debug_root.add(
                    f"Record {debug_record.index}: {debug_record.type_name} "
                    f"({debug_record.size_of_data:,} bytes){detail}",
                    data=debug_record,
                    allow_expand=False,
                )
        self._overlay_root = tree.root.add(
            "Overlay",
            data=self.structure.overlay,
            expand=True,
        )
        if self.structure.overlay is None:
            self._overlay_root.add("No overlay bytes reported", allow_expand=False)

    def _render_resource_record(
        self,
        record: (
            PEResourceDirectoryRecord
            | PEResourceDataRecord
            | PEBaseRelocationBlock
            | PEASLRAssessment
            | PETLSDirectory
            | PETLSCallback
            | PEExceptionDirectory
            | PEExceptionPage
            | PERuntimeFunction
            | PELoadConfiguration
            | PECFGEvidence
            | PECFGTargetPage
            | PEAuthenticode
            | PEWinCertificate
            | PERichHeader
            | PEDebugDirectory
            | PEDebugRecord
            | PEOverlay
            | PEDotNetHeader
            | PEDotNetStream
            | PEDotNetAssemblyReference
            | None
        ),
    ) -> None:
        log = self.query_one("#pe-directories-log", RichLog)
        log.clear()
        log.write("[bold cyan]Optional-header data directories[/bold cyan]")
        log.write("Index  Directory             Address    Size       Interpretation")
        for directory in self.structure.data_directories:
            interpretation = "file offset" if directory.index == 4 else "RVA"
            log.write(
                f"{directory.index:>5}  {_safe(directory.name, 64):<20} "
                f"0x{directory.rva:08x} 0x{directory.size:08x}  {interpretation}"
            )
        if not self.structure.data_directories:
            log.write("[dim]No data directories were reported.[/dim]")
        log.write(
            "\n[bold cyan]PE data-directory explorer[/bold cyan]\n"
            "[dim]Resources use type → name/ID → language → data file. "
            "Select a file and press Enter to open it safely inside AIDebug; "
            "press D to download/export the exact bytes. Certificate, debug, "
            "and overlay payloads support the same safe workflow. Select a "
            "relocation block, TLS record, runtime function, or security record "
            "to inspect it.[/dim]"
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
                    f"\n{data_count:,} resource files and "
                    f"{len(self.structure.base_relocations):,} relocation blocks "
                    f"and {len(self.structure.tls.callbacks) if self.structure.tls else 0:,} "
                    "TLS callbacks and "
                    f"{len(self.structure.exceptions.functions) if self.structure.exceptions else 0:,} "
                    "runtime functions found. Use the explorer on the left to inspect one."
                )
            if self.structure.aslr is not None:
                log.write(f"\n[bold cyan]ASLR[/bold cyan]  {self.structure.aslr.status}")
        elif isinstance(record, PEASLRAssessment):
            log.write(f"\n[bold cyan]ASLR assessment[/bold cyan]\n{_safe(record.status)}")
            log.write(f"DYNAMIC_BASE             {'set' if record.dynamic_base else 'not set'}")
            log.write(
                f"HIGH_ENTROPY_VA           {'set' if record.high_entropy_va else 'not set'}"
            )
            log.write(
                f"RELOCS_STRIPPED           {'set' if record.relocations_stripped else 'not set'}"
            )
            log.write(f"Relocation directory RVA 0x{record.directory_rva:08x}")
            log.write(f"Relocation directory size 0x{record.directory_size:08x}")
            log.write(f"Parsed blocks            {record.parsed_blocks:,}")
            log.write(f"Parsed entries           {record.parsed_entries:,}")
            log.write(f"Usable entries           {record.usable_entries:,}")
            log.write("\n[bold cyan]Assessment clues[/bold cyan]")
            for clue in record.clues:
                log.write(f"[cyan]• {_safe(clue, 512)}[/cyan]")
        elif isinstance(record, PEBaseRelocationBlock):
            page = self._bounded_record_page(
                "pe-base-relocations",
                len(record.entries),
            )
            start = page * self.RECORD_PAGE_SIZE
            selected = record.entries[start:start + self.RECORD_PAGE_SIZE]
            total = page_count(len(record.entries), self.RECORD_PAGE_SIZE)
            log.write(
                f"\n[bold cyan]IMAGE_BASE_RELOCATION block {record.index} — "
                f"page {page + 1}/{total}[/bold cyan]"
            )
            log.write(f"Header file offset       0x{record.file_offset:08x}")
            log.write(f"VirtualAddress (page RVA) 0x{record.virtual_address:08x}")
            log.write(f"SizeOfBlock              0x{record.size_of_block:08x}")
            log.write(f"Entries                  {len(record.entries):,}")
            log.write(
                "\nIndex  File offset  Type  Offset  Target RVA  Target VA          Type name"
            )
            for entry in selected:
                log.write(
                    f"{entry.index:>5}  0x{entry.file_offset:08x}  "
                    f"{entry.type:>4}  0x{entry.offset:03x}  "
                    f"0x{entry.rva:08x} 0x{entry.address:016x}  "
                    f"{_safe(entry.type_name, 96)}"
                )
        elif isinstance(record, PETLSDirectory):
            structure_name = (
                "IMAGE_TLS_DIRECTORY64"
                if record.is_pe32_plus
                else "IMAGE_TLS_DIRECTORY32"
            )
            log.write(f"\n[bold cyan]{structure_name}[/bold cyan]")
            log.write(
                "[bold yellow]TLS callbacks may execute before the image entry "
                "point.[/bold yellow]"
            )
            log.write(f"Directory file offset    0x{record.file_offset:08x}")
            log.write(
                f"StartAddressOfRawData    0x{record.start_address_of_raw_data:016x}"
            )
            log.write(
                f"EndAddressOfRawData      0x{record.end_address_of_raw_data:016x}"
            )
            log.write(f"TLS template RVA         {_number(record.raw_data_rva)}")
            log.write(f"TLS template file offset {_number(record.raw_data_file_offset)}")
            log.write(
                f"TLS template size        0x{record.raw_data_size:x} "
                f"({record.raw_data_size:,})"
            )
            if record.raw_data_complete:
                log.write(f"TLS template SHA-256     {_safe(record.raw_data_sha256)}")
            elif record.raw_data_size:
                log.write(
                    "[yellow]TLS template range       incomplete: "
                    f"{record.raw_data_available_size:,}/{record.raw_data_size:,} "
                    "bytes available[/yellow]"
                )
            if record.raw_data_preview:
                preview_hex = " ".join(
                    f"{byte:02x}" for byte in record.raw_data_preview
                )
                preview_ascii = "".join(
                    chr(byte) if 32 <= byte <= 126 else "."
                    for byte in record.raw_data_preview
                )
                log.write(f"TLS template preview hex {preview_hex}")
                log.write(f"TLS template preview text {_safe(preview_ascii)}")
            log.write(f"AddressOfIndex           0x{record.address_of_index:016x}")
            log.write(f"Index RVA                {_number(record.index_rva)}")
            log.write(f"Index file offset        {_number(record.index_file_offset)}")
            log.write(f"AddressOfCallBacks       0x{record.address_of_callbacks:016x}")
            log.write(f"Callback-table RVA       {_number(record.callbacks_rva)}")
            log.write(
                f"Callback-table file offset {_number(record.callbacks_file_offset)}"
            )
            log.write(f"SizeOfZeroFill           0x{record.size_of_zero_fill:x}")
            log.write(f"Characteristics          0x{record.characteristics:08x}")
            log.write(f"Callbacks                {len(record.callbacks):,}")
            terminator = (
                "confirmed null pointer"
                if record.callbacks_terminated
                else "not confirmed or table absent"
            )
            log.write(f"Callback-table terminator {terminator}")
            for warning in record.warnings:
                log.write(f"[yellow]Warning                  {_safe(warning)}[/yellow]")
        elif isinstance(record, PETLSCallback):
            log.write(f"\n[bold cyan]TLS callback {record.index}[/bold cyan]")
            log.write(
                "[bold yellow]This function may execute before the normal PE "
                "entry point.[/bold yellow]"
            )
            log.write(
                f"Pointer entry file offset 0x{record.table_entry_file_offset:08x}"
            )
            log.write(f"Callback VA              0x{record.address:016x}")
            log.write(f"Callback RVA             {_number(record.rva)}")
            log.write(f"Callback file offset     {_number(record.file_offset)}")
        elif isinstance(record, PEExceptionDirectory):
            log.write("\n[bold cyan]Exception Directory / .pdata[/bold cyan]")
            log.write(f"Machine                  0x{record.machine:04x}")
            log.write(f"x64 UNWIND_INFO decoding {'enabled' if record.is_x64 else 'not applicable'}")
            log.write(f"Runtime functions        {len(record.functions):,}")
            log.write(
                "[dim]Runtime-function entries describe function ranges and the "
                "metadata used for stack unwinding and exception dispatch. Expand "
                "a numbered folder to inspect individual functions.[/dim]"
            )
            for warning in record.warnings:
                log.write(f"[yellow]Warning                  {_safe(warning)}[/yellow]")
        elif isinstance(record, PEExceptionPage):
            log.write(
                f"\n[bold cyan]RUNTIME_FUNCTION records {record.start}–"
                f"{record.end}[/bold cyan]"
            )
            log.write(
                "Index  File offset  Begin RVA  End RVA    Unwind RVA  Function VA range"
            )
            for function in record.functions:
                file_offset = (
                    f"0x{function.file_offset:08x}"
                    if function.file_offset >= 0
                    else "unmapped".rjust(10)
                )
                log.write(
                    f"{function.index:>5}  {file_offset}  "
                    f"0x{function.begin_address:08x} 0x{function.end_address:08x} "
                    f"0x{function.unwind_data:08x}  "
                    f"0x{function.begin_va:016x}–0x{function.end_va:016x}"
                )
        elif isinstance(record, PERuntimeFunction):
            log.write(f"\n[bold cyan]RUNTIME_FUNCTION {record.index}[/bold cyan]")
            if record.file_offset >= 0:
                log.write(f"Record file offset       0x{record.file_offset:08x}")
            else:
                log.write("Record file offset       [yellow]unavailable[/yellow]")
            log.write(f"BeginAddress (RVA)       0x{record.begin_address:08x}")
            log.write(f"EndAddress (RVA)         0x{record.end_address:08x}")
            log.write(f"Function start VA        0x{record.begin_va:016x}")
            log.write(f"Function end VA          0x{record.end_va:016x}")
            log.write(f"UnwindData (RVA)         0x{record.unwind_data:08x}")
            unwind = record.unwind_info
            if unwind is None:
                log.write("[yellow]UNWIND_INFO could not be decoded.[/yellow]")
            else:
                log.write("\n[bold cyan]UNWIND_INFO[/bold cyan]")
                log.write(f"RVA                      0x{unwind.rva:08x}")
                log.write(f"File offset              0x{unwind.file_offset:08x}")
                log.write(f"Version                  {unwind.version}")
                log.write(f"Flags                    0x{unwind.flags:02x}")
                for flag_name in unwind.flag_names:
                    log.write(f"                         [green]↳ {_safe(flag_name)}[/green]")
                log.write(f"SizeOfProlog             {unwind.size_of_prolog}")
                log.write(f"CountOfCodes             {unwind.count_of_codes}")
                log.write(
                    f"FrameRegister            {unwind.frame_register} "
                    f"({_safe(unwind.frame_register_name)})"
                )
                log.write(f"FrameOffset              {unwind.frame_offset}")
                log.write("\nSlot  CodeOff  Op  Info  Slots  Operation")
                for code in unwind.codes:
                    log.write(
                        f"{code.slot_index:>4}  0x{code.code_offset:02x}    "
                        f"{code.unwind_op:>2}  {code.op_info:>4}  "
                        f"{code.slots_used:>5}  {_safe(code.op_name, 64)} — "
                        f"{_safe(code.description, 160)}"
                    )
                if not unwind.codes:
                    log.write("[dim]No unwind operations.[/dim]")
                if unwind.exception_handler_rva is not None:
                    log.write(
                        "Exception handler RVA    "
                        f"0x{unwind.exception_handler_rva:08x}"
                    )
                    log.write(
                        "Handler file offset      "
                        f"{_number(unwind.exception_handler_file_offset)}"
                    )
                    log.write(
                        "Language data file offset "
                        f"{_number(unwind.language_data_file_offset)}"
                    )
                if unwind.chained_function is not None:
                    chained_begin, chained_end, chained_unwind = unwind.chained_function
                    log.write("[bold cyan]Chained RUNTIME_FUNCTION[/bold cyan]")
                    log.write(f"  BeginAddress           0x{chained_begin:08x}")
                    log.write(f"  EndAddress             0x{chained_end:08x}")
                    log.write(f"  UnwindData             0x{chained_unwind:08x}")
                for warning in unwind.warnings:
                    log.write(f"[yellow]Warning                  {_safe(warning)}[/yellow]")
        elif isinstance(record, PECFGEvidence):
            log.write("\n[bold cyan]Control Flow Guard evidence[/bold cyan]")
            log.write(
                "[dim]CFG is supported by a chain of independent metadata. A "
                "header bit alone is not proof that the image contains coherent "
                "instrumentation and valid-target metadata.[/dim]"
            )
            log.write(
                f"Optional Header GUARD_CF      "
                f"{'set' if record.header_guard_cf else 'not set'}"
            )
            log.write(
                f"CF_INSTRUMENTED               "
                f"{'set' if record.instrumented else 'not set'}"
            )
            log.write(
                f"CFW_INSTRUMENTED              "
                f"{'set' if record.write_integrity_instrumented else 'not set'}"
            )
            log.write(
                f"CF_FUNCTION_TABLE_PRESENT     "
                f"{'set' if record.function_table_present else 'not set'}"
            )
            log.write("\n[bold cyan]Loader pointer slots[/bold cyan]")
            log.write(
                f"GuardCFCheckFunctionPointer    "
                f"{_number(record.check_function_pointer)}"
            )
            log.write(
                f"  RVA / file offset           "
                f"{_number(record.check_function_rva)} / "
                f"{_number(record.check_function_file_offset)}"
            )
            log.write(
                f"GuardCFDispatchFunctionPointer "
                f"{_number(record.dispatch_function_pointer)}"
            )
            log.write(
                f"  RVA / file offset           "
                f"{_number(record.dispatch_function_rva)} / "
                f"{_number(record.dispatch_function_file_offset)}"
            )
            log.write("\n[bold cyan]Guard Function ID table (GFIDS)[/bold cyan]")
            log.write(f"Table VA                     {_number(record.function_table)}")
            log.write(f"Table RVA                    {_number(record.function_table_rva)}")
            log.write(
                f"Table file offset            "
                f"{_number(record.function_table_file_offset)}"
            )
            log.write(f"Declared targets             {record.function_count:,}")
            log.write(f"Parsed targets               {len(record.targets):,}")
            log.write(f"Entry stride                 {record.entry_stride} bytes")
            log.write(
                f"Strictly sorted and unique   "
                f"{'yes' if record.targets_sorted else 'NO'}"
            )
            log.write(
                f"Complete table               "
                f"{'yes' if record.table_complete else 'NO'}"
            )
            suppressed = sum(
                "IMAGE_GUARD_FLAG_FID_SUPPRESSED" in target.flag_names
                for target in record.targets
            )
            export_suppressed = sum(
                "IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED" in target.flag_names
                for target in record.targets
            )
            log.write(f"Explicitly suppressed        {suppressed:,}")
            log.write(f"Export suppressed            {export_suppressed:,}")
            if record.targets:
                log.write(
                    "[dim]Select a GFIDS target range beneath this node to see "
                    "every parsed target RVA, mapped file offset, and metadata.[/dim]"
                )
            for warning in record.warnings:
                log.write(f"[yellow]Warning                      {_safe(warning)}[/yellow]")
        elif isinstance(record, PECFGTargetPage):
            log.write(
                f"\n[bold cyan]GFIDS targets {record.start}–{record.end}[/bold cyan]"
            )
            log.write(
                "[dim]Each record begins with a 4-byte target RVA; optional "
                "metadata bytes follow according to the GuardFlags stride.[/dim]"
            )
            log.write("Index  Entry file  Target RVA  Target VA           Code file  Metadata / flags")
            for target in record.targets:
                target_offset = (
                    f"0x{target.file_offset:08x}"
                    if target.file_offset is not None
                    else "unmapped".rjust(10)
                )
                metadata = target.metadata.hex() if target.metadata else "—"
                flags = ", ".join(target.flag_names) if target.flag_names else "—"
                log.write(
                    f"{target.index:>5}  0x{target.entry_file_offset:08x}  "
                    f"0x{target.rva:08x}  0x{target.va:016x}  "
                    f"{target_offset}  {_safe(metadata, 64)} / {_safe(flags, 160)}"
                )
        elif isinstance(record, PEAuthenticode):
            log.write("\n[bold cyan]Authenticode / Attribute Certificate Table[/bold cyan]")
            log.write(
                "[dim]Unlike other data directories, the Security Directory value "
                "is a file offset—not an RVA. Embedded signatures are optional; a "
                "file can also be signed through an external catalog.[/dim]"
            )
            log.write(f"Table file offset          0x{record.table_file_offset:08x}")
            log.write(f"Declared table size        0x{record.table_size:x} ({record.table_size:,})")
            log.write(f"WIN_CERTIFICATE entries    {len(record.entries):,}")
            log.write(
                f"Complete bounded traversal  "
                f"{'yes' if record.table_complete else 'NO'}"
            )
            matches = sum(entry.digest_matches is True for entry in record.entries)
            mismatches = sum(entry.digest_matches is False for entry in record.entries)
            unavailable = sum(entry.digest_matches is None for entry in record.entries)
            log.write(f"Authenticode digest matches {matches:,}")
            log.write(f"Authenticode mismatches     {mismatches:,}")
            log.write(f"Digest comparison unavailable {unavailable:,}")
            log.write(
                "[dim]Select a WIN_CERTIFICATE entry for signer, timestamp, "
                "certificate-chain, and digest evidence. Enter opens the exact "
                "bCertificate bytes; D exports them safely.[/dim]"
            )
            for warning in record.warnings:
                log.write(f"[yellow]Warning                    {_safe(warning)}[/yellow]")
        elif isinstance(record, PEWinCertificate):
            log.write(
                f"\n[bold cyan]WIN_CERTIFICATE {record.index}[/bold cyan]"
            )
            log.write(f"Structure file offset      0x{record.file_offset:08x}")
            log.write(f"dwLength                   0x{record.declared_length:x} ({record.declared_length:,})")
            log.write(f"Aligned traversal length   {record.aligned_length:,}")
            log.write(
                f"wRevision                   0x{record.revision:04x} "
                f"({_safe(record.revision_name)})"
            )
            log.write(
                f"wCertificateType            0x{record.certificate_type:04x} "
                f"({_safe(record.certificate_type_name)})"
            )
            log.write(f"bCertificate file offset   0x{record.content_file_offset:08x}")
            log.write(f"bCertificate size          {record.content_size:,}")
            log.write(f"bCertificate SHA-256       {_safe(record.content_sha256)}")
            log.write(f"Complete entry             {'yes' if record.complete else 'NO'}")
            log.write(f"PKCS#7 content type        {_safe(record.pkcs7_content_type)}")
            log.write(f"Nested signatures          {record.nested_signature_count:,}")

            log.write("\n[bold cyan]Authenticode image-digest evidence[/bold cyan]")
            log.write(
                f"Embedded algorithm          "
                f"{_safe(record.embedded_digest_algorithm)}"
            )
            log.write(f"Embedded digest             {_safe(record.embedded_digest)}")
            log.write(f"Computed PE image digest    {_safe(record.computed_digest)}")
            if record.digest_matches is True:
                log.write(
                    "[bold green]Digest comparison           MATCH — hashed PE "
                    "image content agrees with the signed digest[/bold green]"
                )
            elif record.digest_matches is False:
                log.write(
                    "[bold red]Digest comparison           MISMATCH — hashed PE "
                    "image content differs from the signed digest[/bold red]"
                )
            else:
                log.write("[yellow]Digest comparison           unavailable[/yellow]")
            log.write(
                "[dim]A digest match is integrity evidence only. It does not by "
                "itself establish signer identity, certificate trust, revocation "
                "status, or timestamp validity.[/dim]"
            )

            log.write("\n[bold cyan]PKCS#7 signers[/bold cyan]")
            for signer in record.signers:
                log.write(f"[bold]Signer {signer.index}[/bold]  {_safe(signer.identifier, 512)}")
                log.write(f"  Digest algorithm         {_safe(signer.digest_algorithm)}")
                log.write(f"  Signature algorithm      {_safe(signer.signature_algorithm)}")
                log.write(f"  Signing time             {_safe(signer.signing_time)}")
                log.write(
                    f"  Timestamp attribute      "
                    f"{'present' if signer.timestamp_present else 'not found'}"
                )
                for timestamp in signer.timestamp_times:
                    log.write(f"    [cyan]↳ {_safe(timestamp)}[/cyan]")
                log.write(
                    f"  Matched certificate      "
                    f"{_safe(signer.matched_certificate_sha256)}"
                )
                log.write(
                    f"  Signed messageDigest     "
                    f"{_safe(signer.signed_message_digest)}"
                )
                content_status = (
                    "MATCH"
                    if signer.content_digest_matches is True
                    else "MISMATCH"
                    if signer.content_digest_matches is False
                    else "unavailable"
                )
                signature_status = (
                    "VALID"
                    if signer.signature_valid is True
                    else "INVALID"
                    if signer.signature_valid is False
                    else "unavailable"
                )
                log.write(f"  Signed-content digest    {content_status}")
                log.write(f"  Cryptographic signature {signature_status}")
                log.write(
                    f"    [dim]↳ {_safe(signer.verification_note, 512)}[/dim]"
                )
            if not record.signers:
                log.write("[dim]No PKCS#7 signer records decoded.[/dim]")

            log.write("\n[bold cyan]Embedded X.509 certificates[/bold cyan]")
            for certificate in record.certificates:
                log.write(
                    f"[bold]Certificate {certificate.index}[/bold]  "
                    f"SHA-256 {_safe(certificate.sha256_fingerprint)}"
                )
                log.write(f"  Subject                  {_safe(certificate.subject, 1024)}")
                log.write(f"  Issuer                   {_safe(certificate.issuer, 1024)}")
                log.write(f"  Serial                   {_safe(certificate.serial_number)}")
                log.write(
                    f"  Validity                 {_safe(certificate.not_valid_before)} → "
                    f"{_safe(certificate.not_valid_after)}"
                )
                log.write(
                    f"  Algorithms               signature="
                    f"{_safe(certificate.signature_algorithm)}, public-key="
                    f"{_safe(certificate.public_key_algorithm)}"
                )
                log.write(f"  CA certificate           {_safe(certificate.is_ca)}")
            if not record.certificates:
                log.write("[dim]No embedded X.509 certificates decoded.[/dim]")
            log.write(
                f"\n[bold green]Payload file  {certificate_filename(record)}[/bold green]"
            )
            log.write(
                "[dim]Press Enter to inspect the exact PKCS#7/certificate bytes "
                "inside AIDebug, or D to export them without overwrite.[/dim]"
            )
            for warning in record.warnings:
                log.write(f"[yellow]Warning                    {_safe(warning, 1024)}[/yellow]")
        elif isinstance(record, PERichHeader):
            log.write("\n[bold cyan]Rich header evidence[/bold cyan]")
            log.write(
                "[dim]The Rich structure is undocumented compiler/linker metadata. "
                "It can be absent, copied, or forged, so product/build values are "
                "clues—not attribution.[/dim]"
            )
            dans_offset = (
                _number(record.dans_file_offset)
                if record.dans_file_offset >= 0
                else "—"
            )
            log.write(f"DanS file offset          {dans_offset}")
            log.write(f"Rich file offset          0x{record.rich_file_offset:08x}")
            log.write(f"XOR key / checksum        0x{record.xor_key:08x}")
            log.write(f"Decoded span              {record.clear_data_size:,} bytes")
            log.write(f"Decoded entries           {len(record.entries):,}")
            log.write("\nIndex  Product ID  Build number  Use count")
            for entry in record.entries:
                log.write(
                    f"{entry.index:>5}  {entry.product_id:>10}  "
                    f"{entry.build_number:>12}  {entry.use_count:>9}"
                )
            for warning in record.warnings:
                log.write(f"[yellow]Warning                  {_safe(warning)}[/yellow]")
        elif isinstance(record, PEDebugDirectory):
            log.write("\n[bold cyan]Debug Directory[/bold cyan]")
            log.write(
                "[dim]IMAGE_DEBUG_DIRECTORY records are 28 bytes. Embedded PDB "
                "paths and timestamps are untrusted build clues, not provenance.[/dim]"
            )
            log.write(f"Directory RVA             0x{record.rva:08x}")
            log.write(f"Directory file offset     {_number(record.file_offset)}")
            log.write(f"Declared size             0x{record.size:x} ({record.size:,})")
            log.write(f"Parsed records            {len(record.records):,}")
            log.write(f"Complete traversal        {'yes' if record.complete else 'NO'}")
            log.write(
                "[dim]Select a record to inspect its fields. Enter opens complete "
                "debug bytes; D exports them without execution.[/dim]"
            )
            for warning in record.warnings:
                log.write(f"[yellow]Warning                  {_safe(warning)}[/yellow]")
        elif isinstance(record, PEDebugRecord):
            log.write(f"\n[bold cyan]IMAGE_DEBUG_DIRECTORY record {record.index}[/bold cyan]")
            log.write(f"Record file offset        0x{record.file_offset:08x}")
            log.write(f"Characteristics           0x{record.characteristics:08x}")
            log.write(f"TimeDateStamp             0x{record.time_date_stamp:08x}")
            log.write(f"Version                   {record.major_version}.{record.minor_version}")
            log.write(f"Type                      {record.type} ({_safe(record.type_name)})")
            log.write(
                f"SizeOfData                0x{record.size_of_data:x} "
                f"({record.size_of_data:,})"
            )
            log.write(f"AddressOfRawData (RVA)    0x{record.address_of_raw_data:08x}")
            log.write(f"PointerToRawData (file)   0x{record.pointer_to_raw_data:08x}")
            log.write(f"Resolved file offset      {_number(record.data_file_offset)}")
            log.write(f"Available bytes           {record.available_size:,}")
            log.write(f"Complete payload          {'yes' if record.complete else 'NO'}")
            log.write(f"Payload SHA-256           {_safe(record.data_sha256)}")
            if record.codeview_signature is not None:
                log.write("\n[bold cyan]CodeView evidence[/bold cyan]")
                log.write(f"Signature                 {_safe(record.codeview_signature)}")
                log.write(f"PDB signature GUID        {_safe(record.pdb_guid)}")
                log.write(f"PDB age                   {_safe(record.pdb_age)}")
                log.write(f"PDB path                  {_safe(record.pdb_path, 4096)}")
            if record.preview:
                log.write(f"Preview (hex)             {record.preview.hex(' ')}")
            for warning in record.warnings:
                log.write(f"[yellow]Warning                  {_safe(warning)}[/yellow]")
        elif isinstance(record, PEOverlay):
            log.write("\n[bold cyan]Overlay evidence[/bold cyan]")
            log.write(
                "[dim]Overlay means bytes following the mapped image. It may "
                "contain a certificate table, installer data, configuration, or "
                "malicious payloads; presence alone is not a verdict.[/dim]"
            )
            log.write(f"File offset               0x{record.file_offset:08x}")
            log.write(f"Size                      {record.size:,} bytes")
            log.write(f"SHA-256                   {record.sha256}")
            log.write(f"Entropy                   {record.entropy:.3f}")
            log.write(f"Preview (hex)             {record.preview.hex(' ')}")
            log.write(
                "[dim]Press Enter to inspect every overlay byte; D exports the "
                "exact range with owner-only permissions.[/dim]"
            )
        elif isinstance(record, PEDotNetHeader):
            log.write("\n[bold cyan].NET / CLR assembly[/bold cyan]")
            log.write(
                "[dim]Static ECMA-335 evidence parsed directly from the PE. The "
                "CLR is not loaded and no managed initializer or method executes.[/dim]"
            )
            log.write("\n[bold cyan]IMAGE_COR20_HEADER[/bold cyan]")
            log.write(f"COM Descriptor RVA        0x{record.rva:08x}")
            log.write(f"COM Descriptor size       0x{record.size:x} ({record.size:,})")
            log.write(f"Header file offset        {_number(record.file_offset)}")
            log.write(f"cb                        0x{record.cb:x} ({record.cb})")
            log.write(f"Runtime version           {record.runtime_major}.{record.runtime_minor}")
            log.write(f"Flags                     0x{record.flags:08x}")
            for flag_name in record.flag_names:
                log.write(f"                          [green]↳ {_safe(flag_name)}[/green]")
            log.write(
                f"Entry point               0x{record.entry_point:08x} "
                f"({_safe(record.entry_point_kind)})"
            )
            if record.entry_point_kind == "managed metadata token":
                token_table = (record.entry_point >> 24) & 0xFF
                token_rid = record.entry_point & 0x00FFFFFF
                token_name = (
                    "MethodDef" if token_table == 0x06
                    else "File" if token_table == 0x26
                    else f"table 0x{token_table:02x}"
                )
                log.write(
                    f"  Token decode            {_safe(token_name)}, RID {token_rid}"
                )
            log.write("\n[bold cyan]CLR data directories[/bold cyan]")
            for name, rva, size in (
                ("MetaData", record.metadata_rva, record.metadata_size),
                ("Resources", record.resources_rva, record.resources_size),
                ("StrongNameSignature", record.strong_name_rva, record.strong_name_size),
                ("CodeManagerTable", record.code_manager_rva, record.code_manager_size),
                ("VTableFixups", record.vtable_fixups_rva, record.vtable_fixups_size),
                ("ExportAddressTableJumps", record.export_jumps_rva, record.export_jumps_size),
                ("ManagedNativeHeader", record.managed_native_header_rva, record.managed_native_header_size),
            ):
                log.write(f"{name:<25} RVA 0x{rva:08x}, size 0x{size:x}")
            log.write(f"Metadata file offset      {_number(record.metadata_file_offset)}")
            log.write(f"Metadata version          {_safe(record.metadata_version)}")
            log.write(f"Module name               {_safe(record.module_name)}")
            if record.assembly is not None:
                log.write("\n[bold cyan]Assembly identity[/bold cyan]")
                log.write(f"Name                      {_safe(record.assembly.name)}")
                log.write(f"Version                   {_safe(record.assembly.version)}")
                log.write(f"Culture                   {_safe(record.assembly.culture)}")
                log.write(f"Flags                     0x{record.assembly.flags:08x}")
                log.write(f"Hash algorithm            0x{record.assembly.hash_algorithm:08x}")
            else:
                log.write("\n[dim]No Assembly table identity parsed (the image may be a netmodule).[/dim]")
            log.write("\n[bold cyan]Strong-name evidence[/bold cyan]")
            log.write(f"Signature file offset     {_number(record.strong_name_file_offset)}")
            log.write(f"Signature SHA-256         {_safe(record.strong_name_sha256)}")
            log.write(
                f"STRONGNAMESIGNED flag      "
                f"{'set' if record.flags & 0x8 else 'not set'}"
            )
            log.write(
                "[dim]Presence of a strong-name blob is identity/integrity metadata, "
                "not publisher trust or Authenticode validation.[/dim]"
            )
            log.write("\n[bold cyan]Metadata streams[/bold cyan]")
            log.write("Index  Name         Offset      Size        File offset  Complete  SHA-256")
            for stream in record.streams:
                stream_offset = (
                    f"0x{stream.file_offset:08x}"
                    if stream.file_offset is not None
                    else "unmapped"
                )
                log.write(
                    f"{stream.index:>5}  {_safe(stream.name, 12):<12} "
                    f"0x{stream.metadata_offset:08x} 0x{stream.size:08x}  "
                    f"{stream_offset:<11} {'yes' if stream.complete else 'NO':<8} "
                    f"{_safe(stream.sha256, 64)}"
                )
            log.write("\n[bold cyan]Managed metadata tables[/bold cyan]")
            log.write("ID  Table                    Rows       Row size  File offset")
            for table in record.tables:
                row_size = str(table.row_size) if table.row_size is not None else "—"
                table_offset = (
                    f"0x{table.file_offset:08x}"
                    if table.file_offset is not None
                    else "unmapped"
                )
                log.write(
                    f"{table.index:>2}  {_safe(table.name, 24):<24} "
                    f"{table.row_count:>10,} {row_size:>9}  {table_offset}"
                )
            log.write(f"\nAssembly references       {len(record.assembly_references):,}")
            log.write(
                "[dim]Expand Metadata streams or Assembly references in the tree. "
                "Complete streams can be opened with Enter and exported with D.[/dim]"
            )
            for warning in record.warnings:
                log.write(f"[yellow]Warning                  {_safe(warning)}[/yellow]")
        elif isinstance(record, PEDotNetStream):
            log.write(f"\n[bold cyan].NET metadata stream {_safe(record.name)}[/bold cyan]")
            log.write(f"Stream index              {record.index}")
            log.write(f"Metadata-relative offset  0x{record.metadata_offset:08x}")
            log.write(f"Declared size             0x{record.size:x} ({record.size:,})")
            log.write(f"File offset               {_number(record.file_offset)}")
            log.write(f"Available bytes           {record.available_size:,}")
            log.write(f"Complete payload          {'yes' if record.complete else 'NO'}")
            log.write(f"SHA-256                   {_safe(record.sha256)}")
            log.write(f"Preview (hex)             {record.preview.hex(' ')}")
            log.write(
                "[dim]Press Enter to inspect the exact stream bytes; D exports "
                "them without overwrite.[/dim]"
            )
            for warning in record.warnings:
                log.write(f"[yellow]Warning                  {_safe(warning)}[/yellow]")
        elif isinstance(record, PEDotNetAssemblyReference):
            log.write(f"\n[bold cyan]AssemblyRef row {record.index}[/bold cyan]")
            log.write(f"Name                      {_safe(record.name)}")
            log.write(f"Version                   {_safe(record.version)}")
            log.write(f"Culture                   {_safe(record.culture)}")
            log.write(f"Flags                     0x{record.flags:08x}")
            log.write(
                "[dim]This is a declared dependency in metadata, not evidence that "
                "the assembly was resolved or loaded at runtime.[/dim]"
            )
        elif isinstance(record, PELoadConfiguration):
            log.write("\n[bold cyan]Load Configuration Directory[/bold cyan]")
            if record.file_offset is None:
                log.write("Directory file offset    [yellow]unavailable[/yellow]")
            else:
                log.write(f"Directory file offset    0x{record.file_offset:08x}")
            log.write(f"Declared Size            0x{record.declared_size:x}")
            log.write(f"GuardFlags               0x{record.guard_flags:08x}")
            for flag_name in record.guard_flag_names:
                log.write(f"                         [green]↳ {_safe(flag_name)}[/green]")
            log.write("\n[bold cyan]Exploit-mitigation assessment[/bold cyan]")
            log.write(
                "[dim]Static evidence indicates image compatibility or compiler "
                "intent; it does not prove effective runtime process policy.[/dim]"
            )
            for finding in record.mitigations:
                if finding.status in {
                    "present",
                    "declared",
                    "cookie present",
                    "table present",
                    "structurally compatible",
                }:
                    style = "green"
                elif "inconsistent" in finding.status or "unused" in finding.status:
                    style = "yellow"
                else:
                    style = "dim"
                log.write(
                    f"[{style}]{_safe(finding.name, 64):<32} "
                    f"{_safe(finding.status, 64)}[/{style}]"
                )
                for evidence in finding.evidence:
                    log.write(f"    [dim]• {_safe(evidence, 512)}[/dim]")
            log.write("\n[bold cyan]Raw load-config fields[/bold cyan]")
            log.write("File offset  Size  Field                              Value")
            for field in record.fields:
                offset = (
                    f"0x{field.file_offset:08x}"
                    if field.file_offset is not None
                    else "—".rjust(10)
                )
                size = str(field.size) if field.size is not None else "—"
                log.write(
                    f"{offset}  {size:>4}  {_safe(field.name, 34):<34} "
                    f"{_header_value(field.value)}"
                )
                if field.target_rva is not None:
                    mapped = (
                        f"0x{field.target_file_offset:x}"
                        if field.target_file_offset is not None
                        else "unmapped"
                    )
                    log.write(
                        f"                 [cyan]↳ target RVA 0x{field.target_rva:x}, "
                        f"file offset {mapped}[/cyan]"
                    )
            if not record.fields:
                log.write("[dim]No load-config structure fields were parsed.[/dim]")
            for warning in record.warnings:
                log.write(f"[yellow]Warning                  {_safe(warning)}[/yellow]")
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
        if self.structure.base_relocations_truncated:
            log.write(
                "\n[yellow]Base-relocation parsing reached its configured block "
                "or entry safety limit; displayed counts are partial.[/yellow]"
            )
        if self.structure.tls_truncated:
            log.write(
                "\n[yellow]TLS callback traversal reached its configured or file "
                "boundary before a null terminator.[/yellow]"
            )
        if self.structure.exceptions_truncated:
            log.write(
                "\n[yellow]Runtime-function parsing reached its configured safety "
                "limit; displayed records are partial.[/yellow]"
            )

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
        if event.control.id != "pe-resource-tree":
            return
        record = event.node.data
        if isinstance(
            record,
            (
                PEResourceDirectoryRecord,
                PEResourceDataRecord,
                PEBaseRelocationBlock,
                PEASLRAssessment,
                PETLSDirectory,
                PETLSCallback,
                PEExceptionDirectory,
                PEExceptionPage,
                PERuntimeFunction,
                PELoadConfiguration,
                PECFGEvidence,
                PECFGTargetPage,
                PEAuthenticode,
                PEWinCertificate,
                PERichHeader,
                PEDebugDirectory,
                PEDebugRecord,
                PEOverlay,
                PEDotNetHeader,
                PEDotNetStream,
                PEDotNetAssemblyReference,
            ),
        ):
            if isinstance(record, PEBaseRelocationBlock):
                self._pages["pe-base-relocations"] = 0
                self._selected_relocation_block = record
            else:
                self._selected_relocation_block = None
            self._render_resource_record(record)
        else:
            self._selected_relocation_block = None
            self._render_resource_record(None)

    def on_tree_node_expanded(self, event: Tree.NodeExpanded) -> None:
        if event.control.id != "pe-resource-tree":
            return
        page = event.node.data
        if not isinstance(page, PEExceptionPage) or event.node.children:
            return
        for function in page.functions:
            label = (
                f"Function {function.index}: RVA 0x{function.begin_address:08x}–"
                f"0x{function.end_address:08x}"
            )
            self._exception_function_nodes[function.index] = event.node.add(
                label,
                data=function,
                allow_expand=False,
            )

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        if event.control.id != "pe-resource-tree":
            return
        record = event.node.data
        if isinstance(record, PEWinCertificate):
            if certificate_payload(self.structure, record) is None:
                self.query_one("#pe-status", Static).update(
                    Text(
                        "Certificate cannot be opened: its declared byte range "
                        "is incomplete."
                    )
                )
                return
            self.app.push_screen(CertificatePayloadScreen(self.structure, record))
            return
        if isinstance(record, PEDebugRecord):
            payload = debug_payload(self.structure, record)
            if payload is None:
                self.query_one("#pe-status", Static).update(
                    Text("Debug payload cannot be opened: its declared range is incomplete.")
                )
                return
            self.app.push_screen(
                EvidencePayloadScreen(
                    f"Debug record {record.index} ({record.type_name})",
                    payload,
                    record.data_sha256 or "unavailable",
                    record.data_file_offset or 0,
                )
            )
            return
        if isinstance(record, PEOverlay):
            payload = overlay_payload(self.structure, record)
            if payload is not None:
                self.app.push_screen(
                    EvidencePayloadScreen(
                        "PE overlay",
                        payload,
                        record.sha256,
                        record.file_offset,
                    )
                )
            return
        if isinstance(record, PEDotNetStream):
            payload = dotnet_stream_payload(self.structure, record)
            if payload is None:
                self.query_one("#pe-status", Static).update(
                    Text(".NET stream cannot be opened: its declared range is incomplete.")
                )
                return
            self.app.push_screen(
                EvidencePayloadScreen(
                    f".NET metadata stream {record.name}",
                    payload,
                    record.sha256 or "unavailable",
                    record.file_offset or 0,
                )
            )
            return
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
        if active == "pe-directories" and self._selected_relocation_block is not None:
            return "pe-base-relocations"
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
        if tab == "pe-base-relocations":
            count = (
                len(self._selected_relocation_block.entries)
                if self._selected_relocation_block is not None
                else 0
            )
            return page_count(count, self.RECORD_PAGE_SIZE)
        if tab == "pe-imports":
            return page_count(len(self.structure.imports), self.RECORD_PAGE_SIZE)
        if tab == "pe-exports":
            return page_count(len(self.structure.exports), self.RECORD_PAGE_SIZE)
        return 1

    def _render_active_page(self, tab: str) -> None:
        if tab == "pe-hex":
            self._render_hex()
        elif tab == "pe-base-relocations":
            if self._selected_relocation_block is not None:
                self._render_resource_record(self._selected_relocation_block)
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
                "Read-only PE evidence view. In Directories: Enter opens and D "
                "downloads a resource, certificate, debug, .NET, or overlay payload."
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
                Text("Open the Directories tab and select a resource file first.")
            )
            return
        node = self.query_one("#pe-resource-tree", Tree).cursor_node
        record = node.data if node is not None else None
        if isinstance(record, PEWinCertificate):
            try:
                destination = export_certificate(self.structure, record)
            except FileExistsError:
                message = "Export refused: the destination already exists."
            except (OSError, ValueError) as exc:
                message = f"Certificate export failed: {exc}"
            else:
                message = f"Certificate downloaded to {destination.resolve()}"
            self.query_one("#pe-status", Static).update(Text(message))
            return
        if isinstance(record, PEDebugRecord):
            try:
                destination = export_debug_payload(self.structure, record)
            except FileExistsError:
                message = "Export refused: the destination already exists."
            except (OSError, ValueError) as exc:
                message = f"Debug payload export failed: {exc}"
            else:
                message = f"Debug payload downloaded to {destination.resolve()}"
            self.query_one("#pe-status", Static).update(Text(message))
            return
        if isinstance(record, PEOverlay):
            try:
                destination = export_overlay(self.structure, record)
            except FileExistsError:
                message = "Export refused: the destination already exists."
            except (OSError, ValueError) as exc:
                message = f"Overlay export failed: {exc}"
            else:
                message = f"Overlay downloaded to {destination.resolve()}"
            self.query_one("#pe-status", Static).update(Text(message))
            return
        if isinstance(record, PEDotNetStream):
            try:
                destination = export_dotnet_stream(self.structure, record)
            except FileExistsError:
                message = "Export refused: the destination already exists."
            except (OSError, ValueError) as exc:
                message = f".NET stream export failed: {exc}"
            else:
                message = f".NET stream downloaded to {destination.resolve()}"
            self.query_one("#pe-status", Static).update(Text(message))
            return
        if not isinstance(record, PEResourceDataRecord):
            self.query_one("#pe-status", Static).update(
                Text(
                    "Select a resource, certificate, debug record, .NET stream, or overlay, then press D."
                )
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
