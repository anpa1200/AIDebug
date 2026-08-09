"""Read-only, evidence-preserving inspection of Portable Executable files."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

import config

try:
    import pefile

    HAS_PEFILE = True
except ImportError:  # pragma: no cover - the package is a required dependency
    pefile = None
    HAS_PEFILE = False


DATA_DIRECTORY_NAMES = (
    "EXPORT",
    "IMPORT",
    "RESOURCE",
    "EXCEPTION",
    "SECURITY",
    "BASERELOC",
    "DEBUG",
    "ARCHITECTURE",
    "GLOBALPTR",
    "TLS",
    "LOAD_CONFIG",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT",
    "COM_DESCRIPTOR",
    "RESERVED",
)


@dataclass(frozen=True)
class PEHeaderField:
    name: str
    value: Any
    file_offset: int | None = None
    size: int | None = None


@dataclass(frozen=True)
class PEHeader:
    name: str
    fields: tuple[PEHeaderField, ...] = ()


@dataclass(frozen=True)
class PEDataDirectory:
    index: int
    name: str
    rva: int
    size: int


@dataclass(frozen=True)
class PESectionRecord:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int
    entropy: float


@dataclass(frozen=True)
class PEImportRecord:
    kind: str
    dll: str
    name: str
    ordinal: int | None
    hint: int | None
    iat_address: int | None


@dataclass(frozen=True)
class PEExportRecord:
    name: str
    ordinal: int
    rva: int
    address: int
    forwarder: str | None = None


@dataclass(frozen=True)
class PEStructure:
    filename: str
    sha256: str
    file_size: int
    arch: str
    bits: int
    image_base: int
    entry_point: int
    headers: tuple[PEHeader, ...]
    data_directories: tuple[PEDataDirectory, ...]
    sections: tuple[PESectionRecord, ...]
    imports: tuple[PEImportRecord, ...]
    exports: tuple[PEExportRecord, ...]
    overlay_offset: int | None
    overlay_size: int
    raw_data: bytes = field(repr=False)
    imports_truncated: bool = False
    exports_truncated: bool = False


class PEStructureAnalyzer:
    """Build a complete PE inspection model from the bytes already analyzed."""

    def analyze(self, binary_info) -> PEStructure:
        if str(getattr(binary_info, "file_format", "")).upper() != "PE":
            raise ValueError("PE Structure is available only for Windows PE files")
        if not HAS_PEFILE:
            raise ImportError("pefile not installed — run: pip install pefile")

        raw_data = bytes(getattr(binary_info, "raw_data", b""))
        if not raw_data:
            raise ValueError("The analyzed PE bytes are unavailable")
        if len(raw_data) > config.MAX_BINARY_SIZE_BYTES:
            raise ValueError("The PE exceeds AIDebug's configured analysis limit")

        pe = pefile.PE(data=raw_data, fast_load=False)
        try:
            headers = [
                self._header("DOS header", pe.DOS_HEADER),
                PEHeader(
                    "NT signature",
                    (
                        PEHeaderField(
                            "Signature",
                            int(pe.NT_HEADERS.Signature),
                            int(pe.DOS_HEADER.e_lfanew),
                            4,
                        ),
                    ),
                ),
                self._header("COFF file header", pe.FILE_HEADER),
                self._header("Optional header", pe.OPTIONAL_HEADER),
            ]
            directories = tuple(
                PEDataDirectory(
                    index=index,
                    name=(
                        DATA_DIRECTORY_NAMES[index]
                        if index < len(DATA_DIRECTORY_NAMES)
                        else f"DIRECTORY_{index}"
                    ),
                    rva=int(directory.VirtualAddress),
                    size=int(directory.Size),
                )
                for index, directory in enumerate(
                    getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", ())
                )
            )
            sections = tuple(self._section(section) for section in pe.sections)
            imports, imports_truncated = self._imports(pe)
            exports, exports_truncated = self._exports(pe)

            overlay_offset = pe.get_overlay_data_start_offset()
            if overlay_offset is not None:
                overlay_offset = int(overlay_offset)
                overlay_size = max(0, len(raw_data) - overlay_offset)
            else:
                overlay_size = 0

            return PEStructure(
                filename=str(binary_info.filename),
                sha256=str(binary_info.sha256),
                file_size=len(raw_data),
                arch=str(binary_info.arch),
                bits=int(binary_info.bits),
                image_base=int(pe.OPTIONAL_HEADER.ImageBase),
                entry_point=(
                    int(pe.OPTIONAL_HEADER.ImageBase)
                    + int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                ),
                headers=tuple(headers),
                data_directories=directories,
                sections=sections,
                imports=imports,
                exports=exports,
                overlay_offset=overlay_offset,
                overlay_size=overlay_size,
                raw_data=raw_data,
                imports_truncated=imports_truncated,
                exports_truncated=exports_truncated,
            )
        finally:
            pe.close()

    @staticmethod
    def _header(name: str, structure) -> PEHeader:
        dumped = structure.dump_dict()
        fields = []
        for field_name, metadata in dumped.items():
            if field_name == "Structure" or not isinstance(metadata, dict):
                continue
            file_offset = metadata.get("FileOffset")
            size = metadata.get("Size")
            fields.append(
                PEHeaderField(
                    name=str(field_name),
                    value=metadata.get("Value"),
                    file_offset=(int(file_offset) if file_offset is not None else None),
                    size=(int(size) if size is not None else None),
                )
            )
        return PEHeader(name=name, fields=tuple(fields))

    @staticmethod
    def _section(section) -> PESectionRecord:
        name = bytes(section.Name).rstrip(b"\x00").decode("utf-8", errors="replace")
        try:
            entropy = float(section.get_entropy())
        except (AttributeError, TypeError, ValueError):
            entropy = 0.0
        return PESectionRecord(
            name=name,
            virtual_address=int(section.VirtualAddress),
            virtual_size=int(section.Misc_VirtualSize),
            raw_offset=int(section.PointerToRawData),
            raw_size=int(section.SizeOfRawData),
            characteristics=int(section.Characteristics),
            entropy=entropy,
        )

    @staticmethod
    def _decode(value) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def _imports(self, pe) -> tuple[tuple[PEImportRecord, ...], bool]:
        records = []
        truncated = False
        sources = (
            ("import", getattr(pe, "DIRECTORY_ENTRY_IMPORT", ())),
            ("delay", getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", ())),
        )
        for kind, entries in sources:
            for entry in entries:
                dll = self._decode(getattr(entry, "dll", None)) or "<unknown DLL>"
                for item in getattr(entry, "imports", ()):
                    if len(records) >= config.MAX_IMPORT_FUNCTIONS:
                        truncated = True
                        break
                    ordinal = getattr(item, "ordinal", None)
                    raw_name = getattr(item, "name", None)
                    name = self._decode(raw_name) if raw_name else f"ordinal_{ordinal}"
                    records.append(
                        PEImportRecord(
                            kind=kind,
                            dll=dll,
                            name=name,
                            ordinal=(int(ordinal) if ordinal is not None else None),
                            hint=(
                                int(item.hint)
                                if getattr(item, "hint", None) is not None
                                else None
                            ),
                            iat_address=(
                                int(item.address)
                                if getattr(item, "address", None) is not None
                                else None
                            ),
                        )
                    )
                if truncated:
                    break
            if truncated:
                break
        return tuple(records), truncated

    def _exports(self, pe) -> tuple[tuple[PEExportRecord, ...], bool]:
        directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        symbols = list(getattr(directory, "symbols", ()))
        truncated = len(symbols) > config.MAX_EXPORTS
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        records = []
        for symbol in symbols[:config.MAX_EXPORTS]:
            ordinal = int(symbol.ordinal)
            rva = int(symbol.address)
            raw_name = getattr(symbol, "name", None)
            records.append(
                PEExportRecord(
                    name=self._decode(raw_name) if raw_name else f"ordinal_{ordinal}",
                    ordinal=ordinal,
                    rva=rva,
                    address=image_base + rva,
                    forwarder=(
                        self._decode(symbol.forwarder)
                        if getattr(symbol, "forwarder", None)
                        else None
                    ),
                )
            )
        return tuple(records), truncated


def page_count(item_count: int, page_size: int) -> int:
    """Return at least one page so empty views remain navigable."""
    if page_size <= 0:
        raise ValueError("page_size must be positive")
    return max(1, math.ceil(max(0, item_count) / page_size))


def render_hex_page(
    data: bytes,
    page: int,
    *,
    page_size: int = 4096,
    row_width: int = 16,
) -> tuple[str, int, int]:
    """Render one deterministic page while keeping every file byte reachable."""
    if page_size <= 0 or row_width <= 0:
        raise ValueError("page_size and row_width must be positive")
    total_pages = page_count(len(data), page_size)
    selected = min(max(0, int(page)), total_pages - 1)
    start = selected * page_size
    chunk = data[start:start + page_size]
    lines = []
    for relative in range(0, len(chunk), row_width):
        row = chunk[relative:relative + row_width]
        hexadecimal = " ".join(f"{byte:02x}" for byte in row)
        hexadecimal = hexadecimal.ljust(row_width * 3 - 1)
        ascii_text = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in row)
        lines.append(f"{start + relative:08x}  {hexadecimal}  |{ascii_text}| ")
    if not lines:
        lines.append("<empty file>")
    return "\n".join(lines), selected, total_pages
