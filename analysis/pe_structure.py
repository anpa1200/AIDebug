"""Read-only, evidence-preserving inspection of Portable Executable files."""

from __future__ import annotations

import hashlib
import math
import struct
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

COFF_CHARACTERISTIC_FLAGS = (
    (0x0001, "IMAGE_FILE_RELOCS_STRIPPED"),
    (0x0002, "IMAGE_FILE_EXECUTABLE_IMAGE"),
    (0x0004, "IMAGE_FILE_LINE_NUMS_STRIPPED"),
    (0x0008, "IMAGE_FILE_LOCAL_SYMS_STRIPPED"),
    (0x0010, "IMAGE_FILE_AGGRESSIVE_WS_TRIM"),
    (0x0020, "IMAGE_FILE_LARGE_ADDRESS_AWARE"),
    (0x0040, "IMAGE_FILE_RESERVED_0040"),
    (0x0080, "IMAGE_FILE_BYTES_REVERSED_LO"),
    (0x0100, "IMAGE_FILE_32BIT_MACHINE"),
    (0x0200, "IMAGE_FILE_DEBUG_STRIPPED"),
    (0x0400, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"),
    (0x0800, "IMAGE_FILE_NET_RUN_FROM_SWAP"),
    (0x1000, "IMAGE_FILE_SYSTEM"),
    (0x2000, "IMAGE_FILE_DLL"),
    (0x4000, "IMAGE_FILE_UP_SYSTEM_ONLY"),
    (0x8000, "IMAGE_FILE_BYTES_REVERSED_HI"),
)

DLL_CHARACTERISTIC_FLAGS = (
    (0x0020, "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA"),
    (0x0040, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"),
    (0x0080, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY"),
    (0x0100, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT"),
    (0x0200, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION"),
    (0x0400, "IMAGE_DLLCHARACTERISTICS_NO_SEH"),
    (0x0800, "IMAGE_DLLCHARACTERISTICS_NO_BIND"),
    (0x1000, "IMAGE_DLLCHARACTERISTICS_APPCONTAINER"),
    (0x2000, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER"),
    (0x4000, "IMAGE_DLLCHARACTERISTICS_GUARD_CF"),
    (0x8000, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"),
)

SECTION_CHARACTERISTIC_FLAGS_BEFORE_ALIGNMENT = (
    (0x00000008, "IMAGE_SCN_TYPE_NO_PAD"),
    (0x00000020, "IMAGE_SCN_CNT_CODE"),
    (0x00000040, "IMAGE_SCN_CNT_INITIALIZED_DATA"),
    (0x00000080, "IMAGE_SCN_CNT_UNINITIALIZED_DATA"),
    (0x00000100, "IMAGE_SCN_LNK_OTHER"),
    (0x00000200, "IMAGE_SCN_LNK_INFO"),
    (0x00000800, "IMAGE_SCN_LNK_REMOVE"),
    (0x00001000, "IMAGE_SCN_LNK_COMDAT"),
    (0x00004000, "IMAGE_SCN_NO_DEFER_SPEC_EXC"),
    (0x00008000, "IMAGE_SCN_GPREL"),
    (0x00020000, "IMAGE_SCN_MEM_PURGEABLE / IMAGE_SCN_MEM_16BIT"),
    (0x00040000, "IMAGE_SCN_MEM_LOCKED"),
    (0x00080000, "IMAGE_SCN_MEM_PRELOAD"),
)

SECTION_ALIGNMENT_FLAGS = {
    0x00100000: "IMAGE_SCN_ALIGN_1BYTES",
    0x00200000: "IMAGE_SCN_ALIGN_2BYTES",
    0x00300000: "IMAGE_SCN_ALIGN_4BYTES",
    0x00400000: "IMAGE_SCN_ALIGN_8BYTES",
    0x00500000: "IMAGE_SCN_ALIGN_16BYTES",
    0x00600000: "IMAGE_SCN_ALIGN_32BYTES",
    0x00700000: "IMAGE_SCN_ALIGN_64BYTES",
    0x00800000: "IMAGE_SCN_ALIGN_128BYTES",
    0x00900000: "IMAGE_SCN_ALIGN_256BYTES",
    0x00A00000: "IMAGE_SCN_ALIGN_512BYTES",
    0x00B00000: "IMAGE_SCN_ALIGN_1024BYTES",
    0x00C00000: "IMAGE_SCN_ALIGN_2048BYTES",
    0x00D00000: "IMAGE_SCN_ALIGN_4096BYTES",
    0x00E00000: "IMAGE_SCN_ALIGN_8192BYTES",
}

SECTION_CHARACTERISTIC_FLAGS_AFTER_ALIGNMENT = (
    (0x01000000, "IMAGE_SCN_LNK_NRELOC_OVFL"),
    (0x02000000, "IMAGE_SCN_MEM_DISCARDABLE"),
    (0x04000000, "IMAGE_SCN_MEM_NOT_CACHED"),
    (0x08000000, "IMAGE_SCN_MEM_NOT_PAGED"),
    (0x10000000, "IMAGE_SCN_MEM_SHARED"),
    (0x20000000, "IMAGE_SCN_MEM_EXECUTE"),
    (0x40000000, "IMAGE_SCN_MEM_READ"),
    (0x80000000, "IMAGE_SCN_MEM_WRITE"),
)


def decode_coff_characteristics(value: int) -> tuple[str, ...]:
    """Decode an IMAGE_FILE_HEADER Characteristics bitmask without hiding it."""
    numeric = int(value)
    decoded = [name for mask, name in COFF_CHARACTERISTIC_FLAGS if numeric & mask]
    known_mask = sum(mask for mask, _name in COFF_CHARACTERISTIC_FLAGS)
    unknown = numeric & ~known_mask
    if unknown:
        decoded.append(f"UNKNOWN_0x{unknown:x}")
    return tuple(decoded)


def decode_dll_characteristics(value: int) -> tuple[str, ...]:
    """Decode an Optional Header DllCharacteristics bitmask."""
    numeric = int(value)
    decoded = [name for mask, name in DLL_CHARACTERISTIC_FLAGS if numeric & mask]
    known_mask = sum(mask for mask, _name in DLL_CHARACTERISTIC_FLAGS)
    unknown = numeric & ~known_mask
    if unknown:
        decoded.append(f"UNKNOWN_0x{unknown:x}")
    return tuple(decoded)


def decode_section_characteristics(value: int) -> tuple[str, ...]:
    """Decode IMAGE_SECTION_HEADER Characteristics, including alignment."""
    numeric = int(value)
    decoded = [
        name
        for mask, name in SECTION_CHARACTERISTIC_FLAGS_BEFORE_ALIGNMENT
        if numeric & mask
    ]
    alignment = numeric & 0x00F00000
    if alignment:
        decoded.append(
            SECTION_ALIGNMENT_FLAGS.get(
                alignment,
                f"IMAGE_SCN_ALIGN_UNKNOWN_0x{alignment:x}",
            )
        )
    decoded.extend(
        name
        for mask, name in SECTION_CHARACTERISTIC_FLAGS_AFTER_ALIGNMENT
        if numeric & mask
    )
    known_mask = 0x00F00000
    for mask, _name in (
        SECTION_CHARACTERISTIC_FLAGS_BEFORE_ALIGNMENT
        + SECTION_CHARACTERISTIC_FLAGS_AFTER_ALIGNMENT
    ):
        known_mask |= mask
    unknown = numeric & ~known_mask
    if unknown:
        decoded.append(f"UNKNOWN_0x{unknown:x}")
    return tuple(decoded)


def dll_mitigation_clues(value: int, *, pe32_plus: bool) -> tuple[str, ...]:
    """Translate loader flags into cautious mitigation evidence statements."""
    numeric = int(value)
    clues = [
        (
            "ASLR: declared via DYNAMIC_BASE"
            if numeric & 0x0040
            else "ASLR: not declared (DYNAMIC_BASE absent)"
        ),
        (
            "DEP/NX: declared via NX_COMPAT"
            if numeric & 0x0100
            else "DEP/NX: not declared (NX_COMPAT absent)"
        ),
        (
            "CFG: declared via GUARD_CF; validate Load Config guard metadata"
            if numeric & 0x4000
            else "CFG: not declared (GUARD_CF absent)"
        ),
    ]
    if numeric & 0x0020:
        if pe32_plus:
            clues.append(
                "High-entropy ASLR: requested; meaningful with DYNAMIC_BASE"
            )
        else:
            clues.append(
                "High-entropy VA flag is set on PE32; validate actual loader behavior"
            )
    if numeric & 0x0080:
        clues.append("Code integrity: FORCE_INTEGRITY declared")
    if numeric & 0x1000:
        clues.append("AppContainer: image declares AppContainer compatibility")
    if numeric & 0x0400:
        clues.append("SEH: image declares that it does not use structured exception handling")
    return tuple(clues)


@dataclass(frozen=True)
class PEHeaderField:
    name: str
    value: Any
    file_offset: int | None = None
    size: int | None = None
    decoded_flags: tuple[str, ...] = ()
    mitigation_clues: tuple[str, ...] = ()


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
    pointer_to_relocations: int = 0
    pointer_to_linenumbers: int = 0
    number_of_relocations: int = 0
    number_of_linenumbers: int = 0
    characteristic_flags: tuple[str, ...] = ()
    header_offset: int | None = None


@dataclass(frozen=True)
class PEImportRecord:
    kind: str
    dll: str
    name: str
    ordinal: int | None
    hint: int | None
    iat_address: int | None


@dataclass(frozen=True)
class PEImportDescriptorRecord:
    index: int
    dll: str
    file_offset: int
    original_first_thunk: int
    time_date_stamp: int
    forwarder_chain: int
    name_rva: int
    first_thunk: int
    is_zero_terminator: bool = False


@dataclass(frozen=True)
class PEDelayImportDescriptorRecord:
    index: int
    dll: str
    file_offset: int
    attributes: int
    dll_name: int
    module_handle: int
    import_address_table: int
    import_name_table: int
    bound_import_address_table: int
    unload_information_table: int
    time_date_stamp: int
    is_zero_terminator: bool = False

    @property
    def uses_rvas(self) -> bool:
        return bool(self.attributes & 1)


@dataclass(frozen=True)
class PEResourceDirectoryRecord:
    path: tuple[str, ...]
    file_offset: int
    characteristics: int
    time_date_stamp: int
    major_version: int
    minor_version: int
    named_entries: int
    id_entries: int


@dataclass(frozen=True)
class PEResourceDataRecord:
    path: tuple[str, ...]
    entry_file_offset: int
    data_rva: int
    data_file_offset: int | None
    size: int
    available_size: int
    code_page: int
    reserved: int
    sha256: str | None
    preview: bytes

    @property
    def complete(self) -> bool:
        return self.data_file_offset is not None and self.available_size == self.size


PEResourceRecord = PEResourceDirectoryRecord | PEResourceDataRecord


@dataclass(frozen=True)
class PEBaseRelocationEntry:
    index: int
    file_offset: int
    type: int
    type_name: str
    offset: int
    rva: int
    address: int


@dataclass(frozen=True)
class PEBaseRelocationBlock:
    index: int
    file_offset: int
    virtual_address: int
    size_of_block: int
    entries: tuple[PEBaseRelocationEntry, ...]


@dataclass(frozen=True)
class PEASLRAssessment:
    dynamic_base: bool
    high_entropy_va: bool
    relocations_stripped: bool
    directory_rva: int
    directory_size: int
    parsed_blocks: int
    parsed_entries: int
    usable_entries: int
    status: str
    clues: tuple[str, ...]


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
    import_descriptors: tuple[PEImportDescriptorRecord, ...] = ()
    delay_import_descriptors: tuple[PEDelayImportDescriptorRecord, ...] = ()
    resources: tuple[PEResourceRecord, ...] = ()
    base_relocations: tuple[PEBaseRelocationBlock, ...] = ()
    aslr: PEASLRAssessment | None = None
    imports_truncated: bool = False
    import_descriptors_truncated: bool = False
    delay_import_descriptors_truncated: bool = False
    resources_truncated: bool = False
    base_relocations_truncated: bool = False
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
            import_descriptors, import_descriptors_truncated = (
                self._import_descriptors(pe, raw_data)
            )
            delay_descriptors, delay_descriptors_truncated = (
                self._delay_import_descriptors(pe, raw_data)
            )
            resources, resources_truncated = self._resources(pe, raw_data)
            base_relocations, base_relocations_truncated = self._base_relocations(pe)
            aslr = self._aslr_assessment(
                pe,
                base_relocations,
                base_relocations_truncated,
            )
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
                import_descriptors=import_descriptors,
                delay_import_descriptors=delay_descriptors,
                resources=resources,
                base_relocations=base_relocations,
                aslr=aslr,
                imports_truncated=imports_truncated,
                import_descriptors_truncated=import_descriptors_truncated,
                delay_import_descriptors_truncated=delay_descriptors_truncated,
                resources_truncated=resources_truncated,
                base_relocations_truncated=base_relocations_truncated,
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
            value = metadata.get("Value")
            decoded_flags = ()
            mitigation_clues = ()
            if (
                name == "COFF file header"
                and field_name == "Characteristics"
                and isinstance(value, int)
            ):
                decoded_flags = decode_coff_characteristics(value)
            elif (
                name == "Optional header"
                and field_name == "DllCharacteristics"
                and isinstance(value, int)
            ):
                decoded_flags = decode_dll_characteristics(value)
                mitigation_clues = dll_mitigation_clues(
                    value,
                    pe32_plus=int(getattr(structure, "Magic", 0)) == 0x20B,
                )
            fields.append(
                PEHeaderField(
                    name=str(field_name),
                    value=value,
                    file_offset=(int(file_offset) if file_offset is not None else None),
                    size=(int(size) if size is not None else None),
                    decoded_flags=decoded_flags,
                    mitigation_clues=mitigation_clues,
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
            pointer_to_relocations=int(
                getattr(section, "PointerToRelocations", 0)
            ),
            pointer_to_linenumbers=int(
                getattr(section, "PointerToLinenumbers", 0)
            ),
            number_of_relocations=int(getattr(section, "NumberOfRelocations", 0)),
            number_of_linenumbers=int(getattr(section, "NumberOfLinenumbers", 0)),
            characteristic_flags=decode_section_characteristics(
                int(section.Characteristics)
            ),
            header_offset=(
                int(section.get_file_offset())
                if callable(getattr(section, "get_file_offset", None))
                else None
            ),
        )

    @staticmethod
    def _decode(value) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def _import_descriptors(
        self,
        pe,
        raw_data: bytes,
    ) -> tuple[tuple[PEImportDescriptorRecord, ...], bool]:
        entries = list(getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()))
        truncated = len(entries) > config.MAX_IMPORT_DESCRIPTORS
        selected = entries[:config.MAX_IMPORT_DESCRIPTORS]
        records = []
        for index, entry in enumerate(selected):
            descriptor = getattr(entry, "struct", None)
            if descriptor is None:
                continue
            records.append(
                PEImportDescriptorRecord(
                    index=index,
                    dll=self._decode(getattr(entry, "dll", None))
                    or "<unknown DLL>",
                    file_offset=int(descriptor.get_file_offset()),
                    original_first_thunk=int(
                        getattr(
                            descriptor,
                            "OriginalFirstThunk",
                            getattr(descriptor, "Characteristics", 0),
                        )
                    ),
                    time_date_stamp=int(getattr(descriptor, "TimeDateStamp", 0)),
                    forwarder_chain=int(getattr(descriptor, "ForwarderChain", 0)),
                    name_rva=int(getattr(descriptor, "Name", 0)),
                    first_thunk=int(getattr(descriptor, "FirstThunk", 0)),
                )
            )

        if not truncated:
            terminator_offset = self._import_terminator_offset(pe, records)
            if (
                terminator_offset is not None
                and 0 <= terminator_offset <= len(raw_data) - 20
                and raw_data[terminator_offset:terminator_offset + 20] == bytes(20)
            ):
                records.append(
                    PEImportDescriptorRecord(
                        index=len(records),
                        dll="<all-zero terminator>",
                        file_offset=terminator_offset,
                        original_first_thunk=0,
                        time_date_stamp=0,
                        forwarder_chain=0,
                        name_rva=0,
                        first_thunk=0,
                        is_zero_terminator=True,
                    )
                )
        return tuple(records), truncated

    @staticmethod
    def _import_terminator_offset(
        pe,
        records: list[PEImportDescriptorRecord],
    ) -> int | None:
        if records:
            return records[-1].file_offset + 20
        directories = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", ())
        if len(directories) <= 1 or int(directories[1].VirtualAddress) == 0:
            return None
        try:
            return int(pe.get_offset_from_rva(int(directories[1].VirtualAddress)))
        except (AttributeError, TypeError, ValueError, pefile.PEFormatError):
            return None

    def _delay_import_descriptors(
        self,
        pe,
        raw_data: bytes,
    ) -> tuple[tuple[PEDelayImportDescriptorRecord, ...], bool]:
        entries = list(getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", ()))
        truncated = len(entries) > config.MAX_DELAY_IMPORT_DESCRIPTORS
        selected = entries[:config.MAX_DELAY_IMPORT_DESCRIPTORS]
        records = []
        for index, entry in enumerate(selected):
            descriptor = getattr(entry, "struct", None)
            if descriptor is None:
                continue
            file_offset = int(descriptor.get_file_offset())
            if file_offset < 0 or file_offset > len(raw_data) - 32:
                truncated = True
                continue
            values = struct.unpack_from("<8I", raw_data, file_offset)
            records.append(
                PEDelayImportDescriptorRecord(
                    index=index,
                    dll=self._decode(getattr(entry, "dll", None))
                    or "<unknown DLL>",
                    file_offset=file_offset,
                    attributes=values[0],
                    dll_name=values[1],
                    module_handle=values[2],
                    import_address_table=values[3],
                    import_name_table=values[4],
                    bound_import_address_table=values[5],
                    unload_information_table=values[6],
                    time_date_stamp=values[7],
                )
            )

        if not truncated:
            terminator_offset = self._delay_import_terminator_offset(pe, records)
            if (
                terminator_offset is not None
                and 0 <= terminator_offset <= len(raw_data) - 32
                and raw_data[terminator_offset:terminator_offset + 32] == bytes(32)
            ):
                records.append(
                    PEDelayImportDescriptorRecord(
                        index=len(records),
                        dll="<all-zero terminator>",
                        file_offset=terminator_offset,
                        attributes=0,
                        dll_name=0,
                        module_handle=0,
                        import_address_table=0,
                        import_name_table=0,
                        bound_import_address_table=0,
                        unload_information_table=0,
                        time_date_stamp=0,
                        is_zero_terminator=True,
                    )
                )
        return tuple(records), truncated

    @staticmethod
    def _delay_import_terminator_offset(
        pe,
        records: list[PEDelayImportDescriptorRecord],
    ) -> int | None:
        if records:
            return records[-1].file_offset + 32
        directories = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", ())
        if len(directories) <= 13 or int(directories[13].VirtualAddress) == 0:
            return None
        try:
            return int(pe.get_offset_from_rva(int(directories[13].VirtualAddress)))
        except (AttributeError, TypeError, ValueError, pefile.PEFormatError):
            return None

    def _resources(
        self,
        pe,
        raw_data: bytes,
    ) -> tuple[tuple[PEResourceRecord, ...], bool]:
        root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        if root is None:
            return (), False

        records: list[PEResourceRecord] = []
        truncated = False
        seen_directories: set[int] = set()

        def append(record: PEResourceRecord) -> bool:
            nonlocal truncated
            if len(records) >= config.MAX_RESOURCE_RECORDS:
                truncated = True
                return False
            records.append(record)
            return True

        def walk(directory, path: tuple[str, ...], depth: int) -> None:
            nonlocal truncated
            if depth > config.MAX_RESOURCE_DEPTH:
                truncated = True
                return
            identity = id(directory)
            if identity in seen_directories:
                truncated = True
                return
            seen_directories.add(identity)
            header = getattr(directory, "struct", None)
            if header is None:
                truncated = True
                return
            if not append(
                PEResourceDirectoryRecord(
                    path=path,
                    file_offset=int(header.get_file_offset()),
                    characteristics=int(getattr(header, "Characteristics", 0)),
                    time_date_stamp=int(getattr(header, "TimeDateStamp", 0)),
                    major_version=int(getattr(header, "MajorVersion", 0)),
                    minor_version=int(getattr(header, "MinorVersion", 0)),
                    named_entries=int(getattr(header, "NumberOfNamedEntries", 0)),
                    id_entries=int(getattr(header, "NumberOfIdEntries", 0)),
                )
            ):
                return
            for entry in getattr(directory, "entries", ()):
                child_path = path + (self._resource_entry_label(entry, depth),)
                child_directory = getattr(entry, "directory", None)
                if child_directory is not None:
                    walk(child_directory, child_path, depth + 1)
                    if truncated and len(records) >= config.MAX_RESOURCE_RECORDS:
                        return
                    continue
                data = getattr(getattr(entry, "data", None), "struct", None)
                if data is not None and not append(
                    self._resource_data_record(pe, raw_data, child_path, data)
                ):
                    return

        walk(root, ("<root>",), 0)
        return tuple(records), truncated

    @staticmethod
    def _resource_entry_label(entry, depth: int) -> str:
        name = getattr(entry, "name", None)
        if name is not None:
            return str(name)
        resource_id = int(getattr(entry, "id", 0))
        if depth == 0:
            return f"{pefile.RESOURCE_TYPE.get(resource_id, 'TYPE')} ({resource_id})"
        if depth == 2:
            return f"LANG_{resource_id}"
        return f"ID_{resource_id}"

    @staticmethod
    def _resource_data_record(
        pe,
        raw_data: bytes,
        path: tuple[str, ...],
        data,
    ) -> PEResourceDataRecord:
        data_rva = int(getattr(data, "OffsetToData", 0))
        size = max(0, int(getattr(data, "Size", 0)))
        try:
            data_file_offset = int(pe.get_offset_from_rva(data_rva))
        except (AttributeError, TypeError, ValueError, pefile.PEFormatError):
            data_file_offset = None

        available_size = 0
        preview = b""
        digest = None
        if data_file_offset is not None and 0 <= data_file_offset <= len(raw_data):
            available_size = min(size, len(raw_data) - data_file_offset)
            view = memoryview(raw_data)[
                data_file_offset:data_file_offset + available_size
            ]
            preview = bytes(view[:config.MAX_RESOURCE_PREVIEW_BYTES])
            if available_size == size:
                digest = hashlib.sha256(view).hexdigest()
        return PEResourceDataRecord(
            path=path,
            entry_file_offset=int(data.get_file_offset()),
            data_rva=data_rva,
            data_file_offset=data_file_offset,
            size=size,
            available_size=available_size,
            code_page=int(getattr(data, "CodePage", 0)),
            reserved=int(getattr(data, "Reserved", 0)),
            sha256=digest,
            preview=preview,
        )

    @staticmethod
    def _base_relocations(
        pe,
    ) -> tuple[tuple[PEBaseRelocationBlock, ...], bool]:
        source_blocks = list(getattr(pe, "DIRECTORY_ENTRY_BASERELOC", ()))
        truncated = len(source_blocks) > config.MAX_BASE_RELOCATION_BLOCKS
        records = []
        entry_count = 0
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        for block_index, block in enumerate(
            source_blocks[:config.MAX_BASE_RELOCATION_BLOCKS]
        ):
            structure = getattr(block, "struct", None)
            if structure is None:
                truncated = True
                continue
            block_offset = int(structure.get_file_offset())
            page_rva = int(getattr(structure, "VirtualAddress", 0))
            size_of_block = int(getattr(structure, "SizeOfBlock", 0))
            entries = []
            for entry_index, entry in enumerate(getattr(block, "entries", ())):
                if entry_count >= config.MAX_BASE_RELOCATION_ENTRIES:
                    truncated = True
                    break
                relocation_type = int(getattr(entry, "type", 0))
                rva = int(getattr(entry, "rva", page_rva))
                entry_structure = getattr(entry, "struct", None)
                try:
                    file_offset = int(entry_structure.get_file_offset())
                except (AttributeError, TypeError, ValueError):
                    file_offset = block_offset + 8 + entry_index * 2
                entries.append(
                    PEBaseRelocationEntry(
                        index=entry_index,
                        file_offset=file_offset,
                        type=relocation_type,
                        type_name=str(
                            pefile.RELOCATION_TYPE.get(
                                relocation_type,
                                f"IMAGE_REL_BASED_UNKNOWN_{relocation_type}",
                            )
                        ),
                        offset=max(0, rva - page_rva),
                        rva=rva,
                        address=image_base + rva,
                    )
                )
                entry_count += 1
            records.append(
                PEBaseRelocationBlock(
                    index=block_index,
                    file_offset=block_offset,
                    virtual_address=page_rva,
                    size_of_block=size_of_block,
                    entries=tuple(entries),
                )
            )
            if entry_count >= config.MAX_BASE_RELOCATION_ENTRIES:
                break
        if len(records) < len(source_blocks):
            truncated = True
        return tuple(records), truncated

    @staticmethod
    def _aslr_assessment(
        pe,
        blocks: tuple[PEBaseRelocationBlock, ...],
        truncated: bool,
    ) -> PEASLRAssessment:
        dll_characteristics = int(
            getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0)
        )
        file_characteristics = int(getattr(pe.FILE_HEADER, "Characteristics", 0))
        directories = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", ())
        relocation_directory = directories[5] if len(directories) > 5 else None
        directory_rva = int(getattr(relocation_directory, "VirtualAddress", 0))
        directory_size = int(getattr(relocation_directory, "Size", 0))
        dynamic_base = bool(dll_characteristics & 0x0040)
        high_entropy_va = bool(dll_characteristics & 0x0020)
        relocations_stripped = bool(file_characteristics & 0x0001)
        parsed_entries = sum(len(block.entries) for block in blocks)
        usable_entries = sum(
            entry.type != 0 for block in blocks for entry in block.entries
        )

        if relocations_stripped:
            status = (
                "Base relocations are marked stripped; normal image rebasing is "
                "not available."
            )
        elif not dynamic_base:
            status = "The image does not declare DYNAMIC_BASE ASLR opt-in."
        elif directory_rva == 0 or directory_size == 0:
            status = (
                "DYNAMIC_BASE is declared, but the base-relocation directory is absent."
            )
        elif usable_entries == 0:
            status = (
                "DYNAMIC_BASE is declared, but no usable non-ABSOLUTE relocation "
                "entries were parsed."
            )
        else:
            status = (
                "The image declares DYNAMIC_BASE and contains usable base "
                "relocations; it is structurally ASLR-compatible."
            )

        clues = [
            f"DYNAMIC_BASE: {'set' if dynamic_base else 'not set'}",
            f"HIGH_ENTROPY_VA: {'set' if high_entropy_va else 'not set'}",
            f"RELOCS_STRIPPED: {'set' if relocations_stripped else 'not set'}",
            (
                f"Base-relocation directory: RVA 0x{directory_rva:08x}, "
                f"size 0x{directory_size:x}"
            ),
            (
                f"Parsed relocation evidence: {len(blocks):,} blocks, "
                f"{parsed_entries:,} entries, {usable_entries:,} usable"
            ),
            (
                "Header flags and relocation structure indicate compatibility; "
                "they do not prove that the OS randomized this process at runtime."
            ),
        ]
        if int(getattr(pe.OPTIONAL_HEADER, "Magic", 0)) != 0x20B and high_entropy_va:
            clues.append("HIGH_ENTROPY_VA is not meaningful for this PE32 image.")
        if truncated:
            clues.append(
                "Relocation evidence reached a configured display limit; counts are partial."
            )
        return PEASLRAssessment(
            dynamic_base=dynamic_base,
            high_entropy_va=high_entropy_va,
            relocations_stripped=relocations_stripped,
            directory_rva=directory_rva,
            directory_size=directory_size,
            parsed_blocks=len(blocks),
            parsed_entries=parsed_entries,
            usable_entries=usable_entries,
            status=status,
            clues=tuple(clues),
        )

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
