"""Read-only, evidence-preserving inspection of Portable Executable files."""

from __future__ import annotations

import hashlib
import math
import struct
import uuid
from dataclasses import dataclass, field
from typing import Any

import config

try:
    import pefile

    HAS_PEFILE = True
except ImportError:  # pragma: no cover - the package is a required dependency
    pefile = None
    HAS_PEFILE = False

try:
    from asn1crypto import algos, cms

    HAS_ASN1CRYPTO = True
except ImportError:  # pragma: no cover - declared as a required dependency
    algos = None
    cms = None
    HAS_ASN1CRYPTO = False

try:
    from cryptography import x509 as crypto_x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa

    HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - declared as a required dependency
    crypto_x509 = None
    InvalidSignature = Exception
    hashes = None
    dsa = None
    ec = None
    padding = None
    rsa = None
    HAS_CRYPTOGRAPHY = False


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

UNWIND_REGISTER_NAMES = (
    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
)

UNWIND_OPERATION_NAMES = {
    0: "UWOP_PUSH_NONVOL",
    1: "UWOP_ALLOC_LARGE",
    2: "UWOP_ALLOC_SMALL",
    3: "UWOP_SET_FPREG",
    4: "UWOP_SAVE_NONVOL",
    5: "UWOP_SAVE_NONVOL_FAR",
    6: "UWOP_EPILOG",
    7: "UWOP_SPARE_CODE",
    8: "UWOP_SAVE_XMM128",
    9: "UWOP_SAVE_XMM128_FAR",
    10: "UWOP_PUSH_MACHFRAME",
}

GUARD_FLAG_NAMES = (
    (0x00000100, "IMAGE_GUARD_CF_INSTRUMENTED"),
    (0x00000200, "IMAGE_GUARD_CFW_INSTRUMENTED"),
    (0x00000400, "IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT"),
    (0x00000800, "IMAGE_GUARD_SECURITY_COOKIE_UNUSED"),
    (0x00001000, "IMAGE_GUARD_PROTECT_DELAYLOAD_IAT"),
    (0x00002000, "IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION"),
    (0x00004000, "IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT"),
    (0x00008000, "IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION"),
    (0x00010000, "IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT"),
    (0x00020000, "IMAGE_GUARD_RF_INSTRUMENTED"),
    (0x00040000, "IMAGE_GUARD_RF_ENABLE"),
    (0x00080000, "IMAGE_GUARD_RF_STRICT"),
    (0x00100000, "IMAGE_GUARD_RETPOLINE_PRESENT"),
    (0x00400000, "IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT"),
    (0x00800000, "IMAGE_GUARD_XFG_ENABLED"),
    (0x01000000, "IMAGE_GUARD_CASTGUARD_PRESENT"),
    (0x02000000, "IMAGE_GUARD_MEMCPY_PRESENT"),
)

WIN_CERTIFICATE_REVISIONS = {
    0x0100: "WIN_CERT_REVISION_1_0",
    0x0200: "WIN_CERT_REVISION_2_0",
}

WIN_CERTIFICATE_TYPES = {
    0x0001: "WIN_CERT_TYPE_X509",
    0x0002: "WIN_CERT_TYPE_PKCS_SIGNED_DATA",
    0x0003: "WIN_CERT_TYPE_RESERVED_1",
    0x0004: "WIN_CERT_TYPE_TS_STACK_SIGNED",
    0x0009: "WIN_CERT_TYPE_PKCS1_SIGN",
}

DEBUG_TYPE_NAMES = {
    0: "IMAGE_DEBUG_TYPE_UNKNOWN",
    1: "IMAGE_DEBUG_TYPE_COFF",
    2: "IMAGE_DEBUG_TYPE_CODEVIEW",
    3: "IMAGE_DEBUG_TYPE_FPO",
    4: "IMAGE_DEBUG_TYPE_MISC",
    5: "IMAGE_DEBUG_TYPE_EXCEPTION",
    6: "IMAGE_DEBUG_TYPE_FIXUP",
    7: "IMAGE_DEBUG_TYPE_OMAP_TO_SRC",
    8: "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC",
    9: "IMAGE_DEBUG_TYPE_BORLAND",
    10: "IMAGE_DEBUG_TYPE_RESERVED10",
    11: "IMAGE_DEBUG_TYPE_CLSID",
    12: "IMAGE_DEBUG_TYPE_VC_FEATURE",
    13: "IMAGE_DEBUG_TYPE_POGO",
    14: "IMAGE_DEBUG_TYPE_ILTCG",
    15: "IMAGE_DEBUG_TYPE_MPX",
    16: "IMAGE_DEBUG_TYPE_REPRO",
    17: "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS",
}

CLR_FLAG_NAMES = (
    (0x00000001, "COMIMAGE_FLAGS_ILONLY"),
    (0x00000002, "COMIMAGE_FLAGS_32BITREQUIRED"),
    (0x00000004, "COMIMAGE_FLAGS_IL_LIBRARY"),
    (0x00000008, "COMIMAGE_FLAGS_STRONGNAMESIGNED"),
    (0x00000010, "COMIMAGE_FLAGS_NATIVE_ENTRYPOINT"),
    (0x00010000, "COMIMAGE_FLAGS_TRACKDEBUGDATA"),
    (0x00020000, "COMIMAGE_FLAGS_32BITPREFERRED"),
)

DOTNET_TABLE_NAMES = (
    "Module", "TypeRef", "TypeDef", "FieldPtr", "Field", "MethodPtr",
    "MethodDef", "ParamPtr", "Param", "InterfaceImpl", "MemberRef",
    "Constant", "CustomAttribute", "FieldMarshal", "DeclSecurity",
    "ClassLayout", "FieldLayout", "StandAloneSig", "EventMap", "EventPtr",
    "Event", "PropertyMap", "PropertyPtr", "Property", "MethodSemantics",
    "MethodImpl", "ModuleRef", "TypeSpec", "ImplMap", "FieldRVA", "ENCLog",
    "ENCMap", "Assembly", "AssemblyProcessor", "AssemblyOS", "AssemblyRef",
    "AssemblyRefProcessor", "AssemblyRefOS", "File", "ExportedType",
    "ManifestResource", "NestedClass", "GenericParam", "MethodSpec",
    "GenericParamConstraint",
)

LOAD_CONFIG_POINTER_FIELDS = {
    "LockPrefixTable",
    "EditList",
    "SecurityCookie",
    "SEHandlerTable",
    "GuardCFCheckFunctionPointer",
    "GuardCFDispatchFunctionPointer",
    "GuardCFFunctionTable",
    "GuardAddressTakenIatEntryTable",
    "GuardLongJumpTargetTable",
    "DynamicValueRelocTable",
    "CHPEMetadataPointer",
    "GuardRFFailureRoutine",
    "GuardRFFailureRoutineFunctionPointer",
    "GuardRFVerifyStackPointerFunctionPointer",
    "EnclaveConfigurationPointer",
    "VolatileMetadataPointer",
    "GuardEHContinuationTable",
    "GuardXFGCheckFunctionPointer",
    "GuardXFGDispatchFunctionPointer",
    "GuardXFGTableDispatchFunctionPointer",
    "CastGuardOsDeterminedFailureMode",
    "GuardMemcpyFunctionPointer",
}


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
class PERichEntry:
    index: int
    product_id: int
    build_number: int
    use_count: int


@dataclass(frozen=True)
class PERichHeader:
    dans_file_offset: int
    rich_file_offset: int
    xor_key: int
    clear_data_size: int
    entries: tuple[PERichEntry, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class PEDebugRecord:
    index: int
    file_offset: int
    characteristics: int
    time_date_stamp: int
    major_version: int
    minor_version: int
    type: int
    type_name: str
    size_of_data: int
    address_of_raw_data: int
    pointer_to_raw_data: int
    data_file_offset: int | None
    available_size: int
    data_sha256: str | None
    preview: bytes
    codeview_signature: str | None
    pdb_guid: str | None
    pdb_age: int | None
    pdb_path: str | None
    warnings: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return (
            self.data_file_offset is not None
            and self.available_size == self.size_of_data
        )


@dataclass(frozen=True)
class PEDebugDirectory:
    rva: int
    size: int
    file_offset: int | None
    records: tuple[PEDebugRecord, ...]
    complete: bool
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class PEOverlay:
    file_offset: int
    size: int
    sha256: str
    entropy: float
    preview: bytes


@dataclass(frozen=True)
class PEDotNetStream:
    index: int
    name: str
    metadata_offset: int
    size: int
    file_offset: int | None
    available_size: int
    sha256: str | None
    preview: bytes
    warnings: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return self.file_offset is not None and self.available_size == self.size


@dataclass(frozen=True)
class PEDotNetTable:
    index: int
    name: str
    row_count: int
    row_size: int | None
    file_offset: int | None


@dataclass(frozen=True)
class PEDotNetAssemblyIdentity:
    name: str
    version: str
    culture: str
    flags: int
    hash_algorithm: int


@dataclass(frozen=True)
class PEDotNetAssemblyReference:
    index: int
    name: str
    version: str
    culture: str
    flags: int


@dataclass(frozen=True)
class PEDotNetHeader:
    rva: int
    size: int
    file_offset: int | None
    cb: int
    runtime_major: int
    runtime_minor: int
    metadata_rva: int
    metadata_size: int
    metadata_file_offset: int | None
    flags: int
    flag_names: tuple[str, ...]
    entry_point: int
    entry_point_kind: str
    resources_rva: int
    resources_size: int
    strong_name_rva: int
    strong_name_size: int
    strong_name_file_offset: int | None
    strong_name_sha256: str | None
    code_manager_rva: int
    code_manager_size: int
    vtable_fixups_rva: int
    vtable_fixups_size: int
    export_jumps_rva: int
    export_jumps_size: int
    managed_native_header_rva: int
    managed_native_header_size: int
    metadata_version: str | None
    streams: tuple[PEDotNetStream, ...]
    tables: tuple[PEDotNetTable, ...]
    module_name: str | None
    assembly: PEDotNetAssemblyIdentity | None
    assembly_references: tuple[PEDotNetAssemblyReference, ...]
    warnings: tuple[str, ...]


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
class PETLSCallback:
    index: int
    table_entry_file_offset: int
    address: int
    rva: int | None
    file_offset: int | None


@dataclass(frozen=True)
class PETLSDirectory:
    file_offset: int
    is_pe32_plus: bool
    start_address_of_raw_data: int
    end_address_of_raw_data: int
    raw_data_rva: int | None
    raw_data_file_offset: int | None
    raw_data_size: int
    raw_data_available_size: int
    raw_data_sha256: str | None
    raw_data_preview: bytes
    address_of_index: int
    index_rva: int | None
    index_file_offset: int | None
    address_of_callbacks: int
    callbacks_rva: int | None
    callbacks_file_offset: int | None
    size_of_zero_fill: int
    characteristics: int
    callbacks: tuple[PETLSCallback, ...]
    callbacks_terminated: bool
    warnings: tuple[str, ...]

    @property
    def raw_data_complete(self) -> bool:
        return (
            self.raw_data_file_offset is not None
            and self.raw_data_available_size == self.raw_data_size
        )


@dataclass(frozen=True)
class PEUnwindCode:
    slot_index: int
    code_offset: int
    unwind_op: int
    op_info: int
    op_name: str
    slots_used: int
    description: str


@dataclass(frozen=True)
class PEUnwindInfo:
    rva: int
    file_offset: int
    version: int
    flags: int
    flag_names: tuple[str, ...]
    size_of_prolog: int
    count_of_codes: int
    frame_register: int
    frame_register_name: str
    frame_offset: int
    codes: tuple[PEUnwindCode, ...]
    exception_handler_rva: int | None
    exception_handler_file_offset: int | None
    language_data_file_offset: int | None
    chained_function: tuple[int, int, int] | None
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class PERuntimeFunction:
    index: int
    file_offset: int
    begin_address: int
    end_address: int
    begin_va: int
    end_va: int
    unwind_data: int
    unwind_info: PEUnwindInfo | None


@dataclass(frozen=True)
class PEExceptionDirectory:
    machine: int
    is_x64: bool
    functions: tuple[PERuntimeFunction, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class PELoadConfigField:
    name: str
    value: object
    file_offset: int | None
    size: int | None
    target_rva: int | None = None
    target_file_offset: int | None = None


@dataclass(frozen=True)
class PEMitigationFinding:
    name: str
    status: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class PECFGTarget:
    index: int
    entry_file_offset: int
    rva: int
    va: int
    file_offset: int | None
    metadata: bytes
    flag_names: tuple[str, ...]


@dataclass(frozen=True)
class PECFGEvidence:
    header_guard_cf: bool
    instrumented: bool
    write_integrity_instrumented: bool
    function_table_present: bool
    check_function_pointer: int
    check_function_rva: int | None
    check_function_file_offset: int | None
    dispatch_function_pointer: int
    dispatch_function_rva: int | None
    dispatch_function_file_offset: int | None
    function_table: int
    function_table_rva: int | None
    function_table_file_offset: int | None
    function_count: int
    entry_stride: int
    targets: tuple[PECFGTarget, ...]
    targets_sorted: bool
    table_complete: bool
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class PELoadConfiguration:
    file_offset: int | None
    declared_size: int
    fields: tuple[PELoadConfigField, ...]
    guard_flags: int
    guard_flag_names: tuple[str, ...]
    mitigations: tuple[PEMitigationFinding, ...]
    warnings: tuple[str, ...]
    cfg: PECFGEvidence | None = None


@dataclass(frozen=True)
class PEEmbeddedCertificate:
    index: int
    subject: str
    issuer: str
    serial_number: str
    not_valid_before: str
    not_valid_after: str
    sha256_fingerprint: str
    signature_algorithm: str
    public_key_algorithm: str
    is_ca: bool | None


@dataclass(frozen=True)
class PEAuthenticodeSigner:
    index: int
    identifier: str
    digest_algorithm: str
    signature_algorithm: str
    signing_time: str | None
    timestamp_present: bool
    timestamp_times: tuple[str, ...]
    matched_certificate_sha256: str | None
    signed_message_digest: str | None
    content_digest_matches: bool | None
    signature_valid: bool | None
    verification_note: str | None


@dataclass(frozen=True)
class PEWinCertificate:
    index: int
    file_offset: int
    declared_length: int
    aligned_length: int
    revision: int
    revision_name: str
    certificate_type: int
    certificate_type_name: str
    content_file_offset: int
    content_size: int
    content_sha256: str | None
    complete: bool
    pkcs7_content_type: str | None
    embedded_digest_algorithm: str | None
    embedded_digest: str | None
    computed_digest: str | None
    digest_matches: bool | None
    nested_signature_count: int
    signers: tuple[PEAuthenticodeSigner, ...]
    certificates: tuple[PEEmbeddedCertificate, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class PEAuthenticode:
    table_file_offset: int
    table_size: int
    entries: tuple[PEWinCertificate, ...]
    table_complete: bool
    warnings: tuple[str, ...]


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
    tls: PETLSDirectory | None = None
    exceptions: PEExceptionDirectory | None = None
    load_configuration: PELoadConfiguration | None = None
    authenticode: PEAuthenticode | None = None
    rich_header: PERichHeader | None = None
    debug_directory: PEDebugDirectory | None = None
    overlay: PEOverlay | None = None
    dotnet: PEDotNetHeader | None = None
    imports_truncated: bool = False
    import_descriptors_truncated: bool = False
    delay_import_descriptors_truncated: bool = False
    resources_truncated: bool = False
    base_relocations_truncated: bool = False
    tls_truncated: bool = False
    exceptions_truncated: bool = False
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
            tls, tls_truncated = self._tls(pe, raw_data)
            exceptions, exceptions_truncated = self._exceptions(pe, raw_data)
            load_configuration = self._load_configuration(pe, aslr, raw_data)
            authenticode = self._authenticode(pe, raw_data)
            rich_header = self._rich_header(pe, raw_data)
            debug_directory = self._debug_directory(pe, raw_data)
            dotnet = self._dotnet(pe, raw_data)
            imports, imports_truncated = self._imports(pe)
            exports, exports_truncated = self._exports(pe)

            overlay_offset = pe.get_overlay_data_start_offset()
            if overlay_offset is not None:
                overlay_offset = int(overlay_offset)
                overlay_size = max(0, len(raw_data) - overlay_offset)
            else:
                overlay_size = 0
            overlay = self._overlay(raw_data, overlay_offset)

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
                tls=tls,
                exceptions=exceptions,
                load_configuration=load_configuration,
                authenticode=authenticode,
                rich_header=rich_header,
                debug_directory=debug_directory,
                overlay=overlay,
                dotnet=dotnet,
                imports_truncated=imports_truncated,
                import_descriptors_truncated=import_descriptors_truncated,
                delay_import_descriptors_truncated=delay_descriptors_truncated,
                resources_truncated=resources_truncated,
                base_relocations_truncated=base_relocations_truncated,
                tls_truncated=tls_truncated,
                exceptions_truncated=exceptions_truncated,
                exports_truncated=exports_truncated,
            )
        finally:
            pe.close()

    @staticmethod
    def _rich_header(pe, raw_data: bytes) -> PERichHeader | None:
        """Decode bounded Rich-header evidence from the DOS stub."""
        pe_offset = max(0, int(getattr(pe.DOS_HEADER, "e_lfanew", 0)))
        search_end = min(len(raw_data), pe_offset or len(raw_data))
        rich_offset = raw_data.rfind(b"Rich", 0x40, search_end)
        if rich_offset < 0:
            return None
        warnings: list[str] = []
        if rich_offset + 8 > search_end:
            return PERichHeader(
                dans_file_offset=-1,
                rich_file_offset=rich_offset,
                xor_key=0,
                clear_data_size=0,
                entries=(),
                warnings=("Rich marker is truncated before its XOR key.",),
            )
        xor_key = struct.unpack_from("<I", raw_data, rich_offset + 4)[0]
        dans_offset = -1
        for offset in range(rich_offset - 4, 0x3F, -4):
            encoded = struct.unpack_from("<I", raw_data, offset)[0]
            if encoded ^ xor_key == 0x536E6144:  # little-endian "DanS"
                dans_offset = offset
                break
        if dans_offset < 0:
            return PERichHeader(
                dans_file_offset=-1,
                rich_file_offset=rich_offset,
                xor_key=xor_key,
                clear_data_size=0,
                entries=(),
                warnings=("Rich marker found, but its XOR-decoded DanS marker was not found.",),
            )
        if dans_offset + 16 > rich_offset:
            warnings.append("Rich header is too short for the DanS padding fields.")
            entries_offset = rich_offset
        else:
            entries_offset = dans_offset + 16
            padding = tuple(
                struct.unpack_from("<I", raw_data, dans_offset + 4 + index * 4)[0]
                ^ xor_key
                for index in range(3)
            )
            if padding != (0, 0, 0):
                warnings.append("The three XOR-decoded DanS padding DWORDs are not all zero.")
        available_pairs = max(0, (rich_offset - entries_offset) // 8)
        count = min(available_pairs, config.MAX_RICH_HEADER_ENTRIES)
        entries = []
        for index in range(count):
            offset = entries_offset + index * 8
            component = struct.unpack_from("<I", raw_data, offset)[0] ^ xor_key
            use_count = struct.unpack_from("<I", raw_data, offset + 4)[0] ^ xor_key
            entries.append(
                PERichEntry(
                    index=index,
                    product_id=(component >> 16) & 0xFFFF,
                    build_number=component & 0xFFFF,
                    use_count=use_count,
                )
            )
        if (rich_offset - entries_offset) % 8:
            warnings.append("Rich entry area is not an exact sequence of 8-byte records.")
        if available_pairs > config.MAX_RICH_HEADER_ENTRIES:
            warnings.append(
                "Rich entry parsing stopped at MAX_RICH_HEADER_ENTRIES "
                f"({config.MAX_RICH_HEADER_ENTRIES:,})."
            )
        return PERichHeader(
            dans_file_offset=dans_offset,
            rich_file_offset=rich_offset,
            xor_key=xor_key,
            clear_data_size=rich_offset - dans_offset,
            entries=tuple(entries),
            warnings=tuple(warnings),
        )

    @classmethod
    def _debug_directory(cls, pe, raw_data: bytes) -> PEDebugDirectory | None:
        """Parse IMAGE_DEBUG_DIRECTORY records and bounded CodeView evidence."""
        directories = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", ())
        if len(directories) <= 6:
            return None
        directory = directories[6]
        rva = int(getattr(directory, "VirtualAddress", 0))
        size = max(0, int(getattr(directory, "Size", 0)))
        if not rva or not size:
            return None
        warnings: list[str] = []
        try:
            file_offset = int(pe.get_offset_from_rva(rva))
        except (AttributeError, TypeError, ValueError, pefile.PEFormatError):
            return PEDebugDirectory(
                rva=rva,
                size=size,
                file_offset=None,
                records=(),
                complete=False,
                warnings=("Debug Directory RVA does not map to file bytes.",),
            )
        if file_offset < 0 or file_offset > len(raw_data):
            return PEDebugDirectory(
                rva=rva,
                size=size,
                file_offset=file_offset,
                records=(),
                complete=False,
                warnings=("Debug Directory file offset is outside the analyzed file.",),
            )
        available = min(size, len(raw_data) - file_offset)
        declared_count = size // 28
        available_count = available // 28
        parsed_count = min(
            declared_count,
            available_count,
            config.MAX_DEBUG_DIRECTORY_ENTRIES,
        )
        if size % 28:
            warnings.append("Debug Directory size is not a multiple of 28 bytes.")
        if available < size:
            warnings.append("Debug Directory extends beyond the analyzed file.")
        if declared_count > config.MAX_DEBUG_DIRECTORY_ENTRIES:
            warnings.append(
                "Debug record parsing stopped at MAX_DEBUG_DIRECTORY_ENTRIES "
                f"({config.MAX_DEBUG_DIRECTORY_ENTRIES:,})."
            )
        records = []
        for index in range(parsed_count):
            record_offset = file_offset + index * 28
            fields = struct.unpack_from("<IIHHIIII", raw_data, record_offset)
            records.append(cls._debug_record(pe, raw_data, index, record_offset, fields))
        complete = (
            available == size
            and size % 28 == 0
            and parsed_count == declared_count
        )
        return PEDebugDirectory(
            rva=rva,
            size=size,
            file_offset=file_offset,
            records=tuple(records),
            complete=complete,
            warnings=tuple(warnings),
        )

    @staticmethod
    def _debug_record(pe, raw_data: bytes, index: int, file_offset: int, fields) -> PEDebugRecord:
        (
            characteristics,
            time_date_stamp,
            major_version,
            minor_version,
            debug_type,
            size_of_data,
            address_of_raw_data,
            pointer_to_raw_data,
        ) = (int(value) for value in fields)
        warnings: list[str] = []
        data_offset: int | None = pointer_to_raw_data or None
        if data_offset is None and address_of_raw_data:
            try:
                data_offset = int(pe.get_offset_from_rva(address_of_raw_data))
            except (AttributeError, TypeError, ValueError, pefile.PEFormatError):
                warnings.append("AddressOfRawData does not map to file bytes.")
        available_size = 0
        preview = b""
        digest = None
        payload = b""
        if data_offset is not None and 0 <= data_offset <= len(raw_data):
            available_size = min(size_of_data, len(raw_data) - data_offset)
            payload = raw_data[data_offset:data_offset + available_size]
            preview = payload[:config.MAX_DEBUG_DATA_PREVIEW_BYTES]
            if available_size == size_of_data:
                digest = hashlib.sha256(payload).hexdigest()
            else:
                warnings.append("Debug payload extends beyond the analyzed file.")
        elif size_of_data:
            warnings.append("Debug payload file offset is outside the analyzed file.")

        signature = None
        pdb_guid = None
        pdb_age = None
        pdb_path = None
        if debug_type == 2 and payload:
            signature_bytes = payload[:4]
            signature = (
                signature_bytes.decode("ascii", errors="replace")
                if len(signature_bytes) == 4
                else signature_bytes.hex()
            )
            if signature_bytes == b"RSDS":
                if len(payload) < 24:
                    warnings.append("RSDS CodeView record is shorter than 24 bytes.")
                else:
                    pdb_guid = str(uuid.UUID(bytes_le=payload[4:20])).upper()
                    pdb_age = struct.unpack_from("<I", payload, 20)[0]
                    path_bytes = payload[24:24 + config.MAX_PDB_PATH_BYTES]
                    terminator = path_bytes.find(b"\x00")
                    if terminator >= 0:
                        path_bytes = path_bytes[:terminator]
                    else:
                        warnings.append("RSDS PDB path is unterminated or exceeds the configured bound.")
                    pdb_path = path_bytes.decode("utf-8", errors="replace")
            elif signature_bytes == b"NB10":
                if len(payload) < 16:
                    warnings.append("NB10 CodeView record is shorter than 16 bytes.")
                else:
                    pdb_age = struct.unpack_from("<I", payload, 12)[0]
                    path_bytes = payload[16:16 + config.MAX_PDB_PATH_BYTES]
                    terminator = path_bytes.find(b"\x00")
                    if terminator >= 0:
                        path_bytes = path_bytes[:terminator]
                    else:
                        warnings.append("NB10 PDB path is unterminated or exceeds the configured bound.")
                    pdb_path = path_bytes.decode("utf-8", errors="replace")
            else:
                warnings.append("Unrecognized CodeView signature; raw bytes remain available.")
        return PEDebugRecord(
            index=index,
            file_offset=file_offset,
            characteristics=characteristics,
            time_date_stamp=time_date_stamp,
            major_version=major_version,
            minor_version=minor_version,
            type=debug_type,
            type_name=DEBUG_TYPE_NAMES.get(debug_type, f"IMAGE_DEBUG_TYPE_{debug_type}"),
            size_of_data=size_of_data,
            address_of_raw_data=address_of_raw_data,
            pointer_to_raw_data=pointer_to_raw_data,
            data_file_offset=data_offset,
            available_size=available_size,
            data_sha256=digest,
            preview=preview,
            codeview_signature=signature,
            pdb_guid=pdb_guid,
            pdb_age=pdb_age,
            pdb_path=pdb_path,
            warnings=tuple(warnings),
        )

    @staticmethod
    def _overlay(raw_data: bytes, offset: int | None) -> PEOverlay | None:
        if offset is None or offset < 0 or offset >= len(raw_data):
            return None
        payload = raw_data[offset:]
        counts = [0] * 256
        for value in payload:
            counts[value] += 1
        entropy = -sum(
            (count / len(payload)) * math.log2(count / len(payload))
            for count in counts
            if count
        )
        return PEOverlay(
            file_offset=offset,
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            entropy=entropy,
            preview=payload[:config.MAX_OVERLAY_PREVIEW_BYTES],
        )

    @classmethod
    def _dotnet(cls, pe, raw_data: bytes) -> PEDotNetHeader | None:
        """Parse the CLR header and ECMA-335 metadata without loading the assembly."""
        directories = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", ())
        if len(directories) <= 14:
            return None
        directory = directories[14]
        rva = int(getattr(directory, "VirtualAddress", 0))
        size = max(0, int(getattr(directory, "Size", 0)))
        if not rva or not size:
            return None
        warnings: list[str] = []
        file_offset = cls._dotnet_rva_offset(pe, rva)

        def incomplete(reason: str) -> PEDotNetHeader:
            return PEDotNetHeader(
                rva=rva,
                size=size,
                file_offset=file_offset,
                cb=0,
                runtime_major=0,
                runtime_minor=0,
                metadata_rva=0,
                metadata_size=0,
                metadata_file_offset=None,
                flags=0,
                flag_names=(),
                entry_point=0,
                entry_point_kind="metadata token",
                resources_rva=0,
                resources_size=0,
                strong_name_rva=0,
                strong_name_size=0,
                strong_name_file_offset=None,
                strong_name_sha256=None,
                code_manager_rva=0,
                code_manager_size=0,
                vtable_fixups_rva=0,
                vtable_fixups_size=0,
                export_jumps_rva=0,
                export_jumps_size=0,
                managed_native_header_rva=0,
                managed_native_header_size=0,
                metadata_version=None,
                streams=(),
                tables=(),
                module_name=None,
                assembly=None,
                assembly_references=(),
                warnings=(reason,),
            )

        if file_offset is None:
            return incomplete("COM Descriptor RVA does not map to file bytes.")
        if file_offset < 0 or file_offset > len(raw_data) - 72:
            return incomplete("IMAGE_COR20_HEADER is truncated or outside the analyzed file.")
        (
            cb,
            runtime_major,
            runtime_minor,
            metadata_rva,
            metadata_size,
            flags,
            entry_point,
        ) = struct.unpack_from("<IHHIIII", raw_data, file_offset)
        directories_values = struct.unpack_from("<12I", raw_data, file_offset + 24)
        (
            resources_rva,
            resources_size,
            strong_name_rva,
            strong_name_size,
            code_manager_rva,
            code_manager_size,
            vtable_fixups_rva,
            vtable_fixups_size,
            export_jumps_rva,
            export_jumps_size,
            managed_native_header_rva,
            managed_native_header_size,
        ) = directories_values
        if cb < 72:
            warnings.append(f"CLR header cb is {cb}, smaller than IMAGE_COR20_HEADER (72).")
        elif cb > size:
            warnings.append("CLR header cb exceeds the COM Descriptor directory size.")
        known_flags = sum(mask for mask, _name in CLR_FLAG_NAMES)
        flag_names = [name for mask, name in CLR_FLAG_NAMES if flags & mask]
        if flags & ~known_flags:
            flag_names.append(f"UNKNOWN_0x{flags & ~known_flags:x}")
        entry_point_kind = "native RVA" if flags & 0x10 else "managed metadata token"
        metadata = cls._dotnet_metadata(pe, raw_data, metadata_rva, metadata_size)
        (
            metadata_file_offset,
            metadata_version,
            streams,
            tables,
            module_name,
            assembly,
            assembly_references,
            metadata_warnings,
        ) = metadata
        warnings.extend(metadata_warnings)
        strong_name_file_offset = cls._dotnet_rva_offset(pe, strong_name_rva)
        strong_name_sha256 = None
        if strong_name_size:
            if (
                strong_name_file_offset is None
                or strong_name_file_offset < 0
                or strong_name_file_offset + strong_name_size > len(raw_data)
            ):
                warnings.append("Strong-name signature range is unmapped or truncated.")
            else:
                strong_name_sha256 = hashlib.sha256(
                    raw_data[
                        strong_name_file_offset:
                        strong_name_file_offset + strong_name_size
                    ]
                ).hexdigest()
        return PEDotNetHeader(
            rva=rva,
            size=size,
            file_offset=file_offset,
            cb=cb,
            runtime_major=runtime_major,
            runtime_minor=runtime_minor,
            metadata_rva=metadata_rva,
            metadata_size=metadata_size,
            metadata_file_offset=metadata_file_offset,
            flags=flags,
            flag_names=tuple(flag_names),
            entry_point=entry_point,
            entry_point_kind=entry_point_kind,
            resources_rva=resources_rva,
            resources_size=resources_size,
            strong_name_rva=strong_name_rva,
            strong_name_size=strong_name_size,
            strong_name_file_offset=strong_name_file_offset,
            strong_name_sha256=strong_name_sha256,
            code_manager_rva=code_manager_rva,
            code_manager_size=code_manager_size,
            vtable_fixups_rva=vtable_fixups_rva,
            vtable_fixups_size=vtable_fixups_size,
            export_jumps_rva=export_jumps_rva,
            export_jumps_size=export_jumps_size,
            managed_native_header_rva=managed_native_header_rva,
            managed_native_header_size=managed_native_header_size,
            metadata_version=metadata_version,
            streams=streams,
            tables=tables,
            module_name=module_name,
            assembly=assembly,
            assembly_references=assembly_references,
            warnings=tuple(warnings),
        )

    @staticmethod
    def _dotnet_rva_offset(pe, rva: int) -> int | None:
        if not rva:
            return None
        try:
            return int(pe.get_offset_from_rva(int(rva)))
        except (AttributeError, TypeError, ValueError, pefile.PEFormatError):
            return None

    @classmethod
    def _dotnet_metadata(cls, pe, raw_data: bytes, rva: int, size: int):
        warnings: list[str] = []
        file_offset = cls._dotnet_rva_offset(pe, rva)
        empty = (file_offset, None, (), (), None, None, (), tuple(warnings))
        if not rva or not size:
            warnings.append("CLR metadata directory is absent.")
            return (*empty[:-1], tuple(warnings))
        if file_offset is None or file_offset < 0 or file_offset >= len(raw_data):
            warnings.append("CLR metadata RVA does not map to file bytes.")
            return (*empty[:-1], tuple(warnings))
        available = min(size, len(raw_data) - file_offset)
        metadata = raw_data[file_offset:file_offset + available]
        if available < size:
            warnings.append("CLR metadata root extends beyond the analyzed file.")
        if len(metadata) < 20 or metadata[:4] != b"BSJB":
            warnings.append("CLR metadata root is truncated or lacks the BSJB signature.")
            return (file_offset, None, (), (), None, None, (), tuple(warnings))
        version_length = struct.unpack_from("<I", metadata, 12)[0]
        if version_length > config.MAX_DOTNET_VERSION_BYTES:
            warnings.append("CLR metadata version string exceeds the configured bound.")
            return (file_offset, None, (), (), None, None, (), tuple(warnings))
        if 16 + version_length > len(metadata):
            warnings.append("CLR metadata version string is truncated.")
            return (file_offset, None, (), (), None, None, (), tuple(warnings))
        version_bytes = metadata[16:16 + version_length]
        metadata_version = version_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")
        cursor = (16 + version_length + 3) & ~3
        if cursor + 4 > len(metadata):
            warnings.append("CLR metadata stream-count header is truncated.")
            return (file_offset, metadata_version, (), (), None, None, (), tuple(warnings))
        _flags, declared_streams = struct.unpack_from("<HH", metadata, cursor)
        cursor += 4
        stream_count = min(declared_streams, config.MAX_DOTNET_METADATA_STREAMS)
        if declared_streams > config.MAX_DOTNET_METADATA_STREAMS:
            warnings.append(
                "CLR stream parsing stopped at MAX_DOTNET_METADATA_STREAMS "
                f"({config.MAX_DOTNET_METADATA_STREAMS})."
            )
        streams: list[PEDotNetStream] = []
        for index in range(stream_count):
            if cursor + 8 > len(metadata):
                warnings.append("CLR stream-header array is truncated.")
                break
            stream_offset, stream_size = struct.unpack_from("<II", metadata, cursor)
            name_start = cursor + 8
            name_limit = min(
                len(metadata),
                name_start + config.MAX_DOTNET_STREAM_NAME_BYTES,
            )
            name_end = metadata.find(b"\x00", name_start, name_limit)
            if name_end < 0:
                warnings.append(f"CLR stream {index} has no bounded null-terminated name.")
                break
            name = metadata[name_start:name_end].decode("ascii", errors="replace")
            cursor = name_start + ((name_end - name_start + 1 + 3) & ~3)
            stream_file_offset = file_offset + stream_offset
            stream_available = 0
            stream_digest = None
            preview = b""
            stream_warnings: list[str] = []
            if stream_offset > size or stream_file_offset > len(raw_data):
                stream_warnings.append("Stream offset is outside the metadata/file range.")
                mapped_offset = None
            else:
                mapped_offset = stream_file_offset
                metadata_remaining = max(0, size - stream_offset)
                file_remaining = max(0, len(raw_data) - stream_file_offset)
                stream_available = min(stream_size, metadata_remaining, file_remaining)
                payload = raw_data[
                    stream_file_offset:stream_file_offset + stream_available
                ]
                preview = payload[:config.MAX_DOTNET_PREVIEW_BYTES]
                if stream_available == stream_size:
                    stream_digest = hashlib.sha256(payload).hexdigest()
                else:
                    stream_warnings.append("Stream payload is truncated.")
            streams.append(
                PEDotNetStream(
                    index=index,
                    name=name,
                    metadata_offset=stream_offset,
                    size=stream_size,
                    file_offset=mapped_offset,
                    available_size=stream_available,
                    sha256=stream_digest,
                    preview=preview,
                    warnings=tuple(stream_warnings),
                )
            )
        table_stream = next(
            (stream for stream in streams if stream.name in {"#~", "#-"}),
            None,
        )
        string_stream = next(
            (stream for stream in streams if stream.name == "#Strings"),
            None,
        )
        tables, module_name, assembly, references, table_warnings = cls._dotnet_tables(
            raw_data,
            table_stream,
            string_stream,
        )
        warnings.extend(table_warnings)
        return (
            file_offset,
            metadata_version,
            tuple(streams),
            tables,
            module_name,
            assembly,
            references,
            tuple(warnings),
        )

    @classmethod
    def _dotnet_tables(
        cls,
        raw_data: bytes,
        table_stream: PEDotNetStream | None,
        string_stream: PEDotNetStream | None,
    ):
        warnings: list[str] = []
        if table_stream is None or table_stream.file_offset is None:
            return (), None, None, (), tuple(warnings)
        data = raw_data[
            table_stream.file_offset:
            table_stream.file_offset + table_stream.available_size
        ]
        if len(data) < 24:
            warnings.append("Managed metadata tables stream is truncated before its header.")
            return (), None, None, (), tuple(warnings)
        heap_sizes = data[6]
        valid_mask = struct.unpack_from("<Q", data, 8)[0]
        cursor = 24
        row_counts = [0] * 64
        for table_id in range(64):
            if not valid_mask & (1 << table_id):
                continue
            if cursor + 4 > len(data):
                warnings.append("Managed metadata row-count array is truncated.")
                return (), None, None, (), tuple(warnings)
            row_counts[table_id] = struct.unpack_from("<I", data, cursor)[0]
            cursor += 4
        rows_start = cursor
        tables: list[PEDotNetTable] = []
        table_offsets: dict[int, int] = {}
        offsets_known = True
        for table_id, row_count in enumerate(row_counts):
            if not row_count:
                continue
            row_size = cls._dotnet_row_size(table_id, row_counts, heap_sizes)
            file_position = (
                table_stream.file_offset + cursor
                if offsets_known and row_size is not None
                else None
            )
            name = (
                DOTNET_TABLE_NAMES[table_id]
                if table_id < len(DOTNET_TABLE_NAMES)
                else f"Table_{table_id}"
            )
            tables.append(PEDotNetTable(table_id, name, row_count, row_size, file_position))
            if not offsets_known or row_size is None:
                offsets_known = False
                warnings.append(f"Row layout for managed metadata table {name} is unsupported.")
                continue
            span = row_size * row_count
            if cursor + span > len(data):
                warnings.append(f"Managed metadata table {name} is truncated.")
                offsets_known = False
                continue
            table_offsets[table_id] = table_stream.file_offset + cursor
            cursor += span
        if rows_start > len(data):
            warnings.append("Managed metadata table rows begin outside the stream.")
        string_size = 4 if heap_sizes & 0x01 else 2
        module_name = None
        if row_counts[0] and 0 in table_offsets:
            name_index = cls._read_index(raw_data, table_offsets[0] + 2, string_size)
            module_name = cls._dotnet_string(raw_data, string_stream, name_index)
        assembly = None
        if row_counts[32] and 32 in table_offsets:
            offset = table_offsets[32]
            row_size = cls._dotnet_row_size(32, row_counts, heap_sizes)
            if row_size is not None and offset + row_size <= len(raw_data):
                hash_algorithm = struct.unpack_from("<I", raw_data, offset)[0]
                major, minor, build, revision = struct.unpack_from("<4H", raw_data, offset + 4)
                flags = struct.unpack_from("<I", raw_data, offset + 12)[0]
                blob_size = 4 if heap_sizes & 0x04 else 2
                index_offset = offset + 16 + blob_size
                name_index = cls._read_index(raw_data, index_offset, string_size)
                culture_index = cls._read_index(raw_data, index_offset + string_size, string_size)
                assembly = PEDotNetAssemblyIdentity(
                    name=cls._dotnet_string(raw_data, string_stream, name_index) or "<unnamed>",
                    version=f"{major}.{minor}.{build}.{revision}",
                    culture=cls._dotnet_string(raw_data, string_stream, culture_index) or "neutral",
                    flags=flags,
                    hash_algorithm=hash_algorithm,
                )
        references: list[PEDotNetAssemblyReference] = []
        if row_counts[35] and 35 in table_offsets:
            offset = table_offsets[35]
            row_size = cls._dotnet_row_size(35, row_counts, heap_sizes)
            selected = min(row_counts[35], config.MAX_DOTNET_ASSEMBLY_REFERENCES)
            if row_counts[35] > selected:
                warnings.append(
                    "AssemblyRef parsing stopped at MAX_DOTNET_ASSEMBLY_REFERENCES "
                    f"({config.MAX_DOTNET_ASSEMBLY_REFERENCES:,})."
                )
            blob_size = 4 if heap_sizes & 0x04 else 2
            if row_size is not None:
                for index in range(selected):
                    row = offset + index * row_size
                    if row + row_size > len(raw_data):
                        warnings.append("AssemblyRef table is truncated.")
                        break
                    major, minor, build, revision = struct.unpack_from("<4H", raw_data, row)
                    flags = struct.unpack_from("<I", raw_data, row + 8)[0]
                    index_offset = row + 12 + blob_size
                    name_index = cls._read_index(raw_data, index_offset, string_size)
                    culture_index = cls._read_index(raw_data, index_offset + string_size, string_size)
                    references.append(
                        PEDotNetAssemblyReference(
                            index=index,
                            name=cls._dotnet_string(raw_data, string_stream, name_index) or "<unnamed>",
                            version=f"{major}.{minor}.{build}.{revision}",
                            culture=cls._dotnet_string(raw_data, string_stream, culture_index) or "neutral",
                            flags=flags,
                        )
                    )
        return tuple(tables), module_name, assembly, tuple(references), tuple(warnings)

    @staticmethod
    def _read_index(raw_data: bytes, offset: int, size: int) -> int:
        if offset < 0 or offset + size > len(raw_data):
            return 0
        return int.from_bytes(raw_data[offset:offset + size], "little")

    @staticmethod
    def _dotnet_string(
        raw_data: bytes,
        stream: PEDotNetStream | None,
        index: int,
    ) -> str | None:
        if index == 0:
            return ""
        if stream is None or stream.file_offset is None or index >= stream.available_size:
            return None
        start = stream.file_offset + index
        limit = min(
            stream.file_offset + stream.available_size,
            start + config.MAX_DOTNET_STRING_BYTES,
        )
        end = raw_data.find(b"\x00", start, limit)
        if end < 0:
            end = limit
        return raw_data[start:end].decode("utf-8", errors="replace")

    @staticmethod
    def _dotnet_row_size(table_id: int, rows: list[int], heap_sizes: int) -> int | None:
        string = 4 if heap_sizes & 0x01 else 2
        guid = 4 if heap_sizes & 0x02 else 2
        blob = 4 if heap_sizes & 0x04 else 2

        def table(index: int) -> int:
            return 4 if rows[index] >= 0x10000 else 2

        coded_tables = {
            "TypeDefOrRef": (2, (2, 1, 27)),
            "HasConstant": (2, (4, 8, 23)),
            "HasCustomAttribute": (5, (6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43)),
            "HasFieldMarshal": (1, (4, 8)),
            "HasDeclSecurity": (2, (2, 6, 32)),
            "MemberRefParent": (3, (2, 1, 26, 6, 27)),
            "HasSemantics": (1, (20, 23)),
            "MethodDefOrRef": (1, (6, 10)),
            "MemberForwarded": (1, (4, 6)),
            "Implementation": (2, (38, 35, 39)),
            "CustomAttributeType": (3, (6, 10)),
            "ResolutionScope": (2, (0, 26, 35, 1)),
            "TypeOrMethodDef": (1, (2, 6)),
        }

        def coded(name: str) -> int:
            tag_bits, candidates = coded_tables[name]
            threshold = 1 << (16 - tag_bits)
            return 4 if max((rows[index] for index in candidates), default=0) >= threshold else 2

        schemas = {
            0: (2, string, guid, guid, guid),
            1: (coded("ResolutionScope"), string, string),
            2: (4, string, string, coded("TypeDefOrRef"), table(4), table(6)),
            3: (table(4),),
            4: (2, string, blob),
            5: (table(6),),
            6: (4, 2, 2, string, blob, table(8)),
            7: (table(8),),
            8: (2, 2, string),
            9: (table(2), coded("TypeDefOrRef")),
            10: (coded("MemberRefParent"), string, blob),
            11: (2, coded("HasConstant"), blob),
            12: (coded("HasCustomAttribute"), coded("CustomAttributeType"), blob),
            13: (coded("HasFieldMarshal"), blob),
            14: (2, coded("HasDeclSecurity"), blob),
            15: (2, 4, table(2)),
            16: (4, table(4)),
            17: (blob,),
            18: (table(2), table(20)),
            19: (table(20),),
            20: (2, string, coded("TypeDefOrRef")),
            21: (table(2), table(23)),
            22: (table(23),),
            23: (2, string, blob),
            24: (2, table(6), coded("HasSemantics")),
            25: (table(2), coded("MethodDefOrRef"), coded("MethodDefOrRef")),
            26: (string,),
            27: (blob,),
            28: (2, coded("MemberForwarded"), string, table(26)),
            29: (4, table(4)),
            30: (4, 4),
            31: (4,),
            32: (4, 2, 2, 2, 2, 4, blob, string, string),
            33: (4,),
            34: (4, 4, 4),
            35: (2, 2, 2, 2, 4, blob, string, string, blob),
            36: (4, table(35)),
            37: (4, 4, 4, table(35)),
            38: (4, string, blob),
            39: (4, 4, string, string, coded("Implementation")),
            40: (4, 4, string, coded("Implementation")),
            41: (table(2), table(2)),
            42: (2, 2, coded("TypeOrMethodDef"), string),
            43: (coded("MethodDefOrRef"), blob),
            44: (table(42), coded("TypeDefOrRef")),
        }
        schema = schemas.get(table_id)
        return sum(schema) if schema is not None else None

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

    @classmethod
    def _load_configuration(
        cls,
        pe,
        aslr: PEASLRAssessment,
        raw_data: bytes,
    ) -> PELoadConfiguration:
        entry = getattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None)
        structure = getattr(entry, "struct", None)
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        values: dict[str, object] = {}
        fields = []
        warnings = []
        file_offset = None
        if structure is not None:
            try:
                file_offset = int(structure.get_file_offset())
            except (AttributeError, TypeError, ValueError):
                pass
            dumped = structure.dump_dict()
            if file_offset is None:
                field_offsets = [
                    int(metadata["FileOffset"])
                    for metadata in dumped.values()
                    if isinstance(metadata, dict)
                    and metadata.get("FileOffset") is not None
                ]
                if field_offsets:
                    file_offset = min(field_offsets)
                else:
                    warnings.append("Load Configuration file offset is unavailable.")
            for field_name, metadata in dumped.items():
                if field_name == "Structure" or not isinstance(metadata, dict):
                    continue
                value = metadata.get("Value")
                values[str(field_name)] = value
                target_rva = None
                target_file_offset = None
                if (
                    field_name in LOAD_CONFIG_POINTER_FIELDS
                    and isinstance(value, int)
                    and value != 0
                ):
                    if value >= image_base:
                        target_rva = value - image_base
                        try:
                            mapped = int(pe.get_offset_from_rva(target_rva))
                        except (
                            AttributeError,
                            TypeError,
                            ValueError,
                            pefile.PEFormatError,
                        ):
                            mapped = -1
                        if 0 <= mapped <= len(raw_data):
                            target_file_offset = mapped
                    else:
                        warnings.append(
                            f"{field_name} contains nonzero address 0x{value:x} "
                            "below ImageBase."
                        )
                fields.append(
                    PELoadConfigField(
                        name=str(field_name),
                        value=value,
                        file_offset=(
                            int(metadata["FileOffset"])
                            if metadata.get("FileOffset") is not None
                            else None
                        ),
                        size=(
                            int(metadata["Size"])
                            if metadata.get("Size") is not None
                            else None
                        ),
                        target_rva=target_rva,
                        target_file_offset=target_file_offset,
                    )
                )
        else:
            warnings.append("No Load Configuration Directory was parsed.")

        guard_flags = int(values.get("GuardFlags", 0) or 0)
        guard_flag_names = [
            name for mask, name in GUARD_FLAG_NAMES if guard_flags & mask
        ]
        table_stride_extra = (guard_flags & 0xF0000000) >> 28
        if table_stride_extra:
            guard_flag_names.append(
                f"IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_{4 + table_stride_extra}"
            )
        known_guard_mask = 0xF0000000 | sum(mask for mask, _ in GUARD_FLAG_NAMES)
        unknown_guard_flags = guard_flags & ~known_guard_mask
        if unknown_guard_flags:
            guard_flag_names.append(f"UNKNOWN_0x{unknown_guard_flags:x}")
        cfg = cls._cfg_evidence(pe, raw_data, values, guard_flags)
        return PELoadConfiguration(
            file_offset=file_offset,
            declared_size=int(values.get("Size", 0) or 0),
            fields=tuple(fields),
            guard_flags=guard_flags,
            guard_flag_names=tuple(guard_flag_names),
            mitigations=cls._mitigation_findings(pe, aslr, values, guard_flags),
            warnings=tuple(dict.fromkeys(warnings)),
            cfg=cfg,
        )

    @staticmethod
    def _cfg_evidence(
        pe,
        raw_data: bytes,
        values: dict[str, object],
        guard_flags: int,
    ) -> PECFGEvidence:
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        dll_characteristics = int(
            getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0)
        )
        warnings = []

        def number(name: str) -> int:
            value = values.get(name, 0)
            return int(value) if isinstance(value, int) else 0

        def map_va(value: int) -> tuple[int | None, int | None]:
            if not value or value < image_base:
                return None, None
            rva = value - image_base
            try:
                file_offset = int(pe.get_offset_from_rva(rva))
            except (
                AttributeError,
                TypeError,
                ValueError,
                pefile.PEFormatError,
            ):
                return rva, None
            if not 0 <= file_offset < len(raw_data):
                return rva, None
            return rva, file_offset

        header_guard_cf = bool(dll_characteristics & 0x4000)
        instrumented = bool(guard_flags & 0x00000100)
        write_instrumented = bool(guard_flags & 0x00000200)
        table_present = bool(guard_flags & 0x00000400)
        check_pointer = number("GuardCFCheckFunctionPointer")
        dispatch_pointer = number("GuardCFDispatchFunctionPointer")
        table = number("GuardCFFunctionTable")
        count = number("GuardCFFunctionCount")
        check_rva, check_offset = map_va(check_pointer)
        dispatch_rva, dispatch_offset = map_va(dispatch_pointer)
        table_rva, table_offset = map_va(table)
        stride = 4 + ((guard_flags & 0xF0000000) >> 28)

        if header_guard_cf != instrumented:
            warnings.append(
                "Optional Header GUARD_CF and IMAGE_GUARD_CF_INSTRUMENTED disagree."
            )
        if table_present and count and not table:
            warnings.append(
                "GuardFlags declares a GFIDS table and the count is nonzero, but "
                "GuardCFFunctionTable is null."
            )
        if table_present and count and table_offset is None:
            warnings.append("The declared GFIDS table does not map into file bytes.")
        if not table_present and (table or count):
            warnings.append(
                "GuardCFFunctionTable/count is populated without "
                "IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT."
            )
        if instrumented and not check_pointer and not dispatch_pointer:
            warnings.append(
                "CFG instrumentation is declared, but both check and dispatch "
                "pointer slots are null."
            )

        targets = []
        table_complete = count == 0
        if count and table_offset is not None:
            available = max(0, len(raw_data) - table_offset) // stride
            parsed_count = min(count, available, config.MAX_CFG_FUNCTIONS)
            for index in range(parsed_count):
                entry_offset = table_offset + index * stride
                target_rva = struct.unpack_from("<I", raw_data, entry_offset)[0]
                metadata = raw_data[entry_offset + 4:entry_offset + stride]
                flag_names = []
                if metadata:
                    if metadata[0] & 0x01:
                        flag_names.append("IMAGE_GUARD_FLAG_FID_SUPPRESSED")
                    if metadata[0] & 0x02:
                        flag_names.append("IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED")
                    unknown = metadata[0] & ~0x03
                    if unknown:
                        flag_names.append(f"UNKNOWN_0x{unknown:02x}")
                try:
                    target_offset = int(pe.get_offset_from_rva(target_rva))
                except (
                    AttributeError,
                    TypeError,
                    ValueError,
                    pefile.PEFormatError,
                ):
                    target_offset = None
                if target_offset is not None and not 0 <= target_offset < len(raw_data):
                    target_offset = None
                targets.append(
                    PECFGTarget(
                        index=index,
                        entry_file_offset=entry_offset,
                        rva=target_rva,
                        va=image_base + target_rva,
                        file_offset=target_offset,
                        metadata=metadata,
                        flag_names=tuple(flag_names),
                    )
                )
            table_complete = len(targets) == count
            if count > config.MAX_CFG_FUNCTIONS:
                warnings.append(
                    f"GFIDS parsing stopped at MAX_CFG_FUNCTIONS "
                    f"({config.MAX_CFG_FUNCTIONS:,}) of {count:,} declared entries."
                )
            elif available < count:
                warnings.append(
                    f"GFIDS table is truncated: {count:,} entries declared, "
                    f"only {available:,} fit in the analyzed bytes."
                )

        targets_sorted = all(
            left.rva < right.rva for left, right in zip(targets, targets[1:])
        )
        if len(targets) > 1 and not targets_sorted:
            warnings.append("GFIDS target RVAs are not strictly sorted and unique.")

        return PECFGEvidence(
            header_guard_cf=header_guard_cf,
            instrumented=instrumented,
            write_integrity_instrumented=write_instrumented,
            function_table_present=table_present,
            check_function_pointer=check_pointer,
            check_function_rva=check_rva,
            check_function_file_offset=check_offset,
            dispatch_function_pointer=dispatch_pointer,
            dispatch_function_rva=dispatch_rva,
            dispatch_function_file_offset=dispatch_offset,
            function_table=table,
            function_table_rva=table_rva,
            function_table_file_offset=table_offset,
            function_count=count,
            entry_stride=stride,
            targets=tuple(targets),
            targets_sorted=targets_sorted,
            table_complete=table_complete,
            warnings=tuple(dict.fromkeys(warnings)),
        )

    @classmethod
    def _authenticode(cls, pe, raw_data: bytes) -> PEAuthenticode | None:
        directories = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", ())
        if len(directories) <= 4:
            return None
        directory = directories[4]
        table_offset = int(getattr(directory, "VirtualAddress", 0))
        table_size = int(getattr(directory, "Size", 0))
        if not table_offset or not table_size:
            return None

        warnings = []
        declared_end = table_offset + table_size
        table_end = min(declared_end, len(raw_data))
        table_complete = declared_end <= len(raw_data)
        if table_offset < 0 or table_offset >= len(raw_data):
            return PEAuthenticode(
                table_file_offset=table_offset,
                table_size=table_size,
                entries=(),
                table_complete=False,
                warnings=("Certificate Table file offset is outside the analyzed bytes.",),
            )
        if table_offset % 8:
            warnings.append("Certificate Table file offset is not quadword-aligned.")
        if not table_complete:
            warnings.append(
                "Certificate Table extends beyond the analyzed file; evidence is partial."
            )

        entries = []
        cursor = table_offset
        while cursor < table_end and len(entries) < config.MAX_WIN_CERTIFICATE_ENTRIES:
            remaining = table_end - cursor
            if remaining < 8:
                if any(raw_data[cursor:table_end]):
                    warnings.append(
                        f"{remaining} non-padding bytes remain after the last complete "
                        "WIN_CERTIFICATE header."
                    )
                break
            declared_length, revision, certificate_type = struct.unpack_from(
                "<IHH", raw_data, cursor
            )
            if declared_length == 0 and not any(raw_data[cursor:table_end]):
                break
            if declared_length < 8:
                warnings.append(
                    f"WIN_CERTIFICATE at 0x{cursor:x} declares invalid length "
                    f"{declared_length}; traversal stopped."
                )
                table_complete = False
                break

            declared_entry_end = cursor + declared_length
            content_end = min(declared_entry_end, table_end)
            complete = declared_entry_end <= table_end
            content = raw_data[cursor + 8:content_end]
            entry_warnings = []
            if not complete:
                entry_warnings.append(
                    "WIN_CERTIFICATE extends beyond the declared Certificate Table."
                )
                table_complete = False
            details = cls._pkcs7_details(
                pe,
                raw_data,
                content,
                certificate_type,
                entry_warnings,
            )
            entries.append(
                PEWinCertificate(
                    index=len(entries),
                    file_offset=cursor,
                    declared_length=declared_length,
                    aligned_length=(declared_length + 7) & ~7,
                    revision=revision,
                    revision_name=WIN_CERTIFICATE_REVISIONS.get(
                        revision, f"UNKNOWN_REVISION_0x{revision:04x}"
                    ),
                    certificate_type=certificate_type,
                    certificate_type_name=WIN_CERTIFICATE_TYPES.get(
                        certificate_type, f"UNKNOWN_TYPE_0x{certificate_type:04x}"
                    ),
                    content_file_offset=cursor + 8,
                    content_size=len(content),
                    content_sha256=(hashlib.sha256(content).hexdigest() if content else None),
                    complete=complete,
                    pkcs7_content_type=details[0],
                    embedded_digest_algorithm=details[1],
                    embedded_digest=details[2],
                    computed_digest=details[3],
                    digest_matches=details[4],
                    nested_signature_count=details[5],
                    signers=details[6],
                    certificates=details[7],
                    warnings=tuple(dict.fromkeys(entry_warnings)),
                )
            )
            next_cursor = cursor + ((declared_length + 7) & ~7)
            if next_cursor <= cursor:
                table_complete = False
                warnings.append("Certificate traversal made no forward progress.")
                break
            cursor = next_cursor

        if len(entries) == config.MAX_WIN_CERTIFICATE_ENTRIES and cursor < table_end:
            warnings.append(
                f"Certificate traversal stopped at MAX_WIN_CERTIFICATE_ENTRIES "
                f"({config.MAX_WIN_CERTIFICATE_ENTRIES:,})."
            )
            table_complete = False
        return PEAuthenticode(
            table_file_offset=table_offset,
            table_size=table_size,
            entries=tuple(entries),
            table_complete=table_complete,
            warnings=tuple(dict.fromkeys(warnings)),
        )

    @classmethod
    def _pkcs7_details(
        cls,
        pe,
        raw_data: bytes,
        content: bytes,
        certificate_type: int,
        warnings: list[str],
    ) -> tuple[
        str | None,
        str | None,
        str | None,
        str | None,
        bool | None,
        int,
        tuple[PEAuthenticodeSigner, ...],
        tuple[PEEmbeddedCertificate, ...],
    ]:
        empty = (None, None, None, None, None, 0, (), ())
        if certificate_type != 0x0002:
            warnings.append(
                "This WIN_CERTIFICATE is not PKCS#7 SignedData; Authenticode "
                "details were not decoded."
            )
            return empty
        if not HAS_ASN1CRYPTO:
            warnings.append(
                "asn1crypto is unavailable; install project dependencies to decode PKCS#7."
            )
            return empty
        try:
            content_info = cms.ContentInfo.load(content, strict=False)
            content_type = str(content_info["content_type"].native)
            if content_type != "signed_data":
                warnings.append(f"PKCS#7 content type is {content_type}, not signed_data.")
                return (content_type, None, None, None, None, 0, (), ())
            signed_data = content_info["content"]
        except (TypeError, ValueError, KeyError) as exc:
            warnings.append(f"PKCS#7 parsing failed: {exc}")
            return empty

        certificate_models = []
        certificate_objects = []
        try:
            choices = signed_data["certificates"]
            for choice_index, choice in enumerate(choices):
                if choice_index >= config.MAX_PKCS7_CERTIFICATES:
                    break
                if choice.name != "certificate":
                    continue
                certificate = choice.chosen
                constraints = certificate.basic_constraints_value
                is_ca = (
                    bool(constraints.native.get("ca"))
                    if constraints is not None
                    else None
                )
                model = PEEmbeddedCertificate(
                    index=len(certificate_models),
                    subject=certificate.subject.human_friendly,
                    issuer=certificate.issuer.human_friendly,
                    serial_number=f"0x{certificate.serial_number:x}",
                    not_valid_before=certificate.not_valid_before.isoformat(),
                    not_valid_after=certificate.not_valid_after.isoformat(),
                    sha256_fingerprint=certificate.sha256_fingerprint.replace(" ", "").lower(),
                    signature_algorithm=str(certificate.signature_algo),
                    public_key_algorithm=str(certificate.public_key.algorithm),
                    is_ca=is_ca,
                )
                certificate_objects.append(certificate)
                certificate_models.append(model)
            if len(choices) > config.MAX_PKCS7_CERTIFICATES:
                warnings.append(
                    f"Embedded certificate display stopped at "
                    f"MAX_PKCS7_CERTIFICATES ({config.MAX_PKCS7_CERTIFICATES:,})."
                )
        except (TypeError, ValueError, KeyError) as exc:
            warnings.append(f"Embedded X.509 certificate parsing failed: {exc}")

        embedded_algorithm = None
        embedded_digest = None
        computed_digest = None
        digest_matches = None
        signed_content = None
        try:
            encapsulated = signed_data["encap_content_info"]
            if encapsulated["content_type"].dotted == "1.3.6.1.4.1.311.2.1.4":
                signed_content = cls._spc_signed_content(encapsulated["content"])
                embedded_algorithm, embedded_bytes = cls._spc_indirect_digest(
                    encapsulated["content"]
                )
                embedded_digest = embedded_bytes.hex()
                computed = cls._authenticode_image_digest(
                    pe, raw_data, embedded_algorithm
                )
                if computed is not None:
                    computed_digest = computed.hex()
                    digest_matches = computed == embedded_bytes
            else:
                warnings.append(
                    "Encapsulated PKCS#7 content is not SPC_INDIRECT_DATA_CONTENT."
                )
        except (TypeError, ValueError, KeyError, IndexError) as exc:
            warnings.append(f"Embedded Authenticode digest parsing failed: {exc}")

        signer_models = []
        nested_signature_count = 0
        try:
            for index, signer in enumerate(signed_data["signer_infos"]):
                sid = signer["sid"]
                matched_fingerprint = None
                matched_certificate = None
                if sid.name == "issuer_and_serial_number":
                    chosen = sid.chosen
                    serial = int(chosen["serial_number"].native)
                    issuer = chosen["issuer"]
                    identifier = (
                        f"issuer={issuer.human_friendly}; serial=0x{serial:x}"
                    )
                    for certificate, model in zip(
                        certificate_objects, certificate_models
                    ):
                        if certificate.serial_number == serial and certificate.issuer == issuer:
                            matched_fingerprint = model.sha256_fingerprint
                            matched_certificate = certificate
                            break
                else:
                    identifier = f"{sid.name}={sid.native}"

                signing_time = None
                signed_message_digest = None
                signed_message_digest_bytes = None
                for attribute in signer["signed_attrs"]:
                    attribute_type = attribute["type"].native
                    if attribute_type == "signing_time" and attribute["values"]:
                        signing_time = attribute["values"][0].native.isoformat()
                    elif attribute_type == "message_digest" and attribute["values"]:
                        signed_message_digest_bytes = attribute["values"][0].native
                        signed_message_digest = signed_message_digest_bytes.hex()

                content_digest_matches = None
                if signed_content is not None and signed_message_digest_bytes is not None:
                    try:
                        content_digest_matches = (
                            hashlib.new(
                                str(signer["digest_algorithm"]["algorithm"].native),
                                signed_content,
                            ).digest()
                            == signed_message_digest_bytes
                        )
                    except (TypeError, ValueError):
                        pass
                signature_valid, verification_note = cls._verify_pkcs7_signature(
                    matched_certificate,
                    signer,
                )

                timestamp_times = []
                timestamp_present = False
                for attribute in signer["unsigned_attrs"]:
                    dotted = attribute["type"].dotted
                    attribute_type = attribute["type"].native
                    if attribute_type == "microsoft_nested_signature":
                        nested_signature_count += len(attribute["values"])
                    if dotted in {
                        "1.2.840.113549.1.9.6",
                        "1.3.6.1.4.1.311.3.3.1",
                    }:
                        timestamp_present = True
                    if dotted == "1.2.840.113549.1.9.6":
                        for counter_signer in attribute["values"]:
                            for counter_attribute in counter_signer["signed_attrs"]:
                                if (
                                    counter_attribute["type"].native == "signing_time"
                                    and counter_attribute["values"]
                                ):
                                    timestamp_times.append(
                                        counter_attribute["values"][0].native.isoformat()
                                    )

                signer_models.append(
                    PEAuthenticodeSigner(
                        index=index,
                        identifier=identifier,
                        digest_algorithm=str(
                            signer["digest_algorithm"]["algorithm"].native
                        ),
                        signature_algorithm=str(
                            signer["signature_algorithm"]["algorithm"].native
                        ),
                        signing_time=signing_time,
                        timestamp_present=timestamp_present,
                        timestamp_times=tuple(timestamp_times),
                        matched_certificate_sha256=matched_fingerprint,
                        signed_message_digest=signed_message_digest,
                        content_digest_matches=content_digest_matches,
                        signature_valid=signature_valid,
                        verification_note=verification_note,
                    )
                )
        except (TypeError, ValueError, KeyError) as exc:
            warnings.append(f"PKCS#7 signer parsing failed: {exc}")

        warnings.append(
            "Local cryptographic verification does not establish the Windows "
            "trust chain, revocation status, or timestamp-authority trust."
        )
        return (
            content_type,
            embedded_algorithm,
            embedded_digest,
            computed_digest,
            digest_matches,
            nested_signature_count,
            tuple(signer_models),
            tuple(certificate_models),
        )

    @staticmethod
    def _der_tlv(data: bytes, offset: int = 0) -> tuple[int, int, int, int]:
        if offset < 0 or offset + 2 > len(data):
            raise ValueError("truncated DER element")
        tag = data[offset]
        cursor = offset + 1
        length = data[cursor]
        cursor += 1
        if length & 0x80:
            length_octets = length & 0x7F
            if not length_octets or length_octets > 4:
                raise ValueError("unsupported DER length")
            if cursor + length_octets > len(data):
                raise ValueError("truncated DER length")
            length = int.from_bytes(
                data[cursor:cursor + length_octets], "big"
            )
            cursor += length_octets
        end = cursor + length
        if end > len(data):
            raise ValueError("DER element exceeds available bytes")
        return tag, cursor, end, end

    @classmethod
    def _spc_indirect_digest(cls, content) -> tuple[str, bytes]:
        body = cls._spc_signed_content(content)
        _, _, _, digest_info_offset = cls._der_tlv(body)
        digest_info = body[digest_info_offset:]
        tag, start, end, _ = cls._der_tlv(digest_info)
        if tag != 0x30:
            raise ValueError("SPC DigestInfo is not a sequence")
        digest_body = digest_info[start:end]
        _, _, _, algorithm_end = cls._der_tlv(digest_body)
        algorithm = str(
            algos.DigestAlgorithm.load(digest_body[:algorithm_end])[
                "algorithm"
            ].native
        )
        tag, digest_start, digest_end, _ = cls._der_tlv(
            digest_body, algorithm_end
        )
        if tag != 0x04:
            raise ValueError("SPC digest is not an octet string")
        return algorithm, digest_body[digest_start:digest_end]

    @classmethod
    def _spc_signed_content(cls, content) -> bytes:
        wrapped = content.dump()
        tag, start, end, _ = cls._der_tlv(wrapped)
        if tag != 0xA0:
            raise ValueError("SPC content lacks the expected explicit wrapper")
        root = wrapped[start:end]
        tag, start, end, _ = cls._der_tlv(root)
        if tag != 0x30:
            raise ValueError("SPC content is not a DER sequence")
        return root[start:end]

    @staticmethod
    def _verify_pkcs7_signature(certificate, signer) -> tuple[bool | None, str | None]:
        if certificate is None:
            return None, "Signer certificate was not found in the embedded chain."
        if not HAS_CRYPTOGRAPHY:
            return None, "cryptography is unavailable."
        hash_classes = {
            "sha1": hashes.SHA1,
            "sha224": hashes.SHA224,
            "sha256": hashes.SHA256,
            "sha384": hashes.SHA384,
            "sha512": hashes.SHA512,
        }
        digest_name = str(signer["digest_algorithm"]["algorithm"].native)
        hash_class = hash_classes.get(digest_name)
        if hash_class is None:
            return None, f"Unsupported signer digest algorithm: {digest_name}."
        try:
            public_key = crypto_x509.load_der_x509_certificate(
                certificate.dump()
            ).public_key()
            signed_attributes = signer["signed_attrs"].dump()
            if not signed_attributes:
                return None, "Signer has no signed attributes."
            signed_attributes = b"\x31" + signed_attributes[1:]
            signature = signer["signature"].native
            signature_algorithm = str(
                signer["signature_algorithm"]["algorithm"].native
            )
            if isinstance(public_key, rsa.RSAPublicKey):
                if signature_algorithm not in {
                    "rsassa_pkcs1v15",
                    "sha1_rsa",
                    "sha224_rsa",
                    "sha256_rsa",
                    "sha384_rsa",
                    "sha512_rsa",
                }:
                    return None, (
                        f"Unsupported RSA signature parameters: {signature_algorithm}."
                    )
                public_key.verify(
                    signature,
                    signed_attributes,
                    padding.PKCS1v15(),
                    hash_class(),
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature,
                    signed_attributes,
                    ec.ECDSA(hash_class()),
                )
            elif isinstance(public_key, dsa.DSAPublicKey):
                public_key.verify(signature, signed_attributes, hash_class())
            else:
                return None, (
                    f"Unsupported signer public-key type: "
                    f"{type(public_key).__name__}."
                )
        except InvalidSignature:
            return False, "PKCS#7 signer signature did not verify."
        except (TypeError, ValueError, KeyError) as exc:
            return None, f"PKCS#7 signature verification unavailable: {exc}"
        return True, "PKCS#7 signer signature verified cryptographically."

    @staticmethod
    def _authenticode_image_digest(
        pe,
        raw_data: bytes,
        algorithm: str,
    ) -> bytes | None:
        try:
            digest = hashlib.new(algorithm)
            optional_fields = pe.OPTIONAL_HEADER.dump_dict()
            checksum_offset = int(optional_fields["CheckSum"]["FileOffset"])
            security_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            security_entry_offset = int(security_directory.get_file_offset())
            size_of_headers = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
        except (AttributeError, KeyError, TypeError, ValueError):
            return None
        if not (
            0 <= checksum_offset
            and checksum_offset + 4 <= security_entry_offset
            and security_entry_offset + 8 <= size_of_headers <= len(raw_data)
        ):
            return None
        digest.update(raw_data[:checksum_offset])
        digest.update(raw_data[checksum_offset + 4:security_entry_offset])
        digest.update(raw_data[security_entry_offset + 8:size_of_headers])
        previous_end = size_of_headers
        for section in sorted(
            pe.sections,
            key=lambda item: int(item.PointerToRawData),
        ):
            start = int(section.PointerToRawData)
            end = start + int(section.SizeOfRawData)
            if start < previous_end or end < start or end > len(raw_data):
                return None
            digest.update(raw_data[start:end])
            previous_end = end
        return digest.digest()

    @staticmethod
    def _mitigation_findings(
        pe,
        aslr: PEASLRAssessment,
        values: dict[str, object],
        guard_flags: int,
    ) -> tuple[PEMitigationFinding, ...]:
        dll_characteristics = int(
            getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0)
        )
        is_pe32_plus = int(getattr(pe.OPTIONAL_HEADER, "Magic", 0)) == 0x20B

        def number(name: str) -> int:
            value = values.get(name, 0)
            return int(value) if isinstance(value, int) else 0

        if aslr.dynamic_base and aslr.usable_entries and not aslr.relocations_stripped:
            aslr_status = "structurally compatible"
        elif aslr.dynamic_base:
            aslr_status = "inconsistent or incomplete"
        else:
            aslr_status = "not declared"

        guard_cf_header = bool(dll_characteristics & 0x4000)
        guard_cf_instrumented = bool(guard_flags & 0x00000100)
        guard_cf_table_declared = bool(guard_flags & 0x00000400)
        guard_cf_table = guard_cf_table_declared and bool(
            (
                number("GuardCFFunctionTable")
                and number("GuardCFFunctionCount")
            )
            or (
                not number("GuardCFFunctionTable")
                and not number("GuardCFFunctionCount")
            )
        )
        if guard_cf_header and guard_cf_instrumented and guard_cf_table:
            cfg_status = "present"
        elif guard_cf_header or guard_cf_instrumented or guard_cf_table:
            cfg_status = "inconsistent or partial"
        else:
            cfg_status = "not indicated"

        security_cookie = number("SecurityCookie")
        cookie_unused = bool(guard_flags & 0x00000800)
        if cookie_unused:
            cookie_status = "explicitly unused"
        elif security_cookie:
            cookie_status = "cookie present"
        else:
            cookie_status = "not indicated"

        no_seh = bool(dll_characteristics & 0x0400)
        if is_pe32_plus:
            safe_seh_status = "not applicable to x64"
        elif no_seh:
            safe_seh_status = "SEH disabled by NO_SEH"
        elif number("SEHandlerTable") and number("SEHandlerCount"):
            safe_seh_status = "table present"
        else:
            safe_seh_status = "not indicated"

        return (
            PEMitigationFinding("ASLR", aslr_status, (aslr.status,)),
            PEMitigationFinding(
                "High-entropy ASLR",
                (
                    "declared"
                    if is_pe32_plus and dll_characteristics & 0x0020
                    else "not indicated"
                ),
                ("Requires PE32+, DYNAMIC_BASE, and loader support.",),
            ),
            PEMitigationFinding(
                "DEP / NX",
                "declared" if dll_characteristics & 0x0100 else "not indicated",
                ("Derived from IMAGE_DLLCHARACTERISTICS_NX_COMPAT.",),
            ),
            PEMitigationFinding(
                "Control Flow Guard",
                cfg_status,
                (
                    f"GUARD_CF header bit: {'set' if guard_cf_header else 'not set'}",
                    (
                        "Load-config instrumentation/table evidence: "
                        f"instrumented={guard_cf_instrumented}, "
                        f"table-flag={guard_cf_table_declared}, "
                        f"table-coherent={guard_cf_table}, "
                        f"targets={number('GuardCFFunctionCount')}"
                    ),
                ),
            ),
            PEMitigationFinding(
                "Stack security cookie (/GS)",
                cookie_status,
                (
                    f"SecurityCookie address: 0x{security_cookie:x}",
                    "Cookie presence does not prove every function was instrumented.",
                ),
            ),
            PEMitigationFinding(
                "SafeSEH",
                safe_seh_status,
                (
                    f"SEHandlerTable=0x{number('SEHandlerTable'):x}, "
                    f"SEHandlerCount={number('SEHandlerCount')}",
                ),
            ),
            PEMitigationFinding(
                "Return Flow Guard",
                "declared" if guard_flags & 0x00060000 else "not indicated",
                ("Derived from RF_INSTRUMENTED / RF_ENABLE GuardFlags.",),
            ),
            PEMitigationFinding(
                "EH continuation guard",
                (
                    "table present"
                    if guard_flags & 0x00400000
                    and number("GuardEHContinuationTable")
                    and number("GuardEHContinuationCount")
                    else "not indicated"
                ),
                ("Protects valid exception-continuation targets when supported.",),
            ),
            PEMitigationFinding(
                "Extended Flow Guard (XFG)",
                "declared" if guard_flags & 0x00800000 else "not indicated",
                ("Derived from IMAGE_GUARD_XFG_ENABLED.",),
            ),
            PEMitigationFinding(
                "Retpoline",
                "declared" if guard_flags & 0x00100000 else "not indicated",
                ("Derived from IMAGE_GUARD_RETPOLINE_PRESENT.",),
            ),
            PEMitigationFinding(
                "Code integrity",
                "declared" if dll_characteristics & 0x0080 else "not indicated",
                ("Derived from IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY.",),
            ),
            PEMitigationFinding(
                "AppContainer",
                "declared" if dll_characteristics & 0x1000 else "not indicated",
                ("Derived from IMAGE_DLLCHARACTERISTICS_APPCONTAINER.",),
            ),
        )

    @staticmethod
    def _tls(
        pe,
        raw_data: bytes,
    ) -> tuple[PETLSDirectory | None, bool]:
        tls_entry = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
        structure = getattr(tls_entry, "struct", None)
        if structure is None:
            return None, False

        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        is_pe32_plus = int(getattr(pe.OPTIONAL_HEADER, "Magic", 0)) == 0x20B
        pointer_size = 8 if is_pe32_plus else 4
        warnings = []
        truncated = False

        def va_to_rva(address: int) -> int | None:
            if address == 0 or address < image_base:
                return None
            return address - image_base

        def mapped_offset(rva: int | None) -> int | None:
            if rva is None:
                return None
            try:
                offset = int(pe.get_offset_from_rva(rva))
            except (AttributeError, TypeError, ValueError, pefile.PEFormatError):
                return None
            return offset if 0 <= offset <= len(raw_data) else None

        start_address = int(getattr(structure, "StartAddressOfRawData", 0))
        end_address = int(getattr(structure, "EndAddressOfRawData", 0))
        if end_address < start_address:
            raw_data_size = 0
            warnings.append("EndAddressOfRawData precedes StartAddressOfRawData.")
        else:
            raw_data_size = end_address - start_address
        raw_data_rva = va_to_rva(start_address)
        raw_data_file_offset = mapped_offset(raw_data_rva)
        raw_data_available_size = 0
        raw_data_preview = b""
        raw_data_sha256 = None
        if raw_data_file_offset is not None:
            raw_data_available_size = min(
                raw_data_size,
                len(raw_data) - raw_data_file_offset,
            )
            view = memoryview(raw_data)[
                raw_data_file_offset:raw_data_file_offset + raw_data_available_size
            ]
            raw_data_preview = bytes(view[:config.MAX_TLS_PREVIEW_BYTES])
            if raw_data_available_size == raw_data_size:
                raw_data_sha256 = hashlib.sha256(view).hexdigest()
            else:
                warnings.append("TLS template data extends beyond the analyzed file.")
        elif raw_data_size:
            warnings.append("TLS template-data VA could not be mapped to the file.")

        address_of_index = int(getattr(structure, "AddressOfIndex", 0))
        index_rva = va_to_rva(address_of_index)
        index_file_offset = mapped_offset(index_rva)
        address_of_callbacks = int(getattr(structure, "AddressOfCallBacks", 0))
        callbacks_rva = va_to_rva(address_of_callbacks)
        callbacks_file_offset = mapped_offset(callbacks_rva)
        callbacks = []
        callbacks_terminated = False
        if address_of_callbacks and callbacks_file_offset is None:
            warnings.append("TLS callback-table VA could not be mapped to the file.")
        elif callbacks_file_offset is not None:
            for index in range(config.MAX_TLS_CALLBACKS):
                entry_offset = callbacks_file_offset + index * pointer_size
                entry_end = entry_offset + pointer_size
                if entry_end > len(raw_data):
                    warnings.append("TLS callback table extends beyond the analyzed file.")
                    truncated = True
                    break
                callback_address = int.from_bytes(
                    raw_data[entry_offset:entry_end],
                    "little",
                )
                if callback_address == 0:
                    callbacks_terminated = True
                    break
                callback_rva = va_to_rva(callback_address)
                callbacks.append(
                    PETLSCallback(
                        index=index,
                        table_entry_file_offset=entry_offset,
                        address=callback_address,
                        rva=callback_rva,
                        file_offset=mapped_offset(callback_rva),
                    )
                )
            else:
                warnings.append(
                    "TLS callback traversal reached MAX_TLS_CALLBACKS without a "
                    "null terminator."
                )
                truncated = True

        return (
            PETLSDirectory(
                file_offset=int(structure.get_file_offset()),
                is_pe32_plus=is_pe32_plus,
                start_address_of_raw_data=start_address,
                end_address_of_raw_data=end_address,
                raw_data_rva=raw_data_rva,
                raw_data_file_offset=raw_data_file_offset,
                raw_data_size=raw_data_size,
                raw_data_available_size=raw_data_available_size,
                raw_data_sha256=raw_data_sha256,
                raw_data_preview=raw_data_preview,
                address_of_index=address_of_index,
                index_rva=index_rva,
                index_file_offset=index_file_offset,
                address_of_callbacks=address_of_callbacks,
                callbacks_rva=callbacks_rva,
                callbacks_file_offset=callbacks_file_offset,
                size_of_zero_fill=int(getattr(structure, "SizeOfZeroFill", 0)),
                characteristics=int(getattr(structure, "Characteristics", 0)),
                callbacks=tuple(callbacks),
                callbacks_terminated=callbacks_terminated,
                warnings=tuple(warnings),
            ),
            truncated,
        )

    @classmethod
    def _exceptions(
        cls,
        pe,
        raw_data: bytes,
    ) -> tuple[PEExceptionDirectory | None, bool]:
        source = list(getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", ()))
        machine = int(getattr(pe.FILE_HEADER, "Machine", 0))
        is_x64 = machine == 0x8664
        directories = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", ())
        exception_directory = directories[3] if len(directories) > 3 else None
        directory_present = bool(
            int(getattr(exception_directory, "VirtualAddress", 0))
            and int(getattr(exception_directory, "Size", 0))
        )
        if not source and not directory_present:
            return None, False

        truncated = len(source) > config.MAX_RUNTIME_FUNCTIONS
        warnings = []
        if directory_present and not source:
            warnings.append(
                "The Exception Directory is present but no runtime-function "
                "records were parsed."
            )
        if not is_x64 and source:
            warnings.append(
                "Runtime-function records are shown, but x64 UNWIND_INFO decoding "
                "does not apply to this machine type."
            )
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        functions = []
        for index, entry in enumerate(source[:config.MAX_RUNTIME_FUNCTIONS]):
            structure = getattr(entry, "struct", entry)
            begin_address = int(getattr(structure, "BeginAddress", 0))
            end_address = int(getattr(structure, "EndAddress", 0))
            unwind_data = int(
                getattr(
                    structure,
                    "UnwindData",
                    getattr(structure, "UnwindInfoAddress", 0),
                )
            )
            try:
                file_offset = int(structure.get_file_offset())
            except (AttributeError, TypeError, ValueError):
                file_offset = -1
            unwind_info = None
            if is_x64 and unwind_data:
                unwind_info = cls._unwind_info(pe, raw_data, unwind_data)
                if unwind_info is None:
                    warnings.append(
                        f"Runtime function {index} references unmapped UNWIND_INFO "
                        f"RVA 0x{unwind_data:08x}."
                    )
            if end_address < begin_address:
                warnings.append(
                    f"Runtime function {index} has EndAddress before BeginAddress."
                )
            functions.append(
                PERuntimeFunction(
                    index=index,
                    file_offset=file_offset,
                    begin_address=begin_address,
                    end_address=end_address,
                    begin_va=image_base + begin_address,
                    end_va=image_base + end_address,
                    unwind_data=unwind_data,
                    unwind_info=unwind_info,
                )
            )
        if truncated:
            warnings.append(
                "Runtime-function parsing reached MAX_RUNTIME_FUNCTIONS; records are partial."
            )
        return (
            PEExceptionDirectory(
                machine=machine,
                is_x64=is_x64,
                functions=tuple(functions),
                warnings=tuple(warnings),
            ),
            truncated,
        )

    @classmethod
    def _unwind_info(cls, pe, raw_data: bytes, rva: int) -> PEUnwindInfo | None:
        try:
            file_offset = int(pe.get_offset_from_rva(rva))
        except (AttributeError, TypeError, ValueError, pefile.PEFormatError):
            return None
        if file_offset < 0 or file_offset + 4 > len(raw_data):
            return None

        version_and_flags = raw_data[file_offset]
        version = version_and_flags & 0x07
        flags = version_and_flags >> 3
        size_of_prolog = raw_data[file_offset + 1]
        count_of_codes = raw_data[file_offset + 2]
        frame = raw_data[file_offset + 3]
        frame_register = frame & 0x0F
        frame_offset = (frame >> 4) * 16
        frame_register_name = (
            UNWIND_REGISTER_NAMES[frame_register] if frame_register else "none"
        )
        warnings = []
        codes_end = file_offset + 4 + count_of_codes * 2
        available_slots = count_of_codes
        if codes_end > len(raw_data):
            available_slots = max(0, (len(raw_data) - file_offset - 4) // 2)
            warnings.append("UNWIND_CODE array extends beyond the analyzed file.")
        codes = cls._unwind_codes(
            raw_data,
            file_offset + 4,
            available_slots,
            warnings,
        )

        flag_names = []
        if flags & 0x01:
            flag_names.append("UNW_FLAG_EHANDLER")
        if flags & 0x02:
            flag_names.append("UNW_FLAG_UHANDLER")
        if flags & 0x04:
            flag_names.append("UNW_FLAG_CHAININFO")
        unknown_flags = flags & ~0x07
        if unknown_flags:
            flag_names.append(f"UNKNOWN_0x{unknown_flags:x}")
        if not flag_names:
            flag_names.append("UNW_FLAG_NHANDLER")

        exception_handler_rva = None
        exception_handler_file_offset = None
        language_data_file_offset = None
        chained_function = None
        optional_offset = file_offset + 4 + ((count_of_codes + 1) & ~1) * 2
        if codes_end <= len(raw_data):
            if flags & 0x04:
                if flags & 0x03:
                    warnings.append(
                        "UNW_FLAG_CHAININFO is combined with a handler flag, which "
                        "is invalid for x64 UNWIND_INFO."
                    )
                if optional_offset + 12 <= len(raw_data):
                    chained_function = struct.unpack_from("<III", raw_data, optional_offset)
                else:
                    warnings.append("Chained RUNTIME_FUNCTION extends beyond the file.")
            elif flags & 0x03:
                if optional_offset + 4 <= len(raw_data):
                    exception_handler_rva = struct.unpack_from(
                        "<I",
                        raw_data,
                        optional_offset,
                    )[0]
                    language_data_file_offset = optional_offset + 4
                    try:
                        exception_handler_file_offset = int(
                            pe.get_offset_from_rva(exception_handler_rva)
                        )
                    except (
                        AttributeError,
                        TypeError,
                        ValueError,
                        pefile.PEFormatError,
                    ):
                        warnings.append("Exception-handler RVA could not be mapped.")
                else:
                    warnings.append("Exception-handler RVA extends beyond the file.")
        if version not in (1, 2):
            warnings.append(f"Unexpected UNWIND_INFO version {version}.")

        return PEUnwindInfo(
            rva=rva,
            file_offset=file_offset,
            version=version,
            flags=flags,
            flag_names=tuple(flag_names),
            size_of_prolog=size_of_prolog,
            count_of_codes=count_of_codes,
            frame_register=frame_register,
            frame_register_name=frame_register_name,
            frame_offset=frame_offset,
            codes=codes,
            exception_handler_rva=exception_handler_rva,
            exception_handler_file_offset=exception_handler_file_offset,
            language_data_file_offset=language_data_file_offset,
            chained_function=chained_function,
            warnings=tuple(warnings),
        )

    @staticmethod
    def _unwind_codes(
        raw_data: bytes,
        codes_offset: int,
        slot_count: int,
        warnings: list[str],
    ) -> tuple[PEUnwindCode, ...]:
        records = []
        slot = 0
        while slot < slot_count:
            offset = codes_offset + slot * 2
            code_offset = raw_data[offset]
            operation_byte = raw_data[offset + 1]
            unwind_op = operation_byte & 0x0F
            op_info = operation_byte >> 4
            op_name = UNWIND_OPERATION_NAMES.get(unwind_op, f"UWOP_UNKNOWN_{unwind_op}")
            slots_used, description = PEStructureAnalyzer._describe_unwind_operation(
                raw_data,
                codes_offset,
                slot,
                slot_count,
                unwind_op,
                op_info,
            )
            if slot + slots_used > slot_count:
                warnings.append(
                    f"{op_name} at unwind slot {slot} requires {slots_used} slots, "
                    "but the array ends early."
                )
                slots_used = 1
                description = "truncated operation payload"
            records.append(
                PEUnwindCode(
                    slot_index=slot,
                    code_offset=code_offset,
                    unwind_op=unwind_op,
                    op_info=op_info,
                    op_name=op_name,
                    slots_used=slots_used,
                    description=description,
                )
            )
            slot += slots_used
        return tuple(records)

    @staticmethod
    def _describe_unwind_operation(
        raw_data: bytes,
        codes_offset: int,
        slot: int,
        slot_count: int,
        unwind_op: int,
        op_info: int,
    ) -> tuple[int, str]:
        register = UNWIND_REGISTER_NAMES[op_info]

        def word(extra_slot: int) -> int:
            if slot + extra_slot >= slot_count:
                return 0
            return struct.unpack_from(
                "<H",
                raw_data,
                codes_offset + (slot + extra_slot) * 2,
            )[0]

        if unwind_op == 0:
            return 1, f"push nonvolatile register {register}"
        if unwind_op == 1:
            if op_info == 0:
                return 2, f"allocate {word(1) * 8} bytes"
            if op_info == 1:
                size = word(1) | (word(2) << 16)
                return 3, f"allocate {size} bytes"
            return 1, f"invalid UWOP_ALLOC_LARGE OpInfo {op_info}"
        if unwind_op == 2:
            return 1, f"allocate {op_info * 8 + 8} bytes"
        if unwind_op == 3:
            return 1, "establish frame pointer"
        if unwind_op == 4:
            return 2, f"save {register} at stack offset {word(1) * 8}"
        if unwind_op == 5:
            offset = word(1) | (word(2) << 16)
            return 3, f"save {register} at far stack offset {offset}"
        if unwind_op == 6:
            return 1, f"epilogue marker (OpInfo {op_info})"
        if unwind_op == 7:
            return 1, "reserved/spare unwind operation"
        if unwind_op == 8:
            return 2, f"save XMM{op_info} at stack offset {word(1) * 16}"
        if unwind_op == 9:
            offset = word(1) | (word(2) << 16)
            return 3, f"save XMM{op_info} at far stack offset {offset}"
        if unwind_op == 10:
            error_code = "with error code" if op_info else "without error code"
            return 1, f"push machine frame {error_code}"
        return 1, f"unknown unwind operation (OpInfo {op_info})"

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
