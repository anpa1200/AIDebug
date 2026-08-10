import asyncio
import hashlib
import struct
import uuid
from dataclasses import replace
from types import SimpleNamespace

from textual.app import App

from analysis import pe_structure
from analysis.pe_structure import (
    PEASLRAssessment,
    PEAuthenticode,
    PEAuthenticodeSigner,
    PEBaseRelocationBlock,
    PEBaseRelocationEntry,
    PECFGEvidence,
    PECFGTarget,
    PEDataDirectory,
    PEDebugDirectory,
    PEDebugRecord,
    PEDelayImportDescriptorRecord,
    PEDotNetAssemblyIdentity,
    PEDotNetAssemblyReference,
    PEDotNetHeader,
    PEDotNetStream,
    PEDotNetTable,
    PEEmbeddedCertificate,
    PEExceptionDirectory,
    PEExportRecord,
    PEHeader,
    PEHeaderField,
    PEImportDescriptorRecord,
    PEImportRecord,
    PELoadConfigField,
    PELoadConfiguration,
    PEMitigationFinding,
    PEOverlay,
    PEResourceDataRecord,
    PEResourceDirectoryRecord,
    PERichEntry,
    PERichHeader,
    PERuntimeFunction,
    PESectionRecord,
    PEStructure,
    PEStructureAnalyzer,
    PETLSCallback,
    PETLSDirectory,
    PEUnwindCode,
    PEUnwindInfo,
    PEWinCertificate,
    decode_coff_characteristics,
    decode_dll_characteristics,
    decode_section_characteristics,
    dll_mitigation_clues,
    page_count,
    render_hex_page,
)
from ui.pe_tui import (
    CertificatePayloadScreen,
    EvidencePayloadScreen,
    PEStructureScreen,
    ResourcePayloadScreen,
    certificate_filename,
    certificate_payload,
    debug_payload,
    dotnet_stream_payload,
    export_certificate,
    export_debug_payload,
    export_dotnet_stream,
    export_overlay,
    export_resource,
    overlay_payload,
    resource_filename,
    resource_payload,
)


class FakeStructure:
    def __init__(self, name, offset, values):
        self._name = name
        self._offset = offset
        self._values = values
        for name, value in values.items():
            setattr(self, name, value)

    def dump_dict(self):
        result = {"Structure": self._name}
        for index, (name, value) in enumerate(self._values.items()):
            result[name] = {
                "FileOffset": self._offset + index * 4,
                "Offset": index * 4,
                "Size": 4,
                "Value": value,
            }
        return result


class FakeSection:
    Name = b".text\x00\x00\x00"
    VirtualAddress = 0x1000
    Misc_VirtualSize = 0x222
    PointerToRawData = 0x400
    SizeOfRawData = 0x400
    PointerToRelocations = 0x1234
    PointerToLinenumbers = 0x5678
    NumberOfRelocations = 3
    NumberOfLinenumbers = 4
    Characteristics = 0x60000020

    @staticmethod
    def get_entropy():
        return 6.25

    @staticmethod
    def get_file_offset():
        return 0x188


class FakeImportDescriptor:
    OriginalFirstThunk = 0x3000
    TimeDateStamp = 0x12345678
    ForwarderChain = 0
    Name = 0x3500
    FirstThunk = 0x4000

    @staticmethod
    def get_file_offset():
        return 0x200


class FakeDelayImportDescriptor:
    @staticmethod
    def get_file_offset():
        return 0x240


class FakeResourceDirectoryHeader:
    Characteristics = 0
    TimeDateStamp = 0x12345678
    MajorVersion = 1
    MinorVersion = 2

    def __init__(self, offset, named_entries, id_entries):
        self._offset = offset
        self.NumberOfNamedEntries = named_entries
        self.NumberOfIdEntries = id_entries

    def get_file_offset(self):
        return self._offset


class FakeResourceDataEntry:
    OffsetToData = 0x6000
    Size = 25
    CodePage = 65001
    Reserved = 0

    @staticmethod
    def get_file_offset():
        return 0x2E0


class FakeBaseRelocationStructure:
    VirtualAddress = 0x1000
    SizeOfBlock = 12

    @staticmethod
    def get_file_offset():
        return 0x340


class FakeRelocationEntryStructure:
    def __init__(self, offset):
        self.offset = offset

    def get_file_offset(self):
        return self.offset


class FakeTLSStructure:
    StartAddressOfRawData = 0x140006200
    EndAddressOfRawData = 0x140006210
    AddressOfIndex = 0x140006380
    AddressOfCallBacks = 0x140006300
    SizeOfZeroFill = 8
    Characteristics = 0x00300000

    @staticmethod
    def get_file_offset():
        return 0x360


class FakeRuntimeFunctionStructure:
    BeginAddress = 0x1100
    EndAddress = 0x1150
    UnwindData = 0x6400

    @staticmethod
    def get_file_offset():
        return 0x400


class FakePE:
    closed = False

    def __init__(self):
        self.DOS_HEADER = FakeStructure("IMAGE_DOS_HEADER", 0, {"e_magic": 0x5A4D})
        self.DOS_HEADER.e_lfanew = 0x80
        self.NT_HEADERS = SimpleNamespace(Signature=0x4550)
        self.FILE_HEADER = FakeStructure(
            "IMAGE_FILE_HEADER",
            0x84,
            {
                "Machine": 0x8664,
                "NumberOfSections": 1,
                "Characteristics": 0x3123,
            },
        )
        self.OPTIONAL_HEADER = FakeStructure(
            "IMAGE_OPTIONAL_HEADER64",
            0x98,
            {"Magic": 0x20B, "DllCharacteristics": 0x41E0},
        )
        self.OPTIONAL_HEADER.Magic = 0x20B
        self.OPTIONAL_HEADER.ImageBase = 0x140000000
        self.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1010
        self.OPTIONAL_HEADER.DATA_DIRECTORY = [
            SimpleNamespace(VirtualAddress=0x3000, Size=0x80),
            SimpleNamespace(VirtualAddress=0x4000, Size=0x90),
            SimpleNamespace(VirtualAddress=0x5000, Size=0xA0),
            SimpleNamespace(VirtualAddress=0x9000, Size=12),
            SimpleNamespace(VirtualAddress=0, Size=0),
            SimpleNamespace(VirtualAddress=0x7000, Size=0x0C),
            SimpleNamespace(VirtualAddress=0, Size=0),
            SimpleNamespace(VirtualAddress=0, Size=0),
            SimpleNamespace(VirtualAddress=0, Size=0),
            SimpleNamespace(VirtualAddress=0x8000, Size=0x28),
            SimpleNamespace(VirtualAddress=0xA000, Size=0x140),
        ]
        self.sections = [FakeSection()]
        imported = SimpleNamespace(
            name=b"CreateFileW", ordinal=None, hint=120, address=0x140004000
        )
        delayed = SimpleNamespace(
            name=None, ordinal=7, hint=None, address=0x140004008
        )
        self.DIRECTORY_ENTRY_IMPORT = [
            SimpleNamespace(
                dll=b"KERNEL32.dll",
                imports=[imported],
                struct=FakeImportDescriptor(),
            )
        ]
        self.DIRECTORY_ENTRY_DELAY_IMPORT = [
            SimpleNamespace(
                dll=b"DELAY.dll",
                imports=[delayed],
                struct=FakeDelayImportDescriptor(),
            )
        ]
        language_entry = SimpleNamespace(
            name=None,
            id=1033,
            data=SimpleNamespace(struct=FakeResourceDataEntry()),
        )
        language_directory = SimpleNamespace(
            struct=FakeResourceDirectoryHeader(0x2C0, 0, 1),
            entries=[language_entry],
        )
        name_entry = SimpleNamespace(
            name=None,
            id=1,
            directory=language_directory,
        )
        name_directory = SimpleNamespace(
            struct=FakeResourceDirectoryHeader(0x2A0, 0, 1),
            entries=[name_entry],
        )
        type_entry = SimpleNamespace(name=None, id=24, directory=name_directory)
        self.DIRECTORY_ENTRY_RESOURCE = SimpleNamespace(
            struct=FakeResourceDirectoryHeader(0x280, 0, 1),
            entries=[type_entry],
        )
        self.DIRECTORY_ENTRY_BASERELOC = [
            SimpleNamespace(
                struct=FakeBaseRelocationStructure(),
                entries=[
                    SimpleNamespace(
                        type=3,
                        rva=0x1010,
                        struct=FakeRelocationEntryStructure(0x348),
                    ),
                    SimpleNamespace(
                        type=0,
                        rva=0x1000,
                        struct=FakeRelocationEntryStructure(0x34A),
                    ),
                ],
            )
        ]
        self.DIRECTORY_ENTRY_TLS = SimpleNamespace(struct=FakeTLSStructure())
        self.DIRECTORY_ENTRY_EXCEPTION = [
            SimpleNamespace(struct=FakeRuntimeFunctionStructure())
        ]
        self.DIRECTORY_ENTRY_LOAD_CONFIG = SimpleNamespace(
            struct=FakeStructure(
                "IMAGE_LOAD_CONFIG_DIRECTORY64",
                0x580,
                {
                    "Size": 0x140,
                    "TimeDateStamp": 0x12345678,
                    "SecurityCookie": 0x140006500,
                    "GuardCFCheckFunctionPointer": 0x140006510,
                    "GuardCFFunctionTable": 0x140006600,
                    "GuardCFFunctionCount": 3,
                    "GuardFlags": 0x00C00500,
                    "GuardEHContinuationTable": 0x140006700,
                    "GuardEHContinuationCount": 2,
                    "GuardXFGCheckFunctionPointer": 0x140006800,
                },
            )
        )
        exported = SimpleNamespace(
            name=b"Run", ordinal=1, address=0x1100, forwarder=b"OTHER.Target"
        )
        self.DIRECTORY_ENTRY_EXPORT = SimpleNamespace(symbols=[exported])

    @staticmethod
    def get_overlay_data_start_offset():
        return 0x800

    @staticmethod
    def get_offset_from_rva(rva):
        offsets = {
            0x6000: 0x300,
            0x6200: 0x380,
            0x6300: 0x3A0,
            0x6380: 0x3C0,
            0x1010: 0x410,
            0x1200: 0x500,
            0x6400: 0x440,
            0x6500: 0x520,
            0x6510: 0x530,
            0x6600: 0x540,
            0x6700: 0x560,
            0x6800: 0x570,
        }
        if rva in offsets:
            return offsets[rva]
        raise pe_structure.pefile.PEFormatError("unmapped test RVA")

    def close(self):
        self.closed = True


def _model(raw_data=None):
    raw_data_buffer = bytearray(
        raw_data if raw_data is not None else bytes(range(256)) * 20
    )
    resource_bytes = b"<assembly>safe</assembly>"
    raw_data_buffer[0x300:0x300 + len(resource_bytes)] = resource_bytes
    tls_template = b"TLS-DATA-1234567"
    raw_data_buffer[0x380:0x390] = tls_template
    struct.pack_into("<QQ", raw_data_buffer, 0x3A0, 0x140001010, 0)
    raw_data_buffer[0x440:0x448] = bytes((0x09, 8, 2, 5, 8, 0x32, 4, 0x50))
    struct.pack_into("<I", raw_data_buffer, 0x448, 0x1200)
    struct.pack_into("<III", raw_data_buffer, 0x540, 0x1010, 0x1200, 0x6500)
    certificate_content = b"PKCS7"
    raw_data_buffer[0x608:0x608 + len(certificate_content)] = certificate_content
    raw_data = bytes(raw_data_buffer)
    return PEStructure(
        filename="sample.exe",
        sha256="a" * 64,
        file_size=len(raw_data),
        arch="x86-64",
        bits=64,
        image_base=0x140000000,
        entry_point=0x140001010,
        headers=(
            PEHeader("DOS header", (PEHeaderField("e_magic", 0x5A4D, 0, 2),)),
            PEHeader(
                "COFF file header",
                (
                    PEHeaderField(
                        "Characteristics",
                        0x2022,
                        0x96,
                        2,
                        (
                            "IMAGE_FILE_EXECUTABLE_IMAGE",
                            "IMAGE_FILE_LARGE_ADDRESS_AWARE",
                            "IMAGE_FILE_DLL",
                        ),
                    ),
                ),
            ),
            PEHeader(
                "Optional header",
                (
                    PEHeaderField(
                        name="DllCharacteristics",
                        value=0x4140,
                        file_offset=0xDE,
                        size=2,
                        decoded_flags=(
                            "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
                            "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
                            "IMAGE_DLLCHARACTERISTICS_GUARD_CF",
                        ),
                        mitigation_clues=(
                            "ASLR: declared via DYNAMIC_BASE",
                            "DEP/NX: declared via NX_COMPAT",
                            "CFG: declared via GUARD_CF; validate Load Config guard metadata",
                        ),
                    ),
                ),
            ),
        ),
        data_directories=(PEDataDirectory(0, "EXPORT", 0x3000, 0x80),),
        sections=(
            PESectionRecord(
                ".text",
                0x1000,
                0x200,
                0x400,
                0x200,
                0x60000020,
                6.1,
                pointer_to_relocations=0x1234,
                pointer_to_linenumbers=0x5678,
                number_of_relocations=3,
                number_of_linenumbers=4,
                characteristic_flags=(
                    "IMAGE_SCN_CNT_CODE",
                    "IMAGE_SCN_MEM_EXECUTE",
                    "IMAGE_SCN_MEM_READ",
                ),
                header_offset=0x188,
            ),
        ),
        imports=(
            PEImportRecord("import", "KERNEL32.dll", "CreateFileW", None, 120, 0x140004000),
        ),
        exports=(
            PEExportRecord("Run", 1, 0x1100, 0x140001100, None),
        ),
        overlay_offset=None,
        overlay_size=0,
        raw_data=raw_data,
        import_descriptors=(
            PEImportDescriptorRecord(
                0,
                "KERNEL32.dll",
                0x200,
                0x3000,
                0x12345678,
                0,
                0x3500,
                0x4000,
            ),
            PEImportDescriptorRecord(
                1,
                "<all-zero terminator>",
                0x214,
                0,
                0,
                0,
                0,
                0,
                True,
            ),
        ),
        delay_import_descriptors=(
            PEDelayImportDescriptorRecord(
                0,
                "DELAY.dll",
                0x240,
                1,
                0x5100,
                0x5200,
                0x5300,
                0x5400,
                0x5500,
                0x5600,
                0x12345678,
            ),
            PEDelayImportDescriptorRecord(
                1,
                "<all-zero terminator>",
                0x260,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                True,
            ),
        ),
        resources=(
            PEResourceDirectoryRecord(
                ("<root>",),
                0x280,
                0,
                0x12345678,
                1,
                2,
                0,
                1,
            ),
            PEResourceDirectoryRecord(
                ("<root>", "RT_MANIFEST (24)"),
                0x2A0,
                0,
                0x12345678,
                1,
                2,
                0,
                1,
            ),
            PEResourceDirectoryRecord(
                ("<root>", "RT_MANIFEST (24)", "ID_1"),
                0x2C0,
                0,
                0x12345678,
                1,
                2,
                0,
                1,
            ),
            PEResourceDataRecord(
                ("<root>", "RT_MANIFEST (24)", "ID_1", "LANG_1033"),
                0x2E0,
                0x6000,
                0x300,
                25,
                25,
                65001,
                0,
                hashlib.sha256(resource_bytes).hexdigest(),
                b"<assembly>safe</assembly>",
            ),
        ),
        base_relocations=(
            PEBaseRelocationBlock(
                index=0,
                file_offset=0x340,
                virtual_address=0x1000,
                size_of_block=12,
                entries=(
                    PEBaseRelocationEntry(
                        0,
                        0x348,
                        3,
                        "IMAGE_REL_BASED_HIGHLOW",
                        0x10,
                        0x1010,
                        0x140001010,
                    ),
                    PEBaseRelocationEntry(
                        1,
                        0x34A,
                        0,
                        "IMAGE_REL_BASED_ABSOLUTE",
                        0,
                        0x1000,
                        0x140001000,
                    ),
                ),
            ),
        ),
        aslr=PEASLRAssessment(
            dynamic_base=True,
            high_entropy_va=False,
            relocations_stripped=False,
            directory_rva=0x7000,
            directory_size=12,
            parsed_blocks=1,
            parsed_entries=2,
            usable_entries=1,
            status=(
                "The image declares DYNAMIC_BASE and contains usable base "
                "relocations; it is structurally ASLR-compatible."
            ),
            clues=(
                "DYNAMIC_BASE: set",
                "Header flags and relocation structure indicate compatibility; "
                "they do not prove runtime randomization.",
            ),
        ),
        tls=PETLSDirectory(
            file_offset=0x360,
            is_pe32_plus=True,
            start_address_of_raw_data=0x140006200,
            end_address_of_raw_data=0x140006210,
            raw_data_rva=0x6200,
            raw_data_file_offset=0x380,
            raw_data_size=16,
            raw_data_available_size=16,
            raw_data_sha256=hashlib.sha256(tls_template).hexdigest(),
            raw_data_preview=tls_template,
            address_of_index=0x140006380,
            index_rva=0x6380,
            index_file_offset=0x3C0,
            address_of_callbacks=0x140006300,
            callbacks_rva=0x6300,
            callbacks_file_offset=0x3A0,
            size_of_zero_fill=8,
            characteristics=0x00300000,
            callbacks=(
                PETLSCallback(
                    index=0,
                    table_entry_file_offset=0x3A0,
                    address=0x140001010,
                    rva=0x1010,
                    file_offset=0x410,
                ),
            ),
            callbacks_terminated=True,
            warnings=(),
        ),
        exceptions=PEExceptionDirectory(
            machine=0x8664,
            is_x64=True,
            functions=(
                PERuntimeFunction(
                    index=0,
                    file_offset=0x400,
                    begin_address=0x1100,
                    end_address=0x1150,
                    begin_va=0x140001100,
                    end_va=0x140001150,
                    unwind_data=0x6400,
                    unwind_info=PEUnwindInfo(
                        rva=0x6400,
                        file_offset=0x440,
                        version=1,
                        flags=1,
                        flag_names=("UNW_FLAG_EHANDLER",),
                        size_of_prolog=8,
                        count_of_codes=2,
                        frame_register=5,
                        frame_register_name="RBP",
                        frame_offset=0,
                        codes=(
                            PEUnwindCode(
                                0,
                                8,
                                2,
                                3,
                                "UWOP_ALLOC_SMALL",
                                1,
                                "allocate 32 bytes",
                            ),
                            PEUnwindCode(
                                1,
                                4,
                                0,
                                5,
                                "UWOP_PUSH_NONVOL",
                                1,
                                "push nonvolatile register RBP",
                            ),
                        ),
                        exception_handler_rva=0x1200,
                        exception_handler_file_offset=0x500,
                        language_data_file_offset=0x44C,
                        chained_function=None,
                        warnings=(),
                    ),
                ),
            ),
            warnings=(),
        ),
        load_configuration=PELoadConfiguration(
            file_offset=0x580,
            declared_size=0x140,
            fields=(
                PELoadConfigField("Size", 0x140, 0x580, 4),
                PELoadConfigField(
                    "SecurityCookie",
                    0x140006500,
                    0x588,
                    8,
                    0x6500,
                    0x520,
                ),
                PELoadConfigField(
                    "GuardCFFunctionTable",
                    0x140006600,
                    0x590,
                    8,
                    0x6600,
                    0x540,
                ),
                PELoadConfigField("GuardCFFunctionCount", 3, 0x598, 8),
                PELoadConfigField("GuardFlags", 0x00C00500, 0x5A0, 4),
            ),
            guard_flags=0x00C00500,
            guard_flag_names=(
                "IMAGE_GUARD_CF_INSTRUMENTED",
                "IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT",
                "IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT",
                "IMAGE_GUARD_XFG_ENABLED",
            ),
            mitigations=(
                PEMitigationFinding(
                    "ASLR",
                    "structurally compatible",
                    ("DYNAMIC_BASE plus usable relocations.",),
                ),
                PEMitigationFinding(
                    "Control Flow Guard",
                    "present",
                    ("Header and load-config evidence agree.",),
                ),
                PEMitigationFinding(
                    "Stack security cookie (/GS)",
                    "cookie present",
                    ("SecurityCookie address: 0x140006500",),
                ),
                PEMitigationFinding(
                    "SafeSEH",
                    "not applicable to x64",
                    ("x64 uses unwind metadata.",),
                ),
            ),
            warnings=(),
            cfg=PECFGEvidence(
                header_guard_cf=True,
                instrumented=True,
                write_integrity_instrumented=False,
                function_table_present=True,
                check_function_pointer=0x140006510,
                check_function_rva=0x6510,
                check_function_file_offset=0x530,
                dispatch_function_pointer=0,
                dispatch_function_rva=None,
                dispatch_function_file_offset=None,
                function_table=0x140006600,
                function_table_rva=0x6600,
                function_table_file_offset=0x540,
                function_count=3,
                entry_stride=4,
                targets=(
                    PECFGTarget(0, 0x540, 0x1010, 0x140001010, 0x410, b"", ()),
                    PECFGTarget(1, 0x544, 0x1200, 0x140001200, 0x500, b"", ()),
                    PECFGTarget(2, 0x548, 0x6500, 0x140006500, 0x520, b"", ()),
                ),
                targets_sorted=True,
                table_complete=True,
                warnings=(),
            ),
        ),
        authenticode=PEAuthenticode(
            table_file_offset=0x600,
            table_size=16,
            entries=(
                PEWinCertificate(
                    index=0,
                    file_offset=0x600,
                    declared_length=13,
                    aligned_length=16,
                    revision=0x0200,
                    revision_name="WIN_CERT_REVISION_2_0",
                    certificate_type=0x0002,
                    certificate_type_name="WIN_CERT_TYPE_PKCS_SIGNED_DATA",
                    content_file_offset=0x608,
                    content_size=5,
                    content_sha256=hashlib.sha256(certificate_content).hexdigest(),
                    complete=True,
                    pkcs7_content_type="signed_data",
                    embedded_digest_algorithm="sha256",
                    embedded_digest="ab" * 32,
                    computed_digest="ab" * 32,
                    digest_matches=True,
                    nested_signature_count=1,
                    signers=(
                        PEAuthenticodeSigner(
                            index=0,
                            identifier="issuer=Test CA; serial=0x1234",
                            digest_algorithm="sha256",
                            signature_algorithm="rsassa_pkcs1v15",
                            signing_time="2026-08-10T07:00:00+00:00",
                            timestamp_present=True,
                            timestamp_times=("2026-08-10T07:00:01+00:00",),
                            matched_certificate_sha256="cd" * 32,
                            signed_message_digest="ef" * 32,
                            content_digest_matches=True,
                            signature_valid=True,
                            verification_note=(
                                "PKCS#7 signer signature verified cryptographically."
                            ),
                        ),
                    ),
                    certificates=(
                        PEEmbeddedCertificate(
                            index=0,
                            subject="Common Name: Test Signer",
                            issuer="Common Name: Test CA",
                            serial_number="0x1234",
                            not_valid_before="2026-01-01T00:00:00+00:00",
                            not_valid_after="2027-01-01T00:00:00+00:00",
                            sha256_fingerprint="cd" * 32,
                            signature_algorithm="rsassa_pkcs1v15",
                            public_key_algorithm="rsa",
                            is_ca=False,
                        ),
                    ),
                    warnings=("Windows trust validation was not performed.",),
                ),
            ),
            table_complete=True,
            warnings=(),
        ),
        rich_header=PERichHeader(
            dans_file_offset=0x80,
            rich_file_offset=0xA0,
            xor_key=0x12345678,
            clear_data_size=0x20,
            entries=(PERichEntry(0, 0x0102, 0x3456, 7),),
            warnings=(),
        ),
        debug_directory=PEDebugDirectory(
            rva=0x6900,
            size=28,
            file_offset=0x680,
            records=(
                PEDebugRecord(
                    index=0,
                    file_offset=0x680,
                    characteristics=0,
                    time_date_stamp=0x5F3759DF,
                    major_version=1,
                    minor_version=0,
                    type=2,
                    type_name="IMAGE_DEBUG_TYPE_CODEVIEW",
                    size_of_data=16,
                    address_of_raw_data=0x7000,
                    pointer_to_raw_data=0x700,
                    data_file_offset=0x700,
                    available_size=16,
                    data_sha256=hashlib.sha256(raw_data[0x700:0x710]).hexdigest(),
                    preview=raw_data[0x700:0x710],
                    codeview_signature="RSDS",
                    pdb_guid="00112233-4455-6677-8899-AABBCCDDEEFF",
                    pdb_age=3,
                    pdb_path=r"C:\build\sample.pdb",
                    warnings=(),
                ),
            ),
            complete=True,
            warnings=(),
        ),
        overlay=PEOverlay(
            file_offset=len(raw_data) - 12,
            size=12,
            sha256=hashlib.sha256(raw_data[-12:]).hexdigest(),
            entropy=1.0,
            preview=raw_data[-12:],
        ),
        dotnet=PEDotNetHeader(
            rva=0x7000,
            size=72,
            file_offset=0x680,
            cb=72,
            runtime_major=2,
            runtime_minor=5,
            metadata_rva=0x7100,
            metadata_size=0x100,
            metadata_file_offset=0x700,
            flags=0x9,
            flag_names=("COMIMAGE_FLAGS_ILONLY", "COMIMAGE_FLAGS_STRONGNAMESIGNED"),
            entry_point=0x06000001,
            entry_point_kind="managed metadata token",
            resources_rva=0,
            resources_size=0,
            strong_name_rva=0x7200,
            strong_name_size=16,
            strong_name_file_offset=0x800,
            strong_name_sha256=hashlib.sha256(raw_data[0x800:0x810]).hexdigest(),
            code_manager_rva=0,
            code_manager_size=0,
            vtable_fixups_rva=0,
            vtable_fixups_size=0,
            export_jumps_rva=0,
            export_jumps_size=0,
            managed_native_header_rva=0,
            managed_native_header_size=0,
            metadata_version="v4.0.30319",
            streams=(
                PEDotNetStream(
                    0,
                    "#~",
                    0x100,
                    16,
                    0x800,
                    16,
                    hashlib.sha256(raw_data[0x800:0x810]).hexdigest(),
                    raw_data[0x800:0x810],
                    (),
                ),
            ),
            tables=(PEDotNetTable(32, "Assembly", 1, 22, 0x820),),
            module_name="ManagedSample.dll",
            assembly=PEDotNetAssemblyIdentity(
                "ManagedSample",
                "1.2.3.4",
                "neutral",
                1,
                0x8004,
            ),
            assembly_references=(
                PEDotNetAssemblyReference(0, "System.Runtime", "6.0.0.0", "neutral", 0),
            ),
            warnings=(),
        ),
    )


def test_pe_structure_uses_analyzed_bytes_and_recovers_all_tables(monkeypatch):
    fake_pe = FakePE()
    monkeypatch.setattr(pe_structure.pefile, "PE", lambda **kwargs: fake_pe)
    raw_data_buffer = bytearray(b"MZ" + bytes(4094))
    struct.pack_into(
        "<8I",
        raw_data_buffer,
        0x240,
        1,
        0x5100,
        0x5200,
        0x5300,
        0x5400,
        0x5500,
        0x5600,
        0x12345678,
    )
    resource_bytes = b"<assembly>safe</assembly>"
    raw_data_buffer[0x300:0x300 + len(resource_bytes)] = resource_bytes
    tls_template = b"TLS-DATA-1234567"
    raw_data_buffer[0x380:0x390] = tls_template
    struct.pack_into("<QQ", raw_data_buffer, 0x3A0, 0x140001010, 0)
    raw_data_buffer[0x440:0x448] = bytes((0x09, 8, 2, 5, 8, 0x32, 4, 0x50))
    struct.pack_into("<I", raw_data_buffer, 0x448, 0x1200)
    struct.pack_into("<III", raw_data_buffer, 0x540, 0x1010, 0x1200, 0x6500)
    raw_data = bytes(raw_data_buffer)
    info = SimpleNamespace(
        filename="[sample].exe",
        sha256="b" * 64,
        file_format="PE",
        arch="x86-64",
        bits=64,
        raw_data=raw_data,
    )

    model = PEStructureAnalyzer().analyze(info)

    assert model.raw_data is raw_data
    assert model.entry_point == 0x140001010
    assert [header.name for header in model.headers] == [
        "DOS header",
        "NT signature",
        "COFF file header",
        "Optional header",
    ]
    assert model.sections[0].raw_offset == 0x400
    assert model.sections[0].pointer_to_relocations == 0x1234
    assert model.sections[0].pointer_to_linenumbers == 0x5678
    assert model.sections[0].number_of_relocations == 3
    assert model.sections[0].number_of_linenumbers == 4
    assert model.sections[0].header_offset == 0x188
    assert model.sections[0].characteristic_flags == (
        "IMAGE_SCN_CNT_CODE",
        "IMAGE_SCN_MEM_EXECUTE",
        "IMAGE_SCN_MEM_READ",
    )
    assert model.import_descriptors == (
        PEImportDescriptorRecord(
            0,
            "KERNEL32.dll",
            0x200,
            0x3000,
            0x12345678,
            0,
            0x3500,
            0x4000,
        ),
        PEImportDescriptorRecord(
            1,
            "<all-zero terminator>",
            0x214,
            0,
            0,
            0,
            0,
            0,
            True,
        ),
    )
    assert model.delay_import_descriptors == (
        PEDelayImportDescriptorRecord(
            0,
            "DELAY.dll",
            0x240,
            1,
            0x5100,
            0x5200,
            0x5300,
            0x5400,
            0x5500,
            0x5600,
            0x12345678,
        ),
        PEDelayImportDescriptorRecord(
            1,
            "<all-zero terminator>",
            0x260,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            True,
        ),
    )
    assert model.resources[:3] == (
        PEResourceDirectoryRecord(
            ("<root>",), 0x280, 0, 0x12345678, 1, 2, 0, 1
        ),
        PEResourceDirectoryRecord(
            ("<root>", "RT_MANIFEST (24)"),
            0x2A0,
            0,
            0x12345678,
            1,
            2,
            0,
            1,
        ),
        PEResourceDirectoryRecord(
            ("<root>", "RT_MANIFEST (24)", "ID_1"),
            0x2C0,
            0,
            0x12345678,
            1,
            2,
            0,
            1,
        ),
    )
    resource = model.resources[3]
    assert isinstance(resource, PEResourceDataRecord)
    assert resource.path[-1] == "LANG_1033"
    assert resource.data_file_offset == 0x300
    assert resource.complete
    assert resource.sha256 == hashlib.sha256(resource_bytes).hexdigest()
    assert resource.preview == resource_bytes
    assert model.base_relocations == (
        PEBaseRelocationBlock(
            index=0,
            file_offset=0x340,
            virtual_address=0x1000,
            size_of_block=12,
            entries=(
                PEBaseRelocationEntry(
                    0,
                    0x348,
                    3,
                    "IMAGE_REL_BASED_HIGHLOW",
                    0x10,
                    0x1010,
                    0x140001010,
                ),
                PEBaseRelocationEntry(
                    1,
                    0x34A,
                    0,
                    "IMAGE_REL_BASED_ABSOLUTE",
                    0,
                    0x1000,
                    0x140001000,
                ),
            ),
        ),
    )
    assert model.aslr is not None
    assert model.aslr.dynamic_base
    assert model.aslr.high_entropy_va
    assert model.aslr.relocations_stripped
    assert model.aslr.directory_rva == 0x7000
    assert model.aslr.parsed_blocks == 1
    assert model.aslr.parsed_entries == 2
    assert model.aslr.usable_entries == 1
    assert "marked stripped" in model.aslr.status
    assert model.tls is not None
    assert model.tls.file_offset == 0x360
    assert model.tls.is_pe32_plus
    assert model.tls.start_address_of_raw_data == 0x140006200
    assert model.tls.end_address_of_raw_data == 0x140006210
    assert model.tls.raw_data_rva == 0x6200
    assert model.tls.raw_data_file_offset == 0x380
    assert model.tls.raw_data_size == 16
    assert model.tls.raw_data_complete
    assert model.tls.raw_data_sha256 == hashlib.sha256(tls_template).hexdigest()
    assert model.tls.address_of_index == 0x140006380
    assert model.tls.index_rva == 0x6380
    assert model.tls.index_file_offset == 0x3C0
    assert model.tls.address_of_callbacks == 0x140006300
    assert model.tls.callbacks_rva == 0x6300
    assert model.tls.callbacks_file_offset == 0x3A0
    assert model.tls.callbacks == (
        PETLSCallback(0, 0x3A0, 0x140001010, 0x1010, 0x410),
    )
    assert model.tls.callbacks_terminated
    assert not model.tls.warnings
    assert model.exceptions is not None
    assert model.exceptions.machine == 0x8664
    assert model.exceptions.is_x64
    assert len(model.exceptions.functions) == 1
    runtime_function = model.exceptions.functions[0]
    assert runtime_function.file_offset == 0x400
    assert runtime_function.begin_address == 0x1100
    assert runtime_function.end_address == 0x1150
    assert runtime_function.begin_va == 0x140001100
    assert runtime_function.end_va == 0x140001150
    assert runtime_function.unwind_data == 0x6400
    unwind = runtime_function.unwind_info
    assert unwind is not None
    assert unwind.rva == 0x6400
    assert unwind.file_offset == 0x440
    assert unwind.version == 1
    assert unwind.flag_names == ("UNW_FLAG_EHANDLER",)
    assert unwind.size_of_prolog == 8
    assert unwind.count_of_codes == 2
    assert unwind.frame_register_name == "RBP"
    assert [code.op_name for code in unwind.codes] == [
        "UWOP_ALLOC_SMALL",
        "UWOP_PUSH_NONVOL",
    ]
    assert [code.description for code in unwind.codes] == [
        "allocate 32 bytes",
        "push nonvolatile register RBP",
    ]
    assert unwind.exception_handler_rva == 0x1200
    assert unwind.exception_handler_file_offset == 0x500
    assert unwind.language_data_file_offset == 0x44C
    assert not unwind.warnings
    load_config = model.load_configuration
    assert load_config is not None
    assert load_config.file_offset == 0x580
    assert load_config.declared_size == 0x140
    assert load_config.guard_flags == 0x00C00500
    assert load_config.guard_flag_names == (
        "IMAGE_GUARD_CF_INSTRUMENTED",
        "IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT",
        "IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT",
        "IMAGE_GUARD_XFG_ENABLED",
    )
    cfg = load_config.cfg
    assert cfg is not None
    assert cfg.header_guard_cf
    assert cfg.instrumented
    assert not cfg.write_integrity_instrumented
    assert cfg.function_table_present
    assert cfg.check_function_pointer == 0x140006510
    assert cfg.check_function_rva == 0x6510
    assert cfg.check_function_file_offset == 0x530
    assert cfg.function_table == 0x140006600
    assert cfg.function_table_rva == 0x6600
    assert cfg.function_table_file_offset == 0x540
    assert cfg.function_count == 3
    assert cfg.entry_stride == 4
    assert [target.rva for target in cfg.targets] == [0x1010, 0x1200, 0x6500]
    assert [target.file_offset for target in cfg.targets] == [0x410, 0x500, 0x520]
    assert cfg.targets_sorted
    assert cfg.table_complete
    assert not cfg.warnings
    security_cookie = next(
        field for field in load_config.fields if field.name == "SecurityCookie"
    )
    assert security_cookie.value == 0x140006500
    assert security_cookie.target_rva == 0x6500
    assert security_cookie.target_file_offset == 0x520
    mitigation_status = {
        finding.name: finding.status for finding in load_config.mitigations
    }
    assert mitigation_status["ASLR"] == "inconsistent or incomplete"
    assert mitigation_status["High-entropy ASLR"] == "declared"
    assert mitigation_status["DEP / NX"] == "declared"
    assert mitigation_status["Control Flow Guard"] == "present"
    assert mitigation_status["Stack security cookie (/GS)"] == "cookie present"
    assert mitigation_status["SafeSEH"] == "not applicable to x64"
    assert mitigation_status["EH continuation guard"] == "table present"
    assert mitigation_status["Extended Flow Guard (XFG)"] == "declared"
    assert mitigation_status["Code integrity"] == "declared"
    assert [(item.kind, item.name) for item in model.imports] == [
        ("import", "CreateFileW"),
        ("delay", "ordinal_7"),
    ]
    assert model.exports[0].forwarder == "OTHER.Target"
    characteristics = next(
        field
        for header in model.headers
        if header.name == "COFF file header"
        for field in header.fields
        if field.name == "Characteristics"
    )
    assert characteristics.value == 0x3123
    assert characteristics.decoded_flags == (
        "IMAGE_FILE_RELOCS_STRIPPED",
        "IMAGE_FILE_EXECUTABLE_IMAGE",
        "IMAGE_FILE_LARGE_ADDRESS_AWARE",
        "IMAGE_FILE_32BIT_MACHINE",
        "IMAGE_FILE_SYSTEM",
        "IMAGE_FILE_DLL",
    )
    dll_characteristics = next(
        field
        for header in model.headers
        if header.name == "Optional header"
        for field in header.fields
        if field.name == "DllCharacteristics"
    )
    assert dll_characteristics.value == 0x41E0
    assert dll_characteristics.decoded_flags == (
        "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
        "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
        "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
        "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
        "IMAGE_DLLCHARACTERISTICS_GUARD_CF",
    )
    assert dll_characteristics.mitigation_clues == (
        "ASLR: declared via DYNAMIC_BASE",
        "DEP/NX: declared via NX_COMPAT",
        "CFG: declared via GUARD_CF; validate Load Config guard metadata",
        "High-entropy ASLR: requested; meaningful with DYNAMIC_BASE",
        "Code integrity: FORCE_INTEGRITY declared",
    )
    assert model.overlay_offset == 0x800
    assert model.overlay_size == 2048
    assert fake_pe.closed


def test_cfg_gfids_stride_and_suppression_metadata_are_decoded():
    raw_data = bytearray(4096)
    struct.pack_into("<IBIB", raw_data, 0x540, 0x1010, 0x01, 0x1200, 0x02)
    evidence = PEStructureAnalyzer._cfg_evidence(
        FakePE(),
        bytes(raw_data),
        {
            "GuardCFCheckFunctionPointer": 0x140006510,
            "GuardCFFunctionTable": 0x140006600,
            "GuardCFFunctionCount": 2,
        },
        0x10000500,
    )

    assert evidence.entry_stride == 5
    assert evidence.table_complete
    assert evidence.targets_sorted
    assert [target.metadata for target in evidence.targets] == [b"\x01", b"\x02"]
    assert evidence.targets[0].flag_names == ("IMAGE_GUARD_FLAG_FID_SUPPRESSED",)
    assert evidence.targets[1].flag_names == (
        "IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED",
    )


def test_rich_header_decodes_dans_entries_and_xor_key():
    raw_data = bytearray(0x100)
    key = 0xA1B2C3D4
    dans_offset = 0x40
    rich_offset = 0x60
    struct.pack_into("<I", raw_data, dans_offset, 0x536E6144 ^ key)
    for offset in (0x44, 0x48, 0x4C):
        struct.pack_into("<I", raw_data, offset, key)
    component = (0x0123 << 16) | 0x4567
    struct.pack_into("<II", raw_data, 0x50, component ^ key, 9 ^ key)
    struct.pack_into("<II", raw_data, 0x58, 0x00020003 ^ key, 4 ^ key)
    raw_data[rich_offset:rich_offset + 4] = b"Rich"
    struct.pack_into("<I", raw_data, rich_offset + 4, key)
    pe = SimpleNamespace(DOS_HEADER=SimpleNamespace(e_lfanew=0x80))

    rich = PEStructureAnalyzer._rich_header(pe, bytes(raw_data))

    assert isinstance(rich, PERichHeader)
    assert rich.dans_file_offset == dans_offset
    assert rich.rich_file_offset == rich_offset
    assert rich.xor_key == key
    assert [(entry.product_id, entry.build_number, entry.use_count) for entry in rich.entries] == [
        (0x0123, 0x4567, 9),
        (2, 3, 4),
    ]
    assert not rich.warnings


def test_debug_directory_decodes_rsds_guid_age_and_pdb_path():
    raw_data = bytearray(0x200)
    directory_offset = 0x20
    payload_offset = 0x80
    pdb_guid = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
    payload = b"RSDS" + pdb_guid.bytes_le + struct.pack("<I", 7) + b"C:\\build\\sample.pdb\x00"
    raw_data[payload_offset:payload_offset + len(payload)] = payload
    struct.pack_into(
        "<IIHHIIII",
        raw_data,
        directory_offset,
        0,
        0x5F3759DF,
        1,
        2,
        2,
        len(payload),
        0x2000,
        payload_offset,
    )
    directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(7)]
    directories[6] = SimpleNamespace(VirtualAddress=0x1000, Size=28)
    pe = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=directories),
        get_offset_from_rva=lambda rva: directory_offset if rva == 0x1000 else 0,
    )

    debug = PEStructureAnalyzer._debug_directory(pe, bytes(raw_data))

    assert isinstance(debug, PEDebugDirectory)
    assert debug.complete
    assert len(debug.records) == 1
    record = debug.records[0]
    assert record.type_name == "IMAGE_DEBUG_TYPE_CODEVIEW"
    assert record.complete
    assert record.codeview_signature == "RSDS"
    assert record.pdb_guid == str(pdb_guid).upper()
    assert record.pdb_age == 7
    assert record.pdb_path == "C:\\build\\sample.pdb"
    assert record.data_sha256 == hashlib.sha256(payload).hexdigest()


def test_debug_directory_marks_truncated_payload_without_hashing_it():
    raw_data = bytearray(0x90)
    struct.pack_into(
        "<IIHHIIII",
        raw_data,
        0x20,
        0,
        0,
        0,
        0,
        2,
        0x40,
        0,
        0x80,
    )
    raw_data[0x80:0x90] = b"RSDS" + bytes(12)
    directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(7)]
    directories[6] = SimpleNamespace(VirtualAddress=0x1000, Size=28)
    pe = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=directories),
        get_offset_from_rva=lambda _rva: 0x20,
    )

    record = PEStructureAnalyzer._debug_directory(pe, bytes(raw_data)).records[0]

    assert not record.complete
    assert record.available_size == 16
    assert record.data_sha256 is None
    assert any("extends beyond" in warning for warning in record.warnings)


def test_overlay_model_hashes_and_measures_exact_trailing_bytes():
    raw_data = b"MZ" + bytes(30) + b"OVERLAY-DATA"

    overlay = PEStructureAnalyzer._overlay(raw_data, 32)

    assert isinstance(overlay, PEOverlay)
    assert overlay.file_offset == 32
    assert overlay.size == len(b"OVERLAY-DATA")
    assert overlay.sha256 == hashlib.sha256(b"OVERLAY-DATA").hexdigest()
    assert overlay.preview == b"OVERLAY-DATA"
    assert overlay.entropy > 0


def test_dotnet_parser_decodes_clr_header_streams_identity_and_references():
    raw_data = bytearray(0x600)
    clr_offset = 0x100
    metadata_offset = 0x200
    strong_name_offset = 0x500
    metadata_version = b"v4.0.30319\x00"
    strings = b"\x00Sample.dll\x00ManagedSample\x00System.Runtime\x00"
    module_name_index = 1
    assembly_name_index = strings.index(b"ManagedSample")
    reference_name_index = strings.index(b"System.Runtime")

    table_stream = bytearray()
    valid_mask = (1 << 0) | (1 << 32) | (1 << 35)
    table_stream.extend(struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid_mask, 0))
    table_stream.extend(struct.pack("<III", 1, 1, 1))
    table_stream.extend(struct.pack("<HHHHH", 0, module_name_index, 0, 0, 0))
    table_stream.extend(
        struct.pack(
            "<IHHHHIHHH",
            0x00008004,
            1,
            2,
            3,
            4,
            1,
            0,
            assembly_name_index,
            0,
        )
    )
    table_stream.extend(
        struct.pack(
            "<HHHHIHHHH",
            6,
            0,
            0,
            0,
            0,
            0,
            reference_name_index,
            0,
            0,
        )
    )

    metadata_header_size = 16 + len(metadata_version)
    metadata_header_size = (metadata_header_size + 3) & ~3
    metadata_header_size += 4
    stream_headers_size = 12 + 20
    table_offset = metadata_header_size + stream_headers_size
    strings_offset = table_offset + len(table_stream)
    metadata_size = strings_offset + len(strings)
    struct.pack_into("<IHHII", raw_data, metadata_offset, 0x424A5342, 1, 1, 0, len(metadata_version))
    raw_data[metadata_offset + 16:metadata_offset + 16 + len(metadata_version)] = metadata_version
    cursor = metadata_offset + ((16 + len(metadata_version) + 3) & ~3)
    struct.pack_into("<HH", raw_data, cursor, 0, 2)
    cursor += 4
    struct.pack_into("<II", raw_data, cursor, table_offset, len(table_stream))
    raw_data[cursor + 8:cursor + 11] = b"#~\x00"
    cursor += 12
    struct.pack_into("<II", raw_data, cursor, strings_offset, len(strings))
    raw_data[cursor + 8:cursor + 17] = b"#Strings\x00"
    raw_data[metadata_offset + table_offset:metadata_offset + table_offset + len(table_stream)] = table_stream
    raw_data[metadata_offset + strings_offset:metadata_offset + strings_offset + len(strings)] = strings
    raw_data[strong_name_offset:strong_name_offset + 16] = bytes(range(16))

    struct.pack_into(
        "<IHHIIII12I",
        raw_data,
        clr_offset,
        72,
        2,
        5,
        0x2000,
        metadata_size,
        0x9,
        0x06000001,
        0,
        0,
        0x3000,
        16,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(15)]
    directories[14] = SimpleNamespace(VirtualAddress=0x1000, Size=72)
    offsets = {0x1000: clr_offset, 0x2000: metadata_offset, 0x3000: strong_name_offset}
    pe = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=directories),
        get_offset_from_rva=lambda rva: offsets[rva],
    )

    dotnet = PEStructureAnalyzer._dotnet(pe, bytes(raw_data))

    assert isinstance(dotnet, PEDotNetHeader)
    assert dotnet.runtime_major == 2 and dotnet.runtime_minor == 5
    assert dotnet.flag_names == (
        "COMIMAGE_FLAGS_ILONLY",
        "COMIMAGE_FLAGS_STRONGNAMESIGNED",
    )
    assert dotnet.entry_point == 0x06000001
    assert dotnet.metadata_version == "v4.0.30319"
    assert [stream.name for stream in dotnet.streams] == ["#~", "#Strings"]
    assert dotnet.module_name == "Sample.dll"
    assert dotnet.assembly == PEDotNetAssemblyIdentity(
        "ManagedSample", "1.2.3.4", "neutral", 1, 0x00008004
    )
    assert dotnet.assembly_references == (
        PEDotNetAssemblyReference(0, "System.Runtime", "6.0.0.0", "neutral", 0),
    )
    table_counts = {table.name: table.row_count for table in dotnet.tables}
    assert table_counts == {"Module": 1, "Assembly": 1, "AssemblyRef": 1}
    assert dotnet.strong_name_sha256 == hashlib.sha256(bytes(range(16))).hexdigest()
    assert not dotnet.warnings


def test_win_certificate_table_is_file_offset_based_and_bounded():
    raw_data = bytearray(0x200)
    content = b"CERT!"
    struct.pack_into("<IHH", raw_data, 0x100, 13, 0x0200, 0x0001)
    raw_data[0x108:0x10D] = content
    directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(5)]
    directories[4] = SimpleNamespace(VirtualAddress=0x100, Size=16)
    pe = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=directories),
    )

    evidence = PEStructureAnalyzer._authenticode(pe, bytes(raw_data))

    assert evidence is not None
    assert evidence.table_file_offset == 0x100
    assert evidence.table_size == 16
    assert evidence.table_complete
    assert len(evidence.entries) == 1
    entry = evidence.entries[0]
    assert entry.file_offset == 0x100
    assert entry.declared_length == 13
    assert entry.aligned_length == 16
    assert entry.revision_name == "WIN_CERT_REVISION_2_0"
    assert entry.certificate_type_name == "WIN_CERT_TYPE_X509"
    assert entry.content_file_offset == 0x108
    assert entry.content_size == 5
    assert entry.content_sha256 == hashlib.sha256(content).hexdigest()
    assert entry.complete
    assert "not PKCS#7" in entry.warnings[0]


def test_spc_indirect_digest_and_authenticode_hash_exclusions():
    expected_digest = bytes(range(32))
    digest_algorithm = bytes.fromhex("300d06096086480165030402010500")
    digest_info = b"\x30\x31" + digest_algorithm + b"\x04\x20" + expected_digest
    spc = b"\x30\x35\x30\x00" + digest_info
    wrapped = b"\xa0\x37" + spc
    algorithm, parsed_digest = PEStructureAnalyzer._spc_indirect_digest(
        SimpleNamespace(dump=lambda: wrapped)
    )
    assert algorithm == "sha256"
    assert parsed_digest == expected_digest

    raw_data = bytes(range(256)) * 5

    class SecurityDirectory:
        @staticmethod
        def get_file_offset():
            return 0x118

    class OptionalHeader:
        SizeOfHeaders = 0x200
        DATA_DIRECTORY = [SimpleNamespace() for _ in range(4)] + [SecurityDirectory()]

        @staticmethod
        def dump_dict():
            return {"CheckSum": {"FileOffset": 0x100}}

    sections = [
        SimpleNamespace(PointerToRawData=0x300, SizeOfRawData=0x100),
        SimpleNamespace(PointerToRawData=0x200, SizeOfRawData=0x100),
    ]
    pe = SimpleNamespace(OPTIONAL_HEADER=OptionalHeader(), sections=sections)
    expected = hashlib.sha256(
        raw_data[:0x100]
        + raw_data[0x104:0x118]
        + raw_data[0x120:0x200]
        + raw_data[0x200:0x300]
        + raw_data[0x300:0x400]
    ).digest()
    assert (
        PEStructureAnalyzer._authenticode_image_digest(pe, raw_data, "sha256")
        == expected
    )


def test_decode_coff_characteristics_preserves_unknown_bits():
    assert decode_coff_characteristics(0x12002) == (
        "IMAGE_FILE_EXECUTABLE_IMAGE",
        "IMAGE_FILE_DLL",
        "UNKNOWN_0x10000",
    )


def test_dll_characteristics_decode_and_missing_mitigation_clues():
    assert decode_dll_characteristics(0x141) == (
        "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
        "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
        "UNKNOWN_0x1",
    )


def test_section_characteristics_decode_alignment_permissions_and_unknown_bits():
    assert decode_section_characteristics(0xE0300020) == (
        "IMAGE_SCN_CNT_CODE",
        "IMAGE_SCN_ALIGN_4BYTES",
        "IMAGE_SCN_MEM_EXECUTE",
        "IMAGE_SCN_MEM_READ",
        "IMAGE_SCN_MEM_WRITE",
    )
    assert decode_section_characteristics(0x00000021) == (
        "IMAGE_SCN_CNT_CODE",
        "UNKNOWN_0x1",
    )
    assert dll_mitigation_clues(0, pe32_plus=False) == (
        "ASLR: not declared (DYNAMIC_BASE absent)",
        "DEP/NX: not declared (NX_COMPAT absent)",
        "CFG: not declared (GUARD_CF absent)",
    )


def test_pe_structure_rejects_non_pe_input():
    info = SimpleNamespace(file_format="ELF", raw_data=b"\x7fELF")
    try:
        PEStructureAnalyzer().analyze(info)
    except ValueError as exc:
        assert "only for Windows PE" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("non-PE input was accepted")


def test_resource_data_record_marks_incomplete_file_ranges():
    data = SimpleNamespace(
        OffsetToData=0x7000,
        Size=10,
        CodePage=0,
        Reserved=0,
        get_file_offset=lambda: 0x220,
    )
    pe = SimpleNamespace(get_offset_from_rva=lambda _rva: 6)

    record = PEStructureAnalyzer._resource_data_record(
        pe,
        b"01234567",
        ("<root>", "RT_RCDATA (10)", "ID_1", "LANG_1033"),
        data,
    )

    assert not record.complete
    assert record.available_size == 2
    assert record.preview == b"67"
    assert record.sha256 is None


def test_aslr_assessment_reports_missing_opt_in_and_directory():
    pe = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Characteristics=0),
        OPTIONAL_HEADER=SimpleNamespace(
            DllCharacteristics=0,
            Magic=0x10B,
            DATA_DIRECTORY=[SimpleNamespace(VirtualAddress=0, Size=0)] * 6,
        ),
    )

    assessment = PEStructureAnalyzer._aslr_assessment(pe, (), False)

    assert not assessment.dynamic_base
    assert not assessment.relocations_stripped
    assert assessment.directory_rva == 0
    assert assessment.usable_entries == 0
    assert "does not declare DYNAMIC_BASE" in assessment.status


def test_resource_payload_filename_and_secure_export(tmp_path):
    model = _model()
    record = next(
        item for item in model.resources if isinstance(item, PEResourceDataRecord)
    )

    assert resource_payload(model, record) == model.raw_data[0x300:0x319]
    filename = resource_filename(record)
    assert filename.endswith(".xml")
    assert "/" not in filename and "\\" not in filename

    destination = export_resource(model, record, tmp_path / "exports")

    assert destination.read_bytes() == model.raw_data[0x300:0x319]
    assert destination.stat().st_mode & 0o777 == 0o600
    try:
        export_resource(model, record, tmp_path / "exports")
    except FileExistsError:
        pass
    else:  # pragma: no cover
        raise AssertionError("resource export overwrote an existing file")

    real_directory = tmp_path / "real-directory"
    real_directory.mkdir()
    symlinked_root = tmp_path / "symlinked-root"
    symlinked_root.symlink_to(real_directory, target_is_directory=True)
    try:
        export_resource(model, record, symlinked_root)
    except OSError as exc:
        assert "safe directory" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("resource export followed a symlinked output root")

    certificate = model.authenticode.entries[0]
    assert certificate_filename(certificate).endswith(".p7b")
    assert certificate_payload(model, certificate) == b"PKCS7"
    certificate_destination = export_certificate(
        model,
        certificate,
        tmp_path / "certificate-exports",
    )
    assert certificate_destination.read_bytes() == b"PKCS7"
    assert certificate_destination.stat().st_mode & 0o777 == 0o600


def test_debug_and_overlay_payloads_open_and_export_exact_bytes(tmp_path):
    model = _model()
    debug_bytes = model.raw_data[0x700:0x710]
    debug = PEDebugRecord(
        index=0,
        file_offset=0x680,
        characteristics=0,
        time_date_stamp=0,
        major_version=0,
        minor_version=0,
        type=2,
        type_name="IMAGE_DEBUG_TYPE_CODEVIEW",
        size_of_data=len(debug_bytes),
        address_of_raw_data=0,
        pointer_to_raw_data=0x700,
        data_file_offset=0x700,
        available_size=len(debug_bytes),
        data_sha256=hashlib.sha256(debug_bytes).hexdigest(),
        preview=debug_bytes,
        codeview_signature=None,
        pdb_guid=None,
        pdb_age=None,
        pdb_path=None,
        warnings=(),
    )
    overlay_bytes = model.raw_data[-12:]
    overlay = PEOverlay(
        file_offset=len(model.raw_data) - len(overlay_bytes),
        size=len(overlay_bytes),
        sha256=hashlib.sha256(overlay_bytes).hexdigest(),
        entropy=1.0,
        preview=overlay_bytes,
    )
    model = replace(model, debug_directory=PEDebugDirectory(0x1000, 28, 0x680, (debug,), True, ()), overlay=overlay)
    dotnet_stream = model.dotnet.streams[0]

    assert debug_payload(model, debug) == debug_bytes
    assert overlay_payload(model, overlay) == overlay_bytes
    assert dotnet_stream_payload(model, dotnet_stream) == model.raw_data[0x800:0x810]
    debug_destination = export_debug_payload(model, debug, tmp_path / "debug")
    overlay_destination = export_overlay(model, overlay, tmp_path / "overlay")
    dotnet_destination = export_dotnet_stream(model, dotnet_stream, tmp_path / "dotnet")

    assert debug_destination.read_bytes() == debug_bytes
    assert overlay_destination.read_bytes() == overlay_bytes
    assert dotnet_destination.read_bytes() == model.raw_data[0x800:0x810]
    assert debug_destination.stat().st_mode & 0o777 == 0o600
    assert overlay_destination.stat().st_mode & 0o777 == 0o600
    assert dotnet_destination.stat().st_mode & 0o777 == 0o600
    for exporter, record, root in (
        (export_debug_payload, debug, tmp_path / "debug"),
        (export_overlay, overlay, tmp_path / "overlay"),
        (export_dotnet_stream, dotnet_stream, tmp_path / "dotnet"),
    ):
        try:
            exporter(model, record, root)
        except FileExistsError:
            pass
        else:  # pragma: no cover
            raise AssertionError("evidence export overwrote an existing file")


def test_hex_pages_keep_first_middle_and_final_bytes_reachable():
    data = bytes(range(256)) * 33 + b"FINAL"
    assert page_count(len(data), 4096) == 3

    first, selected, total = render_hex_page(data, 0, page_size=4096)
    assert selected == 0 and total == 3
    assert "00000000" in first

    final, selected, total = render_hex_page(data, 999, page_size=4096)
    assert selected == 2 and total == 3
    assert f"{8192:08x}" in final
    assert "FINAL" in final


def test_pe_structure_screen_pages_whole_file():
    class Host(App):
        def on_mount(self):
            self.push_screen(PEStructureScreen(_model()))

    async def scenario():
        app = Host()
        async with app.run_test() as pilot:
            screen = app.screen
            tabs = screen.query_one("#pe-tabs")
            tabs.active = "pe-hex"
            await pilot.pause()
            await pilot.press("pagedown")
            await pilot.pause()

            assert screen._pages["pe-hex"] == 1
            rendered = "\n".join(
                line.text for line in screen.query_one("#pe-hex-log").lines
            )
            assert "page 2/2" in rendered
            assert "00001000" in rendered
            tabs.active = "pe-headers"
            await pilot.pause()
            headers = "\n".join(
                line.text for line in screen.query_one("#pe-headers-log").lines
            )
            assert "Characteristics" in headers
            assert "IMAGE_FILE_EXECUTABLE_IMAGE" in headers
            assert "IMAGE_FILE_LARGE_ADDRESS_AWARE" in headers
            assert "IMAGE_FILE_DLL" in headers
            assert "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE" in headers
            assert "IMAGE_DLLCHARACTERISTICS_NX_COMPAT" in headers
            assert "IMAGE_DLLCHARACTERISTICS_GUARD_CF" in headers
            assert "ASLR: declared via DYNAMIC_BASE" in headers
            assert "Header flags are clues, not proof" in headers
            tabs.active = "pe-sections"
            await pilot.pause()
            sections = "\n".join(
                line.text for line in screen.query_one("#pe-sections-log").lines
            )
            assert "Each record is 40 bytes" in sections
            assert "PointerToRelocations" in sections
            assert "PointerToLinenumbers" in sections
            assert "NumberOfRelocations" in sections
            assert "NumberOfLinenumbers" in sections
            assert "IMAGE_SCN_CNT_CODE" in sections
            assert "IMAGE_SCN_MEM_EXECUTE" in sections
            assert "IMAGE_SCN_MEM_READ" in sections
            assert "Memory permissions            R-X" in sections
            tabs.active = "pe-directories"
            await pilot.pause()
            directories = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "Optional-header data directories" in directories
            assert "PE data-directory explorer" in directories
            assert "type → name/ID → language → data file" in directories
            tree = screen.query_one("#pe-resource-tree")
            data_node = screen._resource_nodes[
                (
                    "<root>",
                    "RT_MANIFEST (24)",
                    "ID_1",
                    "LANG_1033",
                    "<data>",
                )
            ]
            tree.move_cursor(data_node)
            tree.focus()
            await pilot.pause()
            directories = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "RT_MANIFEST (24)" in directories
            assert "ID_1" in directories
            assert "LANG_1033" in directories
            assert "Data-entry file offset" in directories
            assert "OffsetToData (RVA)" in directories
            assert "CodePage                 65001" in directories
            assert "SHA-256" in directories
            assert "Preview (hex)" in directories
            assert "Preview (ASCII)" in directories
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, ResourcePayloadScreen)
            payload_view = "\n".join(
                line.text
                for line in app.screen.query_one("#resource-payload-log").lines
            )
            assert "Resource payload" in payload_view
            assert "UTF-8 text preview" in payload_view
            assert "<assembly>safe</assembly>" in payload_view
            await pilot.press("escape")
            await pilot.pause()
            screen = app.screen
            tree = screen.query_one("#pe-resource-tree")
            tree.move_cursor(screen._dotnet_root)
            await pilot.pause()
            dotnet_view = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert ".NET / CLR assembly" in dotnet_view
            assert "IMAGE_COR20_HEADER" in dotnet_view
            assert "COMIMAGE_FLAGS_ILONLY" in dotnet_view
            assert "ManagedSample" in dotnet_view
            assert "1.2.3.4" in dotnet_view
            assert "MethodDef, RID 1" in dotnet_view
            assert "Assembly references       1" in dotnet_view
            tree.move_cursor(screen._dotnet_reference_nodes[0])
            await pilot.pause()
            dotnet_reference_view = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "AssemblyRef row 0" in dotnet_reference_view
            assert "System.Runtime" in dotnet_reference_view
            tree.move_cursor(screen._dotnet_stream_nodes[0])
            await pilot.pause()
            dotnet_stream_view = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert ".NET metadata stream #~" in dotnet_stream_view
            assert "Complete payload          yes" in dotnet_stream_view
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, EvidencePayloadScreen)
            await pilot.press("escape")
            await pilot.pause()
            screen = app.screen
            tree = screen.query_one("#pe-resource-tree")
            tree.move_cursor(screen._rich_header_root)
            await pilot.pause()
            rich_view = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "Rich header evidence" in rich_view
            assert "XOR key / checksum        0x12345678" in rich_view
            assert "258" in rich_view
            tree.move_cursor(screen._debug_root)
            await pilot.pause()
            debug_directory_view = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "Debug Directory" in debug_directory_view
            assert "Parsed records            1" in debug_directory_view
            tree.move_cursor(screen._debug_nodes[0])
            await pilot.pause()
            debug_record_view = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "IMAGE_DEBUG_DIRECTORY record 0" in debug_record_view
            assert "IMAGE_DEBUG_TYPE_CODEVIEW" in debug_record_view
            assert "PDB signature GUID" in debug_record_view
            assert r"C:\build\sample.pdb" in debug_record_view
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, EvidencePayloadScreen)
            await pilot.press("escape")
            await pilot.pause()
            screen = app.screen
            tree = screen.query_one("#pe-resource-tree")
            tree.move_cursor(screen._overlay_root)
            await pilot.pause()
            overlay_view = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "Overlay evidence" in overlay_view
            assert "presence alone is not a verdict" in overlay_view
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, EvidencePayloadScreen)
            await pilot.press("escape")
            await pilot.pause()
            screen = app.screen
            tabs = screen.query_one("#pe-tabs")
            tree = screen.query_one("#pe-resource-tree")
            tree.move_cursor(screen._relocation_root)
            await pilot.pause()
            relocation_assessment = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "ASLR assessment" in relocation_assessment
            assert "DYNAMIC_BASE             set" in relocation_assessment
            assert "HIGH_ENTROPY_VA           not set" in relocation_assessment
            assert "RELOCS_STRIPPED           not set" in relocation_assessment
            assert "structurally ASLR-compatible" in relocation_assessment
            assert "do not prove runtime randomization" in relocation_assessment
            tree.move_cursor(screen._relocation_nodes[0])
            await pilot.pause()
            relocation_block = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "IMAGE_BASE_RELOCATION block 0" in relocation_block
            assert "Header file offset       0x00000340" in relocation_block
            assert "VirtualAddress (page RVA) 0x00001000" in relocation_block
            assert "SizeOfBlock              0x0000000c" in relocation_block
            assert "IMAGE_REL_BASED_HIGHLOW" in relocation_block
            assert "IMAGE_REL_BASED_ABSOLUTE" in relocation_block
            assert "0x00001010" in relocation_block
            assert "0x0000000140001010" in relocation_block
            tree.move_cursor(screen._tls_root)
            await pilot.pause()
            tls_directory = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "IMAGE_TLS_DIRECTORY64" in tls_directory
            assert "may execute before the image entry point" in tls_directory
            assert "Directory file offset    0x00000360" in tls_directory
            assert "StartAddressOfRawData    0x0000000140006200" in tls_directory
            assert "EndAddressOfRawData      0x0000000140006210" in tls_directory
            assert "TLS template RVA         0x6200" in tls_directory
            assert "TLS template file offset 0x380" in tls_directory
            assert "TLS template SHA-256" in tls_directory
            assert "TLS template preview hex" in tls_directory
            assert "AddressOfIndex           0x0000000140006380" in tls_directory
            assert "AddressOfCallBacks       0x0000000140006300" in tls_directory
            assert "Callback-table RVA       0x6300" in tls_directory
            assert "Callback-table terminator confirmed null pointer" in tls_directory
            tree.move_cursor(screen._tls_callback_nodes[0])
            await pilot.pause()
            tls_callback = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "TLS callback 0" in tls_callback
            assert "before the normal PE entry point" in tls_callback
            assert "Pointer entry file offset 0x000003a0" in tls_callback
            assert "Callback VA              0x0000000140001010" in tls_callback
            assert "Callback RVA             0x1010" in tls_callback
            assert "Callback file offset     0x410" in tls_callback
            tree.move_cursor(screen._exception_root)
            await pilot.pause()
            exception_summary = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "Exception Directory / .pdata" in exception_summary
            assert "Machine                  0x8664" in exception_summary
            assert "x64 UNWIND_INFO decoding enabled" in exception_summary
            assert "Runtime functions        1" in exception_summary
            exception_page_node = screen._exception_page_nodes[0]
            exception_page_node.expand()
            await pilot.pause()
            tree.move_cursor(exception_page_node)
            await pilot.pause()
            exception_page = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "RUNTIME_FUNCTION records 0–0" in exception_page
            assert "0x00001100" in exception_page
            assert "0x00001150" in exception_page
            assert "0x00006400" in exception_page
            tree.move_cursor(screen._exception_function_nodes[0])
            await pilot.pause()
            unwind_view = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "RUNTIME_FUNCTION 0" in unwind_view
            assert "UNWIND_INFO" in unwind_view
            assert "UNW_FLAG_EHANDLER" in unwind_view
            assert "SizeOfProlog             8" in unwind_view
            assert "CountOfCodes             2" in unwind_view
            assert "FrameRegister            5 (RBP)" in unwind_view
            assert "UWOP_ALLOC_SMALL — allocate 32 bytes" in unwind_view
            assert "UWOP_PUSH_NONVOL — push nonvolatile register RBP" in unwind_view
            assert "Exception handler RVA    0x00001200" in unwind_view
            assert "Handler file offset      0x500" in unwind_view
            assert "Language data file offset 0x44c" in unwind_view
            tree.move_cursor(screen._load_config_root)
            await pilot.pause()
            load_config_view = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "Load Configuration Directory" in load_config_view
            assert "Directory file offset    0x00000580" in load_config_view
            assert "Declared Size            0x140" in load_config_view
            assert "GuardFlags               0x00c00500" in load_config_view
            assert "IMAGE_GUARD_CF_INSTRUMENTED" in load_config_view
            assert "IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT" in load_config_view
            assert "IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT" in load_config_view
            assert "IMAGE_GUARD_XFG_ENABLED" in load_config_view
            assert "Exploit-mitigation assessment" in load_config_view
            assert "ASLR                             structurally compatible" in load_config_view
            assert "Control Flow Guard               present" in load_config_view
            assert "Stack security cookie (/GS)      cookie present" in load_config_view
            assert "SafeSEH                          not applicable to x64" in load_config_view
            assert "Raw load-config fields" in load_config_view
            assert "SecurityCookie" in load_config_view
            assert "target RVA 0x6500, file offset 0x520" in load_config_view
            tree.move_cursor(screen._cfg_root)
            await pilot.pause()
            cfg_view = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "Control Flow Guard evidence" in cfg_view
            assert "Optional Header GUARD_CF      set" in cfg_view
            assert "CF_INSTRUMENTED               set" in cfg_view
            assert "CF_FUNCTION_TABLE_PRESENT     set" in cfg_view
            assert "GuardCFCheckFunctionPointer" in cfg_view
            assert "Guard Function ID table (GFIDS)" in cfg_view
            assert "Declared targets             3" in cfg_view
            assert "Parsed targets               3" in cfg_view
            assert "Entry stride                 4 bytes" in cfg_view
            assert "Strictly sorted and unique   yes" in cfg_view
            assert "Complete table               yes" in cfg_view
            tree.move_cursor(screen._cfg_page_nodes[0])
            await pilot.pause()
            cfg_targets = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "GFIDS targets 0–2" in cfg_targets
            assert "0x00001010" in cfg_targets
            assert "0x00001200" in cfg_targets
            assert "0x00006500" in cfg_targets
            assert "0x00000410" in cfg_targets
            tree.move_cursor(screen._authenticode_root)
            await pilot.pause()
            authenticode_view = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "Authenticode / Attribute Certificate Table" in authenticode_view
            assert "file offset—not an RVA" in authenticode_view
            assert "Table file offset          0x00000600" in authenticode_view
            assert "WIN_CERTIFICATE entries    1" in authenticode_view
            assert "Authenticode digest matches 1" in authenticode_view
            tree.move_cursor(screen._certificate_nodes[0])
            await pilot.pause()
            certificate_view = "\n".join(
                line.text for line in screen.query_one("#pe-directories-log").lines
            )
            assert "WIN_CERTIFICATE 0" in certificate_view
            assert "WIN_CERT_REVISION_2_0" in certificate_view
            assert "WIN_CERT_TYPE_PKCS_SIGNED_DATA" in certificate_view
            assert "Authenticode image-digest evidence" in certificate_view
            assert "Digest comparison           MATCH" in certificate_view
            assert "PKCS#7 signers" in certificate_view
            assert "issuer=Test CA; serial=0x1234" in certificate_view
            assert "Signed-content digest    MATCH" in certificate_view
            assert "Cryptographic signature VALID" in certificate_view
            assert "Embedded X.509 certificates" in certificate_view
            assert "Common Name: Test Signer" in certificate_view
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, CertificatePayloadScreen)
            certificate_payload_view = "\n".join(
                line.text
                for line in app.screen.query_one("#certificate-payload-log").lines
            )
            assert "bCertificate payload" in certificate_payload_view
            assert "PKCS7" in certificate_payload_view
            await pilot.press("escape")
            await pilot.pause()
            screen = app.screen
            tabs = screen.query_one("#pe-tabs")
            tabs.active = "pe-import-descriptors"
            await pilot.pause()
            descriptors = "\n".join(
                line.text
                for line in screen.query_one("#pe-import-descriptors-log").lines
            )
            assert "IMAGE_IMPORT_DESCRIPTOR records" in descriptors
            assert "OriginalFirstThunk (INT)" in descriptors
            assert "TimeDateStamp" in descriptors
            assert "ForwarderChain" in descriptors
            assert "Name" in descriptors
            assert "FirstThunk (IAT)" in descriptors
            assert "All-zero terminator" in descriptors
            assert "IMAGE_DELAYLOAD_DESCRIPTOR records" in descriptors
            assert "Attributes / grAttrs" in descriptors
            assert "DllName / szName" in descriptors
            assert "ModuleHandle / phmod" in descriptors
            assert "ImportAddressTable / pIAT" in descriptors
            assert "ImportNameTable / pINT" in descriptors
            assert "BoundImportAddress / pBoundIAT" in descriptors
            assert "UnloadInformation / pUnloadIAT" in descriptors
            assert "TimeDateStamp / dwTimeStamp" in descriptors
            assert {pane.id for pane in screen.query("TabbedContent TabPane")} == {
                "pe-overview",
                "pe-hex",
                "pe-headers",
                "pe-sections",
                "pe-directories",
                "pe-import-descriptors",
                "pe-imports",
                "pe-exports",
            }

    asyncio.run(scenario())
