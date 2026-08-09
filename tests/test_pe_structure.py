import asyncio
import hashlib
import struct
from types import SimpleNamespace

from textual.app import App

from analysis import pe_structure
from analysis.pe_structure import (
    PEASLRAssessment,
    PEBaseRelocationBlock,
    PEBaseRelocationEntry,
    PEDataDirectory,
    PEDelayImportDescriptorRecord,
    PEExportRecord,
    PEHeader,
    PEHeaderField,
    PEImportDescriptorRecord,
    PEImportRecord,
    PEResourceDataRecord,
    PEResourceDirectoryRecord,
    PESectionRecord,
    PEStructure,
    PEStructureAnalyzer,
    decode_coff_characteristics,
    decode_dll_characteristics,
    decode_section_characteristics,
    dll_mitigation_clues,
    page_count,
    render_hex_page,
)
from ui.pe_tui import (
    PEStructureScreen,
    ResourcePayloadScreen,
    export_resource,
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
            SimpleNamespace(VirtualAddress=0, Size=0),
            SimpleNamespace(VirtualAddress=0, Size=0),
            SimpleNamespace(VirtualAddress=0x7000, Size=0x0C),
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
        exported = SimpleNamespace(
            name=b"Run", ordinal=1, address=0x1100, forwarder=b"OTHER.Target"
        )
        self.DIRECTORY_ENTRY_EXPORT = SimpleNamespace(symbols=[exported])

    @staticmethod
    def get_overlay_data_start_offset():
        return 0x800

    @staticmethod
    def get_offset_from_rva(rva):
        if rva == 0x6000:
            return 0x300
        raise pe_structure.pefile.PEFormatError("unmapped test RVA")

    def close(self):
        self.closed = True


def _model(raw_data=None):
    raw_data_buffer = bytearray(
        raw_data if raw_data is not None else bytes(range(256)) * 20
    )
    resource_bytes = b"<assembly>safe</assembly>"
    raw_data_buffer[0x300:0x300 + len(resource_bytes)] = resource_bytes
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
