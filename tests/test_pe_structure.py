import asyncio
from types import SimpleNamespace

from textual.app import App

from analysis import pe_structure
from analysis.pe_structure import (
    PEDataDirectory,
    PEExportRecord,
    PEHeader,
    PEHeaderField,
    PEImportRecord,
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
from ui.pe_tui import PEStructureScreen


class FakeStructure:
    def __init__(self, name, offset, values):
        self._name = name
        self._offset = offset
        self._values = values

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
        ]
        self.sections = [FakeSection()]
        imported = SimpleNamespace(
            name=b"CreateFileW", ordinal=None, hint=120, address=0x140004000
        )
        delayed = SimpleNamespace(
            name=None, ordinal=7, hint=None, address=0x140004008
        )
        self.DIRECTORY_ENTRY_IMPORT = [
            SimpleNamespace(dll=b"KERNEL32.dll", imports=[imported])
        ]
        self.DIRECTORY_ENTRY_DELAY_IMPORT = [
            SimpleNamespace(dll=b"DELAY.dll", imports=[delayed])
        ]
        exported = SimpleNamespace(
            name=b"Run", ordinal=1, address=0x1100, forwarder=b"OTHER.Target"
        )
        self.DIRECTORY_ENTRY_EXPORT = SimpleNamespace(symbols=[exported])

    @staticmethod
    def get_overlay_data_start_offset():
        return 0x800

    def close(self):
        self.closed = True


def _model(raw_data=None):
    raw_data = raw_data if raw_data is not None else bytes(range(256)) * 20
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
    )


def test_pe_structure_uses_analyzed_bytes_and_recovers_all_tables(monkeypatch):
    fake_pe = FakePE()
    monkeypatch.setattr(pe_structure.pefile, "PE", lambda **kwargs: fake_pe)
    raw_data = b"MZ" + bytes(4094)
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
            assert {pane.id for pane in screen.query("TabbedContent TabPane")} == {
                "pe-overview",
                "pe-hex",
                "pe-headers",
                "pe-sections",
                "pe-directories",
                "pe-imports",
                "pe-exports",
            }

    asyncio.run(scenario())
