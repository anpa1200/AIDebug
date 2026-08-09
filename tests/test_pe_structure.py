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
    Characteristics = 0x60000020

    @staticmethod
    def get_entropy():
        return 6.25


class FakePE:
    closed = False

    def __init__(self):
        self.DOS_HEADER = FakeStructure("IMAGE_DOS_HEADER", 0, {"e_magic": 0x5A4D})
        self.DOS_HEADER.e_lfanew = 0x80
        self.NT_HEADERS = SimpleNamespace(Signature=0x4550)
        self.FILE_HEADER = FakeStructure(
            "IMAGE_FILE_HEADER", 0x84, {"Machine": 0x8664, "NumberOfSections": 1}
        )
        self.OPTIONAL_HEADER = FakeStructure(
            "IMAGE_OPTIONAL_HEADER64", 0x98, {"Magic": 0x20B}
        )
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
        ),
        data_directories=(PEDataDirectory(0, "EXPORT", 0x3000, 0x80),),
        sections=(
            PESectionRecord(".text", 0x1000, 0x200, 0x400, 0x200, 0x60000020, 6.1),
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
    assert [(item.kind, item.name) for item in model.imports] == [
        ("import", "CreateFileW"),
        ("delay", "ordinal_7"),
    ]
    assert model.exports[0].forwarder == "OTHER.Target"
    assert model.overlay_offset == 0x800
    assert model.overlay_size == 2048
    assert fake_pe.closed


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
