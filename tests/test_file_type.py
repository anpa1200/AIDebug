import io
import zipfile

import pytest

from analysis import file_type
from analysis.file_type import FileTypeDetector


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return output.getvalue()


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"\x7fELF" + bytes(64), "ELF executable/object"),
        (b"%PDF-1.7\n", "PDF document"),
        (b"\x89PNG\r\n\x1a\n" + bytes(16), "PNG image"),
        (b"RIFF" + bytes(4) + b"WAVE", "WAV audio"),
        (b"\x00\x00\x00\x18ftypisom" + bytes(12), "ISO Base Media (MP4-family)"),
        (b"SQLite format 3\x00" + bytes(32), "SQLite database"),
        (b"#!/usr/bin/env python3\nprint('ok')\n", "Script"),
    ],
)
def test_common_signatures(data, expected):
    result = FileTypeDetector().identify_bytes(data)
    assert result.type_name == expected
    assert result.confidence >= 0.90
    assert result.ai_used is False


def test_pe_uses_e_lfanew_structure():
    data = bytearray(256)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (128).to_bytes(4, "little")
    data[128:132] = b"PE\x00\x00"
    result = FileTypeDetector().identify_bytes(bytes(data), filename="renamed.jpg")
    assert result.type_name == "Windows Portable Executable"
    assert result.method == "structure"
    assert result.confidence == 1.0


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        ({"AndroidManifest.xml": b"x", "classes.dex": b"dex\n"}, "Android APK"),
        ({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0"}, "Java archive"),
        ({"[Content_Types].xml": b"x", "word/document.xml": b"x"}, "Microsoft Word OOXML document"),
        ({"mimetype": b"application/epub+zip"}, "EPUB document"),
    ],
)
def test_zip_container_refinement(files, expected):
    result = FileTypeDetector().identify_bytes(_zip_bytes(files))
    assert result.type_name == expected
    assert result.method == "container"


def test_extension_is_only_a_hint_for_text():
    result = FileTypeDetector().identify_bytes(b"print('hello')\n", filename="sample.py")
    assert result.type_name == "Python source"
    assert result.method == "text+extension"
    assert result.confidence < 0.90


def test_unknown_uses_bounded_ai_fallback(tmp_path):
    sample = tmp_path / "mystery.bin"
    sample.write_bytes(bytes(range(1, 200)))
    observed = {}

    def identify(evidence):
        observed.update(evidence)
        return {
            "type_name": "Proprietary telemetry container",
            "mime_type": "application/octet-stream",
            "extensions": [".tlm"],
            "confidence": 0.95,
            "evidence": ["header layout resembles a telemetry record"],
            "alternatives": ["encrypted data"],
        }

    result = FileTypeDetector().identify(sample, ai_identifier=identify)
    assert result.ai_used is True
    assert result.method == "ai-inference"
    assert result.confidence == 0.60
    assert set(observed) == {
        "filename_extension", "size", "sha256", "header_hex", "tail_hex",
        "sample_entropy", "nul_ratio",
    }
    assert len(observed["header_hex"]) <= FileTypeDetector.MAX_AI_HEADER_BYTES * 2
    assert str(sample) not in str(observed)


def test_unknown_stays_unknown_without_ai():
    result = FileTypeDetector().identify_bytes(bytes(range(1, 200)))
    assert result.is_unknown
    assert result.ai_used is False


def test_optional_libmagic_extends_local_database(monkeypatch):
    class FakeMagic:
        @staticmethod
        def from_buffer(data, mime=False):
            assert data
            return "application/x-custom" if mime else "Custom forensic artifact"

    monkeypatch.setattr(file_type, "HAS_LIBMAGIC", True)
    monkeypatch.setattr(file_type, "magic", FakeMagic())
    result = FileTypeDetector().identify_bytes(bytes(range(1, 200)))
    assert result.type_name == "Custom forensic artifact"
    assert result.mime_type == "application/x-custom"
    assert result.method == "libmagic"
    assert result.ai_used is False
