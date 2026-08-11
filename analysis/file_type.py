"""Bounded, evidence-led file-type identification.

The detector never executes or extracts the inspected file.  It combines a
curated signature table, safe container metadata inspection, optional libmagic
classification, and a low-confidence AI fallback for genuinely unknown data.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import mimetypes
import os
import re
import stat
import zipfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

import config

try:
    import magic

    HAS_LIBMAGIC = True
except ImportError:
    magic = None
    HAS_LIBMAGIC = False


@dataclass(frozen=True)
class FileTypeResult:
    type_name: str
    mime_type: str
    extensions: tuple[str, ...] = ()
    confidence: float = 0.0
    method: str = "unknown"
    evidence: tuple[str, ...] = ()
    ai_used: bool = False
    alternatives: tuple[str, ...] = ()
    sha256: str = ""
    size: int = 0

    @property
    def is_unknown(self) -> bool:
        return self.type_name == "Unknown"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class _Signature:
    offset: int
    magic: bytes
    type_name: str
    mime_type: str
    extensions: tuple[str, ...]
    confidence: float = 0.99
    mask: bytes | None = None


_SIGNATURES = (
    _Signature(0, b"MZ", "DOS/Windows executable", "application/x-dosexec", (".exe", ".dll", ".sys"), 0.75),
    _Signature(0, b"\x7fELF", "ELF executable/object", "application/x-elf", (".elf", ".so", ".o")),
    _Signature(0, b"\xfe\xed\xfa\xce", "Mach-O 32-bit", "application/x-mach-binary", (".macho",)),
    _Signature(0, b"\xce\xfa\xed\xfe", "Mach-O 32-bit (little-endian)", "application/x-mach-binary", (".macho",)),
    _Signature(0, b"\xfe\xed\xfa\xcf", "Mach-O 64-bit", "application/x-mach-binary", (".macho",)),
    _Signature(0, b"\xcf\xfa\xed\xfe", "Mach-O 64-bit (little-endian)", "application/x-mach-binary", (".macho",)),
    _Signature(0, b"\xca\xfe\xba\xbe", "Mach-O universal/Java class candidate", "application/octet-stream", (".macho", ".class"), 0.80),
    _Signature(0, b"\xca\xfe\xba\xbf", "Mach-O universal 64-bit", "application/x-mach-binary", (".macho",)),
    _Signature(0, b"\x00asm", "WebAssembly module", "application/wasm", (".wasm",)),
    _Signature(0, b"dex\n", "Android DEX bytecode", "application/vnd.android.dex", (".dex",)),
    _Signature(0, b"%PDF-", "PDF document", "application/pdf", (".pdf",)),
    _Signature(0, b"PK\x03\x04", "ZIP archive", "application/zip", (".zip",)),
    _Signature(0, b"PK\x05\x06", "Empty ZIP archive", "application/zip", (".zip",)),
    _Signature(0, b"PK\x07\x08", "Spanned ZIP archive", "application/zip", (".zip",)),
    _Signature(0, b"\x1f\x8b\x08", "Gzip archive", "application/gzip", (".gz", ".tgz")),
    _Signature(0, b"BZh", "Bzip2 archive", "application/x-bzip2", (".bz2",)),
    _Signature(0, b"\xfd7zXZ\x00", "XZ archive", "application/x-xz", (".xz",)),
    _Signature(0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "application/x-7z-compressed", (".7z",)),
    _Signature(0, b"Rar!\x1a\x07", "RAR archive", "application/vnd.rar", (".rar",)),
    _Signature(0, b"MSCF", "Microsoft Cabinet archive", "application/vnd.ms-cab-compressed", (".cab",)),
    _Signature(257, b"ustar", "TAR archive", "application/x-tar", (".tar",)),
    _Signature(0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE Compound Document", "application/x-ole-storage", (".doc", ".xls", ".ppt", ".msi"), 0.95),
    _Signature(0, b"SQLite format 3\x00", "SQLite database", "application/vnd.sqlite3", (".sqlite", ".db")),
    _Signature(0, b"\x89PNG\r\n\x1a\n", "PNG image", "image/png", (".png",)),
    _Signature(0, b"\xff\xd8\xff", "JPEG image", "image/jpeg", (".jpg", ".jpeg")),
    _Signature(0, b"GIF87a", "GIF image", "image/gif", (".gif",)),
    _Signature(0, b"GIF89a", "GIF image", "image/gif", (".gif",)),
    _Signature(0, b"BM", "BMP image", "image/bmp", (".bmp",), 0.95),
    _Signature(0, b"II*\x00", "TIFF image (little-endian)", "image/tiff", (".tif", ".tiff")),
    _Signature(0, b"MM\x00*", "TIFF image (big-endian)", "image/tiff", (".tif", ".tiff")),
    _Signature(0, b"fLaC", "FLAC audio", "audio/flac", (".flac",)),
    _Signature(0, b"OggS", "Ogg container", "application/ogg", (".ogg", ".oga", ".ogv")),
    _Signature(0, b"ID3", "MP3 audio with ID3", "audio/mpeg", (".mp3",), 0.98),
    _Signature(0, b"\x1aE\xdf\xa3", "Matroska/WebM container", "video/x-matroska", (".mkv", ".webm"), 0.95),
    _Signature(0, b"regf", "Windows Registry hive", "application/x-windows-registry", (".dat", ".hiv")),
    _Signature(0, b"ElfFile\x00", "Windows Event Log", "application/x-evtx", (".evtx",)),
    _Signature(0, b"\x4d\x3c\xb2\xa1", "PCAP capture (little-endian)", "application/vnd.tcpdump.pcap", (".pcap",)),
    _Signature(0, b"\xa1\xb2\x3c\x4d", "PCAP capture (big-endian)", "application/vnd.tcpdump.pcap", (".pcap",)),
    _Signature(0, b"\x0a\x0d\x0d\x0a", "PCAP-NG capture", "application/x-pcapng", (".pcapng",)),
    _Signature(0, b"QFI\xfb", "QEMU QCOW disk image", "application/x-qemu-disk", (".qcow", ".qcow2")),
    _Signature(0, b"KDMV", "VMware virtual disk", "application/x-vmdk", (".vmdk",)),
)


class FileTypeDetector:
    """Identify file families without trusting filename extensions."""

    MAX_AI_HEADER_BYTES = 96
    MAX_ZIP_NAMES = 4096

    def identify(
        self,
        path: str | os.PathLike[str],
        *,
        ai_identifier: Callable[[dict], FileTypeResult | dict | None] | None = None,
    ) -> FileTypeResult:
        path_obj = Path(path)
        try:
            path_stat = path_obj.stat()
        except OSError as exc:
            raise ValueError(f"Unable to inspect file path: {exc}") from exc
        if not stat.S_ISREG(path_stat.st_mode):
            raise ValueError("File path must point to a regular file")
        if path_stat.st_size > config.MAX_BINARY_SIZE_BYTES:
            raise ValueError(
                f"File is too large ({path_stat.st_size} bytes); maximum is "
                f"{config.MAX_BINARY_SIZE_BYTES} bytes"
            )

        open_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(path_obj, open_flags)
        except OSError as exc:
            raise ValueError(f"Unable to open file path: {exc}") from exc
        with os.fdopen(descriptor, "rb") as stream:
            opened_stat = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened_stat.st_mode):
                raise ValueError("File path must point to a regular file")
            if opened_stat.st_size > config.MAX_BINARY_SIZE_BYTES:
                raise ValueError(
                    f"File is too large ({opened_stat.st_size} bytes); maximum is "
                    f"{config.MAX_BINARY_SIZE_BYTES} bytes"
                )
            data = stream.read(config.MAX_BINARY_SIZE_BYTES + 1)
        if len(data) > config.MAX_BINARY_SIZE_BYTES:
            raise ValueError(
                f"File exceeds the {config.MAX_BINARY_SIZE_BYTES}-byte identification limit"
            )
        sha256 = hashlib.sha256(data).hexdigest()
        result = self.identify_bytes(data, filename=path_obj.name)
        result = self._with_file_metadata(result, sha256, len(data))
        if result.is_unknown and ai_identifier is not None:
            evidence = self.ai_evidence(data, path_obj.name, sha256)
            try:
                candidate = ai_identifier(evidence)
            except Exception as exc:
                return self._with_evidence(result, f"AI fallback unavailable: {type(exc).__name__}")
            normalized = self._normalize_ai_result(candidate, sha256, len(data))
            if normalized is not None:
                return normalized
        return result

    def identify_bytes(self, data: bytes, *, filename: str = "") -> FileTypeResult:
        if not data:
            return FileTypeResult("Empty file", "application/x-empty", confidence=1.0, method="content")

        special = self._structured_signatures(data)
        if special is not None:
            return special

        for signature in _SIGNATURES:
            candidate = data[signature.offset:signature.offset + len(signature.magic)]
            if signature.mask is not None:
                candidate = bytes(a & b for a, b in zip(candidate, signature.mask, strict=False))
            if candidate == signature.magic:
                result = FileTypeResult(
                    signature.type_name,
                    signature.mime_type,
                    signature.extensions,
                    signature.confidence,
                    "magic",
                    (f"signature at offset {signature.offset}",),
                )
                if signature.mime_type == "application/zip":
                    return self._identify_zip(data, result)
                return result

        libmagic_result = self._identify_libmagic(data)
        if libmagic_result is not None:
            return libmagic_result
        text_result = self._identify_text(data, filename)
        if text_result is not None:
            return text_result
        return FileTypeResult(
            "Unknown",
            "application/octet-stream",
            confidence=0.0,
            method="unknown",
            evidence=("no supported deterministic signature matched",),
        )

    def ai_evidence(self, data: bytes, filename: str, sha256: str) -> dict:
        sample = data[:4096]
        return {
            "filename_extension": Path(filename).suffix.lower()[:32],
            "size": len(data),
            "sha256": sha256,
            "header_hex": data[:self.MAX_AI_HEADER_BYTES].hex(),
            "tail_hex": data[-32:].hex() if data else "",
            "sample_entropy": round(self._entropy(sample), 4),
            "nul_ratio": round(sample.count(0) / max(1, len(sample)), 4),
        }

    @staticmethod
    def _structured_signatures(data: bytes) -> FileTypeResult | None:
        if len(data) >= 64 and data[:2] == b"MZ":
            pe_offset = int.from_bytes(data[0x3C:0x40], "little")
            if 0 < pe_offset <= len(data) - 4 and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                return FileTypeResult(
                    "Windows Portable Executable",
                    "application/vnd.microsoft.portable-executable",
                    (".exe", ".dll", ".sys"),
                    1.0,
                    "structure",
                    ("MZ header and PE signature at e_lfanew",),
                )
        if len(data) >= 12 and data[:4] == b"RIFF":
            form = data[8:12]
            mapping = {
                b"WAVE": ("WAV audio", "audio/wav", (".wav",)),
                b"AVI ": ("AVI video", "video/x-msvideo", (".avi",)),
                b"WEBP": ("WebP image", "image/webp", (".webp",)),
            }
            if form in mapping:
                name, mime, extensions = mapping[form]
                return FileTypeResult(name, mime, extensions, 0.99, "magic", ("RIFF form type",))
        if len(data) >= 12 and data[4:8] == b"ftyp":
            brand = data[8:12].decode("ascii", errors="replace")
            name = "QuickTime media" if brand == "qt  " else "ISO Base Media (MP4-family)"
            mime = "video/quicktime" if brand == "qt  " else "video/mp4"
            return FileTypeResult(name, mime, (".mov",) if brand == "qt  " else (".mp4", ".m4a", ".m4v"), 0.97, "magic", (f"ftyp brand {brand!r}",))
        if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
            return FileTypeResult("ISO 9660 disk image", "application/x-iso9660-image", (".iso",), 0.99, "magic", ("CD001 volume descriptor",))
        return None

    def _identify_zip(self, data: bytes, base: FileTypeResult) -> FileTypeResult:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = archive.namelist()[:self.MAX_ZIP_NAMES]
                name_set = set(names)
                if "AndroidManifest.xml" in name_set and any(name.endswith("classes.dex") for name in names):
                    return FileTypeResult("Android APK", "application/vnd.android.package-archive", (".apk",), 1.0, "container", ("ZIP with AndroidManifest.xml and DEX",))
                if "META-INF/MANIFEST.MF" in name_set:
                    return FileTypeResult("Java archive", "application/java-archive", (".jar",), 0.99, "container", ("ZIP with JAR manifest",))
                for prefix, name, mime, extensions in (
                    ("word/", "Microsoft Word OOXML document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", (".docx",)),
                    ("xl/", "Microsoft Excel OOXML workbook", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", (".xlsx",)),
                    ("ppt/", "Microsoft PowerPoint OOXML presentation", "application/vnd.openxmlformats-officedocument.presentationml.presentation", (".pptx",)),
                ):
                    if "[Content_Types].xml" in name_set and any(item.startswith(prefix) for item in names):
                        return FileTypeResult(name, mime, extensions, 1.0, "container", (f"OOXML {prefix.rstrip('/')} entries",))
                if "mimetype" in name_set:
                    with archive.open("mimetype") as member:
                        value = member.read(128).decode("ascii", errors="ignore")
                    if value == "application/epub+zip":
                        return FileTypeResult("EPUB document", value, (".epub",), 1.0, "container", ("EPUB mimetype entry",))
                    odf = {
                        "application/vnd.oasis.opendocument.text": ("OpenDocument text", (".odt",)),
                        "application/vnd.oasis.opendocument.spreadsheet": ("OpenDocument spreadsheet", (".ods",)),
                        "application/vnd.oasis.opendocument.presentation": ("OpenDocument presentation", (".odp",)),
                    }
                    if value in odf:
                        name, extensions = odf[value]
                        return FileTypeResult(name, value, extensions, 1.0, "container", ("OpenDocument mimetype entry",))
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
            return self._with_evidence(base, "ZIP structure is malformed or encrypted")
        return base

    @staticmethod
    def _identify_text(data: bytes, filename: str) -> FileTypeResult | None:
        sample = data[:65536]
        if b"\x00" in sample:
            return None
        try:
            text = sample.decode("utf-8")
        except UnicodeDecodeError:
            return None
        stripped = text.lstrip("\ufeff \t\r\n")
        if stripped.startswith("#!"):
            interpreter = stripped.splitlines()[0][:160]
            return FileTypeResult("Script", "text/x-script", confidence=0.98, method="content", evidence=(interpreter,))
        if stripped.startswith("{\\rtf"):
            return FileTypeResult("Rich Text Format", "application/rtf", (".rtf",), 0.99, "content", ("RTF control header",))
        if stripped.startswith(("<?xml", "<svg")):
            if stripped.startswith("<svg") or re.search(r"<svg(?:\s|>)", stripped[:1024], re.I):
                return FileTypeResult("SVG image", "image/svg+xml", (".svg",), 0.98, "content", ("SVG root element",))
            return FileTypeResult("XML document", "application/xml", (".xml",), 0.95, "content", ("XML declaration/root",))
        if re.match(r"<!doctype\s+html|<html(?:\s|>)", stripped[:1024], re.I):
            return FileTypeResult("HTML document", "text/html", (".html", ".htm"), 0.98, "content", ("HTML root/doctype",))
        if stripped[:1] in {"{", "["}:
            try:
                json.loads(stripped)
                return FileTypeResult("JSON document", "application/json", (".json",), 0.99, "content", ("valid JSON syntax",))
            except json.JSONDecodeError:
                pass
        suffix = Path(filename).suffix.lower()
        language = {
            ".py": ("Python source", "text/x-python"),
            ".js": ("JavaScript source", "text/javascript"),
            ".ts": ("TypeScript source", "text/typescript"),
            ".sh": ("Shell script", "text/x-shellscript"),
            ".ps1": ("PowerShell script", "text/x-powershell"),
            ".c": ("C source", "text/x-c"),
            ".cpp": ("C++ source", "text/x-c++"),
            ".java": ("Java source", "text/x-java-source"),
            ".md": ("Markdown document", "text/markdown"),
            ".yaml": ("YAML document", "application/yaml"),
            ".yml": ("YAML document", "application/yaml"),
            ".csv": ("CSV text", "text/csv"),
        }.get(suffix)
        if language:
            return FileTypeResult(language[0], language[1], (suffix,), 0.75, "text+extension", ("valid UTF-8 text; extension used as a hint",))
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
        if printable / max(1, len(text)) >= 0.95:
            return FileTypeResult("UTF-8 text", "text/plain", (".txt",), 0.90, "content", ("valid predominantly printable UTF-8",))
        return None

    @staticmethod
    def _identify_libmagic(data: bytes) -> FileTypeResult | None:
        if not HAS_LIBMAGIC or magic is None:
            return None
        try:
            mime = str(magic.from_buffer(data, mime=True) or "").strip()
            description = str(magic.from_buffer(data) or "").strip()
        except Exception:
            return None
        if not mime or mime == "application/octet-stream" or description.lower() == "data":
            return None
        extensions = tuple(mimetypes.guess_all_extensions(mime, strict=False)[:8])
        return FileTypeResult(
            type_name=description[:160],
            mime_type=mime[:160],
            extensions=extensions,
            confidence=0.90,
            method="libmagic",
            evidence=("identified by the installed libmagic database",),
        )

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in counts if count)

    @staticmethod
    def _with_file_metadata(result: FileTypeResult, sha256: str, size: int) -> FileTypeResult:
        values = result.to_dict()
        values.update(sha256=sha256, size=size)
        return FileTypeResult(**values)

    @staticmethod
    def _with_evidence(result: FileTypeResult, message: str) -> FileTypeResult:
        values = result.to_dict()
        values["evidence"] = (*result.evidence, message[:256])
        return FileTypeResult(**values)

    @staticmethod
    def _normalize_ai_result(candidate, sha256: str, size: int) -> FileTypeResult | None:
        if isinstance(candidate, FileTypeResult):
            values = candidate.to_dict()
        elif isinstance(candidate, dict):
            values = dict(candidate)
        else:
            return None
        type_name = str(values.get("type_name") or "Unknown")[:160]
        if type_name == "Unknown":
            return None
        def bounded_items(name: str, limit: int) -> tuple[str, ...]:
            items = values.get(name, ())
            if not isinstance(items, (list, tuple)):
                return ()
            return tuple(str(item)[:limit] for item in items[:8])

        extensions = bounded_items("extensions", 32)
        alternatives = bounded_items("alternatives", 160)
        evidence = bounded_items("evidence", 256)
        try:
            confidence = min(0.60, max(0.0, float(values.get("confidence", 0.0))))
        except (TypeError, ValueError):
            confidence = 0.0
        return FileTypeResult(
            type_name=type_name,
            mime_type=str(values.get("mime_type") or "application/octet-stream")[:160],
            extensions=extensions,
            confidence=confidence,
            method="ai-inference",
            evidence=evidence or ("AI inference from bounded metadata; analyst verification required",),
            ai_used=True,
            alternatives=alternatives,
            sha256=sha256,
            size=size,
        )
