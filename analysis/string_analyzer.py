"""Offset-aware string extraction and security-oriented classification.

The implementation is deliberately dependency-free.  It treats strings as evidence:
the original file offset and encoding are retained, classification can be multi-label,
and imported APIs are annotated rather than silently mixed with extracted bytes.
"""

from __future__ import annotations

import codecs
import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import unicodedata
from collections import Counter, defaultdict, deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

import config

CATEGORY_ORDER = (
    "url",
    "ip_address",
    "ipv4",
    "ipv6",
    "domain",
    "email",
    "registry_key",
    "named_pipe",
    "device_path",
    "unc_path",
    "windows_path",
    "posix_path",
    "dll",
    "api",
    "powershell",
    "command",
    "service",
    "mutex",
    "hash",
    "guid",
    "crypto_material",
    "pdb_path",
    "filename",
    "scheduled_task",
    "persistence",
    "anti_analysis",
    "credential",
    "user_agent",
    "base64",
    "hex",
    "config",
    "debug",
    "error",
    "text",
)

MAX_CANDIDATES_IN_MEMORY = config.MAX_EXTRACTED_STRINGS
MAX_RECORDED_OCCURRENCES = 4_096
MAX_ENTITIES_PER_RECORD = 32
MAX_ENTITY_NAME_CHARS = 256
MAX_IMPORT_MODULES_PER_API = 8
MAX_IMPORT_MODULE_NAME_CHARS = 128
MAX_IMPORT_PROVENANCE_CHARS = 4_096
MAX_RECORD_DESCRIPTION_CHARS = 4_096
UTF16_SCAN_CHUNK_BYTES = 1024 * 1024

_WEIGHTS = {
    "url": 30,
    "ip_address": 34,
    "ipv4": 34,
    "ipv6": 34,
    "domain": 18,
    "email": 14,
    "registry_key": 28,
    "named_pipe": 38,
    "device_path": 28,
    "unc_path": 24,
    "windows_path": 14,
    "posix_path": 12,
    "dll": 10,
    "api": 16,
    "powershell": 45,
    "command": 32,
    "service": 20,
    "mutex": 30,
    "hash": 25,
    "guid": 12,
    "crypto_material": 30,
    "pdb_path": 16,
    "filename": 6,
    "scheduled_task": 34,
    "persistence": 40,
    "anti_analysis": 38,
    "credential": 38,
    "user_agent": 20,
    "base64": 18,
    "hex": 12,
    "config": 8,
    "debug": 10,
    "error": 8,
    "text": 0,
}

_URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"']+")
_DOMAIN_TOKEN_RE = re.compile(
    r"(?iu)(?<![@\w.-])(?:[a-z0-9\u0080-\uffff](?:[a-z0-9\u0080-\uffff-]{0,61}"
    r"[a-z0-9\u0080-\uffff])?\.)+[a-z0-9\u0080-\uffff-]{1,63}\.?(?![\w.-])"
)
_EMAIL_RE = re.compile(r"(?i)(?<![\w.+-])[\w.+-]{1,64}@[a-z0-9-]+(?:\.[a-z0-9-]+)+(?![\w.-])")
_IP_LIKE_RE = re.compile(
    r"(?i)(?<![\w.\[\]%-])(?:\[[0-9a-f:.%]+\](?::\d+)?|[0-9a-f:.%]+)"
    r"(?![\w.\[\]%-])"
)
_DLL_RE = re.compile(r"(?i)(?:^|[\\/])?([\w.+-]+(?:\.dll|\.dylib|\.so(?:\.\d+)*))\b")
_REGISTRY_RE = re.compile(
    r"(?i)(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\r\n]+"
)
_WINDOWS_PATH_RE = re.compile(r"(?i)(?<!\w)[a-z]:\\[^\r\n<>\"|?*]+")
_UNC_RE = re.compile(r"\\\\(?![.?]\\)[^\\\s]+\\[^\r\n<>\"|?*]+")
_DEVICE_RE = re.compile(r"(?i)(?:\\\\[.?]\\|\\Device\\|\\DosDevices\\)[^\r\n]+")
_POSIX_PATH_RE = re.compile(
    r"(?<![\w.])/(?:etc|tmp|var|usr|bin|sbin|home|root|opt|proc|dev|run|Library)/[^\s\x00]*"
)
_PIPE_RE = re.compile(r"(?i)(?:\\\\\.\\pipe\\|\\Device\\NamedPipe\\)[^\s\\]+")
_HASH_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})(?![0-9a-f])")
_HEX_RE = re.compile(r"(?i)^(?:0x)?[0-9a-f]{16,}$")
_B64_RE = re.compile(r"^(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
_CONFIG_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
_CONFIG_KEYS = frozenset({
    "access_key",
    "access_token",
    "api_key",
    "auth_token",
    "base_url",
    "database",
    "db",
    "debug",
    "directory",
    "empty",
    "enabled",
    "endpoint",
    "file",
    "host",
    "hostname",
    "key",
    "log_level",
    "message",
    "mode",
    "model",
    "password",
    "path",
    "port",
    "provider",
    "proxy",
    "pwd",
    "retries",
    "secret",
    "server",
    "timeout",
    "token",
    "trace",
    "url",
    "user",
    "username",
})
_CREDENTIAL_RE = re.compile(
    r"(?i)\b(?:passw(?:or)?d|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|credential|bearer)\b"
)
_ERROR_RE = re.compile(r"(?i)\b(?:error|failed|failure|fatal|exception|denied|invalid|cannot|unable)\b")
_DEBUG_RE = re.compile(r"(?i)\b(?:debug|trace|assert(?:ion)?|breakpoint|stack trace)\b")
_POWERSHELL_RE = re.compile(
    r"(?i)(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|-(?:enc|encodedcommand)\b|invoke-(?:expression|webrequest)|downloadstring\s*\()"
)
_COMMAND_RE = re.compile(
    r"(?i)(?<![\w.-])(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|wscript|cscript|rundll32|regsvr32|mshta|certutil|bitsadmin|schtasks|sc(?:\.exe)?|wmic|bash|sh|zsh|curl|wget|nc|netcat|chmod|chown|sudo|systemctl)\b"
)
_IDENTIFIER_RE = re.compile(r"(?<![\w@$?])[A-Za-z_][A-Za-z0-9_@$?]{2,127}(?![\w@$?])")
_USER_AGENT_RE = re.compile(
    r"(?i)(?:Mozilla/\d|(?:curl|Wget|python-requests|Go-http-client)/[\d.]+|User-Agent\s*:)"
)
_SERVICE_RE = re.compile(
    r"(?i)(?:\\CurrentControlSet\\Services\\|\b(?:CreateService|OpenService|StartService|DeleteService)(?:A|W)?\b|\bservice(?:name)?\s*[:=])"
)
_MUTEX_RE = re.compile(r"(?i)(?:\b(?:Global|Local)\\[^\\\s]{3,}|\bmutex\s*[:=]|\bCreateMutex(?:A|W)?\b)")
_GUID_RE = re.compile(
    r"(?i)(?<![0-9a-f])\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?(?![0-9a-f])"
)
_PEM_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?(?:PRIVATE KEY|PUBLIC KEY|CERTIFICATE)-----")
_PDB_RE = re.compile(r"(?i)(?:[a-z]:\\|/)?[^\s<>\"|?*]+\.pdb\b")
_FILENAME_RE = re.compile(
    r"(?i)(?<![\w.-])[\w()+@ -]{1,128}\.(?:exe|dll|sys|scr|com|bat|cmd|ps1|vbs|js|jar|so|dylib|bin|dat|cfg|conf|ini|json|xml|log|pdb|zip|rar|7z)(?![\w.-])"
)
_SCHEDULED_RE = re.compile(
    r"(?i)(?:\bschtasks(?:\.exe)?\b|\\Schedule\\TaskCache\\|\b(?:Register|Create)ScheduledTask\b|\bat\s+/every:)"
)
_PERSISTENCE_RE = re.compile(
    r"(?i)(?:\\CurrentVersion\\Run(?:Once)?(?:\\|$)|\\Startup\\|\\CurrentControlSet\\Services\\|\bschtasks(?:\.exe)?\b|\bCreateService(?:A|W)?\b)"
)
_ANTI_ANALYSIS_RE = re.compile(
    r"(?i)(?<!\w)(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|ptrace|OutputDebugString|sandbox|virtualbox|vmware|qemu|wireshark|procmon|x64dbg|ollydbg)(?!\w)"
)
_UTF8_RUN_RE = re.compile(
    rb"(?:"
    rb"[\x09\x20-\x7e]|"
    rb"[\xc2-\xdf][\x80-\xbf]|"
    rb"\xe0[\xa0-\xbf][\x80-\xbf]|"
    rb"[\xe1-\xec\xee-\xef][\x80-\xbf]{2}|"
    rb"\xed[\x80-\x9f][\x80-\xbf]|"
    rb"\xf0[\x90-\xbf][\x80-\xbf]{2}|"
    rb"[\xf1-\xf3][\x80-\xbf]{3}|"
    rb"\xf4[\x80-\x8f][\x80-\xbf]{2}"
    rb")+"
)
_NON_ASCII_BYTES_RE = re.compile(rb"[\x80-\xff]")
_UTF16_SHIFTED_ASCII = "".join(chr(codepoint << 8) for codepoint in range(0x20, 0x7F))
_UTF16_NONASCII_SEGMENT_RE = re.compile(
    r"(?:\A|(?<=\x00))([^\x00]*[^\x00\x01-\x7f"
    + re.escape(_UTF16_SHIFTED_ASCII)
    + r"][^\x00]*)(?=\x00|\Z)"
)
@lru_cache(maxsize=1)
def _utf16_printable_run_re() -> re.Pattern[str]:
    """Build an exact Unicode-printable run matcher once, then scan in C."""

    def escaped(codepoint: int) -> str:
        if codepoint <= 0xFF:
            return f"\\x{codepoint:02x}"
        if codepoint <= 0xFFFF:
            return f"\\u{codepoint:04x}"
        return f"\\U{codepoint:08x}"

    ranges: list[tuple[int, int]] = []
    start: int | None = None
    previous: int | None = None
    for codepoint in range(0x110000):
        character = chr(codepoint)
        printable = character == "\t" or (
            character.isprintable()
            and unicodedata.category(character) not in {"Cc", "Cs", "Cn"}
        )
        if printable:
            if start is None:
                start = previous = codepoint
            elif previous is not None and codepoint == previous + 1:
                previous = codepoint
            else:
                ranges.append((start, previous if previous is not None else start))
                start = previous = codepoint
    if start is not None:
        ranges.append((start, previous if previous is not None else start))
    character_class = "".join(
        escaped(first) if first == last else f"{escaped(first)}-{escaped(last)}"
        for first, last in ranges
    )
    return re.compile(f"[{character_class}]+")


def _bounded_match_spans(
    pattern: re.Pattern[bytes], data: bytes, limit: int
) -> tuple[list[tuple[int, int]], int]:
    """Count all regex matches, materializing only deterministic head/tail spans."""
    total = sum(1 for _ in pattern.finditer(data))
    if total == 0:
        return [], 0
    head_count = min(total, (limit + 1) // 2)
    tail_count = min(max(0, total - head_count), limit - head_count)
    tail_start = total - tail_count
    spans = [
        (match.start(), match.end())
        for index, match in enumerate(pattern.finditer(data))
        if index < head_count or index >= tail_start
    ]
    return spans, total


def _load_descriptions() -> tuple[dict[str, str], dict[str, str]]:
    path = Path(__file__).with_name("data") / "string_descriptions.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        payload = {}
    dlls = {str(k).casefold(): str(v) for k, v in payload.get("dlls", {}).items()}
    apis = {str(k).casefold(): str(v) for k, v in payload.get("apis", {}).items()}
    return dlls, apis


def _load_iana_tlds() -> frozenset[str]:
    """Load the packaged IANA root-zone snapshot without network or host data."""
    path = Path(__file__).with_name("data") / "iana_tlds.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        tlds = payload.get("tlds", ())
    except (OSError, ValueError, TypeError):
        tlds = ()
    return frozenset(
        str(value).strip().casefold()
        for value in tlds
        if isinstance(value, str) and value.strip()
    )


_DLL_DESCRIPTIONS, _API_DESCRIPTIONS = _load_descriptions()
_KNOWN_APIS = frozenset(_API_DESCRIPTIONS)
_IANA_TLDS = _load_iana_tlds()


def normalize_domain_candidate(value: str) -> str | None:
    """Return a validated ASCII IANA-rooted domain, or ``None``.

    The check is intentionally offline. It validates syntax and a bundled root-zone
    snapshot; it does not assert that the name is registered or reachable.
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if candidate.endswith("."):
        candidate = candidate[:-1]
    if not candidate or len(candidate) > 253 or ".." in candidate:
        return None
    try:
        ascii_domain = candidate.encode("idna").decode("ascii").casefold()
    except UnicodeError:
        return None
    if len(ascii_domain) > 253:
        return None
    labels = ascii_domain.split(".")
    if len(labels) < 2 or labels[-1] not in _IANA_TLDS:
        return None
    if not all(
        1 <= len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        and re.fullmatch(r"[a-z0-9-]+", label)
        for label in labels
    ):
        return None
    return ascii_domain


def valid_domain_candidate(value: str) -> bool:
    """Return whether ``value`` is a complete, IANA-rooted domain token."""
    return normalize_domain_candidate(value) is not None


def parse_ip_candidate(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse a complete IP token, optionally with a valid port or IPv6 zone."""
    if not isinstance(value, str):
        return None
    token = value.strip()
    if not token:
        return None
    host = token
    bracketed = token.startswith("[")
    if bracketed:
        closing = token.find("]")
        if closing < 0 or token.find("[", 1) >= 0 or token.find("]", closing + 1) >= 0:
            return None
        host = token[1:closing]
        remainder = token[closing + 1 :]
        if remainder:
            if not remainder.startswith(":") or not remainder[1:].isdigit():
                return None
            port = int(remainder[1:])
            if not 0 <= port <= 65535:
                return None
    elif token.count(".") == 3 and token.count(":") == 1:
        host, port_text = token.rsplit(":", 1)
        if not port_text.isdigit() or not 0 <= int(port_text) <= 65535:
            return None
    elif "]" in token or "[" in token:
        return None

    if "%" in host:
        if ":" not in host or host.count("%") != 1:
            return None
        host, zone = host.rsplit("%", 1)
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", zone):
            return None
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return None
    if bracketed and parsed.version != 6:
        return None
    if parsed.version == 6 and parsed.is_unspecified:
        return None
    return parsed


def valid_ip_candidate(value: str, version: int | None = None) -> bool:
    """Return whether ``value`` is a complete supported IP token."""
    parsed = parse_ip_candidate(value)
    return parsed is not None and (version is None or parsed.version == version)


def iter_ip_candidates(value: str) -> tuple[str, ...]:
    """Return complete, non-overlapping IP source tokens from untrusted text."""
    if not isinstance(value, str) or value.count("[") != value.count("]"):
        return ()
    return tuple(
        match.group()
        for match in _IP_LIKE_RE.finditer(value)
        if parse_ip_candidate(match.group()) is not None
    )


def valid_url_candidate(value: str) -> bool:
    """Validate a complete HTTP(S)/FTP URL and its typed host syntax."""
    if not isinstance(value, str):
        return False
    candidate = value.rstrip(".,);")
    try:
        parsed = urlsplit(candidate)
        _ = parsed.port
    except ValueError:
        return False
    if parsed.scheme.casefold() not in {"http", "https", "ftp"} or not parsed.hostname:
        return False
    hostname = parsed.hostname
    return valid_ip_candidate(hostname) or valid_domain_candidate(hostname)


def iter_domain_candidates(value: str, *, conservative: bool = True) -> tuple[str, ...]:
    """Return strict IANA-rooted domain spans from untrusted text.

    Conservative mode removes common filename and short screenshot/OCR fragments;
    it is appropriate for deterministic triage. Syntax-only consumers may disable
    that contextual filter while retaining maximal-token and IANA validation.
    """
    if not isinstance(value, str):
        return ()
    stripped = value.strip()
    if _EMAIL_RE.fullmatch(stripped) or _DLL_RE.fullmatch(stripped):
        return ()
    exact_domain = stripped.rstrip(".")
    if valid_domain_candidate(stripped):
        labels = exact_domain.split(".")
        if not conservative or not (
            len(labels) == 2
            and (len(exact_domain) < 7 or min(map(len, labels)) < 3)
        ):
            return (exact_domain,)
    results: list[str] = []
    for match in _DOMAIN_TOKEN_RE.finditer(value):
        candidate = match.group().rstrip(".")
        if not valid_domain_candidate(candidate):
            continue
        if conservative:
            labels = candidate.split(".")
            if len(labels) == 2 and (
                len(candidate) < 7 or min(map(len, labels)) < 3
            ):
                continue
            if _FILENAME_RE.fullmatch(stripped) or _PDB_RE.fullmatch(stripped):
                continue
            before = value[match.start() - 1] if match.start() else ""
            if before in {"/", "\\"} and "://" not in value[: match.start()]:
                continue
        results.append(candidate)
    return tuple(results)


def valid_config_assignment(value: str) -> bool:
    """Recognize one conservative environment/INI/YAML-style assignment line."""
    if not isinstance(value, str) or "\n" in value or "\r" in value:
        return False
    line = value.strip()
    if not line or line.startswith(("#", ";", "//")):
        return False
    if re.match(r"[A-Za-z][A-Za-z0-9+.-]*://", line):
        return False

    def credible_key(key: str, *, colon: bool) -> bool:
        folded = key.casefold()
        if folded in _CONFIG_KEYS:
            return True
        if colon:
            return False
        return bool(re.fullmatch(r"_?[A-Z][A-Z0-9_]{3,63}", key))

    def credible_value(raw_value: str, *, allow_empty: bool) -> bool:
        if not raw_value:
            return allow_empty
        if raw_value.startswith(("=", ">", "<", ":")):
            return False
        return bool(re.search(r"[A-Za-z0-9]", raw_value))

    equals = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_.-]{0,63})\s*=\s*(.*)", line)
    if equals:
        key, raw_value = equals.groups()
        if not credible_key(key, colon=False) or not credible_value(
            raw_value, allow_empty=True
        ):
            return False
        if key.casefold() not in _CONFIG_KEYS and raw_value and len(raw_value) < 2:
            return False
        return True

    colon = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_.-]{0,63})\s*:\s*(\S(?:.*\S)?)", line)
    if not colon:
        return False
    key, raw_value = colon.groups()
    # Bare prose, log prefixes, and HTTP headers are much more common than
    # standalone YAML/config keys with these names.
    if key.casefold() in {
        "accept",
        "authorization",
        "content-length",
        "content-type",
        "cookie",
        "date",
        "error",
        "exception",
        "failed",
        "fatal",
        "host",
        "location",
        "referer",
        "set-cookie",
        "trace",
        "user-agent",
        "warning",
    }:
        return False
    if not credible_key(key, colon=True) or not credible_value(
        raw_value, allow_empty=False
    ):
        return False
    if key.casefold() == "server" and not valid_url_candidate(raw_value):
        return False
    if re.search(r"\s", raw_value) and not (
        len(raw_value) >= 2 and raw_value[0] == raw_value[-1] and raw_value[0] in {'"', "'"}
    ):
        return False
    return True


@dataclass(frozen=True, slots=True)
class StringRecord:
    record_id: str
    value: str
    encoding: str
    offset: int
    address: int | None
    byte_length: int
    char_length: int
    categories: tuple[str, ...]
    confidence: str
    reasons: tuple[str, ...]
    description: str
    entities: tuple[tuple[str, str], ...]
    section: str | None
    suspicion_score: int
    occurrence_count: int = 1
    occurrence_offsets: tuple[int, ...] = ()
    occurrence_addresses: tuple[int | None, ...] = ()
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        # Compatibility names let the TUI and exported reports consume records
        # without weakening the canonical field names above.
        result.update(
            {
                "id": self.record_id,
                "file_offset": self.offset,
                "va": self.address,
                "score": self.suspicion_score,
                "descriptions": (self.description,) if self.description else (),
            }
        )
        return result

    def to_ai_dict(self) -> dict[str, Any]:
        """A compact, JSON-safe representation retaining analysis evidence."""
        return {
            "id": self.record_id,
            "value": self.value,
            "encoding": self.encoding,
            "offset": self.offset,
            "address": self.address,
            "byte_length": self.byte_length,
            "char_length": self.char_length,
            "deterministic_categories": list(self.categories),
            "deterministic_confidence": self.confidence,
            "deterministic_reasons": list(self.reasons),
            "deterministic_entities": [
                {"kind": kind, "canonical_name": name} for kind, name in self.entities
            ],
        }


@dataclass(frozen=True, slots=True)
class SmartStringAnalysis:
    """Immutable inventory and coverage metadata.

    Every selected encoding scans the complete bounded artifact. When retention
    reaches its ceiling, ``extracted_count`` and ``omitted_count`` remain exact and
    the inventory keeps deterministic evidence from both the beginning and end.
    """

    records: tuple[StringRecord, ...]
    extracted_count: int
    retained_count: int
    extraction_truncated: bool
    filtered_count: int
    counts: Mapping[str, int]
    omitted_count: int = 0
    count_is_lower_bound: bool = False
    coverage_reasons: tuple[str, ...] = ()
    scanned_bytes: int = 0
    total_bytes: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "records", tuple(self.records))
        object.__setattr__(self, "counts", MappingProxyType(dict(self.counts)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": [record.to_dict() for record in self.records],
            "extracted_count": self.extracted_count,
            "retained_count": self.retained_count,
            "extraction_truncated": self.extraction_truncated,
            "filtered_count": self.filtered_count,
            "counts": dict(self.counts),
            "omitted_count": self.omitted_count,
            "count_is_lower_bound": self.count_is_lower_bound,
            "coverage_reasons": list(self.coverage_reasons),
            "scanned_bytes": self.scanned_bytes,
            "total_bytes": self.total_bytes,
        }

    @property
    def complete(self) -> bool:
        return not self.extraction_truncated

    def filter(
        self,
        *,
        min_length: int = 0,
        category: str | None = None,
        search: str = "",
        encoding: str | None = None,
    ) -> tuple[StringRecord, ...]:
        """Return a stable filtered view for UI and programmatic consumers."""
        if min_length < 0:
            raise ValueError("min_length cannot be negative")
        needle = search.casefold().strip()
        category_key = category.casefold() if category else None
        encoding_key = encoding.casefold() if encoding else None
        result = []
        for record in self.records:
            if record.char_length < min_length:
                continue
            if category_key and category_key not in {item.casefold() for item in record.categories}:
                continue
            if encoding_key and record.encoding.casefold() != encoding_key:
                continue
            searchable = "\n".join(
                (record.value, record.description, *record.categories, *record.reasons)
            ).casefold()
            if needle and needle not in searchable:
                continue
            result.append(record)
        return tuple(result)

    def to_ai_chunks(self, max_items: int = 250, max_chars: int = 80_000) -> list[list[dict[str, Any]]]:
        """Split records into deterministic prompt-safe chunks.

        No string is silently clipped: a record that cannot fit causes an explicit
        error so the caller can choose a larger evidence budget.
        """
        if max_items < 1 or max_chars < 256:
            raise ValueError("max_items must be positive and max_chars must be at least 256")
        chunks: list[list[dict[str, Any]]] = []
        current: list[dict[str, Any]] = []
        current_chars = 2
        for record in self.records:
            item = record.to_ai_dict()
            encoded = json.dumps(item, ensure_ascii=False, separators=(",", ":"))
            if len(encoded) + 2 > max_chars:
                raise ValueError(f"String record {record.record_id!r} exceeds the max_chars chunk bound")
            item_size = len(encoded) + (1 if current else 0)
            if current and (len(current) >= max_items or current_chars + item_size > max_chars):
                chunks.append(current)
                current = []
                current_chars = 2
                item_size = len(encoded)
            current.append(item)
            current_chars += item_size
        if current:
            chunks.append(current)
        return chunks


@dataclass(slots=True)
class _Candidate:
    value: str
    encoding: str
    offset: int
    byte_length: int
    char_length: int
    truncated: bool = False


class _CandidateCollector:
    """Keep bounded head/tail evidence while counting a complete scan exactly."""

    def __init__(self, limit: int) -> None:
        self.limit = max(1, limit)
        self.head_limit = (self.limit + 1) // 2
        self.tail_limit = self.limit - self.head_limit
        self.head: list[_Candidate] = []
        self.tail: deque[_Candidate] = deque(maxlen=self.tail_limit)
        self.total = 0

    def add(self, candidate: _Candidate) -> None:
        self.total += 1
        if len(self.head) < self.head_limit:
            self.head.append(candidate)
        elif self.tail_limit:
            self.tail.append(candidate)

    def seed(self, candidates: Sequence[_Candidate], total: int) -> None:
        """Initialize an empty collector from preselected head/tail candidates."""
        if self.total or self.head or self.tail:
            raise ValueError("candidate collector can only be seeded once")
        head_count = min(total, self.head_limit, len(candidates))
        self.head.extend(candidates[:head_count])
        if self.tail_limit and len(candidates) > head_count:
            self.tail.extend(candidates[head_count:])
        self.total = total

    def finish(self) -> tuple[list[_Candidate], int]:
        return [*self.head, *self.tail], self.total


@dataclass(slots=True)
class _WideRunState:
    offset: int
    preview: str
    byte_length: int
    char_length: int
    has_non_ascii: bool

    def extend(self, text: str, byte_length: int, preview_limit: int) -> None:
        if len(self.preview) < preview_limit:
            remaining = preview_limit - len(self.preview)
            self.preview += text[:remaining]
        self.byte_length += byte_length
        self.char_length += len(text)
        self.has_non_ascii = self.has_non_ascii or not text.isascii()

    def candidate(self, encoding: str, preview_limit: int) -> _Candidate:
        return _Candidate(
            value=self.preview,
            encoding=encoding,
            offset=self.offset,
            byte_length=self.byte_length,
            char_length=self.char_length,
            truncated=self.char_length > preview_limit,
        )


@dataclass(frozen=True, slots=True)
class _ImportSummary:
    modules: tuple[str, ...]
    total_modules: int


class StringAnalyzer:
    """Extract and classify strings from untrusted binary data.

    ``max_strings`` is a 25,000-record output ceiling divided fairly across enabled
    encodings. All bytes are scanned; retention truncation is surfaced explicitly.
    """

    def __init__(
        self,
        min_length: int = config.MIN_STRING_LENGTH,
        max_length: int = config.MAX_STRING_CHARS,
        max_strings: int = config.MAX_EXTRACTED_STRINGS,
        encodings: Iterable[str] = ("ascii", "utf-8", "utf-16le", "utf-16be"),
    ) -> None:
        if min_length < 1:
            raise ValueError("min_length must be positive")
        if max_length < min_length:
            raise ValueError("max_length must be greater than or equal to min_length")
        if max_strings < 1:
            raise ValueError("max_strings must be positive")
        if max_strings > config.MAX_EXTRACTED_STRINGS:
            raise ValueError(f"max_strings cannot exceed {config.MAX_EXTRACTED_STRINGS}")
        normalized = tuple(dict.fromkeys(e.lower().replace("_", "-") for e in encodings))
        valid = {"ascii", "utf-8", "utf-16le", "utf-16be"}
        if not normalized or not set(normalized) <= valid:
            raise ValueError(f"encodings must be selected from {sorted(valid)}")
        self.min_length = min_length
        self.max_length = max_length
        self.max_strings = min(max_strings, MAX_CANDIDATES_IN_MEMORY)
        self.encodings = normalized

    def analyze(
        self,
        data: bytes | bytearray | memoryview,
        *,
        image_base: int | None = None,
        offset_mapper: Callable[[int], int | None] | None = None,
        sections: Sequence[Any] = (),
        imports: Iterable[Any] = (),
    ) -> SmartStringAnalysis:
        raw = bytes(data)
        candidates, extracted_count, omitted_count, coverage_reasons = self._extract(raw)
        import_map = self._normalize_imports(imports)

        grouped: dict[tuple[Any, ...], list[_Candidate]] = defaultdict(list)
        occurrence_totals: Counter[tuple[Any, ...]] = Counter()
        for candidate in candidates:
            # A bounded preview cannot prove two long source runs are identical.
            # Keep such records distinct rather than manufacturing an occurrence.
            identity = candidate.offset if candidate.truncated else None
            key = (
                candidate.value,
                candidate.encoding,
                candidate.byte_length,
                candidate.char_length,
                identity,
            )
            occurrence_totals[key] += 1
            grouped[key].append(candidate)

        records: list[StringRecord] = []
        for group_key, occurrences in grouped.items():
            candidate = min(occurrences, key=lambda c: c.offset if c.offset >= 0 else math.inf)
            value = candidate.value
            if not self.min_length <= len(value) <= self.max_length:
                continue
            categories, reasons, description, entities, score, confidence = self._classify(value, import_map)
            if candidate.truncated:
                reasons = (
                    *reasons,
                    f"Preview limited to {self.max_length} of {candidate.char_length} characters",
                )
            ordered_occurrences = sorted(occurrences, key=lambda item: item.offset)
            if len(ordered_occurrences) > MAX_RECORDED_OCCURRENCES:
                head_count = (MAX_RECORDED_OCCURRENCES + 1) // 2
                tail_count = MAX_RECORDED_OCCURRENCES - head_count
                ordered_occurrences = [
                    *ordered_occurrences[:head_count],
                    *ordered_occurrences[-tail_count:],
                ]
            occurrence_offsets = tuple(item.offset for item in ordered_occurrences)
            occurrence_addresses = tuple(
                self._address(item.offset, image_base, offset_mapper) for item in ordered_occurrences
            )
            address = occurrence_addresses[0]
            section = self._section_name(candidate.offset, address, sections)
            digest = hashlib.sha256(
                f"{candidate.encoding}\0{candidate.offset}\0{value}".encode("utf-8", "surrogatepass")
            ).hexdigest()[:16]
            records.append(
                StringRecord(
                    record_id=f"str-{digest}",
                    value=value,
                    encoding=candidate.encoding,
                    offset=candidate.offset,
                    address=address,
                    byte_length=candidate.byte_length,
                    char_length=candidate.char_length,
                    categories=categories,
                    confidence=confidence,
                    reasons=reasons,
                    description=description,
                    entities=entities,
                    section=section,
                    suspicion_score=score,
                    occurrence_count=occurrence_totals[group_key],
                    occurrence_offsets=occurrence_offsets,
                    occurrence_addresses=occurrence_addresses,
                    truncated=candidate.truncated,
                )
            )

        records.sort(
            key=lambda r: (
                -r.suspicion_score,
                tuple(
                    CATEGORY_ORDER.index(c) if c in CATEGORY_ORDER else len(CATEGORY_ORDER)
                    for c in r.categories
                ),
                r.value.casefold(),
                r.value,
                r.offset,
                r.encoding,
            )
        )
        record_cap_omitted = max(0, len(records) - self.max_strings)
        omitted_count += record_cap_omitted
        truncated = omitted_count > 0
        coverage_reason_list = list(coverage_reasons)
        if record_cap_omitted:
            coverage_reason_list.append(
                f"retained record ceiling omitted {record_cap_omitted} records "
                f"after limiting output to {self.max_strings}"
            )
        if truncated:
            records = records[: self.max_strings]
        counts = Counter(category for record in records for category in record.categories)
        counts["all"] = len(records)
        counts["suspicious"] = sum(record.suspicion_score >= 30 for record in records)
        return SmartStringAnalysis(
            records=tuple(records),
            extracted_count=extracted_count,
            retained_count=len(records),
            extraction_truncated=truncated,
            filtered_count=max(0, extracted_count - len(records)),
            counts=dict(sorted(counts.items())),
            omitted_count=omitted_count,
            count_is_lower_bound=False,
            coverage_reasons=tuple(dict.fromkeys(coverage_reason_list)),
            scanned_bytes=len(raw),
            total_bytes=len(raw),
        )

    def analyze_file(self, path: str | Path, **kwargs: Any) -> SmartStringAnalysis:
        sample_path = os.fspath(path)
        try:
            path_stat = os.stat(sample_path)
        except OSError as exc:
            raise ValueError(f"Unable to inspect string-analysis path: {exc}") from exc
        if not stat.S_ISREG(path_stat.st_mode):
            raise ValueError("String-analysis path must point to a regular file")
        if path_stat.st_size > config.MAX_BINARY_SIZE_BYTES:
            raise ValueError(
                f"File is too large ({path_stat.st_size} bytes); "
                f"maximum is {config.MAX_BINARY_SIZE_BYTES} bytes"
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(sample_path, flags)
        except OSError as exc:
            raise ValueError(f"Unable to open string-analysis path: {exc}") from exc
        with os.fdopen(descriptor, "rb") as stream:
            opened_stat = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened_stat.st_mode):
                raise ValueError("String-analysis path must point to a regular file")
            if opened_stat.st_size > config.MAX_BINARY_SIZE_BYTES:
                raise ValueError(
                    f"File is too large ({opened_stat.st_size} bytes); "
                    f"maximum is {config.MAX_BINARY_SIZE_BYTES} bytes"
                )
            data = stream.read(config.MAX_BINARY_SIZE_BYTES + 1)
        if len(data) > config.MAX_BINARY_SIZE_BYTES:
            raise ValueError(f"File exceeds the {config.MAX_BINARY_SIZE_BYTES}-byte analysis limit")
        return self.analyze(data, **kwargs)

    def analyze_binary(self, binary_info: Any) -> SmartStringAnalysis:
        sections = tuple(getattr(binary_info, "sections", ()) or ())

        def offset_mapper(offset: int) -> int | None:
            for section in sections:
                raw_offset = (
                    section.get("raw_offset")
                    if isinstance(section, Mapping)
                    else getattr(section, "raw_offset", None)
                )
                raw_size = (
                    section.get("raw_size", 0)
                    if isinstance(section, Mapping)
                    else getattr(section, "raw_size", 0)
                )
                virtual_address = (
                    section.get("virtual_address")
                    if isinstance(section, Mapping)
                    else getattr(section, "virtual_address", None)
                )
                if (
                    isinstance(raw_offset, int)
                    and isinstance(raw_size, int)
                    and isinstance(virtual_address, int)
                    and raw_offset >= 0
                    and raw_size > 0
                    and virtual_address >= 0
                    and raw_offset <= offset < raw_offset + raw_size
                ):
                    return virtual_address + (offset - raw_offset)
            return None

        return self.analyze(
            binary_info.raw_data,
            offset_mapper=offset_mapper,
            sections=sections,
            imports=getattr(binary_info, "imports", ()),
        )

    def _extract(
        self, data: bytes
    ) -> tuple[list[_Candidate], int, int, tuple[str, ...]]:
        result: list[_Candidate] = []
        total = 0
        omitted = 0
        coverage_reasons: list[str] = []
        extractors: list[tuple[str, Callable[[int], tuple[list[_Candidate], int]]]] = []
        if "ascii" in self.encodings:
            extractors.append(("ascii", lambda limit: self._extract_ascii(data, limit)))
        if "utf-8" in self.encodings:
            extractors.append(("utf-8", lambda limit: self._extract_utf8(data, limit)))
        if "utf-16le" in self.encodings:
            extractors.append(("utf-16le", lambda limit: self._extract_utf16(data, "utf-16le", limit)))
        if "utf-16be" in self.encodings:
            extractors.append(("utf-16be", lambda limit: self._extract_utf16(data, "utf-16be", limit)))
        quota = max(1, math.ceil(self.max_strings / max(1, len(extractors))))
        for encoding, extractor in extractors:
            items, count = extractor(quota)
            result.extend(items)
            total += count
            if count > len(items):
                omitted += count - len(items)
                coverage_reasons.append(
                    f"{encoding} retained {len(items)} of {count} extracted candidates "
                    "after a complete scan"
                )
        cleaned = self._suppress_utf16_artifacts(result, data)
        return cleaned, total, omitted, tuple(coverage_reasons)

    def _extract_ascii(self, data: bytes, limit: int) -> tuple[list[_Candidate], int]:
        pattern = re.compile(
            rb"[\x09\x20-\x7e]{" + str(self.min_length).encode("ascii") + rb",}"
        )
        spans, total = _bounded_match_spans(pattern, data, limit)
        result: list[_Candidate] = []
        for start, end in spans:
            byte_length = end - start
            preview_length = min(byte_length, self.max_length)
            value = data[start : start + preview_length].decode("ascii")
            result.append(
                _Candidate(
                    value,
                    "ascii",
                    start,
                    byte_length,
                    byte_length,
                    byte_length > self.max_length,
                )
            )
        return result, total

    def _extract_utf8(self, data: bytes, limit: int) -> tuple[list[_Candidate], int]:
        collector = _CandidateCollector(limit)
        if data.isascii():
            return collector.finish()
        # Invalid bytes are hard boundaries; unrelated evidence is never silently
        # joined by decoding with replacement or ignored errors.
        for match in _UTF8_RUN_RE.finditer(data):
            if _NON_ASCII_BYTES_RE.search(data, match.start(), match.end()) is None:
                continue
            decoder = codecs.getincrementaldecoder("utf-8")("strict")
            preview_parts: list[str] = []
            preview_length = 0
            char_length = 0
            printable = True
            position = match.start()
            while position < match.end():
                end = min(position + UTF16_SCAN_CHUNK_BYTES, match.end())
                text = decoder.decode(
                    data[position:end], final=end == match.end()
                )
                char_length += len(text)
                if not text.isprintable() and any(
                    character != "\t" and not self._printable(character)
                    for character in text
                ):
                    printable = False
                    break
                if preview_length < self.max_length:
                    part = text[: self.max_length - preview_length]
                    preview_parts.append(part)
                    preview_length += len(part)
                position = end
            if not printable or char_length < self.min_length:
                continue
            collector.add(
                _Candidate(
                    "".join(preview_parts),
                    "utf-8",
                    match.start(),
                    match.end() - match.start(),
                    char_length,
                    char_length > self.max_length,
                )
            )
        return collector.finish()

    def _extract_utf16(self, data: bytes, encoding: str, limit: int) -> tuple[list[_Candidate], int]:
        collector = _CandidateCollector(limit)
        ascii_unit = (
            rb"[\x09\x20-\x7e]\x00"
            if encoding.endswith("le")
            else rb"\x00[\x09\x20-\x7e]"
        )
        wide_ascii_pattern = re.compile(
            rb"(?:" + ascii_unit + rb"){" + str(self.min_length).encode("ascii") + rb",}"
        )
        ascii_spans, ascii_total = _bounded_match_spans(
            wide_ascii_pattern, data, limit
        )
        ascii_candidates: list[_Candidate] = []
        for start, end in ascii_spans:
            char_count = (end - start) // 2
            preview_bytes = data[
                start : start + min(char_count, self.max_length) * 2
            ]
            ascii_candidates.append(
                _Candidate(
                    preview_bytes.decode(encoding),
                    encoding,
                    start,
                    end - start,
                    char_count,
                    char_count > self.max_length,
                )
            )
        collector.seed(ascii_candidates, ascii_total)

        for parity in (0, 1):
            self._extract_general_utf16(data, encoding, parity, collector)
        return collector.finish()

    def _extract_general_utf16(
        self,
        data: bytes,
        encoding: str,
        parity: int,
        collector: _CandidateCollector,
    ) -> None:
        """Scan NUL-anchored Unicode-wide runs across the complete file in chunks."""
        printable_run = _utf16_printable_run_re()
        prefix_state: _WideRunState | None = None
        suffix_state: _WideRunState | None = None
        prefix_active = False
        segment_preceded_nul = False

        def byte_size(text: str) -> int:
            return len(text.encode(encoding, "surrogatepass"))

        def new_state(text: str, offset: int) -> _WideRunState:
            return _WideRunState(
                offset=offset,
                preview=text[: self.max_length],
                byte_length=byte_size(text),
                char_length=len(text),
                has_non_ascii=not text.isascii(),
            )

        def process_piece(piece: str, offset: int) -> None:
            nonlocal prefix_active, prefix_state, suffix_state
            if not piece:
                return
            prefix_match = printable_run.match(piece)
            prefix_length = prefix_match.end() if prefix_match is not None else 0
            if prefix_active:
                if prefix_length:
                    prefix_text = piece[:prefix_length]
                    prefix_bytes = byte_size(prefix_text)
                    if prefix_state is None:
                        prefix_state = new_state(prefix_text, offset)
                    else:
                        prefix_state.extend(prefix_text, prefix_bytes, self.max_length)
                if prefix_length != len(piece):
                    prefix_active = False

            reversed_piece = piece[::-1]
            suffix_match = printable_run.match(reversed_piece)
            suffix_length = suffix_match.end() if suffix_match is not None else 0
            if suffix_length == len(piece) and suffix_state is not None:
                suffix_state.extend(piece, byte_size(piece), self.max_length)
            elif suffix_length:
                suffix_start = len(piece) - suffix_length
                preceding_bytes = byte_size(piece[:suffix_start])
                suffix_state = new_state(piece[suffix_start:], offset + preceding_bytes)
            else:
                suffix_state = None

        def finish_segment(*, terminated: bool) -> None:
            nonlocal prefix_active, prefix_state, suffix_state, segment_preceded_nul
            states: list[_WideRunState] = []
            if segment_preceded_nul and prefix_state is not None:
                states.append(prefix_state)
            if terminated and suffix_state is not None:
                states.append(suffix_state)
            seen: set[tuple[int, int]] = set()
            for state in states:
                identity = (state.offset, state.byte_length)
                if (
                    identity in seen
                    or state.char_length < self.min_length
                    or not state.has_non_ascii
                ):
                    continue
                seen.add(identity)
                candidate = state.candidate(encoding, self.max_length)
                if self._credible_utf16(candidate, data):
                    collector.add(candidate)
            prefix_state = None
            suffix_state = None
            prefix_active = True
            segment_preceded_nul = True

        position = parity
        data_length = len(data)
        endian = "little" if encoding.endswith("le") else "big"
        while position + 1 < data_length:
            end = min(position + UTF16_SCAN_CHUNK_BYTES, data_length)
            end -= (end - position) % 2
            if end <= position:
                break
            if end < data_length and end - position >= 2:
                final_unit = int.from_bytes(data[end - 2 : end], endian)
                if 0xD800 <= final_unit <= 0xDBFF:
                    end -= 2
            decoded = data[position:end].decode(encoding, "surrogatepass")
            first_zero = decoded.find("\x00")
            if first_zero < 0:
                process_piece(decoded, position)
                position = end
                continue

            leading = decoded[:first_zero]
            process_piece(leading, position)
            finish_segment(terminated=True)

            mapping_character = 0
            mapping_bytes = 0
            for match in _UTF16_NONASCII_SEGMENT_RE.finditer(decoded):
                segment_start, segment_end = match.span(1)
                # Leading and trailing pieces are handled by the cross-chunk
                # state above/below. Everything here has real NUL boundaries.
                if segment_start == 0 or segment_end == len(decoded):
                    continue
                mapping_bytes += byte_size(decoded[mapping_character:segment_start])
                mapping_character = segment_start
                prefix_state = None
                suffix_state = None
                prefix_active = True
                segment_preceded_nul = True
                process_piece(match.group(1), position + mapping_bytes)
                finish_segment(terminated=True)

            last_zero = decoded.rfind("\x00")
            trailing_start = last_zero + 1
            trailing_offset = position + byte_size(decoded[:trailing_start])
            prefix_state = None
            suffix_state = None
            prefix_active = True
            segment_preceded_nul = True
            process_piece(decoded[trailing_start:], trailing_offset)
            position = end

        # A run beginning immediately after a real NUL boundary remains valid at
        # EOF even without a second terminator. A trailing suffix without a prefix
        # boundary is intentionally not promoted to Unicode text.
        finish_segment(terminated=False)

    def _make_utf16_candidate(
        self,
        chars: list[str],
        start: int | None,
        encoding: str,
        char_count: int,
        byte_length: int,
    ) -> _Candidate | None:
        if start is None or char_count < self.min_length:
            return None
        value = "".join(chars)
        return _Candidate(
            value,
            encoding,
            start,
            byte_length,
            char_count,
            char_count > self.max_length,
        )

    @staticmethod
    def _suppress_utf16_artifacts(candidates: list[_Candidate], data: bytes) -> list[_Candidate]:
        wide = [candidate for candidate in candidates if candidate.encoding in {"utf-16le", "utf-16be"}]
        by_location: dict[tuple[str, int], list[_Candidate]] = defaultdict(list)
        preferred_encoding: dict[str, tuple[int, str]] = {}
        for candidate in wide:
            by_location[(candidate.encoding, candidate.offset)].append(candidate)
            current = preferred_encoding.get(candidate.value)
            if current is None or candidate.offset < current[0]:
                preferred_encoding[candidate.value] = (candidate.offset, candidate.encoding)
        rejected: set[int] = set()

        def following_nuls(candidate: _Candidate) -> int:
            count = 0
            position = candidate.offset + candidate.byte_length
            while position < len(data) and count < 4 and data[position] == 0:
                count += 1
                position += 1
            return count

        for left in wide:
            opposite = "utf-16be" if left.encoding == "utf-16le" else "utf-16le"
            neighbors = (
                *by_location.get((opposite, left.offset - 1), ()),
                *by_location.get((opposite, left.offset + 1), ()),
            )
            for right in neighbors:
                shorter, longer = (left, right) if left.char_length < right.char_length else (right, left)
                if left.value == right.value and left.byte_length == right.byte_length:
                    left_distance = abs(following_nuls(left) - 2)
                    right_distance = abs(following_nuls(right) - 2)
                    if left_distance != right_distance:
                        rejected.add(id(left if left_distance > right_distance else right))
                    else:
                        preferred = preferred_encoding[left.value][1]
                        rejected.add(id(right if left.encoding == preferred else left))
                    continue
                if shorter.value == longer.value[1:] and shorter.byte_length <= longer.byte_length:
                    shorter_distance = abs(following_nuls(shorter) - 2)
                    longer_distance = abs(following_nuls(longer) - 2)
                    if shorter_distance != longer_distance:
                        rejected.add(id(shorter if shorter_distance > longer_distance else longer))
                    else:
                        rejected.add(id(shorter))
                    continue
                overlap = min(
                    left.offset + left.byte_length,
                    right.offset + right.byte_length,
                ) - max(left.offset, right.offset)
                asciiish = max(
                    sum(ord(character) < 128 for character in left.value)
                    / max(1, len(left.value)),
                    sum(ord(character) < 128 for character in right.value)
                    / max(1, len(right.value)),
                )
                if (
                    overlap >= 0.80 * min(left.byte_length, right.byte_length)
                    and asciiish >= 0.70
                ):
                    left_distance = abs(following_nuls(left) - 2)
                    right_distance = abs(following_nuls(right) - 2)
                    if left_distance != right_distance:
                        rejected.add(id(left if left_distance > right_distance else right))
        return [candidate for candidate in candidates if id(candidate) not in rejected]

    @classmethod
    def _credible_utf16(cls, candidate: _Candidate, data: bytes) -> bool:
        preview_bytes = len(candidate.value.encode(candidate.encoding, "surrogatepass"))
        raw = data[candidate.offset : candidate.offset + preview_bytes]
        if not raw:
            return False
        for position in range(0, len(raw) - 1, 2):
            first, second = raw[position], raw[position + 1]
            both_ascii_bytes = (
                (first == 9 or 0x20 <= first <= 0x7E)
                and (second == 9 or 0x20 <= second <= 0x7E)
            )
            wrong_ascii_wide = (
                candidate.encoding == "utf-16be"
                and second == 0
                and 0x20 <= first <= 0x7E
            ) or (
                candidate.encoding == "utf-16le"
                and first == 0
                and 0x20 <= second <= 0x7E
            )
            if both_ascii_bytes or wrong_ascii_wide:
                return False
        nul_density = raw.count(0) / len(raw)
        asciiish = sum(ord(char) < 128 for char in candidate.value) / len(candidate.value)
        if asciiish >= 0.70:
            return nul_density >= 0.25 and cls._text_quality(candidate.value) >= 0.65

        end = candidate.offset + candidate.byte_length
        terminated = data[end : end + 2] == b"\x00\x00"
        prefixed = candidate.offset >= 2 and data[candidate.offset - 2 : candidate.offset] == b"\x00\x00"
        if not (terminated or prefixed):
            return False

        scripts: Counter[str] = Counter()
        letter_count = 0
        for char in candidate.value:
            if not char.isalpha():
                continue
            letter_count += 1
            name = unicodedata.name(char, "")
            script = next(
                (
                    label
                    for label in (
                        "LATIN",
                        "CYRILLIC",
                        "GREEK",
                        "HEBREW",
                        "ARABIC",
                        "DEVANAGARI",
                        "THAI",
                        "HIRAGANA",
                        "KATAKANA",
                        "HANGUL",
                        "CJK",
                    )
                    if label in name
                ),
                "OTHER",
            )
            scripts[script] += 1
        if letter_count < max(2, math.ceil(len(candidate.value) * 0.45)):
            # Permit symbol-rich strings (for example emoji) only when anchored by
            # some ASCII text and a proper wide-string boundary.
            return asciiish >= 0.25 and terminated
        if scripts.get("OTHER", 0):
            return False
        dominant_script, dominant_count = max(scripts.items(), key=lambda item: item[1])
        if dominant_count / letter_count < 0.90:
            return False
        if any(char.isspace() for char in candidate.value):
            return True
        if dominant_script == "LATIN" and asciiish < 0.25:
            return False
        if dominant_script in {"CJK", "HIRAGANA", "KATAKANA", "HANGUL"}:
            return len(candidate.value) >= 8
        return len(candidate.value) >= 6

    @staticmethod
    def _printable(char: str) -> bool:
        return char == "\t" or (char.isprintable() and unicodedata.category(char) not in {"Cc", "Cs", "Cn"})

    @classmethod
    def _valid_utf16_unit(cls, pair: bytes, unit: int, char: str, encoding: str) -> bool:
        if not cls._printable(char) or 0xD800 <= unit <= 0xDFFF:
            return False
        # Two adjacent ASCII bytes are overwhelmingly more likely to be part of an
        # ordinary byte string than one CJK UTF-16 code unit. This boundary also
        # prevents an ASCII run immediately before a wide string being glued to it.
        if all(byte == 9 or 0x20 <= byte <= 0x7E for byte in pair):
            return False
        # An ASCII-wide string interpreted with the opposite byte order becomes a
        # run of U+xx00 code points (for example, "A\\0" -> U+4100).
        wrong_ascii_wide = (encoding == "utf-16be" and pair[1] == 0 and 0x20 <= pair[0] <= 0x7E) or (
            encoding == "utf-16le" and pair[0] == 0 and 0x20 <= pair[1] <= 0x7E
        )
        return not wrong_ascii_wide

    @staticmethod
    def _text_quality(value: str) -> float:
        if not value:
            return 0.0
        useful = sum(
            ch.isalnum()
            or ch.isspace()
            or unicodedata.category(ch).startswith("S")
            or ch in r".,:;!?@#$%^&*()_+-=[]{}\/'\"|<>~`"
            for ch in value
        )
        return useful / len(value)

    @staticmethod
    def _normalize_imports(imports: Iterable[Any]) -> dict[str, _ImportSummary]:
        normalized: dict[str, set[str]] = defaultdict(set)
        if isinstance(imports, Mapping):
            imports = imports.items()
        for item in imports:
            if isinstance(item, tuple) and len(item) == 2:
                library, functions = item
            elif isinstance(item, Mapping):
                library = item.get("dll") or item.get("library") or "unknown module"
                functions = item.get("functions") or item.get("apis") or ()
            else:
                library = getattr(item, "dll", getattr(item, "library", "unknown module"))
                functions = getattr(item, "functions", ())
            if isinstance(functions, str):
                functions = (functions,)
            for function in functions:
                name = str(function)
                normalized[name.casefold()].add(str(library))
        summaries: dict[str, _ImportSummary] = {}
        for name, libraries in normalized.items():
            ordered = sorted(libraries, key=lambda value: (value.casefold(), value))
            bounded = tuple(
                library
                if len(library) <= MAX_IMPORT_MODULE_NAME_CHARS
                else library[: MAX_IMPORT_MODULE_NAME_CHARS - 1] + "…"
                for library in ordered[:MAX_IMPORT_MODULES_PER_API]
            )
            summaries[name] = _ImportSummary(
                modules=bounded,
                total_modules=len(ordered),
            )
        return summaries

    @staticmethod
    def _address(
        offset: int, image_base: int | None, mapper: Callable[[int], int | None] | None
    ) -> int | None:
        if offset < 0:
            return None
        if mapper is not None:
            try:
                mapped = mapper(offset)
            except (LookupError, TypeError, ValueError):
                return None
            return (
                mapped if isinstance(mapped, int) and not isinstance(mapped, bool) and mapped >= 0 else None
            )
        if isinstance(image_base, int) and not isinstance(image_base, bool) and image_base >= 0:
            return image_base + offset
        return None

    @staticmethod
    def _section_name(offset: int, address: int | None, sections: Sequence[Any]) -> str | None:
        for section in sections:
            name = (
                str(section.get("name", ""))
                if isinstance(section, Mapping)
                else str(getattr(section, "name", ""))
            )
            raw_offset = (
                section.get("raw_offset")
                if isinstance(section, Mapping)
                else getattr(section, "raw_offset", None)
            )
            raw_size = (
                section.get("raw_size", 0)
                if isinstance(section, Mapping)
                else getattr(section, "raw_size", 0)
            )
            virtual = (
                section.get("virtual_address")
                if isinstance(section, Mapping)
                else getattr(section, "virtual_address", None)
            )
            virtual_size = (
                section.get("virtual_size", 0)
                if isinstance(section, Mapping)
                else getattr(section, "virtual_size", 0)
            )
            if raw_offset is not None and raw_offset <= offset < raw_offset + raw_size:
                return name or None
            if address is not None and virtual is not None and virtual <= address < virtual + virtual_size:
                return name or None
        return None

    def _classify(
        self, value: str, imports: Mapping[str, _ImportSummary]
    ) -> tuple[
        tuple[str, ...],
        tuple[str, ...],
        str,
        tuple[tuple[str, str], ...],
        int,
        str,
    ]:
        matched: set[str] = set()
        reasons: list[str] = []
        descriptions: list[str] = []
        imported_any = False

        def add(category: str, reason: str) -> None:
            matched.add(category)
            if reason not in reasons:
                reasons.append(reason)

        urls = _URL_RE.findall(value)
        if any(self._valid_url(url) for url in urls):
            add("url", "Contains a syntactically valid network URL")
        if _EMAIL_RE.search(value):
            add("email", "Contains an email address")
        if self._contains_domain(value) and not _DLL_RE.fullmatch(value.strip()):
            add("domain", "Contains a DNS-style domain name")
        ip_versions = self._ip_versions(value)
        if ip_versions:
            add("ip_address", "Contains a valid IPv4 or IPv6 address")
            if 4 in ip_versions:
                add("ipv4", "Contains a valid IPv4 address")
            if 6 in ip_versions:
                add("ipv6", "Contains a valid IPv6 address")
        if _REGISTRY_RE.search(value):
            add("registry_key", "Contains a Windows Registry key path")
        if _PIPE_RE.search(value):
            add("named_pipe", "References a Windows named pipe")
        if _DEVICE_RE.search(value):
            add("device_path", "References a Windows device namespace")
        if _UNC_RE.search(value):
            add("unc_path", "Contains a UNC network path")
        if _WINDOWS_PATH_RE.search(value):
            add("windows_path", "Contains an absolute Windows path")
        if _POSIX_PATH_RE.search(value):
            add("posix_path", "Contains an absolute POSIX path")
        dll_names: list[str] = []
        seen_dll_names: set[str] = set()
        for match in _DLL_RE.finditer(value):
            name = match.group(1)
            identity = name.casefold()
            if identity in seen_dll_names:
                continue
            seen_dll_names.add(identity)
            dll_names.append(name)
        if dll_names:
            add("dll", "Names a dynamic or shared library")

        api_names: list[str] = []
        seen_api_names: set[str] = set()
        for token_match in _IDENTIFIER_RE.finditer(value):
            token = token_match.group()
            folded = token.casefold()
            api_base = re.sub(r"[AW]$", "", token) if len(token) > 2 else token
            if imports.get(folded) or folded in _KNOWN_APIS or api_base.casefold() in _KNOWN_APIS:
                if folded not in seen_api_names:
                    seen_api_names.add(folded)
                    api_names.append(token)
        if api_names:
            add("api", "Matches a known operating-system or runtime API")
        entity_candidates = [
            *(("dll", name, self._dll_description(name)) for name in dll_names),
            *(("api", name, self._api_description(name)) for name in api_names),
        ]
        entities: list[tuple[str, str]] = []
        description_chars = 0
        for kind, name, entity_description in entity_candidates:
            if len(entities) >= MAX_ENTITIES_PER_RECORD or len(name) > MAX_ENTITY_NAME_CHARS:
                continue
            separator_chars = 1 if descriptions else 0
            if (
                description_chars + separator_chars + len(entity_description)
                > MAX_RECORD_DESCRIPTION_CHARS
            ):
                continue
            entities.append((kind, name))
            descriptions.append(entity_description)
            description_chars += separator_chars + len(entity_description)
        entity_omitted = len(entity_candidates) - len(entities)
        if entity_omitted:
            reasons.append(
                f"DLL/API annotations retained {len(entities)} of "
                f"{len(entity_candidates)} candidates under per-record safety caps"
            )

        provenance_chars = 0
        omitted_provenance = 0
        for kind, api_name in entities:
            if kind != "api":
                continue
            imported = imports.get(api_name.casefold(), set())
            if imported:
                imported_any = True
                module_text = ", ".join(imported.modules)
                hidden_modules = imported.total_modules - len(imported.modules)
                if hidden_modules:
                    module_text += f" (+{hidden_modules} more modules)"
                provenance = f"Imported from {module_text} ({api_name})"
                separator_chars = 1 if provenance_chars else 0
                if (
                    provenance_chars + separator_chars + len(provenance)
                    <= MAX_IMPORT_PROVENANCE_CHARS
                ):
                    reasons.append(provenance)
                    provenance_chars += separator_chars + len(provenance)
                else:
                    omitted_provenance += 1
        if omitted_provenance:
            reasons.append(
                f"Import provenance omitted for {omitted_provenance} API candidates "
                "under the per-record text cap"
            )
        if _POWERSHELL_RE.search(value):
            add("powershell", "Contains PowerShell execution syntax")
        if _COMMAND_RE.search(value):
            add("command", "Contains a shell or system command")
        if _SERVICE_RE.search(value):
            add("service", "References Windows service-control behavior")
        if _MUTEX_RE.search(value):
            add("mutex", "Contains a mutex name or mutex API")
        hash_tokens = _HASH_RE.findall(value)
        if any(self._base64_entropy(token) >= 2.5 for token in hash_tokens):
            add("hash", "Contains a common cryptographic hash representation")
        if _GUID_RE.search(value):
            add("guid", "Contains a GUID or CLSID-style identifier")
        if _PEM_RE.search(value):
            add("crypto_material", "Contains a PEM cryptographic-material header")
        if _PDB_RE.search(value):
            add("pdb_path", "References a Program Database debugging-symbol file")
        if _FILENAME_RE.search(value) and not self._contains_domain(value):
            add("filename", "Contains a security-relevant filename")
        if _SCHEDULED_RE.search(value):
            add("scheduled_task", "References scheduled-task creation or configuration")
        if _PERSISTENCE_RE.search(value):
            add("persistence", "Matches a common startup or service persistence location")
        if _ANTI_ANALYSIS_RE.search(value):
            add("anti_analysis", "Contains debugging, sandbox, or analysis-tool terminology")
        if _CREDENTIAL_RE.search(value):
            add("credential", "Contains credential or authentication terminology")
        if _USER_AGENT_RE.search(value):
            add("user_agent", "Contains an HTTP user-agent signature")
        compact = value.strip()
        looks_base64 = self._looks_base64(compact)
        if looks_base64:
            add("base64", "Looks like Base64-encoded data")
        if (
            _HEX_RE.fullmatch(compact)
            and not _HASH_RE.fullmatch(compact)
            and self._base64_entropy(compact.removeprefix("0x")) >= 2.5
        ):
            add("hex", "Looks like hexadecimal-encoded data")
        if valid_config_assignment(value):
            add("config", "Looks like a configuration assignment")
        if _DEBUG_RE.search(value):
            add("debug", "Contains debugging or tracing terminology")
        if _ERROR_RE.search(value):
            add("error", "Contains an error or failure message")
        if not matched:
            add("text", "Printable string")

        categories = tuple(category for category in CATEGORY_ORDER if category in matched)
        category_families = {
            category: (
                "network_location"
                if category in {"url", "domain", "ip_address", "ipv4", "ipv6"}
            else "path" if category in {
                "registry_key", "named_pipe", "device_path", "unc_path", "windows_path",
                "posix_path", "pdb_path", "filename",
            }
            else "execution" if category in {
                "powershell", "command", "service", "scheduled_task", "persistence",
            }
            else "configuration" if category in {"config", "debug", "error"}
            else category
            )
            for category in categories
            if category != "text"
        }
        signal_families = set(category_families.values())
        family_weights = {
            family: max(
                _WEIGHTS[category]
                for category, category_family in category_families.items()
                if category_family == family
            )
            for family in signal_families
        }
        score = min(
            100,
            max(family_weights.values(), default=0)
            + min(30, 5 * max(0, len(signal_families) - 1)),
        )
        # Several independent signal families should increase confidence without
        # claiming that aliases for one observation are separate evidence.
        confidence = (
            "high" if imported_any or len(signal_families) >= 2
            else "medium" if signal_families
            else "low"
        )
        description = " ".join(dict.fromkeys(descriptions))
        if not description:
            description = self._generic_description(categories)
        return categories, tuple(reasons), description, tuple(entities), score, confidence

    @staticmethod
    def _valid_url(value: str) -> bool:
        return valid_url_candidate(value)

    @staticmethod
    def _contains_ip(value: str) -> bool:
        return bool(StringAnalyzer._ip_versions(value))

    @staticmethod
    def _ip_versions(value: str) -> set[int]:
        return {
            parsed.version
            for token in iter_ip_candidates(value)
            if (parsed := parse_ip_candidate(token)) is not None
        }

    @staticmethod
    def _contains_domain(value: str) -> bool:
        return bool(iter_domain_candidates(value))

    @staticmethod
    def _base64_entropy(value: str) -> float:
        counts = Counter(value.rstrip("="))
        length = sum(counts.values())
        return (
            -sum((count / length) * math.log2(count / length) for count in counts.values()) if length else 0.0
        )

    @classmethod
    def _looks_base64(cls, value: str) -> bool:
        if not _B64_RE.fullmatch(value) or cls._base64_entropy(value) < 3.2:
            return False
        classes = sum(
            (
                any(char.islower() for char in value),
                any(char.isupper() for char in value),
                any(char.isdigit() for char in value),
                any(char in "+/=" for char in value),
            )
        )
        return classes >= 2

    @staticmethod
    def _dll_description(name: str) -> str:
        basename = re.split(r"[\\/]", name)[-1].casefold()
        exact = _DLL_DESCRIPTIONS.get(basename)
        if exact:
            return f"{name}: {exact}"
        stem = re.sub(r"(?:\.dll|\.dylib|\.so(?:\.\d+)*)$", "", basename, flags=re.I)
        return f"{name}: Dynamic/shared library '{stem}'; no curated capability description is available."

    @staticmethod
    def _api_description(name: str) -> str:
        base = re.sub(r"[AW]$", "", name) if len(name) > 2 else name
        exact = _API_DESCRIPTIONS.get(name.casefold()) or _API_DESCRIPTIONS.get(base.casefold())
        if exact:
            suffix = (
                " (Unicode variant)."
                if name.endswith("W")
                else " (ANSI variant)."
                if name.endswith("A")
                else ""
            )
            return f"{name}: {exact}{suffix}"
        return f"{name}: Imported API/function; behavior depends on its providing module and arguments."

    @staticmethod
    def _generic_description(categories: tuple[str, ...]) -> str:
        if categories == ("text",):
            return "Printable program string with no high-confidence structured indicator."
        labels = ", ".join(category.replace("_", " ") for category in categories)
        return f"Detected as {labels}. Classification is contextual and does not by itself prove malicious intent."


# A discoverable alias for callers that prefer the feature name over the short class name.
SmartStringAnalyzer = StringAnalyzer

__all__ = [
    "CATEGORY_ORDER",
    "SmartStringAnalysis",
    "SmartStringAnalyzer",
    "StringAnalyzer",
    "StringRecord",
    "normalize_domain_candidate",
    "iter_domain_candidates",
    "iter_ip_candidates",
    "parse_ip_candidate",
    "valid_config_assignment",
    "valid_domain_candidate",
    "valid_ip_candidate",
    "valid_url_candidate",
]
