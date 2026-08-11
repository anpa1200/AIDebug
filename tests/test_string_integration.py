import json
import os
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from analysis import StaticAnalyzer
from main import build_string_report_document


def _clean_ai_environment(tmp_path):
    environment = dict(os.environ)
    for key in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OLLAMA_BASE_URL",
        "AIDEBUG_LLM_BASE_URL",
    ):
        environment.pop(key, None)
    environment["AIDEBUG_ENV_FILE"] = str(tmp_path / "missing.env")
    environment["AIDEBUG_LLM_PROVIDER"] = "auto"
    return environment


@pytest.mark.skipif(not os.path.isfile("/bin/true"), reason="safe ELF fixture unavailable")
def test_static_analyzer_builds_rich_strings_and_legacy_projection():
    info = StaticAnalyzer(min_string_length=4).analyze("/bin/true")

    assert info.string_analysis is not None
    assert info.string_analysis.retained_count == len(info.string_analysis.records)
    assert info.string_analysis.retained_count >= len(info.strings)
    assert info.all_string_data
    first = info.string_analysis.records[0]
    assert first.record_id
    assert first.offset >= 0
    assert first.encoding in {"ascii", "utf-8", "utf-16le", "utf-16be"}


def test_legacy_projection_never_treats_unmapped_file_offsets_as_virtual_addresses():
    records = (
        SimpleNamespace(
            value="mapped",
            address=0x401000,
            occurrence_addresses=(0x401000,),
        ),
        SimpleNamespace(
            value="overlay-only",
            address=None,
            offset=0x900,
            occurrence_addresses=(None,),
            occurrence_offsets=(0x900,),
        ),
    )

    values, by_address = StaticAnalyzer._compatibility_string_projection(
        SimpleNamespace(records=records)
    )

    assert values == ["mapped", "overlay-only"]
    assert by_address == {0x401000: "mapped"}


def test_string_json_preserves_entity_and_incomplete_coverage_metadata():
    record = SimpleNamespace(
        record_id="str-one",
        value="kernel32.dll CreateFileW",
        encoding="ascii",
        offset=4,
        address=0x401004,
        byte_length=24,
        char_length=24,
        categories=("dll", "api"),
        confidence="high",
        suspicion_score=10,
        reasons=("Known candidates",),
        description="neutral descriptions",
        entities=(("dll", "kernel32.dll"), ("api", "CreateFileW")),
        section=".rdata",
        occurrence_count=1,
        occurrence_offsets=(4,),
        occurrence_addresses=(0x401004,),
        truncated=False,
    )
    analysis = SimpleNamespace(
        records=(record,),
        extracted_count=2,
        retained_count=1,
        extraction_truncated=True,
        omitted_count=1,
        count_is_lower_bound=True,
        coverage_reasons=("candidate_limit",),
        complete=False,
        scanned_bytes=64,
        total_bytes=128,
    )
    binary = SimpleNamespace(
        filename="sample.exe",
        sha256="a" * 64,
        file_format="PE",
        arch="x86-64",
        bits=64,
        os_target="Windows",
        raw_data=b"x" * 128,
        string_analysis=analysis,
    )

    document = build_string_report_document(binary)

    assert document["coverage"]["count_is_lower_bound"] is True
    assert document["coverage"]["coverage_reasons"] == ["candidate_limit"]
    assert document["strings"][0]["entities"] == [
        {"kind": "dll", "canonical_name": "kernel32.dll"},
        {"kind": "api", "canonical_name": "CreateFileW"},
    ]


@pytest.mark.skipif(not os.path.isfile("/bin/true"), reason="safe ELF fixture unavailable")
def test_deterministic_strings_cli_needs_no_provider_or_database(tmp_path):
    destination = tmp_path / "reports" / "strings.json"
    database = tmp_path / "must-not-exist.db"
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--binary",
            "/bin/true",
            "--strings",
            "--no-tui",
            "--min-string-length",
            "4",
            "--string-category",
            "api",
            "--strings-output",
            str(destination),
            "--db",
            str(database),
        ],
        check=False,
        text=True,
        capture_output=True,
        env=_clean_ai_environment(tmp_path),
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    assert "String Intelligence" in result.stdout
    assert "Discovering functions" not in result.stdout
    assert destination.is_file()
    assert not database.exists()
    document = json.loads(destination.read_text(encoding="utf-8"))
    assert document["_schema"] == "aidebug/strings/v1"
    assert document["filters"]["categories"] == ["api"]
    # Category filters change the CLI view, never canonical extraction coverage.
    assert len(document["strings"]) == document["coverage"]["retained_count"]
    assert document["coverage"]["displayed_count"] <= len(document["strings"])
    if os.name != "nt":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600


@pytest.mark.skipif(not os.path.isfile("/bin/true"), reason="safe ELF fixture unavailable")
def test_whole_string_remote_cli_requires_cost_acknowledgement_before_work(tmp_path):
    database = tmp_path / "must-not-exist.db"
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--binary",
            "/bin/true",
            "--strings",
            "--no-tui",
            "--analyze-strings",
            "--db",
            str(database),
        ],
        check=False,
        text=True,
        capture_output=True,
        env=_clean_ai_environment(tmp_path),
        timeout=10,
    )

    assert result.returncode == 2
    assert "--accept-ai-cost" in result.stderr
    assert not database.exists()


@pytest.mark.skipif(not os.path.isfile("/bin/true"), reason="safe ELF fixture unavailable")
def test_remote_ollama_cannot_bypass_whole_string_cost_gate(tmp_path):
    environment = _clean_ai_environment(tmp_path)
    environment["AIDEBUG_LLM_PROVIDER"] = "ollama"
    environment["OLLAMA_BASE_URL"] = "https://ollama.example/v1"
    database = tmp_path / "must-not-exist.db"

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--binary",
            "/bin/true",
            "--strings",
            "--no-tui",
            "--analyze-strings",
            "--db",
            str(database),
        ],
        check=False,
        text=True,
        capture_output=True,
        env=environment,
        timeout=10,
    )

    assert result.returncode == 2
    assert "--accept-ai-cost" in result.stderr
    assert not database.exists()


def test_string_cli_argument_relationships_are_fail_closed(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"not an executable")

    missing_mode = subprocess.run(
        [sys.executable, "main.py", "--binary", str(sample), "--analyze-strings"],
        check=False,
        text=True,
        capture_output=True,
        env=_clean_ai_environment(tmp_path),
    )
    assert missing_mode.returncode == 2
    assert "requires --strings --no-tui" in missing_mode.stderr

    excessive_length = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--binary",
            str(sample),
            "--strings",
            "--no-tui",
            "--min-string-length",
            "4097",
        ],
        check=False,
        text=True,
        capture_output=True,
        env=_clean_ai_environment(tmp_path),
    )
    assert excessive_length.returncode == 2
    assert "cannot exceed" in excessive_length.stderr

    modifier_without_workspace = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--binary",
            str(sample),
            "--offline",
            "--string-encoding",
            "ascii",
        ],
        check=False,
        text=True,
        capture_output=True,
        env=_clean_ai_environment(tmp_path),
    )
    assert modifier_without_workspace.returncode == 2
    assert "require --strings" in modifier_without_workspace.stderr

    tui_category = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--binary",
            str(sample),
            "--strings",
            "--offline",
            "--string-category",
            "url",
        ],
        check=False,
        text=True,
        capture_output=True,
        env=_clean_ai_environment(tmp_path),
    )
    assert tui_category.returncode == 2
    assert "requires --strings --no-tui" in tui_category.stderr
