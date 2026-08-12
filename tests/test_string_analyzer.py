import os
from collections import Counter
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from analysis.static_analyzer import ImportInfo
from analysis.string_analyzer import (
    SmartStringAnalyzer,
    StringAnalyzer,
    StringRecord,
    normalize_domain_candidate,
    parse_ip_candidate,
    valid_config_assignment,
    valid_domain_candidate,
    valid_ip_candidate,
    valid_url_candidate,
)


def by_value(analysis, value, encoding=None):
    return next(
        record
        for record in analysis.records
        if record.value == value and (encoding is None or record.encoding == encoding)
    )


def test_extracts_ascii_utf8_and_both_utf16_encodings_with_offsets():
    ascii_value = b"hello-ascii"
    utf8_value = "Привет мир"
    le_value = "HKEY_LOCAL_MACHINE\\Software\\Acme"
    be_value = "/etc/cron.d/update"
    blob = (
        b"\x00"
        + ascii_value
        + b"\x00"
        + utf8_value.encode("utf-8")
        + b"\x00"
        + le_value.encode("utf-16le")
        + b"\x00\x00"
        + be_value.encode("utf-16be")
        + b"\x00\x00"
    )

    result = StringAnalyzer(min_length=5).analyze(blob, image_base=0x400000)

    ascii_record = by_value(result, "hello-ascii", "ascii")
    assert ascii_record.offset == 1
    assert ascii_record.address == 0x400001
    assert ascii_record.byte_length == len(ascii_value)
    utf8_record = by_value(result, utf8_value, "utf-8")
    assert utf8_record.byte_length == len(utf8_value.encode("utf-8"))
    assert "registry_key" in by_value(result, le_value, "utf-16le").categories
    assert "posix_path" in by_value(result, be_value, "utf-16be").categories
    # Byte-order detection must not produce the classic U+xx00 false positive.
    assert not any(record.value.startswith("䠀䬀䔀夀") for record in result.records)


def test_invalid_utf8_bytes_are_boundaries_not_silently_joined():
    blob = b"prefix \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82\xffsuffix \xe4\xb8\x96\xe7\x95\x8c"

    result = StringAnalyzer(min_length=4, encodings=("utf-8",)).analyze(blob)

    assert by_value(result, "prefix Привет", "utf-8").offset == 0
    assert by_value(result, "suffix 世界", "utf-8").offset == blob.index(b"suffix")
    assert not any("Приветsuffix" in record.value for record in result.records)


def test_multicategory_iocs_are_validated_and_sorted_by_suspicion():
    blob = (
        b"https://192.0.2.4/drop.exe\x00"
        b"not-an-ip 999.999.999.999\x00"
        b"cmd.exe /c powershell.exe -EncodedCommand SQBFAFgA\x00"
        b"analyst@example.org\x00"
        b"ordinary message\x00"
    )

    result = StringAnalyzer(min_length=4).analyze(blob)

    ioc = by_value(result, "https://192.0.2.4/drop.exe")
    assert {"url", "ip_address", "ipv4"} <= set(ioc.categories)
    invalid_ip = by_value(result, "not-an-ip 999.999.999.999")
    assert "ip_address" not in invalid_ip.categories
    command = by_value(result, "cmd.exe /c powershell.exe -EncodedCommand SQBFAFgA")
    assert {"command", "powershell"} <= set(command.categories)
    assert result.records[0].suspicion_score >= result.records[-1].suspicion_score
    assert result.counts["url"] == 1


def test_ip_with_port_and_prefixed_command_are_detected_without_substrings():
    result = StringAnalyzer(min_length=4).analyze(
        b"connect to 192.0.2.44:8443\x00please run cmd.exe /c whoami\x00notcmd.exe.helper\x00"
    )

    assert "ip_address" in by_value(result, "connect to 192.0.2.44:8443").categories
    assert "command" in by_value(result, "please run cmd.exe /c whoami").categories
    assert "command" not in by_value(result, "notcmd.exe.helper").categories


def test_extended_structured_and_behavioral_categories_are_multilabel():
    values = [
        "beefdead-1234-5678-90ab-0123456789ab",
        "-----BEGIN PRIVATE KEY-----",
        r"C:\build\sample.pdb",
        "dropper.exe",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
        "please run schtasks.exe /create /tn Update",
        "IsDebuggerPresent vmware sandbox",
        "2001:db8::5",
    ]
    result = StringAnalyzer(min_length=4).analyze(b"\x00".join(item.encode() for item in values))

    assert "guid" in by_value(result, values[0]).categories
    assert "crypto_material" in by_value(result, values[1]).categories
    assert {"pdb_path", "filename"} <= set(by_value(result, values[2]).categories)
    assert "filename" in by_value(result, values[3]).categories
    assert "persistence" in by_value(result, values[4]).categories
    assert {"scheduled_task", "persistence", "command"} <= set(by_value(result, values[5]).categories)
    assert "anti_analysis" in by_value(result, values[6]).categories
    assert {"ip_address", "ipv6"} <= set(by_value(result, values[7]).categories)


def test_filenames_are_not_mislabeled_as_domains_and_base64_is_not_config():
    result = StringAnalyzer(min_length=4).analyze(b"cmd.exe /c whoami\x00QUJDREVGR0hJSktMTU5PUA==\x00")

    command = by_value(result, "cmd.exe /c whoami")
    encoded = by_value(result, "QUJDREVGR0hJSktMTU5PUA==")
    assert "domain" not in command.categories
    assert "base64" in encoded.categories
    assert "config" not in encoded.categories


def test_ambiguous_lowercase_and_repeated_encodings_avoid_false_positives():
    result = StringAnalyzer(min_length=4).analyze(b"abcdefghijklmnop\x00aaaaaaaaaaaaaaaa\x00foo.bar\x00")

    assert "base64" not in by_value(result, "abcdefghijklmnop").categories
    assert "hex" not in by_value(result, "aaaaaaaaaaaaaaaa").categories
    domain = by_value(result, "foo.bar")
    assert "domain" in domain.categories
    assert domain.confidence == "medium"


@pytest.mark.parametrize(
    "value",
    [
        "release-1.2.3.4-beta",
        "build.1.2.3.4.dll",
        "192.0.2.1.example",
        "2001:db8::1.example",
        "2001:db8::1%",
        "[2001:db8::1",
        "2001:db8::1]junk",
        "999.999.999.999",
        "::",
    ],
)
def test_ip_detection_rejects_malformed_or_embedded_maximal_tokens(value):
    record = by_value(StringAnalyzer(min_length=2, encodings=("ascii",)).analyze(value.encode()), value)

    assert "ip_address" not in record.categories


@pytest.mark.parametrize(
    ("value", "version"),
    [
        ("192.0.2.44", 4),
        ("192.0.2.44:8443", 4),
        ("::1", 6),
        ("2001:db8::5", 6),
        ("[2001:db8::5]:443", 6),
        ("fe80::1%eth0", 6),
        ("[fe80::1%eth0]:443", 6),
        ("::ffff:192.0.2.1", 6),
    ],
)
def test_strict_ip_candidate_parser_accepts_complete_supported_tokens(value, version):
    assert valid_ip_candidate(value, version)
    assert parse_ip_candidate(value).version == version


@pytest.mark.parametrize(
    "value",
    [
        "[2001]",
        "[192.0.2.1]",
        "[2001:db8::1]:65536",
        "[2001:db8::1]:abc",
        "2001:db8::1%bad zone",
        "2001:db8:::1",
        "01.2.3.4",
    ],
)
def test_strict_ip_candidate_parser_rejects_invalid_complete_tokens(value):
    assert parse_ip_candidate(value) is None


@pytest.mark.parametrize(
    "value",
    [
        "example.com",
        "EXAMPLE.COM.",
        "foo.bar",
        "example.co.uk",
        "xn--e1afmkfd.xn--p1ai",
        "пример.рф",
    ],
)
def test_offline_iana_domain_validation_accepts_valid_domains(value):
    assert valid_domain_candidate(value)
    assert normalize_domain_candidate(value)


@pytest.mark.parametrize(
    "value",
    [
        "foo.notarealtld",
        "report.txt",
        "photo.png",
        "1.2.3.4",
        "a..com",
        "-bad.com",
        "bad-.com",
        "a_b.com",
        "a." + "b" * 64 + ".com",
        "a.b",
        "JP.Mz",
        "dN5t.aw",
    ],
)
def test_domain_classification_rejects_invalid_filenames_and_screenshot_fragments(value):
    record = by_value(StringAnalyzer(min_length=2, encodings=("ascii",)).analyze(value.encode()), value)

    assert "domain" not in record.categories


def test_domain_classification_avoids_filename_alias_and_correlated_confidence():
    result = StringAnalyzer(min_length=3, encodings=("ascii",)).analyze(
        b"example.com\x00https://example.com\x00192.0.2.1\x00foo.bar"
    )

    domain = by_value(result, "example.com")
    url = by_value(result, "https://example.com")
    ip = by_value(result, "192.0.2.1")
    assert domain.categories == ("domain",)
    assert domain.confidence == "medium"
    assert "filename" not in url.categories
    assert url.confidence == "medium"
    assert ip.confidence == "medium"
    assert "domain" in by_value(result, "foo.bar").categories


@pytest.mark.parametrize(
    "value",
    [
        "PORT=443",
        "debug:true",
        "api_key = secret",
        "endpoint=https://example.com/api",
        "EMPTY=",
        'message: "hello world"',
    ],
)
def test_config_assignment_accepts_strict_env_ini_and_colon_forms(value):
    assert valid_config_assignment(value)
    record = by_value(StringAnalyzer(min_length=3, encodings=("ascii",)).analyze(value.encode()), value)
    assert "config" in record.categories


@pytest.mark.parametrize(
    "value",
    [
        "key==value",
        "key=>value",
        "Error: failed",
        "Content-Type: application/json",
        "username: alice smith",
        "not config: prose",
        "foo:=bar",
        "D_C=b",
        "ABC=x",
    ],
)
def test_config_assignment_rejects_logs_headers_prose_and_operator_mistakes(value):
    assert not valid_config_assignment(value)
    record = by_value(StringAnalyzer(min_length=3, encodings=("ascii",)).analyze(value.encode()), value)
    assert "config" not in record.categories


def test_config_assignment_rejects_non_ascii_keys_before_extraction():
    assert not valid_config_assignment("ÅKEY=value")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://example.com/path", True),
        ("http://192.0.2.1:8080/path", True),
        ("http://[2001:db8::1]:8080/path", True),
        ("http://-bad..com/path", False),
        ("http://999.999.999.999/path", False),
        ("http://foo/path", False),
    ],
)
def test_shared_url_candidate_validator_requires_a_strict_host(value, expected):
    assert valid_url_candidate(value) is expected


def test_embedded_multiple_dll_and_api_entities_all_receive_descriptions():
    value = "Load kernel32.dll and custom.dll then call CreateFileW and VendorApi"
    imports = {
        "kernel32.dll": ["CreateFileW"],
        "custom.dll": ["VendorApi"],
    }

    record = by_value(StringAnalyzer(min_length=4).analyze(value.encode(), imports=imports), value)

    assert record.entities == (
        ("dll", "kernel32.dll"),
        ("dll", "custom.dll"),
        ("api", "CreateFileW"),
        ("api", "VendorApi"),
    )
    assert all(name in record.description for _, name in record.entities)
    assert len(record.to_ai_dict()["deterministic_entities"]) == 4


def test_dll_and_api_entities_deduplicate_case_insensitively():
    value = "KERNEL32.DLL kernel32.dll CreateFileW createfilew"

    record = by_value(StringAnalyzer(min_length=4).analyze(value.encode()), value)

    assert record.entities == (
        ("dll", "KERNEL32.DLL"),
        ("api", "CreateFileW"),
    )
    assert record.description.count("KERNEL32.DLL") == 1
    assert record.description.count("CreateFileW") == 1


def test_custom_record_cap_reports_exact_omissions():
    result = StringAnalyzer(
        min_length=4,
        max_strings=1,
        encodings=("ascii",),
    ).analyze(b"first\0second\0")

    assert result.extracted_count == 2
    assert result.retained_count == 1
    assert result.extraction_truncated is True
    assert result.omitted_count == 1
    assert any("retained 1 of 2" in reason for reason in result.coverage_reasons)


def test_per_record_entity_and_description_caps_bound_adversarial_values():
    value = " ".join(f"x{index}.dll" for index in range(400))

    record = by_value(
        StringAnalyzer(min_length=4, encodings=("ascii",)).analyze(value.encode()),
        value,
    )

    assert len(record.entities) <= 32
    assert len(record.description) <= 4_096
    assert all(f"{name}:" in record.description for _, name in record.entities)
    assert any("retained" in reason and "400 candidates" in reason for reason in record.reasons)
    assert len(record.to_ai_dict()["deterministic_entities"]) == len(record.entities)


def test_import_provenance_is_bounded_and_reports_hidden_modules():
    imports = {
        f"module-{index}-{'x' * 180}.dll": ["CreateFileW"]
        for index in range(1_000)
    }

    record = by_value(
        StringAnalyzer(min_length=4, encodings=("ascii",)).analyze(
            b"CreateFileW\0",
            imports=imports,
        ),
        "CreateFileW",
    )

    provenance = next(reason for reason in record.reasons if reason.startswith("Imported from "))
    assert "+992 more modules" in provenance
    assert len(provenance) <= 1_200
    assert sum(len(reason) for reason in record.reasons) <= 4_500


def test_dll_api_descriptions_import_provenance_and_fallbacks():
    imports = [
        ImportInfo("kernel32.dll", ["CreateRemoteThread", "VendorOperationW"]),
        ImportInfo("custom-agent.dll", []),
    ]
    blob = b"kernel32.dll\x00custom-agent.dll\x00CreateRemoteThread\x00VendorOperationW\x00"

    result = StringAnalyzer(min_length=4).analyze(blob, imports=imports)

    dll = by_value(result, "kernel32.dll")
    assert "dll" in dll.categories
    assert "process" in dll.description.lower()
    unknown_dll = by_value(result, "custom-agent.dll")
    assert "no curated" in unknown_dll.description.lower()
    api = by_value(result, "CreateRemoteThread")
    assert "api" in api.categories
    assert "process injection" in api.description.lower()
    assert any(reason.startswith("Imported from kernel32.dll") for reason in api.reasons)
    fallback = by_value(result, "VendorOperationW")
    assert "api" in fallback.categories
    assert "behavior depends" in fallback.description.lower()


def test_import_metadata_does_not_invent_non_extracted_records():
    result = StringAnalyzer(min_length=4).analyze(b"ordinary text\x00", imports={"ws2_32.dll": ["connect"]})

    assert [record.value for record in result.records] == ["ordinary text"]


def test_deduplicates_occurrences_and_records_are_immutable():
    result = StringAnalyzer(min_length=4).analyze(b"same-value\x00same-value\x00")
    record = by_value(result, "same-value")

    assert record.occurrence_count == 2
    assert record.occurrence_offsets == (0, 11)
    assert record.occurrence_addresses == (None, None)
    assert record.to_dict()["file_offset"] == 0
    assert record.to_dict()["id"] == record.record_id
    with pytest.raises(FrozenInstanceError):
        record.value = "changed"
    assert isinstance(record, StringRecord)


def test_occurrence_addresses_keep_every_valid_mapped_location():
    result = StringAnalyzer(min_length=4).analyze(
        b"repeat-me\x00repeat-me\x00", offset_mapper=lambda offset: 0x1000 + offset
    )

    record = by_value(result, "repeat-me")
    assert record.occurrence_offsets == (0, 10)
    assert record.occurrence_addresses == (0x1000, 0x100A)
    assert record.address == 0x1000


def test_oversized_runs_keep_bounded_previews_and_original_lengths():
    ascii_value = "A" * 30
    utf8_value = "Приветмир"
    wide_value = "wide-string-value"
    blob = (
        ascii_value.encode()
        + b"\x00"
        + utf8_value.encode()
        + b"\x00"
        + wide_value.encode("utf-16le")
        + b"\x00\x00"
    )

    result = StringAnalyzer(min_length=4, max_length=6).analyze(blob)

    ascii_record = by_value(result, "AAAAAA", "ascii")
    utf8_record = by_value(result, utf8_value[:6], "utf-8")
    wide_record = by_value(result, wide_value[:6], "utf-16le")
    assert (ascii_record.char_length, ascii_record.byte_length) == (30, 30)
    assert (utf8_record.char_length, utf8_record.byte_length) == (
        len(utf8_value),
        len(utf8_value.encode()),
    )
    assert (wide_record.char_length, wide_record.byte_length) == (
        len(wide_value),
        len(wide_value.encode("utf-16le")),
    )
    assert all(record.truncated for record in (ascii_record, utf8_record, wide_record))
    assert all(
        "Preview limited" in " ".join(record.reasons) for record in (ascii_record, utf8_record, wide_record)
    )


@pytest.mark.parametrize("encoding", ["utf-16le", "utf-16be"])
def test_utf16_surrogate_pairs_are_one_character_inside_a_run(encoding):
    value = "ab😀cd"
    blob = b"\x00" + value.encode(encoding) + b"\x00\x00"

    result = StringAnalyzer(min_length=5, encodings=(encoding,)).analyze(blob)

    record = by_value(result, value, encoding)
    assert record.char_length == 5
    assert record.byte_length == 12


@pytest.mark.parametrize("encoding", ["utf-16le", "utf-16be"])
def test_coherent_non_latin_utf16_is_preserved(encoding):
    value = "Привет мир"
    result = StringAnalyzer(min_length=5, encodings=(encoding,)).analyze(
        b"\x00\x00" + value.encode(encoding) + b"\x00\x00"
    )

    assert by_value(result, value, encoding).char_length == len(value)


@pytest.mark.parametrize("encoding", ["utf-16le", "utf-16be"])
def test_shifted_opposite_endian_utf16_suffix_is_suppressed(encoding):
    value = "hello world"
    result = StringAnalyzer(min_length=5).analyze(value.encode(encoding) + b"\x00\x00")

    wide = [record for record in result.records if record.encoding.startswith("utf-16")]
    assert [(record.value, record.encoding) for record in wide] == [(value, encoding)]


def test_candidate_and_occurrence_collection_is_bounded(monkeypatch):
    monkeypatch.setattr("analysis.string_analyzer.MAX_CANDIDATES_IN_MEMORY", 5_000)
    blob = b"repeat-me\x00" * 6_000

    result = StringAnalyzer(min_length=4, encodings=("ascii",)).analyze(blob)

    record = by_value(result, "repeat-me")
    # The entire input is scanned and counted while retained occurrence metadata
    # remains bounded and spatially representative.
    assert result.extracted_count == 6_000
    assert result.extraction_truncated is True
    assert result.omitted_count == 1_000
    assert result.count_is_lower_bound is False
    assert result.scanned_bytes == len(blob)
    assert record.occurrence_count == 5_000
    assert len(record.occurrence_offsets) == 4_096
    assert record.occurrence_offsets[-1] == len(blob) - len(b"repeat-me\x00")


@pytest.mark.skipif(not os.path.isfile("/bin/true"), reason="safe ELF fixture unavailable")
def test_normal_elf_wide_noise_does_not_dominate_ascii():
    result = StringAnalyzer().analyze_file("/bin/true")
    encodings = Counter(record.encoding for record in result.records)

    assert encodings["utf-16le"] + encodings["utf-16be"] <= encodings["ascii"]


def test_full_wide_scan_crosses_chunks_and_finds_middle_evidence(monkeypatch):
    monkeypatch.setattr("analysis.string_analyzer.UTF16_SCAN_CHUNK_BYTES", 128)
    marker = "middle evidence".encode("utf-16le") + b"\x00\x00"
    blob = b"\xff" * 1_000 + marker + b"\xff" * 1_000

    result = StringAnalyzer(min_length=5).analyze(blob)

    record = by_value(result, "middle evidence", "utf-16le")
    assert record.offset == 1_000
    assert result.extraction_truncated is False
    assert result.count_is_lower_bound is False
    assert result.omitted_count == 0
    assert result.scanned_bytes == result.total_bytes == len(blob)


def test_length_encoding_filters_cap_and_stable_record_ids():
    blob = b"abc\x00eligible-one\x00eligible-two\x00" + "wide text".encode("utf-16le")
    analyzer = SmartStringAnalyzer(min_length=4, max_length=20, max_strings=2, encodings=("ascii",))

    first = analyzer.analyze(blob)
    second = analyzer.analyze(blob)

    assert first.extraction_truncated is False  # only two eligible ASCII records
    assert first.retained_count == 2
    assert all(record.encoding == "ascii" for record in first.records)
    assert [record.record_id for record in first.records] == [record.record_id for record in second.records]


def test_section_resolution_offset_mapper_and_ai_chunk_limits():
    blob = b"\x00http://one.example/path\x00http://two.example/path\x00"
    sections = [{"name": ".rdata", "raw_offset": 1, "raw_size": len(blob)}]
    result = StringAnalyzer(min_length=4).analyze(
        blob, offset_mapper=lambda offset: 0x140001000 + offset, sections=sections
    )

    assert all(record.section == ".rdata" for record in result.records)
    assert all(record.address == 0x140001000 + record.offset for record in result.records)
    chunks = result.to_ai_chunks(max_items=1, max_chars=2_000)
    assert len(chunks) == result.retained_count
    assert all(len(chunk) == 1 for chunk in chunks)
    assert all(isinstance(chunk[0]["deterministic_categories"], list) for chunk in chunks)
    assert all(isinstance(chunk[0]["offset"], int) for chunk in chunks)
    assert result.to_dict()["counts"]["all"] == result.retained_count


def test_invalid_mapper_results_are_unmapped():
    for mapped in (-1, True, "0x1000", None):
        result = StringAnalyzer(min_length=4).analyze(
            b"printable\x00", offset_mapper=lambda _offset, value=mapped: value
        )
        assert by_value(result, "printable").address is None


def test_analyze_binary_maps_section_offsets_without_inventing_header_addresses():
    raw_data = bytearray(b"\x00" * 0x500)
    raw_data[0x20:0x29] = b"headerstr"
    raw_data[0x400:0x40A] = b"mapped-str"
    binary_info = SimpleNamespace(
        raw_data=bytes(raw_data),
        image_base=0x400000,
        sections=(
            SimpleNamespace(
                name=".rdata",
                raw_offset=0x400,
                raw_size=0x100,
                virtual_address=0x401000,
                virtual_size=0x100,
            ),
        ),
        imports=(),
    )

    result = StringAnalyzer(min_length=4, encodings=("ascii",)).analyze_binary(binary_info)

    assert by_value(result, "headerstr").address is None
    mapped = by_value(result, "mapped-str")
    assert mapped.address == 0x401000
    assert mapped.section == ".rdata"


def test_analyze_file_enforces_regular_file_and_size_limit(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"printable string\x00")
    monkeypatch.setattr("analysis.string_analyzer.config.MAX_BINARY_SIZE_BYTES", 8)

    with pytest.raises(ValueError, match="too large"):
        StringAnalyzer(min_length=4).analyze_file(sample)
    with pytest.raises(ValueError, match="regular file"):
        StringAnalyzer(min_length=4).analyze_file(tmp_path)


def test_constructor_and_chunk_limits_reject_unsafe_values():
    with pytest.raises(ValueError):
        StringAnalyzer(min_length=0)
    with pytest.raises(ValueError):
        StringAnalyzer(min_length=10, max_length=9)
    with pytest.raises(ValueError):
        StringAnalyzer(encodings=("latin-1",))
    with pytest.raises(ValueError):
        StringAnalyzer().analyze(b"printable string").to_ai_chunks(max_chars=100)
