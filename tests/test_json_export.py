import json

from reporting.json_export import JSONExporter


def test_json_export_builds_risk_summary_and_iocs():
    session = {
        "id": 7,
        "filename": "sample.exe",
        "binary_path": "/lab/sample.exe",
        "sha256": "a" * 64,
        "arch": "x86-64",
        "bits": 64,
        "os_target": "windows",
        "file_format": "PE",
        "analysis_origin": "binary",
        "compiled_sha256": "",
        "created_at": "2026-06-15T00:00:00Z",
    }
    traces = [
        {
            "address": 0x401000,
            "name": "sub_401000",
            "instruction_count": 12,
            "risk_level": "HIGH",
            "mitre_technique": "T1027",
            "strings_referenced": json.dumps(["c2.example.test", ".text"]),
            "calls_to": json.dumps([0x402000]),
            "called_from": json.dumps([]),
            "decompiled_code": "uintptr_t decode_config(void) { return rax; }",
            "decompile_language": "pseudo-c",
            "ai_analysis_json": json.dumps(
                {
                    "summary": "Decodes configuration data",
                    "suggested_name": "decode_config",
                    "behaviors": ["XOR loop"],
                    "mitre_technique": "T1027",
                }
            ),
        }
    ]
    api_calls = [
        {
            "module": "kernel32.dll",
            "function": "CreateFileA",
            "args_json": json.dumps(["config.dat"]),
            "retval": "0x44",
            "timestamp": "2026-06-15T00:01:00Z",
        }
    ]

    network_events = [
        {
            "event_type": "connect",
            "function": "connect",
            "ip": "203.0.113.8",
            "port": 443,
            "size": 0,
            "url": "https://example.test/",
            "headers": "Authorization: secret",
            "timestamp": 42,
        }
    ]
    patterns = [
        {
            "address": 0x401000,
            "name": "xor_decryption_loop",
            "description": "XOR loop",
            "severity": "HIGH",
            "evidence": "xor eax, 0x41",
        }
    ]
    runtime_events = [
        {
            "event_type": "executable_protection_transition",
            "logged_at": "2026-06-15T00:02:00Z",
            "payload_json": json.dumps(
                {
                    "event": "executable_protection_transition",
                    "address": "0x500000",
                    "confidence": "heuristic",
                }
            ),
        }
    ]

    doc = JSONExporter()._build(
        session,
        traces,
        api_calls,
        network_events=network_events,
        runtime_events=runtime_events,
        patterns=patterns,
    )

    assert doc["_schema"] == "aidebug/session/v2"
    assert doc["summary"]["highest_risk"] == "HIGH"
    assert doc["binary"]["format"] == "PE"
    assert doc["binary"]["analysis_origin"] == "binary"
    assert doc["summary"]["mitre_techniques"] == {"T1027": 1}
    assert doc["summary"]["api_calls_logged"] == 1
    assert doc["summary"]["network_events_logged"] == 1
    assert doc["summary"]["runtime_events_logged"] == 1
    assert doc["summary"]["ioc_strings"][0]["value"] == "c2.example.test"
    assert doc["functions"][0]["name"] == "decode_config"
    assert doc["functions"][0]["size_bytes"] is None
    assert doc["functions"][0]["deterministic_patterns"][0]["severity"] == "HIGH"
    assert doc["functions"][0]["decompilation"]["confidence"] == "heuristic"
    assert "decode_config" in doc["functions"][0]["decompilation"]["code"]
    assert doc["network_events"][0]["ip"] == "203.0.113.8"
    assert doc["runtime_events"][0]["payload"]["confidence"] == "heuristic"
    assert doc["runtime_events"][0]["timestamp"] == "2026-06-15T00:02:00Z"
    assert "sensitive" in doc["_privacy_notice"]


def test_json_export_normalizes_malformed_external_records(tmp_path):
    exporter = JSONExporter()
    output = tmp_path / "report.json"
    session = {"id": 1, "bits": "not-a-number", "filename": None}
    traces = [
        "invalid",
        {
            "address": "nope",
            "risk_level": "<script>",
            "ai_analysis_json": "[]",
            "snapshot_json": '{"entry_registers":{"x":NaN}}',
            "strings_referenced": '[1, {"bad": true}, "valid-ioc.test"]',
            "calls_to": "{}",
        },
    ]

    exporter.export(session, traces, [{"args_json": "{}"}], output)
    doc = json.loads(output.read_text(encoding="utf-8"))

    assert doc["binary"]["bits"] == 0
    assert doc["summary"]["risk_counts"]["UNKNOWN"] == 1
    assert doc["functions"][0]["address"] == "0x0"
    assert doc["functions"][0]["snapshot"] is not None
    assert doc["functions"][0]["snapshot"]["entry_registers"]["x"] is None
    assert doc["functions"][0]["calls_to"] == []
    assert doc["api_calls"][0]["args"] == []
