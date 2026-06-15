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

    doc = JSONExporter()._build(session, traces, api_calls)

    assert doc["_schema"] == "aidebug/session/v1"
    assert doc["summary"]["highest_risk"] == "HIGH"
    assert doc["summary"]["mitre_techniques"] == {"T1027": 1}
    assert doc["summary"]["api_calls_logged"] == 1
    assert doc["summary"]["ioc_strings"][0]["value"] == "c2.example.test"
    assert doc["functions"][0]["name"] == "decode_config"
