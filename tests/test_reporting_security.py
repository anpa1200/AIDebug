import json
import os
import re

from reporting._io import atomic_write_text
from reporting.html_report import HTMLReporter
from reporting.json_export import JSONExporter


class PatternStore:
    def get_patterns(self, session_id, address):
        assert session_id == "<session>"
        assert address == 0x401000
        return [
            {
                "severity": 'HIGH\" onmouseover=\"alert(1)',
                "name": "</span><script>alert(2)</script>",
                "description": "<img src=x onerror=alert(3)>",
                "evidence": "<svg/onload=alert(4)>",
            }
        ]

    def get_api_calls(self, session_id):
        return [
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "module": "<script>module</script>",
                "function": "CreateFileA",
                "args_json": '["<img src=x onerror=bad()>"]',
                "retval": "0x1",
            }
        ]

    def get_network_events(self, session_id):
        return [
            {
                "event_type": "connect",
                "function": "connect",
                "url": "https://example.test/<script>",
                "size": 12,
            }
        ]

    def get_runtime_events(self, session_id):
        return [
            {
                "event_type": "executable_protection_transition",
                "logged_at": "2026-01-01T00:00:01Z",
                "payload_json": '{"confidence":"heuristic","address":"<svg>"}',
            }
        ]


def test_html_report_escapes_hostile_store_fields_and_uses_nonce_csp(tmp_path):
    session = {
        "id": "<session>",
        "filename": "</title><script>alert(1)</script>.exe",
        "sha256": '<img src=x onerror="alert(2)">',
        "arch": "x86<script>",
        "bits": 64,
        "os_target": "windows&linux",
        "created_at": "<svg/onload=alert(5)>",
    }
    traces = [
        {
            "address": "0x401000",
            "name": "<script>alert(6)</script>",
            "risk_level": 'HIGH\" onclick=\"alert(7)',
            "disassembly": "0x401000: mov eax, <script>alert(8)</script>\n0x401005: ret",
            "decompiled_code": "</pre><script>alert(11)</script>",
            "decompile_language": 'cpp\" onmouseover=\"alert(12)',
            "decompile_backend": '<img src=x onerror=alert(13)>',
            "decompile_warning": '<svg onload=alert(14)>',
            "ai_analysis_json": json.dumps(
                {
                    "suggested_name": "</h2><script>alert(9)</script>",
                    "summary": "<img src=x onerror=alert(10)>",
                    "parameters": [
                        {
                            "name": "<b>p</b>",
                            "type": 'x\" onmouseover=\"bad',
                            "description": "<script>bad()</script>",
                        }
                    ],
                    "behaviors": ["<svg onload=bad()>"],
                    "notes": "</div><script>bad()</script>",
                }
            ),
        }
    ]
    output = tmp_path / "report.html"

    HTMLReporter().generate(session, traces, output, store=PatternStore())
    report = output.read_text(encoding="utf-8")

    assert "<script>alert" not in report
    assert "<img src=x" not in report
    assert "<svg/onload" not in report
    assert "onclick=" not in report
    assert "onmouseover=" not in report
    assert "&lt;script&gt;alert(9)&lt;/script&gt;" in report
    assert "&lt;script&gt;alert(11)&lt;/script&gt;" in report
    assert "Decompiler Output" in report
    assert 'data-function-index="0"' in report
    nonce_match = re.search(r'<script nonce="([A-Za-z0-9_-]+)">', report)
    assert nonce_match
    assert f"script-src 'nonce-{nonce_match.group(1)}'" in report
    assert "CFG: " not in report  # SVG is emitted, not the TUI text renderer.
    assert '<svg xmlns="http://www.w3.org/2000/svg"' in report
    assert "API call evidence" in report
    assert "Network evidence" in report
    assert "Runtime heuristic evidence" in report
    assert "heuristic evidence, not proof" in report
    assert (os.stat(output).st_mode & 0o777) == 0o600


def test_atomic_export_replaces_destination_symlink_without_following_it(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("do not overwrite", encoding="utf-8")
    destination = tmp_path / "export.json"
    try:
        destination.symlink_to(victim)
    except (OSError, NotImplementedError):
        return

    JSONExporter().export({}, [], [], destination)

    assert not destination.is_symlink()
    assert victim.read_text(encoding="utf-8") == "do not overwrite"
    assert json.loads(destination.read_text(encoding="utf-8"))["_schema"] == "aidebug/session/v2"


def test_atomic_writer_falls_back_when_fchmod_is_unavailable(monkeypatch, tmp_path):
    monkeypatch.delattr(os, "fchmod", raising=False)
    output = tmp_path / "portable.txt"

    assert atomic_write_text(output, "complete\n") == str(output)
    assert output.read_text(encoding="utf-8") == "complete\n"
