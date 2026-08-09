import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from argparse import Namespace

import pytest

import config
import main
import reporting.yara_generator
import storage
from analysis.source_analyzer import CSourceAnalyzer


def _fake_ghidra(tmp_path):
    launcher = tmp_path / "analyzeHeadless"
    launcher.write_text(
        """#!/usr/bin/env python3
import pathlib
import sys

script_index = sys.argv.index("AIDebugDecompile.java")
output_directory = pathlib.Path(sys.argv[script_index + 1])
address_file = pathlib.Path(sys.argv[script_index + 2])
for address in address_file.read_text(encoding="ascii").splitlines():
    output_directory.joinpath(address + ".c").write_text(
        "int ghidra_function(void) {\\n    return 0;\\n}\\n",
        encoding="utf-8",
    )
""",
        encoding="utf-8",
    )
    launcher.chmod(0o700)
    return launcher


def test_main_help_runs():
    result = subprocess.run(
        [sys.executable, "main.py", "--help"],
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0
    assert "AIDebug" in result.stdout
    assert "--binary" in result.stdout
    assert "--source" in result.stdout
    assert "--decompile" in result.stdout
    assert "--decompile-all" in result.stdout
    assert "--learn" in result.stdout
    assert "--history" in result.stdout
    assert "--learning-compiler" in result.stdout
    assert "--breakpoint" in result.stdout


def test_learning_mode_lists_and_opens_lessons_without_database(tmp_path):
    db_path = tmp_path / "must-not-exist.db"
    listed = subprocess.run(
        [sys.executable, "main.py", "--learn", "--db", str(db_path)],
        check=False,
        text=True,
        capture_output=True,
    )
    # Learning mode deliberately conflicts with analysis/storage overrides so
    # it cannot accidentally create application state.
    assert listed.returncode == 2
    assert "--learn cannot be combined" in listed.stderr
    assert not db_path.exists()

    opened = subprocess.run(
        [sys.executable, "main.py", "--learn", "arithmetic", "--no-tui"],
        check=False,
        text=True,
        capture_output=True,
    )
    assert opened.returncode == 0
    assert "Integer addition" in opened.stdout
    assert "Analyze one real compiled function" in opened.stdout


def test_version_matches_release_metadata():
    result = subprocess.run(
        [sys.executable, "main.py", "--version"],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == f"AIDebug {config.APP_VERSION}"


def test_session_list_without_api_key(tmp_path):
    db_path = tmp_path / "traces.db"
    result = subprocess.run(
        [sys.executable, "main.py", "--db", str(db_path), "--list-sessions"],
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0
    assert "No analysis sessions found" in result.stdout


def test_hash_history_accepts_file_and_prints_prior_ai_findings(tmp_path, capsys):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"same sample bytes")
    expected_hash = hashlib.sha256(sample.read_bytes()).hexdigest()

    class FakeStore:
        db_path = str(tmp_path / "traces.db")

        def find_sessions_by_sha256(self, sha256):
            assert sha256 == expected_hash
            return [{
                "id": 7,
                "status": "completed",
                "analysis_mode": "static",
                "analyzer": "Claude test",
                "created_at": "2026-08-09 10:00:00",
                "completed_at": "2026-08-09 10:01:00",
                "function_count": 1,
                "pattern_count": 2,
                "api_call_count": 0,
                "network_event_count": 0,
                "runtime_event_count": 0,
                "critical_count": 0,
                "high_count": 1,
                "medium_count": 0,
                "low_count": 0,
            }]

        def get_all_traces(self, session_id):
            assert session_id == 7
            return [{
                "address": 0x401000,
                "name": "sub_401000",
                "risk_level": "HIGH",
                "mitre_technique": "T1059",
                "ai_analysis_json": json.dumps({
                    "suggested_name": "possible_command_runner",
                    "summary": "May launch a command interpreter.",
                }),
            }]

    sessions = main.show_hash_history(FakeStore(), str(sample))
    output = capsys.readouterr().out
    assert sessions[0]["id"] == 7
    assert expected_hash in output
    assert "possible_command_runner" in output
    assert "aidebug --session 7 --json-export" in output


def test_hash_history_rejects_partial_hash():
    with pytest.raises(main.CLIError, match="full 64-character SHA-256"):
        main._history_sha256("abc123")


@pytest.mark.skipif(not os.path.isfile("/bin/true"), reason="safe ELF fixture unavailable")
def test_reopening_same_binary_restores_hash_history_and_finishes_sessions(tmp_path):
    db_path = tmp_path / "history.db"
    command = [
        sys.executable,
        "main.py",
        "--binary",
        "/bin/true",
        "--offline",
        "--no-tui",
        "--max-functions",
        "1",
        "--db",
        str(db_path),
    ]
    first = subprocess.run(command, check=False, text=True, capture_output=True)
    second = subprocess.run(command, check=False, text=True, capture_output=True)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert "Recognized SHA-256" not in first.stdout
    assert "Recognized SHA-256" in second.stdout
    assert "Compatible function results will be restored automatically" in second.stdout

    connection = sqlite3.connect(db_path)
    try:
        rows = connection.execute(
            "SELECT analysis_mode, analyzer, status, completed_at "
            "FROM sessions ORDER BY id"
        ).fetchall()
    finally:
        connection.close()
    assert len(rows) == 2
    assert all(row[0] == "static" for row in rows)
    assert all(row[1] == "Deterministic offline analysis" for row in rows)
    assert all(row[2] == "completed" for row in rows)
    assert all(row[3] for row in rows)


def test_no_operation_has_no_database_side_effect(tmp_path):
    db_path = tmp_path / "must-not-exist.db"
    result = subprocess.run(
        [sys.executable, "main.py", "--db", str(db_path)],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 2
    assert "choose --binary" in result.stderr
    assert not db_path.exists()


def test_missing_report_session_returns_nonzero(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--db",
            str(tmp_path / "traces.db"),
            "--session",
            "99",
            "--json-export",
            "--out-dir",
            str(tmp_path / "reports"),
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 1
    assert "Session 99 not found" in result.stderr


def test_remote_bulk_requires_cost_acknowledgement_before_db_open(tmp_path):
    db_path = tmp_path / "must-not-exist.db"
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--binary",
            sys.executable,
            "--no-tui",
            "--db",
            str(db_path),
        ],
        check=False,
        text=True,
        capture_output=True,
        env={key: value for key, value in os.environ.items() if key != "ANTHROPIC_API_KEY"},
    )

    assert result.returncode == 2
    assert "--accept-ai-cost" in result.stderr
    assert "--offline" in result.stderr
    assert not db_path.exists()


def test_bulk_function_limit_is_bounded_before_db_open(tmp_path):
    db_path = tmp_path / "must-not-exist.db"
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--binary",
            sys.executable,
            "--offline",
            "--no-tui",
            "--max-functions",
            "301",
            "--db",
            str(db_path),
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 2
    assert "cannot exceed" in result.stderr
    assert not db_path.exists()


def test_offline_cli_analyzes_without_anthropic_key(tmp_path):
    sample = shutil.which("true")
    if sample is None:
        pytest.skip("A small local ELF fixture is unavailable")
    db_path = tmp_path / "offline.db"
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--binary",
            sample,
            "--offline",
            "--no-tui",
            "--max-functions",
            "1",
            "--db",
            str(db_path),
        ],
        check=False,
        text=True,
        capture_output=True,
        env={key: value for key, value in os.environ.items() if key != "ANTHROPIC_API_KEY"},
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert "Offline mode" in result.stdout
    assert "Bulk preflight: 1 function" in result.stdout
    assert str(db_path) in result.stdout
    assert db_path.exists()


def test_offline_cli_decompiles_elf_with_ghidra_and_persists_output(tmp_path):
    sample = shutil.which("true")
    if sample is None:
        pytest.skip("A small local ELF fixture is unavailable")
    db_path = tmp_path / "decompile.db"
    launcher = _fake_ghidra(tmp_path)
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--binary",
            sample,
            "--offline",
            "--no-tui",
            "--decompile",
            "--ghidra-headless",
            str(launcher),
            "--max-functions",
            "1",
            "--db",
            str(db_path),
        ],
        check=False,
        text=True,
        capture_output=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert "ghidra decompilation" in result.stdout
    assert "int ghidra_function" in result.stdout
    with sqlite3.connect(db_path) as connection:
        code, language, backend = connection.execute(
            "SELECT decompiled_code, decompile_language, decompile_backend "
            "FROM function_traces"
        ).fetchone()
    assert code.startswith("int ghidra_function")
    assert language == "c"
    assert backend == "ghidra"


def test_decompile_all_writes_combined_program(tmp_path):
    sample = shutil.which("true")
    if sample is None:
        pytest.skip("A small local ELF fixture is unavailable")
    launcher = _fake_ghidra(tmp_path)
    destination = tmp_path / "whole-program.c"
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--binary",
            sample,
            "--offline",
            "--no-tui",
            "--decompile-all",
            str(destination),
            "--ghidra-headless",
            str(launcher),
            "--max-functions",
            "1",
            "--db",
            str(tmp_path / "full.db"),
        ],
        check=False,
        text=True,
        capture_output=True,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    assert "Full decompilation" in result.stdout
    content = destination.read_text(encoding="utf-8")
    assert "full-program Ghidra reconstruction" in content
    assert "not recovered original source" in content
    assert "int ghidra_function" in content


def test_decompile_requires_an_input_before_database_open(tmp_path):
    db_path = tmp_path / "must-not-exist.db"
    result = subprocess.run(
        [sys.executable, "main.py", "--decompile", "--db", str(db_path)],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 2
    assert "--decompile requires --binary or --source" in result.stderr
    assert not db_path.exists()


@pytest.mark.skipif(
    not CSourceAnalyzer.sandbox_available()
    or not any(shutil.which(name) for name in ("cc", "gcc", "clang")),
    reason="A usable Bubblewrap sandbox or ELF-capable C compiler is unavailable",
)
def test_offline_cli_analyzes_c_source_via_temporary_elf(tmp_path):
    source = tmp_path / "sample.c"
    source.write_text(
        "static __attribute__((noinline)) int helper(int x) { return x + 1; }\n"
        "int main(void) { return helper(4); }\n",
        encoding="utf-8",
    )
    db_path = tmp_path / "source.db"
    launcher = _fake_ghidra(tmp_path)

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--source",
            str(source),
            "--offline",
            "--no-tui",
            "--max-functions",
            "2",
            "--decompile",
            "--ghidra-headless",
            str(launcher),
            "--report",
            "--json-export",
            "--out-dir",
            str(tmp_path / "reports"),
            "--db",
            str(db_path),
        ],
        check=False,
        text=True,
        capture_output=True,
        env={key: value for key, value in os.environ.items() if key != "ANTHROPIC_API_KEY"},
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    assert "temporary ELF analysis artifact" in result.stdout
    assert "Format   : C/ELF" in result.stdout
    assert "Found 2 functions" in result.stdout
    assert "Ghidra decompiled" in result.stdout
    assert db_path.exists()
    reports = list((tmp_path / "reports").iterdir())
    assert {path.suffix for path in reports} == {".html", ".json"}
    exported = json.loads(next(path for path in reports if path.suffix == ".json").read_text())
    assert exported["functions"][0]["decompilation"]["language"] == "c"
    assert exported["functions"][0]["decompilation"]["backend"] == "ghidra"


def test_c_source_rejects_dynamic_and_yara_modes_before_db_open(tmp_path):
    source = tmp_path / "sample.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")

    for index, (extra_args, expected) in enumerate((
        (["--mode", "dynamic"], "never executed"),
        (["--yara"], "unavailable for C source"),
    )):
        db_path = tmp_path / f"rejected-{index}.db"
        result = subprocess.run(
            [
                sys.executable,
                "main.py",
                "--source",
                str(source),
                "--offline",
                "--db",
                str(db_path),
                *extra_args,
            ],
            check=False,
            text=True,
            capture_output=True,
        )

        assert result.returncode == 2
        assert expected in result.stderr
        assert not db_path.exists()


def test_execute_always_closes_store(monkeypatch, tmp_path):
    instances = []

    class FakeStore:
        def __init__(self, db_path):
            self.db_path = db_path
            self.closed = False
            instances.append(self)

        def list_sessions(self):
            return []

        def close(self):
            self.closed = True

    monkeypatch.setattr(storage, "TraceStore", FakeStore)
    args = Namespace(
        db=str(tmp_path / "unused.db"),
        list_sessions=True,
        report=False,
        yara=False,
        json_export=False,
        binary=None,
    )

    assert main._execute(args) == 0
    assert instances[0].closed


def test_reports_confine_hostile_database_filename_to_output_directory(tmp_path):
    class FakeStore:
        def get_session(self, session_id):
            return {"id": session_id, "filename": "../../escape\x1b[31m.exe"}

        def get_all_traces(self, session_id):
            return []

        def get_api_calls(self, session_id):
            return []

        def get_network_events(self, session_id):
            return []

        def get_runtime_events(self, session_id):
            return []

        def get_patterns(self, session_id, address=None):
            return []

    output_directory = tmp_path / "reports"
    assert main.run_reports(
        FakeStore(),
        7,
        str(output_directory),
        do_json=True,
    )

    outputs = list(output_directory.iterdir())
    assert len(outputs) == 1
    assert outputs[0].parent == output_directory
    assert outputs[0].name == "escape_31m_exe_session_7_export.json"
    assert not (tmp_path / "escape.json").exists()


def test_report_only_remote_yara_forwards_cli_function_cap(monkeypatch, tmp_path):
    observed = {}

    class FakeStore:
        def __init__(self, db_path):
            self.db_path = db_path
            self.closed = False

        def get_session(self, session_id):
            return {"id": session_id, "filename": "sample.exe"}

        def get_all_traces(self, session_id):
            return [{"risk_level": "HIGH", "address": index} for index in range(3)]

        def get_api_calls(self, session_id):
            return []

        def get_network_events(self, session_id):
            return []

        def get_runtime_events(self, session_id):
            return []

        def get_patterns(self, session_id, address=None):
            return []

        def close(self):
            self.closed = True

    class FakeYaraGenerator:
        def __init__(self, *, allow_remote):
            observed["allow_remote"] = allow_remote

        def generate(self, session, traces, output_path, *, max_rules=None):
            observed.update(
                session=session,
                trace_count=len(traces),
                output_path=output_path,
                max_rules=max_rules,
            )
            return str(output_path), min(len(traces), max_rules)

    store = FakeStore(str(tmp_path / "unused.db"))
    monkeypatch.setattr(storage, "TraceStore", lambda db_path: store)
    monkeypatch.setattr(reporting.yara_generator, "YaraGenerator", FakeYaraGenerator)
    args = Namespace(
        db=store.db_path,
        list_sessions=False,
        report=False,
        yara=True,
        json_export=False,
        binary=None,
        session=7,
        out_dir=str(tmp_path / "reports"),
        accept_ai_cost=True,
        offline=False,
        max_functions=1,
    )

    assert main._execute(args) == 0
    assert observed["allow_remote"] is True
    assert observed["trace_count"] == 3
    assert observed["max_rules"] == 1
    assert store.closed


def test_report_only_remote_yara_failure_returns_nonzero(monkeypatch, tmp_path, capsys):
    class FakeStore:
        def __init__(self, db_path):
            self.db_path = db_path

        def get_session(self, session_id):
            return {"id": session_id, "filename": "sample.exe"}

        def get_all_traces(self, session_id):
            return [
                {
                    "risk_level": "HIGH",
                    "address": 0x401000,
                    "name": "danger",
                    "ai_analysis_json": "{}",
                    "strings_referenced": "[]",
                    "disassembly": "0x401000: ret",
                }
            ]

        def get_api_calls(self, session_id):
            return []

        def get_network_events(self, session_id):
            return []

        def get_runtime_events(self, session_id):
            return []

        def get_patterns(self, session_id, address=None):
            return []

        def close(self):
            pass

    store = FakeStore(str(tmp_path / "unused.db"))
    monkeypatch.setattr(storage, "TraceStore", lambda db_path: store)
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "")
    output_directory = tmp_path / "reports"
    args = Namespace(
        db=store.db_path,
        list_sessions=False,
        report=False,
        yara=True,
        json_export=False,
        binary=None,
        session=7,
        out_dir=str(output_directory),
        accept_ai_cost=True,
        offline=False,
        max_functions=1,
    )

    assert main._execute(args) == 1
    stderr = capsys.readouterr().err
    assert "Remote YARA request failed" in stderr
    assert "No deterministic fallback was substituted" in stderr
    assert not (output_directory / "sample_exe_session_7.yar").exists()


def test_terminal_text_escapes_control_sequences():
    rendered = main._terminal_text("sample\x1b[2J\nnext")
    assert "\x1b" not in rendered
    assert rendered == "sample\\x1b[2J\\x0anext"
