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


def test_offline_cli_decompiles_elf_and_persists_pseudo_source(tmp_path):
    sample = shutil.which("true")
    if sample is None:
        pytest.skip("A small local ELF fixture is unavailable")
    db_path = tmp_path / "decompile.db"
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--binary",
            sample,
            "--offline",
            "--no-tui",
            "--decompile",
            "cpp",
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
    assert "Heuristic decompilation" in result.stdout
    assert "std::uintptr_t" in result.stdout
    with sqlite3.connect(db_path) as connection:
        code, language = connection.execute(
            "SELECT decompiled_code, decompile_language FROM function_traces"
        ).fetchone()
    assert code.startswith("std::uintptr_t")
    assert language == "cpp"


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
    not any(shutil.which(name) for name in ("cc", "gcc", "clang")),
    reason="an ELF-capable C compiler is unavailable",
)
def test_offline_cli_analyzes_c_source_via_temporary_elf(tmp_path):
    source = tmp_path / "sample.c"
    source.write_text(
        "static __attribute__((noinline)) int helper(int x) { return x + 1; }\n"
        "int main(void) { return helper(4); }\n",
        encoding="utf-8",
    )
    db_path = tmp_path / "source.db"

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
            "cpp",
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
    assert "heuristic cpp function reconstruction" in result.stdout
    assert db_path.exists()
    reports = list((tmp_path / "reports").iterdir())
    assert {path.suffix for path in reports} == {".html", ".json"}
    exported = json.loads(next(path for path in reports if path.suffix == ".json").read_text())
    assert exported["functions"][0]["decompilation"]["language"] == "cpp"


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
