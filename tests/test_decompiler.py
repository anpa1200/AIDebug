from types import SimpleNamespace

import pytest

import config
from analysis.decompiler import (
    DecompilerError,
    GhidraDecompiler,
    render_full_decompilation,
    write_full_decompilation,
)


def _binary(*, image_base=0):
    return SimpleNamespace(raw_data=b"\x7fELF\x02\x01fixture", image_base=image_base)


def _launcher(tmp_path):
    executable = tmp_path / "analyzeHeadless"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    return executable


def test_ghidra_backend_returns_bounded_real_decompiler_output(tmp_path, monkeypatch):
    launcher = _launcher(tmp_path)
    monkeypatch.setattr(config, "MAX_DECOMPILED_CHARS", 180)
    captured_command = []

    def fake_run(self, command, working):
        captured_command.extend(command)
        script_index = command.index("AIDebugDecompile.java")
        output_directory = __import__("pathlib").Path(command[script_index + 1])
        output_directory.joinpath("1000.c").write_text(
            "int sample_function(int value) {\n"
            "  return value + 1;\n"
            "}\n" + ("x" * 300),
            encoding="utf-8",
        )

    monkeypatch.setattr(GhidraDecompiler, "_run", fake_run)
    result = GhidraDecompiler(
        _binary(image_base=0x400000), executable=launcher
    ).decompile([0x1000])[0x1000]

    assert result.language == "c"
    assert result.backend == "ghidra"
    assert result.code.startswith("int sample_function")
    assert len(result.code) == 180
    assert "not the original source" in result.warning
    script_index = captured_command.index("AIDebugDecompile.java")
    assert captured_command[script_index + 3] == str(0x400000)


def test_ghidra_backend_reports_per_function_failures(tmp_path, monkeypatch):
    launcher = _launcher(tmp_path)

    def fake_run(self, command, working):
        script_index = command.index("AIDebugDecompile.java")
        output_directory = __import__("pathlib").Path(command[script_index + 1])
        output_directory.joinpath("errors.log").write_text(
            "1000: function not identified\n", encoding="utf-8"
        )

    monkeypatch.setattr(GhidraDecompiler, "_run", fake_run)
    with pytest.raises(DecompilerError, match="function not identified"):
        GhidraDecompiler(_binary(), executable=launcher).decompile([0x1000])


def test_ghidra_backend_rejects_missing_launcher(tmp_path):
    with pytest.raises(DecompilerError, match="Unable to inspect Ghidra launcher"):
        GhidraDecompiler(_binary(), executable=tmp_path / "missing")


@pytest.mark.parametrize("address", [-1, True, "1000"])
def test_ghidra_backend_rejects_invalid_addresses(tmp_path, address):
    backend = GhidraDecompiler(_binary(), executable=_launcher(tmp_path))
    with pytest.raises(ValueError, match="non-negative integers"):
        backend.decompile([address])


def test_full_decompilation_combines_functions_and_refuses_overwrite(tmp_path):
    first = SimpleNamespace(
        name="main",
        decompiled_code="int main(void) { return helper(); }",
        decompile_backend="ghidra",
        decompile_language="c",
    )
    second = SimpleNamespace(
        name="helper",
        decompiled_code="int helper(void) { return 7; }",
        decompile_backend="ghidra",
        decompile_language="c",
    )
    functions = {0x1000: first, 0x1100: second}
    disassembler = SimpleNamespace(get_function=functions.get)
    info = SimpleNamespace(
        filename="sample.elf",
        sha256="a" * 64,
        arch="x86-64",
        bits=64,
    )

    content = render_full_decompilation(info, disassembler, [0x1000, 0x1100])
    assert "not recovered original source" in content
    assert "Function main at 0x1000" in content
    assert "int helper" in content

    destination = tmp_path / "full.c"
    assert write_full_decompilation(destination, info, disassembler, [0x1000, 0x1100]) == destination
    assert destination.stat().st_mode & 0o777 == 0o600
    with pytest.raises(DecompilerError, match="Refusing to overwrite"):
        write_full_decompilation(destination, info, disassembler, [0x1000])
