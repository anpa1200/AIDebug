from types import SimpleNamespace

import pytest

import config
from analysis.decompiler import PseudoDecompiler
from analysis.disassembler import Function, Instruction


def _binary(arch="x86-64"):
    return SimpleNamespace(arch=arch, bits=64)


def test_pseudo_c_reconstructs_data_flow_branches_calls_and_return():
    callee = Function(0x2000, "known_helper", [Instruction(0x2000, "ret", "", b"")])
    function = Function(
        0x1000,
        "sample_function",
        [
            Instruction(0x1000, "mov", "eax, 5", b""),
            Instruction(0x1002, "cmp", "ecx, 0", b""),
            Instruction(0x1004, "je", "0x100a", b""),
            Instruction(0x1006, "call", "0x2000", b""),
            Instruction(0x1008, "add", "eax, 1", b""),
            Instruction(0x100A, "ret", "", b""),
        ],
    )
    disassembler = SimpleNamespace(functions={0x1000: function, 0x2000: callee})

    result = PseudoDecompiler(_binary(), disassembler).decompile(function)

    assert result.language == "pseudo-c"
    assert "uintptr_t sample_function" in result.code
    assert "eax = 5;" in result.code
    assert "if (equal(compare(ecx, 0))) goto loc_100a;" in result.code
    assert "known_helper(/* arguments reconstructed by ABI */)" in result.code
    assert "loc_100a:" in result.code
    assert "return rax;" in result.code
    assert result.confidence == "heuristic"
    assert "not the original source" in result.warning


def test_cpp_mode_is_bounded_and_sanitizes_untrusted_disassembly(monkeypatch):
    monkeypatch.setattr(config, "MAX_DECOMPILED_CHARS", 180)
    function = Function(
        0x1000,
        "7 bad*/name",
        [Instruction(0x1000 + index, "mystery", "evil*/\x1b[31m", b"") for index in range(20)],
    )

    result = PseudoDecompiler(_binary(), language="cpp").decompile(function)

    assert result.code.startswith("std::uintptr_t fn_7_bad__name")
    assert "evil*/" not in result.code
    assert "\x1b" not in result.code
    assert len(result.code) <= 180
    assert "output truncated" in result.code


def test_decompiler_rejects_unknown_output_language():
    with pytest.raises(ValueError, match="Unsupported decompilation language"):
        PseudoDecompiler(_binary(), language="python")
