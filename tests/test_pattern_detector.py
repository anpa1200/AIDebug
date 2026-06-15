from analysis.disassembler import Function, Instruction
from analysis.pattern_detector import PatternDetector


def insn(address, mnemonic, op_str=""):
    return Instruction(address=address, mnemonic=mnemonic, op_str=op_str, raw_bytes=b"")


def names(patterns):
    return {pattern.name for pattern in patterns}


def test_detects_xor_decryption_loop():
    function = Function(
        address=0x1000,
        name="sub_1000",
        instructions=[
            insn(0x1000, "mov", "ecx, 4"),
            insn(0x1001, "xor", "byte ptr [eax], 0x41"),
            insn(0x1002, "inc", "eax"),
            insn(0x1003, "loop", "0x1001"),
        ],
    )

    patterns = PatternDetector().detect(function)

    assert "xor_decryption_loop" in names(patterns)
    assert next(p for p in patterns if p.name == "xor_decryption_loop").severity == "HIGH"


def test_ignores_register_zeroing_xor_loop():
    function = Function(
        address=0x2000,
        name="sub_2000",
        instructions=[
            insn(0x2000, "xor", "eax, eax"),
            insn(0x2001, "inc", "ecx"),
            insn(0x2002, "loop", "0x2000"),
        ],
    )

    assert "xor_decryption_loop" not in names(PatternDetector().detect(function))


def test_detects_stack_string_construction():
    function = Function(
        address=0x3000,
        name="sub_3000",
        instructions=[
            insn(0x3000, "mov", "byte ptr [esp+0], 0x63"),
            insn(0x3001, "mov", "byte ptr [esp+1], 0x6d"),
            insn(0x3002, "mov", "byte ptr [esp+2], 0x64"),
            insn(0x3003, "mov", "byte ptr [esp+3], 0x00"),
            insn(0x3004, "ret"),
        ],
    )

    patterns = PatternDetector().detect(function)

    assert "stack_string" in names(patterns)


def test_detects_base64_alphabet_reference():
    function = Function(
        address=0x4000,
        name="sub_4000",
        instructions=[insn(0x4000, "ret")],
        strings_referenced=["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"],
    )

    patterns = PatternDetector().detect(function)

    assert "base64_alphabet_reference" in names(patterns)
