"""Bounded, deterministic machine-code to pseudo-source reconstruction.

This is intentionally a conservative renderer rather than a claim that the
original C/C++ source can be recovered.  It preserves control-flow labels and
falls back to explicit ``asm`` comments whenever an instruction cannot be
represented safely.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import config

from .disassembler import Function, Instruction
from .static_analyzer import BinaryInfo


@dataclass(frozen=True)
class DecompiledFunction:
    language: str
    code: str
    confidence: str = "heuristic"
    warning: str = (
        "Heuristic reconstruction from machine code; this is not the original source. "
        "Types, names, expressions, and control flow may be inaccurate."
    )


class PseudoDecompiler:
    """Render a :class:`Function` as conservative pseudo-C or C++-style text."""

    LANGUAGES = {"pseudo-c", "cpp"}
    _IDENTIFIER = re.compile(r"[^A-Za-z0-9_]")
    _ADDRESS = re.compile(r"^(?:#)?(?:0x[0-9a-fA-F]+|[0-9]+)$")
    _CONDITIONS = {
        "je": "equal", "jz": "equal", "jne": "not_equal", "jnz": "not_equal",
        "jg": "signed_greater", "jnle": "signed_greater",
        "jge": "signed_greater_equal", "jnl": "signed_greater_equal",
        "jl": "signed_less", "jnge": "signed_less",
        "jle": "signed_less_equal", "jng": "signed_less_equal",
        "ja": "unsigned_above", "jnbe": "unsigned_above",
        "jae": "unsigned_above_equal", "jnb": "unsigned_above_equal",
        "jb": "unsigned_below", "jnae": "unsigned_below",
        "jbe": "unsigned_below_equal", "jna": "unsigned_below_equal",
        "js": "negative", "jns": "not_negative", "jo": "overflow",
        "jno": "not_overflow", "jp": "parity", "jpe": "parity",
        "jnp": "not_parity", "jpo": "not_parity",
        "beq": "equal", "bne": "not_equal", "bgt": "signed_greater",
        "bge": "signed_greater_equal", "blt": "signed_less",
        "ble": "signed_less_equal", "bhi": "unsigned_above",
        "bhs": "unsigned_above_equal", "blo": "unsigned_below",
        "bls": "unsigned_below_equal", "cbz": "zero", "cbnz": "not_zero",
        "tbz": "bit_clear", "tbnz": "bit_set",
    }

    def __init__(
        self,
        binary_info: BinaryInfo,
        disassembler=None,
        *,
        language: str = "pseudo-c",
    ):
        if language not in self.LANGUAGES:
            choices = ", ".join(sorted(self.LANGUAGES))
            raise ValueError(f"Unsupported decompilation language {language!r}; choose {choices}")
        self.info = binary_info
        self.disassembler = disassembler
        self.language = language

    def decompile(self, function: Function) -> DecompiledFunction:
        """Return bounded pseudo-source for one already-disassembled function."""
        function_name = self._identifier(function.name, f"sub_{function.address:x}")
        instructions = list(function.instructions[:config.MAX_INSTRUCTIONS_PER_FUNCTION])
        labels = self._branch_labels(function, instructions)
        return_register = self._return_register()
        integer_type = "std::uintptr_t" if self.language == "cpp" else "uintptr_t"
        lines = [
            f"{integer_type} {function_name}(/* parameters unknown */) {{",
            "    // Heuristic reconstruction from machine code; not original source.",
            "    // Types, names, expressions, and control flow may be inaccurate.",
            f"    {integer_type} result = 0;  // probable return value ({return_register})",
        ]

        last_condition = None
        for instruction in instructions:
            if instruction.address in labels:
                lines.append(f"{labels[instruction.address]}:")
            rendered, last_condition = self._render_instruction(
                instruction,
                labels,
                last_condition,
                return_register,
            )
            lines.extend(f"    {line}" if line else "" for line in rendered)

        if not instructions or instructions[-1].mnemonic.lower() not in {
            "ret", "retn", "retf", "retq",
        }:
            lines.append("    return result;")
        lines.append("}")
        code = self._bounded("\n".join(lines))
        return DecompiledFunction(language=self.language, code=code)

    def _render_instruction(
        self,
        instruction: Instruction,
        labels: dict[int, str],
        last_condition: str | None,
        return_register: str,
    ) -> tuple[list[str], str | None]:
        mnemonic = self._safe_text(instruction.mnemonic, 32).lower()
        operands = self._split_operands(instruction.op_str)
        safe_operands = [self._operand(item) for item in operands]

        if mnemonic in {"endbr64", "endbr32", "nop", "hint"}:
            return [f"/* {mnemonic} */"], last_condition

        if mnemonic in {"mov", "movabs", "movzx", "movsx", "movsxd"} and len(safe_operands) >= 2:
            destination, source = safe_operands[:2]
            if mnemonic == "movzx":
                source = f"zero_extend({source})"
            elif mnemonic in {"movsx", "movsxd"}:
                source = f"sign_extend({source})"
            assignment = f"{destination} = {source};"
            if self._register_name(operands[0]) == return_register:
                assignment += " result = " + destination + ";"
            return [assignment], last_condition

        if mnemonic in {"lea", "adr", "adrp"} and len(safe_operands) >= 2:
            return [f"{safe_operands[0]} = address_of({safe_operands[1]});"], last_condition

        if mnemonic in {"add", "sub", "and", "or", "xor"} and len(safe_operands) >= 2:
            destination, source = safe_operands[:2]
            if mnemonic == "xor" and self._same_operand(operands[0], operands[1]):
                statement = f"{destination} = 0;"
            else:
                operator = {"add": "+=", "sub": "-=", "and": "&=", "or": "|=", "xor": "^="}[mnemonic]
                statement = f"{destination} {operator} {source};"
            if self._register_name(operands[0]) == return_register:
                statement += " result = " + destination + ";"
            return [statement], last_condition

        if mnemonic in {"inc", "dec", "neg", "not"} and safe_operands:
            expression = {
                "inc": f"++{safe_operands[0]};",
                "dec": f"--{safe_operands[0]};",
                "neg": f"{safe_operands[0]} = -{safe_operands[0]};",
                "not": f"{safe_operands[0]} = ~{safe_operands[0]};",
            }[mnemonic]
            return [expression], last_condition

        if mnemonic in {"shl", "sal", "shr", "sar"} and len(safe_operands) >= 2:
            operator = "<<=" if mnemonic in {"shl", "sal"} else ">>="
            return [f"{safe_operands[0]} {operator} {safe_operands[1]};"], last_condition

        if mnemonic in {"rol", "ror"} and len(safe_operands) >= 2:
            helper = "rotate_left" if mnemonic == "rol" else "rotate_right"
            return [
                f"{safe_operands[0]} = {helper}({safe_operands[0]}, {safe_operands[1]});"
            ], last_condition

        if mnemonic in {"imul", "mul"} and len(safe_operands) >= 2:
            if len(safe_operands) >= 3:
                return [
                    f"{safe_operands[0]} = {safe_operands[1]} * {safe_operands[2]};"
                ], last_condition
            return [f"{safe_operands[0]} *= {safe_operands[1]};"], last_condition

        if mnemonic in {"cmp", "test"} and len(safe_operands) >= 2:
            helper = "compare" if mnemonic == "cmp" else "test_bits"
            condition = f"{helper}({safe_operands[0]}, {safe_operands[1]})"
            return [f"/* flags = {condition}; */"], condition

        if mnemonic in self._CONDITIONS:
            target = self._target(operands[-1] if operands else "")
            target_text = labels.get(target, self._target_text(target, safe_operands))
            condition = self._condition_expression(mnemonic, last_condition, safe_operands)
            return [f"if ({condition}) goto {target_text};"], last_condition

        if mnemonic in {"jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne"}:
            target = self._target(operands[-1] if operands else "")
            target_text = labels.get(target, self._target_text(target, safe_operands))
            return [f"if ({mnemonic}_condition()) goto {target_text};"], last_condition

        if mnemonic in {"jmp", "jmpq", "b"}:
            target = self._target(operands[-1] if operands else "")
            target_text = labels.get(target, self._target_text(target, safe_operands))
            indirect = " /* indirect or tail call */" if target is None else ""
            return [f"goto {target_text};{indirect}"], last_condition

        if mnemonic in {"call", "callq", "bl", "blx", "jal", "jalr"}:
            return [f"result = {self._call_target(operands)}(/* arguments reconstructed by ABI */);"], last_condition

        if mnemonic in {"ret", "retn", "retf", "retq"}:
            return [f"return {return_register};"], last_condition

        if mnemonic in {"syscall", "sysenter", "svc", "ecall"}:
            return ["result = system_call(/* register arguments */);"], last_condition

        if mnemonic == "push" and safe_operands:
            return [f"stack_push({safe_operands[0]});"], last_condition
        if mnemonic == "pop" and safe_operands:
            return [f"{safe_operands[0]} = stack_pop();"], last_condition

        assembly = " ".join(part for part in (mnemonic, self._safe_comment(instruction.op_str)) if part)
        return [f"/* asm: {assembly} */"], last_condition

    def _condition_expression(
        self,
        mnemonic: str,
        last_condition: str | None,
        operands: list[str],
    ) -> str:
        condition_name = self._CONDITIONS[mnemonic]
        if mnemonic in {"cbz", "cbnz"} and operands:
            operator = "==" if mnemonic == "cbz" else "!="
            return f"{operands[0]} {operator} 0"
        if mnemonic in {"tbz", "tbnz"} and len(operands) >= 2:
            helper = "bit_is_clear" if mnemonic == "tbz" else "bit_is_set"
            return f"{helper}({operands[0]}, {operands[1]})"
        if last_condition:
            return f"{condition_name}({last_condition})"
        return f"{condition_name}(flags)"

    def _branch_labels(self, function: Function, instructions: list[Instruction]) -> dict[int, str]:
        addresses = {instruction.address for instruction in instructions}
        labels = {}
        for instruction in instructions:
            mnemonic = instruction.mnemonic.lower()
            if mnemonic not in {*self._CONDITIONS, "jmp", "jmpq", "b", "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne"}:
                continue
            operands = self._split_operands(instruction.op_str)
            target = self._target(operands[-1] if operands else "")
            if target in addresses and target != function.address:
                labels[target] = f"loc_{target:x}"
        return labels

    def _call_target(self, operands: list[str]) -> str:
        raw = operands[-1] if operands else ""
        target = self._target(raw)
        if target is not None and self.disassembler is not None:
            function = self.disassembler.functions.get(target)
            if function:
                return self._identifier(function.name, f"sub_{target:x}")
        if target is not None:
            return f"sub_{target:x}"
        rendered = self._operand(raw) if raw else "unknown_target"
        return f"indirect_call({rendered})"

    @staticmethod
    def _split_operands(value: str) -> list[str]:
        value = str(value or "")[:2_048]
        result = []
        current = []
        depth = 0
        for character in value:
            if character in "[({":
                depth += 1
            elif character in "])}" and depth:
                depth -= 1
            if character == "," and depth == 0:
                result.append("".join(current).strip())
                current = []
            else:
                current.append(character)
        if current or value.endswith(","):
            result.append("".join(current).strip())
        return result

    def _operand(self, value: str) -> str:
        text = self._safe_text(value, 512).strip()
        text = re.sub(
            r"\b(?:byte|word|dword|qword|xmmword|ymmword|zmmword)\s+ptr\s+",
            "",
            text,
            flags=re.IGNORECASE,
        )
        text = re.sub(r"\b(?:cs|ds|es|ss|fs|gs):", lambda match: match.group(0).upper(), text)
        if "[" in text and "]" in text:
            text = text.replace("[", "MEM[")
        return text or "unknown"

    @staticmethod
    def _register_name(value: str) -> str:
        return str(value or "").strip().lower()

    @classmethod
    def _same_operand(cls, left: str, right: str) -> bool:
        return cls._register_name(left) == cls._register_name(right)

    @classmethod
    def _target(cls, value: str) -> int | None:
        text = str(value or "").strip().split()[0] if str(value or "").strip() else ""
        if not cls._ADDRESS.fullmatch(text):
            return None
        try:
            return int(text.removeprefix("#"), 0)
        except (TypeError, ValueError, OverflowError):
            return None

    @staticmethod
    def _target_text(target: int | None, operands: list[str]) -> str:
        if target is not None:
            return f"loc_{target:x}"
        return f"unknown_target_{PseudoDecompiler._identifier('_'.join(operands), 'branch')}"

    def _return_register(self) -> str:
        arch = str(self.info.arch).lower()
        if arch == "x86-64":
            return "rax"
        if arch == "x86":
            return "eax"
        if arch in {"aarch64", "arm64"}:
            return "x0"
        if arch == "arm":
            return "r0"
        if "riscv" in arch:
            return "a0"
        return "result"

    @classmethod
    def _identifier(cls, value: str, fallback: str) -> str:
        cleaned = cls._IDENTIFIER.sub("_", cls._safe_text(value, 128)).strip("_")
        if not cleaned:
            cleaned = fallback
        if cleaned[0].isdigit():
            cleaned = f"fn_{cleaned}"
        return cleaned

    @staticmethod
    def _safe_text(value: object, limit: int) -> str:
        text = str(value or "")[:limit]
        return "".join(character for character in text if character in "\t" or ord(character) >= 32)

    @classmethod
    def _safe_comment(cls, value: object) -> str:
        return cls._safe_text(value, 512).replace("*/", "* /")

    @staticmethod
    def _bounded(code: str) -> str:
        limit = config.MAX_DECOMPILED_CHARS
        if len(code) <= limit:
            return code
        marker = "\n    /* output truncated by AIDebug safety limit */\n}"
        return code[:max(0, limit - len(marker))].rstrip() + marker
