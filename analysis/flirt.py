"""
FLIRT — Fast Library Identification and Recognition.

Identifies known compiler-generated and library functions so the AI analyzer
can skip them (saving API cost and reducing noise in reports).

Approach:
  1. Import-wrapper detection   — thin function that just JMPs to an IAT entry
  2. CRC16 prologue matching    — first 32 bytes (address bytes zeroed) vs DB
  3. Call-pattern inference     — function that only calls one known import
  4. Size-based filtering       — very small functions (≤3 insns) with no calls
"""
from __future__ import annotations
import json
import os
import struct
from dataclasses import dataclass
from typing import Optional

from .disassembler import Function
from .static_analyzer import BinaryInfo


@dataclass
class FlirtMatch:
    function_name: str
    library: str
    confidence: str   # 'exact' | 'inferred' | 'wrapper'
    skip_ai: bool     # True → skip sending to Claude


# ---------------------------------------------------------------------------
# CRC-16 (CCITT)
# ---------------------------------------------------------------------------

def _crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = (crc << 1) ^ 0x1021 if crc & 0x8000 else crc << 1
            crc &= 0xFFFF
    return crc


def _function_fingerprint(function: Function) -> Optional[int]:
    """CRC16 of first 32 instruction bytes, with immediate dword values zeroed."""
    raw = b''
    for insn in function.instructions[:10]:
        b = bytearray(insn.raw_bytes)
        # Zero out any 4-byte absolute address immediates (bytes 1–4 or 2–5)
        if len(b) >= 5 and b[0] in (0xE8, 0xE9, 0x68):   # CALL/JMP/PUSH imm32
            b[1:5] = b'\x00\x00\x00\x00'
        elif len(b) == 6 and b[0] == 0xFF:                 # JMP/CALL [mem32]
            b[2:6] = b'\x00\x00\x00\x00'
        elif len(b) >= 6 and b[0] == 0xB8:                 # MOV eax, imm32
            b[1:5] = b'\x00\x00\x00\x00'
        raw += bytes(b)
        if len(raw) >= 32:
            break
    if len(raw) < 8:
        return None
    return _crc16(raw[:32])


# ---------------------------------------------------------------------------
# Matcher
# ---------------------------------------------------------------------------

class FlirtMatcher:

    def __init__(self, binary_info: BinaryInfo):
        self.binary_info = binary_info
        self._sig_db: dict = self._load_db()
        self._import_thunks: dict = {}    # address -> import name
        self._build_thunk_map()

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def identify(self, function: Function) -> Optional[FlirtMatch]:
        # 1. Import wrapper (JMP [IAT])
        m = self._check_import_wrapper(function)
        if m:
            return m

        # 2. CRC16 signature match
        m = self._check_crc(function)
        if m:
            return m

        # 3. Single-import call inference
        m = self._check_single_import_call(function)
        if m:
            return m

        # 4. Trivial compiler-generated stub
        m = self._check_trivial(function)
        if m:
            return m

        return None

    def is_library_function(self, function: Function) -> bool:
        return self.identify(function) is not None

    # ------------------------------------------------------------------
    # Strategies
    # ------------------------------------------------------------------

    def _check_import_wrapper(self, function: Function) -> Optional[FlirtMatch]:
        """Detects  JMP DWORD PTR [<iat entry>]  — the standard PE import thunk."""
        if len(function.instructions) > 3:
            return None
        for insn in function.instructions:
            if insn.mnemonic.lower() in ('jmp', 'jmpq'):
                # Check if target is in IAT
                target = self._deref_address(insn.op_str)
                if target and target in self._import_thunks:
                    name = self._import_thunks[target]
                    return FlirtMatch(
                        function_name=name,
                        library='import_thunk',
                        confidence='exact',
                        skip_ai=True,
                    )
        return None

    def _check_crc(self, function: Function) -> Optional[FlirtMatch]:
        if not function.instructions:
            return None
        fp = _function_fingerprint(function)
        if fp is None:
            return None
        key = f'{fp:04X}'
        entry = self._sig_db.get(key)
        if entry:
            return FlirtMatch(
                function_name=entry['name'],
                library=entry.get('lib', 'msvcrt'),
                confidence='exact',
                skip_ai=entry.get('skip_ai', True),
            )
        return None

    def _check_single_import_call(self, function: Function) -> Optional[FlirtMatch]:
        """
        If a small function's only call is to one known import,
        infer it's a wrapper for that import.
        """
        if len(function.instructions) > 8:
            return None
        calls = []
        for insn in function.instructions:
            if insn.mnemonic.lower() in ('call', 'callq'):
                target = self._parse_imm(insn.op_str)
                if target and target in self._import_thunks:
                    calls.append(self._import_thunks[target])
        if len(calls) == 1:
            name = f'wrapper_{calls[0]}'
            return FlirtMatch(
                function_name=name,
                library='inferred_wrapper',
                confidence='inferred',
                skip_ai=False,   # small wrapper is still worth showing
            )
        return None

    def _check_trivial(self, function: Function) -> Optional[FlirtMatch]:
        """Functions of ≤2 instructions with no real behavior."""
        insns = [i for i in function.instructions
                 if i.mnemonic.lower() not in ('nop', 'int3')]
        if len(insns) <= 2:
            mnems = {i.mnemonic.lower() for i in insns}
            if mnems <= {'push', 'pop', 'ret', 'retn', 'xor', 'mov'}:
                return FlirtMatch(
                    function_name='trivial_stub',
                    library='compiler',
                    confidence='inferred',
                    skip_ai=True,
                )
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_thunk_map(self):
        """Map IAT addresses → import function names for PE files."""
        if self.binary_info.file_format != 'PE':
            return
        import pefile
        try:
            pe = pefile.PE(self.binary_info.path, fast_load=False)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.address and imp.name:
                            name = imp.name.decode('utf-8', errors='replace')
                            self._import_thunks[imp.address] = name
            pe.close()
        except Exception:
            pass

    def _deref_address(self, op_str: str) -> Optional[int]:
        """Extract address from 'dword ptr [0x401234]' style operands."""
        import re
        m = re.search(r'\[(?:0x)?([0-9a-fA-F]+)\]', op_str)
        if m:
            try:
                return int(m.group(1), 16)
            except ValueError:
                pass
        return None

    def _parse_imm(self, op_str: str) -> Optional[int]:
        try:
            return int(op_str.strip(), 0)
        except (ValueError, TypeError):
            return None

    def _load_db(self) -> dict:
        db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'flirt_sigs.json')
        try:
            with open(db_path, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
