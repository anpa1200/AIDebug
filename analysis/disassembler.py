import capstone
from dataclasses import dataclass, field
from typing import Optional

from .static_analyzer import BinaryInfo, SectionInfo

import config


@dataclass
class Instruction:
    address: int
    mnemonic: str
    op_str: str
    raw_bytes: bytes

    def __str__(self) -> str:
        return f"0x{self.address:08x}:  {self.mnemonic:<8} {self.op_str}"


@dataclass
class Function:
    address: int
    name: str
    instructions: list = field(default_factory=list)
    calls_to: list = field(default_factory=list)
    called_from: list = field(default_factory=list)
    strings_referenced: list = field(default_factory=list)
    size: int = 0
    # Populated after discovery by PatternDetector and FlirtMatcher
    patterns: list = field(default_factory=list)    # [MalwarePattern]
    flirt_match: object = field(default=None)        # FlirtMatch or None
    is_library: bool = False

    @property
    def disassembly_text(self) -> str:
        return '\n'.join(str(i) for i in self.instructions)

    @property
    def is_named(self) -> bool:
        return not self.name.startswith('sub_')


# ---------------------------------------------------------------------------
# Architecture detection helpers
# ---------------------------------------------------------------------------

def _capstone_params(arch: str, bits: int):
    """Return (CS_ARCH, CS_MODE) for the given architecture."""
    key = (arch.lower(), bits)
    table = {
        ('x86', 32):     (capstone.CS_ARCH_X86,   capstone.CS_MODE_32),
        ('x86-64', 64):  (capstone.CS_ARCH_X86,   capstone.CS_MODE_64),
        ('arm', 32):     (capstone.CS_ARCH_ARM,    capstone.CS_MODE_ARM),
        ('aarch64', 64): (capstone.CS_ARCH_ARM64,  capstone.CS_MODE_ARM),
    }
    if key in table:
        return table[key]
    if 'riscv' in arch.lower():
        try:
            mode = capstone.CS_MODE_RISCV64 if bits == 64 else capstone.CS_MODE_RISCV32
            return capstone.CS_ARCH_RISCV, mode
        except AttributeError:
            pass
    # Fallback
    return capstone.CS_ARCH_X86, capstone.CS_MODE_32


# ---------------------------------------------------------------------------
# Disassembler
# ---------------------------------------------------------------------------

class Disassembler:

    CALL_MNEMONICS  = {'call', 'callq', 'jal', 'jalr', 'bl', 'blx'}
    RET_MNEMONICS   = {'ret', 'retn', 'retf', 'retq', 'hlt', 'ud2', 'bx lr'}
    JMP_MNEMONICS   = {'jmp', 'jmpq', 'b'}

    def __init__(self, binary_info: BinaryInfo):
        self.info = binary_info
        arch, mode = _capstone_params(binary_info.arch, binary_info.bits)
        self.cs = capstone.Cs(arch, mode)
        self.cs.detail = True
        self.functions: dict[int, Function] = {}
        self._exec_sections = [s for s in binary_info.sections if 'EXECUTE' in s.flags]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def discover_functions(self) -> list:
        """
        Recursive-descent function discovery.
        Returns sorted list of function start addresses.
        """
        queue: set = set()
        visited: set = set()

        queue.add(self.info.entry_point)
        for exp in self.info.exports:
            if self._in_exec(exp['address']):
                queue.add(exp['address'])

        found = []
        limit = config.MAX_FUNCTIONS_TO_DISCOVER

        while queue and len(found) < limit:
            addr = min(queue)   # process in address order for determinism
            queue.discard(addr)
            if addr in visited:
                continue
            if not self._in_exec(addr):
                continue

            visited.add(addr)
            func = self._disassemble(addr)

            if func.instructions:
                found.append(addr)
                for target in func.calls_to:
                    if target not in visited and self._in_exec(target):
                        queue.add(target)

        # Back-fill called_from references
        for addr in found:
            func = self.functions[addr]
            for target in func.calls_to:
                if target in self.functions:
                    callee = self.functions[target]
                    if addr not in callee.called_from:
                        callee.called_from.append(addr)

        # Apply export names
        for exp in self.info.exports:
            a = exp['address']
            if a in self.functions:
                self.functions[a].name = exp['name']

        # Run pattern detection + FLIRT on all discovered functions
        self._run_enrichment(found)

        return sorted(found)

    def _run_enrichment(self, addresses: list):
        """Run PatternDetector and FlirtMatcher on all functions."""
        try:
            from .pattern_detector import PatternDetector
            from .flirt import FlirtMatcher
            detector = PatternDetector()
            flirt    = FlirtMatcher(self.info)
        except Exception:
            return

        for addr in addresses:
            func = self.functions.get(addr)
            if not func:
                continue
            # Pattern detection
            try:
                func.patterns = detector.detect(func)
            except Exception:
                func.patterns = []
            # FLIRT matching
            try:
                match = flirt.identify(func)
                if match:
                    func.flirt_match = match
                    func.is_library  = match.skip_ai
                    if match.function_name not in ('trivial_stub',) and not func.is_named:
                        func.name = match.function_name
            except Exception:
                pass

    def get_function(self, address: int) -> Optional[Function]:
        if address not in self.functions:
            self._disassemble(address)
        return self.functions.get(address)

    # ------------------------------------------------------------------
    # Internal disassembly
    # ------------------------------------------------------------------

    def _disassemble(self, address: int) -> Function:
        if address in self.functions:
            return self.functions[address]

        code_bytes = self._bytes_at(address)
        if not code_bytes:
            func = Function(address=address, name=f'sub_{address:08x}')
            self.functions[address] = func
            return func

        func = Function(address=address, name=f'sub_{address:08x}')
        calls = set()
        limit = config.MAX_INSTRUCTIONS_PER_FUNCTION

        for insn in self.cs.disasm(code_bytes, address):
            if len(func.instructions) >= limit:
                break

            func.instructions.append(Instruction(
                address=insn.address,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                raw_bytes=bytes(insn.bytes),
            ))

            mnem = insn.mnemonic.lower()

            # Track call targets
            if mnem in self.CALL_MNEMONICS:
                target = self._parse_immediate(insn.op_str)
                if target and self._in_exec(target):
                    calls.add(target)

            # Stop at function-terminating instructions
            if mnem in self.RET_MNEMONICS:
                break

            # Stop at unconditional jumps that look like tail calls
            if mnem in self.JMP_MNEMONICS:
                target = self._parse_immediate(insn.op_str)
                if target and abs(target - address) > 0x2000:
                    break   # tail call out of function
                elif len(func.instructions) > 3:
                    break

        func.calls_to = list(calls)
        if func.instructions:
            last = func.instructions[-1]
            func.size = last.address - address + len(last.raw_bytes)

        func.strings_referenced = self._strings_in_function(func)
        self.functions[address] = func
        return func

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _bytes_at(self, address: int) -> Optional[bytes]:
        for sec in self._exec_sections:
            start = sec.virtual_address
            end = start + len(sec.data)
            if start <= address < end:
                return sec.data[address - start:]
        return None

    def _in_exec(self, address: int) -> bool:
        for sec in self._exec_sections:
            if sec.virtual_address <= address < sec.virtual_address + sec.virtual_size:
                return True
        return False

    def _parse_immediate(self, op_str: str) -> Optional[int]:
        """Extract a hex/decimal immediate from an operand string."""
        op_str = op_str.strip().split(',')[0].strip()
        op_str = op_str.replace('[', '').replace(']', '').strip()
        if '+' in op_str or '-' in op_str:
            return None
        try:
            return int(op_str, 0)
        except ValueError:
            return None

    def _strings_in_function(self, func: Function) -> list:
        """Find strings referenced by immediate addresses in this function."""
        found = []
        sdata = self.info.all_string_data
        for insn in func.instructions:
            for part in insn.op_str.split(','):
                part = part.strip().replace('[', '').replace(']', '')
                try:
                    addr = int(part, 0)
                    if addr in sdata and sdata[addr] not in found:
                        found.append(sdata[addr])
                        if len(found) >= config.MAX_STRINGS_PER_FUNCTION:
                            return found
                except ValueError:
                    pass
        return found
