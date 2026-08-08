import heapq
import logging
from dataclasses import dataclass, field

import capstone

import config

from .static_analyzer import BinaryInfo

logger = logging.getLogger(__name__)


@dataclass
class Instruction:
    address: int
    mnemonic: str
    op_str: str
    raw_bytes: bytes
    referenced_addresses: list = field(default_factory=list)

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
    decompiled_code: str = ''
    decompile_language: str = ''
    decompile_backend: str = ''
    decompile_warning: str = ''

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
    raise ValueError(
        f"Unsupported disassembly architecture: {arch!r} ({bits}-bit). "
        "Refusing to decode it as a different instruction set."
    )


# ---------------------------------------------------------------------------
# Disassembler
# ---------------------------------------------------------------------------

class Disassembler:

    CALL_MNEMONICS  = {'call', 'callq', 'jal', 'jalr', 'bl', 'blx'}
    RET_MNEMONICS   = {'ret', 'retn', 'retf', 'retq', 'hlt', 'ud2'}
    JMP_MNEMONICS   = {'jmp', 'jmpq', 'b'}
    CONDITIONAL_BRANCH_MNEMONICS = {
        'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
        'ja', 'jae', 'jb', 'jbe', 'js', 'jns', 'jo', 'jno',
        'jp', 'jnp', 'jcxz', 'jecxz', 'jrcxz', 'loop', 'loope', 'loopne',
        'beq', 'bne', 'bgt', 'bge', 'blt', 'ble', 'bhi', 'bhs', 'blo', 'bls',
        'cbz', 'cbnz', 'tbz', 'tbnz',
    }

    def __init__(self, binary_info: BinaryInfo):
        self.info = binary_info
        arch, mode = _capstone_params(binary_info.arch, binary_info.bits)
        self.cs = capstone.Cs(arch, mode)
        self.cs.detail = True
        self.functions: dict[int, Function] = {}
        self._exec_sections = [s for s in binary_info.sections if 'EXECUTE' in s.flags]
        self._known_function_starts = {
            binary_info.entry_point,
            *(exp['address'] for exp in binary_info.exports),
            *(sym['address'] for sym in getattr(binary_info, 'function_symbols', [])),
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def discover_functions(self, max_functions: int | None = None) -> list:
        """
        Recursive-descent function discovery.
        Returns sorted list of function start addresses.
        """
        if max_functions is None:
            limit = config.MAX_FUNCTIONS_TO_DISCOVER
        elif (
            isinstance(max_functions, bool)
            or not isinstance(max_functions, int)
            or not 1 <= max_functions <= config.MAX_FUNCTIONS_TO_DISCOVER
        ):
            raise ValueError(
                f'max_functions must be between 1 and {config.MAX_FUNCTIONS_TO_DISCOVER}'
            )
        else:
            limit = max_functions

        queue: set = set()
        visited: set = set()

        queue.add(self.info.entry_point)
        # Seed only as many known ELF symbols/PE exports as this discovery
        # request can return. This prevents a low CLI limit from first
        # sorting/scanning an unbounded symbol table on large runtimes.
        named_seeds = {
            (item['address'], item['name'])
            for item in [
                *getattr(self.info, 'function_symbols', []),
                *self.info.exports,
            ]
        }
        symbol_seeds = heapq.nsmallest(
            limit,
            (
                {'address': address, 'name': name}
                for address, name in named_seeds
                if self._in_exec(address)
            ),
            key=lambda item: (item['address'], item['name']),
        )
        for symbol in symbol_seeds:
            queue.add(symbol['address'])

        found = []

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

        # Apply ELF symbol/PE export names. Exports are processed last so an
        # externally visible name wins when aliases share an address.
        for symbol in [
            *getattr(self.info, 'function_symbols', []),
            *self.info.exports,
        ]:
            a = symbol['address']
            if a in self.functions:
                self.functions[a].name = symbol['name']

        # Run pattern detection + FLIRT on all discovered functions
        self._run_enrichment(found)

        return sorted(found)

    def _run_enrichment(self, addresses: list):
        """Run PatternDetector and FlirtMatcher on all functions."""
        from .pattern_detector import PatternDetector

        detector = PatternDetector(self.info)
        try:
            from .flirt import FlirtMatcher

            flirt = FlirtMatcher(self.info)
        except Exception as exc:
            logger.warning('Library-hint enrichment is unavailable: %s', exc)
            flirt = None

        for addr in addresses:
            func = self.functions.get(addr)
            if not func:
                continue
            # Deterministic pattern detection is a core output. Fail the load
            # rather than silently presenting an empty result after an error.
            func.patterns = detector.detect(func)
            # FLIRT matching
            if flirt is None:
                continue
            try:
                match = flirt.identify(func)
                if match:
                    func.flirt_match = match
                    func.is_library  = match.skip_ai
                    # Only verified import-thunk matches are authoritative
                    # enough to rename code automatically. Heuristic CRC and
                    # shape matches remain visible as hints on ``flirt_match``.
                    if match.confidence == 'exact' and not func.is_named:
                        func.name = match.function_name
            except Exception as exc:
                logger.debug('FLIRT enrichment failed at %#x: %s', addr, exc)

    def get_function(self, address: int) -> Function | None:
        if isinstance(address, bool) or not isinstance(address, int) or address < 0:
            raise ValueError("Function address must be a non-negative integer")
        if address not in self.functions:
            self._disassemble(address)
        return self.functions.get(address)

    # ------------------------------------------------------------------
    # Internal disassembly
    # ------------------------------------------------------------------

    def _disassemble(self, address: int) -> Function:
        if address in self.functions:
            return self.functions[address]

        func = Function(address=address, name=f'sub_{address:08x}')
        calls = set()
        limit = config.MAX_INSTRUCTIONS_PER_FUNCTION
        pending_blocks = {address}
        decoded = {}

        while pending_blocks and len(decoded) < limit:
            block_address = min(pending_blocks)
            pending_blocks.remove(block_address)
            remaining = limit - len(decoded)
            code_bytes = self._bytes_at(block_address, max_bytes=max(16, remaining * 16))
            if not code_bytes:
                continue

            for insn in self.cs.disasm(code_bytes, block_address):
                if len(decoded) >= limit or insn.address in decoded:
                    break
                if insn.address != address and insn.address in self._known_function_starts:
                    break

                decoded[insn.address] = Instruction(
                    address=insn.address,
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    raw_bytes=bytes(insn.bytes),
                    referenced_addresses=self._referenced_addresses(insn),
                )
                mnem = insn.mnemonic.lower()

                if mnem in self.CALL_MNEMONICS:
                    target = self._parse_immediate(insn.op_str)
                    if target is not None and self._in_exec(target):
                        calls.add(target)

                if self._is_return(insn):
                    break

                target = self._branch_target(mnem, insn.op_str)
                if mnem in self.CONDITIONAL_BRANCH_MNEMONICS:
                    if target is not None and self._in_exec(target) and target not in decoded:
                        pending_blocks.add(target)
                    continue

                if mnem in self.JMP_MNEMONICS:
                    if target is not None and self._in_exec(target):
                        if target in self._known_function_starts and target != address:
                            calls.add(target)  # direct tail call
                        elif target not in decoded:
                            pending_blocks.add(target)
                    break

        func.instructions = [decoded[key] for key in sorted(decoded)]

        func.calls_to = sorted(calls)
        if func.instructions:
            last = max(func.instructions, key=lambda item: item.address)
            func.size = last.address - address + len(last.raw_bytes)

        func.strings_referenced = self._strings_in_function(func)
        self.functions[address] = func
        return func

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _bytes_at(self, address: int, max_bytes: int | None = None) -> bytes | None:
        for sec in self._exec_sections:
            start = sec.virtual_address
            end = start + len(sec.data)
            if start <= address < end:
                offset = address - start
                stop = None if max_bytes is None else offset + max_bytes
                return sec.data[offset:stop]
        return None

    def _in_exec(self, address: int) -> bool:
        for sec in self._exec_sections:
            if sec.virtual_address <= address < sec.virtual_address + sec.virtual_size:
                return True
        return False

    def _parse_immediate(self, op_str: str) -> int | None:
        """Extract a hex/decimal immediate from an operand string."""
        op_str = op_str.strip().split(',')[0].strip()
        op_str = op_str.replace('[', '').replace(']', '').strip()
        op_str = op_str.lstrip('#$')
        if '+' in op_str or '-' in op_str:
            return None
        try:
            return int(op_str, 0)
        except ValueError:
            return None

    def _branch_target(self, mnemonic: str, op_str: str) -> int | None:
        if mnemonic in {'cbz', 'cbnz', 'tbz', 'tbnz'}:
            operand = op_str.rsplit(',', 1)[-1]
            return self._parse_immediate(operand)
        return self._parse_immediate(op_str)

    def _is_return(self, insn) -> bool:
        """Recognize return instructions without conflating mnemonic/operands."""
        mnem = insn.mnemonic.lower()
        operands = insn.op_str.lower().replace(' ', '')
        if mnem in self.RET_MNEMONICS:
            return True
        if mnem == 'bx' and operands == 'lr':
            return True
        if mnem == 'br' and operands in {'x30', 'lr'}:
            return True
        if mnem == 'pop' and 'pc' in operands.strip('{}').split(','):
            return True
        return False

    def _strings_in_function(self, func: Function) -> list:
        """Find strings referenced by immediate addresses in this function."""
        found = []
        sdata = self.info.all_string_data
        for insn in func.instructions:
            for addr in insn.referenced_addresses:
                if addr in sdata and sdata[addr] not in found:
                    found.append(sdata[addr])
                    if len(found) >= config.MAX_STRINGS_PER_FUNCTION:
                        return found
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

    def _referenced_addresses(self, insn) -> list[int]:
        """Resolve bounded direct/RIP-relative memory references from Capstone detail."""
        found = set()
        if self.info.arch.lower() not in {'x86', 'x86-64'}:
            return []
        try:
            from capstone.x86_const import X86_OP_MEM, X86_REG_EIP, X86_REG_INVALID, X86_REG_RIP
            for operand in insn.operands:
                if operand.type != X86_OP_MEM:
                    continue
                mem = operand.mem
                if mem.base in {X86_REG_RIP, X86_REG_EIP}:
                    found.add(insn.address + insn.size + mem.disp)
                elif mem.base == X86_REG_INVALID and mem.index == X86_REG_INVALID and mem.disp >= 0:
                    found.add(mem.disp)
        except (AttributeError, ImportError):
            return []
        return sorted(found)
