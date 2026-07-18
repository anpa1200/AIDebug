"""
PatternDetector — identifies common malware behavioral patterns in disassembled functions.

Detected patterns:
  - XOR transformation loop      (possible string/config decoding)
  - Stack-write sequence         (possible runtime string construction)
  - Rotate/XOR hash loop         (possible API hash resolution)
  - RDTSC timing sequence        (profiling or possible anti-analysis)
  - Direct syscall instruction   (context-dependent candidate)
  - NOP sequence                 (compiler padding or shellcode alignment)
  - Null-preserving XOR          (possible encoder sequence)
  - Base64-like alphabet ref     (benign or malicious encoding)
"""
from __future__ import annotations

from dataclasses import dataclass

from .disassembler import Function, Instruction


@dataclass
class MalwarePattern:
    name: str
    description: str
    severity: str        # 'INFO' | 'MEDIUM' | 'HIGH'
    address: int         # address where pattern starts
    evidence: str = ''   # human-readable evidence snippet

    @property
    def severity_badge(self) -> str:
        return {'HIGH': '[HIGH]', 'MEDIUM': '[MED ]', 'INFO': '[INFO]'}.get(self.severity, '[??? ]')

    @property
    def severity_color(self) -> str:
        return {'HIGH': 'red', 'MEDIUM': 'yellow', 'INFO': 'cyan'}.get(self.severity, 'white')


class PatternDetector:

    def __init__(self, binary_info=None):
        self.binary_info = binary_info

    def detect(self, function: Function) -> list[MalwarePattern]:
        patterns = []
        insns = function.instructions
        if not insns:
            return patterns

        patterns += self._xor_decryption_loop(insns)
        patterns += self._stack_strings(insns)
        patterns += self._api_hash_resolution(insns)
        patterns += self._rdtsc_timing(insns)
        patterns += self._direct_syscall(insns)
        patterns += self._nop_sled(insns)
        patterns += self._null_safe_xor(insns)
        patterns += self._base64_table(function)

        # Deduplicate by (name, address)
        seen = set()
        unique = []
        for p in patterns:
            key = (p.name, p.address)
            if key not in seen:
                seen.add(key)
                unique.append(p)
        return unique

    # ------------------------------------------------------------------
    # Individual detectors
    # ------------------------------------------------------------------

    def _xor_decryption_loop(self, insns: list) -> list:
        """Detect XOR operations inside a loop (backward jump + xor on memory)."""
        results = []
        addrs = {i.address: i for i in insns}
        addr_list = [i.address for i in insns]

        for idx, insn in enumerate(insns):
            mnem = insn.mnemonic.lower()
            # Look for backward jumps (loop indicators)
            if mnem in ('jmp', 'je', 'jne', 'jz', 'jnz', 'jl', 'jle', 'jg', 'jge',
                        'jb', 'jbe', 'ja', 'jae', 'loop', 'loope', 'loopne'):
                try:
                    target = int(insn.op_str.strip(), 0)
                except (ValueError, TypeError):
                    continue

                if target >= insn.address:
                    continue  # not a backward jump

                # Look for XOR in the loop body
                loop_start = addr_list.index(target) if target in addrs else -1
                if loop_start < 0:
                    continue

                loop_insns = insns[loop_start:idx + 1]
                xor_insns = [i for i in loop_insns if i.mnemonic.lower() == 'xor']

                for xi in xor_insns:
                    # Skip xor reg,reg (zeroing pattern, not decryption)
                    parts = [p.strip() for p in xi.op_str.split(',')]
                    if len(parts) == 2 and parts[0] == parts[1]:
                        continue
                    # Skip xor with 0
                    if len(parts) == 2 and parts[1] in ('0', '0x0'):
                        continue

                    results.append(MalwarePattern(
                        name='xor_decryption_loop',
                        description=(
                            'XOR loop candidate — may transform a string, configuration, or buffer; '
                            'validate the operands and data flow'
                        ),
                        severity='HIGH',
                        address=target,
                        evidence=f'xor {xi.op_str}  @ loop 0x{target:08x}–0x{insn.address:08x}',
                    ))
                    break  # one report per loop
        return results

    def _stack_strings(self, insns: list) -> list:
        """Detect stack string construction: consecutive mov byte/word to [esp+N]."""
        consecutive = 0
        start_addr = 0

        for insn in insns:
            mnem = insn.mnemonic.lower()
            ops  = insn.op_str.lower()

            is_stack_mov = (
                mnem in ('mov', 'movb', 'movw') and
                ('byte ptr' in ops or 'word ptr' in ops) and
                ('[esp' in ops or '[ebp' in ops or '[rsp' in ops or '[rbp' in ops)
            )
            if is_stack_mov:
                if consecutive == 0:
                    start_addr = insn.address
                consecutive += 1
            else:
                if consecutive >= 4:
                    return [MalwarePattern(
                        name='stack_string',
                        description=(
                            'Stack-write sequence — may construct a string at runtime; this can '
                            'obscure static strings but also occurs in benign compiled code'
                        ),
                        severity='MEDIUM',
                        address=start_addr,
                        evidence=f'{consecutive} consecutive byte-MOVs to stack starting 0x{start_addr:08x}',
                    )]
                consecutive = 0

        if consecutive >= 4:
            return [MalwarePattern(
                name='stack_string',
                description=(
                    'Stack-write sequence — may construct a string at runtime; this can '
                    'obscure static strings but also occurs in benign compiled code'
                ),
                severity='MEDIUM',
                address=start_addr,
                evidence=f'{consecutive} consecutive byte-MOVs to stack',
            )]
        return []

    def _api_hash_resolution(self, insns: list) -> list:
        """
        Detect API hash resolution pattern:
        ROR/ROL + XOR/ADD loop used to hash module/function names.
        Common in shellcode and loaders.
        """
        has_ror_rol = any(i.mnemonic.lower() in ('ror', 'rol') for i in insns)
        has_xor     = any(i.mnemonic.lower() == 'xor' for i in insns)
        has_loop    = any(i.mnemonic.lower() in ('loop', 'loope', 'loopne') or
                         (i.mnemonic.lower().startswith('j') and
                          self._is_backward_jump(i, insns))
                         for i in insns)

        if has_ror_rol and has_xor and has_loop:
            ror_insn = next(i for i in insns if i.mnemonic.lower() in ('ror', 'rol'))
            return [MalwarePattern(
                name='api_hash_resolution',
                description='API hash-resolution candidate — rotate/XOR loop may resolve Windows APIs dynamically; validate its inputs and call sites',
                severity='HIGH',
                address=ror_insn.address,
                evidence=f'{ror_insn.mnemonic} {ror_insn.op_str} inside loop with xor',
            )]
        return []

    def _rdtsc_timing(self, insns: list) -> list:
        """Detect RDTSC-based timing checks (sandbox evasion)."""
        rdtsc_insns = [i for i in insns if i.mnemonic.lower() == 'rdtsc']
        if len(rdtsc_insns) >= 2:
            return [MalwarePattern(
                name='rdtsc_timing_check',
                description=(
                    'Repeated RDTSC timing sequence — may support profiling or an anti-analysis '
                    'timing check; validate the measured delta and branch behavior'
                ),
                severity='HIGH',
                address=rdtsc_insns[0].address,
                evidence=f'Two RDTSC at 0x{rdtsc_insns[0].address:08x} and 0x{rdtsc_insns[1].address:08x}',
            )]
        if rdtsc_insns:
            return [MalwarePattern(
                name='rdtsc_timing_check',
                description=(
                    'RDTSC timestamp read — common in profiling and low-level code, and sometimes '
                    'used in timing-based anti-analysis checks'
                ),
                severity='MEDIUM',
                address=rdtsc_insns[0].address,
                evidence=f'rdtsc @ 0x{rdtsc_insns[0].address:08x}',
            )]
        return []

    def _direct_syscall(self, insns: list) -> list:
        """Detect direct syscalls without treating normal Linux syscalls as malicious."""
        os_target = getattr(self.binary_info, 'os_target', 'Unknown')
        if os_target == 'Windows':
            severity = 'HIGH'
            description = (
                'Direct Windows syscall candidate — may bypass ntdll user-mode hooks; '
                'validate the surrounding stub and syscall number'
            )
        elif os_target == 'Linux':
            severity = 'INFO'
            description = (
                'Direct Linux syscall instruction — a normal userspace/kernel boundary; '
                'security significance depends on the syscall number and surrounding behavior'
            )
        else:
            severity = 'MEDIUM'
            description = (
                'Direct syscall instruction observed — operating-system context is unknown; '
                'validate before treating it as evasion'
            )
        for insn in insns:
            mnem = insn.mnemonic.lower()
            if mnem in ('syscall', 'sysenter'):
                return [MalwarePattern(
                    name='direct_syscall',
                    description=description,
                    severity=severity,
                    address=insn.address,
                    evidence=f'{mnem} @ 0x{insn.address:08x}',
                )]
            if mnem == 'int' and insn.op_str.strip() in ('0x2e', '2eh', '0x2E'):
                return [MalwarePattern(
                    name='direct_syscall',
                    description=description,
                    severity=severity,
                    address=insn.address,
                    evidence=f'int 0x2e @ 0x{insn.address:08x}',
                )]
        return []

    def _nop_sled(self, insns: list) -> list:
        """Detect NOP sleds (5+ consecutive NOPs)."""
        run = 0
        start = 0
        for insn in insns:
            if insn.mnemonic.lower() == 'nop':
                if run == 0:
                    start = insn.address
                run += 1
                if run >= 5:
                    return [MalwarePattern(
                        name='nop_sled',
                        description=(
                            'NOP sequence — may be shellcode alignment, compiler padding, '
                            'or benign hot-patch space'
                        ),
                        severity='INFO',
                        address=start,
                        evidence=f'{run}+ NOPs starting at 0x{start:08x}',
                    )]
            else:
                run = 0
        return []

    def _null_safe_xor(self, insns: list) -> list:
        """
        Detect null-byte-preserving XOR pattern:
        `test al,al / jz skip / xor al,key` used in encoded shellcode.
        """
        for i in range(len(insns) - 2):
            a, b, c = insns[i], insns[i+1], insns[i+2]
            if (a.mnemonic.lower() == 'test' and
                    b.mnemonic.lower() in ('jz', 'je') and
                    c.mnemonic.lower() == 'xor'):
                return [MalwarePattern(
                    name='null_preserving_xor',
                    description='Null-preserving XOR candidate — test/branch/XOR sequence may be an encoder; validate the enclosing loop and buffer use',
                    severity='HIGH',
                    address=a.address,
                    evidence=f'test/jz/xor sequence @ 0x{a.address:08x}',
                )]
        return []

    def _base64_table(self, function: Function) -> list:
        """Detect reference to a Base64 alphabet string."""
        B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        for s in function.strings_referenced:
            clean = s.replace('[W] ', '')
            if clean == B64 or (len(clean) >= 32 and all(c in B64 + '=' for c in clean)):
                return [MalwarePattern(
                    name='base64_alphabet_reference',
                    description='Base64-like alphabet referenced — common in benign and malicious encoders; validate surrounding data flow',
                    severity='INFO',
                    address=function.address,
                    evidence=f'String: "{clean[:32]}…"',
                )]
        return []

    # ------------------------------------------------------------------

    def _is_backward_jump(self, insn: Instruction, all_insns: list) -> bool:
        if not insn.mnemonic.lower().startswith('j'):
            return False
        try:
            target = int(insn.op_str.strip(), 0)
            return target < insn.address
        except (ValueError, TypeError):
            return False
