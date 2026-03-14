from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MemoryDiff:
    """Before/after snapshot of a single memory region."""
    address: int
    data_before: bytes
    data_after:  bytes

    @property
    def changed_bytes(self) -> list:
        """Returns list of (offset, old_byte, new_byte) for every changed byte."""
        return [
            (i, b, a)
            for i, (b, a) in enumerate(zip(self.data_before, self.data_after))
            if b != a
        ]

    @property
    def diff_summary(self) -> str:
        changes = self.changed_bytes
        if not changes:
            return 'no changes'
        parts = [f'+{hex(self.address + off)}: {hex(old)}→{hex(new)}'
                 for off, old, new in changes[:8]]
        suffix = f' (+{len(changes) - 8} more)' if len(changes) > 8 else ''
        return ', '.join(parts) + suffix

    @property
    def hex_before(self) -> str:
        return self.data_before[:32].hex()

    @property
    def hex_after(self) -> str:
        return self.data_after[:32].hex()


@dataclass
class FunctionSnapshot:
    """
    Captures CPU/memory state at function entry and exit.
    Populated by the Frida engine during dynamic analysis.
    """
    function_address: int

    # ---- Entry state ----
    entry_registers:    dict  = field(default_factory=dict)
    entry_stack:        bytes = b''
    entry_heap_regions: list  = field(default_factory=list)  # [MemoryDiff before-only]

    # ---- Exit state ----
    exit_registers: dict  = field(default_factory=dict)
    exit_stack:     bytes = b''

    # ---- Memory diffs (populated after function returns) ----
    memory_diffs: list = field(default_factory=list)   # [MemoryDiff]

    # ---- Derived ----
    return_value: int = 0

    # ---- Network events that happened during this function ----
    network_events: list = field(default_factory=list)   # [{event, data, ...}]

    # ------------------------------------------------------------------

    @property
    def entry_stack_hex(self) -> str:
        return self.entry_stack[:32].hex() if self.entry_stack else ''

    @property
    def memory_diff_summary(self) -> str:
        if self.memory_diffs:
            summaries = [d.diff_summary for d in self.memory_diffs if d.changed_bytes]
            if summaries:
                return ' | '.join(summaries[:3])
        # Fall back to register diff
        if not self.entry_registers or not self.exit_registers:
            return 'no diff available'
        changed = []
        for reg, val_before in self.entry_registers.items():
            val_after = self.exit_registers.get(reg)
            if val_after is not None and val_before != val_after:
                try:
                    b = int(val_before, 0) if isinstance(val_before, str) else val_before
                    a = int(val_after,  0) if isinstance(val_after,  str) else val_after
                    changed.append(f'{reg}: {hex(b)} → {hex(a)}')
                except (ValueError, TypeError):
                    changed.append(f'{reg}: {val_before} → {val_after}')
        return ', '.join(changed) if changed else 'no register changes'

    @property
    def full_diff_text(self) -> str:
        """Multi-line diff report for TUI display."""
        lines = []

        # Register changes
        reg_changes = []
        for reg, before in self.entry_registers.items():
            after = self.exit_registers.get(reg)
            if after and before != after:
                try:
                    b = int(before, 0) if isinstance(before, str) else before
                    a = int(after,  0) if isinstance(after,  str) else after
                    reg_changes.append(f'  {reg.upper():<5} {hex(b):>12}  →  {hex(a):<12}  Δ={hex(a-b)}')
                except (ValueError, TypeError):
                    reg_changes.append(f'  {reg.upper():<5} {before}  →  {after}')
        if reg_changes:
            lines.append('REGISTER CHANGES:')
            lines.extend(reg_changes)

        # Memory diffs
        for diff in self.memory_diffs:
            changes = diff.changed_bytes
            if changes:
                lines.append(f'\nMEMORY DIFF @ {hex(diff.address)}:')
                lines.append(f'  Before: {diff.hex_before}')
                lines.append(f'  After:  {diff.hex_after}')
                lines.append(f'  {len(changes)} byte(s) changed')

        # Return value
        if self.return_value:
            lines.append(f'\nRETURN VALUE: {hex(self.return_value)} ({self.return_value})')

        return '\n'.join(lines) if lines else '(no changes detected)'
