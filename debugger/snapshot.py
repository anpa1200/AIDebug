from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FunctionSnapshot:
    """
    Captures CPU/memory state at function entry and exit.
    Populated by the Frida engine during dynamic analysis.
    """
    function_address: int

    # ---- Entry state ----
    entry_registers: dict = field(default_factory=dict)
    entry_stack: bytes = b''
    entry_heap_regions: list = field(default_factory=list)   # [{addr, data}, ...]

    # ---- Exit state ----
    exit_registers: dict = field(default_factory=dict)
    exit_stack: bytes = b''

    # ---- Derived ----
    return_value: int = 0

    @property
    def entry_stack_hex(self) -> str:
        return self.entry_stack[:32].hex() if self.entry_stack else ''

    @property
    def memory_diff_summary(self) -> str:
        if not self.entry_registers or not self.exit_registers:
            return 'no diff available'
        changed = []
        for reg, val_before in self.entry_registers.items():
            val_after = self.exit_registers.get(reg)
            if val_after is not None and val_before != val_after:
                try:
                    before_i = int(val_before, 0) if isinstance(val_before, str) else val_before
                    after_i  = int(val_after,  0) if isinstance(val_after,  str) else val_after
                    changed.append(f'{reg}: {hex(before_i)} → {hex(after_i)}')
                except (ValueError, TypeError):
                    changed.append(f'{reg}: {val_before} → {val_after}')
        return ', '.join(changed) if changed else 'no register changes'
