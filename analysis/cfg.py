"""
CFG — Control Flow Graph builder and renderer.

Builds a CFG from a Function object (basic block decomposition),
then renders it either as:
  - Plain text  (for TUI display)
  - Inline SVG  (for HTML reports, no external dependency)
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from .disassembler import Function, Instruction

BRANCH_MNEMONICS = {
    'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
    'ja', 'jae', 'jb', 'jbe', 'js', 'jns', 'jo', 'jno',
    'jp', 'jnp', 'jcxz', 'jecxz', 'jrcxz',
}
UNCOND_JMP = {'jmp', 'jmpq', 'b'}
RET_MNEMONICS = {'ret', 'retn', 'retf', 'retq', 'hlt', 'ud2'}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class BasicBlock:
    start: int
    instructions: list = field(default_factory=list)
    successors: list = field(default_factory=list)    # [int address]
    predecessors: list = field(default_factory=list)  # [int address]
    block_type: str = 'normal'   # 'normal' | 'branch' | 'ret' | 'call_end'

    @property
    def end(self) -> int:
        return self.instructions[-1].address if self.instructions else self.start

    @property
    def label(self) -> str:
        return f'0x{self.start:08x}'

    @property
    def last_mnem(self) -> str:
        return self.instructions[-1].mnemonic if self.instructions else ''


@dataclass
class CFG:
    function_address: int
    blocks: dict = field(default_factory=dict)   # start_addr -> BasicBlock

    @property
    def entry(self) -> Optional[BasicBlock]:
        return self.blocks.get(self.function_address)

    @property
    def block_count(self) -> int:
        return len(self.blocks)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class CFGBuilder:

    def build(self, function: Function) -> CFG:
        cfg = CFG(function_address=function.address)
        if not function.instructions:
            return cfg

        # --- Pass 1: find block-start addresses ---
        leaders = set()
        leaders.add(function.instructions[0].address)

        insns = function.instructions
        for i, insn in enumerate(insns):
            mnem = insn.mnemonic.lower()
            is_branch = mnem in BRANCH_MNEMONICS
            is_jmp    = mnem in UNCOND_JMP
            is_ret    = mnem in RET_MNEMONICS

            if is_branch or is_jmp:
                # target is a leader
                target = self._parse_imm(insn.op_str)
                if target:
                    leaders.add(target)
                # instruction after branch is a leader (fallthrough)
                if i + 1 < len(insns):
                    leaders.add(insns[i + 1].address)

            if is_ret:
                if i + 1 < len(insns):
                    leaders.add(insns[i + 1].address)

        leaders_sorted = sorted(leaders)

        # --- Pass 2: split instructions into blocks ---
        leader_index = {addr: idx for idx, addr in enumerate(leaders_sorted)}
        current_block = None

        for insn in insns:
            if insn.address in leaders:
                current_block = BasicBlock(start=insn.address)
                cfg.blocks[insn.address] = current_block
            if current_block is not None:
                current_block.instructions.append(insn)

        # --- Pass 3: connect blocks ---
        for block in cfg.blocks.values():
            if not block.instructions:
                continue
            last = block.instructions[-1]
            mnem = last.mnemonic.lower()

            if mnem in RET_MNEMONICS:
                block.block_type = 'ret'

            elif mnem in UNCOND_JMP:
                block.block_type = 'branch'
                target = self._parse_imm(last.op_str)
                if target and target in cfg.blocks:
                    block.successors.append(target)
                    cfg.blocks[target].predecessors.append(block.start)

            elif mnem in BRANCH_MNEMONICS:
                block.block_type = 'branch'
                # taken branch
                target = self._parse_imm(last.op_str)
                if target and target in cfg.blocks:
                    block.successors.append(target)
                    cfg.blocks[target].predecessors.append(block.start)
                # fallthrough
                ft = self._fallthrough(block, insns)
                if ft and ft in cfg.blocks:
                    block.successors.append(ft)
                    cfg.blocks[ft].predecessors.append(block.start)

            else:
                # Sequential fallthrough
                ft = self._fallthrough(block, insns)
                if ft and ft in cfg.blocks:
                    block.successors.append(ft)
                    cfg.blocks[ft].predecessors.append(block.start)

        return cfg

    def _parse_imm(self, op_str: str) -> Optional[int]:
        op = op_str.strip().split(',')[0].strip().replace('[', '').replace(']', '')
        if '+' in op or '-' in op:
            return None
        try:
            return int(op, 0)
        except ValueError:
            return None

    def _fallthrough(self, block: BasicBlock, all_insns: list) -> Optional[int]:
        """Return the address of the instruction immediately after this block."""
        last_addr = block.instructions[-1].address
        for i, insn in enumerate(all_insns):
            if insn.address == last_addr and i + 1 < len(all_insns):
                return all_insns[i + 1].address
        return None


# ---------------------------------------------------------------------------
# Text renderer (TUI)
# ---------------------------------------------------------------------------

class CFGTextRenderer:
    MAX_INSNS_PER_BLOCK = 6   # truncate long blocks for readability

    def render(self, cfg: CFG) -> str:
        if not cfg.blocks:
            return '(no CFG — function has no instructions)'

        lines = [f'CFG: {cfg.block_count} basic blocks\n']
        # BFS order from entry
        visited, queue = set(), [cfg.function_address]

        while queue:
            addr = queue.pop(0)
            if addr in visited or addr not in cfg.blocks:
                continue
            visited.add(addr)
            block = cfg.blocks[addr]

            type_icon = {'ret': '◼', 'branch': '◆', 'normal': '▶'}.get(block.block_type, '▶')
            lines.append(f'┌── {type_icon} Block {block.label} '
                         f'({len(block.instructions)} insns) ──')

            shown = block.instructions[:self.MAX_INSNS_PER_BLOCK]
            for insn in shown:
                lines.append(f'│  0x{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}')
            if len(block.instructions) > self.MAX_INSNS_PER_BLOCK:
                lines.append(f'│  … ({len(block.instructions) - self.MAX_INSNS_PER_BLOCK} more)')

            if block.successors:
                succs = ', '.join(f'0x{s:08x}' for s in block.successors)
                lines.append(f'└── → {succs}\n')
            else:
                lines.append('└── (exit)\n')

            for s in block.successors:
                if s not in visited:
                    queue.append(s)

        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# SVG renderer (HTML report)
# ---------------------------------------------------------------------------

class CFGSVGRenderer:
    BLOCK_W   = 280
    BLOCK_H_BASE = 28   # header height
    LINE_H    = 16      # per instruction
    H_GAP     = 80      # vertical gap between layers
    W_GAP     = 40      # horizontal gap between blocks in same layer
    MAX_INSNS = 12      # max instructions shown per block in SVG

    COLORS = {
        'ret':    '#1a3a1a',
        'branch': '#2a2a0a',
        'normal': '#0d1117',
    }
    BORDER = {
        'ret':    '#2ea043',
        'branch': '#e3b341',
        'normal': '#30363d',
    }

    def render(self, cfg: CFG) -> str:
        if not cfg.blocks:
            return '<p style="color:#8b949e">No CFG available.</p>'

        # BFS to assign layers
        layers = self._assign_layers(cfg)
        if not layers:
            return '<p style="color:#8b949e">CFG layout failed.</p>'

        # Assign pixel positions
        positions = {}
        max_layer_w = max(len(blks) for blks in layers.values()) if layers else 1
        total_h = 0

        for layer_idx in sorted(layers):
            blks = layers[layer_idx]
            layer_w = len(blks) * (self.BLOCK_W + self.W_GAP) - self.W_GAP
            x_start = 20
            y = layer_idx * (200 + self.H_GAP) + 20

            for i, addr in enumerate(blks):
                block = cfg.blocks[addr]
                n_lines = min(len(block.instructions), self.MAX_INSNS) + 1
                bh = self.BLOCK_H_BASE + n_lines * self.LINE_H
                x = x_start + i * (self.BLOCK_W + self.W_GAP)
                positions[addr] = (x, y, self.BLOCK_W, bh)
            total_h = max(total_h, y + 300)

        total_w = max_layer_w * (self.BLOCK_W + self.W_GAP) + 40

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'width="{total_w}" height="{total_h}" '
            f'style="background:#0d1117;border-radius:6px;display:block;max-width:100%;overflow:auto">'
        ]

        # Draw edges first (behind blocks)
        for block in cfg.blocks.values():
            if block.start not in positions:
                continue
            x1, y1, w1, h1 = positions[block.start]
            cx1 = x1 + w1 // 2
            cy1 = y1 + h1

            for i, succ in enumerate(block.successors):
                if succ not in positions:
                    continue
                x2, y2, w2, h2 = positions[succ]
                cx2 = x2 + w2 // 2
                cy2 = y2
                color = '#e3b341' if i == 0 and len(block.successors) > 1 else '#58a6ff'
                mid_y = (cy1 + cy2) // 2
                svg_parts.append(
                    f'<path d="M{cx1},{cy1} C{cx1},{mid_y} {cx2},{mid_y} {cx2},{cy2}" '
                    f'stroke="{color}" stroke-width="1.5" fill="none" marker-end="url(#arrow)"/>'
                )

        # Arrow marker def
        svg_parts.insert(1,
            '<defs><marker id="arrow" markerWidth="8" markerHeight="8" '
            'refX="6" refY="3" orient="auto">'
            '<path d="M0,0 L0,6 L8,3 z" fill="#58a6ff"/>'
            '</marker></defs>'
        )

        # Draw blocks
        for block in cfg.blocks.values():
            if block.start not in positions:
                continue
            x, y, w, h = positions[block.start]
            bg  = self.COLORS.get(block.block_type, self.COLORS['normal'])
            bdr = self.BORDER.get(block.block_type, self.BORDER['normal'])

            svg_parts.append(
                f'<rect x="{x}" y="{y}" width="{w}" height="{h}" '
                f'rx="4" fill="{bg}" stroke="{bdr}" stroke-width="1"/>'
            )
            # Header
            svg_parts.append(
                f'<rect x="{x}" y="{y}" width="{w}" height="{self.BLOCK_H_BASE}" '
                f'rx="4" fill="{bdr}" opacity="0.4"/>'
            )
            svg_parts.append(
                f'<text x="{x+8}" y="{y+18}" font-family="monospace" '
                f'font-size="11" fill="#f0f6fc" font-weight="bold">'
                f'{block.label}  ({len(block.instructions)} insns)</text>'
            )

            shown = block.instructions[:self.MAX_INSNS]
            for j, insn in enumerate(shown):
                iy = y + self.BLOCK_H_BASE + j * self.LINE_H + 13
                mnem_color = self._mnem_color(insn.mnemonic)
                svg_parts.append(
                    f'<text x="{x+8}" y="{iy}" font-family="monospace" font-size="10" fill="#6e7681">'
                    f'{insn.address:08x}:</text>'
                )
                svg_parts.append(
                    f'<text x="{x+80}" y="{iy}" font-family="monospace" font-size="10" fill="{mnem_color}">'
                    f'{self._esc(insn.mnemonic)}</text>'
                )
                ops = self._esc(insn.op_str[:24])
                svg_parts.append(
                    f'<text x="{x+145}" y="{iy}" font-family="monospace" font-size="10" fill="#8b949e">'
                    f'{ops}</text>'
                )

            if len(block.instructions) > self.MAX_INSNS:
                iy = y + self.BLOCK_H_BASE + self.MAX_INSNS * self.LINE_H + 13
                svg_parts.append(
                    f'<text x="{x+8}" y="{iy}" font-family="monospace" font-size="10" fill="#484f58">'
                    f'…{len(block.instructions) - self.MAX_INSNS} more</text>'
                )

        svg_parts.append('</svg>')
        return '\n'.join(svg_parts)

    def _assign_layers(self, cfg: CFG) -> dict:
        layers: dict[int, list] = {}
        depth: dict[int, int] = {}
        queue = [cfg.function_address]
        depth[cfg.function_address] = 0

        while queue:
            addr = queue.pop(0)
            if addr not in cfg.blocks:
                continue
            block = cfg.blocks[addr]
            d = depth[addr]
            layers.setdefault(d, [])
            if addr not in layers[d]:
                layers[d].append(addr)
            for succ in block.successors:
                if succ not in depth:
                    depth[succ] = d + 1
                    queue.append(succ)
        return layers

    def _mnem_color(self, mnem: str) -> str:
        m = mnem.lower()
        if m in ('call', 'callq'):  return '#f8c95a'
        if m in RET_MNEMONICS:      return '#56d364'
        if m in BRANCH_MNEMONICS or m in UNCOND_JMP: return '#bc8cff'
        if m in ('push', 'pop'):    return '#79c0ff'
        return '#c9d1d9'

    def _esc(self, s: str) -> str:
        return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
