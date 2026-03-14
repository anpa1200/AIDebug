import json
import os
from dataclasses import dataclass, field
from typing import Optional

import anthropic

import config
from .static_analyzer import BinaryInfo
from .disassembler import Function


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class AIAnalysis:
    suggested_name: str
    summary: str
    parameters: list
    return_value: str
    behaviors: list
    mitre_technique: Optional[str]
    risk_level: str          # LOW / MEDIUM / HIGH / CRITICAL
    notes: str
    raw_response: str = field(default='', repr=False)

    RISK_COLORS = {
        'LOW':      'green',
        'MEDIUM':   'yellow',
        'HIGH':     'red',
        'CRITICAL': 'bright_red',
    }
    RISK_BADGES = {
        'LOW':      '[LOW ]',
        'MEDIUM':   '[MED ]',
        'HIGH':     '[HIGH]',
        'CRITICAL': '[CRIT]',
    }

    @property
    def risk_color(self) -> str:
        return self.RISK_COLORS.get(self.risk_level, 'white')

    @property
    def risk_badge(self) -> str:
        return self.RISK_BADGES.get(self.risk_level, '[??? ]')


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are an expert malware reverse engineer and security analyst with 15+ years of experience. "
    "You analyze disassembled code and runtime snapshots to identify malicious behavior, explain "
    "functionality, and classify threats. You are precise, technical, and provide actionable "
    "intelligence. Always respond with valid JSON only — no markdown fences, no extra text."
)

ANALYSIS_TEMPLATE = """\
Analyze this function from a potentially malicious binary.

BINARY INFO:
  File      : {filename}
  Arch      : {arch} {bits}-bit
  OS Target : {os_target}
  SHA256    : {sha256_short}...

KNOWN IMPORTED APIs:
{imports}

FUNCTION ADDRESS: {addr_hex}
{name_hint}
DISASSEMBLY ({insn_count} instructions):
{disassembly}

REFERENCED STRINGS:
{strings}

CROSS-REFERENCES:
  Called from : {called_from}
  Calls to    : {calls_to}
{runtime_block}
Return a JSON object with exactly these fields:
{{
  "suggested_name":  "snake_case_descriptive_name",
  "summary":         "2-3 sentence description of what this function does and why it matters",
  "parameters":      [{{"name": "p", "type": "t", "description": "what it represents"}}],
  "return_value":    "what the return value means",
  "behaviors":       ["observable", "behaviors", "as", "a", "list"],
  "mitre_technique": "T1234 - Name  or  null",
  "risk_level":      "LOW|MEDIUM|HIGH|CRITICAL",
  "notes":           "anti-analysis tricks, obfuscation, or analyst notes"
}}"""

FOLLOWUP_SYSTEM = (
    "You are a malware reverse engineering assistant. Answer the analyst's question about "
    "the function in the context already established. Be concise and technical. "
    "Plain text, no JSON required."
)


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class AIAnalyzer:

    def __init__(self, api_key: str = None):
        key = api_key or config.ANTHROPIC_API_KEY
        if not key:
            raise ValueError(
                "ANTHROPIC_API_KEY is not set. Export it before running:\n"
                "  export ANTHROPIC_API_KEY=sk-ant-..."
            )
        self.client = anthropic.Anthropic(api_key=key)
        self._history: list = []          # conversation turns for follow-up

    # ------------------------------------------------------------------
    # Main function analysis
    # ------------------------------------------------------------------

    def analyze_function(
        self,
        function: Function,
        binary_info: BinaryInfo,
        snapshot=None,
        force: bool = False,
    ) -> AIAnalysis:
        # Skip library functions unless forced
        if function.is_library and not force:
            match = function.flirt_match
            lib   = match.library if match else 'compiler'
            name  = match.function_name if match else function.name
            return AIAnalysis(
                suggested_name=name,
                summary=f'[FLIRT] Identified as {name} from {lib}. Skipped AI analysis.',
                parameters=[],
                return_value='',
                behaviors=[f'Library function: {lib}'],
                mitre_technique=None,
                risk_level='LOW',
                notes='Identified by FLIRT signature — not a custom malware function.',
            )

        prompt = self._build_prompt(function, binary_info, snapshot)
        self._history = [{"role": "user", "content": prompt}]

        response = self.client.messages.create(
            model=config.AI_MODEL,
            max_tokens=config.AI_MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=self._history,
        )

        raw = response.content[0].text
        self._history.append({"role": "assistant", "content": raw})
        return self._parse(raw)

    # ------------------------------------------------------------------
    # Follow-up chat
    # ------------------------------------------------------------------

    def ask_followup(self, question: str) -> str:
        if not self._history:
            return "No function is currently selected for analysis."

        self._history.append({"role": "user", "content": question})

        response = self.client.messages.create(
            model=config.AI_MODEL,
            max_tokens=1024,
            system=FOLLOWUP_SYSTEM,
            messages=self._history,
        )

        answer = response.content[0].text
        self._history.append({"role": "assistant", "content": answer})
        return answer

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_prompt(self, func: Function, info: BinaryInfo, snapshot) -> str:
        # Imports summary (top 10 DLLs, max 15 functions each)
        if info.imports:
            imp_lines = []
            for imp in info.imports[:10]:
                funcs_preview = ', '.join(imp.functions[:15])
                if len(imp.functions) > 15:
                    funcs_preview += f', ... (+{len(imp.functions)-15} more)'
                imp_lines.append(f"  {imp.dll}: {funcs_preview}")
            imports_text = '\n'.join(imp_lines)
        else:
            imports_text = '  (none / stripped)'

        # Cross-refs
        called_from = ', '.join(f'0x{a:08x}' for a in func.called_from[:5]) or 'unknown'
        calls_to    = ', '.join(f'0x{a:08x}' for a in func.calls_to[:10])   or 'none'

        # Referenced strings
        strings_text = '\n'.join(f'  "{s}"' for s in func.strings_referenced[:15]) or '  (none detected)'

        # Name hint (if already named from exports)
        name_hint = f'Known name: {func.name}\n' if func.is_named else ''

        # Optional runtime snapshot block
        runtime_block = ''
        if snapshot:
            entry_regs = ', '.join(f'{k}={v}' for k, v in snapshot.entry_registers.items())
            exit_regs  = ', '.join(f'{k}={v}' for k, v in snapshot.exit_registers.items())
            runtime_block = (
                f"\nRUNTIME SNAPSHOT:\n"
                f"  Entry registers : {entry_regs}\n"
                f"  Exit  registers : {exit_regs}\n"
                f"  Stack (entry)   : {snapshot.entry_stack_hex[:64]}\n"
                f"  Register changes: {snapshot.memory_diff_summary}\n"
                f"  Return value    : {hex(snapshot.return_value)}\n"
            )

        # Detected patterns block
        patterns_text = ''
        if getattr(func, 'patterns', None):
            lines = [f'  [{p.severity}] {p.name}: {p.evidence}' for p in func.patterns]
            patterns_text = '\nPRE-DETECTED PATTERNS:\n' + '\n'.join(lines) + '\n'

        return ANALYSIS_TEMPLATE.format(
            filename=info.filename,
            arch=info.arch,
            bits=info.bits,
            os_target=info.os_target,
            sha256_short=info.sha256[:16],
            imports=imports_text,
            addr_hex=hex(func.address),
            name_hint=name_hint,
            insn_count=len(func.instructions),
            disassembly=func.disassembly_text[:config.MAX_DISASSEMBLY_CHARS],
            strings=strings_text,
            called_from=called_from,
            calls_to=calls_to,
            runtime_block=runtime_block + patterns_text,
        )

    def _parse(self, raw: str) -> AIAnalysis:
        text = raw.strip()
        # Strip markdown fences if model adds them
        if text.startswith('```'):
            parts = text.split('```')
            text = parts[1].lstrip('json').strip() if len(parts) > 1 else text

        try:
            data = json.loads(text)
            return AIAnalysis(
                suggested_name=data.get('suggested_name', 'unknown_function'),
                summary=data.get('summary', ''),
                parameters=data.get('parameters', []),
                return_value=data.get('return_value', ''),
                behaviors=data.get('behaviors', []),
                mitre_technique=data.get('mitre_technique'),
                risk_level=data.get('risk_level', 'LOW').upper(),
                notes=data.get('notes', ''),
                raw_response=raw,
            )
        except json.JSONDecodeError:
            return AIAnalysis(
                suggested_name='parse_error',
                summary=raw[:500],
                parameters=[],
                return_value='unknown',
                behaviors=[],
                mitre_technique=None,
                risk_level='LOW',
                notes='Failed to parse structured JSON response from AI.',
                raw_response=raw,
            )
