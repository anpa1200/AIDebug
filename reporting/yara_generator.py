"""
YaraGenerator — asks Claude to write a YARA rule for each HIGH/CRITICAL function,
then assembles all rules into a single .yar file.
"""
import json
import re
import os
from datetime import datetime

import anthropic
import config


YARA_SYSTEM = (
    "You are a malware detection engineer specializing in YARA rule authoring. "
    "Write precise, low-false-positive YARA rules based on function analysis. "
    "Rules must be syntactically valid YARA 4.x. Respond with the raw YARA rule only — "
    "no explanation, no markdown fences."
)

YARA_PROMPT = """\
Write a YARA rule for the following malware function.

FUNCTION: {name}
ADDRESS:  {address}
RISK:     {risk}
MITRE:    {mitre}

SUMMARY:
{summary}

BEHAVIORS:
{behaviors}

REFERENCED STRINGS:
{strings}

DISASSEMBLY (excerpt):
{disasm_excerpt}

Requirements:
- Rule name: {rule_name}
- Include meta: description, author = "AIDebug", date, mitre_technique, risk_level
- Use byte patterns from the disassembly where practical (opcodes, immediate values)
- Use string conditions for any referenced strings
- Keep the condition tight to minimize false positives
- Add a comment above the rule explaining the detection logic
"""


def _sanitize_rule_name(name: str) -> str:
    """Convert a function name to a valid YARA identifier."""
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    if name and name[0].isdigit():
        name = 'func_' + name
    return name or 'unknown_function'


class YaraGenerator:

    TARGET_RISK_LEVELS = {'CRITICAL', 'HIGH'}

    def __init__(self, api_key: str = None):
        key = api_key or config.ANTHROPIC_API_KEY
        self.client = anthropic.Anthropic(api_key=key)

    def generate(self, session: dict, traces: list, output_path: str) -> tuple:
        """
        Generate YARA rules for HIGH and CRITICAL functions.
        Returns (output_path, rule_count).
        """
        targets = [
            t for t in traces
            if (t.get('risk_level') or '').upper() in self.TARGET_RISK_LEVELS
            and t.get('ai_analysis_json')
        ]

        if not targets:
            print("[YARA] No HIGH/CRITICAL functions found — nothing to generate.")
            return output_path, 0

        filename  = session.get('filename', 'unknown')
        sha256    = session.get('sha256', '')
        generated = datetime.now().strftime('%Y-%m-%d')

        header = (
            f"// AIDebug YARA Ruleset\n"
            f"// File    : {filename}\n"
            f"// SHA-256 : {sha256}\n"
            f"// Generated: {generated}\n"
            f"// Rules   : {len(targets)} (HIGH + CRITICAL only)\n"
            f"//\n"
            f"// WARNING: Review and test before deploying to production.\n\n"
        )

        rules = []
        for trace in targets:
            rule = self._generate_rule(trace, filename)
            if rule:
                rules.append(rule)
                print(f"  [YARA] {trace.get('name') or hex(trace.get('address',0))}  → rule written")

        content = header + '\n\n'.join(rules)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)

        return output_path, len(rules)

    # ------------------------------------------------------------------

    def _generate_rule(self, trace: dict, filename: str) -> str:
        ai_raw = trace.get('ai_analysis_json', '{}')
        try:
            ai = json.loads(ai_raw)
        except Exception:
            ai = {}

        name     = ai.get('suggested_name') or trace.get('name') or f"sub_{trace.get('address', 0):08x}"
        address  = trace.get('address', 0)
        risk     = (trace.get('risk_level') or 'HIGH').upper()
        mitre    = ai.get('mitre_technique') or 'N/A'
        summary  = ai.get('summary', '')
        behaviors = '\n'.join(f'  - {b}' for b in ai.get('behaviors', []))
        strings_ref = json.loads(trace.get('strings_referenced') or '[]')
        strings_text = '\n'.join(f'  "{s}"' for s in strings_ref[:8]) or '  (none)'
        disasm   = (trace.get('disassembly') or '')[:1500]
        rule_name = _sanitize_rule_name(name)

        prompt = YARA_PROMPT.format(
            name=name,
            address=hex(address),
            risk=risk,
            mitre=mitre,
            summary=summary,
            behaviors=behaviors or '  (none)',
            strings=strings_text,
            disasm_excerpt=disasm,
            rule_name=rule_name,
        )

        try:
            response = self.client.messages.create(
                model=config.AI_MODEL,
                max_tokens=1024,
                system=YARA_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.content[0].text.strip()
            # Strip accidental markdown fences
            if raw.startswith('```'):
                raw = re.sub(r'^```[a-z]*\n?', '', raw)
                raw = re.sub(r'\n?```$', '', raw)
            return raw.strip()
        except Exception as e:
            # Fall back to a minimal template rule so the file stays valid
            return self._fallback_rule(rule_name, name, address, risk, mitre, summary, strings_ref)

    def _fallback_rule(self, rule_name, name, address, risk, mitre, summary, strings_ref) -> str:
        str_defs = ''
        str_cond = 'false'
        for i, s in enumerate(strings_ref[:5]):
            safe = s.replace('\\', '\\\\').replace('"', '\\"')
            str_defs += f'        $s{i} = "{safe}" ascii wide\n'
        if strings_ref:
            str_cond = ' or '.join(f'$s{i}' for i in range(min(5, len(strings_ref))))

        return f"""\
// Detection for {name} ({risk}) — fallback template (AI call failed)
// {summary[:100]}
rule {rule_name} {{
    meta:
        description = "Detects {name} — {risk} risk function"
        author      = "AIDebug"
        mitre_technique = "{mitre}"
        risk_level  = "{risk}"
        function_va = "{hex(address)}"
    strings:
{str_defs or '        // no string references found\n'}
    condition:
        {str_cond}
}}"""
