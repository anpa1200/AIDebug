"""
HTMLReporter — generates a self-contained HTML analysis report from a TraceStore session.
All CSS is embedded; the output is a single .html file with no external dependencies.
"""
import json
import os
from datetime import datetime

try:
    from analysis.cfg import CFGBuilder, CFGSVGRenderer
    from analysis.disassembler import Function, Instruction
    _CFG_AVAILABLE = True
except ImportError:
    _CFG_AVAILABLE = False


RISK_COLOR = {
    'CRITICAL': '#e74c3c',
    'HIGH':     '#e67e22',
    'MEDIUM':   '#f1c40f',
    'LOW':      '#2ecc71',
}
RISK_BG = {
    'CRITICAL': '#2c0a0a',
    'HIGH':     '#2c1a0a',
    'MEDIUM':   '#2c260a',
    'LOW':      '#0a2c12',
}


def _esc(text: str) -> str:
    return (str(text)
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;'))


CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    background: #0d1117; color: #c9d1d9;
    font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px;
    line-height: 1.6;
}
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }

/* ---- Header ---- */
.header {
    background: #161b22; border-bottom: 1px solid #30363d;
    padding: 24px 40px;
}
.header h1 { font-size: 22px; color: #f0f6fc; font-weight: 600; }
.header .subtitle { color: #8b949e; font-size: 13px; margin-top: 4px; }
.meta-grid {
    display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
    gap: 12px; margin-top: 20px;
}
.meta-card {
    background: #0d1117; border: 1px solid #30363d;
    border-radius: 6px; padding: 12px 16px;
}
.meta-card .label { font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: .5px; }
.meta-card .value { font-size: 15px; color: #f0f6fc; font-weight: 500; margin-top: 2px; }

/* ---- Risk summary bar ---- */
.risk-bar {
    display: flex; gap: 12px; padding: 16px 40px;
    background: #161b22; border-bottom: 1px solid #30363d;
}
.risk-pill {
    padding: 4px 14px; border-radius: 20px;
    font-size: 13px; font-weight: 600;
}

/* ---- Main layout ---- */
.container { display: flex; height: calc(100vh - 200px); }
.sidebar {
    width: 300px; min-width: 260px;
    background: #161b22; border-right: 1px solid #30363d;
    overflow-y: auto; flex-shrink: 0;
}
.content { flex: 1; overflow-y: auto; padding: 0; }

/* ---- Sidebar function list ---- */
.func-item {
    padding: 10px 16px; border-bottom: 1px solid #21262d;
    cursor: pointer; transition: background .15s;
}
.func-item:hover { background: #1c2128; }
.func-item.active { background: #1f2937; border-left: 3px solid #58a6ff; }
.func-item .badge {
    display: inline-block; font-size: 10px; font-weight: 700;
    padding: 1px 6px; border-radius: 3px; margin-right: 6px;
    letter-spacing: .3px;
}
.func-item .addr { font-family: monospace; font-size: 12px; color: #8b949e; }
.func-item .name { font-size: 13px; color: #c9d1d9; margin-top: 2px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* ---- Function detail ---- */
.func-detail { display: none; padding: 28px 36px; }
.func-detail.active { display: block; }
.func-detail h2 { font-size: 18px; color: #f0f6fc; margin-bottom: 4px; }
.func-detail .addr-line { font-family: monospace; color: #8b949e; font-size: 13px; margin-bottom: 20px; }

.section-title {
    font-size: 11px; font-weight: 600; color: #8b949e;
    text-transform: uppercase; letter-spacing: .8px;
    margin: 20px 0 8px;
    padding-bottom: 6px; border-bottom: 1px solid #21262d;
}
.summary-text { color: #c9d1d9; line-height: 1.7; }
.mitre-tag {
    display: inline-block; margin-top: 10px;
    background: #1a2332; border: 1px solid #1f6feb;
    color: #58a6ff; font-size: 12px; padding: 3px 10px; border-radius: 4px;
}

.behavior-list { list-style: none; margin-top: 4px; }
.behavior-list li { padding: 3px 0; color: #c9d1d9; }
.behavior-list li::before { content: '•  '; color: #58a6ff; }

.param-table { width: 100%; border-collapse: collapse; margin-top: 6px; font-size: 13px; }
.param-table th {
    text-align: left; padding: 6px 10px;
    background: #21262d; color: #8b949e; font-weight: 500;
    border-bottom: 1px solid #30363d;
}
.param-table td { padding: 7px 10px; border-bottom: 1px solid #21262d; }
.param-table td:first-child { font-family: monospace; color: #79c0ff; }
.param-table td:nth-child(2) { color: #ffa657; }

.notes-box {
    background: #161b22; border: 1px solid #30363d;
    border-left: 3px solid #8b949e;
    padding: 10px 14px; border-radius: 4px;
    color: #8b949e; font-size: 13px; margin-top: 6px; line-height: 1.6;
}

/* ---- Disassembly ---- */
.disasm {
    background: #0d1117; border: 1px solid #21262d;
    border-radius: 6px; overflow-x: auto;
    font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 12px;
    margin-top: 6px;
}
.disasm-line { display: flex; padding: 2px 14px; line-height: 1.8; }
.disasm-line:hover { background: #1c2128; }
.disasm-addr { color: #6e7681; min-width: 100px; }
.disasm-mnem { min-width: 90px; }
.disasm-mnem.call  { color: #f8c95a; }
.disasm-mnem.ret   { color: #56d364; }
.disasm-mnem.jmp   { color: #bc8cff; }
.disasm-mnem.push,
.disasm-mnem.pop   { color: #79c0ff; }
.disasm-mnem.other { color: #c9d1d9; }
.disasm-ops  { color: #8b949e; }

/* ---- Risk badge colors ---- */
.badge-CRITICAL { background: #3d0e0e; color: #f85149; border: 1px solid #6e1a1a; }
.badge-HIGH     { background: #3d1f0e; color: #ffa657; border: 1px solid #6e3a1a; }
.badge-MEDIUM   { background: #3d3200; color: #e3b341; border: 1px solid #6e5a00; }
.badge-LOW      { background: #0e3d1a; color: #56d364; border: 1px solid #1a6e30; }
.badge-NONE     { background: #21262d; color: #8b949e; border: 1px solid #30363d; }

/* ---- CFG SVG ---- */
.cfg-container {
    background: #0d1117; border: 1px solid #21262d;
    border-radius: 6px; overflow-x: auto; margin-top: 6px;
    padding: 12px; text-align: center;
}
.cfg-container svg { max-width: 100%; height: auto; }

/* ---- Pattern list ---- */
.pattern-item {
    padding: 8px 12px; border-left: 3px solid #30363d;
    margin-bottom: 8px; background: #161b22; border-radius: 0 4px 4px 0;
}
.pattern-item.sev-HIGH    { border-color: #ffa657; }
.pattern-item.sev-MEDIUM  { border-color: #e3b341; }
.pattern-item.sev-INFO    { border-color: #79c0ff; }
.pattern-badge {
    font-size: 10px; font-weight: 700; padding: 1px 6px;
    border-radius: 3px; margin-right: 8px;
}
.pat-HIGH   { background: #3d1f0e; color: #ffa657; }
.pat-MEDIUM { background: #3d3200; color: #e3b341; }
.pat-INFO   { background: #0d1e3d; color: #79c0ff; }
.pattern-name { font-weight: 600; color: #f0f6fc; }
.pattern-evidence { font-size: 12px; color: #8b949e; margin-top: 3px; font-family: monospace; }

/* ---- Scrollbar ---- */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0d1117; }
::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
"""

JS = """
function showFunc(id) {
    document.querySelectorAll('.func-detail').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.func-item').forEach(el => el.classList.remove('active'));
    var detail = document.getElementById('detail-' + id);
    var item   = document.getElementById('item-' + id);
    if (detail) detail.classList.add('active');
    if (item)   item.classList.add('active');
}
// Auto-show first function
window.addEventListener('DOMContentLoaded', function() {
    var first = document.querySelector('.func-item');
    if (first) first.click();
});
"""


class HTMLReporter:

    def generate(self, session: dict, traces: list, output_path: str,
                 disassembler=None, store=None):
        """
        Generate a self-contained HTML report.
        session:      dict from TraceStore.get_session()
        traces:       list from TraceStore.get_all_traces()
        output_path:  where to write the .html file
        disassembler: optional Disassembler (enables inline CFG SVGs)
        store:        optional TraceStore (enables pattern sections)
        """
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for t in traces:
            lvl = (t.get('risk_level') or 'LOW').upper()
            if lvl in risk_counts:
                risk_counts[lvl] += 1

        html = self._build(session, traces, risk_counts, disassembler, store)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        return output_path

    # ------------------------------------------------------------------

    def _build(self, session, traces, risk_counts, disassembler=None, store=None) -> str:
        filename   = _esc(session.get('filename', 'unknown'))
        sha256     = _esc(session.get('sha256', ''))
        arch       = _esc(f"{session.get('arch', '?')} {session.get('bits', '?')}-bit")
        os_target  = _esc(session.get('os_target', '?'))
        created_at = _esc(session.get('created_at', ''))
        generated  = datetime.now().strftime('%Y-%m-%d %H:%M')

        # Meta cards
        meta = f"""
        <div class="meta-grid">
            <div class="meta-card"><div class="label">File</div><div class="value">{filename}</div></div>
            <div class="meta-card"><div class="label">Architecture</div><div class="value">{arch}</div></div>
            <div class="meta-card"><div class="label">OS Target</div><div class="value">{os_target}</div></div>
            <div class="meta-card"><div class="label">SHA-256</div><div class="value" style="font-family:monospace;font-size:11px">{sha256[:32]}...</div></div>
            <div class="meta-card"><div class="label">Functions Analyzed</div><div class="value">{len(traces)}</div></div>
            <div class="meta-card"><div class="label">Session</div><div class="value">{created_at}</div></div>
        </div>"""

        # Risk summary bar
        pills = ''
        for lvl in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            cnt = risk_counts[lvl]
            color = RISK_COLOR[lvl]
            bg    = RISK_BG[lvl]
            pills += (f'<span class="risk-pill" style="background:{bg};color:{color};'
                      f'border:1px solid {color}">{lvl}: {cnt}</span>')

        # Sidebar + detail panels
        sidebar  = ''
        details  = ''

        for i, trace in enumerate(traces):
            idx       = i
            addr      = trace.get('address', 0)
            risk      = (trace.get('risk_level') or 'NONE').upper()
            ai_raw    = trace.get('ai_analysis_json') or '{}'
            disasm    = trace.get('disassembly') or ''
            try:
                ai = json.loads(ai_raw)
            except Exception:
                ai = {}

            name      = _esc(ai.get('suggested_name') or trace.get('name') or f'sub_{addr:08x}')
            summary   = _esc(ai.get('summary', ''))
            ret_val   = _esc(ai.get('return_value', ''))
            mitre     = _esc(ai.get('mitre_technique') or '')
            notes     = _esc(ai.get('notes', ''))
            behaviors = ai.get('behaviors', [])
            params    = ai.get('parameters', [])
            badge_cls = f'badge-{risk}' if risk in RISK_COLOR else 'badge-NONE'
            short_risk = {'CRITICAL':'CRIT','HIGH':'HIGH','MEDIUM':'MED ','LOW':'LOW '}.get(risk, '--- ')

            # Sidebar item
            sidebar += f"""
            <div class="func-item" id="item-{idx}" onclick="showFunc({idx})">
                <span class="badge {badge_cls}">{short_risk}</span>
                <span class="addr">0x{addr:08x}</span>
                <div class="name">{name}</div>
            </div>"""

            # Detail panel
            behaviors_html = ''.join(f'<li>{_esc(b)}</li>' for b in behaviors) if behaviors else '<li>None identified</li>'

            params_rows = ''
            for p in params:
                params_rows += (f'<tr><td>{_esc(p.get("name","?"))}</td>'
                                f'<td>{_esc(p.get("type","?"))}</td>'
                                f'<td>{_esc(p.get("description",""))}</td></tr>')
            params_html = (f'<table class="param-table"><thead><tr>'
                           f'<th>Name</th><th>Type</th><th>Description</th>'
                           f'</tr></thead><tbody>{params_rows}</tbody></table>'
                           if params else '<span style="color:#8b949e">No parameters identified</span>')

            mitre_html = f'<div class="mitre-tag">{mitre}</div>' if mitre else ''
            notes_html = f'<div class="notes-box">{notes}</div>' if notes else ''
            ret_html   = f'<div class="notes-box">{ret_val}</div>' if ret_val else ''

            disasm_html = self._render_disasm(disasm)
            cfg_html     = self._render_cfg_svg(addr, disassembler)
            patterns_html = self._render_patterns_html(
                store.get_patterns(session['id'], addr) if store else []
            )

            details += f"""
            <div class="func-detail" id="detail-{idx}">
                <h2>{name}</h2>
                <div class="addr-line">Address: 0x{addr:08x}
                    &nbsp;&nbsp;
                    <span class="badge {badge_cls}" style="font-size:11px">{risk}</span>
                </div>

                <div class="section-title">Summary</div>
                <div class="summary-text">{summary}</div>
                {mitre_html}

                <div class="section-title">Behaviors</div>
                <ul class="behavior-list">{behaviors_html}</ul>

                <div class="section-title">Parameters</div>
                {params_html}

                <div class="section-title">Return Value</div>
                {ret_html}

                <div class="section-title">Analyst Notes</div>
                {notes_html}

                {patterns_html}

                <div class="section-title">Control Flow Graph</div>
                {cfg_html}

                <div class="section-title">Disassembly</div>
                {disasm_html}
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AIDebug Report — {filename}</title>
<style>{CSS}</style>
</head>
<body>

<div class="header">
    <h1>AIDebug Analysis Report — {filename}</h1>
    <div class="subtitle">Generated {generated} &nbsp;|&nbsp; Session {session.get('id','?')}</div>
    {meta}
</div>

<div class="risk-bar">{pills}</div>

<div class="container">
    <div class="sidebar">{sidebar}</div>
    <div class="content">{details}</div>
</div>

<script>{JS}</script>
</body>
</html>"""

    def _render_cfg_svg(self, address: int, disassembler) -> str:
        if not disassembler or not _CFG_AVAILABLE:
            return '<div class="cfg-container"><span style="color:#8b949e">CFG not available (static mode)</span></div>'
        try:
            func = disassembler.get_function(address)
            if not func or not func.instructions:
                return '<div class="cfg-container"><span style="color:#8b949e">No instructions found</span></div>'
            cfg = CFGBuilder().build(func)
            svg = CFGSVGRenderer().render(cfg)
            return f'<div class="cfg-container">{svg}</div>'
        except Exception as exc:
            return f'<div class="cfg-container"><span style="color:#8b949e">CFG error: {_esc(str(exc))}</span></div>'

    def _render_patterns_html(self, patterns: list) -> str:
        if not patterns:
            return ''
        items = ''
        for p in patterns:
            sev = (p.get('severity') or 'INFO').upper()
            badge_cls = f'pat-{sev}' if sev in ('HIGH', 'MEDIUM', 'INFO') else 'pat-INFO'
            items += f"""
            <div class="pattern-item sev-{sev}">
                <span class="pattern-badge {badge_cls}">{sev}</span>
                <span class="pattern-name">{_esc(p.get('name',''))}</span>
                <div class="pattern-evidence">{_esc(p.get('evidence',''))}</div>
            </div>"""
        return f'<div class="section-title">Detected Patterns</div>{items}'

    def _render_disasm(self, disasm_text: str) -> str:
        if not disasm_text:
            return '<div class="disasm"><div class="disasm-line"><span style="color:#8b949e">No disassembly available</span></div></div>'

        lines_html = ''
        for line in disasm_text.splitlines()[:300]:
            parts = line.split(':', 1)
            if len(parts) != 2:
                continue
            addr = _esc(parts[0].strip())
            rest = parts[1].strip().split(None, 1)
            mnem = _esc(rest[0]) if rest else ''
            ops  = _esc(rest[1]) if len(rest) > 1 else ''

            mnem_lower = mnem.lower()
            if mnem_lower in ('call', 'callq'):
                cls = 'call'
            elif mnem_lower in ('ret', 'retn', 'retf', 'retq'):
                cls = 'ret'
            elif mnem_lower.startswith('j'):
                cls = 'jmp'
            elif mnem_lower in ('push', 'pop'):
                cls = 'push'
            else:
                cls = 'other'

            lines_html += (f'<div class="disasm-line">'
                           f'<span class="disasm-addr">{addr}:</span>'
                           f'<span class="disasm-mnem {cls}">{mnem}</span>'
                           f'<span class="disasm-ops">{ops}</span>'
                           f'</div>')

        return f'<div class="disasm">{lines_html}</div>'
