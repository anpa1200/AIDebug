"""
HTMLReporter — generates a self-contained HTML analysis report from a TraceStore session.
All CSS is embedded; the output is a single .html file with no external dependencies.
"""
import html
import json
import secrets
from datetime import datetime
from typing import Any

try:
    from analysis.cfg import CFGBuilder, CFGSVGRenderer
    from analysis.disassembler import Function, Instruction
    _CFG_AVAILABLE = True
except ImportError:
    _CFG_AVAILABLE = False

from ._io import atomic_write_text

RISK_COLOR = {
    'CRITICAL': '#e74c3c',
    'HIGH':     '#e67e22',
    'MEDIUM':   '#f1c40f',
    'LOW':      '#2ecc71',
    'UNKNOWN':  '#8b949e',
}
RISK_BG = {
    'CRITICAL': '#2c0a0a',
    'HIGH':     '#2c1a0a',
    'MEDIUM':   '#2c260a',
    'LOW':      '#0a2c12',
    'UNKNOWN':  '#21262d',
}
RISK_LEVELS = tuple(RISK_COLOR)


def _esc(text: Any) -> str:
    # Escape ``=`` as an additional defense-in-depth measure: the value remains
    # human-readable in the browser but cannot form an event-handler assignment
    # if a future template edit accidentally moves it into an attribute context.
    return html.escape(str(text), quote=True).replace("=", "&#x3D;")


def _nonnegative_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        number = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(0, number)


def _risk_level(value: Any) -> str:
    level = value.strip().upper() if isinstance(value, str) else "UNKNOWN"
    return level if level in RISK_LEVELS else "UNKNOWN"


def _json_object(value: Any) -> dict:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value:
        return {}
    try:
        parsed = json.loads(value)
    except (ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _text_list(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _dict_list(value: Any) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


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

/* ---- Dynamic evidence ---- */
.dynamic-evidence {
    padding: 18px 40px; background: #0d1117; border-bottom: 1px solid #30363d;
}
.dynamic-evidence h2 { font-size: 16px; color: #f0f6fc; margin-bottom: 8px; }
.privacy-note { color: #d29922; font-size: 12px; margin-bottom: 12px; }
.evidence-table {
    width: 100%; border-collapse: collapse; margin: 8px 0 18px; font-size: 12px;
}
.evidence-table th, .evidence-table td {
    text-align: left; vertical-align: top; padding: 5px 8px;
    border-bottom: 1px solid #21262d; overflow-wrap: anywhere;
}
.evidence-table th { color: #8b949e; background: #161b22; }

/* ---- Main layout ---- */
.container { display: flex; height: 75vh; min-height: 560px; }
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
.badge-UNKNOWN  { background: #21262d; color: #8b949e; border: 1px solid #30363d; }
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
    document.querySelectorAll('.func-item').forEach(function(item) {
        item.addEventListener('click', function() {
            showFunc(item.dataset.functionIndex);
        });
    });
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
        session = session if isinstance(session, dict) else {}
        traces = traces if isinstance(traces, list) else []
        normalized_traces = [trace for trace in traces if isinstance(trace, dict)]
        risk_counts = {level: 0 for level in RISK_LEVELS}
        for trace in normalized_traces:
            ai = _json_object(trace.get("ai_analysis_json"))
            level = _risk_level(trace.get("risk_level") or ai.get("risk_level"))
            risk_counts[level] += 1

        api_calls = self._store_records(store, "get_api_calls", session.get("id"))
        network_events = self._store_records(store, "get_network_events", session.get("id"))
        runtime_events = self._store_records(store, "get_runtime_events", session.get("id"))

        report = self._build(
            session,
            normalized_traces,
            risk_counts,
            disassembler,
            store,
            api_calls,
            network_events,
            runtime_events,
        )
        return atomic_write_text(output_path, report)

    # ------------------------------------------------------------------

    def _build(self, session, traces, risk_counts, disassembler=None, store=None,
               api_calls=None, network_events=None, runtime_events=None) -> str:
        api_calls = api_calls if isinstance(api_calls, list) else []
        network_events = network_events if isinstance(network_events, list) else []
        runtime_events = runtime_events if isinstance(runtime_events, list) else []
        filename   = _esc(session.get('filename', 'unknown'))
        sha256     = _esc(session.get('sha256', ''))
        arch       = _esc(f"{session.get('arch', '?')} {session.get('bits', '?')}-bit")
        os_target  = _esc(session.get('os_target', '?'))
        created_at = _esc(session.get('created_at', ''))
        generated  = _esc(datetime.now().strftime('%Y-%m-%d %H:%M'))
        session_id = _esc(session.get("id", "?"))
        script_nonce = secrets.token_urlsafe(24)

        # Meta cards
        meta = f"""
        <div class="meta-grid">
            <div class="meta-card"><div class="label">File</div><div class="value">{filename}</div></div>
            <div class="meta-card"><div class="label">Architecture</div><div class="value">{arch}</div></div>
            <div class="meta-card"><div class="label">OS Target</div><div class="value">{os_target}</div></div>
            <div class="meta-card"><div class="label">SHA-256</div><div class="value" style="font-family:monospace;font-size:11px">{sha256[:32]}...</div></div>
            <div class="meta-card"><div class="label">Functions Analyzed</div><div class="value">{len(traces)}</div></div>
            <div class="meta-card"><div class="label">API Calls</div><div class="value">{len(api_calls)}</div></div>
            <div class="meta-card"><div class="label">Network Events</div><div class="value">{len(network_events)}</div></div>
            <div class="meta-card"><div class="label">Runtime Hints</div><div class="value">{len(runtime_events)}</div></div>
            <div class="meta-card"><div class="label">Session</div><div class="value">{created_at}</div></div>
        </div>"""

        # Risk summary bar
        pills = ''
        for lvl in RISK_LEVELS:
            cnt = _nonnegative_int(risk_counts.get(lvl))
            color = RISK_COLOR[lvl]
            bg    = RISK_BG[lvl]
            pills += (f'<span class="risk-pill" style="background:{bg};color:{color};'
                      f'border:1px solid {color}">{lvl}: {cnt}</span>')

        # Sidebar + detail panels
        sidebar  = ''
        details  = ''

        for i, trace in enumerate(traces):
            idx       = i
            addr      = _nonnegative_int(trace.get('address'))
            ai        = _json_object(trace.get('ai_analysis_json'))
            risk      = _risk_level(trace.get('risk_level') or ai.get('risk_level'))
            disasm    = trace.get('disassembly') or ''

            name      = _esc(ai.get('suggested_name') or trace.get('name') or f'sub_{addr:08x}')
            summary   = _esc(ai.get('summary', ''))
            ret_val   = _esc(ai.get('return_value', ''))
            mitre     = _esc(ai.get('mitre_technique') or '')
            notes     = _esc(ai.get('notes', ''))
            behaviors = _text_list(ai.get('behaviors'))
            params    = _dict_list(ai.get('parameters'))
            badge_cls = f'badge-{risk}'
            short_risk = {
                'CRITICAL': 'CRIT',
                'HIGH': 'HIGH',
                'MEDIUM': 'MED ',
                'LOW': 'LOW ',
                'UNKNOWN': '--- ',
            }[risk]

            # Sidebar item
            sidebar += f"""
            <div class="func-item" id="item-{idx}" data-function-index="{idx}">
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
            cfg_html     = self._render_cfg_svg(addr, disassembler, disasm)
            patterns = []
            if store and session.get("id") is not None:
                patterns = store.get_patterns(session.get("id"), addr)
            patterns_html = self._render_patterns_html(patterns)

            details += f"""
            <div class="func-detail" id="detail-{idx}">
                <h2>{name}</h2>
                <div class="addr-line">Address: 0x{addr:08x}
                    &nbsp;&nbsp;
                    <span class="badge {badge_cls}" style="font-size:11px">{_esc(risk)}</span>
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

        if not details:
            details = (
                '<div class="func-detail active">'
                '<h2>No function analyses available</h2>'
                '<div class="summary-text">This session does not contain any stored function traces.</div>'
                '</div>'
            )

        dynamic_evidence = self._render_dynamic_evidence(
            api_calls,
            network_events,
            runtime_events,
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; connect-src 'none'; form-action 'none'; frame-ancestors 'none'; img-src data:; object-src 'none'; script-src 'nonce-{script_nonce}'; style-src 'unsafe-inline'">
<title>AIDebug Report — {filename}</title>
<style>{CSS}</style>
</head>
<body>

<div class="header">
    <h1>AIDebug Analysis Report — {filename}</h1>
    <div class="subtitle">Generated {generated} &nbsp;|&nbsp; Session {session_id}</div>
    {meta}
</div>

<div class="risk-bar">{pills}</div>
{dynamic_evidence}

<div class="container">
    <div class="sidebar">{sidebar}</div>
    <div class="content">{details}</div>
</div>

<script nonce="{script_nonce}">{JS}</script>
</body>
</html>"""

    def _store_records(self, store, method_name: str, session_id: Any) -> list:
        method = getattr(store, method_name, None) if store is not None else None
        if not callable(method) or session_id is None:
            return []
        records = method(session_id)
        return records if isinstance(records, list) else []

    def _render_dynamic_evidence(self, api_calls, network_events, runtime_events) -> str:
        if not api_calls and not network_events and not runtime_events:
            return ""

        sections = []
        api_rows = []
        for record in api_calls[:500]:
            if not isinstance(record, dict):
                continue
            args = record.get("args_json") or record.get("args") or []
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except (TypeError, ValueError, json.JSONDecodeError):
                    pass
            api_rows.append(
                "<tr>"
                f"<td>{_esc(record.get('timestamp', ''))}</td>"
                f"<td>{_esc(record.get('module', ''))}</td>"
                f"<td>{_esc(record.get('function', ''))}</td>"
                f"<td>{_esc(str(args)[:1000])}</td>"
                f"<td>{_esc(record.get('retval', ''))}</td>"
                "</tr>"
            )
        if api_rows:
            sections.append(
                "<h2>API call evidence</h2>"
                '<table class="evidence-table"><thead><tr>'
                "<th>Time</th><th>Module</th><th>Function</th><th>Arguments</th><th>Return</th>"
                f"</tr></thead><tbody>{''.join(api_rows)}</tbody></table>"
            )

        network_rows = []
        for record in network_events[:500]:
            if not isinstance(record, dict):
                continue
            destination = record.get("url") or (
                f"{record.get('ip', '')}:{record.get('port', 0)}"
                if record.get("ip")
                else ""
            )
            network_rows.append(
                "<tr>"
                f"<td>{_esc(record.get('logged_at') or record.get('timestamp', ''))}</td>"
                f"<td>{_esc(record.get('event_type') or record.get('event', ''))}</td>"
                f"<td>{_esc(record.get('function', ''))}</td>"
                f"<td>{_esc(destination)}</td>"
                f"<td>{_esc(_nonnegative_int(record.get('size')))}</td>"
                "</tr>"
            )
        if network_rows:
            sections.append(
                "<h2>Network evidence</h2>"
                '<table class="evidence-table"><thead><tr>'
                "<th>Time</th><th>Event</th><th>Function</th><th>Destination</th><th>Bytes</th>"
                f"</tr></thead><tbody>{''.join(network_rows)}</tbody></table>"
            )

        runtime_rows = []
        for record in runtime_events[:500]:
            if not isinstance(record, dict):
                continue
            payload = _json_object(record.get("payload_json"))
            runtime_rows.append(
                "<tr>"
                f"<td>{_esc(record.get('logged_at') or record.get('timestamp', ''))}</td>"
                f"<td>{_esc(record.get('event_type') or payload.get('event', ''))}</td>"
                f"<td>{_esc(json.dumps(payload, ensure_ascii=False, sort_keys=True)[:2000])}</td>"
                "</tr>"
            )
        if runtime_rows:
            sections.append(
                "<h2>Runtime heuristic evidence</h2>"
                '<table class="evidence-table"><thead><tr>'
                "<th>Time</th><th>Event</th><th>Details</th>"
                f"</tr></thead><tbody>{''.join(runtime_rows)}</tbody></table>"
            )

        total = len(api_calls) + len(network_events) + len(runtime_events)
        shown = min(len(api_calls), 500) + min(len(network_events), 500) + min(len(runtime_events), 500)
        truncation = f" Showing the first {shown} of {total} records." if shown < total else ""
        return (
            '<section class="dynamic-evidence"><div class="privacy-note">'
            "Dynamic records may contain sensitive arguments, destinations, and payload metadata. "
            "Protection-transition events are heuristic evidence, not proof of unpacking or an OEP."
            f"{_esc(truncation)}</div>{''.join(sections)}</section>"
        )

    def _render_cfg_svg(self, address: int, disassembler, disassembly: Any = "") -> str:
        if not _CFG_AVAILABLE:
            return '<div class="cfg-container"><span style="color:#8b949e">CFG renderer unavailable</span></div>'
        try:
            func = disassembler.get_function(address) if disassembler else None
            if not func:
                func = self._function_from_disassembly(address, disassembly)
            if not func or not func.instructions:
                return '<div class="cfg-container"><span style="color:#8b949e">No instructions found</span></div>'
            cfg = CFGBuilder().build(func)
            svg = CFGSVGRenderer().render(cfg)
            return f'<div class="cfg-container">{svg}</div>'
        except Exception as exc:
            return f'<div class="cfg-container"><span style="color:#8b949e">CFG error: {_esc(str(exc))}</span></div>'

    def _function_from_disassembly(self, address: int, disassembly: Any):
        """Reconstruct the CFG inputs available in a persisted trace."""
        instructions = []
        for line in str(disassembly or "").splitlines()[:300]:
            parts = line.split(":", 1)
            if len(parts) != 2:
                continue
            try:
                instruction_address = int(parts[0].strip(), 0)
            except (TypeError, ValueError, OverflowError):
                continue
            operation = parts[1].strip().split(None, 1)
            if not operation:
                continue
            mnemonic = operation[0][:32]
            operands = operation[1][:512] if len(operation) > 1 else ""
            instructions.append(
                Instruction(
                    address=instruction_address,
                    mnemonic=mnemonic,
                    op_str=operands,
                    raw_bytes=b"",
                )
            )
        return Function(
            address=instructions[0].address if instructions else address,
            name=f"sub_{address:08x}",
            instructions=instructions,
        )

    def _render_patterns_html(self, patterns: list) -> str:
        if not isinstance(patterns, list) or not patterns:
            return ''
        items = ''
        for p in patterns:
            if not isinstance(p, dict):
                continue
            raw_severity = p.get("severity")
            severity = raw_severity.strip().upper() if isinstance(raw_severity, str) else "INFO"
            severity = severity if severity in ("HIGH", "MEDIUM", "INFO") else "INFO"
            badge_cls = f'pat-{severity}'
            items += f"""
            <div class="pattern-item sev-{severity}">
                <span class="pattern-badge {badge_cls}">{severity}</span>
                <span class="pattern-name">{_esc(p.get('name',''))}</span>
                <div>{_esc(p.get('description',''))}</div>
                <div class="pattern-evidence">{_esc(p.get('evidence',''))}</div>
            </div>"""
        return f'<div class="section-title">Detected Patterns</div>{items}' if items else ''

    def _render_disasm(self, disasm_text: str) -> str:
        if not disasm_text:
            return '<div class="disasm"><div class="disasm-line"><span style="color:#8b949e">No disassembly available</span></div></div>'

        lines_html = ''
        for line in str(disasm_text).splitlines()[:300]:
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
