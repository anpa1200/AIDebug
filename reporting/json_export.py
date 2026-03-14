"""
JSONExporter — exports a full analysis session as structured JSON.

Output schema is designed for ingestion into:
  - Elasticsearch / OpenSearch  (SIEM)
  - Splunk (JSON over HEC)
  - SOAR platforms (Palo Alto XSOAR, Splunk SOAR, etc.)
  - Any threat intel platform accepting STIX-like JSON
"""
import json
import os
from datetime import datetime, timezone


class JSONExporter:

    def export(self, session: dict, traces: list, api_calls: list,
               output_path: str) -> str:
        """
        Write a structured JSON export to output_path.
        Returns the output path.
        """
        doc = self._build(session, traces, api_calls)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)
        return output_path

    # ------------------------------------------------------------------

    def _build(self, session: dict, traces: list, api_calls: list) -> dict:
        risk_summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        mitre_techniques = {}

        functions = []
        for trace in traces:
            ai_raw = trace.get('ai_analysis_json') or '{}'
            try:
                ai = json.loads(ai_raw)
            except Exception:
                ai = {}

            snap_raw = trace.get('snapshot_json') or '{}'
            try:
                snap = json.loads(snap_raw)
            except Exception:
                snap = {}

            risk = (trace.get('risk_level') or 'UNKNOWN').upper()
            risk_summary[risk] = risk_summary.get(risk, 0) + 1

            mitre = trace.get('mitre_technique') or ai.get('mitre_technique')
            if mitre:
                mitre_techniques[mitre] = mitre_techniques.get(mitre, 0) + 1

            func = {
                # Identity
                "address":         hex(trace.get('address', 0)),
                "address_int":     trace.get('address', 0),
                "name":            ai.get('suggested_name') or trace.get('name'),
                "instruction_count": trace.get('instruction_count', 0),
                "size_bytes":      trace.get('instruction_count', 0),   # approximation

                # Graph
                "calls_to":        self._load_json_field(trace, 'calls_to', []),
                "called_from":     self._load_json_field(trace, 'called_from', []),
                "strings_referenced": self._load_json_field(trace, 'strings_referenced', []),

                # AI analysis
                "ai": {
                    "summary":         ai.get('summary', ''),
                    "parameters":      ai.get('parameters', []),
                    "return_value":    ai.get('return_value', ''),
                    "behaviors":       ai.get('behaviors', []),
                    "mitre_technique": mitre,
                    "risk_level":      risk,
                    "notes":           ai.get('notes', ''),
                },

                # Runtime snapshot (populated in dynamic mode)
                "snapshot": {
                    "entry_registers": snap.get('entry_registers', {}),
                    "exit_registers":  snap.get('exit_registers', {}),
                    "return_value":    snap.get('return_value', 0),
                } if snap.get('entry_registers') else None,

                # Timestamps
                "analyzed_at": trace.get('analyzed_at', ''),
            }
            functions.append(func)

        # Sort by risk
        risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
        functions.sort(key=lambda f: risk_order.get(f['ai']['risk_level'], 4))

        # API call log (dynamic mode)
        api_log = []
        for call in api_calls:
            api_log.append({
                "module":    call.get('module', ''),
                "function":  call.get('function', ''),
                "args":      self._load_json_field(call, 'args_json', []),
                "retval":    call.get('retval', ''),
                "timestamp": call.get('timestamp', ''),
            })

        return {
            # Schema version for future compatibility
            "_schema":  "aidebug/session/v1",
            "_exported": datetime.now(timezone.utc).isoformat(),

            # Binary metadata
            "binary": {
                "filename":   session.get('filename', ''),
                "path":       session.get('binary_path', ''),
                "sha256":     session.get('sha256', ''),
                "arch":       session.get('arch', ''),
                "bits":       session.get('bits', 0),
                "os_target":  session.get('os_target', ''),
            },

            # Session metadata
            "session": {
                "id":          session.get('id'),
                "created_at":  session.get('created_at', ''),
            },

            # High-level summary — ideal for SIEM dashboard fields
            "summary": {
                "total_functions":    len(functions),
                "analyzed_functions": sum(1 for f in functions if f['ai']['summary']),
                "risk_counts":        risk_summary,
                "mitre_techniques":   mitre_techniques,
                "api_calls_logged":   len(api_log),
                "highest_risk":       self._highest_risk(risk_summary),
                "ioc_strings":        self._collect_ioc_strings(functions),
            },

            # Full function list
            "functions": functions,

            # Win32 API call log (dynamic mode only)
            "api_calls": api_log,
        }

    # ------------------------------------------------------------------

    def _load_json_field(self, record: dict, key: str, default):
        raw = record.get(key)
        if not raw:
            return default
        if isinstance(raw, (list, dict)):
            return raw
        try:
            return json.loads(raw)
        except Exception:
            return default

    def _highest_risk(self, counts: dict) -> str:
        for level in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            if counts.get(level, 0) > 0:
                return level
        return 'UNKNOWN'

    def _collect_ioc_strings(self, functions: list) -> list:
        """
        Pull strings referenced by HIGH/CRITICAL functions as potential IOCs.
        Filters out generic compiler strings.
        """
        SKIP = {'This program cannot be run in DOS mode', '.text', '.data',
                '.rdata', '.reloc', '!This', 'RSDS'}
        iocs = []
        seen = set()
        for func in functions:
            if func['ai']['risk_level'] not in ('CRITICAL', 'HIGH'):
                continue
            for s in func.get('strings_referenced', []):
                if len(s) > 5 and s not in seen and not any(skip in s for skip in SKIP):
                    iocs.append({
                        "value":    s,
                        "function": func.get('name', ''),
                        "address":  func.get('address', ''),
                        "risk":     func['ai']['risk_level'],
                    })
                    seen.add(s)
        return iocs[:50]   # cap at 50 IOCs
