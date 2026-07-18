"""
JSONExporter — exports a full analysis session as structured JSON.

Schema v2 retains the v1 binary/session/function/API fields and adds bounded
deterministic-pattern and dynamic-network evidence. Consumers should branch on
``_schema`` and ignore unknown fields for forward compatibility.

The output is an AIDebug-native interchange document. It is not STIX and is
not a vendor-native SIEM/SOAR payload; use a tested custom adapter to map its
versioned fields into a destination system.
"""
import json
import math
from datetime import datetime, timezone
from typing import Any

from ._io import atomic_write_text

RISK_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


class JSONExporter:

    def export(self, session: dict, traces: list, api_calls: list,
               output_path: str, *, network_events: list | None = None,
               runtime_events: list | None = None,
               patterns: list | None = None) -> str:
        """
        Write a structured JSON export to output_path.
        Returns the output path.
        """
        doc = self._build(
            session,
            traces,
            api_calls,
            network_events=network_events,
            runtime_events=runtime_events,
            patterns=patterns,
        )
        content = json.dumps(
            doc,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        ) + "\n"
        return atomic_write_text(output_path, content)

    # ------------------------------------------------------------------

    def _build(self, session: dict, traces: list, api_calls: list,
               *, network_events: list | None = None,
               runtime_events: list | None = None,
               patterns: list | None = None) -> dict:
        session = session if isinstance(session, dict) else {}
        traces = traces if isinstance(traces, list) else []
        api_calls = api_calls if isinstance(api_calls, list) else []
        network_events = network_events if isinstance(network_events, list) else []
        runtime_events = runtime_events if isinstance(runtime_events, list) else []
        patterns = patterns if isinstance(patterns, list) else []

        patterns_by_address: dict[int, list[dict]] = {}
        for pattern in patterns:
            if not isinstance(pattern, dict):
                continue
            pattern_address = self._nonnegative_int(pattern.get("address"))
            severity = self._text(pattern.get("severity")).strip().upper()
            if severity not in {"HIGH", "MEDIUM", "INFO"}:
                severity = "INFO"
            patterns_by_address.setdefault(pattern_address, []).append({
                "name": self._text(pattern.get("name")),
                "description": self._text(pattern.get("description")),
                "severity": severity,
                "evidence": self._text(pattern.get("evidence")),
            })

        risk_summary = {level: 0 for level in (*RISK_LEVELS, "UNKNOWN")}
        mitre_techniques = {}

        functions = []
        for trace in traces:
            if not isinstance(trace, dict):
                continue

            ai = self._load_json_object(trace.get("ai_analysis_json"))
            snap = self._load_json_object(trace.get("snapshot_json"))
            address = self._nonnegative_int(trace.get("address"))
            instruction_count = self._nonnegative_int(
                trace.get("instruction_count")
            )
            risk = self._risk_level(trace.get("risk_level") or ai.get("risk_level"))
            risk_summary[risk] += 1

            mitre = trace.get("mitre_technique") or ai.get("mitre_technique")
            mitre = mitre.strip() if isinstance(mitre, str) else None
            if mitre:
                mitre_techniques[mitre] = mitre_techniques.get(mitre, 0) + 1

            calls_to = self._json_list(trace, "calls_to")
            called_from = self._json_list(trace, "called_from")
            strings_referenced = [
                value
                for value in self._json_list(trace, "strings_referenced")
                if isinstance(value, str)
            ]

            explicit_size = trace.get("size_bytes", trace.get("size"))
            size_bytes = (
                self._nonnegative_int(explicit_size)
                if explicit_size is not None
                else None
            )

            func = {
                # Identity
                "address":         hex(address),
                "address_int":     address,
                "name":            self._text(ai.get("suggested_name") or trace.get("name")),
                "instruction_count": instruction_count,
                # Older TraceStore rows do not record byte size.  Do not
                # mislabel instruction count as a byte measurement.
                "size_bytes":      size_bytes,

                # Graph
                "calls_to":        calls_to,
                "called_from":     called_from,
                "strings_referenced": strings_referenced,
                "deterministic_patterns": patterns_by_address.get(address, []),

                # AI analysis
                "ai": {
                    "summary":         self._text(ai.get("summary")),
                    "parameters":      self._dict_list(ai.get("parameters")),
                    "return_value":    self._text(ai.get("return_value")),
                    "behaviors":       self._text_list(ai.get("behaviors")),
                    "mitre_technique": mitre,
                    "risk_level":      risk,
                    "notes":           self._text(ai.get("notes")),
                },

                # Runtime snapshot (populated in dynamic mode)
                "snapshot": {
                    "entry_registers": self._json_safe_dict(snap.get("entry_registers")),
                    "exit_registers":  self._json_safe_dict(snap.get("exit_registers")),
                    "return_value":    self._json_safe(snap.get("return_value", 0)),
                } if isinstance(snap.get("entry_registers"), dict) and snap["entry_registers"] else None,

                # Timestamps
                "analyzed_at": self._text(trace.get("analyzed_at")),
            }
            functions.append(func)

        # Sort by risk
        risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
        functions.sort(key=lambda f: risk_order.get(f['ai']['risk_level'], 4))

        # API call log (dynamic mode)
        api_log = []
        api_limit = 10_000
        for call in api_calls[:api_limit]:
            if not isinstance(call, dict):
                continue
            api_log.append({
                "module":    self._text(call.get("module")),
                "function":  self._text(call.get("function")),
                "args":      self._json_list(call, "args_json"),
                "retval":    self._text(call.get("retval")),
                "timestamp": self._text(call.get("timestamp")),
            })

        network_log = []
        network_limit = 10_000
        for event in network_events[:network_limit]:
            if not isinstance(event, dict):
                continue
            port = self._nonnegative_int(event.get("port"))
            network_log.append({
                "event": self._text(event.get("event_type") or event.get("event"))[:64],
                "function": self._text(event.get("function"))[:256],
                "ip": self._text(event.get("ip"))[:512],
                "port": min(port, 65_535),
                "data_hex": self._text(event.get("data_hex") or event.get("data"))[:8_192],
                "size": self._nonnegative_int(event.get("size")),
                "url": self._text(event.get("url"))[:2_048],
                "headers": self._text(event.get("headers"))[:8_192],
                "timestamp": self._json_safe(event.get("timestamp", "")),
            })

        runtime_log = []
        runtime_limit = 10_000
        for event in runtime_events[:runtime_limit]:
            if not isinstance(event, dict):
                continue
            payload = self._load_json_object(event.get("payload_json"))
            runtime_log.append({
                "event": self._text(event.get("event_type") or payload.get("event"))[:128],
                "payload": self._json_safe(payload),
                "timestamp": self._text(event.get("logged_at") or event.get("timestamp")),
            })

        return {
            # Schema version for future compatibility
            "_schema":  "aidebug/session/v2",
            "_exported": datetime.now(timezone.utc).isoformat(),
            "_privacy_notice": (
                "Dynamic API and network records may contain sensitive arguments, "
                "URLs, headers, addresses, or payload excerpts. Handle accordingly."
            ),

            # Binary metadata
            "binary": {
                "filename":   self._text(session.get("filename")),
                "path":       self._text(session.get("binary_path")),
                "sha256":     self._text(session.get("sha256")),
                "arch":       self._text(session.get("arch")),
                "bits":       self._nonnegative_int(session.get("bits")),
                "os_target":  self._text(session.get("os_target")),
            },

            # Session metadata
            "session": {
                "id":          self._json_safe(session.get("id")),
                "created_at":  self._text(session.get("created_at")),
            },

            # High-level summary — ideal for SIEM dashboard fields
            "summary": {
                "total_functions":    len(functions),
                "analyzed_functions": sum(1 for f in functions if f['ai']['summary']),
                "risk_counts":        risk_summary,
                "mitre_techniques":   mitre_techniques,
                "api_calls_logged":   len(api_log),
                "api_calls_truncated": len(api_calls) > api_limit,
                "network_events_logged": len(network_log),
                "network_events_truncated": len(network_events) > network_limit,
                "runtime_events_logged": len(runtime_log),
                "runtime_events_truncated": len(runtime_events) > runtime_limit,
                "highest_risk":       self._highest_risk(risk_summary),
                "ioc_strings":        self._collect_ioc_strings(functions),
            },

            # Full function list
            "functions": functions,

            # Win32 API call log (dynamic mode only)
            "api_calls": api_log,

            # Bounded dynamic network telemetry. Payload and header fields can
            # contain sensitive material; see _privacy_notice.
            "network_events": network_log,

            # Other bounded dynamic evidence, including executable protection
            # transitions. These are heuristic observations, not unpack/OEP proof.
            "runtime_events": runtime_log,
        }

    # ------------------------------------------------------------------

    def _load_json_field(self, record: dict, key: str, default):
        raw = record.get(key)
        if not raw:
            return default
        if isinstance(raw, (list, dict)):
            return self._json_safe(raw)
        try:
            return self._json_safe(json.loads(raw))
        except (TypeError, ValueError, json.JSONDecodeError):
            return default

    def _load_json_object(self, raw: Any) -> dict:
        if isinstance(raw, dict):
            return raw
        if not isinstance(raw, str) or not raw:
            return {}
        try:
            value = json.loads(raw)
        except (ValueError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    def _json_list(self, record: dict, key: str) -> list:
        value = self._load_json_field(record, key, [])
        return value if isinstance(value, list) else []

    def _risk_level(self, value: Any) -> str:
        level = value.strip().upper() if isinstance(value, str) else "UNKNOWN"
        return level if level in RISK_LEVELS else "UNKNOWN"

    def _nonnegative_int(self, value: Any) -> int:
        if isinstance(value, bool):
            return 0
        try:
            number = int(value, 0) if isinstance(value, str) else int(value)
        except (TypeError, ValueError, OverflowError):
            return 0
        return max(0, number)

    def _text(self, value: Any) -> str:
        return value if isinstance(value, str) else "" if value is None else str(value)

    def _text_list(self, value: Any) -> list[str]:
        return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []

    def _dict_list(self, value: Any) -> list[dict]:
        if not isinstance(value, list):
            return []
        return [self._json_safe_dict(item) for item in value if isinstance(item, dict)]

    def _json_safe_dict(self, value: Any) -> dict:
        if not isinstance(value, dict):
            return {}
        return {
            str(key): self._json_safe(item)
            for key, item in value.items()
        }

    def _json_safe(self, value: Any) -> Any:
        """Return a standards-compliant JSON value for data from external stores."""
        if value is None or isinstance(value, (str, bool, int)):
            return value
        if isinstance(value, float):
            return value if math.isfinite(value) else None
        if isinstance(value, list):
            return [self._json_safe(item) for item in value]
        if isinstance(value, dict):
            return self._json_safe_dict(value)
        return str(value)

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
        skip_markers = {
            "This program cannot be run in DOS mode",
            ".text",
            ".data",
            ".rdata",
            ".reloc",
            "!This",
            "RSDS",
        }
        iocs = []
        seen = set()
        for func in functions:
            if func['ai']['risk_level'] not in ('CRITICAL', 'HIGH'):
                continue
            for s in func.get('strings_referenced', []):
                if (
                    isinstance(s, str)
                    and len(s) > 5
                    and s not in seen
                    and not any(marker in s for marker in skip_markers)
                ):
                    iocs.append({
                        "value":    s,
                        "function": func.get('name', ''),
                        "address":  func.get('address', ''),
                        "risk":     func['ai']['risk_level'],
                    })
                    seen.add(s)
        return iocs[:50]   # cap at 50 IOCs
