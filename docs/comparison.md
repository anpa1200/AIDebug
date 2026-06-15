# Comparison

AIDebug is not intended to replace full reverse-engineering suites. It sits
between first-pass triage and deeper manual analysis.

| Tool Type | Strength | AIDebug Role |
|---|---|---|
| Disassembler | Deep manual reverse engineering | Adds triage summaries and report output |
| Sandbox | Runtime behavior and detonation telemetry | Adds function-level notes and export artifacts |
| YARA tooling | Rule authoring and testing | Generates analyst-review seed rules |
| CTI platform | Knowledge management and enrichment | Produces JSON and IOC material for ingest |
| AIDebug | Triage to detection handoff | Combines patterns, ATT&CK candidates, reports, and exports |

## Where AIDebug Fits

Use AIDebug when the analyst needs:

- a quick structured view of suspicious functions
- a reportable summary for a case note
- candidate ATT&CK mappings to review
- early YARA and IOC material for detection engineering
- repeatable JSON output from a triage session

Use a full disassembler, sandbox, and manual review when the investigation
requires exploit analysis, unpacking, protocol reconstruction, attribution, or
production-quality detections.
