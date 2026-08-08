# Analyst Workflow

This workflow describes how to use AIDebug as a triage accelerator in a malware
analysis lab. It does not replace manual reverse engineering.

## 1. Prepare The Lab

- Use an isolated malware-analysis VM or sandbox.
- Disable shared clipboard and shared folders unless required.
- Keep live samples out of GitHub issues, pull requests, and documentation.
- Store case files in a controlled evidence directory.
- Select a per-case database with `--db`; do not mix unrelated investigations.

## 2. Run Static Triage

```bash
aidebug --binary sample.exe --offline --no-tui --report --json-export \
  --db case/session.db --out-dir case/reports/
```

Offline mode uses local deterministic pattern evidence. For optional remote AI,
install the `ai` extra, review the remote-data policy, set
`ANTHROPIC_API_KEY`, and add `--accept-ai-cost` to bulk commands.

Review:

- binary metadata
- function list
- suspicious behavior patterns
- deterministic findings and any optional remote ATT&CK candidates
- strings referenced by high-risk functions
- generated HTML and JSON outputs

### C source triage

With Bubblewrap and an ELF-capable compiler installed, analyze one C
translation unit without executing it:

```bash
aidebug --source sample.c --offline --no-tui --report \
  --db case/source-session.db --out-dir case/reports/
```

The source is capped at 2 MiB, copied into a filesystem sandbox, compiled into
a temporary ELF shared object, and removed after parsing. The session keeps the
source hash and compiled-artifact hash. Local project headers and multi-file
builds are not supported. Do not use `--mode dynamic` or `--yara` with source
input.

### Optional pseudo-source view

Request local heuristic pseudo-C or C++-style output during PE, ELF, or C-source
analysis:

```bash
aidebug --binary sample.elf --offline --no-tui --decompile
aidebug --source sample.c --offline --no-tui --decompile cpp
```

The result is stored per function and appears in the TUI, HTML report, and JSON
export. Treat it as a readability aid. Confirm control flow and data types in a
full disassembler/decompiler before relying on it in an investigation.

## 3. Review Findings

Treat every output as a hypothesis:

- Confirm suspicious functions in a disassembler.
- Compare any heuristic pseudo-source with the underlying instructions and CFG.
- Check whether an ATT&CK technique is supported by behavior evidence.
- Remove weak IOCs and generic strings.
- Test generated YARA candidates against known-good and known-bad files.

## 4. Optional Dynamic Analysis

Dynamic mode is for controlled labs only:

```bash
aidebug --binary sample.exe --mode dynamic --pid 1234 --offline
```

Dynamic mode requires the `dynamic` extra and Frida 17.x. It can record bounded
runtime, API, protection-transition, and network-hook evidence when supported
hooks fire. `--max-functions N` is additionally bounded by a 50-function hook
ceiling in dynamic mode. AIDebug waits for each script's readiness message,
reports its current hook count, and returns a degraded result if a script or
hook reports an instrumentation error. A ready observer with zero current hooks
may attach later when a watched module loads; it is not capture evidence. Verify
address mapping and coverage; this mode is not packet capture, automatic
unpacking, or exhaustive execution tracing.

## 5. Export And Handoff

Use the versioned AIDebug JSON through a reviewed custom adapter and the HTML
report for analyst notes. JSON is not STIX or a vendor-native SIEM/OpenCTI
schema. YARA output is seed material and must be compiled and tested.
