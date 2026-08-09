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

Ubuntu 24.04 can deny Bubblewrap's UID mapping when AppArmor's unprivileged
user-namespace restriction is enabled but no Bubblewrap profile is loaded. In
that case, install and load AppArmor's `bwrap-userns-restrict` profile. Keep the
global restriction enabled; disabling it weakens protection for every
unconfined application on the host.

### Optional decompiler view

Request local Ghidra C-like output during PE, ELF, or C-source analysis:

```bash
aidebug --binary sample.elf --offline --no-tui --decompile
aidebug --source sample.c --offline --no-tui --decompile \
  --ghidra-headless /opt/ghidra/support/analyzeHeadless
```

Write one combined reconstruction for every discovered function:

```bash
aidebug --binary sample.elf --offline --no-tui \
  --decompile-all case/sample-full.c
```

The destination is created once with owner-only permissions. AIDebug refuses to
overwrite it. “All” remains subject to the 300-function discovery ceiling and
does not imply that stripped, indirect, packed, or unreachable functions were
recovered.

Ghidra must be installed and its `support/analyzeHeadless` launcher available on
`PATH`, in a common installation location, via `AIDEBUG_GHIDRA_HEADLESS`, or via
`--ghidra-headless`. The result is stored per function and appears in the TUI,
HTML report, and JSON export. It is reconstructed C-like code rather than the
original source, so confirm control flow and inferred data types against the
underlying instructions before relying on it in an investigation.

When remote AI analyzes a function with decompiler output, it also returns a
structured cross-check status, confidence, findings, and optional corrected
pseudo-code. This comparison consumes decompiled text at the remote-data
boundary and is a second hypothesis—not semantic-equivalence proof.

## 3. Review Findings

Treat every output as a hypothesis:

- Confirm suspicious functions in a disassembler.
- Compare decompiler reconstruction with the underlying instructions and CFG.
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

### Active local ELF debugging

Active mode is distinct from Frida tracing. It launches a local ELF under GDB
and waits at an analyst-selected symbol or address:

```bash
aidebug --binary ./sample.elf --mode debug --breakpoint main
```

Use `break`, `continue`, `step`, `next`, `finish`, `registers`, `changes`, `io`,
and `disassemble` inside the debugger prompt. Function inputs and outputs are
calling-convention candidates unless GDB provides an explicit return value;
check debug types, stack arguments, and the callee body before treating them as
confirmed. Repeatable `--debug-command` options support controlled automation.
The target executes, so use a disposable, network-controlled VM.

## 5. Learning Mode

Open the 100 bundled real-function lessons in AIDebug's original full-screen
GUI. A search topic filters the left catalog without compiling an artifact:

```bash
aidebug --learn
aidebug --learn "loops and arrays"
```

Selecting a lesson compiles its trusted C function into a temporary,
non-executed ELF, decodes the complete symbol through AIDebug, and reconstructs
pseudo-code through Ghidra. An exact command preselects and opens that lesson:

```bash
aidebug --learn subtract
aidebug --learn switch-dispatch
aidebug --learn movsxd
aidebug --learn binary-search
```

Add `--no-tui` to list lessons or print one analyzed lesson without opening the
interactive GUI.

Each catalog entry maps to one file under `learning/cases/`; only the selected
file is compiled. Learning Mode is local-only and does not create a session
database. Exact lessons require an x86-64 ELF compiler and Ghidra. Output
includes the exact source-file path and contents, compiler and artifact
provenance, real instruction bytes, and Ghidra's explicit non-original-source
warning; it never substitutes handwritten pseudo-code.

Load a separate analyst-maintained collection without copying it into the
package:

```bash
aidebug --learn --learning-collection /path/to/cases
aidebug --learn parse-header --learning-collection /path/to/cases
```

The collection directory requires `case_common.h` and matching `*.c` files;
`collection.json` is optional but recommended for stable ordering and metadata.
The repository's `learning/cases/collection.json` is the 100-case reference.
External source is path-contained and size-validated, but it is still parsed by
the local compiler and should be reviewed before use.

## 6. Export And Handoff

Use the versioned AIDebug JSON through a reviewed custom adapter and the HTML
report for analyst notes. JSON is not STIX or a vendor-native SIEM/OpenCTI
schema. YARA output is seed material and must be compiled and tested.
