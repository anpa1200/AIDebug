# Changelog

## Unreleased

## 1.3.4 - 2026-08-09

- Added SHA-256-indexed local analysis history. Reopening identical sample
  bytes now announces prior sessions, restores compatible stored function
  analyses without another AI request, and exposes session/evidence summaries
  in the main GUI's new History tab.
- Added `aidebug --history FILE_OR_SHA256` for local lookup when only a sample
  hash remains, plus session mode, analyzer, completion status, and completion
  time metadata in the SQLite store.
- Expanded the real Learning Mode corpus from 47 to 53 standalone C files with
  integer negation, masked-bit testing, variable rotate-right, post-tested
  loops, binary search, and in-place buffer reversal cases.

## 1.3.3 - 2026-08-08

- Integrated real Learning Mode into AIDebug's original full-screen Textual
  GUI. The left catalog selects one standalone source case while synchronized
  panes show its exact C source, compiler-generated assembly, Ghidra
  pseudo-code, lesson guidance, and build provenance.
- Changed `aidebug --learn` and exact lesson commands to open the interactive
  GUI by default. The existing non-interactive catalog and lesson report remain
  available with `--no-tui` for scripts and release smoke tests.

## 1.3.2 - 2026-08-08

- Replaced the shared Learning Mode translation unit with 47 independently
  packaged source files under `learning/cases/`. Selecting a lesson now
  compiles only that case file, then shows that exact file beside its complete
  machine instructions and Ghidra reconstruction.
- Added dedicated real cases for MOV load/store, LEA address calculation, LEA
  arithmetic, MOVZX, MOVSX, MOVSXD, and XCHG. The XCHG case uses explicit
  source-level inline assembly so its compiled artifact reliably contains the
  instruction instead of depending on an optimizer's swap implementation.
- Added source-file provenance to Learning Mode and retained aliases for the
  v1.3.1 data-movement lesson IDs.

## 1.3.1 - 2026-08-08

- Replaced handwritten Learning Mode assembly and pseudo-code cards with 44
  real, safe C functions compiled into a temporary ELF artifact that is never
  executed. AIDebug now resolves the selected symbol, displays its complete
  compiler-generated instructions and bytes, and uses Ghidra to reconstruct
  pseudo-code from that machine code.
- Preserved ELF symbol sizes during static analysis so live lessons can decode
  the complete compiled function, including switch case blocks that recursive
  control-flow discovery cannot reach through an unresolved jump table.
- Added compiler, function address, artifact SHA-256, decompiler provenance,
  source function, and reconstruction warnings to every analyzed lesson.

## 1.3.0 - 2026-08-08

- Added `--decompile-all FILE.c` to reconstruct every discovered function in
  one provenance-marked, owner-only C-like output without overwriting an
  existing analyst file.
- Added structured LLM cross-checks of Ghidra output against bounded assembly,
  control flow, calls, strings, patterns, and runtime evidence whenever remote
  AI analyzes a decompiled function. Results distinguish consistency,
  uncertainty, and contradiction; they never claim recovery of original code.
- Added analyst-controlled local ELF debugging through GDB/MI with symbolic or
  address breakpoints, continue, instruction step/next, function finish,
  complete register access, core-register deltas, disassembly context, and
  calling-convention input/return candidates.
- Added a local `--learn` mode with 44 searchable x86/x64 instruction,
  structure-recovery, Windows-behavior, and internals lessons. Every lesson
  includes assembly, pseudo-code, state effects, an analyst clue, and a common
  misreading.

## 1.2.0 - 2026-08-08

- Added optional `--decompile` integration with Ghidra's headless native-code
  decompiler. Bounded C-like output, backend metadata, and reconstruction
  warnings flow through the CLI, TUI, SQLite session, HTML report, and JSON
  export. The command fails clearly when Ghidra is unavailable and never falls
  back to heuristic register translation presented as decompilation.
- Added bounded `.c` source analysis through a Bubblewrap-isolated, temporary
  ELF compilation path that never executes the generated artifact; source
  provenance and compiled-artifact hashes are retained in sessions and reports.
- Expanded ELF function discovery to retain named local function symbols in
  addition to entry-point, call-target, and exported-function seeds.
- Added fail-closed release metadata, dependency, package-content, wheel smoke,
  lint, test, Bandit, dependency-audit, and secret-scan gates.
- Hardened PyPI publishing so an exact version-matched release tag is tested,
  built once, and the same artifact is published without `skip-existing`.
- Corrected capability, privacy, offline/remote-AI, IOC, integration, dynamic
  instrumentation, screenshot, and packaging claims across the documentation.
- Consolidated the heuristic signature database under `analysis/data/` and
  removed an unreferenced generated malware report from the source tree.
- Expanded safe CLI, analyzer, storage, report, and release metadata tests.
- Added explicit CI/release validation for the Frida 17.x dynamic extra and the
  declared Textual compatibility floor.
- Updated illustrative JSON evidence to the current session schema v2 and
  documented sample, discovery, instruction, and event-retention caps.
- Made remote AI and AI-backed YARA paths explicit, bounded, prompt-isolated,
  locally validated, and fail-closed; deliberate offline analysis remains
  deterministic and does not require the optional AI dependency.
- Hardened PE/ELF parsing, function discovery, disassembly, CFG traversal,
  heuristic descriptions, terminal rendering, TUI request handling, and
  private atomic HTML/JSON/YARA output.
- Added bounded undefined dynamic-symbol extraction for ELF inputs and explicit
  symbol/import/export resource ceilings.
- Serialized SQLite schema migration, made event caps authoritative across
  concurrent connections, and tightened database/sidecar permissions on a
  best-effort basis.
- Added Frida script-readiness and error reporting, ASLR/PIE-aware function
  hooks, bounded event buffers, correct wide-string reads, successful-call byte
  counts, and socket-to-peer correlation for supported Winsock telemetry.
- Added session IDs to generated filenames to prevent cross-session report
  collisions in a shared output directory.

## 1.1.0 - 2026-06-15

- Added reviewer-facing maturity documentation for validation, safety, sample
  evidence, comparison, and curated-list resubmission readiness.
- Added safe mock outputs for JSON, YARA, and HTML report review.
- Added screenshots for the TUI, behavioral pattern tab, CFG view, pattern
  output, and four-panel workflow.
- Expanded deterministic unit coverage for pattern detection and JSON export.
- Clarified that AIDebug outputs analyst-review seed material, not final
  attribution or production-ready detection logic.

## 1.0.0

- Published the first public PyPI package as `1200km-aidebug`.
- Added safe mock outputs for JSON, YARA, and HTML report review.
- Added screenshots for the TUI, behavior tab, CFG view, and pattern output.
- Added Debian/Kali and REMnux packaging notes.
- Added GitHub Actions for tests and package build.
- Added issue templates and a discussion workflow template.
