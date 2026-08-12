# Changelog

## Unreleased

## 3.1.0 - 2026-08-11

- Added whole-file ASCII, UTF-8, UTF-16LE, and UTF-16BE string extraction with
  stable offsets, mapped addresses, bounded occurrence metadata, exact coverage,
  multi-label security categories, deterministic ranking, and local DLL/API
  descriptions.
- Added a paginated String Intelligence terminal workspace and a dedicated
  owner-only streaming JSON export with length, encoding, category, and search
  filters.
- Added explicit opt-in whole-inventory AI triage with prompt-injection
  isolation, bounded chunks, per-string schema validation, grounded IOC checks,
  circuit breaking, complete coverage accounting, and structured reduction.
- Treat non-loopback Ollama endpoints as remote evidence transfers and require
  the same cost/privacy acknowledgement as other remote providers.
- Hardened domain, IP-address, and configuration detection against short binary
  fragments, malformed maximal tokens, filename overlap, and correlated-category
  confidence inflation. Deterministic and AI IOC checks share the same offline,
  IANA-rooted validation rules.

## 3.0.0 - 2026-08-10

- Expanded the PE workspace with complete TLS directory and callback evidence,
  x64 exception/runtime-function tables, decoded unwind information, load
  configuration fields, and correlated exploit-mitigation assessments.
- Added detailed Control Flow Guard evidence, including check/dispatch
  pointers, Guard flags, and bounded Guard Function ID table parsing.
- Added Authenticode certificate inspection and cryptographic verification,
  Rich-header decoding, Debug Directory and CodeView records, and exact overlay
  inspection/export with explicit evidence boundaries.
- Added managed PE inspection for CLR headers, metadata streams, ECMA-335 table
  layouts, assemblies, references, resources, and strong-name metadata without
  initializing the CLR or executing managed code.
- Added provider-explicit AI configuration for Anthropic, OpenAI, Google
  Gemini, and local Ollama endpoints through a private environment file, with
  fail-closed provider selection and bounded evidence handling.
- Updated the main documentation with the published practical PE-file guide
  and the complete AIDebug 3.0 workflow.

## 2.0.0 - 2026-08-09

- Added the main-GUI Hex / PE workspace. Every loaded binary can be inspected
  through a bounded whole-file hexadecimal view, while PE32 and PE32+ inputs
  additionally expose DOS, NT, COFF, and optional headers, sections, data
  directories, normal and delay imports, exports, forwarders, and overlays.
- Added complete Ghidra-backed reconstruction for discovered functions,
  assembly-grounded optional LLM verification, and analyst-controlled local
  ELF debugging with breakpoints, stepping, register deltas, and function
  input/output candidates.
- Added safe one-file C analysis through isolated temporary ELF compilation,
  with the generated artifact analyzed but never executed.
- Replaced simulated learning cards with 100 independently compiled C cases
  that show original source, real compiler output, and Ghidra pseudo-code in
  the main GUI. Added validated external learning collections with an optional
  schema-versioned manifest.
- Added SHA-256-indexed local analysis history, compatible finding restoration,
  session lifecycle metadata, and file-or-hash history lookup.
- Raised the supported Textual floor to 8.2.8 and consolidated the packaging,
  safety, dependency, reporting, and release-validation contracts for the 2.x
  line.

## 1.3.4 - 2026-08-09

- Added SHA-256-indexed local analysis history. Reopening identical sample
  bytes now announces prior sessions, restores compatible stored function
  analyses without another AI request, and exposes session/evidence summaries
  in the main GUI's new History tab.
- Added `aidebug --history FILE_OR_SHA256` for local lookup when only a sample
  hash remains, plus session mode, analyzer, completion status, and completion
  time metadata in the SQLite store.
- Expanded the real Learning Mode corpus to 100 standalone C files spanning
  instruction semantics, control flow, buffers, parsers, structures, callbacks,
  and reverse-engineering patterns.
- Added `--learning-collection DIR` to validate and load external C lesson
  directories in the original GUI. Optional `collection.json` manifests define
  stable ordering and metadata without allowing source paths to escape the
  collection root.

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
