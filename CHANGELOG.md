# Changelog

## Unreleased

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
