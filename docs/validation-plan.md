# Validation Plan

This plan defines how AIDebug behavior should be evaluated without publishing
live malware.

## Evaluation Inputs

Use safe inputs:

- toy programs with known behavior
- mock trace records
- sanitized public report excerpts
- generated PE/ELF fixtures that do not perform harmful actions

Do not use live malware in the repository.

## What To Measure

| Area | Evidence |
|---|---|
| Pattern detection | Expected pattern names and severities |
| ATT&CK mapping | Technique candidate plus behavior evidence |
| JSON export | Schema stability and field completeness |
| YARA output | Syntax and false-positive review notes |
| Reports | Analyst-readable explanation and source evidence |
| CLI behavior | Stable help, reporting, and session commands |

## Current Baseline

- Tests run in CI on Python 3.10, 3.11, 3.12, and 3.13.
- CI separately exercises the headless TUI at the declared Textual 0.52.0 floor
  and installs/imports the Frida 17.x dynamic extra on Python 3.12.
- CI runs Ruff, Bandit, declared-dependency audits, secret scanning, exact
  release metadata checks, package builds, Twine validation, and a fresh-wheel
  offline static-analysis smoke test.
- The mock YARA candidate is compiled with `yara-python` in CI.
- Fresh-wheel smoke tests also generate and compile a deterministic offline
  YARA candidate from `/bin/true` analysis without installing remote-AI code in
  the wheel environment.
- Safe mock JSON, YARA, and HTML outputs are available in `examples/mock-output/`.
- Illustrative screenshots and mock output are integrity checked but are not
  treated as accuracy evidence.
- Deterministic tests cover CLI, offline/remote boundaries, storage, reporting,
  pattern detection, dynamic message handling, and release metadata.

## Acceptance Criteria For New Rules

New pattern detectors should include:

- a short behavior description
- severity rationale
- at least one positive unit test
- at least one negative or non-triggering case when practical
- documentation of likely false positives
