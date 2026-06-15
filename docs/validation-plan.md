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

- CLI smoke tests run in CI on Python 3.10, 3.11, and 3.12.
- Package build runs in CI.
- Safe mock JSON, YARA, and HTML outputs are available in `examples/mock-output/`.
- Deterministic unit tests cover core pattern detection and JSON export behavior.

## Acceptance Criteria For New Rules

New pattern detectors should include:

- a short behavior description
- severity rationale
- at least one positive unit test
- at least one negative or non-triggering case when practical
- documentation of likely false positives
