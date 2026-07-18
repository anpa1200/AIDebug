# Maintainers

## Current Maintainer

- Andrey Pautov (`@anpa1200`)

## Maintained Scope

AIDebug is maintained as a defensive malware-analysis and reverse-engineering
triage tool. The maintained scope is:

- static PE/ELF inspection and function discovery
- behavioral pattern detection
- ATT&CK candidate mapping
- analyst-reviewed YARA seed generation
- versioned JSON, HTML, heuristic IOC-string, and report output
- optional Frida-based dynamic instrumentation in isolated labs
- packaging for Python, Debian-family labs, Kali, and REMnux-style workflows

Out of scope:

- malware execution on an analyst workstation
- automated attribution claims
- production blocking decisions without human review
- offensive deployment guidance

## Maintenance Commitments

- Review reproducible bug reports and security reports.
- Keep safe demo data and examples free of live malware.
- Keep package metadata, release notes, and install instructions current.
- Prefer deterministic tests for parsers, exporters, and pattern detectors.
- Document false-positive and false-negative limitations.

## Release Process

1. Complete the metadata and release-note updates.
2. Run `./scripts/release-readiness.sh`.
3. Merge only after required CI and review pass.
4. Tag the exact protected release commit.
5. Publish through the protected PyPI environment.
6. Verify PyPI provenance and update external status tracking.
