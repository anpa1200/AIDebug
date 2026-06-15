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
- JSON, HTML, IOC, and report output
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

1. Run the local test suite.
2. Build the Python package.
3. Update `CHANGELOG.md`.
4. Tag the release.
5. Publish the package.
6. Update external submission tracking in `DISCOVERY.md`.
