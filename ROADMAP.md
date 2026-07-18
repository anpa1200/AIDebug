# Roadmap

This roadmap is intentionally conservative. AIDebug should become more useful
to malware analysts by becoming more reproducible, better documented, and more
careful about evidence quality.

## Next: Reproducible Analysis Baseline

- Add a larger safe benchmark corpus made from toy binaries and mock traces.
- Add expected outputs for ATT&CK candidates, risk labels, IOC extraction, and
  YARA fallback generation.
- Add JSON schema validation for exported sessions.
- Add tests for static analyzer edge cases across PE and ELF samples.

## Later: Analyst Review Workflow

- Add a review status field to exported findings.
- Separate generated hypotheses from analyst-confirmed findings.
- Add report sections for false-positive notes and reviewer decisions.
- Add import/export examples for SIEM and CTI platforms.

## Later: Dynamic Mode Hardening

- Add clearer sandbox setup guidance for Frida, Wine, and operator-managed
  network-simulation workflows.
- Add safer defaults around process attach and remote Frida hosts.
- Add safe live-fixture integration coverage across explicitly supported target
  operating systems and architectures; current tests exercise mock contracts.

## Packaging And Distribution

- Revisit deferred/closed distribution proposals only after their documented
  maturity gates are met; continue accurate status tracking for open proposals.
- Validate Debian/Kali and REMnux proposals on their actual target
  distributions before claiming support.
- Evaluate bit-for-bit reproducible builds and a release SBOM in addition to
  the existing isolated build, wheel smoke, and PyPI provenance checks.

## Curated-List Readiness

Before resubmitting to strict curated lists, collect:

- multiple tagged releases
- passing CI history
- public usage evidence or third-party feedback
- complete documentation for install, use, safety, and limitations
- clear maintainer and security policy files
