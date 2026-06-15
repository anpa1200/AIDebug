# Roadmap

This roadmap is intentionally conservative. AIDebug should become more useful
to malware analysts by becoming more reproducible, better documented, and more
careful about evidence quality.

## 1.1: Reproducible Analysis Baseline

- Add a larger safe benchmark corpus made from toy binaries and mock traces.
- Add expected outputs for ATT&CK candidates, risk labels, IOC extraction, and
  YARA fallback generation.
- Add JSON schema validation for exported sessions.
- Add tests for static analyzer edge cases across PE and ELF samples.

## 1.2: Analyst Review Workflow

- Add a review status field to exported findings.
- Separate generated hypotheses from analyst-confirmed findings.
- Add report sections for false-positive notes and reviewer decisions.
- Add import/export examples for SIEM and CTI platforms.

## 1.3: Dynamic Mode Hardening

- Add clearer sandbox setup guidance for Frida, Wine, and INetSim workflows.
- Add safer defaults around process attach and remote Frida hosts.
- Add dynamic-mode mock tests that do not execute malware.

## 1.4: Packaging And Distribution

- Continue Kali, REMnux, and BlackArch submission tracking.
- Add reproducible package build notes.
- Add install smoke tests for fresh virtual environments.

## Curated-List Readiness

Before resubmitting to strict curated lists, collect:

- multiple tagged releases
- passing CI history
- public usage evidence or third-party feedback
- complete documentation for install, use, safety, and limitations
- clear maintainer and security policy files
