# Release Readiness

This document separates repeatable repository checks from operator-controlled
release and deployment decisions. Passing the local script makes a commit a
release candidate; it does not publish it or prove third-party adoption.

## Repeatable Gate

From a supported Python environment with Node.js available for Frida-script
syntax checks:

```bash
./scripts/release-readiness.sh
```

The script creates isolated validation and wheel-smoke virtual environments;
it does not audit unrelated packages in the caller's active environment.

The gate verifies:

- version consistency across Python, citation, changelog, Debian, man-page, and
  release-note metadata;
- exact dependency-specifier consistency between `pyproject.toml` and
  `requirements.txt`;
- Ruff, pytest, Bandit, `pip check`, and `pip-audit`;
- installation/import validation for the optional Frida 17.x `dynamic` extra;
- local compilation and broad-rule screening for AI-backed YARA candidates;
- wheel and source-distribution metadata with Twine;
- required JavaScript and heuristic signature data in the wheel;
- absence of known generated reports, databases, bytecode, and duplicate
  signature databases in distribution archives;
- installation from the built wheel plus safe static ELF parsing and offline
  JSON/YARA generation smokes.

GitHub CI repeats these checks on supported Python versions, installs and
imports the optional dynamic extra on Python 3.12, exercises its mock contracts,
exercises the headless TUI against the declared `textual==0.52.0` compatibility
floor, and adds a pinned Gitleaks history scan. These checks do not replace live
Frida validation on each target OS/architecture. The TUI floor is a
compatibility check for the tested headless workflows, not a claim that every
future Textual version is compatible. The release workflow checks out the
GitHub release tag, requires it to match the package version and belong to the
default-branch history, rejects GitHub prereleases, validates it, builds exactly
once, and passes that same artifact to PyPI Trusted Publishing.

## Evidence Boundaries

The repository screenshots and mock reports are illustrative examples. They are
not automated acceptance evidence and must not be used to claim detection
accuracy. Tests and workflow logs are the repeatable evidence for a specific
commit. PyPI provenance is the evidence that a published file came from a
specific release workflow, tag, and source commit.

## Manual Release Controls

An owner must verify all of the following outside the source tree:

- `main` and `v*` tags are protected;
- required CI checks and review are enforced;
- the `pypi` environment requires appropriate approval;
- Dependabot alerts/security updates, secret scanning/push protection, and code
  scanning are enabled where available;
- private vulnerability reporting is enabled and monitored;
- release notes describe only features in the tagged commit;
- the public package is installed in a fresh isolated environment;
- Debian/Kali and REMnux proposals are not described as accepted or validated
  until their upstream maintainers and target systems confirm them.

## Current Status

The current public version is v1.1.0. Work under `Unreleased` is post-v1.1.0
and needs a new version/tag. The Debian/Kali proposal supports only the tested
offline base until optional AI/Frida dependency decisions are made, and it has
not been accepted or validated on current Kali builders. The checked Ubuntu
Noble repository is below several declared dependency floors and is not Kali
validation. The generic top-level Python package layout also remains
compatibility debt for a future namespace migration. The public Medium article
and open Kali request still contain older, broader capability/dependency claims;
update those external pages before using them to promote the next release.
