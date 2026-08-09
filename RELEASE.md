# Release Process

This checklist keeps AIDebug releases reviewer-friendly and package-ready.
The public v1.1.0 artifacts are historical and immutable. The source tree is
prepared as v1.3.4; its package is not public until an exact `v1.3.4` tag and
GitHub release complete the verified publishing workflow.

## Pre-Release

- Update `pyproject.toml` version.
- Update `CHANGELOG.md`.
- Add `docs/release-notes/vX.Y.Z.md`.
- Update `CITATION.cff`.
- Update package/discovery links if the public release tag changes.
- Confirm no live malware samples are added.
- Review remote-AI data handling and safe-example provenance.
- Confirm the working tree is clean and the release commit is on the protected
  default branch.

## Verification

Node.js must be available so the gate can syntax-check all bundled Frida
JavaScript.

```bash
./scripts/release-readiness.sh
```

The script creates isolated validation and wheel-smoke virtual environments.

The local gate checks release metadata, Ruff, tests, Bandit, installed
dependencies, declared dependency vulnerabilities, distribution contents,
Twine metadata, installation/import of the Frida 17.x dynamic extra,
installation from the built wheel, bundled runtime data, and a safe static parse
of `/bin/true`. CI additionally scans repository history with Gitleaks. The
optional-extra check is not live target-OS instrumentation evidence. A release
is not accepted when any required gate fails.

## GitHub Release

1. Merge the release commit after required CI checks pass.
2. Create tag `vX.Y.Z` at that exact commit.
3. Create the GitHub release for that tag and use
   `docs/release-notes/vX.Y.Z.md` as the release body.
4. The publish workflow rejects GitHub prereleases, verifies tag/version
   consistency and that the release commit is on the default branch, repeats
   the required checks, builds once, and publishes that tested artifact with
   PyPI Trusted Publishing. Existing PyPI files are an error; they are never
   silently skipped.
5. Verify the PyPI provenance points to the intended tag and commit.

## Post-Release

- Check PyPI metadata renders correctly.
- Check README screenshot links.
- Update external submission references only after the release exists.

## Repository Settings Required

Repository files cannot enforce these controls. Before release, an owner must:

- protect `main` with required CI checks and review requirements;
- protect release tags such as `v*` from modification or deletion;
- enable Dependabot security updates and alerts;
- enable GitHub secret scanning and push protection where the plan supports it;
- enable code scanning or an equivalent maintained SAST integration;
- enable and monitor GitHub private vulnerability reporting;
- require approval on the protected `pypi` environment.

## Known Packaging Blockers

- The Debian/Kali files are a proposal whose offline path is tested locally and
  in autopkgtest metadata; it still needs a clean target-distribution build and
  maintainer review. The local Ubuntu Noble apt snapshot is below the declared
  Capstone, pyelftools, and Textual floors, so it is not package-validation
  evidence. Remote AI and Frida need separate package decisions.
- The wheel currently installs generic top-level modules and packages such as
  `config`, `analysis`, `storage`, and `ui`. Moving them below an `aidebug`
  namespace is structural work for a future compatibility-planned release.
- REMnux and Kali files must be tested in their actual target distributions;
  local metadata validation is not an upstream acceptance result.
