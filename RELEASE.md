# Release Process

This checklist keeps AIDebug releases reviewer-friendly and package-ready.
Historical release artifacts are immutable. The source tree is prepared for
v3.1.0; it becomes a published release only after the version-matched tag and
GitHub release complete the verified workflow. The current published release is
[v3.0.0](https://github.com/anpa1200/AIDebug/releases/tag/v3.0.0), and its
[PyPI package](https://pypi.org/project/1200km-aidebug/3.0.0/) is built and
smoke-tested from that exact version-matched tag by the verified publishing
workflow.

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

1. Review the release PR, record the owner's release consent, and merge only
   after every required CI check passes for the final candidate. Follow the
   [solo-maintainer policy](#solo-maintainer-review-and-release-approval).
2. Create tag `vX.Y.Z` at that exact commit.
3. Create the GitHub release for that tag and use
   `docs/release-notes/vX.Y.Z.md` as the release body.
4. The publish workflow rejects GitHub prereleases, verifies tag/version
   consistency and that the release commit is on the default branch, requires
   a successful `secret-scan` check for that exact commit, repeats the required
   checks, builds once, and publishes that tested artifact with PyPI Trusted
   Publishing. Existing PyPI files are an error; they are never silently
   skipped.
5. Owner `anpa1200` approves the waiting `pypi` environment deployment after
   verifying the tag, commit and required validation. This deployment approval
   is separate from prior consent to prepare or publish a release.
6. Verify the PyPI provenance points to the intended tag and commit.

If GitHub delivery or an external service interrupts publishing after the tag
and release exist, retry the immutable tag from the default branch without
moving or recreating it:

```bash
gh workflow run publish.yml --ref main -f release_tag=vX.Y.Z
```

## Post-Release

- Check PyPI metadata renders correctly.
- Check README screenshot links.
- Update external submission references only after the release exists.

## Repository Settings Required

Repository files cannot enforce these controls. Before release, an owner must:

- protect `main` with mandatory pull requests and all required CI checks;
  configure **zero required approving reviews** under the solo-maintainer
  policy below;
- protect release tags such as `v*` from modification or deletion;
- enable Dependabot security updates and alerts;
- enable GitHub secret scanning and push protection where the plan supports it;
- enable code scanning or an equivalent maintained SAST integration;
- enable and monitor GitHub private vulnerability reporting;
- require owner `anpa1200` approval on the protected `pypi` environment; allow
  that owner to approve their own workflow run so a second account is not
  required, and retain the deployment approval in GitHub's environment record.

## Solo-Maintainer Review and Release Approval

Owner `anpa1200` approved this policy on **9 October 2026**. A release still
requires a reviewable pull request, passing CI and recorded owner consent.
GitHub's required approving-review count is **zero**: the owner is the sole
maintainer and cannot submit an approving PR review to a PR authored by the
same account. No second reviewer or second account is required.

Require all ten current CI job contexts on `main`: `secret-scan`, `quality`,
`test (3.10)`, `test (3.11)`, `test (3.12)`, `test (3.13)`, `textual-floor`,
`dynamic-extra`, `dependency-audit`, and `build`. Verify their names against
the actual workflow checks when configuring protection. Record the owner's
review and release consent in the release PR or linked release record. Prior
conditional consent does not establish that the final candidate passed its
checks or that publication has occurred.

The owner must separately approve the `pypi` deployment. Keep required CI,
version-tag protection and the remaining repository controls enforced; the
zero PR-approval count does not waive those gates. Complete the required live
provider validation for the 3.1 candidate before publication, in addition to
the automated release gate and exact-commit CI checks.

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
