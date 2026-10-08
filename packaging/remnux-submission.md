# REMnux Submission History: AIDebug

## Accepted integration

Verified 8 October 2026: [PR #355](https://github.com/REMnux/salt-states/pull/355)
merged on 7 October, first included in
[salt-states v2026.41.4](https://github.com/REMnux/salt-states/releases/tag/v2026.41.4).
See [current integration guidance](../docs/remnux.md) for the accepted state,
package track, installed paths and optional requirements.

The [maintainer follow-up](https://github.com/REMnux/salt-states/commit/0b8b812aeceb9113bba977f4f0c8ae0d698c26df)
changed the proposal to unpinned `1200km-aidebug[ai]`, enabled upgrades, and
added the offline/privacy warning. Acceptance does not publish source 3.1.

## Historical deferred proposal and resubmission

REMnux issue #345 was closed on 2026-06-22. The maintainer deferred inclusion
until the project demonstrates ongoing maintenance and greater maturity. A
follow-up comment was posted on 2026-08-11 citing that evidence (66 commits
and three tagged releases — v1.1.0, v2.0.0, v3.0.0 — since the issue closed).
The local state is retained as the version-pinned proposal submitted in
PR #355 on 14 August. It differs from the accepted upstream state.

Candidate Salt state: `packaging/remnux/aidebug.sls`

Upstream destination:

```text
remnux/python3-packages/aidebug.sls
```

Upstream `remnux/python3-packages/init.sls` include:

```yaml
  - remnux.python3-packages.aidebug
```

## Historical proposal validation command

The original PR records testing the submitted state with:

```bash
salt-call -l debug --local --retcode-passthrough --state-output=mixed state.sls remnux.python3-packages.aidebug
aidebug --help
```

## Links

- Repository: https://github.com/anpa1200/AIDebug
- Release: https://github.com/anpa1200/AIDebug/releases/tag/v3.0.0
- PyPI: https://pypi.org/project/1200km-aidebug/
- REMnux proposal: https://github.com/REMnux/salt-states/issues/345

## Notes

The historical proposal installs the reviewed v3.0.0 PyPI package into `/opt/aidebug` using
REMnux's virtualenv pattern and creates `/usr/local/bin/aidebug`. It deliberately
does not track or upgrade to the latest PyPI release. The accepted state does.
These historical checks do not establish a new validation of the adjusted
state or an installed REMnux image.
