# REMnux Submission Prep: AIDebug

## Deferred proposal

REMnux issue #345 was closed on 2026-06-22. The maintainer deferred inclusion
until the project demonstrates ongoing maintenance and greater maturity. The
state below is retained only as a version-pinned proposal for a future review;
it is not part of REMnux.

Candidate Salt state: `packaging/remnux/aidebug.sls`

Expected REMnux destination if accepted:

```text
remnux/python3-packages/aidebug.sls
```

Expected `remnux/python3-packages/init.sls` include:

```yaml
  - remnux.python3-packages.aidebug
```

## Validation command

After copying the state into the REMnux salt-states tree:

```bash
salt-call -l debug --local --retcode-passthrough --state-output=mixed state.sls remnux.python3-packages.aidebug
aidebug --help
```

## Links

- Repository: https://github.com/anpa1200/AIDebug
- Release: https://github.com/anpa1200/AIDebug/releases/tag/v1.1.0
- PyPI: https://pypi.org/project/1200km-aidebug/
- REMnux proposal: https://github.com/REMnux/salt-states/issues/345

## Notes

The proposal installs the reviewed v1.1.0 PyPI package into `/opt/aidebug` using
REMnux's virtualenv pattern and creates `/usr/local/bin/aidebug`. It deliberately
does not track or upgrade to the latest unreviewed PyPI release.
