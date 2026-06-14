# REMnux Submission Prep: AIDebug

## Proposed state

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
- Release: https://github.com/anpa1200/AIDebug/releases/tag/v1.0.0
- PyPI: https://pypi.org/project/1200km-aidebug/
- REMnux proposal: https://github.com/REMnux/salt-states/issues/345

## Notes

The state installs the PyPI package into `/opt/aidebug` using REMnux's common
virtualenv pattern and creates `/usr/local/bin/aidebug`.
