# AIDebug in REMnux

Status verified **8 October 2026**. REMnux accepted AIDebug on 7 October through
[salt-states PR #355](https://github.com/REMnux/salt-states/pull/355), and first
included its state in
[v2026.41.4](https://github.com/REMnux/salt-states/releases/tag/v2026.41.4).
The official documentation added it under static code analysis and AI tools in
[commit d30aee6](https://github.com/REMnux/docs/commit/d30aee6f676dc90de66e5a58bf39bc33e52172f6).
Inclusion is distribution integration, not a security certification, detection
benchmark, or measurement of user adoption.

## What the accepted state installs

The [versioned state](https://github.com/REMnux/salt-states/blob/v2026.41.4/remnux/python3-packages/aidebug.sls)
matches the [current upstream state](https://github.com/REMnux/salt-states/blob/master/remnux/python3-packages/aidebug.sls)
at this check. It creates `/opt/aidebug`, installs unpinned
`1200km-aidebug[ai]` from PyPI with `upgrade: True`, and symlinks
`/usr/local/bin/aidebug` to `/opt/aidebug/bin/aidebug`.

The [maintainer adjustment](https://github.com/REMnux/salt-states/commit/0b8b812aeceb9113bba977f4f0c8ae0d698c26df)
changed the submitted pinned base package to `[ai]`, enabled upgrades, and added
the `--offline` warning. The repository's
[original pinned state](../packaging/remnux/aidebug.sls) remains historical
submission evidence; use upstream for actual REMnux provisioning.

Pinning the Salt-state release does **not** pin the PyPI package it resolves.
On 8 October the latest published package is 3.0.0; source is 3.1.0. REMnux
inclusion does not publish 3.1 or enable its String Intelligence commands.
For those, use a separate environment and the
[reviewed source installation](../README.md#reviewed-310-source).

## Verify the installed environment

Follow the [official REMnux documentation](https://docs.remnux.org/) for
installing/updating your lab. Verify the executable and installed package:

```bash
command -v aidebug
aidebug --version
aidebug --help
/opt/aidebug/bin/python3 -m pip show 1200km-aidebug
```

A safe published-package smoke inspects the local system ELF without executing it:

```bash
mkdir -p case/reports
aidebug --binary /bin/true --offline --no-tui --max-functions 5 \
  --json-export --out-dir case/reports --db case/aidebug.sqlite
```

This documentation update verifies upstream source and release records; it
does not claim a new REMnux VM installation or Salt execution test.

## Optional capabilities and data handling

The `[ai]` extra installs Anthropic/OpenAI clients and the local YARA compiler
binding. It does not configure a key, guarantee provider/model availability,
or install `[dynamic]`. A Frida package in another REMnux environment does not
establish availability inside `/opt/aidebug`.

Ghidra and compatible Java, GDB, an ELF-capable C compiler, usable Bubblewrap
and user namespaces, Frida target-side components, and any Ollama model/server
remain workflow-specific requirements. The AIDebug Salt state does not
provision these tools. Consult the [analyst workflow](analyst-workflow.md).

Use `--offline` for local analysis. Remote AI can send sample evidence to the
configured provider; bulk use requires `--accept-ai-cost`. Configure a private
file explicitly through `AIDEBUG_ENV_FILE`, following
[provider setup](../README.md#ai-providers) and the
[remote-data boundary](safety-model.md#remote-ai-data-boundary).
GDB launches its target; Frida instruments a running process. Use execution
features only in an isolated, authorized lab.
