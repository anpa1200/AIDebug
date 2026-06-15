# Contributing

Contributions are welcome when they improve correctness, reproducibility, or defensive value.

Good contributions include bug fixes, parser improvements, safer defaults, tests, and clearer analyst documentation.

Open an issue before large rewrites.

## Pull Requests

- Keep PRs focused.
- Include tests where practical.
- Update docs when behavior changes.
- Keep offensive content framed for authorized defensive work.

## Safe Reproduction Data

Do not upload live malware, weaponized samples, private customer data, or
unredacted incident material. Good reproduction material includes:

- toy source code
- synthetic binaries
- redacted logs
- hashes and metadata
- mock JSON traces
- sanitized disassembly excerpts

## Mapping And Detection Changes

Changes to ATT&CK mappings, risk labels, or YARA output should include:

- the behavior evidence that supports the change
- expected false positives or false negatives
- at least one deterministic test when practical
- documentation updates if analyst interpretation changes
