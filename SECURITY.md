# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| latest `main` | Best-effort fixes and development validation |
| latest PyPI release | Yes |
| older releases and branches | No, unless a security advisory says otherwise |

## Reporting A Vulnerability

Report security issues privately to `1200km@gmail.com`.

Do not open a public GitHub issue for a vulnerability.

The maintainer will acknowledge a reproducible report and coordinate a
disclosure timeline based on severity and fix availability. Do not assume that
emailing a sample authorizes execution or third-party AI submission.

The `--identify` command performs deterministic local classification first.
Only when the result remains unknown and AI is enabled may it send bounded
metadata to the configured provider: extension, size, SHA-256, up to 96 header
bytes, 32 tail bytes, sample entropy, and NUL ratio. It does not send the file
body, extracted strings, or filesystem path. Use `--offline` to prohibit that
request.

## Scope

This policy covers vulnerabilities in this repository's code, packaging, examples, and documentation. It does not cover third-party services, external APIs, or lab targets.

Reports should include the affected version or commit, a safe reproduction, and
impact. Do not attach live malware, API keys, customer evidence, or unredacted
session databases.
