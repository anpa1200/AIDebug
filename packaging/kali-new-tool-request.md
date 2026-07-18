# Historical Kali Tracking Note: AIDebug

The linked `kali-meta` work item was closed on 2026-06-16. Its decision text was
not independently captured. A separate official Kali New Tool Request,
[issue 0009743](https://bugs.kali.org/view.php?id=9743), remains `new`/open as
of 2026-07-18 and contains stale v1.0.0 metadata. Use
`docs/kali-new-tool-request.md` for a future update to that existing request;
do not open a duplicate or describe this historical file as an active request.

## Tool

AIDebug is an AI-assisted malware reverse-engineering debugger and triage CLI.
It turns function-level evidence into deterministic offline findings, optional
remote-AI ATT&CK candidates, YARA seeds, versioned JSON with heuristic IOC
strings, and HTML analyst reports.

## Links

- Repository: https://github.com/anpa1200/AIDebug
- Release: https://github.com/anpa1200/AIDebug/releases/tag/v1.1.0
- PyPI: https://pypi.org/project/1200km-aidebug/
- Documentation/article: https://medium.com/@1200km/ai-powered-malware-debugger-that-explains-every-function-it-sees-2a28ef75df8a
- Kali request: https://gitlab.com/kalilinux/packages/kali-meta/-/work_items/26
- Official Kali New Tool Request: https://bugs.kali.org/view.php?id=9743

## Install

```bash
pip install 1200km-aidebug
aidebug --help
```

Optional dynamic tracing:

```bash
pip install "1200km-aidebug[dynamic]"
```

## Debian/Kali packaging status

This repository includes Debian/Kali package metadata under `debian/`:

- `debian/control`
- `debian/changelog`
- `debian/rules`
- `debian/watch`
- `debian/copyright`
- `debian/tests/control`
- `debian/aidebug.1`

## Package metadata

- Source package: `aidebug`
- Binary package: `aidebug`
- CLI: `aidebug`
- License: MIT
- Language: Python
- Version: 1.1.0

## Safety

The tool is intended for authorized malware-analysis labs and isolated VMs.
Static analysis can inspect binaries without executing them. Dynamic Frida mode
should be used only in controlled environments.
