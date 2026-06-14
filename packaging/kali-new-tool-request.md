# Kali Tool Request: AIDebug

## Tool

AIDebug is an AI-assisted malware reverse-engineering debugger and triage CLI.
It turns function-level behavior into MITRE ATT&CK mappings, YARA candidates,
IOC exports, JSON output, and HTML analyst reports.

## Links

- Repository: https://github.com/anpa1200/AIDebug
- Release: https://github.com/anpa1200/AIDebug/releases/tag/v1.0.0
- PyPI: https://pypi.org/project/1200km-aidebug/
- Documentation/article: https://medium.com/@1200km/ai-powered-malware-debugger-that-explains-every-function-it-sees-2a28ef75df8a
- Kali request: https://gitlab.com/kalilinux/packages/kali-meta/-/work_items/26

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
- Version: 1.0.0

## Safety

The tool is intended for authorized malware-analysis labs and isolated VMs.
Static analysis can inspect binaries without executing them. Dynamic Frida mode
should be used only in controlled environments.
