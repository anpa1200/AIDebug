# Kali Linux New Tool Request: AIDebug

Submit under **New Tool Requests** at <https://bugs.kali.org/>.

Do not submit this through `kali-meta`; Kali maintainers directed new tool
requests to the bug tracker workflow documented at:
<https://www.kali.org/docs/tools/submitting-tools/>.

## Summary

aidebug - AI-assisted malware reverse-engineering debugger

## Description

[Name] - AIDebug

[Version] - 1.1.0

Use the tagged release, not a moving branch:
<https://github.com/anpa1200/AIDebug/releases/tag/v1.1.0>

[Homepage] - <https://github.com/anpa1200/AIDebug>

[Download] -

- Release: <https://github.com/anpa1200/AIDebug/releases/tag/v1.1.0>
- PyPI: <https://pypi.org/project/1200km-aidebug/>

[Author] - Andrey Pautov

[Licence] - MIT

[Description] - AIDebug is a Python malware-analysis and reverse-engineering
CLI/TUI that turns function-level behavior into ATT&CK mappings, IOC exports,
YARA seed rules, JSON output, and analyst HTML reports. It supports PE and ELF
triage, Capstone disassembly, behavioral pattern detection, optional Frida
dynamic instrumentation, and optional AI-backed explanation. The AI features are
optional; the core analysis path still produces structured analyst outputs
without an API key.

[Dependencies] -

Runtime Python dependencies:

- Python >= 3.10
- anthropic >= 0.40
- capstone >= 5
- pefile >= 2023.2.7
- pyelftools >= 0.31
- rich >= 13.0.0
- textual >= 0.52.0

Optional dynamic-analysis dependency:

- frida >= 16

[Similar tools] - radare2/rizin, cutter, ghidra, edb-debugger, pefile,
detect-it-easy, yara, capa. AIDebug is not a replacement for those tools; it is
a fast triage layer that produces detection-oriented outputs from function
behavior.

[Activity] - Active. Public release v1.1.0 was prepared on 2026-06-15. The
project includes PyPI packaging, GitHub release artifacts, CI, tests, safe demo
examples, Debian/Kali packaging metadata, a man page, and autopkgtest metadata.

[How to install] -

From the tagged PyPI release:

```bash
pipx install 1200km-aidebug
aidebug --help
```

Or from the release source archive:

```bash
wget https://github.com/anpa1200/AIDebug/archive/refs/tags/v1.1.0.tar.gz
tar -xf v1.1.0.tar.gz
cd AIDebug-1.1.0
python3 -m venv .venv
. .venv/bin/activate
pip install .
aidebug --help
```

[How to use] -

```bash
aidebug --help
aidebug --binary ./sample.exe --no-tui --report --json-export --out-dir ./reports
aidebug --binary ./sample.elf --no-ai --no-tui --json-export --out-dir ./reports
```

AI-backed function explanations and YARA generation require `ANTHROPIC_API_KEY`.
Static parsing, disassembly, pattern detection, IOC extraction, and report
generation can run without AI.

[Packaged] - Not currently packaged in Debian or Kali. Upstream includes
Debian/Kali packaging metadata under `debian/`, a man page, and autopkgtest
metadata to make Kali review easier.
