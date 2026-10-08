# Kali Linux New Tool Request Update: AIDebug

> **Update draft, verified against the 3.0.0 tag and 3.1 source on 8 October
> 2026.** Use the published 3.0.0 release for this package request. Source 3.1
> adds String Intelligence but has no published package yet. Target Kali
> dependency resolution and build validation remain required before submission.

An official Kali **New Tool Requests** issue already exists:
<https://bugs.kali.org/view.php?id=9743>. It was still `new`/open when checked
in the 8 October 2026 audit, and its public description still identifies v1.0.0 and older
dependency/capability claims. Do not open a duplicate. After the
target-distribution build is validated, post a concise correction/update to that
issue using the reviewed information below.

Do not use `kali-meta` as a second request. Kali's documented new-tool process
uses the bug tracker workflow described at:
<https://www.kali.org/docs/tools/submitting-tools/>.

## Summary

aidebug - AI-assisted malware reverse-engineering debugger

## Description

[Name] - AIDebug

[Version] - 3.0.0 (published; source milestone 3.1.0 remains unpublished)

Use the tagged release, not a moving branch:
<https://github.com/anpa1200/AIDebug/releases/tag/v3.0.0>

[Homepage] - <https://github.com/anpa1200/AIDebug>

[Download] -

- Release: <https://github.com/anpa1200/AIDebug/releases/tag/v3.0.0>
- PyPI: <https://pypi.org/project/1200km-aidebug/>

[Author] - Andrey Pautov

[Licence] - MIT

[Description] - AIDebug is a Python malware-analysis and reverse-engineering
CLI/TUI that turns function-level evidence into optional ATT&CK candidates,
heuristic IOC strings in JSON, YARA seed rules, and analyst HTML reports. It supports PE and ELF
triage, Capstone disassembly, behavioral pattern detection, optional Frida
dynamic instrumentation, and optional AI-backed explanation. The AI features are
optional; the core analysis path still produces structured analyst outputs
without an API key.

[Dependencies] -

Runtime Python dependencies:

- Python >= 3.10
- asn1crypto >= 1.5.1
- capstone >= 5
- cryptography >= 43
- pefile >= 2023.2.7
- pyelftools >= 0.31
- python-dotenv >= 1.0.1
- rich >= 15.0.0
- textual >= 8.2.8

Optional dynamic-analysis dependency:

- frida >= 17.17.0,<18

Optional remote-AI dependencies:

- anthropic >= 0.120.2
- openai >= 2.0.0 (OpenAI, Gemini and Ollama-compatible transport)
- yara-python >= 4.5.4 (local fail-closed validation for AI YARA candidates)

[Similar tools] - radare2/rizin, cutter, ghidra, edb-debugger, pefile,
detect-it-easy, yara, capa. AIDebug is not a replacement for those tools; it is
a fast triage layer that produces detection-oriented outputs from function
behavior.

[Activity] - Active. Public release v3.0.0 was published on 2026-08-10. The
project includes PyPI packaging, GitHub release artifacts, CI, tests, safe demo
examples, Debian/Kali packaging metadata, a man page, and autopkgtest metadata.

[How to install] -

From the tagged PyPI release:

```bash
pipx install "1200km-aidebug==3.0.0"
aidebug --help
```

Or from the release source archive:

```bash
wget https://github.com/anpa1200/AIDebug/archive/refs/tags/v3.0.0.tar.gz
tar -xf v3.0.0.tar.gz
cd AIDebug-3.0.0
python3 -m venv .venv
. .venv/bin/activate
pip install .
aidebug --help
```

[How to use] -

```bash
aidebug --help
aidebug --binary ./sample.exe --offline --no-tui --report --json-export --out-dir ./reports
aidebug --binary ./sample.elf --offline --no-tui --json-export --out-dir ./reports
```

Remote-AI function explanations and AI-enhanced YARA candidates require the
`ai` extra and an explicitly configured Anthropic, OpenAI, Gemini or
Ollama-compatible endpoint. Static parsing, disassembly, pattern
detection, heuristic string extraction, deterministic YARA candidates, and
report generation can run without AI. Offline findings are deterministic
heuristic candidates and do not include model-generated ATT&CK conclusions.

[Packaged] - Not currently packaged in Debian or Kali. Upstream includes
Debian/Kali packaging metadata under `debian/`, a man page, and autopkgtest
metadata to make Kali review easier.

The declarations in `debian/control` still need alignment with the full
upstream dependency matrix and a target-distribution build. In particular,
its Rich floor is stale and asn1crypto/cryptography/python-dotenv are missing
from explicit build/runtime lists. Do not describe this draft as a validated
Kali package. See [dependency notes](../packaging/kali-dependency-notes.md).
