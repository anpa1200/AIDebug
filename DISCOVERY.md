# AIDebug Discovery And Launch Kit

This file keeps external promotion consistent. Use one flagship message per
platform: AIDebug accelerates malware triage and produces analyst-review seed
material, not final automated truth.

## Canonical Links

- Repository: https://github.com/anpa1200/AIDebug
- PyPI: https://pypi.org/project/1200km-aidebug/
- Release: https://github.com/anpa1200/AIDebug/releases/tag/v1.1.0
- Article: https://medium.com/@1200km/ai-powered-malware-debugger-that-explains-every-function-it-sees-2a28ef75df8a
- Portfolio hub: https://1200km.com/

## One-Line Pitch

AIDebug is an AI-assisted malware reverse-engineering debugger that turns
function behavior into ATT&CK mappings, YARA candidates, IOC exports, JSON, and
analyst reports.

## Short Description

AIDebug helps malware analysts move from binary triage to detection-ready
outputs. It combines Capstone disassembly, behavioral pattern detection,
optional Frida dynamic tracing, CFG review, ATT&CK mapping, IOC export, YARA
candidate generation, and HTML/JSON reporting. It is designed for isolated
malware-analysis labs and requires analyst review before operational use.

## Install Block

```bash
pip install 1200km-aidebug
aidebug --help
```

Optional dynamic instrumentation support:

```bash
pip install "1200km-aidebug[dynamic]"
```

## Safety Statement

AIDebug does not replace reverse engineering. It accelerates triage and
produces analyst-review seed material: ATT&CK mappings, YARA candidates, IOC
exports, and reports. Run unknown binaries only in an isolated malware-analysis
VM or lab.

## Platform-Specific Copy

### Hacker News / Show HN

Title:

```text
Show HN: AIDebug - AI-assisted malware reverse-engineering debugger
```

Body:

```text
I built AIDebug to reduce the manual gap between malware triage and detection
engineering. It inspects PE/ELF samples, extracts suspicious function behavior,
maps candidate ATT&CK techniques, and emits analyst-review outputs: HTML/JSON
reports, IOC exports, YARA candidates, and CFG views.

It is not an attribution engine and it does not replace a reverse engineer. The
goal is faster first-pass triage with structured artifacts that a malware
analyst can review, correct, and feed into CTI or detection workflows.

Repo: https://github.com/anpa1200/AIDebug
PyPI: pip install 1200km-aidebug
```

### Reddit r/ReverseEngineering

```text
I built an AI-assisted malware triage/debugging tool and would appreciate
technical feedback from reverse engineers.

AIDebug combines Capstone disassembly, behavioral pattern detection, CFG
review, optional Frida tracing, ATT&CK mapping, IOC export, YARA candidate
generation, and HTML/JSON reports. The useful part for me is the workflow:
function behavior -> analyst notes -> detection seed material.

It does not upload or require live malware examples in the repo. The examples
are safe mock outputs and toy code. Unknown binaries should only be analyzed in
an isolated lab.

Repo: https://github.com/anpa1200/AIDebug
Install: pip install 1200km-aidebug
```

### Reddit r/blueteamsec

```text
I released AIDebug, a malware triage tool focused on turning reverse-engineering
findings into blue-team artifacts.

Outputs include ATT&CK technique candidates, IOC lists, YARA seed rules,
SIEM/SOAR-friendly JSON, and analyst HTML reports. The intent is not "AI
reverses malware"; it is faster triage and cleaner handoff into detection
engineering.

Repo: https://github.com/anpa1200/AIDebug
PyPI: https://pypi.org/project/1200km-aidebug/
```

### LinkedIn

```text
I released AIDebug: an AI-assisted malware reverse-engineering debugger for
analyst-reviewed triage.

The workflow is simple:
binary sample -> function behavior -> suspicious patterns -> ATT&CK candidates
-> YARA seed rules -> IOC export -> HTML/JSON analyst report.

This is not automated attribution and it does not replace manual reverse
engineering. The goal is to accelerate the mechanical part of triage and create
structured outputs that malware analysts and detection engineers can review.

GitHub: https://github.com/anpa1200/AIDebug
PyPI: pip install 1200km-aidebug
Release: https://github.com/anpa1200/AIDebug/releases/tag/v1.1.0
```

### X / Twitter Thread

```text
1/ I released AIDebug: an AI-assisted malware reverse-engineering debugger.

2/ It turns function behavior into analyst-review outputs: ATT&CK candidates,
YARA seed rules, IOC exports, JSON, and HTML reports.

3/ It combines Capstone disassembly, behavioral pattern detection, CFG review,
and optional Frida dynamic tracing.

4/ The point is not "AI replaces reverse engineers." The point is faster first
triage and cleaner detection-engineering handoff.

5/ Safe examples are included; no live malware is required in the repo.

6/ GitHub: https://github.com/anpa1200/AIDebug
PyPI: pip install 1200km-aidebug
```

## Newsletter Pitch

Subject:

```text
AIDebug: AI-assisted malware triage tool with ATT&CK/YARA/IOC output
```

Body:

```text
Hi,

I released AIDebug, an open-source Python tool for malware triage and reverse
engineering workflows. It combines disassembly, behavioral pattern detection,
optional Frida tracing, CFG review, ATT&CK technique candidates, IOC export,
YARA seed generation, and HTML/JSON reports.

The focus is practical analyst workflow: faster first-pass triage and
detection-ready artifacts that still require human review.

GitHub: https://github.com/anpa1200/AIDebug
PyPI: https://pypi.org/project/1200km-aidebug/
Release: https://github.com/anpa1200/AIDebug/releases/tag/v1.1.0

Best,
Andrey Pautov
```

## External Proof Loop

Track progress as:

1. Release and package are public.
2. Demo screenshots and examples are present.
3. Curated-list PRs are open.
4. Maintainer feedback is answered.
5. Accepted links are added back to the README and portfolio.
6. Medium/LinkedIn/Reddit/HN posts point to the same canonical install path.

## Current Curated-List Submissions

- Kali Linux: https://gitlab.com/kalilinux/packages/kali-meta/-/work_items/26
- BlackArch: https://github.com/BlackArch/blackarch/issues/4965
- REMnux: https://github.com/REMnux/salt-states/issues/345
- awesome-reversing: https://github.com/tylerha97/awesome-reversing/pull/32
- awesome-yara: https://github.com/InQuest/awesome-yara/pull/78
- awesome-threat-intelligence: https://github.com/hslatman/awesome-threat-intelligence/pull/384
- awesome-python-security: https://github.com/guardrailsio/awesome-python-security/pull/26
- malware-analysis list: https://github.com/brandonhimpfen/awesome-malware-analysis/pull/6
- Malware-Analysis list: https://github.com/kh4sh3i/Malware-Analysis/pull/2
