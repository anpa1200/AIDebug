# AIDebug Discovery And Launch Kit

This file keeps external promotion consistent. Use one flagship message per
platform: AIDebug accelerates malware triage and produces analyst-review seed
material, not final automated truth.

> Draft status: this copy describes v1.3.1 source behavior on `main`. Replace
> the historical v1.1.0 release link and PyPI install claims only after v1.3.1
> is tagged and available from PyPI.

## Canonical Links

- Repository: https://github.com/anpa1200/AIDebug
- PyPI: https://pypi.org/project/1200km-aidebug/
- Release: https://github.com/anpa1200/AIDebug/releases/tag/v1.1.0
- Article: https://medium.com/@1200km/ai-powered-malware-debugger-that-explains-every-function-it-sees-2a28ef75df8a
- Portfolio hub: https://1200km.com/

## One-Line Pitch

AIDebug is malware reverse-engineering triage tooling that turns discovered
function evidence into deterministic offline findings, optional remote-AI
ATT&CK candidates, YARA seeds, heuristic IOC strings in JSON, and reports.

## Short Description

AIDebug helps malware analysts move from binary triage to review-ready
outputs. It combines Capstone disassembly, behavioral pattern detection,
optional Frida dynamic tracing, CFG review, optional ATT&CK candidates,
heuristic string extraction, YARA candidates, and HTML/versioned-JSON reporting. It is designed for isolated
malware-analysis labs and requires analyst review before operational use.

## Install Block

```bash
git clone https://github.com/anpa1200/AIDebug.git
cd AIDebug
pip install -e .
aidebug --help
aidebug --binary /path/to/sample --offline --no-tui
```

Optional dynamic instrumentation support:

```bash
pip install -e ".[dynamic]"
```

Optional remote AI requires `pip install -e ".[ai]"`, an authorized
`ANTHROPIC_API_KEY`, and explicit cost acknowledgement for bulk commands.

## Safety Statement

AIDebug does not replace reverse engineering. It accelerates triage and
produces analyst-review seed material: optional ATT&CK candidates, YARA
candidates, heuristic strings, and reports. Run unknown binaries only in an isolated malware-analysis
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
can request candidate ATT&CK techniques, and emits analyst-review outputs:
HTML/versioned-JSON reports, heuristic IOC strings, YARA candidates, and CFG views.

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
review, optional Frida tracing, optional ATT&CK candidates, heuristic string
extraction, YARA candidates, and HTML/versioned-JSON reports. The useful part for me is the workflow:
function behavior -> analyst notes -> detection seed material.

It does not upload or require live malware examples in the repo. The examples
are safe mock outputs and toy code. Unknown binaries should only be analyzed in
an isolated lab.

Repo: https://github.com/anpa1200/AIDebug
Install: pip install 1200km-aidebug; start with --offline
```

### Reddit r/blueteamsec

```text
I released AIDebug, a malware triage tool focused on turning reverse-engineering
findings into blue-team artifacts.

Outputs include optional ATT&CK technique candidates, heuristic IOC strings,
YARA seed rules, versioned JSON for custom adapters, and analyst HTML reports. The intent is not "AI
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
-> YARA seed rules -> heuristic strings -> HTML/versioned-JSON analyst report.

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
YARA seed rules, heuristic IOC strings, versioned JSON, and HTML reports.

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
optional Frida tracing, CFG review, ATT&CK technique candidates, heuristic
string extraction, YARA seed generation, and HTML/versioned-JSON reports.

The focus is practical analyst workflow: faster first-pass triage and
review-ready artifacts that still require validation before operational use.

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

## External Submission Status

Status checked 2026-07-18. A merged list entry is discovery evidence, not a
security review or technical endorsement.

| Destination | Status | Reference |
|---|---|---|
| awesome-yara | Merged/accepted | [PR #78](https://github.com/InQuest/awesome-yara/pull/78) |
| awesome-reversing | Open | [PR #32](https://github.com/tylerha97/awesome-reversing/pull/32) |
| awesome-threat-intelligence | Open | [PR #384](https://github.com/hslatman/awesome-threat-intelligence/pull/384) |
| awesome-python-security | Open | [PR #26](https://github.com/guardrailsio/awesome-python-security/pull/26) |
| Malware-Analysis | Open | [PR #2](https://github.com/kh4sh3i/Malware-Analysis/pull/2) |
| BlackArch | Open proposal | [Issue #4965](https://github.com/BlackArch/blackarch/issues/4965) |
| REMnux | Closed/deferred on 2026-06-22 pending maintenance and maturity evidence | [Issue #345](https://github.com/REMnux/salt-states/issues/345) |
| awesome-malware-analysis | Closed without merge | [PR #6](https://github.com/brandonhimpfen/awesome-malware-analysis/pull/6) |
| Kali New Tool Request | `new`/open; public request still contains v1.0.0 metadata | [Issue 0009743](https://bugs.kali.org/view.php?id=9743) |
| Kali tracking work item | Closed on 2026-06-16; decision text was not independently captured | [Work item #26](https://gitlab.com/kalilinux/packages/kali-meta/-/work_items/26) |

Do not label closed/deferred proposals as pending acceptance. Recheck every
status at publication time rather than copying this table indefinitely.
