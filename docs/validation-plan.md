# Validation Plan

This plan defines how AIDebug behavior should be evaluated without publishing
live malware.

## Evaluation Inputs

Use safe inputs:

- toy programs with known behavior
- mock trace records
- sanitized public report excerpts
- generated PE/ELF fixtures that do not perform harmful actions

Do not use live malware in the repository.

## What To Measure

| Area | Evidence |
|---|---|
| Pattern detection | Expected pattern names and severities |
| ATT&CK mapping | Technique candidate plus behavior evidence |
| JSON export | Schema stability and field completeness |
| YARA output | Syntax and false-positive review notes |
| Reports | Analyst-readable explanation and source evidence |
| CLI behavior | Stable help, reporting, and session commands |

## Current Baseline

- Tests run in CI on Python 3.10, 3.11, 3.12, and 3.13.
- CI separately exercises the headless TUI at the declared Textual 8.2.8 floor
  and installs/imports the Frida 17.x dynamic extra on Python 3.12.
- CI runs Ruff, Bandit, declared-dependency audits, secret scanning, exact
  release metadata checks, package builds, Twine validation, and a fresh-wheel
  offline static-analysis smoke test.
- The mock YARA candidate is compiled with `yara-python` in CI.
- Fresh-wheel smoke tests also generate and compile a deterministic offline
  YARA candidate from `/bin/true` analysis without installing remote-AI code in
  the wheel environment.
- Safe mock JSON, YARA, and HTML outputs are available in `examples/mock-output/`.
- Illustrative screenshots and mock output are integrity checked but are not
  treated as accuracy evidence.
- Deterministic tests cover CLI, offline/remote boundaries, storage, reporting,
  pattern detection, dynamic message handling, and release metadata.

## Acceptance Criteria For New Rules

New pattern detectors should include:

- a short behavior description
- severity rationale
- at least one positive unit test
- at least one negative or non-triggering case when practical
- documentation of likely false positives

## Source 3.1 evidence map

| Contract | Existing focused checks | Interpretation |
|---|---|---|
| Occurrence-aware four-encoding extraction, offsets and retention/truncation | `tests/test_string_analyzer.py` | Synthetic extraction/coverage contracts |
| Conservative domains/IPs/configuration and DLL/API descriptions | `tests/test_string_analyzer.py`, `tests/test_string_integration.py` | Deterministic boundary cases; not a malware benchmark |
| Per-ID chunk/reducer grounding, failed coverage, cancellation | `tests/test_string_ai.py` | Fake-client/provider contract tests; no paid provider request |
| Strings CLI privacy, filtering and owner-private JSON | `tests/test_string_integration.py`, `tests/test_reporting_security.py` | Local synthetic output and failure behavior |
| Strings UI filters and explicit AI action | `tests/test_strings_tui.py` | Headless Textual interaction |
| Arbitrary-file identification | `tests/test_file_type.py` | Signature/container tests and simulated libmagic/AI |
| Learning corpus | `tests/test_learning.py` | Real compilation/disassembly of 100 bundled cases; fake decompiler |
| Ghidra/GDB/Frida adapters | `tests/test_decompiler.py`, `tests/test_active_debugger.py`, `tests/test_dynamic_cli.py` | Wrapper, parser and simulated-target contracts |
| Version/dependencies/distribution contents | `tests/test_release_metadata.py`, `scripts/check_release_metadata.py`, `scripts/check_distribution.py` | Metadata and archive contracts |

The audited [main CI run](https://github.com/anpa1200/AIDebug/actions/runs/36867078414)
on 1 October 2026 at `80b0b7172b592814504c405a16bf4cc0ce4161eb` passed all
10 jobs. Each Python 3.10–3.13 matrix job reported 435 passed and 3 skipped;
Textual-floor reported 18 passed; dynamic-extra reported 56 passed and 2 skipped.
These are dated existing results, not a fresh verification of a later commit.
The wheel smoke generated a zero-rule YARA file, so compilation success there
does not establish rule usefulness or precision.

`check_docs.py` checks local Markdown links and heading fragments. It does not
check external URLs, fact accuracy, installation flows or manpage option
coverage. Recheck those separately when editing guidance.

## Integration work and implementation limits

- Add a separately recorded lab verification with pinned Ghidra/Java and real
  GDB/Frida on harmless targets. Record versions, fixture hashes, commands,
  expected observations and failures. Green fake-client tests do not prove
  live backend or current remote-model availability.
- C-source isolation tests skip when compiler/Bubblewrap prerequisites are not
  usable. Require the prerequisites in a release lab and retain skip reasons;
  three generic skips in a past log do not establish which tests skipped.
- External Learning compilation lacks the `--source` Bubblewrap isolation.
  Treat its cases/header as trusted input until a separate implementation
  change adds and validates compiler isolation.
- ZIP's 4,096-name slice follows central-directory parsing; a future pre-parse
  bound or isolated parser and explicit truncated classification are needed.
- Built-in signatures omit conventional microsecond PCAP. A separate source
  fix should add both byte orders with harmless global-header regression
  fixtures. Documentation describes the present coverage rather than claiming
  that fix already happened.
- String AI exit 0 means report production, including partial review. Consume
  JSON coverage/assessment/limitations; a future strict-completion option would
  require a separate CLI behavior change.
- Offline YARA seeds bypass the remote compiler/probe path. Compile and test
  them separately; generic probes on AI candidates are not a benign-corpus
  false-positive benchmark.
- OS Independent metadata does not establish full Windows/macOS parity:
  current CI runs on Ubuntu. Target OS, Kali package builds and REMnux Salt/VM
  installation need their own execution evidence.

Remote-provider smoke tests need authorized evidence and cost scope; a local
Ollama run is a separate useful integration check. No precision/recall,
production false-positive rate or malware-family accuracy follows from the
current test counts or screenshots.
