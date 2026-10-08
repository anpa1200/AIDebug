# Local validation evidence

## Documentation refresh: 8 October 2026

Prepared in an isolated clone on `docs/3.1-audit-remnux-20261008`, based on
`80b0b7172b592814504c405a16bf4cc0ce4161eb`. This records checks of the
documentation working tree before commit; runtime code, dependency declarations
and existing screenshot bytes were unchanged. Python 3.13.12 on Linux; source
tests used existing local dependencies. Build tools and the wheel smoke used
new isolated workspace virtual environments.

| Check | Observed result | Scope |
|---|---|---|
| `python -m pytest -q -rs` | 435 passed, 3 skipped, 42.64 seconds | Existing regression suite; skips at test_cli.py:462 and test_core_runtime.py:129/:198 explicitly report unavailable Bubblewrap/C toolchain |
| Ruff and Bandit | Passed | Existing source lint and medium/high-confidence static security checks |
| Release metadata and screenshot manifest | Passed | Version/dependency consistency and unchanged illustrative asset integrity |
| Local Markdown links | Passed | Repository link/heading targets; external links and factual claims reviewed separately |
| CLI/manpage inspection | 39 option names represented; 82 documented command lines use valid flags | Parser comparison of Markdown commands; includes aliases and automatic help |
| Manpage rendering | Passed, no groff diagnostics | `groff -man -Tutf8 debian/aidebug.1` |
| Wheel/sdist build, Twine and archive contents | Passed | Declared build tools installed into a fresh build environment |
| Fresh base-wheel install | Passed; `pip check` clean; version 3.1.0 | No editable checkout or AI/dynamic extra in the wheel environment |
| Wheel offline ELF/JSON/YARA smoke | Passed | Inspected `/bin/true` without executing it; generated zero-rule YARA file compiled separately |
| Wheel strings export | Passed | 144 retained records; complete bounded byte scan; AI absent; output mode 0600 |
| Portfolio demo | Passed | Generated renamed benign empty ZIP; offline identification; no AI |
| Mock YARA and Frida JavaScript | Passed | Mock rule compilation and JavaScript syntax checks |

The [generated benign strings example](examples/generated-output/README.md)
records a separate eight-record ASCII/minimum-length-50 export with exact
input/output hashes. It is not a malware accuracy benchmark.

REMnux acceptance/state/release links and the four closed contribution PRs were
checked against current upstream records. Original article Figures 3, 10, 11
and 12 were inspected as pixels; see [qualified captions](docs/sample-evidence.md#31-article-screenshot-provenance).
The completed audit report was read through Library. Its ZIP download returned
HTTP 403 on both supported attempts; report text and public original screenshots
provided the relevant evidence through supported alternatives.

No live malware, Ghidra installation, GDB inferior, Frida target, REMnux Salt/VM,
or paid provider was run. Current dependency-audit and secret-scan outcomes for
the pushed commit should be taken from its GitHub CI run, rather than inferred
from the local checks above. Remaining source/packaging work is listed in the
[validation plan](docs/validation-plan.md#integration-work-and-implementation-limits).

## Historical portfolio check: 1 October 2026

Date: 2026-10-01. The reviewed changes were applied to public `main` at `e770c52da2e1669d81594817e3040f4744741642` in an isolated clone. Checks below distinguish local editorial evidence from broader application and release validation.

| Check | Status | Scope |
|---|---|---|
| `python3 examples/portfolio_demo.py` | Verified: exit 0 | Offline benign/synthetic or help check only |
| Broader capabilities | Not run | Other analyzers, TUI, PE/ELF workflows, debugging, decompilation and providers not run. Runtime dependencies supplied by the existing canonical checkout virtual environment; no fresh install or dependency reproducibility claimed. |

## Retained output

```text
$ python3 examples/portfolio_demo.py
{
  "type_name": "Empty ZIP archive",
  "mime_type": "application/zip",
  "extensions": [
    ".zip"
  ],
  "confidence": 0.99,
  "method": "magic",
  "evidence": [
    "signature at offset 0"
  ],
  "ai_used": false,
  "alternatives": [],
  "sha256": "8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85",
  "size": 22
}
PASS: renamed empty ZIP identified from bytes; AI unused; sample never executed
```
