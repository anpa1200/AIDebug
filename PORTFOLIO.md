# Review guide: Evidence-focused reverse-engineering CLI

Andrey Pautov develops the Python analyst interface, offline triage, string intelligence, PE inspection and reporting workflows. Capstone, Ghidra, GDB and optional AI providers are integrations, not original tools authored by this project.

## Architecture and contribution

CLI/TUI → bounded static analyzers → evidence records → analyst-review JSON/HTML and detection candidates. Optional debugger and provider paths are separate capabilities.

Role relevance: Malware triage, reverse engineering tooling, safe AI-assisted analysis, Python delivery.

## Safe reproducible quickstart

Run from the repository root. Python 3.10–3.13 with the project runtime dependencies installed. From a fresh checkout: create and activate a virtual environment, then `python -m pip install -e .`. Installation may download packages; the demo itself makes no provider calls. For a disconnected lab, install dependencies from an approved local wheel cache first.

```bash
python examples/portfolio_demo.py
```

Expected result:

```text
JSON describing application/zip, size 22 and ai_used=false, followed by PASS. The input is a generated empty ZIP deliberately named renamed.dat.
```

These commands use committed or generated benign/synthetic input. They do not execute malware, invoke a hosted provider, scan a target or require credentials.

## Evidence to inspect

[Example provenance](examples/README.md) · [Security boundaries](SECURITY.md)

[REMnux integration](docs/remnux.md) records acceptance on 7 October 2026 and
first inclusion in salt-states v2026.41.4. It is distribution evidence, with
explicit package/source and optional-backend boundaries.



## Validation and limitations

This executes the real offline identification CLI, not the ZIP. It does not validate malware classification, decompilation, debugging, YARA quality or AI accuracy. Existing mock outputs in examples/mock-output are hand-authored illustrations.

See [validation.md](validation.md) for checks performed on the exact source snapshot, verified results and capabilities not run. Existing release/CI claims remain historical repository statements, not fresh certification.

Preserve the full [README](README.md) and original technical documentation for installation, deployment and capability details.
