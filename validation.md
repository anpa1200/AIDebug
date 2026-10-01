# Local validation evidence

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
