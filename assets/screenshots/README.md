# Screenshot Provenance

These PNG files are illustrative captures associated with the historical
companion article. They help explain the intended interface, but they are not
reproducible validation proof for the current commit and do not establish
detection accuracy.

| File | Dimensions | SHA-256 |
|---|---:|---|
| `behavioral-patterns-tab.png` | 800×363 | `3e44d6fce656623c674caa318186c0d3effa4ad090a1d7f40d4f1707ef5a91b0` |
| `control-flow-graph.png` | 550×604 | `48740252ad0c50192813abab3e9bf53d3394d959643b0810dc8682595bf05e4b` |
| `four-panel-tui.png` | 800×456 | `9378bc38426571c94a724eb352a5e7875a7429fffe19f746f0913b7aceb44777` |
| `pattern-detection-output.png` | 534×221 | `8c16eca507eb7d0d2fd05b8fd96b331b1bec738db657f596ee0953ce8910d610` |
| `tui-function-analysis.png` | 800×447 | `9f0036ee08e52ac7ecaff44b0744a41af1d70e84cf325146e0d802a173856c84` |

The release gate verifies these bytes and dimensions to detect accidental
replacement. That integrity check does not make the images current evidence.

For a future recapture, use a safe synthetic fixture in an isolated lab, record
the exact commit, command, terminal dimensions, operating system, Python and
dependency versions, redact paths and secrets, update the manifest in
`scripts/check_evidence_assets.py`, and state which panels show live versus
mock data.
