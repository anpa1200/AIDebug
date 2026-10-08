# Sample Evidence

This file points reviewers to safe illustrative material that demonstrates the
shape of AIDebug output without including live malware. Screenshots and mock
outputs are not automated validation proof or detection-accuracy evidence.

## Safe Inputs

- `examples/toy_xor_config.py`: benign toy logic used for documentation.

## Generated local output

[Benign String Intelligence export](../examples/generated-output/README.md):
an unmodified 3.1 exporter result from `/bin/true`, with provenance, hashes and
explicit ASCII/minimum-length scope. This is a local extraction/export check,
not detection-accuracy evidence.

## Mock Outputs

- `examples/mock-output/aidebug-session.json`: hand-authored schema-v2 offline
  session example with an all-zero mock hash and redacted path.
- `examples/mock-output/aidebug-candidate.yar`: illustrative YARA seed.
- `examples/mock-output/aidebug-report.html`: compact illustrative HTML
  fragment, not a complete current generated report.

## Screenshots

The historical captures have a documented integrity manifest and limitations in
`assets/screenshots/README.md`.

- `assets/screenshots/tui-function-analysis.png`
- `assets/screenshots/behavioral-patterns-tab.png`
- `assets/screenshots/control-flow-graph.png`
- `assets/screenshots/pattern-detection-output.png`
- `assets/screenshots/four-panel-tui.png`

## Packaging Evidence

- `pyproject.toml`: Python package metadata.
- `debian/`: Debian-family packaging files.
- `packaging/kali-new-tool-request.md`: historical Kali tracking note;
  `docs/kali-new-tool-request.md` is the current update draft.
- [REMnux integration](remnux.md): accepted state/release and package boundary;
  `packaging/remnux-submission.md` preserves proposal history.

## 3.1 article screenshot provenance

The [maintained 3.1 review](https://1200km.com/articles/read/2026/2026-08-13-aidebug-3-1-full-release-review/)
is the feature/workflow reference. Its reused screenshots remain historical,
illustrative evidence. Inspection of the original pixels on 8 October 2026
established these qualifications:

| Figure | Visible evidence | Correct interpretation |
|---|---|---|
| [3](https://1200km.com/articles/assets/images/aidebug-cfg-61b0119075851a1cb519f681005b448e.png) | PE directories, load configuration, CFG evidence and GFIDS targets | Control Flow Guard, not a function basic-block control-flow graph |
| [10](https://1200km.com/articles/assets/images/binary-decompilation-9dded55fdc7e8fa62e3ebe4c20505e85.png) | Selected AI Analysis tab with an LLM decompilation cross-check | Illustrates AI commentary; the Decompiled C tab is visible but not selected |
| [11](https://1200km.com/articles/assets/images/learning-mode-catalog-d92e91fe8328ff1356979be82c49a4a9.png) | Header and footer show 47 real C cases | Historical catalog; current bundled manifest contains 100 |
| [12](https://1200km.com/articles/assets/images/learning-mode-case-bbec9d0e1174aa3d56694645fec8112c.png) | 47-case header, selected mov-load source, instructions and reconstruction | Historical selected lesson; not a current 100-case capture |

These notes qualify repository references; the website article and image bytes
were not changed. Do not relabel the old captures as fresh 3.1 runtime evidence.

## Repeatable Evidence

- `scripts/check_evidence_assets.py` checks screenshot integrity/dimensions and
  parses the mock JSON.
- CI compiles the mock YARA file with `yara-python`.
- Unit tests and the release gate—not screenshots—are the acceptance evidence
  for a specific commit.
