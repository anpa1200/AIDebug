# Sample Evidence

This file points reviewers to safe illustrative material that demonstrates the
shape of AIDebug output without including live malware. Screenshots and mock
outputs are not automated validation proof or detection-accuracy evidence.

## Safe Inputs

- `examples/toy_xor_config.py`: benign toy logic used for documentation.

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
- `packaging/kali-new-tool-request.md`: Kali submission material.
- `packaging/remnux-submission.md`: deferred REMnux proposal and outcome.

## Repeatable Evidence

- `scripts/check_evidence_assets.py` checks screenshot integrity/dimensions and
  parses the mock JSON.
- CI compiles the mock YARA file with `yara-python`.
- Unit tests and the release gate—not screenshots—are the acceptance evidence
  for a specific commit.
