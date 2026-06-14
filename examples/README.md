# AIDebug Examples

This directory contains safe, non-malicious example material for documentation,
testing, and demonstrations.

## Contents

- `toy_xor_config.py` - benign toy source that demonstrates the kind of XOR loop
  AIDebug is designed to flag in real malware. It does not exploit, persist,
  evade, or connect to anything.
- `mock-output/aidebug-session.json` - representative JSON export from a mock
  analysis session.
- `mock-output/aidebug-candidate.yar` - representative analyst-review YARA seed.
- `mock-output/aidebug-report.html` - compact mock HTML report.

## Usage

The mock outputs are intended for README screenshots, parser tests, and UI
examples. They are not generated from live malware.

To run the toy source:

```bash
python examples/toy_xor_config.py
```

To run AIDebug on a real sample, use an isolated malware-analysis VM or lab.
Do not execute unknown binaries on your host OS.
