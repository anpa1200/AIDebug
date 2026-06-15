# Analyst Workflow

This workflow describes how to use AIDebug as a triage accelerator in a malware
analysis lab. It does not replace manual reverse engineering.

## 1. Prepare The Lab

- Use an isolated malware-analysis VM or sandbox.
- Disable shared clipboard and shared folders unless required.
- Keep live samples out of GitHub issues, pull requests, and documentation.
- Store case files in a controlled evidence directory.

## 2. Run Static Triage

```bash
aidebug --binary sample.exe --no-tui --report --json-export --out-dir reports/
```

Review:

- binary metadata
- function list
- suspicious behavior patterns
- ATT&CK candidate mappings
- strings referenced by high-risk functions
- generated HTML and JSON outputs

## 3. Review Findings

Treat every output as a hypothesis:

- Confirm suspicious functions in a disassembler.
- Check whether an ATT&CK technique is supported by behavior evidence.
- Remove weak IOCs and generic strings.
- Test generated YARA candidates against known-good and known-bad files.

## 4. Optional Dynamic Analysis

Dynamic mode is for controlled labs only:

```bash
aidebug --binary sample.exe --mode dynamic --pid 1234
```

Use dynamic mode to capture runtime snapshots and API activity when static
evidence is insufficient.

## 5. Export And Handoff

Use the generated JSON for downstream tools and the HTML report for analyst
notes. The YARA output is seed material and must be tested before use.
