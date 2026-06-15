# Safety Model

AIDebug is defensive malware-analysis tooling. The repository must stay safe to
browse, clone, test, and review.

## Safe Repository Policy

- Do not commit live malware.
- Do not attach live malware to issues or pull requests.
- Use hashes, redacted logs, toy programs, or mock outputs for reproduction.
- Keep examples non-malicious and clearly labeled.

## Execution Boundaries

Static analysis reads binary files. Dynamic mode attaches Frida to a process or
sandbox target and should only be used:

- with authorization
- in an isolated malware-analysis VM or lab
- against samples the analyst is permitted to examine
- with network controls appropriate to the investigation

## AI Output Boundaries

AI-generated analysis is not authoritative. AIDebug output should be treated as:

- a triage hypothesis
- a draft analyst note
- a detection engineering seed
- a prompt for deeper reverse engineering

It should not be treated as final attribution, final detection logic, or a
production blocking decision without analyst review.

## Responsible Disclosure

Security issues in AIDebug itself should be reported privately using the process
in `SECURITY.md`.
