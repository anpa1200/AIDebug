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

C source analysis is static preparation, not dynamic execution. AIDebug copies
one selected `.c` file into a temporary directory, invokes an allowlisted local
compiler inside a Bubblewrap filesystem sandbox, verifies that the result is
ELF, parses it, and deletes it. The compiled artifact is never launched.
Bubblewrap is mandatory because preprocessors and inline assembly can otherwise
read unrelated host files. The sandbox exposes compiler/runtime paths, device
nodes, a private temporary filesystem, and the copied source only; project-local
headers and multi-file builds are intentionally outside the current boundary.

## AI Output Boundaries

AI-generated analysis is not authoritative. AIDebug output should be treated as:

- a triage hypothesis
- a draft analyst note
- a detection engineering seed
- a prompt for deeper reverse engineering

It should not be treated as final attribution, final detection logic, or a
production blocking decision without analyst review.

## Remote AI Data Boundary

Remote analysis sends evidence to Anthropic. Depending on analysis mode, that
evidence can include the sample filename, full SHA-256 hash, architecture and OS
metadata, imported APIs, function disassembly, referenced strings,
cross-references, deterministic pattern findings, and optional runtime register
or stack context. Treat all of it as potentially sensitive incident data.

Before remote analysis:

- obtain authorization to send the evidence to a third party;
- review the provider's current retention, training, regional-processing, and
  contractual policies;
- do not submit secrets, customer data, embargoed samples, or regulated content
  unless the applicable policy and agreement permit it;
- prefer the documented offline mode when remote processing is not authorized.

An API key is a secret. Supply it through the environment, never CLI arguments,
screenshots, reports, issues, or committed files.

## Local Evidence And Retention

Session databases and exports are not encrypted by AIDebug. They may contain
sample paths and hashes, imported APIs, referenced strings, AI output, API-call
arguments, URLs and headers, network metadata and up to the tracer's configured
payload capture, register/stack context, and other runtime evidence.

- Use isolated per-case storage with restrictive filesystem permissions.
- Apply investigation retention and deletion requirements to databases,
  reports, YARA candidates, and JSON exports.
- Redact evidence before sharing it in tickets, chat, documentation, or public
  repositories.
- Do not mistake deletion of an export for deletion of the SQLite session that
  produced it.
- Treat remote Frida and captured traffic as untrusted input.

## Analysis Coverage Limits

### Operational bounds

Current source defaults reject inputs that are not readable regular files.
Binary inputs are capped at 128 MiB. C inputs are capped at 2 MiB and 30 seconds
of sandboxed compilation; dynamic execution and YARA generation are disabled
for source inputs. Extraction is capped at 100,000 strings with 4,096
characters per string. Symbol-table scanning is capped at 100,000 records, with
at most 50,000 import and 50,000 export candidates retained. Discovery is capped
at 300 function candidates and 250 instructions per function; bulk CLI analysis
defaults to 25 selected functions.
Optional pseudo-source is capped at 12,000 characters per function. It is a
deterministic instruction translation with explicit uncertainty, not recovered
original C/C++: types, names, expressions, and structured control flow can be
wrong. The underlying disassembly remains the primary local evidence.
Dynamic instrumentation uses the lower of `--max-functions` and a 50-function
hook ceiling. Script readiness and hook errors are surfaced by the CLI. A
zero-hook observer may be waiting for a watched module to load and must not be
treated as evidence that target behavior was captured.

YARA generation considers at most `--max-functions` HIGH/CRITICAL traces per
ruleset. Remote candidates must compile locally and are rejected if they match
empty or minimal generic PE/ELF probes; this is a safety screen, not a
false-positive benchmark, so every candidate still requires corpus testing.

API-call, network, and runtime-event persistence is capped at 10,000 records per
category per session. JSON export applies the same 10,000-record category caps,
while HTML reports show at most 500 records from each category. Truncation caps
protect analyst resources; they are not completeness or time-based retention
guarantees. The SQLite database remains on disk until the operator applies the
case retention/deletion policy described above.

### Analytical limits

Function discovery is bounded recursive descent from entry and exported
function candidates, plus named local ELF function symbols when present; it is
not exhaustive whole-binary recovery. Indirect calls,
stripped or unreachable code, overlays, packed code, unusual compiler output,
and unsupported architecture details may be missed. Static virtual addresses
may not equal runtime addresses when ASLR, PIE, or rebasing applies; analysts
must verify dynamic hook coverage.

Library identification uses compact heuristic signatures and structural rules,
not authoritative FLIRT databases. A 16-bit signature can collide, and inferred
library names must be manually verified. Protection-transition and prologue
hints are unpacking leads; they do not prove an original entry point or perform
automatic dumping and re-analysis.

## Responsible Disclosure

Security issues in AIDebug itself should be reported privately using the process
in `SECURITY.md`.
