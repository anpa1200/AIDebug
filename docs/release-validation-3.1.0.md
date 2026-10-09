# AIDebug 3.1.0 candidate validation

Checked **9 October 2026** against main commit
[`f8440da`](https://github.com/anpa1200/AIDebug/commit/f8440da301976ce05b98d4dc86d3097672280038).
The preparation branch changes documentation and dates only; Python runtime
and dependency declarations are unchanged. **Publication is blocked** by the
repository controls below. These are candidate results, not evidence of an
already published 3.1 package or a REMnux VM installation.

## Automated release gate

`./scripts/release-readiness.sh` completed successfully in isolated temporary
environments on Linux/Python 3.13.12:

| Check | Result and boundary |
|---|---|
| Pytest | **438 passed, no skips**, 48.82 seconds |
| C-source isolation | All three previously skipped compiler/Bubblewrap tests ran, including refusal to embed an unrelated host file |
| Metadata, documentation and illustrative asset integrity | Passed; the original source's `Unreleased` entries separately caused the tag-specific metadata check to refuse publication |
| Ruff and Bandit | Passed; Bandit included `learning` |
| `pip check` | Passed in gate, base-wheel, `[ai]` upgrade and `[dynamic]` environments |
| Declared base, AI and dynamic dependency audits | Each reported no known vulnerabilities at this check |
| Frida JavaScript and mock YARA | Syntax/compilation checks passed |
| Build, Twine and distribution contents | Wheel and sdist passed |
| Installed base-wheel smoke | Version, help, learning catalog, packaged data, static ELF, JSON and offline YARA passed |

After the metadata preparation, the tag-specific check passed for `v3.1.0` and
the full local gate passed again: **438 tests, no skips**, 48.21 seconds.
This follow-up validates the prepared documentation/metadata working tree;
it does not resolve the repository controls or the incomplete live AI review.

The exact baseline's [main CI](https://github.com/anpa1200/AIDebug/actions/runs/37834907373)
also passed all ten jobs, including Gitleaks and Python 3.10–3.13. Its three
compiler/sandbox skips differ from this local lab's zero-skip run; they are not
silently counted as executed CI tests. A later preparation commit requires its
own CI result before any merge or tag.

## Clean candidate installation and REMnux-style upgrade

Separate fresh virtual environments installed the built base wheel and the
published `1200km-aidebug[ai]==3.0.0`. The latter was then upgraded with the
local candidate wheel's `[ai]` extra. It reported **AIDebug 3.1.0**, no broken
requirements, and no installed Frida distribution. This verifies the package
upgrade shape used by [REMnux](remnux.md), not Salt provisioning on REMnux.

Both environments passed CLI identification, offline ELF/JSON/YARA output,
the 100-case learning catalog and String Intelligence export. The generated
harmless ELF retained 96 strings, scanned all 18,104 bytes, and included the
expected DLL, API and URL evidence. JSON reported complete deterministic
inventory coverage, absent AI analysis and mode 0600. A separately delimited
UTF-16LE fixture was detected. No inspected ELF was executed by these static
checks.

Anthropic 1.12.1, OpenAI 3.26.1 and YARA-Python 4.5.4 installed successfully.
Anthropic, OpenAI, Gemini-compatible and loopback Ollama clients initialized
with synthetic keys and were closed **without remote requests**. This is SDK
construction evidence, not successful cloud-provider analysis.

## Live optional backend results

Only the generated harmless arithmetic target was executed for GDB/Frida.
The fixture adds 2 and 3 repeatedly, prints a sum of 500, and exits normally.
It performs no file writes or network requests.

| Backend | Live result |
|---|---|
| Ghidra 12.1.2 / OpenJDK 25.0.4.1 | Installed-wheel adapter reconstructed the fixture's `release_add` as `return right + left` |
| Learning Mode | Installed wheel compiled trusted bundled `mov-load`, displayed real disassembly and obtained real Ghidra reconstruction; artifact was not executed |
| GDB 15.1 | Adapter hit `release_add`, observed arguments 2/3, finished with `GDB return=5`, and completed the target normally |
| Frida 17.23.1 | Spawned the fixture, installed one PIE-aware function interceptor and received a return-value event of 5 |
| Installed-wheel `--source` | Bubblewrap 0.9.0 / GCC 13.3.0 compilation and static JSON export passed; compiler output was not executed |
| Local Ollama / `qwen2.5:3b` | **Incomplete AI review**: one retained/sent string, zero reviewed, failed chunk 0; aggregate `unknown`, `complete=false` |

The Ollama model ran on CPU with a reported 4,096-token context. Its failure
does not prove an SDK defect or identify whether generation, schema validation
or the request failed; the public report deliberately retains the bounded
`AIAnalyzerError` diagnostic. Fail-closed reporting worked, but no successful
live end-to-end string-AI review was established. A suitable provider/model
needs a separately authorized successful validation before claiming that
integration works. No paid provider, Windows/macOS target or real malware was
used.

## Required controls and unresolved release gates

[RELEASE.md](../RELEASE.md#repository-settings-required) requires repository
settings outside the source tree before publication. Fresh checks found:

| Control | Observed state |
|---|---|
| Protected `main`, required CI and review | `protected=false`; no required check/review enforcement |
| Protected `v*` tags | No repository rulesets; no release-tag protection was established |
| Approval on the `pypi` environment | No protection rules or deployment-branch policy |
| Private vulnerability reporting | Disabled |
| Dependabot alerts and automated security fixes | Read endpoints returned HTTP 401; status could not be verified |
| Secret-scanning/push-protection settings | Security settings absent from the readable repository metadata; history scanning passed, but platform controls remain unverified |
| Maintained SAST | Bandit gate passed; no additional code-scanning claim is made |

The owner must choose/authorize the repository controls and an independent
reviewer. Enforcing one review on a PR authored by the same account requires a
different eligible reviewer. None of these settings was silently enabled,
disabled or waived. No tag, GitHub release, Trusted Publishing dispatch or
PyPI upload was attempted.

Routine metadata preparation folds the documentation changes into 3.1.0,
dates the prepared release consistently and preserves 11 August as the source
milestone. It does not describe 3.1 as already published.

External Learning compilation's trust boundary, offline YARA validation,
string-AI completion semantics, ZIP central-directory allocation, conventional
PCAP coverage and Debian/Kali work remain as documented in the
[validation plan](validation-plan.md#integration-work-and-implementation-limits).
No runtime/security remediation was made in this preparation branch.

## Baseline candidate artifact and fixture hashes

These local archives were built from **f8440da**, before metadata preparation.
They are not final release artifacts or PyPI downloads. Rebuild and verify the
actual immutable tagged/published artifacts after the gates are resolved.

| File | SHA-256 |
|---|---|
| `1200km_aidebug-3.1.0-py3-none-any.whl` | `8b2428d3692d3b2ec45d9a61b9f0c036757ade28e9855b7eaab171052aa3e661` |
| `1200km_aidebug-3.1.0.tar.gz` | `5f947ebad9690240b334414c1b67986a216b048c547b7eb76b25affbf6651a3f` |
| Generated `toy.c` | `a6e5c4eb6fc13116eedf17414b93fa0fab580dd7e7f54661e6007192ef7995b7` |
| Generated PIE ELF `toy` | `4d79ddac615c6a94487db49ff5a58022181443201b109a723be83e68e4e30cf6` |

Local logs, the exact smoke harness, generated fixtures, dependency snapshots
and archives are retained in the executor workspace's `release-evidence`
directory. The original checkout was preserved.
