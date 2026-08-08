# Kali/Debian Dependency Notes

The included `debian/` metadata expresses the upstream minimum versions. The
local apt snapshot checked on 2026-07-18 is Ubuntu Noble, not Kali, so it can
confirm package names but cannot validate a Kali build.

## Local package-name and version check

- `python3-capstone` 4.0.2: **below** the required 5.x floor
- `python3-pefile` 2023.2.7: meets the declared floor
- `python3-pyelftools` 0.30: **below** the required 0.31 floor
- `python3-packaging` 24.0: meets the build/test floor
- `python3-rich` 13.7.1: meets the declared floor
- `python3-textual` 0.1.13: **below** the required 0.52 floor
- `pybuild-plugin-pyproject`
- `dh-python`
- `debhelper-compat`
- `bubblewrap` and `gcc` are suggested system packages for the optional `.c`
  to temporary-ELF source-analysis path; the generated artifact is never run.

The Debian control file uses versioned relationships so an incompatible target
fails dependency resolution rather than producing a package with unsupported
libraries. A current Kali builder/repository check is still required.

## Dependency gaps to discuss with Kali maintainers

These optional upstream Python packages did not have matching Debian/Kali
packages in the review environment:

- `anthropic` (required only for the opt-in remote-AI path; `--offline` does
  not import or call it)
- `frida` (optional dynamic instrumentation)

Practical options:

1. Keep the initial Debian package offline-only and exercise `--offline` in
   autopkgtest, as the current proposal does; or package `python3-anthropic`
   before enabling the remote-AI path.
2. Package `python3-frida` separately only if Kali maintainers want the optional
   dynamic extra in the distribution.
3. The current source package keeps Anthropic in the optional `ai` extra. A
   Debian package can remain an offline-only build when its description makes
   that feature boundary explicit.

Upstream's `ai` extra also includes `yara-python >= 4.5` so every model-produced
rule is compiled and screened locally before it can be written. A target
package must map and version-check that compiler binding, or leave AI-backed
YARA generation disabled; deterministic offline candidate generation does not
import the binding.

The Debian metadata is still a packaging proposal, not an accepted Kali
package. Its autopkgtest validates the supported offline path; remote AI and
dynamic Frida features require separate dependency decisions by maintainers.
