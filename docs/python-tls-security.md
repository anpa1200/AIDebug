# Python TLS trust remediation

The [Python security advisory](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576)
requires pip >=26.2.2 and certifi >=2026.10.19 after the October 2026 emSign CA
incident. An older pip still trusts its bundled vulnerable certificates even
when the operating system CA store has been updated. Updating certifi alone
does not update pip's separate bundled copy.

This is a trust-store vulnerability, not evidence that an AIDebug release was
modified. The GitHub publisher was fixed separately in
[PR #43](https://github.com/anpa1200/AIDebug/pull/43). That workflow change does
not update installed virtual environments or already-published PyPI files.

## Secure bootstrap

Use a supported, patched Python and the operating system's security updates.
The pip wheel below supports Python >=3.10. Python 3.10 is end-of-life; existing
3.10 environments can receive this pip mitigation but should migrate to a
supported interpreter. A pip/certifi update alone does not patch Python,
virtualenv, operating-system certificates, or other applications. The advisory
also calls for virtualenv >=21.14.12 and pipx >=1.18.7 where those tools are used;
update them through the supported system or application installation channel.

For a current source checkout, activate the intended virtual environment and
run `python scripts/bootstrap_pip.py` before other package installations. The
standard-library helper checks the current pip version, skips an already-fixed
stable version, installs only the advisory's hash-pinned wheel when necessary,
and verifies the result. It fails closed if installation or version checks fail.

Published 3.0.0 packages and historical source revisions do not contain that
helper. Run this standalone, version-aware bootstrap in the intended environment.
It skips an already-patched stable pip and never downgrades a newer one:

```bash
python - <<'PY'
import importlib.metadata
import re
import subprocess
import sys


def patched(version):
    match = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?(?:\.post\d+)?(?:\+[a-zA-Z0-9.]+)?", version)
    if match is None:
        raise RuntimeError("Unrecognized pip version; review it before installing anything")
    return tuple(int(part or 0) for part in match.groups()) >= (26, 2, 2)


if not patched(importlib.metadata.version("pip")):
    subprocess.run(
        [sys.executable, "-m", "pip", "--isolated", "--disable-pip-version-check",
         "install", "--no-index", "--no-deps", "--no-cache-dir", "--only-binary=:all:",
         "https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"],
        check=True,
    )
if not patched(importlib.metadata.version("pip")):
    raise RuntimeError("pip is still below 26.2.2; stop before installing anything")
print("Patched pip verified:", importlib.metadata.version("pip"))
PY
```

The SHA-256 is from the advisory, not from an untrusted download response. The
bootstrap disables package-index resolution, dependency downloads, cache use,
and pip's background version check. An unrecognized pip version or failed hash,
TLS, installation, or post-install check stops the bootstrap. If it fails, do not
run subsequent installation steps; do not use `--trusted-host` or disable
certificate verification.

Once pip is patched, update the environment's separate certifi bundle:

```bash
python -m pip install --upgrade "certifi>=2026.10.19"
python -m pip show pip certifi
python -m pip check
```

Repeat the checks for every environment that performs package downloads or
remote analysis. Recreating an environment does not guarantee its seeded pip
is current. New AI/all/dev AIDebug installs require the certifi floor; the offline
base package does not add network dependencies.

## Existing REMnux environment

Use the interpreter that owns AIDebug, not the system Python or another venv:

```bash
/opt/aidebug/bin/python3 -m pip show 1200km-aidebug pip certifi
```

With the privileges needed to update `/opt/aidebug`, apply the secure bootstrap
above using `/opt/aidebug/bin/python3` instead of `python`; it checks whether
an upgrade is needed. Only after it succeeds, run:

```bash
/opt/aidebug/bin/python3 -m pip install --upgrade "certifi>=2026.10.19"
/opt/aidebug/bin/python3 -m pip show 1200km-aidebug pip certifi
/opt/aidebug/bin/python3 -m pip check
/opt/aidebug/bin/aidebug --version
```

This changes pip/certifi, not the AIDebug release. Official REMnux updates are
still required for its system Python, virtualenv and other tools. The historical
state under `packaging/remnux/` is submission evidence, not the currently accepted
upstream provisioning file. Consult [REMnux integration](remnux.md) for that
boundary. No live REMnux VM validation is implied by this document.

## CI and release audits

CI's audit job installs all AIDebug extras, verifies dependency consistency,
and audits a frozen snapshot of the complete installed third-party dependency
graph. The local and publishing gates audit their installed dev/dynamic graph.
Only the first-party AIDebug package is excluded because its current source
version is not published; tests, static analysis and wheel smoke checks cover it.
Metadata checks still enforce parity between the requirements files and extras.

The audit uses `--strict --disable-pip --no-deps` only on fully resolved installed
pins. Do not apply those flags directly to the project's unpinned requirements.
This avoids pip-audit 2.10.1's resolver creating a new environment with an old
ensurepip seed before upgrading pip. Normal isolated builds use the already
patched outer pip; each explicit wheel-smoke environment is bootstrapped again.
