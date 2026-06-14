# Kali/Debian Dependency Notes

The included `debian/` metadata is prepared for the currently packaged Python
dependencies available in Debian/Kali-style repositories on this machine.

## Packaged dependencies found locally

- `python3-capstone`
- `python3-pefile`
- `python3-pyelftools`
- `python3-rich`
- `python3-textual`
- `pybuild-plugin-pyproject`
- `dh-python`
- `debhelper-compat`

## Dependency gaps to discuss with Kali maintainers

These upstream Python packages are declared by the PyPI project but did not have
matching Debian/Kali packages in the local apt cache:

- `anthropic`
- `frida`

Practical options:

1. Package `python3-anthropic` and `python3-frida` separately, then add them to
   `Depends` or `Recommends`.
2. Keep the Kali package focused on static analysis and document AI/dynamic
   features as optional extras installed outside the Debian package.
3. Split optional features later, if maintainers prefer a minimal package first.

The current Debian metadata avoids non-existent binary package names so the
control file stays valid for initial maintainer review.
