# Release Process

This checklist keeps AIDebug releases reviewer-friendly and package-ready.

## Pre-Release

- Update `pyproject.toml` version.
- Update `CHANGELOG.md`.
- Add `docs/release-notes/vX.Y.Z.md`.
- Update `CITATION.cff`.
- Update package/discovery links if the public release tag changes.
- Confirm no live malware samples are added.

## Verification

```bash
python3 -m pip install -e ".[dev]"
python3 -m pytest -q
rm -rf dist build *.egg-info
python3 -m build
python3 -m twine check dist/*
```

## GitHub Release

1. Create tag `vX.Y.Z`.
2. Attach source distribution and wheel from `dist/`.
3. Paste `docs/release-notes/vX.Y.Z.md` as the release body.
4. Verify the PyPI workflow publishes or skips existing artifacts cleanly.

## Post-Release

- Check PyPI metadata renders correctly.
- Check README screenshot links.
- Update external submission references only after the release exists.
