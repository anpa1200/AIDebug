#!/usr/bin/env python3
"""Fail when AIDebug's duplicated release metadata drifts out of sync."""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 support
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(f"release metadata error: {message}", file=sys.stderr)
    raise SystemExit(1)


def config_version() -> str:
    tree = ast.parse((ROOT / "config.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == "APP_VERSION" for target in node.targets):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    fail("config.py must define APP_VERSION as a string literal")
    return ""  # pragma: no cover


def quoted_yaml_value(path: Path, key: str) -> str:
    pattern = re.compile(rf"^{re.escape(key)}:\s*[\"']?([^\"'#\s]+)[\"']?\s*$", re.MULTILINE)
    match = pattern.search(path.read_text(encoding="utf-8"))
    if not match:
        fail(f"{path.relative_to(ROOT)} does not define {key}")
    return match.group(1)


def changelog_release() -> tuple[str, str]:
    match = re.search(
        r"^##\s+(\d+\.\d+\.\d+)\s+-\s+(\d{4}-\d{2}-\d{2})\s*$",
        (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if not match:
        fail("CHANGELOG.md must begin with a dated semantic-version release heading")
    return match.group(1), match.group(2)


def has_unreleased_changes() -> bool:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(
        r"^## Unreleased\s*$\n(?P<body>.*?)(?=^##\s)",
        changelog,
        re.MULTILINE | re.DOTALL,
    )
    return bool(match and match.group("body").strip())


def debian_upstream_version() -> str:
    first_line = (ROOT / "debian/changelog").read_text(encoding="utf-8").splitlines()[0]
    match = re.match(r"^aidebug \(([^)]+)\)", first_line)
    if not match:
        fail("debian/changelog has an invalid first line")
    return match.group(1).split("-", 1)[0]


def normalized_requirements(lines: list[str]) -> set[tuple[str, str, str, str, str]]:
    requirements: set[tuple[str, str, str, str, str]] = set()
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        requirement = Requirement(line)
        requirements.add(
            (
                canonicalize_name(requirement.name),
                ",".join(sorted(requirement.extras)),
                str(requirement.specifier),
                requirement.url or "",
                str(requirement.marker or ""),
            )
        )
    return requirements


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="release tag to verify, for example v1.1.0")
    args = parser.parse_args()

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = project["version"]
    cff_version = quoted_yaml_value(ROOT / "CITATION.cff", "version")
    cff_date = quoted_yaml_value(ROOT / "CITATION.cff", "date-released")
    changelog_version, changelog_date = changelog_release()

    copies = {
        "config.py APP_VERSION": config_version(),
        "CITATION.cff version": cff_version,
        "CHANGELOG.md latest release": changelog_version,
        "debian/changelog upstream version": debian_upstream_version(),
    }
    for source, candidate in copies.items():
        if candidate != version:
            fail(f"{source} is {candidate!r}, expected {version!r}")

    if cff_date != changelog_date:
        fail(f"CITATION.cff date {cff_date!r} does not match changelog date {changelog_date!r}")

    release_notes = ROOT / "docs" / "release-notes" / f"v{version}.md"
    if not release_notes.is_file():
        fail(f"missing {release_notes.relative_to(ROOT)}")

    man_page = (ROOT / "debian/aidebug.1").read_text(encoding="utf-8")
    if f'"aidebug {version}"' not in man_page:
        fail(f"debian/aidebug.1 does not identify aidebug {version}")

    runtime_requirements = normalized_requirements(project["dependencies"])
    file_requirements = normalized_requirements(
        (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    )
    if runtime_requirements != file_requirements:
        fail(
            "requirements.txt and project dependencies differ: "
            f"only pyproject={sorted(runtime_requirements - file_requirements)}, "
            f"only requirements={sorted(file_requirements - runtime_requirements)}"
        )

    extra_files = {
        "ai": ROOT / "requirements-ai.txt",
        "dynamic": ROOT / "requirements-dynamic.txt",
    }
    for extra, path in extra_files.items():
        declared = normalized_requirements(project["optional-dependencies"][extra])
        mirrored = normalized_requirements(path.read_text(encoding="utf-8").splitlines())
        if declared != mirrored:
            fail(f"{path.name} does not match the {extra!r} optional dependency set")

    expected_all = normalized_requirements(
        project["optional-dependencies"]["ai"] + project["optional-dependencies"]["dynamic"]
    )
    declared_all = normalized_requirements(project["optional-dependencies"]["all"])
    if declared_all != expected_all:
        fail("the 'all' extra must be the union of the 'ai' and 'dynamic' extras")

    if args.tag:
        expected_tag = f"v{version}"
        if args.tag != expected_tag:
            fail(f"release tag {args.tag!r} does not match package version ({expected_tag!r})")
        if has_unreleased_changes():
            fail("CHANGELOG.md still contains Unreleased changes; bump the version and prepare release notes")

    suffix = " Unreleased changes require a new version before tagging." if has_unreleased_changes() else ""
    print(f"Release metadata is consistent for v{version}.{suffix}")


if __name__ == "__main__":
    main()
