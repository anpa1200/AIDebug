#!/usr/bin/env python3
"""Check local Markdown links and heading fragments without network access."""

from __future__ import annotations

import re
import urllib.parse
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"!?(?:\[[^\]]*\])\(([^)]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$", re.MULTILINE)


def slug(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return re.sub(r"\s", "-", text)


def anchors(path: Path) -> set[str]:
    counts: Counter[str] = Counter()
    result: set[str] = set()
    for heading in HEADING.findall(path.read_text(encoding="utf-8")):
        base = slug(heading)
        suffix = f"-{counts[base]}" if counts[base] else ""
        result.add(f"{base}{suffix}")
        counts[base] += 1
    return result


def main() -> None:
    markdown_files = sorted(
        path for path in ROOT.rglob("*.md") if ".git" not in path.parts and "build" not in path.parts
    )
    failures: list[str] = []
    checked = 0

    for source in markdown_files:
        text = source.read_text(encoding="utf-8")
        # Avoid treating examples inside fenced code blocks as links.
        text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
        for raw_target in LINK.findall(text):
            target = raw_target.strip().strip("<>").split(maxsplit=1)[0]
            if target.startswith(("http://", "https://", "mailto:", "data:")):
                continue
            path_part, separator, fragment = target.partition("#")
            destination = source if not path_part else source.parent / urllib.parse.unquote(path_part)
            destination = destination.resolve()
            checked += 1
            try:
                destination.relative_to(ROOT)
            except ValueError:
                failures.append(f"{source.relative_to(ROOT)}: link escapes repository: {target}")
                continue
            if not destination.exists():
                failures.append(f"{source.relative_to(ROOT)}: missing target: {target}")
                continue
            if separator and fragment and destination.is_file() and destination.suffix.lower() == ".md":
                decoded_fragment = urllib.parse.unquote(fragment).lower()
                if decoded_fragment not in anchors(destination):
                    failures.append(
                        f"{source.relative_to(ROOT)}: missing heading #{decoded_fragment} in "
                        f"{destination.relative_to(ROOT)}"
                    )

    if failures:
        raise SystemExit("\n".join(failures))
    print(f"Checked {checked} local Markdown links across {len(markdown_files)} files.")


if __name__ == "__main__":
    main()
