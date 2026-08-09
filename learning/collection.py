"""Validated external Learning Mode collections."""
from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from .catalog import Lesson, catalog

COLLECTION_MANIFEST = "collection.json"
COMMON_HEADER = "case_common.h"
MAX_COLLECTION_CASES = 500
MAX_MANIFEST_BYTES = 1_000_000
MAX_SOURCE_BYTES = 256_000
MAX_HEADER_BYTES = 64_000
_LESSON_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")


class LearningCollectionError(ValueError):
    """An external learning collection is malformed or unsafe to load."""


@dataclass(frozen=True)
class LearningCollection:
    """A validated directory of standalone C learning cases."""

    name: str
    root: Path
    lessons: tuple[Lesson, ...]
    source_paths: dict[str, Path]
    header_path: Path

    def get_lesson(self, lesson_id: str) -> Lesson | None:
        normalized = lesson_id.strip().lower()
        return next(
            (lesson for lesson in self.lessons if lesson.lesson_id == normalized),
            None,
        )

    def find_lessons(self, query: str) -> tuple[Lesson, ...]:
        needle = query.strip().lower()
        if not needle or needle in {"list", "all"}:
            return self.lessons
        return tuple(
            lesson
            for lesson in self.lessons
            if needle
            in " ".join(
                (
                    lesson.lesson_id,
                    lesson.function_name,
                    lesson.title,
                    lesson.category,
                )
            ).lower()
        )

    def read_case(self, lesson_id: str) -> tuple[str, str]:
        try:
            path = self.source_paths[lesson_id]
        except KeyError as exc:
            raise LearningCollectionError(
                f"External collection has no source for lesson {lesson_id}"
            ) from exc
        return os.fspath(path), _read_text(path, MAX_SOURCE_BYTES, "case source")

    def read_common_header(self) -> str:
        return _read_text(self.header_path, MAX_HEADER_BYTES, "common header")


def load_learning_collection(path: str | os.PathLike[str]) -> LearningCollection:
    """Load a directory containing case_common.h, C cases, and an optional manifest."""
    candidate = Path(path).expanduser()
    try:
        root = candidate.resolve(strict=True)
    except OSError as exc:
        raise LearningCollectionError(f"Unable to open learning collection: {exc}") from exc
    if not root.is_dir():
        raise LearningCollectionError(f"Learning collection is not a directory: {root}")

    header_path = _contained_file(root, Path(COMMON_HEADER), ".h")
    manifest_path = root / COLLECTION_MANIFEST
    if manifest_path.exists():
        name, records, inherit_builtin = _manifest_records(root, manifest_path)
    else:
        name = root.name
        inherit_builtin = False
        records = [
            {"id": item.stem, "source": item.name}
            for item in sorted(root.glob("*.c"))
        ]
    if not records:
        raise LearningCollectionError("Learning collection contains no C cases")
    if len(records) > MAX_COLLECTION_CASES:
        raise LearningCollectionError(
            f"Learning collection exceeds the {MAX_COLLECTION_CASES}-case limit"
        )

    lessons: list[Lesson] = []
    sources: dict[str, Path] = {}
    builtins = {lesson.lesson_id: lesson for lesson in catalog()}
    for index, record in enumerate(records, start=1):
        if isinstance(record, str):
            inherited = builtins.get(record) if inherit_builtin else None
            record = (
                {
                    "id": inherited.lesson_id,
                    "title": inherited.title,
                    "category": inherited.category,
                    "explanation": inherited.explanation,
                    "effects": inherited.effects,
                    "analyst_clue": inherited.analyst_clue,
                    "pitfall": inherited.pitfall,
                }
                if inherited is not None
                else {"id": record}
            )
        if not isinstance(record, dict):
            raise LearningCollectionError(
                f"Manifest case {index} must be an ID string or metadata object"
            )
        lesson_id = _required_id(record.get("id"), index)
        if lesson_id in sources:
            raise LearningCollectionError(f"Duplicate learning case ID: {lesson_id}")
        source_name = record.get("source", f"{lesson_id}.c")
        if not isinstance(source_name, str) or not source_name.strip():
            raise LearningCollectionError(f"Case {lesson_id} has an invalid source path")
        source_path = _contained_file(root, Path(source_name), ".c")
        function_name = f"learn_{lesson_id.replace('-', '_')}"
        source = _read_text(source_path, MAX_SOURCE_BYTES, "case source")
        if re.search(rf"\b{re.escape(function_name)}\s*\(", source) is None:
            raise LearningCollectionError(
                f"Case {lesson_id} must define {function_name}(...)"
            )

        title = _text_field(record, "title", lesson_id.replace("-", " ").title())
        category = _text_field(record, "category", "external collection")
        lessons.append(
            Lesson(
                lesson_id=lesson_id,
                title=title,
                category=category,
                function_name=function_name,
                explanation=_text_field(
                    record,
                    "explanation",
                    f"External real-code lesson: {title}.",
                ),
                effects=_text_field(
                    record,
                    "effects",
                    "Inspect the compiler-generated instructions and data flow.",
                ),
                analyst_clue=_text_field(
                    record,
                    "analyst_clue",
                    "Compare the exact C source with the disassembly and Ghidra output.",
                ),
                pitfall=_text_field(
                    record,
                    "pitfall",
                    "Compiler output can vary by version and optimization strategy.",
                ),
            )
        )
        sources[lesson_id] = source_path

    return LearningCollection(
        name=name,
        root=root,
        lessons=tuple(lessons),
        source_paths=sources,
        header_path=header_path,
    )


def _manifest_records(root: Path, path: Path) -> tuple[str, list, bool]:
    manifest_path = _contained_file(root, Path(path.name), ".json")
    raw = _read_text(manifest_path, MAX_MANIFEST_BYTES, "collection manifest")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LearningCollectionError(f"Invalid collection.json: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise LearningCollectionError("collection.json must use schema_version 1")
    name = payload.get("name", root.name)
    if not isinstance(name, str) or not name.strip() or len(name) > 120:
        raise LearningCollectionError("collection.json has an invalid name")
    records = payload.get("cases")
    if not isinstance(records, list):
        raise LearningCollectionError("collection.json cases must be a list")
    inherit_builtin = payload.get("inherit_builtin_metadata", False)
    if not isinstance(inherit_builtin, bool):
        raise LearningCollectionError(
            "collection.json inherit_builtin_metadata must be true or false"
        )
    return name.strip(), records, inherit_builtin


def _required_id(value, index: int) -> str:
    if not isinstance(value, str):
        raise LearningCollectionError(f"Manifest case {index} has no valid ID")
    lesson_id = value.strip().lower()
    if _LESSON_ID.fullmatch(lesson_id) is None:
        raise LearningCollectionError(
            f"Invalid learning case ID {value!r}; use lowercase letters, digits, and hyphens"
        )
    return lesson_id


def _text_field(record: dict, key: str, default: str) -> str:
    value = record.get(key, default)
    if not isinstance(value, str) or not value.strip() or len(value) > 2_000:
        raise LearningCollectionError(f"Case metadata field {key!r} is invalid")
    return value.strip()


def _contained_file(root: Path, relative: Path, suffix: str) -> Path:
    if relative.is_absolute() or relative.suffix.lower() != suffix:
        raise LearningCollectionError(f"Collection file must be a relative {suffix} path")
    try:
        resolved = (root / relative).resolve(strict=True)
    except OSError as exc:
        raise LearningCollectionError(f"Unable to open collection file {relative}: {exc}") from exc
    if not resolved.is_relative_to(root):
        raise LearningCollectionError(f"Collection path escapes its directory: {relative}")
    try:
        mode = resolved.stat().st_mode
    except OSError as exc:
        raise LearningCollectionError(f"Unable to inspect collection file {relative}: {exc}") from exc
    if not stat.S_ISREG(mode):
        raise LearningCollectionError(f"Collection path is not a regular file: {relative}")
    return resolved


def _read_text(path: Path, limit: int, label: str) -> str:
    try:
        size = path.stat().st_size
        if size > limit:
            raise LearningCollectionError(f"{label.title()} exceeds the {limit}-byte limit: {path}")
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise LearningCollectionError(f"{label.title()} must be UTF-8: {path}") from exc
    except OSError as exc:
        raise LearningCollectionError(f"Unable to read {label} {path}: {exc}") from exc
