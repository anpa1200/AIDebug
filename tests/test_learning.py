import json
import shutil
from types import SimpleNamespace

import pytest

from learning import (
    LearningCollectionError,
    LiveLearningAnalyzer,
    catalog,
    find_lessons,
    get_lesson,
    load_learning_collection,
)


def test_learning_catalog_has_one_hundred_complete_unique_lessons():
    lessons = catalog()
    assert len(lessons) == 100
    assert len({lesson.lesson_id for lesson in lessons}) == len(lessons)
    for lesson in lessons:
        assert lesson.title
        assert lesson.category
        assert lesson.function_name.startswith("learn_")
        assert lesson.explanation
        assert lesson.effects
        assert lesson.analyst_clue
        assert lesson.pitfall


def test_learning_catalog_supports_exact_and_category_search():
    assert get_lesson("mov-load").function_name == "learn_mov_load"
    assert get_lesson("load-u32").lesson_id == "mov-load"
    assert get_lesson("missing") is None
    matches = find_lessons("arithmetic")
    assert matches
    assert any(lesson.category == "arithmetic" for lesson in matches)


def test_every_catalog_lesson_maps_to_one_real_c_function():
    for lesson in catalog():
        filename, source = LiveLearningAnalyzer._read_case(lesson.lesson_id)
        assert filename == f"{lesson.lesson_id}.c"
        assert lesson.function_name in source


@pytest.mark.skipif(not any(shutil.which(name) for name in ("cc", "gcc", "clang")), reason="no C compiler")
def test_live_learning_compiles_real_elf_and_uses_real_disassembly():
    class FakeDecompiler:
        def __init__(self, info, executable=None):
            assert info.raw_data.startswith(b"\x7fELF")
            assert executable is None

        def decompile(self, addresses):
            address = addresses[0]
            return {
                address: SimpleNamespace(
                    code="int learn_subtract(int left, int right) { return left - right; }",
                    backend="test-ghidra",
                    warning="test reconstruction",
                )
            }

    result = LiveLearningAnalyzer(decompiler_factory=FakeDecompiler).analyze(
        get_lesson("subtract")
    )

    assert "learn_subtract" in result.source
    assert result.source_file == "learning/cases/subtract.c"
    assert "sub" in result.assembly.lower()
    assert "0x" in result.assembly
    assert result.pseudocode.startswith("int learn_subtract")
    assert len(result.artifact_sha256) == 64


@pytest.mark.skipif(not any(shutil.which(name) for name in ("cc", "gcc", "clang")), reason="no C compiler")
def test_dedicated_data_movement_files_emit_their_real_instruction_families():
    class FakeDecompiler:
        def __init__(self, info, executable=None):
            self.info = info

        def decompile(self, addresses):
            address = addresses[0]
            return {
                address: SimpleNamespace(
                    code="void reconstructed_from_machine_code(void) {}",
                    backend="test-ghidra",
                    warning="test reconstruction",
                )
            }

    analyzer = LiveLearningAnalyzer(decompiler_factory=FakeDecompiler)
    expected = {
        "mov-load": "mov eax",
        "mov-store": "mov dword ptr",
        "lea-address": "lea rax",
        "lea-arithmetic": "lea eax",
        "movzx": "movzx",
        "movsx": "movsx",
        "movsxd": "movsxd",
        "xchg": "xchg",
    }
    for lesson_id, mnemonic in expected.items():
        result = analyzer.analyze(get_lesson(lesson_id))
        assert result.source_file == f"learning/cases/{lesson_id}.c"
        assert mnemonic in result.assembly.lower()


@pytest.mark.skipif(not any(shutil.which(name) for name in ("cc", "gcc", "clang")), reason="no C compiler")
@pytest.mark.parametrize("lesson_id", tuple(item.lesson_id for item in catalog()))
def test_every_learning_case_compiles_to_real_disassembly(lesson_id):
    class FakeDecompiler:
        def __init__(self, info, executable=None):
            assert info.raw_data.startswith(b"\x7fELF")

        def decompile(self, addresses):
            address = addresses[0]
            return {
                address: SimpleNamespace(
                    code="void reconstructed_from_machine_code(void) {}",
                    backend="test-ghidra",
                    warning="test reconstruction",
                )
            }

    result = LiveLearningAnalyzer(decompiler_factory=FakeDecompiler).analyze(
        get_lesson(lesson_id)
    )

    assert result.source_file == f"learning/cases/{lesson_id}.c"
    assert result.lesson.function_name in result.source
    assert result.assembly.strip()
    assert "0x" in result.assembly


def test_repository_core_collection_manifest_lists_all_cases():
    collection = load_learning_collection("learning/cases")

    assert collection.name == "AIDebug Core 100"
    assert len(collection.lessons) == 100
    assert tuple(item.lesson_id for item in collection.lessons) == tuple(
        item.lesson_id for item in catalog()
    )
    assert collection.get_lesson("binary-search").title == "Binary search"


def test_external_collection_loads_manifest_metadata_and_source(tmp_path):
    collection_root = tmp_path / "external-lessons"
    collection_root.mkdir()
    (collection_root / "case_common.h").write_text(
        "#include <stdint.h>\n#define LEARN __attribute__((noinline, used))\n",
        encoding="utf-8",
    )
    (collection_root / "external-add.c").write_text(
        '#include "case_common.h"\n'
        "LEARN uint32_t learn_external_add(uint32_t value) { return value + 7u; }\n",
        encoding="utf-8",
    )
    (collection_root / "collection.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "name": "Analyst Cases",
                "cases": [
                    {
                        "id": "external-add",
                        "title": "External addition",
                        "category": "analyst collection",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    collection = load_learning_collection(collection_root)

    assert collection.name == "Analyst Cases"
    assert collection.get_lesson("external-add").function_name == "learn_external_add"
    source_path, source = collection.read_case("external-add")
    assert source_path == str((collection_root / "external-add.c").resolve())
    assert "learn_external_add" in source


def test_external_collection_rejects_source_path_escape(tmp_path):
    collection_root = tmp_path / "external-lessons"
    collection_root.mkdir()
    (collection_root / "case_common.h").write_text("#include <stdint.h>\n", encoding="utf-8")
    (tmp_path / "outside.c").write_text(
        "int learn_escape(void) { return 0; }\n",
        encoding="utf-8",
    )
    (collection_root / "collection.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "cases": [{"id": "escape", "source": "../outside.c"}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(LearningCollectionError, match="escapes its directory"):
        load_learning_collection(collection_root)


@pytest.mark.skipif(not any(shutil.which(name) for name in ("cc", "gcc", "clang")), reason="no C compiler")
def test_external_collection_case_runs_through_real_analysis_pipeline(tmp_path):
    collection_root = tmp_path / "external-lessons"
    collection_root.mkdir()
    (collection_root / "case_common.h").write_text(
        "#include <stdint.h>\n#define LEARN __attribute__((noinline, used))\n",
        encoding="utf-8",
    )
    (collection_root / "external-add.c").write_text(
        '#include "case_common.h"\n'
        "LEARN uint32_t learn_external_add(uint32_t value) { return value + 7u; }\n",
        encoding="utf-8",
    )
    collection = load_learning_collection(collection_root)

    class FakeDecompiler:
        def __init__(self, info, executable=None):
            assert info.raw_data.startswith(b"\x7fELF")

        def decompile(self, addresses):
            address = addresses[0]
            return {
                address: SimpleNamespace(
                    code="uint32_t learn_external_add(uint32_t value) { return value + 7; }",
                    backend="test-ghidra",
                    warning="test reconstruction",
                )
            }

    result = LiveLearningAnalyzer(
        collection=collection,
        decompiler_factory=FakeDecompiler,
    ).analyze(collection.get_lesson("external-add"))

    assert result.source_file == str((collection_root / "external-add.c").resolve())
    assert "learn_external_add" in result.source
    assert "0x" in result.assembly
    assert "learn_external_add" in result.pseudocode
