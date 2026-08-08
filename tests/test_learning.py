import shutil
from types import SimpleNamespace

import pytest

from learning import LiveLearningAnalyzer, catalog, find_lessons, get_lesson


def test_learning_catalog_has_at_least_thirty_complete_unique_lessons():
    lessons = catalog()
    assert len(lessons) >= 30
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
