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
    assert get_lesson("load-u32").function_name == "learn_load_u32"
    assert get_lesson("missing") is None
    matches = find_lessons("arithmetic")
    assert matches
    assert any(lesson.category == "arithmetic" for lesson in matches)


def test_every_catalog_lesson_maps_to_one_real_c_function():
    corpus = LiveLearningAnalyzer._read_corpus()
    for lesson in catalog():
        source = LiveLearningAnalyzer._extract_function_source(corpus, lesson.lesson_id)
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
    assert "sub" in result.assembly.lower()
    assert "0x" in result.assembly
    assert result.pseudocode.startswith("int learn_subtract")
    assert len(result.artifact_sha256) == 64
