from learning import catalog, find_lessons, get_lesson


def test_learning_catalog_has_at_least_thirty_complete_unique_lessons():
    lessons = catalog()
    assert len(lessons) >= 30
    assert len({lesson.lesson_id for lesson in lessons}) == len(lessons)
    for lesson in lessons:
        assert lesson.title
        assert lesson.category
        assert lesson.assembly
        assert lesson.pseudocode
        assert lesson.explanation
        assert lesson.effects
        assert lesson.analyst_clue
        assert lesson.pitfall


def test_learning_catalog_supports_exact_and_category_search():
    assert get_lesson("mov-load").pseudocode.startswith("value =")
    assert get_lesson("missing") is None
    matches = find_lessons("control flow")
    assert matches
    assert all(lesson.category == "control flow" for lesson in matches)
