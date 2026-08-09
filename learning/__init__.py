"""Built-in reverse-engineering learning mode."""

from .catalog import Lesson, catalog, find_lessons, get_lesson
from .collection import (
    LearningCollection,
    LearningCollectionError,
    load_learning_collection,
)
from .live import AnalyzedLesson, LearningAnalysisError, LiveLearningAnalyzer
from .renderer import render_catalog, render_lesson

__all__ = [
    "Lesson",
    "AnalyzedLesson",
    "LearningAnalysisError",
    "LearningCollection",
    "LearningCollectionError",
    "LiveLearningAnalyzer",
    "catalog",
    "find_lessons",
    "get_lesson",
    "load_learning_collection",
    "render_catalog",
    "render_lesson",
]
