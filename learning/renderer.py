"""Rich terminal rendering for learning-mode lessons."""
from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from .catalog import Lesson
from .live import AnalyzedLesson


def render_catalog(lessons: tuple[Lesson, ...], console: Console | None = None) -> None:
    output = console or Console()
    table = Table(title=f"AIDebug Learning Mode — {len(lessons)} lessons")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Category", style="magenta")
    table.add_column("Lesson", style="bold")
    for lesson in lessons:
        table.add_row(lesson.lesson_id, lesson.category, lesson.title)
    output.print(table)
    output.print(
        "Analyze one real compiled function with: "
        "[cyan]aidebug --learn LESSON_ID[/cyan]"
    )


def render_lesson(result: AnalyzedLesson, console: Console | None = None) -> None:
    output = console or Console()
    lesson = result.lesson
    body = Group(
        Text(f"Category: {lesson.category}", style="dim"),
        Text(f"Function: {lesson.function_name} @ 0x{result.function_address:x}", style="dim"),
        Text(f"Source file: {result.source_file}", style="dim"),
        Text(f"Compiler: {result.compiler}", style="dim"),
        Text(f"Artifact SHA-256: {result.artifact_sha256}", style="dim"),
        Text("\nReal C function compiled for this lesson", style="bold magenta"),
        Syntax(result.source, "c", theme="ansi_dark", word_wrap=True),
        Text("Compiler-generated assembly (address, bytes, instruction)", style="bold cyan"),
        Syntax(result.assembly, "asm", theme="ansi_dark", word_wrap=False),
        Text(f"{result.decompiler}-generated pseudo-code", style="bold green"),
        Syntax(result.pseudocode, "c", theme="ansi_dark", word_wrap=True),
        Text(result.warning, style="dim italic"),
        Text("What it means", style="bold"),
        Text(lesson.explanation),
        Text("\nRegister / flag effects", style="bold"),
        Text(lesson.effects),
        Text("\nAnalyst clue", style="bold yellow"),
        Text(lesson.analyst_clue),
        Text("\nCommon misreading", style="bold red"),
        Text(lesson.pitfall),
    )
    output.print(
        Panel(
            body,
            title=f"{lesson.lesson_id} — {lesson.title} — LIVE ELF ANALYSIS",
            border_style="blue",
        )
    )
