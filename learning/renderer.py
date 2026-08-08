"""Rich terminal rendering for learning-mode lessons."""
from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from .catalog import Lesson


def render_catalog(lessons: tuple[Lesson, ...], console: Console | None = None) -> None:
    output = console or Console()
    table = Table(title=f"AIDebug Learning Mode — {len(lessons)} lessons")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Category", style="magenta")
    table.add_column("Lesson", style="bold")
    for lesson in lessons:
        table.add_row(lesson.lesson_id, lesson.category, lesson.title)
    output.print(table)
    output.print("Open one lesson with: [cyan]aidebug --learn LESSON_ID[/cyan]")


def render_lesson(lesson: Lesson, console: Console | None = None) -> None:
    output = console or Console()
    body = Group(
        Text(f"Category: {lesson.category}", style="dim"),
        Text("\nAssembly", style="bold cyan"),
        Syntax(lesson.assembly, "asm", theme="ansi_dark", word_wrap=False),
        Text("Pseudo-code", style="bold green"),
        Syntax(lesson.pseudocode, "c", theme="ansi_dark", word_wrap=True),
        Text("What it means", style="bold"),
        Text(lesson.explanation),
        Text("\nRegister / flag effects", style="bold"),
        Text(lesson.effects),
        Text("\nAnalyst clue", style="bold yellow"),
        Text(lesson.analyst_clue),
        Text("\nCommon misreading", style="bold red"),
        Text(lesson.pitfall),
    )
    output.print(Panel(body, title=f"{lesson.lesson_id} — {lesson.title}", border_style="blue"))
