"""The test-suite guard against markup that a theme cannot colour."""

from __future__ import annotations

import pytest
from rich.errors import MarkupError
from rich.text import Text
from textual.content import Content

from e2e.harness.markup_guard import named_colour_tags, theme_variable_tags, watch


@pytest.mark.parametrize(
    ("markup", "tags"),
    [
        ("[bold cyan]Title[/bold cyan]", ["[bold cyan]"]),
        ("[bright_green]ok[/]", ["[bright_green]"]),
        ("[b $background on yellow] DEMO [/]", ["[b $background on yellow]"]),
        ("[$text-warning]warn[/$text-warning] [dim]note[/dim]", []),
        ("\\[red] is text, [redacted] is not a colour", []),
    ],
)
def test_named_colour_tags(markup, tags) -> None:
    assert named_colour_tags(markup) == tags


def test_theme_variable_tags() -> None:
    markup = "[bold $text-accent]a[/] [$accent 50%]b[/] [b]c[/b] [red]d[/red]"
    assert theme_variable_tags(markup) == ["[bold $text-accent]", "[$accent 50%]"]


def test_watch_reports_each_parser_its_own_mistake() -> None:
    with watch() as watcher:
        Content.from_markup("[red]fixed[/red] [$text-error]themed[/]")
        Text.from_markup("[red]palette[/red]")
        with pytest.raises(MarkupError):
            Text.from_markup("[$text-error]unknown to Rich[/$text-error]")
    assert [(f.parser, f.tags) for f in watcher.findings] == [
        ("Textual", ["[red]"]),
        ("Rich", ["[$text-error]"]),
    ]


def test_watch_restores_the_parsers() -> None:
    import rich.markup
    import textual.markup

    before = (textual.markup.to_content, rich.markup.render)
    with watch():
        assert (textual.markup.to_content, rich.markup.render) != before
    assert (textual.markup.to_content, rich.markup.render) == before
