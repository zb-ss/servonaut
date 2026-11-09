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


@pytest.fixture
def shipped_parsers():
    """The parsers as the app runs them: the backstop live."""
    from servonaut.utils import markup_backstop

    markup_backstop.install()
    yield markup_backstop
    markup_backstop.install()


def test_watch_reports_each_parser_its_own_mistake(shipped_parsers) -> None:
    with watch() as watcher:
        Content.from_markup("[red]fixed[/red] [$text-error]themed[/]")
        Text.from_markup("[red]palette[/red]")
        # Not an error here: the backstop shows it as text, and the guard records it.
        Text.from_markup("[$text-error]unknown to Rich[/$text-error]")
    assert [(f.parser, f.tags[0]) for f in watcher.findings[:2]] == [
        ("Textual", "[red]"),
        ("Rich", "[$text-error]"),
    ]
    assert watcher.findings[2].parser == "Rich"
    assert watcher.findings[2].tags[0].startswith("[malformed markup: closing tag '[/$text-error]'")
    assert len(watcher.findings) == 3


def test_a_broken_app_string_is_still_reported_with_the_backstop_live(shipped_parsers) -> None:
    with watch() as watcher:
        content = Content.from_markup("[bold]Deploy [/italic] finished")
        text = Text.from_markup("[bold]Deploy [/italic] finished")
    assert content.plain == text.plain == "[bold]Deploy [/italic] finished"
    assert [f.parser for f in watcher.findings] == ["Textual", "Rich"]
    assert all("malformed markup" in f.tags[0] for f in watcher.findings)


def test_watch_runs_the_shipped_parsers_underneath(shipped_parsers) -> None:
    import rich.markup
    import textual.markup

    with watch():
        assert shipped_parsers.safe_to_content in _chain(textual.markup.to_content)
        assert shipped_parsers.safe_rich_render in _chain(rich.markup.render)
        assert shipped_parsers.installed()  # live beneath the checkers
        shipped_parsers.install()  # an app starting inside the watch must not loop the layers
        assert Content.from_markup("a[/]b").plain == "a[/]b"
    assert shipped_parsers.installed()


def test_watch_over_the_raw_parsers_still_raises() -> None:
    from servonaut.utils import markup_backstop

    with markup_backstop.suspended():
        with watch() as watcher:
            with pytest.raises(MarkupError):
                Text.from_markup("[$text-error]unknown to Rich[/$text-error]")
    assert [f.parser for f in watcher.findings] == ["Rich", "Rich"]


def test_the_backstop_installed_inside_a_watch_stays_live_after_it(shipped_parsers) -> None:
    from servonaut.utils import markup_backstop

    markup_backstop.uninstall()
    with watch():
        markup_backstop.install()
        assert markup_backstop.installed()
    # The harness restored what it found; the next install starts from the live state.
    markup_backstop.install()
    assert markup_backstop.installed()
    assert Content.from_markup("a[/]b").plain == "a[/]b"


def _chain(function):
    chain = []
    while function is not None:
        chain.append(function)
        function = getattr(function, "__wrapped__", None)
    return chain


def test_watch_restores_the_parsers() -> None:
    import rich.markup
    import textual.markup

    before = (textual.markup.to_content, rich.markup.render)
    with watch():
        assert (textual.markup.to_content, rich.markup.render) != before
    assert (textual.markup.to_content, rich.markup.render) == before
