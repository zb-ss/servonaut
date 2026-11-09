"""The markup backstop: no parse of a plain string carries an action, a link or an error.

1. Fingerprints. The backstop replaces two parser functions and relies on how
   Textual and Rich call them. Each test fails when an upgrade changes what the
   backstop depends on, so a new Textual or Rich cannot silently bypass it.
2. Behaviour. Strings from outside the app through every parser path are inert, in real
   widgets, and the app's own styling survives.
"""
from __future__ import annotations

import dataclasses
import hashlib
import inspect
import sys
import textwrap

import pytest
import rich.console
import rich.markup
import textual.markup
from rich.style import Style as RichStyle
from rich.text import Text
from textual.app import App, ComposeResult
from textual.content import Content
from textual.style import Style as TextualStyle
from textual.widgets import Button, DataTable, Label, OptionList, Select, Static, Tree

from servonaut.utils import markup_backstop


@pytest.fixture(autouse=True)
def installed_backstop():
    markup_backstop.install()
    yield
    markup_backstop.install()


def _digest(function) -> str:
    return hashlib.sha256(textwrap.dedent(inspect.getsource(function)).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------

_UPSTREAM_SOURCE_SHA256 = {
    "textual.markup.to_content": "6f0f40a7f6c5e00b5632a4f370fb3e9a2d4a41cb5dc9ecd565cf1ac4467c5ecb",
    "rich.markup.render": "32aa0fea30886f05bd09868554406534d9a589cf5527d1ef7d9eb7921eccaf76",
    "Content.from_markup": "feb8b319a3d36ee51734271840fd08f4dc28103438c78bb7af124bcb71e3f8ba",
    "Text.from_markup": "fee121e23cf3cb8397a594b173e6028c7a9c85b9b31782b3ac8e631482cfc3a1",
    "Console.render_str": "165e260177f9a5b6a07e194b51679b9c3fc0b4274496aaeec4803cbc3223d3ac",
    "RichStyle.clear_meta_and_links": "3362b4fb7f4a32d25b36ad3c25e13b03c1ddf1f0130b659e16f41ac5ea6c8134",
}


def _upstream_functions():
    return {
        "textual.markup.to_content": markup_backstop.original_textual_parser(),
        "rich.markup.render": markup_backstop.original_rich_parser(),
        "Content.from_markup": Content.from_markup,
        "Text.from_markup": Text.from_markup,
        "Console.render_str": rich.console.Console.render_str,
        "RichStyle.clear_meta_and_links": RichStyle.clear_meta_and_links,
    }


@pytest.mark.parametrize("name", sorted(_UPSTREAM_SOURCE_SHA256))
def test_upstream_function_is_the_one_the_backstop_was_written_against(name) -> None:
    assert _digest(_upstream_functions()[name]) == _UPSTREAM_SOURCE_SHA256[name]


def test_the_wrappers_sit_where_every_caller_looks_them_up() -> None:
    # These callers import the parser when they run, so replacing the module
    # attribute is enough for them.
    assert "from textual.markup import to_content" in inspect.getsource(Content.from_markup)
    assert "from .markup import render" in inspect.getsource(Text.from_markup)
    assert "render_markup(" in inspect.getsource(rich.console.Console.render_str)
    assert textual.markup.to_content is markup_backstop.safe_to_content
    assert rich.markup.render is markup_backstop.safe_rich_render
    assert rich.console.render_markup is markup_backstop.safe_rich_render


def test_no_other_module_keeps_a_reference_to_an_upstream_parser() -> None:
    originals = (markup_backstop.original_textual_parser(), markup_backstop.original_rich_parser())
    holders = sorted(
        f"{name}.{attribute}"
        for name, module in list(sys.modules.items())
        if module is not None and name.split(".")[0] in {"textual", "rich"}
        for attribute, value in list(vars(module).items())
        if any(value is original for original in originals)
    )
    # The stylesheet's own error help text is not app text; the rest are the
    # modules the backstop replaces.
    assert [h for h in holders if not h.startswith("textual.css.")] == []


def test_style_objects_still_have_the_fields_the_cleaning_removes() -> None:
    assert {"link", "_meta"} <= {field.name for field in dataclasses.fields(TextualStyle)}
    assert TextualStyle(link="https://example.invalid").link
    assert RichStyle(link="https://example.invalid")._link
    assert RichStyle(meta={"@click": "x"})._meta
    assert hasattr(Text("x"), "_spans")


def test_installing_twice_wraps_once() -> None:
    before = (textual.markup.to_content, rich.markup.render)
    markup_backstop.install()
    markup_backstop.install()
    assert (textual.markup.to_content, rich.markup.render) == before
    assert markup_backstop.original_textual_parser() is not markup_backstop.safe_to_content


def test_uninstall_and_suspended_restore_the_upstream_parsers() -> None:
    upstream = markup_backstop.original_textual_parser()
    with markup_backstop.suspended():
        assert textual.markup.to_content is upstream
        assert not markup_backstop.installed()
        with pytest.raises(textual.markup.MarkupError):
            Content.from_markup("a[/]b")
    assert markup_backstop.installed()
    assert Content.from_markup("a[/]b").plain == "a[/]b"


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

OUTSIDE_STRINGS = [
    "[@click=app.quit]x[/]",
    "[ @click=app.quit]x",
    "[$accent @click=screen.dismiss(True)]x",
    "[B @click=app.bell]x[/]",
    "\\[@click=app.quit]x\\[/]",
    "a[/]b",
    "key-1[/]",
    "\\[/]",
    "[link=https://example.invalid]x[/link]",
    '[link="https://example.invalid"]x[/link]',
    "[bold link=https://example.invalid]x[/]",
    "[@click=app.quit]never closed",
    "[b][i]x[/b]",
]


def _textual_style_is_inert(style) -> bool:
    if isinstance(style, str):
        return "=" not in style
    return not style.link and style._meta is None


def _rich_style_is_inert(style) -> bool:
    if isinstance(style, RichStyle):
        return not style._link and not style._meta
    words = style.split()
    return "link" not in words and not any(word.startswith("@") for word in words)


@pytest.mark.parametrize("sample", OUTSIDE_STRINGS)
def test_textual_parse_is_inert(sample: str) -> None:
    content = Content.from_markup(f"[b]Name:[/b] {sample}")
    assert all(_textual_style_is_inert(span.style) for span in content.spans)


@pytest.mark.parametrize("sample", OUTSIDE_STRINGS)
def test_rich_parse_is_inert(sample: str) -> None:
    text = Text.from_markup(f"[b]Name:[/b] {sample}")
    assert all(_rich_style_is_inert(span.style) for span in text.spans)
    console_text = rich.console.Console(record=True, width=80).render_str(sample)
    assert all(_rich_style_is_inert(span.style) for span in console_text.spans)


@pytest.mark.parametrize("sample", ["a[/]b", "key-1[/]", "[/]", "x[/b]y"])
def test_a_malformed_tag_is_shown_as_text_by_both_parsers(sample: str) -> None:
    assert Content.from_markup(sample).plain == sample
    assert Text.from_markup(sample).plain == sample


def test_a_malformed_tag_keeps_the_requested_base_style() -> None:
    assert Text.from_markup("a[/]b", style="bold").style == "bold"
    assert [str(span.style) for span in Content.styled("x", "bold").spans] == ["bold"]


def test_app_markup_keeps_its_styling() -> None:
    content = Content.from_markup("[bold $text-accent]Title[/] [dim]note[/dim]")
    assert content.plain == "Title note"
    assert [str(span.style) for span in content.spans] == ["bold $text-accent", "dim"]
    text = Text.from_markup("[bold blue]folder[/bold blue] [dim]x[/]")
    assert [str(span.style) for span in text.spans] == ["bold blue", "dim"]


def test_a_clean_parse_returns_the_parsers_own_object() -> None:
    upstream = markup_backstop.original_textual_parser()("[b]x[/b]")
    assert Content.from_markup("[b]x[/b]").spans == upstream.spans


# ---------------------------------------------------------------------------
# Real widgets
# ---------------------------------------------------------------------------

PAYLOADS = [
    "[@click=app.bell]x[/]",
    "[ @click=app.bell]x[/]",
    "key-1[/]",
    "[link=https://example.invalid/p]L[/link]",
]


class _Host(App):
    def __init__(self, build) -> None:
        super().__init__()
        self._build = build

    def compose(self) -> ComposeResult:
        yield from self._build()


def _drawn_cells(app):
    screen = app.screen
    width, height = app.size
    for y in range(height):
        for x in range(width):
            try:
                style = screen.get_style_at(x, y)
            except Exception:  # noqa: BLE001 - an undrawn cell
                continue
            if style is not None:
                yield style


def _widgets(payload: str):
    def build_table():
        table = DataTable()
        table.add_columns("name")
        yield table

    def tree():
        tree_widget = Tree("root")
        tree_widget.root.expand()
        tree_widget.root.add_leaf(payload)
        yield tree_widget

    return {
        "static": lambda: [Static(payload)],
        "label": lambda: [Label(payload)],
        "button": lambda: [Button(payload)],
        "option_list": lambda: [OptionList(payload)],
        "select": lambda: [Select([(payload, 1)], value=1)],
        "tree": tree,
        "table": build_table,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["static", "label", "button", "option_list", "select", "tree", "table"])
@pytest.mark.parametrize("payload", PAYLOADS)
async def test_widgets_draw_outside_text_with_nothing_clickable(kind: str, payload: str) -> None:
    app = _Host(_widgets(payload)[kind])
    async with app.run_test(size=(100, 30)) as pilot:
        if kind == "table":
            app.query_one(DataTable).add_row(payload)
        await pilot.pause()
        cells = list(_drawn_cells(app))
        assert cells
        assert not [c for c in cells if c.meta and any(key.startswith("@") for key in c.meta)]
        assert not [c for c in cells if c.link]


@pytest.mark.asyncio
async def test_notifications_and_border_titles_are_inert() -> None:
    def build():
        widget = Static("body")
        widget.styles.border = ("round", "white")
        widget.styles.height = 5
        yield widget

    app = _Host(build)
    async with app.run_test(size=(100, 30), notifications=True) as pilot:
        app.query_one(Static).border_title = "[@click=app.bell]t[/]"
        app.query_one(Static).border_subtitle = "a[/]b"
        app.notify("[@click=app.bell]n[/] key-1[/]", timeout=30)
        await pilot.pause()
        await pilot.pause(0.05)
        cells = list(_drawn_cells(app))
        assert not [c for c in cells if c.meta and any(key.startswith("@") for key in c.meta)]


@pytest.mark.asyncio
async def test_a_link_built_as_content_still_links() -> None:
    from servonaut.utils.markup import web_link

    app = _Host(lambda: [Static(web_link("https://example.invalid/activate", "$text-accent"))])
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        assert any(c.link == "https://example.invalid/activate" for c in _drawn_cells(app))
