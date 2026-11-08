"""Text from outside the app never reaches the terminal as control sequences.

Every widget's text becomes terminal bytes in ``Strip.render``. These tests
render widgets holding a hostile name through Textual's compositor (the exact
bytes written to the terminal) and compare them with the same screen showing
the name without its control characters: the output must be identical, so
nothing hostile got through, the visible text stays readable and no column
moved.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import re
import textwrap
from typing import Any, Callable, List

import pytest
from rich.console import Console
from rich.segment import Segment
from rich.style import Style
from rich.text import Text
from textual.app import App, ComposeResult
from textual.strip import Strip
from textual.widgets import DataTable, RichLog, Static, Tree

from servonaut.utils import terminal_output
from servonaut.utils.markup import escape_markup
from servonaut.widgets.instance_table import InstanceTable

# OSC 52 (clipboard), OSC 8 (hidden link), OSC 0 (title), a CSI screen clear
# and cursor move, a C1 CSI (one byte), and a bidi override.
HOSTILE = (
    "web\x1b]52;c;aGVsbG8=\x07\x1b]8;;http://1.2.3.4/\x1b\\\x1b]0;pwned\x07"
    "\x1b[2J\x1b[10;10H\x9b31m\u202eevil-1"
)
BENIGN = re.sub("[\x00-\x1f\x7f-\x9f\u202e]", "", HOSTILE)

# What Textual itself writes: cursor positions, styles and link wrappers.
_TEXTUAL_OWN = re.compile(
    r"\x1b\[\d+;\d+H|\x1b\[[0-9;:]*m|\x1b\]8;id=[^;\x1b]*;[^\x1b\x07]*\x1b\\|\x1b\]8;;\x1b\\"
)
_STILL_UNSAFE = re.compile("[\x00-\x09\x0b-\x1f\x7f-\x9f\u202e]")

SIZE = (80, 14)


@pytest.fixture(autouse=True)
def filter_installed():
    terminal_output.install()
    yield
    terminal_output.install()


def _frame(app: App) -> str:
    update = app.screen._compositor.render_update(full=True)
    return update.render_segments(app.console)


def _show(build: Callable[[str], Any], name: str, *, after: Callable[[App], None] = None) -> str:
    """The bytes a terminal receives for one widget showing *name*."""

    class Host(App):
        def compose(self) -> ComposeResult:
            yield build(name)

    async def run() -> str:
        app = Host()
        async with app.run_test(size=SIZE, notifications=True) as pilot:
            if after is not None:
                after(app)
            await pilot.pause()
            await pilot.pause()
            return _frame(app)

    return asyncio.run(run())


def _assert_safe(frame: str) -> None:
    assert not _STILL_UNSAFE.search(_TEXTUAL_OWN.sub("", frame))


def _table(name_as: Callable[[str], Any]) -> Callable[[str], DataTable]:
    def build(name: str) -> DataTable:
        table = DataTable()
        table.add_columns("Name", "Next")
        table.add_row(name_as(name), "next-col")
        return table

    return build


def _tree(name: str) -> Tree:
    tree: Tree = Tree("fleet")
    tree.root.expand()
    tree.root.add_leaf(Text(name))
    return tree


def _rich_log(name: str) -> RichLog:
    log = RichLog(markup=False)
    log.write(Text(name))
    return log


def _static_escaped(name: str) -> Static:
    return Static(f"[b]{escape_markup(name)}[/b] tail")


SINKS = {
    "datatable_str": _table(lambda name: name),
    "datatable_text": _table(lambda name: Text(name)),
    "tree": _tree,
    "richlog": _rich_log,
    "static_escaped": _static_escaped,
}


@pytest.mark.parametrize("sink", sorted(SINKS))
def test_hostile_name_renders_as_the_benign_name(sink: str) -> None:
    build = SINKS[sink]
    hostile = _show(build, HOSTILE)
    _assert_safe(hostile)
    assert "\x1b]52" not in hostile
    assert "web]52" in hostile  # the name is drawn, not dropped
    assert hostile == _show(build, BENIGN)


def test_hostile_name_is_dropped_by_an_unfiltered_render() -> None:
    """The comparison above would pass trivially if the probe were harmless."""
    terminal_output.uninstall()
    try:
        assert "\x1b]52" in _show(SINKS["datatable_str"], HOSTILE)
    finally:
        terminal_output.install()


def test_toast_with_a_hostile_name() -> None:
    def build(_name: str) -> Static:
        return Static("")

    def toast(name: str) -> Callable[[App], None]:
        return lambda app: app.notify(name, title=name, markup=False)

    hostile = _show(build, HOSTILE, after=toast(HOSTILE))
    _assert_safe(hostile)
    assert "\x1b]52" not in hostile
    # A toast sizes itself from the raw text, so its wrapping can differ from
    # the benign render by a cell; the text must still be there to read.
    assert "web]52;c;aGVsbG8=" in hostile


def test_instance_table_with_a_hostile_instance_name() -> None:
    def frame(name: str) -> str:
        class Host(App):
            def compose(self) -> ComposeResult:
                yield InstanceTable()

        async def run() -> str:
            app = Host()
            async with app.run_test(size=(160, 14)) as pilot:
                app.query_one(InstanceTable).populate([{
                    "id": "i-0000000000000001", "name": name, "type": "t3.micro",
                    "state": "running", "public_ip": "1.2.3.4", "private_ip": "10.0.0.1",
                    "region": "us-east-1", "key_name": name,
                }])
                await pilot.pause()
                await pilot.pause()
                return _frame(app)

        return asyncio.run(run())

    hostile = frame(HOSTILE)
    _assert_safe(hostile)
    assert "web]52" in hostile
    assert hostile == frame(BENIGN)


def test_hostile_cell_does_not_move_the_next_column() -> None:
    """The name's controls take no cells, so the next column starts where it did."""
    build = SINKS["datatable_str"]
    hostile_rows = _show(build, HOSTILE).split("\n")
    benign_rows = _show(build, BENIGN).split("\n")
    assert hostile_rows == benign_rows
    assert any("web]52" in row and "next-col" in row for row in hostile_rows)


def test_link_target_holding_escape_is_not_written() -> None:
    console = Console(color_system="truecolor")
    hostile = Strip([Segment("go", Style(link="http://1.2.3.4/\x1b]52;c;QQ==\x07x"))])
    rendered = hostile.render(console)
    assert "\x1b]52" not in rendered
    assert "\x1b]8" not in rendered
    assert "go" in rendered


def test_safe_link_is_untouched() -> None:
    console = Console(color_system="truecolor")
    strip = Strip([Segment("go", Style(link="http://1.2.3.4/a"))])
    assert "\x1b]8;" in strip.render(console)
    assert "http://1.2.3.4/a" in strip.render(console)


def test_clean_strips_render_exactly_as_textual_renders_them() -> None:
    """Styles and links are Textual's own output; the filter adds nothing."""
    console = Console(color_system="truecolor")
    segments: List[Segment] = [
        Segment("plain"),
        Segment("bold", Style(bold=True, color="red", bgcolor="blue")),
        Segment("link", Style(link="http://1.2.3.4/", underline=True)),
    ]
    filtered = Strip(list(segments)).render(console)
    terminal_output.uninstall()
    try:
        original = Strip(list(segments)).render(console)
    finally:
        terminal_output.install()
    assert filtered == original


def test_install_wraps_once() -> None:
    first = Strip.render
    terminal_output.install()
    terminal_output.install()
    assert Strip.render is first


def test_render_cache_is_kept() -> None:
    console = Console(color_system="truecolor")
    strip = Strip([Segment("a\x1b[2Jb")])
    first = strip.render(console)
    assert first == "a[2Jb"
    assert strip._render_cache == "a[2Jb"
    assert strip.render(console) is first


def test_only_hostile_characters_are_removed() -> None:
    console = Console(color_system="truecolor")
    assert Strip([Segment("na\x1bme é中")]).render(console) == "name é中"


# SHA-256 of the source of Textual's Strip.render, which the filter wraps and
# relies on (it fills ``_render_cache`` from ``_segments``). If Textual changes
# it, check that the wrapper still sees every segment before updating this.
_UPSTREAM_STRIP_RENDER_SHA256 = "5ee47748339d389933ceb50e8fc1a25aab7bb53cfe46fb883b0cb0c66f1e4c2b"


def test_upstream_strip_render_is_the_one_the_filter_wraps() -> None:
    original = getattr(Strip.render, "_servonaut_original_render")
    source = textwrap.dedent(inspect.getsource(original))
    assert hashlib.sha256(source.encode()).hexdigest() == _UPSTREAM_STRIP_RENDER_SHA256


def _source_hash(function: Any) -> str:
    return hashlib.sha256(textwrap.dedent(inspect.getsource(function)).encode()).hexdigest()


# The filter relies on more than Strip.render: the link is written by
# Strip.render_style, and each way of building a frame update must render its
# strips through Strip.render. A Textual upgrade that changes any of these
# must be checked before these hashes are updated.
_UPSTREAM_SOURCE_SHA256 = {
    "Strip.render_style": "a7e0cafb8cf327cee47e958b3c94282d314bfaa9707f303c7af4955eda4cbcfc",
    "LayoutUpdate.render_segments": "241f12e4f5ea085af4d3497297c094bd4e52f9622f9af24da88c427871298d8c",
    "ChopsUpdate.render_segments": "d6ddb7d34a6c23ec3b838ae320f471f1062c52c135034ff1f6a11709c5bc3a34",
    "InlineUpdate.render_segments": "99ddb64572ce70324341d13f9fe6df53cf4c8206fbc7efb83f5df3df4e25dca9",
}


def test_every_path_to_the_terminal_still_goes_through_strip_render() -> None:
    from textual import _compositor

    functions = {
        "Strip.render_style": Strip.render_style,
        "LayoutUpdate.render_segments": _compositor.LayoutUpdate.render_segments,
        "ChopsUpdate.render_segments": _compositor.ChopsUpdate.render_segments,
        "InlineUpdate.render_segments": _compositor.InlineUpdate.render_segments,
    }
    assert {name: _source_hash(function) for name, function in functions.items()} == (
        _UPSTREAM_SOURCE_SHA256
    )


def test_a_partial_update_after_the_first_frame_is_filtered_too() -> None:
    """Live frames are mostly partial updates (ChopsUpdate), not full ones."""
    from textual._compositor import ChopsUpdate

    sent: List[Any] = []

    class Host(App):
        def compose(self) -> ComposeResult:
            table = DataTable()
            table.add_columns("Name", "Next")
            table.add_row("web-1", "next-col")
            yield table

        def _display(self, screen: Any, renderable: Any) -> None:
            sent.append(renderable)
            super()._display(screen, renderable)

    async def run() -> str:
        app = Host()
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            sent.clear()
            app.query_one(DataTable).update_cell_at((0, 0), HOSTILE, update_width=True)
            await pilot.pause()
            await pilot.pause()
            partial = [u for u in sent if isinstance(u, ChopsUpdate)]
            assert partial, "no partial update was drawn"
            return "".join(u.render_segments(app.console) for u in partial)

    frame = asyncio.run(run())
    _assert_safe(frame)
    assert "\x1b]52" not in frame
    assert "web]52" in frame
