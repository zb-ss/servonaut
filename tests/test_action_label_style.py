"""Action labels and colours on the memory, findings and cloud tool screens.

Actions are plain sentence-case words with a quiet key hint (``ActionButton``),
and every colour comes from the theme. These guards fail when a ``1.``-style
prefix, a ``(x)`` key suffix, a bracketed pseudo-button or a named colour
comes back into those files.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src" / "servonaut"

SCREEN_FILES = [
    "screens/memory.py",
    "screens/findings.py",
    "screens/memory_drift.py",
    "widgets/memory_prompt.py",
    "screens/custom_servers.py",
    "screens/ip_ban.py",
    "screens/cloudwatch_browser.py",
    "screens/cloudtrail_browser.py",
]
STYLE_FILES = [
    "memory_screen.tcss",
    "styles/screens/memory.tcss",
    "styles/screens/findings.tcss",
    "styles/screens/custom_servers.tcss",
    "styles/screens/ip_ban.tcss",
    "styles/screens/cloudwatch.tcss",
    "styles/screens/cloudtrail.tcss",
]

_COLOUR = (
    r"(?:dark|light)?(?:red|green|yellow|cyan|blue|magenta|white|black|orange|purple|pink|gray|grey)"
)
# A label such as "r. Refresh" / "enter. Open" (a key and a dot before the words).
_PREFIX_LABEL = re.compile(
    r"""Button\(\s*(?:label\s*=\s*)?f?["'](?:[A-Za-z]{1,5}|\d)\.\s"""
)
# A label such as "Save (s)" or a pseudo-button such as "[All]".
_BRACKET_LABEL = re.compile(
    r"""Button\(\s*(?:label\s*=\s*)?f?["'][^"']*\([A-Za-z]{1,5}\)["']"""
)
_PSEUDO_BUTTON = re.compile(r"""\\+\[[A-Za-z]+\\*\]""")
# A style that is only a colour name and modifiers ("red", "bold red", "red bold"),
# or markup tags that contain one ("[yellow]", "[dim yellow]", "[/red]").
_NAMED_COLOUR = re.compile(
    r"""["'](?:(?:bold|dim|italic|underline|reverse|not)\s+)*""" + _COLOUR
    + r"""(?:\s+(?:bold|dim|italic|underline|reverse))*["']"""
    + r"""|\[/?(?:[a-z]+\s+)*""" + _COLOUR + r"""(?:\s+[a-z]+)*\]"""
)
# A stylesheet value that names a colour instead of a theme variable.
_CSS_NAMED_COLOUR = re.compile(
    r"(?:border\S*|background\S*|color|outline\S*|tint)\s*:[^;{}$]*?\b" + _COLOUR + r"\b"
)
_CSS_HEX = re.compile(r"#[0-9a-fA-F]{3,8}\b")


def _text(relative: str) -> str:
    return (SRC / relative).read_text(encoding="utf-8")


@pytest.mark.parametrize("relative", SCREEN_FILES)
def test_no_prefix_or_bracket_button_labels(relative: str) -> None:
    source = _text(relative)
    assert not _PREFIX_LABEL.search(source), "a `key.` prefix label came back"
    assert not _BRACKET_LABEL.search(source), "a `(x)` key suffix label came back"
    assert not _PSEUDO_BUTTON.search(source), "text pretending to be a button came back"


@pytest.mark.parametrize("relative", SCREEN_FILES)
def test_no_named_colours_in_screen_code(relative: str) -> None:
    assert not _NAMED_COLOUR.search(_text(relative)), "a named colour came back"


@pytest.mark.parametrize("relative", STYLE_FILES)
def test_no_hex_or_named_colours_in_styles(relative: str) -> None:
    text = _text(relative)
    assert not _CSS_HEX.search(text)
    assert not _CSS_NAMED_COLOUR.search(text)


# ---------------------------------------------------------------------------
# Behaviour: a button and its key run the same action
# ---------------------------------------------------------------------------

from textual.app import App, ComposeResult  # noqa: E402

from servonaut.widgets.action_button import ActionButton  # noqa: E402
from servonaut.widgets.memory_prompt import MemoryPrompt  # noqa: E402


class _PromptHost(App):
    def compose(self) -> ComposeResult:
        yield MemoryPrompt({"id": "i-1", "name": "web-1"})


@pytest.mark.asyncio
async def test_memory_prompt_buttons_and_keys_share_actions(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(MemoryPrompt, "_dispatch_build", lambda self: calls.append("build"))
    monkeypatch.setattr(MemoryPrompt, "_increment_dismissal", lambda self: calls.append("dismiss"))
    app = _PromptHost()
    async with app.run_test(size=(100, 30)) as pilot:
        accept = app.query_one("#memory_prompt_accept", ActionButton)
        dismiss = app.query_one("#memory_prompt_dismiss", ActionButton)
        assert (accept.words, dismiss.words) == ("Build", "Dismiss")
        assert accept.label.plain.split() == ["Build", "y"]
        assert dismiss.label.plain.split() == ["Dismiss", "n"]
        await pilot.click("#memory_prompt_accept")
        await pilot.pause()
        assert calls == ["build"]


# ---------------------------------------------------------------------------
# The guards themselves: each regression they exist for is caught
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("line", [
    'Text("x", style="red bold")',
    'Static("[dim yellow]x[/dim yellow]")',
    'return "bold green"',
    'Button(label="r. Refresh", id="b")',
    'Button("1. Refresh", id="b")',
])
def test_label_and_colour_guards_catch_the_regressions(line: str) -> None:
    assert (
        _PREFIX_LABEL.search(line) or _NAMED_COLOUR.search(line)
    ), line


@pytest.mark.parametrize("line", [
    "border: round red;",
    "background: darkred;",
    "color: cyan;",
])
def test_style_guard_catches_named_colours(line: str) -> None:
    assert _CSS_NAMED_COLOUR.search(line), line


@pytest.mark.parametrize("line", [
    "border: round $border-blurred;",
    "background: $primary-darken-1;",
    "color: $text-error;",
    'Static("[$text-success]ok[/$text-success] required")',
])
def test_guards_leave_theme_tokens_alone(line: str) -> None:
    assert not _CSS_NAMED_COLOUR.search(line)
    assert not _NAMED_COLOUR.search(line)
