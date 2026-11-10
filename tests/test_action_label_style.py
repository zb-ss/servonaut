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

# A label such as "r. Refresh" / "enter. Open" (a key and a dot before the words).
_PREFIX_LABEL = re.compile(r"""Button\(\s*f?["'](?:[A-Za-z]{1,5}|\d)\.\s""")
# A label such as "Save (s)" or a pseudo-button such as "[All]".
_BRACKET_LABEL = re.compile(r"""Button\(\s*f?["'][^"']*\([A-Za-z]{1,5}\)["']""")
_PSEUDO_BUTTON = re.compile(r"""\\+\[[A-Za-z]+\\*\]""")
_NAMED_COLOUR = re.compile(
    r"""\[(?:bold )?/?(?:green|red|yellow|cyan|blue|magenta|white|black)\]"""
    r"""|style=["'](?:bold )?(?:green|red|yellow|cyan|blue|magenta)\b"""
    r"""|["'](?:bold )?(?:green|red|yellow|cyan|blue|magenta)["']"""
)
_HEX_OR_NAMED_CSS = re.compile(
    r"#[0-9a-fA-F]{3,8}\b|:\s*(?:green|red|yellow|cyan|blue|magenta|white|black)\s*;"
)


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
    assert not _HEX_OR_NAMED_CSS.search(_text(relative))


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
