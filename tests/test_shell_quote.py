"""``shell_quote`` gives one literal word to a POSIX shell and to fish.

In fish a backslash is an escape even inside single quotes, so ``shlex.quote``
output for a name holding a backslash can end its quote early. The function is
checked three ways: byte-for-byte against ``shlex.quote`` for backslash-free
input, by running real shells, and against a model of fish's documented
quoting rules (single quotes: ``\\\\`` and ``\\'`` are escapes; double quotes:
``\\\\``, ``\\"``, ``\\$`` are escapes and ``$`` expands).
"""
from __future__ import annotations

import shlex
import shutil
import subprocess

import pytest

from servonaut.config.schema import AppConfig
from servonaut.services.log_viewer_service import LogViewerService
from servonaut.utils.remote_shell import shell_path, shell_quote, shell_word

MARKER = "marker"

NAMES = [
    "\\",
    "bs\\",
    "a\\\\b",
    "A\\'X\";touch " + MARKER + ";#",
    "plain",
    "with space",
    "it's",
    "$(touch " + MARKER + ")",
    "`touch " + MARKER + "`",
    "",
    "\\$HOME",
    "x\\",
    "\\'",
]


@pytest.mark.parametrize("value", ["", "plain", "a b", "it's", "$(x)", "~/x", "a;b", "é"])
def test_backslash_free_input_is_exactly_shlex_quote(value) -> None:
    assert shell_quote(value) == shlex.quote(value)


def _fish_words(text: str) -> list[str]:
    """Split *text* the way fish's documented quoting rules do (no expansion but ``$``)."""
    words, current, i, in_word = [], "", 0, False
    while i < len(text):
        c = text[i]
        if c == "'":
            in_word = True
            i += 1
            while text[i] != "'":
                if text[i] == "\\" and text[i + 1] in "\\'":
                    current += text[i + 1]
                    i += 2
                else:
                    current += text[i]
                    i += 1
            i += 1
        elif c == '"':
            in_word = True
            i += 1
            while text[i] != '"':
                assert text[i] != "$", "an expanding $ inside double quotes"
                if text[i] == "\\" and text[i + 1] in '\\"$':
                    current += text[i + 1]
                    i += 2
                else:
                    current += text[i]
                    i += 1
            i += 1
        elif c.isspace():
            if in_word:
                words.append(current)
                current, in_word = "", False
            i += 1
        else:
            assert c not in "\\$;|&<>()*?~#{}", f"unquoted {c!r} would be special in fish"
            current += c
            in_word = True
            i += 1
    if in_word:
        words.append(current)
    return words


@pytest.mark.parametrize("value", NAMES)
def test_fish_reads_one_word_equal_to_the_value(value) -> None:
    assert _fish_words(shell_quote(value)) == [value]


@pytest.mark.parametrize("value", NAMES)
def test_posix_shell_reads_one_word_equal_to_the_value(value) -> None:
    done = subprocess.run(
        ["sh", "-c", f"printf '%s' {shell_quote(value)}"], capture_output=True, text=True, check=False,
    )
    assert done.stdout == value


@pytest.mark.skipif(shutil.which("fish") is None, reason="fish is not installed")
@pytest.mark.parametrize("value", NAMES)
def test_real_fish_reads_one_word_equal_to_the_value(value) -> None:
    done = subprocess.run(
        ["fish", "-c", f"printf '%s' {shell_quote(value)}"], capture_output=True, text=True, check=False,
    )
    assert done.stdout == value


def test_shlex_quote_alone_is_not_enough_for_fish() -> None:
    # The reason the function exists: the model reads this output as three words.
    assert _fish_words("'A\\'X'") != ["A\\'X"]


def test_words_and_paths_keep_their_anchors() -> None:
    assert shell_word("-n") == "./-n"
    assert shell_word("a\\b") == 'a"\\\\"b'
    assert shell_path("~/a\\b") == '"$HOME"/' + 'a"\\\\"b'
    assert shell_path("~") == '"$HOME"'


@pytest.mark.parametrize("value", NAMES[:4])
def test_builders_quote_a_backslash_name_for_fish(value) -> None:
    class Manager:
        def get(self):
            return AppConfig()

    service = LogViewerService(Manager())
    path = "/w/" + value
    for command in (
        service.get_tail_command(path, follow=False),
        service.get_read_command(path + ".1"),
    ):
        words = _fish_words(command)
        assert words[-1] == path or words[-1] == path + ".1"
