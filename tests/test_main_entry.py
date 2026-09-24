"""Tests for the ``main()`` entry-point wrapper.

Ctrl+C anywhere in the CLI must produce a one-line "Cancelled." and exit
code 130 (128+SIGINT) — never a raw KeyboardInterrupt traceback. Ctrl+C is
the only cancellation mechanism a headless invocation has, so it has to
read as a normal outcome, not a crash.
"""
from __future__ import annotations

import io

import pytest

import servonaut.main as main_mod


def test_keyboard_interrupt_exits_130_without_traceback(monkeypatch, capsys):
    monkeypatch.setattr(main_mod, "_main", lambda: (_ for _ in ()).throw(KeyboardInterrupt()))

    with pytest.raises(SystemExit) as excinfo:
        main_mod.main()

    assert excinfo.value.code == 130
    err = capsys.readouterr().err
    assert "Cancelled." in err
    assert "Traceback" not in err


def test_normal_exit_passes_through(monkeypatch):
    """SystemExit from a handler propagates untouched (wrapper only owns
    KeyboardInterrupt)."""
    monkeypatch.setattr(main_mod, "_main", lambda: (_ for _ in ()).throw(SystemExit(3)))

    with pytest.raises(SystemExit) as excinfo:
        main_mod.main()

    assert excinfo.value.code == 3


def _text_stream(errors: str) -> io.TextIOWrapper:
    return io.TextIOWrapper(io.BytesIO(), encoding="latin-1", errors=errors)


def test_stdio_is_utf8_and_keeps_each_stream_error_handler(monkeypatch):
    """A lone surrogate (e.g. from an undecodable file name) must stay writable."""
    streams = {
        "stdin": _text_stream("surrogateescape"),
        "stdout": _text_stream("surrogateescape"),
        "stderr": _text_stream("backslashreplace"),
    }
    for name, stream in streams.items():
        monkeypatch.setattr(main_mod.sys, name, stream)

    main_mod._configure_stdio()

    assert {name: stream.encoding for name, stream in streams.items()} == dict.fromkeys(
        streams, "utf-8"
    )
    assert {name: stream.errors for name, stream in streams.items()} == {
        "stdin": "surrogateescape",
        "stdout": "surrogateescape",
        "stderr": "backslashreplace",
    }
    streams["stdout"].write("file-\udce9\n")
    streams["stderr"].write("file-\udce9\n")


def test_entry_point_configures_stdio_once(monkeypatch):
    calls: list[None] = []
    monkeypatch.setattr(main_mod, "_configure_stdio", lambda: calls.append(None))
    monkeypatch.setattr(main_mod, "_prune_empty_env", lambda: None)
    monkeypatch.setattr(main_mod.sys, "argv", ["servonaut", "--version"])

    with pytest.raises(SystemExit):
        main_mod.main()

    assert len(calls) == 1
