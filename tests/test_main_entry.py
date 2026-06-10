"""Tests for the ``main()`` entry-point wrapper.

Ctrl+C anywhere in the CLI must produce a one-line "Cancelled." and exit
code 130 (128+SIGINT) — never a raw KeyboardInterrupt traceback. Ctrl+C is
the only cancellation mechanism a headless invocation has, so it has to
read as a normal outcome, not a crash.
"""
from __future__ import annotations

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
