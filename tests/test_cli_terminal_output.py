"""The CLI shows control characters in printed names as text, never raw."""

from __future__ import annotations

import sys

import pytest

from servonaut import main as main_module

HOSTILE = "web\x1b]52;c;aGVsbG8=\x07\x1b[2J\x9b31m‮-1"


def _raw_controls(text: str) -> bool:
    return any(ch in text for ch in ("\x1b", "\x07", "\x9b", "‮"))


def _run(monkeypatch: pytest.MonkeyPatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["servonaut", *argv])
    try:
        main_module.main()
    except SystemExit as exit_:
        return int(exit_.code or 0)
    return 0


def test_a_printed_server_table_shows_the_name_as_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from servonaut.cli import hetzner

    def handler(_args: object) -> int:
        hetzner._print_servers_table([{
            "id": "1", "name": HOSTILE, "type": "cx22", "state": "running",
            "public_ip": "1.2.3.4", "region": "fsn1",
        }])
        return 0

    monkeypatch.setattr(hetzner, "handle_hetzner_command", handler)
    _run_dispatch(monkeypatch, "hetzner")
    out = capsys.readouterr().out
    assert "web\\x1b]52" in out
    assert not _raw_controls(out)


@pytest.mark.parametrize("subcommand", ["team", "ca", "ssh", "hetzner", "db"])
def test_every_printing_command_filters_stdout_and_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], subcommand: str
) -> None:
    module = __import__(f"servonaut.cli.{subcommand}", fromlist=["x"])

    def handler(_args: object) -> int:
        print(f"name: {HOSTILE}")
        print(f"error: {HOSTILE}", file=sys.stderr)
        sys.stdout.write(f"partial {HOSTILE}\n")
        return 3

    monkeypatch.setattr(module, f"handle_{subcommand}_command", handler)
    status = _run_dispatch(monkeypatch, subcommand)
    captured = capsys.readouterr()
    assert status == 3
    assert not _raw_controls(captured.out)
    assert not _raw_controls(captured.err)
    assert "\\x1b" in captured.out


def _run_dispatch(monkeypatch: pytest.MonkeyPatch, subcommand: str) -> int:
    monkeypatch.setattr(
        main_module.argparse.ArgumentParser, "parse_args",
        lambda self, *a, **k: main_module.argparse.Namespace(
            subcommand=subcommand, debug=False, ai_provider=None, no_tools=False,
        ),
    )
    return _run(monkeypatch, subcommand)


def test_streams_are_restored_after_the_command(monkeypatch: pytest.MonkeyPatch) -> None:
    before = (sys.stdout, sys.stderr)
    _run_dispatch(monkeypatch, "servers")
    assert (sys.stdout, sys.stderr) == before


def test_the_tui_and_mcp_paths_keep_the_raw_streams() -> None:
    assert "mcp" not in main_module._TEXT_SUBCOMMANDS
    assert "connect" not in main_module._TEXT_SUBCOMMANDS
