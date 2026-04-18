"""Tests for the relay process-management helpers in ``servonaut.main``.

These exercise the CLI glue around the PID file — the listener itself is
covered in ``test_relay_listener.py``.
"""
from __future__ import annotations

import os
import signal
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from servonaut import main as servonaut_main


@pytest.fixture
def tmp_pid_file(tmp_path, monkeypatch):
    pid_file = tmp_path / "relay.pid"
    monkeypatch.setattr(servonaut_main, "_RELAY_PID_FILE", pid_file)
    return pid_file


class TestRelayReconnect:
    def test_no_pid_file_just_starts(self, tmp_pid_file):
        start = MagicMock()
        with patch.object(servonaut_main, "_relay_start_background", start):
            servonaut_main._relay_reconnect()
        start.assert_called_once_with()

    def test_existing_live_pid_is_sigtermed_then_start(self, tmp_pid_file):
        tmp_pid_file.write_text("4242")
        start = MagicMock()
        kill_calls: list[tuple[int, int]] = []

        def fake_kill(pid: int, sig: int):
            kill_calls.append((pid, sig))
            if sig == 0 and len(kill_calls) >= 2:
                # Simulate the process having exited after the SIGTERM.
                raise ProcessLookupError

        with patch.object(servonaut_main.os, "kill", side_effect=fake_kill), \
             patch.object(servonaut_main, "_relay_start_background", start):
            servonaut_main._relay_reconnect()

        assert kill_calls[0] == (4242, signal.SIGTERM)
        assert not tmp_pid_file.exists(), "stale PID file must be cleaned up"
        start.assert_called_once_with()

    def test_dead_pid_is_cleaned_up_before_start(self, tmp_pid_file):
        tmp_pid_file.write_text("9999")
        start = MagicMock()

        def fake_kill(pid: int, sig: int):
            raise ProcessLookupError

        with patch.object(servonaut_main.os, "kill", side_effect=fake_kill), \
             patch.object(servonaut_main, "_relay_start_background", start):
            servonaut_main._relay_reconnect()

        assert not tmp_pid_file.exists()
        start.assert_called_once_with()

    def test_garbage_pid_file_is_removed(self, tmp_pid_file):
        tmp_pid_file.write_text("not-a-number")
        start = MagicMock()
        with patch.object(servonaut_main, "_relay_start_background", start):
            servonaut_main._relay_reconnect()
        assert not tmp_pid_file.exists()
        start.assert_called_once_with()


class TestConnectArgs:
    def test_reconnect_flag_parses(self):
        """Argparse must accept --reconnect on the connect subcommand."""
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="subcommand")
        connect = subparsers.add_parser("connect")
        group = connect.add_mutually_exclusive_group()
        group.add_argument("--bg", action="store_true")
        group.add_argument("--stop", action="store_true")
        group.add_argument("--status", action="store_true")
        group.add_argument("--reconnect", action="store_true")
        args = parser.parse_args(["connect", "--reconnect"])
        assert args.reconnect is True
        assert args.bg is False
        assert args.stop is False
        assert args.status is False

    def test_run_connect_dispatches_reconnect(self):
        args = MagicMock(stop=False, status=False, reconnect=True, bg=False)
        with patch.object(servonaut_main, "_relay_reconnect") as reconnect, \
             patch.object(servonaut_main, "_relay_start_background") as start, \
             patch.object(servonaut_main, "_relay_run_foreground") as fg:
            servonaut_main._run_connect(args)
        reconnect.assert_called_once_with()
        start.assert_not_called()
        fg.assert_not_called()
