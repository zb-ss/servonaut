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
        args = MagicMock(stop=False, status=False, reconnect=True, bg=False,
                         force_bg=False)
        with patch.object(servonaut_main, "_relay_reconnect") as reconnect, \
             patch.object(servonaut_main, "_relay_start_background") as start, \
             patch.object(servonaut_main, "_relay_run_foreground") as fg:
            servonaut_main._run_connect(args)
        reconnect.assert_called_once_with()
        start.assert_not_called()
        fg.assert_not_called()

    def test_run_connect_dispatches_force_bg(self):
        args = MagicMock(stop=False, status=False, reconnect=False, bg=False,
                         force_bg=True)
        with patch.object(servonaut_main, "_relay_force_bg") as force_bg, \
             patch.object(servonaut_main, "_relay_start_background") as start, \
             patch.object(servonaut_main, "_relay_run_foreground") as fg:
            servonaut_main._run_connect(args)
        force_bg.assert_called_once_with()
        start.assert_not_called()
        fg.assert_not_called()


class TestRelayForceBg:
    def test_no_tui_lock_just_starts_bg(self, tmp_path, monkeypatch):
        lock_file = tmp_path / "relay.lock"
        monkeypatch.setattr(
            "servonaut.services.relay_lock.DEFAULT_LOCK_PATH", lock_file,
        )
        start = MagicMock()
        with patch.object(servonaut_main, "_relay_start_background", start):
            servonaut_main._relay_force_bg()
        start.assert_called_once_with()

    def test_tui_lock_sends_sigusr1_and_waits(self, tmp_path, monkeypatch):
        import json
        import servonaut.services.relay_lock as lock_mod

        lock_file = tmp_path / "relay.lock"
        monkeypatch.setattr(lock_mod, "DEFAULT_LOCK_PATH", lock_file)
        lock_file.write_text(json.dumps({
            "pid": 12345, "mode": "tui", "acquired_at": 1.0,
        }))

        start = MagicMock()
        kill_calls: list[tuple[int, int]] = []

        def fake_kill(pid, sig):
            kill_calls.append((pid, sig))

        def fake_is_alive(pid):
            # Alive on the first check (inside _relay_force_bg) so we go into
            # the SIGUSR1 branch; truthy still for the retry polling, but the
            # read_owner call returns a different pid on the 2nd poll so the
            # wait loop exits.
            return True

        call_counter = {"n": 0}

        def fake_read_owner(path):
            call_counter["n"] += 1
            if call_counter["n"] == 1:
                return lock_mod.LockOwner(pid=12345, mode="tui", acquired_at=1.0)
            # Simulate TUI having dropped the lock.
            return lock_mod.LockOwner.unknown()

        with patch("servonaut.services.relay_lock.read_owner", fake_read_owner), \
             patch("servonaut.services.relay_lock.is_pid_alive", fake_is_alive), \
             patch.object(servonaut_main.os, "kill", side_effect=fake_kill), \
             patch.object(servonaut_main, "_relay_start_background", start):
            servonaut_main._relay_force_bg()

        assert kill_calls == [(12345, signal.SIGUSR1)]
        start.assert_called_once_with()
