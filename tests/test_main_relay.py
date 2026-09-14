"""Relay process-lifecycle integration tests for ``servonaut.main``."""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from servonaut import main as servonaut_main
from servonaut.services.relay_control import ControlResponse
from servonaut.services.relay_lock import LockOwner


@pytest.fixture
def relay_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    runtime = SimpleNamespace(data_root=tmp_path)
    monkeypatch.setattr("servonaut.runtime.detect_runtime", lambda: runtime)
    return runtime


class TestRelayReconnect:
    def test_reconnect_starts_only_after_safe_stop(self, relay_runtime) -> None:
        start = MagicMock()
        with patch.object(servonaut_main, "_relay_stop", return_value=True) as stop, patch.object(
            servonaut_main, "_relay_start_background", start
        ):
            servonaut_main._relay_reconnect()

        stop.assert_called_once_with(relay_runtime)
        start.assert_called_once_with(relay_runtime)

    def test_reconnect_never_starts_after_unverified_stop(self, relay_runtime) -> None:
        start = MagicMock()
        with patch.object(servonaut_main, "_relay_stop", return_value=False) as stop, patch.object(
            servonaut_main, "_relay_start_background", start
        ):
            servonaut_main._relay_reconnect()

        stop.assert_called_once_with(relay_runtime)
        start.assert_not_called()

    def test_reconnect_collects_one_runtime_for_stop_and_start(
        self, relay_runtime, monkeypatch
    ) -> None:
        detect = MagicMock(return_value=relay_runtime)
        stop = MagicMock(return_value=True)
        start = MagicMock()
        monkeypatch.setattr("servonaut.runtime.detect_runtime", detect)

        with patch.object(servonaut_main, "_relay_stop", stop), patch.object(
            servonaut_main, "_relay_start_background", start
        ):
            servonaut_main._relay_reconnect()

        detect.assert_called_once_with()
        stop.assert_called_once_with(relay_runtime)
        start.assert_called_once_with(relay_runtime)


class TestConnectArgs:
    def test_reconnect_flag_parses(self) -> None:
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

    def test_run_connect_dispatches_reconnect(self) -> None:
        args = MagicMock(stop=False, status=False, reconnect=True, bg=False, force_bg=False)
        with patch.object(servonaut_main, "_relay_reconnect") as reconnect, patch.object(
            servonaut_main, "_relay_start_background"
        ) as start, patch.object(servonaut_main, "_relay_run_foreground") as foreground:
            servonaut_main._run_connect(args)

        reconnect.assert_called_once_with()
        start.assert_not_called()
        foreground.assert_not_called()

    def test_run_connect_dispatches_force_bg(self) -> None:
        args = MagicMock(stop=False, status=False, reconnect=False, bg=False, force_bg=True)
        with patch.object(servonaut_main, "_relay_force_bg") as force_bg, patch.object(
            servonaut_main, "_relay_start_background"
        ) as start, patch.object(servonaut_main, "_relay_run_foreground") as foreground:
            servonaut_main._run_connect(args)

        force_bg.assert_called_once_with()
        start.assert_not_called()
        foreground.assert_not_called()


class TestRelayForceBg:
    def test_no_live_tui_lock_starts_background(self, relay_runtime, monkeypatch) -> None:
        monkeypatch.setattr("servonaut.services.relay_lock.active_owner", lambda path: None)
        start = MagicMock()
        with patch.object(servonaut_main, "_relay_start_background", start):
            servonaut_main._relay_force_bg()

        start.assert_called_once_with(relay_runtime)

    def test_force_bg_collects_one_runtime_and_passes_it_to_background(
        self, relay_runtime, monkeypatch
    ) -> None:
        detect = MagicMock(return_value=relay_runtime)
        start = MagicMock()
        monkeypatch.setattr("servonaut.runtime.detect_runtime", detect)
        monkeypatch.setattr("servonaut.services.relay_lock.active_owner", lambda path: None)

        with patch.object(servonaut_main, "_relay_start_background", start):
            servonaut_main._relay_force_bg()

        detect.assert_called_once_with()
        start.assert_called_once_with(relay_runtime)

    def test_authenticated_release_acknowledgement_precedes_background_start(
        self, relay_runtime, monkeypatch
    ) -> None:
        monkeypatch.setattr(
            "servonaut.services.relay_lock.active_owner",
            lambda path: LockOwner(pid=os.getpid(), mode="tui"),
        )
        monkeypatch.setattr(
            "servonaut.services.process_control.is_process_alive", lambda pid: True
        )
        requested: dict[str, Path] = {}

        async def request_release(*, record_path: Path, lock_path: Path) -> ControlResponse:
            requested["record"] = record_path
            requested["lock"] = lock_path
            return ControlResponse(ok=True, released=True)

        monkeypatch.setattr("servonaut.services.relay_control.request_relay_release", request_release)
        start = MagicMock()
        with patch.object(servonaut_main, "_relay_start_background", start):
            servonaut_main._relay_force_bg()

        assert requested == {
            "record": relay_runtime.data_root / "relay-control.json",
            "lock": relay_runtime.data_root / "relay.lock",
        }
        start.assert_called_once_with(relay_runtime)

    def test_control_failure_never_starts_background(self, relay_runtime, monkeypatch) -> None:
        monkeypatch.setattr(
            "servonaut.services.relay_lock.active_owner",
            lambda path: LockOwner(pid=os.getpid(), mode="tui"),
        )
        monkeypatch.setattr(
            "servonaut.services.process_control.is_process_alive", lambda pid: True
        )

        async def request_release(**kwargs) -> ControlResponse:
            return ControlResponse(ok=False, released=False, error="Control unavailable.")

        monkeypatch.setattr("servonaut.services.relay_control.request_relay_release", request_release)
        start = MagicMock()
        with pytest.raises(SystemExit) as exc_info, patch.object(
            servonaut_main, "_relay_start_background", start
        ):
            servonaut_main._relay_force_bg()

        assert exc_info.value.code == 3
        start.assert_not_called()

    def test_dead_tui_lock_exits_nonzero_without_background_start(
        self, relay_runtime, monkeypatch
    ) -> None:
        monkeypatch.setattr(
            "servonaut.services.relay_lock.active_owner",
            lambda path: LockOwner(pid=os.getpid(), mode="tui"),
        )
        monkeypatch.setattr(
            "servonaut.services.process_control.is_process_alive", lambda pid: False
        )
        start = MagicMock()

        with pytest.raises(SystemExit) as exc_info, patch.object(
            servonaut_main, "_relay_start_background", start
        ):
            servonaut_main._relay_force_bg()

        assert exc_info.value.code == 3
        start.assert_not_called()
