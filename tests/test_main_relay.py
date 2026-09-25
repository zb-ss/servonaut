"""Relay process-lifecycle integration tests for ``servonaut.main``."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from servonaut import main as servonaut_main
from servonaut.config.schema import AppConfig, RelayConfig
from servonaut.services.relay_control import ControlResponse
from servonaut.services.relay_lock import LockOwner, active_owner

from .relay_fake_server import BASE_URL, MERCURE_URL, FakeRelayServer, finishes_within


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


class _SignedOutAuthService:
    """No stored session: the env-var token pair drives the listener."""

    is_authenticated = False


class TestRelayForegroundSessionExpiry:
    def test_rejected_session_stops_listener_and_exits_nonzero(
        self, relay_runtime, monkeypatch, capsys, tmp_path,
    ) -> None:
        pytest.importorskip("httpx_sse")
        server = FakeRelayServer(
            heartbeat_status=401, heartbeat_waits_for_subscription=True,
        )
        server.install(monkeypatch)
        config_manager = MagicMock()
        config_manager.get.return_value = AppConfig(relay=RelayConfig(
            base_url=BASE_URL, mercure_url=MERCURE_URL, heartbeat_interval=30,
        ))
        monkeypatch.setattr(
            "servonaut.config.manager.ConfigManager", lambda: config_manager,
        )
        monkeypatch.setattr(
            "servonaut.services.auth_service.AuthService", _SignedOutAuthService,
        )
        monkeypatch.setenv("SERVONAUT_RELAY_TOKEN", "relay-token")
        monkeypatch.setenv("SERVONAUT_USER_ID", "42")
        relay_log = tmp_path / "relay.log"
        monkeypatch.setattr("servonaut.utils.relay_log._DEFAULT_LOG_PATH", relay_log)

        # Bound the listener run so a regression fails instead of hanging.
        finished_in_time: list[bool] = []
        real_run = asyncio.run

        def bounded_run(coro):
            async def guarded():
                finished_in_time.append(await finishes_within(coro))
            return real_run(guarded())

        monkeypatch.setattr(asyncio, "run", bounded_run)

        with pytest.raises(SystemExit) as exc_info:
            servonaut_main._relay_run_foreground()

        assert finished_in_time == [True]
        assert exc_info.value.code == servonaut_main.RELAY_EXIT_SESSION_EXPIRED
        assert exc_info.value.code != 0
        out = capsys.readouterr().out
        assert "Connected to relay" in out  # the rejection hit an idle subscription
        assert "Relay stopped" in out
        assert "start the relay again" in out
        events = [json.loads(line) for line in relay_log.read_text().splitlines()]
        expiry = [e for e in events if e["event"] == "session_expired"]
        assert len(expiry) == 1 and "start the relay again" in expiry[0]["message"]
        assert events[-1]["event"] == "stopped"
        assert events[-1]["reason"] == "session_expired"
        assert active_owner(relay_runtime.data_root / "relay.lock") is None

    @pytest.mark.parametrize(
        ("uses_env_token", "remedy"),
        [(False, "`servonaut login`"), (True, "SERVONAUT_RELAY_TOKEN")],
    )
    def test_session_expired_message_names_the_remedy(
        self, uses_env_token, remedy,
    ) -> None:
        message = servonaut_main._relay_session_expired_message(uses_env_token)

        assert "expired or" in message
        assert remedy in message
        assert "start the relay again" in message
        assert "servonaut connect --bg" in message
