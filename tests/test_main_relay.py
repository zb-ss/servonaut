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

from .relay_fake_server import (
    BASE_URL, MERCURE_URL, FakeRelayServer, RefreshReply, finishes_within,
)


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


class _StoredSession:
    """A stored OAuth session whose refresh fails.

    ``revoked_by_refresh`` picks the server's verdict: the session was
    revoked (``invalid_grant``: it is gone), or the failure was transient
    (network error, 429, 5xx: the session stays authenticated).
    """

    def __init__(self, *, revoked_by_refresh: bool) -> None:
        self._revoked_by_refresh = revoked_by_refresh
        self._revoked = False
        self.refresh_attempts = 0
        self._token = SimpleNamespace(user_id=42)

    @property
    def is_authenticated(self) -> bool:
        return not self._revoked

    @property
    def access_token(self) -> str | None:
        return None if self._revoked else "stored-access-token"

    async def refresh_token(self) -> bool:
        self.refresh_attempts += 1
        if self._revoked_by_refresh:
            self._revoked = True
        return False


@pytest.fixture
def foreground_relay(relay_runtime, monkeypatch, tmp_path) -> Path:
    """Wire ``_relay_run_foreground`` to temp files; return the relay log path."""
    pytest.importorskip("httpx_sse")
    config = AppConfig(relay=RelayConfig(
        base_url=BASE_URL, mercure_url=MERCURE_URL, heartbeat_interval=0,
    ))
    config.mcp.audit_path = str(tmp_path / "mcp_audit.jsonl")
    config_manager = MagicMock()
    config_manager.get.return_value = config
    monkeypatch.setattr("servonaut.config.manager.ConfigManager", lambda: config_manager)
    monkeypatch.setattr(
        "servonaut.mcp.server.build_headless_tools", lambda _config_manager: MagicMock(),
    )
    relay_log = tmp_path / "relay.log"
    monkeypatch.setattr("servonaut.utils.relay_log._DEFAULT_LOG_PATH", relay_log)
    return relay_log


def _use_auth(monkeypatch, *, session=None) -> None:
    """Sign in with ``session``, or use the env-var token pair when None."""
    if session is None:
        monkeypatch.setattr(
            "servonaut.services.auth_service.AuthService", _SignedOutAuthService,
        )
        monkeypatch.setenv("SERVONAUT_RELAY_TOKEN", "relay-token")
        monkeypatch.setenv("SERVONAUT_USER_ID", "42")
        return
    monkeypatch.setattr("servonaut.services.auth_service.AuthService", lambda: session)
    monkeypatch.delenv("SERVONAUT_RELAY_TOKEN", raising=False)
    monkeypatch.delenv("SERVONAUT_USER_ID", raising=False)


def _drive_listener(monkeypatch, driver) -> None:
    """Replace ``asyncio.run`` so ``driver(listener_coro)`` runs the listener."""
    real_run = asyncio.run
    monkeypatch.setattr(asyncio, "run", lambda coro: real_run(driver(coro)))


def _relay_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


class TestRelayForegroundSessionExpiry:
    @pytest.mark.parametrize(
        ("signed_in", "remedy"),
        [(False, "SERVONAUT_RELAY_TOKEN"), (True, "`servonaut login`")],
        ids=["env-token-rejected", "session-revoked"],
    )
    def test_rejected_session_stops_listener_and_exits_4(
        self, relay_runtime, foreground_relay, monkeypatch, capsys, signed_in, remedy,
    ) -> None:
        server = FakeRelayServer(
            heartbeat_statuses=[401], heartbeat_waits_for_subscription=True,
        )
        server.install(monkeypatch)
        session = _StoredSession(revoked_by_refresh=True) if signed_in else None
        _use_auth(monkeypatch, session=session)
        finished_in_time: list[bool] = []

        async def bounded(coro):
            # A regression fails here instead of hanging the suite.
            finished_in_time.append(await finishes_within(coro))

        _drive_listener(monkeypatch, bounded)

        with pytest.raises(SystemExit) as exc_info:
            servonaut_main._relay_run_foreground()

        assert finished_in_time == [True]
        assert exc_info.value.code == servonaut_main.RELAY_EXIT_SESSION_EXPIRED == 4
        out = capsys.readouterr().out
        assert "Connected to relay" in out  # the rejection hit an idle subscription
        assert "Relay stopped" in out and remedy in out
        assert "start the relay again" in out
        events = _relay_events(foreground_relay)
        expiry = [e for e in events if e["event"] == "session_expired"]
        assert len(expiry) == 1 and "start the relay again" in expiry[0]["message"]
        assert events[-1]["event"] == "stopped"
        assert events[-1]["reason"] == "session_expired"
        assert active_owner(relay_runtime.data_root / "relay.lock") is None

    def test_transient_refresh_failure_keeps_the_relay_running(
        self, relay_runtime, foreground_relay, monkeypatch, capsys,
    ) -> None:
        server = FakeRelayServer(heartbeat_statuses=[401, 200])
        server.install(monkeypatch)
        session = _StoredSession(revoked_by_refresh=False)
        _use_auth(monkeypatch, session=session)
        outcome: dict[str, bool] = {}

        async def until_recovered_then_interrupt(coro):
            task = asyncio.ensure_future(coro)

            async def recovered() -> None:
                while 200 not in server.heartbeat_replies and not task.done():
                    await asyncio.sleep(0)

            await asyncio.wait_for(recovered(), timeout=5)
            outcome["still_running"] = not task.done()
            task.cancel()  # the user interrupts the listener
            await asyncio.wait({task}, timeout=5)
            outcome["ended_cancelled"] = task.cancelled()

        _drive_listener(monkeypatch, until_recovered_then_interrupt)

        servonaut_main._relay_run_foreground()  # no SystemExit

        assert outcome == {"still_running": True, "ended_cancelled": True}
        assert session.refresh_attempts == 1
        assert server.heartbeat_replies[:2] == [401, 200]
        assert "Relay stopped" not in capsys.readouterr().out
        events = _relay_events(foreground_relay)
        assert not any(e["event"] == "session_expired" for e in events)
        assert events[-1]["event"] == "stopped"
        assert events[-1]["reason"] == "shutdown"

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


class _SessionWhoseRefreshCuresNothing:
    """A valid stored session: every refresh succeeds, yet the server keeps
    rejecting the relay's heartbeats."""

    is_authenticated = True
    access_token = "stored-access-token"

    def __init__(self) -> None:
        self.refresh_attempts = 0
        self._token = SimpleNamespace(user_id=42)

    async def refresh_token(self) -> bool:
        self.refresh_attempts += 1
        return True


def _interrupt_once(outcome: dict, condition):
    """A listener driver: wait for ``condition()``, then interrupt the listener."""

    async def driver(coro):
        task = asyncio.ensure_future(coro)

        async def reached() -> None:
            while not condition() and not task.done():
                await asyncio.sleep(0)

        await asyncio.wait_for(reached(), timeout=5)
        outcome["still_running"] = not task.done()
        task.cancel()  # the user interrupts the listener
        await asyncio.wait({task}, timeout=5)

    return driver


class TestRelayForegroundRefreshBlocked:
    def test_waf_block_on_refresh_keeps_the_session_and_the_relay(
        self, relay_runtime, foreground_relay, monkeypatch, tmp_path, capsys,
    ) -> None:
        """A heartbeat 401 whose refresh meets a WAF's HTML 403 is transient:
        the stored session survives and the relay does not exit with 4."""
        from servonaut.services.auth_service import AuthService

        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "access_token": "stored-access-token",
            "refresh_token": "stored-refresh-token",
            "expires_at": 0,
            "user_id": 42,
        }))
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
        monkeypatch.setenv("SERVONAUT_API_URL", BASE_URL)
        server = FakeRelayServer(
            heartbeat_statuses=[401, 200],
            refresh_replies=[RefreshReply(
                403,
                "<html><body>Access denied: request blocked</body></html>",
                "text/html",
            )],
        )
        server.install(monkeypatch)
        session = AuthService()
        _use_auth(monkeypatch, session=session)
        outcome: dict[str, bool] = {}
        _drive_listener(monkeypatch, _interrupt_once(
            outcome, lambda: 200 in server.heartbeat_replies,
        ))

        servonaut_main._relay_run_foreground()  # no SystemExit

        assert outcome == {"still_running": True}
        assert server.refresh_requests == 1
        assert session.is_authenticated is True
        assert json.loads(auth_file.read_text())["refresh_token"] == "stored-refresh-token"
        assert "Relay stopped" not in capsys.readouterr().out
        events = _relay_events(foreground_relay)
        assert not any(e["event"] == "session_expired" for e in events)
        assert events[-1]["reason"] == "shutdown"


class TestRelayForegroundPersistentRejection:
    def test_rejection_on_valid_session_is_logged_once_and_retried(
        self, relay_runtime, foreground_relay, monkeypatch, capsys,
    ) -> None:
        server = FakeRelayServer(heartbeat_statuses=[200, 401])
        server.install(monkeypatch)
        session = _SessionWhoseRefreshCuresNothing()
        _use_auth(monkeypatch, session=session)
        outcome: dict[str, bool] = {}

        def rejected_events() -> list[dict]:
            if not foreground_relay.exists():
                return []
            return [
                e for e in _relay_events(foreground_relay)
                if e["event"] == "heartbeat_rejected"
            ]

        # Run a few ticks past the alert to show it is not repeated.
        _drive_listener(monkeypatch, _interrupt_once(
            outcome,
            lambda: rejected_events() and session.refresh_attempts >= 6,
        ))

        servonaut_main._relay_run_foreground()  # keeps retrying; no SystemExit

        assert outcome == {"still_running": True}
        assert len(rejected_events()) == 1
        assert "Relay stopped" not in capsys.readouterr().out
        events = _relay_events(foreground_relay)
        assert not any(e["event"] == "session_expired" for e in events)
        assert events[-1]["reason"] == "shutdown"
