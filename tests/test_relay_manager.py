"""Tests for the TUI-side RelayManager lifecycle orchestrator.

We stub RelayListener entirely via the ``listener_factory`` injection point
— the listener itself is covered by ``test_relay_listener.py`` and we don't
want to re-test Mercure semantics here.
"""
from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import AppConfig, RelayConfig
from servonaut.services.relay_lock import (
    DEFAULT_LOCK_PATH,
    RelayAlreadyActiveError,
    RelayLock,
)
from servonaut.services.relay_manager import RelayManager, RelayState, StartResult


def _run(coro):
    return asyncio.run(coro)


def _make_auth(*, authenticated: bool = True, mcp_connections: int = 5,
               user_id: str = "42", token: str = "tok"):
    entitlements = {
        "plan": "solo",
        "mcp_connections": mcp_connections,
        "user_id": user_id,
    }
    t = SimpleNamespace(
        access_token=token,
        refresh_token="r",
        expires_at=time.time() + 3600,
        plan="solo",
        email="a@b.c",
        entitlements=entitlements,
        entitlements_fetched_at=time.time(),
    )
    svc = MagicMock()
    svc.is_authenticated = authenticated
    svc.access_token = token if authenticated else None
    svc.plan = "solo"
    svc._token = t
    return svc


def _make_config(*, base_url="https://staging.servonaut.dev",
                 mercure_url="https://staging.servonaut.dev/.well-known/mercure"):
    cfg = AppConfig(relay=RelayConfig(
        base_url=base_url, mercure_url=mercure_url, heartbeat_interval=30,
    ))
    cm = MagicMock()
    cm.get.return_value = cfg
    return cm


class _StubListener:
    """Stand-in for RelayListener: waits on a future, fires hooks on demand."""
    def __init__(self, *, on_connected=None, on_disconnected=None,
                 client_id="host-stub"):
        self.on_connected = on_connected
        self.on_disconnected = on_disconnected
        self.client_id = client_id
        self.started = asyncio.Event()
        self.stopped = False
        self._stop_event = asyncio.Event()

    async def run(self) -> None:
        self.started.set()
        # Immediately fire connected to drive the manager into CONNECTED state.
        if self.on_connected:
            await self.on_connected()
        try:
            await self._stop_event.wait()
        except asyncio.CancelledError:
            raise
        finally:
            if self.on_disconnected:
                await self.on_disconnected()

    def stop(self) -> None:
        self.stopped = True
        self._stop_event.set()


@pytest.fixture
def lock_path(tmp_path):
    return tmp_path / "relay.lock"


@pytest.fixture(autouse=True)
def relay_log_tempdir(tmp_path, monkeypatch):
    """Redirect the relay structured log to a tmp file so tests don't pollute."""
    from servonaut.utils import relay_log
    monkeypatch.setattr(relay_log, "_DEFAULT_LOG_PATH", tmp_path / "relay.log")


# ---------------------------------------------------------------------------
# check_applicability
# ---------------------------------------------------------------------------

class TestApplicability:
    def test_not_logged_in(self, lock_path):
        mgr = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(authenticated=False),
            lock_path=lock_path,
        )
        result = mgr.check_applicability()
        assert result.state is RelayState.DISABLED

    def test_free_tier_has_no_entitlement(self, lock_path):
        mgr = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(mcp_connections=0),
            lock_path=lock_path,
        )
        result = mgr.check_applicability()
        assert result.state is RelayState.NO_ENTITLEMENT
        assert "Upgrade" in result.message

    def test_missing_relay_urls(self, lock_path):
        mgr = RelayManager(
            config_manager=_make_config(base_url="", mercure_url=""),
            auth_service=_make_auth(),
            lock_path=lock_path,
        )
        result = mgr.check_applicability()
        assert result.state is RelayState.NOT_CONFIGURED

    def test_external_bg_listener_holding_lock(self, lock_path):
        # Write a lock payload simulating a live bg listener (pid == us).
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        import os
        lock_path.write_text(json.dumps({
            "pid": os.getpid(), "mode": "bg", "acquired_at": 1.0,
        }))
        mgr = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
        )
        result = mgr.check_applicability()
        assert result.state is RelayState.EXTERNAL
        assert result.external_owner is not None
        assert result.external_owner.mode == "bg"

    def test_happy_path_returns_connecting(self, lock_path):
        mgr = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
        )
        result = mgr.check_applicability()
        assert result.state is RelayState.CONNECTING


# ---------------------------------------------------------------------------
# start / stop lifecycle
# ---------------------------------------------------------------------------

class TestStartStop:
    def test_start_acquires_lock_and_emits_connecting_then_connected(self, lock_path):
        stub = _StubListener()
        states: list[RelayState] = []
        mgr = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
            on_state_change=states.append,
            listener_factory=lambda **kw: stub.__init__(**kw) or stub,
        )
        # Drive the manager through one full cycle.
        async def scenario():
            result = await mgr.start()
            assert result.state is RelayState.CONNECTING
            # Give the task a tick to run the listener and fire on_connected.
            await asyncio.sleep(0.05)
            assert mgr.state is RelayState.CONNECTED
            await mgr.stop()
            assert mgr.state is RelayState.STOPPED

        _run(scenario())
        assert RelayState.CONNECTING in states
        assert RelayState.CONNECTED in states
        assert RelayState.STOPPED in states
        # Lock must be released; next acquire in the same process succeeds.
        RelayLock(mode="bg", path=lock_path).acquire().release()

    def test_start_defers_when_bg_holds_lock(self, lock_path):
        # Hold the lock from this process as 'bg'; the manager's start should see EXTERNAL.
        external = RelayLock(mode="bg", path=lock_path).acquire()
        try:
            mgr = RelayManager(
                config_manager=_make_config(),
                auth_service=_make_auth(),
                lock_path=lock_path,
                listener_factory=lambda **kw: _StubListener(**kw),
            )
            result = _run(mgr.start())
            assert result.state is RelayState.EXTERNAL
            assert mgr.state is RelayState.EXTERNAL
            assert result.external_owner.mode == "bg"
        finally:
            external.release()

    def test_double_start_no_op(self, lock_path):
        stub = _StubListener()
        mgr = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
            listener_factory=lambda **kw: stub.__init__(**kw) or stub,
        )
        async def scenario():
            r1 = await mgr.start()
            r2 = await mgr.start()
            assert r1.state is RelayState.CONNECTING
            # Second start is a no-op — returns current state.
            assert r2.message == "Already running."
            await mgr.stop()
        _run(scenario())

    def test_listener_crash_flips_state_to_error(self, lock_path):
        class _BadListener(_StubListener):
            async def run(self):
                self.started.set()
                raise RuntimeError("kaboom")
        mgr = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
            listener_factory=lambda **kw: _BadListener(**kw),
        )
        async def scenario():
            await mgr.start()
            await asyncio.sleep(0.05)
            assert mgr.state is RelayState.ERROR
            await mgr.stop()
        _run(scenario())

    def test_listener_factory_import_error_returns_error_state(self, lock_path):
        def factory(**kw):
            raise ImportError("httpx-sse missing")
        mgr = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
            listener_factory=factory,
        )
        result = _run(mgr.start())
        assert result.state is RelayState.ERROR
        assert "httpx-sse" in result.message


# ---------------------------------------------------------------------------
# restart
# ---------------------------------------------------------------------------

class TestRestart:
    def test_restart_stops_then_starts(self, lock_path):
        calls = {"n": 0}

        def factory(**kw):
            calls["n"] += 1
            return _StubListener(**kw)

        mgr = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
            listener_factory=factory,
        )
        async def scenario():
            await mgr.start()
            await asyncio.sleep(0.02)
            result = await mgr.restart()
            assert result.state is RelayState.CONNECTING
            await asyncio.sleep(0.05)
            await mgr.stop()
        _run(scenario())
        assert calls["n"] == 2
