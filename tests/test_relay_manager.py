"""Tests for the TUI-side RelayManager lifecycle orchestrator.

We stub RelayListener entirely via the ``listener_factory`` injection point
— the listener itself is covered by ``test_relay_listener.py`` and we don't
want to re-test Mercure semantics here.
"""
from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import AppConfig, RelayConfig
from servonaut.services import relay_control
from servonaut.services.relay_control import LocalControlServer, request_relay_release
from servonaut.services.relay_lock import (
    RelayLock,
    active_owner,
)
from servonaut.services.relay_manager import (
    RelayManager,
    RelayState,
    derive_relay_urls,
)


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


def _make_config(*, base_url="https://staging.example.com",
                 mercure_url="https://staging.example.com/.well-known/mercure"):
    cfg = AppConfig(relay=RelayConfig(
        base_url=base_url, mercure_url=mercure_url, heartbeat_interval=30,
    ))
    cm = MagicMock()
    cm.get.return_value = cfg
    return cm


class _StubListener:
    """Stand-in for RelayListener: waits on a future, fires hooks on demand."""
    def __init__(self, *, on_connected=None, on_disconnected=None,
                 on_session_expired=None,
                 client_id="host-stub"):
        self.on_connected = on_connected
        self.on_disconnected = on_disconnected
        self.on_session_expired = on_session_expired
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
    from servonaut.services import relay_control
    from servonaut.utils import relay_log

    monkeypatch.setattr(relay_log, "_DEFAULT_LOG_PATH", tmp_path / "relay.log")
    monkeypatch.setattr(
        relay_control,
        "default_control_record_path",
        lambda: tmp_path / "relay-control.json",
    )


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
        # Metadata alone is intentionally insufficient: hold the real lock.
        external = RelayLock(mode="bg", path=lock_path).acquire()
        try:
            mgr = RelayManager(
                config_manager=_make_config(),
                auth_service=_make_auth(),
                lock_path=lock_path,
            )
            result = mgr.check_applicability()
            assert result.state is RelayState.EXTERNAL
            assert result.external_owner is not None
            assert result.external_owner.mode == "bg"
        finally:
            external.release()

    def test_happy_path_returns_connecting(self, lock_path):
        mgr = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
        )
        result = mgr.check_applicability()
        assert result.state is RelayState.CONNECTING


# ---------------------------------------------------------------------------
# derive_relay_urls / ensure_configured
# ---------------------------------------------------------------------------

class TestDeriveRelayUrls:
    def test_prod_strips_api_subdomain_for_mercure(self):
        base, mercure = derive_relay_urls("https://api.servonaut.dev")
        assert base == "https://api.servonaut.dev"
        assert mercure == "https://servonaut.dev/.well-known/mercure"

    def test_staging_keeps_host_for_mercure(self):
        base, mercure = derive_relay_urls("https://staging.example.com")
        assert base == "https://staging.example.com"
        assert mercure == "https://staging.example.com/.well-known/mercure"

    def test_trailing_slash_dropped_on_base(self):
        base, _ = derive_relay_urls("https://api.servonaut.dev/")
        assert base == "https://api.servonaut.dev"

    def test_invalid_url_raises(self):
        with pytest.raises(ValueError):
            derive_relay_urls("not-a-url")


class TestEnsureConfigured:
    def _mk_manager(self, *, base_url="", mercure_url="", lock_path=None):
        cfg = AppConfig(relay=RelayConfig(
            base_url=base_url, mercure_url=mercure_url, heartbeat_interval=30,
        ))
        cm = MagicMock()
        cm.get.return_value = cfg
        mgr = RelayManager(
            config_manager=cm,
            auth_service=_make_auth(),
            lock_path=lock_path,
        )
        return mgr, cm, cfg

    def test_noop_when_both_urls_present(self, lock_path, monkeypatch):
        monkeypatch.setenv("SERVONAUT_API_URL", "https://api.servonaut.dev")
        mgr, cm, cfg = self._mk_manager(
            base_url="https://api.example.com",
            mercure_url="https://mercure.example.com/.well-known/mercure",
            lock_path=lock_path,
        )
        assert mgr.ensure_configured() is True
        cm.save.assert_not_called()
        # Pre-existing values are NOT overwritten with derived values.
        assert cfg.relay.base_url == "https://api.example.com"

    def test_fills_both_when_empty_and_persists(self, lock_path, monkeypatch):
        monkeypatch.setenv("SERVONAUT_API_URL", "https://api.servonaut.dev")
        mgr, cm, cfg = self._mk_manager(lock_path=lock_path)
        assert mgr.ensure_configured() is True
        assert cfg.relay.base_url == "https://api.servonaut.dev"
        assert cfg.relay.mercure_url == "https://servonaut.dev/.well-known/mercure"
        cm.save.assert_called_once_with(cfg)

    def test_fills_only_missing_field(self, lock_path, monkeypatch):
        monkeypatch.setenv("SERVONAUT_API_URL", "https://api.servonaut.dev")
        mgr, cm, cfg = self._mk_manager(
            base_url="https://my.custom.api/",
            mercure_url="",
            lock_path=lock_path,
        )
        assert mgr.ensure_configured() is True
        # base_url left intact, only mercure_url filled.
        assert cfg.relay.base_url == "https://my.custom.api/"
        assert cfg.relay.mercure_url == "https://servonaut.dev/.well-known/mercure"
        cm.save.assert_called_once()

    def test_save_failure_returns_false_without_raising(self, lock_path, monkeypatch):
        monkeypatch.setenv("SERVONAUT_API_URL", "https://api.servonaut.dev")
        mgr, cm, _ = self._mk_manager(lock_path=lock_path)
        cm.save.side_effect = OSError("disk full")
        assert mgr.ensure_configured() is False


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

    def test_start_reports_an_unopenable_lock_as_an_error_state(self, tmp_path):
        """The TUI worker receives an ERROR result instead of an escaping OSError."""
        blocker = tmp_path / "not-a-directory"
        blocker.write_text("", encoding="utf-8")
        factory = MagicMock()
        states: list[RelayState] = []
        mgr = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=blocker / "relay.lock",
            on_state_change=states.append,
            listener_factory=factory,
        )

        result = _run(mgr.start())

        assert result.state is RelayState.ERROR
        assert "relay lock" in result.message
        assert str(tmp_path) not in result.message
        assert mgr.state is RelayState.ERROR
        assert states == [RelayState.ERROR]
        assert not mgr.is_running
        factory.assert_not_called()

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

    def test_control_request_stops_listener_and_releases_lock(self, lock_path, tmp_path):
        stub = _StubListener()
        manager = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
            listener_factory=lambda **kw: stub.__init__(**kw) or stub,
        )

        async def scenario():
            result = await manager.start()
            assert result.state is RelayState.CONNECTING
            await asyncio.sleep(0.02)
            record_path = tmp_path / "relay-control.json"
            response = await request_relay_release(record_path, lock_path)
            assert response.ok is True
            assert response.released is True
            assert manager.state is RelayState.STOPPED
            assert active_owner(lock_path) is None
            assert stub.stopped is True

        _run(scenario())

    def test_control_server_is_built_from_the_configured_record_path(
        self, lock_path, tmp_path
    ):
        record_path = tmp_path / "control" / "relay-control.json"
        built_with: list[dict[str, object]] = []

        def control_factory(**kwargs):
            built_with.append(kwargs)
            return LocalControlServer(**kwargs)

        stub = _StubListener()
        manager = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
            listener_factory=lambda **kw: stub.__init__(**kw) or stub,
            control_server_factory=control_factory,
            control_record_path=record_path,
        )

        async def scenario():
            await manager.start()
            assert record_path.exists()
            await manager.stop()

        _run(scenario())
        assert built_with == [{"record_path": record_path}]

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

    def test_delayed_control_bind_precedes_immediate_listener_failure(
        self,
        lock_path,
        tmp_path,
        monkeypatch,
    ):
        bind_entered = asyncio.Event()
        permit_bind = asyncio.Event()
        original_start_server = relay_control.asyncio.start_server
        controls: list[LocalControlServer] = []

        class _TrackingControlServer(LocalControlServer):
            bound_port: int | None = None

            async def start(self, release_callback):
                record = await super().start(release_callback)
                self.bound_port = record.port
                return record

        class _ImmediateFailure(_StubListener):
            async def run(self):
                self.started.set()
                raise RuntimeError("listener failed")

        async def delayed_start_server(*args, **kwargs):
            bind_entered.set()
            await permit_bind.wait()
            return await original_start_server(*args, **kwargs)

        def control_factory(**kwargs):
            control = _TrackingControlServer(**kwargs)
            controls.append(control)
            return control

        monkeypatch.setattr(relay_control.asyncio, "start_server", delayed_start_server)
        listener = _ImmediateFailure()
        manager = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
            listener_factory=lambda **kwargs: listener.__init__(**kwargs) or listener,
            control_server_factory=control_factory,
        )

        async def scenario():
            start_task = asyncio.create_task(manager.start())
            await asyncio.wait_for(bind_entered.wait(), timeout=0.2)
            assert listener.started.is_set() is False
            assert not (tmp_path / "relay-control.json").exists()

            permit_bind.set()
            result = await start_task
            assert result.state is RelayState.CONNECTING
            for _ in range(20):
                if manager.state is RelayState.ERROR and not controls[0].is_running:
                    break
                await asyncio.sleep(0.01)

            control = controls[0]
            assert manager.state is RelayState.ERROR
            assert control.bound_port is not None
            assert control.is_running is False
            assert not (tmp_path / "relay-control.json").exists()
            assert active_owner(lock_path) is None
            with pytest.raises(OSError):
                await asyncio.open_connection("127.0.0.1", control.bound_port)

            replacement = RelayManager(
                config_manager=_make_config(),
                auth_service=_make_auth(),
                lock_path=lock_path,
                listener_factory=lambda **kwargs: _StubListener(**kwargs),
            )
            replacement_result = await replacement.start()
            assert replacement_result.state is RelayState.CONNECTING
            await replacement.stop()

        _run(scenario())

    def test_stop_during_control_bind_leaves_no_orphan_resources(
        self,
        lock_path,
        tmp_path,
        monkeypatch,
    ):
        bind_entered = asyncio.Event()
        permit_bind = asyncio.Event()
        original_start_server = relay_control.asyncio.start_server
        controls: list[LocalControlServer] = []

        class _TrackingControlServer(LocalControlServer):
            bound_port: int | None = None

            async def start(self, release_callback):
                record = await super().start(release_callback)
                self.bound_port = record.port
                return record

        async def delayed_start_server(*args, **kwargs):
            bind_entered.set()
            await permit_bind.wait()
            return await original_start_server(*args, **kwargs)

        def control_factory(**kwargs):
            control = _TrackingControlServer(**kwargs)
            controls.append(control)
            return control

        monkeypatch.setattr(relay_control.asyncio, "start_server", delayed_start_server)
        listener = _StubListener()
        manager = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
            listener_factory=lambda **kwargs: listener.__init__(**kwargs) or listener,
            control_server_factory=control_factory,
        )

        async def scenario():
            start_task = asyncio.create_task(manager.start())
            await asyncio.wait_for(bind_entered.wait(), timeout=0.2)
            stop_task = asyncio.create_task(manager.stop())
            await asyncio.sleep(0)
            assert stop_task.done() is False

            permit_bind.set()
            start_result = await start_task
            await stop_task

            control = controls[0]
            assert start_result.state is RelayState.STOPPED
            assert manager.state is RelayState.STOPPED
            assert listener.started.is_set() is False
            assert control.bound_port is not None
            assert control.is_running is False
            assert not (tmp_path / "relay-control.json").exists()
            assert active_owner(lock_path) is None
            with pytest.raises(OSError):
                await asyncio.open_connection("127.0.0.1", control.bound_port)

            replacement = LocalControlServer(tmp_path / "relay-control.json")
            replacement_lock = RelayLock(mode="tui", path=lock_path).acquire()
            try:
                record = await replacement.start(lambda: None)
                assert record.port > 0
            finally:
                await replacement.close()
                replacement_lock.release()

        _run(scenario())

    def test_double_cancel_during_bound_control_start_rolls_back_all_state(
        self,
        lock_path,
        tmp_path,
    ):
        control_bound = asyncio.Event()
        permit_close = asyncio.Event()
        close_entered = asyncio.Event()
        controls: list[LocalControlServer] = []

        class _BoundControlServer(LocalControlServer):
            bound_record = None

            async def start(self, release_callback):
                record = await super().start(release_callback)
                self.bound_record = record
                control_bound.set()
                await asyncio.Event().wait()
                return record

            async def close(self) -> None:
                close_entered.set()
                await permit_close.wait()
                await super().close()

        def control_factory(**kwargs):
            control = _BoundControlServer(**kwargs)
            controls.append(control)
            return control

        listener = _StubListener()
        manager = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
            listener_factory=lambda **kwargs: listener.__init__(**kwargs) or listener,
            control_server_factory=control_factory,
        )

        async def scenario():
            start_task = asyncio.create_task(manager.start())
            await asyncio.wait_for(control_bound.wait(), timeout=0.2)
            control = controls[0]
            record = control.bound_record
            assert record is not None
            assert (tmp_path / "relay-control.json").exists()

            start_task.cancel()
            await asyncio.wait_for(close_entered.wait(), timeout=0.2)
            await asyncio.sleep(0)
            start_task.cancel()
            permit_close.set()
            with pytest.raises(asyncio.CancelledError):
                await start_task

            assert manager.state is RelayState.STOPPED
            assert listener.started.is_set() is False
            assert manager._control_server is None
            assert manager._task is None
            assert manager._listener is None
            assert not (tmp_path / "relay-control.json").exists()
            assert active_owner(lock_path) is None
            assert control.is_running is False
            with pytest.raises(OSError):
                await asyncio.open_connection("127.0.0.1", record.port)

            replacement = RelayManager(
                config_manager=_make_config(),
                auth_service=_make_auth(),
                lock_path=lock_path,
                listener_factory=lambda **kwargs: _StubListener(**kwargs),
            )
            replacement_result = await replacement.start()
            assert replacement_result.state is RelayState.CONNECTING
            await replacement.stop()

        _run(scenario())

    def test_cancel_during_ordinary_startup_failure_rolls_back_all_state(
        self,
        lock_path,
        tmp_path,
    ):
        permit_close = asyncio.Event()
        close_entered = asyncio.Event()
        controls: list[LocalControlServer] = []

        class _FailingControlServer(LocalControlServer):
            bound_record = None

            async def start(self, release_callback):
                record = await super().start(release_callback)
                self.bound_record = record
                raise OSError("simulated startup failure")

            async def close(self) -> None:
                close_entered.set()
                await permit_close.wait()
                await super().close()

        def control_factory(**kwargs):
            control = _FailingControlServer(**kwargs)
            controls.append(control)
            return control

        listener = _StubListener()
        manager = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
            listener_factory=lambda **kwargs: listener.__init__(**kwargs) or listener,
            control_server_factory=control_factory,
        )

        async def scenario():
            start_task = asyncio.create_task(manager.start())
            await asyncio.wait_for(close_entered.wait(), timeout=0.2)
            control = controls[0]
            record = control.bound_record
            assert record is not None
            assert (tmp_path / "relay-control.json").exists()

            start_task.cancel()
            permit_close.set()
            with pytest.raises(asyncio.CancelledError):
                await start_task

            assert manager.state is RelayState.ERROR
            assert listener.started.is_set() is False
            assert manager._control_server is None
            assert manager._task is None
            assert manager._listener is None
            assert not (tmp_path / "relay-control.json").exists()
            assert active_owner(lock_path) is None
            assert control.is_running is False
            with pytest.raises(OSError):
                await asyncio.open_connection("127.0.0.1", record.port)

            replacement = RelayManager(
                config_manager=_make_config(),
                auth_service=_make_auth(),
                lock_path=lock_path,
                listener_factory=lambda **kwargs: _StubListener(**kwargs),
            )
            replacement_result = await replacement.start()
            assert replacement_result.state is RelayState.CONNECTING
            await replacement.stop()

        _run(scenario())

    def test_cancelled_stop_cleans_partial_client_and_all_owned_state(
        self,
        lock_path,
        tmp_path,
        monkeypatch,
    ):
        listener = _StubListener()
        manager = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
            listener_factory=lambda **kwargs: listener.__init__(**kwargs) or listener,
        )

        async def scenario():
            start_result = await manager.start()
            assert start_result.state is RelayState.CONNECTING
            control = manager._control_server
            assert control is not None
            record = control._record
            assert record is not None
            original_close = control.close
            close_entered = asyncio.Event()
            permit_close = asyncio.Event()
            close_calls = 0

            async def delayed_close() -> None:
                nonlocal close_calls
                close_calls += 1
                close_entered.set()
                if close_calls == 1:
                    await permit_close.wait()
                await original_close()

            monkeypatch.setattr(control, "close", delayed_close)
            reader, writer = await asyncio.open_connection("127.0.0.1", record.port)
            try:
                writer.write(b'{"protocol_version":1')
                await writer.drain()

                stop_task = asyncio.create_task(manager.stop())
                await asyncio.wait_for(close_entered.wait(), timeout=0.2)
                stop_task.cancel()
                await asyncio.sleep(0)
                stop_task.cancel()
                permit_close.set()
                with pytest.raises(asyncio.CancelledError):
                    await stop_task

                assert close_calls == 1
                assert manager.state is RelayState.STOPPED
                assert manager._control_server is None
                assert manager._task is None
                assert manager._listener is None
                assert listener.stopped is True
                assert active_owner(lock_path) is None
                assert not (tmp_path / "relay-control.json").exists()
                assert await asyncio.wait_for(reader.read(), timeout=0.2) == b""
                with pytest.raises(OSError):
                    await asyncio.open_connection("127.0.0.1", record.port)

                replacement = RelayManager(
                    config_manager=_make_config(),
                    auth_service=_make_auth(),
                    lock_path=lock_path,
                    listener_factory=lambda **kwargs: _StubListener(**kwargs),
                )
                replacement_result = await replacement.start()
                assert replacement_result.state is RelayState.CONNECTING
                await replacement.stop()
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass

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


# ---------------------------------------------------------------------------
# Session-expired propagation (heartbeat 401 → indicator goes red)
# ---------------------------------------------------------------------------


class TestSessionExpired:
    """When the listener fires its on_session_expired hook (because the
    heartbeat got a 401), the manager must transition to
    SESSION_EXPIRED and stop the listener so the indicator stops
    showing 'connected' and we don't keep posting a known-bad bearer.
    """

    def test_handle_session_expired_transitions_state(self, lock_path):
        states: list = []

        mgr = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
            listener_factory=lambda **kw: _StubListener(**kw),
            on_state_change=lambda s: states.append(s),
        )

        async def scenario():
            await mgr.start()
            await asyncio.sleep(0.02)
            await mgr._handle_session_expired()
            await asyncio.sleep(0.02)

        _run(scenario())
        assert RelayState.SESSION_EXPIRED in states
        # The state observed by callbacks ends on SESSION_EXPIRED, not
        # an intermediate STOPPED, so the sidebar settles on the
        # right label.
        assert states[-1] is RelayState.SESSION_EXPIRED

    def test_listener_run_session_expiry_settles_state_after_cancellation(
        self,
        lock_path,
        tmp_path,
    ):
        """The real listener gather must not lose the expiry state on cancel."""
        pytest.importorskip("httpx_sse")
        from servonaut.services.relay_listener import RelayListener

        class _ExpiryListener(RelayListener):
            def __init__(self, **kwargs):
                super().__init__(
                    executors=MagicMock(),
                    base_url="https://relay.example.test",
                    mercure_url="https://mercure.example.test/.well-known/mercure",
                    auth_token="placeholder",
                    user_id="test-user",
                    heartbeat_interval=30,
                    **kwargs,
                )
                self.heartbeat_started = asyncio.Event()
                self._listen_stopped = asyncio.Event()

            async def _listen_forever(self) -> None:
                await self._listen_stopped.wait()

            async def _heartbeat_loop(self) -> None:
                self.heartbeat_started.set()
                await self._safe_fire_session_expired()

            def stop(self) -> None:
                super().stop()
                self._listen_stopped.set()

        listeners = []

        def listener_factory(**kwargs):
            listener = _ExpiryListener(**kwargs)
            listeners.append(listener)
            return listener

        manager = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
            listener_factory=listener_factory,
        )

        async def scenario():
            result = await manager.start()
            assert result.state is RelayState.CONNECTING
            listener_task = manager._task
            control_server = manager._control_server
            assert listener_task is not None
            assert control_server is not None
            record = control_server._record
            assert record is not None

            listener = listeners[0]
            await asyncio.wait_for(listener.heartbeat_started.wait(), timeout=0.5)
            await asyncio.wait_for(listener_task, timeout=0.5)
            async def wait_for_expiry() -> None:
                while manager.state is not RelayState.SESSION_EXPIRED:
                    await asyncio.sleep(0)

            await asyncio.wait_for(wait_for_expiry(), timeout=0.5)

            assert manager.state is RelayState.SESSION_EXPIRED
            assert manager._control_server is None
            assert manager._listener is None
            assert manager._task is None
            assert manager.is_running is False
            assert active_owner(lock_path) is None
            assert not (tmp_path / "relay-control.json").exists()
            with pytest.raises(OSError):
                await asyncio.open_connection("127.0.0.1", record.port)

        _run(scenario())

    def test_heartbeat_401_on_idle_subscription_reaches_manager_hook(
        self, lock_path, monkeypatch, capsys,
    ):
        """A real listener parked on an idle hub subscription still hands a
        heartbeat 401 to the manager, which stops it and settles on
        SESSION_EXPIRED. The headless CLI's stop message is not printed."""
        pytest.importorskip("httpx_sse")
        from servonaut.services.relay_listener import RelayListener

        from .relay_fake_server import BASE_URL, MERCURE_URL, FakeRelayServer

        server = FakeRelayServer(
            heartbeat_status=401, heartbeat_waits_for_subscription=True,
        )
        server.install(monkeypatch)
        states: list = []
        expired = asyncio.Event()

        def on_state_change(state):
            states.append(state)
            if state is RelayState.SESSION_EXPIRED:
                expired.set()

        def listener_factory(**hooks):
            return RelayListener(
                executors=MagicMock(),
                base_url=BASE_URL,
                mercure_url=MERCURE_URL,
                auth_token="tok",
                user_id="42",
                heartbeat_interval=30,
                **hooks,
            )

        manager = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
            listener_factory=listener_factory,
            on_state_change=on_state_change,
        )

        async def scenario():
            await manager.start()
            listener_task = manager._task
            await asyncio.wait_for(server.subscribed.wait(), timeout=5)
            await asyncio.wait_for(expired.wait(), timeout=5)
            await asyncio.wait_for(
                asyncio.gather(listener_task, return_exceptions=True), timeout=5,
            )
            current = asyncio.current_task()
            return [
                task for task in asyncio.all_tasks()
                if task is not current and not task.done()
            ]

        leftover_tasks = _run(scenario())

        assert states == [
            RelayState.CONNECTING, RelayState.STOPPED, RelayState.SESSION_EXPIRED,
        ]
        assert server.heartbeats == 1
        assert manager.is_running is False
        assert active_owner(lock_path) is None
        assert leftover_tasks == []
        assert "Relay stopped" not in capsys.readouterr().out

    def test_handle_session_expired_is_idempotent(self, lock_path):
        states: list = []

        mgr = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
            listener_factory=lambda **kw: _StubListener(**kw),
            on_state_change=lambda s: states.append(s),
        )

        async def scenario():
            await mgr.start()
            await asyncio.sleep(0.02)
            await mgr._handle_session_expired()
            await mgr._handle_session_expired()
            await mgr._handle_session_expired()

        _run(scenario())
        # Only one transition INTO SESSION_EXPIRED, regardless of how
        # many times the hook fires (defends against the heartbeat
        # firing before stop() has fully landed).
        assert states.count(RelayState.SESSION_EXPIRED) == 1

    def test_notify_session_expired_public_alias(self, lock_path):
        """The public passthrough exists so callers that catch a 401
        on a non-relay endpoint (e.g. AIConversationsScreen) can flip
        the indicator immediately instead of waiting up to 30s for the
        next heartbeat tick to notice."""
        mgr = RelayManager(
            config_manager=_make_config(),
            auth_service=_make_auth(),
            lock_path=lock_path,
            listener_factory=lambda **kw: _StubListener(**kw),
        )

        async def scenario():
            await mgr.start()
            await asyncio.sleep(0.02)
            await mgr.notify_session_expired()

        _run(scenario())
        assert mgr.state is RelayState.SESSION_EXPIRED
