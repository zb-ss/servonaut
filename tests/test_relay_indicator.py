"""Tests for RelayIndicator's click routing.

The widget normally opens RelayStatusScreen on click — except in the
SESSION_EXPIRED state, where the user can't fix anything from that
screen (relay is stopped, the bearer is bad). In that one state the
click must route to LoginScreen so the obvious next step (sign in) is
one click away.
"""
from __future__ import annotations

from unittest.mock import MagicMock

from servonaut.services.relay_manager import RelayState
from servonaut.widgets.relay_indicator import RelayIndicator


class _FakeIndicator:
    """Duck-typed stand-in for RelayIndicator.

    The reactive ``state`` descriptor on the real class refuses to be
    set without a properly initialised Textual node, but the click
    handler only reads ``self.state`` and ``self.app`` — so a plain
    object with those two attributes is enough to exercise the
    routing branch under test.
    """

    def __init__(self, state):
        self.state = state
        self.app = MagicMock()


def _click_with_state(state) -> MagicMock:
    fake = _FakeIndicator(state)
    RelayIndicator.on_click(fake)  # type: ignore[arg-type]
    return fake.app


def test_click_in_connected_state_opens_relay_status_screen():
    from servonaut.widgets.relay_indicator import RelayStatusScreen

    app = _click_with_state(RelayState.CONNECTED)

    app.push_screen.assert_called_once()
    pushed = app.push_screen.call_args.args[0]
    assert isinstance(pushed, RelayStatusScreen)


def test_click_in_session_expired_pushes_login_screen():
    """The whole point of the SESSION_EXPIRED affordance — clicking the
    indicator must take the user straight to the login flow."""
    from servonaut.screens.login import LoginScreen

    app = _click_with_state(RelayState.SESSION_EXPIRED)

    app.push_screen.assert_called_once()
    pushed = app.push_screen.call_args.args[0]
    assert isinstance(pushed, LoginScreen)


def test_click_in_other_states_still_uses_relay_status_screen():
    """ERROR, STOPPED, DISABLED, etc. all keep the existing behaviour
    — RelayStatusScreen has the right diagnostics for those."""
    from servonaut.widgets.relay_indicator import RelayStatusScreen

    for state in (
        RelayState.ERROR,
        RelayState.STOPPED,
        RelayState.DISABLED,
        RelayState.CONNECTING,
        RelayState.EXTERNAL,
        RelayState.NO_ENTITLEMENT,
        RelayState.NOT_CONFIGURED,
    ):
        app = _click_with_state(state)
        pushed = app.push_screen.call_args.args[0]
        assert isinstance(pushed, RelayStatusScreen), (
            f"State {state} should keep RelayStatusScreen routing"
        )


def _status_screen() -> tuple[object, MagicMock]:
    """A RelayStatusScreen with its ``app`` and widget lookup replaced."""
    from servonaut.widgets.relay_indicator import RelayStatusScreen

    screen = object.__new__(RelayStatusScreen)
    widget = MagicMock()
    screen.query_one = MagicMock(return_value=widget)  # type: ignore[method-assign]
    return screen, widget


def test_local_status_reads_the_lock_in_the_runtime_data_root(tmp_path, monkeypatch):
    import os

    from servonaut.services.relay_lock import RelayLock
    from servonaut.widgets.relay_indicator import RelayStatusScreen

    app = MagicMock()
    app.relay_state = RelayState.EXTERNAL
    app.relay_lock_path = tmp_path / "relay.lock"
    monkeypatch.setattr(RelayStatusScreen, "app", property(lambda _self: app))
    screen, widget = _status_screen()

    with RelayLock(mode="bg", path=app.relay_lock_path):
        screen._refresh_local()

    text = widget.update.call_args.args[0]
    assert f"lock owner: bg (PID {os.getpid()})" in text


def test_restart_reports_a_failed_start_without_ending_the_app(monkeypatch):
    import asyncio

    from servonaut.services.relay_manager import StartResult
    from servonaut.widgets.relay_indicator import RelayStatusScreen

    app = MagicMock()

    async def restart() -> StartResult:
        return StartResult(RelayState.ERROR, "Could not open the relay lock (Permission denied).")

    app.relay_manager.restart = restart
    monkeypatch.setattr(RelayStatusScreen, "app", property(lambda _self: app))
    screen, _widget = _status_screen()

    screen._do_restart()

    worker_call = app.run_worker.call_args
    assert worker_call.kwargs["exit_on_error"] is False
    asyncio.run(worker_call.args[0])
    failure = [
        call for call in app.notify.call_args_list if call.kwargs.get("severity") == "error"
    ]
    assert len(failure) == 1
    assert "Permission denied" in failure[0].args[0]
    assert failure[0].kwargs["markup"] is False
