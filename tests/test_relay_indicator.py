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
