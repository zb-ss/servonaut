"""Test the session-expired toast surfaced by ServonautApp on the
RelayState transition into SESSION_EXPIRED.

The label change on the small sidebar dot is easy to miss; the toast
gives a one-time, plain-text instruction telling the user how to
recover (click the indicator to sign in). We pin the trigger condition
here so the toast can't silently regress.
"""
from __future__ import annotations

from unittest.mock import MagicMock

from servonaut.app import ServonautApp
from servonaut.services.relay_manager import RelayState


class _StubApp:
    """Duck-typed stand-in for ServonautApp.

    ``_on_relay_state_change`` only touches ``self.relay_state``,
    ``self.query``, and ``self.notify`` — a plain object with those
    is enough to exercise the toast trigger without spinning up
    Textual.
    """

    def __init__(self, prior_state):
        self.relay_state = prior_state
        self.notify = MagicMock()
        self.query = MagicMock(return_value=[])


def _fire(prior, new):
    stub = _StubApp(prior)
    ServonautApp._on_relay_state_change(stub, new)  # type: ignore[arg-type]
    return stub


def test_transition_into_session_expired_fires_toast():
    stub = _fire(RelayState.CONNECTED, RelayState.SESSION_EXPIRED)

    stub.notify.assert_called_once()
    args = stub.notify.call_args
    assert "session expired" in args.args[0].lower()
    assert "sign in" in args.args[0].lower()
    # ``markup=False`` is mandatory — the message is one we control,
    # but the policy across the app is uniform to avoid policy drift.
    assert args.kwargs.get("markup") is False
    assert args.kwargs.get("severity") == "warning"


def test_already_session_expired_does_not_re_fire_toast():
    """Repeat firings (e.g. heartbeat tick after AIConversationsScreen
    already triggered notify_session_expired) must not surface a
    duplicate toast for the same condition."""
    stub = _fire(RelayState.SESSION_EXPIRED, RelayState.SESSION_EXPIRED)

    stub.notify.assert_not_called()


def test_other_transitions_do_not_fire_session_expired_toast():
    """Any other state change keeps the original silent behaviour."""
    for prior, new in [
        (RelayState.CONNECTING, RelayState.CONNECTED),
        (RelayState.CONNECTED, RelayState.STOPPED),
        (RelayState.CONNECTED, RelayState.ERROR),
        (None, RelayState.DISABLED),
    ]:
        stub = _fire(prior, new)
        stub.notify.assert_not_called(), (
            f"Toast must not fire on transition {prior} -> {new}"
        )
