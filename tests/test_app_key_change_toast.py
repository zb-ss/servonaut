"""The toast that tells the user a catch-up skipped a changed member key."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from servonaut.app import ServonautApp
from servonaut.services.memory.team_wraps import KeyChange, PendingKeyChange


def _pending(instance_id: str = "i-1") -> PendingKeyChange:
    return PendingKeyChange(KeyChange("team-a", 7, "Real Person", "a" * 64), instance_id)


def _app(*, demo: bool = False):
    redaction = MagicMock()
    redaction.redact_name = lambda name: "stand-in"
    return SimpleNamespace(
        instances=[{"id": "fake-1", "name": "stand-in"}] if demo else [{"id": "i-1", "name": "web-1"}],
        _instances_pristine=[{"id": "i-1", "name": "web-1"}],
        demo_mode=demo,
        redaction_service=redaction if demo else None,
        notify=MagicMock(),
    )


def _toast(app, pending) -> str:
    ServonautApp._announce_member_key_change(app, pending)
    app.notify.assert_called_once()
    assert app.notify.call_args.kwargs["markup"] is False
    return app.notify.call_args.args[0]


def test_the_toast_names_the_server_and_where_to_confirm_but_not_the_member():
    message = _toast(_app(), _pending())
    assert "web-1" in message
    assert "Fleet Memory" in message and "S" in message
    assert "Real Person" not in message


def test_in_demo_mode_the_server_is_a_stand_in():
    message = _toast(_app(demo=True), _pending())
    assert "web-1" not in message and "stand-in" in message


def test_an_unknown_server_is_still_announced_without_its_id():
    message = _toast(_app(), _pending("i-unknown"))
    assert "i-unknown" not in message and "a server" in message


def test_the_toast_uses_the_default_lifetime():
    app = _app()
    _toast(app, _pending())
    assert "timeout" not in app.notify.call_args.kwargs
