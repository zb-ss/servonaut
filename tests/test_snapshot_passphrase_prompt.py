"""Regression tests for the snapshot-manager passphrase prompt mode.

Bug: ``_prompt_passphrase_then`` chose "Set Sync Passphrase" (type-it-twice)
vs "Enter Sync Passphrase" based on the *local probe file*. A brand-new
machine restoring an existing snapshot has no probe, so it was mis-prompted to
SET a brand-new passphrase — which could never decrypt the existing snapshot.

The fix: "Set" mode is gated on ``allow_set`` (True only for a first-ever push
to an account with zero snapshots) AND the absence of a local probe. Restores
always prompt to ENTER.
"""
from unittest.mock import MagicMock, PropertyMock, patch

from servonaut.screens.snapshot_manager import SnapshotManagerScreen


def _make_screen(*, has_probe: bool, cached=None):
    """Build a screen without running Textual __init__ and stub its deps."""
    screen = object.__new__(SnapshotManagerScreen)
    sync = MagicMock()
    sync._cached_passphrase = cached
    sync.has_probe.return_value = has_probe
    # Instance attribute shadows the bound method for our call site.
    screen._sync_service = lambda: sync
    return screen


def _captured_modal(screen, **kwargs):
    """Invoke _prompt_passphrase_then and return the PassphraseModal pushed."""
    mock_app = MagicMock()
    with patch.object(
        SnapshotManagerScreen, "app", new_callable=PropertyMock, return_value=mock_app
    ):
        screen._prompt_passphrase_then(lambda pp: None, **kwargs)
    if not mock_app.push_screen.called:
        return None
    return mock_app.push_screen.call_args[0][0]


def test_restore_always_prompts_enter_on_fresh_machine():
    """No probe (new machine), restore (allow_set defaults False) -> ENTER."""
    screen = _make_screen(has_probe=False)
    modal = _captured_modal(screen)  # restore path: no allow_set
    assert modal is not None
    assert modal._confirm is False
    assert modal._title == "Enter Sync Passphrase"


def test_restore_prompts_enter_even_with_probe():
    screen = _make_screen(has_probe=True)
    modal = _captured_modal(screen)
    assert modal._confirm is False
    assert modal._title == "Enter Sync Passphrase"


def test_first_push_no_probe_prompts_set():
    """First push (account empty -> allow_set=True), no probe -> SET."""
    screen = _make_screen(has_probe=False)
    modal = _captured_modal(screen, allow_set=True)
    assert modal._confirm is True
    assert modal._title == "Set Sync Passphrase"


def test_allow_set_is_overridden_by_existing_probe():
    """Even on a first push, a local probe means a passphrase already exists."""
    screen = _make_screen(has_probe=True)
    modal = _captured_modal(screen, allow_set=True)
    assert modal._confirm is False
    assert modal._title == "Enter Sync Passphrase"


def test_subsequent_push_prompts_enter():
    """Account already has snapshots -> allow_set=False -> ENTER."""
    screen = _make_screen(has_probe=False)
    modal = _captured_modal(screen, allow_set=False)
    assert modal._confirm is False
    assert modal._title == "Enter Sync Passphrase"


def test_cached_passphrase_skips_modal():
    screen = _make_screen(has_probe=False, cached="hunter2hunter2")
    captured = {}
    mock_app = MagicMock()
    with patch.object(
        SnapshotManagerScreen, "app", new_callable=PropertyMock, return_value=mock_app
    ):
        screen._prompt_passphrase_then(lambda pp: captured.setdefault("pp", pp))
    assert mock_app.push_screen.called is False
    assert captured["pp"] == "hunter2hunter2"
