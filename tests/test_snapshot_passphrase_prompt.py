"""Regression tests for the snapshot-manager passphrase prompt mode.

Bug: ``_prompt_passphrase_then`` chose "Set sync passphrase" (type-it-twice)
vs "Enter sync passphrase" based on the *local probe file*. A brand-new
machine restoring an existing snapshot has no probe, so it was mis-prompted to
SET a brand-new passphrase — which could never decrypt the existing snapshot.

The fix: "Set" mode is gated on ``allow_set`` (True only for a first-ever push
to an account with zero snapshots) AND the absence of a local probe. Restores
always prompt to ENTER.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

from servonaut.screens.snapshot_manager import ConfirmModal, SnapshotManagerScreen
from servonaut.services import config_crypto
from servonaut.services.config_sync_service import ConfigKeyError


def _make_screen(*, has_probe: bool, cached: bool = False, mode: str = "passphrase"):
    """Build a screen without running Textual __init__ and stub its deps."""
    screen = object.__new__(SnapshotManagerScreen)
    sync = MagicMock()
    sync.has_cached_passphrase.return_value = cached
    sync.has_probe.return_value = has_probe
    sync.key_mode = AsyncMock(return_value=mode)
    # Instance attributes shadow the bound methods for our call sites.
    screen._sync_service = lambda: sync
    screen._set_status = MagicMock()
    screen._snapshots = []
    screen.notify = MagicMock()
    screen.sync = sync
    return screen


def _run(screen, **kwargs):
    """Resolve the key mode; return (modal pushed or None, then-calls)."""
    mock_app = MagicMock()
    calls = []
    with patch.object(
        SnapshotManagerScreen, "app", new_callable=PropertyMock, return_value=mock_app
    ):
        asyncio.run(
            screen._resolve_key_mode(
                lambda pp: calls.append(pp), kwargs.get("allow_set", False)
            )
        )
    modal = mock_app.push_screen.call_args[0][0] if mock_app.push_screen.called else None
    return modal, calls


def test_restore_always_prompts_enter_on_fresh_machine():
    """No probe (new machine), restore (allow_set False) -> ENTER."""
    modal, _ = _run(_make_screen(has_probe=False))
    assert modal is not None
    assert modal._confirm is False
    assert modal._title == "Enter sync passphrase"


def test_restore_prompts_enter_even_with_probe():
    modal, _ = _run(_make_screen(has_probe=True))
    assert modal._confirm is False
    assert modal._title == "Enter sync passphrase"


def test_first_push_no_probe_prompts_set():
    """First push (account empty -> allow_set=True), no probe -> SET."""
    modal, _ = _run(_make_screen(has_probe=False), allow_set=True)
    assert modal._confirm is True
    assert modal._title == "Set sync passphrase"


def test_allow_set_is_overridden_by_existing_probe():
    modal, _ = _run(_make_screen(has_probe=True), allow_set=True)
    assert modal._confirm is False
    assert modal._title == "Enter sync passphrase"


def test_subsequent_push_prompts_enter():
    modal, _ = _run(_make_screen(has_probe=False), allow_set=False)
    assert modal._confirm is False
    assert modal._title == "Enter sync passphrase"


def test_cached_passphrase_skips_modal():
    modal, calls = _run(_make_screen(has_probe=False, cached=True))
    assert modal is None
    # The service falls back to its own cache for None.
    assert calls == [None]


def test_vault_mode_pushes_without_modal():
    screen = _make_screen(has_probe=False, mode="vault")
    modal, calls = _run(screen, allow_set=True)
    assert modal is None
    assert calls == [None]
    assert screen._set_status.call_args_list[0][0][0].startswith("[dim]Checking sync key")


def test_key_mode_failure_shows_client_text_and_never_continues():
    screen = _make_screen(has_probe=False)
    screen.sync.key_mode = AsyncMock(side_effect=ConfigKeyError("vault_not_ready"))
    modal, calls = _run(screen)
    assert modal is None
    assert calls == []
    assert screen.notify.call_args.kwargs["markup"] is False
    assert "vault" in screen.notify.call_args[0][0].lower()


def _prompt_for_snapshot(snapshot):
    screen = _make_screen(has_probe=False, mode="vault")
    mock_app = MagicMock()
    calls = []
    with patch.object(
        SnapshotManagerScreen, "app", new_callable=PropertyMock, return_value=mock_app
    ):
        screen._prompt_passphrase_then(lambda pp: calls.append(pp), snapshot=snapshot)
    return screen, mock_app, calls


def test_restoring_vault_snapshot_needs_no_passphrase():
    screen, mock_app, calls = _prompt_for_snapshot({"id": "s1", "key_custody": "vault"})
    assert mock_app.push_screen.called is False
    assert calls == [None]
    screen.sync.key_mode.assert_not_called()


def test_restoring_passphrase_snapshot_still_asks_in_vault_mode():
    screen, mock_app, calls = _prompt_for_snapshot({"id": "s1", "key_custody": "passphrase"})
    modal = mock_app.push_screen.call_args[0][0]
    assert modal._title == "Enter sync passphrase"
    assert calls == []
    screen.sync.key_mode.assert_not_called()


def test_restoring_snapshot_without_custody_field_asks():
    _, mock_app, _ = _prompt_for_snapshot({"id": "s1"})
    assert mock_app.push_screen.call_args[0][0]._title == "Enter sync passphrase"


# -- move key to vault --------------------------------------------------


def _move_screen(*, unlocked: bool, snapshots):
    screen = _make_screen(has_probe=False)
    screen._snapshots = snapshots
    screen._moving_key = False
    shown = {}

    def query_one(selector, *_a):
        widget = shown.setdefault(selector, MagicMock())
        return widget

    screen.query_one = query_one
    screen.shown = shown
    mock_app = MagicMock()
    mock_app.vault_command_service = MagicMock(is_unlocked=unlocked)
    return screen, mock_app


def _offer(screen, mock_app):
    with patch.object(
        SnapshotManagerScreen, "app", new_callable=PropertyMock, return_value=mock_app
    ):
        screen._sync_move_offer()
    return screen.shown["#snap_btn_move_to_vault"].display


def test_move_offer_shown_for_passphrase_snapshots_when_vault_ready():
    screen, app = _move_screen(
        unlocked=True,
        snapshots=[{"key_custody": "vault"}, {"key_custody": "passphrase"}],
    )
    assert _offer(screen, app) is True
    assert screen.shown["#snapshots_move_notice"].display is True


def test_move_offer_hidden_when_vault_not_ready_or_all_vault():
    locked, app = _move_screen(unlocked=False, snapshots=[{"key_custody": "passphrase"}])
    assert _offer(locked, app) is False
    done, app = _move_screen(unlocked=True, snapshots=[{"key_custody": "vault"}])
    assert _offer(done, app) is False


def test_move_button_opens_confirm_that_names_the_replacement():
    screen, app = _move_screen(unlocked=True, snapshots=[{"key_custody": "passphrase"}])
    with patch.object(
        SnapshotManagerScreen, "app", new_callable=PropertyMock, return_value=app
    ):
        screen.action_move_key_to_vault()
    modal = app.push_screen.call_args[0][0]
    assert isinstance(modal, ConfirmModal)
    assert "replaced by one new snapshot" in modal._message
    assert "passphrase stops being needed" in modal._message


def test_declined_confirm_does_not_move():
    screen, _ = _move_screen(unlocked=True, snapshots=[])
    screen.run_worker = MagicMock()
    screen._move_after_confirm(False)
    screen.run_worker.assert_not_called()


def test_confirmed_move_runs_in_its_own_worker_group():
    screen, _ = _move_screen(unlocked=True, snapshots=[])
    screen.run_worker = MagicMock(side_effect=lambda coro, **kw: coro.close())
    screen._move_after_confirm(True)
    assert screen.run_worker.call_args.kwargs["group"] == "config_sync_move"


def test_do_move_reports_progress_and_reloads():
    screen, _ = _move_screen(unlocked=True, snapshots=[])
    screen._load_snapshots = AsyncMock()

    async def fake_move(progress, *, recovery_gate):
        progress("key")
        progress("cleanup")
        return {"key_created": True, "pushed": True, "deleted": 2}

    screen.sync.move_key_to_vault = fake_move
    asyncio.run(screen._do_move_key())
    texts = [c[0][0] for c in screen._set_status.call_args_list]
    assert any("Preparing the vault key" in t for t in texts)
    assert screen.notify.call_args[0][0] == "Config sync key moved to your vault."
    screen._load_snapshots.assert_awaited_once()
    assert screen._moving_key is False


def test_do_move_hands_the_recovery_gate_to_the_service():
    screen, _ = _move_screen(unlocked=True, snapshots=[])
    screen._load_snapshots = AsyncMock()
    screen.sync.move_key_to_vault = AsyncMock(return_value={"key_created": True, "pushed": True, "deleted": 0})
    asyncio.run(screen._do_move_key())
    assert screen.sync.move_key_to_vault.call_args.kwargs["recovery_gate"] == screen._prove_recovery


def _prove(screen, app, answer, verify):
    """Run ``_prove_recovery`` with the prompt answered by *answer* and the vault check *verify*."""
    app.vault_command_service.verify_recovery_key = verify

    def push(modal, callback):
        callback(answer)

    app.push_screen = push
    with patch.object(SnapshotManagerScreen, "app", new_callable=PropertyMock, return_value=app):
        return asyncio.run(screen._prove_recovery())


def test_recovery_gate_passes_when_the_vault_accepts_the_key():
    screen, app = _move_screen(unlocked=True, snapshots=[])
    verify = AsyncMock(return_value=True)
    assert _prove(screen, app, "TEST-RECOVERY-KEY", verify) is None
    verify.assert_awaited_once_with("TEST-RECOVERY-KEY")


def test_recovery_gate_stops_on_a_wrong_key_and_on_cancel():
    import pytest
    from servonaut.services.memory.custody_move import MoveAborted, MoveStopped

    screen, app = _move_screen(unlocked=True, snapshots=[])
    with pytest.raises(MoveStopped) as stopped:
        _prove(screen, app, "TEST-RECOVERY-KEY", AsyncMock(return_value=False))
    assert stopped.value.reason == "recovery_key_mismatch"
    with pytest.raises(MoveAborted):
        _prove(screen, app, None, AsyncMock())


def test_do_move_cancelled_prompt_changes_nothing_and_says_so():
    from servonaut.services.memory.custody_move import MoveAborted

    screen, _ = _move_screen(unlocked=True, snapshots=[])
    screen._load_snapshots = AsyncMock()
    screen.sync.move_key_to_vault = AsyncMock(side_effect=MoveAborted())
    asyncio.run(screen._do_move_key())
    assert screen.notify.call_args[0][0] == "Move cancelled. Nothing was changed."
    assert screen.notify.call_args.kwargs.get("severity") is None
    screen._load_snapshots.assert_not_awaited()


def test_do_move_failure_shows_custody_text_with_markup_off():
    screen, _ = _move_screen(unlocked=True, snapshots=[])
    screen._load_snapshots = AsyncMock()
    screen.sync.move_key_to_vault = AsyncMock(side_effect=ConfigKeyError("no_vault_snapshot"))
    asyncio.run(screen._do_move_key())
    assert screen.notify.call_args.kwargs["markup"] is False
    assert screen.notify.call_args[0][0] == ConfigKeyError("no_vault_snapshot").args[0]
    screen._load_snapshots.assert_not_awaited()
    assert screen._moving_key is False


# -- restore error text -------------------------------------------------


def test_vault_snapshot_decrypt_failure_does_not_blame_the_passphrase():
    screen = _make_screen(has_probe=False)
    screen.sync.restore_by_id = AsyncMock(
        side_effect=config_crypto.DecryptionError("not in your vault")
    )
    asyncio.run(screen._do_restore({"id": "s1", "key_custody": "vault"}, None))
    assert screen.notify.call_args[0][0] == "not in your vault"
    assert screen.notify.call_args.kwargs["markup"] is False


def test_a_refused_push_shows_the_client_text_not_push_failed():
    screen = _make_screen(has_probe=False, mode="vault")
    screen.sync.push = AsyncMock(side_effect=ConfigKeyError("config_key_not_ready"))
    asyncio.run(screen._do_push("laptop", None))
    shown = screen.notify.call_args[0][0]
    assert shown.startswith("Your config sync key is not in your vault yet")
    assert not shown.startswith("Push failed")
    assert screen.notify.call_args.kwargs["markup"] is False
    assert "Push failed" not in screen._set_status.call_args[0][0]


def test_a_service_refusal_of_a_push_shows_the_client_text():
    from servonaut.services.api_client import APIError

    screen = _make_screen(has_probe=False, mode="vault")
    screen.sync.push = AsyncMock(side_effect=APIError(
        code="config_key_not_ready", message="No live config key item", status=409))
    asyncio.run(screen._do_push("laptop", None))
    shown = screen.notify.call_args[0][0]
    assert shown.startswith("Your config sync key is not in your vault yet")
    assert "No live config key item" not in shown
    assert "No live config key item" not in screen._set_status.call_args[0][0]
