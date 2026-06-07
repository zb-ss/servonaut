"""Tests for AIConversationsScreen — Wave 2 hosted-AI history surface.

Implementation note: rather than spinning up Textual's ``App.run_test``
pilot for every assertion (which requires a fully wired CSS path and a
mountable widget tree), we exercise the screen at two levels:

  * ``compose()`` — assert the static structure (Sidebar + DataTable +
    action buttons). No app context required.
  * action methods — invoke ``action_archive``/``action_delete``/
    ``action_export`` on a screen whose ``app`` attribute is a MagicMock
    that exposes ``ai_conversations_client``, ``notify``, ``push_screen``,
    and ``run_worker``. This isolates the Wave 2 control flow from Wave 1
    (already covered by ``test_ai_conversations.py``) and from Wave 3
    (still in flight).

We use ``MagicMock(spec=AIConversationsClient)`` so positional misuse of
its async methods fails at test time — matching the convention called
out in the project's Memory Sync conventions.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.screens.ai_conversations_screen import (
    AIConversationsScreen,
    _ConfirmModal,
    _ExportPathModal,
)
from servonaut.services.ai_conversations import (
    AIConversationsClient,
    ConversationSummary,
)


def run(coro):
    """Synchronous asyncio wrapper — matches the project test convention."""
    return asyncio.run(coro)


def _make_summary(
    *,
    id: str = "conv-1",
    title: str = "Why is nginx 502ing?",
    status: str = "active",
    updated_at: str = "2026-04-15T10:30:00Z",
    message_count: int = 4,
    last_model: str = "gemini-2-flash-002",
) -> ConversationSummary:
    return ConversationSummary(
        id=id,
        title=title,
        status=status,
        created_at="2026-04-15T10:00:00Z",
        updated_at=updated_at,
        message_count=message_count,
        last_model=last_model,
    )


def _mocked_screen() -> tuple[AIConversationsScreen, MagicMock, MagicMock]:
    """Build a screen with a mocked ``app`` and ``ai_conversations_client``.

    Returns ``(screen, app_mock, client_mock)``. The screen's
    ``_selected`` helper is monkey-patched per-test so callers don't have
    to construct a real DataTable.
    """
    screen = AIConversationsScreen()

    client = MagicMock(spec=AIConversationsClient)
    client.list = AsyncMock(return_value=[_make_summary()])
    client.patch = AsyncMock(return_value={"id": "conv-1"})
    client.delete = AsyncMock(return_value=None)
    client.export_md = AsyncMock(return_value=Path("/tmp/conv-1.md"))

    app = MagicMock()
    app.ai_conversations_client = client
    app.notify = MagicMock()
    app.push_screen = MagicMock()
    app.run_worker = MagicMock()

    # Replace the read-only Screen.app descriptor for the duration of the test.
    type(screen).app = property(lambda self, _a=app: _a)  # type: ignore[assignment]
    return screen, app, client


@pytest.mark.asyncio
async def test_screen_renders_sidebar_and_table():
    """A mounted screen exposes both a Sidebar and the conversations DataTable.

    Textual's container context-managers (``with Horizontal(...)``) require
    an active App context, so we mount the screen via ``App.run_test``
    rather than calling ``compose()`` directly.
    """
    from textual.app import App
    from textual.widgets import DataTable

    from servonaut.widgets.sidebar import Sidebar

    class _Host(App):
        def on_mount(self) -> None:
            # Wire a stub client so on_mount → _load_page doesn't NPE.
            stub = MagicMock(spec=AIConversationsClient)
            stub.list = AsyncMock(return_value=[])
            self.ai_conversations_client = stub
            self.push_screen(AIConversationsScreen())

    app = _Host()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        # Sidebar is mounted on the active screen.
        sidebars = list(app.screen.query(Sidebar))
        assert sidebars, "Screen must include a Sidebar widget"
        tables = list(app.screen.query(DataTable))
        assert any(t.id == "convs_table" for t in tables), (
            "Screen must include a DataTable with id=convs_table"
        )


def test_load_page_calls_client_list_with_correct_args():
    """``_load_page()`` issues ``client.list(limit=25, before=None, status='active')``."""
    screen, _app, client = _mocked_screen()
    # _load_page touches the ProgressIndicator widget through query_one, but
    # the screen isn't mounted in this test — neutralise those lookups.
    screen.query_one = MagicMock()  # type: ignore[assignment]
    screen.query_one.return_value = MagicMock(start=MagicMock(), stop=MagicMock())
    screen._render_table = MagicMock()  # type: ignore[assignment]
    screen._update_status = MagicMock()  # type: ignore[assignment]

    run(screen._load_page())

    client.list.assert_awaited_once_with(limit=25, before=None, status="active")


def test_archive_calls_patch_after_confirmation():
    """A confirmed archive flow ends with ``client.patch(uuid, status='archived')``."""
    screen, app, client = _mocked_screen()

    conv = _make_summary()
    screen._conversations = [conv]
    screen._selected = MagicMock(return_value=conv)  # type: ignore[assignment]
    screen._render_table = MagicMock()  # type: ignore[assignment]
    screen._update_status = MagicMock()  # type: ignore[assignment]

    # Press 'a': pushes the confirm modal (we don't need to render it).
    screen.action_archive()
    assert app.push_screen.called, "action_archive must push a confirm modal"
    # First positional arg is the modal instance.
    pushed_modal = app.push_screen.call_args.args[0]
    assert isinstance(pushed_modal, _ConfirmModal)

    # Simulate the user confirming: this is what the callback does.
    run(screen._do_archive(conv))

    client.patch.assert_awaited_once_with("conv-1", status="archived")
    # Local list dropped the row.
    assert screen._conversations == []


def test_delete_pushes_confirm_modal():
    """``action_delete`` pushes a danger-styled confirm modal before any network call."""
    screen, app, client = _mocked_screen()

    conv = _make_summary()
    screen._conversations = [conv]
    screen._selected = MagicMock(return_value=conv)  # type: ignore[assignment]

    screen.action_delete()

    assert app.push_screen.called, "action_delete must push a confirm modal"
    pushed_modal = app.push_screen.call_args.args[0]
    assert isinstance(pushed_modal, _ConfirmModal)
    # No premature network call — delete must wait for the callback.
    client.delete.assert_not_called()


def test_export_path_traversal_surfaces_as_toast():
    """A path-traversal ``ValueError`` from the client becomes a notify, not a crash.

    A5 — also asserts the notify uses ``markup=False`` so a server-supplied
    Rich-markup payload in the exception message can't hijack the toast.
    """
    screen, app, client = _mocked_screen()
    client.export_md = AsyncMock(
        side_effect=ValueError("Export path must be inside CWD or ~/Downloads")
    )
    conv = _make_summary()

    # Drive the actual export coroutine — bypass the Path modal.
    run(screen._do_export(conv, "/etc/passwd"))

    client.export_md.assert_awaited_once()
    assert app.notify.called, "Path-traversal must surface to the user"
    # Verify severity is error so it's visually distinct from a success toast.
    kwargs = app.notify.call_args.kwargs
    assert kwargs.get("severity") == "error"
    # A5 — markup must be off so injected ``[link=evil]`` brackets render
    # literally in the toast, not as a Rich Link.
    assert kwargs.get("markup") is False


def test_archive_apierror_with_markup_uses_markup_false():
    """A5 — Archive failure surfaces with ``markup=False``.

    Drives ``_do_archive`` against a client whose ``patch`` raises an
    APIError carrying Rich markup; asserts the notify call passed
    ``markup=False`` so the bracketed payload renders literally.
    """
    from servonaut.services.api_client import APIError

    screen, app, client = _mocked_screen()
    client.patch = AsyncMock(
        side_effect=APIError(
            code="rate_limited",
            message="[link=evil]click[/link]",
            status=429,
        )
    )
    conv = _make_summary()

    run(screen._do_archive(conv))

    assert app.notify.called
    kwargs = app.notify.call_args.kwargs
    assert kwargs.get("markup") is False


def test_export_action_pushes_path_modal():
    """``action_export`` prompts for a destination path before downloading."""
    screen, app, _client = _mocked_screen()
    conv = _make_summary(title="My Investigation")
    screen._selected = MagicMock(return_value=conv)  # type: ignore[assignment]

    screen.action_export()

    assert app.push_screen.called
    pushed_modal = app.push_screen.call_args.args[0]
    assert isinstance(pushed_modal, _ExportPathModal)


def test_archive_without_selection_warns_and_returns():
    """Pressing 'a' with no row selected must warn — not crash, not call client."""
    screen, app, client = _mocked_screen()
    screen._selected = MagicMock(return_value=None)  # type: ignore[assignment]

    screen.action_archive()

    # Warning toast surfaced, no modal pushed, no network call.
    assert app.notify.called
    kwargs = app.notify.call_args.kwargs
    assert kwargs.get("severity") == "warning"
    assert not app.push_screen.called
    client.patch.assert_not_called()


# ---------------------------------------------------------------------------
# Tabs (Cloud / Local) — initial tab + Local-tab action routing
# ---------------------------------------------------------------------------


def _mocked_screen_with_chat_service(
    *,
    authenticated: bool = True,
    premium: bool = True,
    local_sessions=None,
):
    """Variant of _mocked_screen wired with a ChatService mock for the
    Local tab. Returns ``(screen, app_mock, client_mock, chat_service_mock)``.
    """
    screen = AIConversationsScreen()

    client = MagicMock(spec=AIConversationsClient)
    client.list = AsyncMock(return_value=[])
    client.delete = AsyncMock(return_value=None)

    chat_service = MagicMock()
    chat_service.list_sessions = MagicMock(return_value=local_sessions or [])
    chat_service.delete_session = MagicMock(return_value=True)

    auth = MagicMock()
    auth.is_authenticated = authenticated
    auth.has_feature = MagicMock(side_effect=lambda f: premium and f == "premium_ai")

    app = MagicMock()
    app.ai_conversations_client = client
    app.chat_service = chat_service
    app.auth_service = auth
    app.notify = MagicMock()
    app.push_screen = MagicMock()
    app.pop_screen = MagicMock()
    app.run_worker = MagicMock()

    type(screen).app = property(lambda self, _a=app: _a)  # type: ignore[assignment]
    return screen, app, client, chat_service


def test_initial_tab_is_cloud_for_premium_user():
    screen, _, _, _ = _mocked_screen_with_chat_service(
        authenticated=True, premium=True,
    )
    assert screen._initial_tab() == "tab_cloud"
    assert screen._active_tab == "tab_cloud"


def test_initial_tab_is_local_for_logged_out_user():
    screen, _, _, _ = _mocked_screen_with_chat_service(
        authenticated=False, premium=False,
    )
    assert screen._initial_tab() == "tab_local"
    assert screen._active_tab == "tab_local"


def test_initial_tab_is_local_for_authenticated_non_premium():
    screen, _, _, _ = _mocked_screen_with_chat_service(
        authenticated=True, premium=False,
    )
    assert screen._initial_tab() == "tab_local"


def test_local_delete_paired_session_also_deletes_remote():
    """Deleting a Local row that has a remote_conversation_id must drop
    both the local file AND the paired Cloud row, otherwise the user
    sees zombie rows on the Cloud tab."""
    screen, _, client, chat_service = _mocked_screen_with_chat_service()

    row = {
        "id": "local-1",
        "title": "Paired session",
        "remote_conversation_id": "conv-remote-1",
    }
    # Stub render so we don't need a mounted DataTable.
    screen._render_table = MagicMock()  # type: ignore[assignment]
    screen._update_status = MagicMock()  # type: ignore[assignment]
    screen._reload_local_table = MagicMock()  # type: ignore[assignment]

    run(screen._do_local_delete(row))

    client.delete.assert_awaited_once_with("conv-remote-1")
    chat_service.delete_session.assert_called_once_with("local-1")


def test_local_delete_unpaired_session_skips_remote_call():
    """Unpaired Local rows have no Cloud counterpart — the server delete
    must not fire, otherwise we'd 404 on every local-only delete."""
    screen, _, client, chat_service = _mocked_screen_with_chat_service()

    row = {
        "id": "local-2",
        "title": "Local only",
        "remote_conversation_id": None,
    }
    screen._reload_local_table = MagicMock()  # type: ignore[assignment]

    run(screen._do_local_delete(row))

    client.delete.assert_not_called()
    chat_service.delete_session.assert_called_once_with("local-2")


def test_local_delete_remote_failure_still_removes_local():
    """A 5xx on the paired remote delete must NOT block the local file
    delete — the user explicitly asked to remove the row, and we
    surface the cloud-side failure as a non-fatal warning."""
    screen, app, client, chat_service = _mocked_screen_with_chat_service()
    client.delete = AsyncMock(side_effect=RuntimeError("boom"))

    row = {
        "id": "local-3",
        "title": "Paired but server angry",
        "remote_conversation_id": "conv-x",
    }
    screen._reload_local_table = MagicMock()  # type: ignore[assignment]

    run(screen._do_local_delete(row))

    chat_service.delete_session.assert_called_once_with("local-3")
    # User is told what failed.
    notify_severities = [
        c.kwargs.get("severity") for c in app.notify.call_args_list
    ]
    assert "warning" in notify_severities


def test_archive_on_local_tab_is_a_no_op_with_hint():
    """Archive is a Cloud-only feature — pressing 'a' on the Local tab
    must surface a hint, not crash on missing state."""
    screen, app, _, _ = _mocked_screen_with_chat_service()
    screen._active_tab = "tab_local"

    screen.action_archive()

    app.notify.assert_called_once()
    args = app.notify.call_args
    assert "Cloud-only" in args.args[0]


def test_export_on_local_tab_is_a_no_op_with_hint():
    screen, app, _, _ = _mocked_screen_with_chat_service()
    screen._active_tab = "tab_local"

    screen.action_export()

    app.notify.assert_called_once()
    args = app.notify.call_args
    assert "Cloud-only" in args.args[0]


def test_local_filter_narrows_visible_slice():
    """The Local-tab filter input must filter by title, case-insensitive."""
    sessions = [
        {"id": "a", "title": "Why is nginx 502ing", "updated_at": "2026-05-04",
         "message_count": 4, "last_provider": "openai",
         "remote_conversation_id": None},
        {"id": "b", "title": "AWS billing for May", "updated_at": "2026-05-03",
         "message_count": 2, "last_provider": "ollama",
         "remote_conversation_id": None},
    ]
    screen, _, _, _ = _mocked_screen_with_chat_service(local_sessions=sessions)
    screen._local_sessions = sessions

    screen._local_filter = "nginx"
    visible = screen._local_filtered()
    assert [s["id"] for s in visible] == ["a"]

    screen._local_filter = "AWS"
    visible = screen._local_filtered()
    assert [s["id"] for s in visible] == ["b"]


def test_group_by_date_buckets_correctly():
    """Today/Yesterday/Earlier-this-week/Older buckets are populated by updated_at."""
    from datetime import datetime, timedelta, timezone

    screen = AIConversationsScreen()
    now = datetime.now(tz=timezone.utc)
    items = [
        _make_summary(id="t", updated_at=now.isoformat()),
        _make_summary(id="y", updated_at=(now - timedelta(days=1)).isoformat()),
        _make_summary(id="w", updated_at=(now - timedelta(days=4)).isoformat()),
        _make_summary(id="o", updated_at=(now - timedelta(days=30)).isoformat()),
    ]
    groups = screen._group_by_date(items)

    assert [c.id for c in groups["Today"]] == ["t"]
    assert [c.id for c in groups["Yesterday"]] == ["y"]
    assert [c.id for c in groups["Earlier this week"]] == ["w"]
    assert [c.id for c in groups["Older"]] == ["o"]
