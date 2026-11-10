"""Relay status keeps complete diagnostics and native controls reachable."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest
from textual.content import Content
from textual.command import CommandPalette
from textual.containers import Container
from textual.widgets import Button, Static

from servonaut.services.relay_manager import RelayState
from servonaut.services.redaction_service import RedactionService
from servonaut.widgets.busy_indicator import BusyIndicator
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.relay_indicator import RelayStatusScreen
from tests._async_bounds import wait_until
from tests.test_workspace_account_leaf import _AccountHost

pytestmark = pytest.mark.usefixtures("navigation_open")


def _painted(app, widget) -> str:
    strips = app.screen._compositor.render_strips()
    return "\n".join(
        strips[y].crop(widget.region.x, widget.region.right).text
        for y in range(max(0, widget.region.y), min(len(strips), widget.region.bottom))
    )


def _plain(value) -> str:
    return value.plain if isinstance(value, Content) else Content.from_markup(str(value)).plain


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_long_relay_diagnostics_keep_actions_and_full_values(size, monkeypatch) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    # Plain long text isolates viewport fit from the literal-markup regressions.
    reason = "Unavailable: example diagnostic detail " * 100 + "final-diagnostic"
    status = AsyncMock(return_value=json.dumps({"error": {"message": reason}}))
    monkeypatch.setattr(
        "servonaut.widgets.relay_indicator._build_mcp_tools_for_this_app",
        lambda app: SimpleNamespace(relay_status=status),
    )
    app = _AccountHost()
    app.relay_state = RelayState.ERROR
    app.relay_manager.last_error = reason
    async with app.run_test(size=size) as pilot:
        origin = app.screen
        screen = RelayStatusScreen()
        await app.push_screen(screen)
        backend = screen.query_one("#backend_status", Static)
        await wait_until(lambda: "final-diagnostic" in str(backend.content))
        await pilot.pause()
        # Native mouse hits prove that long text cannot displace or cover
        # the controls, including Close at the narrow supported size.
        for button_id, label in (
            ("btn_relay_restart", "Restart"), ("btn_relay_stop", "Stop"),
            ("btn_relay_close", "Close"),
        ):
            button = screen.query_one(f"#{button_id}", Button)
            assert screen.region.contains_region(button.region)
            assert app.get_widget_at(*button.region.center)[0] is button
            assert label in _painted(app, button)
        local = screen.query_one("#local_status", Static)
        assert reason in _plain(local.content)
        assert reason in _plain(backend.content)
        document = screen.query_one("#relay_card")
        assert document.max_scroll_y > 0
        document.focus()
        await pilot.press("end")
        await pilot.pause()
        assert "final-diagnostic" in _painted(app, document)
        await pilot.click("#btn_relay_close")
        await pilot.pause()
        assert app.screen is origin
        app.relay_manager.restart.assert_not_awaited()
        app.relay_manager.stop.assert_not_awaited()


@pytest.mark.asyncio
async def test_backend_loading_indicator_covers_the_existing_read(monkeypatch) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    release = asyncio.Event()
    entered = asyncio.Event()

    async def status():
        entered.set()
        await release.wait()
        return json.dumps({"connected": True, "client_ids": []})

    monkeypatch.setattr(
        "servonaut.widgets.relay_indicator._build_mcp_tools_for_this_app",
        lambda app: SimpleNamespace(relay_status=status),
    )
    app = _AccountHost()
    async with app.run_test(size=(100, 30)) as pilot:
        screen = RelayStatusScreen()
        await app.push_screen(screen)
        await wait_until(entered.is_set)
        busy = screen.query_one("#relay_backend_busy", BusyIndicator)
        assert busy.is_active
        assert "loading" in str(screen.query_one("#backend_status", Static).content)
        release.set()
        await wait_until(lambda: not busy.is_active)
        assert "connected" in str(screen.query_one("#backend_status", Static).content)


@pytest.mark.asyncio
@pytest.mark.parametrize("response_error", [True, False])
async def test_backend_errors_remain_literal(response_error) -> None:
    message = "Request failed [$text-error]literal[/$text-error] [unmatched"
    tools = SimpleNamespace(relay_status=AsyncMock(
        return_value=json.dumps({"error": {"message": message}}),
        side_effect=None if response_error else RuntimeError(message),
    ))
    screen = object.__new__(RelayStatusScreen)
    widget = MagicMock()
    screen.query_one = MagicMock(return_value=widget)
    with (
        patch.object(RelayStatusScreen, "app", new_callable=PropertyMock, return_value=SimpleNamespace()),
        patch("servonaut.widgets.relay_indicator._build_mcp_tools_for_this_app", return_value=tools),
    ):
        await screen._refresh_backend()
    assert _plain(widget.update.call_args.args[0]) == f"Backend: error — {message}"


def test_local_error_theme_tags_and_unmatched_brackets_remain_literal(monkeypatch) -> None:
    reason = "Refused [$text-error]literal[/$text-error] [unmatched"
    app = SimpleNamespace(
        relay_state=RelayState.ERROR, relay_lock_path=None,
        relay_manager=SimpleNamespace(last_error=reason),
    )
    screen = object.__new__(RelayStatusScreen)
    widget = MagicMock()
    screen.query_one = MagicMock(return_value=widget)
    monkeypatch.setattr("servonaut.services.relay_lock.read_owner", lambda path: SimpleNamespace(pid=None))
    with patch.object(RelayStatusScreen, "app", new_callable=PropertyMock, return_value=app):
        screen._refresh_local()
    assert _plain(widget.update.call_args.args[0]) == f"Local: error\n{reason}"


@pytest.mark.asyncio
@pytest.mark.parametrize("close_with", ["close", "escape"])
async def test_closing_pending_relay_status_cancels_the_read(close_with, monkeypatch) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    entered, cancelled, finished, release = (asyncio.Event() for _ in range(4))

    async def status():
        entered.set()
        try:
            await release.wait()
            return json.dumps({"connected": True})
        except asyncio.CancelledError:
            cancelled.set()
            raise
        finally:
            finished.set()

    monkeypatch.setattr(
        "servonaut.widgets.relay_indicator._build_mcp_tools_for_this_app",
        lambda app: SimpleNamespace(relay_status=status),
    )
    app = _AccountHost()
    async with app.run_test(size=(100, 30)) as pilot:
        origin = app.screen
        screen = RelayStatusScreen()
        await app.push_screen(screen)
        await wait_until(entered.is_set)
        read = next(worker for worker in app.workers if worker.name == "relay_modal_backend")
        assert read.node is screen
        if close_with == "close":
            assert await pilot.click("#btn_relay_close")
        else:
            await pilot.press("escape")
        await wait_until(lambda: (
            app.screen is origin and finished.is_set()
            and not any(worker.node is screen for worker in app.workers)
        ))
        assert cancelled.is_set()
        assert not any(worker.node is screen for worker in app.workers)
        release.set()
        await pilot.pause()
        assert app.screen is origin and app.is_running


@pytest.mark.asyncio
async def test_relay_closed_during_mount_cannot_leave_an_orphan_read(monkeypatch) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    entered, cancelled, release = (asyncio.Event() for _ in range(3))

    async def status():
        entered.set()
        try:
            await release.wait()
            return json.dumps({"connected": True})
        except asyncio.CancelledError:
            cancelled.set()
            raise

    monkeypatch.setattr(
        "servonaut.widgets.relay_indicator._build_mcp_tools_for_this_app",
        lambda app: SimpleNamespace(relay_status=status),
    )
    app = _AccountHost()
    async with app.run_test(size=(100, 30)) as pilot:
        origin = app.screen
        screen = RelayStatusScreen()
        original_refresh = screen._refresh_local

        def close_while_mounting():
            original_refresh()
            screen.action_back()

        monkeypatch.setattr(screen, "_refresh_local", close_while_mounting)
        await app.push_screen(screen)
        await wait_until(lambda: (
            app.screen is origin and not screen.is_attached
            and not any(worker.node is screen for worker in app.workers)
        ))
        await pilot.pause()
        assert not any(worker.node is screen for worker in app.workers)
        assert not entered.is_set() or cancelled.is_set()
        release.set()
        await pilot.pause()
        assert app.screen is origin and app.is_running


@pytest.mark.asyncio
async def test_backend_completion_during_child_teardown_cannot_publish(monkeypatch) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    entered, release, finished = (asyncio.Event() for _ in range(3))

    async def status():
        entered.set()
        try:
            await release.wait()
            return json.dumps({"connected": True})
        finally:
            finished.set()

    def release_during_child_unmount(widget):
        if widget.id == "backend_status":
            # The callback runs after this child detaches, while ancestor
            # teardown still precedes cancellation of the screen's workers.
            asyncio.get_running_loop().call_soon(release.set)

    async def keep_parent_unmount_open(widget):
        if widget.id in {"relay_backend_area", "relay_card"}:
            await wait_until(finished.is_set)

    monkeypatch.setattr(Static, "on_unmount", release_during_child_unmount, raising=False)
    monkeypatch.setattr(Container, "on_unmount", keep_parent_unmount_open, raising=False)
    monkeypatch.setattr(
        "servonaut.widgets.relay_indicator._build_mcp_tools_for_this_app",
        lambda app: SimpleNamespace(relay_status=status),
    )
    app = _AccountHost()
    async with app.run_test(size=(100, 30)) as pilot:
        origin = app.screen
        screen = RelayStatusScreen()
        await app.push_screen(screen)
        await wait_until(entered.is_set)
        backend = screen.query_one("#backend_status", Static)
        original = backend.content
        screen.action_back()
        await wait_until(lambda: (
            app.screen is origin and finished.is_set() and not screen.is_attached
        ))
        assert backend.content == original
        assert not any(worker.node is screen for worker in app.workers)
        assert app.is_running and app._exception is None


@pytest.mark.asyncio
async def test_relay_read_can_start_under_a_temporary_command_palette(monkeypatch) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    entered, release = (asyncio.Event() for _ in range(2))

    async def status():
        entered.set()
        await release.wait()
        return json.dumps({"connected": True})

    monkeypatch.setattr(
        "servonaut.widgets.relay_indicator._build_mcp_tools_for_this_app",
        lambda app: SimpleNamespace(relay_status=status),
    )
    app = _AccountHost()
    async with app.run_test(size=(100, 30)) as pilot:
        screen = RelayStatusScreen()
        original_refresh = screen._refresh_local

        def cover_while_mounting():
            original_refresh()
            app.action_command_palette()

        monkeypatch.setattr(screen, "_refresh_local", cover_while_mounting)
        await app.push_screen(screen)
        await wait_until(lambda: isinstance(app.screen, CommandPalette) and entered.is_set())
        assert screen in app.screen_stack
        release.set()
        await wait_until(lambda: "connected" in str(screen.query_one("#backend_status", Static).content))
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen)
        assert not screen.query_one("#relay_backend_busy", BusyIndicator).is_active
        assert app.is_running and app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("demo", [False, True])
async def test_backend_client_ids_are_literal_and_keep_demo_redaction(demo, monkeypatch) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    client = "[$text-error]peer[/$text-error]["
    status = AsyncMock(return_value=json.dumps({"connected": True, "client_ids": [client]}))
    monkeypatch.setattr(
        "servonaut.widgets.relay_indicator._build_mcp_tools_for_this_app",
        lambda app: SimpleNamespace(relay_status=status),
    )
    app = _AccountHost()
    app.demo_mode = demo
    app.redaction_service = RedactionService() if demo else None
    expected = app.redaction_service.redact_name(client) if demo else client
    async with app.run_test(size=(100, 30)) as pilot:
        screen = RelayStatusScreen()
        await app.push_screen(screen)
        backend = screen.query_one("#backend_status", Static)
        await wait_until(lambda: "listening:" in str(backend.content))
        await pilot.pause()
        assert f"listening: {expected}" in _plain(backend.content)
        assert expected.replace(" ", "") in _painted(app, backend).replace("\n", "").replace(" ", "")
        if demo:
            assert client not in _plain(backend.content)
        assert app._exception is None
