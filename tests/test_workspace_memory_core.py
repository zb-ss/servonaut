"""Native memory workspaces preserve their content and per-screen chat state."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from textual import events
from textual.pilot import Pilot
from textual.widgets import Button, DataTable, Input, Static, TextArea

from servonaut.config.schema import AppConfig, MemoryConfig
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.memory import MemoryScreen, SimpleConfirmModal
from servonaut.screens.memory_export import MemoryExportScreen
from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.upsell_modal import UpsellModal
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import (
    BoundarySample, ReflowCase, assert_button_label_painted, assert_essential_targets,
    assert_layout, content, one_layout_transition, open_case, open_chat, preserve_native_state,
)
from tests.test_fleet_workspace_layout import _open_chat
from tests.test_memory_dashboard_regressions import _memory_service, _module
from tests.test_memory_sync_ui import _AuthStub, _SetupSyncStub
from tests.test_workspace_pilot import _Host, _click
from tests.test_workspace_reflow import _painted


KINDS = ("memory-populated", "memory-empty", "export", "sync-configured", "sync-setup")


@pytest.fixture(autouse=True)
def _local_services_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    monkeypatch.setattr(
        "servonaut.services.memory.passphrase_store.keyring_available", lambda: True,
    )
    for name in ("get_passphrase", "store_passphrase", "clear_passphrase"):
        monkeypatch.setattr(f"servonaut.services.memory.passphrase_store.{name}", Mock())


class _MemoryWorkspaceApp(_Host):
    """Reuse the native workspace app and existing in-memory memory-service seams."""

    def __init__(self, kind: str, *, navigation_visible: bool = True) -> None:
        super().__init__(navigation_visible=navigation_visible)
        self.kind = kind
        self.memory_instance = {**self.instances[0], "provider": "custom"}
        module = _module("os")
        module["observed"] = {"version": "1.0", "service": "example"}
        self.modules = {} if kind == "memory-empty" else {"os": module}
        self.memory_service = _memory_service(self.modules)
        self.memory_service.list_all.return_value = []
        self.memory_service.clear.side_effect = self._clear_modules
        self.memory_service.refresh_all = AsyncMock(return_value=[])
        self.memory_service.refresh = AsyncMock(return_value=None)
        self.memory_service.pin = AsyncMock(return_value=None)
        self.memory_sync_service = _SetupSyncStub()
        if kind in ("memory-empty", "sync-setup"):
            self.memory_sync_service.is_configured = False
        self.auth_service = _AuthStub()
        self.auth_service.has_feature = lambda slug: slug in {
            "memory_sync", "memory_compliance_export", "memory_ai_summary",
        }
        self.ai_analysis_service = SimpleNamespace(
            available_memory_summary_providers=lambda: ["openai"],
        )
        self.ai_summary_service = SimpleNamespace()
        self.shared_memory_reader = None
        self.export_service = SimpleNamespace(
            export=AsyncMock(return_value="example-export.tar.gz"),
            verify_export=AsyncMock(return_value=True),
        )
        self.config = AppConfig(memory=MemoryConfig())
        self.config_manager = Mock()
        self.config_manager.get.return_value = self.config
        self.config_manager.update.side_effect = self._update_config

    def _update_config(self, **changes: object) -> None:
        for key, value in changes.items():
            setattr(self.config, key, value)

    def _clear_modules(self, instance_id: str, *, modules: list[str], provider: str) -> None:
        for module in modules:
            self.modules.pop(module, None)

    def on_mount(self, event: events.Mount) -> None:
        event.prevent_default()
        if self.kind.startswith("memory-"):
            screen = MemoryScreen(dict(self.memory_instance))
        elif self.kind == "export":
            screen = MemoryExportScreen()
        else:
            screen = MemorySyncSetupScreen()
        self.push_screen(screen)


def _state(screen: WorkspaceScreen) -> object:
    if isinstance(screen, MemoryScreen):
        table = screen.query_one("#memory-table", DataTable)
        return (
            table.cursor_row, table.row_count,
            screen.query_one("#memory-container").scroll_y,
            tuple(screen.query_one(f"#{name}").has_class("hidden") for name in (
                "memory-empty-state", "memory-cloud-banner", "memory-opt-out-banner",
                "memory-shared-source",
            )),
            tuple((button.id, button.disabled) for button in
                  screen.query_one("#memory-container").query(Button)),
            screen._has_local_memory,
        )
    if isinstance(screen, MemoryExportScreen):
        return (
            screen.query_one("#export-from-input", Input).value,
            screen.query_one("#export-to-input", Input).value,
            screen.query_one("#export-status", Static).content,
        )
    body = screen.query_one("#msync_body")
    return (tuple(body.children), tuple(
        (button.id, button.disabled) for button in body.query(Button)
    ))


def _seed(screen: WorkspaceScreen) -> None:
    if isinstance(screen, MemoryScreen):
        table = screen.query_one("#memory-table", DataTable)
        if table.row_count > 1:
            table.move_cursor(row=1)
    elif isinstance(screen, MemoryExportScreen):
        screen.query_one("#export-from-input", Input).value = "2024-01-01T00:00:00Z"
        screen.query_one("#export-to-input", Input).value = "2024-12-31T23:59:59Z"
        screen.query_one("#export-status", Static).update("Ready for export")


async def _active_screen(app: _MemoryWorkspaceApp, pilot: Pilot) -> WorkspaceScreen:
    return app.screen


async def _ready(screen: WorkspaceScreen) -> None:
    if isinstance(screen, MemoryScreen):
        await wait_until(lambda: bool(screen.query("#memory-table")))
    elif isinstance(screen, MemorySyncSetupScreen):
        await wait_until(lambda: bool(screen.query_one("#msync_body").children))
    else:
        await wait_until(lambda: bool(screen.query("#export-from-input")))


# Qualified native columns and separately measured layout policy.
_MEASURED_BOUNDARIES = {
    'memory-populated': {
        ('chat-min', False): (
            BoundarySample((113, 50), 68, True, True),
            BoundarySample((115, 50), 69, False, True),
            BoundarySample((116, 50), 70, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((155, 50), 68, True, True),
            BoundarySample((156, 50), 69, True, True),
            BoundarySample((157, 50), 70, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((156, 50), 94, False, True),
            BoundarySample((158, 50), 95, False, True),
            BoundarySample((159, 50), 96, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((183, 50), 94, False, True),
            BoundarySample((184, 50), 95, False, False),
            BoundarySample((185, 50), 96, False, False),
        ),
    },
    'memory-empty': {
        ('chat-min', False): (
            BoundarySample((113, 50), 68, True, True),
            BoundarySample((115, 50), 69, False, True),
            BoundarySample((116, 50), 70, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((155, 50), 68, True, True),
            BoundarySample((156, 50), 69, True, True),
            BoundarySample((157, 50), 70, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((156, 50), 94, False, True),
            BoundarySample((158, 50), 95, False, True),
            BoundarySample((159, 50), 96, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((183, 50), 94, False, True),
            BoundarySample((184, 50), 95, False, False),
            BoundarySample((185, 50), 96, False, False),
        ),
    },
    'export': {
        ('chat-min', False): (
            BoundarySample((92, 50), 47, True, True),
            BoundarySample((93, 50), 48, False, True),
            BoundarySample((94, 50), 49, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((120, 50), 47, True, True),
            BoundarySample((121, 50), 48, True, True),
            BoundarySample((122, 50), 49, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((131, 50), 79, False, True),
            BoundarySample((133, 50), 80, False, True),
            BoundarySample((134, 50), 81, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((168, 50), 79, False, True),
            BoundarySample((169, 50), 80, False, False),
            BoundarySample((170, 50), 81, False, False),
        ),
    },
    'sync-configured': {
        ('chat-min', False): (
            BoundarySample((100, 50), 55, True, True),
            BoundarySample((101, 50), 56, False, True),
            BoundarySample((102, 50), 57, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((133, 50), 55, True, True),
            BoundarySample((135, 50), 56, False, True),
            BoundarySample((136, 50), 57, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((158, 50), 95, False, True),
            BoundarySample((160, 50), 96, False, False),
            BoundarySample((161, 50), 97, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((184, 50), 95, False, True),
            BoundarySample((185, 50), 96, False, False),
            BoundarySample((186, 50), 97, False, False),
        ),
    },
    'sync-setup': {
        ('chat-min', False): (
            BoundarySample((100, 50), 55, True, True),
            BoundarySample((101, 50), 56, False, True),
            BoundarySample((102, 50), 57, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((133, 50), 55, True, True),
            BoundarySample((135, 50), 56, False, True),
            BoundarySample((136, 50), 57, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((158, 50), 95, False, True),
            BoundarySample((160, 50), 96, False, False),
            BoundarySample((161, 50), 97, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((184, 50), 95, False, True),
            BoundarySample((185, 50), 96, False, False),
            BoundarySample((186, 50), 97, False, False),
        ),
    },
}


def memory_case(kind: str) -> ReflowCase:
    primary = {
        "memory-populated": "#memory-table", "memory-empty": "#btn_empty_probe",
        "export": "#export-scroll", "sync-configured": "#msync_body", "sync-setup": "#msync_body",
    }[kind]
    targets = {
        "memory-populated": (
            "#memory-table", "#btn_refresh_all", "#btn_refresh_module", "#btn_pin_key",
            "#btn_clear_module", "#btn_annotate", "#btn_view_summary", "#btn_export",
            "#btn_sync_now", "#btn_enhance_ai", "#btn_build_ai",
        ),
        "memory-empty": ("#btn_empty_probe",),
        "export": (
            "#export-from-input", "#export-to-input", "#btn-export-start", "#btn-export-back",
        ),
        "sync-configured": (
            "#msync_btn_sync_now", "#msync_btn_rotate", "#msync_btn_disable", "#msync_btn_remember",
        ),
        "sync-setup": ("#msync_btn_setup", "#msync_btn_learn"),
    }[kind]
    return ReflowCase(
        name=kind,
        app_factory=lambda visible: _MemoryWorkspaceApp(kind, navigation_visible=visible),
        open_screen=_active_screen, ready=_ready, primary_focus_selector=primary,
        essential_targets=targets, seed_state=_seed, state=_state, painted_targets=(),
        boundaries=_MEASURED_BOUNDARIES[kind],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("chat_state", ["closed", "open", "collapsed"])
async def test_memory_workspace_pane_combinations(
    kind: str, navigation_visible: bool, size: tuple[int, int], chat_state: str,
) -> None:
    case = memory_case(kind)
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=size) as pilot:
        screen = await open_case(case, app, pilot)
        initial = case.state(screen)
        if chat_state != "closed":
            panel = await open_chat(app, pilot, screen)
            if chat_state == "collapsed":
                await pilot.press("f2")
                await wait_until(lambda: panel._collapsed)
                await pilot.pause()
        assert_layout(app, screen)
        assert case.state(screen) == initial
        if screen.query_one(".workspace-content").display:
            await assert_essential_targets(case, app, pilot, screen)
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_memory_workspace_keeps_native_state_and_chat_identity(kind: str) -> None:
    case = memory_case(kind)
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await preserve_native_state(case, app, pilot, screen)
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("kind_of_boundary", ["chat-min", "content-narrow"])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_memory_workspace_uses_qualified_native_boundaries(
    kind: str, kind_of_boundary: str, navigation_visible: bool,
) -> None:
    case = memory_case(kind)
    # Fails closed until qualified native samples exist (boundaries=None).
    samples = case.boundary_samples(kind_of_boundary, navigation_visible)
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        baseline = case.state(screen)
        await open_chat(app, pilot, screen)
        threshold = (
            screen.CHAT_MIN_CONTENT_WIDTH if kind_of_boundary == "chat-min"
            else screen.CONTENT_NARROW_WIDTH
        )
        # Samples straddle the declared threshold by exactly one native cell.
        assert [sample.native_content_width for sample in samples] == [
            threshold - 1, threshold, threshold + 1,
        ]
        for sample in samples:
            with one_layout_transition(screen):
                await pilot.resize_terminal(*sample.size)
                await pilot.pause()
            assert screen.has_class("-chat-replace") is sample.expected_replace
            assert screen.has_class("-content-narrow") is sample.expected_content_narrow
            assert_layout(app, screen)
            if sample.expected_replace:
                # Counterfactual: force the columns the policy hides, measure
                # the native width, then restore and re-check the real flags.
                with patch.object(screen, "CHAT_MIN_CONTENT_WIDTH", 1):
                    screen.apply_workspace_state()
                    await pilot.pause()
                    assert content(screen).region.width == sample.native_content_width
                screen.apply_workspace_state()
                await pilot.pause()
                assert screen.has_class("-chat-replace") is sample.expected_replace
                assert screen.has_class("-content-narrow") is sample.expected_content_narrow
                assert not content(screen).display
            else:
                assert content(screen).region.width == sample.native_content_width
                if isinstance(screen, MemoryScreen):
                    assert case.state(screen) == baseline
                    entry_scroll = content(screen).scroll_y
                await assert_essential_targets(case, app, pilot, screen)
                if isinstance(screen, MemoryScreen):
                    # The visibility probe deliberately scrolls to each action.
                    content(screen).scroll_to(y=entry_scroll, animate=False, immediate=True)
                    await pilot.pause()
            assert case.state(screen) == baseline


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,keys", [("memory-populated", ("r", "c", "a", "p", "S")),
                                      ("sync-configured", ("r",))])
async def test_navigation_typing_does_not_start_memory_operations(
    kind: str, keys: tuple[str, ...], monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _MemoryWorkspaceApp(kind, navigation_visible=False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        actions = (
            ("refresh_all", "clear_module", "annotate", "pin_key", "sync_now")
            if kind.startswith("memory-") else ("refresh",)
        )
        callbacks = [Mock() for _ in actions]
        for name, callback in zip(actions, callbacks):
            monkeypatch.setattr(screen, f"action_{name}", callback)
        await pilot.press("shift+f6")
        await wait_until(lambda: screen.query_one(Sidebar).has_focus_within)
        for key in keys:
            await pilot.press(key)
        assert app.screen is screen
        for callback in callbacks:
            callback.assert_not_called()
        await pilot.press("escape")
        assert not screen.query_one(Sidebar).navigation_mode


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["chat", "navigation"])
async def test_empty_memory_origin_returns_to_table_after_population(route: str) -> None:
    app = _MemoryWorkspaceApp("memory-empty", navigation_visible=False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        origin = screen.query_one("#btn_empty_probe", Button)
        await wait_until(lambda: app.focused is origin)
        if route == "chat":
            await _open_chat(app, pilot)
        else:
            await pilot.press("shift+f6")
            await wait_until(lambda: screen.query_one(Sidebar).has_focus_within)
        parked = app.focused
        app.modules["os"] = _module("os")
        screen.refresh_memory_status()
        await pilot.pause()
        assert screen.query_one("#memory-empty-state").has_class("hidden")
        assert app.focused is parked
        await pilot.press("f2" if route == "chat" else "escape")
        await wait_until(lambda: app.focused is screen.query_one("#memory-table"))
        assert app.focused is not screen.query_one("#btn_open_memory_sync_setup")
        assert MemoryScreen.AUTO_FOCUS == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("confirm", [False, True])
async def test_clear_confirmation_keeps_table_context_and_chat_draft(confirm: bool) -> None:
    app = _MemoryWorkspaceApp("memory-populated", navigation_visible=False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        table = screen.query_one("#memory-table", DataTable)
        table.move_cursor(row=1)
        original_row, original_count = table.cursor_row, table.row_count
        panel = await _open_chat(app, pilot)
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Keep this draft while confirming")
        table.focus()
        await wait_until(lambda: app.focused is table)
        await pilot.press("c")
        await wait_until(lambda: isinstance(app.screen, SimpleConfirmModal))
        assert app.focused is app.screen.query_one("#confirm_no_btn", Button)
        await _click(pilot, "#confirm_yes_btn" if confirm else "#confirm_no_btn")
        await wait_until(lambda: app.screen is screen)
        assert screen.query_one(ChatPanel) is panel
        assert editor.text == "Keep this draft while confirming"
        if confirm:
            await wait_until(lambda: app.memory_service.clear.called)
            app.memory_service.clear.assert_called_once_with(
                app.memory_instance["id"], modules=["os"], provider="custom",
            )
            assert table.row_count == 0
            assert not screen.query_one("#memory-empty-state").has_class("hidden")
        else:
            await pilot.pause()
            app.memory_service.clear.assert_not_called()
            assert app.focused is table and table.row_count == original_count
            assert table.cursor_row == original_row


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_manual_memory_sync_survives_navigation_with_chat(size: tuple[int, int]) -> None:
    app = _MemoryWorkspaceApp("sync-configured", navigation_visible=False)
    sync = app.memory_sync_service
    async with app.run_test(size=size) as pilot:
        screen = app.screen
        panel = await _open_chat(app, pilot)
        panel.query_one("#chat-input", TextArea).load_text("Retain this screen's draft")
        await pilot.press("f2")
        await pilot.pause()
        button = screen.query_one("#msync_btn_sync_now", Button)
        button.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        await _click(pilot, "#msync_btn_sync_now")
        await wait_until(sync.second_batch_started.is_set)
        await pilot.press("f2")
        assert screen.query_one(ChatPanel) is panel
        await app.push_screen(InstanceListScreen())
        await pilot.pause()
        sync.release_second_batch.set()
        await wait_until(lambda: not getattr(app, "_memory_manual_sync_in_progress", False))
        assert sync.pending == 0 and sync.drain_calls == 3
        app.pop_screen()
        await pilot.pause()
        assert app.screen is screen and screen.query_one(ChatPanel) is panel
        assert panel.query_one("#chat-input", TextArea).text == "Retain this screen's draft"


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_export_upsell_keeps_date_values_and_returns_to_native_focus(
    size: tuple[int, int],
) -> None:
    app = _MemoryWorkspaceApp("export")
    app.auth_service.has_feature = lambda _slug: False
    async with app.run_test(size=size) as pilot:
        await wait_until(lambda: isinstance(app.screen, UpsellModal))
        export = next(
            screen for screen in app.screen_stack if isinstance(screen, MemoryExportScreen)
        )
        export.query_one("#export-from-input", Input).value = "2024-01-01"
        await pilot.press("escape")
        await wait_until(lambda: app.screen is export)
        assert export.query_one("#export-from-input", Input).value == "2024-01-01"
        assert app.focused is export.query_one("#export-scroll")
        await _click(pilot, "#workspace_navigation")
        await wait_until(lambda: not export.query_one(Sidebar).display)


@pytest.mark.asyncio
@pytest.mark.parametrize("module_name", ["module[/b]name", "[bold]module[/bold]"])
async def test_clear_prompt_escapes_selected_module_without_changing_raw_target(
    module_name: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _MemoryWorkspaceApp("memory-populated", navigation_visible=False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        monkeypatch.setattr(screen, "_get_cursor_module_key", lambda: (module_name, "version"))
        screen.query_one("#memory-table", DataTable).focus()
        await pilot.press("c")
        await wait_until(lambda: isinstance(app.screen, SimpleConfirmModal))
        message = app.screen.query_one("#confirm_message", Static)
        assert message.render().plain == f"Clear module {module_name}?"
        assert module_name in _painted(app, message)
        await _click(pilot, "#confirm_yes_btn")
        await wait_until(lambda: app.screen is screen)
        await wait_until(lambda: app.memory_service.clear.called)
        app.memory_service.clear.assert_called_once_with(
            app.memory_instance["id"], modules=[module_name], provider="custom",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light", "ansi-dark", "ansi-light"])
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("kind,width", [("memory-populated", 95), ("memory-populated", 96),
                                       ("memory-populated", 99), ("sync-configured", 71),
                                       ("sync-configured", 75), ("sync-configured", 104)])
async def test_memory_action_rows_paint_inside_their_actual_content_width(
    theme: str, navigation_visible: bool, kind: str, width: int,
) -> None:
    app = _MemoryWorkspaceApp(kind, navigation_visible=navigation_visible)
    app.theme = theme
    async with app.run_test(size=(width + (25 if navigation_visible else 0), 50)) as pilot:
        screen = app.screen
        body = screen.query_one(
            "#memory-container" if kind.startswith("memory-") else "#msync_container",
        )
        assert body.region.width == width
        targets = (
            ("btn_refresh_all", "btn_refresh_module", "btn_pin_key", "btn_clear_module", "btn_annotate")
            if kind.startswith("memory-") else
            ("msync_btn_sync_now", "msync_btn_rotate", "msync_btn_disable", "msync_btn_remember")
        )
        for name in targets:
            button = screen.query_one(f"#{name}", Button)
            button.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            assert body.region.x <= button.region.x < button.region.right <= body.region.right
            assert app.get_widget_at(*button.region.center)[0] is button
            assert body.scrollable_content_region.contains_region(button.region)
            assert screen.find_widget(button).clip.contains_region(button.region)
            assert_button_label_painted(app, button)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_rotate_prompts_keep_chat_draft_and_restore_busy_controls(
    size: tuple[int, int],
) -> None:
    import asyncio
    from servonaut.screens.memory_keys import PassphraseEnrolModal

    app = _MemoryWorkspaceApp("sync-configured", navigation_visible=False)
    app.config.memory.sync_remember_device = True
    entered, release = asyncio.Event(), asyncio.Event()

    async def rotate(old: str, new: str) -> None:
        entered.set()
        await release.wait()

    app.memory_sync_service.rotate_keypair = AsyncMock(side_effect=rotate)

    def _prompt_ready(mode: str, previous: object | None = None) -> bool:
        modal = app.screen
        if (not isinstance(modal, PassphraseEnrolModal) or modal is previous
                or modal._mode != mode or not modal.is_mounted):
            return False
        required = [("#enrol-pass1", Input), ("#enrol-btn-confirm", Button)]
        if mode == "enrol":
            required.append(("#enrol-pass2", Input))
        for selector, expected_type in required:
            children = list(modal.query(selector))
            if (len(children) != 1 or not isinstance(children[0], expected_type)
                    or not children[0].is_mounted):
                return False
        return True

    async with app.run_test(size=size) as pilot:
        screen = app.screen
        await _ready(screen)
        body = screen.query_one("#msync_body")
        original_cards = tuple(body.children)
        assert original_cards
        panel = await _open_chat(app, pilot)
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Keep this draft while rotating")
        await pilot.press("f2")
        await pilot.pause()
        origin = screen.query_one("#msync_btn_rotate", Button)
        origin.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        origin.focus()
        await _click(pilot, "#msync_btn_rotate")
        await wait_until(lambda: _prompt_ready("unlock"))
        unlock_prompt = app.screen
        old = "example old passphrase 2026"
        new = "example new passphrase 2026"
        app.screen.query_one("#enrol-pass1", Input).value = old
        confirm = app.screen.query_one("#enrol-btn-confirm", Button)
        # Wait for validation and layout before Pilot captures mouse coordinates.
        await wait_until(lambda: not confirm.disabled)
        await pilot.pause()
        assert confirm.is_mounted and confirm.region.width > 0 and confirm.region.height > 0
        assert app.get_widget_at(*confirm.region.center)[0] is confirm
        await _click(pilot, "#enrol-btn-confirm")
        await wait_until(lambda: _prompt_ready("enrol", unlock_prompt))
        app.screen.query_one("#enrol-pass1", Input).value = new
        app.screen.query_one("#enrol-pass2", Input).value = new
        confirm = app.screen.query_one("#enrol-btn-confirm", Button)
        await wait_until(lambda: not confirm.disabled)
        await pilot.pause()
        assert confirm.is_mounted and confirm.region.width > 0 and confirm.region.height > 0
        assert app.get_widget_at(*confirm.region.center)[0] is confirm
        await _click(pilot, "#enrol-btn-confirm")
        try:
            await wait_until(entered.is_set)
            assert app.screen is screen
            actions = list(screen.query(".msync_card_actions Button"))
            assert actions and all(button.disabled for button in actions)
            assert screen.query_one(ChatPanel) is panel
            assert editor.text == "Keep this draft while rotating"
        finally:
            release.set()
        await wait_until(lambda: bool(body.children)
                         and tuple(body.children) != original_cards
                         and all(not card.is_attached for card in original_cards))
        await wait_until(lambda: bool(screen.query(".msync_card_actions Button")) and all(
            not button.disabled for button in screen.query(".msync_card_actions Button")
        ))
        app.memory_sync_service.rotate_keypair.assert_awaited_once_with(old, new)
        app.config_manager.update.assert_called_once()
        updated_memory = app.config_manager.update.call_args.kwargs["memory"]
        assert isinstance(updated_memory, MemoryConfig)
        assert not updated_memory.sync_remember_device
        assert not app.config_manager.get().memory.sync_remember_device
        assert editor.text == "Keep this draft while rotating"
