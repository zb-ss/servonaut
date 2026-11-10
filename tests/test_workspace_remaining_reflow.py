"""Native workspace consumers retain their content, focus and service boundaries."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from textual.pilot import Pilot
from textual.widgets import Button, DataTable, Input, Markdown, Static, TextArea
from textual.widgets.text_area import Selection

from servonaut.app import ServonautApp
from servonaut.config.schema import AIProviderConfig, AppConfig
from servonaut.screens.ai_analysis import AIAnalysisScreen
from servonaut.screens.ai_conversations_screen import AIConversationsScreen, _ConfirmModal
from servonaut.screens.help import HelpScreen, build_help_text
from servonaut.screens.main_menu import MainMenuScreen
from servonaut.services.chat_service import ChatSession
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.progress_indicator import ProgressIndicator
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import (
    BoundarySample, ReflowCase, assert_controls, assert_essential_targets, assert_layout,
    collapse_chat, content, open_case, open_chat, preserve_native_state, tab_to,
)
from tests.test_fleet_workspace_layout import _LayoutHost
from tests.test_selection_copy import _Clipboard, _drag
from tests.test_selection_copy import clipboard as clipboard
from tests.test_workspace_pilot import _click
from tests.test_workspace_reflow import _painted

pytestmark = pytest.mark.usefixtures("navigation_open")


TITLE = "Disk café [literal] Ω"
INPUT = "first café\nsecond Ω"
OUTPUT = "  café [literal]\nline two Ω  "
_SERVICE_VIOLATIONS: list[str] = []


def _refuse_service(operation: str) -> None:
    _SERVICE_VIOLATIONS.append(operation)
    raise AssertionError("Unexpected service operation: " + operation)


def _summary() -> SimpleNamespace:
    return SimpleNamespace(
        id="conversation-one", title=TITLE, status="active", message_count=2,
        created_at="2026-01-01T00:00:00Z", updated_at="2026-01-01T00:00:00Z",
        last_model="example-model",
    )


class _RemainingHost(_LayoutHost):
    """Keep the accepted native app host; service results are inert fixtures."""

    def __init__(self, navigation_visible: bool = True) -> None:
        super().__init__(navigation_visible=navigation_visible)
        config = AppConfig(ai_provider=AIProviderConfig(provider="ollama"))

        def update_config(**changes: object) -> None:
            nonlocal config
            config = replace(config, **changes)

        self.config_manager = SimpleNamespace(get=lambda: config, update=update_config)
        self.auth_service = SimpleNamespace(
            is_authenticated=False, has_feature=lambda feature: False,
        )
        self.ai_conversations_client = SimpleNamespace(
            list=AsyncMock(return_value=[_summary()]),
            patch=AsyncMock(return_value={}), delete=AsyncMock(return_value=None),
            export_md=AsyncMock(return_value="fixture.md"),
        )
        self.chat_service = SimpleNamespace(
            list_sessions=Mock(return_value=[{
                "id": "session-one", "title": TITLE, "message_count": 2,
                "updated_at": "2026-01-01T00:00:00Z", "last_provider": "Example",
                "remote_conversation_id": None,
            }]),
            delete_session=Mock(return_value=True),
        )
        self.ai_analysis_service = SimpleNamespace(
            estimate_tokens=lambda text: len(text.split()),
            chunk_text=lambda text: [text],
            analyze_text=AsyncMock(side_effect=lambda *args, **kwargs: _refuse_service("analysis")),
        )
        self.update_service = SimpleNamespace(
            check_for_update=Mock(return_value=None), current_version="0.0.0",
            run_upgrade=AsyncMock(side_effect=lambda *args, **kwargs: _refuse_service("upgrade")),
        )
        self.scan_service = SimpleNamespace(
            scan_server=AsyncMock(side_effect=lambda *args, **kwargs: _refuse_service("scan")),
        )
        self.aws_service = SimpleNamespace(
            fetch_instances_cached=AsyncMock(
                side_effect=lambda *args, **kwargs: _refuse_service("provider"),
            ),
        )
        self.theme = "servonaut"


@pytest.fixture(autouse=True)
def _no_external_services(monkeypatch: pytest.MonkeyPatch, clipboard: _Clipboard) -> Iterator[None]:
    # The shared suite isolates HOME before importing the product.
    _SERVICE_VIOLATIONS.clear()
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    ssh = AsyncMock(side_effect=AssertionError("Unexpected remote operation"))
    secret = Mock(side_effect=AssertionError("Unexpected secret lookup"))
    connection = AsyncMock(side_effect=AssertionError("Unexpected network"))
    process = Mock(side_effect=AssertionError("Unexpected subprocess"))
    keyring = Mock(side_effect=AssertionError("Unexpected keyring operation"))
    monkeypatch.setattr("servonaut.screens.ai_analysis.run_ssh_subprocess", ssh)
    monkeypatch.setattr("servonaut.screens.ai_analysis.resolve_secret", secret)
    monkeypatch.setattr(asyncio.BaseEventLoop, "create_connection", connection)
    monkeypatch.setattr("subprocess.Popen", process)
    for name in ("get_password", "set_password", "delete_password"):
        monkeypatch.setattr("keyring." + name, keyring)
    yield
    ssh.assert_not_awaited()
    secret.assert_not_called()
    connection.assert_not_awaited()
    process.assert_not_called()
    keyring.assert_not_called()
    assert not _SERVICE_VIOLATIONS


PRIMARY = {
    "help": "#help_container", "analysis": "#ai_text_input",
    "dashboard": "#card_list", "history": "#local_filter",
}


def _opener(kind: str) -> Callable[[ServonautApp, Pilot], Awaitable[WorkspaceScreen]]:
    async def open_screen(app: ServonautApp, pilot: Pilot) -> WorkspaceScreen:
        factories = {
            "help": HelpScreen, "analysis": lambda: AIAnalysisScreen(text=INPUT),
            "dashboard": MainMenuScreen, "history": AIConversationsScreen,
        }
        screen = factories[kind]()
        await app.push_screen(screen)
        await _ready(screen)
        await pilot.pause()
        if kind == "dashboard":
            # This initial focus is explicitly owned by the existing mount handler.
            assert app.focused is screen.query_one("#card_list")
        else:
            # A deliberate journey precondition, not a guessed native initial focus.
            screen.query_one(PRIMARY[kind]).focus()
            await pilot.pause()
        return screen
    return open_screen


async def _ready(screen: WorkspaceScreen) -> None:
    if isinstance(screen, HelpScreen):
        await wait_until(lambda: bool(screen.query_one(Markdown).children))
    elif isinstance(screen, AIConversationsScreen):
        await wait_until(lambda: not screen._loading and screen.query_one("#convs_table", DataTable).row_count == 1)
        await wait_until(lambda: screen.query_one("#local_table", DataTable).row_count == 1)
    elif isinstance(screen, MainMenuScreen):
        await wait_until(lambda: screen.query_one("#stat-total", Static).render().plain == "2\nTotal Servers")


def _seed(screen: WorkspaceScreen) -> None:
    if isinstance(screen, AIAnalysisScreen):
        source = screen.query_one("#ai_text_input", TextArea)
        source.selection = Selection((0, 2), (1, 3))
        screen.query_one("#ai_user_prompt", Input).value = "Keep [literal] Ω"
        screen.query_one("#ai_output", TextArea).load_text(OUTPUT)
        screen._output_text = OUTPUT
    elif isinstance(screen, AIConversationsScreen):
        screen.query_one("#local_table", DataTable).move_cursor(row=0)
        screen.query_one("#local_filter", Input).value = "Disk"


def _state(screen: WorkspaceScreen) -> object:
    if isinstance(screen, HelpScreen):
        document = screen.query_one(Markdown)
        return document, document.source
    if isinstance(screen, AIAnalysisScreen):
        source = screen.query_one("#ai_text_input", TextArea)
        output = screen.query_one("#ai_output", TextArea)
        return (source, source.document, source.text, source.selection,
                output, output.document, output.text,
                screen.query_one("#ai_user_prompt", Input).value, screen._output_text)
    if isinstance(screen, MainMenuScreen):
        return tuple((node, node.render().plain) for node in screen.query(".stat-card"))
    table = screen.query_one("#local_table", DataTable)
    return (screen._active_tab, screen._local_filter, screen._local_offset,
            table, table.cursor_row, tuple(screen._local_sessions))


# Native boundary samples are deliberately absent until qualified measurements.
# Qualified native columns and separately measured layout policy.
_MEASURED_BOUNDARIES = {
    'help': {
        ('chat-min', False): (
            BoundarySample((84, 50), 39, True, True),
            BoundarySample((85, 50), 40, False, True),
            BoundarySample((86, 50), 41, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((109, 50), 39, True, True),
            BoundarySample((110, 50), 40, False, True),
            BoundarySample((111, 50), 41, False, True),
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
    'analysis': {
        ('chat-min', False): (
            BoundarySample((108, 50), 63, True, True),
            BoundarySample((109, 50), 64, False, True),
            BoundarySample((110, 50), 65, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((146, 50), 63, True, True),
            BoundarySample((148, 50), 64, True, True),
            BoundarySample((149, 50), 65, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((148, 50), 89, False, True),
            BoundarySample((150, 50), 90, False, False),
            BoundarySample((151, 50), 91, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((178, 50), 89, False, True),
            BoundarySample((179, 50), 90, False, False),
            BoundarySample((180, 50), 91, False, False),
        ),
    },
    'dashboard': {
        ('chat-min', False): (
            BoundarySample((125, 50), 75, True, True),
            BoundarySample((126, 50), 76, True, True),
            BoundarySample((127, 50), 77, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((164, 50), 75, True, True),
            BoundarySample((165, 50), 76, False, True),
            BoundarySample((166, 50), 77, False, True),
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
    'history': {
        ('chat-min', False): (
            BoundarySample((155, 50), 93, True, True),
            BoundarySample((156, 50), 94, True, True),
            BoundarySample((157, 50), 95, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((182, 50), 93, True, True),
            BoundarySample((183, 50), 94, False, True),
            BoundarySample((184, 50), 95, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((173, 50), 109, False, True),
            BoundarySample((174, 50), 110, False, False),
            BoundarySample((175, 50), 111, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((198, 50), 109, False, True),
            BoundarySample((199, 50), 110, False, False),
            BoundarySample((200, 50), 111, False, False),
        ),
    },
}


CASES = (
    ReflowCase("help", _RemainingHost, _opener("help"), _ready,
               PRIMARY["help"], ("#help_container",), _seed, _state, (), boundaries=_MEASURED_BOUNDARIES['help']),
    ReflowCase("analysis", _RemainingHost, _opener("analysis"), _ready,
               PRIMARY["analysis"], ("#ai_text_input", "#ai_filter_input", "#btn_filter_apply",
               "#btn_filter_clear", "#ai_user_prompt", "#btn_analyze", "#ai_output", "#btn_back"),
               _seed, _state, (("#ai_text_input", "first café"),), boundaries=_MEASURED_BOUNDARIES['analysis']),
    ReflowCase("dashboard", _RemainingHost, _opener("dashboard"), _ready,
               PRIMARY["dashboard"], tuple("#" + name for name in (
                   "card_list", "card_custom_servers", "card_cloudwatch",
                   "card_ip_ban", "card_cloudtrail", "card_scan")),
               _seed, _state, (), boundaries=_MEASURED_BOUNDARIES['dashboard']),
    ReflowCase("history", _RemainingHost, _opener("history"), _ready,
               PRIMARY["history"], ("#local_filter", "#local_table", "#btn_local_open",
               "#btn_local_delete", "#btn_local_more", "#btn_local_refresh"),
               _seed, _state, (("#local_table", TITLE),), boundaries=_MEASURED_BOUNDARIES['history']),
)
IDS = [case.name for case in CASES]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=IDS)
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("navigation_visible,chat_open", [
    (False, False), (False, True), (True, False), (True, True),
])
async def test_remaining_workspace_four_visibility_states(
    case: ReflowCase, size: tuple[int, int], navigation_visible: bool, chat_open: bool,
) -> None:
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=size) as pilot:
        screen = await open_case(case, app, pilot)
        baseline = case.state(screen)
        if chat_open:
            await open_chat(app, pilot, screen)
        assert_layout(app, screen)
        assert screen.query_one(Sidebar).display is navigation_visible
        assert case.state(screen) == baseline
        if content(screen).display:
            await assert_essential_targets(case, app, pilot, screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=IDS)
async def test_remaining_native_draft_selection_state_and_tab_journey(case: ReflowCase) -> None:
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await preserve_native_state(case, app, pilot, screen)
        if isinstance(screen, HelpScreen):
            assert screen.query_one(Markdown).source == build_help_text()


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=IDS)
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("kind", ["chat-min", "content-narrow"])
async def test_remaining_qualified_native_boundaries(
    case: ReflowCase, navigation_visible: bool, kind: str,
) -> None:
    samples = case.boundary_samples(kind, navigation_visible)
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=samples[0].size) as pilot:
        screen = await open_case(case, app, pilot)
        baseline = case.state(screen)
        await open_chat(app, pilot, screen)
        threshold = screen.CHAT_MIN_CONTENT_WIDTH if kind == "chat-min" else screen.CONTENT_NARROW_WIDTH
        assert [sample.native_content_width for sample in samples] == [threshold - 1, threshold, threshold + 1]
        for sample in samples:
            await pilot.resize_terminal(*sample.size)
            await pilot.pause()
            assert screen.has_class("-chat-replace") is sample.expected_replace
            assert screen.has_class("-content-narrow") is sample.expected_content_narrow
            assert_layout(app, screen)
            if sample.expected_replace:
                # Width-only counterfactual; hidden content need not be usable.
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
                await assert_essential_targets(case, app, pilot, screen)
            assert case.state(screen) == baseline


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=IDS)
async def test_remaining_modal_barrier_returns_visible_content_or_chat(case: ReflowCase) -> None:
    app = case.app_factory(True)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await open_case(case, app, pilot)
        panel = await open_chat(app, pilot, screen)
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Keep Ω draft")
        modal = _ConfirmModal("Review", "No operation is connected.")
        results: list[bool] = []
        await app.push_screen(modal, results.append)
        await wait_until(lambda: app.focused is modal.query_one("#btn_no"))
        app.workspace_state.navigation_visible = False
        await pilot.press("shift+f6", "f2", "ctrl+g")
        assert app.screen is modal and app.focused is modal.query_one("#btn_no")
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen)
        assert results == [False] and not screen.query_one(Sidebar).display
        await pilot.pause()
        assert app.focused is not None and app.focused.region
        assert app.focused.visible and editor.text == "Keep Ω draft"
        if not content(screen).display:
            assert app.focused is editor
        assert_controls(app, screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("writer_succeeds", [True, False])
async def test_analysis_output_native_gesture_after_replacement_is_literal_once(
    clipboard: _Clipboard, writer_succeeds: bool,
) -> None:
    clipboard.succeeds = writer_succeeds
    app = _RemainingHost(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(CASES[1], app, pilot)
        await open_chat(app, pilot, screen)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        await collapse_chat(app, pilot, screen)
        output = screen.query_one("#ai_output", TextArea)
        output.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        await _drag(pilot, output, (0, 0), (len("line two Ω  "), 1))
        assert output.selected_text == OUTPUT and clipboard.calls == [OUTPUT]
        if not writer_succeeds:
            assert app.clipboard == OUTPUT


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [False, True])
async def test_conversations_native_loading_and_error_finish_without_losing_local_state(
    failure: bool,
) -> None:
    app = _RemainingHost()
    started, release = asyncio.Event(), asyncio.Event()

    async def load(**kwargs: object) -> list[SimpleNamespace]:
        started.set()
        await release.wait()
        if failure:
            raise RuntimeError("[literal] load failure")
        return [_summary()]

    app.ai_conversations_client.list.side_effect = load
    async with app.run_test(size=(100, 30)) as pilot:
        screen = AIConversationsScreen()
        await app.push_screen(screen)
        try:
            await wait_until(started.is_set)
            progress = screen.query_one(ProgressIndicator)
            assert screen._loading and progress._active
            assert screen.query_one("#local_table", DataTable).row_count == 1
            await pilot.press("f2")
            await pilot.pause()
            assert_layout(app, screen)
        finally:
            release.set()
        await wait_until(lambda: not screen._loading and not progress._active)
        assert screen.query_one("#local_table", DataTable).row_count == 1
        cloud = screen.query_one("#convs_table", DataTable)
        if failure:
            assert cloud.row_count == 0
            assert "[literal] load failure" in screen.query_one("#convs_status", Static).render().plain
        else:
            assert cloud.row_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("via", ["pointer", "keyboard"])
async def test_dashboard_preserves_real_card_route_and_original_explicit_focus(via: str) -> None:
    app = _RemainingHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = MainMenuScreen()
        await app.push_screen(screen)
        await pilot.pause()
        assert app.focused is screen.query_one("#card_list")
        if via == "pointer":
            await _click(pilot, "#card_list")
        else:
            await pilot.press("1")
        await wait_until(lambda: app.screen is not screen)
        assert app.screen.__class__.__name__ == "InstanceListScreen"
        app.update_service.run_upgrade.assert_not_awaited()
        app.scan_service.scan_server.assert_not_awaited()
        app.aws_service.fetch_instances_cached.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("case,theme", [
    (CASES[0], "servonaut-light"), (CASES[1], "ansi-light"),
    (CASES[2], "ansi-dark"), (CASES[3], "servonaut"),
], ids=["help-light", "analysis-ansi-light", "dashboard-ansi-dark", "history-dark"])
async def test_remaining_representative_palette_native_fit(case: ReflowCase, theme: str) -> None:
    app = case.app_factory(True)
    app.theme = theme
    assert app.config_manager.get().theme == theme
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await assert_essential_targets(case, app, pilot, screen)
        assert_layout(app, screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("tab", ["cloud", "local"])
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_history_both_tabs_keep_every_action_painted_and_hittable(
    tab: str, size: tuple[int, int], navigation_visible: bool,
) -> None:
    app = _RemainingHost(navigation_visible)
    async with app.run_test(size=size) as pilot:
        screen = await _opener("history")(app, pilot)
        assert await pilot.click(f"#--content-tab-tab_{tab}")
        await wait_until(lambda: screen._active_tab == f"tab_{tab}")
        field = screen.query_one("#convs_filter" if tab == "cloud" else "#local_filter")
        await tab_to(pilot, field)
        assert app.focused is field
        prefix = "convs" if tab == "cloud" else "local"
        names = ("open", "archive", "delete", "export", "more", "refresh") if tab == "cloud" else ("open", "delete", "more", "refresh")
        for name in names:
            button = screen.query_one(f"#btn_{prefix}_{name}", Button)
            button.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            assert content(screen).region.contains_region(button.region)
            assert screen.region.contains_region(button.region)
            assert app.get_widget_at(*button.region.center)[0] is button
            assert button.label.plain in _painted(app, button)
        await pilot.press("f2")
        await pilot.pause()
        assert_layout(app, screen)
        await collapse_chat(app, pilot, screen)
        assert screen._active_tab == f"tab_{tab}" and app.focused is field


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [False, True])
async def test_analysis_native_completion_and_failure_release_busy_controls(failure: bool) -> None:
    app = _RemainingHost(False)
    started, release = asyncio.Event(), asyncio.Event()

    async def analyze(text: str, *, system_prompt: str) -> dict[str, object]:
        assert text == INPUT and system_prompt == "Keep [literal] Ω"
        started.set()
        await release.wait()
        if failure:
            raise RuntimeError("fixture analysis failure")
        return {"content": OUTPUT, "model": "example-model", "estimated_cost": 0}

    app.ai_analysis_service.analyze_text.side_effect = analyze
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(CASES[1], app, pilot)
        try:
            await pilot.press("f5")
            await wait_until(started.is_set)
            assert screen.query_one("#btn_analyze", Button).disabled
            assert screen.query_one(ProgressIndicator)._active
            await pilot.press("f2")
            await pilot.pause()
            assert_layout(app, screen)
        finally:
            release.set()
        await wait_until(lambda: not screen.query_one("#btn_analyze", Button).disabled)
        assert not screen.query_one(ProgressIndicator)._active
        app.ai_analysis_service.analyze_text.assert_awaited_once_with(INPUT, system_prompt="Keep [literal] Ω")
        if failure:
            assert "fixture analysis failure" in screen.query_one("#ai_status", Static).render().plain
        else:
            assert screen.query_one("#ai_output", TextArea).text == OUTPUT
            assert screen._output_text == OUTPUT


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["q", "escape"])
async def test_global_help_route_and_close_preserve_origin_chat_draft(key: str) -> None:
    app = _RemainingHost(False)
    async with app.run_test(size=(160, 50)) as pilot:
        origin = app.screen
        panel = await open_chat(app, pilot, origin)
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Origin café Ω")
        document = editor.document
        app.action_show_help()
        # The route pushes synchronously; its widgets mount asynchronously.
        await wait_until(lambda: (
            isinstance(app.screen, HelpScreen)
            and app.screen.is_mounted
            and bool(app.screen.query(Markdown))
        ))
        await _ready(app.screen)
        await pilot.press(key)
        await wait_until(lambda: app.screen is origin)
        assert origin.query_one(ChatPanel) is panel
        assert editor.document is document and editor.text == "Origin café Ω"


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["help", "analysis", "dashboard", "history"])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_remaining_native_initial_focus_is_visible_without_navigation_mode(
    kind: str, navigation_visible: bool,
) -> None:
    app = _RemainingHost(navigation_visible)
    factories = {
        "help": HelpScreen, "analysis": lambda: AIAnalysisScreen(text=INPUT),
        "dashboard": MainMenuScreen, "history": AIConversationsScreen,
    }
    async with app.run_test(size=(160, 50)) as pilot:
        screen = factories[kind]()
        await app.push_screen(screen)
        await _ready(screen)
        await pilot.pause()
        focused = app.focused
        assert focused is not None and focused.screen is screen
        assert focused.region and screen.region.contains(*focused.region.center)
        assert focused.visible and not screen.query_one(Sidebar).navigation_mode
        if kind == "dashboard":
            assert focused is screen.query_one("#card_list")
        # Exact first-widget comparison for the other native consumers is an
        # original-source qualification obligation, not a guessed selector.


@pytest.mark.asyncio
async def test_popping_history_cancels_only_its_held_loading_worker() -> None:
    app = _RemainingHost()
    started, cancelled, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def load(**kwargs: object) -> list[SimpleNamespace]:
        started.set()
        try:
            await release.wait()
            return []
        finally:
            cancelled.set()

    app.ai_conversations_client.list.side_effect = load
    async with app.run_test(size=(100, 30)) as pilot:
        origin = app.screen
        await app.push_screen(AIConversationsScreen())
        history = app.screen
        try:
            await wait_until(started.is_set)
            worker = next(worker for worker in app.workers if worker.node is history and worker.name == "convs_load")
            await pilot.press("escape")
            await wait_until(lambda: app.screen is origin and worker.is_finished and cancelled.is_set())
            assert not history.is_attached
            assert app._exception is None
        finally:
            release.set()


@pytest.mark.asyncio
async def test_help_collapse_preserves_held_turn_but_explicit_end_cancels_it() -> None:
    app = _RemainingHost(False)
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def held_turn() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    async with app.run_test(size=(100, 30)) as pilot:
        screen = await open_case(CASES[0], app, pilot)
        panel = await open_chat(app, pilot, screen)
        session = panel._session = ChatSession(id="help-session")
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Preserve café Ω")
        editor.selection = Selection((0, 0), (0, 8))
        document, selection = editor.document, editor.selection
        worker = panel.run_worker(held_turn(), group="ai_chat")
        await wait_until(started.is_set)
        await collapse_chat(app, pilot, screen)
        assert panel.is_attached and not cancelled.is_set() and not worker.is_finished
        assert panel._session is session and editor.document is document
        assert editor.selection == selection and editor.text == "Preserve café Ω"
        await pilot.press("ctrl+g")
        await wait_until(lambda: not panel._collapsed and app.focused is editor)
        assert panel._session is session and editor.document is document
        assert editor.selection == selection and not cancelled.is_set()
        await _click(pilot, "#workspace_chat_end")
        await wait_until(lambda: not panel.is_attached and worker.is_finished and cancelled.is_set())
        assert not screen.query(ChatPanel)
        assert app.screen is screen and content(screen).display


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,key", [
    ("analysis", "y"), ("dashboard", "q"), ("dashboard", "0"),
    ("history", "d"),
])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_remaining_navigation_mode_suppresses_content_shortcuts(
    kind: str, key: str, navigation_visible: bool, clipboard: _Clipboard,
) -> None:
    app = _RemainingHost(navigation_visible)
    case = next(case for case in CASES if case.name == kind)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        app.copy_to_clipboard("retain clipboard sentinel")
        await pilot.press("shift+f6")
        sidebar = screen.query_one(Sidebar)
        await wait_until(lambda: sidebar.navigation_mode and sidebar.has_focus_within)
        await pilot.press(key)
        await pilot.pause()
        assert app.is_running and app.screen is screen and app._exception is None
        assert sidebar.navigation_mode and sidebar.has_focus_within
        assert clipboard.calls == [] and app.clipboard == "retain clipboard sentinel"
        app.ai_conversations_client.delete.assert_not_awaited()
        app.ai_conversations_client.patch.assert_not_awaited()
        app.scan_service.scan_server.assert_not_awaited()
        app.update_service.run_upgrade.assert_not_awaited()
        await pilot.press("shift+f6")
        await wait_until(lambda: not sidebar.navigation_mode)
        assert content(screen).display and app.focused is not None
        if kind == "dashboard":
            await pilot.press(key)
            await wait_until(lambda: not app.is_running)


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_conversations_cloud_short_view_keeps_row_and_actions_visible(
    navigation_visible: bool,
) -> None:
    app = _RemainingHost(navigation_visible)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await open_case(CASES[3], app, pilot)
        assert await pilot.click("#--content-tab-tab_cloud")
        await wait_until(lambda: screen._active_tab == "tab_cloud")
        await _ready(screen)
        await pilot.pause()
        selectors = ("#convs_filter", "#convs_table", "#btn_convs_open", "#btn_convs_archive",
                     "#btn_convs_delete", "#btn_convs_export", "#btn_convs_more", "#btn_convs_refresh")
        cloud = replace(CASES[3], name="history-cloud", primary_focus_selector="#convs_filter",
                        essential_targets=selectors, painted_targets=(("#convs_table", TITLE),))
        before = _state(screen), app.focused, app.ai_conversations_client.list.await_count
        await assert_essential_targets(cloud, app, pilot, screen)
        # Every shown action must fit together, including disabled actions.
        for button in screen.query_one("#convs_actions").query(Button):
            assert content(screen).region.contains_region(button.region)
            assert app.screen.region.contains_region(button.region)
            # A narrow layout shows the actions as one-row buttons.
            assert button.region.height == 1
            assert app.get_widget_at(*button.region.center)[0] is button
            assert button.label.plain in _painted(app, button)
        assert (_state(screen), app.focused, app.ai_conversations_client.list.await_count) == before
        assert not app.ai_conversations_client.patch.await_count
        assert not app.ai_conversations_client.delete.await_count and app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_conversations_actions_stay_visible_when_the_status_is_long(
    navigation_visible: bool,
) -> None:
    app = _RemainingHost(navigation_visible)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await open_case(CASES[3], app, pilot)
        assert await pilot.click("#--content-tab-tab_cloud")
        await wait_until(lambda: screen._active_tab == "tab_cloud")
        await _ready(screen)
        screen.query_one("#convs_status").update("a long status message " * 12)
        await pilot.pause()
        for button in screen.query_one("#convs_actions").query(Button):
            await wait_until(lambda b=button: screen.can_view_entire(b))
            assert app.get_widget_at(*button.region.center)[0] is button


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_dashboard_modified_quit_remains_available_during_navigation(
    navigation_visible: bool,
) -> None:
    app = _RemainingHost(navigation_visible)
    case = next(case for case in CASES if case.name == "dashboard")
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await pilot.press("shift+f6")
        sidebar = screen.query_one(Sidebar)
        await wait_until(lambda: sidebar.navigation_mode and sidebar.has_focus_within)
        await pilot.press("ctrl+q")
        await wait_until(lambda: not app.is_running)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (80, 24)])
@pytest.mark.parametrize("scrolling", [False, True], ids=["short", "scrolling"])
async def test_analysis_completed_output_has_native_text_viewport_on_short_screens(
    size: tuple[int, int], scrolling: bool,
) -> None:
    app = _RemainingHost(True)
    first, last = "First [literal] Ω", "Last readable line"
    lines = [first, last] if not scrolling else [first, *[f"Output line {i}" for i in range(12)], last]
    reply = "\n".join(lines)
    app.ai_analysis_service.analyze_text.side_effect = None
    app.ai_analysis_service.analyze_text.return_value = {
        "content": reply, "model": "fixture-model", "estimated_cost": 0,
        "input_tokens": 41, "output_tokens": 11, "tokens_used": 52,
    }
    async with app.run_test(size=size) as pilot:
        origin = app.screen
        screen = await open_case(CASES[1], app, pilot)
        assert screen.query_one(Sidebar).display
        await pilot.press("f5")
        await wait_until(lambda: screen._output_text == reply and not screen.query_one("#btn_analyze", Button).disabled)
        app.ai_analysis_service.analyze_text.assert_awaited_once_with(INPUT, system_prompt="Keep [literal] Ω")
        assert not screen.query_one(ProgressIndicator)._active
        assert "Analysis complete." in screen.query_one("#ai_status", Static).render().plain
        output = screen.query_one("#ai_output", TextArea)
        document = output.document
        await tab_to(pilot, output)
        for _ in range(len(lines) + 1):
            if output.cursor_location[0] == 0:
                break
            await pilot.press("pageup")
        assert output.cursor_location[0] == 0
        await pilot.pause()
        assert output.content_region.height >= 2
        body = screen.query_one("#ai_container")
        assert screen.region.contains_region(output.content_region)
        assert body.scrollable_content_region.contains_region(output.content_region)
        assert app.get_widget_at(*output.content_region.center)[0] is output

        def painted_output() -> str:
            box = output.content_region.intersection(body.scrollable_content_region).intersection(screen.region)
            strips = screen._compositor.render_strips()
            return "\n".join(strips[y].crop(box.x, box.right).text for y in range(box.y, box.bottom))

        assert first in " ".join(painted_output().split())
        for _ in range(len(lines) + 1):
            if output.cursor_location[0] == len(lines) - 1:
                break
            await pilot.press("pagedown")
        assert output.cursor_location[0] == len(lines) - 1
        await pilot.pause()
        assert last in " ".join(painted_output().split())
        if scrolling:
            assert output.scroll_y > 0
        for _ in range(len(lines) + 1):
            if output.cursor_location[0] == 0:
                break
            await pilot.press("pageup")
        assert output.cursor_location[0] == 0
        await pilot.pause()
        assert output.scroll_y == 0 and first in " ".join(painted_output().split())
        assert output.read_only and output.text == reply and output.document is document
        assert screen._output_text == reply
        back = screen.query_one("#btn_back", Button)
        await tab_to(pilot, back)
        await pilot.pause()
        assert screen.region.contains_region(back.region)
        assert body.scrollable_content_region.contains_region(back.region)
        assert app.get_widget_at(*back.region.center)[0] is back
        assert "Back" in _painted(app, back)
        metadata = screen.query_one("#ai_cost_info", Static)
        assert body.scrollable_content_region.contains_region(metadata.region)
        assert "".join(metadata.render().plain.split()) in "".join(_painted(app, metadata).split())
        assert "41 in / 11 out (52 total)" in metadata.render().plain
        await pilot.press("enter")
        await wait_until(lambda: app.screen is origin)
        assert app._exception is None


@pytest.mark.asyncio
async def test_analysis_new_request_clears_previous_metadata_before_failed_result(
    clipboard: _Clipboard,
) -> None:
    app = _RemainingHost(True)
    started, release = asyncio.Event(), asyncio.Event()
    calls = 0
    error = "OpenAI API error (401): Incorrect API key provided"

    async def analyze(text: str, *, system_prompt: str) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return {"content": OUTPUT, "model": "fixture-model", "estimated_cost": 0,
                    "input_tokens": 41, "output_tokens": 11, "tokens_used": 52}
        started.set()
        await release.wait()
        raise RuntimeError(error)

    app.ai_analysis_service.analyze_text.side_effect = analyze
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await open_case(CASES[1], app, pilot)
        await pilot.press("f5")
        await wait_until(lambda: calls == 1 and not screen.query_one("#btn_analyze", Button).disabled)
        metadata = screen.query_one("#ai_cost_info", Static)
        assert "41 in / 11 out (52 total)" in metadata.render().plain
        assert screen._output_text == OUTPUT
        try:
            await pilot.press("f5")
            await wait_until(started.is_set)
            assert screen.query_one("#btn_analyze", Button).disabled
            assert screen.query_one(ProgressIndicator)._active
            assert metadata.render().plain == ""
            assert screen.query_one("#ai_output", TextArea).text == "" and screen._output_text == ""
        finally:
            release.set()
        await wait_until(lambda: not screen.query_one("#btn_analyze", Button).disabled)
        assert "Error: " + error == screen.query_one("#ai_status", Static).render().plain
        assert metadata.render().plain == ""
        assert screen.query_one("#ai_output", TextArea).text == "" and screen._output_text == ""
        assert not screen.query_one(ProgressIndicator)._active
        with patch.object(app, "notify", wraps=app.notify) as notify:
            screen.action_copy_output()
            notify.assert_called_once_with("Nothing to copy", title="", severity="warning", markup=True)
        assert clipboard.calls == []
        assert app.ai_analysis_service.analyze_text.await_count == 2
        for call in app.ai_analysis_service.analyze_text.await_args_list:
            assert call.args == (INPUT,) and call.kwargs == {"system_prompt": "Keep [literal] Ω"}
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("case", [c for c in CASES if c.name in {"history"}], ids=lambda c: c.name)
async def test_action_hints_are_bindings_and_the_key_matches_the_click(case: ReflowCase) -> None:
    from tests._hint_conformance import assert_hints_match_bindings, record_actions

    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        calls: list[str] = []
        record_actions(screen, calls)
        handovers = {"refresh": "refresh_local", "open_selected": "open_local", "delete": "delete_local"}
        assert await assert_hints_match_bindings(pilot, screen, calls, handovers) >= 1
