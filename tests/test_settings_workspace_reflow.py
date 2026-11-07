"""Settings keeps real fields, account actions and drafts usable beside chat."""

from __future__ import annotations

import ast
import re
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from textual import events
from textual.pilot import Pilot
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import Button, DataTable, Input, Static, TextArea
from textual.widgets.text_area import Selection

from servonaut.app import ServonautApp
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig, AWSAccount, AWSConfig
from servonaut.screens.hetzner_setup import HetznerSetupScreen
from servonaut.screens.settings.base import SettingsPanel
from servonaut.screens.settings.shell import DiscardChangesModal, SettingsScreen
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import (
    BoundarySample,
    ReflowCase,
    assert_essential_targets,
    assert_layout,
    collapse_chat,
    content,
    one_layout_transition,
    open_case,
    open_chat,
    preserve_native_state,
    tab_to,
)
from tests.test_fleet_workspace_layout import _open_chat as _native_open_chat
from tests.test_settings_credentials_presentation import _CredentialsApp
from tests.test_workspace_pilot import _click
from tests.test_workspace_reflow import _painted


USERNAME = "operator-café-Ω"
ACCOUNT_FIELDS = {
    "aws": "#aws_default_region",
    "hetzner": "#hetzner_cache_ttl",
    "ovh": "#ovh_audit_path",
}


# Native integer widths and raw-budget policy flags are qualified separately.
# A rounded +0 column can still be replaced while its raw budget is below70.
MEASURED_BOUNDARIES = {
    ('chat-min', False): (
        BoundarySample((115, 40), 69, True, True),
        BoundarySample((116, 40), 70, True, True),
        BoundarySample((117, 40), 71, False, True),
    ),
    ('chat-min', True): (
        BoundarySample((156, 40), 69, True, True),
        BoundarySample((158, 40), 70, True, True),
        BoundarySample((159, 40), 71, False, True),
    ),
    ('content-narrow', False): (
        BoundarySample((156, 40), 94, False, True),
        BoundarySample((158, 40), 95, False, True),
        BoundarySample((159, 40), 96, False, False),
    ),
    ('content-narrow', True): (
        BoundarySample((183, 40), 94, False, True),
        BoundarySample((184, 40), 95, False, False),
        BoundarySample((185, 40), 96, False, False),
    ),
}


@pytest.fixture(autouse=True)
def _no_external_work(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep real forms/config semantics, with every external boundary inert."""
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    monkeypatch.setattr("servonaut.config.manager._migrate_legacy_paths", lambda: None)
    monkeypatch.setattr("servonaut.config.manager._ensure_config_dir", lambda: None)
    monkeypatch.setattr(
        "servonaut.screens.settings.aws_accounts.detected_aws_profiles", lambda: [],
    )
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    tripwire = Mock(side_effect=AssertionError("Unexpected external operation"))
    for target in (
        "subprocess.Popen", "subprocess.run", "socket.create_connection",
        "asyncio.open_connection", "boto3.session.Session",
        "servonaut.screens.settings.accounts.rebuild_accounts",
        "servonaut.screens.settings.accounts.refresh_provider_fleet",
        "servonaut.screens.settings.panels.aws.rebuild_accounts",
        "servonaut.screens.settings.panels.aws.refresh_provider_fleet",
        "servonaut.screens.settings.panels.hetzner.rebuild_accounts",
        "servonaut.screens.settings.panels.hetzner.refresh_provider_fleet",
        "servonaut.screens.settings.panels.ovh.rebuild_accounts",
        "servonaut.screens.settings.panels.ovh.refresh_provider_fleet",
    ):
        monkeypatch.setattr(target, tripwire)
    yield
    tripwire.assert_not_called()


@pytest.fixture
def manager(tmp_path: Path) -> ConfigManager:
    config = AppConfig(aws=AWSConfig(accounts=[
        AWSAccount(label="secondary", profile="secondary"),
    ]))
    config.ovh.ovh_audit_path = str(tmp_path / "audit.json")
    manager = ConfigManager(config_path=tmp_path / "config.json")
    manager.save(config)
    manager.load()
    return manager


def _factory(
    manager: ConfigManager, panel_id: str,
) -> Callable[[bool], _CredentialsApp]:
    def create(visible: bool) -> _CredentialsApp:
        app = _CredentialsApp(manager, panel_id, visible)
        app.theme = "servonaut"
        return app
    return create


async def _screen(app: ServonautApp, pilot: Pilot) -> WorkspaceScreen:
    await wait_until(lambda: isinstance(app.screen, SettingsScreen))
    return app.screen


async def _ready(screen: WorkspaceScreen) -> None:
    assert isinstance(screen, SettingsScreen)
    await wait_until(lambda: screen._current_panel() is not None)
    panel = screen._current_panel()
    await wait_until(lambda: panel._loaded and not panel._settling)


def _seed(screen: WorkspaceScreen) -> None:
    if screen.query("#general_username"):
        screen.query_one("#general_username", Input).value = USERNAME
    if screen.query("#aws_default_region"):
        screen.query_one("#aws_default_region", Input).value = "eu-west-2"
        screen.query_one("#aws_accounts_table", DataTable).move_cursor(row=1)


def _state(screen: WorkspaceScreen) -> object:
    assert isinstance(screen, SettingsScreen)
    return (
        screen._active_id,
        tuple(screen._panels.items()),
        tuple(screen._content_of.items()),
        tuple((field, field.value) for field in content(screen).query(Input)),
        tuple(
            (
                panel, panel.current_values(), dict(panel._snapshot),
                panel.is_dirty(),
                panel.query_one(f"#dirty_{panel.PANEL_ID}", Static).render().plain,
            )
            for panel in screen._panels.values()
        ),
        tuple((table, table.cursor_row) for table in content(screen).query(DataTable)),
        tuple(
            (group, section.collapsed) for group, section in screen._sections.items()
        ),
    )


def _case(manager: ConfigManager, panel_id: str = "general") -> ReflowCase:
    field = "#general_username" if panel_id == "general" else ACCOUNT_FIELDS[panel_id]
    targets = ("#settings-search", field, f"#save_{panel_id}")
    painted = ()
    if panel_id == "aws":
        targets += (
            "#settings-back", "#navbtn_aws", "#btn_aws_account_add",
            "#btn_aws_account_add_profile", "#btn_aws_account_edit",
            "#btn_aws_account_remove",
        )
        painted = (("#dirty_aws", "● unsaved"), ("#save_aws", "Save changes"))
    # Keep measured native geometry separate from raw-budget policy flags.
    return ReflowCase(
        "settings-" + panel_id, _factory(manager, panel_id), _screen, _ready,
        "#settings-search", targets, _seed, _state, painted, boundaries=MEASURED_BOUNDARIES,
    )


def _exposed(app: ServonautApp, target: Widget, viewport: Widget) -> None:
    assert target.region.width > 0 and target.region.height > 0
    assert viewport.scrollable_content_region.contains_region(target.region)
    assert app.screen.region.contains_region(target.region)
    for y in range(target.region.y, target.region.bottom):
        for x in range(target.region.x, target.region.right):
            hit = app.get_widget_at(x, y)[0]
            assert hit is target or target in hit.ancestors


async def _assert_field_fit(
    app: ServonautApp, pilot: Pilot, field: Input,
) -> None:
    field.scroll_visible(animate=False, immediate=True)
    await pilot.pause()
    panel = next(
        parent for parent in field.ancestors if isinstance(parent, SettingsPanel)
    )
    body = panel.query_one(".panel-body")
    _exposed(app, field, body)
    label = field.parent.query_one(".label", Static)
    if app.screen.has_class("-content-narrow"):
        assert label.region.bottom <= field.region.y
        assert field.region.x == label.region.x
    else:
        assert label.region.right <= field.region.x
    # A full sample username proves editable content, not just a nonzero box.
    assert field.content_region.width >= len(USERNAME)
    if field.id == "general_username":
        assert USERNAME in _painted(app, field)


async def _assert_save_fit(
    app: ServonautApp, pilot: Pilot, panel_id: str,
) -> None:
    save = app.screen.query_one(f"#save_{panel_id}", Button)
    panel = app.screen.query_one(f"#panel_{panel_id}")
    assert panel.content_region.contains_region(save.region)
    for y in range(save.region.y, save.region.bottom):
        for x in range(save.region.x, save.region.right):
            assert app.get_widget_at(x, y)[0] is save
    assert "Save changes" in _painted(app, save)
    await tab_to(pilot, save)
    assert app.focused is save


async def _assert_account_actions(
    app: ServonautApp, pilot: Pilot, provider: str,
) -> None:
    panel = app.screen.query_one(f"#panel_{provider}")
    body = panel.query_one(".panel-body")
    actions = list(panel.query(".accounts-action"))
    expected = 4 if provider == "aws" else 3
    assert len(actions) == expected
    for action in actions:
        assert isinstance(action, Button)
        action.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        if not action.disabled:
            await tab_to(pilot, action)
            await pilot.pause()
            assert app.focused is action
        _exposed(app, action, body)
        assert action.parent.content_region.contains_region(action.region)
        region = action.content_region
        strips = app.screen._compositor.render_strips()
        painted_label = " ".join(
            strips[y].crop(region.x, region.right).text
            for y in range(region.y, region.bottom)
        )
        assert " ".join(action.label.plain.split()) in " ".join(painted_label.split())


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("chat_open", [False, True])
async def test_settings_visibility_keeps_actual_field_and_pinned_save_usable(
    manager: ConfigManager, size: tuple[int, int],
    navigation_visible: bool, chat_open: bool,
) -> None:
    case = _case(manager)
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=size) as pilot:
        screen = await open_case(case, app, pilot)
        baseline = case.state(screen)
        if chat_open:
            await open_chat(app, pilot, screen)
        assert_layout(app, screen)
        assert screen.query_one(Sidebar).display is navigation_visible
        assert case.state(screen) == baseline
        if chat_open and size == (160, 50):
            assert content(screen).display
        if content(screen).display:
            await _assert_field_fit(app, pilot, screen.query_one("#general_username"))
            await _assert_save_fit(app, pilot, "general")


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["aws", "hetzner", "ovh"])
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("chat_open", [False, True])
async def test_accounts_keep_actual_fields_and_all_native_actions_exposed(
    manager: ConfigManager, provider: str, size: tuple[int, int],
    navigation_visible: bool, chat_open: bool,
) -> None:
    case = _case(manager, provider)
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=size) as pilot:
        screen = await open_case(case, app, pilot)
        baseline = case.state(screen)
        if chat_open:
            await open_chat(app, pilot, screen)
        assert_layout(app, screen)
        if chat_open and size == (160, 50):
            assert content(screen).display
        if not content(screen).display:
            await collapse_chat(app, pilot, screen)
        await _assert_field_fit(app, pilot, screen.query_one(ACCOUNT_FIELDS[provider]))
        await _assert_account_actions(app, pilot, provider)
        await _assert_save_fit(app, pilot, provider)
        assert case.state(screen) == baseline


@pytest.mark.asyncio
@pytest.mark.timeout(120)  # Full reflow and native focus traversal exceed the default budget.
async def test_dirty_cached_aws_cursor_and_native_chat_selection_survive_reflow(
    manager: ConfigManager,
) -> None:
    case = _case(manager, "aws")
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        panel = screen.query_one("#panel_aws", SettingsPanel)
        await wait_until(panel.is_dirty)
        saved = manager.get().aws.default_region
        await preserve_native_state(case, app, pilot, screen)
        assert panel.is_dirty()
        assert manager.get().aws.default_region == saved
        assert screen._panels == {"aws": panel}
        assert screen.query_one("#aws_accounts_table", DataTable).cursor_row == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_reflow_keeps_dirty_guard_lazy_cache_search_and_parked_chat(
    manager: ConfigManager, navigation_visible: bool,
) -> None:
    case = _case(manager)
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        general = screen.query_one("#panel_general", SettingsPanel)
        await wait_until(general.is_dirty)
        chat = await open_chat(app, pilot, screen)
        editor = chat.query_one("#chat-input", TextArea)
        editor.load_text("Preserve café chat")
        editor.selection = Selection((0, 0), (0, 8))
        document, selection = editor.document, editor.selection
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        await collapse_chat(app, pilot, screen)
        await pilot.press("ctrl+f")
        search = screen.query_one("#settings-search", Input)
        await pilot.press(*"history")
        assert search.value == "history"
        destination = screen.query_one("#navbtn_history_paths", Button)
        await tab_to(pilot, destination)
        await pilot.press("enter")
        await wait_until(lambda: isinstance(app.screen, DiscardChangesModal))
        assert app.focused is app.screen.query_one("#discard-cancel")
        assert "history_paths" not in screen._panels
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen)
        assert general.is_dirty() and screen._active_id == "general"
        assert screen.query_one("#general_username", Input).value == USERNAME
        await tab_to(pilot, destination)
        await pilot.press("enter")
        await wait_until(lambda: isinstance(app.screen, DiscardChangesModal))
        await _click(pilot, "#discard-confirm")
        await wait_until(lambda: app.screen is screen)
        await _ready(screen)
        assert screen._active_id == "history_paths"
        assert not general.is_dirty()
        assert set(screen._panels) == {"general", "history_paths"}
        assert search.value == "history" and chat.is_attached and chat._collapsed
        assert editor.document is document and editor.selection == selection
        assert editor.text == "Preserve café chat"
        search.focus()
        await pilot.press("ctrl+shift+a", "backspace")
        await wait_until(lambda: search.value == "")
        general_button = screen.query_one("#navbtn_general", Button)
        await wait_until(lambda: general_button.display)
        assert general_button.display
        await tab_to(pilot, general_button)
        await pilot.press("enter")
        await wait_until(lambda: screen._active_id == "general")
        assert screen._panels["general"] is general


@pytest.mark.asyncio
@pytest.mark.timeout(120)  # Three widths each retain a full native Settings focus traversal.
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("kind", ["chat-min", "content-narrow"])
async def test_qualified_settings_boundaries_measure_fields_and_account_actions(
    manager: ConfigManager, navigation_visible: bool, kind: str,
) -> None:
    case = _case(manager, "aws")
    samples = case.boundary_samples(kind, navigation_visible)
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=samples[0].size) as pilot:
        screen = await open_case(case, app, pilot)
        baseline = case.state(screen)
        await open_chat(app, pilot, screen)
        threshold = (
            screen.CHAT_MIN_CONTENT_WIDTH if kind == "chat-min"
            else screen.CONTENT_NARROW_WIDTH
        )
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
                # Width only while forcing columns that the real policy hides.
                with patch.object(screen, "CHAT_MIN_CONTENT_WIDTH", 1):
                    screen.apply_workspace_state()
                    await pilot.pause()
                    assert content(screen).region.width == sample.native_content_width
                screen.apply_workspace_state()
                await pilot.pause()
                assert screen.has_class("-chat-replace") is sample.expected_replace
                assert screen.has_class("-content-narrow") is (
                    sample.expected_content_narrow
                )
                assert not content(screen).display
            else:
                assert content(screen).region.width == sample.native_content_width
                await _assert_field_fit(
                    app, pilot, screen.query_one(ACCOUNT_FIELDS["aws"]),
                )
                await _assert_account_actions(app, pilot, "aws")
                await _assert_save_fit(app, pilot, "aws")
            assert case.state(screen) == baseline


@pytest.mark.asyncio
async def test_navigation_crossing_and_modal_resume_keep_settings_origin(
    manager: ConfigManager,
) -> None:
    case = _case(manager)
    sample = case.boundary_samples("chat-min", True)[0]
    assert sample.expected_replace
    app = case.app_factory(False)
    async with app.run_test(size=sample.size) as pilot:
        screen = await open_case(case, app, pilot)
        chat = await open_chat(app, pilot, screen)
        editor = chat.query_one("#chat-input", TextArea)
        editor.load_text("Keep this navigation draft")
        document = editor.document
        assert content(screen).display
        origin = screen.query_one("#general_username", Input)
        await tab_to(pilot, origin)
        await pilot.press("shift+f6")
        sidebar = screen.query_one(Sidebar)
        await wait_until(lambda: sidebar.navigation_mode and sidebar.has_focus_within)
        assert not content(screen).display
        modal = DiscardChangesModal("General")
        await app.push_screen(modal)
        await wait_until(lambda: app.focused is modal.query_one("#discard-cancel"))
        assert not sidebar.navigation_mode and not sidebar.display
        assert content(screen).display and screen.focused is origin
        await pilot.press("shift+f6", "f2", "ctrl+g")
        assert app.screen is modal and app.focused is modal.query_one("#discard-cancel")
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen and app.focused is origin)
        assert editor.document is document
        assert editor.text == "Keep this navigation draft"
        assert screen.query_one("#general_username", Input).value == USERNAME


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut-light", "ansi-dark", "ansi-light"])
async def test_representative_palettes_keep_actual_field_and_save_painted(
    manager: ConfigManager, theme: str,
) -> None:
    case = _case(manager)
    app = case.app_factory(True)
    app.theme = theme
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await open_chat(app, pilot, screen)
        assert content(screen).display
        assert_layout(app, screen)
        await _assert_field_fit(app, pilot, screen.query_one("#general_username"))
        await _assert_save_fit(app, pilot, "general")
        await collapse_chat(app, pilot, screen)
        await assert_essential_targets(case, app, pilot, screen)


def test_settings_style_rules_cannot_rejoin_terminal_width_policy() -> None:
    source = Path(__file__).resolve().parents[1] / "src"
    selector = re.compile(r"SettingsScreen\.-(?:narrow|wide)(?=[\s.#:{])")
    coupled: list[str] = []
    for path in source.rglob("*.tcss"):
        if selector.search(path.read_text()):
            coupled.append(str(path.relative_to(source)))
    for path in source.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not any(
                isinstance(target, ast.Name) and target.id == "DEFAULT_CSS"
                for target in node.targets
            ):
                continue
            if isinstance(node.value, ast.Constant) and isinstance(
                node.value.value, str,
            ):
                if selector.search(node.value.value):
                    coupled.append(str(path.relative_to(source)))
    assert not coupled, coupled


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_escape_dirty_replaced_settings_keeps_visible_chat_then_discards(
    manager: ConfigManager, navigation_visible: bool,
) -> None:
    case = _case(manager)
    landing = Screen()

    class _LandingApp(_CredentialsApp):
        def on_mount(self, event: events.Mount) -> None:
            event.prevent_default()
            self.push_screen(landing)
            self.push_screen(SettingsScreen(self.panel_id))

    def create(visible: bool) -> _CredentialsApp:
        host = _LandingApp(manager, "general", visible)
        host.theme = "servonaut"
        return host

    # Keep the real pop route while providing an inert screen below Settings.
    case = replace(case, app_factory=create)
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await open_case(case, app, pilot)
        assert app.screen_stack[-2] is landing
        assert len(app.screen_stack) == 3
        panel = screen.query_one("#panel_general", SettingsPanel)
        await wait_until(panel.is_dirty)
        baseline = case.state(screen)
        chat = await open_chat(app, pilot, screen)
        editor = chat.query_one("#chat-input", TextArea)
        editor.load_text("Keep this visible draft")
        assert screen.has_class("-chat-replace") and not content(screen).display
        await pilot.press("escape")
        await wait_until(lambda: isinstance(app.screen, DiscardChangesModal))
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen and app.focused is editor)
        assert screen.has_class("-chat-replace") and not content(screen).display
        assert case.state(screen) == baseline
        assert editor.text == "Keep this visible draft"
        await pilot.press("escape")
        await wait_until(lambda: isinstance(app.screen, DiscardChangesModal))
        await _click(pilot, "#discard-confirm")
        await wait_until(lambda: app.screen is landing)
        assert not panel.is_dirty()


@pytest.mark.asyncio
async def test_ctrl_f_cannot_send_typing_to_search_inside_replaced_content(
    manager: ConfigManager,
) -> None:
    case = _case(manager)
    app = case.app_factory(False)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await open_case(case, app, pilot)
        chat = await open_chat(app, pilot, screen)
        editor = chat.query_one("#chat-input", TextArea)
        search = screen.query_one("#settings-search", Input)
        assert screen.has_class("-chat-replace")
        await pilot.press("ctrl+f")
        await pilot.pause()
        assert app.focused is editor
        assert not search.has_focus
        await pilot.press(*"visible draft")
        assert editor.text == "visible draft" and search.value == ""


@pytest.mark.asyncio
async def test_first_lazy_hetzner_build_beside_chat_has_stacked_fields_and_actions(
    manager: ConfigManager,
) -> None:
    app = _factory(manager, "general")(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _screen(app, pilot)
        await _ready(screen)
        assert set(screen._panels) == {"general"}
        initial = screen._panels["general"]
        chat = await open_chat(app, pilot, screen)
        document = chat.query_one("#chat-input", TextArea).document
        assert screen.has_class("-content-narrow") and content(screen).display
        await tab_to(pilot, screen.query_one("#settings-search"))
        await pilot.press(*"hetzner")
        await tab_to(pilot, screen.query_one("#navbtn_hetzner"))
        await pilot.press("enter")
        await wait_until(lambda: screen._active_id == "hetzner")
        await _ready(screen)
        assert set(screen._panels) == {"general", "hetzner"}
        assert screen._panels["general"] is initial
        assert chat.query_one("#chat-input", TextArea).document is document
        await _assert_field_fit(app, pilot, screen.query_one("#hetzner_cache_ttl"))
        await _assert_account_actions(app, pilot, "hetzner")
        await _assert_save_fit(app, pilot, "hetzner")


@pytest.mark.asyncio
async def test_hetzner_add_child_return_refreshes_and_applies_reflow_once(
    manager: ConfigManager, monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager.update(hetzner=replace(manager.get().hetzner, enabled=True))
    app = _factory(manager, "hetzner")(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _screen(app, pilot)
        await _ready(screen)
        panel = screen._current_panel()
        field = panel.query_one("#hetzner_cache_ttl", Input)
        field.value = "451"
        await wait_until(panel.is_dirty)
        chat = await open_chat(app, pilot, screen)
        editor = chat.query_one("#chat-input", TextArea)
        editor.load_text("Keep this provider draft")
        document = editor.document
        add = screen.query_one("#btn_hetzner_account_add", Button)
        add.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        await _click(pilot, "#btn_hetzner_account_add")
        await wait_until(lambda: isinstance(app.screen, HetznerSetupScreen))
        child = app.screen
        await wait_until(lambda: child.is_mounted and app.focused is not None)
        assert app.screen is child
        assert app.focused.screen is child
        refresh = Mock(wraps=panel.refresh_external_state)
        apply_state = Mock(wraps=screen.apply_workspace_state)
        monkeypatch.setattr(panel, "refresh_external_state", refresh)
        monkeypatch.setattr(screen, "apply_workspace_state", apply_state)
        with one_layout_transition(screen):
            await pilot.press("escape")
            await wait_until(lambda: app.screen is screen)
            await pilot.pause()
        refresh.assert_called_once_with()
        apply_state.assert_called_once_with()
        assert screen._current_panel() is panel and panel.is_dirty()
        assert field.value == "451" and content(screen).display
        assert chat.is_attached and not chat._collapsed
        assert editor.document is document and editor.text == "Keep this provider draft"
        assert_layout(app, screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("size,navigation_visible,chat_open", [
    ((120, 40), True, False), ((128, 40), True, False),
    ((136, 40), True, False), ((160, 50), False, True),
])
async def test_aws_actions_fit_original_wide_terminal_ranges(
    manager: ConfigManager, size: tuple[int, int],
    navigation_visible: bool, chat_open: bool,
) -> None:
    # This probe can run against exact original shell/CSS, before any grid fix.
    app = _factory(manager, "aws")(navigation_visible)
    async with app.run_test(size=size) as pilot:
        screen = await _screen(app, pilot)
        await _ready(screen)
        if chat_open:
            await _native_open_chat(app, pilot)
        await _assert_account_actions(app, pilot, "aws")
        await _assert_save_fit(app, pilot, "aws")
