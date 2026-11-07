"""Provider setup forms keep fields, results and routes intact beside chat."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, create_autospec, patch

import pytest
from textual.pilot import Pilot
from textual.widgets import Button, Input, Static

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig
from servonaut.screens.hetzner_setup import HetznerSetupScreen
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.ovh_setup import OVHSetupScreen
from servonaut.services.hetzner_service import HetznerService
from servonaut.services.ovh_service import OVHService
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import (
    BoundarySample, ReflowCase, assert_button_label_painted, assert_essential_targets,
    assert_layout, collapse_chat, content,
    one_layout_transition, open_case, open_chat, preserve_native_state,
)
from tests.test_workspace_pilot import _Host, _click


class _SetupHost(_Host):
    """The accepted native workspace host with an in-memory config."""

    def __init__(self, navigation_visible: bool = True) -> None:
        super().__init__(navigation_visible=navigation_visible)
        config = AppConfig()
        # Both providers already set up, so every action button is shown.
        config.hetzner.enabled = True
        config.hetzner.api_token = "example-token"
        config.ovh.enabled = True
        config.ovh.application_key = "example-app-key"
        config.ovh.application_secret = "example-app-secret"
        config.ovh.consumer_key = "example-consumer-key"
        self.config = config
        self.config_manager = SimpleNamespace(
            get=lambda: self.config, save=Mock(), update=Mock(),
        )


@pytest.fixture(autouse=True)
def _inert_boundaries(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict]:
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    trips = {
        "browser": Mock(side_effect=AssertionError("Unexpected browser")),
        "process": Mock(side_effect=AssertionError("Unexpected subprocess")),
        "async_process": AsyncMock(side_effect=AssertionError("Unexpected subprocess")),
        "socket": Mock(side_effect=AssertionError("Unexpected network")),
        "connection": AsyncMock(side_effect=AssertionError("Unexpected network")),
        "keyring": Mock(side_effect=AssertionError("Unexpected keyring operation")),
    }
    monkeypatch.setattr("webbrowser.open", trips["browser"])
    monkeypatch.setattr("subprocess.Popen", trips["process"])
    monkeypatch.setattr("subprocess.run", trips["process"])
    monkeypatch.setattr("asyncio.create_subprocess_exec", trips["async_process"])
    monkeypatch.setattr("socket.create_connection", trips["socket"])
    monkeypatch.setattr(asyncio.BaseEventLoop, "create_connection", trips["connection"])
    for name in ("get_password", "set_password", "delete_password"):
        monkeypatch.setattr("keyring." + name, trips["keyring"])
    yield trips
    trips["browser"].assert_not_called()
    trips["process"].assert_not_called()
    trips["async_process"].assert_not_awaited()
    trips["socket"].assert_not_called()
    trips["connection"].assert_not_awaited()
    trips["keyring"].assert_not_called()


SCREENS = {"hetzner": HetznerSetupScreen, "ovh": OVHSetupScreen}
# Per provider: (username input, its value after mount, test button, save-off
# button, add-another button, back button, test result, action row).
IDS = {
    "hetzner": SimpleNamespace(
        username="#hetzner_input_username", username_value="root",
        test="#btn_hetzner_test", save="#btn_hetzner_save", keep_off="#btn_hetzner_disable",
        add="#btn_hetzner_add_project", back="#btn_hetzner_back",
        result="#hetzner_test_result", row=".hetzner_action_row",
        token="#hetzner_input_token",
    ),
    "ovh": SimpleNamespace(
        username="#ovh_input_default_username", username_value="",
        test="#btn_ovh_test", save="#btn_ovh_save", keep_off="#btn_ovh_disable",
        add="#btn_ovh_add_account", back="#btn_ovh_back",
        result="#ovh_test_result", row=".ovh_action_row",
        token="#ovh_input_app_key",
    ),
}


def _opener(kind: str) -> Callable[[ServonautApp, Pilot], Awaitable[WorkspaceScreen]]:
    async def open_screen(app: ServonautApp, pilot: Pilot) -> WorkspaceScreen:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        screen = SCREENS[kind]()
        app.root_results = []
        await app.push_screen(screen, app.root_results.append)
        return screen
    return open_screen


def _kind(screen: WorkspaceScreen) -> str:
    return "hetzner" if isinstance(screen, HetznerSetupScreen) else "ovh"


async def _ready(screen: WorkspaceScreen) -> None:
    ids = IDS[_kind(screen)]
    await wait_until(lambda: screen.query_one(ids.token, Input).value != "")
    assert screen.query_one(ids.test, Button).label.plain == "Test Connection"


def _seed(screen: WorkspaceScreen) -> None:
    # A typed but unsaved value that must survive every reflow.
    screen.query_one(IDS[_kind(screen)].username, Input).value = "deploy"


def _state(screen: WorkspaceScreen) -> object:
    ids = IDS[_kind(screen)]
    return (
        screen.query_one(ids.username, Input).value,
        screen.query_one(ids.token, Input).value,
        screen.query_one(ids.result, Static).render().plain,
        tuple(button.label.plain for button in screen.query_one(ids.row).query(Button)),
    )


def _buttons(kind: str) -> tuple[str, ...]:
    ids = IDS[kind]
    return (ids.test, ids.save, ids.keep_off, ids.add, ids.back)


# Derived native first focus: the form container is the first focusable
# widget in DOM order. open_case characterises it.
PRIMARY = {"hetzner": "#hetzner_setup_container", "ovh": "#ovh_setup_container"}
TARGETS = {kind: (IDS[kind].token, IDS[kind].username) + _buttons(kind) for kind in SCREENS}
KINDS = ("hetzner", "ovh")
# Native boundary samples are deliberately absent until qualified measurements.
# Qualified native columns and separately measured layout policy.
_MEASURED_BOUNDARIES = {
    'hetzner': {
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
    'ovh': {
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


CASES = tuple(
    ReflowCase(kind, _SetupHost, _opener(kind), _ready, PRIMARY[kind], TARGETS[kind],
               _seed, _state, (), boundaries=_MEASURED_BOUNDARIES[kind])
    for kind in KINDS
)


def _case(kind: str) -> ReflowCase:
    return next(case for case in CASES if case.name == kind)


async def _assert_whole_toolbar(
    app: ServonautApp, pilot: Pilot, screen: WorkspaceScreen, kind: str,
) -> None:
    # Every action button, at the single scroll offset that reveals the row;
    # where the current layout clips it these cells stay red until a scoped
    # responsive change is approved.
    body = content(screen)
    row = screen.query_one(IDS[kind].row)
    focused = app.focused
    row.scroll_visible(animate=False, immediate=True)
    await pilot.pause()
    offset = (body.scroll_x, body.scroll_y, row.scroll_x)
    visible = body.scrollable_content_region
    for selector in _buttons(kind):
        button = screen.query_one(selector, Button)
        assert button.region.width > 0 and button.region.height > 0, selector
        assert row.content_region.x <= button.region.x, selector
        assert button.region.right <= row.content_region.right, selector
        assert visible.contains_region(button.region), selector
        hit = app.get_widget_at(*button.region.center)[0]
        assert hit is button or button in hit.ancestors, selector
        assert_button_label_painted(app, button)
    assert (body.scroll_x, body.scroll_y, row.scroll_x) == offset
    assert app.focused is focused


async def _type_into(pilot: Pilot, field: Input, text: str) -> None:
    field.value = ""
    field.focus()
    await wait_until(lambda: field.app.focused is field)
    await pilot.press(*text)
    await wait_until(lambda: field.value == text)


async def _enter_rail(pilot: Pilot, screen: WorkspaceScreen) -> Sidebar:
    await pilot.press("shift+f6")
    sidebar = screen.query_one(Sidebar)
    await wait_until(lambda: sidebar.navigation_mode and sidebar.has_focus_within)
    return sidebar


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=KINDS)
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("chat_open", [False, True])
async def test_setup_workspace_pane_combinations(
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
            await _assert_whole_toolbar(app, pilot, screen, case.name)
        assert app.config_manager.save.call_count == 0
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=KINDS)
async def test_setup_workspace_native_state_survives_reflow(case: ReflowCase) -> None:
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await preserve_native_state(case, app, pilot, screen)
        await _assert_whole_toolbar(app, pilot, screen, case.name)
        assert app.config_manager.save.call_count == 0
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=KINDS)
@pytest.mark.parametrize("kind", ["chat-min", "content-narrow"])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_setup_workspace_uses_qualified_native_boundaries(
    case: ReflowCase, kind: str, navigation_visible: bool,
) -> None:
    # Fails closed until qualified native samples exist (boundaries=None).
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
                await assert_essential_targets(case, app, pilot, screen)
                await _assert_whole_toolbar(app, pilot, screen, case.name)
            assert case.state(screen) == baseline


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_setup_typing_and_escape_follow_the_inherited_guard(kind: str) -> None:
    case = _case(kind)
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        field = screen.query_one(IDS[kind].username, Input)
        await _type_into(pilot, field, "ops")
        # Escape is the only binding and stays enabled in content and rail.
        assert screen.check_action("back", ()) is True
        await _enter_rail(pilot, screen)
        assert screen.check_action("back", ()) is True
        await pilot.press("x")
        await pilot.pause()
        # A printable key from the rail never reaches the form.
        assert field.value == "ops" and app.screen is screen
        assert app.config_manager.save.call_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_setup_save_without_enable_saves_typed_values_then_pops(kind: str) -> None:
    case = _case(kind)
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        ids = IDS[kind]
        await _type_into(pilot, screen.query_one(ids.username, Input), "debian")
        await _assert_whole_toolbar(app, pilot, screen, kind)
        await _click(pilot, ids.keep_off)
        await wait_until(lambda: app.screen is not screen)
        # Saved once, through the fake config manager, then popped (the
        # pushed result callback is dropped uncalled).
        app.config_manager.save.assert_called_once_with(app.config)
        block = getattr(app.config, kind)
        assert block.enabled is False and block.default_username == "debian"
        assert isinstance(app.screen, InstanceListScreen)
        assert app.root_results == []


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_setup_add_another_switches_to_itself_without_a_result(kind: str) -> None:
    case = _case(kind)
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        below = app.screen_stack[-2]
        await _assert_whole_toolbar(app, pilot, screen, kind)
        await _click(pilot, IDS[kind].add)
        await wait_until(lambda: screen not in app.screen_stack)
        added = app.screen
        assert type(added) is SCREENS[kind] and added._add_extra is True
        # switch_screen replaces only the form: the opener stays beneath, and
        # the replaced form's callback is never called.
        assert app.screen_stack[-2] is below
        assert app.root_results == []
        assert app.config_manager.save.call_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_setup_escape_pops_without_saving(kind: str) -> None:
    case = _case(kind)
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await _type_into(pilot, screen.query_one(IDS[kind].username, Input), "unsaved")
        await pilot.press("escape")
        await wait_until(lambda: app.screen is not screen)
        assert isinstance(app.screen, InstanceListScreen)
        assert app.root_results == [] and app.config_manager.save.call_count == 0
        assert getattr(app.config, kind).default_username != "unsaved"


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_setup_held_connection_test_survives_chat_reflow(
    kind: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = asyncio.Event()
    if kind == "hetzner":
        service = create_autospec(HetznerService, instance=True)

        async def _result() -> dict:
            await release.wait()
            return {"ok": True, "project": "demo"}
        for method in ("list_server_types", "list_images", "list_locations", "list_ssh_keys"):
            getattr(service, method).return_value = []
        target = "servonaut.services.hetzner_service.HetznerService"
        installer = "_install_hcloud_if_needed"
    else:
        service = create_autospec(OVHService, instance=True)

        async def _result() -> dict:
            await release.wait()
            return {"success": True, "account": "demo-account", "message": ""}
        target = "servonaut.services.ovh_service.OVHService"
        installer = "_install_ovh_if_needed"
    service.test_connection.side_effect = _result
    factory = Mock(return_value=service)
    monkeypatch.setattr(target, factory)
    case = _case(kind)
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        ids = IDS[kind]
        # The SDK check would install a package: it is replaced, never run.
        with patch.object(screen, installer, AsyncMock(return_value=True)) as install:
            await _assert_whole_toolbar(app, pilot, screen, kind)
            await _click(pilot, ids.test)
            await wait_until(lambda: service.test_connection.await_count == 1)
            worker = next(w for w in app.workers if w.name == f"{kind}_test")
            panel = await open_chat(app, pilot, screen)
            await pilot.resize_terminal(100, 30)
            await pilot.pause()
            assert screen.has_class("-chat-replace") and not content(screen).display
            await pilot.resize_terminal(160, 50)
            await pilot.pause()
            await collapse_chat(app, pilot, screen)
            assert not worker.is_finished and panel.is_attached
            release.set()
            await wait_until(lambda: worker.is_finished)
        install.assert_awaited_once_with()
        assert factory.call_count == 1
        (config,), options = factory.call_args
        if kind == "hetzner":
            assert options == {"allow_ambient_token": True}
            assert (config.enabled, config.api_token) == (True, "example-token")
        else:
            assert options == {"allow_ambient_config": True}
            assert (config.enabled, config.endpoint, config.application_key) == (
                False, "ovh-eu", "example-app-key")
        assert "Connection successful!" in screen.query_one(ids.result, Static).render().plain
        assert app.screen is screen and app.config_manager.save.call_count == 0
        assert app._exception is None
