"""Secrets workspaces keep their state, hotkeys and provider boundaries beside chat."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from pathlib import PurePosixPath
from unittest.mock import AsyncMock, MagicMock, Mock, create_autospec, patch

import pytest
from textual.containers import VerticalScroll
from textual.pilot import Pilot
from textual.widgets import Button, Input, Static

import servonaut.screens.secrets_setup as secrets_setup_module
from servonaut.app import ServonautApp
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.secrets import SecretsScreen
from servonaut.screens.secrets_list import SecretsListScreen
from servonaut.screens.secrets_setup import SecretsSetupScreen
from servonaut.services.secret_provider import LocalProvider
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import (
    BoundarySample, ReflowCase, assert_button_label_painted, assert_essential_targets, assert_layout, collapse_chat, content,
    one_layout_transition, open_case, open_chat, preserve_native_state, tab_to,
)
from tests.test_selection_copy import _Clipboard, _drag
from tests.test_selection_copy import clipboard as clipboard
from tests.test_secrets_screen import _mock_auth, _mock_guard
from tests.test_workspace_pilot import _Host
from tests.test_workspace_reflow import _painted

pytestmark = pytest.mark.usefixtures("navigation_open")


# One name carries markup-like brackets and non-ASCII text to prove literal copy.
NAMES = ["db-password", "café [literal] Ω"]


class _SecretsHost(_Host):
    """The accepted native workspace host with the secrets screens' fakes."""

    def __init__(self, navigation_visible: bool = True) -> None:
        super().__init__(navigation_visible=navigation_visible)
        self.auth_service = _mock_auth(plan="solo")
        self.entitlement_guard = _mock_guard(allow_secrets=True)
        self.api_client = MagicMock()
        self.ssh_service = MagicMock()


@pytest.fixture(autouse=True)
def _inert_boundaries(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict]:
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    provider = create_autospec(LocalProvider, instance=True)
    provider.provider_name = "local"
    # The status card shows the local store path; keep it a neutral literal.
    provider.path = PurePosixPath("example-secrets.json")
    provider.list_secrets.return_value = list(NAMES)
    monkeypatch.setattr(
        "servonaut.services.secret_provider_resolver.resolve_secret_provider",
        lambda *args, **kwargs: provider,
    )
    monkeypatch.setattr("servonaut.services.secrets_status.shutil.which", lambda name: None)
    monkeypatch.setattr(secrets_setup_module.bws, "bws_installed", lambda: False)
    monkeypatch.setattr(secrets_setup_module.bws, "token_is_set", lambda env: False)
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
    yield {"provider": provider, **trips}
    trips["browser"].assert_not_called()
    trips["process"].assert_not_called()
    trips["async_process"].assert_not_awaited()
    trips["socket"].assert_not_called()
    trips["connection"].assert_not_awaited()
    trips["keyring"].assert_not_called()


def _opener(kind: str) -> Callable[[ServonautApp, Pilot], Awaitable[WorkspaceScreen]]:
    async def open_screen(app: ServonautApp, pilot: Pilot) -> WorkspaceScreen:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        screen = {"secrets": SecretsScreen, "list": SecretsListScreen,
                  "setup": SecretsSetupScreen}[kind]()
        await app.push_screen(screen)
        return screen
    return open_screen


def _plain(widget: Static) -> str:
    return widget.render().plain


async def _ready(screen: WorkspaceScreen) -> None:
    if isinstance(screen, SecretsScreen):
        await wait_until(lambda: bool(screen.query_one("#secrets_body").children))
    elif isinstance(screen, SecretsListScreen):
        await wait_until(lambda: len(screen.query(".secrets_list_name")) == len(NAMES))
    else:
        await wait_until(lambda: "bws CLI" in _plain(screen.query_one("#setup_preflight", Static)))


def _seed(screen: WorkspaceScreen) -> None:
    if isinstance(screen, SecretsSetupScreen):
        screen.query_one("#token_env", Input).value = "EXAMPLE_TOKEN_ENV"


def _state(screen: WorkspaceScreen) -> object:
    if isinstance(screen, SecretsScreen):
        body = screen.query_one("#secrets_body")
        return (tuple(body.children), _plain(screen.query_one("#secrets_status_pill", Static)))
    if isinstance(screen, SecretsListScreen):
        return (screen.query_one("#secrets_list_filter", Input).value,
                tuple(_plain(name) for name in screen.query(".secrets_list_name")))
    return (screen.query_one("#token_env", Input).value, screen._selected_project_id,
            _plain(screen.query_one("#setup_preflight", Static)))


# List explicitly focuses its filter; other screens use native DOM order.
# Rail and workspace controls do not take initial focus from content.
# open_case checks each screen's primary content target on arrival.
PRIMARY = {"secrets": "#secrets_body", "list": "#secrets_list_filter",
           "setup": "#secrets_setup_body"}
TARGETS = {
    "secrets": ("#secrets_body",),
    "list": ("#secrets_list_filter",),
    "setup": ("#token_env", "#list_projects", "#test_conn", "#save", "#project_list"),
}
KINDS = ("secrets", "list", "setup")
# Native columns and fractional layout policy are checked independently.
# A rounded content width can reach a boundary while its policy stays below it.
_MEASURED_BOUNDARIES = {
    'secrets': {
        ('chat-min', False): (
            BoundarySample((104, 50), 59, True, True),
            BoundarySample((105, 50), 60, False, True),
            BoundarySample((106, 50), 61, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((140, 50), 59, True, True),
            BoundarySample((141, 50), 60, True, True),
            BoundarySample((142, 50), 61, False, True),
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
    'list': {
        ('chat-min', False): (
            BoundarySample((92, 50), 47, True, True),
            BoundarySample((93, 50), 48, False, False),
            BoundarySample((94, 50), 49, False, False),
        ),
        ('chat-min', True): (
            BoundarySample((120, 50), 47, True, True),
            BoundarySample((121, 50), 48, True, True),
            BoundarySample((122, 50), 49, False, False),
        ),
        ('content-narrow', False): (
            BoundarySample((92, 50), 47, True, True),
            BoundarySample((93, 50), 48, False, False),
            BoundarySample((94, 50), 49, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((120, 50), 47, True, True),
            BoundarySample((121, 50), 48, True, True),
            BoundarySample((122, 50), 49, False, False),
        ),
    },
    'setup': {
        ('chat-min', False): (
            BoundarySample((106, 50), 61, True, True),
            BoundarySample((107, 50), 62, False, True),
            BoundarySample((108, 50), 63, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((143, 50), 61, True, True),
            BoundarySample((145, 50), 62, False, True),
            BoundarySample((146, 50), 63, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((151, 50), 91, False, True),
            BoundarySample((153, 50), 92, False, True),
            BoundarySample((154, 50), 93, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((180, 50), 91, False, True),
            BoundarySample((181, 50), 92, False, False),
            BoundarySample((182, 50), 93, False, False),
        ),
    },
}


CASES = tuple(
    ReflowCase(kind, _SecretsHost, _opener(kind), _ready, PRIMARY[kind],
               TARGETS[kind], _seed, _state, (), boundaries=_MEASURED_BOUNDARIES[kind])
    for kind in KINDS
)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=KINDS)
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("chat_open", [False, True])
async def test_secrets_workspace_pane_combinations(
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
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=KINDS)
async def test_secrets_workspace_native_state_survives_reflow(case: ReflowCase) -> None:
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await preserve_native_state(case, app, pilot, screen)
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=KINDS)
@pytest.mark.parametrize("kind", ["chat-min", "content-narrow"])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_secrets_workspace_uses_qualified_native_boundaries(
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
            assert case.state(screen) == baseline


async def _enter_rail(pilot: Pilot, screen: WorkspaceScreen) -> Sidebar:
    await pilot.press("shift+f6")
    sidebar = screen.query_one(Sidebar)
    await wait_until(lambda: sidebar.navigation_mode and sidebar.has_focus_within)
    return sidebar


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,key", [
    ("secrets", key) for key in ("r", "l", "c", "o", "u", "i", "g", "v", "s")
] + [("list", "r")])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_rail_focused_secrets_keys_have_no_side_effects(
    kind: str, key: str, navigation_visible: bool, _inert_boundaries: dict,
) -> None:
    case = next(case for case in CASES if case.name == kind)
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        provider = _inert_boundaries["provider"]
        before = (case.state(screen), provider.list_secrets.await_count,
                  app.auth_service.active_team_slug.await_count)
        sidebar = await _enter_rail(pilot, screen)
        await pilot.press(key)
        await pilot.pause()
        # Any pushed screen, refresh, browser or install would change these.
        assert app.screen is screen
        assert (case.state(screen), provider.list_secrets.await_count,
                app.auth_service.active_team_slug.await_count) == before
        assert sidebar.navigation_mode and sidebar.has_focus_within
        await pilot.press("escape")
        await wait_until(lambda: not sidebar.navigation_mode)
        assert app.screen is screen and app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("key,expected", [("l", SecretsListScreen), ("g", SecretsSetupScreen)])
async def test_secrets_navigation_keys_still_run_from_content(key: str, expected: type) -> None:
    case = next(case for case in CASES if case.name == "secrets")
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        await open_case(case, app, pilot)
        await pilot.press(key)
        await wait_until(lambda: isinstance(app.screen, expected))


@pytest.mark.asyncio
async def test_check_action_composes_rail_guard_before_passthrough() -> None:
    secrets_case = next(case for case in CASES if case.name == "secrets")
    app = secrets_case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(secrets_case, app, pilot)
        assert screen.check_action("open_upgrade", ()) is True
        await _enter_rail(pilot, screen)
        assert screen.check_action("open_upgrade", ()) is None
        assert screen.check_action("install_bws", ()) is None
    list_case = next(case for case in CASES if case.name == "list")
    app = list_case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(list_case, app, pilot)
        # The filter Input keeps the original passthrough for printable keys.
        assert app.focused is screen.query_one("#secrets_list_filter", Input)
        assert screen.check_action("refresh", ()) is None
        await pilot.press(*"api")
        await wait_until(lambda: screen.query_one("#secrets_list_filter", Input).value == "api")


@pytest.mark.asyncio
async def test_secret_names_only_and_list_filter_survive_chat_replacement(
    _inert_boundaries: dict, clipboard: _Clipboard,
) -> None:
    case = next(case for case in CASES if case.name == "list")
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        field = screen.query_one("#secrets_list_filter", Input)
        field.value = "db"

        def rendered() -> list[str]:
            return [_plain(widget) for widget in screen.query(".secrets_list_name")]

        # The filter really narrows the rendered rows, not just the field.
        await wait_until(lambda: rendered() == [NAMES[0]])
        await open_chat(app, pilot, screen)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        assert screen.has_class("-chat-replace") and not content(screen).display
        await pilot.resize_terminal(160, 50)
        await pilot.pause()
        assert field.value == "db" and content(screen).display
        assert rendered() == [NAMES[0]]
        await collapse_chat(app, pilot, screen)
        field.value = ""
        await wait_until(lambda: rendered() == NAMES)
        # Native mouse selection of a rendered name, through the app's existing
        # selection-copy route; the payload is the literal Unicode name.
        name = screen.query(".secrets_list_name")[1]
        name.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        await _drag(pilot, name, (0, 0), (len(NAMES[1]), 0))
        await wait_until(lambda: bool(clipboard.calls))
        assert clipboard.calls == [NAMES[1]]
        _inert_boundaries["provider"].list_secrets.assert_awaited_once_with()
        # Only names are listed; the provider is never asked for a value.
        assert not _inert_boundaries["provider"].get_secret.called


@pytest.mark.asyncio
async def test_compact_names_list_keeps_native_filter_rows_copy_and_return_reachable(
    _inert_boundaries: dict, clipboard: _Clipboard,
) -> None:
    # Neutral names reproduce the compact list without requesting secret values.
    names = ["db/app-1", "hooks/deploy"]
    provider = _inert_boundaries["provider"]
    provider.list_secrets.return_value = list(names)
    case = next(case for case in CASES if case.name == "list")
    app = case.app_factory(True)
    async with app.run_test(size=(80, 24), notifications=True) as pilot:
        screen = await open_case(case, app, pilot)
        outer = content(screen)
        records = screen.query_one("#secrets_list_records")
        body = screen.query_one("#secrets_list_body", VerticalScroll)
        field = screen.query_one("#secrets_list_filter", Input)
        summary = screen.query_one("#secrets_list_summary", Static)

        async def enter(target) -> None:
            await tab_to(pilot, target)
            await pilot.wait_for_scheduled_animations()
            await pilot.pause()
            assert app.focused is target

        def exposed(target) -> None:
            assert screen.query_one(Sidebar).display
            assert not screen.has_class("-chat-open")
            assert app.screen.region.contains_region(target.region)
            assert outer.scrollable_content_region.contains_region(target.region)
            hit = app.get_widget_at(*target.content_region.center)[0]
            assert hit is target or target in hit.ancestors

        def rendered_names() -> list[str]:
            return [_plain(widget) for widget in screen.query(".secrets_list_name")]

        def full_names() -> None:
            assert rendered_names() == names
            for widget, name in zip(screen.query(".secrets_list_name"), names):
                exposed(widget)
                assert body.scrollable_content_region.contains_region(widget.region)
                assert name in _painted(app, widget)

        assert app.focused is field
        assert screen.query_one(Sidebar).display
        assert not screen.has_class("-chat-open")
        assert body.scrollable_content_region.height >= 3
        # The outer scroller cannot reveal children clipped by this inner card.
        assert records.content_region.contains_region(body.region)
        await enter(body)
        exposed(body)
        full_names()
        assert "local — 2 secrets" in _painted(app, summary)
        name = screen.query(".secrets_list_name")[0]
        await _drag(pilot, name, (0, 0), (len(names[0]), 0))
        await wait_until(lambda: bool(clipboard.calls))
        assert clipboard.calls == [names[0]]

        await enter(field)
        exposed(field)
        await pilot.press(*"qa-no-match")
        await wait_until(lambda: not screen.query(".secrets_list_name") and bool(body.query(Static)))
        await pilot.pause()
        assert field.value == "qa-no-match"
        assert "qa-no-match" in _painted(app, field)
        await enter(body)
        empty = body.query_one(".secrets_list_card Static", Static)
        exposed(empty)
        assert "No names match the filter." in _painted(app, empty)
        assert "local — 2 secrets (showing 0 of 2)" in _painted(app, summary)
        assert screen._all_names == names

        await enter(field)
        await pilot.press("home", "shift+end", "backspace")
        await wait_until(lambda: len(screen.query(".secrets_list_name")) == len(names))
        await pilot.pause()
        assert field.value == ""
        await enter(body)
        full_names()
        for selector in ("#secrets_names_refresh", "#secrets_names_back"):
            button = screen.query_one(selector, Button)
            await enter(button)
            exposed(button)
            assert_button_label_painted(app, button)
        back = screen.query_one("#secrets_names_back", Button)
        assert await pilot.click(back)
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        assert app.workspace_state.navigation_visible
        provider.list_secrets.assert_awaited_once_with()
        provider.get_secret.assert_not_called()
        assert app._exception is None
