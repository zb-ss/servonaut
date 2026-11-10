"""Native account and certificate workspaces preserve state and worker targets."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from textual.pilot import Pilot
from textual.widgets import Button, Select, Static

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig
from servonaut.screens.ca import CaScreen, _EVERY_ENROLLED_SERVER
from servonaut.screens.login import LoginScreen
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import (
    BoundarySample, ReflowCase, assert_essential_targets, assert_layout, collapse_chat, content,
    open_case, open_chat, preserve_native_state,
)
from tests.test_ca_screen_pickers import _PickerService, _team_settled
from tests.test_fleet_workspace_layout import _LayoutHost
from tests.test_login_screen import _click_ready_login
from tests.test_workspace_pilot import _click

pytestmark = pytest.mark.usefixtures("navigation_open")


_VIOLATIONS: list[str] = []


def _refuse(name: str) -> None:
    _VIOLATIONS.append(name)
    raise AssertionError("Unexpected access operation: " + name)


class _Auth:
    """Only the real authentication API used by the account and sidebar."""

    def __init__(self, authenticated: bool = False) -> None:
        self.is_authenticated = authenticated
        self.plan = "solo"
        self._token = SimpleNamespace(email="person@example.invalid") if authenticated else None  # leak-guard:allow — synthetic address
        self.config_sync = True
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.finished: list[str] = []
        self.gates: dict[str, asyncio.Event] = {}
        self.failures: dict[str, Exception] = {}
        self.valid = True
        self.poll_result = True

    def has_feature(self, feature: str) -> bool:
        return self.is_authenticated and feature == "config_sync" and self.config_sync

    def get_plan_features(self) -> dict[str, bool]:
        return {"config_sync": self.config_sync, "premium_ai": True, "allow_dangerous_ai_tools": True}

    def _get_cached_entitlements(self) -> dict[str, object]:
        return {"email": "person@example.invalid", "plan": self.plan, "features": self.get_plan_features()}  # leak-guard:allow — synthetic address

    async def _answer(self, name: str, **arguments: object) -> None:
        self.calls.append((name, arguments))
        if name in self.gates:
            await self.gates[name].wait()
        if name in self.failures:
            raise self.failures[name]
        self.finished.append(name)

    async def validate_token(self) -> bool:
        await self._answer("validate_token")
        return self.valid

    async def start_device_flow(self, *, client_kind: str = "cli") -> dict[str, object]:
        await self._answer("start_device_flow", client_kind=client_kind)
        return {"device_code": "fixture-device-code", "user_code": "ABCD-1234",
                "verification_uri": "https://example.invalid/activate", "interval": 1}

    async def poll_for_token(self, device_code: str, interval: int = 5, max_wait_seconds: int = 120, *, client_kind: str = "cli") -> bool:
        await self._answer("poll_for_token", device_code=device_code, interval=interval, client_kind=client_kind)
        self.is_authenticated = self.poll_result
        return self.poll_result

    async def logout(self) -> None:
        await self._answer("logout")
        self.is_authenticated = False

    def sign_out_locally(self) -> None:
        self.calls.append(("sign_out_locally", {}))
        self.is_authenticated = False


class _CA(_PickerService):
    """Reuse recorded read fixtures; explicitly authorize each fake mutation."""

    def __init__(self) -> None:
        super().__init__()
        self.allowed_actions: set[str] = set()
        self.cancelled: list[str] = []

    async def _answer(self, name: str, **kwargs: object) -> None:
        if name in {"ca_enable", "ca_audit", "ca_enroll", "ca_deliver_krl", "ca_break_glass_scan"} and name not in self.allowed_actions:
            _refuse(name)
        try:
            await super()._answer(name, **kwargs)
        except asyncio.CancelledError:
            self.cancelled.append(name)
            raise


class _AccessHost(_LayoutHost):
    def __init__(self, navigation_visible: bool = True, *, state: str = "out") -> None:
        super().__init__(navigation_visible=navigation_visible)
        config = AppConfig()

        def update(**changes: object) -> None:
            nonlocal config
            config = replace(config, **changes)

        self.config_manager = SimpleNamespace(get=lambda: config, update=update)
        self.auth_service = None if state == "unavailable" else _Auth(state == "in")
        self.vault_command_service = _CA()
        self.config_sync_service = None
        self.init_paid_services = Mock()
        self.on_user_login_success = Mock()
        self.on_user_logout = Mock()
        self.notes: list[tuple[str, dict[str, object]]] = []
        self.theme = "servonaut"

    def notify(self, message: str, **kwargs: object) -> None:
        self.notes.append((message, kwargs))
        super().notify(message, **kwargs)


@pytest.fixture(autouse=True)
def _fake_access_boundaries(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    _VIOLATIONS.clear()
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    monkeypatch.setattr("servonaut.screens.login.endpoint_override_errors", lambda names: [])
    network = AsyncMock(side_effect=lambda *a, **kw: _refuse("network"))
    process = Mock(side_effect=lambda *a, **kw: _refuse("subprocess"))
    keyring = Mock(side_effect=lambda *a, **kw: _refuse("keyring"))
    monkeypatch.setattr(asyncio.BaseEventLoop, "create_connection", network)
    monkeypatch.setattr("subprocess.Popen", process)
    for name in ("get_password", "set_password", "delete_password"):
        monkeypatch.setattr("keyring." + name, keyring)
    yield
    network.assert_not_awaited()
    process.assert_not_called()
    keyring.assert_not_called()
    assert not _VIOLATIONS


async def _ready(screen: WorkspaceScreen) -> None:
    if isinstance(screen, CaScreen):
        await wait_until(lambda: screen._teams_listed)
        if screen.query_one("#ca_team", Select).value is Select.NULL:
            # Textual schedules focus on the app queue after team loading.
            await wait_until(lambda: screen.app.focused is screen.query_one("#ca_team"))
            assert screen.app.focused is screen.query_one("#ca_team")
            screen.query_one("#ca_team", Select).value = "ops"
        await _team_settled(screen.app._access_pilot, screen)
        await wait_until(lambda: not screen.query_one("#ca_audit", Button).disabled)
    else:
        await wait_until(lambda: any(screen.query_one(selector).display for selector in (
            "#no_httpx_notice", "#logged_out_container", "#device_flow_container", "#logged_in_container",
        )))


def _opener(state: str) -> Callable[[ServonautApp, Pilot], Awaitable[WorkspaceScreen]]:
    async def open_screen(app: ServonautApp, pilot: Pilot) -> WorkspaceScreen:
        app._access_pilot = pilot
        screen = CaScreen() if state == "ca" else LoginScreen()
        await app.push_screen(screen)
        if state == "flow":
            app.auth_service.gates["poll_for_token"] = asyncio.Event()
            await _click_ready_login(pilot)
            await wait_until(lambda: any(name == "poll_for_token" for name, args in app.auth_service.calls))
        await _ready(screen)
        # Journey setup is distinct from the original initial-focus oracle below.
        screen.query_one(PRIMARY[state]).focus()
        await pilot.pause()
        return screen
    return open_screen


PRIMARY = {"unavailable": "#login_container", "out": "#btn_login", "in": "#btn_back",
           "flow": "#btn_cancel_login", "ca": "#ca_team"}
TARGETS = {
    "unavailable": ("#no_httpx_notice", "#btn_back"),
    "out": ("#btn_login", "#btn_back"),
    "in": ("#account_info", "#plan_info", "#btn_logout", "#btn_logout_local", "#btn_back"),
    "flow": ("#device_url", "#device_code", "#device_status", "#btn_cancel_login"),
    "ca": ("#ca_team", "#ca_server", "#ca_break_glass", "#ca_refresh", "#ca_audit",
           "#ca_enroll", "#ca_krl", "#ca_break_glass_scan"),
}


def _seed(screen: WorkspaceScreen) -> None:
    if isinstance(screen, CaScreen):
        screen.query_one("#ca_server", Select).value = _EVERY_ENROLLED_SERVER


def _state(screen: WorkspaceScreen) -> object:
    if isinstance(screen, CaScreen):
        return tuple(screen.query_one(selector, Select).value for selector in ("#ca_team", "#ca_server", "#ca_break_glass")), screen._active_team, screen._picker_state.copy(), screen._action_running
    return (screen._polling, screen._device_code, screen._return_to,
            tuple(screen.query_one(selector).display for selector in (
                "#no_httpx_notice", "#logged_out_container", "#device_flow_container", "#logged_in_container",
                "#login_actions", "#btn_back", "#btn_logout", "#btn_logout_local",
            )))


# Explicit native policy/width samples remain absent until a serial qualification.
# Qualified native columns and separately measured layout policy.
_MEASURED_BOUNDARIES = {
    'unavailable': {
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
            BoundarySample((163, 50), 99, False, True),
            BoundarySample((164, 50), 100, False, False),
            BoundarySample((165, 50), 101, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((188, 50), 99, False, True),
            BoundarySample((189, 50), 100, False, False),
            BoundarySample((190, 50), 101, False, False),
        ),
    },
    'out': {
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
            BoundarySample((163, 50), 99, False, True),
            BoundarySample((164, 50), 100, False, False),
            BoundarySample((165, 50), 101, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((188, 50), 99, False, True),
            BoundarySample((189, 50), 100, False, False),
            BoundarySample((190, 50), 101, False, False),
        ),
    },
    'in': {
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
            BoundarySample((163, 50), 99, False, True),
            BoundarySample((164, 50), 100, False, False),
            BoundarySample((165, 50), 101, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((188, 50), 99, False, True),
            BoundarySample((189, 50), 100, False, False),
            BoundarySample((190, 50), 101, False, False),
        ),
    },
    'flow': {
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
            BoundarySample((163, 50), 99, False, True),
            BoundarySample((164, 50), 100, False, False),
            BoundarySample((165, 50), 101, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((188, 50), 99, False, True),
            BoundarySample((189, 50), 100, False, False),
            BoundarySample((190, 50), 101, False, False),
        ),
    },
    'ca': {
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
            BoundarySample((145, 50), 87, False, True),
            BoundarySample((146, 50), 88, False, True),
            BoundarySample((147, 50), 89, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((176, 50), 87, False, True),
            BoundarySample((177, 50), 88, False, False),
            BoundarySample((178, 50), 89, False, False),
        ),
    },
}


CASES = tuple(ReflowCase(
    state, lambda visible, state=state: _AccessHost(visible, state=state),
    _opener(state), _ready, PRIMARY[state], TARGETS[state], _seed, _state, (), boundaries=_MEASURED_BOUNDARIES[state],
) for state in PRIMARY)
IDS = [case.name for case in CASES]
ORIGINAL_LOGIN_FOCUS: dict[str, str | None] | None = {
    'unavailable': 'login_container',
    'out': 'login_container',
    'in': 'login_container',
    'flow': None,
}
ORIGINAL_BUSY_RAIL: dict[bool, tuple[str, bool, bool]] | None = {
    False: ('InstanceListScreen', False, True),
    True: ('InstanceListScreen', False, True),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=IDS)
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("navigation_visible,chat_open", [(False, False), (False, True), (True, False), (True, True)])
async def test_access_four_visibility_states(case: ReflowCase, size: tuple[int, int], navigation_visible: bool, chat_open: bool) -> None:
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=size) as pilot:
        screen = await open_case(case, app, pilot)
        before = case.state(screen)
        if chat_open:
            await open_chat(app, pilot, screen)
        assert_layout(app, screen)
        assert screen.query_one(Sidebar).display is navigation_visible
        assert case.state(screen) == before
        if content(screen).display:
            await assert_essential_targets(case, app, pilot, screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=IDS)
async def test_access_state_native_tab_and_chat_restore(case: ReflowCase) -> None:
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        traversable = replace(case, essential_targets=tuple(s for s in case.essential_targets if screen.query_one(s).focusable))
        await preserve_native_state(traversable, app, pilot, screen)
        await assert_essential_targets(case, app, pilot, screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=IDS)
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("kind", ["chat-min", "content-narrow"])
async def test_access_qualified_native_boundaries(case: ReflowCase, navigation_visible: bool, kind: str) -> None:
    samples = case.boundary_samples(kind, navigation_visible)
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=samples[0].size) as pilot:
        screen = await open_case(case, app, pilot)
        await open_chat(app, pilot, screen)
        threshold = screen.CHAT_MIN_CONTENT_WIDTH if kind == "chat-min" else screen.CONTENT_NARROW_WIDTH
        assert [sample.native_content_width for sample in samples] == [threshold - 1, threshold, threshold + 1]
        before = case.state(screen)
        for sample in samples:
            await pilot.resize_terminal(*sample.size)
            await pilot.pause()
            assert screen.has_class("-chat-replace") is sample.expected_replace
            assert screen.has_class("-content-narrow") is sample.expected_content_narrow
            assert_layout(app, screen)
            if sample.expected_replace:
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
            assert case.state(screen) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["unavailable", "out", "in", "flow"])
async def test_login_original_initial_focus_not_guessed(state: str) -> None:
    assert ORIGINAL_LOGIN_FOCUS is not None and state in ORIGINAL_LOGIN_FOCUS, "Qualify original login focus before migrating the oracle"
    app = _AccessHost(False, state=state)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = LoginScreen()
        await app.push_screen(screen)
        if state == "flow":
            app.auth_service.gates["poll_for_token"] = asyncio.Event()
            await _click_ready_login(pilot)
            await wait_until(lambda: screen._device_code is not None)
        await pilot.pause()
        assert (app.focused.id if app.focused else None) == ORIGINAL_LOGIN_FOCUS[state]


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_ca_native_rail_refresh_guard_and_content_positive_control(navigation_visible: bool) -> None:
    app = _AccessHost(navigation_visible)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(CASES[-1], app, pilot)
        service = app.vault_command_service
        before = list(service.calls)
        await pilot.press("shift+f6")
        sidebar = screen.query_one(Sidebar)
        await wait_until(lambda: sidebar.navigation_mode and sidebar.has_focus_within)
        await pilot.press("r")
        await pilot.pause()
        assert service.calls == before and not screen._action_running
        await pilot.press("escape", "r")
        await wait_until(lambda: len(service.calls) > len(before))
        assert len(service.calls_to("ca_status")) == 2
        assert not _VIOLATIONS


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_ca_busy_native_back_refuses_then_exact_target_finishes(navigation_visible: bool) -> None:
    app = _AccessHost(navigation_visible)
    service = app.vault_command_service
    service.allowed_actions.add("ca_audit")
    gate = service.gates["ca_audit"] = asyncio.Event()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(CASES[-1], app, pilot)
        await _click(pilot, "#ca_audit")
        await wait_until(lambda: screen._action_running and bool(service.calls_to("ca_audit")))
        busy = screen.query_one("#ca_busy")
        assert busy.is_active and "Auditing the certificate issuance chain" in busy.message
        await pilot.press("escape")
        assert app.screen is screen and screen._action_running
        assert any("still running" in message for message, kwargs in app.notes)
        assert service.calls_to("ca_audit") == [{"team": "ops"}]
        gate.set()
        await wait_until(lambda: not screen._action_running)
        await wait_until(lambda: not busy.is_active)
        assert service.finished.count("ca_audit") == 1
        assert "ops" in screen._active_team


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_ca_busy_native_rail_request_matches_qualified_original_policy(navigation_visible: bool) -> None:
    assert ORIGINAL_BUSY_RAIL is not None and navigation_visible in ORIGINAL_BUSY_RAIL, "Qualify existing busy route/worker behavior; do not invent a hold"
    app = _AccessHost(navigation_visible)
    service = app.vault_command_service
    service.allowed_actions.add("ca_audit")
    gate = service.gates["ca_audit"] = asyncio.Event()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(CASES[-1], app, pilot)
        await _click(pilot, "#ca_audit")
        await wait_until(lambda: screen._action_running)
        sidebar = screen.query_one(Sidebar)
        if not sidebar.display:
            await _click(pilot, "#workspace_navigation")
        core = sidebar.query_one("#section_core")
        if core.collapsed:
            header = core.query_one(".section-header", Button)
            assert header.region.area and app.get_widget_at(*header.region.center)[0] is header
            await _click(pilot, "#section_core > .section-header")
            await wait_until(lambda: not core.collapsed)
            await pilot.pause()
        target = sidebar.query_one("#nav_list", Button)
        assert target.region.area and target.region.intersection(screen.region) == target.region
        assert app.get_widget_at(*target.region.center)[0] is target
        await _click(pilot, "#nav_list")
        await pilot.pause()
        assert service.calls_to("ca_audit") == [{"team": "ops"}]
        actual = (type(app.screen).__name__, "ca_audit" in service.finished, "ca_audit" in service.cancelled)
        assert actual == ORIGINAL_BUSY_RAIL[navigation_visible]
        gate.set()


@pytest.mark.asyncio
@pytest.mark.parametrize("case,theme", [(CASES[1], "servonaut"), (CASES[2], "servonaut-light"), (CASES[3], "ansi-dark"), (CASES[4], "ansi-light")])
async def test_access_representative_named_palettes(case: ReflowCase, theme: str) -> None:
    app = case.app_factory(True)
    app.theme = theme
    assert app.config_manager.get().theme == theme
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await assert_essential_targets(case, app, pilot, screen)
        assert_layout(app, screen)
