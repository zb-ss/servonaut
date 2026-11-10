"""Security workspaces retain native selection, permission gates and targets."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from textual.containers import VerticalScroll
from textual.pilot import Pilot
from textual.widgets import Button, DataTable, Input, RichLog, Select, Static

from servonaut.app import ServonautApp
from servonaut.config.accounts import AccountRef
from servonaut.config.schema import AppConfig
from servonaut.screens.cloudtrail_browser import CloudTrailBrowserScreen
from servonaut.screens.cloudwatch_browser import CloudWatchBrowserScreen
from servonaut.screens.findings import FindingDetailScreen, FindingsScreen
from servonaut.screens.ip_ban import IPBanScreen
from servonaut.services.api_client import PaymentRequiredError
from servonaut.services.cloudtrail_service import LookupPage
from servonaut.widgets.account_picker import AccountPicker
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import (
    BoundarySample, ReflowCase,
    assert_essential_targets as _assert_essential_targets,
    assert_layout, collapse_chat, content, open_case, open_chat,
    preserve_native_state, tab_to,
)
from tests.test_findings_screen import _finding, _mock_auth, _mock_findings_service
from tests.test_fleet_workspace_layout import _LayoutHost
from tests.test_selection_copy import _Clipboard
from tests.test_selection_copy import clipboard as clipboard
from tests.test_workspace_pilot import _click
from tests.test_workspace_reflow import _painted

pytestmark = pytest.mark.usefixtures("navigation_open")


MESSAGE = "GET /report café [literal] Ω from 1.1.1.1"
TRAIL = {
    "event_time": "2026-01-01 00:00:01", "event_name": "ReadResource",
    "username": "operator", "source_ip": "1.1.1.1", "resource_name": "web-1",
    "resource_type": "Example::Resource", "region": "us-east-1", "error_code": "",
    "raw_event": '{"message":"café Ω"}',
}
_VIOLATIONS: list[str] = []


def _refuse(name: str) -> None:
    _VIOLATIONS.append(name)
    raise AssertionError("Unexpected external operation: " + name)


class _SecurityHost(_LayoutHost):
    audit_path: Path | None = None

    def __init__(self, navigation_visible: bool = True, *, multi: bool = False) -> None:
        super().__init__(navigation_visible=navigation_visible)
        assert self.audit_path is not None
        config = AppConfig()
        config.ip_ban_audit_path = str(self.audit_path)
        config.cloudwatch_default_region = ""
        config.cloudtrail_default_region = ""

        def update(**changes: object) -> None:
            nonlocal config
            config = replace(config, **changes)

        self.config_manager = SimpleNamespace(get=lambda: config, update=update)
        self.account_refs = [AccountRef("aws", "primary", True)]
        if multi:
            self.account_refs.append(AccountRef("aws", "secondary", False))
        self.cloudwatch_service = SimpleNamespace(
            list_log_groups=AsyncMock(return_value=[{"name": "/logs/example"}]),
            get_log_events=AsyncMock(return_value=[{
                "timestamp": "2026-01-01 00:00:01", "message": MESSAGE,
                "log_stream": "stream-one",
            }]),
        )
        self.cloudtrail_service = SimpleNamespace(
            lookup_page=AsyncMock(return_value=LookupPage(events=[dict(TRAIL)], next_token=None)),
        )
        self.ip_ban_service = SimpleNamespace(
            get_configs=lambda: [SimpleNamespace(name="example-waf", method="waf", account="")],
            list_banned=AsyncMock(return_value=["1.1.1.1/32", "8.8.8.8/32"]),
            ban_ip=AsyncMock(side_effect=lambda *a, **kw: _refuse("ban")),
            unban_ip=AsyncMock(side_effect=lambda *a, **kw: _refuse("unban")),
        )
        self.auth_service = _mock_auth()
        self.findings_service = _mock_findings_service([
            _finding(title="Finding café [literal] Ω"),
        ])
        for name in ("acknowledge", "resolve", "suppress", "remediate", "remediate_preview",
                     "revert_preview", "revert", "await_remediation_outcome", "await_revert_outcome", "scan"):
            setattr(self.findings_service, name, AsyncMock(
                side_effect=lambda *a, _name=name, **kw: _refuse(_name),
            ))
        self.findings_service.stream_scan = Mock(side_effect=lambda **kw: _refuse("stream_scan"))
        self.theme = "servonaut"


@pytest.fixture(autouse=True)
def _fake_boundaries(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    _VIOLATIONS.clear()
    monkeypatch.setattr(_SecurityHost, "audit_path", tmp_path / "audit.json")
    (tmp_path / "audit.json").write_text("[]")
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    monkeypatch.setattr("servonaut.screens.cloudwatch_browser.provider_accounts", lambda app, provider: app.account_refs)
    monkeypatch.setattr("servonaut.screens.cloudtrail_browser.provider_accounts", lambda app, provider: app.account_refs)
    monkeypatch.setattr(CloudWatchBrowserScreen, "_fetch_ip_geo", AsyncMock(return_value=None))
    monkeypatch.setattr(CloudWatchBrowserScreen, "_fetch_abuse_info", AsyncMock(return_value=None))
    network = AsyncMock(side_effect=lambda *a, **kw: _refuse("network"))
    process = Mock(side_effect=lambda *a, **kw: _refuse("process"))
    keyring = Mock(side_effect=lambda *a, **kw: _refuse("keyring"))
    monkeypatch.setattr(asyncio.BaseEventLoop, "create_connection", network)
    monkeypatch.setattr("subprocess.Popen", process)
    monkeypatch.setattr("webbrowser.open", Mock(side_effect=lambda *a, **kw: _refuse("browser")))
    for name in ("get_password", "set_password", "delete_password"):
        monkeypatch.setattr("keyring." + name, keyring)
    yield
    assert not _VIOLATIONS
    network.assert_not_awaited()
    process.assert_not_called()
    keyring.assert_not_called()


async def assert_essential_targets(
    case: ReflowCase, app: ServonautApp, pilot: Pilot, screen: WorkspaceScreen,
) -> None:
    if not isinstance(screen, CloudWatchBrowserScreen):
        await _assert_essential_targets(case, app, pilot, screen)
        return
    detail = screen.query_one("#cloudwatch_detail", VerticalScroll)
    if not detail.max_scroll_y:
        await _assert_essential_targets(replace(case, painted_targets=()), app, pilot, screen)
        for selector, text in case.painted_targets:
            widget = screen.query_one(selector)
            widget.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            assert text in str(widget.content)
            assert text in " ".join(_painted(app, widget).split())
        return
    # Keep every original native control/label check; read the longer detail in
    # its real scroller rather than assuming its entire content fits one pose.
    await _assert_essential_targets(replace(case, painted_targets=()), app, pilot, screen)
    target = screen.query_one("#cloudwatch_detail_text", Static)
    source_content, source_plain = target.content, str(target.content)
    baseline, focused = case.state(screen), app.focused
    filter_input = screen.query_one("#cw_input_filter_pattern", Input)
    selection = filter_input.selection
    try:
        # Reverse traversal reaches the detail without refocusing the filter
        # Input (whose native focus behavior deliberately selects its value).
        for _ in range(len(app.screen.focus_chain) + 1):
            if app.focused is detail:
                break
            await pilot.press("shift+tab")
        else:
            pytest.fail("Native reverse Tab did not reach the event detail")
        await pilot.press("home")
        await wait_until(lambda: detail.scroll_y == 0)
        await pilot.pause()
        for line in source_plain.splitlines()[:2]:
            assert line in _painted(app, target)
        await pilot.press("end")
        await wait_until(lambda: detail.scroll_y == detail.max_scroll_y)
        await pilot.pause()
        assert detail.scroll_y > 0
        for selector, text in case.painted_targets:
            widget = screen.query_one(selector)
            assert text in str(widget.content)
            assert text in " ".join(_painted(app, widget).split())
        assert target.content is source_content and str(target.content) == source_plain
        assert case.state(screen) == baseline and filter_input.selection == selection
    finally:
        if focused is not None:
            await tab_to(pilot, focused)
        assert app.focused is focused
        assert target.content is source_content and str(target.content) == source_plain
        assert case.state(screen) == baseline and filter_input.selection == selection


PRIMARY = {
    "watch": "#cw_select_region", "trail": "#ct_select_region",
    "ban": "#ban_config_selector", "inbox": "#findings_table",
    "detail": "#finding_detail_body",
}


def _opener(kind: str) -> Callable[[ServonautApp, Pilot], Awaitable[WorkspaceScreen]]:
    async def open_screen(app: ServonautApp, pilot: Pilot) -> WorkspaceScreen:
        factories = {
            "watch": CloudWatchBrowserScreen, "trail": CloudTrailBrowserScreen,
            "ban": IPBanScreen, "inbox": FindingsScreen,
            "detail": lambda: FindingDetailScreen(_finding(title="Finding café [literal] Ω")),
        }
        screen = factories[kind]()
        await app.push_screen(screen)
        await pilot.pause()
        if kind == "watch":
            screen.query_one("#cw_select_region", Select).value = "us-east-1"
            await wait_until(lambda: app.cloudwatch_service.list_log_groups.await_count == 1)
            await wait_until(lambda: screen.query_one("#cw_select_log_group", Select).prompt == "Select log group")
            screen.query_one("#cw_select_log_group", Select).value = "/logs/example"
            await pilot.pause()
            await pilot.press("f5")
        elif kind == "trail":
            await pilot.press("f5")
        elif kind == "ban":
            assert app.focused is screen.query_one("#ban_config_selector")
            screen.query_one("#ban_config_selector", Select).value = "example-waf"
        await _ready(screen)
        # Explicit journey setup, not a guessed original native initial focus.
        screen.query_one(PRIMARY[kind]).focus()
        await pilot.pause()
        return screen
    return open_screen


async def _ready(screen: WorkspaceScreen) -> None:
    if isinstance(screen, CloudWatchBrowserScreen):
        await wait_until(lambda: bool(screen._events) and not screen.query_one("#cw_btn_fetch", Button).disabled)
    elif isinstance(screen, CloudTrailBrowserScreen):
        await wait_until(lambda: bool(screen._events) and not screen.query_one("#ct_btn_fetch", Button).disabled)
    elif isinstance(screen, IPBanScreen):
        await wait_until(lambda: screen.query_one("#banned_table", DataTable).row_count == 2)
    elif isinstance(screen, FindingsScreen):
        await wait_until(lambda: screen._gate_state == "active" and bool(screen._rows))
    else:
        await wait_until(lambda: bool(screen.query_one("#finding_detail_body").children))


def _seed(screen: WorkspaceScreen) -> None:
    if isinstance(screen, CloudWatchBrowserScreen):
        screen._selected_event_row = 0
        screen._show_event_detail(0)
        screen.query_one("#cw_input_filter_pattern", Input).value = "café Ω"
    elif isinstance(screen, CloudTrailBrowserScreen):
        screen._selected_event = screen._events[0]
        screen._show_event_detail(screen._selected_event)
    elif isinstance(screen, IPBanScreen):
        screen.query_one("#banned_table", DataTable).move_cursor(row=1)
        screen.query_one("#ip_input", Input).value = "1.1.1.1"


def _state(screen: WorkspaceScreen) -> object:
    if isinstance(screen, CloudWatchBrowserScreen):
        return (tuple(screen._events), screen._selected_event_row, screen._current_page,
                screen._account, screen.query_one("#cw_input_filter_pattern", Input).value)
    if isinstance(screen, CloudTrailBrowserScreen):
        return tuple(screen._events), screen._selected_event, screen._current_page, screen._account, screen._filter_values()
    if isinstance(screen, IPBanScreen):
        return (screen._field_binding, tuple(screen._banned_real), screen._selected_config,
                screen.query_one("#ip_input", Input).value,
                screen.query_one("#banned_table", DataTable).cursor_row)
    if isinstance(screen, FindingsScreen):
        return screen._gate_state, tuple(screen._rows), screen._offset, screen._status_filter, screen._severity_filter
    return screen._finding.copy(), screen._changed, screen.query_one("#finding_detail_body")


# No computed terminal-width fixtures: native policy samples must be qualified.
# Qualified native columns and separately measured layout policy.
_MEASURED_BOUNDARIES = {
    'watch': {
        ('chat-min', False): (
            BoundarySample((131, 50), 79, True, True),
            BoundarySample((133, 50), 80, True, True),
            BoundarySample((134, 50), 81, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((168, 50), 79, True, True),
            BoundarySample((169, 50), 80, False, True),
            BoundarySample((170, 50), 81, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((188, 50), 124, False, True),
            BoundarySample((189, 50), 125, False, False),
            BoundarySample((190, 50), 126, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((213, 50), 124, False, True),
            BoundarySample((214, 50), 125, False, False),
            BoundarySample((215, 50), 126, False, False),
        ),
    },
    'trail': {
        ('chat-min', False): (
            BoundarySample((131, 50), 79, True, True),
            BoundarySample((133, 50), 80, True, True),
            BoundarySample((134, 50), 81, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((168, 50), 79, True, True),
            BoundarySample((169, 50), 80, False, True),
            BoundarySample((170, 50), 81, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((188, 50), 124, False, True),
            BoundarySample((189, 50), 125, False, False),
            BoundarySample((190, 50), 126, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((213, 50), 124, False, True),
            BoundarySample((214, 50), 125, False, False),
            BoundarySample((215, 50), 126, False, False),
        ),
    },
    'ban': {
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
    'inbox': {
        ('chat-min', False): (
            BoundarySample((167, 50), 103, True, True),
            BoundarySample((168, 50), 104, False, True),
            BoundarySample((169, 50), 105, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((192, 50), 103, True, True),
            BoundarySample((193, 50), 104, False, True),
            BoundarySample((194, 50), 105, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((183, 50), 119, False, True),
            BoundarySample((184, 50), 120, False, False),
            BoundarySample((185, 50), 121, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((208, 50), 119, False, True),
            BoundarySample((209, 50), 120, False, False),
            BoundarySample((210, 50), 121, False, False),
        ),
    },
    'detail': {
        ('chat-min', False): (
            BoundarySample((131, 50), 79, True, True),
            BoundarySample((133, 50), 80, True, True),
            BoundarySample((134, 50), 81, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((168, 50), 79, True, True),
            BoundarySample((169, 50), 80, False, True),
            BoundarySample((170, 50), 81, False, True),
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


CASES = (
    ReflowCase("watch", _SecurityHost, _opener("watch"), _ready, PRIMARY["watch"],
               ("#cw_select_region", "#cw_select_log_group", "#cw_select_time_range",
                "#cw_input_filter_pattern", "#cw_btn_fetch", "#cw_btn_back", "#cloudwatch_events_table",
                "#cloudwatch_ips_table", "#cw_btn_ban_ip", "#cw_btn_prev", "#cw_btn_next"),
               _seed, _state, (("#cloudwatch_detail_text", MESSAGE),), boundaries=_MEASURED_BOUNDARIES['watch']),
    ReflowCase("trail", _SecurityHost, _opener("trail"), _ready, PRIMARY["trail"],
               ("#ct_select_region", "#ct_select_time_range", "#ct_select_event_name",
                "#ct_select_username", "#ct_select_resource_type", "#ct_btn_fetch", "#ct_btn_back",
                "#cloudtrail_table", "#ct_btn_prev", "#ct_btn_next"), _seed, _state, (), boundaries=_MEASURED_BOUNDARIES['trail']),
    ReflowCase("ban", _SecurityHost, _opener("ban"), _ready, PRIMARY["ban"],
               ("#ban_config_selector", "#ip_input", "#btn_ban", "#btn_unban", "#btn_refresh",
                "#btn_back", "#banned_table", "#audit_log"), _seed, _state, (), boundaries=_MEASURED_BOUNDARIES['ban']),
    ReflowCase("inbox", _SecurityHost, _opener("inbox"), _ready, PRIMARY["inbox"],
               ("#findings_table", "#btn_findings_scan", "#btn_findings_refresh", "#btn_findings_open",
                "#btn_findings_status_filter", "#btn_findings_severity_filter"), _seed, _state, (), boundaries=_MEASURED_BOUNDARIES['inbox']),
    ReflowCase("detail", _SecurityHost, _opener("detail"), _ready, PRIMARY["detail"],
               ("#finding_detail_body", "#btn_finding_ack", "#btn_finding_resolve",
                "#btn_finding_suppress", "#btn_finding_back"), _seed, _state, (), boundaries=_MEASURED_BOUNDARIES['detail']),
)
IDS = [case.name for case in CASES]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=IDS)
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("navigation_visible,chat_open", [
    (False, False), (False, True), (True, False), (True, True),
])
async def test_security_workspace_visibility_and_every_native_target(
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
async def test_security_native_state_selection_and_tab_round_trip(case: ReflowCase) -> None:
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        # Disabled pager controls still need paint/hit geometry, not Tab stops.
        traversable = replace(case, essential_targets=tuple(
            selector for selector in case.essential_targets
            if screen.query_one(selector).focusable
        ))
        await preserve_native_state(traversable, app, pilot, screen)
        await assert_essential_targets(case, app, pilot, screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=IDS)
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("kind", ["chat-min", "content-narrow"])
async def test_security_qualified_native_boundaries(
    case: ReflowCase, navigation_visible: bool, kind: str,
) -> None:
    samples = case.boundary_samples(kind, navigation_visible)
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=samples[0].size) as pilot:
        screen = await open_case(case, app, pilot)
        await open_chat(app, pilot, screen)
        threshold = screen.CHAT_MIN_CONTENT_WIDTH if kind == "chat-min" else screen.CONTENT_NARROW_WIDTH
        assert [sample.native_content_width for sample in samples] == [threshold - 1, threshold, threshold + 1]
        baseline = case.state(screen)
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
            assert case.state(screen) == baseline


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,key", [("watch", "y"), ("trail", "y"), ("ban", "y"), ("inbox", "s"), ("detail", "a")])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_security_navigation_mode_does_not_copy_scan_or_triage(
    kind: str, key: str, navigation_visible: bool, clipboard: _Clipboard,
) -> None:
    app = _SecurityHost(navigation_visible)
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
        assert clipboard.calls == [] and app.clipboard == "retain clipboard sentinel"
        assert sidebar.navigation_mode and not _VIOLATIONS


@pytest.mark.asyncio
@pytest.mark.parametrize("prefill", ["", "1.1.1.1"])
async def test_ip_ban_preserves_original_conditional_initial_focus(prefill: str) -> None:
    app = _SecurityHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = IPBanScreen(prefill_ip=prefill)
        await app.push_screen(screen)
        await pilot.pause()
        expected = "#ip_input" if prefill else "#ban_config_selector"
        assert app.focused is screen.query_one(expected)
        await open_chat(app, pilot, screen)
        await collapse_chat(app, pilot, screen)
        assert app.focused is screen.query_one(expected)
        assert screen._prefill_real_ip == prefill


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["watch", "trail"])
@pytest.mark.parametrize("writer_succeeds", [False, True])
async def test_security_selected_record_copy_survives_native_reflow(
    kind: str, writer_succeeds: bool, clipboard: _Clipboard,
) -> None:
    clipboard.succeeds = writer_succeeds
    app = _SecurityHost(False)
    case = next(case for case in CASES if case.name == kind)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await open_chat(app, pilot, screen)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        await collapse_chat(app, pilot, screen)
        selector = "#cloudwatch_events_table" if kind == "watch" else "#cloudtrail_table"
        screen.query_one(selector).focus()
        await pilot.press("y")
        await pilot.pause()
        assert len(clipboard.calls) == 1
        if kind == "watch":
            assert clipboard.calls == [MESSAGE]
        else:
            assert 'Raw Event:\n' + TRAIL["raw_event"] in clipboard.calls[0]
            assert "ReadResource" in clipboard.calls[0]
        if not writer_succeeds:
            assert app.clipboard == clipboard.calls[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("gate", ["unauth", "upgrade", "unavailable", "server-402"])
async def test_findings_gate_survives_workspace_round_trip_without_scan(gate: str) -> None:
    app = _SecurityHost(False)
    app.auth_service = _mock_auth(authenticated=gate != "unauth", entitled=gate != "upgrade")
    service = app.findings_service
    if gate == "unavailable":
        app.findings_service = None
    elif gate == "server-402":
        service.list_findings.side_effect = PaymentRequiredError(code="payment_required", message="Plan required", status=402)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = FindingsScreen()
        await app.push_screen(screen)
        expected = "upgrade" if gate == "server-402" else gate
        await wait_until(lambda: screen._gate_state == expected)
        await pilot.press("s")
        await open_chat(app, pilot, screen)
        await collapse_chat(app, pilot, screen)
        await pilot.press("s")
        assert screen._gate_state == expected and not screen._scanning
        assert screen.query_one("#findings_state_body").display
        assert not screen.query_one("#findings_table_card").display
        if gate in ("unauth", "upgrade", "unavailable"):
            service.list_findings.assert_not_awaited()
        assert not _VIOLATIONS


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["watch", "trail"])
async def test_security_multiple_accounts_keep_filters_and_account_value(kind: str) -> None:
    app = _SecurityHost(True, multi=True)
    case = next(case for case in CASES if case.name == kind)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        picker = screen.query_one(AccountPicker)
        assert picker.display and picker.account == "primary"
        await assert_essential_targets(case, app, pilot, screen)
        panel = await open_chat(app, pilot, screen)
        assert_layout(app, screen)
        if content(screen).display:
            await assert_essential_targets(case, app, pilot, screen)
        await collapse_chat(app, pilot, screen)
        assert picker.account == "primary" and panel.is_attached


@pytest.mark.asyncio
@pytest.mark.parametrize("case,theme", [(CASES[0], "ansi-dark"), (CASES[1], "servonaut-light"), (CASES[2], "ansi-light"), (CASES[4], "servonaut")])
async def test_security_representative_palettes_keep_native_targets(case: ReflowCase, theme: str) -> None:
    app = case.app_factory(True)
    app.theme = theme
    assert app.config_manager.get().theme == theme
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await assert_essential_targets(case, app, pilot, screen)
        assert_layout(app, screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_ip_ban_empty_short_view_keeps_table_header_and_audit_readable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, navigation_visible: bool,
) -> None:
    app = _SecurityHost(navigation_visible)
    configs = Mock(return_value=[])
    monkeypatch.setattr(app.ip_ban_service, "get_configs", configs)
    app.config_manager.update(ip_ban_audit_path=str(tmp_path / "absent-audit.json"))
    config = app.config_manager.get()
    case = next(case for case in CASES if case.name == "ban")
    async with app.run_test(size=(100, 30)) as pilot:
        screen = IPBanScreen()
        await app.push_screen(screen)
        table = screen.query_one("#banned_table", DataTable)
        await wait_until(lambda: len(table.columns) == 4)
        await pilot.pause()
        hint = screen.query_one("#ip_ban_empty_hint", Static)
        audit = screen.query_one("#audit_log", RichLog)
        assert hint.display and table.show_header and table.row_count == 0
        assert app.focused is screen.query_one("#ban_config_selector", Select)
        assert screen.query_one("#ban_config_selector", Select).value is Select.NULL
        assert_layout(app, screen)
        baseline, config_reads = _state(screen), configs.call_count
        # Keep every existing field/action hit and complete button-label check.
        await assert_essential_targets(case, app, pilot, screen)
        for target, expected in (
            (hint, str(hint.content)),
            (table, "IP / CIDR"),
            (audit, "No audit log entries yet."),
        ):
            target.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            hit = app.get_widget_at(*target.region.center)[0]
            assert hit is target or target in hit.ancestors
            # Read native content cells so borders do not interrupt wrapped text.
            region = target.content_region
            assert screen.region.contains_region(region)
            rows = screen._compositor.render_strips()
            painted = "\n".join(rows[y].crop(region.x, region.right).text
                                for y in range(region.y, region.bottom))
            assert " ".join(expected.split()) in " ".join(painted.split())
        assert _state(screen) == baseline and configs.call_count == config_reads
        assert app.config_manager.get() is config
        assert screen.query_one("#ban_config_selector", Select).value is Select.NULL
        app.ip_ban_service.list_banned.assert_not_awaited()
        app.ip_ban_service.ban_ip.assert_not_awaited()
        app.ip_ban_service.unban_ip.assert_not_awaited()
