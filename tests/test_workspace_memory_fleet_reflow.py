"""Memory workspace consumers retain drafts, selections and consent boundaries."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from textual.pilot import Pilot
from textual.widgets import Button, Checkbox, DataTable, Markdown, Select, SelectionList

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig
from servonaut.screens.fleet_memory import FleetMemoryScreen
from servonaut.screens.memory_drift import MemoryDriftScreen
from servonaut.screens.memory_key_change import MemberKeyChangeScreen
from servonaut.screens.memory_share import ShareInstanceScreen
from servonaut.screens.memory_summary import MemorySummaryScreen
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import (
    BoundarySample, ReflowCase, assert_essential_targets, assert_layout, collapse_chat, content,
    open_case, open_chat, preserve_native_state,
)
from tests.test_fleet_memory_live_update import _make_memory_service
from tests.test_fleet_workspace_layout import _LayoutHost
from tests.test_memory_key_change_screen import _change
from tests.test_memory_screens import _auth_with_feature, _make_drift_service
from tests.test_selection_copy import _Clipboard
from tests.test_selection_copy import clipboard as clipboard


SUMMARY = "# Local summary\n\nFacts café [literal] Ω.\n"
_REAL_FLEET_APP = FleetMemoryScreen.__dict__["app"]
_VIOLATIONS: list[str] = []


def _refuse(name: str) -> None:
    _VIOLATIONS.append(name)
    raise AssertionError("Unexpected memory operation: " + name)


def _event() -> SimpleNamespace:
    return SimpleNamespace(
        id="drift-one", instance_id="id-web-1", module="os", severity="medium",
        detected_at="2026-01-01T00:00:00Z", acknowledged_at=None,
        old_hash="old-hash", new_hash="new-hash", old_envelope_id="old-one",
        new_envelope_id="new-one",
    )


class _MemoryHost(_LayoutHost):
    def __init__(self, navigation_visible: bool = True) -> None:
        super().__init__(navigation_visible=navigation_visible)
        config = AppConfig()

        def update(**changes: object) -> None:
            nonlocal config
            config = replace(config, **changes)

        self.config_manager = SimpleNamespace(get=lambda: config, update=update)
        self.auth_service = _auth_with_feature({"memory_team_share": True, "memory_drift": True})
        self.auth_service.list_teams = AsyncMock(return_value=[{"name": "Example Team", "slug": "example-team"}])
        self.prompt_memory_sync_unlock = AsyncMock(return_value=None)
        self._refresh_fleet_auto_scan_loop = Mock(side_effect=lambda: _refuse("auto scan"))
        self.memory_sync_service = None
        self.shared_memory_reader = None
        memory_reads = _make_memory_service(module_map={
            row["id"]: {"os": {"probed_at": "2026-01-01T00:00:00Z"}} for row in self.instances
        })
        # Expose only real service seams; unknown names must not become mocks.
        self.memory_service = SimpleNamespace(
            snapshot_stale_seconds=memory_reads.snapshot_stale_seconds,
            is_memory_disabled=memory_reads.is_memory_disabled,
            get_all_modules=memory_reads.get_all_modules,
            clear=Mock(side_effect=lambda *a, **kw: _refuse("clear")),
            build=AsyncMock(side_effect=lambda *a, **kw: _refuse("build")),
            build_report=AsyncMock(side_effect=lambda *a, **kw: _refuse("build report")),
            refresh=AsyncMock(side_effect=lambda *a, **kw: _refuse("refresh")),
            refresh_report=AsyncMock(side_effect=lambda *a, **kw: _refuse("refresh report")),
        )
        self.fleet_service = SimpleNamespace(get_merged_fleet=AsyncMock(return_value=[
            {**row, "provider": "custom", "source": "local", "modules": 1}
            for row in self.instances
        ]))
        self.fleet_scan_service = SimpleNamespace(
            last_reasons={},
            eligible_instances=Mock(return_value=list(self.instances)),
            skipped_instances=Mock(return_value=[]),
            scan=AsyncMock(side_effect=lambda *a, **kw: _refuse("fleet scan")),
        )
        self.start_fleet_manual_scan = Mock(side_effect=lambda *a, **kw: _refuse("start fleet scan"))
        self.drift_service = _make_drift_service([_event()])
        self.drift_service.acknowledge_drift.side_effect = lambda *a, **kw: _refuse("acknowledge")
        self.memory_retrieval_service = SimpleNamespace(get_snapshot=AsyncMock(
            side_effect=lambda instance_id, module, snapshot_id: SimpleNamespace(
                plaintext={"release": "before" if snapshot_id == "old-one" else "after café [literal] Ω"},
            ),
        ))
        self.team_memory_service = SimpleNamespace(
            list_team_member_keys=AsyncMock(return_value=[]),
            find_live_grant=AsyncMock(return_value=None),
            eligible_members=lambda keys, role: keys,
            grant_coverage=AsyncMock(return_value={}), waiting_key_changes=lambda slug, coverage: [],
            purge_grant=AsyncMock(side_effect=lambda *a, **kw: _refuse("purge")),
            revoke_grant=AsyncMock(side_effect=lambda *a, **kw: _refuse("revoke")),
            share_instance=AsyncMock(side_effect=lambda *a, **kw: _refuse("share")),
            reshare_instance=AsyncMock(side_effect=lambda *a, **kw: _refuse("reshare")),
            confirm_member_keys=Mock(side_effect=lambda *a, **kw: _refuse("confirm member keys")),
            top_up_grant=AsyncMock(side_effect=lambda *a, **kw: _refuse("top up grant")),
        )
        self.theme = "servonaut"


@pytest.fixture(autouse=True)
def _fake_memory_boundaries(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    _VIOLATIONS.clear()
    # Other memory unit hosts replace this property; restore the captured native one.
    monkeypatch.setattr(FleetMemoryScreen, "app", _REAL_FLEET_APP)
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
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


PRIMARY = {
    "fleet": "#fleet-memory-table", "share": "#share-team-select",
    "summary": "#memory-summary-scroll", "drift": "#drift-table",
    "keys": "#keychange-btn-cancel",
}


def _opener(kind: str) -> Callable[[ServonautApp, Pilot], Awaitable[WorkspaceScreen]]:
    async def open_screen(app: ServonautApp, pilot: Pilot) -> WorkspaceScreen:
        factories = {
            "fleet": FleetMemoryScreen,
            "share": lambda: ShareInstanceScreen(app.instances[0]),
            "summary": lambda: MemorySummaryScreen(title="Summary café [literal] Ω", summary=SUMMARY, source_label="Local deterministic facts"),
            "drift": MemoryDriftScreen,
            "keys": lambda: MemberKeyChangeScreen([_change(2, "Lee [literal] Ω"), _change(3, "Kim")]),
        }
        screen = factories[kind]()
        await app.push_screen(screen)
        await _ready(screen)
        await pilot.pause()
        if kind == "keys":
            assert app.focused is screen.query_one(PRIMARY[kind])
        else:
            # Explicit journey setup, not a guessed native first-focus oracle.
            screen.query_one(PRIMARY[kind]).focus()
        await pilot.pause()
        return screen
    return open_screen


async def _ready(screen: WorkspaceScreen) -> None:
    if isinstance(screen, FleetMemoryScreen):
        await wait_until(lambda: screen.query_one("#fleet-memory-table", DataTable).row_count == 2)
    elif isinstance(screen, ShareInstanceScreen):
        await wait_until(lambda: bool(screen._teams) and "example-team" in screen._keys_by_team)
    elif isinstance(screen, MemorySummaryScreen):
        await wait_until(lambda: bool(screen.query_one(Markdown).children))
    elif isinstance(screen, MemoryDriftScreen):
        await wait_until(lambda: screen.query_one("#drift-table", DataTable).row_count == 1)
    else:
        await wait_until(lambda: len(screen.query(Checkbox)) == 2)


def _seed(screen: WorkspaceScreen) -> None:
    if isinstance(screen, FleetMemoryScreen):
        screen.query_one("#fleet-memory-table", DataTable).move_cursor(row=1)
    elif isinstance(screen, ShareInstanceScreen):
        screen.query_one("#share-role-select", Select).value = "member"
        screen.query_one("#share-modules-list", SelectionList).select("os")
    elif isinstance(screen, MemberKeyChangeScreen):
        screen.query_one("#keychange-check-0", Checkbox).value = True


def _state(screen: WorkspaceScreen) -> object:
    if isinstance(screen, FleetMemoryScreen):
        return tuple((row["raw_id"], row["status"]) for row in screen._rows), screen.query_one(DataTable).cursor_row
    if isinstance(screen, ShareInstanceScreen):
        return (screen.query_one("#share-team-select", Select).value,
                screen.query_one("#share-role-select", Select).value,
                tuple(screen.query_one(SelectionList).selected), screen._instance, screen._grant)
    if isinstance(screen, MemorySummaryScreen):
        reader = screen.query_one(Markdown)
        return reader, reader.source, screen._source_label
    if isinstance(screen, MemoryDriftScreen):
        return tuple(screen._events), screen._show_unack_only, screen.query_one(DataTable).cursor_row
    return tuple(screen._changes), tuple(box.value for box in screen.query(Checkbox)), screen._mode


# Native width/policy samples remain absent until real boundary qualification.
# Qualified native columns and separately measured layout policy.
_MEASURED_BOUNDARIES = {
    'fleet': {
        ('chat-min', False): (
            BoundarySample((183, 50), 119, True, True),
            BoundarySample((184, 50), 120, False, True),
            BoundarySample((185, 50), 121, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((208, 50), 119, True, True),
            BoundarySample((209, 50), 120, False, True),
            BoundarySample((210, 50), 121, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((203, 50), 139, False, True),
            BoundarySample((204, 50), 140, False, False),
            BoundarySample((205, 50), 141, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((228, 50), 139, False, True),
            BoundarySample((229, 50), 140, False, False),
            BoundarySample((230, 50), 141, False, False),
        ),
    },
    'share': {
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
    'summary': {
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
    'drift': {
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
    'keys': {
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


CASES = (
    ReflowCase("fleet", _MemoryHost, _opener("fleet"), _ready, PRIMARY["fleet"],
               ("#fleet-memory-table", "#btn_scan_all", "#btn_refresh_stale", "#btn_refresh_view",
                "#btn_open", "#btn_clear", "#btn_toggle_auto_scan"), _seed, _state, (), boundaries=_MEASURED_BOUNDARIES['fleet']),
    ReflowCase("share", _MemoryHost, _opener("share"), _ready, PRIMARY["share"],
               ("#share-team-select", "#share-role-select", "#share-modules-list", "#share-btn-cancel", "#share-btn-confirm"), _seed, _state, (), boundaries=_MEASURED_BOUNDARIES['share']),
    ReflowCase("summary", _MemoryHost, _opener("summary"), _ready, PRIMARY["summary"],
               ("#memory-summary-scroll", "#memory-summary-back"), _seed, _state, (), boundaries=_MEASURED_BOUNDARIES['summary']),
    ReflowCase("drift", _MemoryHost, _opener("drift"), _ready, PRIMARY["drift"],
               ("#drift-table", "#btn-drift-refresh", "#btn-drift-ack", "#btn-drift-unack"), _seed, _state, (), boundaries=_MEASURED_BOUNDARIES['drift']),
    ReflowCase("keys", _MemoryHost, _opener("keys"), _ready, PRIMARY["keys"],
               ("#keychange-btn-cancel", "#keychange-check-0", "#keychange-check-1", "#keychange-btn-confirm"), _seed, _state, (), boundaries=_MEASURED_BOUNDARIES['keys']),
)
IDS = [case.name for case in CASES]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=IDS)
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("navigation_visible,chat_open", [(False, False), (False, True), (True, False), (True, True)])
async def test_memory_workspace_four_visibility_states(case: ReflowCase, size: tuple[int, int], navigation_visible: bool, chat_open: bool) -> None:
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
async def test_memory_state_and_native_tab_survive_replacement(case: ReflowCase) -> None:
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
async def test_memory_qualified_native_boundaries(case: ReflowCase, navigation_visible: bool, kind: str) -> None:
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
@pytest.mark.parametrize("kind,key", [("fleet", "s"), ("fleet", "x"), ("fleet", "a"), ("drift", "a")])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_memory_rail_keys_do_not_scan_clear_toggle_or_ack(kind: str, key: str, navigation_visible: bool, clipboard: _Clipboard) -> None:
    app = _MemoryHost(navigation_visible)
    case = next(case for case in CASES if case.name == kind)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        old = app.config_manager.get().memory.auto_scan_enabled
        await pilot.press("shift+f6")
        sidebar = screen.query_one(Sidebar)
        await wait_until(lambda: sidebar.navigation_mode and sidebar.has_focus_within)
        await pilot.press(key)
        await pilot.pause()
        assert app.screen is screen and app.is_running and not _VIOLATIONS
        assert sidebar.navigation_mode and clipboard.calls == []
        assert app.config_manager.get().memory.auto_scan_enabled is old


@pytest.mark.asyncio
@pytest.mark.parametrize("case,theme", [(CASES[0], "ansi-dark"), (CASES[1], "servonaut-light"), (CASES[2], "ansi-light"), (CASES[4], "servonaut")])
async def test_memory_representative_named_palettes(case: ReflowCase, theme: str) -> None:
    app = case.app_factory(True)
    app.theme = theme
    assert app.config_manager.get().theme == theme
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await assert_essential_targets(case, app, pilot, screen)
        assert_layout(app, screen)
