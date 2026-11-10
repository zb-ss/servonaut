"""Vault workspaces preserve native context and explicit service boundaries."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator, Mapping, Sequence
from typing import Any, ClassVar
from unittest.mock import AsyncMock, Mock, create_autospec, patch

import pytest
from textual.pilot import Pilot
from textual.widgets import Button, Checkbox, Collapsible, DataTable

from servonaut.config.schema import AppConfig
from servonaut.screens import vault_auto_bind
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.vault import VaultScreen
from servonaut.screens.vault_auto_bind import VaultAutoBindScreen
from servonaut.services.vault.auto_bind import AutoBindRow, FETCHED, KeyMatch, READY, _HOST_KEY_VISITS
from servonaut.services.vault.errors import VaultUserError
from servonaut.services.vault.command_service import VaultCommandService, _NAMED_KEY_CHOICES
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import (
    BoundarySample, ReflowCase, assert_essential_targets, assert_layout, content, open_case,
    one_layout_transition, open_chat, preserve_native_state, tab_to,
)
from tests.test_workspace_pilot import _Host, _click
from tests.test_workspace_reflow import _painted

pytestmark = pytest.mark.usefixtures("navigation_open")


HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
# Pin the existing 71-cell reveal-width contract using synthetic material.
RECOVERY_KEY = "SVRK1-" + "ABCD-" * 12 + "ABCDE"
SIZES = ((160, 50), (100, 30))


class _VaultService:
    """The injected facade surface, with only synthetic in-memory records."""

    def __init__(self) -> None:
        self.local: str | None = "example-local-identity"
        self.remote: dict[str, str] | None = {"identity_id": "identity-1", "trust_status": "confirmed"}
        self.vaults = [
            {"vault_id": "vault-1", "kind": "personal", "name": "Personal [example]",
             "my_role": "owner", "my_grant": {"version": 1},
             "permissions": {"grant": True}, "counts": {"items": 2, "open_exposures": 1}},
            {"vault_id": "vault-2", "kind": "team", "name": "Other Ω",
             "team": {"slug": "example", "name": "Example team"}, "my_role": "owner",
             "my_grant": {"version": 1}, "permissions": {"grant": True}, "counts": {}},
        ]
        self.items = [{"item_id": "key-1", "type": "ssh_key", "revision": 1,
                       "public_fingerprint": "SHA256:example"}]
        self.devices = [{"device_id": "device-1", "name": "Example computer", "status": "pending"}]
        self.reads: list[str] = []
        self.operations: list[tuple[str, Any]] = []
        self.results: list[tuple[str, Any]] = []
        self.teams_entered = asyncio.Event()
        self.teams_release = asyncio.Event()
        self.teams_release.set()
        self.server_error: Exception | None = None
        self.bind_entered = asyncio.Event()
        self.bind_release = asyncio.Event()
        self.bind_release.set()
        self.bind_cancelled = False
        self.need_host_keys = False
        for name in (
            "status", "unlock_existing_identity", "list_vaults", "can_create_personal_vault",
            "drain_device_pending_events", "list_items", "ssh_key_choices", "list_devices",
            "list_exposures", "team_choices", "shared_server_choices", "creatable_vaults",
            "records_new_host_keys", "create_vault", "recover", "rotate_recovery_key",
            "approve_device", "process_grants", "show_item", "default_device_name",
        ):
            signature = getattr(VaultCommandService, name).__get__(self, type(self))
            setattr(self, name, create_autospec(signature, side_effect=getattr(self, name)))

    async def status(self) -> dict[str, Any]:
        self.reads.append("status")
        return {"remote": {"identity": self.remote}, "local_identity": self.local,
                "fingerprint": self.local}

    def unlock_existing_identity(self) -> bool:
        return False

    async def list_vaults(self) -> list[dict[str, Any]]:
        self.reads.append("vaults")
        return [dict(row) for row in self.vaults]

    def can_create_personal_vault(self) -> bool:
        return False

    def drain_device_pending_events(self) -> list[Any]:
        return []

    async def list_items(self, *, vault_id: str, include_deleted: bool = False) -> dict[str, Any]:
        assert vault_id == "vault-1" and include_deleted is False
        self.reads.append("items")
        return {"data": [dict(row) for row in self.items]}

    async def ssh_key_choices(self, *, vault_id: str, name_limit: int | None = _NAMED_KEY_CHOICES) -> list[dict[str, str]]:
        assert vault_id == "vault-1" and name_limit is None
        return [{"item_id": "key-1", "name": "web-1", "label": "Example key", "fingerprint": "SHA256:example"}]

    async def list_devices(self) -> list[dict[str, str]]:
        self.reads.append("devices")
        return [dict(row) for row in self.devices]

    async def list_exposures(self, *, vault_id: str) -> dict[str, Any]:
        assert vault_id == "vault-1"
        return {"data": [{"item_id": "key-1", "exposure_id": "exposure-1", "reason": "Example review"}]}

    async def team_choices(self) -> list[dict[str, str]]:
        self.teams_entered.set()
        await self.teams_release.wait()
        return [{"slug": "example", "label": "Example team"}]

    async def shared_server_choices(self, *, team: str) -> list[dict[str, str]]:
        if self.server_error:
            raise self.server_error
        return [{"server_id": "server-1", "label": "web-1"}]

    async def creatable_vaults(self, vaults: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        assert vaults == self.vaults
        return [{"team": "other-example", "label": "Other example team"}]

    def records_new_host_keys(self) -> bool:
        return True

    async def create_vault(self, *, team: str | None, name: str | None, grant_policy: str) -> dict[str, Any]:
        self.operations.append(("create", {"team": team, "name": name, "grant_policy": grant_policy}))
        return {"vault_id": "created-example"}

    async def recover(self, *, recovery_key: str, device_name: str | None, platform: str | None) -> dict[str, Any]:
        self.operations.append(("recover", {"recovery_key": recovery_key, "device_name": device_name, "platform": platform}))
        self.local = "recovered-example"
        return {"recovered": True}

    async def rotate_recovery_key(self, *, recovery_confirmation: Any = None) -> dict[str, Any]:
        assert callable(recovery_confirmation)
        accepted = await recovery_confirmation(RECOVERY_KEY)
        self.results.append(("recovery", accepted))
        if not accepted:
            raise VaultUserError("recovery key was not confirmed")
        return {"confirmed": accepted}

    async def approve_device(self, *, device_id: str, confirmation: Any) -> dict[str, Any]:
        accepted = await confirmation("1234 5678 9012")
        self.results.append(("sas", accepted))
        if not accepted:
            raise VaultUserError("device safety number was not confirmed; registration was rejected")
        return {"confirmed": accepted}

    async def process_grants(self, *, vault_id: str | None = None, interactive: bool = False, approval: Any = None) -> list[dict[str, Any]]:
        assert vault_id == "vault-1" and interactive is False and callable(approval)
        accepted = await approval({"display_name": "Example member", "role": "member"}, "1234 5678", False)
        self.results.append(("member", accepted))
        return [{"accepted": ["member-1"] if accepted else [], "skipped": [] if accepted else ["member-1"]}]

    async def show_item(self, *, vault_id: str, item_id: str, reveal: bool) -> dict[str, Any]:
        self.operations.append(("reveal", {"vault_id": vault_id, "item_id": item_id, "reveal": reveal}))
        return {"plaintext": {"value": "example-secret[/b]Ω"}}

    def default_device_name(self) -> str:
        return "Example computer"


class _MemoryConfig:
    created: ClassVar[list[_MemoryConfig]] = []

    def __init__(self) -> None:
        self._config = AppConfig()
        self.save = Mock(side_effect=AssertionError("Unexpected config save"))
        self.update = Mock(side_effect=AssertionError("Unexpected config update"))
        self.created.append(self)

    def get(self) -> AppConfig:
        return self._config


class _VaultHost(_Host):
    def __init__(self, navigation_visible: bool = True) -> None:
        self.notes: list[str] = []
        super().__init__(navigation_visible=navigation_visible)
        self.vault_command_service = _VaultService()
        self.vault_available = True
        self.config_manager = _MemoryConfig()
        self._instances_pristine = [dict(row) for row in self.instances]
        self.copied = Mock()
        self.copy_to_clipboard = self.copied

    def notify(self, message: str, **kwargs: Any) -> None:
        self.notes.append(str(message))
        super().notify(message, **kwargs)


@pytest.fixture(autouse=True)
def inert_services(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(_MemoryConfig, "created", [])
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    process = Mock(side_effect=AssertionError("Unexpected subprocess"))
    network = Mock(side_effect=AssertionError("Unexpected network"))
    keyring = Mock(side_effect=AssertionError("Unexpected keyring operation"))
    browser = Mock(side_effect=AssertionError("Unexpected browser"))
    monkeypatch.setattr("subprocess.Popen", process)
    monkeypatch.setattr("subprocess.run", process)
    async_process = AsyncMock(side_effect=AssertionError("Unexpected async subprocess"))
    monkeypatch.setattr("asyncio.create_subprocess_exec", async_process)
    monkeypatch.setattr("asyncio.create_subprocess_shell", async_process)
    monkeypatch.setattr("socket.create_connection", network)
    monkeypatch.setattr("webbrowser.open", browser)
    for name in ("get_password", "set_password", "delete_password"):
        monkeypatch.setattr("keyring." + name, keyring)

    async def no_connection(*args: Any, **kwargs: Any) -> None:
        network()

    monkeypatch.setattr(asyncio.BaseEventLoop, "create_connection", no_connection)

    async def planned(service: _VaultService, instances: Any, keys: Any, *, team: str | None = None, host_keys_for: Any = None) -> list[AutoBindRow]:
        from servonaut.services.vault.auto_bind import NO_HOST_KEYS
        assert team is None and host_keys_for is None
        return [AutoBindRow(row, NO_HOST_KEYS if service.need_host_keys else READY,
                            match=KeyMatch("key-1", str(row["name"]), "server name"),
                            host="10.0.0.1", login="deploy",
                            host_keys=[] if service.need_host_keys else [HOST_KEY]) for row in instances]

    async def applied(service: _VaultService, rows: Any, *, vault_id: str, team: str | None = None, reviewed_fetched: bool = False, on_progress: Any = None) -> None:
        assert vault_id == "vault-1" and team is None and reviewed_fetched is False
        assert callable(on_progress)
        service.bind_entered.set()
        try:
            await service.bind_release.wait()
        except asyncio.CancelledError:
            service.bind_cancelled = True
            raise
        for index, row in enumerate(rows):
            service.operations.append(("bind", str(row.instance["id"])))
            row.result = "bound"
            on_progress(index, row)

    async def fetched(service: _VaultService, rows: Any, *, on_progress: Any = None, host_keys_for: Any = None, console_output_reader: Any = None, accounts: Any = None, max_concurrency: int = _HOST_KEY_VISITS) -> None:
        assert callable(on_progress) and host_keys_for is None and console_output_reader is None
        service.operations.append(("fetch", tuple(str(row.instance["id"]) for row in rows)))
        for index, row in enumerate(rows):
            row.status = FETCHED
            row.host_keys = [HOST_KEY]
            on_progress(index + 1, row)

    for name, fake in (("plan_auto_bind", planned), ("apply_auto_bind", applied),
                       ("fetch_host_keys_for_rows", fetched)):
        monkeypatch.setattr(vault_auto_bind, name, create_autospec(getattr(vault_auto_bind, name), side_effect=fake))
    yield
    for guard in (process, network, keyring, browser):
        guard.assert_not_called()
    async_process.assert_not_called()
    for config in _MemoryConfig.created:
        config.save.assert_not_called()
        config.update.assert_not_called()


async def stable_open(app: _VaultHost, kind: str) -> VaultScreen | VaultAutoBindScreen:
    await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
    screen = VaultScreen() if kind == "vault" else VaultAutoBindScreen()
    await app.push_screen(screen)
    await ready(screen)
    return screen


async def ready(screen: WorkspaceScreen) -> None:
    if isinstance(screen, VaultScreen):
        await wait_until(lambda: screen._identity_state == "ready" and not screen._busy_work)
        await wait_until(lambda: screen.query_one("#vault_table", DataTable).row_count == 2)
    else:
        await wait_until(lambda: not screen._busy.is_busy and len(screen._rows) == 2)


def state(screen: WorkspaceScreen) -> object:
    if isinstance(screen, VaultScreen):
        table = screen.query_one("#vault_table", DataTable)
        return table, table.cursor_row, screen._table_mode, screen._selected_vault_id, tuple(row["vault_id"] for row in screen._vaults)
    table = screen.query_one("#auto_bind_table", DataTable)
    return (table, table.cursor_row, frozenset(screen._selected), screen._selected_target,
            screen.query_one("#auto_bind_trust", Checkbox).value, tuple(id(row) for row in screen._rows))


def seed(screen: WorkspaceScreen) -> None:
    table = screen.query_one("#vault_table" if isinstance(screen, VaultScreen) else "#auto_bind_table", DataTable)
    table.move_cursor(row=1)


# Qualified native columns and separately measured layout policy.
_MEASURED_BOUNDARIES = {
    'vault': {
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
    'auto': {
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


def case_for(kind: str) -> ReflowCase:
    async def opener(app: _VaultHost, pilot: Pilot) -> WorkspaceScreen:
        return await stable_open(app, kind)

    targets = (("#vault_table", "#vault_refresh", "#vault_create", "#vault_items", "#vault_reveal", "#vault_rotate")
               if kind == "vault" else ("#auto_bind_vault_select", "#auto_bind_table", "#auto_bind_trust",
                                       "#auto_bind_apply", "#auto_bind_all", "#auto_bind_none", "#auto_bind_back"))
    return ReflowCase(kind, _VaultHost, opener, ready,
                      "#vault_table" if kind == "vault" else "#auto_bind_vault_select",
                      targets, seed, state, (), boundaries=_MEASURED_BOUNDARIES[kind])


async def reveal_secondary_vault_target(pilot: Pilot, screen: WorkspaceScreen) -> None:
    """Check the irreversible actions are laid out with the rest, and nothing ran."""
    if not isinstance(screen, VaultScreen):
        return
    before = state(screen)
    before_operations = tuple(pilot.app.vault_command_service.operations)
    assert screen.query_one("#vault_danger_group").display
    assert screen.query_one("#vault_rotate").display
    assert state(screen) == before
    assert tuple(pilot.app.vault_command_service.operations) == before_operations


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["vault", "auto"])
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [False, True])
@pytest.mark.parametrize("chat", [False, True])
async def test_vault_panes_keep_context(kind: str, size: tuple[int, int], navigation: bool, chat: bool) -> None:
    case = case_for(kind)
    app = case.app_factory(navigation)
    async with app.run_test(size=size) as pilot:
        screen = await open_case(case, app, pilot)
        await reveal_secondary_vault_target(pilot, screen)
        before = state(screen)
        if chat:
            await open_chat(app, pilot, screen)
        assert_layout(app, screen)
        assert screen.query_one(Sidebar).display is navigation
        assert state(screen) == before
        outer = screen.query_one("#vault_layout" if kind == "vault" else "#auto_bind_layout")
        inner = screen.query_one("#main-layout")
        controls = screen.query_one("#workspace_navigation").parent
        assert outer.is_attached and controls.parent is screen
        assert inner.region.x == outer.content_region.x
        assert inner.region.right == outer.content_region.right
        assert inner.region.bottom == outer.content_region.bottom
        assert inner.region.y == controls.region.bottom
        assert outer.content_region.contains_region(inner.region)
        assert not inner.region.overlaps(controls.region)
        assert outer.max_scroll_y == inner.max_scroll_y == 0
        if content(screen).display:
            await assert_essential_targets(case, app, pilot, screen)
        assert not app.vault_command_service.operations and app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["vault", "auto"])
async def test_vault_native_state_and_chat_survive_reflow(kind: str) -> None:
    case = case_for(kind)
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await reveal_secondary_vault_target(pilot, screen)
        await preserve_native_state(case, app, pilot, screen)
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["vault", "auto"])
@pytest.mark.parametrize("boundary", ["chat-min", "content-narrow"])
@pytest.mark.parametrize("navigation", [False, True])
async def test_vault_qualified_native_boundaries(kind: str, boundary: str, navigation: bool) -> None:
    case = case_for(kind)
    samples = case.boundary_samples(boundary, navigation)
    app = case.app_factory(navigation)
    async with app.run_test(size=samples[0].size) as pilot:
        screen = await open_case(case, app, pilot)
        await reveal_secondary_vault_target(pilot, screen)
        baseline = case.state(screen)
        await open_chat(app, pilot, screen)
        threshold = screen.CHAT_MIN_CONTENT_WIDTH if boundary == "chat-min" else screen.CONTENT_NARROW_WIDTH
        assert [sample.native_content_width for sample in samples] == [threshold - 1, threshold, threshold + 1]
        for sample in samples:
            with one_layout_transition(screen):
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
                assert_layout(app, screen)
            else:
                assert content(screen).region.width == sample.native_content_width
                await assert_essential_targets(case, app, pilot, screen)
            assert case.state(screen) == baseline


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,key", [("vault", "r"), ("vault", "v"), ("vault", "e"),
                                      ("vault", "d"), ("vault", "g"), ("auto", "f"), ("auto", "r"), ("auto", "space")])
@pytest.mark.parametrize("navigation", [False, True])
async def test_vault_rail_keys_do_not_change_content(kind: str, key: str, navigation: bool) -> None:
    app = _VaultHost(navigation)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await stable_open(app, kind)
        before = (state(screen), list(app.vault_command_service.reads),
                  list(app.vault_command_service.operations), list(app.notes))
        await pilot.press("shift+f6")
        sidebar = screen.query_one(Sidebar)
        await wait_until(lambda: sidebar.navigation_mode and sidebar.has_focus_within)
        await pilot.press(key)
        await pilot.pause()
        assert app.screen is screen and sidebar.navigation_mode and sidebar.has_focus_within
        assert (state(screen), app.vault_command_service.reads,
                app.vault_command_service.operations, app.notes) == before
        await pilot.press("escape")
        await wait_until(lambda: not sidebar.navigation_mode)
        assert app.screen is screen and app._exception is None


@pytest.mark.asyncio
async def test_auto_bind_content_space_keeps_native_selection_toggle() -> None:
    app = _VaultHost(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await stable_open(app, "auto")
        table = screen.query_one("#auto_bind_table", DataTable)
        table.focus()
        await pilot.pause()
        before = set(screen._selected)
        await pilot.press("space")
        await pilot.pause()
        assert screen._selected == before.symmetric_difference({table.cursor_row})
        assert not app.vault_command_service.operations


@pytest.mark.asyncio
@pytest.mark.parametrize("child", [False, True])
async def test_vault_hold_applies_to_rail_palette_and_quit_across_stack(child: bool) -> None:
    app = _VaultHost(False)
    async with app.run_test(size=(160, 50)) as pilot:
        vault = await stable_open(app, "vault")
        top = vault
        if child:
            top = VaultAutoBindScreen()
            await app.push_screen(top)
            await ready(top)
        await pilot.press("shift+f6")
        sidebar = top.query_one(Sidebar)
        await wait_until(lambda: sidebar.navigation_mode and sidebar.has_focus_within)
        held_focus = app.focused
        async with vault._busy("Example held vault change", holds_screen=True):
            assert app._navigation_hold_reason()
            await pilot.press("shift+f6")
            await pilot.pause()
            assert sidebar.navigation_mode and sidebar.has_focus_within
            assert app.focused is held_focus
            for _ in range(len(app.screen.focus_chain) + 1):
                if isinstance(app.focused, Button) and (app.focused.id or "").startswith("nav_"):
                    break
                await pilot.press("tab")
            assert isinstance(app.focused, Button) and (app.focused.id or "").startswith("nav_")
            await pilot.press("enter", "ctrl+p", "q")
            await pilot.pause()
            assert app.is_running and app.screen is top
            assert sidebar.has_focus_within and not app.vault_command_service.operations
        assert sidebar.has_focus_within


@pytest.mark.asyncio
async def test_auto_bind_alone_does_not_hold_and_leaving_cancels_its_worker() -> None:
    app = _VaultHost(False)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await stable_open(app, "auto")
        service = app.vault_command_service
        service.bind_release.clear()
        trust = screen.query_one("#auto_bind_trust", Checkbox)
        # Data readiness can precede the short/narrow presentation update.
        await wait_until(lambda: (
            screen.has_class("-content-narrow") and screen.has_class("-short")
        ))
        await pilot.pause()
        await wait_until(lambda: (
            trust.region.width > 0 and trust.region.height > 0
            and screen.region.contains_region(trust.region)
            and app.get_widget_at(*trust.region.offset)[0] is trust
            and trust.label.plain in _painted(app, trust)
        ))
        assert trust.value is False
        assert await pilot.click(trust)
        await wait_until(lambda: trust.value is True)
        await _click(pilot, "#auto_bind_apply")
        await wait_until(service.bind_entered.is_set)
        assert app._navigation_hold_reason() is None
        await pilot.press("escape")
        await wait_until(lambda: screen not in app.screen_stack)
        await wait_until(lambda: service.bind_cancelled)
        assert not service.operations
        assert isinstance(app.screen, InstanceListScreen) and app._exception is None


def _assert_auto_bind_action_labels(app: _VaultHost, screen: VaultAutoBindScreen) -> None:
    row = screen.query_one("#auto_bind_actions")
    buttons = list(row.query(Button))
    assert [button.id for button in buttons] == [
        "auto_bind_apply", "auto_bind_fetch_keys", "auto_bind_all", "auto_bind_none", "auto_bind_back",
    ]
    for button in buttons:
        assert content(screen).region.contains_region(button.region)
        assert row.region.contains_region(button.region)
        assert button.region.height == 3
        assert app.get_widget_at(*button.region.center)[0] is button
        assert button.label.plain in _painted(app, button)


@pytest.mark.asyncio
@pytest.mark.parametrize(("navigation", "chat", "size"), [
    (False, False, (110, 50)), (True, False, (135, 50)),
    (False, True, (174, 50)), (True, True, (199, 50)),
])
async def test_auto_bind_count_digit_growth_repaints_without_resize(
    navigation: bool, chat: bool, size: tuple[int, int],
) -> None:
    app = _VaultHost(navigation)
    # Ten synthetic servers exercise a real selected-count digit transition.
    app.instances = [dict(app.instances[0], id=f"id-web-{index}", name=f"web-{index}")
                     for index in range(1, 11)]
    app._instances_pristine = [dict(row) for row in app.instances]
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        screen = VaultAutoBindScreen()
        await app.push_screen(screen)
        await wait_until(lambda: not screen._busy.is_busy and len(screen._rows) == 10)
        table = screen.query_one("#auto_bind_table", DataTable)
        await tab_to(pilot, table)
        assert len(screen._selected) == 10
        await pilot.press("space")
        await wait_until(lambda: len(screen._selected) == 9)
        if chat:
            await open_chat(app, pilot, screen)
        # Establish the qualified 110-cell wide-grid pose before the count changes.
        await pilot.resize_terminal(*size)
        await pilot.pause()
        await tab_to(pilot, table)
        await pilot.pause()
        assert content(screen).region.width == 110
        assert not screen.has_class("-content-narrow")
        apply = screen.query_one("#auto_bind_apply", Button)
        assert apply.label.plain == "Bind selected (9)" and not apply.disabled
        _assert_auto_bind_action_labels(app, screen)
        geometry = app.size, content(screen).region, screen.query_one("#auto_bind_actions").region
        reads = list(app.vault_command_service.reads)
        for count in (10, 9, 10):
            await pilot.press("space")
            await wait_until(lambda: len(screen._selected) == count)
            await pilot.pause()
            await pilot.pause()
            assert apply.label.plain == f"Bind selected ({count})" and not apply.disabled
            _assert_auto_bind_action_labels(app, screen)
            assert (app.size, content(screen).region, screen.query_one("#auto_bind_actions").region) == geometry
            assert app.focused is table and table.cursor_row == 0
        assert app.vault_command_service.reads == reads
        assert not app.vault_command_service.operations and app._exception is None


@pytest.mark.asyncio
async def test_auto_bind_action_hints_are_bindings_and_the_key_matches_the_click() -> None:
    from tests._hint_conformance import assert_hints_match_bindings, record_actions

    case = case_for("auto")
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        calls: list[str] = []
        record_actions(screen, calls)
        await assert_hints_match_bindings(pilot, screen, calls)
