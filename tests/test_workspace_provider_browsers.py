"""Provider browsers keep views, targets and toolbars usable beside chat."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call, create_autospec, patch

import pytest
from textual.pilot import Pilot
from textual.widgets import Button, DataTable, Input

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig
from servonaut.screens.bw_vault_manager import BwVaultManagerScreen
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.object_storage import ObjectStorageScreen
from servonaut.screens.ovh_dns import OVHDNSScreen
from servonaut.services.bw_session_service import BwAuthState, BwItemSummary, BwSessionService
from servonaut.services.bw_ssh_config_service import BwSshConfigService
from servonaut.services.interfaces import BucketListing
from servonaut.services.object_storage_service import ObjectStorageService
from servonaut.services.ovh_audit import OVHAuditLogger
from servonaut.services.ovh_dns_service import OVHDNSService
from servonaut.services.ovh_ip_service import OVHIPService
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

pytestmark = pytest.mark.usefixtures("navigation_open")


BUCKETS = ({"name": "assets", "creation_date": "2026-01-01"},
           {"name": "backups", "creation_date": "2026-01-02"})
ZONES = ["example.com", "example.org"]
RECORD = {"id": 101, "fieldType": "A", "subDomain": "www", "target": "9.9.9.9", "ttl": 3600}
ITEMS = ("item-1abcdef0", "item-2abcdef0")
VAULT_URL = "https://vault.example.com"


class _BrowserHost(_Host):
    """The accepted native workspace host with exact provider fakes.

    Every mutating call fails closed: it is journaled (the fixture asserts the
    journal is empty) and raises, unless a mutation journey allows it.
    """

    # Replaced with a fresh list by the autouse fixture for every test.
    journal: list = []

    def __init__(self, navigation_visible: bool = True) -> None:
        super().__init__(navigation_visible=navigation_visible)
        self.config = AppConfig()
        self.config_manager = SimpleNamespace(
            get=lambda: self.config,
            save=Mock(side_effect=self._deny("config_manager.save")),
            update=Mock(side_effect=self._theme_only),
        )
        self.list_release = asyncio.Event()
        self.list_release.set()
        # Object storage (no account registry: the default-account alias).
        storage = create_autospec(ObjectStorageService, instance=True)
        storage.search_buckets.side_effect = self._buckets
        storage.list_objects.side_effect = self._objects
        self.ovh_object_storage_service = storage
        # OVH DNS and reverse DNS.
        dns = create_autospec(OVHDNSService, instance=True)
        dns.list_domains.return_value = list(ZONES)
        dns.list_records.return_value = [dict(RECORD)]
        for method in ("create_record", "update_record", "delete_record", "refresh_zone"):
            getattr(dns, method).return_value = True
        self.ovh_dns_service = dns
        ip = create_autospec(OVHIPService, instance=True)
        ip.list_ips.return_value = [{"ip": "9.9.9.0/24"}]
        ip.list_reverse_dns.return_value = [
            {"ipReverse": "9.9.9.9", "reverse": "mail.example.com."},
        ]
        self.ovh_ip_service = ip
        self.ovh_service = create_autospec(OVHService, instance=True)
        self.ovh_service.check_credentials.return_value = None
        self.ovh_audit = create_autospec(OVHAuditLogger, instance=True)
        # Bitwarden: the folder ensure writes on load, so it only records.
        self.entitlement_guard = SimpleNamespace(check=Mock(return_value=(True, "")))
        bw = create_autospec(BwSessionService, instance=True)
        bw.status.return_value = BwAuthState.UNLOCKED
        bw.ensure_servonaut_folder.return_value = "folder-1"
        bw.list_items.return_value = [
            BwItemSummary(id=ITEMS[0], name="deploy-key", type=5, has_ssh_key=True),
            BwItemSummary(id=ITEMS[1], name="backup-key", type=5, has_ssh_key=True),
        ]
        self.bw_session_service = bw
        cfg = create_autospec(BwSshConfigService, instance=True)
        cfg.get_personal_config.return_value = {"config": {"vault_url": VAULT_URL}}
        cfg.list_personal_instances.return_value = [
            {"provider": "custom", "instance_id": "id-web-1", "ssh_verify_status": "verified"},
        ]
        cfg.get_personal_instance_ref.return_value = {"ssh_credential_ref": {"item_id": ITEMS[0]}}
        self.bw_ssh_config_service = cfg
        # Loading the vault always ensures its folder (a write when it is
        # missing); the fake only records it and the load test pins the call.
        for owner, names in (
            (storage, ("create_bucket", "delete_bucket", "delete_object", "upload_object",
                       "download_object", "copy_object", "move_object",
                       "generate_presigned_url")),
            (dns, ("create_record", "update_record", "delete_record", "refresh_zone")),
            (ip, ("set_reverse_dns", "delete_reverse_dns")),
            (self.ovh_audit, ("log_action",)),
            (bw, ("create_ssh_key_item",)),
            (cfg, ("put_personal_config", "put_personal_instance_ref",
                   "delete_personal_instance_ref")),
        ):
            for name in names:
                getattr(owner, name).side_effect = self._deny(name)

    def _deny(self, name: str) -> Callable[..., object]:
        def denied(*args: object, **kwargs: object) -> object:
            type(self).journal.append((name, args, kwargs))
            raise AssertionError(f"Unexpected mutation: {name}")
        return denied

    def _theme_only(self, **fields: object) -> None:
        # The app remembers its theme through update() whenever the theme
        # watcher runs; any other config write from these screens is denied.
        if set(fields) != {"theme"}:
            self._deny("config_manager.update")(**fields)

    @staticmethod
    def allow(*mutators: Mock) -> None:
        """Let a mutation journey use *mutators* (their return values apply)."""
        for mutator in mutators:
            mutator.side_effect = None

    async def _buckets(self) -> BucketListing:
        await self.list_release.wait()
        return BucketListing(buckets=[dict(b) for b in BUCKETS],
                             endpoint="https://s3.example.com", region="gra")

    async def _objects(
        self, bucket: str, prefix: str = "", delimiter: str = "/", region: str = "",
    ) -> dict:
        if prefix == "docs/":
            return {"folders": [], "objects": [
                {"key": "docs/guide.md", "size": 20, "last_modified": "2026-01-03"}]}
        return {"folders": ["docs/"], "objects": [
            {"key": "readme.txt", "size": 10, "last_modified": "2026-01-02"}]}


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
    journal: list = []
    monkeypatch.setattr(_BrowserHost, "journal", journal)
    yield trips
    # Screens catch service errors, so a denied mutation is caught here.
    assert journal == []
    trips["browser"].assert_not_called()
    trips["process"].assert_not_called()
    trips["async_process"].assert_not_awaited()
    trips["socket"].assert_not_called()
    trips["connection"].assert_not_awaited()
    trips["keyring"].assert_not_called()


SCREENS: dict[str, Callable[[], WorkspaceScreen]] = {
    "s3": lambda: ObjectStorageScreen(provider="ovh"),
    "dns": OVHDNSScreen,
    "vault": BwVaultManagerScreen,
}


def _opener(kind: str) -> Callable[[ServonautApp, Pilot], Awaitable[WorkspaceScreen]]:
    async def open_screen(app: ServonautApp, pilot: Pilot) -> WorkspaceScreen:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        screen = SCREENS[kind]()
        app.root_results = []
        await app.push_screen(screen, app.root_results.append)
        return screen
    return open_screen


async def _workers_done(app: ServonautApp, *names: str) -> None:
    await wait_until(lambda: not [
        worker for worker in app.workers
        if worker.name in names and not worker.is_finished
    ])


async def _ready(screen: WorkspaceScreen) -> None:
    if isinstance(screen, ObjectStorageScreen):
        await wait_until(lambda: screen.query_one("#s3_table", DataTable).row_count == 2)
        await _workers_done(screen.app, "s3_load_buckets")
    elif isinstance(screen, OVHDNSScreen):
        await wait_until(lambda: screen.query_one("#domains_table", DataTable).row_count == 2)
        await wait_until(lambda: screen._rdns_loaded)
    else:
        await wait_until(lambda: screen.query_one(
            "#bw_vault_mgr_table", DataTable).row_count == 2)
        await wait_until(lambda: not screen._loading)


def _seed(screen: WorkspaceScreen) -> None:
    # Non-default state that must survive every reflow.
    selector = {ObjectStorageScreen: "#s3_table", OVHDNSScreen: "#domains_table",
                BwVaultManagerScreen: "#bw_vault_mgr_table"}[type(screen)]
    screen.query_one(selector, DataTable).move_cursor(row=1)


S3_FORMS = ("#s3_new_bucket_form", "#s3_upload_form", "#s3_download_form",
            "#s3_copy_form", "#s3_move_form", "#s3_url_display")


def _state(screen: WorkspaceScreen) -> object:
    if isinstance(screen, ObjectStorageScreen):
        table = screen.query_one("#s3_table", DataTable)
        return (screen._view, screen._current_bucket, screen._prefix, table,
                table.row_count, table.cursor_row,
                tuple(screen.query_one(form).display for form in S3_FORMS))
    if isinstance(screen, OVHDNSScreen):
        domains = screen.query_one("#domains_table", DataTable)
        return (tuple(screen._domains), domains.cursor_row, screen._selected_zone,
                screen.query_one("#records_table", DataTable).row_count,
                screen.query_one("#record_form").display,
                screen.query_one("#rdns_form").display,
                tuple(entry["ip"] for entry in screen._rdns_entries))
    table = screen.query_one("#bw_vault_mgr_table", DataTable)
    return (table, table.row_count, table.cursor_row,
            tuple(row["item_id"] for row in screen._rows))


S3_BUTTONS = ("#btn_s3_refresh", "#btn_s3_new_bucket", "#btn_s3_up", "#btn_s3_open",
              "#btn_s3_upload", "#btn_s3_download", "#btn_s3_delete", "#btn_s3_copy",
              "#btn_s3_move", "#btn_s3_share", "#btn_s3_back")
DNS_BUTTONS = ("#btn_add", "#btn_edit", "#btn_delete", "#btn_refresh_zone", "#btn_back")
RDNS_BUTTONS = ("#btn_rdns_edit", "#btn_rdns_delete", "#btn_rdns_reload")
VAULT_BUTTONS = ("#btn_bw_vault_refresh", "#btn_bw_vault_open", "#btn_bw_vault_edit",
                 "#btn_bw_vault_import")
# Every toolbar row and all of its buttons. They must fit the content width
# wherever the content is shown; where the current layout clips a row these
# cells stay red until a scoped responsive toolbar change is approved.
TOOLBARS = {
    "s3": (("#s3_actions", S3_BUTTONS),),
    "dns": (("#dns_actions", DNS_BUTTONS), ("#rdns_actions", RDNS_BUTTONS)),
    "vault": (("#bw_vault_mgr_actions", VAULT_BUTTONS),),
}
# Derived native first focus: the content container is the first focusable
# widget in DOM order (the single-account picker is disabled). open_case
# characterises it.
PRIMARY = {"s3": "#s3_container", "dns": "#dns_container", "vault": "#bw_vault_mgr_container"}
TARGETS = {
    "s3": ("#s3_table",) + S3_BUTTONS,
    "dns": ("#domains_table", "#records_table") + DNS_BUTTONS + ("#rdns_table",) + RDNS_BUTTONS,
    "vault": ("#bw_vault_mgr_table",) + VAULT_BUTTONS,
}
PAINTED = {
    "s3": (("#s3_table", "assets"),),
    "dns": (("#domains_table", "example.com"),),
    "vault": (("#bw_vault_mgr_table", "deploy-key"),),
}
KINDS = ("s3", "dns", "vault")
# Native boundary samples are deliberately absent until qualified measurements.
# Qualified native columns and separately measured layout policy.
_MEASURED_BOUNDARIES = {
    's3': {
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
            BoundarySample((166, 50), 102, False, True),
            BoundarySample((167, 50), 103, False, False),
            BoundarySample((168, 50), 104, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((191, 50), 102, False, True),
            BoundarySample((192, 50), 103, False, False),
            BoundarySample((193, 50), 104, False, False),
        ),
    },
    'dns': {
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
            BoundarySample((136, 50), 82, False, True),
            BoundarySample((138, 50), 83, False, True),
            BoundarySample((139, 50), 84, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((171, 50), 82, False, True),
            BoundarySample((172, 50), 83, False, False),
            BoundarySample((173, 50), 84, False, False),
        ),
    },
}


CASES = tuple(
    ReflowCase(kind, _BrowserHost, _opener(kind), _ready, PRIMARY[kind], TARGETS[kind],
               _seed, _state, PAINTED[kind], boundaries=_MEASURED_BOUNDARIES[kind])
    for kind in KINDS
)


def _case(kind: str) -> ReflowCase:
    return next(case for case in CASES if case.name == kind)


async def _assert_whole_toolbars(
    app: ServonautApp, pilot: Pilot, screen: WorkspaceScreen, kind: str,
) -> None:
    body = content(screen)
    focused = app.focused
    for row_selector, buttons in TOOLBARS[kind]:
        row = screen.query_one(row_selector)
        # Reveal the row once; every button is then checked at that one
        # scroll offset, so no per-button scroll can manufacture a fit.
        row.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        offset = (body.scroll_x, body.scroll_y, row.scroll_x)
        visible = body.scrollable_content_region
        for selector in buttons:
            button = screen.query_one(selector, Button)
            assert button.region.width > 0 and button.region.height > 0, selector
            assert row.content_region.x <= button.region.x, selector
            assert button.region.right <= row.content_region.right, selector
            assert visible.contains_region(button.region), selector
            # Disabled buttons stay disabled; geometry, hit and paint matter.
            hit = app.get_widget_at(*button.region.center)[0]
            assert hit is button or button in hit.ancestors, selector
            assert_button_label_painted(app, button)
        assert (body.scroll_x, body.scroll_y, row.scroll_x) == offset, row_selector
    assert app.focused is focused


def _s3_effects(app: _BrowserHost) -> tuple:
    storage = app.ovh_object_storage_service
    return tuple(getattr(storage, method).await_count for method in (
        "search_buckets", "list_objects", "create_bucket", "delete_bucket",
        "delete_object", "upload_object", "download_object", "copy_object",
        "move_object", "generate_presigned_url",
    )) + (tuple(app.root_results),)


def _vault_effects(app: _BrowserHost) -> tuple:
    bw, cfg = app.bw_session_service, app.bw_ssh_config_service
    return (bw.status.await_count, bw.ensure_servonaut_folder.await_count,
            bw.list_items.await_count, cfg.get_personal_config.await_count,
            cfg.list_personal_instances.await_count,
            cfg.get_personal_instance_ref.await_count, tuple(app.root_results))


async def _type_and_confirm(pilot: Pilot, confirm: ConfirmActionScreen, word: str) -> None:
    def ready() -> bool:
        if pilot.app._exception is not None:
            raise pilot.app._exception
        if pilot.app.screen is not confirm or not confirm.is_mounted or not confirm.is_attached:
            return False
        for selector, expected_type in (
            ("#confirm_input", Input), ("#btn_confirm", Button), ("#btn_cancel", Button),
        ):
            children = list(confirm.query(selector))
            if len(children) != 1 or not isinstance(children[0], expected_type):
                return False
            child = children[0]
            if not child.is_mounted or not child.is_attached:
                return False
            if child.region.width <= 0 or child.region.height <= 0:
                return False
        return not confirm._layout_required

    await wait_until(ready)
    box = confirm.query_one("#confirm_input", Input)
    box.focus()
    await wait_until(lambda: confirm.app.focused is box)
    await pilot.press(*word)
    await wait_until(lambda: not confirm.query_one("#btn_confirm", Button).disabled)
    await _click(pilot, "#btn_confirm")


async def _focus_table(pilot: Pilot, screen: WorkspaceScreen, selector: str, row: int) -> DataTable:
    table = screen.query_one(selector, DataTable)
    table.focus()
    await wait_until(lambda: screen.app.focused is table)
    table.move_cursor(row=row)
    await pilot.pause()
    return table


async def _s3_open(pilot: Pilot, screen: ObjectStorageScreen, row: int, calls: int) -> None:
    await _focus_table(pilot, screen, "#s3_table", row)
    await pilot.press("o")
    storage = screen.app.ovh_object_storage_service
    await wait_until(lambda: storage.list_objects.await_count == calls)
    await _workers_done(screen.app, "s3_load_objects")


async def _s3_into_folder(pilot: Pilot, screen: ObjectStorageScreen) -> None:
    await _s3_open(pilot, screen, 0, 1)  # bucket "assets"
    await _s3_open(pilot, screen, 0, 2)  # folder "docs/"
    assert (screen._current_bucket, screen._prefix) == ("assets", "docs/")


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
async def test_browser_workspace_pane_combinations(
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
            await _assert_whole_toolbars(app, pilot, screen, case.name)
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=KINDS)
async def test_browser_workspace_native_state_survives_reflow(case: ReflowCase) -> None:
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await preserve_native_state(case, app, pilot, screen)
        await _assert_whole_toolbars(app, pilot, screen, case.name)
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=KINDS)
@pytest.mark.parametrize("kind", ["chat-min", "content-narrow"])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_browser_workspace_uses_qualified_native_boundaries(
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
                await _assert_whole_toolbars(app, pilot, screen, case.name)
            assert case.state(screen) == baseline


@pytest.mark.asyncio
# Each key in the view where it would act from the content.
@pytest.mark.parametrize("key,view", [
    ("r", "buckets"), ("o", "buckets"), ("d", "buckets"), ("u", "folder"), ("d", "folder"),
])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_rail_focused_object_storage_keys_have_no_side_effects(
    key: str, view: str, navigation_visible: bool,
) -> None:
    case = _case("s3")
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        if view == "folder":
            await _s3_into_folder(pilot, screen)
        await _focus_table(pilot, screen, "#s3_table", 0)
        before = (case.state(screen), _s3_effects(app), tuple(app.screen_stack))
        sidebar = await _enter_rail(pilot, screen)
        await pilot.press(key)
        await pilot.pause()
        # A reload, a navigation, a delete confirm or a hidden form would show here.
        assert app.screen is screen
        assert (case.state(screen), _s3_effects(app), tuple(app.screen_stack)) == before
        assert sidebar.navigation_mode and sidebar.has_focus_within
        await pilot.press("escape")
        await wait_until(lambda: not sidebar.navigation_mode)
        assert app.screen is screen and app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["r", "o", "e", "a"])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_rail_focused_vault_keys_have_no_side_effects(
    key: str, navigation_visible: bool,
) -> None:
    case = _case("vault")
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        # Row 0 is the key a server references, so every key would act on it.
        await _focus_table(pilot, screen, "#bw_vault_mgr_table", 0)
        before = (case.state(screen), _vault_effects(app), tuple(app.screen_stack))
        sidebar = await _enter_rail(pilot, screen)
        await pilot.press(key)
        await pilot.pause()
        # A reload, a browser, the ref editor or the import picker would show here.
        assert app.screen is screen
        assert (case.state(screen), _vault_effects(app), tuple(app.screen_stack)) == before
        assert sidebar.navigation_mode and sidebar.has_focus_within
        await pilot.press("escape")
        await wait_until(lambda: not sidebar.navigation_mode)
        assert app.screen is screen and app._exception is None


@pytest.mark.asyncio
async def test_check_action_composes_rail_guard_before_passthrough() -> None:
    for kind, selector, action in (("s3", "#s3_table", "refresh"),
                                   ("dns", "#domains_table", "back"),
                                   ("vault", "#bw_vault_mgr_table", "refresh")):
        case = _case(kind)
        app = case.app_factory(True)
        async with app.run_test(size=(160, 50)) as pilot:
            screen = await open_case(case, app, pilot)
            await _focus_table(pilot, screen, selector, 0)
            assert screen.check_action(action, ()) is True, kind
            await _enter_rail(pilot, screen)
            # Printable single-key bindings are muted from the rail; Escape is not.
            assert screen.check_action("back", ()) is True, kind
            if action == "refresh":
                # The guard is keyed by action, so the vault's F5 (which shares
                # `refresh` with `r`) is muted from the rail too.
                assert screen.check_action("refresh", ()) is None, kind


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_object_storage_back_is_two_level(navigation_visible: bool) -> None:
    case = _case("s3")
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        storage = app.ovh_object_storage_service
        await _s3_open(pilot, screen, 0, 1)
        assert screen._view == "objects"
        await pilot.press("escape")
        await wait_until(lambda: storage.search_buckets.await_count == 2)
        await _workers_done(app, "s3_load_buckets")
        # Objects view → buckets view, without leaving the screen.
        assert app.screen is screen and screen._view == "buckets"
        assert screen._current_bucket == "" and screen._prefix == ""
        await pilot.press("escape")
        await wait_until(lambda: app.screen is not screen)
        # Buckets view → the previous screen; pop drops the result callback.
        assert isinstance(app.screen, InstanceListScreen)
        assert app.root_results == []
        assert storage.delete_bucket.await_count == 0


@pytest.mark.asyncio
async def test_object_storage_navigation_lists_exact_prefixes() -> None:
    case = _case("s3")
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await _s3_into_folder(pilot, screen)
        await pilot.press("u")
        storage = app.ovh_object_storage_service
        await wait_until(lambda: storage.list_objects.await_count == 3)
        await _workers_done(app, "s3_load_objects")
        assert storage.list_objects.await_args_list == [
            call("assets", prefix=prefix, delimiter="/", region="")
            for prefix in ("", "docs/", "")
        ]
        assert screen._prefix == "" and storage.search_buckets.await_count == 1


@pytest.mark.asyncio
async def test_object_storage_delete_beside_chat_targets_the_captured_object() -> None:
    case = _case("s3")
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await open_chat(app, pilot, screen)
        assert content(screen).display
        await _s3_open(pilot, screen, 0, 1)
        await _focus_table(pilot, screen, "#s3_table", 1)
        assert screen._get_selected_object_info() == {"type": "object", "key": "readme.txt"}
        app.allow(app.ovh_object_storage_service.delete_object)
        await pilot.press("d")
        await wait_until(lambda: isinstance(app.screen, ConfirmActionScreen))
        await _type_and_confirm(pilot, app.screen, "readme.txt")
        storage = app.ovh_object_storage_service
        await wait_until(lambda: storage.delete_object.await_count == 1)
        await _workers_done(app, "s3_delete_object", "s3_load_objects")
        assert app.screen is screen
        storage.delete_object.assert_awaited_once_with("assets", "readme.txt", "")
        assert storage.list_objects.await_count == 2
        assert storage.delete_bucket.await_count == 0


@pytest.mark.asyncio
async def test_object_storage_upload_sends_the_typed_target(tmp_path: Path) -> None:
    case = _case("s3")
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await _s3_open(pilot, screen, 0, 1)
        app.allow(app.ovh_object_storage_service.upload_object)
        await _click(pilot, "#btn_s3_upload")
        form = screen.query_one("#s3_upload_form")
        await wait_until(lambda: form.display)
        local = str(tmp_path / "notes.txt")
        screen.query_one("#s3_input_upload_path", Input).value = local
        key = screen.query_one("#s3_input_upload_key", Input)
        key.focus()
        await wait_until(lambda: app.focused is key)
        await pilot.press(*"notes.txt")
        await wait_until(lambda: key.value == "notes.txt")
        # Native Tab reveals the following submit row in the scrolling form.
        assert app.focused is key
        await pilot.press("tab")
        await pilot.pause()
        await pilot.wait_for_scheduled_animations()
        await pilot.pause()
        submit = screen.query_one("#btn_s3_do_upload", Button)
        assert app.focused is submit
        assert_button_label_painted(app, submit)
        assert app.get_widget_at(*submit.region.center)[0] is submit
        await _click(pilot, "#btn_s3_do_upload")
        storage = app.ovh_object_storage_service
        await wait_until(lambda: storage.upload_object.await_count == 1)
        await _workers_done(app, "s3_upload", "s3_load_objects")
        storage.upload_object.assert_awaited_once_with("assets", "notes.txt", local, "")
        # The fake service never reads the local path.
        assert not (tmp_path / "notes.txt").exists() and not form.display


@pytest.mark.asyncio
async def test_object_storage_held_listing_survives_chat_reflow() -> None:
    app = _BrowserHost(True)
    app.list_release.clear()
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        screen = ObjectStorageScreen(provider="ovh")
        await app.push_screen(screen)
        storage = app.ovh_object_storage_service
        await wait_until(lambda: storage.search_buckets.await_count == 1)
        worker = next(w for w in app.workers if w.name == "s3_load_buckets")
        panel = await open_chat(app, pilot, screen)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        assert screen.has_class("-chat-replace") and not content(screen).display
        await pilot.resize_terminal(160, 50)
        await pilot.pause()
        await collapse_chat(app, pilot, screen)
        assert not worker.is_finished and panel.is_attached
        app.list_release.set()
        table = screen.query_one("#s3_table", DataTable)
        await wait_until(lambda: table.row_count == 2)
        await wait_until(lambda: worker.is_finished)
        assert storage.search_buckets.await_args_list == [call()]
        assert [b["name"] for b in screen._buckets] == [b["name"] for b in BUCKETS]
        assert app._exception is None


@pytest.mark.asyncio
async def test_dns_record_delete_beside_chat_targets_the_captured_record() -> None:
    case = _case("dns")
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await open_chat(app, pilot, screen)
        assert content(screen).display
        dns = app.ovh_dns_service
        await _focus_table(pilot, screen, "#domains_table", 0)
        await pilot.press("enter")
        records = screen.query_one("#records_table", DataTable)
        await wait_until(lambda: records.row_count == 1)
        assert screen._selected_zone == "example.com"
        await _focus_table(pilot, screen, "#records_table", 0)
        app.allow(dns.delete_record, dns.refresh_zone, app.ovh_audit.log_action)
        await _click(pilot, "#btn_delete")
        await wait_until(lambda: isinstance(app.screen, ConfirmActionScreen))
        await _type_and_confirm(pilot, app.screen, "9.9.9.9")
        await wait_until(lambda: dns.delete_record.await_count == 1)
        await wait_until(lambda: dns.list_records.await_count == 2)
        await pilot.pause()
        assert app.screen is screen
        dns.delete_record.assert_awaited_once_with("example.com", 101)
        dns.refresh_zone.assert_awaited_once_with("example.com")
        app.ovh_audit.log_action.assert_called_once_with(
            "dns_delete_record", "example.com", {"record_id": 101, "target": "9.9.9.9"},
            confirmed=True,
        )
        assert dns.list_records.await_args_list == [call("example.com")] * 2
        assert (dns.create_record.await_count, dns.update_record.await_count) == (0, 0)


@pytest.mark.asyncio
async def test_vault_load_reads_and_ensures_only_the_configured_folder() -> None:
    case = _case("vault")
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        bw, cfg = app.bw_session_service, app.bw_ssh_config_service
        bw.status.assert_awaited_once_with()
        # The folder ensure creates a missing folder; the fake only records it.
        bw.ensure_servonaut_folder.assert_awaited_once_with("Servonaut")
        bw.list_items.assert_awaited_once_with(folder_id="folder-1", ssh_only=True)
        cfg.get_personal_config.assert_awaited_once_with()
        cfg.list_personal_instances.assert_awaited_once_with()
        cfg.get_personal_instance_ref.assert_awaited_once_with("custom", "id-web-1")
        assert [row["item_id"] for row in screen._rows] == list(ITEMS)
        assert [ref["instance_id"] for ref in screen._rows[0]["refs"]] == ["id-web-1"]
        assert screen._rows[1]["refs"] == []
        assert app.screen is screen and app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["o", "r"])
async def test_vault_keys_still_act_from_content(
    key: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened = Mock()
    monkeypatch.setattr("webbrowser.open", opened)
    case = _case("vault")
    app = case.app_factory(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        bw = app.bw_session_service
        await _focus_table(pilot, screen, "#bw_vault_mgr_table", 0)
        await pilot.press(key)
        if key == "o":
            await wait_until(lambda: opened.called)
            opened.assert_called_once_with(f"{VAULT_URL}/#/vault?itemId={ITEMS[0]}")
            assert bw.status.await_count == 1
        else:
            await wait_until(lambda: bw.status.await_count == 2)
            await wait_until(lambda: not screen._loading)
            assert bw.ensure_servonaut_folder.await_args_list == [call("Servonaut")] * 2
            assert bw.list_items.await_args_list == [
                call(folder_id="folder-1", ssh_only=True)] * 2
            opened.assert_not_called()
        assert app.screen is screen and app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("case", [c for c in CASES if c.name in {"s3", "vault"}], ids=lambda c: c.name)
async def test_action_hints_are_bindings_and_the_key_matches_the_click(case: ReflowCase) -> None:
    from tests._hint_conformance import assert_hints_match_bindings, record_actions

    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        calls: list[str] = []
        record_actions(screen, calls)
        assert await assert_hints_match_bindings(pilot, screen, calls) >= 1
