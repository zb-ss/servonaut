"""Cloud workspaces retain native forms, loaded rows and focus through reflow."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterator
from unittest.mock import AsyncMock, patch

import pytest
from textual.pilot import Pilot
from textual.widgets import Button, DataTable, Input, Static, TextArea

from servonaut.app import ServonautApp
from servonaut.screens.aws_create import AWSCreateScreen
from servonaut.screens.aws_manager import AWSManagerScreen
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.hetzner_create import HetznerCreateScreen
from servonaut.screens.hetzner_manager import HetznerManagerScreen
from servonaut.screens.hetzner_ssh_keys import HetznerSSHKeysScreen
from servonaut.widgets.account_picker import AccountPicker
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import (
    BoundarySample, ReflowCase,
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
from tests.test_selection_copy import _Clipboard, _drag
from tests.test_selection_copy import clipboard as clipboard
from tests.test_workspace_cloud_managers import _CloudApp
from tests.test_workspace_pilot import _click
from tests.test_workspace_reflow import _painted


MUTATIONS = {
    "aws_service": (
        "run_instances", "start_instance", "stop_instance", "reboot_instance",
        "terminate_instance",
    ),
    "hetzner_service": (
        "create_server", "delete_server", "power_on", "shutdown", "power_off",
        "reboot", "create_ssh_key", "delete_ssh_key",
    ),
}


@pytest.fixture(autouse=True)
def _isolated_providers(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    mutations: list[AsyncMock] = []
    original_init = _CloudApp.__init__

    def initialize(
        self: _CloudApp, screen_type: type[WorkspaceScreen], visible: bool = True,
    ) -> None:
        # The existing host supplies only _aws()/_hetzner() AsyncMock lists.
        original_init(self, screen_type, visible)
        for service_name, methods in MUTATIONS.items():
            service = getattr(self, service_name)
            for method in methods:
                guard = AsyncMock(
                    side_effect=AssertionError("Unexpected cloud mutation"),
                )
                setattr(service, method, guard)
                mutations.append(guard)

    monkeypatch.setattr(_CloudApp, "__init__", initialize)
    yield
    for mutation in mutations:
        mutation.assert_not_called()


def _factory(
    screen_type: type[WorkspaceScreen],
) -> Callable[[bool], _CloudApp]:
    def create(visible: bool) -> _CloudApp:
        app = _CloudApp(screen_type, visible)
        app.theme = "servonaut"
        return app
    return create


async def _screen(app: ServonautApp, pilot: Pilot) -> WorkspaceScreen:
    assert isinstance(app, _CloudApp)
    await wait_until(lambda: isinstance(app.screen, app.screen_type))
    return app.screen


async def _ready(screen: WorkspaceScreen) -> None:
    # Wait for every wizard table, not only the region/type bootstrap table.
    await wait_until(lambda: bool(screen.query(DataTable)))
    await wait_until(lambda: all(table.row_count for table in screen.query(DataTable)))
    await wait_until(lambda: not getattr(screen, "_loading", False))


def _seed(screen: WorkspaceScreen) -> None:
    if isinstance(screen, AWSCreateScreen):
        screen.query_one("#aws_input_name", Input).value = "web-nsdr-01"
    elif isinstance(screen, HetznerCreateScreen):
        screen.query_one("#hetzner_input_name", Input).value = "web-nsdr-01"
    elif isinstance(screen, (AWSManagerScreen, HetznerManagerScreen)):
        screen.query_one(DataTable).move_cursor(row=1)


def _state(screen: WorkspaceScreen) -> object:
    tables = tuple(
        (table, table.cursor_row,
         tuple(tuple(table.get_row_at(i)) for i in range(table.row_count)))
        for table in screen.query(DataTable)
    )
    inputs = tuple((field, field.value) for field in screen.query(Input))
    accounts = tuple((picker, picker.account) for picker in screen.query(AccountPicker))
    buttons = tuple(
        (button, button.disabled) for button in content(screen).query(Button)
    )
    loaded = tuple(
        (name, repr(getattr(screen, name)))
        for name in (
            "_raw_instances", "_api_ids", "_regions", "_amis", "_instance_types",
            "_key_pairs", "_subnets", "_security_groups", "_server_types",
            "_images", "_locations", "_ssh_keys", "_keys",
        ) if hasattr(screen, name)
    )
    reads = tuple(
        (service_name, name, value.await_count)
        for service_name in MUTATIONS
        for name, value in vars(getattr(screen.app, service_name)).items()
        if isinstance(value, AsyncMock) and name not in MUTATIONS[service_name]
    )
    return tables, inputs, accounts, buttons, loaded, reads


# All boundary mappings remain absent until actual native qualification.
# Terminal fixtures must pin native integer widths and independently qualified
# raw Fraction flags; native offset zero does not imply policy equality.
# Qualified native columns and separately measured layout policy.
_MEASURED_BOUNDARIES = {
    'aws-create': {
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
    'aws-manager': {
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
            BoundarySample((167, 50), 103, False, True),
            BoundarySample((168, 50), 104, False, False),
            BoundarySample((169, 50), 105, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((192, 50), 103, False, True),
            BoundarySample((193, 50), 104, False, False),
            BoundarySample((194, 50), 105, False, False),
        ),
    },
    'hetzner-create': {
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
    'hetzner-manager': {
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
            BoundarySample((180, 50), 116, False, True),
            BoundarySample((181, 50), 117, False, False),
            BoundarySample((182, 50), 118, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((205, 50), 116, False, True),
            BoundarySample((206, 50), 117, False, False),
            BoundarySample((207, 50), 118, False, False),
        ),
    },
    'hetzner-keys': {
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
            BoundarySample((167, 50), 103, False, True),
            BoundarySample((168, 50), 104, False, False),
            BoundarySample((169, 50), 105, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((192, 50), 103, False, True),
            BoundarySample((193, 50), 104, False, False),
            BoundarySample((194, 50), 105, False, False),
        ),
    },
}


CASES = (
    ReflowCase(
        "aws-create", _factory(AWSCreateScreen), _screen, _ready,
        "#aws_create_container",
        ("#aws_input_name", "#aws_regions_table", "#aws_amis_table",
         "#aws_types_table", "#aws_keys_table", "#aws_subnets_table", "#aws_sg_table",
         "#btn_aws_create_submit", "#btn_aws_create_back"),
        _seed, _state, (("#aws_regions_table", "us-east-1"),), boundaries=_MEASURED_BOUNDARIES['aws-create'],
    ),
    ReflowCase(
        "aws-manager", _factory(AWSManagerScreen), _screen, _ready,
        "#aws_mgr_container",
        ("#aws_mgr_table", "#btn_aws_mgr_refresh", "#btn_aws_mgr_new",
         "#btn_aws_mgr_start", "#btn_aws_mgr_terminate"),
        _seed, _state, (("#aws_mgr_table", "db-1"),), boundaries=_MEASURED_BOUNDARIES['aws-manager'],
    ),
    ReflowCase(
        "hetzner-create", _factory(HetznerCreateScreen), _screen, _ready,
        "#hetzner_create_container",
        ("#hetzner_input_name", "#hetzner_types_table", "#hetzner_images_table",
         "#hetzner_locations_table", "#hetzner_keys_table",
         "#btn_hetzner_create_submit", "#btn_hetzner_create_back"),
        _seed, _state, (("#hetzner_types_table", "small"),), boundaries=_MEASURED_BOUNDARIES['hetzner-create'],
    ),
    ReflowCase(
        "hetzner-manager", _factory(HetznerManagerScreen), _screen, _ready,
        "#hetzner_mgr_container",
        ("#hetzner_mgr_table", "#btn_hetzner_mgr_refresh", "#btn_hetzner_mgr_new",
         "#btn_hetzner_mgr_power_on", "#btn_hetzner_mgr_delete"),
        _seed, _state, (("#hetzner_mgr_table", "db-1"),), boundaries=_MEASURED_BOUNDARIES['hetzner-manager'],
    ),
    ReflowCase(
        "hetzner-keys", _factory(HetznerSSHKeysScreen), _screen, _ready,
        "#hetzner_ssh_keys_container",
        ("#hetzner_ssh_keys_table", "#btn_hetzner_ssh_refresh",
         "#btn_hetzner_ssh_add", "#btn_hetzner_ssh_delete", "#btn_hetzner_ssh_back"),
        _seed, _state, (("#hetzner_ssh_keys_table", "example-key"),), boundaries=_MEASURED_BOUNDARIES['hetzner-keys'],
    ),
)
CASE_IDS = [case.name for case in CASES]
COPY_TARGETS = {
    "aws-create": ("#aws_create_title", "EC2"),
    "aws-manager": ("#aws_mgr_header", "AWS"),
    "hetzner-create": ("#hetzner_create_title", "Hetzner"),
    "hetzner-manager": ("#hetzner_mgr_header", "Hetzner"),
    "hetzner-keys": ("#hetzner_ssh_keys_header", "SSH"),
}
TOOLBARS = {
    "aws-create": "#aws_create_actions",
    "aws-manager": "#aws_mgr_actions",
    "hetzner-create": "#hetzner_create_actions",
    "hetzner-manager": "#hetzner_mgr_actions",
    "hetzner-keys": "#hetzner_ssh_keys_actions",
}


async def _assert_toolbar_exposed(
    case: ReflowCase, app: ServonautApp, pilot: Pilot, screen: WorkspaceScreen,
) -> None:
    # Disabled actions still need visible labels and intact native hit regions;
    # they correctly remain outside the keyboard focus chain.
    buttons = list(screen.query_one(TOOLBARS[case.name]).query(Button))
    assert buttons
    for button in buttons:
        button.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        assert content(screen).region.contains_region(button.region)
        assert screen.region.contains_region(button.region)
        assert app.get_widget_at(*button.region.center)[0] is button
        assert button.label.plain in _painted(app, button)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("navigation_visible,chat_open", [
    (False, False), (False, True), (True, False), (True, True),
])
async def test_cloud_reflow_preserves_four_visibility_states_and_loaded_content(
    case: ReflowCase, size: tuple[int, int],
    navigation_visible: bool, chat_open: bool,
) -> None:
    app = case.app_factory(navigation_visible)
    async with app.run_test(size=size) as pilot:
        screen = await open_case(case, app, pilot)
        baseline = case.state(screen)
        if chat_open:
            panel = await open_chat(app, pilot, screen)
        assert_layout(app, screen)
        assert screen.query_one(Sidebar).display is navigation_visible
        assert case.state(screen) == baseline
        if chat_open:
            available = screen._available_content_width(
                screen.query_one("#main-layout"), panel,
            )
            assert available is not None
            expected_replace = available < screen.CHAT_MIN_CONTENT_WIDTH
            assert screen.has_class("-chat-replace") is expected_replace
            assert content(screen).display is (not expected_replace)
            assert content(screen).is_attached
        if content(screen).display:
            await assert_essential_targets(case, app, pilot, screen)
            await _assert_toolbar_exposed(case, app, pilot, screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
async def test_cloud_reflow_retains_native_focus_forms_selection_and_tab_targets(
    case: ReflowCase,
) -> None:
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await preserve_native_state(case, app, pilot, screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
async def test_cloud_literal_title_copy_survives_replacement_and_restore(
    case: ReflowCase, clipboard: _Clipboard,
) -> None:
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await open_chat(app, pilot, screen)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        await collapse_chat(app, pilot, screen)
        selector, literal = COPY_TARGETS[case.name]
        title = screen.query_one(selector, Static)
        title.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        rows = _painted(app, title).splitlines()
        row = next(i for i, text in enumerate(rows) if literal in text)
        x = title.region.x - title.content_region.x + rows[row].index(literal)
        y = title.region.y - title.content_region.y + row
        await _drag(pilot, title, (x, y), (x + len(literal), y))
        assert clipboard.calls == [literal]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("kind", ["chat-min", "content-narrow"])
async def test_cloud_qualified_native_boundary_preserves_painted_fit(
    case: ReflowCase, navigation_visible: bool, kind: str,
) -> None:
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
                # Probe native width only; real policy replaces this content.
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
                await assert_essential_targets(case, app, pilot, screen)
                await _assert_toolbar_exposed(case, app, pilot, screen)
            assert case.state(screen) == baseline


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
async def test_cloud_navigation_crossing_modal_keeps_native_origin_and_draft(
    case: ReflowCase,
) -> None:
    sample = case.boundary_samples("chat-min", True)[0]
    assert sample.expected_replace
    app = case.app_factory(False)
    async with app.run_test(size=sample.size) as pilot:
        screen = await open_case(case, app, pilot)
        panel = await open_chat(app, pilot, screen)
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Keep the cloud draft")
        document = editor.document
        assert content(screen).display
        origin = screen.query_one(case.primary_focus_selector)
        await tab_to(pilot, origin)
        await pilot.press("shift+f6")
        sidebar = screen.query_one(Sidebar)
        await wait_until(lambda: sidebar.navigation_mode and sidebar.has_focus_within)
        assert not content(screen).display
        modal = ConfirmActionScreen(
            "Review action", "No cloud operation is connected.",
            ["Keep this workspace intact"], "CONFIRM", "Confirm",
        )
        await app.push_screen(modal)
        await wait_until(lambda: app.focused is modal.query_one("#confirm_input"))
        assert not sidebar.navigation_mode and not sidebar.display
        assert content(screen).display and screen.focused is origin
        await pilot.press("shift+f6", "f2", "ctrl+g")
        assert app.screen is modal and app.focused is modal.query_one("#confirm_input")
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen and app.focused is origin)
        assert editor.document is document and editor.text == "Keep the cloud draft"


@pytest.mark.asyncio
@pytest.mark.parametrize("case,theme", [
    (CASES[0], "servonaut-light"), (CASES[3], "ansi-dark"),
    (CASES[4], "ansi-light"),
], ids=["aws-create-light", "hetzner-manager-ansi-dark", "keys-ansi-light"])
async def test_cloud_representative_palettes_keep_native_targets(
    case: ReflowCase, theme: str,
) -> None:
    app = case.app_factory(True)
    app.theme = theme
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await open_chat(app, pilot, screen)
        assert_layout(app, screen)
        await collapse_chat(app, pilot, screen)
        await assert_essential_targets(case, app, pilot, screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("case,service_name,method", [
    (CASES[0], "aws_service", "list_regions"),
    (CASES[2], "hetzner_service", "list_server_types"),
], ids=["aws-create", "hetzner-create"])
async def test_native_worker_load_finishes_under_replaced_chat_without_focus_theft(
    case: ReflowCase, service_name: str, method: str,
) -> None:
    app = case.app_factory(False)
    service = getattr(app, service_name)
    original = getattr(service, method)
    started, release = asyncio.Event(), asyncio.Event()

    async def gated(*args: object, **kwargs: object) -> list[object]:
        started.set()
        await release.wait()
        return await original(*args, **kwargs)

    setattr(service, method, AsyncMock(side_effect=gated))
    async with app.run_test(size=(100, 30)) as pilot:
        try:
            screen = await case.open_screen(app, pilot)
            await wait_until(started.is_set)
            assert app.focused is screen.query_one(case.primary_focus_selector)
            panel = await open_chat(app, pilot, screen)
            editor = panel.query_one("#chat-input", TextArea)
            editor.load_text("Keep typing during loading")
            assert not content(screen).display
            release.set()
            await case.ready(screen)
            await pilot.pause()
            assert app.focused is editor and not content(screen).display
            assert editor.text == "Keep typing during loading"
            await pilot.resize_terminal(160, 50)
            await pilot.pause()
            await collapse_chat(app, pilot, screen)
            await wait_until(
                lambda: app.focused is screen.query_one(case.primary_focus_selector),
            )
        finally:
            release.set()


@pytest.mark.asyncio
async def test_native_key_add_form_dock_and_unsaved_fields_survive_reflow() -> None:
    case = CASES[4]
    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await tab_to(pilot, screen.query_one("#btn_hetzner_ssh_add"))
        await _click(pilot, "#btn_hetzner_ssh_add")
        name = screen.query_one("#hetzner_ssh_input_name", Input)
        public_key = screen.query_one("#hetzner_ssh_input_public_key", Input)
        await wait_until(lambda: app.focused is name)
        await pilot.press(*"example-key-draft")
        await tab_to(pilot, public_key)
        # This is deliberately not a usable key and Save is never activated.
        await pilot.press(*"ssh-ed25519 example-public-key")
        baseline = case.state(screen)
        await open_chat(app, pilot, screen)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        assert not content(screen).display
        await collapse_chat(app, pilot, screen)
        await wait_until(lambda: app.focused is public_key)
        assert case.state(screen) == baseline
        form = screen.query_one("#hetzner_ssh_add_form")
        assert not form.has_class("hidden")
        for selector in ("#btn_hetzner_ssh_save", "#btn_hetzner_ssh_cancel"):
            button = screen.query_one(selector, Button)
            await tab_to(pilot, button)
            await pilot.pause()
            assert screen.region.contains_region(button.region)
            assert app.get_widget_at(*button.region.center)[0] is button
            assert button.label.plain in _painted(app, button)
        await _click(pilot, "#btn_hetzner_ssh_cancel")
        await pilot.pause()
        assert form.has_class("hidden")


@pytest.mark.asyncio
@pytest.mark.parametrize("case", [c for c in CASES if c.name in {"hetzner-keys"}], ids=lambda c: c.name)
async def test_action_hints_are_bindings_and_the_key_matches_the_click(case: ReflowCase) -> None:
    from tests._hint_conformance import assert_hints_match_bindings, record_actions

    app = case.app_factory(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        calls: list[str] = []
        record_actions(screen, calls)
        assert await assert_hints_match_bindings(pilot, screen, calls) >= 1
