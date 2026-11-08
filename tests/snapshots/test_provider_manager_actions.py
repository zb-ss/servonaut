"""AWS, OVH and Hetzner managers share one action rail: roles, danger zone, muted actions."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from textual.widgets import DataTable

from servonaut.widgets.action_button import ActionButton, ActionRow
from servonaut.widgets.chat_panel import ChatPanel
from tests._async_bounds import wait_until
from tests.snapshots import _harness
from tests.test_fleet_workspace_layout import _open_chat


@dataclass(frozen=True)
class Manager:
    nav_id: str
    screen: str
    prefix: str
    table: str
    rows: int
    # (button id suffix, key, handler)
    actions: tuple[tuple[str, str | None, str], ...]
    start: str
    others: tuple[str, ...]
    danger: str
    # row index -> ids of the power/danger actions that are enabled when it is selected
    enabled: dict[int, frozenset[str]]


AWS = Manager(
    "nav_aws_manage", "AWSManagerScreen", "aws_mgr", "aws_mgr_table", len(_harness.AWS_ROWS),
    (("refresh", "f5", "action_refresh"), ("new", "n", "action_new"), ("start", "s", "action_start"),
     ("stop", "t", "action_stop"), ("reboot", "b", "action_reboot"),
     ("terminate", "d", "action_terminate")),
    "start", ("stop", "reboot"), "terminate",
    {0: frozenset({"stop", "reboot", "terminate"}), 1: frozenset({"start", "terminate"})},
)
OVH = Manager(
    "nav_ovh_manage", "OVHManagerScreen", "ovh_mgr", "ovh_mgr_table", len(_harness.OVH_ROWS),
    (("refresh", "f5", "action_refresh"), ("new", "n", "action_new"), ("start", "s", "action_start"),
     ("stop", "t", "action_stop"), ("reboot", "b", "action_reboot"), ("delete", "d", "action_delete")),
    "start", ("stop", "reboot"), "delete",
    {0: frozenset({"stop", "reboot"}), 1: frozenset({"start", "delete"})},
)
HETZNER = Manager(
    "nav_hetzner_manage", "HetznerManagerScreen", "hetzner_mgr", "hetzner_mgr_table",
    len(_harness.HETZNER_ROWS),
    (("refresh", "f5", "action_refresh"), ("new", "n", "action_new"), ("power_on", "s", "action_power_on"),
     ("shutdown", "t", "action_shutdown"), ("power_off", None, "action_power_off"),
     ("reboot", "b", "action_reboot"), ("delete", "d", "action_delete")),
    "power_on", ("shutdown", "reboot"), "delete",
    {0: frozenset({"shutdown", "power_off", "reboot", "delete"})},
)
MANAGERS = [AWS, OVH, HETZNER]
IDS = ["aws", "ovh", "hetzner"]
SIZES = [(160, 50), (100, 30)]
POWER_AND_DANGER = {"start", "stop", "reboot", "terminate", "delete", "power_on", "shutdown", "power_off"}


@pytest.fixture(autouse=True)
def _no_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)


def _bid(manager: Manager, suffix: str) -> str:
    return f"btn_{manager.prefix}_{suffix}"


async def _open(app, pilot, manager: Manager, row: int | None = 0):
    await _harness.wait_for_fleet(pilot)
    app.screen.query_one(f"#{manager.nav_id}").press()
    screen = await _harness.wait_for_screen(pilot, manager.screen)
    table = screen.query_one(f"#{manager.table}", DataTable)
    await wait_until(lambda: table.row_count == manager.rows)
    if row is not None:
        table.move_cursor(row=row)
    await pilot.pause()
    await pilot.pause()
    return screen


@pytest.mark.asyncio
@pytest.mark.parametrize("manager", MANAGERS, ids=IDS)
async def test_roles_and_the_danger_zone(manager: Manager) -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open(app, pilot, manager)
        button = lambda suffix: screen.query_one(f"#{_bid(manager, suffix)}", ActionButton)  # noqa: E731
        assert button("new").has_class("-primary")
        assert not button("refresh").has_class("-primary")
        assert button(manager.start).has_class("-primary")
        for suffix in manager.others:
            for role in ("-primary", "-error"):
                assert not button(suffix).has_class(role), suffix
        danger = screen.query_one(".provider-manager-danger")
        assert str(danger.query_one(".provider-manager-action-label").content) == "Danger zone"
        assert [b.id for b in danger.query(ActionButton)] == [_bid(manager, manager.danger)]
        assert button(manager.danger).has_class("-error")
        everyday = screen.query(".provider-manager-action-group").exclude(".provider-manager-danger")
        for group in everyday:
            assert not any(b.has_class("-error") for b in group.query(ActionButton))


@pytest.mark.asyncio
async def test_hetzner_power_off_is_a_risky_action_listed_last() -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open(app, pilot, HETZNER)
        power_off = screen.query_one("#btn_hetzner_mgr_power_off", ActionButton)
        assert power_off.has_class("-warning")
        assert "pulling the plug" in str(power_off.tooltip)
        group = next(a for a in power_off.ancestors if a.has_class("provider-manager-action-group"))
        assert not group.has_class("provider-manager-danger")
        assert [b.id for b in group.query(ActionButton)][-1] == "btn_hetzner_mgr_power_off"


@pytest.mark.asyncio
@pytest.mark.parametrize("manager", MANAGERS, ids=IDS)
async def test_actions_follow_the_selected_row_and_say_why_not(manager: Manager) -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open(app, pilot, manager, row=None)
        table = screen.query_one(f"#{manager.table}", DataTable)
        everything = {b.id for b in screen.query(ActionButton) if b.id}
        gated = {i for i in everything if i.removeprefix(f"btn_{manager.prefix}_") in POWER_AND_DANGER}
        for row, enabled in manager.enabled.items():
            table.focus()
            table.move_cursor(row=row)
            await pilot.pause()
            await pilot.pause()
            for button_id in gated:
                button = screen.query_one(f"#{button_id}", ActionButton)
                is_enabled = button_id.removeprefix(f"btn_{manager.prefix}_") in enabled
                assert (not button.disabled) is is_enabled, (row, button_id)
                if not is_enabled:
                    assert button.tooltip, f"{button_id} is disabled without a reason"
                elif not button_id.endswith("power_off"):
                    assert not button.tooltip


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_disabled_actions_are_visibly_muted(size) -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=size) as pilot:
        screen = await _open(app, pilot, AWS, row=0)  # app-1 is running: Start is disabled
        start = screen.query_one("#btn_aws_mgr_start", ActionButton)
        stop = screen.query_one("#btn_aws_mgr_stop", ActionButton)
        launch = screen.query_one("#btn_aws_mgr_new", ActionButton)
        assert start.disabled and not stop.disabled
        assert start.has_class("-primary"), "a disabled primary keeps its role class"
        assert start.styles.color != stop.styles.color
        assert start.styles.background.a == 0, "a disabled Start keeps the primary fill"
        if start.compact:
            assert launch.styles.background.a > 0, "compact primary is filled when enabled"


@pytest.mark.asyncio
@pytest.mark.parametrize("manager", MANAGERS, ids=IDS)
async def test_every_action_is_reachable_by_click_and_key(manager: Manager) -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open(app, pilot, manager)
        for suffix, key, handler in manager.actions:
            calls: list[str] = []
            setattr(screen, handler, lambda handler=handler, calls=calls: calls.append(handler))
            button = screen.query_one(f"#{_bid(manager, suffix)}", ActionButton)
            button.disabled = False  # the wiring is under test, not the row's state
            button.press()
            await pilot.pause()
            assert calls == [handler], f"click {suffix}"
            if key:
                screen.query_one(f"#{manager.table}").focus()
                await pilot.press(key)
                await pilot.pause()
                assert calls == [handler, handler], f"key {key}"


@pytest.mark.asyncio
@pytest.mark.parametrize("manager", MANAGERS, ids=IDS)
@pytest.mark.parametrize("chat", [False, True])
async def test_no_action_is_clipped_across_a_width_sweep(manager: Manager, chat: bool) -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(160, 40)) as pilot:
        screen = await _open(app, pilot, manager)
        if chat:
            await _open_chat(app, pilot)
        for width in (*range(160, 111, -16), *range(110, 79, -6)):
            await pilot.resize_terminal(width, 40)
            previous = None
            for _ in range(20):
                await pilot.pause()
                current = [(b.id, b.region) for b in screen.query(ActionButton)]
                if current == previous:
                    break
                previous = current
            if not screen.query_one(f"#{manager.prefix}_container").display:
                continue
            rail = screen.query_one(".provider-manager-rail")
            for row in screen.query(ActionRow):
                for button in row.query(ActionButton):
                    assert row.region.contains_region(button.region), (width, button.id)
                    assert rail.region.contains_region(button.region), (width, button.id)
                    assert button.content_size.width >= button.label.cell_length, (width, button.id)
            danger = screen.query(".provider-manager-danger ActionButton").first()
            danger.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            assert app.get_widget_at(*danger.region.center)[0] is danger, (width, "danger button not reachable")


@pytest.mark.asyncio
@pytest.mark.parametrize("manager", MANAGERS, ids=IDS)
async def test_demo_mode_keeps_the_rail_and_hides_real_names(manager: Manager) -> None:
    app = _harness.SnapshotApp(demo=True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open(app, pilot, manager)
        assert app.demo_mode
        real_names = {row["name"] for row in (_harness.AWS_ROWS + _harness.OVH_ROWS + _harness.HETZNER_ROWS)}
        shown = str(screen.query_one(f"#{manager.prefix}_selection").content)
        assert shown and shown not in real_names
        ids = {b.id for b in screen.query(ActionButton)}
        assert {_bid(manager, suffix) for suffix, _key, _handler in manager.actions} <= ids


@pytest.mark.asyncio
@pytest.mark.parametrize("manager", MANAGERS, ids=IDS)
async def test_buttons_are_compact_exactly_when_the_content_is_narrow(manager: Manager) -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open(app, pilot, manager)
        assert not any(b.compact for b in screen.query(ActionButton))
        await pilot.resize_terminal(100, 30)
        await wait_until(lambda: all(b.compact for b in screen.query(ActionButton)))
        await pilot.resize_terminal(160, 50)
        await wait_until(lambda: not any(b.compact for b in screen.query(ActionButton)))


def _state_matrix(manager: Manager) -> list[tuple[dict, frozenset[str]]]:
    """(row changes, ids of the power/danger actions enabled) for transitional states too."""
    if manager is AWS:
        return [
            ({"state": "running"}, frozenset({"stop", "reboot", "terminate"})),
            ({"state": "stopped"}, frozenset({"start", "terminate"})),
            ({"state": "pending"}, frozenset({"terminate"})),
            ({"state": "stopping"}, frozenset({"terminate"})),
            ({"state": "shutting-down"}, frozenset()),
            ({"state": "terminated"}, frozenset()),
            ({"state": "RUNNING"}, frozenset({"stop", "reboot", "terminate"})),
        ]
    if manager is HETZNER:
        return [
            ({"state": "running"}, frozenset({"shutdown", "power_off", "reboot", "delete"})),
            ({"state": "off"}, frozenset({"power_on", "delete"})),
            ({"state": "starting"}, frozenset({"delete"})),
            ({"state": "stopping"}, frozenset({"delete"})),
            ({"state": "deleting"}, frozenset({"delete"})),
            ({"state": "unknown"}, frozenset({"delete"})),
        ]
    return [
        ({"provider_type": "vps", "state": "running"}, frozenset({"stop", "reboot"})),
        ({"provider_type": "vps", "state": "stopped"}, frozenset({"start"})),
        ({"provider_type": "vps", "state": "pending"}, frozenset()),
        ({"provider_type": "cloud", "state": "active"}, frozenset({"stop", "reboot", "delete"})),
        ({"provider_type": "cloud", "state": "shutoff"}, frozenset({"start", "delete"})),
        ({"provider_type": "cloud", "state": "pending"}, frozenset({"delete"})),
        ({"provider_type": "dedicated", "state": "running"}, frozenset({"reboot"})),
        ({"provider_type": "dedicated", "state": "pending"}, frozenset({"reboot"})),
        ({"provider_type": "", "state": "running"}, frozenset()),
        ({"provider_type": "baremetal", "state": "running"}, frozenset()),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("manager", MANAGERS, ids=IDS)
async def test_every_state_enables_exactly_the_right_actions(manager: Manager) -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open(app, pilot, manager)
        gated = {
            b.id for b in screen.query(ActionButton)
            if b.id and b.id.removeprefix(f"btn_{manager.prefix}_") in POWER_AND_DANGER
        }
        for changes, enabled in _state_matrix(manager):
            screen._instances[0].update(changes)
            screen._sync_action_buttons()
            await pilot.pause()
            for button_id in gated:
                button = screen.query_one(f"#{button_id}", ActionButton)
                is_enabled = button_id.removeprefix(f"btn_{manager.prefix}_") in enabled
                assert (not button.disabled) is is_enabled, (changes, button_id)
                if not is_enabled:
                    assert button.tooltip, (changes, button_id)
                elif not button_id.endswith("power_off"):
                    assert not button.tooltip, (changes, button_id)


# Shortcut -> (button suffix, handler under test). Only actions with a disabled state are listed.
KEYED = {
    "aws": (("s", "start"), ("t", "stop"), ("b", "reboot")),
    "ovh": (("s", "start"), ("t", "stop"), ("b", "reboot")),
    "hetzner": (("s", "power_on"), ("t", "shutdown"), ("b", "reboot")),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("manager,name", list(zip(MANAGERS, IDS)), ids=IDS)
async def test_shortcuts_refuse_what_the_button_refuses(manager: Manager, name: str) -> None:
    """A key on a row whose button is disabled says why and starts nothing."""
    app = _harness.SnapshotApp()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open(app, pilot, manager)
        started: list[str] = []
        screen._run_lifecycle = lambda method: started.append(method)
        for changes, enabled in _state_matrix(manager):
            screen._instances[0].update(changes)
            screen._sync_action_buttons()
            await pilot.pause()
            for key, suffix in KEYED[name]:
                button = screen.query_one(f"#{_bid(manager, suffix)}", ActionButton)
                notes: list[str] = []
                original = screen.notify
                screen.notify = lambda message, **kw: notes.append(message)  # noqa: E731
                started.clear()
                screen.query_one(f"#{manager.table}").focus()
                await pilot.press(key)
                await pilot.pause()
                screen.notify = original
                if button.disabled:
                    assert not started, (changes, key, "started a disabled action")
                    assert notes == [button.tooltip], (changes, key, notes)
                else:
                    assert started and not notes, (changes, key)


@pytest.mark.asyncio
@pytest.mark.parametrize("manager", MANAGERS, ids=IDS)
async def test_narrow_layout_shows_every_action_without_scrolling(manager: Manager) -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _open(app, pilot, manager)
        container = screen.query_one(f"#{manager.prefix}_container")
        buttons = [b for b in screen.query(".provider-manager-rail ActionButton")]
        assert container.scroll_y == 0
        for button in buttons:
            assert container.region.contains_region(button.region), (button.id, button.region, container.region)
        assert not screen.query_one(f"#{manager.prefix}_hint").display
        rail = screen.query_one(".provider-manager-rail")
        table_panel = screen.query_one(".provider-manager-inventory")
        assert rail.region.y < table_panel.region.y


@pytest.mark.asyncio
@pytest.mark.parametrize("manager", MANAGERS, ids=IDS)
async def test_wide_layout_keeps_the_table_before_the_rail(manager: Manager) -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open(app, pilot, manager)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        await pilot.resize_terminal(160, 50)
        for _ in range(6):
            await pilot.pause()
        rail = screen.query_one(".provider-manager-rail")
        table_panel = screen.query_one(".provider-manager-inventory")
        assert table_panel.region.x < rail.region.x
        assert screen.query_one(f"#{manager.prefix}_hint").display


@pytest.mark.asyncio
@pytest.mark.parametrize("manager", MANAGERS, ids=IDS)
@pytest.mark.parametrize("size", SIZES)
async def test_every_button_on_a_screen_is_in_the_same_hint_state(manager: Manager, size) -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=size) as pilot:
        screen = await _open(app, pilot, manager)
        buttons = [b for b in screen.query(".provider-manager-rail ActionButton")]
        has_hint = {b.id: bool(b._key) and b._hint for b in buttons if b._key}
        assert len(set(has_hint.values())) == 1, has_hint
        shown = {b.id: b.label.plain.endswith(b._key) for b in buttons if b._key}
        assert len(set(shown.values())) == 1, shown


def _style_signature(app, widget) -> frozenset[tuple]:
    """The colours and attributes painted over *widget*, without its text."""
    rows = app.screen._compositor.render_strips()
    cells = set()
    for y in range(widget.region.y, widget.region.bottom):
        for segment in rows[y].crop(widget.region.x, widget.region.right):
            style = segment.style
            if style is None or not segment.text.strip():
                continue
            cells.add((
                str(style.color), str(style.bgcolor), style.bold, style.dim,
                style.underline, style.reverse,
            ))
    return frozenset(cells)


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["ansi-dark", "ansi-light", "servonaut", "servonaut-light"])
@pytest.mark.parametrize("size", SIZES)
async def test_disabled_default_and_danger_actions_paint_distinctly(theme, size) -> None:
    app = _harness.SnapshotApp()
    app.theme = theme
    async with app.run_test(size=size) as pilot:
        screen = await _open(app, pilot, AWS, row=1)  # stopped: Stop is disabled
        disabled = screen.query_one("#btn_aws_mgr_stop", ActionButton)
        default = screen.query_one("#btn_aws_mgr_refresh", ActionButton)
        danger = screen.query_one("#btn_aws_mgr_terminate", ActionButton)
        for button in (disabled, default, danger):
            button.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
        signatures = {
            "disabled": _style_signature(app, disabled),
            "default": _style_signature(app, default),
            "danger": _style_signature(app, danger),
        }
        assert all(signatures.values()), signatures
        names = list(signatures)
        for index, first in enumerate(names):
            for second in names[index + 1:]:
                assert signatures[first] != signatures[second], (theme, size, first, second)
