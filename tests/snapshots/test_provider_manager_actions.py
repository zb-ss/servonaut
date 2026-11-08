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
        table.focus()
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
async def test_hetzner_power_off_is_a_risky_action() -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open(app, pilot, HETZNER)
        assert screen.query_one("#btn_hetzner_mgr_power_off", ActionButton).has_class("-warning")


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
                else:
                    assert not button.tooltip


@pytest.mark.asyncio
async def test_disabled_actions_are_visibly_muted() -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open(app, pilot, AWS, row=1)  # db-1 is stopped
        stop = screen.query_one("#btn_aws_mgr_stop", ActionButton)
        start = screen.query_one("#btn_aws_mgr_start", ActionButton)
        assert stop.disabled and not start.disabled
        assert stop.styles.color != start.styles.color
        enabled_default = screen.query_one("#btn_aws_mgr_refresh", ActionButton)
        assert stop.styles.color != enabled_default.styles.color


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
