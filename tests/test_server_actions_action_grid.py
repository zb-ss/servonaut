"""The server-actions toolbar reads as aligned, labelled groups.

Hosted in the real app so the shipped stylesheet decides the geometry.
"""

from __future__ import annotations

import pytest
from textual.widgets import Button, Tree

from servonaut.screens.server_actions import ServerActionsScreen
from servonaut.widgets.chat_panel import ChatPanel
from tests._async_bounds import wait_until
from tests.test_fleet_workspace_layout import _LayoutHost, _open_chat

SIZES = [(160, 50), (100, 30)]


@pytest.fixture(autouse=True)
def _no_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)


async def _open_actions(app: _LayoutHost, pilot) -> ServerActionsScreen:
    await app.push_screen(ServerActionsScreen(app.instances[0]))
    await pilot.pause()
    screen = app.screen
    await wait_until(
        lambda: not screen._layout_required
        and screen.query_one("#btn_back", Button).region.width > 0
    )
    return screen


def _assert_action_geometry(screen: ServerActionsScreen) -> None:
    toolbar = screen.query_one("#action_buttons")
    buttons = list(screen.query("#action_buttons Button"))
    assert len(buttons) >= 15
    widths = [button.region.width for button in buttons]
    assert max(widths) - min(widths) <= 1, dict(zip((b.id for b in buttons), widths))
    for button in buttons:
        region = button.region
        assert region.width > 0 and region.height > 0, button.id
        assert toolbar.region.contains_region(region), button.id
        group = next((a for a in button.ancestors if a.has_class("sa-group")), None)
        assert group is not None, f"{button.id} is not inside a category group"
        assert group.region.contains_region(region), button.id
        assert button.label.plain.strip(), button.id
    for index, first in enumerate(buttons):
        for second in buttons[index + 1:]:
            assert not first.region.overlaps(second.region), (first.id, second.id)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_every_action_sits_in_its_own_group_without_overlap(size) -> None:
    app = _LayoutHost()
    async with app.run_test(size=size) as pilot:
        screen = await _open_actions(app, pilot)
        _assert_action_geometry(screen)


@pytest.mark.asyncio
async def test_groups_share_one_left_edge_and_stack_in_order() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        groups = list(screen.query("#action_buttons .sa-group"))
        assert [str(g.query_one(".section_label").content) for g in groups] == [
            "CONNECT", "INSPECT", "OPERATE", "MANAGE", "",
        ]
        assert len({g.region.x for g in groups}) == 1
        assert len({g.query_one(".sa-group-actions").region.x for g in groups}) == 1
        for above, below in zip(groups, groups[1:]):
            assert above.region.bottom <= below.region.y
        assert groups[-1].query_one(Button).id == "btn_back"


@pytest.mark.asyncio
async def test_wide_layout_aligns_buttons_into_three_columns() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        columns = {
            button.region.x for button in screen.query("#action_buttons Button")
        }
        assert len(columns) == 3
        widths = {button.region.width for button in screen.query("#action_buttons Button")}
        assert max(widths) - min(widths) <= 1, widths


@pytest.mark.asyncio
async def test_actions_stay_visible_with_chat_open() -> None:
    app = _LayoutHost(navigation_visible=False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        await _open_chat(app, pilot)
        await wait_until(lambda: not screen._layout_required)
        _assert_action_geometry(screen)


@pytest.mark.asyncio
async def test_labels_share_one_key_prefix_format() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        for button in screen.query("#action_buttons Button"):
            label = button.label.plain
            assert label[1:3] == ". ", label


@pytest.mark.asyncio
async def test_vault_key_has_a_key_binding() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        calls: list[str] = []
        screen.action_use_vault_key = lambda: calls.append("vault")
        await pilot.press("k")
        assert calls == ["vault"]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_inline_browse_collapses_toolbar_and_escape_restores_it(
    size, monkeypatch,
) -> None:
    monkeypatch.setattr(
        "servonaut.screens.file_browser.build_remote_tree",
        lambda *args, **kwargs: Tree("Remote files", id="remote_tree"),
    )
    app = _LayoutHost()
    async with app.run_test(size=size) as pilot:
        screen = await _open_actions(app, pilot)
        toolbar = screen.query_one("#action_buttons")
        overview = screen.query_one("#sa-overview")
        screen.query_one("#btn_browse", Button).focus()
        await pilot.pause()

        screen._open_inline_browse()
        await pilot.pause()
        assert screen.has_class("-inline-open")
        assert not toolbar.display and not overview.display
        tree = screen.query_one("#remote_tree", Tree)
        assert screen.focused is tree
        assert tree.region.height >= screen.query_one("#sa-detail").region.height // 2

        await pilot.press("escape")
        await pilot.pause()
        assert not screen.has_class("-inline-open")
        assert toolbar.display and overview.display
        assert screen.focused is screen.query_one("#btn_browse", Button)
        _assert_action_geometry(screen)


@pytest.mark.asyncio
async def test_inline_browse_returns_focus_to_the_opening_action(monkeypatch) -> None:
    monkeypatch.setattr(
        "servonaut.screens.file_browser.build_remote_tree",
        lambda *args, **kwargs: Tree("Remote files", id="remote_tree"),
    )
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        screen.query_one("#btn_memory", Button).focus()
        await pilot.pause()
        screen._open_inline_browse()
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        assert screen.focused is screen.query_one("#btn_memory", Button)
