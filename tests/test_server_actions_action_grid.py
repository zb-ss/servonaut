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


def _bound_keys(screen: ServerActionsScreen) -> set[str]:
    return {binding.key.lower() for binding in ServerActionsScreen.BINDINGS}


def _assert_prefix_matches_binding(screen: ServerActionsScreen) -> None:
    """A button shows a key prefix exactly when that key is bound."""
    keys = _bound_keys(screen)
    for button in screen.query("#action_buttons Button"):
        label = button.label.plain
        prefixed = label[1:3] == ". "
        if prefixed:
            assert label[0].lower() in keys, label
        else:
            assert button.id.startswith("btn_ovh_"), label


@pytest.mark.asyncio
async def test_labels_show_a_key_prefix_exactly_when_the_key_is_bound() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        _assert_prefix_matches_binding(screen)
        assert not screen.query("#btn_ovh_reinstall")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_ovh_group_follows_the_label_rule_and_precedes_back(size) -> None:
    app = _LayoutHost()
    app.instances[0].update(is_ovh=True)
    async with app.run_test(size=size) as pilot:
        screen = await _open_actions(app, pilot)
        await wait_until(lambda: bool(screen.query("#btn_ovh_firewall")))
        await pilot.pause()
        _assert_prefix_matches_binding(screen)
        _assert_action_geometry(screen)
        groups = list(screen.query("#action_buttons .sa-group"))
        assert str(groups[-2].query_one(".section_label").content) == "OVH"
        assert groups[-1].query_one(Button).id == "btn_back"


@pytest.mark.asyncio
async def test_vault_key_is_bound_to_u_and_not_k() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        assert screen.query_one("#btn_use_vault_key", Button).label.plain.startswith("U. ")
        assert "k" not in _bound_keys(screen)
        calls: list[str] = []
        screen.action_use_vault_key = lambda: calls.append("vault")
        await pilot.press("u")
        assert calls == ["vault"]


@pytest.mark.asyncio
@pytest.mark.parametrize("size,gap", [((160, 50), 1), ((100, 30), 0)])
async def test_back_gets_a_spacer_only_when_rows_are_plentiful(size, gap) -> None:
    app = _LayoutHost()
    async with app.run_test(size=size) as pilot:
        screen = await _open_actions(app, pilot)
        groups = list(screen.query("#action_buttons .sa-group"))
        assert groups[-1].region.y - groups[-2].region.bottom == gap


@pytest.mark.asyncio
async def test_short_terminal_gives_the_overview_twelve_rows() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _open_actions(app, pilot)
        assert screen.query_one("#sa-overview").region.height >= 12


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_toolbar_keeps_its_one_cell_inset(size) -> None:
    app = _LayoutHost()
    async with app.run_test(size=size) as pilot:
        screen = await _open_actions(app, pilot)
        _assert_inset(screen)


@pytest.mark.asyncio
async def test_toolbar_keeps_its_inset_with_chat_open() -> None:
    app = _LayoutHost(navigation_visible=False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        await _open_chat(app, pilot)
        await wait_until(lambda: not screen._layout_required)
        _assert_inset(screen)


def _assert_inset(screen: ServerActionsScreen) -> None:
    toolbar = screen.query_one("#action_buttons")
    content = toolbar.content_region
    assert content.x == toolbar.region.x + 1
    assert content.right == toolbar.region.right - 1
    for button in screen.query("#action_buttons Button"):
        assert content.contains_region(button.region), button.id


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
