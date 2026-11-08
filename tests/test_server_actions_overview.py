"""The server overview: a toolbar, cards that own their actions, a diagnostics strip.

Hosted in the real app so the shipped stylesheet decides the geometry.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from textual.widgets import Button, Tree

from servonaut.screens.server_actions import ServerActionsScreen
from servonaut.widgets.action_button import ActionButton
from servonaut.widgets.chat_panel import ChatPanel
from tests._async_bounds import wait_until
from tests.test_fleet_workspace_layout import _LayoutHost, _open_chat

SIZES = [(160, 50), (100, 30)]
TOOLBAR_IDS = ["btn_back", "btn_browse", "btn_scp", "btn_command", "btn_ssh"]
CARD_OF = {
    "btn_copy_id": "card_identity", "btn_copy_summary": "card_identity",
    "btn_use_vault_key": "card_network", "btn_manage_ssh_ref": "card_network",
    "btn_verify_ssh": "card_network", "btn_live": "card_live",
    "btn_memory": "card_memory", "btn_findings": "card_memory",
    "btn_db_creds": "card_memory", "btn_logs": "sa-diagnostics",
    "btn_ai_analysis": "sa-diagnostics", "btn_scan": "sa-diagnostics",
    "btn_ban_ip": "sa-diagnostics",
}
OVH_CARD_OF = {f"btn_ovh_{name}": "sa-provider" for name in ("reinstall", "resize", "snapshots", "firewall")}


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
    await pilot.pause()
    return screen


def _assert_overview_geometry(screen: ServerActionsScreen) -> None:
    buttons = list(screen.query(ActionButton))
    toolbar = [screen.query_one(f"#{name}") for name in TOOLBAR_IDS]
    assert len({button.region.y for button in toolbar}) == 1, "toolbar wraps"
    assert max(b.region.bottom for b in toolbar) <= screen.query_one("#sa-detail").region.y
    for index, first in enumerate(buttons):
        assert first.region.width > 0 and first.region.height > 0, first.id
        assert first.content_size.width >= first.label.cell_length, f"{first.id} label is clipped"
        for second in buttons[index + 1:]:
            assert not first.region.overlaps(second.region), (first.id, second.id)
    placed = {**CARD_OF, **(OVH_CARD_OF if screen.query("#sa-provider") else {})}
    for button_id, card_id in placed.items():
        card = screen.query_one(f"#{card_id}")
        button = screen.query_one(f"#{button_id}")
        assert card.region.contains_region(button.region), (button_id, card_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_geometry_has_no_overlap_clipping_or_stray_buttons(size) -> None:
    app = _LayoutHost()
    async with app.run_test(size=size) as pilot:
        screen = await _open_actions(app, pilot)
        _assert_overview_geometry(screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_geometry_with_the_provider_card(size) -> None:
    app = _LayoutHost()
    app.instances[0].update(is_ovh=True, provider_type="vps")
    async with app.run_test(size=size) as pilot:
        screen = await _open_actions(app, pilot)
        await wait_until(lambda: bool(screen.query("#btn_ovh_firewall")))
        await pilot.pause()
        _assert_overview_geometry(screen)


@pytest.mark.asyncio
async def test_geometry_with_chat_open() -> None:
    app = _LayoutHost(navigation_visible=False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        await _open_chat(app, pilot)
        await wait_until(lambda: not screen._layout_required)
        await pilot.pause()
        _assert_overview_geometry(screen)


@pytest.mark.asyncio
async def test_ban_ip_is_last_in_diagnostics_and_in_the_error_role() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        strip = [b.id for b in screen.query("#sa-diagnostics ActionButton")]
        assert strip[-1] == "btn_ban_ip"
        assert screen.query_one("#btn_ban_ip").has_class("-error")
        assert screen.query_one("#btn_ssh").has_class("-primary")


@pytest.mark.asyncio
async def test_diagnostics_is_reachable_by_scrolling_at_100x30() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _open_actions(app, pilot)
        overview = screen.query_one("#sa-overview")
        assert overview.region.height >= 12
        overview.scroll_to_widget(screen.query_one("#btn_ban_ip"), animate=False)
        await pilot.pause()
        assert overview.region.contains_region(screen.query_one("#btn_ban_ip").region)


@pytest.mark.asyncio
async def test_buttons_are_compact_exactly_when_the_layout_is_narrow() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        buttons = list(screen.query(ActionButton))
        assert not any(button.compact for button in buttons)
        await pilot.resize_terminal(100, 30)
        await wait_until(lambda: all(button.compact for button in screen.query(ActionButton)))
        assert screen.query_one("#btn_browse", ActionButton).label.plain.startswith("Browse  ")
        await wait_until(
            lambda: all(b.region.height == 1 for b in screen.query("#action_buttons ActionButton"))
        )
        await pilot.resize_terminal(160, 50)
        await wait_until(lambda: not any(button.compact for button in screen.query(ActionButton)))
        assert screen.query_one("#btn_browse", ActionButton).label.plain.startswith("Browse files")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_ovh_extras_have_their_own_card_after_the_diagnostics(size) -> None:
    app = _LayoutHost()
    app.instances[0].update(is_ovh=True, provider_type="vps")
    async with app.run_test(size=size) as pilot:
        screen = await _open_actions(app, pilot)
        await wait_until(lambda: bool(screen.query("#btn_ovh_firewall")))
        await pilot.pause()
        provider = screen.query_one("#sa-provider")
        overview = screen.query_one("#sa-overview")
        overview.scroll_to_widget(provider, animate=False)
        await pilot.pause()
        assert provider.region.y >= screen.query_one("#sa-diagnostics").region.bottom
        for name in ("reinstall", "resize", "snapshots", "firewall"):
            button = screen.query_one(f"#btn_ovh_{name}")
            assert provider.region.contains_region(button.region), name
        assert screen.query_one("#btn_ovh_reinstall").has_class("-error")
        assert not screen.query("#action_buttons #btn_ovh_reinstall")


ACTION_TABLE = [
    ("btn_browse", "1", "action_action_1"),
    ("btn_command", "2", "action_action_2"),
    ("btn_ssh", "3", "action_action_3"),
    ("btn_scp", "4", "action_action_4"),
    ("btn_scan", "5", "action_action_5"),
    ("btn_logs", "6", "action_action_6"),
    ("btn_ai_analysis", "7", "action_action_7"),
    ("btn_ban_ip", "8", "action_action_8"),
    ("btn_memory", "m", "action_open_memory"),
    ("btn_db_creds", "d", "action_scan_db_creds"),
    ("btn_findings", "f", "action_open_findings"),
    ("btn_live", "l", "action_toggle_live"),
    ("btn_manage_ssh_ref", "r", "action_manage_ssh_ref"),
    ("btn_verify_ssh", "v", "action_verify_ssh"),
    ("btn_use_vault_key", "u", "action_use_vault_key"),
    ("btn_back", "9", "action_back"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("button_id,key,handler", ACTION_TABLE)
async def test_every_action_is_reachable_by_click_and_by_key(button_id, key, handler) -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        calls: list[str] = []
        setattr(screen, handler, lambda: calls.append(handler))
        screen.query_one(f"#{button_id}", Button).press()
        await pilot.pause()
        assert calls == [handler], "click"
        await pilot.press(key)
        await pilot.pause()
        assert calls == [handler, handler], "key"


@pytest.mark.asyncio
async def test_key_hints_match_real_bindings() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        keys = {binding.key.lower() for binding in ServerActionsScreen.BINDINGS}
        for button in screen.query(ActionButton):
            hint = button.label.plain.rsplit("  ", 1)[-1] if "  " in button.label.plain else None
            if hint is not None:
                assert hint.lower() in keys, button.id
            else:
                assert button.id in {"btn_copy_id", "btn_copy_summary"}, button.id


@pytest.mark.asyncio
async def test_copy_actions_copy_what_is_displayed() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        copied: list[str] = []
        with patch("servonaut.utils.platform_utils.copy_to_clipboard", lambda text: copied.append(text) or True):
            screen.query_one("#btn_copy_id", Button).press()
            screen.query_one("#btn_copy_summary", Button).press()
            await pilot.pause()
        assert copied[0] == str(app.instances[0]["id"])
        assert str(app.instances[0]["id"]) in copied[1] and "Identity" in copied[1]


@pytest.mark.asyncio
@pytest.mark.parametrize("suggested", [True, False])
async def test_vault_key_is_primary_only_when_it_is_the_next_step(suggested) -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        button = screen.query_one("#btn_use_vault_key", ActionButton)
        screen._vault_binding_source = None if suggested else "native"
        with patch.object(screen, "_vault_runtime_for_lookup", return_value=object()):
            screen._sync_vault_button_role()
        assert button.has_class("-primary") is suggested


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_inline_browse_collapses_toolbar_and_escape_restores_it(size, monkeypatch) -> None:
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
        _assert_overview_geometry(screen)


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


HOSTILE_VALUES = ["x [/", "[ @click=app.bell]x", "[ $surface]h", "trail\\", "[b]bold[/b]"]


@pytest.mark.asyncio
@pytest.mark.parametrize("value", HOSTILE_VALUES)
async def test_hostile_server_text_is_literal_and_copied_as_shown(value, monkeypatch) -> None:
    app = _LayoutHost()
    app.instances[0].update(name=value, id=value, group=value)
    rang: list[str] = []
    monkeypatch.setattr(app, "action_bell", lambda: rang.append("bell"), raising=False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        assert app._exception is None
        for selector in ("#server_context", "#server_identity", "#server_info"):
            content = screen.query_one(selector).content
            assert not any("@click" in str(span.style) for span in content.spans), selector
        assert value in screen.query_one("#server_identity").content.plain
        copied: list[str] = []
        with patch("servonaut.utils.platform_utils.copy_to_clipboard", lambda text: copied.append(text) or True):
            screen.query_one("#btn_copy_id", Button).press()
            await pilot.pause()
        assert copied == [value]
        assert not rang


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_no_button_is_stretched_past_its_label(size) -> None:
    app = _LayoutHost()
    app.instances[0].update(is_ovh=True)
    async with app.run_test(size=size) as pilot:
        screen = await _open_actions(app, pilot)
        await wait_until(lambda: bool(screen.query("#btn_ovh_firewall")))
        await pilot.pause()
        for button in screen.query(ActionButton):
            widest = button.label.cell_length + (4 if button.compact else 6)
            assert button.region.width <= widest, (button.id, button.region.width, widest)


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["down", "up"])
async def test_arrow_keys_walk_the_actions_and_keep_focus_in_view(key) -> None:
    app = _LayoutHost()
    app.instances[0].update(is_ovh=True, provider_type="vps")
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _open_actions(app, pilot)
        await wait_until(lambda: bool(screen.query("#btn_ovh_firewall")))
        await pilot.pause()
        overview = screen.query_one("#sa-overview")
        order = [b for b in screen.query(ActionButton) if b.display]
        for _ in range(len(order) + 1):
            before = screen.focused
            await pilot.press(key)
            await pilot.pause()
            step = 1 if key == "down" else -1
            assert screen.focused is order[(order.index(before) + step) % len(order)]
            if screen.focused in overview.query(ActionButton):
                assert overview.region.contains_region(screen.focused.region), screen.focused.id
