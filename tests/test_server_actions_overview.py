"""The server overview: a toolbar, cards that own their actions, a diagnostics strip.

Hosted in the real app so the shipped stylesheet decides the geometry.
"""

from __future__ import annotations

from types import SimpleNamespace
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


def _vault_service(binding, delay: float = 0.0):
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    async def personal_binding(instance):
        await asyncio.sleep(delay)
        return binding

    service = MagicMock()
    service.store.identity = object()
    service.personal_binding = AsyncMock(side_effect=personal_binding)
    return service


@pytest.mark.asyncio
async def test_vault_key_is_primary_until_a_binding_is_found() -> None:
    app = _LayoutHost()
    app.vault_command_service = _vault_service({"source": "servonaut_vault"}, delay=1.5)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        button = screen.query_one("#btn_use_vault_key", ActionButton)
        assert button.has_class("-primary"), "nothing bound yet: the next step"
        await wait_until(lambda: not button.has_class("-primary"))


@pytest.mark.asyncio
async def test_vault_key_is_primary_when_nothing_is_bound() -> None:
    app = _LayoutHost()
    app.vault_command_service = _vault_service(None)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        await pilot.pause()
        assert screen.query_one("#btn_use_vault_key", ActionButton).has_class("-primary")


@pytest.mark.asyncio
async def test_vault_key_is_not_primary_without_a_usable_vault() -> None:
    app = _LayoutHost()
    app.vault_command_service = None
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        assert not screen.query_one("#btn_use_vault_key", ActionButton).has_class("-primary")


@pytest.mark.asyncio
async def test_vault_key_is_not_primary_when_a_team_key_is_already_bound() -> None:
    app = _LayoutHost()
    app.vault_command_service = _vault_service(None)
    team_row = {"team_slug": "ops", "team_name": "ops", "credential_binding": {"source": "servonaut_vault"}}
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        with patch.object(screen, "_sharing_teams", return_value=[team_row]):
            screen._render_server_info()
        await pilot.pause()
        assert "Team key for ops" in screen.query_one("#server_info").content.plain
        assert not screen.query_one("#btn_use_vault_key", ActionButton).has_class("-primary")


@pytest.mark.asyncio
async def test_live_poll_label_follows_the_poller() -> None:
    from servonaut.services.live_stats_service import LiveStatsError

    class _Service:
        mode = "run"

        async def watch(self, instance):
            if self.mode == "fail":
                raise LiveStatsError("no route")
            while True:
                import asyncio
                await asyncio.sleep(0.05)
                yield SimpleNamespace()

    app = _LayoutHost()
    service = _Service()
    app.live_stats_service = service
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        label = lambda: screen.query_one("#btn_live", ActionButton).label.plain  # noqa: E731
        assert label().startswith("Live poll: off")
        with patch("servonaut.screens.server_actions.format_live_stats", lambda stats: "stats"):
            await pilot.press("l")
            await wait_until(lambda: label().startswith("Live poll: on"))
            await pilot.press("l")
            await wait_until(lambda: label().startswith("Live poll: off"))
            service.mode = "fail"
            await pilot.press("l")
            await wait_until(lambda: label().startswith("Live poll: off") and not screen._live_on)


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


AWS_ROW = {
    "id": "i-0123456789abcdef0", "name": "web-1", "type": "t3.micro", "state": "running",
    "public_ip": "54.1.2.3", "private_ip": "10.0.0.5", "region": "eu-west-1", "key_name": "k",
}
BASTION = "bastion-1.example.internal"


def _row_for(kind: str) -> dict:
    if kind == "aws":
        return dict(AWS_ROW)
    if kind == "ovh":
        return {**AWS_ROW, "id": "vps-0123abcd.vps.example.net", "is_ovh": True, "provider_type": "vps"}
    return {**AWS_ROW, "id": "custom-0123456789", "is_custom": True, "username": "deploy", "group": "edge"}


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["aws", "ovh", "custom"])
@pytest.mark.parametrize("when", ["before", "after"])
async def test_copy_in_demo_mode_copies_the_redacted_value(kind, when) -> None:
    app = _LayoutHost()
    app.instances[0] = _row_for(kind)
    real = dict(app.instances[0])
    app.connection_service = SimpleNamespace(
        resolve_profile=lambda inst: SimpleNamespace(bastion_host=BASTION) if kind == "aws" else None,
    )
    async with app.run_test(size=(160, 50)) as pilot:
        if when == "before":
            app.action_toggle_demo()
            await pilot.pause()
        screen = await _open_actions(app, pilot)
        if when == "after":
            app.action_toggle_demo()
            await pilot.pause()
            await pilot.pause()
        assert app.demo_mode
        shown_id = next(
            line.partition(": ")[2] for line in screen.query_one("#server_identity").content.plain.splitlines()
            if line.partition(": ")[0] in ("Instance ID", "ID")
        )
        copied: list[str] = []
        with patch("servonaut.utils.platform_utils.copy_to_clipboard", lambda text: copied.append(text) or True):
            screen.query_one("#btn_copy_id", Button).press()
            screen.query_one("#btn_copy_summary", Button).press()
            await pilot.pause()
        assert copied[0] == shown_id and shown_id != real["id"]
        everything = "\n".join(copied)
        for secret in (real["id"], real["name"], real["public_ip"], real["private_ip"], BASTION):
            assert secret not in everything, secret


def _paint_signature(app, widget) -> set[tuple]:
    """What the terminal would draw over *widget*: text and every style attribute."""
    rows = app.screen._compositor.render_strips()
    cells: set[tuple] = set()
    for y in range(widget.region.y, widget.region.bottom):
        for segment in rows[y].crop(widget.region.x, widget.region.right):
            style = segment.style
            cells.add((
                segment.text,
                str(getattr(style, "color", None)), str(getattr(style, "bgcolor", None)),
                getattr(style, "bold", None), getattr(style, "underline", None),
                getattr(style, "reverse", None),
            ))
    return cells


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light", "ansi-dark", "ansi-light"])
@pytest.mark.parametrize("button_id", ["btn_ssh", "btn_browse"])
async def test_focus_and_hover_are_visible_on_compact_buttons(theme, button_id) -> None:
    app = _LayoutHost()
    app.theme = theme
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _open_actions(app, pilot)
        button = screen.query_one(f"#{button_id}", ActionButton)
        assert button.compact
        screen.query_one("#btn_back", ActionButton).focus()
        await pilot.hover(offset=(0, 0))
        await pilot.pause()
        idle = _paint_signature(app, button)
        button.focus()
        await pilot.pause()
        assert _paint_signature(app, button) != idle, "focus is not visible"
        screen.query_one("#btn_back", ActionButton).focus()
        await pilot.hover(button)
        await pilot.pause()
        assert _paint_signature(app, button) != idle, "hover is not visible"
