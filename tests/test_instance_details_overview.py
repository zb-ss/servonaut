"""Instance overview retains full metadata and restores its inline workspace."""

from types import SimpleNamespace
from unittest.mock import PropertyMock, patch

import pytest
from textual.content import Content
from textual.containers import VerticalScroll
from textual.widgets import Button, Static, TextArea, Tree

from servonaut.screens.instance_list import instance_detail_text
from servonaut.screens.server_actions import ServerActionsScreen
from servonaut.widgets.chat_panel import ChatPanel
from tests._async_bounds import wait_until
from tests.test_fleet_workspace_layout import _LayoutHost


def test_fleet_document_retains_full_literal_values_in_labelled_lines() -> None:
    row = {
        "name": "web-[b]東京[/b]-" + "x" * 140, "id": "server-full-id",
        "provider": "custom", "state": "running", "type": "small",
        "public_ip": "192.0.2.10", "private_ip": "10.0.0.1",
        "username": "deploy", "port": 2200, "region": "local",
        "group": "example", "key_name": "full-key-name",
        "account_qualified": True, "account": "personal", "account_id": "account-full-id",
    }
    document = instance_detail_text(row)
    assert "  |  " not in document
    assert len(document.splitlines()) >= 5
    for key, value in row.items():
        if key != "account_qualified":
            assert str(value) in document
    assert "Username: deploy   Port: 2200" in document


@pytest.mark.parametrize("extra, identity_value, network_value", [
    ({}, "Instance ID: server-1", "Private IP: 10.0.0.1"),
    ({"is_ovh": True, "provider_type": "vps", "os": "Debian [b]12"}, "OS: Debian [b]12", "Reverse DNS: web.example.test"),
    ({"is_custom": True, "group": "edge"}, "Group: edge", "Username: deploy"),
    ({"is_shared": True, "team_name": "example-team", "login_user": "team-user"}, "Team: example-team", "Team login: team-user"),
])
def test_sections_preserve_provider_values_and_credentials(extra, identity_value, network_value) -> None:
    row = dict(
        id="server-1", name="web-[b]東京[/b]", state="running",
        public_ip="192.0.2.10", private_ip="10.0.0.1", username="deploy",
        account_qualified=True, account="personal", **extra,
    )
    app = SimpleNamespace(
        demo_mode=False, redaction_service=None,
        connection_service=SimpleNamespace(resolve_profile=lambda row: None),
    )
    screen = ServerActionsScreen(row)
    screen._reverse_dns = "web.example.test"
    with (
        patch.object(ServerActionsScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "_sharing_teams", return_value=[]),
    ):
        context, identity, network = [part.plain for part in screen._server_info_sections()]
    assert "web-[b]東京[/b]" in context
    assert "Account: personal" in context
    assert identity_value in identity
    assert network_value in network
    assert "Target: 192.0.2.10" in network
    assert "SSH credential: Automatic resolution" in network


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_files_uses_viewport_and_escape_restores_overview(size, monkeypatch) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    monkeypatch.setattr(
        "servonaut.screens.file_browser.build_remote_tree",
        lambda *args, **kwargs: Tree("Remote files", id="remote_tree"),
    )
    app = _LayoutHost()
    async with app.run_test(size=size) as pilot:
        await app.push_screen(ServerActionsScreen(app.instances[0]))
        await pilot.pause()
        screen = app.screen
        context = screen.query_one("#server_context", Static)
        identity = screen.query_one("#server_identity", Static)
        network = screen.query_one("#server_info", Static)

        def overview_ready() -> bool:
            narrow = size[0] == 100
            if screen.has_class("-content-narrow") != narrow or screen._layout_required:
                return False
            left, right = identity.region, network.region
            if min(left.width, left.height, right.width, right.height) <= 0:
                return False
            if narrow:
                return left.x == right.x and left.width == right.width and left.bottom <= right.y
            return left.y == right.y and left.right <= right.x

        await wait_until(overview_ready)
        if size[0] == 160:
            assert identity.region.right <= network.region.x
        else:
            assert identity.region.bottom <= network.region.y
        overview = screen.query_one("#sa-overview", VerticalScroll)
        screen.query_one("#memory_panel", Static).update("\n".join(f"Fact {index}" for index in range(40)))
        screen.query_one("#btn_memory", Button).focus()
        await pilot.pause()
        overview.scroll_to(y=5, animate=False, force=True)
        await pilot.pause()
        scroll_y = overview.scroll_y
        assert scroll_y > 0
        screen._open_inline_browse()
        await pilot.pause()
        assert not overview.display and context.display
        tree = screen.query_one("#remote_tree", Tree)
        assert screen.focused is tree
        assert tree.region.height >= screen.query_one("#sa-detail").region.height // 2
        await pilot.press("escape")
        await pilot.pause()
        assert screen.query_one("#sa-overview") is overview and overview.display
        assert screen.query_one("#server_identity") is identity
        assert overview.scroll_y == scroll_y
        assert screen.focused is screen.query_one("#btn_memory")


@pytest.mark.asyncio
async def test_failed_files_open_keeps_overview_and_selected_document(monkeypatch) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)

    def fail_tree(*args, **kwargs):
        raise RuntimeError("Fixture connection unavailable")

    monkeypatch.setattr("servonaut.screens.file_browser.build_remote_tree", fail_tree)
    app = _LayoutHost()
    async with app.run_test(size=(100, 30)) as pilot:
        document = app.screen.query_one("#instance_detail", TextArea).document
        await app.push_screen(ServerActionsScreen(app.instances[0]))
        await pilot.pause()
        screen = app.screen
        screen._open_inline_browse()
        await pilot.pause()
        assert screen._inline_view is None
        assert screen.query_one("#sa-overview").display
        assert not screen.query_one("#sa-inline").display
        await pilot.press("escape")
        await pilot.pause()
        assert app.screen.query_one("#instance_detail", TextArea).document is document


@pytest.mark.asyncio
async def test_long_context_keeps_full_values_without_starving_files(monkeypatch) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    monkeypatch.setattr(
        "servonaut.screens.file_browser.build_remote_tree",
        lambda *args, **kwargs: Tree("Remote files", id="remote_tree"),
    )
    app = _LayoutHost()
    app.instances[0].update(
        name="web-[b]東京[/b]-" + "name" * 100,
        account="account-" + "full" * 100, account_qualified=True,
    )
    async with app.run_test(size=(100, 30)) as pilot:
        await app.push_screen(ServerActionsScreen(app.instances[0]))
        await pilot.pause()
        screen = app.screen
        context = screen.query_one("#server_context", Static)
        for key in ("name", "account"):
            assert app.instances[0][key] in context.content.plain
        assert screen.query_one("#sa-overview").region.height >= 12
        screen._open_inline_browse()
        await pilot.pause()
        assert screen.query_one("#sa-inline").region.height >= 12
        assert screen.query_one("#remote_tree").region.height >= 7
