"""Server identity survives scrolling and header labels remain readable."""

from __future__ import annotations

from collections.abc import Iterator
import asyncio
import io
import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest
from rich.console import Console
from rich.style import Style
from textual.color import Color
from textual.pilot import Pilot
from textual.widget import Widget
from textual.widgets import Button, Input, LoadingIndicator, RadioSet, Static

from servonaut.config.schema import ConnectionProfile, ConnectionRule
from servonaut.screens.file_browser import FileBrowserScreen
from servonaut.screens.scp_transfer import SCPTransferScreen
from servonaut.screens.server_actions import ServerActionsScreen
from servonaut.styles.themes import SERVONAUT_ANSI_DARK, SERVONAUT_ANSI_LIGHT
from servonaut.utils.instance_resolver import display_name
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.remote_tree import RemoteTree
from servonaut.widgets.sidebar import Sidebar
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import open_chat, tab_to
from tests.test_navigation_dialog_contrast import _assert_readable
from tests.test_workspace_server_screens import _ServerWorkspaceApp, _server

pytestmark = pytest.mark.usefixtures("navigation_open")


THEMES = ["servonaut", "servonaut-light", "ansi-dark", "ansi-light"]


@pytest.fixture(autouse=True)
def _no_external_operations(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    refusals = []

    def refuse(*args: object, **kwargs: object) -> None:
        refusals.append("external operation")
        raise AssertionError("Unexpected external operation")

    monkeypatch.setattr("servonaut.widgets.remote_tree.run_ssh", refuse)
    monkeypatch.setattr("socket.create_connection", refuse)
    monkeypatch.setattr("httpx.Client.send", refuse)
    monkeypatch.setattr("httpx.AsyncClient.send", refuse)
    yield
    assert not refusals


@pytest.fixture
def hosts() -> Iterator[list[_ServerWorkspaceApp]]:
    apps: list[_ServerWorkspaceApp] = []
    yield apps
    for app in apps:
        app.scan_service.scan_server.assert_not_awaited()
        app.ovh_vps_service.upgrade.assert_not_awaited()
        app.ovh_vps_service.reinstall.assert_not_awaited()
        for name in ("build_upload_command", "build_download_command", "execute_transfer"):
            getattr(app.scp_service, name).assert_not_called()


def _host(
    hosts: list[_ServerWorkspaceApp], theme: str, navigation_visible: bool,
) -> _ServerWorkspaceApp:
    app = _ServerWorkspaceApp(navigation_visible)
    app.theme = theme
    app.vault_command_service = None
    app.ansi_theme_dark = SERVONAUT_ANSI_DARK
    app.ansi_theme_light = SERVONAUT_ANSI_LIGHT
    app.scan_service.scan_server = AsyncMock(side_effect=AssertionError("Unexpected scan"))
    app.ovh_vps_service.upgrade = AsyncMock(side_effect=AssertionError("Unexpected resize"))
    app.ovh_vps_service.reinstall = AsyncMock(side_effect=AssertionError("Unexpected reinstall"))
    app.scp_service = Mock()
    for name in ("build_upload_command", "build_download_command", "execute_transfer"):
        getattr(app.scp_service, name).side_effect = AssertionError("Unexpected transfer")
    hosts.append(app)
    return app


def _painted_rows(app: _ServerWorkspaceApp, widget: Widget) -> list[tuple[int, int, str]]:
    """Crop actual composed rows to the widget and the terminal viewport."""
    bounds = widget.region.intersection(app.screen.region)
    strips = app.screen._compositor.render_strips()
    return [
        (bounds.x, y, strips[y].crop(bounds.x, bounds.right).text)
        for y in range(bounds.y, bounds.bottom)
    ]


def _label_styles(app: _ServerWorkspaceApp, widget: Widget, label: str) -> list[Style]:
    for left, y, row in _painted_rows(app, widget):
        offset = row.find(label)
        if offset < 0:
            continue
        cells = range(left + offset, left + offset + len(label))
        if not all(app.get_widget_at(x, y)[0] is widget for x in cells):
            continue
        return [app.screen._compositor.get_style_at(x, y) for x in cells]
    pytest.fail(f"Complete {label!r} is not painted and hit-testable in {widget!r}")


def _text(app: _ServerWorkspaceApp, widget: Widget) -> str:
    return "\n".join(row for _, _, row in _painted_rows(app, widget))


def _capture(app: _ServerWorkspaceApp, directory: Path, name: str) -> None:
    """Keep the native frame before a paint assertion can fail."""
    console = Console(
        width=app.size.width, height=app.size.height, file=io.StringIO(),
        force_terminal=True, color_system="truecolor", record=True,
        legacy_windows=False, safe_box=False,
    )
    console.print(app.screen._compositor.render_update(
        full=True, screen_stack=app._background_screens, simplify=False,
    ))
    light = app.theme.endswith("light")
    palette = SERVONAUT_ANSI_LIGHT if light else SERVONAUT_ANSI_DARK
    directory.joinpath(f"{name}.svg").write_text(
        console.export_svg(title=name, theme=palette, clear=False), encoding="utf-8",
    )
    widgets = {}
    for selector in (
        "#workspace_context", "#transfer_container", "#transfer_banner",
        "#local_path_input", "#browser_header", "#remote_tree",
    ):
        matches = list(app.screen.query(selector))
        if matches:
            widget = matches[0]
            widgets[selector] = {
                "region": list(widget.region), "display": widget.display,
                "scroll_offset": list(widget.scroll_offset),
                "painted": _text(app, widget),
            }
    directory.joinpath(f"{name}.json").write_text(json.dumps({
        "theme": app.theme, "viewport": list(app.size),
        "export_palette": "SERVONAUT_ANSI_LIGHT" if light else "SERVONAUT_ANSI_DARK",
        "navigation_visible": app.screen.query_one(Sidebar).display,
        "focused": app.focused.id if app.focused else None,
        "widgets": widgets,
    }, indent=2) + "\n", encoding="utf-8")


def _form_state(screen: SCPTransferScreen) -> tuple[object, ...]:
    local = screen.query_one("#local_path_input", Input)
    remote = screen.query_one("#remote_path_input", Input)
    radios = screen.query_one("#direction_selector", RadioSet)
    return (
        local, local.value, local.cursor_position, local.selection,
        remote, remote.value, remote.cursor_position, remote.selection,
        radios, radios.pressed_index, screen._transfer_direction,
    )


async def _click(app: _ServerWorkspaceApp, pilot: Pilot, button: Button) -> None:
    await wait_until(lambda: not button.has_class("-active"))
    assert app.get_widget_at(*button.region.center)[0] is button
    assert await pilot.click(button)
    await pilot.pause()


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("navigation_visible,width", [(True, 129), (False, 98)])
async def test_transfer_keeps_identity_when_native_scrolling_hides_banner(
    hosts: list[_ServerWorkspaceApp], tmp_path: Path,
    theme: str, navigation_visible: bool, width: int,
) -> None:
    # These are accepted native visible-minimum WIDTH samples. Height/scroll
    # behavior is deliberately asserted afresh against the mounted viewport.
    app = _host(hosts, theme, navigation_visible)
    async with app.run_test(size=(width, 40)) as pilot:
        screen = SCPTransferScreen(app.instances[0])
        await app.push_screen(screen)
        await pilot.pause()
        local = screen.query_one("#local_path_input", Input)
        assert app.focused is local
        local.value = "/tmp/report.txt"
        screen.query_one("#remote_path_input", Input).value = "/srv/report.txt"
        panel = await open_chat(app, pilot, screen)
        body = screen.query_one("#transfer_container")
        assert body.display and not screen.has_class("-chat-replace")
        await tab_to(pilot, local)
        local.scroll_visible(animate=False, top=True, immediate=True)
        await pilot.pause()
        _capture(app, tmp_path, "transfer-native-scrolled")
        assert body.scroll_offset.y > 0
        assert "Instance:" not in _text(app, body)
        assert "web-1" not in _text(app, body)
        assert app.get_widget_at(*local.region.center)[0] is local
        context = screen.query_one("#workspace_context", Static)
        _label_styles(app, context, "Transfer · web-1")
        baseline, focus, offset = _form_state(screen), app.focused, body.scroll_offset
        navigation = screen.query_one("#workspace_navigation", Button)
        await _click(app, pilot, navigation)
        await _click(app, pilot, navigation)
        assert screen.query_one(Sidebar).display is navigation_visible
        assert _form_state(screen) == baseline
        expected_focus = focus if navigation_visible else panel.query_one("#chat-input")
        assert app.focused is expected_focus
        assert body.scroll_offset == offset
        _label_styles(app, context, "Transfer · web-1")
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_transfer_real_demo_key_refreshes_context_and_banner_without_rebuilding_form(
    hosts: list[_ServerWorkspaceApp], tmp_path: Path,
    size: tuple[int, int], navigation_visible: bool,
) -> None:
    app = _host(hosts, "servonaut", navigation_visible)
    row = app.instances[0]
    # Use a supported ID shape to exercise shown-ID redaction and real targeting.
    row.update(name="web-1", id="i-0123456789abcdef0", account="team", account_qualified=True)
    original_id = row["id"]
    async with app.run_test(size=size) as pilot:
        screen = SCPTransferScreen(row)
        await app.push_screen(screen)
        await pilot.pause()
        local = screen.query_one("#local_path_input", Input)
        remote = screen.query_one("#remote_path_input", Input)
        local.value, remote.value = "/tmp/report.txt", "/srv/report.txt"
        local.cursor_position = 4
        baseline, focus = _form_state(screen), app.focused
        workers = tuple(app.workers)
        context = screen.query_one("#workspace_context", Static)
        banner = screen.query_one("#transfer_banner", Static)
        for demo in (True, False):
            body = screen.query_one("#transfer_container")
            offset = body.scroll_offset
            await pilot.press("ctrl+shift+d")
            await pilot.pause()
            _capture(app, tmp_path, f"transfer-demo-{demo}-before-scroll")
            assert app.demo_mode is demo
            shown = display_name(row)
            assert row["name"] in banner.render().plain
            assert context.render().plain == f"Transfer · {shown}"
            if demo:
                assert row["name"] != "web-1" and row["id"] != original_id
                assert "web-1" not in context.render().plain + banner.render().plain
                assert "team" not in context.render().plain + banner.render().plain
            assert app.connection_instance(row)["id"] == original_id
            assert _form_state(screen) == baseline and app.focused is focus
            assert tuple(app.workers) == workers
            assert body.scroll_offset == offset
            _label_styles(app, context, f"Transfer · {shown}")
            banner.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            _capture(app, tmp_path, f"transfer-demo-{demo}-banner-visible")
            _label_styles(app, banner, f"Instance: {row['name']}")
            local.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            assert app.get_widget_at(*local.region.center)[0] is local
        # The live hook must update the existing banner, not replace form widgets.
        assert screen.query_one("#transfer_banner") is banner
        banner.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        _label_styles(app, banner, "Instance: web-1")
        _label_styles(app, context, "Transfer · team/web-1")
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("value_source", ["name", "bastion"])
async def test_file_browser_untrusted_header_values_are_literal_and_keep_target(
    hosts: list[_ServerWorkspaceApp], tmp_path: Path, value_source: str,
) -> None:
    app = _host(hosts, "servonaut", False)
    row = app.instances[0]
    if value_source == "name":
        row["name"] = "web[/b]"
        profile = None
        expected = row["name"]
    else:
        profile = ConnectionProfile(name="example-jump", bastion_host="jump[/b].example.test")
        config = app.config_manager.get()
        config.connection_profiles = [profile]
        config.connection_rules = [ConnectionRule("example-rule", {}, profile.name)]
        expected = profile.bastion_host
    target = app.connection_service.get_target_host(row, profile)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = FileBrowserScreen(row)
        await app.push_screen(screen)
        await pilot.pause()
        header = screen.query_one("#browser_header", Static)
        tree = screen.query_one(RemoteTree)
        _capture(app, tmp_path, "file-browser-literal-value")
        assert expected in header.render().plain
        _label_styles(app, header, expected)
        assert tree._instance == row and tree._profile is profile
        assert tree._host == target
        if profile is not None:
            assert profile.bastion_host == expected
        path = "/srv/[b]report[/b].txt"
        leaf = tree.root.add_leaf("report.txt", data={"path": path, "type": "file"})
        # New nodes acquire native line positions on the next layout. Use
        # real keyboard navigation once that layout has reached the screen.
        await pilot.pause()
        assert app.focused is tree
        await pilot.press("end")
        await pilot.pause()
        assert screen.query_one("#browser_path", Static).render().plain == f"Path · {path}"
        assert tree.cursor_node is leaf and app.focused is tree
        assert app._exception is None


@pytest.mark.asyncio
async def test_file_path_demo_toggle_redraws_without_mutating_operational_path(
    hosts: list[_ServerWorkspaceApp],
) -> None:
    app = _host(hosts, "servonaut", False)
    # Documentation-range IPs are already demo stand-ins, so use a neutral
    # public address to exercise actual address redaction.
    app.instances[0]["public_ip"] = "1.1.1.1"
    path = "/srv/web-1/1.1.1.1/[b]report[/b].txt"
    async with app.run_test(size=(100, 30)) as pilot:
        screen = FileBrowserScreen(app.instances[0])
        await app.push_screen(screen)
        await pilot.pause()
        tree = screen.query_one(RemoteTree)
        leaf = tree.root.add_leaf("report.txt", data={"path": path, "type": "file"})
        await pilot.pause()
        assert app.focused is tree
        await pilot.press("end")
        await pilot.pause()
        context = screen.query_one("#browser_path", Static)
        host = tree._host
        assert context.render().plain == f"Path · {path}"
        for demo in (True, False):
            await pilot.press("ctrl+shift+d")
            await pilot.pause()
            assert app.demo_mode is demo
            shown = context.render().plain
            assert shown == f"Path · {app.redact_display_text(path)}"
            if demo:
                assert "web-1" not in shown and "1.1.1.1" not in shown
            assert leaf.data["path"] == path and tree._host == host
            assert tree.cursor_node is leaf and app.focused is tree
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_long_file_context_scrolls_independently_of_tree(
    hosts: list[_ServerWorkspaceApp], navigation_visible: bool,
) -> None:
    app = _host(hosts, "servonaut", navigation_visible)
    app.instances[0]["name"] = "server " + "segment " * 100
    path = "/srv/" + "nested/" * 130 + " visible-tail.txt"
    async with app.run_test(size=(100, 30)) as pilot:
        screen = FileBrowserScreen(app.instances[0])
        await app.push_screen(screen)
        await pilot.pause()
        tree = screen.query_one(RemoteTree)
        leaf = tree.root.add_leaf("report.txt", data={"path": path, "type": "file"})
        await pilot.pause()
        assert app.focused is tree
        await pilot.press("end")
        await pilot.pause()
        assert tree.region.height >= 4
        assert screen.query_one("#browser_path", Static).render().plain == f"Path · {path}"
        for selector in ("#browser_header_scroll", "#browser_path_scroll"):
            scroller = screen.query_one(selector)
            assert scroller.region.height <= 4 and scroller.max_scroll_y > 0
            scroller.focus()
            await pilot.press("end")
            await pilot.wait_for_scheduled_animations()
            assert scroller.scroll_offset.y == scroller.max_scroll_y
            assert tree.region.height >= 4 and tree.cursor_node is leaf
        painted = "\n".join(row for _, _, row in _painted_rows(app, screen.query_one("#browser_path_scroll")))
        assert "visible-tail.txt" in painted
        tree.focus()
        await pilot.pause()
        assert app.focused is tree and tree.cursor_node is leaf
        assert app._exception is None


@pytest.mark.asyncio
async def test_restarted_transfer_keeps_spinner_until_current_worker_finishes(
    hosts: list[_ServerWorkspaceApp], tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _host(hosts, "servonaut", False)
    source = tmp_path / "report.txt"
    source.write_text("fixture payload", encoding="utf-8")
    gates = [asyncio.Event() for _ in range(3)]
    calls = []

    async def delayed_transfer(conn: dict, local_path: str, remote_path: str):
        index = len(calls)
        calls.append((conn, local_path, remote_path))
        await gates[index].wait()
        return 0, "", ""

    async with app.run_test(size=(160, 50)) as pilot:
        screen = SCPTransferScreen(app.instances[0])
        await app.push_screen(screen)
        await pilot.pause()
        monkeypatch.setattr(screen, "_transfer", delayed_transfer)
        screen.query_one("#local_path_input", Input).value = str(source)
        screen.query_one("#remote_path_input", Input).value = "/srv/report.txt"
        spinner = screen.query_one("#transfer_loading", LoadingIndicator)
        status = screen.query_one("#status_output", Static)
        screen._start_transfer()
        await wait_until(lambda: len(calls) == 1)
        predecessor = screen._transfer_worker
        screen._start_transfer()
        await wait_until(lambda: len(calls) == 2 and predecessor.is_finished)
        await pilot.pause()
        assert spinner.display and "Transferring" in status.render().plain
        gates[1].set()
        await wait_until(lambda: not spinner.display)
        assert "completed successfully" in status.render().plain
        screen._start_transfer()
        await wait_until(lambda: len(calls) == 3)
        screen._transfer_worker.cancel()
        await wait_until(lambda: not spinner.display)
        assert status.render().plain == "Transfer cancelled."
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("name,shown_id,expected", [
    ("web[/b]", "id-web", "web[/b]"),
    ("web\x1b\u202e-1", "id-web", "web-1"),
    ("", "id[/b]", "id[/b]"),
    ("", "", "server"),
])
async def test_transfer_context_uses_literal_terminal_safe_shown_identity(
    hosts: list[_ServerWorkspaceApp], name: str, shown_id: str, expected: str,
) -> None:
    app = _host(hosts, "servonaut", False)
    app.instances[0].update(name=name, id=shown_id)
    async with app.run_test(size=(100, 30)) as pilot:
        await app.push_screen(SCPTransferScreen(app.instances[0]))
        await pilot.pause()
        context = app.screen.query_one("#workspace_context", Static)
        assert context.render().plain == f"Transfer · {expected}"
        _label_styles(app, context, f"Transfer · {expected}")
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_file_browser_header_labels_have_readable_actual_paint(
    hosts: list[_ServerWorkspaceApp], tmp_path: Path,
    theme: str, size: tuple[int, int], navigation_visible: bool,
) -> None:
    app = _host(hosts, theme, navigation_visible)
    async with app.run_test(size=size) as pilot:
        screen = FileBrowserScreen(app.instances[0])
        await app.push_screen(screen)
        await pilot.pause()
        header = screen.query_one("#browser_header", Static)
        tree = screen.query_one(RemoteTree)
        assert app.focused is tree
        body = screen.query_one("#file_browser_container")
        row = screen.query_one("#main-layout")
        sidebar = screen.query_one(Sidebar)

        def header_layout_ready() -> bool:
            available = row.content_region.width - (
                sidebar.outer_size.width if sidebar.display else 0
            )
            expected_narrow = available < screen.CONTENT_NARROW_WIDTH
            return (
                available > 0
                and sidebar.display is navigation_visible
                and body.region.width == available
                and screen.has_class("-content-narrow") is expected_narrow
                and header.region.x == body.content_region.x
                and header.region.width == body.content_region.width
            )

        await wait_until(header_layout_ready)
        region = header.region
        _capture(app, tmp_path, "file-browser-initial-header")
        # The established contrast helper resolves actual dim/reverse/default
        # paint against all six explicit export palettes, including both ANSI backgrounds.
        for label in ("File Browser:", "Connection:"):
            _assert_readable(_label_styles(app, header, label), context=f"{theme}/{label}")
        _label_styles(app, header, "web-1")
        _label_styles(app, header, "Direct")
        assert tree.region.y >= header.region.bottom
        assert app.get_widget_at(*tree.region.center)[0] is tree
        await pilot.press("end")
        await pilot.pause()
        assert header.region == region and app.focused is tree
        _label_styles(app, header, "File Browser:")
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light"])
async def test_header_scope_preserves_native_inline_browser_tree(
    hosts: list[_ServerWorkspaceApp], theme: str, tmp_path: Path,
) -> None:
    app = _host(hosts, theme, False)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = ServerActionsScreen(app.instances[0])
        await app.push_screen(screen)
        await pilot.pause()
        browse = screen.query_one("#btn_browse", Button)
        browse.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        await _click(app, pilot, browse)
        await wait_until(lambda: bool(screen.query(RemoteTree)))
        tree = screen.query_one(RemoteTree)
        await wait_until(lambda: app.focused is tree)
        assert app.screen is screen and not screen.query("#browser_header")
        assert tree.styles.background == Color.parse(app.get_css_variables()["surface"])
        leaf = tree.root.add_leaf("report.txt")
        await pilot.pause()
        await pilot.press("end")
        await pilot.wait_for_scheduled_animations()
        tree.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        assert tree.cursor_node is leaf
        _capture(app, tmp_path, "inline-browser-native-end")
        _label_styles(app, tree, "report.txt")
        assert app.get_widget_at(*tree.region.center)[0] is tree
        await pilot.press("escape")
        await pilot.pause()
        assert app.screen is screen and not screen.query(RemoteTree)
        assert app._exception is None
