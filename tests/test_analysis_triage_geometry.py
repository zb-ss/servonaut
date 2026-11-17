"""Native readers keep gate cards, long errors and path actions reachable."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from unittest.mock import AsyncMock, Mock

import pytest
from textual.containers import VerticalScroll
from textual.content import Content
from textual.widgets import Button, Static, TextArea

from servonaut.screens.ai_analysis import AIAnalysisScreen
from servonaut.screens.findings import FindingDetailScreen, FindingsScreen
from servonaut.screens.log_picker import BrowseRemoteScreen
from servonaut.widgets.chat_panel import ChatPanel
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import tab_to
from tests.test_findings_screen import _finding, _mock_auth, _mock_findings_service
from tests.test_workspace_logs import _LogHost, _viewer_instance
from tests.test_workspace_reflow import _painted
from tests.test_workspace_remaining_reflow import _RemainingHost

pytestmark = pytest.mark.usefixtures("navigation_open")


@pytest.fixture(autouse=True)
def _inert_geometry_boundaries(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    connection = AsyncMock(side_effect=AssertionError("Unexpected network"))
    process = Mock(side_effect=AssertionError("Unexpected subprocess"))
    keyring = Mock(side_effect=AssertionError("Unexpected keyring operation"))
    monkeypatch.setattr(asyncio.BaseEventLoop, "create_connection", connection)
    monkeypatch.setattr("subprocess.Popen", process)
    for name in ("get_password", "set_password", "delete_password"):
        monkeypatch.setattr("keyring." + name, keyring)
    yield
    connection.assert_not_awaited()
    process.assert_not_called()
    keyring.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["unauth", "upgrade", "detail"])
async def test_findings_short_cards_do_not_expand_to_reader_height(kind: str) -> None:
    app = _RemainingHost(False)
    app.auth_service = _mock_auth(authenticated=kind != "unauth", entitled=kind != "upgrade")
    app.findings_service = _mock_findings_service()
    screen = (
        FindingDetailScreen(_finding(remediations=[], evidence=["Evidence café [literal] Ω"]))
        if kind == "detail" else FindingsScreen()
    )
    reader_id = "#finding_detail_body" if kind == "detail" else "#findings_state_body"
    async with app.run_test(size=(100, 30)) as pilot:
        await app.push_screen(screen)
        reader = screen.query_one(reader_id, VerticalScroll)
        await wait_until(lambda: len(reader.query(".findings_card")) >= 2)
        await pilot.pause()
        cards = list(reader.query(".findings_card"))
        for card in cards:
            # Short cards share a reader; each must leave room for its neighbour.
            assert 0 < card.region.height < reader.content_region.height
            title = card.query_one(".findings_card_title", Static)
            title.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            assert title.render().plain in _painted(app, title)
        if kind != "detail":
            assert not screen.query_one("#findings_table_card").display
            assert not screen.query_one("#findings_actions").display
            app.findings_service.list_findings.assert_not_awaited()


@pytest.mark.asyncio
async def test_analysis_long_error_keeps_output_and_back_reachable() -> None:
    app = _RemainingHost(False)
    screen = AIAnalysisScreen(text="Source café [literal] Ω")
    error = "\n".join(["Provider error café [literal] Ω", *[f"Diagnostic line {i}" for i in range(40)]])
    async with app.run_test(size=(80, 24)) as pilot:
        origin = app.screen
        await app.push_screen(screen)
        screen.query_one("#ai_status", Static).update(Content.assemble(error))
        output = screen.query_one("#ai_output", TextArea)
        output.load_text("First readable line\nLast readable line")
        document = output.document
        await pilot.pause()
        result = screen.query_one("#ai_result_panel")
        assert result.max_scroll_y > 0
        await tab_to(pilot, output)
        await pilot.pause()
        assert output.content_region.height >= 2
        assert result.scrollable_content_region.contains_region(output.content_region)
        assert "First readable line" in _painted(app, output)
        back = screen.query_one("#btn_back", Button)
        await tab_to(pilot, back)
        await pilot.pause()
        # Back belongs to the shared run controls, outside the output reader.
        body = screen.query_one("#ai_container")
        workbench = screen.query_one("#ai_workbench")
        controls = screen.query_one("#ai_run_controls")
        actions = screen.query_one("#ai_action_row")
        assert result.parent is workbench and workbench.parent is body
        assert back.parent is actions and actions.parent is controls
        assert controls.parent is body
        assert actions.scrollable_content_region.contains_region(back.region)
        assert controls.scrollable_content_region.contains_region(back.region)
        assert body.scrollable_content_region.contains_region(back.region)
        assert screen.region.contains_region(back.region)
        assert screen._compositor.find_widget(back).clip.contains_region(back.region)
        assert app.get_widget_at(*back.region.center)[0] is back
        assert "Back" in _painted(app, back)
        assert screen.query_one("#ai_status", Static).render().plain == error
        assert output.document is document
        assert output.text == "First readable line\nLast readable line"
        await pilot.press("enter")
        await wait_until(lambda: app.screen is origin)
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("width", [48, 56])
async def test_remote_path_actions_paint_complete_labels_in_narrow_content(width: int) -> None:
    app = _LogHost(False)
    screen = BrowseRemoteScreen(_viewer_instance())
    async with app.run_test(size=(width, 30)) as pilot:
        await app.push_screen(screen)
        await wait_until(lambda: bool(screen.query("#browse_tree")))
        await pilot.pause()
        for selector, label in (
            ("#browse_add_file", "Add as file"),
            ("#browse_add_directory", "Add directory"),
            ("#browse_back", "Back"),
        ):
            button = screen.query_one(selector, Button)
            await tab_to(pilot, button)
            await pilot.pause()
            assert label in _painted(app, button)
            assert app.get_widget_at(*button.region.center)[0] is button
