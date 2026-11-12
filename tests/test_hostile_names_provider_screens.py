"""Names from a provider or a server are drawn literally, whatever they contain."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from rich.text import Text

from servonaut.screens.aws_manager import AWSManagerScreen
from servonaut.screens.command_overlay import CommandOverlay
from servonaut.screens.hetzner_manager import HetznerManagerScreen
from servonaut.screens.ovh_manager import OVHManagerScreen
from tests._async_bounds import wait_until
from tests.test_command_overlay_presentation import ROW, _Host
from tests.test_workspace_reflow import _painted

HOSTILE = ["a [link=", "a[/]b", "x\\", "[@click=app.quit]z[/]"]
THEME = {"text-success": "#8AD4A1", "text-warning": "#FFC473", "text-accent": "#FFC473", "text-error": "#D17E92"}


def _manager_cells(screen_type: type, table_id: str, name: str) -> tuple:
    screen = screen_type.__new__(screen_type)
    screen._instances = [{"id": name, "name": name, "type": name, "state": "running",
                          "public_ip": name, "region": name, "provider_type": name,
                          "created_at": name}]
    table = MagicMock(row_count=0, cursor_row=0)
    with patch.object(screen, "query_one", return_value=table), \
         patch.object(screen, "_sync_action_buttons"), \
         patch.object(screen, "_update_resource_context"), \
         patch.object(screen_type, "app", new=MagicMock(get_css_variables=lambda: THEME)):
        screen._render_table()
    return table.add_row.call_args.args


@pytest.mark.parametrize("name", HOSTILE)
@pytest.mark.parametrize("screen_type, table_id", [
    (AWSManagerScreen, "#aws_mgr_table"), (HetznerManagerScreen, "#hetzner_mgr_table"),
    (OVHManagerScreen, "#ovh_mgr_table"),
])
def test_manager_table_cells_are_literal_text(screen_type: type, table_id: str, name: str) -> None:
    cells = _manager_cells(screen_type, table_id, name)
    # A column too narrow for the text ends it with an ellipsis; the cell is
    # still literal text, so it is counted by the start of the name.
    start = name[:8]
    texts = [cell for cell in cells if isinstance(cell, Text) and start in cell.plain]
    # Name, type, kind, public address and region: none of them is a markup string.
    assert len(texts) >= 4
    assert not [cell for cell in cells if isinstance(cell, str) and start in cell]
    assert all(
        isinstance(cell, Text) for cell in cells[1:] if start in str(cell)
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("name", HOSTILE)
async def test_command_overlay_shows_the_name_and_profile_literally(
    monkeypatch: pytest.MonkeyPatch, name: str,
) -> None:
    monkeypatch.setattr(CommandOverlay, "_detect_missing_profile", lambda self: name)
    app = _Host()
    async with app.run_test(size=(160, 50)) as pilot:
        overlay = await _open_named(app, pilot, name)
        header = _painted(app, overlay.query_one("#command_header"))
        assert name in header
        output = _painted(app, overlay.query_one("#command_output"))
        assert f"Connected to {name}" in output
        assert f"'{name}' not found" in output
        assert app._exception is None


async def _open_named(app: _Host, pilot, name: str) -> CommandOverlay:
    from textual.widgets import Input

    overlay = CommandOverlay({**ROW, "name": name})
    await app.push_screen(overlay)
    await wait_until(lambda: app.focused is overlay.query_one("#command_input", Input))
    await pilot.pause()
    return overlay
