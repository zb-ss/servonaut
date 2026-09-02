"""Style guard: the Custom Servers add form must not be clipped.

Screen tests that build their own wrapper app never load the stylesheet, so
this one mounts ``CSS_FILES`` and measures the real layout: the form has to
grow to its content (height auto) and every input must lie inside it, on a
47-row terminal as well as a tall one.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from textual.app import App
from textual.widgets import Input

from servonaut.screens.custom_servers import CustomServersScreen
from servonaut.styles import CSS_FILES


class _Host(App):
    CSS_PATH = CSS_FILES

    def __init__(self) -> None:
        super().__init__()
        self.demo_mode = False
        self.redaction_service = None
        self.custom_server_service = MagicMock()
        self.custom_server_service.list_servers.return_value = []
        self.instances = []

    def on_mount(self) -> None:
        self.push_screen(CustomServersScreen())


@pytest.mark.parametrize("size", [(166, 47), (120, 40), (166, 70)])
@pytest.mark.asyncio
async def test_add_form_encloses_every_input(size) -> None:
    app = _Host()
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        await pilot.press("n")
        await pilot.pause()
        screen = app.screen
        form = screen.query_one("#add_form")
        assert str(form.styles.height) == "auto"
        bottom = form.region.y + form.region.height
        for widget in screen.query("#add_form Input"):
            assert widget.region.y + widget.region.height <= bottom, widget.id
        assert isinstance(app.focused, Input)
