"""Layout regression tests for the shared settings form widgets.

Guards the "page-height gap" bug: a Textual ``Vertical`` defaults to
``height: 1fr``, so the rows container inside ``StringListEditor`` /
``KeyValueEditor`` would balloon to fill its parent and push the add row
off-screen. The containers must size to their content instead.
"""

from __future__ import annotations

import pytest
from textual.app import App
from textual.containers import Vertical

from servonaut.screens.settings.widgets import KeyValueEditor, StringListEditor
from servonaut.styles import CSS_FILES


class _EditorHost(App):
    """Tall host so a 1fr-inflated rows container would be obviously large."""

    CSS_PATH = CSS_FILES

    def compose(self):
        # Wrap in the settings-panel class so the content-sizing blanket applies,
        # exactly as panels mount these editors.
        with Vertical(classes="settings-panel"):
            yield StringListEditor(id="sle")
            yield KeyValueEditor(id="kve")


@pytest.mark.asyncio
async def test_list_and_map_editor_rows_are_content_sized():
    app = _EditorHost()
    async with app.run_test(size=(120, 50)) as pilot:
        await pilot.pause()
        sle = app.query_one("#sle", StringListEditor)
        kve = app.query_one("#kve", KeyValueEditor)
        sle.set_values(["a", "b", "c"])
        kve.set_map({"k1": "v1", "k2": "v2"})
        await pilot.pause()
        await pilot.pause()

        # Each row is an Input (Textual default height 3) + 1 margin = ~4 lines.
        # Content-sized: ~rows*4, NOT the 50-row host height a 1fr grab would take.
        list_rows = sle.query_one(".list-rows")
        kv_rows = kve.query_one(".kv-rows")
        assert len(list_rows.children) == 3
        assert len(kv_rows.children) == 2
        # Comfortably below the host height; would be ~50 if inflated to 1fr.
        assert list_rows.region.height <= 3 * 5 + 4, list_rows.region.height
        assert kv_rows.region.height <= 2 * 5 + 4, kv_rows.region.height
