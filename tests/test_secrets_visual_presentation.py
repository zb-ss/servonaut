"""Mouse access to the secrets hub uses the existing hotkey action paths."""
from __future__ import annotations

from unittest.mock import Mock

import pytest
from rich.cells import cell_len
from textual.widget import Widget
from textual.widgets import Button, Static

from tests._native_actions import click_action
from tests.test_workspace_secrets import (
    _SecretsHost, _inert_boundaries as _inert_boundaries, _opener,
)


def _assert_painted_text(app: _SecretsHost, widget: Widget, text: str) -> None:
    """Require visible glyphs whose painted cells belong to the native control."""
    bounds = widget.content_region.intersection(app.screen.region)
    strips = app.screen._compositor.render_strips()
    for y in range(bounds.y, bounds.bottom):
        row = strips[y].crop(bounds.x, bounds.right).text
        offset = row.find(text)
        if offset < 0:
            continue
        left = bounds.x + cell_len(row[:offset])
        for x in range(left, left + cell_len(text)):
            hit = app.get_widget_at(x, y)[0]
            assert hit is widget or widget in hit.ancestors
        return
    pytest.fail(f"{widget.id or widget.css_identifier} did not paint {text!r} in {bounds}")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30), (80, 24)])
async def test_provider_action_controls_dispatch_existing_actions(
    size: tuple[int, int], monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _SecretsHost(navigation_visible=True)
    async with app.run_test(size=size) as pilot:
        screen = await _opener("secrets")(app, pilot)
        buttons = list(screen.query("Button.secrets_action_key"))
        assert buttons
        for button in buttons:
            action = Mock()
            monkeypatch.setattr(screen, f"action_{button.name}", action)
            await click_action(pilot, f"#{button.id}")
            action.assert_called_once_with()
            _assert_painted_text(app, button, str(button.label))
            label = button.parent.query_one(".secrets_action_label", Static)
            _assert_painted_text(app, label, str(label.render()))
        assert app._exception is None
