"""Mouse access to the secrets hub uses the existing hotkey action paths."""
from __future__ import annotations

from unittest.mock import Mock

import pytest
from rich.cells import cell_len
from textual.widget import Widget


from servonaut.widgets.action_button import ActionButton, ActionRow
from tests._async_bounds import wait_until
from tests._native_actions import click_action
from tests.test_workspace_secrets import (
    _SecretsHost, _inert_boundaries as _inert_boundaries, _opener,
)

pytestmark = pytest.mark.usefixtures("navigation_open")


async def _actions_settled(pilot, screen) -> None:
    """Wait until every action row is fitted: wrapped exactly when it must be, buttons inside."""
    def settled() -> bool:
        rows = list(screen.query(ActionRow))
        if not rows:
            return False
        for row in rows:
            buttons = list(row.query(ActionButton))
            width = row.size.width
            if width <= 0 or not buttons:
                return False
            needed = sum(b.natural_width(short=True, hint=True) for b in buttons)
            if row.has_class("-wrap") != (needed > width):
                return False
            if any(b.region.right > row.region.right for b in buttons):
                return False
        return True

    await wait_until(settled)
    await pilot.wait_for_scheduled_animations()


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
        await _actions_settled(pilot, screen)
        buttons = list(screen.query(ActionButton))
        assert buttons
        for button in buttons:
            key = button.id.removeprefix("secrets_action_")
            action = Mock()
            monkeypatch.setattr(screen, f"action_{screen._ACTION_NAMES[key]}", action)
            await click_action(pilot, f"#{button.id}")
            action.assert_called_once_with()
            _assert_painted_text(app, button, button.label.plain.rsplit(None, 1)[0])
        assert app._exception is None


@pytest.mark.asyncio
async def test_actions_are_standard_buttons_with_key_hints() -> None:
    app = _SecretsHost(navigation_visible=True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _opener("secrets")(app, pilot)
        buttons = list(screen.query(ActionButton))
        assert not list(screen.query("Button.secrets_action_key"))
        assert [b.variant for b in buttons].count("primary") == 1
        assert buttons[0].variant == "primary"
        for button in buttons:
            key = button.id.removeprefix("secrets_action_")
            assert str(button.label).endswith(key)
            assert key in screen._ACTION_NAMES


@pytest.mark.asyncio
async def test_every_action_key_triggers_its_action(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _SecretsHost(navigation_visible=True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _opener("secrets")(app, pilot)
        for button in list(screen.query(ActionButton)):
            key = button.id.removeprefix("secrets_action_")
            calls: list[str] = []
            monkeypatch.setattr(
                screen, f"action_{screen._ACTION_NAMES[key]}", lambda calls=calls: calls.append("hit"),
            )
            screen.set_focus(None)
            await pilot.press(key)
            await pilot.pause()
            assert calls == ["hit"], key


@pytest.mark.asyncio
async def test_refreshing_keeps_every_action_inside_the_screen() -> None:
    app = _SecretsHost(navigation_visible=False)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _opener("secrets")(app, pilot)
        for _ in range(4):
            await _actions_settled(pilot, screen)
            old = list(screen.query(ActionRow))
            screen.set_focus(None)
            await pilot.press("r")
            await wait_until(lambda: not any(row.parent is not None for row in old))
            await _actions_settled(pilot, screen)
            for button in screen.query(ActionButton):
                assert button.region.right <= app.screen.region.right, button.id
                assert button.tooltip
