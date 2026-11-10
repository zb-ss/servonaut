"""SSH CA screen: labels keep their own row above a Select; actions are key-hinted buttons."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from textual.app import App
from textual.widgets import Select

from servonaut.screens.ca import CaScreen
from servonaut.styles import CSS_FILES
from servonaut.widgets.action_button import ActionButton

SIZES = [(160, 50), (100, 30)]
ACTION_KEYS = {
    "ca_enable": "s", "ca_refresh": "r", "ca_audit": "a",
    "ca_enroll": "e", "ca_krl": "k", "ca_break_glass_scan": "b",
}


class _Harness(App):
    CSS_PATH = CSS_FILES

    def __init__(self) -> None:
        super().__init__()
        self.vault_command_service = None
        self.config_manager = SimpleNamespace(get=lambda: SimpleNamespace())

    def on_mount(self) -> None:
        self.push_screen(CaScreen())


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_each_label_keeps_its_own_row_above_its_select(size: tuple[int, int]) -> None:
    app = _Harness()
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        setup = app.screen.query_one("#ca_setup")
        labels = list(setup.query(".access_field_label"))
        selects = list(setup.query(Select))
        assert len(labels) == len(selects) == 3
        for label, select in zip(labels, selects):
            assert label.region.height == 1
            assert not label.region.overlaps(select.region)
            assert label.region.bottom <= select.region.y


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_actions_are_hinted_buttons_at_natural_width(size: tuple[int, int]) -> None:
    app = _Harness()
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        for button_id, key in ACTION_KEYS.items():
            button = app.screen.query_one(f"#{button_id}", ActionButton)
            assert button.label.plain.endswith(key)
            if button.display:
                assert button.region.width <= button.natural_width(short=False, hint=True)
                assert button.region.width < app.screen.query_one("#ca_report").region.width // 2


@pytest.mark.asyncio
async def test_action_keys_press_only_buttons_that_could_be_clicked(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _Harness()
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        screen = app.screen
        pressed: list[str | None] = []
        monkeypatch.setattr(screen, "_run_button", pressed.append)
        await pilot.press("a")  # Audit is disabled until a team is chosen
        await pilot.press("s")  # Switch on is hidden until a team reports it is off
        assert pressed == []
        screen.query_one("#ca_audit").disabled = False
        await pilot.press("a")
        assert pressed == ["ca_audit"]
