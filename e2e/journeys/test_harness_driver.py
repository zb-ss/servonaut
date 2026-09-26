"""Self-tests for the TUI driver's own observations and waits.

Each check drives a small app of its own, so it shows what the driver does
rather than what Servonaut does.
"""

from __future__ import annotations

import contextvars

import pytest
from rich.panel import Panel
from textual.app import App, ComposeResult
from textual.containers import Container, VerticalScroll
from textual.widgets import Button, Static

from e2e.harness.pilot import TuiDriver

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]


class _Label(App):
    def compose(self) -> ComposeResult:
        # A Rich renderable, which Textual renders through the active app.
        yield Static(Panel("first draw"), id="label")


async def test_rendered_text_works_outside_the_apps_own_context(journey):
    app = _Label()
    async with app.run_test(size=(60, 10)) as pilot:
        t = TuiDriver(app, pilot, [], journey.staging)
        await t.wait_for_text("first draw")
        app.query_one("#label", Static).update(Panel("second draw"))
        # The desktop host runs the app in tasks of its own, so a journey
        # there reads the screen from a context without an active app, and
        # a widget not drawn since its last change is rendered right here.
        text = contextvars.Context().run(t.rendered_text)
        assert "second draw" in text


class _Card(App):
    """Mounts a card whose button only joins the screen when the card mounts."""

    def __init__(self) -> None:
        super().__init__()
        self.pressed: list[str] = []

    def compose(self) -> ComposeResult:
        yield VerticalScroll(id="body")

    def show_card(self) -> None:
        self.query_one("#body").mount(Container(Button("Go", id="go")))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.pressed.append(event.button.id or "")


async def test_a_click_waits_for_a_button_mounted_with_its_card(journey):
    app = _Card()
    async with app.run_test(size=(60, 10)) as pilot:
        t = TuiDriver(app, pilot, [], journey.staging)
        app.show_card()
        button = await t.wait_for_widget("#go", Button)
        assert button.is_mounted
        await t.click("#go")
        await t.wait_until(lambda: app.pressed == ["go"], desc="the press")


async def test_a_click_on_a_hidden_widget_fails_at_once(journey):
    app = _Card()
    async with app.run_test(size=(60, 10)) as pilot:
        t = TuiDriver(app, pilot, [], journey.staging)
        app.show_card()
        button = await t.wait_for_widget("#go", Button)
        button.display = False
        with pytest.raises(AssertionError, match="is hidden"):
            await t.click("#go")
