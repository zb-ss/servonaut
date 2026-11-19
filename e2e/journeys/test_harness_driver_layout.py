"""Checks that the driver clicks controls after their layout changes."""
import pytest
from textual.app import App, ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Button, Static

from e2e.harness.pilot import TuiDriver

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]


class _Layout(App):
    CSS = """
    #body { height: 1fr; }
    #spacer { height: 1; }
    #result { height: 1; }
    """

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="body"):
            yield Static("Content", id="spacer")
            yield Button("Go", id="go")
        yield Static("Waiting", id="result")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.query_one("#result", Static).update("Pressed " + event.button.id)


async def test_click_after_content_above_grows(journey):
    app = _Layout()
    async with app.run_test(size=(60, 10)) as pilot:
        t = TuiDriver(app, pilot, [], journey.staging)
        app.query_one("#spacer").styles.height = 50
        await t.click(app.query_one("#go", Button))
        await t.wait_for_text("Pressed go")
