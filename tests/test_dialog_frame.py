"""Real-stylesheet dialog navigation and overflow regressions."""

from __future__ import annotations

import pytest
from textual import events
from textual.app import App, ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.power_confirm import PowerActionConfirmModal
from servonaut.screens.settings.shell import DiscardChangesModal
from servonaut.styles import CSS_FILES
from servonaut.styles.themes import SERVONAUT_THEMES
from servonaut.widgets.dialogs import DialogActions, DialogBody, DialogFrame

from tests._async_bounds import wait_until


class DialogHost(App):
    """Host real modals without constructing services or reading app config."""

    CSS_PATH = CSS_FILES

    def __init__(self) -> None:
        super().__init__()
        for theme in SERVONAUT_THEMES:
            self.register_theme(theme)
        self.theme = "servonaut"
        self.animation_level = "none"

    def compose(self) -> ComposeResult:
        yield Input(id="origin")


REGISTERED_THEMES = tuple(sorted(DialogHost().available_themes))


def make_dialog(kind: str, *, long: bool = False) -> tuple[ModalScreen[bool], str]:
    """Use neutral content with enough lines to overflow either viewport."""
    details = ["Services on web-1 will stop."] * (45 if long else 1)
    if kind == "power":
        return PowerActionConfirmModal(
            action="Power off", server_name="web-1", provider="Example Cloud",
            consequence="\n".join(details),
        ), "btn_power_confirm_no"
    if kind == "discard":
        return DiscardChangesModal("\n".join(details) if long else "General"), "discard-cancel"
    return ConfirmActionScreen(
        title="Delete server", description="Review the selected server.",
        consequences=details, confirm_text="web-1", action_label="Delete",
    ), "confirm_input"


def assert_actions_visible(screen: ModalScreen[bool]) -> None:
    """Actions remain fully inside both the dialog and the visible screen."""
    frame = screen.query_one(DialogFrame)
    for button in screen.query_one(DialogActions).query(Button):
        assert button.region.width > 0 and button.region.height > 0
        assert button.visible
        assert screen.region.contains_region(button.region)
        assert frame.content_region.contains_region(button.region)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("kind", ["power", "discard", "confirm"])
async def test_short_dialog_keeps_safe_focus_and_returns_to_origin(
    kind: str, size: tuple[int, int],
) -> None:
    """Short bodies add no tab stop; accidental Enter cannot confirm an action."""
    app = DialogHost()
    screen, safe_id = make_dialog(kind)
    results: list[bool] = []
    async with app.run_test(size=size) as pilot:
        origin = app.query_one("#origin", Input)
        origin.focus()
        await pilot.pause()
        app.push_screen(screen, results.append)
        await pilot.pause()
        assert screen.focused is screen.query_one(f"#{safe_id}")
        assert screen.query_one(DialogBody) not in screen.focus_chain
        assert_actions_visible(screen)
        if kind == "confirm":
            field = screen.query_one("#confirm_input", Input)
            confirm = screen.query_one("#btn_confirm", Button)
            assert confirm.disabled
            await pilot.press(*"web-1")
            await pilot.pause()
            assert field.value == "web-1" and not confirm.disabled
            await pilot.press("enter")
            await pilot.pause()
            assert app.screen is screen and results == []
            await pilot.press("escape")
        else:
            await pilot.press("enter")
        await pilot.pause()
        assert results == [False]
        assert app.screen is not screen
        assert app.focused is origin


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", REGISTERED_THEMES)
async def test_dialog_action_focus_changes_background_in_every_theme(theme: str) -> None:
    """Every action variant has a focus cue beyond bold text or border colour."""
    app = DialogHost()
    app.theme = theme
    screen, _ = make_dialog("confirm")
    results: list[bool] = []
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        field = screen.query_one("#confirm_input", Input)
        button = screen.query_one("#btn_confirm", Button)
        field.value = "web-1"
        await pilot.pause()
        missing_cues: list[str] = []
        for variant in ("default", "warning", "error"):
            button.variant = variant
            field.focus()
            await pilot.pause()
            blurred = (button.styles.background, button.styles.text_style.reverse)
            blurred_render = (button.rich_style.bgcolor, button.rich_style.reverse)
            await pilot.press("tab", "tab")
            await pilot.pause()
            assert screen.focused is button
            focused = (button.styles.background, button.styles.text_style.reverse)
            focused_render = (button.rich_style.bgcolor, button.rich_style.reverse)
            if focused == blurred or focused_render == blurred_render:
                missing_cues.append(variant)
            label_segments = [
                segment
                for y in range(button.size.height)
                for segment in button.render_line(y)
                if "Delete" in segment.text
            ]
            assert label_segments and all(
                segment.style and segment.style.underline
                for segment in label_segments
            )
        assert not missing_cues, f"{theme} lacks background/reverse focus cues: {missing_cues}"
        field.focus()
        field.value = "invalid"
        await pilot.pause()
        assert button.disabled and button.styles.opacity == 0.5
        button.focus()
        await pilot.pause()
        assert screen.focused is field
        await pilot.press("enter")
        await pilot.pause()
        assert results == [] and app.screen is screen
        await pilot.press("escape")
        await pilot.pause()
        assert results == [False]
        power_screen, safe_id = make_dialog("power")
        app.push_screen(power_screen)
        await pilot.pause()
        safe_button = power_screen.query_one(f"#{safe_id}", Button)
        assert power_screen.focused is safe_button
        safe_segments = [
            segment
            for y in range(safe_button.size.height)
            for segment in safe_button.render_line(y)
            if "No" in segment.text
        ]
        assert safe_segments and all(
            segment.style and segment.style.underline for segment in safe_segments
        )
        await pilot.press("enter")
        await pilot.pause()
        assert app.screen is not power_screen


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("severity", ["danger", "warning"])
async def test_short_typed_confirmation_fits_its_content(
    size: tuple[int, int], severity: str,
) -> None:
    """Short detail stays fully visible without expanding into unused blank rows."""
    app = DialogHost()
    screen = ConfirmActionScreen(
        title="Delete server", description="Review the selected server.",
        consequences=["Services on web-1 will stop."], confirm_text="web-1",
        action_label="Delete", severity=severity,
    )
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        body = screen.query_one(DialogBody)
        content_height = sum(
            child.outer_size.height + child.styles.margin.height
            for child in body.children
        )
        assert body.size.height == content_height
        assert body.max_scroll_y == 0
        assert not screen.query_one(DialogFrame).border_subtitle
        assert_actions_visible(screen)
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("push_method", ["callback", "wait"])
async def test_long_confirmation_initially_types_into_input(
    size: tuple[int, int], push_method: str,
) -> None:
    """An overflowing body never takes the first typed confirmation keystrokes."""
    app = DialogHost()
    screen, _ = make_dialog("confirm", long=True)
    results: list[bool] = []
    async with app.run_test(size=size) as pilot:
        worker = None
        if push_method == "callback":
            app.push_screen(screen, results.append)
        else:
            async def wait_for_confirmation() -> None:
                results.append(await app.push_screen_wait(screen))

            worker = app.run_worker(wait_for_confirmation())
        # The worker can push after pause has already drained the previous screen.
        await wait_until(lambda: (
            app.screen is screen and screen.is_mounted
            and screen.query_one(DialogBody).is_mounted
            and screen.query_one(DialogBody).virtual_size.height > 0
            and screen.query_one(DialogBody).container_size.height > 0
            and not screen._layout_required
        ))
        await pilot.pause()
        field = screen.query_one("#confirm_input", Input)
        assert screen.query_one(DialogBody).max_scroll_y > 0
        assert screen.focused is field
        await pilot.press(*"web-1")
        await pilot.pause()
        assert field.value == "web-1"
        assert not screen.query_one("#btn_confirm", Button).disabled
        await pilot.press("enter")
        await pilot.pause()
        assert app.screen is screen and results == []
        await pilot.press("escape")
        await pilot.pause()
        if worker is not None:
            await worker.wait()
        assert results == [False]
        assert app.screen is not screen


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("kind", ["power", "discard", "confirm"])
async def test_long_dialog_scrolls_by_keyboard_without_moving_actions(
    kind: str, size: tuple[int, int],
) -> None:
    """Overflow remains keyboard-readable while confirmation controls stay visible."""
    app = DialogHost()
    screen, _ = make_dialog(kind, long=True)
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        body = screen.query_one(DialogBody)
        frame = screen.query_one(DialogFrame)
        assert body.max_scroll_y > 0
        assert body in screen.focus_chain
        body.focus()
        await pilot.pause()
        assert screen.focused is body
        before = body.scroll_y
        await pilot.press("pagedown")
        await pilot.pause()
        assert body.scroll_y > before
        assert frame.max_scroll_y == 0
        assert_actions_visible(screen)
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("kind", ["power", "discard", "confirm"])
@pytest.mark.parametrize("notification_count", [2, 8])
async def test_notifications_leave_dialog_actions_clickable(
    kind: str, size: tuple[int, int], notification_count: int,
) -> None:
    """Live notifications cannot cover the prompt or intercept a cancel click."""
    app = DialogHost()
    screen, _ = make_dialog(kind)
    results: list[bool] = []
    async with app.run_test(size=size, notifications=True) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        for index in range(notification_count):
            app.notify(f"Example operation {index + 1} completed.", timeout=60)
        await pilot.pause()
        rack = screen.query_one("ToastRack")
        assert len(rack.query("Toast")) == notification_count
        frame = screen.query_one(DialogFrame)
        actions = screen.query_one(DialogActions)
        assert_actions_visible(screen)
        content_regions = [screen.query_one(DialogBody).region, actions.region]
        if kind == "confirm":
            content_regions.append(screen.query_one("#confirm_prompt").region)
        for region in content_regions:
            assert frame.content_region.contains_region(region)
        for region in (frame.region, *content_regions):
            assert screen.region.contains_region(region)
            assert not rack.region.overlaps(region)
        for button in actions.query(Button):
            region = button.region
            hit, _ = app.get_widget_at(
                region.x + region.width // 2,
                region.y + region.height // 2,
            )
            assert hit is button
        for toast in rack.query("Toast"):
            for region in content_regions:
                overlap = toast.region.intersection(region)
                for y in range(overlap.y, overlap.bottom):
                    for x in range(overlap.x, overlap.right):
                        hit, _ = app.get_widget_at(x, y)
                        assert hit is not toast
        cancel_id = {
            "power": "btn_power_confirm_no", "discard": "discard-cancel", "confirm": "btn_cancel",
        }[kind]
        cancel = screen.query_one(f"#{cancel_id}", Button)
        region = cancel.region
        assert await pilot.click(
            offset=(region.x + region.width // 2, region.y + region.height // 2),
        )
        await pilot.pause()
        assert results == [False]
        assert app.screen is not screen


def assert_warning_exposed(app: DialogHost, screen: ConfirmActionScreen) -> None:
    """The complete irreversible-action notice is painted above other widgets."""
    warning = screen.query_one("#severity_message", Static)
    assert warning.render().plain == "This action CANNOT be undone."
    assert screen.query_one(DialogFrame).content_region.contains_region(warning.region)
    assert screen.region.contains_region(warning.region)
    for y in range(warning.region.y, warning.region.bottom):
        for x in range(warning.region.x, warning.region.right):
            hit, _ = app.get_widget_at(x, y)
            assert hit is warning


@pytest.mark.asyncio
@pytest.mark.parametrize("notification_count", [0, 1, 2])
async def test_danger_warning_stays_visible_with_long_consequences(
    notification_count: int,
) -> None:
    """A narrow destructive prompt exposes its warning and advertises hidden detail."""
    app = DialogHost()
    screen = ConfirmActionScreen(
        title="Delete stored keys", description="Review the selected example keys.",
        consequences=[
            "Remove the selected example connection keys from this device and stop using them for future connections.",
            "Other devices retain their copies until an operator updates each device using the normal key management process.",
            "Any example server that still accepts a removed key must be updated separately before the key is no longer usable.",
        ],
        confirm_text="delete keys", action_label="Delete keys",
    )
    results: list[bool] = []
    async with app.run_test(size=(100, 30), notifications=True) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        for index in range(notification_count):
            app.notify(f"Example operation {index + 1} completed.", timeout=60)
        await pilot.pause()
        assert_warning_exposed(app, screen)
        assert_actions_visible(screen)
        field = screen.query_one("#confirm_input", Input)
        confirm = screen.query_one("#btn_confirm", Button)
        assert confirm.disabled
        field.value = "delete keys "
        await pilot.pause()
        assert confirm.disabled
        field.value = "delete keys"
        await pilot.pause()
        assert not confirm.disabled  # Reading to the end is not an additional gate.
        await pilot.press("enter")
        await pilot.pause()
        assert app.screen is screen and results == []
        body = screen.query_one(DialogBody)
        frame = screen.query_one(DialogFrame)
        assert bool(frame.border_subtitle) == (body.max_scroll_y > 0)
        all_consequences_visible = all(
            body.scrollable_content_region.contains_region(item.region)
            for item in body.query(".consequence_item")
        )
        if not all_consequences_visible:
            assert screen.query_one(DialogFrame).border_subtitle
            assert body in screen.focus_chain and body.max_scroll_y > 0
            body.focus()
            await pilot.press("pagedown")
            await pilot.pause()
            assert body.scroll_y > 0
            assert_warning_exposed(app, screen)
        await pilot.click(confirm)
        await pilot.pause()
        assert results == [True]


@pytest.mark.asyncio
async def test_overflow_cue_tracks_resize_and_notification_lifecycle() -> None:
    """The scroll hint appears only while the dialog actually has hidden details."""
    app = DialogHost()
    screen = ConfirmActionScreen(
        title="Delete stored keys",
        description="\n".join(["Review the example key details."] * 10),
        consequences=["Remove the selected example keys."],
        confirm_text="delete keys", action_label="Delete keys",
    )
    async with app.run_test(size=(100, 30), notifications=True) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        frame = screen.query_one(DialogFrame)
        body = screen.query_one(DialogBody)
        assert body.max_scroll_y > 0 and frame.border_subtitle
        assert_warning_exposed(app, screen)
        await pilot.resize_terminal(160, 50)
        await pilot.pause()
        assert body.max_scroll_y == 0 and not frame.border_subtitle
        for index in range(2):
            app.notify(f"Example operation {index + 1} completed.", timeout=60)
        await pilot.pause()
        assert body.max_scroll_y == 0 and not frame.border_subtitle
        assert_warning_exposed(app, screen)
        app.clear_notifications()
        await pilot.pause()
        assert body.max_scroll_y == 0 and not frame.border_subtitle
        assert_warning_exposed(app, screen)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        assert body.max_scroll_y > 0 and frame.border_subtitle
        assert_warning_exposed(app, screen)
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("kind", ["power", "discard", "confirm"])
async def test_dialog_buttons_stay_put_through_notification_lifecycle(
    kind: str, size: tuple[int, int],
) -> None:
    """Notification arrival and expiry cannot move a user's action target."""
    app = DialogHost()
    screen, _ = make_dialog(kind)
    async with app.run_test(size=size, notifications=True) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        buttons = list(screen.query_one(DialogActions).query(Button))
        original_regions = {button.id: button.region for button in buttons}
        for count in (0, 1, 2, 8, 1, 0):
            toasts = list(screen.query("Toast"))
            if len(toasts) > count:
                for toast in toasts[count:]:
                    # Drive native timeout behavior without relying on wall-clock timing.
                    toast._expire()
            else:
                for index in range(len(toasts), count):
                    app.notify(f"Example operation {index + 1} completed.", timeout=60)
            await pilot.pause()
            assert len(screen.query("Toast")) == count
            assert_actions_visible(screen)
            for button in buttons:
                region = original_regions[button.id]
                assert button.region == region, f"{count} notifications moved {button.id}"
                hit, _ = app.get_widget_at(
                    region.x + region.width // 2, region.y + region.height // 2,
                )
                assert hit is button
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_toast_expiry_between_coordinate_read_and_mouse_down_confirms_once(
    size: tuple[int, int],
) -> None:
    """A cached click point survives the expiry of an earlier notification."""
    app = DialogHost()
    screen, _ = make_dialog("confirm")
    results: list[bool] = []
    async with app.run_test(size=size, notifications=True) as pilot:
        app.push_screen(screen, results.append)
        for index in range(2):
            app.notify(f"Example operation {index + 1} completed.", timeout=60)
        await pilot.pause()
        screen.query_one("#confirm_input", Input).value = "web-1"
        await pilot.pause()
        confirm = screen.query_one("#btn_confirm", Button)
        assert not confirm.disabled
        region = confirm.region
        point = (region.x + region.width // 2, region.y + region.height // 2)
        assert app.get_widget_at(*point)[0] is confirm
        # Expire the actual native Toast after acquiring the driver's integer
        # coordinates, then deliver MouseDown at that same point after reflow.
        screen.query("Toast").first()._expire()
        await pilot.pause()
        assert len(screen.query("Toast")) == 1
        assert confirm.region == region
        assert app.get_widget_at(*point)[0] is confirm
        assert await pilot.click(offset=point)
        await pilot.pause()
        assert results == [True]
        assert app.screen is not screen


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_many_notifications_show_newest_and_allow_reading_earlier_alerts(
    size: tuple[int, int],
) -> None:
    """A bounded native notification lane shows new alerts and keeps older ones accessible."""
    app = DialogHost()
    screen, _ = make_dialog("confirm")
    async with app.run_test(size=size, notifications=True) as pilot:
        app.push_screen(screen)
        for index in range(8):
            app.notify(f"Example operation {index + 1} completed.", timeout=60)
        await pilot.pause()
        rack = screen.query_one("ToastRack")
        toasts = list(rack.query("Toast"))
        assert len(toasts) == 8 and rack.max_scroll_y > 0
        assert rack.scroll_y == rack.max_scroll_y
        newest = toasts[-1]
        assert newest.render().plain.endswith("Example operation 8 completed.")
        assert rack.scrollable_content_region.contains_region(newest.region)
        region = newest.region
        assert app.get_widget_at(
            region.x + region.width // 2, region.y + region.height // 2,
        )[0] is newest
        while rack.scroll_y > 0:
            before = rack.scroll_y
            # Pilot has no public wheel method; send its native mouse event
            # through hit testing and bubbling rather than scrolling directly.
            await pilot._post_mouse_events(
                [events.MouseScrollUp], widget=rack,
                offset=(rack.size.width * 3 // 4, rack.size.height // 2),
            )
            await pilot.pause()
            assert rack.scroll_y < before
        assert rack.scrollable_content_region.contains_region(toasts[0].region)
        assert toasts[0].render().plain.endswith("Example operation 1 completed.")
        assert_actions_visible(screen)
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize(
    ("title", "message"),
    [
        ("Relay", "Could not reach the relay; retrying in 30 seconds."),
        (
            "Reboot failed",
            "Could not reboot web-1: the provider refused the request because "
            "the server is locked by another operation in progress.",
        ),
        ("Operation failed", "First detail.\nSecond detail.\nFinal detail."),
    ],
)
async def test_titled_notifications_expose_title_and_complete_message(
    size: tuple[int, int], title: str, message: str,
) -> None:
    """A title plus three message rows fits the notification lane without clipping."""
    app = DialogHost()
    screen, _ = make_dialog("confirm")
    async with app.run_test(size=size, notifications=True) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        frame = screen.query_one(DialogFrame)
        original_frame = frame.region
        buttons = list(screen.query_one(DialogActions).query(Button))
        original_regions = [button.region for button in buttons]
        app.notify(message, title=title, severity="error", timeout=60)
        await pilot.pause()
        rack = screen.query_one("ToastRack")
        toast = rack.query("Toast").first()
        assert toast.render().plain == f"{title}\n{message}"
        assert rack.scrollable_content_region.contains_region(toast.region)
        assert rack.max_scroll_y == 0
        for y in range(toast.content_region.y, toast.content_region.bottom):
            assert app.get_widget_at(toast.content_region.x, y)[0] is toast
        assert frame.region == original_frame
        assert [button.region for button in buttons] == original_regions
        assert_warning_exposed(app, screen)
        assert_actions_visible(screen)
        assert screen.focused is screen.query_one("#confirm_input")
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_long_titled_notification_scrolls_and_dismisses_without_moving_dialog(
    size: tuple[int, int],
) -> None:
    """Native wheel scrolling exposes both ends of an alert taller than its lane."""
    app = DialogHost()
    screen, _ = make_dialog("confirm")
    results: list[bool] = []
    async with app.run_test(size=size, notifications=True) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        frame = screen.query_one(DialogFrame)
        original_frame = frame.region
        buttons = list(screen.query_one(DialogActions).query(Button))
        original_regions = [button.region for button in buttons]
        message = "\n".join(f"Example detail {index + 1}." for index in range(12))
        app.notify(message, title="Operation failed", severity="error", timeout=60)
        await pilot.pause()
        rack = screen.query_one("ToastRack")
        toast = rack.query("Toast").first()
        assert rack.scroll_y == rack.max_scroll_y > 0
        for event, target, expected in (
            (events.MouseScrollUp, 0, "Operation failed"),
            (events.MouseScrollDown, rack.max_scroll_y, "Example detail 12."),
        ):
            while rack.scroll_y != target:
                before = rack.scroll_y
                await pilot._post_mouse_events(
                    [event], widget=rack,
                    offset=(rack.size.width * 3 // 4, rack.size.height // 2),
                )
                await pilot.pause()
                assert rack.scroll_y != before
            y = (
                toast.content_region.bottom - 1
                if target else toast.content_region.y
            )
            point = (toast.content_region.x, y)
            assert rack.scrollable_content_region.contains(*point)
            assert app.get_widget_at(*point)[0] is toast
            assert expected in toast.render_line(y - toast.region.y).text
            assert frame.region == original_frame
            assert [button.region for button in buttons] == original_regions
            assert_warning_exposed(app, screen)
            assert_actions_visible(screen)
            assert screen.focused is screen.query_one("#confirm_input")
        assert await pilot.click(offset=point)
        await pilot.pause()
        assert not rack.query("Toast")
        assert frame.region == original_frame
        assert [button.region for button in buttons] == original_regions
        assert results == []
        await pilot.press("escape")
        await pilot.pause()
        assert results == [False]
