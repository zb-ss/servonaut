"""Utility prompts keep typed guards, raw command results and native parity."""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from textual.app import ComposeResult
from textual.binding import Binding
from textual.pilot import Pilot
from textual.screen import ModalScreen
from textual.widget import Widget
from textual.widgets import Button, Checkbox, Input, OptionList, SelectionList, Static

from servonaut.screens.bulk_action import BulkActionModal
from servonaut.screens.command_overlay import CommandOverlay
from servonaut.screens.command_picker import (
    CommandPickerModal, SaveCommandModal, _DEBOUNCE_SECONDS,
)
from servonaut.utils import platform_utils
from servonaut.widgets.dialogs import DialogBody, DialogContent, DialogFrame
from tests._async_bounds import wait_until
from tests.test_dialog_frame import DialogHost


RAW_COMMAND = "  printf 'café Ω'  "


@pytest.fixture(autouse=True)
def _no_external_effects(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    process = Mock(side_effect=AssertionError("Unexpected process execution"))
    network = Mock(side_effect=AssertionError("Unexpected network connection"))
    async_network = AsyncMock(side_effect=AssertionError("Unexpected async network"))
    config = Mock(side_effect=AssertionError("Unexpected config/secret loading"))
    clipboard = Mock(side_effect=AssertionError("Unexpected clipboard write"))
    monkeypatch.setattr("subprocess.Popen", process)
    monkeypatch.setattr("subprocess.run", process)
    monkeypatch.setattr("socket.create_connection", network)
    monkeypatch.setattr("asyncio.open_connection", async_network)
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", config)
    monkeypatch.setattr(DialogHost, "copy_to_clipboard", clipboard)
    previous = platform_utils.clipboard_writer()
    platform_utils.set_clipboard_writer(clipboard)
    try:
        yield
    finally:
        platform_utils.set_clipboard_writer(previous)
    for guard in (process, network, async_network, config, clipboard):
        guard.assert_not_called()


def _bulk(
    *, count: int = 3, phrase: str | None = "DELETE", ack: bool = False,
) -> BulkActionModal:
    return BulkActionModal(
        "Delete example records", "Review records before continuing. " * 12,
        [(key, f"Record {key}") for key in ("a", "b", "c")[:count]],
        action_label="Delete", confirm_text=phrase,
        acknowledgement=("Include unchecked", "DELETE UNCHECKED") if ack else None,
        acknowledgement_hint="Review unchecked records carefully." if ack else None,
        acknowledgement_keys=["c"] if ack else None,
    )


def _picker(saved: bool = True) -> CommandPickerModal:
    return CommandPickerModal(
        [{"name": "Example", "command": RAW_COMMAND}] if saved else [],
        ["uptime", RAW_COMMAND, "pwd"],
    )


async def _open(
    app: DialogHost, pilot: Pilot, modal: ModalScreen, selector: str,
    results: list[object],
) -> Widget:
    origin = app.query_one("#origin", Input)
    origin.focus()
    await wait_until(lambda: app.focused is origin)
    await app.push_screen(modal, results.append)
    await wait_until(lambda: bool(modal.query(selector)))
    control = modal.query_one(selector)
    await wait_until(lambda: app.focused is control)
    await pilot.pause()
    return control


def _painted(app: DialogHost) -> str:
    return "\n".join(strip.text for strip in app.screen._compositor.render_strips())


async def _tab_to(pilot: Pilot, target: Widget) -> None:
    for _ in range(len(pilot.app.screen.focus_chain) + 1):
        if pilot.app.focused is target:
            return
        await pilot.press("tab")
    raise AssertionError(f"Native Tab must reach {target!r}")


async def _click(pilot: Pilot, selector: str) -> None:
    button = pilot.app.screen.query_one(selector, Button)
    button.scroll_visible(animate=False, immediate=True)
    await wait_until(lambda: not button.has_class("-active"))
    await pilot.pause()
    assert pilot.app.get_widget_at(*button.region.center)[0] is button
    assert await pilot.click(button)
    await pilot.pause()


def _assert_exposed(app: DialogHost, modal: ModalScreen, selector: str) -> None:
    control = modal.query_one(selector)
    frame = modal.query_one(DialogFrame)
    assert control.region.width > 0 and control.region.height > 0
    assert frame.content_region.contains_region(control.region)
    assert modal.region.contains_region(control.region)
    assert app.get_widget_at(*control.region.center)[0] is control
    if isinstance(control, Button):
        assert control.label.plain in _painted(app)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("kind", ["bulk", "picker", "save"])
async def test_utility_prompt_native_focus_and_pinned_action_geometry(
    size: tuple[int, int], kind: str,
) -> None:
    app = DialogHost()
    if kind == "bulk":
        modal, focus = _bulk(), "#bulk_action_cancel"
        selectors = ("#bulk_action_prompt", "#bulk_action_confirm_input",
                     "#bulk_action_status", "#bulk_action_cancel",
                     "#bulk_action_submit")
    elif kind == "picker":
        modal, focus = _picker(), "#picker_search"
        selectors = ("#picker_search", "#picker_cancel")
    else:
        modal, focus = SaveCommandModal("printf hello"), "#save_name_input"
        selectors = ("#save_name_input", "#save_cancel", "#save_submit")
    async with app.run_test(size=size) as pilot:
        await _open(app, pilot, modal, focus, [])
        for selector in selectors:
            _assert_exposed(app, modal, selector)
        if kind == "bulk":
            body = modal.query_one("#bulk_action_body", DialogBody)
            modal.query_one("#bulk_action_description", Static).update(
                "\n".join(
                    f"Review example record detail {index}." for index in range(45)
                )
            )
            await wait_until(lambda: body.max_scroll_y > 0)
            await pilot.pause()
            confirmation = modal.query_one("#bulk_action_confirm_input")
            assert body not in confirmation.ancestors
            assert body.region.bottom <= confirmation.region.y
            before = [modal.query_one(selector).region for selector in selectors]
            initial_scroll = body.scroll_y
            body.focus()
            await pilot.press("end")
            await wait_until(lambda: body.scroll_y > initial_scroll)
            app.notify("Example warning", severity="warning")
            await pilot.pause()
            after = [modal.query_one(selector).region for selector in selectors]
            assert before == after
            for selector in selectors:
                _assert_exposed(app, modal, selector)
        elif kind == "picker":
            listing = modal.query_one("#picker_list", OptionList)
            frame = modal.query_one("#picker_container", DialogFrame)
            body = modal.query_one("#picker_body", DialogContent)
            search = modal.query_one("#picker_search", Input)
            assert list(modal.query(DialogFrame)) == [frame]
            assert list(frame.query(DialogContent)) == [body]
            assert body.parent is frame
            assert list(body.children) == [search, listing]
            assert listing.parent is body
            assert body.content_region.contains_region(search.region)
            assert body.content_region.contains_region(listing.region)
            assert not modal.query(DialogBody)


@pytest.mark.asyncio
@pytest.mark.parametrize("phrase,enabled", [
    ("DELETE", True), ("DELETE ", False), (" DELETE", False), ("delete", False),
])
async def test_bulk_phrase_match_is_exact_and_input_enter_never_submits(
    phrase: str, enabled: bool,
) -> None:
    app, modal, results = DialogHost(), _bulk(), []
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, modal, "#bulk_action_cancel", results)
        modal.query_one(SelectionList).select("a")
        field = modal.query_one("#bulk_action_confirm_input", Input)
        await _tab_to(pilot, field)
        await pilot.press(*phrase)
        await pilot.pause()
        submit = modal.query_one("#bulk_action_submit", Button)
        assert submit.disabled is not enabled
        await pilot.press("enter")
        await pilot.pause()
        assert app.screen is modal and results == []


@pytest.mark.asyncio
async def test_bulk_native_selection_returns_choice_order_on_explicit_click() -> None:
    app, modal, results = DialogHost(), _bulk(), []
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, modal, "#bulk_action_cancel", results)
        listing = modal.query_one(SelectionList)
        await _tab_to(pilot, listing)
        listing.highlighted = 1
        await pilot.press("space", "up", "space")
        assert set(listing.selected) == {"a", "b"}
        await _tab_to(pilot, modal.query_one("#bulk_action_confirm_input"))
        await pilot.press(*"DELETE")
        await _click(pilot, "#bulk_action_submit")
        await wait_until(lambda: bool(results))
        assert results == [["a", "b"]]


@pytest.mark.asyncio
async def test_bulk_acknowledgement_phrase_and_intersection_reset_stay_exact() -> None:
    app, modal = DialogHost(), _bulk(ack=True)
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, modal, "#bulk_action_cancel", [])
        listing = modal.query_one(SelectionList)
        listing.select("a")
        await pilot.pause()
        ack = modal.query_one("#bulk_action_acknowledge", Checkbox)
        assert ack.disabled and not ack.value
        listing.select("c")
        await pilot.pause()
        ack.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        assert await pilot.click(ack)
        await pilot.pause()
        field = modal.query_one("#bulk_action_confirm_input", Input)
        assert modal.acknowledged and field.placeholder == "DELETE UNCHECKED"
        field.value = "DELETE UNCHECKED "
        await pilot.pause()
        assert modal.query_one("#bulk_action_submit", Button).disabled
        field.value = "DELETE UNCHECKED"
        await pilot.pause()
        assert not modal.query_one("#bulk_action_submit", Button).disabled
        listing.deselect("c")
        await pilot.pause()
        assert ack.disabled and not ack.value and not modal.acknowledged
        assert field.placeholder == "DELETE"
        assert modal.query_one("#bulk_action_submit", Button).disabled


@pytest.mark.asyncio
async def test_bulk_native_all_none_updates_count_and_disabled_submit() -> None:
    app, modal = DialogHost(), _bulk()
    async with app.run_test(size=(160, 50)) as pilot:
        await _open(app, pilot, modal, "#bulk_action_cancel", [])
        await _click(pilot, "#bulk_action_all")
        assert set(modal.query_one(SelectionList).selected) == {"a", "b", "c"}
        submit = modal.query_one("#bulk_action_submit", Button)
        assert submit.label.plain == "Delete (3)"
        await _click(pilot, "#bulk_action_none")
        assert modal.query_one(SelectionList).selected == []
        assert modal.query_one("#bulk_action_submit", Button).disabled


@pytest.mark.asyncio
async def test_bulk_without_phrase_still_requires_a_selection() -> None:
    app, modal = DialogHost(), _bulk(phrase=None)
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, modal, "#bulk_action_cancel", [])
        assert not modal.query("#bulk_action_confirm_input")
        assert modal.query_one("#bulk_action_submit", Button).disabled
        modal.query_one(SelectionList).select("a")
        await pilot.pause()
        assert not modal.query_one("#bulk_action_submit", Button).disabled


@pytest.mark.asyncio
@pytest.mark.parametrize("builder", [False, True])
async def test_bulk_demo_redraw_keeps_selection_highlight_and_literal_labels(
    builder: bool,
) -> None:
    app = DialogHost()
    app.demo_mode = False
    app.redaction_service = SimpleNamespace(redact_name=lambda value: "Demo record")
    modal = BulkActionModal(
        "Review [literal]", "Initial description", [("a", "Alpha"), ("b", "Beta")],
        action_label="Remove", confirm_text=None,
        label_builder=(lambda key: "Safe [literal] " + key) if builder else None,
        description_builder=lambda: "Current [literal] description",
    )
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, modal, "#bulk_action_cancel", [])
        listing = modal.query_one(SelectionList)
        listing.select("b")
        listing.highlighted = 1
        app.demo_mode = True
        modal.refresh_after_demo_toggle()
        await pilot.pause()
        assert set(listing.selected) == {"b"} and listing.highlighted == 1
        assert ("Safe [literal]" if builder else "Demo record") in _painted(app)
        assert "Current [literal] description" in _painted(app)


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["enter", "escape"])
async def test_bulk_default_cancel_focus_returns_none_without_selection(
    key: str,
) -> None:
    app, modal, results = DialogHost(), _bulk(), []
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, modal, "#bulk_action_cancel", results)
        await pilot.press(key)
        await wait_until(lambda: bool(results))
        assert results == [None]


async def _click_raw_option(app: DialogHost, pilot: Pilot, listing: OptionList) -> None:
    rows = app.screen._compositor.render_strips()
    row = next(y for y in range(listing.content_region.y, listing.content_region.bottom)
               if "printf" in rows[y].crop(listing.region.x, listing.region.right).text)
    offset = (listing.content_region.x - listing.region.x + 2, row - listing.region.y)
    assert await pilot.click(listing, offset=offset)
    await pilot.pause()


@pytest.mark.asyncio
@pytest.mark.parametrize("submit", ["enter", "pointer"])
async def test_picker_returns_raw_command_through_native_input_or_option_click(
    submit: str,
) -> None:
    app, modal, results = DialogHost(), _picker(), []
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, modal, "#picker_search", results)
        if submit == "enter":
            await pilot.press("enter")
        else:
            await _click_raw_option(app, pilot, modal.query_one(OptionList))
        await wait_until(lambda: bool(results))
        assert results == [RAW_COMMAND]


@pytest.mark.asyncio
async def test_picker_saved_first_deduplication_and_recent_keyboard_mapping() -> None:
    app, modal, results = DialogHost(), _picker(), []
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, modal, "#picker_search", results)
        listing = modal.query_one(OptionList)
        selectable = [listing.get_option_at_index(index)
                      for index in range(listing.option_count)
                      if not listing.get_option_at_index(index).disabled]
        assert len(selectable) == 3
        await _tab_to(pilot, listing)
        await pilot.press("end", "enter")
        await wait_until(lambda: bool(results))
        assert results == ["pwd"]


@pytest.mark.asyncio
async def test_picker_debounce_stops_old_timer_and_uses_latest_query() -> None:
    app, modal = DialogHost(), _picker()
    async with app.run_test(size=(100, 30)) as pilot:
        field = await _open(app, pilot, modal, "#picker_search", [])
        with patch.object(modal, "set_timer", wraps=modal.set_timer) as timer:
            field.value = "up"
            await wait_until(lambda: timer.called)
            first = modal._debounce_timer
            with patch.object(first, "stop", wraps=first.stop) as stop:
                field.value = "pwd"
                await wait_until(lambda: stop.called)
            await wait_until(lambda: list(modal._option_map.values()) == ["pwd"])
        assert all(call.args[0] == _DEBOUNCE_SECONDS for call in timer.call_args_list)
        assert modal._debounce_timer is not first


@pytest.mark.asyncio
@pytest.mark.parametrize("empty", [False, True])
async def test_picker_empty_and_no_match_options_cannot_be_selected(
    empty: bool,
) -> None:
    app = DialogHost()
    modal = CommandPickerModal([], []) if empty else _picker()
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        field = await _open(app, pilot, modal, "#picker_search", results)
        if not empty:
            field.value = "no-such-command"
            await wait_until(lambda: modal._option_map == {})
        listing = modal.query_one(OptionList)
        assert listing.option_count == 1 and listing.get_option_at_index(0).disabled
        await pilot.press("enter")
        await pilot.pause()
        assert app.screen is modal and results == []


@pytest.mark.asyncio
async def test_picker_native_scroll_keeps_search_and_cancel_pinned() -> None:
    app = DialogHost()
    commands = [f"example command {i}" for i in range(100)]
    modal = CommandPickerModal([], commands)
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        field = await _open(app, pilot, modal, "#picker_search", results)
        listing = modal.query_one(OptionList)
        frame = modal.query_one("#picker_container", DialogFrame)
        body = modal.query_one("#picker_body", DialogContent)
        search = modal.query_one("#picker_search", Input)
        assert list(modal.query(DialogFrame)) == [frame]
        assert list(frame.query(DialogContent)) == [body]
        assert body.parent is frame
        assert list(body.children) == [search, listing]
        assert listing.parent is body
        assert body.content_region.contains_region(search.region)
        assert body.content_region.contains_region(listing.region)
        assert not modal.query(DialogBody)
        await wait_until(lambda: listing.max_scroll_y > 0)
        search_region = field.region
        cancel_region = modal.query_one("#picker_cancel").region
        initial_scroll = listing.scroll_y
        await _tab_to(pilot, listing)
        await pilot.press("end")
        await wait_until(lambda: listing.scroll_y > initial_scroll)
        await pilot.pause()
        assert listing.highlighted == listing.option_count - 1
        assert field.region == search_region
        assert modal.query_one("#picker_cancel").region == cancel_region
        _assert_exposed(app, modal, "#picker_search")
        _assert_exposed(app, modal, "#picker_cancel")
        viewport = listing.content_region
        frame = modal.query_one(DialogFrame)
        assert frame.content_region.contains_region(listing.region)
        assert modal.region.contains_region(viewport)
        rows = app.screen._compositor.render_strips()
        row = next(
            y for y in range(viewport.y, viewport.bottom)
            if commands[-1] in rows[y].crop(viewport.x, viewport.right).text
        )
        point = (viewport.x + 2, row)
        assert app.get_widget_at(*point)[0] is listing
        assert await pilot.click(listing, offset=(
            point[0] - listing.region.x, point[1] - listing.region.y,
        ))
        await wait_until(lambda: bool(results))
        assert results == [commands[-1]]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["picker", "save"])
@pytest.mark.parametrize("cancel", ["escape", "pointer"])
async def test_prompt_cancel_delivers_none_to_its_waiting_callback(
    kind: str, cancel: str,
) -> None:
    # Exercise the real result callback; closing the widget alone is insufficient.
    app, results = DialogHost(), []
    modal = _picker() if kind == "picker" else SaveCommandModal("printf hello")
    focus = "#picker_search" if kind == "picker" else "#save_name_input"
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, modal, focus, results)
        if cancel == "escape":
            await pilot.press("escape")
        else:
            selector = "#picker_cancel" if kind == "picker" else "#save_cancel"
            await _click(pilot, selector)
        await wait_until(lambda: app.screen is not modal)
        assert results == [None]


@pytest.mark.asyncio
@pytest.mark.parametrize("submit", ["enter", "pointer"])
async def test_save_name_enter_and_pointer_return_same_trimmed_name_once(
    submit: str,
) -> None:
    app, modal, results = DialogHost(), SaveCommandModal("printf hello"), []
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, modal, "#save_name_input", results)
        await pilot.press(*"  Useful name Ω  ")
        if submit == "enter":
            await pilot.press("enter")
        else:
            await _click(pilot, "#save_submit")
        await wait_until(lambda: bool(results))
        assert results == ["Useful name Ω"]


@pytest.mark.asyncio
@pytest.mark.parametrize("submit", ["enter", "pointer"])
async def test_save_empty_name_warning_is_identical_without_result(submit: str) -> None:
    app, modal, results = DialogHost(), SaveCommandModal("printf hello"), []
    async with app.run_test(size=(100, 30)) as pilot:
        field = await _open(app, pilot, modal, "#save_name_input", results)
        field.value = "   "
        with patch.object(app, "notify", wraps=app.notify) as notify:
            if submit == "enter":
                await pilot.press("enter")
            else:
                await _click(pilot, "#save_submit")
            await wait_until(lambda: notify.called)
        assert notify.call_args.args == ("Name cannot be empty",)
        assert notify.call_args.kwargs["severity"] == "warning"
        assert app.screen is modal and results == []
        _assert_exposed(app, modal, "#save_submit")


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["picker", "save"])
@pytest.mark.parametrize("command", [
    "sed 's/[a-z]//'", 'echo "[/x]"', "printf '[red]literal[/red]'",
])
async def test_user_command_and_saved_name_are_painted_literally(
    kind: str, command: str,
) -> None:
    app = DialogHost()
    modal = (
        CommandPickerModal([{"name": "[bold]Example[/bold]", "command": command}], [])
        if kind == "picker" else SaveCommandModal(command)
    )
    focus = "#picker_search" if kind == "picker" else "#save_name_input"
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, modal, focus, [])
        painted = " ".join(_painted(app).split())
        assert command in painted
        if kind == "picker":
            assert "[bold]Example[/bold]" in painted


class _PickerCaller(ModalScreen):
    """Run the actual picker callback with no SSH console/service startup."""

    BINDINGS = [Binding("ctrl+r", "show_command_picker", "Picker")]
    action_show_command_picker = CommandOverlay.action_show_command_picker

    def compose(self) -> ComposeResult:
        yield Input(value="original", id="command_input")

    def on_mount(self) -> None:
        self.query_one(Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.app.execute_command(event.value)


@pytest.mark.asyncio
async def test_actual_picker_caller_only_fills_raw_input_cursor_and_focus() -> None:
    app = DialogHost()
    app.command_history = SimpleNamespace(
        get_saved_commands=lambda: [{"name": "Example", "command": RAW_COMMAND}],
        get_global_history=lambda: [],
    )
    app.execute_command = Mock(side_effect=AssertionError("Picker executed a command"))
    caller = _PickerCaller()
    async with app.run_test(size=(100, 30)) as pilot:
        await app.push_screen(caller)
        await wait_until(lambda: app.focused is caller.query_one(Input))
        await pilot.press("ctrl+r")
        await wait_until(lambda: isinstance(app.screen, CommandPickerModal))
        await wait_until(lambda: app.focused is app.screen.query_one("#picker_search"))
        await pilot.press("enter")
        await wait_until(lambda: app.screen is caller)
        field = caller.query_one("#command_input", Input)
        assert field.value == RAW_COMMAND and field.cursor_position == len(RAW_COMMAND)
        assert app.focused is field
        app.execute_command.assert_not_called()
