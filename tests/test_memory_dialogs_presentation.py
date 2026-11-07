"""Memory dialogs preserve explicit decisions without performing operations."""

from __future__ import annotations

from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from textual import constants
from textual.app import ComposeResult
from textual.binding import Binding
from textual.pilot import Pilot
from textual.screen import ModalScreen
from textual.widget import Widget
from textual.theme import BUILTIN_THEMES
from textual.widgets import Button, Input, SelectionList, Static, Switch

from servonaut.screens.memory_consent_modal import MemoryInjectionConsentModal
from servonaut.app import ServonautApp
from servonaut.screens.memory_keys import PassphraseEnrolModal, PassphraseResult
from servonaut.screens.team_share_confirm import ShareServersConfirmModal
from servonaut.services.memory import passphrase_store
from servonaut.widgets.dialogs import DialogActions, DialogBody, DialogFrame, DialogNotificationSpace
from servonaut.styles.themes import SERVONAUT_THEMES
from tests._async_bounds import wait_until
from tests.test_basic_dialogs import BasicDialogHost
from tests.test_navigation_dialog_contrast import _contrast, _paint_colours


SIZES = [(160, 50), (100, 30)]
# Native original consent keeps scroll focus and Enter makes no decision.
ORIGINAL_CONSENT_ENTRY: dict[tuple[int, int], tuple[str | None, tuple[object, ...]]] | None = {
    (160, 50): ("consent_body", ()),
    (100, 30): ("consent_body", ()),
}
BLURB_THEMES = tuple(sorted(set(BUILTIN_THEMES) | {theme.name for theme in SERVONAUT_THEMES}))
# Synthetic local input, used only to exercise the strength/matching UI.
PHRASE = "Q7!mR4@vT9#kL2$zN6%pX8&j"
SERVERS = [
    {"id": "example-1", "name": "web-1", "public_ip": "192.0.2.10", "username": "deploy", "port": 22, "region": "local"},
    {"id": "example-2", "name": "db-1", "public_ip": "192.0.2.11", "username": "ubuntu", "port": 2222, "region": "local"},
]


def _colour_fixture(monkeypatch) -> None:
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLORTERM", "truecolor")
    monkeypatch.setenv("TERM", "xterm-256color")
    assert not constants.FILTERS, "Clear TEXTUAL_FILTERS before process import"
    assert constants.COLOR_SYSTEM in {"auto", "truecolor"}, "Clear TEXTUAL_COLOR_SYSTEM before process import"


def _assert_colour_mode(app) -> None:
    assert not app.no_color
    assert not constants.FILTERS
    assert app.console.color_system == "truecolor"


def _active_palette(app):
    return app.ansi_theme_dark if app.current_theme.dark else app.ansi_theme_light


class _Redactor:
    def redact_name(self, value: str) -> str:
        return "demo-server"

    def redact_host(self, value: str) -> str:
        return "192.0.2.99"

    def redact_username(self, value: str) -> str:
        return "demo-user"

    def scrub_stream(self, value: str) -> str:
        return value


class _Host(BasicDialogHost):
    def __init__(self) -> None:
        super().__init__()
        self._textual_ansi_themes = (self.ansi_theme_dark, self.ansi_theme_light)
        self.watch_theme(self.theme)
        forbidden = AssertionError("The modal must return a decision without performing operations")
        self.config_manager = SimpleNamespace(update=Mock(side_effect=forbidden), save=Mock(side_effect=forbidden))
        self.team_service = SimpleNamespace(push_server=AsyncMock(side_effect=forbidden))
        self.memory_service = SimpleNamespace()
        self.demo_mode = False
        self.redaction_service = _Redactor()
        self.notes: list[str] = []

    def watch_theme(self, theme: str) -> None:
        if hasattr(self, "_textual_ansi_themes"):
            ServonautApp._match_ansi_palette(self, theme)

    def notify(self, message: str, **kwargs) -> None:
        self.notes.append(str(message))
        super().notify(message, **kwargs)

    def assert_no_operations(self) -> None:
        self.config_manager.update.assert_not_called()
        self.config_manager.save.assert_not_called()
        self.team_service.push_server.assert_not_called()


@pytest.fixture(autouse=True)
def local_only_keychain(monkeypatch):
    monkeypatch.setattr(passphrase_store, "keyring_available", lambda: False)
    for name in ("get_passphrase", "store_passphrase", "clear_passphrase"):
        monkeypatch.setattr(passphrase_store, name, Mock(side_effect=AssertionError("Modal accessed passphrase storage")))
    yield
    for name in ("get_passphrase", "store_passphrase", "clear_passphrase"):
        getattr(passphrase_store, name).assert_not_called()


def _dialog(kind: str) -> ModalScreen:
    if kind in {"enrol", "unlock"}:
        return PassphraseEnrolModal(mode=kind)
    if kind == "share":
        return ShareServersConfirmModal("Example team", SERVERS)
    return MemoryInjectionConsentModal()


async def _show(app: _Host, pilot: Pilot, screen: ModalScreen) -> list:
    origin = app.screen.query_one("#origin", Input)
    origin.focus()
    results = []
    app.push_screen(screen, results.append)
    await wait_until(lambda: app.screen is screen and screen.is_mounted)
    await pilot.pause()
    return results


def _exposed(app: _Host, widget: Widget) -> bool:
    frame = app.screen.query_one(DialogFrame)
    if not (widget.region.width > 0 and widget.region.height > 0
            and frame.content_region.contains_region(widget.region)
            and app.screen.region.contains_region(widget.region)):
        return False
    for row in range(widget.region.y, widget.region.bottom):
        hit, _ = app.get_widget_at(widget.region.x + widget.region.width // 2, row)
        if hit is not widget and widget not in hit.ancestors:
            return False
    if isinstance(widget, Button) and widget.label.plain not in _painted_widget(app.screen, widget):
        return False
    return True


def _painted_widget(screen: ModalScreen, widget: Widget) -> str:
    region = widget.region.intersection(screen.region)
    rows = screen._compositor.render_strips()
    return "\n".join(rows[y].crop(region.x, region.right).text for y in range(region.y, region.bottom))


def _assert_controls(app: _Host, screen: ModalScreen, *, include_body: bool = True) -> dict[str, object]:
    """Check controls together, without scrolling or focusing each target."""
    widgets = list(screen.query_one(".dialog-footer").query(Button))
    if not include_body:
        for widget in widgets:
            assert _exposed(app, widget)
        return {widget.id: widget.region for widget in widgets}
    displayed = lambda widget: widget.display and all(ancestor.display for ancestor in widget.ancestors if isinstance(ancestor, Widget))
    widgets.extend(widget for widget in screen.query(Input) if displayed(widget))
    widgets.extend(widget for widget in screen.query(".secret-reveal") if displayed(widget))
    for selector in ("#enrol-strength", "#enrol-mismatch", "#enrol-remember-row"):
        for widget in screen.query(selector):
            if displayed(widget):
                # Remember's row includes intended gaps: assert its actual controls.
                targets = list(widget.query(Switch)) if selector.endswith("row") else [widget]
                widgets.extend(targets)
    for widget in widgets:
        assert _exposed(app, widget), f"Control not completely painted/hittable: {widget.id}"
        if isinstance(widget, Static) and widget.render().plain:
            assert " ".join(widget.render().plain.split()) in " ".join(_painted_widget(screen, widget).split())
    return {widget.id: widget.region for widget in widgets}


async def _visit_form_controls(app: _Host, pilot: Pilot, screen: ModalScreen) -> None:
    """Reach capped body fields natively while decisions remain pinned."""
    body = screen.query_one(DialogBody)
    footer = _assert_controls(app, screen, include_body=False)
    initial_focus = app.focused
    displayed = lambda widget: widget.display and all(parent.display for parent in widget.ancestors if isinstance(parent, Widget))
    for widget in screen.query("Input, Switch"):
        if not displayed(widget):
            continue
        await _tab_to(app, pilot, widget)
        await pilot.pause()
        assert _exposed(app, widget)
        if isinstance(widget, Input) and widget.parent is not None:
            for reveal in widget.parent.query(".secret-reveal"):
                assert _exposed(app, reveal)
        assert _assert_controls(app, screen, include_body=False) == footer
    for selector in ("#enrol-strength", "#enrol-mismatch"):
        for widget in screen.query(selector):
            if not displayed(widget):
                continue
            if not _exposed(app, widget):
                assert body.allow_vertical_scroll
                await _tab_to(app, pilot, body)
                await pilot.press("home")
                await pilot.pause()
                for _ in range(int(body.max_scroll_y) + 2):
                    if _exposed(app, widget):
                        break
                    before = body.scroll_y
                    await pilot.press("down")
                    await pilot.pause()
                    assert body.scroll_y > before
            assert _exposed(app, widget)
            assert " ".join(widget.render().plain.split()) in " ".join(_painted_widget(screen, widget).split())
            assert _assert_controls(app, screen, include_body=False) == footer
    if initial_focus is not None and app.focused is not initial_focus:
        await _tab_to(app, pilot, initial_focus)
        await pilot.pause()
    assert app.focused is initial_focus


def _assert_painted_target(app: _Host, container: Widget, text: str, owner: Widget) -> tuple[int, int]:
    """Locate an actual compositor glyph row, then hit-test the whole literal."""
    rows = app.screen._compositor.render_strips()
    region = container.content_region.intersection(app.screen.region)
    for y in range(region.y, region.bottom):
        painted = rows[y].crop(region.x, region.right).text
        start = painted.find(text)
        if start < 0:
            continue
        for x in range(region.x + start, region.x + start + len(text)):
            hit, _ = app.get_widget_at(x, y)
            assert hit is owner or owner in hit.ancestors
        return region.x + start, y
    pytest.fail(f"Native painted endpoint is missing: {text!r}")


async def _click(app: _Host, pilot: Pilot, widget: Widget) -> None:
    if isinstance(widget, Button):
        await wait_until(lambda: not widget.has_class("-active"))
    await pilot.pause()
    await wait_until(lambda: _exposed(app, widget))
    assert await pilot.click(widget)


async def _tab_to(app: _Host, pilot: Pilot, widget: Widget) -> None:
    for _ in range(len(app.screen.focus_chain) + 1):
        if app.focused is widget:
            assert _exposed(app, widget)
            return
        await pilot.press("tab")
    pytest.fail(f"Tab did not reach {widget.id}")


def _text(screen: ModalScreen, selector: str) -> str:
    return screen.query_one(selector, Static).render().plain


def _painted_screen(screen: ModalScreen) -> str:
    return "\n".join(strip.text for strip in screen._compositor.render_strips())


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("kind", ["enrol", "unlock", "share", "consent"])
async def test_escape_returns_none_once_without_side_effects_and_restores_focus(size, kind) -> None:
    app = _Host()
    screen = _dialog(kind)
    async with app.run_test(size=size) as pilot:
        results = await _show(app, pilot, screen)
        await pilot.press("escape")
        await wait_until(lambda: app.screen is not screen)
        assert results == [None]
        assert app.focused is app.screen.query_one("#origin")
        app.assert_no_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("remember", [False, True])
@pytest.mark.parametrize("submit", ["enter", "click"])
async def test_enrol_weak_mismatch_then_matching_input_returns_only_local_result(
    monkeypatch, size, remember, submit,
) -> None:
    monkeypatch.setattr(passphrase_store, "keyring_available", lambda: remember)
    app = _Host()
    screen = PassphraseEnrolModal(remember_default=True)
    async with app.run_test(size=size) as pilot:
        results = await _show(app, pilot, screen)
        first = screen.query_one("#enrol-pass1", Input)
        second = screen.query_one("#enrol-pass2", Input)
        confirm = screen.query_one("#enrol-btn-confirm", Button)
        assert app.focused is first
        first.value = second.value = "a"
        await pilot.pause()
        assert confirm.disabled
        await pilot.press("enter")
        assert results == [] and app.screen is screen
        first.value, second.value = PHRASE, "different input"
        await pilot.pause()
        assert confirm.disabled and "do not match" in _text(screen, "#enrol-mismatch")
        await _visit_form_controls(app, pilot, screen)
        second.value = PHRASE
        await wait_until(lambda: not confirm.disabled)
        assert "Strong" in _text(screen, "#enrol-strength") or "Very strong" in _text(screen, "#enrol-strength")
        await _visit_form_controls(app, pilot, screen)
        assert first.password and PHRASE not in _painted_screen(screen)
        if submit == "enter":
            await _tab_to(app, pilot, first)
            await pilot.press("enter")
            await pilot.pause()
            assert results == [] and app.screen is screen and app.focused is first
            await _tab_to(app, pilot, confirm)
            await pilot.press("enter")
        else:
            await _click(app, pilot, confirm)
        await wait_until(lambda: app.screen is not screen)
        assert results == [PassphraseResult(PHRASE, remember)]
        app.assert_no_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("remember", [False, True])
async def test_unlock_has_one_secret_field_and_preserves_explicit_remember_choice(
    monkeypatch, size, remember,
) -> None:
    monkeypatch.setattr(passphrase_store, "keyring_available", lambda: remember)
    app = _Host()
    screen = PassphraseEnrolModal(mode="unlock", remember_default=True)
    async with app.run_test(size=size) as pilot:
        results = await _show(app, pilot, screen)
        first = screen.query_one("#enrol-pass1", Input)
        confirm = screen.query_one("#enrol-btn-confirm", Button)
        assert app.focused is first and confirm.disabled
        await _visit_form_controls(app, pilot, screen)
        assert not screen.query_one("#enrol-pass2_field").display
        assert screen.query_one("#enrol-remember-row").display is remember
        await pilot.press("a")
        await wait_until(lambda: not confirm.disabled)
        if remember:
            await _click(app, pilot, screen.query_one("#enrol-remember", Switch))
            assert not screen.query_one("#enrol-remember", Switch).value
        await _click(app, pilot, confirm)
        await wait_until(lambda: app.screen is not screen)
        assert results == [PassphraseResult("a", False)]
        app.assert_no_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("kind", ["enrol", "unlock", "share"])
async def test_pointer_cancel_discards_typed_drafts_without_persisting(size, kind) -> None:
    app = _Host()
    screen = _dialog(kind)
    async with app.run_test(size=size) as pilot:
        results = await _show(app, pilot, screen)
        if kind == "share":
            screen.query_one("#share_confirm_name", Input).value = "Edited example"
            selector = "#share_confirm_cancel"
        else:
            screen.query_one("#enrol-pass1", Input).value = PHRASE
            selector = "#enrol-btn-cancel"
        await _click(app, pilot, screen.query_one(selector, Button))
        await wait_until(lambda: app.screen is not screen)
        assert results == [None]
        assert SERVERS[0]["name"] == "web-1"
        app.assert_no_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("demo", [False, True])
async def test_share_selection_edit_and_demo_redraw_preserve_raw_server_dicts(size, demo) -> None:
    original = deepcopy(SERVERS)
    app = _Host()
    screen = ShareServersConfirmModal("Example team", original, skipped_existing=1, skipped_no_address=2)
    async with app.run_test(size=size) as pilot:
        results = await _show(app, pilot, screen)
        listing = screen.query_one("#share_confirm_list", SelectionList)
        assert app.focused is screen.query_one("#share_confirm_cancel")
        assert set(listing.selected) == {0, 1}
        assert "1 server already shared" in _text(screen, "#share_confirm_skipped")
        await _click(app, pilot, screen.query_one("#share_confirm_none", Button))
        await wait_until(lambda: not listing.selected)
        assert screen.query_one("#share_confirm_share", Button).disabled
        await _click(app, pilot, screen.query_one("#share_confirm_all", Button))
        await wait_until(lambda: set(listing.selected) == {0, 1})
        listing.focus()
        await pilot.press("space")
        await wait_until(lambda: listing.selected == [1])
        await pilot.press("down")
        await pilot.pause()
        screen.query_one("#share_confirm_name", Input).value = "db-edited"
        screen.query_one("#share_confirm_username", Input).value = "operator"
        screen.query_one("#share_confirm_port", Input).value = "2202"
        if demo:
            app.demo_mode = True
            screen.refresh_after_demo_toggle()
            await pilot.pause()
            assert "Example team" not in _text(screen, "#share_confirm_title")
            assert screen.query_one("#share_confirm_name", Input).value == "demo-server"
        await _click(app, pilot, screen.query_one("#share_confirm_share", Button))
        await wait_until(lambda: app.screen is not screen)
        assert results == [[{**SERVERS[1], "name": "db-edited", "username": "operator", "port": 2202}]]
        assert original == SERVERS
        app.assert_no_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("field,value", [("name", ""), ("username", "bad user"), ("port", "70000")])
async def test_share_invalid_draft_stays_open_and_focuses_the_offending_field(size, field, value) -> None:
    app = _Host()
    screen = ShareServersConfirmModal("Example team", SERVERS)
    async with app.run_test(size=size) as pilot:
        results = await _show(app, pilot, screen)
        screen.query_one(f"#share_confirm_{field}", Input).value = value
        await pilot.pause()
        await _click(app, pilot, screen.query_one("#share_confirm_share", Button))
        await wait_until(lambda: app.focused is screen.query_one(f"#share_confirm_{field}"))
        assert results == [] and app.screen is screen
        assert app.notes
        app.assert_no_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_share_empty_inventory_never_enables_share(size) -> None:
    app = _Host()
    screen = ShareServersConfirmModal("Example team", [])
    async with app.run_test(size=size) as pilot:
        results = await _show(app, pilot, screen)
        assert app.focused is screen.query_one("#share_confirm_cancel")
        button = screen.query_one("#share_confirm_share", Button)
        assert button.disabled
        assert _exposed(app, button)
        await _click(app, pilot, screen.query_one("#share_confirm_all", Button))
        assert button.disabled and results == []
        await pilot.press("escape")
        await wait_until(lambda: app.screen is not screen)
        assert results == [None]
        app.assert_no_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_share_initial_enter_uses_existing_cancel_default(size) -> None:
    app = _Host()
    screen = ShareServersConfirmModal("Example team", SERVERS)
    async with app.run_test(size=size) as pilot:
        results = await _show(app, pilot, screen)
        await pilot.press("enter")
        await wait_until(lambda: app.screen is not screen)
        assert results == [None]
        app.assert_no_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("decision", ["allowed", "denied"])
async def test_memory_consent_returns_only_explicit_decision_without_persisting(size, decision) -> None:
    app = _Host()
    screen = MemoryInjectionConsentModal()
    async with app.run_test(size=size) as pilot:
        results = await _show(app, pilot, screen)
        button = screen.query_one("#btn_allow" if decision == "allowed" else "#btn_deny", Button)
        await _tab_to(app, pilot, button)
        if decision == "allowed":
            await pilot.press("enter")
        else:
            await _click(app, pilot, button)
        await wait_until(lambda: app.screen is not screen)
        assert results == [decision]
        app.assert_no_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_consent_details_expand_once_and_scroll_to_the_actual_copy_end(size) -> None:
    app = _Host()
    screen = MemoryInjectionConsentModal()
    async with app.run_test(size=size) as pilot:
        results = await _show(app, pilot, screen)
        details = screen.query_one("#consent_details", Static)
        actions = [screen.query_one(f"#btn_{name}", Button) for name in ("allow", "deny", "details")]
        regions = [button.region for button in actions]
        assert not details.display
        await _click(app, pilot, actions[2])
        assert details.display and details.has_class("shown")
        original_copy = details.render().plain
        assert "Example payload" in original_copy
        assert "services/memory/redaction.py" in original_copy
        await _click(app, pilot, actions[2])
        assert details.display and details.render().plain == original_copy
        body = screen.query_one(DialogBody)
        await _tab_to(app, pilot, body)
        await pilot.press("home")
        await pilot.pause()
        start, maximum = body.scroll_y, body.max_scroll_y
        assert start == 0 and maximum > 0
        await pilot.press("end")
        await pilot.pause()
        assert body.scroll_y > start and body.scroll_y == maximum
        final_line = original_copy.splitlines()[-1]
        region = details.content_region.intersection(body.scrollable_content_region).intersection(screen.region)
        rows = screen._compositor.render_strips()
        visible_details = "\n".join(rows[y].crop(region.x, region.right).text for y in range(region.y, region.bottom))
        assert " ".join(final_line.split()) in " ".join(visible_details.split())
        _assert_painted_target(app, body, "services/memory/redaction.py).", details)
        assert [button.region for button in actions] == regions
        assert all(_exposed(app, button) for button in actions)
        assert results == []
        app.assert_no_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_long_share_list_scrolls_without_moving_confirm_or_losing_selection(size) -> None:
    servers = [{**SERVERS[0], "id": f"example-{index}", "name": f"server-{index}"} for index in range(45)]
    app = _Host()
    screen = ShareServersConfirmModal("Example team", servers)
    async with app.run_test(size=size) as pilot:
        results = await _show(app, pilot, screen)
        actions = [screen.query_one(f"#share_confirm_{name}", Button) for name in ("cancel", "share")]
        regions = [button.region for button in actions]
        listing = screen.query_one("#share_confirm_list", SelectionList)
        await _tab_to(app, pilot, listing)
        await pilot.press("home")
        await pilot.pause()
        start, maximum = listing.scroll_y, listing.max_scroll_y
        assert start == 0 and maximum > 0
        await pilot.press("end")
        await wait_until(lambda: listing.highlighted == 44)
        await pilot.pause()
        assert listing.scroll_y > start and listing.scroll_y == maximum
        _assert_painted_target(app, listing, "server-44", listing)
        assert set(listing.selected) == set(range(45))
        await _tab_to(app, pilot, screen.query_one("#share_confirm_port", Input))
        assert [button.region for button in actions] == regions
        assert all(_exposed(app, button) for button in actions)
        assert results == []
        app.assert_no_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("kind", ["enrol", "share", "consent"])
async def test_native_toasts_never_move_or_cover_modal_decision_targets(size, kind) -> None:
    app = _Host()
    screen = _dialog(kind)
    targets = {
        "enrol": ["#enrol-btn-cancel", "#enrol-btn-confirm"],
        "share": ["#share_confirm_cancel", "#share_confirm_share"],
        "consent": ["#btn_allow", "#btn_deny", "#btn_details"],
    }[kind]
    async with app.run_test(size=size, notifications=True) as pilot:
        results = await _show(app, pilot, screen)
        buttons = [screen.query_one(selector, Button) for selector in targets]
        regions = [button.region for button in buttons]
        await _visit_form_controls(app, pilot, screen)
        controls = _assert_controls(app, screen, include_body=False)
        body = screen.query_one(DialogBody)
        scroll = body.scroll_offset
        origin = app.focused
        app.notify("Fabricated validation notice", severity="warning", timeout=1)
        await wait_until(lambda: bool(screen.query("Toast")))
        await pilot.pause()
        assert [button.region for button in buttons] == regions
        assert all(_exposed(app, button) for button in buttons)
        assert app.focused is origin and results == []
        assert _assert_controls(app, screen, include_body=False) == controls
        assert body.scroll_offset == scroll
        await wait_until(lambda: not screen.query("Toast"))
        assert [button.region for button in buttons] == regions
        assert all(_exposed(app, button) for button in buttons)
        assert _assert_controls(app, screen, include_body=False) == controls
        assert body.scroll_offset == scroll
        await _visit_form_controls(app, pilot, screen)
        app.assert_no_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light", "ansi-dark", "ansi-light"])
@pytest.mark.parametrize("kind", ["share", "consent"])
async def test_informational_copy_paints_the_existing_muted_role(theme, kind) -> None:
    app = _Host()
    app.theme = theme
    screen = ShareServersConfirmModal("Example team", SERVERS, skipped_existing=1) if kind == "share" else MemoryInjectionConsentModal()
    async with app.run_test(size=(100, 30)) as pilot:
        await _show(app, pilot, screen)
        selector = "#share_confirm_skipped" if kind == "share" else "#consent_details"
        if kind == "consent":
            await _click(app, pilot, screen.query_one("#btn_details", Button))
        copy = screen.query_one(selector, Static)
        copy.scroll_visible(animate=False)
        await pilot.pause()
        body = screen.query_one(DialogBody)
        before = copy.render().plain
        point = _assert_painted_target(app, copy, before.split()[0], copy)
        assert body.scrollable_content_region.contains(*point)
        actual = screen._compositor.get_style_at(*point).color
        copy.set_styles(f"color: {app.get_css_variables()['text-muted']};")
        await pilot.pause()
        expected = screen._compositor.get_style_at(*point).color
        assert copy.render().plain == before
        assert actual == expected
        app.assert_no_operations()


class _FrameReference(ModalScreen):
    """The same accepted neutral standard frame without consumer-specific IDs."""

    DEFAULT_CLASSES = "dialog-screen"
    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static("Reference"),
            body=DialogBody(Static("Reference")),
            actions=DialogActions(Button("Cancel")),
            size="standard",
            severity="neutral",
        )

    def action_cancel(self) -> None:
        self.dismiss(None)


def _frame_policy(frame: DialogFrame) -> tuple:
    """Compare resolved native geometry and chrome, without restyling a probe."""
    parent = frame.parent
    styles = frame.styles
    assert parent is not None and styles.max_height is not None
    cap = styles.max_height.resolve(parent.content_region.size, frame.app.size)
    return (
        frame.region.width, cap, styles.height, tuple(styles.padding),
        styles.border_top, styles.border_right, styles.border_bottom, styles.border_left,
        styles.overflow_x, styles.overflow_y,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("kind", ["enrol", "unlock"])
async def test_passphrase_frame_matches_the_native_neutral_standard_reference(size, kind) -> None:
    app = _Host()
    async with app.run_test(size=size) as pilot:
        reference = _FrameReference()
        reference_results = await _show(app, pilot, reference)
        expected = _frame_policy(reference.query_one(DialogFrame))
        await pilot.press("escape")
        await wait_until(lambda: app.screen is not reference)
        assert reference_results == [None]
        screen = _dialog(kind)
        results = await _show(app, pilot, screen)
        assert _frame_policy(screen.query_one(DialogFrame)) == expected
        await _visit_form_controls(app, pilot, screen)
        assert results == []
        app.assert_no_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
async def test_consent_original_initial_focus_is_preserved_and_enter_never_decides(size) -> None:
    assert ORIGINAL_CONSENT_ENTRY is not None, "Record source-bound original focus and initial Enter before claiming consent preservation"
    original_focus, original_results = ORIGINAL_CONSENT_ENTRY[size]
    assert original_results == (), "An unsafe original decision needs an explicit correction, never acceptance"
    app = _Host()
    screen = MemoryInjectionConsentModal()
    async with app.run_test(size=size) as pilot:
        results = await _show(app, pilot, screen)
        # No Tab, pointer or direct focus: this is the native initial state.
        focused = screen.focused
        initial_focus = focused.id if focused is not None else None
        await pilot.press("enter")
        await pilot.pause()
        assert results == [] and app.screen is screen
        assert initial_focus == original_focus
        assert app.focused is focused
        app.assert_no_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", BLURB_THEMES)
@pytest.mark.parametrize("mode", ["enrol", "unlock"])
async def test_passphrase_blurb_all_glyphs_are_readable(theme, mode, record_property, monkeypatch) -> None:
    """Measure all visible disclosure runs, including inherited inline dim."""
    from rich.cells import cell_len
    from rich.style import Style

    _colour_fixture(monkeypatch)
    app = _Host()
    assert set(BLURB_THEMES) == set(app.available_themes)
    app.theme = theme
    screen = PassphraseEnrolModal(mode=mode)
    async with app.run_test(size=(160, 50)) as pilot:
        _assert_colour_mode(app)
        results = await _show(app, pilot, screen)
        body = screen.query_one(DialogBody)
        if body.allow_vertical_scroll:
            await _tab_to(app, pilot, body)
            await pilot.press("home")
            await pilot.pause()
        blurb = screen.query_one("#enrol-blurb", Static)
        region = blurb.content_region.intersection(body.scrollable_content_region).intersection(screen.region)
        assert region == blurb.content_region, "Whole disclosure must be visible for its glyph measurement"
        rows = screen._compositor.render_strips()
        painted = "\n".join(rows[y].crop(region.x, region.right).text for y in range(region.y, region.bottom))
        assert " ".join(blurb.render().plain.split()) in " ".join(painted.split())
        expected = (
            "Warning: this passphrase cannot be recovered. If lost, your synced memory data will be permanently inaccessible."
            if mode == "enrol" else "Enter your passphrase to decrypt the stored keypair."
        )
        assert blurb.render().plain == expected
        palette = _active_palette(app)
        runs = []
        for y in range(region.y, region.bottom):
            x = region.x
            for segment in rows[y].crop(region.x, region.right):
                style = segment.style or Style()
                for glyph in segment.text:
                    if glyph.strip():
                        hit, _ = app.get_widget_at(x, y)
                        assert hit is blurb or blurb in hit.ancestors
                    x += cell_len(glyph)
                if segment.text.strip():
                    foreground, background = _paint_colours(style, palette)
                    runs.append({"text": segment.text, "style": str(style), "dim": bool(style.dim), "bold": bool(style.bold),
                                 "foreground": list(foreground), "background": list(background),
                                 "contrast": _contrast(foreground, background)})
        assert runs
        record_property("blurb_glyph_runs", json.dumps({"mode": mode, "theme": theme,
                        "dark": app.current_theme.dark, "registry_count": len(BLURB_THEMES),
                        "colour_system": app.console.color_system, "no_color": app.no_color, "filters": constants.FILTERS,
                        "palette_default_foreground": list(palette.foreground_color), "palette_default_background": list(palette.background_color),
                        "literal": blurb.render().plain, "runs": runs}))
        assert results == []
        app.assert_no_operations()
        if mode == "enrol":
            assert all(run["bold"] for run in runs)
        assert min(run["contrast"] for run in runs) >= 4.5, runs


def _list_literal_styles(app: _Host, listing: SelectionList, literal: str) -> list:
    from rich.style import Style

    region = listing.scrollable_content_region.intersection(app.screen.region)
    for y in range(region.y, region.bottom):
        strip = app.screen._compositor.render_strips()[y].crop(region.x, region.right)
        start = strip.text.find(literal)
        if start < 0:
            continue
        styles, offset = [], 0
        for segment in strip:
            end = offset + len(segment.text)
            overlap = max(0, min(end, start + len(literal)) - max(offset, start))
            styles.extend([segment.style or Style()] * overlap)
            offset = end
        assert len(styles) == len(literal)
        for x in range(region.x + start, region.x + start + len(literal)):
            hit, _ = app.get_widget_at(x, y)
            assert hit is listing or listing in hit.ancestors
        return styles
    pytest.fail(f"Complete list literal is not painted/hittable: {literal!r}")


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", BLURB_THEMES)
async def test_share_highlight_links_native_editor_and_keeps_address_readable(theme, record_property, monkeypatch) -> None:
    _colour_fixture(monkeypatch)
    app = _Host()
    app.theme = theme
    source = deepcopy(SERVERS)
    screen = ShareServersConfirmModal("Example team", source)
    async with app.run_test(size=(160, 50)) as pilot:
        _assert_colour_mode(app)
        results = await _show(app, pilot, screen)
        listing = screen.query_one(SelectionList)
        selected = tuple(listing.selected)
        await _tab_to(app, pilot, listing)
        await pilot.press("home", "down")
        await wait_until(lambda: listing.highlighted == 1 and screen.query_one("#share_confirm_name", Input).value == "db-1")
        drafts = tuple(screen.query_one("#share_confirm_" + name, Input).value for name in ("name", "username", "port"))
        palette = _active_palette(app)
        observations = []
        for focused in (True, False):
            if not focused:
                await _tab_to(app, pilot, screen.query_one("#share_confirm_name", Input))
            await pilot.pause()
            assert listing.has_focus is focused and listing.highlighted == 1
            highlighted = _list_literal_styles(app, listing, "db-1")
            adjacent = _list_literal_styles(app, listing, "web-1")
            address = _list_literal_styles(app, listing, "192.0.2.11")
            signature = lambda style: (_paint_colours(style, palette), bool(style.bold), bool(style.underline), bool(style.reverse))
            distinct = {signature(style) for style in highlighted}.isdisjoint({signature(style) for style in adjacent})
            ratios = [_contrast(*_paint_colours(style, palette)) for style in address]
            observations.append({"focused": focused, "target_distinct": distinct, "address_minimum_contrast": min(ratios),
                                 "highlighted_styles": [str(style) for style in highlighted],
                                 "adjacent_styles": [str(style) for style in adjacent], "address_styles": [str(style) for style in address]})
            assert tuple(listing.selected) == selected
            assert tuple(screen.query_one("#share_confirm_" + name, Input).value for name in ("name", "username", "port")) == drafts
            assert results == [] and source == SERVERS
        record_property("share_target_runs", json.dumps({"theme": theme, "dark": app.current_theme.dark,
                        "colour_system": app.console.color_system, "no_color": app.no_color, "filters": constants.FILTERS,
                        "palette_default_foreground": list(palette.foreground_color), "palette_default_background": list(palette.background_color),
                        "observations": observations}))
        await pilot.press("escape")
        await wait_until(lambda: app.screen is not screen)
        assert results == [None]
        app.assert_no_operations()
        assert all(row["target_distinct"] for row in observations), observations
        assert min(row["address_minimum_contrast"] for row in observations) >= 4.5, observations


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", BLURB_THEMES)
async def test_passphrase_feedback_visible_glyph_contrast(theme, record_property, monkeypatch) -> None:
    # Paint phases must not depend on an optional estimator installation.
    scores = {"": 0, "Abcd12!localx": 2, PHRASE: 4}
    score_calls = []

    def estimate_score(phrase):
        score_calls.append(phrase)
        return scores.get(phrase, 0)

    monkeypatch.setattr("servonaut.services.memory.crypto.estimate_pw_score", estimate_score)
    _colour_fixture(monkeypatch)
    app = _Host()
    app.theme = theme
    screen = PassphraseEnrolModal()
    async with app.run_test(size=(160, 50)) as pilot:
        _assert_colour_mode(app)
        results = await _show(app, pilot, screen)
        first = screen.query_one("#enrol-pass1", Input)
        second = screen.query_one("#enrol-pass2", Input)
        palette = _active_palette(app)
        observations = []
        for phase, phrase, other, score, selector, expected in (
            ("fair", "Abcd12!localx", "Abcd12!localx", 2, "#enrol-strength", "Strength: Fair"),
            ("very-strong", PHRASE, PHRASE, 4, "#enrol-strength", "Strength: Very strong"),
            ("mismatch", PHRASE, "different", 4, "#enrol-mismatch", "Passphrases do not match."),
        ):
            previous_calls = len(score_calls)
            first.value, second.value = phrase, other
            await wait_until(lambda: getattr(screen, "_last_score", None) == score and screen.query_one(selector, Static).render().plain == expected)
            await pilot.pause()
            assert phrase in score_calls[previous_calls:], "The native change must use the local estimator"
            target = screen.query_one(selector, Static)
            x, y = _assert_painted_target(app, target, expected, target)
            styles = [screen._compositor.get_style_at(x + offset, y) for offset, glyph in enumerate(expected) if glyph.strip()]
            runs = [{"style": str(style), "foreground": list(_paint_colours(style, palette)[0]),
                     "background": list(_paint_colours(style, palette)[1]), "contrast": _contrast(*_paint_colours(style, palette))}
                    for style in dict.fromkeys(styles)]
            observations.append({"phase": phase, "score": score, "literal": expected, "runs": runs})
            assert results == []
        record_property("feedback_glyph_runs", json.dumps({"theme": theme, "observations": observations,
                        "scorer_calls": score_calls,
                        "colour_system": app.console.color_system, "no_color": app.no_color, "filters": constants.FILTERS}))
        await pilot.press("escape")
        await wait_until(lambda: app.screen is not screen)
        assert results == [None]
        app.assert_no_operations()
        assert min(run["contrast"] for observation in observations for run in observation["runs"]) >= 4.5, observations
