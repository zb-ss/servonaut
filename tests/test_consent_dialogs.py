"""Mounted privacy choices, notice routes and explicit side-effect boundaries."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, RadioButton, RadioSet, Static

from servonaut.screens.bug_report import BugReportScreen
from servonaut.screens.bug_report_consent_modal import BugReportConsentModal
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.scp_transfer import SCPTransferScreen
from servonaut.services.bug_report_service import (
    BugReportConsent,
    BugReportPayload,
    BugReportService,
)
from servonaut.widgets import upsell_modal
from servonaut.widgets.dialogs import DialogActions, DialogBody, DialogFrame
from servonaut.widgets.upsell_modal import BackendMaintenanceModal, BetaWaitlistModal, UpsellModal
from tests._async_bounds import wait_until
from tests.test_basic_dialogs import BasicDialogHost, assert_exposed

pytestmark = pytest.mark.usefixtures("navigation_open")


def make_dialog(kind: str) -> tuple[ModalScreen, str, str]:
    """Return the modal, initial focus target and its safe dismissal target."""
    if kind == "consent":
        return BugReportConsentModal(), "chk-include-logs", "cancel"
    if kind == "upsell":
        return UpsellModal("unknown_feature"), "upsell-btn-close", "upsell-btn-close"
    if kind == "waitlist":
        return BetaWaitlistModal(), "waitlist-btn-ok", "waitlist-btn-ok"
    return BackendMaintenanceModal(), "maintenance-btn-ok", "maintenance-btn-ok"


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_consent_defaults_and_explicit_continue_return_exact_dataclass(
    size: tuple[int, int],
) -> None:
    app = BasicDialogHost()
    screen = BugReportConsentModal()
    results = []
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        assert screen.focused is screen.query_one("#chk-include-logs", Checkbox)
        assert all(checkbox.value for checkbox in screen.query(Checkbox))
        assert screen.query_one("#channel-selector", RadioSet).pressed_index == 0
        assert results == []
        button = screen.query_one("#continue", Button)
        assert_exposed(app, screen, button)
        assert await pilot.click(button)
        await pilot.pause()
        assert results == [BugReportConsent(True, True, True, "github")]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_consent_keyboard_changes_choices_before_explicit_continue(
    size: tuple[int, int],
) -> None:
    app = BasicDialogHost()
    screen = BugReportConsentModal()
    results = []
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        await pilot.press("space", "tab")
        assert screen.focused is screen.query_one("#chk-include-config", Checkbox)
        await pilot.press("tab", "space", "tab")
        assert screen.focused is screen.query_one("#channel-selector", RadioSet)
        await pilot.press("down", "enter")
        await pilot.pause()
        assert results == [] and app.screen is screen
        assert screen.query_one("#channel-selector", RadioSet).pressed_index == 1
        await pilot.press("tab")
        assert screen.focused is screen.query_one("#continue", Button)
        await pilot.press("enter")
        await pilot.pause()
        assert results == [BugReportConsent(False, True, False, "backend")]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_consent_mouse_reaches_every_choice_without_scrolling_or_moving_actions(
    size: tuple[int, int],
) -> None:
    app = BasicDialogHost()
    screen = BugReportConsentModal()
    results = []
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        body = screen.query_one(DialogBody)
        buttons = list(screen.query_one(DialogActions).query(Button))
        positions = [button.region for button in buttons]
        for checkbox in screen.query(Checkbox):
            assert body.scrollable_content_region.contains_region(checkbox.region)
            assert await pilot.click(checkbox)
            await pilot.pause()
            assert not checkbox.value
        backend = screen.query_one("#radio-backend", RadioButton)
        assert body.scrollable_content_region.contains_region(backend.region)
        assert await pilot.click(backend)
        await pilot.pause()
        assert screen.query_one("#channel-selector", RadioSet).pressed_index == 1
        assert [button.region for button in buttons] == positions
        assert_exposed(app, screen, screen.query_one("#continue", Button))
        assert body.max_scroll_y == 0 and not screen.query_one(DialogFrame).border_subtitle
        assert await pilot.click(screen.query_one("#continue", Button))
        await pilot.pause()
        assert results == [BugReportConsent(False, False, False, "backend")]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("route", ["escape", "click"])
async def test_consent_cancellation_returns_none_and_restores_origin(
    size: tuple[int, int], route: str,
) -> None:
    app = BasicDialogHost()
    screen = BugReportConsentModal()
    results = []
    async with app.run_test(size=size) as pilot:
        origin = app.query_one("#origin", Input)
        origin.focus()
        await pilot.pause()
        app.push_screen(screen, results.append)
        await pilot.pause()
        if route == "escape":
            await pilot.press("escape")
        else:
            assert await pilot.click(screen.query_one("#cancel", Button))
        await pilot.pause()
        assert results == [None] and app.focused is origin


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("route", ["enter", "escape", "click"])
@pytest.mark.parametrize("kind", ["upsell", "waitlist", "maintenance"])
async def test_notice_safe_dismissal_never_opens_browser(
    size: tuple[int, int], route: str, kind: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser = MagicMock()
    monkeypatch.setattr(upsell_modal.webbrowser, "open", browser)
    app = BasicDialogHost()
    screen, focus_id, close_id = make_dialog(kind)
    results = []
    async with app.run_test(size=size) as pilot:
        origin = app.query_one("#origin", Input)
        app.push_screen(screen, results.append)
        await pilot.pause()
        assert screen.focused is screen.query_one(f"#{focus_id}", Button)
        if route == "click":
            assert await pilot.click(screen.query_one(f"#{close_id}", Button))
        else:
            await pilot.press(route)
        await pilot.pause()
        assert results == [None] and app.screen is not screen
        assert app.focused is origin
        browser.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("route", ["keyboard", "mouse"])
async def test_only_explicit_view_plans_opens_existing_billing_route_once(
    size: tuple[int, int], route: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser = MagicMock()
    monkeypatch.setattr(upsell_modal.webbrowser, "open", browser)
    app = BasicDialogHost()
    screen = UpsellModal("memory_sync")
    results = []
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        browser.assert_not_called()
        if route == "keyboard":
            await pilot.press("tab")
            assert screen.focused is screen.query_one("#upsell-btn-upgrade", Button)
            await pilot.press("enter")
        else:
            button = screen.query_one("#upsell-btn-upgrade", Button)
            assert_exposed(app, screen, button)
            assert await pilot.click(button)
        await pilot.pause()
        browser.assert_called_once_with(upsell_modal._BILLING_URL)
        assert results == [None]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("kind", ["upsell", "waitlist", "maintenance"])
async def test_long_notice_copy_scrolls_with_safe_focus_and_pinned_actions(
    size: tuple[int, int], kind: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser = MagicMock()
    monkeypatch.setattr(upsell_modal.webbrowser, "open", browser)
    app = BasicDialogHost()
    screen, focus_id, close_id = make_dialog(kind)
    body_id = {"upsell": "upsell-body", "waitlist": "waitlist-body", "maintenance": "maintenance-body"}[kind]
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        screen.query_one(f"#{body_id}", Static).update("\n".join(["Example explanatory detail."] * 45))
        await pilot.pause()
        assert screen.focused is screen.query_one(f"#{focus_id}", Button)
        body = screen.query_one(DialogBody)
        await wait_until(lambda: bool(screen.query_one(DialogFrame).border_subtitle))
        assert body.max_scroll_y > 0 and screen.query_one(DialogFrame).border_subtitle
        positions = [button.region for button in screen.query_one(DialogActions).query(Button)]
        await pilot.press("shift+tab", "pagedown")
        await pilot.pause()
        assert screen.focused is body and body.scroll_y > 0
        assert [button.region for button in screen.query_one(DialogActions).query(Button)] == positions
        close = screen.query_one(f"#{close_id}", Button)
        assert_exposed(app, screen, close)
        assert await pilot.click(close)
        await pilot.pause()
        browser.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("kind", ["consent", "upsell", "waitlist", "maintenance"])
async def test_notification_lifecycle_preserves_targets_focus_and_form_values(
    size: tuple[int, int], kind: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser = MagicMock()
    monkeypatch.setattr(upsell_modal.webbrowser, "open", browser)
    app = BasicDialogHost()
    screen, focus_id, _ = make_dialog(kind)
    async with app.run_test(size=size, notifications=True) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        if kind == "consent":
            await pilot.press("space")
        frame = screen.query_one(DialogFrame)
        region = frame.region
        buttons = list(screen.query_one(DialogActions).query(Button))
        positions = [button.region for button in buttons]
        for count in (1, 8, 1, 0):
            toasts = list(screen.query("Toast"))
            if len(toasts) > count:
                for toast in toasts[count:]:
                    toast._expire()
            else:
                for index in range(len(toasts), count):
                    app.notify(f"Example operation {index + 1}.", timeout=60)
            await pilot.pause()
            assert len(screen.query("Toast")) == count
            assert frame.region == region and [button.region for button in buttons] == positions
            assert screen.focused is screen.query_one(f"#{focus_id}")
            for button in buttons:
                assert_exposed(app, screen, button)
            if kind == "consent":
                assert not screen.query_one("#chk-include-logs", Checkbox).value
                assert screen.query_one("#channel-selector", RadioSet).pressed_index == 0
        await pilot.press("escape")
        await pilot.pause()
        browser.assert_not_called()


def fake_payload() -> BugReportPayload:
    return BugReportPayload(
        servonaut_version="0.0.0", python_version="3.12", os_release="Example OS",
        textual_version="8.2.8", install_method="unknown", auth_state="anonymous",
        instance_count_by_provider={}, last_traceback=None, log_excerpt=None,
        config_snapshot=None, redacted_categories_found=[],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("decision", ["cancel", "continue", "reconsent-cancel"])
async def test_real_report_caller_collects_only_after_explicit_consent(
    size: tuple[int, int], decision: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Navigation gating is unrelated to the mounted report/consent boundary.
    monkeypatch.setattr(BugReportScreen, "workspace_sidebar", lambda self: Static("Navigation"))
    service = MagicMock(spec=BugReportService)
    service.collect_diagnostics.return_value = fake_payload()
    service.render_preview.return_value = "Example diagnostic preview"
    app = BasicDialogHost()
    app.bug_report_service = service
    report = BugReportScreen()
    async with app.run_test(size=size) as pilot:
        app.push_screen(report)
        await wait_until(lambda: isinstance(app.screen, BugReportConsentModal))
        await pilot.pause()
        service.collect_diagnostics.assert_not_called()
        await pilot.press("space")
        await pilot.pause()
        service.collect_diagnostics.assert_not_called()
        if decision == "cancel":
            await pilot.press("escape")
            await pilot.pause()
            assert report not in app.screen_stack
            service.collect_diagnostics.assert_not_called()
        else:
            assert await pilot.click(app.screen.query_one("#continue", Button))
            await wait_until(lambda: service.collect_diagnostics.call_count == 1)
            await pilot.pause()
            expected = BugReportConsent(False, True, True, "github")
            assert service.collect_diagnostics.call_args.kwargs["consent"] == expected
            assert app.screen is report and report._consent == expected
            if decision == "reconsent-cancel":
                report.query_one("#edit-consent", Button).press()
                await wait_until(lambda: isinstance(app.screen, BugReportConsentModal))
                await pilot.press("escape")
                await pilot.pause()
                assert app.screen is report and report._consent == expected
                service.collect_diagnostics.assert_called_once()
        service.submit.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_consent_choice_labels_fit_the_native_scroll_width(
    size: tuple[int, int],
) -> None:
    """Long privacy labels must wrap rather than lose their final characters."""
    app = BasicDialogHost()
    screen = BugReportConsentModal()
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        body = screen.query_one(DialogBody)
        viewport = body.scrollable_content_region
        for checkbox in screen.query(Checkbox):
            assert checkbox.region.x >= viewport.x
            assert checkbox.region.right <= viewport.right
            rendered = "\n".join(
                checkbox.render_line(y).text for y in range(checkbox.size.height)
            )
            assert str(checkbox.label) in rendered
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light", "textual-dark", "textual-light"])
async def test_consent_description_is_painted_in_native_muted_role(theme: str) -> None:
    """The application stylesheet must preserve the description's intended role."""
    app = BasicDialogHost()
    app.theme = theme
    screen = BugReportConsentModal()
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        screen.query_one(DialogBody).scroll_home(animate=False)
        await pilot.pause()
        copy = screen.query_one("#consent-copy", Static)
        point = (copy.content_region.x, copy.content_region.y)
        actual = screen._compositor.get_style_at(*point).color
        text = copy.render().plain
        # Resolve auto-colour opacity through native CSS as the role reference.
        copy.set_styles(f"color: {app.get_css_variables()['text-muted']};")
        await pilot.pause()
        expected = screen._compositor.get_style_at(*point).color
        assert copy.render().plain == text
        assert actual == expected
        await pilot.press("escape")


@pytest.mark.asyncio
async def test_adjacent_destructive_description_retains_existing_text_role() -> None:
    """Opting consent copy into muted text must not dim the destructive question."""
    app = BasicDialogHost()
    screen = ConfirmActionScreen(
        title="Delete example server", description="Review the example server.",
        consequences=["Example services will stop."], confirm_text="web-1",
        action_label="Delete",
    )
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        description = screen.query_one("#modal_description", Static)
        point = (description.content_region.x, description.content_region.y)
        actual = screen._compositor.get_style_at(*point).color
        description.set_styles(f"color: {app.get_css_variables()['text']};")
        await pilot.pause()
        expected = screen._compositor.get_style_at(*point).color
        assert actual == expected
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light"])
@pytest.mark.parametrize("phase", ["initial", "backend"])
async def test_privacy_copy_and_all_choices_are_simultaneously_painted(
    theme: str, phase: str,
) -> None:
    """Opening or selecting a channel must keep every consent category readable."""
    app = BasicDialogHost()
    app.theme = theme
    screen = BugReportConsentModal()
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        if phase == "backend":
            await pilot.press("tab", "tab", "tab", "down", "space")
            await pilot.pause()
            assert screen.focused is screen.query_one("#channel-selector", RadioSet)
            assert screen.query_one("#channel-selector", RadioSet).pressed_index == 1
        body = screen.query_one(DialogBody)
        strips = screen._compositor.render_strips()
        fields = [screen.query_one("#consent-copy", Static), *screen.query(Checkbox), *screen.query(RadioButton)]
        missing = []
        for field in fields:
            expected = field.render().plain if isinstance(field, Static) else str(field.label)
            visible = field.content_region.intersection(body.scrollable_content_region)
            painted = " ".join(
                " ".join(strips[y].crop(visible.x, visible.right).text for y in range(visible.y, visible.bottom)).split()
            )
            if " ".join(expected.split()) not in painted:
                missing.append(expected)
        assert not missing, (
            f"Consent text is not simultaneously painted: {missing}; "
            f"body scroll {body.scroll_y}/{body.max_scroll_y}, size {body.size}, "
            f"content {body.virtual_size}"
        )
        assert all(checkbox.value for checkbox in screen.query(Checkbox))
        assert results == []
        for button in screen.query_one(DialogActions).query(Button):
            assert_exposed(app, screen, button)
        await pilot.press("escape")
        await pilot.pause()
        assert results == [None]


@pytest.mark.asyncio
async def test_scoped_scp_radio_rules_preserve_compact_direction_appearance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Compact native radios retain keyboard direction changes and path values."""
    def navigation_stub(_screen: SCPTransferScreen) -> Static:
        sidebar = Static("Navigation")
        # Preserve the current rail allocation without constructing its services.
        sidebar.styles.width = 25
        return sidebar

    monkeypatch.setattr(SCPTransferScreen, "workspace_sidebar", navigation_stub)
    app = BasicDialogHost()
    screen = SCPTransferScreen({"id": "web-1", "name": "Example server"})
    async with app.run_test(size=(160, 50)) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        selector = screen.query_one("#direction_selector", RadioSet)
        assert tuple(selector.styles.padding) == (0, 0, 0, 0)
        assert selector.styles.border_top[0] == ""
        for radio in selector.query(RadioButton):
            assert tuple(radio.styles.padding) == (0, 1, 0, 1)
            assert radio.region.width > 0 and radio.region.height == 1
            rendered = "\n".join(radio.render_line(y).text for y in range(radio.size.height))
            assert str(radio.label) in rendered
        assert selector.pressed_index == 0 and screen._transfer_direction == "upload"
        local = screen.query_one("#local_path_input", Input)
        remote = screen.query_one("#remote_path_input", Input)
        local.value, remote.value = "/tmp/report.txt", "/srv/report.txt"
        await pilot.press("shift+tab", "down", "space")
        await pilot.pause()
        assert selector.pressed_index == 1 and screen._transfer_direction == "download"
        assert all(tuple(radio.styles.padding) == (0, 1, 0, 1) for radio in selector.query(RadioButton))
        assert screen.query_one("#local_path_role", Static).render().plain == "Destination · This computer"
        assert screen.query_one("#remote_path_role", Static).render().plain == "Source · Remote server"
        assert (local.value, remote.value) == ("/tmp/report.txt", "/srv/report.txt")
        painted = "\n".join(strip.text for strip in screen._compositor.render_strips())
        assert all(str(radio.label) in painted for radio in selector.query(RadioButton))
        await pilot.press("escape")
