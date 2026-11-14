"""Mounted AI prompt choices, native overflow, literal copy and stable targets."""

from __future__ import annotations

from io import StringIO
from unittest.mock import Mock

import pytest
from rich.console import Console
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Input, Static

from servonaut.screens.ai_fallback_prompt_modal import AIFallbackPromptModal
from servonaut.screens.ai_picker_modal import AIEmptyStateModal, AIProviderFirstRunModal
from servonaut.screens.ai_topup_modal import AITopUpModal
from servonaut.services.ai_balance import AITopupPack
from servonaut.widgets.dialogs import DialogActions, DialogBody, DialogContent, DialogFrame
from servonaut.widgets.safe_header import SafeHeader
from tests._async_bounds import wait_until
from tests.test_basic_dialogs import BasicDialogHost, assert_exposed


def packs(count: int = 2) -> list[AITopupPack]:
    """Use server-shaped catalog fixtures with no billing transport."""
    return [
        AITopupPack(f"pack-{index}", f"Example pack {index}", "GBP", f"£{index}", f"£{index}")
        for index in range(1, count + 1)
    ]


def make_dialog(kind: str) -> tuple[ModalScreen, str, str]:
    """Return a real modal, a body-copy ID and a pinned action ID."""
    if kind == "first_run":
        return AIProviderFirstRunModal("OpenAI"), "ai_picker_body", "btn_pick_existing"
    if kind == "empty":
        return AIEmptyStateModal(), "ai_empty_body", "btn_empty_add_key"
    if kind == "fallback":
        return AIFallbackPromptModal(["OpenAI", "ollama"]), "ai_fallback_body", "btn_fallback_keep"
    return (
        AITopUpModal(packs=packs(), reason="Example balance exhausted.", show_billing_action=True),
        "ai_topup_body", "btn_topup_cancel",
    )


def painted_text(app: BasicDialogHost) -> str:
    """Read the composed terminal viewport, excluding clipped widget lines."""
    output = StringIO()
    console = Console(file=output, width=app.size.width, force_terminal=True, color_system=None)
    console.print(app.screen._compositor.render_update(full=True))
    return output.getvalue()


CHOICES = [
    ("first_run", "btn_pick_servonaut", "servonaut"),
    ("first_run", "btn_pick_existing", "openai"),
    ("empty", "btn_empty_subscribe", "subscribe"),
    ("empty", "btn_empty_add_key", "add_api_key"),
    ("empty", "btn_empty_ollama", "ollama"),
    ("fallback", "btn_fallback_openai", "openai"),
    ("fallback", "btn_fallback_keep", None),
    ("topup", "btn_topup_0", "pack-1"),
    ("topup", "btn_topup_billing", AITopUpModal.BILLING_ACTION),
    ("topup", "btn_topup_cancel", None),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("submit", ["click", "enter"])
@pytest.mark.parametrize("kind, button_id, expected", CHOICES)
async def test_explicit_choice_returns_exact_result_without_opening_browser(
    kind: str, button_id: str, expected: str | None, submit: str,
    size: tuple[int, int], monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser = Mock(side_effect=AssertionError("The modal must leave browser actions to its caller."))
    monkeypatch.setattr("webbrowser.open", browser)
    app = BasicDialogHost()
    screen, _, _ = make_dialog(kind)
    results = []
    async with app.run_test(size=size) as pilot:
        origin = app.query_one("#origin", Input)
        origin.focus()
        app.push_screen(screen, results.append)
        await pilot.pause()
        assert results == []
        button = screen.query_one(f"#{button_id}", Button)
        button.focus()
        button.scroll_visible(animate=False)
        await pilot.pause()
        assert_exposed(app, screen, button)
        if submit == "click":
            assert await pilot.click(button)
        else:
            await pilot.press("enter")
        await pilot.pause()
        assert results == [expected]
        assert app.screen is not screen and app.focused is origin
    browser.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("kind", ["first_run", "empty", "fallback", "topup"])
async def test_escape_returns_none_and_restores_origin_focus(
    kind: str, size: tuple[int, int],
) -> None:
    app = BasicDialogHost()
    screen, _, _ = make_dialog(kind)
    results = []
    async with app.run_test(size=size) as pilot:
        origin = app.query_one("#origin", Input)
        origin.focus()
        app.push_screen(screen, results.append)
        await pilot.pause()
        assert isinstance(screen, ModalScreen)
        assert len(screen.query(SafeHeader)) == len(screen.query(Footer)) == 1
        await pilot.press("escape")
        await pilot.pause()
        assert results == [None]
        assert app.focused is origin


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("kind", ["first_run", "empty", "fallback"])
async def test_overflow_and_notifications_preserve_cached_action_target(
    kind: str, size: tuple[int, int],
) -> None:
    app = BasicDialogHost()
    screen, copy_id, action_id = make_dialog(kind)
    results = []
    async with app.run_test(size=size, notifications=True) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        screen.query_one(f"#{copy_id}", Static).update(
            "\n".join(f"Example detail {index + 1}." for index in range(45))
        )
        await pilot.pause()
        body = screen.query_one(DialogBody)
        frame = screen.query_one(DialogFrame)
        await wait_until(lambda: body.max_scroll_y > 0 and bool(frame.border_subtitle))
        assert body.max_scroll_y > 0
        assert frame.border_subtitle == "Scroll for all details"
        actions = screen.query_one(DialogActions)
        button = screen.query_one(f"#{action_id}", Button)
        initial_frame, initial_actions, initial_button = frame.region, actions.region, button.region
        assert_exposed(app, screen, button)
        for index in range(3):
            app.notify(f"Example notification {index + 1}.", title="Example", timeout=60)
        await pilot.pause()
        assert (frame.region, actions.region, button.region) == (
            initial_frame, initial_actions, initial_button,
        )
        assert not screen.query_one("ToastRack").region.overlaps(frame.region)
        assert_exposed(app, screen, button)
        body.focus()
        await pilot.press("end")
        await pilot.pause()
        assert body.scroll_y > 0
        assert_exposed(app, screen, button)
        app.clear_notifications()
        await pilot.pause()
        assert (frame.region, actions.region, button.region) == (
            initial_frame, initial_actions, initial_button,
        )
        assert await pilot.click(offset=(
            initial_button.x + initial_button.width // 2,
            initial_button.y + initial_button.height // 2,
        ))
        await pilot.pause()
        assert results == [{"first_run": "openai", "empty": "add_api_key"}.get(kind)]


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light"])
async def test_empty_fallback_has_distinct_hint_and_keep_remains_clickable(theme: str) -> None:
    app = BasicDialogHost()
    app.theme = theme
    screen = AIFallbackPromptModal([], title="Switch provider", keep_label="Cancel")
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        assert screen.query_one("#ai_fallback_no_alternate", Static) is not screen.query_one(
            "#ai_fallback_body", Static,
        )
        assert not screen.query("#ai_fallback_buttons")
        body = screen.query_one(DialogBody)
        body.scroll_end(animate=False)
        await pilot.pause()
        assert "No alternate provider configured." in painted_text(app)
        assert await pilot.click(screen.query_one("#btn_fallback_keep", Button))
        await pilot.pause()
        assert results == [None]


@pytest.mark.asyncio
@pytest.mark.parametrize("billing", [False, True])
async def test_empty_catalog_filters_keyless_packs_without_inventing_choices(billing: bool) -> None:
    app = BasicDialogHost()
    screen = AITopUpModal(packs=[Mock(key="")], show_billing_action=billing)
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        assert not screen.query(".ai_topup_pack")
        assert bool(screen.query("#btn_topup_billing")) is billing
        if billing:
            assert "Open billing in your browser" in painted_text(app)
        button = screen.query_one("#btn_topup_billing" if billing else "#btn_topup_cancel", Button)
        assert await pilot.click(button)
        await pilot.pause()
        assert results == [AITopUpModal.BILLING_ACTION if billing else None]


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light"])
async def test_every_normalized_fallback_provider_is_keyboard_reachable(
    theme: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)
    app = BasicDialogHost()
    app.theme = theme
    screen = AIFallbackPromptModal(
        ["OpenAI", "openai", "  Ollama  ", "Anthropic", "Gemini", "", None],
        reason="Example upstream failure.",
    )
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        assert len(screen.query("#ai_fallback_buttons Button")) == 4
        first = screen.query_one("#btn_fallback_openai", Button)
        first.focus()
        await pilot.pause()
        point = (first.content_region.x + first.content_region.width // 2, first.content_region.y)
        focused_style = screen._compositor.get_style_at(*point)
        screen.query_one("#btn_fallback_keep", Button).focus()
        await pilot.pause()
        blurred_style = screen._compositor.get_style_at(*point)
        assert (
            focused_style.bgcolor != blurred_style.bgcolor
            or (focused_style.underline and not blurred_style.underline)
        )
        first.focus()
        await pilot.press("tab", "tab", "tab")
        await pilot.pause()
        last = screen.query_one("#btn_fallback_gemini", Button)
        assert screen.focused is last
        assert screen.region.contains_region(last.region)
        assert app.get_widget_at(
            last.region.x + last.region.width // 2,
            last.region.y + last.region.height // 2,
        )[0] is last
        assert_exposed(app, screen, last)
        assert_exposed(app, screen, screen.query_one("#btn_fallback_keep", Button))
        await pilot.press("enter")
        await pilot.pause()
        assert results == ["gemini"]


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light"])
async def test_long_catalog_reaches_explicit_billing_without_moving_cancel(theme: str) -> None:
    app = BasicDialogHost()
    app.theme = theme
    screen = AITopUpModal(packs=packs(20), show_billing_action=True)
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        cancel = screen.query_one("#btn_topup_cancel", Button)
        initial = cancel.region
        screen.query_one("#btn_topup_0", Button).focus()
        for _ in range(20):
            await pilot.press("tab")
        await pilot.pause()
        billing = screen.query_one("#btn_topup_billing", Button)
        assert screen.focused is billing
        assert screen.query_one("#ai_topup_catalog").scroll_y > 0
        assert cancel.region == initial
        assert_exposed(app, screen, billing)
        assert_exposed(app, screen, cancel)
        await pilot.press("enter")
        await pilot.pause()
        assert results == [AITopUpModal.BILLING_ACTION]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_native_catalog_overflow_toasts_preserve_disclosure_and_cached_cancel(
    size: tuple[int, int],
) -> None:
    """The fixed disclosure never joins catalog scrolling or notification motion."""
    app = BasicDialogHost()
    screen = AITopUpModal(packs=packs(20), reason="Example balance exhausted.")
    results = []
    async with app.run_test(size=size, notifications=True) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        frame = screen.query_one(DialogFrame)
        content = screen.query_one(DialogContent)
        catalog = screen.query_one("#ai_topup_catalog")
        cancel = screen.query_one("#btn_topup_cancel", Button)
        initial = frame.region, cancel.region
        point = (cancel.region.x + cancel.region.width // 2, cancel.region.y + cancel.region.height // 2)
        assert catalog.max_scroll_y > 0
        assert not content.allow_vertical_scroll and content.scroll_y == 0
        assert frame.border_subtitle == ""
        for count in (3, 0):
            app.clear_notifications()
            for index in range(count):
                app.notify(
                    f"Example notification {index + 1}.\nSecond row.\nThird row.",
                    title="Example", timeout=60,
                )
            await pilot.pause()
            assert (frame.region, cancel.region) == initial
            assert screen.max_scroll_y == 0
            if count:
                assert not screen.query_one("ToastRack").region.overlaps(frame.region)
            assert_exposed(app, screen, screen.query_one("#ai_topup_body", Static))
            assert_exposed(app, screen, screen.query_one("#ai_topup_reason", Static))
            assert_exposed(app, screen, cancel)
            assert app.get_widget_at(*point)[0] is cancel
        catalog.scroll_end(animate=False)
        await pilot.pause()
        assert catalog.scroll_y > 0 and content.scroll_y == 0
        assert frame.border_subtitle == ""
        assert_exposed(app, screen, screen.query_one("#ai_topup_body", Static))
        assert (frame.region, cancel.region) == initial
        assert await pilot.click(offset=point)
        await pilot.pause()
        assert results == [None]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["first_run", "fallback", "topup"])
async def test_untrusted_brackets_and_terminal_controls_are_literal(kind: str) -> None:
    app = BasicDialogHost()
    if kind == "first_run":
        screen = AIProviderFirstRunModal("ollama", "https://example.invalid/[red]literal[/red]")
        copy_id, expected = "ai_picker_existing", "example.invalid/[red]literal[/red]"
    elif kind == "fallback":
        screen = AIFallbackPromptModal(
            ["openai"], title="[red]literal title[/red]", body="[blue]literal body[/blue]",
            reason="[yellow]literal reason[/yellow]", keep_label="[green]Keep[/green]",
        )
        copy_id, expected = "ai_fallback_title", "[red]literal title[/red]"
    else:
        screen = AITopUpModal(
            reason="[red]literal reason[/red]\x1b\x07\x9b",
            packs=[AITopupPack("example", "[blue]Pack[/blue]\x1b", "GBP", "[red]£5[/red]\x07", "£5\x9b")],
        )
        copy_id, expected = "ai_topup_reason", "[red]literal reason[/red]"
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        copy = screen.query_one(f"#{copy_id}", Static)
        assert expected in copy.render().plain
        assert expected in painted_text(app)
        if kind == "topup":
            details = screen.query_one(".ai_topup_pack_details", Static).render().plain
            assert "[blue]Pack[/blue]" in details and "[red]£5[/red]" in details
            assert not any(control in details + copy.render().plain for control in ("\x1b", "\x07", "\x9b"))


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("kind, focus_id, expected", [
    ("first_run", "btn_pick_servonaut", ["servonaut"]),
    ("empty", "btn_empty_subscribe", ["subscribe"]),
    ("fallback", "btn_fallback_openai", ["openai"]),
    ("fallback_empty", "btn_fallback_keep", [None]),
    ("topup", "ai_topup_catalog", []),
    ("topup_long", "ai_topup_catalog", []),
    ("topup_billing_only", "ai_topup_catalog", []),
    ("topup_empty", "btn_topup_cancel", [None]),
])
async def test_initial_focus_and_enter_preserve_original_choice_contract(
    size: tuple[int, int], kind: str, focus_id: str, expected: list[str | None],
) -> None:
    """Catalog focus must never silently become a checkout or billing action."""
    app = BasicDialogHost()
    if kind == "fallback_empty":
        screen = AIFallbackPromptModal([])
    elif kind.startswith("topup_"):
        screen = AITopUpModal(
            packs=packs(20) if kind == "topup_long" else (),
            show_billing_action=kind != "topup_empty",
        )
    else:
        screen, _, _ = make_dialog(kind)
    results = []
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        assert screen.focused is screen.query_one(f"#{focus_id}")
        await pilot.press("enter")
        await pilot.pause()
        assert results == expected
        if not expected:
            assert app.screen is screen
            await pilot.press("escape")
            await pilot.pause()
            assert results == [None]


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light"])
@pytest.mark.parametrize("kind", ["fallback", "topup"])
async def test_explanatory_copy_and_initial_choices_are_simultaneously_painted(
    theme: str, kind: str,
) -> None:
    """Native initial focus must retain session and browser disclosures in view."""
    app = BasicDialogHost()
    app.theme = theme
    if kind == "fallback":
        copy = "Pick the provider to use for this chat session. This won't change your default — only the current chat."
        screen = AIFallbackPromptModal(
            ["openai", "ollama", "anthropic", "gemini"],
            title="Switch AI provider", body=copy, keep_label="Cancel",
        )
        expected_copy, copy_id = copy, "ai_fallback_body"
        expected = ["OpenAI", "Ollama (local, private)", "Anthropic", "Gemini", "Cancel"]
        focus_id = "btn_fallback_openai"
    else:
        screen, _, _ = make_dialog("topup")
        expected_copy = (
            "Pick a pack to open Stripe Checkout in your browser. Your "
            "available balance updates after checkout completes."
        )
        copy_id = "ai_topup_body"
        expected = [
            "Example pack 1", "£1", "Example pack 2", "£2",
            "Example balance exhausted.", "Cancel",
        ]
        focus_id = "ai_topup_catalog"
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        assert screen.focused is screen.query_one(f"#{focus_id}")
        copy_widget = screen.query_one(f"#{copy_id}", Static)
        region = copy_widget.content_region
        strips = screen._compositor.render_strips()
        # Crop composed cells, so frame borders between wrapped lines cannot
        # count as copy or hide a disclosure that was actually clipped.
        copy_rows = [
            strip.crop(region.x, region.right).text
            for strip in strips[max(region.y, 0):region.bottom]
        ]
        assert expected_copy in " ".join(" ".join(copy_rows).split())
        assert_exposed(app, screen, copy_widget)
        visible = " ".join(" ".join(strip.text for strip in strips).split())
        for fragment in expected:
            assert fragment in visible
        if kind == "topup":
            for index in range(2):
                assert_exposed(app, screen, screen.query_one(f"#btn_topup_{index}", Button))
        else:
            for button in screen.query("#ai_fallback_buttons Button"):
                assert_exposed(app, screen, button)
        for button in screen.query_one(DialogActions).query(Button):
            assert_exposed(app, screen, button)
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("theme, ansi", [
    ("servonaut", False), ("servonaut-light", False),
    ("textual-dark", False), ("textual-light", False), ("servonaut", True),
])
async def test_topup_catalog_focus_has_a_visible_native_border_cue(
    theme: str, ansi: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catalog focus must be visible without changing the selected pack."""
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)
    app = BasicDialogHost()
    app.ansi_color = ansi
    app.theme = theme
    screen, _, _ = make_dialog("topup")
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        catalog = screen.query_one("#ai_topup_catalog")
        assert screen.focused is catalog
        initial = catalog.region
        frame = screen.query_one(DialogFrame)
        initial_frame = frame.region
        strips = screen._compositor.render_strips()
        focused_strip = strips[catalog.region.y].crop(
            catalog.region.x + 2, catalog.region.right - 2,
        )
        focused_border = focused_strip.text
        screen.query_one("#btn_topup_cancel", Button).focus()
        await pilot.pause()
        strips = screen._compositor.render_strips()
        blurred_strip = strips[catalog.region.y].crop(
            catalog.region.x + 2, catalog.region.right - 2,
        )
        blurred_border = blurred_strip.text
        assert catalog.region == initial and frame.region == initial_frame
        # Both borders are rounded; the cue is the colour the focused one takes.
        assert "─" in focused_border and "─" in blurred_border
        assert {seg.style for seg in focused_strip} != {seg.style for seg in blurred_strip}
        assert strips[frame.region.y].crop(frame.region.x, frame.region.x + 1).text == "╭"
        catalog.focus()
        await pilot.press("enter")
        await pilot.pause()
        assert results == [] and app.screen is screen
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("billing", [False, True])
async def test_empty_and_billing_only_topup_remain_bounded_and_non_approving(
    size: tuple[int, int], billing: bool,
) -> None:
    app = BasicDialogHost()
    screen = AITopUpModal(show_billing_action=billing)
    results = []
    async with app.run_test(size=size, notifications=True) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        frame = screen.query_one(DialogFrame)
        assert frame.region.height <= 24 and screen.max_scroll_y == 0
        # Without pack rows, use at most the shared compact-choice height.
        assert frame.region.height <= 18
        assert_exposed(app, screen, screen.query_one("#ai_topup_body", Static))
        assert_exposed(app, screen, screen.query_one("#btn_topup_cancel", Button))
        assert bool(screen.query("#ai_topup_catalog")) is billing
        if billing:
            assert_exposed(app, screen, screen.query_one("#btn_topup_billing", Button))
            assert screen.focused is screen.query_one("#ai_topup_catalog")
        else:
            assert screen.focused is screen.query_one("#btn_topup_cancel")
        await pilot.press("enter")
        await pilot.pause()
        assert results == ([] if billing else [None])
        if billing:
            await pilot.press("escape")
            await pilot.pause()
            assert results == [None]
