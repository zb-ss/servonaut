"""Tests for ConfirmActionScreen modal."""

from __future__ import annotations

import pytest
from textual.app import App
from textual.widgets import Button, Input, Static

from servonaut.screens.confirm_action import ConfirmActionScreen


def _make_screen(**kwargs) -> ConfirmActionScreen:
    defaults = dict(
        title="Delete Server",
        description="This will delete [bold]my-vps[/bold].",
        consequences=["All data will be lost", "Backups will be removed"],
        confirm_text="my-vps",
        action_label="Delete Now",
        severity="danger",
    )
    defaults.update(kwargs)
    return ConfirmActionScreen(**defaults)


class _WrapperApp(App[bool]):
    """Minimal host app to push a ConfirmActionScreen for testing."""

    def __init__(self, screen: ConfirmActionScreen) -> None:
        super().__init__()
        self._screen = screen

    def on_mount(self) -> None:
        self.push_screen(self._screen)


class TestConfirmActionButtonState:
    @pytest.mark.asyncio
    async def test_confirm_button_disabled_by_default(self):
        app = _WrapperApp(_make_screen())
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            btn = app.screen.query_one("#btn_confirm", Button)
            assert btn.disabled is True

    @pytest.mark.asyncio
    async def test_confirm_button_enabled_on_exact_match(self):
        app = _WrapperApp(_make_screen())
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            inp = app.screen.query_one("#confirm_input", Input)
            inp.value = "my-vps"
            await pilot.pause()
            btn = app.screen.query_one("#btn_confirm", Button)
            assert btn.disabled is False

    @pytest.mark.asyncio
    async def test_confirm_button_stays_disabled_on_partial_match(self):
        app = _WrapperApp(_make_screen())
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            inp = app.screen.query_one("#confirm_input", Input)
            inp.value = "my"
            await pilot.pause()
            btn = app.screen.query_one("#btn_confirm", Button)
            assert btn.disabled is True

    @pytest.mark.asyncio
    async def test_confirm_button_stays_disabled_on_wrong_text(self):
        app = _WrapperApp(_make_screen())
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            inp = app.screen.query_one("#confirm_input", Input)
            inp.value = "wrong"
            await pilot.pause()
            btn = app.screen.query_one("#btn_confirm", Button)
            assert btn.disabled is True

    @pytest.mark.asyncio
    async def test_case_sensitive_match(self):
        # confirm_text="MyVPS" — lowercase "myvps" must NOT enable button
        app = _WrapperApp(_make_screen(confirm_text="MyVPS"))
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            inp = app.screen.query_one("#confirm_input", Input)
            inp.value = "myvps"
            await pilot.pause()
            btn = app.screen.query_one("#btn_confirm", Button)
            assert btn.disabled is True

    @pytest.mark.asyncio
    async def test_button_re_disables_after_clearing(self):
        app = _WrapperApp(_make_screen())
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            inp = app.screen.query_one("#confirm_input", Input)
            inp.value = "my-vps"
            await pilot.pause()
            btn = app.screen.query_one("#btn_confirm", Button)
            assert btn.disabled is False
            inp.value = ""
            await pilot.pause()
            assert btn.disabled is True


class TestConfirmActionDismiss:
    @pytest.mark.asyncio
    async def test_dismiss_true_on_confirm(self):
        dismissed: list = []

        screen = _make_screen()
        screen.dismiss = lambda val=True: dismissed.append(val)  # type: ignore[method-assign]

        app = _WrapperApp(screen)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            inp = app.screen.query_one("#confirm_input", Input)
            inp.value = "my-vps"
            await pilot.pause()
            await pilot.click("#btn_confirm")
            await pilot.pause()

        assert dismissed and dismissed[0] is True

    @pytest.mark.asyncio
    async def test_dismiss_false_on_cancel(self):
        dismissed: list = []

        screen = _make_screen()
        screen.dismiss = lambda val=False: dismissed.append(val)  # type: ignore[method-assign]

        app = _WrapperApp(screen)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.click("#btn_cancel")
            await pilot.pause()

        assert dismissed and dismissed[0] is False

    @pytest.mark.asyncio
    async def test_dismiss_false_on_escape(self):
        dismissed: list = []

        screen = _make_screen()
        screen.dismiss = lambda val=False: dismissed.append(val)  # type: ignore[method-assign]

        app = _WrapperApp(screen)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()

        assert dismissed and dismissed[0] is False


class TestConfirmActionSeverity:
    @pytest.mark.asyncio
    async def test_danger_severity_renders(self):
        app = _WrapperApp(_make_screen(severity="danger"))
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            assert app.screen.query_one("#modal_container") is not None

    @pytest.mark.asyncio
    async def test_warning_severity_renders(self):
        app = _WrapperApp(_make_screen(severity="warning"))
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            assert app.screen.query_one("#modal_container") is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("confirm_text", ["a[/b]c", "x[red]y"])
async def test_confirmation_identifier_is_rendered_literally(confirm_text: str) -> None:
    """Markup-looking identifiers stay readable and require their exact raw value."""
    screen = _make_screen(confirm_text=confirm_text)
    app = _WrapperApp(screen)
    async with app.run_test() as pilot:
        await pilot.pause()
        prompt = screen.query_one("#confirm_prompt", Static).render()
        field = screen.query_one("#confirm_input", Input)
        confirm = screen.query_one("#btn_confirm", Button)
        assert prompt.plain == f'Type "{confirm_text}" to confirm:'
        assert field.placeholder == confirm_text
        for value in (f" {confirm_text}", f"{confirm_text} ", confirm_text[:-1]):
            field.value = value
            await pilot.pause()
            assert confirm.disabled
        field.value = confirm_text
        await pilot.pause()
        assert not confirm.disabled


@pytest.mark.asyncio
async def test_description_and_consequences_keep_trusted_markup() -> None:
    """Escaping the identifier does not flatten callers' formatted explanations."""
    screen = _make_screen(
        description="Review [bold]web-1[/bold].",
        consequences=["Remove [italic]stored files[/italic]."],
    )
    app = _WrapperApp(screen)
    async with app.run_test() as pilot:
        await pilot.pause()
        description = screen.query_one("#modal_description", Static).render()
        consequence = screen.query_one(".consequence_item", Static).render()
        assert description.plain == "Review web-1."
        assert consequence.plain.strip() == "• Remove stored files."
        assert any(
            str(span.style) == "bold" and description.plain[span.start:span.end] == "web-1"
            for span in description.spans
        )
        assert any(
            str(span.style) == "italic" and consequence.plain[span.start:span.end] == "stored files"
            for span in consequence.spans
        )
