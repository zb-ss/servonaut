"""SecretInput: a masked field whose value can be shown to check what was typed or pasted."""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Button, Input

from servonaut.screens.settings.widgets import EnvVarInput
from servonaut.styles import CSS_FILES
from servonaut.widgets.secret_input import SecretInput


class _Host(App):
    demo_mode = False

    def __init__(self) -> None:
        super().__init__()
        self.notes: list[str] = []

    def compose(self) -> ComposeResult:
        yield SecretInput(placeholder="Recovery key", id="secret")
        yield Input(id="after")

    def notify(self, message, *args, **kwargs):  # type: ignore[override]
        self.notes.append(str(message))
        return super().notify(message, *args, **kwargs)


def _button(app: App) -> Button:
    return app.query_one("#secret_reveal", Button)


@pytest.mark.asyncio
async def test_the_value_is_masked_until_shown_and_masked_again_on_hide() -> None:
    app = _Host()
    async with app.run_test() as pilot:
        field = app.query_one(SecretInput)
        inner = app.query_one("#secret", Input)  # callers keep reading the field by its id
        assert field.id == "secret_field" and inner.password and not field.revealed
        assert str(_button(app).label) == "👀 Show"

        await pilot.click("#secret_reveal")
        assert not inner.password and field.revealed and str(_button(app).label) == "👀 Hide"

        await pilot.pause(0.3)  # a button ignores a second press during its press effect
        await pilot.click("#secret_reveal")
        assert inner.password and str(_button(app).label) == "👀 Show"


@pytest.mark.asyncio
async def test_ctrl_r_toggles_while_typing_and_tab_skips_the_button() -> None:
    app = _Host()
    async with app.run_test() as pilot:
        inner = app.query_one("#secret", Input)
        inner.focus()
        await pilot.press("S", "V", "R", "K")
        await pilot.press("ctrl+r")
        assert not inner.password and inner.value == "SVRK"
        await pilot.press("ctrl+r")
        assert inner.password

        await pilot.press("tab")
        assert app.focused is app.query_one("#after", Input)


@pytest.mark.asyncio
async def test_demo_mode_never_shows_a_secret_and_masks_a_shown_one() -> None:
    app = _Host()
    async with app.run_test() as pilot:
        field = app.query_one(SecretInput)
        await pilot.click("#secret_reveal")
        assert field.revealed

        app.demo_mode = True
        field.refresh_after_demo_toggle()
        assert not field.revealed

        await pilot.pause(0.3)
        await pilot.click("#secret_reveal")
        assert not field.revealed
        assert "Secrets stay hidden in demo mode." in app.notes


@pytest.mark.asyncio
async def test_value_and_focus_pass_through_to_the_inner_input() -> None:
    app = _Host()
    async with app.run_test() as pilot:
        field = app.query_one(SecretInput)
        field.value = "SVRK1-ABCDE"
        assert app.query_one("#secret", Input).value == "SVRK1-ABCDE" == field.value
        app.query_one("#after", Input).focus()
        field.focus()
        await pilot.pause()
        assert app.focused is field.input


class _EnvHost(App):
    def compose(self) -> ComposeResult:
        yield EnvVarInput("$OPENAI_API_KEY", password=True, id="api_key")
        yield EnvVarInput("plain", id="plain")


@pytest.mark.asyncio
async def test_settings_secrets_get_the_toggle_and_keep_working_as_before() -> None:
    app = _EnvHost()
    async with app.run_test() as pilot:
        secret = app.query_one("#api_key", EnvVarInput)
        plain = app.query_one("#plain", EnvVarInput)
        assert len(secret.query(SecretInput)) == 1 and len(plain.query(SecretInput)) == 0
        assert secret.password and secret.value == "$OPENAI_API_KEY"
        assert "OPENAI_API_KEY" in str(secret.query_one(".envvar-hint").render())

        secret.value = "sk-test"
        secret.query_one(SecretInput).query_one(Button).press()
        await pilot.pause()
        assert not secret.password and secret.value == "sk-test"


class _RecoveryPromptHost(App):
    """The product styles, so the dialog is measured as users see it."""

    CSS_PATH = CSS_FILES

    def on_mount(self) -> None:
        from servonaut.screens.vault import VaultSecretPromptModal

        self.push_screen(VaultSecretPromptModal("Recover vault identity", "Enter the offline recovery key."))


@pytest.mark.asyncio
async def test_a_whole_recovery_key_fits_beside_show_in_the_recovery_prompt() -> None:
    from servonaut.screens.vault import VaultSecretPromptModal

    app = _RecoveryPromptHost()
    async with app.run_test(size=(120, 40)) as pilot:
        for _ in range(50):
            if isinstance(app.screen, VaultSecretPromptModal) and app.screen.query("#vault_secret_input"):
                break
            await pilot.pause()
        field = app.screen.query_one("#vault_secret_input", Input)
        await pilot.pause()
        recovery_key_length = len("SVRK1-") + 11 * 6 - 1  # SVRK1- and 11 groups of five
        assert field.content_region.width > recovery_key_length  # room for the cursor too
        show = app.screen.query_one("#vault_secret_input_reveal", Button)
        assert app.screen.query_one("#vault_secret_modal").region.contains_region(show.region)
