"""Ask for the name of a new theme file, and confirm before replacing one."""

from __future__ import annotations

from typing import Optional, Tuple

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

from servonaut.styles.user_themes import is_valid_theme_name
from servonaut.widgets.dialogs import DialogActions, DialogBody, DialogFrame, DialogNotificationSpace

NAME_RULE = "1-40 lowercase letters, digits or dashes, starting with a letter or digit."


class ThemeNamePromptScreen(ModalScreen[Optional[Tuple[str, bool]]]):
    """Dismisses with ``(name, replace_existing)``, or ``None`` on cancel.

    A name that already has a file asks for a second press, now labelled
    Replace, so nothing is overwritten by accident.
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=True)]
    AUTO_FOCUS = "#theme_name_input"

    DEFAULT_CSS = """
    ThemeNamePromptScreen #theme_name_error {
        height: auto;
        color: $text-error;
    }
    ThemeNamePromptScreen #theme_name_error.-replace {
        color: $text-warning;
    }
    """

    def __init__(self, suggestion: str, taken: frozenset[str], existing_files: frozenset[str]) -> None:
        """*taken* are theme names already in use; *existing_files* are file names without ``.toml``."""
        super().__init__(classes="dialog-screen")
        self._suggestion = suggestion
        self._taken = taken
        self._existing_files = existing_files
        self._confirming_replace = False

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static("New theme from current", id="theme_name_title", markup=False),
            body=DialogBody(
                Static(
                    f"Saved in your themes folder as <name>.toml. {NAME_RULE}",
                    id="theme_name_hint",
                    markup=False,
                ),
            ),
            status=Vertical(
                Input(value=self._suggestion, placeholder="my-theme", id="theme_name_input"),
                Static("", id="theme_name_error", markup=False),
            ),
            actions=DialogActions(
                Button("Create", variant="primary", id="theme_name_save"),
                Button("Cancel", id="theme_name_cancel"),
                id="theme_name_buttons",
            ),
            id="theme_name_container",
            size="compact",
        )

    def on_input_changed(self, event: Input.Changed) -> None:
        self._set_confirming(False)
        self._show_error(self._problem(event.value.strip()) if event.value.strip() else "")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        self._submit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "theme_name_save":
            self._submit()
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _problem(self, name: str) -> str:
        if not is_valid_theme_name(name):
            return f"Use {NAME_RULE}"
        if name in self._taken and name not in self._existing_files:
            return "A theme with this name already exists."
        return ""

    def _submit(self) -> None:
        name = self.query_one("#theme_name_input", Input).value.strip()
        problem = self._problem(name) if name else "Enter a name."
        if problem:
            self._show_error(problem)
            return
        if name in self._existing_files and not self._confirming_replace:
            self._set_confirming(True)
            self._show_error(f"{name}.toml already exists. Choose Replace to overwrite it.", replace=True)
            return
        self.dismiss((name, self._confirming_replace))

    def _set_confirming(self, confirming: bool) -> None:
        self._confirming_replace = confirming
        button = self.query_one("#theme_name_save", Button)
        button.label = "Replace" if confirming else "Create"
        button.variant = "warning" if confirming else "primary"

    def _show_error(self, message: str, replace: bool = False) -> None:
        error = self.query_one("#theme_name_error", Static)
        error.set_class(replace, "-replace")
        error.update(message)
