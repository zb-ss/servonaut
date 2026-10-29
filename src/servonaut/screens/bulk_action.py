"""A bounded picker with typed confirmation for a destructive batch."""
from __future__ import annotations

from collections.abc import Callable, Sequence

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, SelectionList, Static
from textual.widgets.selection_list import Selection

from servonaut.services.vault.display import terminal_safe


class BulkActionModal(ModalScreen[list[str] | None]):
    """Select records explicitly and type the action before returning their ids."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]
    DEFAULT_CSS = """
    BulkActionModal { align: center middle; }
    BulkActionModal #bulk_action_modal {
        width: 84; max-width: 94%; height: 90%; max-height: 34;
        padding: 1 2; border: round $warning; background: $surface;
    }
    BulkActionModal #bulk_action_title { text-style: bold; color: $text-warning; }
    BulkActionModal #bulk_action_description { height: auto; }
    BulkActionModal #bulk_action_body { height: 1fr; }
    BulkActionModal #bulk_action_list { height: auto; max-height: 8; }
    BulkActionModal Horizontal { height: auto; }
    BulkActionModal Button { margin-right: 1; }
    BulkActionModal #bulk_action_status { height: auto; color: $text-warning; }
    BulkActionModal #bulk_action_acknowledge { width: 1fr; height: auto; }
    BulkActionModal #bulk_action_acknowledge_hint { height: auto; color: $text-warning; }
    BulkActionModal.-short #bulk_action_list { max-height: 6; }
    """
    VERTICAL_BREAKPOINTS = [(0, "-short"), (40, "-tall")]

    def __init__(
        self, title: str, description: str, choices: Sequence[tuple[str, str]],
        *, action_label: str, confirm_text: str | None,
        acknowledgement: tuple[str, str] | None = None,
        acknowledgement_hint: str | None = None,
        label_builder: Callable[[str], str] | None = None,
        description_builder: Callable[[], str] | None = None,
        selected: Sequence[str] = (),
        acknowledgement_keys: Sequence[str] | None = None,
    ) -> None:
        super().__init__()
        self._title = title
        self._description = description
        self._choices = list(choices)
        self._action_label = action_label
        self._confirm_text = confirm_text
        self._acknowledgement = acknowledgement
        self._acknowledgement_hint = acknowledgement_hint
        self._label_builder = label_builder
        self._description_builder = description_builder
        self._initial_selected = set(selected)
        self._acknowledgement_keys = set(acknowledgement_keys) if acknowledgement_keys is not None else None
        self.acknowledged = False

    def compose(self) -> ComposeResult:
        with Vertical(id="bulk_action_modal"):
            yield Static(Text(self._title), id="bulk_action_title")
            with VerticalScroll(id="bulk_action_body"):
                yield Static(Text(self._description_text()), id="bulk_action_description")
                yield SelectionList(id="bulk_action_list")
                with Horizontal():
                    yield Button("Select All", id="bulk_action_all")
                    yield Button("Select None", id="bulk_action_none")
                if self._acknowledgement is not None:
                    yield Checkbox(self._acknowledgement[0], id="bulk_action_acknowledge")
                    yield Static(Text(self._acknowledgement_hint or ""), id="bulk_action_acknowledge_hint")
                yield Static("Choose records to continue.", id="bulk_action_prompt")
                if self._confirm_text is not None:
                    yield Input(id="bulk_action_confirm_input", placeholder=self._confirm_text)
                yield Static("Nothing selected.", id="bulk_action_status")
            with Horizontal():
                yield Button("Cancel", id="bulk_action_cancel")
                yield Button(self._action_label, variant="error", disabled=True, id="bulk_action_submit")

    def on_mount(self) -> None:
        self.refresh_after_demo_toggle()
        self._update_submit()
        self.query_one("#bulk_action_cancel", Button).focus()

    def refresh_after_demo_toggle(self) -> None:
        listing = self.query_one("#bulk_action_list", SelectionList)
        selected = set(listing.selected) if listing.option_count else self._initial_selected
        highlighted = listing.highlighted
        listing.clear_options()
        listing.add_options([
            Selection(Text(self._display(key, label)), key, key in selected)
            for key, label in self._choices
        ])
        if self._choices:
            listing.highlighted = min(highlighted or 0, len(self._choices) - 1)
        self.query_one("#bulk_action_description", Static).update(Text(self._description_text()))

    def _description_text(self) -> str:
        return self._description_builder() if self._description_builder is not None else self._description

    def _display(self, key: str, label: str) -> str:
        if self._label_builder is not None:
            return terminal_safe(self._label_builder(key))
        label = terminal_safe(label)
        redactor = getattr(self.app, "redaction_service", None)
        if getattr(self.app, "demo_mode", False) and redactor is not None:
            return str(redactor.redact_name(label))
        return label

    def _update_submit(self) -> None:
        selected = set(self.query_one("#bulk_action_list", SelectionList).selected)
        count = len(selected)
        if self._acknowledgement is not None and self._acknowledgement_keys is not None:
            checkbox = self.query_one("#bulk_action_acknowledge", Checkbox)
            checkbox.disabled = not bool(selected & self._acknowledgement_keys)
            if checkbox.disabled:
                checkbox.value = self.acknowledged = False
        required = self._acknowledgement[1] if self.acknowledged and self._acknowledgement else self._confirm_text
        confirmed = required is None
        if required is not None:
            confirmation = self.query_one("#bulk_action_confirm_input", Input)
            confirmation.placeholder = required
            confirmed = confirmation.value == required
            self.query_one("#bulk_action_prompt", Static).update(f'Type "{required}" to confirm the selected records:')
        if self._acknowledgement is not None:
            self.query_one("#bulk_action_acknowledge_hint").display = self.acknowledged and bool(self._acknowledgement_hint)
        button = self.query_one("#bulk_action_submit", Button)
        button.disabled = not count or not confirmed
        button.label = f"{self._action_label} ({count})"
        self.query_one("#bulk_action_status", Static).update(f"{count} selected." if count else "Nothing selected.")

    def on_input_changed(self, event: Input.Changed) -> None:
        event.stop()
        self._update_submit()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        event.stop()
        self.acknowledged = event.value
        self._update_submit()

    def on_selection_list_selected_changed(self, event: SelectionList.SelectedChanged) -> None:
        event.stop()
        self._update_submit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        listing = self.query_one("#bulk_action_list", SelectionList)
        if event.button.id == "bulk_action_all":
            listing.select_all()
        elif event.button.id == "bulk_action_none":
            listing.deselect_all()
        elif event.button.id == "bulk_action_cancel":
            self.dismiss(None)
        elif event.button.id == "bulk_action_submit":
            self._update_submit()
            if not event.button.disabled:
                selected = set(listing.selected)
                self.dismiss([key for key, _ in self._choices if key in selected])

    def action_cancel(self) -> None:
        self.dismiss(None)
