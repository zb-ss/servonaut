"""A bounded picker with typed confirmation for a destructive batch."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Static

from servonaut.services.vault.display import terminal_safe
from servonaut.widgets.dialogs import (
    DIALOG_VERTICAL_BREAKPOINTS, DialogActions, DialogBody, DialogContent,
    DialogFrame, DialogNotificationSpace,
)
from servonaut.widgets.filterable_selection import (
    PICKER_BINDINGS, FilterableSelection, PickerActions, SelectionRow, SortOrder,
    without_digest_prefix,
)


@dataclass(frozen=True)
class BulkPreset:
    """A button that replaces the selection with keys the caller computes.

    ``build`` returns the keys to select and a plain-text note shown under the
    description (never interpreted as markup).
    """

    label: str
    build: Callable[[], tuple[Sequence[str], str]]


class BulkActionModal(PickerActions, ModalScreen[list[str] | None]):
    """Select records explicitly and type the action before returning their ids."""

    BINDINGS = [Binding("escape", "cancel", "Cancel"), *PICKER_BINDINGS]
    DEFAULT_CSS = """
    BulkActionModal #bulk_action_title { text-style: bold; color: $text-warning; }
    BulkActionModal #bulk_action_details { height: auto; max-height: 6; margin-bottom: 0; }
    BulkActionModal #bulk_action_description { height: auto; }
    BulkActionModal #bulk_action_note_box { height: auto; max-height: 4; display: none; }
    BulkActionModal #bulk_action_note { height: auto; color: $text-warning; }
    BulkActionModal #bulk_action_acknowledge { width: 1fr; height: auto; }
    BulkActionModal #bulk_action_acknowledge_hint { height: auto; color: $text-warning; }
    BulkActionModal.-dialog-tight #bulk_action_details,
    BulkActionModal.-dialog-minimal #bulk_action_details { max-height: 3; }
    BulkActionModal.-dialog-tight #bulk_action_note_box,
    BulkActionModal.-dialog-minimal #bulk_action_note_box { max-height: 2; }
    """
    VERTICAL_BREAKPOINTS = DIALOG_VERTICAL_BREAKPOINTS

    def __init__(
        self, title: str, description: str, choices: Sequence[tuple[str, str]],
        *, action_label: str, confirm_text: str | None,
        acknowledgement: tuple[str, str] | None = None,
        acknowledgement_hint: str | None = None,
        label_builder: Callable[[str], str] | None = None,
        description_builder: Callable[[], str] | None = None,
        selected: Sequence[str] = (),
        acknowledgement_keys: Sequence[str] | None = None,
        sort_orders: Sequence[SortOrder] = (),
        sort_keys_builder: Callable[[str], Mapping[str, Any]] | None = None,
        preset: BulkPreset | None = None,
    ) -> None:
        super().__init__(classes="dialog-screen")
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
        self._sort_orders = tuple(sort_orders)
        self._sort_keys_builder = sort_keys_builder
        self._preset = preset
        self.acknowledged = False

    def compose(self) -> ComposeResult:
        acknowledgement = []
        if self._acknowledgement is not None:
            acknowledgement = [
                Checkbox(self._acknowledgement[0], id="bulk_action_acknowledge"),
                Static(
                    Text(self._acknowledgement_hint or ""),
                    id="bulk_action_acknowledge_hint",
                ),
            ]
        confirmation = []
        if self._confirm_text is not None:
            confirmation = [
                Input(id="bulk_action_confirm_input", placeholder=self._confirm_text),
            ]
        tools = []
        if self._preset is not None:
            tools = [Button(self._preset.label, id="bulk_action_preset", compact=True)]
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static(Text(self._title), id="bulk_action_title"),
            body=DialogContent(
                DialogBody(
                    Static(Text(self._description_text()), id="bulk_action_description"),
                    id="bulk_action_details",
                ),
                DialogBody(
                    Static(id="bulk_action_note", markup=False),
                    id="bulk_action_note_box",
                ),
                FilterableSelection(
                    prefix="bulk_action",
                    sort_orders=(SortOrder("name", "Name"), *self._sort_orders),
                    tools=tools,
                ),
                *acknowledgement,
                id="bulk_action_body",
            ),
            status=Vertical(
                Static("Choose records to continue.", id="bulk_action_prompt"),
                *confirmation,
            ),
            actions=DialogActions(
                Button("Cancel", id="bulk_action_cancel"),
                Button(
                    self._action_label, variant="error", disabled=True,
                    id="bulk_action_submit",
                ),
            ),
            id="bulk_action_modal",
            size="large",
            severity="warning",
        )

    def on_mount(self) -> None:
        self._picker().set_rows(self._rows())
        self._update_submit()
        self.query_one("#bulk_action_cancel", Button).focus()

    def _rows(self) -> list[SelectionRow]:
        rows = []
        for key, label in self._choices:
            text = self._display(key, label)
            extra = self._sort_keys_builder(key) if self._sort_keys_builder else {}
            rows.append(SelectionRow(
                value=key, label=Text(text), search_text=without_digest_prefix(text),
                selected=key in self._initial_selected,
                sort_keys={"name": text.casefold(), **extra},
            ))
        return rows

    def refresh_after_demo_toggle(self) -> None:
        self._picker().set_rows(self._rows(), keep_selection=True)
        self.query_one("#bulk_action_description", Static).update(Text(self._description_text()))
        note_box = self.query_one("#bulk_action_note_box")
        if self._preset is not None and note_box.display:
            self.query_one("#bulk_action_note", Static).update(Text(self._preset.build()[1]))
        self._update_submit()

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
        selected = set(self._picker().selected)
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
        # A label change alone keeps the button's old width: "(9)" to "(10)" would clip.
        button.refresh(layout=True)

    def on_input_changed(self, event: Input.Changed) -> None:
        event.stop()
        self._update_submit()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        event.stop()
        self.acknowledged = event.value
        self._update_submit()

    def on_filterable_selection_changed(self, event: FilterableSelection.Changed) -> None:
        event.stop()
        self._update_submit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        picker = self._picker()
        if event.button.id == "bulk_action_preset" and self._preset is not None:
            keys, text = self._preset.build()
            picker.select_values(keys, replace=True)
            note = self.query_one("#bulk_action_note", Static)
            note.update(Text(text))
            self.query_one("#bulk_action_note_box").display = bool(text)
            self._update_submit()
        elif event.button.id == "bulk_action_cancel":
            self.dismiss(None)
        elif event.button.id == "bulk_action_submit":
            self._update_submit()
            if not event.button.disabled:
                selected = set(picker.selected)
                self.dismiss([key for key, _ in self._choices if key in selected])

    def action_cancel(self) -> None:
        self.dismiss(None)
