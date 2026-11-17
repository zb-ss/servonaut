"""Confirmation before merging a copied folder with an existing entry."""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.widgets import Button, Static
from servonaut.screens._demo_resolve import display_text
from servonaut.utils.markup import single_line_text
from servonaut.widgets.local_path_tree import local_display_text

from servonaut.widgets.dialogs import DialogActions, DialogBody, DialogFrame, DialogNotificationSpace


class SCPFolderConfirmModal(ModalScreen[bool]):
    DEFAULT_CLASSES = 'dialog-screen'
    BINDINGS = [
        Binding('escape', 'cancel', 'Cancel'),
        Binding('ctrl+shift+d', 'app.toggle_demo', 'Demo mode', show=False),
        Binding('ctrl+e', 'app.toggle_demo', 'Demo mode', show=False),
    ]
    AUTO_FOCUS = '#scp_folder_cancel'
    DEFAULT_CSS = 'SCPFolderConfirmModal #scp_folder_target { height: auto; max-height: 3; overflow-y: auto; }'

    def __init__(self, *, target: str = '', kind: str = 'directory') -> None:
        super().__init__()
        self._target, self._kind = target, kind

    def _target_text(self) -> str:
        label = {'directory': 'Existing folder', 'file': 'Existing file', 'other': 'Existing entry', 'unknown': 'Unchecked destination'}[self._kind]
        shown = display_text(self.app, single_line_text(local_display_text(self._target)))
        redactor = getattr(self.app, 'redaction_service', None)
        if getattr(self.app, 'demo_mode', False) and redactor is not None:
            shown = str(redactor.scrub_stream(shown))
        return f'{label}: {single_line_text(shown)}'

    def refresh_after_demo_toggle(self) -> None:
        self.query_one('#scp_folder_target', Static).update(self._target_text())

    def compose(self) -> ComposeResult:
        can_copy = self._kind in {'directory', 'unknown'}
        heading = 'Copy into the existing folder?' if self._kind == 'directory' else 'Copy without checking the destination?' if can_copy else 'This folder copy will fail'
        detail = (
            'Files with the same name are replaced. Links inside the folder are followed.'
            if self._kind == 'directory' else
            'The destination could not be checked. Existing files may be replaced. Links inside the folder are followed.'
            if can_copy else
            'A folder cannot be copied onto this entry. Choose another destination.'
        )
        buttons = [Button('Cancel', id='scp_folder_cancel')]
        if can_copy:
            buttons.append(Button('Copy into folder' if self._kind == 'directory' else 'Copy folder', id='scp_folder_confirm', variant='warning'))
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static(heading, markup=False),
            body=DialogBody(Static(self._target_text(), id='scp_folder_target', markup=False), Static(detail, markup=False)),
            actions=DialogActions(*buttons),
            size='compact', severity='warning',
        )

    def action_cancel(self) -> None:
        self.dismiss(False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.dismiss(event.button.id == 'scp_folder_confirm')
