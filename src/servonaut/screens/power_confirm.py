"""Yes/no confirmation before a power action that interrupts a server.

Stopping, shutting down, powering off and rebooting take a server's services
down, so the provider managers ask first. The question is a plain yes/no:
typing the name back stays reserved for actions that destroy data (delete,
terminate), which use :class:`ConfirmActionScreen`.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Optional, Tuple

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class PowerActionConfirmModal(ModalScreen[bool]):
    """Ask whether to run a disruptive power action on one server.

    Dismisses with ``True`` only when the action button is pressed. "No" has
    the focus when the modal opens, so a stray Enter cancels.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    # Textual focuses this as soon as the modal is composed, so "No" holds
    # the focus before the first key can arrive.
    AUTO_FOCUS = "#btn_power_confirm_no"

    def __init__(
        self,
        *,
        action: str,
        server_name: str,
        provider: str,
        consequence: str,
    ) -> None:
        """Initialise the modal.

        Args:
            action: Button label and verb, e.g. ``"Power off"``.
            server_name: Name shown for the server (the row's, so a
                demo-mode placeholder stays a placeholder).
            provider: Provider label, e.g. ``"Hetzner Cloud"``.
            consequence: One sentence on what the user will notice.
        """
        super().__init__()
        self._action = action
        self._server_name = server_name
        self._provider = provider
        self._consequence = consequence

    @property
    def message(self) -> str:
        """The question, with every interpolated value markup-escaped."""
        return (
            f"{escape(self._action)} [bold]{escape(self._server_name)}[/bold] "
            f"({escape(self._provider)})?\n\n{escape(self._consequence)}"
        )

    def compose(self) -> ComposeResult:
        yield Container(
            Static(f"[bold yellow]{escape(self._action)} server[/bold yellow]",
                   id="power_confirm_title"),
            Static(self.message, id="power_confirm_message"),
            Horizontal(
                Button("No", id="btn_power_confirm_no"),
                Button(self._action, variant="warning", id="btn_power_confirm_yes"),
                id="power_confirm_buttons",
            ),
            id="power_confirm_container",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.dismiss(event.button.id == "btn_power_confirm_yes")

    def action_cancel(self) -> None:
        self.dismiss(False)


async def confirm_power_action(
    app: Any,
    *,
    action: str,
    server_name: str,
    provider: str,
    consequence: str,
) -> bool:
    """Show :class:`PowerActionConfirmModal` and wait for the answer.

    Must run inside a worker: ``push_screen_wait`` requires one in Textual 8.
    """
    confirmed = await app.push_screen_wait(
        PowerActionConfirmModal(
            action=action,
            server_name=server_name,
            provider=provider,
            consequence=consequence,
        )
    )
    return bool(confirmed)


async def confirm_and_run_power_action(
    app: Any,
    *,
    prompt: Optional[Tuple[str, str]],
    server_name: str,
    provider: str,
    in_progress_verb: str,
    set_status: Callable[[str], None],
    run: Callable[[], Awaitable[None]],
    on_declined: Optional[Callable[[], None]] = None,
) -> bool:
    """Ask before a power action that interrupts a server, then run it.

    The flow the provider managers share: the yes/no question when the
    action is disruptive, a progress line in the manager's status bar, then
    the action itself. Must run inside a worker (see
    :func:`confirm_power_action`).

    Args:
        app: The running app.
        prompt: ``(verb, consequence)`` for a disruptive action, or ``None``
            for one that runs without asking (starting a server).
        server_name: Name shown for the server, taken from the table row so
            a demo-mode placeholder stays a placeholder.
        provider: Provider label shown in the question.
        in_progress_verb: Status-line verb, e.g. ``"Stopping"``.
        set_status: Writes the manager's status line (Rich markup).
        run: Performs the action once confirmed.
        on_declined: Called when the user answers no.

    Returns:
        ``False`` when the user declined, ``True`` once ``run`` finished.
    """
    if prompt is not None:
        action, consequence = prompt
        confirmed = await confirm_power_action(
            app, action=action, server_name=server_name,
            provider=provider, consequence=consequence,
        )
        if not confirmed:
            if on_declined is not None:
                on_declined()
            return False
    set_status(f"[dim]{escape(in_progress_verb)} {escape(server_name)}…[/dim]")
    await run()
    return True
