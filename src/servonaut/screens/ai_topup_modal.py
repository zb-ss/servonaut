"""Top-up pack picker modal (T8).

The caller supplies the current server-advertised pack inventory. The caller
may also offer an explicit billing-page action for a refusal that included a
validated first-party route. The caller awaits the dismiss return value:

- a pack key — the user chose a current pack and the caller requests its
  checkout session;
- :attr:`BILLING_ACTION` — the user selected the separate billing action;
- ``None`` — the user cancelled / pressed Escape.

Per the project ModalScreen convention: this fits the brief-blocking-choice
pattern. Multi-button row, single decision, no content beyond pack
descriptions.
"""
from __future__ import annotations

from typing import Any, Optional, Sequence

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Static

from servonaut.services.ai_balance import safe_terminal_text
from servonaut.widgets.safe_header import SafeHeader


class AITopUpModal(ModalScreen[Optional[str]]):
    """Pack picker for ``POST /api/ai/topup/checkout``.

    Args:
        prefill_pack: Optional pack key to pre-highlight (caller may
            pass it from a CLI ``--pack`` flag). Currently informational.
        reason: Optional context string rendered above the buttons.
            Use cases: ``"Out of monthly tokens"``,
            ``"Budget hard cap reached"``. Plain string — escaped before
            interpolation.
        show_billing_action: Show the explicit billing action for a validated
            server refusal route. The URL remains with the caller, so this
            screen cannot open it itself.

    Returns via ``dismiss``:
        - A server pack key on a pack pick.
        - :attr:`BILLING_ACTION` when the user selects billing.
        - ``None`` if the user dismissed without choosing.
    """

    BILLING_ACTION = "__billing__"

    BINDINGS = [
        Binding("escape", "dismiss_none", "Cancel", show=True),
    ]

    DEFAULT_CSS = """
    AITopUpModal {
        align: center middle;
    }

    AITopUpModal #ai_topup_container {
        width: 78;
        height: auto;
        max-height: 24;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }

    AITopUpModal #ai_topup_title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }

    AITopUpModal #ai_topup_reason {
        color: $warning;
        margin-bottom: 1;
    }

    AITopUpModal #ai_topup_body {
        margin-bottom: 1;
    }

    AITopUpModal #ai_topup_catalog {
        height: auto;
        max-height: 9;
        margin-bottom: 1;
        border: round $primary-background;
        background: $panel;
    }

    AITopUpModal .ai_topup_pack {
        height: 3;
        padding: 0 1;
    }

    AITopUpModal .ai_topup_pack_details {
        width: 1fr;
        height: 3;
        content-align: left middle;
    }

    AITopUpModal .ai_topup_pack Button {
        width: 10;
        min-width: 10;
        height: 3;
    }

    AITopUpModal #ai_topup_catalog #btn_topup_billing {
        width: 100%;
        height: 3;
        margin: 0;
    }

    AITopUpModal #ai_topup_cancel {
        margin-top: 1;
        align: center middle;
    }
    """

    def __init__(
        self,
        *,
        prefill_pack: Optional[str] = None,
        reason: Optional[str] = None,
        packs: Sequence[Any] = (),
        show_billing_action: bool = False,
    ) -> None:
        super().__init__()
        # ``prefill_pack`` is currently informational; reserved for a
        # future "highlight the suggested pack" affordance once the
        # server tells us which pack matches the user's burn rate.
        self._prefill_pack = prefill_pack
        self._reason = safe_terminal_text(reason).strip()
        self._packs = [pack for pack in packs if getattr(pack, "key", "")]
        self._show_billing_action = show_billing_action

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        children = [
            Static(
                "[bold cyan]Top up Servonaut AI[/bold cyan]",
                id="ai_topup_title",
            ),
        ]
        if self._reason:
            children.append(
                Static(
                    f"[bold]{escape(self._reason)}[/bold]",
                    id="ai_topup_reason",
                )
            )
        body = (
            "Open billing in your browser to review available top-up options."
            if self._show_billing_action and not self._packs else
            "Pick a pack to open Stripe Checkout in your browser. Your "
            "available balance updates after checkout completes."
        )
        children.extend([
            Static(
                body,
                id="ai_topup_body",
            ),
            *(
                [
                    VerticalScroll(
                        *[
                            Horizontal(
                                Static(
                                    self._catalog_line(pack),
                                    classes="ai_topup_pack_details",
                                ),
                                Button(
                                    "Choose",
                                    id=f"btn_topup_{index}",
                                    variant="primary",
                                ),
                                classes="ai_topup_pack",
                            )
                            for index, pack in enumerate(self._packs)
                        ],
                        *(
                            [Button("Open billing", id="btn_topup_billing", variant="default")]
                            if self._show_billing_action else []
                        ),
                        id="ai_topup_catalog",
                    )
                ]
                if self._packs or self._show_billing_action else []
            ),
            Vertical(
                Button("Cancel", id="btn_topup_cancel", variant="default"),
                id="ai_topup_cancel",
            ),
        ])
        yield Container(*children, id="ai_topup_container")
        yield Footer()

    @staticmethod
    def _button_label(pack: Any) -> str:
        """Return the short, safe action label for a server pack."""
        raw_label = getattr(pack, "label", getattr(pack, "key", ""))
        return escape(safe_terminal_text(raw_label))

    @classmethod
    def _catalog_line(cls, pack: Any) -> str:
        """Return one readable, sanitized pack price and credit line."""
        label = cls._button_label(pack)
        price = escape(safe_terminal_text(getattr(pack, "display_price", "")))
        credit = escape(safe_terminal_text(getattr(pack, "display_credit", "")))
        details = " · ".join(
            part for part in (price, f"adds {credit}" if credit else "") if part
        )
        return f"[bold]{label}[/bold] — {details}" if details else label

    @classmethod
    def _catalog_text(cls, packs: Sequence[Any]) -> str:
        """Return all readable, sanitized catalog rows for non-UI consumers."""
        return "\n".join(cls._catalog_line(pack) for pack in packs)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "btn_topup_cancel":
            self.dismiss(None)
            return
        if button_id == "btn_topup_billing":
            self.dismiss(self.BILLING_ACTION)
            return
        if button_id.startswith("btn_topup_"):
            try:
                pack = self._packs[int(button_id.removeprefix("btn_topup_"))]
            except (IndexError, ValueError):
                return
            self.dismiss(pack.key)

    def action_dismiss_none(self) -> None:
        self.dismiss(None)


__all__ = ["AITopUpModal"]
