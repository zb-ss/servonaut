"""Top-up pack picker modal (T8).

Brief blocking choice between three top-up packs. The caller (chat
panel quota_exhausted / budget_exhausted handler, or
``servonaut ai topup`` CLI) awaits the dismiss return value:

- ``"small" | "medium" | "large"`` — the user picked a pack; caller
  invokes ``ServonautProvider.topup_checkout(pack)`` and opens the
  returned ``checkout_url`` in the browser.
- ``None`` — the user cancelled / pressed Escape.

Per CLAUDE.md ModalScreen rule: this fits the brief-blocking-choice
pattern. Multi-button row, single decision, no content beyond pack
descriptions.
"""
from __future__ import annotations

from typing import Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Header, Static


# Pack labels — server is authoritative on dollar amount + token count;
# we display rough guidance only. Update if the backend pricing tier
# changes; out-of-date copy is purely cosmetic (server returns the
# correct checkout_url regardless).
_PACK_LABELS = {
    "small":  ("Small",  "≈ 1M tokens"),
    "medium": ("Medium", "≈ 5M tokens"),
    "large":  ("Large",  "≈ 20M tokens"),
}


class AITopUpModal(ModalScreen[Optional[str]]):
    """Pack picker for ``POST /api/ai/topup/checkout``.

    Args:
        prefill_pack: Optional pack name to pre-highlight (caller may
            pass it from a CLI ``--pack`` flag). Currently informational
            only — the modal always shows all three options.
        reason: Optional context string rendered above the buttons.
            Use cases: ``"Out of monthly tokens"``,
            ``"Budget hard cap reached"``. Plain string — escaped before
            interpolation.

    Returns via ``dismiss``:
        - One of ``"small"`` / ``"medium"`` / ``"large"`` on a pack pick.
        - ``None`` if the user dismissed without choosing.
    """

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

    AITopUpModal #ai_topup_buttons {
        height: auto;
        align: center middle;
    }

    AITopUpModal #ai_topup_buttons Button {
        margin: 0 1;
        width: 18;
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
    ) -> None:
        super().__init__()
        # ``prefill_pack`` is currently informational; reserved for a
        # future "highlight the suggested pack" affordance once the
        # server tells us which pack matches the user's burn rate.
        self._prefill_pack = prefill_pack
        self._reason = (reason or "").strip()

    def compose(self) -> ComposeResult:
        yield Header()
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
        children.extend([
            Static(
                "Pick a pack to open Stripe Checkout in your browser. "
                "Top-up tokens stack on top of your monthly quota and never "
                "expire while your subscription is active.",
                id="ai_topup_body",
            ),
            Horizontal(
                Button(
                    self._button_label("small"),
                    id="btn_topup_small",
                    variant="primary",
                ),
                Button(
                    self._button_label("medium"),
                    id="btn_topup_medium",
                    variant="primary",
                ),
                Button(
                    self._button_label("large"),
                    id="btn_topup_large",
                    variant="primary",
                ),
                id="ai_topup_buttons",
            ),
            Vertical(
                Button("Cancel", id="btn_topup_cancel", variant="default"),
                id="ai_topup_cancel",
            ),
        ])
        yield Container(*children, id="ai_topup_container")
        yield Footer()

    @staticmethod
    def _button_label(pack: str) -> str:
        name, hint = _PACK_LABELS.get(pack, (pack.title(), ""))
        if hint:
            return f"{name}\n[dim]{hint}[/dim]"
        return name

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        mapping = {
            "btn_topup_small": "small",
            "btn_topup_medium": "medium",
            "btn_topup_large": "large",
        }
        pack = mapping.get(button_id)
        if pack is not None:
            self.dismiss(pack)
        elif button_id == "btn_topup_cancel":
            self.dismiss(None)

    def action_dismiss_none(self) -> None:
        self.dismiss(None)


__all__ = ["AITopUpModal"]
