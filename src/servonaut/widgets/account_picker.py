"""Account picker for screens that work on one provider account at a time.

A labelled ``Select`` of a provider's accounts, laid out like the other
filter columns (``Vertical(Label, Select)``). It hides itself when the
provider has a single account, so screens look exactly as they did before
extra accounts existed until a second account is configured.
"""

from __future__ import annotations

from typing import List, Optional, Sequence

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.message import Message
from textual.widgets import Label, Select

from servonaut.config.accounts import AccountRef


class AccountPicker(Vertical):
    """Pick one account of a provider.

    Posts :class:`AccountPicker.Changed` with the chosen label whenever the
    selection changes (never on the initial value).
    """

    DEFAULT_CSS = """
    AccountPicker {
        width: auto;
        min-width: 18;
        height: auto;
    }
    AccountPicker > Select {
        width: 24;
    }
    """

    class Changed(Message):
        """The chosen account changed."""

        def __init__(self, picker: "AccountPicker", account: str) -> None:
            super().__init__()
            self.picker = picker
            self.account = account

        @property
        def control(self) -> "AccountPicker":
            return self.picker

    def __init__(
        self,
        accounts: Sequence[AccountRef],
        *,
        value: Optional[str] = None,
        label: str = "Account",
        id: Optional[str] = None,  # noqa: A002 - Textual's widget id
        classes: Optional[str] = None,
    ) -> None:
        super().__init__(id=id, classes=classes)
        self._accounts: List[AccountRef] = list(accounts)
        self._label = label
        wanted = (value or "").lower()
        self._value = next(
            (ref.label for ref in self._accounts if ref.key == wanted),
            self._accounts[0].label if self._accounts else "",
        )
        self.display = len(self._accounts) > 1

    @classmethod
    def for_provider(
        cls, registry, provider: str, *, value: Optional[str] = None,
        id: Optional[str] = None,  # noqa: A002 - Textual's widget id
    ) -> "AccountPicker":
        """A picker over *provider*'s usable accounts (empty without a registry)."""
        accounts = registry.accounts(provider) if registry is not None else []
        return cls(accounts, value=value, id=id)

    @property
    def account(self) -> str:
        """The chosen account's label ("" when the provider has none)."""
        return self._value

    @property
    def accounts(self) -> List[AccountRef]:
        return list(self._accounts)

    def compose(self) -> ComposeResult:
        yield Label(self._label)
        yield Select(
            [(ref.label, ref.label) for ref in self._accounts],
            value=self._value if self._accounts else Select.NULL,
            allow_blank=not self._accounts,
            id=f"{self.id}_select" if self.id else None,
            # A hidden widget still counts as focusable (Textual checks
            # visibility, not display), so a picker with nothing to choose
            # would take the screen's first focus from its real controls.
            disabled=len(self._accounts) <= 1,
        )

    def on_select_changed(self, event: Select.Changed) -> None:
        event.stop()
        value = event.value
        if value is Select.NULL or not isinstance(value, str) or value == self._value:
            return
        self._value = value
        self.post_message(self.Changed(self, value))
