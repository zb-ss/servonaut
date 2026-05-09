"""Provider-aware action bar for :class:`InstanceListScreen`.

Renders horizontally above the instance table. Buttons enable/disable
based on the *active provider* — i.e. the provider all currently
filtered rows belong to. The screen decides what to do when a button
fires by listening for the bar's messages.

Design:

* The bar is dumb. It does not know about Hetzner/OVH/AWS specifics —
  it just tracks ``active_provider`` and dispatches messages tagged
  with that provider so the screen can route to the correct wizard.
* Creatable providers (those with a working "+ New" wizard) are kept
  in :data:`_CREATE_SUPPORTED`. Adding GCP/Azure later means: implement
  the wizard, then add the provider name here.
* AWS and "custom" servers don't have create wizards (AWS uses the
  console, custom servers are added via Settings) — for those the
  button is shown disabled with an explanatory hint, not hidden.
"""

from __future__ import annotations

from typing import Optional, Set

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.message import Message
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Button, Static


_CREATE_SUPPORTED: Set[str] = {"hetzner", "ovh"}


class ProviderActionBar(Widget):
    """Action bar that follows the active filter on the instance list.

    Message flow:

    1. ``InstanceListScreen`` recomputes the active provider on every
       filter change and assigns ``self.active_provider``.
    2. ``watch_active_provider`` updates button enabled state and the
       hint label.
    3. On click, the bar emits :class:`NewInstanceRequested` carrying
       the resolved provider so the screen can ``push_screen`` the
       matching wizard.
    """

    DEFAULT_CSS = """
    ProviderActionBar {
        height: 3;
        background: $surface;
    }
    ProviderActionBar > Horizontal {
        height: 1fr;
        align: left middle;
        padding: 0 1;
    }
    ProviderActionBar Button {
        margin-right: 1;
        min-width: 12;
    }
    ProviderActionBar #action_hint {
        margin-left: 1;
        color: $text-muted;
    }
    """

    active_provider: reactive[str] = reactive("")

    class NewInstanceRequested(Message):
        """Fired when the user clicks ``+ New``.

        ``provider`` is the lowercase provider keyword (``hetzner``,
        ``ovh``, ...) inferred from the active filter, or empty when no
        creatable provider is currently active.
        """

        def __init__(self, provider: str) -> None:
            super().__init__()
            self.provider = provider

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Button("+ New", id="action_new", disabled=True)
            yield Static(
                "[dim]Filter to a provider to enable actions[/dim]",
                id="action_hint",
            )

    def watch_active_provider(self, provider: str) -> None:
        try:
            btn_new = self.query_one("#action_new", Button)
            hint = self.query_one("#action_hint", Static)
        except Exception:
            # Widget not mounted yet — watcher fires once before compose.
            return
        provider = (provider or "").lower()
        if not provider:
            btn_new.disabled = True
            hint.update("[dim]Filter to a provider to enable actions[/dim]")
        elif provider in _CREATE_SUPPORTED:
            btn_new.disabled = False
            hint.update(
                f"[dim]Active provider:[/dim] [b]{provider}[/b]"
            )
        else:
            btn_new.disabled = True
            hint.update(
                f"[dim]Active provider:[/dim] [b]{provider}[/b] "
                f"[dim](no create wizard)[/dim]"
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "action_new":
            event.stop()
            self.post_message(self.NewInstanceRequested(self.active_provider))


def infer_provider(instances: list) -> Optional[str]:
    """Return the lowercase provider name if every instance shares one.

    Returns ``None`` when the list is empty (caller chooses how to
    represent "no filter context") or when more than one provider is
    represented.

    Provider resolution:

    * Each instance dict uses the ``provider`` key (``"hetzner"``,
      ``"ovh"``, ``"aws"``, custom...).
    * Instances without a ``provider`` key are AWS by convention (the
      AWS path predates the multi-provider field).
    """
    providers = {
        (inst.get("provider") or "aws").lower()
        for inst in instances
    }
    if len(providers) == 1:
        return next(iter(providers))
    return None
