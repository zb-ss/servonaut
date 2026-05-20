"""First-connect memory-build prompt banner widget (T11).

Shown once per session per instance on the InstanceListScreen after the
user's first successful SSH connect for that server.  A single keystroke
(``y``) dispatches a background ``MemoryService.build`` for the current
instance; any other key (or the dismiss button) hides the banner and
increments ``AppConfig.memory_first_connect_dismissed_count``.

After three dismissals the app-wide counter suppresses this banner even
on first connects until ``memory reset-prompts`` resets it.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.events import Key
from textual.widget import Widget
from textual.widgets import Button, Static

logger = logging.getLogger(__name__)


# Hard ceiling on the dismiss counter.  Exposed as a module-level constant so
# tests (and the reset-prompts CLI command) can reference it directly.
MAX_DISMISSALS: int = 3


class MemoryPrompt(Widget):
    """Small inline banner offering to probe memory for a newly-connected server.

    Args:
        instance: Instance dict (id, name, provider, ...) to probe when
            the user accepts.
    """

    DEFAULT_CSS = """
    MemoryPrompt {
        height: auto;
        min-height: 3;
        padding: 0 1;
        background: $primary 20%;
        border: round $accent;
        margin: 0 1;
    }
    MemoryPrompt Horizontal {
        height: auto;
        align: left middle;
    }
    MemoryPrompt #memory_prompt_label {
        width: 1fr;
        content-align: left middle;
    }
    MemoryPrompt #memory_prompt_accept {
        margin-right: 1;
    }
    MemoryPrompt.hidden {
        display: none;
    }
    """

    BINDINGS = [
        Binding("y", "accept", "Build memory", show=True),
        Binding("n", "dismiss_banner", "Not now", show=True),
        Binding("escape", "dismiss_banner", "Dismiss", show=False),
    ]

    can_focus = True

    def __init__(self, instance: Dict[str, Any]) -> None:
        super().__init__()
        self._instance = instance

    def _label_markup(self) -> str:
        """Build the Rich-markup body used in the banner label.

        Exposed as a method so tests can verify markup-injection safety
        without mounting the widget inside a Textual pilot app.
        """
        name = self._instance.get("name") or self._instance.get("id", "server")
        # Rich markup escape — instance names come from user/cloud data and
        # must never be interpolated into markup verbatim.
        return (
            f"[b]Build memory[/b] for [cyan]{escape(str(name))}[/cyan]?  "
            "Press [bold yellow]y[/bold yellow] to probe, [bold]n[/bold] to dismiss."
        )

    def compose(self) -> ComposeResult:
        yield Horizontal(
            Static(self._label_markup(), id="memory_prompt_label"),
            Button("y. Build", variant="primary", id="memory_prompt_accept"),
            Button("n. Dismiss", variant="default", id="memory_prompt_dismiss"),
            id="memory_prompt_row",
        )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_accept(self) -> None:
        """Dispatch a memory build worker for this instance."""
        self._dispatch_build()
        self._hide()

    def action_dismiss_banner(self) -> None:
        """Hide the banner and increment the dismissed counter."""
        self._increment_dismissal()
        self._hide()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "memory_prompt_accept":
            self.action_accept()
        elif event.button.id == "memory_prompt_dismiss":
            self.action_dismiss_banner()

    def on_key(self, event: Key) -> None:
        """Swallow single-char 'y'/'n' keys so the banner handles them.

        Without this override the bindings don't fire when the host screen's
        DataTable has focus; we explicitly consume the event here.
        """
        if event.character == "y":
            self.action_accept()
            event.stop()
        elif event.character == "n":
            self.action_dismiss_banner()
            event.stop()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _dispatch_build(self) -> None:
        app = self.app
        memory_service = getattr(app, "memory_service", None)
        if memory_service is None:
            app.notify("Memory service not available.", severity="warning")
            return
        instance = self._instance
        name = instance.get("name") or instance.get("id", "server")

        async def _run_build() -> None:
            try:
                await memory_service.build(instance)
                app.notify(f"Memory probed for {name}.")
            except (OSError, RuntimeError, ValueError) as exc:
                logger.warning("First-connect build failed for %s: %s", name, exc)
                app.notify(f"Memory probe failed: {exc}", severity="error")

        # Spawn the worker on the *app*, not on this widget. The caller
        # (action_accept) immediately hides the banner with self.remove(),
        # which would cancel any worker owned by this widget — meaning
        # the build silently never runs. Owning the worker on the app
        # outlives the banner removal. Distinct group so this worker
        # never cancels the user's in-flight refresh/export operations
        # on the memory screen.
        app.run_worker(
            _run_build(),
            exclusive=False,
            group="memory_first_connect",
            name=f"memory_build_{instance.get('id') or name}",
        )

    def _increment_dismissal(self) -> None:
        app = self.app
        cfg_mgr = getattr(app, "config_manager", None)
        if cfg_mgr is None:
            return
        try:
            config = cfg_mgr.get()
            current = int(
                getattr(config, "memory_first_connect_dismissed_count", 0) or 0
            )
            config.memory_first_connect_dismissed_count = min(
                current + 1, MAX_DISMISSALS
            )
            cfg_mgr.save(config)
        except (OSError, AttributeError) as exc:
            logger.debug("Could not persist dismissed count: %s", exc)

    def _hide(self) -> None:
        self.add_class("hidden")
        # Remove from DOM so subsequent _render passes don't re-query a
        # dismissed widget.
        try:
            self.remove()
        except Exception:  # noqa: BLE001 — remove() can race on shutdown
            pass


def should_show_first_connect_prompt(config: Any) -> bool:
    """Return True when the first-connect banner should be shown.

    Gating rules:
        * Memory must be globally enabled (``config.memory.enabled``).
        * The dismissed counter must be below :data:`MAX_DISMISSALS`.

    This is the *global* gate only. Per-instance gating (does this server
    already have recent memory?) is handled separately by
    :func:`memory_needs_reprompt`.

    Args:
        config: The ``AppConfig`` instance.
    """
    if config is None:
        return False
    memory_cfg = getattr(config, "memory", None)
    if memory_cfg is not None and getattr(memory_cfg, "enabled", True) is False:
        return False
    count = int(getattr(config, "memory_first_connect_dismissed_count", 0) or 0)
    return count < MAX_DISMISSALS


def memory_needs_reprompt(
    age_seconds: Optional[float], reprompt_after_seconds: int
) -> bool:
    """Return ``True`` when a server warrants the first-connect banner.

    Keeps the banner from nagging on every SSH connect: a server is only
    prompted when it has no memory at all, or its snapshot has aged past
    *reprompt_after_seconds*.

    Args:
        age_seconds: Age of the newest probe in seconds, or ``None`` when the
            server has no memory yet.
        reprompt_after_seconds: Re-prompt threshold in seconds — memory older
            than this (or absent entirely) warrants another prompt.
    """
    if age_seconds is None:
        return True
    return age_seconds > reprompt_after_seconds
