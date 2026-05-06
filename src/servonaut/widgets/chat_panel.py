"""Chat panel widget mounted as a sidebar on the active screen.

Wave-3 additions (T5/T6/T8/T10):

- Servonaut-AI streaming routing via :meth:`_do_send_servonaut`. Routes
  user prompts through ``app.servonaut_provider.stream_chat`` when the
  active provider (per :class:`ProviderPreferenceResolver`) is
  ``"servonaut"``; falls back to the existing chat-service path for
  user-keyed providers (OpenAI / Anthropic / Ollama / Gemini).

- Quota footer + provider header indicator. The footer reads from
  ``app.auth_service`` cached :class:`AIQuota`; the header indicator
  shows S/O/A/G/L for the active provider.

- T5 error matrix routing through
  :func:`ai_error_handler.map_error_to_action`: each error code drives
  a deterministic toast / modal / banner UX action.

- T6 tool-bridge driver: stream events of type ``tool_call`` are dispatched
  through ``app.ai_tool_bridge``, with confirm modals (single-y/n
  for ``standard``; typed-RUN for ``dangerous``) sized by guard level.

- T8 top-up flow: ``MODAL_QUOTA_EXHAUSTED`` and
  ``MODAL_BUDGET_EXHAUSTED`` actions push :class:`AITopUpModal`; on a
  pack pick we call ``ServonautProvider.topup_checkout``, open the URL
  via :func:`webbrowser.open`, then schedule
  ``auth.schedule_post_topup_refresh()``.

- T10 second-upstream-unavailable watcher tracks the timestamps of
  ``upstream_unavailable`` errors; on the second hit within 60s we
  either auto-fall-back (when ``ai.local_fallback_provider`` is set)
  or push :class:`AIFallbackPromptModal`.

The Wave-2 ``_do_send`` path remains as the entry point — it dispatches
to ``_do_send_servonaut`` only when the resolver picks Servonaut.
"""

from __future__ import annotations

import logging
import time
import webbrowser
from typing import Any, Dict, List, Optional, Tuple

from rich.markup import escape as _rich_escape
from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal, VerticalScroll
from textual.widget import Widget
from textual.widgets import Button, Input, Label, Static, TextArea

# D6 — module-level ``logger`` placed AFTER all imports so static analysers
# can verify import ordering and lint rules don't flag the gap.
logger = logging.getLogger(__name__)


# Minimal AI Logo (Matches Website)
SERVONAUT_LOGO = (
    "[bold bright_cyan]🖧[/]  [bold]Servonaut AI Assistant[/]\n"
    "   [bold bright_green]●[/] [dim bright_green]MCP Server Online[/]"
)

# Inline bot marker for assistant messages
BOT_MARKER = "[bold bright_cyan]\u25c9[/]"

# T10 watcher: the second ``upstream_unavailable`` within this window
# triggers either an auto-fallback (when ``ai.local_fallback_provider``
# is set) or the :class:`AIFallbackPromptModal`. Per architect plan
# \u00a7T10 invariants.
_UPSTREAM_FAILURE_WINDOW_S = 60.0

# Single-character provider indicator (Risk register \u00a79). Mirrors
# Servonaut/OpenAI/Anthropic/Gemini/oLlama. Unknown providers render '?'.
# Per-session provider indicator — shown on the header button users
# click to change provider for this chat only. The leading ▾ is a
# safe geometric glyph (U+25BE, no VS16 variant) signalling "click
# to pick"; full names beat the old S/O/A/G/L letters for
# discoverability without overflowing the 12-char button min-width.
_PROVIDER_INDICATORS = {
    "servonaut": "▾ Servonaut",
    "openai":    "▾ OpenAI",
    "anthropic": "▾ Anthropic",
    "gemini":    "▾ Gemini",
    "ollama":    "▾ Ollama",
}
_PROVIDER_INDICATOR_DEFAULT = "▾ Provider"


class ChatPanel(Widget):
    """Right-docked sidebar for chatting with the Servonaut DevOps assistant."""

    # Debounce: stale_modules results cached 2 seconds per (instance_id, provider) key.
    _STALE_CACHE_TTL = 2.0

    def __init__(self, **kwargs) -> None:
        super().__init__(id="chat-panel", **kwargs)
        self._session = None  # type: Optional[object]
        self._thinking = False
        self._total_tokens = 0
        self._total_cost = 0.0
        self._model = ""
        # Cache for stale module lookups: key → (timestamp, result)
        self._stale_cache: Dict[tuple, tuple] = {}

        # Wave-3 (T10) — upstream-unavailable watcher state. Stores
        # monotonic timestamps of every ``upstream_unavailable`` event;
        # pruned to the trailing 60s window on every check.
        self._upstream_failures: List[float] = []
        # Session-only provider override (T10 fallback prompt result).
        # NOT persisted — does not mutate ``ai.provider_preference``.
        self._session_provider_override: Optional[str] = None
        # Last seen quota / fallback flags from a usage event (rendered
        # in the chat-stats line).
        self._last_fallback_used: bool = False
        self._last_soft_capped: bool = False
        # Per-turn counter — incremented for every ``tool_call`` SSE
        # event the server emits during the current turn. Used by
        # :meth:`_finalise_servonaut_turn` to write a more informative
        # fallback when ``accumulated`` is empty (model emitted only
        # tool calls and the server's continuation never produced
        # follow-up text).
        self._turn_tool_calls: int = 0
        self._last_hard_capped: bool = False
        # Track which conversation we're streaming for (Servonaut path).
        self._remote_conversation_id: Optional[str] = None
        # B1 — pinned-error state. When the provider resolver decides
        # there's no usable provider (lapsed sub + nothing else
        # configured), we disable the input and render a banner with
        # /Resubscribe/ + /Add a provider/ buttons. Cleared the moment
        # the resolver returns a healthy provider again.
        self._pinned_error_active: bool = False
        # B2 — one-shot modal push state per session. Once we've shown
        # the first-run / empty-state modal we don't reshow it on
        # subsequent ``_check_provider_decision_events`` calls.
        self._first_run_modal_shown: bool = False
        self._empty_state_modal_shown: bool = False

    def compose(self) -> ComposeResult:
        with Vertical(id="chat-inner"):
            # Header with logo and controls
            with Vertical(id="chat-header"):
                yield Static(SERVONAUT_LOGO, id="chat-logo")
                with Horizontal(id="chat-controls"):
                    yield Button("New Chat", id="btn-chat-new", classes="chat-btn")
                    yield Button("History", id="btn-chat-history", classes="chat-btn")
                    # Per-session provider indicator (S/O/A/G/L). Click
                    # to open the picker and override for this session
                    # only — does NOT mutate ai.provider_preference.
                    yield Button(
                        _PROVIDER_INDICATOR_DEFAULT,
                        id="btn-chat-provider",
                        classes="chat-btn",
                    )
                    yield Button("Close", id="btn-chat-close", classes="chat-btn error")
            # Session history list (hidden by default)
            with VerticalScroll(id="chat-history-list", classes="hidden"):
                yield Static("[dim]No saved chats[/dim]", id="chat-history-empty")
            # Stale-memory banner (hidden until staleness detected)
            yield Static("", id="chat-memory-banner", classes="hidden")
            # T4.5 / T10 banner (paying-twice / capability / upstream flaky).
            # Hidden until the resolver / watcher emits a banner event.
            yield Static("", id="chat-banner", classes="hidden")
            # B1 — pinned-error banner: shown when the resolver can't pick
            # a usable provider (lapsed sub + nothing else configured).
            # Two buttons inside a Horizontal so users can resubscribe or
            # open Settings without leaving the chat panel. Hidden until
            # PINNED_ERROR_NO_PROVIDER fires.
            with Horizontal(id="chat-pinned-error-banner", classes="hidden"):
                yield Static(
                    "[red]Servonaut AI subscription ended and no other "
                    "provider is configured.[/red]\n"
                    "Resubscribe or add an OpenAI / Anthropic / Gemini / "
                    "Ollama provider to keep chatting.",
                    id="chat-pinned-error-text",
                )
                yield Button(
                    "Resubscribe",
                    id="btn-pinned-resubscribe",
                    variant="primary",
                )
                yield Button(
                    "Add a provider",
                    id="btn-pinned-add-provider",
                )
            # Message area
            yield VerticalScroll(id="chat-messages")
            # Stats bar
            yield Static("", id="chat-stats")
            # Quota footer (T3) — Servonaut-only; hidden for user-keyed providers.
            yield Static("", id="chat-quota-footer", classes="hidden")
            # Input row
            with Horizontal(id="chat-input-row"):
                yield TextArea("", id="chat-input", soft_wrap=True, tab_behavior="focus")
                yield Button("➤", id="btn-chat-send", variant="primary")

    def on_mount(self) -> None:
        """Load or create a chat session when mounted."""
        self._start_or_resume_session()
        self._update_stats()
        self._update_memory_banner()
        # Wave-3: render banners (paying-twice / capability) and update
        # provider indicator once the panel is composed.
        self._check_provider_decision_events()
        self._update_provider_indicator()
        self._update_quota_footer()

    def focus_input(self) -> None:
        """Focus the chat input field."""
        self.call_after_refresh(self._do_focus_input)

    def _do_focus_input(self) -> None:
        try:
            self.query_one("#chat-input", TextArea).focus()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Focus failed on chat input", exc_info=True)
        self._update_memory_banner()

    # ------------------------------------------------------------------
    # Memory banner + instance resolution
    # ------------------------------------------------------------------

    def _parse_at_prefix(self, text: str) -> Tuple[Optional[dict], str]:
        """Extract an ``@<id-or-name>`` prefix from *text*.

        If the first whitespace-delimited token starts with ``@``, the token
        (without the ``@``) is looked up via ``self.app.resolve_instance``.
        The prefix is stripped from the returned text only when a match is
        found.

        Args:
            text: Raw input string from the chat input field.

        Returns:
            Tuple of (instance_dict_or_None, effective_text).
        """
        parts = text.split(None, 1)
        if not parts or not parts[0].startswith("@"):
            return None, text
        token = parts[0][1:]  # strip leading @
        rest = parts[1] if len(parts) > 1 else ""
        try:
            resolve = getattr(self.app, "resolve_instance", None)
            if resolve is not None:
                inst = resolve(token)
            else:
                # Fallback: linear scan of self.app.instances
                needle = token.lower()
                inst = next(
                    (
                        i for i in getattr(self.app, "instances", [])
                        if (
                            i.get("id", "").lower() == needle
                            or i.get("name", "").lower() == needle
                        )
                    ),
                    None,
                )
        except Exception:
            return None, text
        if inst is None:
            return None, text
        return inst, rest

    def _resolve_active_instance(self, text: str) -> Tuple[Optional[dict], str]:
        """Determine the active instance and strip any ``@`` prefix from text.

        Resolution order:
        1. ``@<token>`` prefix in *text* → ``_parse_at_prefix``.
        2. ``InstanceTable.get_selected_instance()`` on the current screen.

        Args:
            text: Raw input string.

        Returns:
            Tuple of (instance_dict_or_None, text_to_send).
        """
        inst, stripped = self._parse_at_prefix(text)
        if inst is not None:
            return inst, stripped

        # Fallback 1: selected row in the instance table
        try:
            from servonaut.widgets.instance_table import InstanceTable
            table = self.app.screen.query_one(InstanceTable)
            selected = table.get_selected_instance()
            if selected:
                return selected, text
        except Exception:
            pass

        # Fallback 2: screen's own _instance attribute (e.g. ServerActionsScreen)
        try:
            screen_instance = getattr(self.app.screen, "_instance", None)
            if screen_instance is not None:
                return screen_instance, text
        except Exception:
            pass

        return None, text

    def _update_memory_banner(self) -> None:
        """Show or hide the stale-memory banner based on the current instance."""
        try:
            banner = self.query_one("#chat-memory-banner", Static)
        except Exception:
            return

        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            banner.add_class("hidden")
            return

        # Resolve instance without consuming input text (use empty string for prefix check)
        inst, _ = self._resolve_active_instance("")
        if inst is None:
            banner.add_class("hidden")
            return

        instance_id = inst.get("id") or ""
        instance_name = inst.get("name") or ""
        provider = inst.get("provider") or "custom"

        try:
            config = self.app.config_manager.get()
            config_memory = getattr(config, "memory", None)
        except Exception:
            banner.add_class("hidden")
            return

        if config_memory is None or not config_memory.enabled:
            banner.add_class("hidden")
            return

        # Check by both id and name so name-based overrides fire correctly.
        if config_memory.is_instance_disabled(instance_id, instance_name):
            banner.add_class("hidden")
            return

        # Detect the "no memory yet" case first — this is the user's most
        # common trip-up: they ask a question about a server the agent has
        # never probed, and the chat answers blind.  Offer a one-click build.
        try:
            stored_modules = memory_service.get_all_modules(instance_id, provider)
        except Exception:
            stored_modules = {}
        if not stored_modules:
            banner.update(
                f"[cyan]🧠 No memory yet for[/cyan] "
                f"[bold]{_rich_escape(instance_id)}[/bold]. "
                f"Build one and I can answer instantly without SSH round-trips. "
                f"[@click=action_build_memory]Build now[/]"
            )
            banner.remove_class("hidden")
            return

        cache_key = (instance_id, provider)
        now = time.monotonic()
        cached = self._stale_cache.get(cache_key)
        if cached is not None and (now - cached[0]) < self._STALE_CACHE_TTL:
            stale = cached[1]
        else:
            try:
                stale = memory_service.stale_modules(instance_id, provider)
            except Exception:
                banner.add_class("hidden")
                return
            self._stale_cache[cache_key] = (now, stale)

        if not stale:
            banner.add_class("hidden")
            return

        module_list = ", ".join(_rich_escape(m) for m in stale)
        banner.update(
            f"[yellow]Memory is stale for[/yellow] [bold]{_rich_escape(instance_id)}[/bold] "
            f"(modules: {module_list}). "
            f"[@click=action_refresh_memory]Refresh[/]"
        )
        banner.remove_class("hidden")

    def action_refresh_memory(self) -> None:
        """Refresh stale memory for the currently active instance."""
        inst, _ = self._resolve_active_instance("")
        if inst is None:
            self.app.notify("No active instance selected.", severity="warning")
            return
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            return
        self.run_worker(
            memory_service.refresh(inst),
            name="chat_memory_refresh",
        )

    def action_build_memory(self) -> None:
        """Build memory from scratch for the current instance.

        Triggered from the "No memory yet" banner.  Shares the refresh
        worker group so only one memory probe per chat session runs at a
        time, and clears the stale cache on completion so the banner
        updates to green without waiting for the next render tick.
        """
        inst, _ = self._resolve_active_instance("")
        if inst is None:
            self.app.notify("No active instance selected.", severity="warning")
            return
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            return
        name = inst.get("name") or inst.get("id") or "server"
        self.app.notify(f"🧠 Building memory for {name}…")

        async def _build_then_refresh() -> None:
            try:
                if hasattr(memory_service, "build_report"):
                    report = await memory_service.build_report(inst)
                    if report.has_any_success:
                        self.app.notify(
                            f"Memory built for {name}: {report.count} modules."
                        )
                    else:
                        self.app.notify(
                            f"Memory build failed for {name} "
                            f"({report.overall_reason or 'unknown'}). "
                            "Check SSH connectivity.",
                            severity="warning",
                        )
                else:
                    await memory_service.refresh(inst)
                    self.app.notify(f"Memory built for {name}.")
            except Exception as exc:  # noqa: BLE001
                self.app.notify(
                    f"Memory build failed for {name}: {exc}",
                    severity="error",
                )
            finally:
                self._stale_cache.clear()
                self._update_memory_banner()

        self.run_worker(
            _build_then_refresh(),
            name="chat_memory_build",
            group="memory_refresh",
        )

    # ------------------------------------------------------------------
    # Welcome & stats
    # ------------------------------------------------------------------

    def _show_welcome(self) -> None:
        """Show a welcome message if the session is empty."""
        if self._session is None or len(self._session.messages) > 0:  # type: ignore[union-attr]
            return
        container = self.query_one("#chat-messages", VerticalScroll)
        welcome = Static(
            f"{BOT_MARKER} [bold]Servonaut[/bold]\n\n"
            "Hello! I'm your DevOps assistant. I can help with:\n\n"
            "[dim]\u2022[/dim] Server management & SSH issues\n"
            "[dim]\u2022[/dim] AWS operations & troubleshooting\n"
            "[dim]\u2022[/dim] Log analysis & debugging\n"
            "[dim]\u2022[/dim] Networking & security questions\n"
            "[dim]\u2022[/dim] CI/CD pipelines & containerization\n\n"
            "I can also [bold]interact with your servers directly[/bold] \u2014\n"
            "list instances, check status, run commands, and view logs.\n\n"
            "[dim italic]Type a message below to get started.[/dim italic]",
            classes="chat-message-assistant chat-welcome",
        )
        container.mount(welcome)

    def _update_stats(self) -> None:
        """Update the token/cost stats bar.

        Wave-3 additions:
        - ``[dim]via backup vendor[/dim]`` suffix when ``fallback_used``
          was true on the last usage event (T10 acceptance criterion).
        - Soft / hard cap badges via :func:`format_soft_cap_badge`.
        - Tools-disabled note when active provider != servonaut so the
          user knows why the tools panel is hidden.
        """
        try:
            stats_widget = self.query_one("#chat-stats", Static)
        except Exception:
            return

        if self._model:
            parts = [f"[dim]Model:[/dim] [bold]{self._model}[/bold]"]
        else:
            parts = [f"[dim]Model:[/dim] [dim italic]not configured[/dim italic]"]

        if self._total_tokens > 0:
            parts.append(f"[dim]Tokens:[/dim] {self._total_tokens:,}")
        if self._total_cost > 0:
            parts.append(f"[dim]Cost:[/dim] ${self._total_cost:.4f}")

        msg_count = 0
        if self._session is not None:
            msg_count = len(self._session.messages)  # type: ignore[union-attr]
        parts.append(f"[dim]Messages:[/dim] {msg_count}")

        # T10 \u2014 fallback-used badge. Only render after we've seen at
        # least one ``usage`` event flagged ``fallback_used: true``.
        if self._last_fallback_used:
            parts.append("[dim]via backup vendor[/dim]")

        # T7 acceptance \u2014 soft / hard cap badges via formatter helper.
        # Lazy import keeps the chat panel import cost low for users
        # who never authenticate.
        try:
            from servonaut.utils.formatting import format_soft_cap_badge
            # D3 — pass the latest usage.model so the badge reads
            # "downgraded to <actual-model>" rather than hardcoding "Flash".
            badge = format_soft_cap_badge(
                self._last_soft_capped,
                self._last_hard_capped,
                model=self._model or None,
            )
            if badge:
                colour = "red" if self._last_hard_capped else "yellow"
                parts.append(f"[{colour}]{_rich_escape(badge)}[/{colour}]")
        except Exception:  # pragma: no cover \u2014 defensive
            pass

        # Capability note \u2014 tools require Servonaut AI. Drives the
        # T4.5 acceptance "tools panel hidden / greyed when active
        # provider != servonaut".
        active_provider = self._active_provider_name()
        if active_provider and active_provider != "servonaut":
            parts.append("[dim italic]Tool execution requires Servonaut AI.[/dim italic]")

        stats_widget.update("  \u2502  ".join(parts))
        # Update the quota footer + provider indicator in lockstep so a
        # call from the streaming consumer doesn't leave them out of sync.
        self._update_quota_footer()
        self._update_provider_indicator()

    # ------------------------------------------------------------------
    # Wave-3 helpers — provider selection, quota, banners, T10 watcher
    # ------------------------------------------------------------------

    def _active_provider_name(self) -> str:
        """Resolve the provider name we should route the current turn through.

        Order:
          1. Session-only override (T10 fallback prompt result).
          2. :class:`ProviderPreferenceResolver` decision.
          3. Config-file preference / fallthrough.
          4. ``"servonaut"`` if entitled, else ``""``.
        """
        if self._session_provider_override:
            return self._session_provider_override

        resolver = getattr(self.app, "provider_preference_resolver", None)
        if resolver is not None:
            try:
                decision = resolver.resolve()
                return decision.active_provider or ""
            except Exception:
                logger.debug("provider_preference_resolver.resolve() failed", exc_info=True)

        # Fallback: read config + auth directly.
        try:
            cfg = self.app.config_manager.get().ai_provider
            preference = getattr(cfg, "provider_preference", None) or ""
            if preference:
                return preference
            auth = getattr(self.app, "auth_service", None)
            if auth and auth.is_authenticated and auth.has_feature("premium_ai"):
                return "servonaut"
            return cfg.provider or ""
        except Exception:
            return ""

    def _current_quota(self) -> Optional[Any]:
        """Read the cached :class:`AIQuota`, returning ``None`` for free users."""
        auth = getattr(self.app, "auth_service", None)
        if auth is None or not auth.is_authenticated:
            return None
        token = getattr(auth, "_token", None)
        ents = getattr(token, "entitlements", None) if token is not None else None
        if not isinstance(ents, dict):
            return None
        try:
            from servonaut.services.ai_quota import AIQuota
            return AIQuota.from_dict(ents.get("quota"))
        except Exception:
            return None

    def _update_quota_footer(self) -> None:
        """Render the quota footer if the active provider is Servonaut."""
        try:
            footer = self.query_one("#chat-quota-footer", Static)
        except Exception:
            return

        if self._active_provider_name() != "servonaut":
            footer.add_class("hidden")
            return

        quota = self._current_quota()
        if quota is None:
            # Subscribed but no quota seen yet — hide rather than render
            # zeroes.
            footer.add_class("hidden")
            return

        try:
            from servonaut.utils.formatting import (
                format_resets_at,
                format_tokens_remaining,
            )
            tokens_label = format_tokens_remaining(
                quota.tokens_used, quota.tokens_limit, quota.tokens_topup_remaining,
            )
            resets_label = format_resets_at(quota.resets_at)
        except Exception:
            footer.add_class("hidden")
            return

        parts = [f"[dim]Quota:[/dim] [bold]{_rich_escape(tokens_label)}[/bold]"]
        if resets_label:
            parts.append(f"[dim]resets {_rich_escape(resets_label)}[/dim]")
        footer.update("  │  ".join(parts))
        footer.remove_class("hidden")

    def _update_provider_indicator(self) -> None:
        """Update the single-character provider indicator button label."""
        try:
            btn = self.query_one("#btn-chat-provider", Button)
        except Exception:
            return
        active = self._active_provider_name()
        btn.label = _PROVIDER_INDICATORS.get(active, _PROVIDER_INDICATOR_DEFAULT)

    def _set_banner(self, markup: str) -> None:
        """Show *markup* in the chat-banner Static; empty string hides it."""
        try:
            banner = self.query_one("#chat-banner", Static)
        except Exception:
            return
        if not markup:
            banner.add_class("hidden")
            banner.update("")
            return
        banner.update(markup)
        banner.remove_class("hidden")

    def _check_provider_decision_events(self) -> None:
        """Render banners and push first-run / empty-state modals as needed.

        B1/B2 — this method now owns the full set of UI reactions to a
        :class:`ProviderDecision`:

        - Banners (paying-twice, capability) via :meth:`_set_banner`.
        - First-run modal (one-shot per session) via :meth:`push_screen`.
        - Empty-state modal (one-shot per session) via :meth:`push_screen`.
        - Pinned-error state — banner + disabled input until resolved.

        ``screens/ai_analysis.py`` previously claimed ownership of the
        first-run / empty-state modals but never actually pushed them.
        Centralising here keeps modal lifetime single-sourced.
        """
        resolver = getattr(self.app, "provider_preference_resolver", None)
        if resolver is None:
            return
        try:
            decision = resolver.resolve()
        except Exception:
            return

        from servonaut.services.ai_provider_preference import (
            ProviderPreferenceEvent,
        )

        # Pinned-error state is recomputed on every check — we clear it
        # the moment the resolver picks a healthy provider.
        pinned_now = ProviderPreferenceEvent.PINNED_ERROR_NO_PROVIDER in decision.events
        if pinned_now != self._pinned_error_active:
            self._pinned_error_active = pinned_now
            self._apply_pinned_error_state(pinned_now)

        for event in decision.events:
            if event == ProviderPreferenceEvent.SHOW_PAYING_TWICE_BANNER:
                self._set_banner(
                    "[yellow]You're subscribed to Servonaut AI but using your own key — "
                    "you may be paying twice.[/yellow]"
                )
            elif event == ProviderPreferenceEvent.SHOW_CAPABILITY_BANNER:
                self._set_banner(
                    "[cyan]Servonaut AI unlocks deploy / provision / scan + "
                    "account-level reads (billing, ban status) the local "
                    "chat doesn't touch — try a chat?[/cyan]"
                )
            elif event == ProviderPreferenceEvent.SHOW_FIRST_RUN_MODAL:
                # B2 — push the first-run choice modal exactly once per
                # session. Stomping the user's input by re-pushing on
                # every render would be hostile.
                if not self._first_run_modal_shown:
                    self._first_run_modal_shown = True
                    self._push_first_run_modal()
            elif event == ProviderPreferenceEvent.SHOW_EMPTY_STATE:
                # B2 — empty-state onboarding modal. Same one-shot rule.
                if not self._empty_state_modal_shown:
                    self._empty_state_modal_shown = True
                    self._push_empty_state_modal()

    def _apply_pinned_error_state(self, active: bool) -> None:
        """Toggle the pinned-error banner + disable the input row."""
        try:
            banner = self.query_one("#chat-pinned-error-banner", Horizontal)
            chat_input = self.query_one("#chat-input", TextArea)
            send_btn = self.query_one("#btn-chat-send", Button)
        except Exception:
            return
        if active:
            banner.remove_class("hidden")
            chat_input.disabled = True
            send_btn.disabled = True
        else:
            banner.add_class("hidden")
            chat_input.disabled = False
            send_btn.disabled = False

    def _push_first_run_modal(self) -> None:
        """B2 — push :class:`AIProviderFirstRunModal` once per session."""
        from servonaut.screens.ai_picker_modal import AIProviderFirstRunModal

        resolver = getattr(self.app, "provider_preference_resolver", None)
        if resolver is None:
            return

        # The user's actual selected provider is the source of truth for the
        # "Currently configured: [...]" line. The resolver's
        # is_provider_configured() answers "is some non-servonaut config
        # present" but cannot distinguish providers that share the single
        # `api_key` field — iterating it would pick OpenAI whenever any
        # api_key is set, even when the user is on Anthropic / Gemini /
        # Ollama. Read `cfg.provider` instead.
        existing = ""
        base_url = ""
        try:
            cfg = self.app.config_manager.get().ai_provider
            selected = (cfg.provider or "").strip().lower()
            if selected and selected != "servonaut":
                existing = selected
                base_url = getattr(cfg, "base_url", "") or ""
            else:
                # Fallback: selected provider is empty/servonaut but the
                # resolver detected a non-servonaut config (Ollama base_url
                # only, perhaps). Walk the rules to find which one matches
                # so we still render *something* sensible.
                for name in ("ollama", "openai", "anthropic", "gemini"):
                    if resolver.is_provider_configured(name):
                        existing = name
                        base_url = getattr(cfg, "base_url", "") or ""
                        break
        except Exception:
            pass

        def _on_choice(choice: Optional[str]) -> None:
            if not choice:
                return
            try:
                resolver.commit_first_run_choice(choice)  # type: ignore[arg-type]
                self.app.notify(
                    f"Provider preference set to {choice}.",
                    severity="information",
                    markup=False,
                )
                self._check_provider_decision_events()
                self._update_provider_indicator()
                self._update_quota_footer()
            except Exception:
                logger.exception("commit_first_run_choice failed")

        try:
            self.app.push_screen(
                AIProviderFirstRunModal(existing or "ollama", base_url=base_url),
                _on_choice,
            )
        except Exception:
            logger.exception("Failed to push AIProviderFirstRunModal")

    def _push_empty_state_modal(self) -> None:
        """B2 — push :class:`AIEmptyStateModal` once per session."""
        from servonaut.screens.ai_picker_modal import AIEmptyStateModal

        def _on_choice(choice: Optional[str]) -> None:
            if not choice:
                return
            if choice == "subscribe":
                try:
                    webbrowser.open("https://servonaut.dev/pricing")
                except Exception:  # noqa: BLE001
                    pass
            elif choice in ("add_api_key", "ollama"):
                # Defer settings-screen push to the app — chat panel
                # doesn't import the screen module to avoid cycles.
                pusher = getattr(self.app, "open_settings_screen", None)
                if callable(pusher):
                    try:
                        pusher(provider_focus=choice)
                    except Exception:
                        logger.debug(
                            "open_settings_screen raised", exc_info=True,
                        )
                else:
                    self.app.notify(
                        "Open Settings to add a provider.",
                        severity="information",
                        markup=False,
                    )

        try:
            self.app.push_screen(AIEmptyStateModal(), _on_choice)
        except Exception:
            logger.exception("Failed to push AIEmptyStateModal")

    # ------------------------------------------------------------------
    # T10 upstream-unavailable watcher
    # ------------------------------------------------------------------

    def _record_upstream_failure(self) -> None:
        """Append the current monotonic timestamp; prune stale entries."""
        now = time.monotonic()
        self._upstream_failures.append(now)
        cutoff = now - _UPSTREAM_FAILURE_WINDOW_S
        self._upstream_failures = [
            t for t in self._upstream_failures if t >= cutoff
        ]

    def _maybe_offer_fallback(self) -> None:
        """Inspect the failure list; auto-fallback or push the prompt modal.

        Plan §T10 invariant: only on the *second* upstream_unavailable
        within 60s do we even consider acting. First failure: silent.
        """
        if len(self._upstream_failures) < 2:
            return

        # Local fallback configured? Auto-switch session-only.
        try:
            cfg = self.app.config_manager.get().ai_provider
            local_fallback = getattr(cfg, "local_fallback_provider", None) or ""
        except Exception:
            local_fallback = ""

        resolver = getattr(self.app, "provider_preference_resolver", None)

        if local_fallback and resolver is not None:
            try:
                if resolver.is_provider_configured(local_fallback):
                    self._session_provider_override = local_fallback
                    self.app.notify(
                        f"Servonaut AI is unavailable — falling back to "
                        f"{local_fallback} for this session.",
                        severity="warning",
                    )
                    self._update_provider_indicator()
                    self._update_stats()
                    return
            except Exception:
                pass

        # Otherwise, prompt — only if at least one non-Servonaut
        # provider is configured.
        if resolver is None:
            return
        try:
            if not resolver.has_any_non_servonaut_configured():
                return
            available = [
                name for name in ("ollama", "openai", "anthropic", "gemini")
                if resolver.is_provider_configured(name)
            ]
        except Exception:
            return

        from servonaut.screens.ai_fallback_prompt_modal import (
            AIFallbackPromptModal,
        )

        def _on_choice(choice: Optional[str]) -> None:
            if not choice:
                return
            self._session_provider_override = choice
            self.app.notify(
                f"Using {choice} for this session.",
                severity="information",
            )
            self._update_provider_indicator()
            self._update_stats()

        try:
            self.app.push_screen(
                AIFallbackPromptModal(
                    available,
                    reason="Servonaut AI unavailable twice in 60s.",
                ),
                _on_choice,
            )
        except Exception:
            logger.exception("Failed to push AIFallbackPromptModal")

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def _get_chat_service(self) -> Optional[Any]:
        """Get the chat service, returning None if unavailable."""
        try:
            svc = self.app.chat_service  # type: ignore[attr-defined]
        except AttributeError:
            return None
        return svc

    def _start_or_resume_session(self) -> None:
        """Load the most recent session or create a fresh one."""
        chat_service = self._get_chat_service()
        if chat_service is None:
            return

        sessions = chat_service.list_sessions()
        if sessions:
            self._session = chat_service.load_session(sessions[0]["id"])
        if self._session is None:
            self._session = chat_service.create_session()

        self._refresh_messages()

    def _refresh_messages(self) -> None:
        """Rebuild the message display from the current session."""
        container = self.query_one("#chat-messages", VerticalScroll)
        container.remove_children()

        if self._session is None:
            return

        messages = self._session.messages  # type: ignore[union-attr]
        if not messages:
            self._show_welcome()
            return

        for msg in messages:
            # A2 — escape ``msg.content`` at every interpolation site. A
            # malicious model could inject Rich markup (e.g. a clickable
            # ``[link=evil]`` href) that survives a thread-export round-trip
            # and renders as a real Rich Link on next mount. The user-role
            # path is also escaped because conversations imported from the
            # server may include user-role rows fabricated by the model.
            if msg.role == "tool":
                # Tool rows were rendered with Rich markup at write time
                # (header + body) and stored verbatim — re-render the
                # markup so the styling survives reload. The content
                # comes from CLI-side composition (tool name + status +
                # result_summary, each escaped before storage), not
                # raw model output, so re-rendering is safe.
                widget = Static(
                    msg.content or "",
                    classes="chat-message-tool",
                )
                container.mount(widget)
                continue
            safe_content = _rich_escape(msg.content or "")
            if msg.role == "user":
                widget = Static(
                    f"[bold]You[/bold]\n{safe_content}",
                    classes="chat-message-user",
                )
            else:
                widget = Static(
                    f"{BOT_MARKER} [bold]Servonaut[/bold]\n{safe_content}",
                    classes="chat-message-assistant",
                )
            container.mount(widget)

        self.call_after_refresh(self._scroll_to_bottom)
        self._update_stats()

    def _scroll_to_bottom(self) -> None:
        try:
            container = self.query_one("#chat-messages", VerticalScroll)
            container.scroll_end(animate=False)
            # Re-arm follow-tail: the user just acted (sent message,
            # opened a session, refreshed) so they're now at the
            # bottom intentionally.
            self._last_max_scroll_y = container.max_scroll_y
        except Exception:
            pass

    def _follow_tail(self) -> None:
        """Scroll to bottom ONLY if the user was at the previous bottom.

        Streaming tokens, tool results, and skipped-tool rows route
        through this so they keep the viewport pinned to the latest
        message — but only when the user hasn't scrolled up. If they
        have, we leave them alone so they can read earlier messages
        (including the start of the conversation) without being yanked
        back by every token delta.

        Why ``_last_max_scroll_y`` instead of comparing against the
        current ``max_scroll_y``: by the time this callback runs the
        new content has already extended ``max_scroll_y``, so a user
        who WAS at the bottom now looks "scrolled up" by the height of
        the new content. Comparing against the *previous* bottom (the
        one we recorded after the last update) gives us the user's
        intent at the moment the content arrived. Two-row tolerance
        absorbs sub-pixel layout drift.
        """
        try:
            container = self.query_one("#chat-messages", VerticalScroll)
        except Exception:
            return
        last_max = getattr(self, "_last_max_scroll_y", 0)
        if container.scroll_y >= last_max - 2:
            try:
                container.scroll_end(animate=False)
            except Exception:
                pass
        # Record the new bottom for the next call.
        try:
            self._last_max_scroll_y = container.max_scroll_y
        except Exception:
            pass

    def _show_thinking(self, text: str = "Servonaut is thinking...") -> None:
        """Add an animated thinking indicator with customisable text.

        A2 — *text* may originate from a server-controlled status string
        (e.g. SSE token deltas accumulated mid-stream). Escape it before
        interpolation so injected ``[link=...]`` payloads cannot hijack
        the indicator.
        """
        container = self.query_one("#chat-messages", VerticalScroll)
        widget = Static(
            f"{BOT_MARKER} [dim italic]{_rich_escape(text)}[/dim italic]",
            id="chat-thinking",
            classes="chat-message-assistant chat-thinking",
        )
        container.mount(widget)
        self.call_after_refresh(self._scroll_to_bottom)

    def _update_thinking_status(self, text: str) -> None:
        """Update the thinking indicator text (called from worker thread).

        A2 — escape *text* before interpolating into Rich markup. This is
        the primary streaming sink: every token delta we accumulate flows
        through here, so this is the most security-critical escape point.
        """
        try:
            widget = self.query_one("#chat-thinking", Static)
            widget.update(
                f"{BOT_MARKER} [dim italic]{_rich_escape(text)}[/dim italic]"
            )
            # Streaming tokens grow the bubble; without this the viewport
            # stays anchored to the top and the user has to scroll down
            # to see what's being typed. ``_follow_tail`` only scrolls
            # if the user is already at the bottom — scrolling up to
            # re-read earlier turns is preserved.
            self.call_after_refresh(self._follow_tail)
        except Exception:
            pass

    def _hide_thinking(self) -> None:
        """Remove the thinking indicator."""
        try:
            self.query_one("#chat-thinking", Static).remove()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn-chat-new":
            self._new_chat()
        elif button_id == "btn-chat-history":
            self._toggle_history()
        elif button_id == "btn-chat-provider":
            self._toggle_provider_override()
        elif button_id == "btn-chat-send":
            self._send()
        elif button_id == "btn-chat-close":
            self.remove()
        elif button_id == "btn-pinned-resubscribe":
            # B1 — open pricing in the user's default browser.
            try:
                webbrowser.open("https://servonaut.dev/pricing")
            except Exception:  # noqa: BLE001
                self.app.notify(
                    "Open https://servonaut.dev/pricing to resubscribe.",
                    severity="warning",
                    markup=False,
                )
        elif button_id == "btn-pinned-add-provider":
            # B1 — defer to the app to push the settings screen if it
            # supports the helper; otherwise tell the user where to look.
            pusher = getattr(self.app, "open_settings_screen", None)
            if callable(pusher):
                try:
                    pusher()
                except Exception:
                    logger.debug("open_settings_screen raised", exc_info=True)
            else:
                self.app.notify(
                    "Open Settings to add an AI provider.",
                    severity="information",
                    markup=False,
                )
        elif button_id and button_id.startswith("btn-session-"):
            session_id = button_id.removeprefix("btn-session-")
            self._load_session(session_id)
        elif button_id and button_id.startswith("btn-del-session-"):
            session_id = button_id.removeprefix("btn-del-session-")
            self._delete_session(session_id)
        event.stop()

    def _toggle_provider_override(self) -> None:
        """Open a fallback prompt to override the active provider for this session.

        Reuses :class:`AIFallbackPromptModal` since it's already a
        provider-pick modal — semantically identical to the user-driven
        case (T10 explicitly says the override is session-scoped).
        """
        resolver = getattr(self.app, "provider_preference_resolver", None)
        if resolver is None:
            self.app.notify(
                "Provider switching not available.",
                severity="warning",
            )
            return
        try:
            available = [
                name for name in ("servonaut", "ollama", "openai", "anthropic", "gemini")
                if (
                    (name == "servonaut"
                     and self.app.auth_service.is_authenticated
                     and self.app.auth_service.has_feature("premium_ai"))
                    or resolver.is_provider_configured(name)
                )
            ]
        except Exception:
            available = []

        if not available:
            self.app.notify("No providers configured.", severity="warning")
            return

        from servonaut.screens.ai_fallback_prompt_modal import (
            AIFallbackPromptModal,
        )

        def _on_choice(choice: Optional[str]) -> None:
            if not choice:
                return
            self._session_provider_override = choice
            self.app.notify(
                f"Using {choice} for this session.",
                severity="information",
            )
            self._update_provider_indicator()
            self._update_stats()

        # Manual switcher — distinct copy from the T10 fallback prompt
        # so the user isn't told "Servonaut AI is unavailable" when they
        # clicked the provider button on a perfectly working chat.
        self.app.push_screen(
            AIFallbackPromptModal(
                available,
                title="Switch AI provider",
                body=(
                    "Pick the provider to use for this chat session. "
                    "This won't change your default — only the current chat."
                ),
                keep_label="Cancel",
            ),
            _on_choice,
        )

    def on_key(self, event) -> None:
        """Enter sends message, Shift+Enter inserts newline."""
        if event.key == "enter":
            focused = self.app.focused
            if focused is not None and getattr(focused, "id", None) == "chat-input":
                event.prevent_default()
                self._send()

    def _toggle_history(self) -> None:
        """Open the unified Previous Chats screen with Cloud + Local tabs.

        Routing is identical for every user — the screen itself decides
        which tab to start on. Hosted-AI subscribers see Cloud first
        (their hosted history); free / logged-out users land on Cloud
        (which renders an empty / sign-in nudge) and pick Local for
        local-only sessions. The previous behaviour where free users
        got the inline session list inside the chat panel is retired in
        favour of one consistent surface.
        """
        from servonaut.screens.ai_conversations_screen import AIConversationsScreen
        self.app.push_screen(AIConversationsScreen())

    def _populate_history(self) -> None:
        """Populate the history list with saved sessions."""
        chat_service = self._get_chat_service()
        if chat_service is None:
            return

        history_panel = self.query_one("#chat-history-list", VerticalScroll)
        history_panel.remove_children()

        sessions = chat_service.list_sessions()
        if not sessions:
            history_panel.mount(Static("[dim]No saved chats[/dim]", id="chat-history-empty"))
            return

        for s in sessions:
            title = s["title"]
            session_id = s["id"]
            is_current = self._session is not None and self._session.id == session_id
            marker = "[bold cyan]▸[/bold cyan] " if is_current else "  "

            # Parse date for display
            updated = s.get("updated_at", "")
            date_str = ""
            if updated:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(updated)
                    date_str = dt.strftime("%b %d %H:%M")
                except (ValueError, TypeError):
                    pass

            row = Horizontal(classes="chat-history-item")
            load_btn = Button(
                f"{marker}{title[:30]}{'…' if len(title) > 30 else ''} [dim]{date_str}[/dim]",
                id=f"btn-session-{session_id}",
                classes="chat-history-btn",
            )
            del_btn = Button(
                "✕",
                id=f"btn-del-session-{session_id}",
                variant="error",
                classes="chat-history-del",
            )
            history_panel.mount(row)
            row.mount(load_btn)
            row.mount(del_btn)

    def _load_session(self, session_id: str) -> None:
        """Load a session by ID and switch to it."""
        chat_service = self._get_chat_service()
        if chat_service is None:
            return
        session = chat_service.load_session(session_id)
        if session is None:
            self.app.notify("Session not found", severity="error")
            return
        self._session = session
        # If the session is paired with a server-side conversation
        # (ChatSession.remote_conversation_id was stored on disk),
        # restore that pointer so subsequent Servonaut turns continue
        # appending to the same Cloud row instead of starting a new
        # one. Unpaired sessions (None) leave the next turn to create a
        # fresh Cloud thread on first send.
        self._remote_conversation_id = session.remote_conversation_id
        self._total_tokens = 0
        self._total_cost = 0.0
        self._refresh_messages()
        self._update_stats()
        # Hide history panel after selection
        try:
            self.query_one("#chat-history-list", VerticalScroll).add_class("hidden")
        except Exception:
            # Inline history panel may not exist on every layout once we
            # route history through the unified screen.
            pass
        self._do_focus_input()

    def _delete_session(self, session_id: str) -> None:
        """Delete a session and refresh the history list."""
        chat_service = self._get_chat_service()
        if chat_service is None:
            return

        # If deleting the current session, create a new one
        is_current = self._session is not None and self._session.id == session_id
        chat_service.delete_session(session_id)

        if is_current:
            self._session = chat_service.create_session()
            self._remote_conversation_id = None
            self._total_tokens = 0
            self._total_cost = 0.0
            self._refresh_messages()
            self._update_stats()

        # Refresh the history list
        self._populate_history()

    def _new_chat(self) -> None:
        """Create a new session and clear the display."""
        chat_service = self._get_chat_service()
        if chat_service is None:
            return
        self._session = chat_service.create_session()
        # Drop the previous server-side conversation pointer so the next
        # turn creates a fresh /account/ai/conversations row instead of
        # appending to the prior thread. Without this, "New Chat" looks
        # local-only but the server keeps writing to the old thread.
        self._remote_conversation_id = None
        self._total_tokens = 0
        self._total_cost = 0.0
        self._refresh_messages()
        self._update_stats()
        self.query_one("#chat-history-list", VerticalScroll).add_class("hidden")
        self._do_focus_input()

    def _send(self) -> None:
        """Read the input field and dispatch the message as a worker."""
        if self._thinking:
            return
        try:
            inp = self.query_one("#chat-input", TextArea)
        except Exception:
            return

        text = inp.text.strip()
        if not text:
            return

        inp.load_text("")
        self._thinking = True
        self._show_thinking()

        # Risk register §4: keep the streaming consumer in a dedicated
        # worker group so it doesn't collide with memory probes or
        # other background work. ``ai_chat`` is the chat-panel canonical
        # group name for this and related workers (topup, history load).
        self.run_worker(
            self._do_send(text),
            exclusive=False,
            name="ai_chat_send",
            group="ai_chat",
        )

    async def _do_send(self, text: str) -> None:
        """Worker: send message to AI and refresh display.

        Wave-3 dispatch: if the active provider is Servonaut AI we route
        through :meth:`_do_send_servonaut` for streaming + tool-use; for
        any other provider the existing chat-service path runs unchanged.
        """
        active_provider = self._active_provider_name()
        if active_provider == "servonaut":
            await self._do_send_servonaut(text)
            return

        try:
            chat_service = self._get_chat_service()
            if chat_service is None:
                return
            if self._session is None:
                self._session = chat_service.create_session()

            # Resolve active instance and strip any @prefix from the text.
            inst, effective_text = self._resolve_active_instance(text)
            instance_id = inst.get("id") if inst else None
            instance_name = inst.get("name") if inst else None
            instance_provider = (inst.get("provider") or "custom") if inst else "custom"

            result = await chat_service.send_message(
                self._session,
                effective_text,
                status_callback=self._update_thinking_status,
                instance_id=instance_id,
                instance_name=instance_name,
                instance_provider=instance_provider,
                ai_provider=active_provider,
            )
            self._total_tokens += result.get("tokens_used", 0)
            cost = result.get("estimated_cost")
            if cost is not None:
                self._total_cost += cost
            self._model = result.get("model", "") or self._model
        except Exception as exc:
            from servonaut.services.chat_service import ChatMessage
            if self._session is not None:
                self._session.messages.append(  # type: ignore[union-attr]
                    ChatMessage(role="assistant", content=f"Error: {exc}")
                )
        finally:
            self._hide_thinking()
            self._thinking = False
            self._refresh_messages()

    # ------------------------------------------------------------------
    # Servonaut streaming path (T5 + T6 + T8 + T10)
    # ------------------------------------------------------------------

    async def _do_send_servonaut(self, text: str) -> None:
        """Worker: stream a Servonaut-AI chat turn end-to-end.

        C1 — refactored from a 136-LoC monolith into an orchestrator that
        delegates to three focused helpers:

        - :meth:`_servonaut_build_request_body` assembles the SSE request.
        - :meth:`_servonaut_consume_stream` opens the stream and yields events.
        - :meth:`_servonaut_handle_event` dispatches one event at a time.

        Risk register §4: ``ping`` events are absorbed inside ``ai_sse``
        so the UI thread never sees them.
        """
        from servonaut.services.chat_service import ChatMessage

        provider = getattr(self.app, "servonaut_provider", None)
        if provider is None:
            self.app.notify(
                "Servonaut AI not initialised.",
                severity="error",
                markup=False,
            )
            self._hide_thinking()
            self._thinking = False
            return

        chat_service = self._get_chat_service()
        if chat_service is None:
            self._hide_thinking()
            self._thinking = False
            return

        if self._session is None:
            self._session = chat_service.create_session()

        inst, effective_text = self._resolve_active_instance(text)

        self._session.messages.append(  # type: ignore[union-attr]
            ChatMessage(role="user", content=effective_text, provider="servonaut")
        )

        body_kwargs = self._servonaut_build_request_body(
            session_messages=self._session.messages,  # type: ignore[union-attr]
            instance=inst,
            chat_service=chat_service,
        )

        # Reset per-turn tool counter so finalise_turn can tell whether
        # tools ran when accumulated is empty.
        self._turn_tool_calls = 0
        accumulated = ""
        try:
            async for event in self._servonaut_consume_stream(
                provider, body_kwargs,
            ):
                accumulated = await self._servonaut_handle_event(
                    event, accumulated,
                )
                if event.get("event") == "done":
                    break
        except Exception as exc:
            # Stale conversation_id (deleted from another tab, expired,
            # etc.) → server returns 404 *before* the SSE body opens,
            # which surfaces as NotFoundError pre-stream. Drop the id
            # and retry once with a fresh conversation. We only retry
            # when the original request actually carried an id; a 404
            # without one means something else (route mismatch, etc.)
            # and should fall through to the generic error path.
            if (
                self._is_stale_conversation_404(exc)
                and body_kwargs.get("conversation_id")
                and accumulated == ""
            ):
                logger.info(
                    "ai chat: server 404 on conversation_id=%s — "
                    "dropping stale id and retrying once with a fresh "
                    "conversation",
                    body_kwargs.get("conversation_id"),
                )
                self._remote_conversation_id = None
                body_kwargs["conversation_id"] = None
                self._turn_tool_calls = 0
                try:
                    async for event in self._servonaut_consume_stream(
                        provider, body_kwargs,
                    ):
                        accumulated = await self._servonaut_handle_event(
                            event, accumulated,
                        )
                        if event.get("event") == "done":
                            break
                except Exception as retry_exc:
                    self._handle_stream_error(retry_exc, accumulated)
                    self._hide_thinking()
                    self._thinking = False
                    self._refresh_messages()
                    return
            else:
                self._handle_stream_error(exc, accumulated)
                self._hide_thinking()
                self._thinking = False
                self._refresh_messages()
                return

        self._finalise_servonaut_turn(chat_service, accumulated)

    @staticmethod
    def _is_stale_conversation_404(exc: BaseException) -> bool:
        """Detect a 404 raised before the stream opens.

        Matches both ``NotFoundError`` (api_client.py exception type)
        and any ``APIError`` carrying ``status == 404``. We don't sniff
        the message text — the server's 404 envelope shape is internal
        and we shouldn't pin to it.
        """
        from servonaut.services.api_client import APIError, NotFoundError

        if isinstance(exc, NotFoundError):
            return True
        if isinstance(exc, APIError) and getattr(exc, "status", None) == 404:
            return True
        return False

    def _servonaut_build_request_body(
        self,
        *,
        session_messages: List[Any],
        instance: Optional[Dict[str, Any]],
        chat_service: Any,
    ) -> Dict[str, Any]:
        """Assemble the kwargs for :meth:`ServonautProvider.stream_chat`."""
        max_history = getattr(chat_service, "_max_history", 20)
        recent = session_messages[-max_history:]
        api_messages = [
            {"role": m.role, "content": m.content} for m in recent
        ]
        context: Dict[str, Any] = {}
        instance_id = instance.get("id") if instance else None
        if instance_id:
            context["instance_ids"] = [instance_id]

        return {
            "messages": api_messages,
            "system_prompt": "",
            "config": self.app.config_manager.get().ai_provider,
            "conversation_id": self._remote_conversation_id,
            "context": context or None,
            "allow_tools": True,
        }

    async def _servonaut_consume_stream(
        self,
        provider: Any,
        body_kwargs: Dict[str, Any],
    ):
        """Open the SSE stream and yield events.

        Wrapping the provider call in its own helper keeps
        :meth:`_do_send_servonaut` short (C1) and gives test code a
        single seam to mock — patch this method, not the underlying
        provider, when exercising the orchestrator.
        """
        async for event in provider.stream_chat(
            body_kwargs["messages"],
            system_prompt=body_kwargs["system_prompt"],
            config=body_kwargs["config"],
            conversation_id=body_kwargs["conversation_id"],
            context=body_kwargs["context"],
            allow_tools=body_kwargs["allow_tools"],
        ):
            yield event

    async def _servonaut_handle_event(
        self,
        event: Dict[str, Any],
        accumulated: str,
    ) -> str:
        """Dispatch one streamed event; return the (possibly mutated)
        accumulated assistant text.

        Splitting this out of the orchestrator keeps the per-event
        decisions testable in isolation (C1).
        """
        etype = event.get("event")
        data = event.get("data") or {}
        if etype == "conversation":
            # Server emits this as the FIRST SSE frame of every
            # /api/ai/chat stream so the CLI learns the conversation_id
            # before any tool_call arrives. Without it, a turn whose
            # first model output is a tool_call would POST
            # /api/ai/chat/tool-result with an empty conversation_id and
            # 404. Older server builds don't emit this event — the
            # existing ``usage`` path below still captures the id as a
            # fallback.
            conv_id = data.get("conversation_id")
            if conv_id:
                self._remote_conversation_id = str(conv_id)
                # Pair the local session with the remote conversation
                # row so the unified history view can show "uploaded"
                # and the Local-tab paired delete can drop the remote
                # row too. Persist via save_session so the link
                # survives a process restart.
                if self._session is not None:
                    self._session.remote_conversation_id = str(conv_id)  # type: ignore[union-attr]
                    chat_service = self._get_chat_service()
                    if chat_service is not None:
                        try:
                            chat_service.save_session(self._session)
                        except Exception:
                            logger.debug(
                                "Failed to persist remote_conversation_id "
                                "on local session",
                                exc_info=True,
                            )
                logger.info(
                    "ai conversation event: conversation_id=%s", conv_id,
                )
            else:
                logger.warning(
                    "ai conversation event missing conversation_id: %r",
                    data,
                )
        elif etype == "token":
            delta = str(data.get("text") or "")
            accumulated += delta
            # Live-update the thinking bubble with the running text so
            # the user sees streaming output without re-render. A2 —
            # ``_update_thinking_status`` escapes its argument before
            # interpolating into Rich markup.
            self._update_thinking_status(accumulated or "Thinking...")
        elif etype == "tool_call":
            await self._handle_streamed_tool_call(data)
        elif etype == "tool_result":
            # Server-executed tool result — render as a soft collapsed
            # row in messages.
            logger.info(
                "ai tool_result received: call=%s status=%s bytes=%s",
                data.get("tool_call_id"), data.get("status"),
                data.get("bytes"),
            )
            self._render_tool_result_row(data)
        elif etype == "usage":
            self._consume_usage_event(data)
        elif etype == "info":
            code = data.get("code", "info")
            message = data.get("message") or code
            # A1 — server-controlled ``code`` and ``message`` flow
            # straight into a notify. ``markup=False`` keeps brackets
            # literal.
            self.app.notify(
                f"{code}: {message}",
                severity="warning",
                timeout=4,
                markup=False,
            )
        elif etype == "done":
            pass  # caller breaks out of the loop
        else:
            logger.debug("Unhandled SSE event %r", etype)
        return accumulated

    def _finalise_servonaut_turn(
        self,
        chat_service: Any,
        accumulated: str,
    ) -> None:
        """Append the final assistant message + persist + refresh display."""
        from servonaut.services.chat_service import ChatMessage

        stripped = accumulated.strip()
        if stripped:
            final_text = stripped
        elif self._turn_tool_calls > 0:
            # Server emitted tool_call(s) but produced no continuation
            # tokens — the model didn't summarise the tool output. The
            # tool_result rows above show what each tool returned; this
            # bubble just acknowledges the model went silent so the
            # user isn't confused by an empty assistant message.
            final_text = (
                f"(model ran {self._turn_tool_calls} tool"
                f"{'s' if self._turn_tool_calls != 1 else ''} but didn't "
                "summarise — see tool output above)"
            )
            logger.info(
                "Servonaut turn finished with empty text after %d tool call(s); "
                "rendering tool-only fallback bubble",
                self._turn_tool_calls,
            )
        else:
            final_text = "(no response)"
            logger.info(
                "Servonaut turn finished with empty text and zero tool calls — "
                "stream closed without emitting any tokens",
            )
        self._session.messages.append(  # type: ignore[union-attr]
            ChatMessage(
                role="assistant", content=final_text, provider="servonaut",
            )
        )

        # Auto-title from first user message (mirrors chat_service).
        if (
            self._session.title == "New Chat"  # type: ignore[union-attr]
            and len(self._session.messages) >= 2  # type: ignore[union-attr]
        ):
            first_msg = self._session.messages[0].content  # type: ignore[union-attr]
            self._session.title = first_msg[:50] + (  # type: ignore[union-attr]
                "..." if len(first_msg) > 50 else ""
            )

        try:
            chat_service.save_session(self._session)
        except Exception:
            logger.debug("save_session failed", exc_info=True)

        self._hide_thinking()
        self._thinking = False
        self._refresh_messages()

        # T10 watcher — a successful turn proves the upstream is healthy
        # right now, so any failures inside the trailing 60s window are
        # historical noise. Clearing prevents the fallback modal from
        # firing on a single new failure that's only paired with stale
        # entries.
        if self._upstream_failures:
            self._upstream_failures.clear()

    async def _handle_streamed_tool_call(self, data: Dict[str, Any]) -> None:
        """Drive the AI tool-bridge for a single ``tool_call`` SSE event.

        Pushes the right confirm modal (single y/n vs typed RUN) based
        on ``guard_level``, awaits the user's choice, then runs the
        tool via ``app.ai_tool_bridge`` and POSTs the result back.
        """
        bridge = getattr(self.app, "ai_tool_bridge", None)
        if bridge is None:
            self.app.notify("AI tool bridge not available.", severity="error")
            return

        from servonaut.services.ai_tool_bridge import ToolCall, ToolResult

        self._turn_tool_calls += 1

        call = ToolCall(
            tool_call_id=str(data.get("tool_call_id") or ""),
            tool=str(data.get("tool") or ""),
            args=dict(data.get("args") or {}),
            guard_level=str(data.get("guard_level") or "standard"),  # type: ignore[arg-type]
            conversation_id=self._remote_conversation_id or "",
        )

        # INFO-level so users running without --debug can see the flow.
        # Args may carry user data; log only the tool name and ids.
        logger.info(
            "ai tool_call received: tool=%s tool_call_id=%s guard=%s conv=%s",
            call.tool, call.tool_call_id, call.guard_level,
            call.conversation_id or "<empty>",
        )
        if not call.conversation_id:
            logger.warning(
                "tool_call %s arrived before conversation_id was set — POST "
                "to /api/ai/chat/tool-result will be rejected with "
                "validation_failed (empty conversation_id)",
                call.tool_call_id,
            )

        try:
            result = await bridge.handle_tool_call(call)
        except Exception as exc:  # noqa: BLE001
            # C4 — bridge raised before producing a ToolResult. The server's
            # turn stays open until we POST a tool-result back, so synthesise
            # a status="error" envelope and post it before we return. Without
            # this, a single bridge bug could hang every chat that issued a
            # tool_call.
            logger.exception("AIToolBridge.handle_tool_call raised")
            error_message = f"Tool execution failed: {exc}"
            # A1 — exc message is server/runtime-controlled. markup=False.
            self.app.notify(
                error_message, severity="error", markup=False,
            )
            try:
                synthetic = ToolResult(
                    tool_call_id=call.tool_call_id,
                    conversation_id=call.conversation_id,
                    status="error",
                    result=error_message,
                    error=str(exc),
                    bytes=len(error_message.encode("utf-8")),
                )
                await bridge.post_tool_result(synthetic)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "Failed to post synthetic error tool_result for %s",
                    call.tool_call_id,
                )
            return

        # If the bridge couldn't dispatch the tool (unmapped name or
        # missing collaborator), surface a soft note to the user AND a
        # tool_result row to the chat log so the conversation has a
        # record of what happened. The server may also miss its row
        # update in this case (404 swallowed in post_tool_result), but
        # the model still gets the tool_result via the SSE stream the
        # next time it hits the server, OR times out gracefully.
        if getattr(result, "skipped", False):
            # A1 — call.tool is server-controlled. markup=False keeps
            # brackets literal.
            self.app.notify(
                f"Skipped tool: {call.tool} — not available in this CLI build.",
                severity="warning",
                markup=False,
                timeout=5,
            )
            self._render_tool_skipped_row(call.tool, result.error or "")

        try:
            await bridge.post_tool_result(result)
        except Exception as exc:  # noqa: BLE001
            logger.exception("post_tool_result failed")
            # A1 — exc message can carry server-controlled markup.
            self.app.notify(
                f"Posting tool result failed: {exc}",
                severity="error",
                markup=False,
            )

    def _render_tool_result_row(self, data: Dict[str, Any]) -> None:
        """Append a tool-result row to the message scroll for visual context.

        Shows the tool's truncated output (``result_summary`` from the
        server's ``ToolResultEvent``) so the user sees what the tool
        returned even when the model doesn't generate follow-up text.
        Without this, a server that emits a ``tool_result`` and then
        ``done`` (no continuation tokens) leaves the user staring at
        an empty "(no response)" assistant bubble despite the tool
        having succeeded.
        """
        tool_id = _rich_escape(str(data.get("tool_call_id", "")))
        status = _rich_escape(str(data.get("status", "ok")))
        result_summary = data.get("result_summary")
        try:
            container = self.query_one("#chat-messages", VerticalScroll)
        except Exception:
            return

        header = (
            f"[dim italic]Tool result[/dim italic] "
            f"[bold]{tool_id}[/bold] [dim]({status})[/dim]"
        )
        if isinstance(result_summary, str) and result_summary.strip():
            # Server-controlled string — escape every byte before
            # interpolating into Rich markup (CLAUDE.md A2 rule).
            safe_body = _rich_escape(result_summary.strip())
            body = f"\n{safe_body}"
        else:
            body = ""

        widget = Static(
            header + body,
            classes="chat-message-tool",
        )
        container.mount(widget)
        # Tool-result rows can be quite tall (multi-line summary). Pin
        # the viewport to the bottom so the user sees the latest tool
        # output. ``_follow_tail`` respects manual scroll-up.
        self.call_after_refresh(self._follow_tail)
        # Persist if the user opted to keep tool results in local history.
        # Default True (debug-friendly); toggle off in Settings to drop.
        self._maybe_persist_tool_message(header + body)

    def _render_tool_skipped_row(self, tool_name: str, reason: str) -> None:
        """Append a soft-skip row for tools the bridge couldn't dispatch.

        Distinct from ``_render_tool_result_row`` so the user can tell at
        a glance "this didn't run" vs "this ran with status X". All
        interpolated strings escape via ``_rich_escape`` because the tool
        name and reason are server-controlled.
        """
        try:
            container = self.query_one("#chat-messages", VerticalScroll)
        except Exception:
            return
        safe_tool = _rich_escape(tool_name or "?")
        safe_reason = _rich_escape(reason or "tool unavailable")
        rendered = (
            f"[yellow]⊘ Skipped tool[/yellow] [bold]{safe_tool}[/bold] "
            f"[dim]— {safe_reason}[/dim]"
        )
        widget = Static(
            rendered,
            classes="chat-message-tool",
        )
        container.mount(widget)
        self.call_after_refresh(self._follow_tail)
        self._maybe_persist_tool_message(rendered)

    def _maybe_persist_tool_message(self, rendered_markup: str) -> None:
        """Append a ``role="tool"`` ChatMessage when the user opted in.

        Toggled by ``config.chat_keep_tool_results`` (default True).
        Writes the same Rich-markup string the transient render uses so
        the reload path can update the Static widget verbatim — no
        re-formatting on the read side. Defensive at every step:
        unmounted-test-panel callers (no .app, no _session) and a
        missing config field all early-return cleanly.
        """
        try:
            cfg = self.app.config_manager.get()
        except Exception:
            return
        if not getattr(cfg, "chat_keep_tool_results", True):
            return
        session = getattr(self, "_session", None)
        if session is None:
            return
        try:
            from servonaut.services.chat_service import ChatMessage
            session.messages.append(  # type: ignore[union-attr]
                ChatMessage(
                    role="tool",
                    content=rendered_markup,
                    provider="servonaut",
                )
            )
            chat_service = self._get_chat_service()
            if chat_service is not None:
                chat_service.save_session(session)
        except Exception:
            logger.debug("Failed to persist tool message", exc_info=True)

    def _consume_usage_event(self, data: Dict[str, Any]) -> None:
        """Update quota / fallback / cap state from a streamed ``usage`` event."""
        # Token totals — accumulate into the existing counters.
        try:
            in_t = int(data.get("input_tokens") or 0)
            out_t = int(data.get("output_tokens") or 0)
            self._total_tokens += (in_t + out_t)
        except (TypeError, ValueError):
            pass
        model = data.get("model")
        if isinstance(model, str) and model:
            self._model = model
        self._last_fallback_used = bool(data.get("fallback_used", False))
        quota_block = data.get("quota")
        if isinstance(quota_block, dict):
            self._last_soft_capped = bool(quota_block.get("soft_capped", False))
            self._last_hard_capped = bool(quota_block.get("hard_capped", False))
            # Persist the fresh quota onto the AuthToken so the footer
            # picks it up on the next render. We only update the
            # ``quota`` slice; other entitlement fields are unchanged.
            auth = getattr(self.app, "auth_service", None)
            if auth is not None:
                token = getattr(auth, "_token", None)
                if token is not None:
                    ents = dict(getattr(token, "entitlements", None) or {})
                    ents["quota"] = quota_block
                    token.entitlements = ents

        conv_id = data.get("conversation_id")
        if isinstance(conv_id, str) and conv_id:
            self._remote_conversation_id = conv_id

        self._update_stats()

    def _handle_stream_error(self, exc: BaseException, accumulated: str) -> None:
        """Route a streaming error through :func:`map_error_to_action`."""
        from servonaut.services.ai_error_handler import (
            UserFacingAction,
            map_error_to_action,
        )
        from servonaut.services.ai_sse import SSEStreamDead, SSEStreamError
        from servonaut.services.api_client import APIError

        if not isinstance(exc, (APIError, SSEStreamError, SSEStreamDead)):
            logger.exception("Unhandled exception in Servonaut stream")
            # A1 — exc may carry server-controlled markup. markup=False.
            self.app.notify(
                f"Stream failed: {exc}", severity="error", markup=False,
            )
            return

        payload = map_error_to_action(exc)

        # T10 watcher — count upstream_unavailable + heartbeat-deads.
        if payload.code == "upstream_unavailable":
            self._record_upstream_failure()
            self._maybe_offer_fallback()

        action = payload.action

        # A1 — `payload.user_message` is sourced from the server error
        # envelope (APIError.message / SSEStreamError.message). Pass
        # ``markup=False`` to every notify path that carries it so a
        # malicious server cannot inject Rich markup (e.g. a clickable
        # ``[link=evil]`` href) into the toast.
        if action == UserFacingAction.MODAL_QUOTA_EXHAUSTED:
            self._push_topup_modal(reason="Out of monthly tokens.")
        elif action == UserFacingAction.MODAL_BUDGET_EXHAUSTED:
            self._push_topup_modal(reason="Budget hard cap reached.")
        elif action == UserFacingAction.MODAL_UPGRADE_REQUIRED:
            # Refresh entitlements first per plan §T5 entitlement_required
            # ("trigger refresh_entitlements first to handle plan staleness").
            auth = getattr(self.app, "auth_service", None)
            if auth is not None and payload.code == "entitlement_required":
                self.run_worker(
                    auth.fetch_entitlements(),
                    name="ai_refresh_entitlements_post_error",
                    group="ai_chat",
                )
            self.app.notify(
                payload.user_message,
                severity="warning",
                markup=False,
            )
        elif action == UserFacingAction.BANNER_FEATURE_OFF:
            self._set_banner(
                f"[yellow]{_rich_escape(payload.user_message)}[/yellow]"
            )
        elif action == UserFacingAction.BANNER_UPSTREAM_FLAKY:
            self._set_banner(
                f"[yellow]{_rich_escape(payload.user_message)}[/yellow]"
            )
        elif action == UserFacingAction.AUTO_RETRY_WITH_BACKOFF:
            self.app.notify(
                payload.user_message,
                severity="information",
                markup=False,
            )
        elif action == UserFacingAction.AUTO_CHUNK_AND_RETRY:
            self.app.notify(
                payload.user_message,
                severity="warning",
                markup=False,
            )
        elif action == UserFacingAction.LOG_ONLY:
            logger.warning(
                "AI %s: %s (details=%r)",
                payload.code, payload.user_message, payload.details,
            )
            self.app.notify(
                payload.user_message, severity="warning", markup=False,
            )
        else:
            self.app.notify(
                payload.user_message, severity="error", markup=False,
            )

    def _push_topup_modal(self, *, reason: str) -> None:
        """Show :class:`AITopUpModal`; on a pack pick, drive checkout."""
        from servonaut.screens.ai_topup_modal import AITopUpModal

        def _on_pack(pack: Optional[str]) -> None:
            if not pack:
                return
            self.run_worker(
                self._do_topup_checkout(pack),
                name="ai_topup_checkout",
                group="ai_chat",
            )

        try:
            self.app.push_screen(AITopUpModal(reason=reason), _on_pack)
        except Exception:
            logger.exception("Failed to push AITopUpModal")

    async def _do_topup_checkout(self, pack: str) -> None:
        """Worker: open the Stripe Checkout URL and schedule entitlements refresh.

        A4 — validates the URL is a Stripe-hosted checkout origin before
        auto-launching the browser. A mismatch logs a warning and shows
        the URL for manual copy-paste rather than potentially redirecting
        to a phishing page.
        """
        from servonaut.services.ai_providers.servonaut_provider import (
            is_valid_stripe_checkout_url,
        )

        provider = getattr(self.app, "servonaut_provider", None)
        if provider is None:
            # A1/A5 — message contains no server-controlled data, but
            # use markup=False uniformly so behaviour is predictable.
            self.app.notify(
                "Servonaut AI not initialised.", severity="error", markup=False,
            )
            return
        try:
            url = await provider.topup_checkout(pack)
        except Exception as exc:  # noqa: BLE001
            # A1 — exc message can carry server-controlled markup (e.g. the
            # APIError message). Pass through markup=False so brackets stay
            # literal.
            self.app.notify(
                f"Top-up failed: {exc}", severity="error", markup=False,
            )
            return

        # A4 — validate the URL host strictly. Anything other than
        # Stripe's checkout origin: log + tell the user to open manually.
        if not is_valid_stripe_checkout_url(url):
            logger.warning(
                "Top-up checkout returned non-Stripe URL %r (pack=%s) — refusing auto-open",
                url, pack,
            )
            self.app.notify(
                f"Open this URL manually: {url}",
                severity="warning",
                markup=False,
            )
        else:
            try:
                webbrowser.open(url)
            except Exception:
                self.app.notify(
                    f"Open this URL in your browser: {url}",
                    severity="warning",
                    markup=False,
                )

        auth = getattr(self.app, "auth_service", None)
        if auth is not None and hasattr(auth, "schedule_post_topup_refresh"):
            try:
                await auth.schedule_post_topup_refresh()
            except Exception:
                logger.debug("schedule_post_topup_refresh failed", exc_info=True)

    # ------------------------------------------------------------------
    # Public hand-offs called from AIConversationsScreen (Local + Cloud
    # tabs). Both pop the conversations screen on success — see callers.
    # ------------------------------------------------------------------

    def load_local_session(self, session_id: str) -> None:
        """Public alias so AIConversationsScreen's Local tab can swap
        the active chat thread to a saved local session.

        ``_load_session`` already does the right thing (clears the
        remote conversation pointer so a new turn starts a fresh
        Cloud row unless the saved session was paired). Wrapping it
        keeps the public surface stable if the implementation moves.
        """
        self._load_session(session_id)

    def load_remote_conversation(self, uuid: str) -> None:
        """Load a remote (hosted) conversation as the active chat thread.

        Fetches the full thread via
        ``app.ai_conversations_client.get(uuid)``, rebuilds a transient
        :class:`ChatSession` from the returned messages, swaps it in as
        the active session, and re-renders.

        The remote conversation_id is stored separately so the next
        :meth:`_do_send_servonaut` call passes it to ``stream_chat``
        for a continuation turn (server re-attaches the same
        conversation row).
        """
        client = getattr(self.app, "ai_conversations_client", None)
        if client is None:
            self.app.notify(
                "Conversations client not available.", severity="warning",
            )
            return

        async def _load() -> None:
            try:
                thread = await client.get(uuid)
            except Exception as exc:  # noqa: BLE001
                logger.exception("load_remote_conversation get failed")
                # A2 — exc may surface a server-controlled APIError.message
                # carrying Rich markup. ``markup=False`` keeps it literal.
                self.app.notify(
                    f"Failed to load conversation: {exc}",
                    severity="error",
                    markup=False,
                )
                return

            from servonaut.services.chat_service import ChatMessage, ChatSession

            messages: List[ChatMessage] = []
            for raw in thread.get("messages") or []:
                role = str(raw.get("role") or "")
                # Tool / system messages are skipped — the local chat UI
                # only renders user / assistant bubbles.
                if role not in ("user", "assistant"):
                    continue
                content = raw.get("content")
                if isinstance(content, list):
                    # Anthropic-style content blocks → join text-only.
                    parts = [
                        b.get("text", "") for b in content
                        if isinstance(b, dict) and b.get("type") == "text"
                    ]
                    content = "\n".join(p for p in parts if p)
                if not isinstance(content, str):
                    content = str(content or "")
                messages.append(
                    ChatMessage(
                        role=role,
                        content=content,
                        timestamp=str(raw.get("timestamp") or "") or "",
                        provider="servonaut",
                    )
                )

            session = ChatSession(
                id=str(thread.get("id") or uuid),
                title=str(thread.get("title") or "Remote conversation"),
                messages=messages,
                remote_conversation_id=str(uuid),
            )
            self._session = session
            self._remote_conversation_id = str(uuid)
            self._total_tokens = 0
            self._total_cost = 0.0
            self.call_after_refresh(self._refresh_messages)

        self.run_worker(
            _load(),
            name="ai_chat_load_remote",
            group="ai_chat",
            exclusive=True,
        )
