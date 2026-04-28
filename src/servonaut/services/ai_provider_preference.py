"""T4.5 provider preference resolver.

Encodes the 6-row decision tree from
``plans/cli/plan-premium-ai.org`` §"Decision tree at chat-start" plus the
banner-gating rules and lapse fallback ranking. Pure: reads
:class:`AuthService` cached state and :class:`ConfigManager` config; never
performs I/O.

The resolver returns a :class:`ProviderDecision` describing the active
provider AND a list of UX events the chat panel / picker should react to
(modal, banner, toast, pinned-error). Side effects — modal display,
toast, banner dismiss persistence — are caller responsibilities.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Literal, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.config.manager import ConfigManager
    from servonaut.services.auth_service import AuthService


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------


class ProviderPreferenceEvent(Enum):
    """One-shot UX events that the picker / chat panel must react to.

    The resolver emits these from :meth:`ProviderPreferenceResolver.resolve`;
    the consumer fires the appropriate UI (modal, banner, toast) and then
    calls back into :meth:`commit_first_run_choice` or
    :meth:`dismiss_banner` to persist the user's response.
    """

    SHOW_FIRST_RUN_MODAL = "show_first_run_modal"
    SHOW_EMPTY_STATE = "show_empty_state"
    SILENT_LAPSE = "silent_lapse"
    PINNED_ERROR_NO_PROVIDER = "pinned_error_no_provider"
    SHOW_PAYING_TWICE_BANNER = "show_paying_twice_banner"
    SHOW_CAPABILITY_BANNER = "show_capability_banner"


@dataclass
class ProviderDecision:
    """Outcome of resolving the active provider for chat-start.

    Attributes:
        active_provider: Name of the provider to use right now (one of
            ``servonaut``, ``openai``, ``anthropic``, ``ollama``, ``gemini``,
            or ``""`` when no provider is available — pinned-error state).
        events: One-shot UX events to fire (see
            :class:`ProviderPreferenceEvent`).
        fallback_provider: Populated for :class:`SILENT_LAPSE` and
            :class:`PINNED_ERROR_NO_PROVIDER` events so the toast can name
            the provider without re-resolving.
        dismissable_banner_id: Set when an event references a banner that
            can be dismissed forever (paying-twice / capability). Caller
            passes this back to :meth:`dismiss_banner` if the user clicks
            "don't show again".
    """

    active_provider: str
    events: List[ProviderPreferenceEvent] = field(default_factory=list)
    fallback_provider: Optional[str] = None
    dismissable_banner_id: Optional[str] = None


# Banner IDs persisted in ``AIProviderConfig.dismissed_banners``.
PAYING_TWICE_BANNER_ID = "ai.banner.paying_twice"
CAPABILITY_BANNER_ID = "ai.banner.capability"

# Stale-Settings threshold for the "paying twice" banner per plan §banner gating.
_PAYING_TWICE_STALE_SECONDS = 30 * 24 * 3600

# Cloud providers that incur per-token charges separately from a Servonaut
# subscription. Source of "you may be paying twice" detection.
_CLOUD_PROVIDERS = frozenset({"openai", "anthropic", "gemini"})

# Local provider that has no API cost. Source of the capability-framed banner.
_LOCAL_PROVIDER = "ollama"

# Order used by :meth:`_resolve_lapse_fallback` step 3.
_FALLBACK_RANK = ("openai", "anthropic", "ollama", "gemini")


class ProviderPreferenceResolver:
    """Pure resolver — encodes the T4.5 decision tree."""

    # Configured-detection rules per plan §"Has any non-Servonaut provider
    # configured". Each lambda receives the :class:`AIProviderConfig`.
    # v4 — per-provider keys. ``c.key_for(name)`` returns the key bound to
    # *name* (with legacy ``api_key`` as a same-provider fallback) so a
    # leftover OpenAI key no longer makes Anthropic and Gemini look
    # configured too. Ollama still keys off ``base_url`` since it has no
    # API key.
    _CONFIG_RULES = {
        "openai":    lambda c: bool(c.key_for("openai")),
        "anthropic": lambda c: bool(c.key_for("anthropic")),
        # Ollama: configured if the user has either set a non-default base
        # URL (typical of local installs that bind a different port) OR
        # supplied a Cloud API key (https://ollama.com). A user on default
        # local install with no key still needs to be detected; that case
        # would be base_url="" and key="" which we treat as "not
        # configured" because we can't tell whether Ollama is actually
        # running.
        "ollama":    lambda c: bool(c.base_url) or bool(c.key_for("ollama")),
        "gemini":    lambda c: bool(c.key_for("gemini")),
    }

    def __init__(
        self,
        auth_service: "AuthService",
        config_manager: "ConfigManager",
    ) -> None:
        self._auth = auth_service
        self._config_manager = config_manager

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def _cfg(self):
        """Return the current :class:`AIProviderConfig`."""
        return self._config_manager.get().ai_provider

    def is_provider_configured(self, name: str) -> bool:
        """Return True iff *name* is one of the non-Servonaut providers AND
        meets the per-provider configured rule.

        Servonaut is always considered configured for an entitled user — but
        it is NOT included here because this predicate is specifically about
        "user's existing local config". Per plan §"Has any non-Servonaut
        provider configured".
        """
        if name == "servonaut":
            # Caller wants `has_any_non_servonaut_configured` semantics; do
            # not count servonaut.
            return False
        rule = self._CONFIG_RULES.get(name)
        if rule is None:
            return False
        try:
            return bool(rule(self._cfg))
        except Exception:
            return False

    def has_any_non_servonaut_configured(self) -> bool:
        """Return True if any of openai/anthropic/ollama/gemini is configured."""
        return any(
            self.is_provider_configured(name) for name in self._CONFIG_RULES
        )

    def cloud_providers_configured(self) -> List[str]:
        """Subset of {openai, anthropic, gemini} that are configured."""
        return [
            name for name in self._CONFIG_RULES
            if name in _CLOUD_PROVIDERS and self.is_provider_configured(name)
        ]

    # ------------------------------------------------------------------
    # Entitlement / transition state
    # ------------------------------------------------------------------

    def _has_premium_ai(self) -> bool:
        """Auth-cached premium-AI flag. Returns False when unauthenticated."""
        try:
            return bool(self._auth.has_feature("premium_ai"))
        except Exception:
            return False

    def detect_premium_ai_transition(
        self,
    ) -> Optional[Literal["activated", "lapsed"]]:
        """Detect a bool transition from the cached AuthToken state.

        Returns ``"activated"`` for ``False → True``, ``"lapsed"`` for
        ``True → False``, ``None`` otherwise (steady-state or
        :class:`AuthToken` absent). Mirrors Risk §5: a missing token snapshot
        never produces a phantom edge.
        """
        token = getattr(self._auth, "_token", None)
        if token is None:
            return None
        was_active = bool(getattr(token, "premium_ai_was_active", False))
        is_active = self._has_premium_ai()
        if was_active and not is_active:
            return "lapsed"
        if (not was_active) and is_active:
            return "activated"
        return None

    # ------------------------------------------------------------------
    # Banner gating
    # ------------------------------------------------------------------

    def is_banner_dismissed(self, banner_id: str) -> bool:
        """True if the user has dismissed *banner_id* forever."""
        try:
            return banner_id in (self._cfg.dismissed_banners or [])
        except Exception:
            return False

    def _settings_is_stale(self) -> bool:
        """True if the user hasn't visited Settings within the last 30 days.

        ``settings_last_visited_at == 0.0`` (the dataclass default) is
        treated as stale per the agent brief — the banner shows on first
        chat-screen open until the user has visited Settings at least once.
        """
        token = getattr(self._auth, "_token", None)
        if token is None:
            return False  # Unauth: no banner to consider.
        last = float(getattr(token, "settings_last_visited_at", 0.0) or 0.0)
        if last <= 0.0:
            return True
        return (time.time() - last) > _PAYING_TWICE_STALE_SECONDS

    def _emit_banner_events(
        self,
        active_provider: str,
        events: List[ProviderPreferenceEvent],
    ) -> Optional[str]:
        """Append banner events for *active_provider*; return banner_id if any.

        - Cost-framed "paying twice" banner: premium_ai True AND active
          provider is cloud (openai / anthropic / gemini) AND Settings is
          stale AND banner not dismissed.
        - Capability-framed banner: active provider is ollama AND banner not
          dismissed.

        Per plan: the two banners are mutually exclusive by which provider
        is active, so only one can fire per resolve() call.
        """
        if (
            self._has_premium_ai()
            and active_provider in _CLOUD_PROVIDERS
            and self._settings_is_stale()
            and not self.is_banner_dismissed(PAYING_TWICE_BANNER_ID)
        ):
            events.append(ProviderPreferenceEvent.SHOW_PAYING_TWICE_BANNER)
            return PAYING_TWICE_BANNER_ID

        if (
            active_provider == _LOCAL_PROVIDER
            and not self.is_banner_dismissed(CAPABILITY_BANNER_ID)
        ):
            events.append(ProviderPreferenceEvent.SHOW_CAPABILITY_BANNER)
            return CAPABILITY_BANNER_ID

        return None

    # ------------------------------------------------------------------
    # Lapse fallback
    # ------------------------------------------------------------------

    def _resolve_lapse_fallback(self) -> Optional[str]:
        """Pick a lapse fallback per plan §"Subscription lapse / downgrade".

        Priority:
            1. ``ai.local_fallback_provider`` if explicitly set and configured.
            2. ``AuthToken.last_used_provider`` if non-Servonaut and configured.
            3. First configured in (openai, anthropic, ollama, gemini) order.
            4. ``None`` → caller emits PINNED_ERROR_NO_PROVIDER.
        """
        cfg = self._cfg
        explicit = cfg.local_fallback_provider
        if explicit and self.is_provider_configured(explicit):
            return explicit

        token = getattr(self._auth, "_token", None)
        last = ""
        if token is not None:
            last = str(getattr(token, "last_used_provider", "") or "")
        if last and last != "servonaut" and self.is_provider_configured(last):
            return last

        for name in _FALLBACK_RANK:
            if self.is_provider_configured(name):
                return name
        return None

    # ------------------------------------------------------------------
    # Public surface — main resolver
    # ------------------------------------------------------------------

    def resolve(self) -> ProviderDecision:
        """Encode the 6-row decision table from the plan.

        | Subscription | Configured | Preference | active_provider              |
        |--------------|------------|------------|------------------------------|
        | Yes          | Yes        | Yes        | preference                   |
        | Yes          | Yes        | No         | servonaut + FIRST_RUN_MODAL  |
        | Yes          | No         | n/a        | servonaut                    |
        | No           | Yes        | Yes        | preference                   |
        | No           | Yes        | No         | first-configured             |
        | No           | No         | n/a        | "" + EMPTY_STATE             |

        Plus orthogonal lapse / banner / pinned-error annotations.
        """
        events: List[ProviderPreferenceEvent] = []
        cfg = self._cfg
        preference = cfg.provider_preference
        has_premium = self._has_premium_ai()
        any_other = self.has_any_non_servonaut_configured()

        # 1. Lapse detection runs FIRST so a transition that disables
        # servonaut never lands as the active provider.
        transition = self.detect_premium_ai_transition()
        if transition == "lapsed":
            fallback = self._resolve_lapse_fallback()
            if fallback is None:
                return ProviderDecision(
                    active_provider="",
                    events=[ProviderPreferenceEvent.PINNED_ERROR_NO_PROVIDER],
                    fallback_provider=None,
                )
            decision = ProviderDecision(
                active_provider=fallback,
                events=[ProviderPreferenceEvent.SILENT_LAPSE],
                fallback_provider=fallback,
            )
            decision.dismissable_banner_id = self._emit_banner_events(
                fallback, decision.events,
            )
            return decision

        # 2. Subscribed (steady or activated).
        if has_premium:
            if not any_other:
                # Row 3: subscribed, no other provider configured.
                return ProviderDecision(active_provider="servonaut")

            if preference:
                # Row 1: explicit preference wins.
                decision = ProviderDecision(active_provider=preference)
                decision.dismissable_banner_id = self._emit_banner_events(
                    preference, decision.events,
                )
                return decision

            # Row 2: subscribed + other provider + no preference set →
            # default to servonaut and prompt the user via the first-run
            # modal. The transition flag is informational for the
            # caller; the modal fires either way (steady-state subscribers
            # who haven't picked yet still need to be asked).
            events.append(ProviderPreferenceEvent.SHOW_FIRST_RUN_MODAL)
            return ProviderDecision(
                active_provider="servonaut",
                events=events,
            )

        # 3. Not subscribed.
        if not any_other:
            # Row 6: empty-state — neither subscription nor configured provider.
            return ProviderDecision(
                active_provider="",
                events=[ProviderPreferenceEvent.SHOW_EMPTY_STATE],
            )

        if preference and preference != "servonaut":
            # Row 4: honour preference (servonaut preference is meaningless
            # without entitlement; fall through to first-configured).
            decision = ProviderDecision(active_provider=preference)
            decision.dismissable_banner_id = self._emit_banner_events(
                preference, decision.events,
            )
            return decision

        # Row 5: use first-configured.
        first = next(
            (n for n in _FALLBACK_RANK if self.is_provider_configured(n)),
            "",
        )
        decision = ProviderDecision(active_provider=first)
        if first:
            decision.dismissable_banner_id = self._emit_banner_events(
                first, decision.events,
            )
        return decision

    # ------------------------------------------------------------------
    # Mutators (called by the picker / chat panel after user action)
    # ------------------------------------------------------------------

    def commit_first_run_choice(
        self,
        choice: Literal[
            "servonaut", "openai", "anthropic", "ollama", "gemini"
        ],
    ) -> None:
        """Persist the user's first-run-modal pick to ``ai.provider_preference``.

        This is NOT a banner dismiss — it is a routing preference that
        prevents the modal from re-firing. Banners have their own
        :meth:`dismiss_banner`.
        """
        config = self._config_manager.get()
        config.ai_provider.provider_preference = choice
        self._config_manager.save(config)

    def dismiss_banner(self, banner_id: str) -> None:
        """Append *banner_id* to ``ai.dismissed_banners`` and persist.

        Idempotent: dismissing a banner that's already in the list is a
        no-op. Each banner ID is persisted exactly once.
        """
        config = self._config_manager.get()
        if not isinstance(config.ai_provider.dismissed_banners, list):
            config.ai_provider.dismissed_banners = []
        if banner_id not in config.ai_provider.dismissed_banners:
            config.ai_provider.dismissed_banners.append(banner_id)
            self._config_manager.save(config)

    def reset(self) -> None:
        """Implementation of ``servonaut ai provider reset``.

        Clears both the explicit preference AND every dismissed banner so
        the user gets the first-run-modal / banner experience again on the
        next chat-start.
        """
        config = self._config_manager.get()
        config.ai_provider.provider_preference = None
        config.ai_provider.dismissed_banners = []
        self._config_manager.save(config)


__all__ = [
    "ProviderPreferenceEvent",
    "ProviderDecision",
    "ProviderPreferenceResolver",
    "PAYING_TWICE_BANNER_ID",
    "CAPABILITY_BANNER_ID",
]
