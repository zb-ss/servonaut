"""In-memory stand-in for the secrets-management API client.

While servonaut-web's
``GET /api/v1/teams/{slug}/secrets-config`` endpoint is still under
development (kickoff doc Step W5 → security review → Playwright E2E
→ staging deploy), Steps 5 and 6 on the CLI side need *something*
to call. :class:`FakeSecretsConfigClient` is that something: it
implements the same callable signature as
:meth:`APIClient.get_team_secrets_config` so consumers can swap one
for the other without touching call sites.

Scope:
    Lives in ``src/`` rather than ``tests/`` because dev runs of the
    CLI (``servonaut --debug`` against an in-memory team) want to
    exercise the BitwardenProvider path BEFORE the real endpoint is
    live. The fake is opt-in — production wiring (Step 6) selects
    between :class:`APIClient.get_team_secrets_config` and this fake
    via the env var :data:`SERVONAUT_SECRETS_FAKE` (off by default).

Removal plan:
    The kickoff doc Step 7 (joint E2E) will remove the env var and
    the fake's references from the wiring code. The class itself
    stays in the codebase as a test-support utility — the unit
    tests for Step 5 and 6 will keep using it.

Team identifier model:
    The real endpoint is keyed on team SLUG (URL-safe identifier),
    not integer id — locked in the kickoff doc and re-confirmed by
    servonaut-dev's W5 contract delta. This fake follows suit so
    test code reads like production code.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Dict, Optional, Union

logger = logging.getLogger(__name__)


# A scripted error: either an Exception instance or a zero-arg
# callable that constructs one (so test scripts can defer the
# expensive imports if they want). The fake re-raises whichever the
# script returns.
_ErrorFactory = Union[Exception, Callable[[], Exception]]


class FakeSecretsConfigClient:
    """In-memory mock of the secrets-management API surface.

    Configure with :meth:`configure` to return a 200 payload for a
    given ``slug``, or :meth:`configure_error` to make the call
    raise (simulating 402 / 403 / network errors). Unconfigured
    slugs resolve to ``None`` — matching the production endpoint's
    404 → fall-back-to-Local behaviour.

    Thread-safety: not concurrent-safe. The CLI's secrets path is
    single-coroutine-at-a-time (one TUI session, one MCP session)
    so we don't need an asyncio.Lock here. If a future call site
    needs concurrent access, layer that in at the call site, not
    here — we don't want the fake to drift from the real client's
    threading model.
    """

    def __init__(self) -> None:
        # slug → (payload, error_factory). Only one of the two is
        # ever set per entry; the call site picks based on which one
        # is populated.
        self._payloads: Dict[str, Dict[str, Any]] = {}
        self._errors: Dict[str, _ErrorFactory] = {}
        # Optional latency injection — useful when testing the
        # stale-while-revalidate cache path and chat-panel spinners.
        self._latency_seconds: float = 0.0

    # ------------------------------------------------------------------
    # Configuration surface
    # ------------------------------------------------------------------

    def configure(self, slug: str, payload: Dict[str, Any]) -> None:
        """Return ``payload`` (as a 200) for ``slug``.

        ``payload`` is a defensive-copy snapshot — the caller may
        mutate their original dict after the call without it
        bleeding into the fake's state.
        """
        clean = self._clean_slug(slug)
        self._payloads[clean] = dict(payload)
        # Configuring a payload clears any previously-scripted error
        # for the same slug — the two are mutually exclusive.
        self._errors.pop(clean, None)

    def configure_error(self, slug: str, err: _ErrorFactory) -> None:
        """Make :meth:`get_team_secrets_config` raise for ``slug``.

        ``err`` may be the exception INSTANCE itself (raised as-is
        on the next call), or a zero-arg callable that produces one
        each call — used to script "first call 5xx, second call 200"
        flows via a custom factory in tests.
        """
        clean = self._clean_slug(slug)
        self._errors[clean] = err
        self._payloads.pop(clean, None)

    def clear(self, slug: Optional[str] = None) -> None:
        """Drop all scripted state, optionally limited to one slug.

        Useful between test cases when a session-scoped fixture is
        re-used.
        """
        if slug is None:
            self._payloads.clear()
            self._errors.clear()
        else:
            clean = self._clean_slug(slug)
            self._payloads.pop(clean, None)
            self._errors.pop(clean, None)

    def set_latency(self, seconds: float) -> None:
        """Inject artificial delay into every call.

        Mirrors slow network conditions for tests that exercise the
        stale-while-revalidate path (cache hit while background
        refetch is still in flight).
        """
        self._latency_seconds = max(0.0, float(seconds))

    # ------------------------------------------------------------------
    # APIClient.get_team_secrets_config-shaped surface
    # ------------------------------------------------------------------

    async def get_team_secrets_config(
        self,
        slug: str,
    ) -> Optional[Dict[str, Any]]:
        """Same signature + return contract as
        :meth:`APIClient.get_team_secrets_config`.

        Resolution order:
        1. If an error is scripted for ``slug``, raise it.
        2. If a payload is scripted for ``slug``, return a
           defensive copy (callers may mutate their result without
           polluting the fake's state).
        3. Otherwise return ``None`` (production 404 behaviour →
           CLI falls back to LocalProvider).
        """
        if self._latency_seconds > 0:
            await asyncio.sleep(self._latency_seconds)

        clean = self._clean_slug(slug)
        if clean in self._errors:
            err = self._errors[clean]
            raised = err() if callable(err) else err
            raise raised
        if clean in self._payloads:
            return dict(self._payloads[clean])
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _clean_slug(slug: str) -> str:
        """Mirror :meth:`APIClient.get_team_secrets_config`'s slug
        normalisation so a test that writes ``" acme "`` ends up
        configuring ``"acme"`` and is retrieved by the same shape
        the production call site sends."""
        clean = (slug or "").strip()
        if not clean:
            raise ValueError(
                "FakeSecretsConfigClient slug must be a non-empty string; "
                "got %r" % (slug,)
            )
        return clean
