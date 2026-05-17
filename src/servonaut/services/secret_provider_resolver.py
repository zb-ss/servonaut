"""Resolve the active :class:`SecretProviderInterface` for a session.

Step 6 of the kickoff plan
(``~/.dotfiles/org/org/servonaut/plans/kickoff-secrets-management.org``).

The resolver collapses the moving parts — auth state, entitlements,
cached team :class:`SecretsConfig`, environment env-var seam — into
a single function that returns either:

- A concrete provider (:class:`LocalProvider` or
  :class:`BitwardenProvider`) instance the SSH layer should consult
  first when looking up a key by name.
- ``None`` — used for unauthenticated sessions and Free-tier users.
  :class:`SSHService` defaults to legacy ``~/.ssh``-only discovery in
  that case (Step 5 made this branch a zero-behaviour-change path).

Why a free function and not a class with state? The resolver runs
exactly once per app boot (and again on Settings-screen "refresh"
clicks) and the inputs it consumes are already objects with their
own lifecycle. Wrapping it in a stateless function keeps the call
site obvious and lets tests pass mocks without ceremony.

Fetch responsibilities are NOT here:
    The resolver is sync — it consults the *current* cache. Refreshing
    the cache against the live API happens via
    :func:`fetch_and_apply_secrets_config` in this same module, an
    async helper the app boot worker fires when the cache is stale or
    cold. Splitting the two keeps the sync hot path independent of the
    network.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Awaitable, Callable, Optional, Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.services.auth_service import AuthService
    from servonaut.services.entitlement_guard import EntitlementGuard

from servonaut.config.schema import SecretsConfig
from servonaut.services.interfaces import SecretProviderInterface
from servonaut.services.secret_provider import LocalProvider

logger = logging.getLogger(__name__)


# Env var that swaps the production
# :meth:`APIClient.get_team_secrets_config` for the
# :class:`FakeSecretsConfigClient`. Set to a truthy value during dev
# runs while servonaut-web's staging endpoint is still being
# stabilised. Removed from the wiring once Step 7 ships and the
# joint E2E runs against the real endpoint.
FAKE_CLIENT_ENV_VAR = "SERVONAUT_SECRETS_FAKE"


class _SecretsConfigClient(Protocol):
    """Structural type matching both
    :meth:`APIClient.get_team_secrets_config` and
    :meth:`FakeSecretsConfigClient.get_team_secrets_config`.

    Defined here so the resolver doesn't have to depend on the
    concrete APIClient class (and through it httpx, the auth service,
    etc.) at import time.
    """

    async def get_team_secrets_config(
        self, slug: str,
    ) -> Optional[dict]:  # pragma: no cover - protocol body
        ...


def is_fake_client_env_enabled() -> bool:
    """``True`` if :data:`FAKE_CLIENT_ENV_VAR` is set to a truthy value.

    Truthy: ``1``, ``true``, ``yes``, ``on`` (case-insensitive).
    Anything else, including unset, returns False.
    """
    raw = os.environ.get(FAKE_CLIENT_ENV_VAR, "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def resolve_secret_provider(
    auth_service: "AuthService",
    entitlement_guard: "EntitlementGuard",
) -> Optional[SecretProviderInterface]:
    """Pick the active provider for the current session.

    Cascade (each gate failing falls through to the next):

    1. **Unauthenticated** → return ``None``. SSHService keeps legacy
       ``~/.ssh`` behaviour — exactly what a fresh-install / logged-out
       user got before the secrets-management feature shipped.
    2. **Refresh-token revoked** flag set on the auth service → also
       ``None``. The user is effectively logged-out from the secrets
       backend's POV; don't try to use a stale Bitwarden token they
       have no way of refreshing.
    3. **Free tier** → ``None`` (kickoff doc §Tier gating: Solo + Teams
       only). Surfacing an "upgrade your plan" prompt belongs at the
       UI layer; the resolver just doesn't hand out a provider.
    4. **No team config cached + no local-only opt-in** → return
       :class:`LocalProvider`. Solo users with no team association
       still get the local backend as their personal-secrets store.
    5. **Cached config says** ``provider="bitwarden"`` →
       :class:`BitwardenProvider`. We trust the cache's allowlist-
       coerced provider name (Audit Fix 2) so a server-side stale or
       hostile string can never escape to provider construction.
       Missing ``project_id`` in the config falls back to
       :class:`LocalProvider` with a WARNING — the team admin needs
       to finish their setup.
    6. **Cached config says anything else** → :class:`LocalProvider`.
    """
    # Lazy imports of the concrete bitwarden provider so a fresh CLI
    # without the bitwarden extras installed still boots — the
    # constructor doesn't need bws to be present, but the class
    # itself is imported here for instantiation.
    from servonaut.services.bitwarden_provider import BitwardenProvider

    if not auth_service.is_authenticated:
        logger.debug("resolve_secret_provider: unauthenticated → None")
        return None

    allowed, reason = entitlement_guard.check("secrets_management")
    if not allowed:
        logger.info(
            "resolve_secret_provider: secrets_management not entitled (%s) → None",
            reason,
        )
        return None

    cfg = auth_service.cached_secrets_config()
    if not isinstance(cfg, SecretsConfig):
        logger.warning(
            "resolve_secret_provider: unexpected cache shape %s → falling back "
            "to LocalProvider",
            type(cfg).__name__,
        )
        return LocalProvider()

    if cfg.provider == "bitwarden":
        project_id = cfg.config.get("project_id", "") if cfg.config else ""
        if not isinstance(project_id, str) or not project_id:
            logger.warning(
                "resolve_secret_provider: team config says bitwarden but no "
                "project_id present (config=%r); falling back to LocalProvider. "
                "The team admin needs to complete the Bitwarden setup at "
                "/account/teams/<slug>/secrets.",
                cfg.config,
            )
            return LocalProvider()
        token_env_var = cfg.config.get("token_env_var", "BWS_ACCESS_TOKEN")
        if not isinstance(token_env_var, str) or not token_env_var:
            token_env_var = "BWS_ACCESS_TOKEN"
        logger.info(
            "resolve_secret_provider: BitwardenProvider(project_id=%s, "
            "token_env_var=%s)",
            project_id[:8] + "…" if len(project_id) > 8 else project_id,
            token_env_var,
        )
        return BitwardenProvider(
            project_id=project_id,
            token_env_var=token_env_var,
        )

    # cfg.provider == "local" or anything Audit-Fix-2 coerced into it.
    logger.debug("resolve_secret_provider: LocalProvider")
    return LocalProvider()


async def fetch_and_apply_secrets_config(
    auth_service: "AuthService",
    client: _SecretsConfigClient,
    slug: str,
) -> bool:
    """Refresh the cached :class:`SecretsConfig` from the live API.

    Async-safe wrapper around the client's
    :meth:`get_team_secrets_config` so the app boot worker (or a
    future "refresh" command) can fan out without re-implementing
    the error-classification logic.

    Returns:
        ``True`` if the cache moved (apply or clear succeeded).
        ``False`` on transient failure where the existing cache is
        left untouched — same philosophy as
        :meth:`AuthService.refresh_token`'s
        retain-on-transient-failure path.

    Error handling map:

    - 200 → :meth:`AuthService.apply_secrets_config` (Audit Fix 3
      enforces the 16 KiB size cap at the persist layer).
    - 404 (the client returns ``None`` for this case) →
      :meth:`AuthService.clear_secrets_cache` so the next resolve
      drops to :class:`LocalProvider`.
    - :class:`PaymentRequiredError` (402) /
      :class:`ForbiddenError` (403) → clear the cache. The user has
      either downgraded, lost team membership, or had the team
      deleted; the resolver should reflect that on the next call.
    - :class:`APIError` 4xx not enumerated above OR transport error
      → keep the cache, log a WARNING. A flaky network must not
      log the user out of their team's secrets store.
    """
    # Lazy imports to avoid a circular boot order when this module
    # is imported during AuthService construction.
    from servonaut.services.api_client import (
        APIError,
        ForbiddenError,
        PaymentRequiredError,
    )

    try:
        payload = await client.get_team_secrets_config(slug=slug)
    except (PaymentRequiredError, ForbiddenError) as exc:
        logger.info(
            "fetch_and_apply_secrets_config(%s): %s → clearing cache "
            "(falling back to LocalProvider on next resolve)",
            slug, exc.code,
        )
        auth_service.clear_secrets_cache()
        return True
    except APIError as exc:
        logger.warning(
            "fetch_and_apply_secrets_config(%s): API error %s (%s); "
            "keeping existing cache",
            slug, exc.status, exc.code,
        )
        return False
    except Exception as exc:  # noqa: BLE001 — transport-level
        logger.warning(
            "fetch_and_apply_secrets_config(%s): transport error (%s); "
            "keeping existing cache",
            slug, exc,
        )
        return False

    if payload is None:
        # Endpoint returned 404 — no team config exists.
        logger.info(
            "fetch_and_apply_secrets_config(%s): server returned 404; "
            "clearing cache so resolver drops to LocalProvider",
            slug,
        )
        auth_service.clear_secrets_cache()
        return True

    # Defensive slug-consistency check (servonaut-dev's suggestion on
    # the kickoff thread 2026-05-17 15:39 UTC). When the server adds
    # the additive ``team_slug`` echo to the response body, verify it
    # matches the slug we used in the URL. Mismatch = potential
    # server-side mapping bug → log WARNING but do NOT raise; the URL
    # slug was correct (the server returned 200 for it) so the cache
    # is still right for the URL — only the echoed metadata is suspect.
    # Operators can grep the warning; users see no surface effect.
    if isinstance(payload, dict):
        echoed = payload.get("team_slug")
        if isinstance(echoed, str) and echoed and echoed != slug:
            logger.warning(
                "fetch_and_apply_secrets_config(%s): server echoed "
                "team_slug=%r in response body — does NOT match URL "
                "slug. Likely server-side slug-mapping inconsistency; "
                "the URL-side response is still authoritative for the "
                "config payload, but operators should investigate.",
                slug, echoed,
            )

    auth_service.apply_secrets_config(payload)
    return True
