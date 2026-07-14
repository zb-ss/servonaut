"""Resolve the active :class:`SecretProviderInterface` for a session.

Part of the secrets-management feature.

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
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional, Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.services.auth_service import AuthService
    from servonaut.services.entitlement_guard import EntitlementGuard

from servonaut.config.schema import SecretsConfig


@dataclass(frozen=True)
class EffectiveSecretsConfig:
    """Which cached config the provider is actually built from, and why.

    Encapsulates the team→personal→local precedence *including the
    fallthrough*: a team bitwarden config with an unusable project id is
    skipped in favour of a usable personal config, rather than dropping
    straight to Local. Both :func:`resolve_secret_provider` and the status
    snapshot consume this so the resolved provider and the panel never
    disagree about which config is live.
    """

    config: SecretsConfig       # the config the provider is built from
    source: Optional[str]       # "team" | "user" | None (local default)
    provider_name: str          # "bitwarden" | "local"
    # A team bitwarden config was present but unusable (bad project id), so
    # it was skipped. Set whether the fallthrough landed on personal or local.
    team_config_broken: bool = False
    # The offending project id (team, or the user's own broken one) — for the
    # panel's needs-attention message.
    broken_project_id: Optional[str] = None


def _usable_bitwarden(cfg: object) -> bool:
    from servonaut.services.secrets_status import is_valid_project_id

    return (
        isinstance(cfg, SecretsConfig)
        and cfg.provider == "bitwarden"
        and is_valid_project_id((cfg.config or {}).get("project_id"))
    )


def _is_bitwarden(cfg: object) -> bool:
    return isinstance(cfg, SecretsConfig) and cfg.provider == "bitwarden"


def _project_id_of(cfg: object) -> Optional[str]:
    if isinstance(cfg, SecretsConfig):
        return (cfg.config or {}).get("project_id") or None
    return None


def resolve_effective_secrets_config(
    auth_service: "AuthService",
) -> EffectiveSecretsConfig:
    """Resolve the precedence-winning USABLE config (assumes auth+entitled).

    team (if usable) → personal (if team is a broken bitwarden config) →
    LocalProvider default. Pure: consults caches only, no network, no IO.
    """
    source = auth_service.secrets_config_source()  # "team" | "user" | None

    if source == "team":
        team_cfg = auth_service.cached_secrets_config()
        if _usable_bitwarden(team_cfg):
            return EffectiveSecretsConfig(team_cfg, "team", "bitwarden")
        if _is_bitwarden(team_cfg):
            # Team wants bitwarden but its project id is unusable — skip it
            # and try the personal config before dropping to Local.
            broken = _project_id_of(team_cfg)
            user_cfg = auth_service.cached_user_secrets_config()
            if _usable_bitwarden(user_cfg):
                return EffectiveSecretsConfig(
                    user_cfg, "user", "bitwarden",
                    team_config_broken=True, broken_project_id=broken,
                )
            return EffectiveSecretsConfig(
                SecretsConfig.local_default(), None, "local",
                team_config_broken=True, broken_project_id=broken,
            )
        # Team config is a Local provider — honour it.
        return EffectiveSecretsConfig(team_cfg, "team", "local")

    if source == "user":
        user_cfg = auth_service.cached_secrets_config()
        if _usable_bitwarden(user_cfg):
            return EffectiveSecretsConfig(user_cfg, "user", "bitwarden")
        if _is_bitwarden(user_cfg):
            # The user's own bitwarden config is broken → Local, flag the id.
            return EffectiveSecretsConfig(
                user_cfg, "user", "local",
                broken_project_id=_project_id_of(user_cfg),
            )
        return EffectiveSecretsConfig(user_cfg, "user", "local")

    # No server config cached → LocalProvider default.
    return EffectiveSecretsConfig(SecretsConfig.local_default(), None, "local")
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

    async def get_user_secrets_config(
        self,
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
    3. **Free tier** → ``None`` (tier gating: Solo + Teams
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

    eff = resolve_effective_secrets_config(auth_service)
    if eff.team_config_broken:
        logger.warning(
            "resolve_secret_provider: team bitwarden config has an unusable "
            "project_id (%r); %s. Fix it in the team secrets settings.",
            eff.broken_project_id,
            "using the personal config instead" if eff.provider_name == "bitwarden"
            else "falling back to LocalProvider",
        )

    if eff.provider_name == "bitwarden":
        cfg = eff.config
        project_id = (cfg.config or {}).get("project_id", "")
        token_env_var = (cfg.config or {}).get("token_env_var") or "BWS_ACCESS_TOKEN"
        if not isinstance(token_env_var, str) or not token_env_var:
            token_env_var = "BWS_ACCESS_TOKEN"
        logger.info(
            "resolve_secret_provider: BitwardenProvider(project_id=%s, "
            "token_env_var=%s, source=%s)",
            project_id[:8] + "…" if len(project_id) > 8 else project_id,
            token_env_var, eff.source,
        )
        return BitwardenProvider(
            project_id=project_id,
            token_env_var=token_env_var,
        )

    logger.debug("resolve_secret_provider: LocalProvider (source=%s)", eff.source)
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

    # Defensive slug-consistency check. When the server adds
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


async def fetch_and_apply_user_secrets_config(
    auth_service: "AuthService",
    client: _SecretsConfigClient,
) -> bool:
    """Refresh the cached personal :class:`SecretsConfig` from the live API.

    Personal-scope analogue of :func:`fetch_and_apply_secrets_config`,
    hitting ``GET /api/v1/me/secrets-config``. Mutates ONLY the personal
    cache (``apply_user_secrets_config`` / ``clear_user_secrets_cache``)
    so a personal-scope failure never disturbs the team cache — the
    isolation the precedence layer relies on.

    Returns ``True`` if the personal cache moved (apply or clear);
    ``False`` on transient failure where the existing cache is retained.

    Error handling map (identical shape to the team helper):

    - 200 → :meth:`AuthService.apply_user_secrets_config`.
    - 404 (client returns ``None``) →
      :meth:`AuthService.clear_user_secrets_cache`.
    - :class:`PaymentRequiredError` (402) / :class:`ForbiddenError` (403)
      → clear the PERSONAL cache only.
    - :class:`APIError` (other) / transport error → keep the cache.
    """
    from servonaut.services.api_client import (
        APIError,
        ForbiddenError,
        PaymentRequiredError,
    )

    try:
        payload = await client.get_user_secrets_config()
    except (PaymentRequiredError, ForbiddenError) as exc:
        logger.info(
            "fetch_and_apply_user_secrets_config: %s → clearing personal "
            "cache (falling back to team/LocalProvider on next resolve)",
            exc.code,
        )
        auth_service.clear_user_secrets_cache()
        return True
    except APIError as exc:
        logger.warning(
            "fetch_and_apply_user_secrets_config: API error %s (%s); "
            "keeping existing personal cache",
            exc.status, exc.code,
        )
        return False
    except Exception as exc:  # noqa: BLE001 — transport-level
        logger.warning(
            "fetch_and_apply_user_secrets_config: transport error (%s); "
            "keeping existing personal cache",
            exc,
        )
        return False

    if payload is None:
        logger.info(
            "fetch_and_apply_user_secrets_config: server returned 404; "
            "clearing personal cache",
        )
        auth_service.clear_user_secrets_cache()
        return True

    # Decision #2 (handle-both): the ``/me`` body does NOT include
    # ``user_id`` today, so absence is the normal path — just proceed.
    # If a future server revision starts echoing it, warn on mismatch
    # (mirrors the team_slug echo check) but never hard-fail: the bearer
    # token authenticated the request, so the payload is authoritative.
    if isinstance(payload, dict):
        echoed = payload.get("user_id")
        token = getattr(auth_service, "_token", None)
        expected = getattr(token, "user_id", None) if token is not None else None
        if echoed is not None and expected is not None and echoed != expected:
            logger.warning(
                "fetch_and_apply_user_secrets_config: server echoed "
                "user_id=%r which does NOT match the authenticated "
                "user_id=%r — likely a server-side mapping bug; the "
                "bearer-authenticated payload is still authoritative.",
                echoed, expected,
            )

    auth_service.apply_user_secrets_config(payload)
    return True


async def refresh_all_secrets_configs(
    auth_service: "AuthService",
    client: _SecretsConfigClient,
    *,
    slug: Optional[str] = None,
) -> None:
    """Fan out the personal + (optional) team fetches concurrently.

    The personal fetch always runs; the team fetch runs only when an
    active team ``slug`` is supplied. Each sub-fetch owns its own cache
    mutation and error classification, so one failing never disturbs the
    other's cache. Exceptions are swallowed (``return_exceptions=True``)
    because the helpers already log + retain-on-transient — a raised
    exception here would just be noise. The caller re-runs
    :func:`resolve_secret_provider` after this settles.
    """
    import asyncio

    tasks = [fetch_and_apply_user_secrets_config(auth_service, client)]
    if slug:
        tasks.append(fetch_and_apply_secrets_config(auth_service, client, slug))
    await asyncio.gather(*tasks, return_exceptions=True)
