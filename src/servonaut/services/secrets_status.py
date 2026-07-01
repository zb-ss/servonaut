"""Read-only snapshot of the secrets-management state.

Shared between the CLI subcommand (``servonaut secrets status``) and
the TUI :class:`SecretsScreen` (UX Step 9). Both surfaces show the
same information in different shapes, so the computation lives in
one place and the rendering forks downstream.

The summary deliberately captures point-in-time state: it does NOT
fetch from the network, does NOT refresh entitlements, does NOT
mutate any caches. It's a snapshot of what the resolver would see
right now. Anything dynamic (refreshing the team config, listing
provider secrets) is a worker action triggered from the consumer.

Structure choice: ``@dataclass(frozen=True)`` so consumers can rely
on the snapshot not mutating mid-render (a TUI screen that builds
its widget tree from a frozen snapshot can't race with a refresh
worker updating the underlying AuthService mid-frame).
"""
from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.services.auth_service import AuthService
    from servonaut.services.entitlement_guard import EntitlementGuard


@dataclass(frozen=True)
class SecretsStatusSummary:
    """Point-in-time snapshot of the user's secrets-management state.

    Built by :func:`compute_secrets_status` from the AuthService +
    EntitlementGuard. Consumers (CLI ``status`` command, TUI
    SecretsScreen) read fields directly — no methods, no logic in
    the dataclass.
    """

    # --- Authentication & entitlement ---------------------------------
    authenticated: bool
    plan: str
    entitled_secrets_management: bool
    entitlement_reason: str  # human-readable "OK" or upgrade-prompt
    entitled_secrets_team_shared: bool

    # --- Active provider (None → legacy ~/.ssh) -----------------------
    active_provider_name: Optional[str]  # "local" | "bitwarden" | None

    # Which cache served the active config: "team" (team-in-team-context),
    # "user" (personal /me config), or None (LocalProvider default / no
    # config). Drives the "(team)" vs "(personal)" status-pill suffix.
    config_source: Optional[str]

    # --- Bitwarden-specific fields (None when provider != bitwarden) -
    bitwarden_project_id: Optional[str]
    bitwarden_token_env_var: Optional[str]
    bws_path: Optional[str]  # shutil.which("bws") or None
    bws_token_set: bool  # configured env var has a non-empty value

    # --- Local-specific fields (None when provider != local) ---------
    local_secrets_path: Optional[str]

    # --- Cache state --------------------------------------------------
    cache_present: bool  # True iff a fetched config sits in auth.json
    cache_fresh: bool  # True iff < SECRETS_CACHE_TTL since fetch
    cache_updated_at: str  # server-side updated_at (ATOM string)
    cache_fetched_at: float  # CLI-side fetch timestamp (unix)

    # --- Convenience flags consumers like for the empty-states -------
    has_health_warning: bool  # bws missing / token unset when provider=bitwarden


def compute_secrets_status(
    auth_service: "AuthService",
    entitlement_guard: "EntitlementGuard",
) -> SecretsStatusSummary:
    """Build a :class:`SecretsStatusSummary` from the live services.

    Synchronous — consults in-memory caches only. Network-touching
    operations (refresh, list secrets, fetch team list) are workers
    the consumer owns, not part of the snapshot.
    """
    # Lazy imports to avoid the boot-order ladder (this module is
    # consumed by the TUI screen, which is loaded early; the
    # resolver pulls in BitwardenProvider which we want lazy).
    from servonaut.services.secret_provider_resolver import (
        resolve_secret_provider,
    )

    authenticated = auth_service.is_authenticated
    plan = auth_service.plan if authenticated else "free"
    allowed_management, reason_management = entitlement_guard.check(
        "secrets_management",
    )
    allowed_team_shared, _ = entitlement_guard.check("secrets_team_shared")

    if not authenticated:
        # Anonymous / pre-login. No cache to inspect, no provider
        # active. SSH falls back to legacy ~/.ssh discovery.
        return SecretsStatusSummary(
            authenticated=False,
            plan="free",
            entitled_secrets_management=False,
            entitlement_reason=reason_management,
            entitled_secrets_team_shared=False,
            active_provider_name=None,
            config_source=None,
            bitwarden_project_id=None,
            bitwarden_token_env_var=None,
            bws_path=None,
            bws_token_set=False,
            local_secrets_path=None,
            cache_present=False,
            cache_fresh=False,
            cache_updated_at="",
            cache_fetched_at=0.0,
            has_health_warning=False,
        )

    cached = auth_service.cached_secrets_config()
    provider = resolve_secret_provider(auth_service, entitlement_guard)
    provider_name = provider.provider_name if provider is not None else None

    bw_project_id = None
    bw_token_env_var = None
    bws_path: Optional[str] = None
    bws_token_set = False
    local_path: Optional[str] = None
    health_warning = False

    if provider_name == "bitwarden":
        bw_project_id = cached.config.get("project_id") or None
        bw_token_env_var = cached.config.get("token_env_var") or "BWS_ACCESS_TOKEN"
        bws_path = shutil.which("bws")
        if bw_token_env_var:
            raw_token = os.environ.get(bw_token_env_var, "").strip()
            bws_token_set = bool(raw_token)
        # Health warning: provider says bitwarden but the local
        # environment isn't ready to use it. The CLI falls back to
        # ~/.ssh in this case, but the user should be told why.
        health_warning = (bws_path is None) or (not bws_token_set)
    elif provider_name == "local":
        # ``LocalProvider`` exposes ``.path`` via the read-only property
        # we added on the secrets-management Step 1 commit.
        path_attr = getattr(provider, "path", None)
        local_path = str(path_attr) if path_attr is not None else None

    return SecretsStatusSummary(
        authenticated=True,
        plan=plan,
        entitled_secrets_management=allowed_management,
        entitlement_reason=reason_management,
        entitled_secrets_team_shared=allowed_team_shared,
        active_provider_name=provider_name,
        config_source=auth_service.secrets_config_source(),
        bitwarden_project_id=bw_project_id,
        bitwarden_token_env_var=bw_token_env_var,
        bws_path=bws_path,
        bws_token_set=bws_token_set,
        local_secrets_path=local_path,
        cache_present=auth_service.is_secrets_cache_present(),
        cache_fresh=auth_service.is_secrets_cache_fresh(),
        cache_updated_at=cached.updated_at,
        cache_fetched_at=(
            auth_service._token.secrets_fetched_at
            if auth_service._token is not None else 0.0
        ),
        has_health_warning=health_warning,
    )


def format_relative_age(unix_ts: float, now: Optional[float] = None) -> str:
    """Human-friendly relative time for the status display.

    Renders ``"8m ago"``, ``"3 days ago"``, ``"never"``. Sub-second
    differences clip to ``"just now"``. Numbers stay coarse on purpose
    — users want "is this stale?" intuition, not precise stopwatch
    output. Pinned by tests so a future format change is a deliberate
    decision.
    """
    if not unix_ts or unix_ts <= 0:
        return "never"
    clock = time.time() if now is None else now
    delta = max(0.0, clock - unix_ts)
    if delta < 5:
        return "just now"
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta // 60)}m ago"
    if delta < 86400:
        return f"{int(delta // 3600)}h ago"
    days = int(delta // 86400)
    return f"{days} day{'s' if days != 1 else ''} ago"
