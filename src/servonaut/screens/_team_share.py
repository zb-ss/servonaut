"""Shared team-sharing flow used across Server Actions and Custom Servers."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from contextlib import nullcontext
from typing import Any, Optional

from servonaut.screens._busy_work import BusyWork
from servonaut.screens._demo_resolve import (
    connection_instance,
    reconcile_team_memory,
    replace_instances,
)
from servonaut.services.team_service import SHARED
from servonaut.services.team_sharing import (
    server_share_defaults,
    share_candidates,
    share_payload,
)

logger = logging.getLogger(__name__)

_TEAM_CACHE_TTL_SECONDS = 60.0


def cached_teams_for(app: Any, team_svc: Any) -> Optional[list[dict[str, Any]]]:
    """Return cached team dicts for *team_svc* when within the cache TTL."""
    if team_svc is None:
        return None
    entry = getattr(app, "_team_list_cache", None)
    if not isinstance(entry, tuple) or len(entry) != 3:
        return None
    cached_svc, fetched_at, teams = entry
    if cached_svc is not team_svc:
        return None
    if (time.monotonic() - fetched_at) >= _TEAM_CACHE_TTL_SECONDS:
        return None
    return [dict(t) for t in teams if isinstance(t, Mapping)]


def set_cached_teams(app: Any, team_svc: Any, teams: list[dict[str, Any]]) -> None:
    """Store fetched team records on *app* keyed to *team_svc*."""
    if team_svc is None:
        return
    app._team_list_cache = (
        team_svc,
        time.monotonic(),
        [dict(t) for t in teams if isinstance(t, Mapping)],
    )


def clear_cached_teams(app: Any) -> None:
    """Invalidate any cached team list on *app*."""
    app._team_list_cache = None


async def resolve_manageable_teams(
    app: Any,
    team_svc: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return ``(manageable_teams, all_teams)``, reusing the session cache when valid."""
    teams = cached_teams_for(app, team_svc)
    if teams is None:
        raw_teams = await team_svc.list_teams()
        teams = [dict(t) for t in (raw_teams or []) if isinstance(t, Mapping)]
        set_cached_teams(app, team_svc, teams)
    manageable = [
        t
        for t in teams
        if str(t.get("role") or "").lower() in {"owner", "admin"} and t.get("slug")
    ]
    return manageable, teams


async def share_server_with_team_flow(
    screen: Any,
    instance: dict[str, Any],
    team_svc: Any,
    *,
    busy: Optional[BusyWork] = None,
    hold_selector: str = "",
    on_shared: Optional[Callable[[], None]] = None,
) -> None:
    """Pick an eligible team, confirm defaults, push the server, and refresh shared fleet."""
    from servonaut.screens.server_actions import TeamTargetModal
    from servonaut.screens.team_share_confirm import ShareServersConfirmModal
    from servonaut.services.shared_servers import load_shared_servers

    app = screen.app
    holds = (hold_selector,) if hold_selector else ()

    def _run_busy(message: str):
        if busy is not None:
            return busy.running(message, hold=holds)
        return nullcontext()

    try:
        if cached_teams_for(app, team_svc) is None:
            with _run_busy("Loading teams…"):
                manageable, _teams = await resolve_manageable_teams(app, team_svc)
        else:
            manageable, _teams = await resolve_manageable_teams(app, team_svc)
    except Exception as exc:
        app.notify(f"Could not load teams ({exc}).", severity="error", markup=False)
        return

    if not manageable:
        app.notify("Only team owners or admins can share servers.", severity="warning")
        return

    team = manageable[0]
    if len(manageable) > 1:
        picked = await app.push_screen_wait(TeamTargetModal(manageable))
        if not isinstance(picked, Mapping):
            return
        team = dict(picked)

    slug = str(team["slug"])
    team_name = str(team.get("name") or slug)

    try:
        with _run_busy("Checking shared inventory…"):
            shared = await team_svc.list_shared_servers(slug)
    except Exception as exc:
        app.notify(f"Could not read shared servers ({exc}).", severity="error", markup=False)
        return

    own = server_share_defaults(
        getattr(app, "connection_service", None),
        connection_instance(app, instance),
    )
    to_share, skipped_existing, skipped_no_ip = share_candidates([own], shared or [])
    if not to_share:
        if skipped_existing:
            app.notify(f"Already shared with {team_name}.", severity="information", markup=False)
        else:
            app.notify("This server has no routable IP address to share.", severity="warning")
        return

    chosen = await app.push_screen_wait(
        ShareServersConfirmModal(
            team_name,
            to_share,
            skipped_existing=skipped_existing,
            skipped_no_address=skipped_no_ip,
        )
    )
    if not chosen:
        return

    try:
        with _run_busy("Sharing server with team…"):
            results = await team_svc.push_servers(slug, [share_payload(row) for row in chosen])
    except Exception as exc:
        app.notify(f"Could not share server: {exc}", severity="error", markup=False)
        return

    if not any(r.status == SHARED for r in results):
        err = next((r.error for r in results if getattr(r, "error", None)), "unknown error")
        app.notify(f"Could not share server: {err}", severity="error", markup=False)
        return

    try:
        with _run_busy("Refreshing shared inventory…"):
            shared_state = await load_shared_servers(team_svc)
            set_cached_teams(app, team_svc, shared_state.teams)
            replace_instances(app, "shared", shared_state.rows)
            reconcile_team_memory(app)
    except Exception as exc:
        logger.warning("Shared inventory refresh failed after sharing with %s: %s", slug, exc)

    if callable(on_shared) and getattr(screen, "is_attached", False):
        on_shared()
    app.notify(f"Shared with team {team_name}.", markup=False)
