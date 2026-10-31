"""Read-only view of the memory teams share with the user.

A member's own memory store never holds what a team shares: the owner's
copy stays on the service, sealed to each member's key. This reader lists
what is shared and opens it on demand, so a screen or tool can show it next
to (or instead of) a local snapshot.

Nothing here writes: no upload, no local store, no sync queue. Every answer
is kept for ``memory.team_memory_cache_seconds`` so a redraw never asks the
service again, and every failure reads as "nothing shared", because the
shared copy is only ever a fallback.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

from servonaut.services.memory.interfaces import MemoryBackendError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SharedMemory:
    """The modules of one shared server, in the shape of a local snapshot.

    Attributes:
        team_slug: Slug of the team sharing it.
        team_name: Name of that team, for display.
        modules: ``{module: {"observed", "declared", "probed_at"}}``.
    """

    team_slug: str
    team_name: str
    modules: Dict[str, Dict[str, Any]]

    @property
    def probed_at(self) -> str:
        """When the newest module was probed (``""`` when none says)."""
        return max((m.get("probed_at") or "" for m in self.modules.values()), default="")


@dataclass(frozen=True)
class SharedListing:
    """What the team's list says about one shared server, without opening it.

    Attributes:
        team_slug: Slug of the team sharing it.
        team_name: Name of that team.
        module_count: How many modules the user can read.
        last_probe_at: When the server was last probed (``""`` if unknown).
    """

    team_slug: str
    team_name: str
    module_count: int
    last_probe_at: str
    instance: Dict[str, Any] = field(default_factory=dict)

    @property
    def instance_id(self) -> str:
        return str(self.instance.get("instance_id") or "")


class SharedMemoryReader:
    """Lists and opens the memory shared with the user through teams.

    Args:
        team_service: The :class:`TeamMemoryService` to ask.
        ttl_provider: Returns how long, in seconds, an answer is reused.
        clock: Monotonic clock, replaceable in tests.
        teams_provider: Async callable returning the user's teams
            (``[{"slug", "name"}]``); lets :meth:`prefetch_all` find grants
            the user's server list says nothing about.
    """

    def __init__(
        self,
        team_service: Any,
        ttl_provider: Callable[[], float],
        clock: Callable[[], float] = time.monotonic,
        teams_provider: Optional[Callable[[], Any]] = None,
    ) -> None:
        self._teams_provider = teams_provider
        self._team_service = team_service
        self._ttl_provider = ttl_provider
        self._clock = clock
        self._reads: Dict[Tuple[str, str], Tuple[float, Optional[SharedMemory]]] = {}
        self._listings: Dict[Tuple[str, str], SharedListing] = {}

    def _fresh(self, stamped_at: float) -> bool:
        return self._clock() - stamped_at < float(self._ttl_provider() or 0.0)

    def cached_listings(self) -> Dict[Tuple[str, str], SharedListing]:
        """Every listing held, keyed by ``(team_slug, owner's instance id)``."""
        return dict(self._listings)

    def cached_listing(self, team_slug: str, instance_id: str) -> Optional[SharedListing]:
        """The last listing of *instance_id*, without asking the service."""
        return self._listings.get((team_slug, instance_id))

    async def prefetch_all(self, extra_slugs: Any = ()) -> None:
        """List what every team of the user shares (plus *extra_slugs*)."""
        teams: Dict[str, str] = {}
        if self._teams_provider is not None:
            try:
                for team in await self._teams_provider() or []:
                    if isinstance(team, dict) and isinstance(team.get("slug"), str):
                        teams[team["slug"]] = str(team.get("name") or team["slug"])
            except Exception as exc:  # noqa: BLE001 — the team list is optional
                logger.debug("Teams not listed for shared memory: %s", exc)
        for slug in extra_slugs:
            teams.setdefault(slug, slug)
        for slug in sorted(teams):
            try:
                await self.prefetch_listing(slug, teams[slug])
            except Exception as exc:  # noqa: BLE001 — one team must not hide the rest
                logger.warning("Could not list what team %s shares: %s", slug, exc)

    async def prefetch_listing(self, team_slug: str, team_name: str = "") -> None:
        """Ask the service what *team_slug* shares and keep the answer."""
        try:
            shared = await self._team_service.list_shared_instances(team_slug)
        except MemoryBackendError as exc:
            logger.debug("Team %s lists nothing shared: %s", team_slug, exc)
            return
        # The fresh answer replaces the team's old one whole, so a grant that
        # was revoked or narrowed disappears instead of lingering.
        fresh: Dict[Tuple[str, str], SharedListing] = {}
        for item in shared:
            instance_id = item.grant.instance_id or str(item.instance.get("instance_id") or "")
            fresh[(team_slug, instance_id)] = SharedListing(
                team_slug=team_slug,
                team_name=team_name or team_slug,
                module_count=len(item.readable_modules),
                last_probe_at=str(item.instance.get("last_probe_at") or ""),
                instance=dict(item.instance),
            )
        self._listings = {k: v for k, v in self._listings.items() if k[0] != team_slug}
        self._listings.update(fresh)

    async def read(
        self, team_slug: str, team_name: str, instance_id: str
    ) -> Optional[SharedMemory]:
        """Open what *team_slug* shares of *instance_id*, or ``None``."""
        key = (team_slug, instance_id)
        remembered = self._reads.get(key)
        if remembered and self._fresh(remembered[0]):
            return remembered[1]
        result = await self._read_uncached(team_slug, team_name, instance_id)
        self._reads[key] = (self._clock(), result)
        return result

    async def _read_uncached(
        self, team_slug: str, team_name: str, instance_id: str
    ) -> Optional[SharedMemory]:
        try:
            shared = await self._team_service.list_shared_instances(team_slug)
            match = next(
                (s for s in shared
                 if instance_id in (s.grant.instance_id, str(s.instance.get("instance_id") or ""))),
                None,
            )
            if match is None:
                return None
            modules: Dict[str, Dict[str, Any]] = {}
            for module in match.readable_modules:
                try:
                    opened = await self._team_service.read_shared_module(
                        team_slug, match.grant.instance_id, module
                    )
                except ValueError as exc:  # an unsafe id from the service: skip it
                    logger.warning("Skipped shared module %r: %s", module, exc)
                    continue
                if opened is not None:
                    modules[module] = _for_display(opened)
        except MemoryBackendError as exc:
            logger.debug("Nothing readable from team %s: %s", team_slug, exc)
            return None
        return SharedMemory(team_slug, team_name, modules) if modules else None


def _for_display(module: Dict[str, Any]) -> Dict[str, Any]:
    """*module*, with authored notes and findings also as ``observed`` rows.

    The payloads stay under their own keys (``content``, ``findings``); the
    rows only let a table show them. Read-only: nothing here is saved.
    """
    shown = dict(module)
    observed = dict(shown.get("observed") or {})
    if isinstance(shown.get("content"), str):
        observed.setdefault("note", shown["content"])
    if isinstance(shown.get("findings"), list):
        for index, record in enumerate(shown["findings"], 1):
            text = record.get("title") or record.get("text") if isinstance(record, dict) else record
            observed.setdefault(f"finding {index}", str(text if text else record))
    shown["observed"] = observed
    return shown


@dataclass(frozen=True)
class ShareCandidate:
    """One team that may share a server: where to ask, and under which id.

    Attributes:
        team_slug: Slug of the team.
        team_name: Name of the team, for display.
        instance_id: The id the OWNER's grant is keyed on (never the id the
            member's own row carries).
    """

    team_slug: str
    team_name: str
    instance_id: str


def share_candidates(target: Dict[str, Any], fleet_rows: Any) -> list:
    """The teams that may share *target*, from the rows the user lists.

    A team's shared row names its team and the server's real ``instance_id``.
    One of the user's own servers that a team also shares has no such row of
    its own (it is folded into the own row), so the team rows that stand for
    it are found among *fleet_rows*.
    """
    from servonaut.services.memory.team_merge import share_identity
    from servonaut.services.shared_servers import is_shared_row, own_twin

    if is_shared_row(target):
        rows = [target]
    else:
        rows = [
            row for row in fleet_rows or []
            if isinstance(row, dict) and is_shared_row(row)
            and (twin := own_twin(row, [target])) is not None and twin.get("id") == target.get("id")
        ]
    found = []
    for row in rows:
        slug = str(row.get("team_slug") or "")
        instance_id = share_identity(row)["instance_id"]
        if slug and instance_id:
            found.append(ShareCandidate(slug, str(row.get("team_name") or slug), instance_id))
    return found


def apply_display_names(instance: Dict[str, Any], app: Any) -> None:
    """Set a memory-only row's shown name, id and provider for the current demo mode.

    The real values live under ``real_*`` and never change; what is shown is
    derived again whenever demo mode is toggled.
    """
    real_id = instance.get("real_id")
    if not real_id:
        return
    real = {
        "id": str(real_id),
        "name": str(instance.get("real_name") or real_id),
        "provider": str(instance.get("real_provider") or "shared"),
    }
    redaction = getattr(app, "redaction_service", None)
    if getattr(app, "demo_mode", False) and redaction is not None:
        instance["id"] = redaction.redact_instance_id(real["id"])
        instance["name"] = redaction.redact_name(real["name"])
        instance["provider"] = redaction.redact_provider(real["provider"])
        return
    instance.update(real)


def merge_shared(
    local: Dict[str, Dict[str, Any]], shared: Optional[SharedMemory]
) -> Dict[str, Dict[str, Any]]:
    """*local* modules, with a shared module wherever it is newer or missing."""
    if shared is None:
        return local
    merged = dict(local)
    for name, module in shared.modules.items():
        mine = merged.get(name)
        if mine is None or (module.get("probed_at") or "") > (mine.get("probed_at") or ""):
            merged[name] = module
    return merged


def shared_source_text(shared: SharedMemory, team_name: str) -> str:
    """The plain label of where shared memory comes from."""
    probed = shared.probed_at[:16].replace("T", " ")
    when = f", probed {probed}" if probed else ""
    return f"Shared by {team_name}{when}"
