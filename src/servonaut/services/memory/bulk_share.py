"""Share the memory of many servers with one team in one pass.

The single-server Share form runs one :meth:`TeamMemoryService.share_instance`;
this runs it for a list of servers with one set of choices. What it holds to:

- the team's member keys are fetched once and checked once, before anything
  is sent: a changed or unusable key refuses the whole batch;
- the team's existing shares are read once; a server already shared is
  reported and left alone, or replaced with the new settings when asked;
- servers are sent one after another; one failure does not stop the others;
- a rate limit is retried once, after the service's ``Retry-After`` (or the
  configured pause) when that fits the configured wait; when it persists, the
  remaining servers are not sent and the report says how many;
- a server that cannot be shared is skipped with a reason, without a request
  where the reason is known up front.

There is no bulk grant route on the service: every server is one grant POST.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence, Tuple, TypeVar

from servonaut.services.memory.interfaces import (
    BackendMaintenance,
    BetaWaitlist,
    MemoryBackendError,
    MemoryNotFound,
    ReservedInstanceIdError,
    UpsellRequired,
    ValidationFailed,
)
from servonaut.services.memory.path_segments import check_segment
from servonaut.services.memory.retrieval_service import _validate_instance_id
from servonaut.services.memory.team_service import (
    GrantAlreadyExistsError,
    InsufficientWrapsRequired,
    KeyChangedError,
    ShareGoneError,
    UnusableMemberKeyError,
)
from servonaut.services.retry_after import is_rate_limited, retry_after_seconds

logger = logging.getLogger(__name__)

T = TypeVar("T")

# What happened to one server.
SHARED = "shared"
UPDATED = "updated"  # already shared; replaced with the batch's settings
ALREADY_SHARED = "already_shared"  # already shared; left as it was
SKIPPED = "skipped"
FAILED = "failed"
NOT_SENT = "not_sent"  # the batch stopped before this server

# Why (skips, the shares left alone, and the stops).
ID_NOT_ACCEPTED = "id_not_accepted"
NO_SNAPSHOT = "no_snapshot"
NEVER_PROBED = "never_probed"
MEMORY_OFF = "memory_off"
UNRESOLVED = "unresolved"
SAME_SETTINGS = "same_settings"
RATE_LIMITED = "rate_limited"
KEY_RACE = "key_race"
UNAVAILABLE = "unavailable"
REVOKED_ONLY = "revoked_only"

# A batch stops at these: every later server would meet the same answer.
_STOPS = frozenset({RATE_LIMITED, KEY_RACE, UNAVAILABLE})


class MemorySyncLockedError(MemoryBackendError):
    """Raised when the caller's memory key is locked: nothing can be sealed."""

    def __init__(self) -> None:
        super().__init__("Unlock Memory Sync first. Nothing was shared.")


class BatchRateLimitedError(MemoryBackendError):
    """Raised when the service rate-limited the batch before any server was sent.

    Attributes:
        retry_after: The wait the service asked for, in seconds, if it said.
    """

    def __init__(self, retry_after: Optional[float]) -> None:
        self.retry_after = retry_after
        super().__init__("The service is limiting requests. Nothing was shared.")


@dataclass(frozen=True)
class ShareTarget:
    """One server of a batch.

    Attributes:
        instance_id: The id the service knows the server by (the real id,
            never a demo-mode stand-in).
        label: What the user sees for it (a stand-in in demo mode).
        probed: Whether this computer holds memory for it. A server the
            service holds no snapshot of is then "never probed" rather than
            "not uploaded yet".
        memory_off: The user turned memory off for this server.
        resolved: False when demo mode cannot name the real server.
    """

    instance_id: str
    label: str
    probed: bool = True
    memory_off: bool = False
    resolved: bool = True


@dataclass(frozen=True)
class ShareOutcome:
    """What the batch did with one server.

    ``reason`` is one of the reason codes above (empty when there is none);
    ``detail`` is a failure's plain-text explanation, which may carry the
    service's own wording.
    """

    target: ShareTarget
    status: str
    reason: str = ""
    detail: str = ""
    retry_after: Optional[float] = None


@dataclass(frozen=True)
class BulkShareReport:
    """Every server's outcome, in the order given, and who cannot read yet."""

    outcomes: Tuple[ShareOutcome, ...]
    # Eligible members with no memory key yet, once each ({user_id, name, ...}).
    pending: Tuple[Dict[str, Any], ...] = ()

    def with_status(self, status: str) -> List[ShareOutcome]:
        return [o for o in self.outcomes if o.status == status]

    @property
    def not_sent(self) -> int:
        return len(self.with_status(NOT_SENT))

    @property
    def stop_reason(self) -> str:
        """Why the batch stopped early, or ``""``."""
        return next((o.reason for o in self.outcomes if o.status == NOT_SENT), "")

    @property
    def retry_after(self) -> Optional[float]:
        """The wait the service asked for when its rate limit stopped the batch."""
        return next((o.retry_after for o in self.outcomes if o.retry_after is not None), None)


class _Stopped(Exception):
    """A server's request met an answer every later one would meet too."""

    def __init__(self, reason: str, detail: str = "", retry_after: Optional[float] = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail
        self.retry_after = retry_after


def memory_sync_accepts(instance_id: str) -> bool:
    """Whether Memory Sync can store (and so share) a server under *instance_id*."""
    try:
        _validate_instance_id(instance_id)
        check_segment(instance_id, "server")
    except ValueError:
        return False
    return True


def failure_text(exc: BaseException) -> str:
    """A short, plain-text reason for a failed share.

    Never the instance id or team slug a client-side message may carry; the
    service's own message is kept (the screen scrubs it in demo mode).
    """
    from servonaut.services.api_client import APIError

    if isinstance(exc, APIError):
        message = (exc.message or "").strip()
        return f"{message} (HTTP {exc.status})" if message else f"HTTP {exc.status}"
    if isinstance(exc, ValidationFailed):
        return "the service rejected the request"
    if isinstance(exc, MemoryBackendError):
        return str(exc) or type(exc).__name__
    return type(exc).__name__


def _log_reason(exc: BaseException) -> str:
    """The error's type (and HTTP status) for the log: the service's text can name people."""
    status = getattr(exc, "status", None)
    name = type(exc).__name__
    return f"{name} (HTTP {status})" if isinstance(status, int) else name


class BulkMemoryShareService:
    """Shares several servers' memory with one team (see the module docstring).

    Args:
        team_memory_service: The :class:`TeamMemoryService` that seals and posts.
        waits: Returns ``(retry_seconds, max_wait_seconds)``: the pause before
            the one retry of a rate-limited request that names no wait, and the
            longest wait honoured (``MemoryConfig.team_wrap_wait``).
        sleep: The pause (replaced in tests).
    """

    def __init__(
        self,
        team_memory_service: Any,
        waits: Callable[[], Tuple[float, float]],
        *,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
    ) -> None:
        self._team = team_memory_service
        self._waits = waits
        self._sleep = sleep

    async def share(
        self,
        team_slug: str,
        required_role: str,
        modules: Sequence[str],
        targets: Sequence[ShareTarget],
        *,
        update_existing: bool = False,
        on_progress: Optional[Callable[[int, int, ShareOutcome], None]] = None,
    ) -> BulkShareReport:
        """Share every server of *targets* with team *team_slug*, in order.

        Args:
            team_slug: The team.
            required_role: The lowest team role that may read.
            modules: The modules to share (an explicit, non-empty list).
            targets: The servers.
            update_existing: Replace a share that exists with these settings.
                Off: such a server is reported and left as it is.
            on_progress: Called with ``(index, total, outcome)`` after each
                server, counting from 1.

        Raises:
            ValueError: No module was chosen, or the slug is not well formed.
            MemorySyncLockedError: The memory key is locked.
            KeyChangedError: A reader's key needs confirming. Nothing was sent.
            UnusableMemberKeyError: The service sent a key that is not its own.
                Nothing was sent.
            Exception: The member keys or the team's shares could not be read.
                Nothing was sent.
        """
        chosen = list(dict.fromkeys(modules))
        if not chosen:
            raise ValueError("Select at least one module to share.")
        check_segment(team_slug, "team")
        if not self._team.is_unlocked():
            raise MemorySyncLockedError()
        try:
            member_keys = await self._call(lambda: self._team.list_team_member_keys(team_slug))
            self._team.check_member_keys(team_slug, member_keys, required_role)
            live = await self._live_grants(team_slug)
        except _Stopped as stopped:
            raise BatchRateLimitedError(stopped.retry_after) from stopped

        outcomes: List[ShareOutcome] = []
        pending: Dict[int, Dict[str, Any]] = {}
        stop: Optional[_Stopped] = None
        for index, target in enumerate(targets, start=1):
            grant = live.get(target.instance_id)
            outcome = self._without_request(target, grant, required_role, chosen, update_existing)
            if outcome is None and stop is not None:
                outcome = ShareOutcome(target, NOT_SENT, stop.reason, stop.detail, stop.retry_after)
            elif outcome is None:
                outcome, created, stopped = await self._send(
                    team_slug, target, grant, required_role, chosen, member_keys)
                stop = stopped or stop
                self._note_pending(pending, created)
            outcomes.append(outcome)
            if on_progress is not None:
                on_progress(index, len(targets), outcome)
        return BulkShareReport(tuple(outcomes), tuple(pending.values()))

    async def _live_grants(self, team_slug: str) -> Dict[str, Any]:
        """The team's live shares by server id, read once for the batch."""
        shared = await self._call(lambda: self._team.list_shared_instances(team_slug))
        return {s.grant.instance_id: s.grant for s in shared if s.grant.is_live}

    @staticmethod
    def _note_pending(pending: Dict[int, Dict[str, Any]], created: Any) -> None:
        """Add the members a new grant could not seal for yet, once each."""
        for person in getattr(created, "pending_recipients", None) or []:
            user_id = person.get("user_id") if isinstance(person, dict) else None
            if isinstance(user_id, int) and user_id not in pending:
                pending[user_id] = dict(person)

    @staticmethod
    def _without_request(
        target: ShareTarget, grant: Any, role: str, modules: List[str], update_existing: bool
    ) -> Optional[ShareOutcome]:
        """The outcome when no request is needed for it, else None."""
        if not target.resolved:
            return ShareOutcome(target, SKIPPED, UNRESOLVED)
        if target.memory_off:
            return ShareOutcome(target, SKIPPED, MEMORY_OFF)
        if not memory_sync_accepts(target.instance_id):
            return ShareOutcome(target, SKIPPED, ID_NOT_ACCEPTED)
        if grant is None:
            return None
        if not update_existing:
            return ShareOutcome(target, ALREADY_SHARED)
        if grant.required_role == role and grant.modules is not None \
                and set(grant.modules) == set(modules):
            return ShareOutcome(target, ALREADY_SHARED, SAME_SETTINGS)
        return None

    async def _send(
        self, team_slug: str, target: ShareTarget, grant: Any, role: str,
        modules: List[str], member_keys: List[Any],
    ) -> Tuple[ShareOutcome, Any, Optional[_Stopped]]:
        """Share (or replace the share of) one server.

        Returns the outcome, the new grant (or None), and the stop it calls
        for (or None). A replacement is the two steps of
        :meth:`TeamMemoryService.reshare_instance` (its key check already ran
        for the batch), taken one at a time so that a rate limit between them
        retries only the step the service refused.
        """
        updating = grant is not None
        if updating:
            try:
                await self._revoke(team_slug, grant.id)
            except Exception as exc:  # noqa: BLE001 — reported on its row
                outcome = self._failed(target, exc)
                return outcome, None, self._stop_after(outcome)
        try:
            created = await self._call(lambda: self._team.share_instance(
                team_slug=team_slug, instance_id=target.instance_id, required_role=role,
                modules=list(modules), member_pubkeys=member_keys,
            ))
        except Exception as exc:  # noqa: BLE001 — reported on its row
            outcome = self._failed(target, exc)
            stop = self._stop_after(outcome)
            if updating and outcome.status != ALREADY_SHARED:
                # The old share is stopped and the new one is not there.
                outcome = ShareOutcome(target, FAILED, REVOKED_ONLY, outcome.detail,
                                       outcome.retry_after)
            return outcome, None, stop
        return ShareOutcome(target, UPDATED if updating else SHARED), created, None

    @staticmethod
    def _stop_after(outcome: ShareOutcome) -> Optional[_Stopped]:
        """The stop *outcome* calls for: one every later server would meet too."""
        if outcome.status == NOT_SENT or outcome.reason in _STOPS:
            return _Stopped(outcome.reason, outcome.detail, outcome.retry_after)
        return None

    async def _revoke(self, team_slug: str, grant_id: str) -> None:
        """Stop the share being replaced; one that is already gone is fine."""
        from servonaut.services.api_client import APIError

        try:
            await self._call(lambda: self._team.revoke_grant(team_slug, grant_id))
        except (ShareGoneError, APIError) as exc:
            gone = isinstance(exc, ShareGoneError) or exc.status == 404 or (
                exc.status == 409 and exc.code == "grant_not_live")
            if not gone:
                raise

    def _failed(self, target: ShareTarget, exc: BaseException) -> ShareOutcome:
        """The outcome for a server whose request raised *exc*."""
        if isinstance(exc, _Stopped):
            return ShareOutcome(target, NOT_SENT, exc.reason, exc.detail, exc.retry_after)
        if isinstance(exc, GrantAlreadyExistsError):
            return ShareOutcome(target, ALREADY_SHARED)  # shared meanwhile
        if isinstance(exc, MemoryNotFound):
            return ShareOutcome(target, SKIPPED, NO_SNAPSHOT if target.probed else NEVER_PROBED)
        if isinstance(exc, (KeyChangedError, UnusableMemberKeyError, InsufficientWrapsRequired)):
            return ShareOutcome(target, FAILED, KEY_RACE)
        if isinstance(exc, (UpsellRequired, BackendMaintenance, BetaWaitlist)):
            return ShareOutcome(target, FAILED, UNAVAILABLE, failure_text(exc))
        if isinstance(exc, ReservedInstanceIdError):  # an id the service routes refuse
            return ShareOutcome(target, SKIPPED, ID_NOT_ACCEPTED)
        logger.warning("Bulk share: one server failed: %s", _log_reason(exc))
        return ShareOutcome(target, FAILED, detail=failure_text(exc))

    async def _call(self, make: Callable[[], Awaitable[T]]) -> T:
        """Run one request; retry once after a rate limit that fits the wait budget.

        Raises:
            _Stopped: The rate limit asks for longer than the budget, or persists.
        """
        retry_seconds, max_wait = self._waits()
        for attempt in (1, 2):
            try:
                return await make()
            except Exception as exc:
                if not is_rate_limited(exc):
                    raise
                asked = retry_after_seconds(exc)
                wait = retry_seconds if asked is None else asked
                if attempt == 2 or wait > max_wait:
                    raise _Stopped(RATE_LIMITED, retry_after=asked) from exc
                logger.info("Bulk share: rate limited; waiting %.0f s once", wait)
                await self._sleep(wait)
        raise AssertionError("unreachable")  # pragma: no cover
