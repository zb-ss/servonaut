"""App-level Bitwarden SSH keys for the non-terminal connection paths."""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Final, Iterable, Mapping, Optional

from servonaut.services.bw_errors import BwItemNotFoundError
from servonaut.services.bw_key_notice import (
    BW_ITEM_ID,
    BW_KEY_UNAVAILABLE,
    BW_REF_LOOKUP_FAILED,
    bw_item_id,
    bw_key_reason,
)
from servonaut.services.bw_resolver import BwResolver
from servonaut.services.ssh_ref_resolver import (
    BW_KEY_FILE_TTL_SECONDS,
    BW_SUPERSEDED_KEY_GRACE_SECONDS,
    SSH_REF_LOOKUP_TIMEOUT_SECONDS,
    SSH_REF_MEMO_TTL_SECONDS,
    SshRefResolver,
)
from servonaut.utils.ephemeral_key import persistent_bw_ssh_key, remove_bw_ssh_key

logger = logging.getLogger(__name__)

#: How long (seconds) a ref lookup the Servonaut API failed is not retried: a
#: degraded API must not cost a timeout per connection. Kept short so a
#: recovered API is used again soon.
FAILED_REF_LOOKUP_MEMO_SECONDS: Final = 15.0

# The ref memo's value for a lookup that failed (not the same as "no ref").
_LOOKUP_FAILED: Final = object()
# The roll-up's value while the API is out (its read raised or timed out).
_ROLLUP_OUTAGE: Final = object()
# The roll-up's value when it lists nothing and this device never saved a
# ref: the user has no Bitwarden refs, so own servers need no lookup.
_NO_REFS: Final = object()

# A re-read that returns this means the key is gone for good. A shape error
# is not: a crashed or garbled bw run reports one too, so a re-read keeps the
# key in place (only a first read reports it).
_AUTHORITATIVE_NEGATIVES = (BwItemNotFoundError,)


class _NoPersonalRefs:
    async def get_personal_instance_ref(self, _provider, _instance_id):
        return None


class _NoTeamRefs:
    async def get_team_server_ssh_ref(self, _team_slug, _server_id):
        return None


class _FailureRecorder:
    """Passes ref lookups through and notes whether one raised.

    SshRefResolver logs and swallows lookup errors (a failed lookup reads as
    "no ref"); this tells the two apart without changing the resolver.
    """

    def __init__(self, inner: Any, method: str) -> None:
        self._inner = inner
        self._method = method
        self.failed = False

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._inner, name)
        if name != self._method:
            return attr

        async def call(*args: Any, **kwargs: Any) -> Any:
            try:
                return await attr(*args, **kwargs)
            except Exception:
                self.failed = True
                raise

        return call


@dataclass
class _KeyFile:
    """An item's current key file; the file itself is never changed."""

    path: str
    # Clock time after which the key is read through bw again.
    due: float
    # A login with this file was refused: read again on the next lookup.
    reread: bool = False


class BwKeyForgottenError(RuntimeError):
    """Bitwarden keys were dropped twice while one was being read."""


class BwSshKeyProvider:
    """Reads a server's Bitwarden SSH key for ssh/scp, never raising.

    Suppliers are zero-argument callables because the app rebuilds the ref
    and team services on sign-in.

    Key files are immutable: every read that finds a new key writes a new
    0600 file (unique name, private directory), and no file is modified while
    it can be in use. Each item has one current file. The key is read through
    ``bw`` again every *key_ttl_seconds*, and after a login with the current
    file is refused (:meth:`key_refused` only marks it). An unchanged key
    keeps its file; a rotated one gets a new file, and the old one is removed
    *superseded_grace_seconds* later. A re-read that fails for a passing
    reason (vault locked, CLI missing, a timeout, an unreadable answer)
    keeps the current file and waits another TTL; one that finds the item
    gone drops it. The TTL is a re-read interval, not a bound on time on disk: files
    stay until :meth:`forget_keys` (Bitwarden locked in the app, sign-in or
    sign-out, the server's ref edited) or the app quits.

    Every server's ref is looked up on its own and remembered for
    *ref_ttl_seconds*. The ref list (roll-up) is not a per-server filter: it
    may leave out a freshly saved ref. It serves three purposes: a roll-up
    read that fails means an API outage, during which servers that are not
    team-shared get no Bitwarden key (no per-server lookups) for
    *ref_ttl_seconds*; a failed per-server lookup of a server it lists is
    reported (BW_REF_LOOKUP_FAILED); and an empty roll-up together with an
    empty local ref mirror (``has_local_refs``) means the user has no
    Bitwarden refs, so own servers get no per-server lookup until the
    roll-up is read again (after the TTL, or a ref save's forget_refs). Concurrent callers share one roll-up
    read and one key read per item; a failed first read is never
    remembered, so unlocking and retrying works at once. Every Servonaut API
    call is bounded by *lookup_timeout_seconds*.
    """

    def __init__(
        self,
        *,
        ref_service: Callable[[], Any],
        team_service: Callable[[], Any],
        ssh_service: Any,
        session_getter: Optional[Callable[[], Optional[str]]] = None,
        ref_ttl_seconds: float = SSH_REF_MEMO_TTL_SECONDS,
        key_ttl_seconds: float = BW_KEY_FILE_TTL_SECONDS,
        failed_lookup_ttl_seconds: float = FAILED_REF_LOOKUP_MEMO_SECONDS,
        superseded_grace_seconds: float = BW_SUPERSEDED_KEY_GRACE_SECONDS,
        lookup_timeout_seconds: float = SSH_REF_LOOKUP_TIMEOUT_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        resolver_factory: Callable[..., Any] = BwResolver,
    ) -> None:
        self._ref_service = ref_service
        self._team_service = team_service
        self._ssh_service = ssh_service
        self._session_getter = session_getter
        self._ttl = ref_ttl_seconds
        self._key_ttl = key_ttl_seconds
        self._failed_ttl = failed_lookup_ttl_seconds
        self._grace = superseded_grace_seconds
        self._lookup_timeout = lookup_timeout_seconds
        self._clock = clock
        self._resolver_factory = resolver_factory
        self._ref_memo: dict[tuple, tuple[float, Any]] = {}
        self._rollup: Optional[tuple[float, Any]] = None
        self._rollup_read: Optional[asyncio.Task] = None
        # Bumped by forget_refs: a lookup in flight then does not store its answer.
        self._refs_generation = 0
        self._keys: dict[str, _KeyFile] = {}
        # (item_id, path, superseded at) for files replaced by a rotated key.
        self._superseded: list[tuple[str, str, float]] = []
        # Key files whose removal failed (a file in use on Windows, say).
        self._pending_removal: list[str] = []
        self._key_reads: dict[str, asyncio.Task] = {}
        # item_id -> bumped by forget_keys, so a read in flight is not kept.
        self._key_generation: dict[str, int] = {}
        self._all_keys_generation = 0

    async def apply(
        self, conn: Mapping[str, Any], instance: Mapping[str, Any],
    ) -> Optional[dict[str, Any]]:
        """Apply the server's Bitwarden key to *conn*.

        Returns None when the server has no Bitwarden ref, or its ref cannot
        be known during an API outage (the caller's conn stays untouched);
        ``{**conn, "key_path": <file>, "key_source": "bw_<source>",
        BW_ITEM_ID: <item>}`` when the key was read; ``{**conn,
        BW_KEY_UNAVAILABLE: <reason>}`` when the server has a ref but its key
        cannot be read (or its ref could not be looked up). Never raises
        (cancellation excepted).
        """
        try:
            await self._remove_expired_superseded()
            # A ref edited (forget_refs) while this ran: its answer may be the
            # old item, so it is done once more; crossed twice, no key.
            stale: set[str] = set()
            for _ in range(2):
                generation = self._refs_generation
                result, item_id = await self._apply_once(conn, instance)
                if generation == self._refs_generation:
                    self._forget_stale(stale - {item_id})
                    return result
                if item_id:
                    stale.add(item_id)
            self._forget_stale(stale)
            return None
        except Exception as exc:  # noqa: BLE001 - never break the connection
            logger.debug("Bitwarden key lookup skipped (%s)", type(exc).__name__)
            return None

    async def _apply_once(
        self, conn: Mapping[str, Any], instance: Mapping[str, Any],
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """One ref lookup and key read: (apply's answer, the item whose key was read or None)."""
        ref = await self._ref(instance)
        if ref is _LOOKUP_FAILED:
            return await self._lookup_failed(conn, instance), None
        if ref is None:
            return None, None
        item_id = str(ref.item_id)
        try:
            key_path = await self._key_path(item_id)
        except BwKeyForgottenError:
            # Keys were dropped (sign-out, lock, a ref edit) during the read:
            # connect as before; the next apply reads afresh.
            return None, None
        except Exception as exc:  # noqa: BLE001 - an unreadable key leaves the previous connection setup
            logger.info(
                "Bitwarden key not used for %s/%s (%s); connecting as before",
                _provider(instance), instance.get("id"), type(exc).__name__,
            )
            return {**conn, BW_KEY_UNAVAILABLE: bw_key_reason(exc)}, None
        return {
            **conn, "key_path": key_path, "key_source": f"bw_{ref.source}",
            BW_ITEM_ID: item_id,
        }, item_id

    def _forget_stale(self, item_ids: set[str]) -> None:
        """Drop key files read for a ref that was edited meanwhile."""
        for item_id in item_ids:
            self.forget_keys(item_id)

    def key_refused(self, conn: Mapping[str, Any]) -> None:
        """Have the key read again after ssh refused a login with *conn*'s Bitwarden key.

        Only a refusal of the item's current file counts: a connection that
        still held an older file changes nothing. Nothing is removed: other
        servers may share the item's file. Never raises.
        """
        item_id = bw_item_id(conn)
        current = self._keys.get(item_id) if item_id else None
        if current is not None and conn.get("key_path") == current.path:
            logger.info("Bitwarden key refused by the server; it will be read again")
            current.reread = True

    def forget_refs(self, item_ids: Iterable[str] = ()) -> None:
        """Drop the remembered ref lookups, and the key files of *item_ids*."""
        self._refs_generation += 1
        self._ref_memo.clear()
        self._rollup = None
        self._rollup_read = None
        for item_id in item_ids:
            if item_id:
                self.forget_keys(str(item_id))

    def forget_keys(self, item_id: Optional[str] = None) -> None:
        """Remove the key files of *item_id* (all of them when None).

        Current and superseded files are zero-overwritten and removed, and
        earlier failed removals retried; a read in flight is not kept. Never
        raises.
        """
        if item_id is None:
            self._all_keys_generation += 1
            items = set(self._keys) | {item for item, _, _ in self._superseded}
        else:
            self._key_generation[item_id] = self._key_generation.get(item_id, 0) + 1
            items = {item_id}
        for key in items:
            current = self._keys.pop(key, None)
            if current is not None:
                self._remove(current.path)
        kept = []
        for entry in self._superseded:
            if entry[0] in items:
                self._remove(entry[1])
            else:
                kept.append(entry)
        self._superseded = kept
        self._retry_pending_removals()

    # ------------------------------------------------------------------
    # ref lookups
    # ------------------------------------------------------------------

    async def _lookup_failed(
        self, conn: Mapping[str, Any], instance: Mapping[str, Any],
    ) -> Optional[dict[str, Any]]:
        """The reason for a failed per-server ref lookup when the roll-up lists the server.

        Without that evidence of a ref (not listed, no roll-up, a team row)
        a failed lookup leaves the connection as before.
        """
        if instance.get("is_shared") is True:
            return None
        ids = await self._personal_ref_ids()
        if isinstance(ids, frozenset) and str(instance.get("id")) in ids:
            return {**conn, BW_KEY_UNAVAILABLE: BW_REF_LOOKUP_FAILED}
        return None

    async def _ref(self, instance: Mapping[str, Any]) -> Any:
        """The server's ref, None, or _LOOKUP_FAILED.

        A lookup that crossed a forget_refs (the ref was edited meanwhile)
        is discarded and done once more; if that one is crossed too, None.
        """
        for _ in range(2):
            generation = self._refs_generation
            ref = await self._lookup_ref(instance, generation)
            if generation == self._refs_generation:
                return ref
        return None

    async def _lookup_ref(self, instance: Mapping[str, Any], generation: int) -> Any:
        """One ref lookup for *instance*, remembered per server.

        An own server is not looked up during an API outage (None), nor
        when the roll-up and the local mirror say the user has no refs
        (None, remembered for the ref TTL); otherwise it is, listed in the
        roll-up or not. Team-shared servers are always looked up.
        """
        instance_id = instance.get("id")
        if not instance_id:
            return None
        provider = _provider(instance)
        shared = instance.get("is_shared") is True
        team_slug = instance.get("team_slug") if shared else None
        memo_key = (provider, str(instance_id), team_slug)
        hit = self._ref_memo.get(memo_key)
        if hit is not None and hit[0] > self._clock():
            return hit[1]
        ref_service = self._ref_service()
        team_service = self._team_service()
        if ref_service is None and team_service is None:
            return None
        if not shared:
            ids = await self._personal_ref_ids()
            if ids is _ROLLUP_OUTAGE:
                # The API is out: no per-server lookups, the connection as before.
                return None
            if ids is _NO_REFS:
                # No Bitwarden refs anywhere: spare the fleet a request per server.
                self._remember_ref(generation, memo_key, self._ttl, None)
                return None
            # A server the roll-up does not list is still looked up: the
            # roll-up may leave out a freshly saved ref.
        personal = _FailureRecorder(ref_service or _NoPersonalRefs(), "get_personal_instance_ref")
        team = _FailureRecorder(team_service or _NoTeamRefs(), "get_team_server_ssh_ref")
        resolver = SshRefResolver(
            personal, team, self._ssh_service,
            teams_supplier=(
                (lambda: [{"slug": team_slug}])
                if isinstance(team_slug, str) and team_slug else None
            ),
        )
        failed = False
        try:
            ref = await self._bounded(resolver.resolve(dict(instance)))
        except Exception as exc:  # noqa: BLE001 - the lookup is best-effort; a timeout is a failure
            logger.debug("SSH-ref lookup skipped (%s)", type(exc).__name__)
            ref, failed = None, True
        if ref is not None and not (ref.source in {"personal", "team"} and ref.item_id):
            ref = None
        if ref is None and (failed or personal.failed or team.failed):
            # Not "no ref": retried after a short pause, not a full TTL.
            self._remember_ref(generation, memo_key, self._failed_ttl, _LOOKUP_FAILED)
            return _LOOKUP_FAILED
        self._remember_ref(generation, memo_key, self._ttl, ref)
        return ref

    async def _bounded(self, request: Any) -> Any:
        """Await *request* for at most the lookup timeout; the request itself is not cancelled.

        It runs as its own task, so a timeout ends only the wait: a token
        refresh the request started (on a 401) still completes and stores
        the rotated pair. Its late answer is dropped (the caller already
        recorded the failure) and its exception retrieved.
        """
        task = asyncio.ensure_future(request)
        task.add_done_callback(_retrieve_exception)
        return await asyncio.wait_for(asyncio.shield(task), self._lookup_timeout)

    def _remember_ref(self, generation: int, memo_key: tuple, ttl: float, value: Any) -> None:
        if generation == self._refs_generation:
            self._ref_memo[memo_key] = (self._clock() + ttl, value)

    async def _personal_ref_ids(self) -> Any:
        """What the roll-up says, remembered for the ref TTL (forget_refs clears it).

        The ids it lists; None without a roll-up lister; _ROLLUP_OUTAGE when
        its read failed; _NO_REFS when it lists nothing and this device's ref
        mirror is empty too (the user has no Bitwarden refs). A non-empty
        list never skips a server's own lookup: it may leave out a freshly
        saved ref.
        """
        if self._rollup is not None and self._rollup[0] > self._clock():
            return self._rollup[1]
        if self._rollup_read is None:
            self._rollup_read = asyncio.ensure_future(self._read_rollup())
            self._rollup_read.add_done_callback(self._rollup_read_done)
        return await asyncio.shield(self._rollup_read)

    def _rollup_read_done(self, task: asyncio.Task) -> None:
        if self._rollup_read is task:
            self._rollup_read = None

    async def _read_rollup(self) -> Any:
        """Read the roll-up; see :meth:`_personal_ref_ids` for what it returns."""
        generation = self._refs_generation
        ref_service = self._ref_service()
        lister = getattr(ref_service, "list_personal_instances", None)
        if lister is None:
            ids: Any = None
        else:
            try:
                rows = await self._bounded(lister())
                ids = frozenset(
                    str(row.get("instance_id", ""))
                    for row in rows if isinstance(row, dict)
                )
            except Exception as exc:  # noqa: BLE001 - a failed roll-up is an API outage
                logger.info("SSH-ref list unavailable (%s); Bitwarden keys paused", type(exc).__name__)
                ids = _ROLLUP_OUTAGE
            if ids == frozenset() and not await _saved_refs_here(ref_service):
                ids = _NO_REFS
        if generation == self._refs_generation:
            self._rollup = (self._clock() + self._ttl, ids)
        return ids

    # ------------------------------------------------------------------
    # key files
    # ------------------------------------------------------------------

    async def _key_path(self, item_id: str) -> str:
        """The item's current key file; read through bw when missing, due or refused."""
        current = self._keys.get(item_id)
        if current is not None and not os.path.isfile(current.path):
            del self._keys[item_id]
            current = None
        if current is not None and current.due > self._clock() and not current.reread:
            return current.path
        read = self._key_reads.get(item_id)
        if read is None:
            read = asyncio.ensure_future(self._read_key(item_id))
            self._key_reads[item_id] = read
            read.add_done_callback(lambda task: self._key_read_done(item_id, task))
        return await asyncio.shield(read)

    def _key_read_done(self, item_id: str, task: asyncio.Task) -> None:
        if self._key_reads.get(item_id) is task:
            del self._key_reads[item_id]
        if not task.cancelled():
            task.exception()  # retrieved here so a read nobody awaits is not reported

    def _generation(self, item_id: str) -> tuple[int, int]:
        return (self._all_keys_generation, self._key_generation.get(item_id, 0))

    async def _read_key(self, item_id: str) -> str:
        """Read *item_id*'s key through bw; the current file, or a new one when it changed.

        A forget_keys during the read (sign-out, lock, a ref edit) discards
        it, removing any file it wrote, and raises BwKeyForgottenError: no
        decrypted file may exist after the keys were dropped.
        """
        generation = self._generation(item_id)
        resolver = self._resolver_factory(session_getter=self._session_getter)
        try:
            key_body = await asyncio.to_thread(resolver.resolve_ssh_key, item_id)
        except _AUTHORITATIVE_NEGATIVES:
            self.forget_keys(item_id)
            raise
        except Exception as exc:
            return self._keep_current(item_id, generation, exc)
        if self._generation(item_id) != generation:
            raise BwKeyForgottenError("the key was forgotten while it was read")
        now = self._clock()
        current = self._keys.get(item_id)
        if current is not None and await asyncio.to_thread(_holds_key, current.path, key_body):
            if self._generation(item_id) != generation or self._keys.get(item_id) is not current:
                raise BwKeyForgottenError("the key was forgotten while it was compared")
            current.due, current.reread = now + self._key_ttl, False
            return current.path
        path = await asyncio.to_thread(persistent_bw_ssh_key, key_body)
        if self._generation(item_id) != generation:
            if not await asyncio.to_thread(_remove_quietly, path):
                self._keep_pending(path)
            raise BwKeyForgottenError("the key was forgotten while it was written")
        current = self._keys.get(item_id)
        if current is not None:
            self._superseded.append((item_id, current.path, now))
        self._keys[item_id] = _KeyFile(path=path, due=now + self._key_ttl)
        return path

    def _keep_current(self, item_id: str, generation: tuple[int, int], exc: Exception) -> str:
        """After a re-read failed for a passing reason: the current file, read again a TTL later."""
        current = self._keys.get(item_id)
        if current is None or self._generation(item_id) != generation or not os.path.isfile(current.path):
            raise exc
        logger.debug("Bitwarden key not read again (%s); using the one in place", type(exc).__name__)
        current.due, current.reread = self._clock() + self._key_ttl, False
        return current.path

    async def _remove_expired_superseded(self) -> None:
        """Remove superseded files past their grace, and retry failed removals.

        An entry is dropped only once its removal has finished, so a
        cancelled apply leaves the rest for the next apply or forget_keys.
        """
        for path in list(self._pending_removal):
            if await asyncio.to_thread(_remove_quietly, path) and path in self._pending_removal:
                self._pending_removal.remove(path)
        cutoff = self._clock() - self._grace
        for entry in [entry for entry in self._superseded if entry[2] <= cutoff]:
            gone = await asyncio.to_thread(_remove_quietly, entry[1])
            if entry in self._superseded:
                self._superseded.remove(entry)
            if not gone:
                self._keep_pending(entry[1])

    def _remove(self, path: str) -> None:
        """Remove *path* now; a file that survives is retried on the next apply and forget_keys."""
        if not _remove_quietly(path):
            self._keep_pending(path)

    def _keep_pending(self, path: str) -> None:
        if path not in self._pending_removal:
            self._pending_removal.append(path)

    def _retry_pending_removals(self) -> None:
        for path in list(self._pending_removal):
            if _remove_quietly(path) and path in self._pending_removal:
                self._pending_removal.remove(path)


def _provider(instance: Mapping[str, Any]) -> str:
    return str(instance.get("provider", "aws") or "aws").lower()


def _holds_key(path: str, key_body: str) -> bool:
    """Whether the file at *path* already holds *key_body* (as persistent_bw_ssh_key writes it)."""
    body = key_body if key_body.endswith("\n") else key_body + "\n"
    try:
        with open(path, "rb") as handle:
            return hmac.compare_digest(handle.read(), body.encode())
    except OSError:
        return False


def _remove_quietly(path: str) -> bool:
    """Remove a key file; whether it is gone. Never raises.

    A file that survives stays registered with the exit sweeper (see
    remove_bw_ssh_key), and the provider retries it.
    """
    try:
        remove_bw_ssh_key(path)
    except Exception as exc:  # noqa: BLE001 - the provider and the exit sweeper retry
        logger.debug("Bitwarden key file not removed (%s)", type(exc).__name__)
    return not os.path.lexists(path)


async def _saved_refs_here(ref_service: Any) -> bool:
    """Whether this device's ref mirror has a ref; True (look up) when it cannot say."""
    checker = getattr(ref_service, "has_local_refs", None)
    if not callable(checker):
        return True
    try:
        return bool(await asyncio.to_thread(checker))
    except Exception as exc:  # noqa: BLE001 - unknown means "may have refs"
        logger.debug("Local ref mirror check failed (%s)", type(exc).__name__)
        return True


def _retrieve_exception(task: asyncio.Future) -> None:
    """Mark a background lookup's exception as seen (its answer is no longer wanted)."""
    if not task.cancelled():
        task.exception()
