"""Merging a team's copy of a server's memory into the user's own record.

Before memory folded a team's shared server into the user's own row of the
same machine, each was probed, annotated and given findings separately, under
the share's id. Those copies are merged into the user's own record without
losing anything:

* a probed module: the newer ``probed_at`` wins;
* ``annotations.md``: neither side is overwritten; text only the copy (or the
  service) holds is moved, or appended once under a heading that says where
  it came from;
* findings: :meth:`MemoryService.merge_findings` (last writer wins,
  ``superseded_by`` is never unset).

The merge is non-destructive. What the service holds is only READ (never
written into the copy), the copy's folder is never moved or deleted, and its
queued uploads are dropped only after everything is stored. When the target
is verified to contain everything, a small marker is written into the copy's
folder; a later pass skips a marked copy, so a note the user deleted since is
never brought back. Anything short of that (an unreadable file, a service
that could not be read, a failed write) leaves no marker, and the next pass
repeats the idempotent steps. The same rules fold the entry a share left
behind when it was removed and added again under a new id (see
:func:`same_share`), and a member's memory that earlier releases filed under
the team's label.

Data that cannot be read (a note that does not decode, a finding file that
does not parse, a symlink where a file belongs) is never treated as empty:
nothing is written over it. One copy that fails never stops the others.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import (
    Any, Awaitable, Callable, Collection, Dict, List, Mapping, Optional, Sequence, Set, Tuple,
)

from servonaut.services.memory.provider import (
    SHARED_MEMORY_PROVIDER,
    instance_provider,
)
from servonaut.services.shared_servers import is_shared_row, own_twin

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MemoryKey:
    """Where one server's memory is filed: provider slug and instance id."""

    provider: str
    instance_id: str


@dataclass
class MergeStats:
    """What one merge changed in the target."""

    modules: int = 0
    notes: int = 0
    findings: int = 0
    verified: bool = True
    held_notes: bool = False
    held_findings: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.modules or self.notes or self.findings)


@dataclass
class TeamMergeReport:
    """What one pass over the shared rows did."""

    copies: int = 0
    notes: int = 0
    findings: int = 0
    modules: int = 0
    kept: List[str] = field(default_factory=list)
    undecided: int = 0

    def message(self) -> str:
        copies = f"{self.copies} team {'copy' if self.copies == 1 else 'copies'}"
        notes = f"{self.notes} {'note' if self.notes == 1 else 'notes'}"
        findings = f"{self.findings} {'finding' if self.findings == 1 else 'findings'}"
        return f"Merged {copies} into your servers: {notes}, {findings}."


# ---------------------------------------------------------------------------
# Pure rules
# ---------------------------------------------------------------------------


def _parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.rstrip("Z"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def copy_module_wins(own: Optional[Mapping[str, Any]], copy: Mapping[str, Any]) -> bool:
    """Whether the team copy's module replaces the user's own.

    Only a strictly newer ``probed_at`` wins; a tie, an undatable copy or an
    unreadable pair keeps the user's own. A module the user has none of is
    always taken.
    """
    if own is None:
        return True
    copy_at, own_at = _parse_time(copy.get("probed_at")), _parse_time(own.get("probed_at"))
    if copy_at is None:
        return False
    return own_at is None or copy_at > own_at


def is_contained_text(own: str, wanted: str) -> bool:
    """Whether *wanted* appears in *own* as whole lines.

    A note counts as present only when its lines (ignoring trailing blanks)
    follow one another in the user's text. A short note such as ``prod`` is
    therefore not swallowed by a longer line that merely contains the word.
    """
    needle = [line.rstrip() for line in wanted.strip().splitlines()]
    if not needle:
        return True
    haystack = [line.rstrip() for line in own.splitlines()]
    size = len(needle)
    return any(haystack[i:i + size] == needle for i in range(len(haystack) - size + 1))


def _effective_time(record: Mapping[str, Any]) -> str:
    return max(record.get("created_at") or "", record.get("updated_at") or "")


def finding_contained(source: Mapping[str, Any], target: Optional[Mapping[str, Any]]) -> bool:
    """Whether *target* holds everything the finding *source* says.

    Last-writer-wins on the effective time (``max(created_at, updated_at)``):
    the target must be at least as recent, and a ``superseded_by`` on the
    source must also be set on the target (it is never unset by a merge).
    """
    if target is None:
        return False
    if _effective_time(target) < _effective_time(source):
        return False
    return bool(target.get("superseded_by")) or not source.get("superseded_by")


def merge_annotation_text(
    own: str, copy: str, *, source: str, merged_on: str
) -> Tuple[str, bool]:
    """The user's annotations with the team copy's text kept, and whether that changed them.

    The user's text is never rewritten: text only the copy holds becomes the
    annotations when the user has none, and is otherwise appended under a
    heading naming *source* and *merged_on*. Text the user's annotations
    already contain is skipped, so a second merge adds nothing.
    """
    wanted = copy.strip()
    if not wanted or is_contained_text(own, wanted):
        return own, False
    if not own.strip():
        return copy, True
    heading = f"## Notes from {source}, merged {merged_on}"
    return f"{own.rstrip()}\n\n{heading}\n\n{wanted}\n", True


def same_share(first: Mapping[str, Any], second: Mapping[str, Any]) -> bool:
    """Whether two share identities are the same server.

    An identity holds the share's recorded ``instance_id`` and its ``host``,
    ``port`` and ``login``. Equal instance ids are the same server; with no
    id on either side, the same host, port and login are. Anything less is
    undecided, and undecided never merges.
    """
    first_id, second_id = str(first.get("instance_id") or ""), str(second.get("instance_id") or "")
    if first_id and second_id:
        return first_id == second_id
    host = str(first.get("host") or "").strip().lower()
    if not host or host != str(second.get("host") or "").strip().lower():
        return False
    return (
        first.get("port") == second.get("port")
        and str(first.get("login") or "") == str(second.get("login") or "")
    )


def share_identity(row: Mapping[str, Any]) -> Dict[str, Any]:
    """What a share row says about the server it is, for :func:`same_share`."""
    return {
        "instance_id": str(row.get("instance_id") or ""),
        "host": str(row.get("public_ip") or "").strip().lower(),
        "port": row.get("port"),
        "login": str(row.get("username") or ""),
    }


def own_key(row: Mapping[str, Any]) -> MemoryKey:
    """Where the memory of the row *row* is filed."""
    return MemoryKey(instance_provider(row), str(row.get("id") or ""))


# ---------------------------------------------------------------------------
# One merge
# ---------------------------------------------------------------------------

#: The label under which text read from the service is appended.
REMOTE_LABEL = "the service's copy of this server"


class TeamCopyMerger:
    """Merges one memory record into another and checks the result.

    Everything either side holds is read first, strictly: a note, finding or
    module that exists but cannot be read, has the wrong shape, or is a
    symlink raises ``OSError`` / ``ValueError`` before anything is written,
    so unreadable data is never mistaken for empty.

    Args:
        memory_service: The :class:`MemoryService` whose store holds both.
    """

    def __init__(self, memory_service: Any) -> None:
        self._service = memory_service
        self._store = memory_service._store

    def merge(
        self,
        source: MemoryKey,
        target: MemoryKey,
        *,
        source_label: str,
        merged_on: str,
        target_name: str = "",
        remote_notes: str = "",
        remote_records: Sequence[Dict[str, Any]] = (),
    ) -> MergeStats:
        """Merge *source* (and what the service holds) into *target*.

        ``verified`` says everything is in the target. A *source* equal to
        *target* has no local part: only the remote text and records are merged.
        """
        store = self._store
        local = source != target
        theirs = store.read_annotations_strict(source.instance_id, source.provider) if local else ""
        records = (
            store.list_findings(source.instance_id, source.provider, include_superseded=True, strict=True)
            if local else []
        )
        if local:
            store.get_all_modules(source.instance_id, source.provider, strict=True)
        store.read_annotations_strict(target.instance_id, target.provider)
        everything = list(records) + list(remote_records)
        stats = MergeStats(
            held_notes=bool((theirs + remote_notes).strip()), held_findings=bool(everything)
        )
        before = self._finding_snapshot(target)
        if local:
            stats.modules = self._merge_modules(source, target)
        stats.notes = self._merge_notes(target, theirs, source_label, merged_on)
        stats.notes += self._merge_notes(target, remote_notes, REMOTE_LABEL, merged_on)
        self._merge_findings(target, everything)
        stats.findings = self._changed_findings(target, before)
        self._list_target(target, target_name)
        stats.verified = (
            (not local or self.is_contained(source, target))
            and self._notes_contain(target, remote_notes)
            and all(
                finding_contained(r, store.get_finding(target.instance_id, r["id"], target.provider))
                for r in remote_records
            )
        )
        return stats

    def _finding_snapshot(self, target: MemoryKey) -> Dict[str, Any]:
        records = self._store.list_findings(
            target.instance_id, target.provider, include_superseded=True, strict=True
        )
        return {record["id"]: dict(record) for record in records}

    def _changed_findings(self, target: MemoryKey, before: Dict[str, Any]) -> int:
        """How many of the target's findings are new or differ from *before*."""
        after = self._finding_snapshot(target)
        return sum(1 for fid, record in after.items() if before.get(fid) != record)

    def _notes_contain(self, target: MemoryKey, text: str) -> bool:
        kept = self._store.read_annotations_strict(target.instance_id, target.provider)
        return is_contained_text(kept, text)

    def is_contained(self, source: MemoryKey, target: MemoryKey) -> bool:
        """Whether everything *source* holds is in *target* (or superseded there by newer data)."""
        store = self._store
        modules = store.get_all_modules(source.instance_id, source.provider, strict=True)
        for module, data in modules.items():
            kept = store.get_module(target.instance_id, module, target.provider)
            if kept is None or copy_module_wins(kept, data):
                return False
        wanted = store.read_annotations_strict(source.instance_id, source.provider)
        if not self._notes_contain(target, wanted):
            return False
        for record in store.list_findings(
            source.instance_id, source.provider, include_superseded=True, strict=True
        ):
            kept = store.get_finding(target.instance_id, record["id"], target.provider)
            if not finding_contained(record, kept):
                return False
        return True

    def _merge_modules(self, source: MemoryKey, target: MemoryKey) -> int:
        store, changed = self._store, 0
        for module, data in store.get_all_modules(source.instance_id, source.provider, strict=True).items():
            kept = store.get_module(target.instance_id, module, target.provider)
            if not copy_module_wins(kept, data):
                continue
            moved = dict(data)
            if "instance_id" in moved:
                moved["instance_id"] = target.instance_id
            store.save_module(target.instance_id, module, moved, target.provider)
            changed += 1
        return changed

    def _list_target(self, target: MemoryKey, name: str) -> None:
        """Make sure the memory index lists the target with a name, provider and modules."""
        modules = sorted(self._store.get_all_modules(target.instance_id, target.provider))
        self._store.ensure_index_entry(
            target.instance_id, name or target.instance_id, target.provider, modules
        )

    def _merge_notes(self, target: MemoryKey, theirs: str, label: str, merged_on: str) -> int:
        """Merge *theirs* into the target's notes; the read-merge-write is one locked step."""
        if not theirs.strip():
            return 0
        store = self._store
        with store.annotation_lock(target.instance_id):
            mine = store.read_annotations_strict(target.instance_id, target.provider)
            text, changed = merge_annotation_text(mine, theirs, source=label, merged_on=merged_on)
            if not changed:
                return 0
            store.write_annotations(target.instance_id, text, target.provider)
        store.set_annotations_meta(
            target.instance_id,
            annotations_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            annotations_modified_at=datetime.now(tz=timezone.utc).isoformat(),
        )
        return 1

    def _merge_findings(self, target: MemoryKey, records: List[Dict[str, Any]]) -> None:
        if not records:
            return
        stats = self._service.merge_findings(target.instance_id, records, target.provider)
        self._store.set_findings_meta(
            target.instance_id, findings_count=stats.get("active_after", 0)
        )

    def has_copy(self, source: MemoryKey) -> bool:
        return self._store.has_instance_dir(source.instance_id, source.provider)

    def marker(self, source: MemoryKey) -> Optional[Dict[str, Any]]:
        """The merge marker in *source*'s folder; raises for a corrupt one."""
        return self._store.read_merge_marker(source.instance_id, source.provider)

    def mark_merged(self, source: MemoryKey, target: MemoryKey, *, upload_pending: bool) -> None:
        self._store.write_merge_marker(source.instance_id, source.provider, {
            "target_provider": target.provider,
            "target_id": target.instance_id,
            "merged_at": datetime.now(tz=timezone.utc).isoformat(),
            "upload_pending": upload_pending,
        })


# ---------------------------------------------------------------------------
# Which copies fold into which records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MergePlan:
    """One record to fold into another."""

    source: MemoryKey
    target: MemoryKey
    label: str
    target_row: Mapping[str, Any]
    uploads: bool


def _label(row: Mapping[str, Any], earlier: bool) -> str:
    if earlier:
        return "an earlier share of this server"
    team = str(row.get("team_name") or row.get("team_slug") or "").strip()
    return f"the {team} team's copy of this server" if team else "a team's copy of this server"


Discover = Callable[[str], Sequence[str]]


def plan_merges(
    rows: Sequence[Mapping[str, Any]],
    index_entries: Sequence[Mapping[str, Any]],
    discover: Discover,
) -> Tuple[List[MergePlan], int]:
    """What to fold, from the real *rows*, the memory index's entries and the folders on disk.

    *discover* names the provider folders that hold a folder for a share id
    (the store scans the memory root; the index is not consulted, so a copy is
    found on every retry whatever the index says). For every shared row each
    such folder folds into the row's current key: the user's own row when
    :func:`own_twin` confirms one, else the shared row itself (a member's
    view; uploads stay as they were). A row with no folder yet still gets one
    plan whose source is the neutral slug, used only if the service holds
    something for the share. An index entry that recorded the identity of a
    share no row carries any more (the share was removed and added again
    under a new id) folds its folders into the row that is now the same
    server. An entry matching several rows, or none, stays where it is; the
    count of ambiguous ones is returned.
    """
    plans: List[MergePlan] = []
    shared = [row for row in rows if is_shared_row(row) and row.get("id")]
    current = {str(row.get("id") or "") for row in rows}
    for row in shared:
        twin = own_twin(row, rows)
        target_row = twin if twin is not None else row
        target = own_key(target_row)
        share_id = str(row.get("id") or "")
        keys = [MemoryKey(slug, share_id) for slug in discover(share_id)]
        keys = [key for key in keys if key != target] or [MemoryKey(SHARED_MEMORY_PROVIDER, share_id)]
        for key in keys:
            plans.append(MergePlan(key, target, _label(row, False), target_row, twin is not None))

    undecided = 0
    for entry in index_entries:
        identity, entry_id = entry.get("share_identity"), str(entry.get("instance_id") or "")
        if not isinstance(identity, dict) or not entry_id or entry_id in current:
            continue
        matches = [row for row in shared if same_share(identity, share_identity(row))]
        if len(matches) != 1:
            undecided += 1
            continue
        row = matches[0]
        twin = own_twin(row, rows)
        target_row = twin if twin is not None else row
        for slug in discover(entry_id):
            plans.append(MergePlan(
                MemoryKey(slug, entry_id), own_key(target_row), _label(row, True),
                target_row, twin is not None,
            ))
    return plans, undecided


# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------

#: Lists the share ids the sync service holds memory for (one request).
RemoteIdLister = Callable[[], Awaitable[Collection[str]]]

#: What a single copy's merge can raise: unreadable, malformed or unsafe local
#: data. A plan that raises one is left as it was; the pass goes on.
_PLAN_ERRORS = (OSError, ValueError, KeyError)

#: How Memory Sync stands on this computer: not set up (no remote copy can be
#: read here), set up but locked, or usable.
SYNC_OFF, SYNC_LOCKED, SYNC_READY = "off", "locked", "ready"


def sync_state(sync_service: Any) -> str:
    """Whether Memory Sync is not set up, set up but locked, or usable here."""
    if sync_service is None:
        return SYNC_OFF
    if bool(getattr(sync_service, "is_configured", False)):
        return SYNC_READY
    enrolled = getattr(sync_service, "is_enrolled_locally", None)
    return SYNC_LOCKED if callable(enrolled) and bool(enrolled()) else SYNC_OFF


async def _remote_ids(lister: Optional[RemoteIdLister]) -> Optional[Set[str]]:
    """The share ids the service holds memory for, or None when that is unknown."""
    if lister is None:
        return None
    try:
        return {str(item) for item in await lister()}
    except Exception as exc:  # noqa: BLE001 — unknown listing: no copy is marked
        logger.warning("Team copy listing failed: %s", type(exc).__name__)
        return None


def _record_identities(memory_service: Any, rows: Sequence[Mapping[str, Any]]) -> None:
    """Note which server each shared-only row is (see :func:`same_share`).

    The store keeps it for entries not created yet.
    """
    store = memory_service._store
    for row in rows:
        if is_shared_row(row) and row.get("id") and own_twin(row, rows) is None:
            store.set_share_identity(str(row["id"]), share_identity(row))


def _queue_upload(sync_service: Any, memory_service: Any, plan: MergePlan) -> bool:
    """Queue the own row's annotations and findings; True when all of it is stored.

    A duplicate upload is harmless, so this runs again on every retry.
    """
    target = plan.target
    instance = {"id": target.instance_id, "name": str(plan.target_row.get("name") or "")}
    stored = True
    text = memory_service.read_annotations(target.instance_id, target.provider)
    if text.strip():
        stored = bool(sync_service.enqueue_annotations(instance, text)) and stored
    records = memory_service.list_findings(
        target.instance_id, target.provider, include_superseded=True
    )
    if records:
        stored = bool(sync_service.enqueue_findings(instance, records)) and stored
    return stored


@dataclass
class _Pass:
    """What one pass shares between its plans."""

    merger: TeamCopyMerger
    memory_service: Any
    sync_service: Any
    state: str
    remote_ids: Optional[Set[str]]
    merged_on: str
    report: TeamMergeReport
    remote: Dict[str, Tuple[Any, Any]] = field(default_factory=dict)

    async def read_remote(self, share_id: str, name: str) -> Tuple[Any, Any]:
        """The service's notes and findings for a share id (read once per pass)."""
        if share_id not in self.remote:
            self.remote[share_id] = (
                await self.sync_service.fetch_remote_notes(share_id, name),
                await self.sync_service.fetch_remote_findings(share_id, name),
            )
        return self.remote[share_id]


def _remote_settled(run: _Pass, share_id: str) -> bool:
    """Whether the service's side of *share_id* is known: nothing there, or read."""
    if run.state == SYNC_OFF:
        return True
    return run.state == SYNC_READY and run.remote_ids is not None


async def _retry_uploads(plan: MergePlan, run: _Pass, marker: Dict[str, Any]) -> None:
    """Finish the uploads a marked copy still owes; clear the flag when stored."""
    if run.state != SYNC_READY or not plan.uploads:
        return
    if not _queue_upload(run.sync_service, run.memory_service, plan):
        return
    run.sync_service.drop_pending_for({plan.source.instance_id})
    run.merger.mark_merged(plan.source, plan.target, upload_pending=False)


def _is_done(plan: MergePlan, run: _Pass) -> Optional[Dict[str, Any]]:
    """The copy's marker when it was merged into this plan's target and that still exists."""
    merger, source, target = run.merger, plan.source, plan.target
    if not _has_dir(merger, source):
        return None
    marker = merger.marker(source)
    if (
        marker
        and marker.get("target_provider") == target.provider
        and marker.get("target_id") == target.instance_id
        and _has_dir(merger, target)
    ):
        return marker
    return None


def _has_dir(merger: TeamCopyMerger, key: MemoryKey) -> bool:
    try:
        return merger.has_copy(key)
    except ValueError:
        return False


async def _fold(plan: MergePlan, run: _Pass) -> None:
    """Merge one copy into its target; mark it merged only when everything is stored."""
    source_id, report, merger = plan.source.instance_id, run.report, run.merger
    name = str(plan.target_row.get("name") or "")
    if run.memory_service.is_memory_disabled(plan.target.instance_id, name):
        report.kept.append(source_id)
        return
    marker = _is_done(plan, run)
    if marker is not None:
        if marker.get("upload_pending"):
            await _retry_uploads(plan, run, marker)
        return
    listed = run.state == SYNC_READY and run.remote_ids is not None and source_id in run.remote_ids
    on_disk = _has_dir(merger, plan.source)
    if not on_disk and not listed:
        return  # nothing here, and nothing at the service
    remote_notes, remote_records, settled = "", [], _remote_settled(run, source_id)
    if listed:
        notes, findings = await run.read_remote(source_id, name)
        if notes.status == "found":
            remote_notes = notes.text
        if findings.status == "found":
            remote_records = findings.records
        settled = notes.status != "unavailable" and findings.status != "unavailable"
    stats = merger.merge(
        plan.source, plan.target, source_label=plan.label, merged_on=run.merged_on,
        target_name=name, remote_notes=remote_notes, remote_records=remote_records,
    )
    report.notes += stats.notes
    report.findings += stats.findings
    report.modules += stats.modules
    if not stats.verified or not settled:
        logger.warning("Team copy %s not marked: not everything it held can be confirmed in the target", source_id)
        report.kept.append(source_id)
        return
    owes = plan.uploads and run.state == SYNC_READY and (stats.held_notes or stats.held_findings)
    merger.mark_merged(plan.source, plan.target, upload_pending=owes)
    report.copies += 1
    if run.sync_service is not None and plan.uploads and not owes:
        run.sync_service.drop_pending_for({source_id})
    if owes:
        await _retry_uploads(plan, run, {"upload_pending": True})
    if plan.source.instance_id != plan.target.instance_id:
        run.memory_service._store.remove_index_entry(source_id)


async def merge_team_copies(
    memory_service: Any,
    sync_service: Any,
    rows: Sequence[Mapping[str, Any]],
    *,
    today: Optional[str] = None,
    list_remote_ids: Optional[RemoteIdLister] = None,
) -> TeamMergeReport:
    """Fold every team copy of a server's memory into the user's own record.

    *rows* are the real records (never demo-redacted). Nothing is moved or
    deleted. A copy is merged (modules, notes, findings, and the service's
    notes and findings, which are only read) and checked; then a marker is
    written into its folder. A marked copy is skipped by later passes, which
    only finish its uploads. No marker is written while Memory Sync is set up
    but locked, while the one listing *list_remote_ids* (asked only if some
    copy is unmarked) failed, or when reading the service for a listed share
    failed: the next pass repeats the idempotent steps. With Memory Sync not
    set up, nothing is read from the service. A share id the listing names
    that has no local folder is merged from the service alone. One copy that
    fails never stops the others.
    """
    report = TeamMergeReport()
    merger = TeamCopyMerger(memory_service)
    store = memory_service._store
    merged_on = today or datetime.now(tz=timezone.utc).date().isoformat()
    _record_identities(memory_service, rows)
    plans, report.undecided = plan_merges(rows, memory_service.list_all(), store.find_instance_dirs)
    plans = [p for p in plans if store.is_addressable(p.source.instance_id, p.source.provider)]
    state = sync_state(sync_service)
    run = _Pass(merger, memory_service, sync_service, state, None, merged_on, report)
    pending: List[MergePlan] = []
    for plan in plans:
        try:
            marker = _is_done(plan, run)
            if marker is None or marker.get("upload_pending"):
                pending.append(plan)
        except _PLAN_ERRORS as exc:
            logger.warning("Team copy %s kept: %s", plan.source.instance_id, type(exc).__name__)
            report.kept.append(plan.source.instance_id)
    if state == SYNC_READY and pending:
        run.remote_ids = await _remote_ids(list_remote_ids)
    for plan in pending:
        try:
            await _fold(plan, run)
        except _PLAN_ERRORS as exc:
            logger.warning("Team copy %s kept: %s", plan.source.instance_id, type(exc).__name__)
            report.kept.append(plan.source.instance_id)
    return report
