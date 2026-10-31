"""Merging a team's copy of a server's memory into the user's own record.

Before memory folded a team's shared server into the user's own row of the
same machine, each was probed, annotated and given findings separately, under
the share's id. Those copies are merged into the user's own record without
losing anything:

* a probed module: the newer ``probed_at`` wins;
* ``annotations.md``: neither side is overwritten; text only the copy holds is
  moved, or appended once under a heading that says where it came from;
* findings: :meth:`MemoryService.merge_findings` (last writer wins,
  ``superseded_by`` is never unset).

The copy's directory is only moved to a backup after everything it held was
read back from the target. The same rules fold the entry a share left behind
when it was removed and added again under a new id (see :func:`same_share`),
and a member's memory that earlier releases filed under the team's label.

Data that cannot be read (a note that does not decode, a finding file that
does not parse) is never treated as empty: nothing is written over it and the
copy stays where it is. One copy that fails never stops the others.
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
    provider_slug,
)
from servonaut.services.memory.store import _validate_instance_id
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


def _addressable(key: MemoryKey) -> bool:
    """Whether *key* names a directory the store can safely address.

    A team label with a path separator filed its memory in a nested
    directory that no slug can name; such an entry is skipped, and only the
    share id is logged (the label is team-controlled text).
    """
    try:
        _validate_instance_id(key.instance_id)
        _validate_instance_id(key.provider)
    except ValueError:
        logger.warning("Team copy %r skipped: its folder name is not addressable", key.instance_id)
        return False
    return True


def copy_keys(row: Mapping[str, Any], entry: Optional[Mapping[str, Any]] = None) -> List[MemoryKey]:
    """Where a shared row's memory may be filed: under its team's label, as
    earlier releases did, under the label the memory index recorded for it
    (a renamed team), and under the neutral slug."""
    share_id = str(row.get("id") or "")
    slugs = [provider_slug(str(row.get("provider") or ""))]
    if entry is not None:
        slugs.append(provider_slug(str(entry.get("provider") or "")))
    slugs.append(SHARED_MEMORY_PROVIDER)
    keys = [MemoryKey(slug, share_id) for slug in dict.fromkeys(slugs) if slug]
    return [key for key in keys if _addressable(key)]


# ---------------------------------------------------------------------------
# One merge
# ---------------------------------------------------------------------------


class TeamCopyMerger:
    """Merges one memory record into another and checks the result.

    Everything either side holds is read first, strictly: a note or finding
    that exists but cannot be read raises ``OSError`` / ``ValueError`` before
    anything is written, so unreadable data is never mistaken for empty.

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
        earlier_notes: str = "",
    ) -> MergeStats:
        """Merge *source* into *target*; ``verified`` says nothing was lost.

        *earlier_notes* is text the source held before a pull replaced it; it
        is merged after the source's current text and checked the same way.
        """
        store = self._store
        theirs = store.read_annotations_strict(source.instance_id, source.provider)
        store.read_annotations_strict(target.instance_id, target.provider)
        records = store.list_findings(
            source.instance_id, source.provider, include_superseded=True, strict=True
        )
        store.get_all_modules(source.instance_id, source.provider, strict=True)
        stats = MergeStats()
        stats.modules = self._merge_modules(source, target)
        stats.notes = self._merge_notes(target, theirs, source_label, merged_on)
        if earlier_notes.strip() and earlier_notes != theirs:
            stats.notes += self._merge_notes(target, earlier_notes, source_label, merged_on)
        stats.findings = self._merge_findings(target, records)
        if stats.modules or (
            source.instance_id == target.instance_id and (stats.notes or stats.findings)
        ):
            self._list_target(target, target_name)
        stats.verified = self.is_contained(source, target) and (
            not earlier_notes.strip() or self._notes_contain(target, earlier_notes)
        )
        return stats

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
            if store.get_finding(target.instance_id, record["id"], target.provider) is None:
                return False
        return True

    def earlier_notes(self, source: MemoryKey) -> str:
        """The source's notes as they are now, or ``""`` when absent or unreadable.

        Read before a pull may replace them; an unreadable file is left to
        :meth:`merge`, which refuses it.
        """
        try:
            return self._store.read_annotations_strict(source.instance_id, source.provider)
        except (OSError, ValueError):
            return ""

    def _merge_modules(self, source: MemoryKey, target: MemoryKey) -> int:
        store, changed = self._store, 0
        for module, data in store.get_all_modules(source.instance_id, source.provider).items():
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
        """Make sure the memory index lists the target with its modules."""
        modules = sorted(self._store.get_all_modules(target.instance_id, target.provider))
        self._service.update_index(
            target.instance_id, name or target.instance_id, target.provider, modules
        )

    def _merge_notes(self, target: MemoryKey, theirs: str, label: str, merged_on: str) -> int:
        store = self._store
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

    def _merge_findings(self, target: MemoryKey, records: List[Dict[str, Any]]) -> int:
        if not records:
            return 0
        stats = self._service.merge_findings(target.instance_id, records, target.provider)
        self._store.set_findings_meta(
            target.instance_id, findings_count=stats.get("active_after", 0)
        )
        return stats.get("created", 0) + stats.get("updated", 0)

    def back_up(self, source: MemoryKey) -> Optional[Any]:
        """Move the merged copy's directory aside; nothing is deleted."""
        return self._store.backup_instance_dir(source.instance_id, source.provider)

    def has_copy(self, source: MemoryKey) -> bool:
        return self._store.has_instance_dir(source.instance_id, source.provider)


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


def plan_merges(
    rows: Sequence[Mapping[str, Any]], index_entries: Sequence[Mapping[str, Any]]
) -> Tuple[List[MergePlan], int]:
    """What to fold, from the real *rows* and the memory index's entries.

    Every shared row's memory may sit under another provider slug than the one
    it is filed under now (the team's label, as earlier releases did, or the
    label the index recorded). Those entries fold into the row's current key:
    the user's own row when :func:`own_twin` confirms one, else the shared
    row itself (a member's view; uploads stay as they were). An index entry
    that recorded the identity of a share no row carries any more (the share
    was removed and added again under a new id) folds into the row that is now
    the same server, and into the user's own row when that is one. An entry
    matching several rows, or none, stays where it is; the count of ambiguous
    ones is returned.
    """
    plans: List[MergePlan] = []
    by_id = {str(entry.get("instance_id") or ""): entry for entry in index_entries}
    shared = [row for row in rows if is_shared_row(row) and row.get("id")]
    current = {str(row.get("id") or "") for row in rows}
    for row in shared:
        twin = own_twin(row, rows)
        target_row = twin if twin is not None else row
        target = own_key(target_row)
        for key in copy_keys(row, by_id.get(str(row.get("id") or ""))):
            if key != target:
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
        source = MemoryKey(provider_slug(str(entry.get("provider") or "")), entry_id)
        if _addressable(source):
            plans.append(
                MergePlan(source, own_key(target_row), _label(row, True), target_row, twin is not None)
            )
    return plans, undecided


# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------

#: Lists the share ids the sync service holds memory for (one request).
RemoteIdLister = Callable[[], Awaitable[Collection[str]]]

#: What a single copy's merge can raise: unreadable or unsafe local data. A
#: plan that raises one is kept as it was; the pass goes on.
_PLAN_ERRORS = (OSError, ValueError, KeyError)


async def _pull_copy(sync_service: Any, source: MemoryKey, name: str) -> bool:
    """Pull what the service holds for the copy, before it is merged.

    Contract (read from the service's routes): annotations and findings exist
    under a share id only if this same user once synced them under that id,
    so the caller pulls only the ids the fleet listing names. Returns whether
    both pulls ran; a pull that raised leaves the copy to a later pass.
    """
    ok = True
    for pull in (sync_service.pull_annotations, sync_service.pull_findings):
        try:
            await pull(source.instance_id, name, source.provider)
        except Exception as exc:  # noqa: BLE001 — any failure keeps the copy for a later pass
            logger.warning(
                "Team copy pull failed for %s: %s", source.instance_id, type(exc).__name__
            )
            ok = False
    return ok


async def _remote_ids(lister: Optional[RemoteIdLister]) -> Optional[Set[str]]:
    """The share ids the service holds memory for, or None when that is unknown."""
    if lister is None:
        return None
    try:
        return {str(item) for item in await lister()}
    except Exception as exc:  # noqa: BLE001 — unknown listing: keep every copy for a later pass
        logger.warning("Team copy listing failed: %s", type(exc).__name__)
        return None


def _record_identities(memory_service: Any, rows: Sequence[Mapping[str, Any]]) -> None:
    """Note on each shared-only row's entry which server it is (see :func:`same_share`)."""
    store = memory_service._store
    for row in rows:
        if is_shared_row(row) and row.get("id") and own_twin(row, rows) is None:
            store.set_share_identity(str(row["id"]), share_identity(row))


def _upload_merged(
    sync_service: Any, memory_service: Any, plan: MergePlan, stats: MergeStats
) -> None:
    """Queue the user's merged annotations and findings for upload."""
    if sync_service is None or not plan.uploads:
        return
    target = plan.target
    instance = {"id": target.instance_id, "name": str(plan.target_row.get("name") or "")}
    if stats.notes:
        text = memory_service.read_annotations(target.instance_id, target.provider)
        sync_service.enqueue_annotations(instance, text)
    if stats.findings:
        records = memory_service.list_findings(
            target.instance_id, target.provider, include_superseded=True
        )
        sync_service.enqueue_findings(instance, records)


def _has_copy(merger: TeamCopyMerger, key: MemoryKey) -> bool:
    try:
        return merger.has_copy(key)
    except ValueError:
        logger.warning("Team copy %r skipped: its folder name is not addressable", key.instance_id)
        return False


async def _fold(
    plan: MergePlan,
    *,
    merger: TeamCopyMerger,
    memory_service: Any,
    sync_service: Any,
    remote_ids: Optional[Set[str]],
    syncing: bool,
    merged_on: str,
    report: TeamMergeReport,
) -> None:
    """Merge one copy into its target and, when nothing is missing, back it up."""
    source_id = plan.source.instance_id
    name = str(plan.target_row.get("name") or "")
    if memory_service.is_memory_disabled(plan.target.instance_id, name):
        report.kept.append(source_id)
        return
    pulled, earlier = True, ""
    if syncing:
        # Pulling may replace the copy's own notes; keep what they said.
        earlier = merger.earlier_notes(plan.source)
        if remote_ids is None:
            pulled = False
        elif source_id in remote_ids:
            pulled = await _pull_copy(sync_service, plan.source, name)
    stats = merger.merge(
        plan.source, plan.target, source_label=plan.label,
        merged_on=merged_on, target_name=name, earlier_notes=earlier,
    )
    report.notes += stats.notes
    report.findings += stats.findings
    report.modules += stats.modules
    if not stats.verified or not pulled:
        logger.warning("Team copy %s kept: not everything it held can be confirmed in the target", source_id)
        report.kept.append(source_id)
        return
    merger.back_up(plan.source)
    if sync_service is not None and plan.uploads:
        # An own-row fold repeats memory the own row holds; a member's queue
        # for the same id is theirs and stays as it was.
        sync_service.drop_pending_for({source_id})
    _upload_merged(sync_service, memory_service, plan, stats)
    report.copies += 1


async def merge_team_copies(
    memory_service: Any,
    sync_service: Any,
    rows: Sequence[Mapping[str, Any]],
    *,
    today: Optional[str] = None,
    list_remote_ids: Optional[RemoteIdLister] = None,
) -> TeamMergeReport:
    """Fold every team copy of a server's memory into the user's own record.

    *rows* are the real records (never demo-redacted). A copy is moved to a
    backup only after everything it held was read back from the target;
    until then, and whenever the read-back or a pull fails, it stays where it
    is and a later pass retries. One copy that fails never stops the others.

    When sync is configured, *list_remote_ids* (one request) names the share
    ids the service holds memory for; only those are pulled. If the listing
    is missing or fails, local data is still merged but no copy is backed up.
    Without sync nothing is listed or pulled.
    """
    report = TeamMergeReport()
    merger = TeamCopyMerger(memory_service)
    merged_on = today or datetime.now(tz=timezone.utc).date().isoformat()
    _record_identities(memory_service, rows)
    plans, report.undecided = plan_merges(rows, memory_service.list_all())
    work = [p for p in plans if p.source != p.target and _has_copy(merger, p.source)]
    syncing = sync_service is not None and bool(getattr(sync_service, "is_configured", False))
    remote_ids = await _remote_ids(list_remote_ids) if syncing and work else None
    for plan in work:
        try:
            await _fold(
                plan, merger=merger, memory_service=memory_service, sync_service=sync_service,
                remote_ids=remote_ids, syncing=syncing, merged_on=merged_on, report=report,
            )
        except _PLAN_ERRORS as exc:
            logger.warning(
                "Team copy %s kept: %s", plan.source.instance_id, type(exc).__name__
            )
            report.kept.append(plan.source.instance_id)
    return report
