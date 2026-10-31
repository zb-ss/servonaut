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
queued uploads are dropped only after everything is stored. Once the copy's
own data is verified to be in the target, a small marker is written into the
copy's folder; a later pass never merges that data again, so a note the user
deleted since is never brought back. The marker also says whether the
service's notes and findings for the share are still owed
(``remote_notes_pending`` / ``remote_findings_pending``: Memory Sync was
locked here, or that read was unavailable; each part settles on its own).
A later pass with Memory Sync usable reads the service for the share and
merges only what it holds beyond the copy's own data (the service's copy is
usually what this computer uploaded from it, so a note deleted since is not
brought back), into the marker's target, and only while that is still the
server's own record; uploads the target owes continue after that. With Memory Sync not set up nothing is owed. A
marker from an earlier release has the single ``remote_pending`` flag, which
owes both parts. Anything short
of a verified local merge (an unreadable file, a failed write) leaves no
marker, and the next pass repeats the idempotent steps. The same rules fold
the entry a share left behind when it was removed and added again under a new
id (see :func:`same_share`), and a member's memory that earlier releases
filed under the team's label.

Only one pass runs per computer at a time (a lock beside the memory root); a
pass that finds it busy does nothing. The app, the CLI and the MCP server run
the same pass.

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
    Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple,
)

from servonaut.services.memory.provider import (
    SHARED_MEMORY_PROVIDER,
    instance_provider,
)
from servonaut.services.shared_servers import is_shared_row, own_twin
from servonaut.utils.file_lock import UnsafeLockError

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
    skipped: bool = False

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


def text_beyond(remote: str, held: str) -> str:
    """The lines of *remote* that *held* does not already have.

    A line counts as held when the same line (ignoring trailing blanks) is
    in *held*; blank lines separate what is left. Used so the service's copy
    of a note the user already had, and may have deleted since, is not
    merged again.
    """
    present = {line.rstrip() for line in held.splitlines() if line.strip()}
    kept: List[str] = []
    for line in remote.splitlines():
        if line.strip() and line.rstrip() in present:
            continue
        if not line.strip() and (not kept or not kept[-1].strip()):
            continue
        kept.append(line.rstrip())
    return "\n".join(kept).strip()


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
        # Held for the whole merge so the findings step nests inside it; a busy
        # record keeps the copy for the next pass instead of holding the caller.
        with self._store.annotation_lock(target.instance_id, wait=False):
            return self._merge_locked(
                source, target, source_label, merged_on, target_name, remote_notes, remote_records
            )

    def _merge_locked(
        self,
        source: MemoryKey,
        target: MemoryKey,
        source_label: str,
        merged_on: str,
        target_name: str,
        remote_notes: str,
        remote_records: Sequence[Dict[str, Any]],
    ) -> MergeStats:
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
        target_modules = store.get_all_modules(target.instance_id, target.provider, strict=True)
        everything = list(records) + list(remote_records)
        stats = MergeStats(
            held_notes=bool((theirs + remote_notes).strip()), held_findings=bool(everything)
        )
        before = self._finding_snapshot(target)
        if local:
            stats.modules = self._merge_modules(source, target, target_modules)
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

    def _merge_modules(
        self, source: MemoryKey, target: MemoryKey, target_modules: Dict[str, Dict[str, Any]]
    ) -> int:
        store, changed = self._store, 0
        for module, data in store.get_all_modules(source.instance_id, source.provider, strict=True).items():
            kept = target_modules.get(module)
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

    def mark_merged(
        self, source: MemoryKey, target: MemoryKey, *, upload_pending: bool,
        notes_pending: bool = False, findings_pending: bool = False,
    ) -> Dict[str, Any]:
        """Write the marker and return what it holds.

        ``notes_pending`` and ``findings_pending`` say the service's notes or
        findings for the share are still owed to the target (Memory Sync was
        locked, or that read was unavailable). They settle separately.
        ``remote_pending`` (either owed) is kept for the readers of the
        single flag that earlier releases wrote.
        """
        data = {
            "target_provider": target.provider,
            "target_id": target.instance_id,
            "merged_at": datetime.now(tz=timezone.utc).isoformat(),
            "upload_pending": upload_pending,
            "remote_pending": notes_pending or findings_pending,
            "remote_notes_pending": notes_pending,
            "remote_findings_pending": findings_pending,
        }
        self._store.write_merge_marker(source.instance_id, source.provider, data)
        return data


# ---------------------------------------------------------------------------
# Which copies fold into which records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MergePlan:
    """One record to fold into another.

    ``cloud_only`` marks a share with no folder of its own on this computer:
    only what the service holds for it is merged.
    """

    source: MemoryKey
    target: MemoryKey
    label: str
    target_row: Mapping[str, Any]
    uploads: bool
    cloud_only: bool = False


def _label(row: Mapping[str, Any]) -> str:
    team = str(row.get("team_name") or row.get("team_slug") or "").strip()
    return f"the {team} team's copy of this server" if team else "a team's copy of this server"


Discover = Callable[[str], Sequence[str]]


CloudImport = Callable[[str, str], Optional[Dict[str, Any]]]


def plan_merges(
    rows: Sequence[Mapping[str, Any]], discover: Discover, cloud_import: CloudImport
) -> List[MergePlan]:
    """What to fold, from the real *rows* and the folders on disk.

    *discover* names the provider folders that hold a folder for a share id
    (the store scans the memory root; the index is not consulted). For every
    shared row each such folder other than the row's own current key folds
    into that key: the user's own row when :func:`own_twin` confirms one, else
    the shared row itself (a member's view; uploads stay as they were). A
    member's canonical folder is not a copy of itself and gets no plan. A row
    with no folder at all gets one cloud-only plan, and so does a row whose
    import from the service is unfinished (``importing``) or still owes an
    upload, whatever folders exist; *cloud_import* gives that state for a
    (target id, share id). Memory filed under an
    earlier share id (a share removed and added again) is not touched.
    """
    plans: List[MergePlan] = []
    for row in rows:
        if not (is_shared_row(row) and row.get("id")):
            continue
        twin = own_twin(row, rows)
        target_row = twin if twin is not None else row
        target = own_key(target_row)
        share_id = str(row.get("id") or "")
        keys = [MemoryKey(slug, share_id) for slug in discover(share_id)]
        sources = [key for key in keys if key != target]
        label = _label(row)
        if sources:
            plans.extend(MergePlan(key, target, label, target_row, twin is not None) for key in sources)
        state = cloud_import(target.instance_id, share_id) or {}
        unfinished = state.get("state") == "importing" or bool(state.get("upload_pending"))
        if (not keys and not sources) or unfinished:
            plans.append(MergePlan(
                MemoryKey(SHARED_MEMORY_PROVIDER, share_id), target, label, target_row,
                twin is not None, cloud_only=True,
            ))
    return plans


# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------

#: What a single copy's merge can raise: unreadable, malformed or unsafe local
#: data (a wrong-typed value surfaces as ``AttributeError`` / ``TypeError``).
#: A plan that raises one is left as it was; the pass goes on.
_PLAN_ERRORS = (OSError, ValueError, KeyError, AttributeError, TypeError)

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


def _record_identities(memory_service: Any, rows: Sequence[Mapping[str, Any]]) -> None:
    """Note which server each shared-only row is (see :func:`same_share`).

    Recorded for a later release to use; nothing here merges by it.
    """
    store = memory_service._store
    for row in rows:
        if is_shared_row(row) and row.get("id") and own_twin(row, rows) is None:
            store.set_share_identity(str(row["id"]), share_identity(row))


def _queue_upload(sync_service: Any, memory_service: Any, plan: MergePlan) -> bool:
    """Queue the own row's annotations and findings; True when all of it is stored.

    Read strictly: a file that cannot be read is a retryable failure, never
    "nothing to upload". An absent or empty note is nothing to upload. A
    duplicate upload is harmless, so this runs again on every retry.
    """
    target, store = plan.target, memory_service._store
    try:
        text = store.read_annotations_strict(target.instance_id, target.provider)
        records = store.list_findings(
            target.instance_id, target.provider, include_superseded=True, strict=True
        )
    except _PLAN_ERRORS as exc:
        logger.warning("Upload for %s deferred: %s", target.instance_id, type(exc).__name__)
        return False
    instance = {"id": target.instance_id, "name": str(plan.target_row.get("name") or "")}
    stored = True
    if text.strip():
        stored = bool(sync_service.enqueue_annotations(instance, text)) and stored
    if records:
        stored = bool(sync_service.enqueue_findings(instance, records)) and stored
    return stored


def pending_parts(marker: Mapping[str, Any]) -> Tuple[bool, bool]:
    """Which parts of the service's data a marker still owes: ``(notes, findings)``.

    A marker from an earlier release has only the single ``remote_pending``
    flag, which owes both.
    """
    if "remote_notes_pending" in marker or "remote_findings_pending" in marker:
        return marker.get("remote_notes_pending") is True, marker.get("remote_findings_pending") is True
    legacy = marker.get("remote_pending") is True
    return legacy, legacy


@dataclass
class _Pass:
    """What one pass shares between its plans."""

    merger: TeamCopyMerger
    memory_service: Any
    sync_service: Any
    state: str
    merged_on: str
    report: TeamMergeReport
    absent: Set[str]
    remote: Dict[str, Tuple[Any, Any]] = field(default_factory=dict)
    target_mismatch_logged: bool = False

    async def read_remote(self, share_id: str, name: str) -> Tuple[Any, Any]:
        """The service's notes and findings for a share id (read once per pass)."""
        if share_id not in self.remote:
            self.remote[share_id] = (
                await self.sync_service.fetch_remote_notes(share_id, name),
                await self.sync_service.fetch_remote_findings(share_id, name),
            )
        return self.remote[share_id]


async def _retry_uploads(plan: MergePlan, run: _Pass, marker: Dict[str, Any]) -> None:
    """Finish the uploads a marked copy still owes; clear the flag when stored."""
    same_target = (
        marker.get("target_provider") == plan.target.provider
        and marker.get("target_id") == plan.target.instance_id
    )
    if run.state != SYNC_READY or not plan.uploads or not same_target:
        return
    if not _queue_upload(run.sync_service, run.memory_service, plan):
        return
    run.sync_service.drop_pending_for({plan.source.instance_id})
    run.merger.mark_merged(plan.source, plan.target, upload_pending=False)


def _marker(plan: MergePlan, run: _Pass) -> Optional[Dict[str, Any]]:
    """The marker in the plan's source folder, if it has one."""
    merger = run.merger
    try:
        if not merger.has_copy(plan.source):
            return None
    except ValueError:
        return None
    return merger.marker(plan.source)


async def _fold(plan: MergePlan, run: _Pass) -> None:
    """Merge one copy into its target; mark it merged only when everything is stored."""
    source_id, report, merger = plan.source.instance_id, run.report, run.merger
    name = str(plan.target_row.get("name") or "")
    store = run.memory_service._store
    if run.memory_service.is_memory_disabled(plan.target.instance_id, name):
        report.kept.append(source_id)
        return
    if not store.is_addressable(plan.target.instance_id, plan.target.provider):
        logger.warning("Team copy %s kept: its target folder is not addressable", source_id)
        report.kept.append(source_id)
        return
    if plan.cloud_only:
        await _fold_cloud_only(plan, run, name)
        return
    marker = _marker(plan, run)
    if marker is not None:
        await _continue_marked(plan, run, marker)
        return
    remote_notes, remote_records = "", []
    notes_pending = findings_pending = run.state != SYNC_OFF
    if run.state == SYNC_READY:
        notes, findings = await run.read_remote(source_id, name)
        if notes.status == "found":
            remote_notes = notes.text
        if findings.status == "found":
            remote_records = findings.records
        notes_pending = notes.status == "unavailable"
        findings_pending = findings.status == "unavailable"
    stats = merger.merge(
        plan.source, plan.target, source_label=plan.label, merged_on=run.merged_on,
        target_name=name, remote_notes=remote_notes, remote_records=remote_records,
    )
    report.notes += stats.notes
    report.findings += stats.findings
    report.modules += stats.modules
    if not stats.verified:
        logger.warning("Team copy %s not marked: not everything it held can be confirmed in the target", source_id)
        report.kept.append(source_id)
        return
    # The local part is stored: mark it now, whatever the service part, so a
    # note the user deletes later is never merged back. The service part is
    # owed (``remote_pending``) until a pass can read and settle it.
    owes = plan.uploads and run.state != SYNC_OFF and (stats.held_notes or stats.held_findings)
    data = merger.mark_merged(
        plan.source, plan.target, upload_pending=owes,
        notes_pending=notes_pending, findings_pending=findings_pending,
    )
    report.copies += 1
    if not (notes_pending or findings_pending):
        await _settle_uploads(plan, run, data)
    if source_id != plan.target.instance_id:
        store.remove_index_entry(source_id)


async def _settle_uploads(plan: MergePlan, run: _Pass, marker: Dict[str, Any]) -> None:
    """Drop the copy's queued uploads, or finish the ones the target owes."""
    if marker.get("upload_pending"):
        await _retry_uploads(plan, run, marker)
    elif run.sync_service is not None and plan.uploads:
        run.sync_service.drop_pending_for({plan.source.instance_id})


async def _continue_marked(plan: MergePlan, run: _Pass, marker: Dict[str, Any]) -> None:
    """A marked copy is never merged locally again; only the service part and uploads continue.

    Merged once means a note the user deleted since does not come back. Both
    continue only into the target the marker names, and only while that is
    still the plan's target; otherwise the marker is left as it is (the data
    stays in the copy and on the service) and the copy is counted as kept.
    """
    if (marker.get("target_provider"), marker.get("target_id")) != (
        plan.target.provider, plan.target.instance_id,
    ):
        if any(pending_parts(marker)) or marker.get("upload_pending"):
            _note_other_target(plan, run)
        return
    if any(pending_parts(marker)):
        marker = await _complete_remote(plan, run, marker)
    if any(pending_parts(marker)):
        return
    if marker.get("upload_pending"):
        await _retry_uploads(plan, run, marker)


def _note_other_target(plan: MergePlan, run: _Pass) -> None:
    run.report.kept.append(plan.source.instance_id)
    if not run.target_mismatch_logged:
        run.target_mismatch_logged = True
        logger.info("A merged team copy's target is no longer its server's own record; left as it is")


def _beyond_copy(plan: MergePlan, run: _Pass, notes: Any, findings: Any) -> Tuple[str, List[Dict[str, Any]]]:
    """What the service holds beyond the copy's own data (the copy is never modified)."""
    store, source = run.memory_service._store, plan.source
    text = ""
    if notes is not None and notes.status == "found":
        text = text_beyond(notes.text, store.read_annotations_strict(source.instance_id, source.provider))
    records: List[Dict[str, Any]] = []
    if findings is not None and findings.status == "found":
        records = [
            r for r in findings.records
            if not finding_contained(r, store.get_finding(source.instance_id, r["id"], source.provider))
        ]
    return text, records


async def _complete_remote(plan: MergePlan, run: _Pass, marker: Dict[str, Any]) -> Dict[str, Any]:
    """Merge what the service holds beyond the copy into the target; clear what is stored.

    Needs a usable Memory Sync. The service's copy of a share is usually what
    this computer uploaded from the same local copy, so only text and records
    the copy's own folder lacks are merged (a note the user deleted since is
    not brought back). Notes and findings settle separately: a part that was
    read is cleared from the marker while an unavailable one stays owed.
    Returns the marker as it stands afterwards.
    """
    if run.state != SYNC_READY:
        return marker
    source_id, report, target = plan.source.instance_id, run.report, plan.target
    name = str(plan.target_row.get("name") or "")
    if run.memory_service.is_memory_disabled(target.instance_id, name):
        return marker
    notes_owed, findings_owed = pending_parts(marker)
    notes, findings = await run.read_remote(source_id, name)
    notes_owed_now = notes_owed and notes.status != "unavailable"
    findings_owed_now = findings_owed and findings.status != "unavailable"
    if (notes_owed and not notes_owed_now) or (findings_owed and not findings_owed_now):
        report.kept.append(source_id)
    if not (notes_owed_now or findings_owed_now):
        return marker
    text, records = _beyond_copy(
        plan, run, notes if notes_owed_now else None, findings if findings_owed_now else None
    )
    stats = run.merger.merge(
        target, target, source_label=plan.label, merged_on=run.merged_on, target_name=name,
        remote_notes=text, remote_records=records,
    )
    report.notes += stats.notes
    report.findings += stats.findings
    if not stats.verified:
        report.kept.append(source_id)
        return marker
    owes = bool(marker.get("upload_pending")) or (
        plan.uploads and (stats.held_notes or stats.held_findings)
    )
    data = run.merger.mark_merged(
        plan.source, target, upload_pending=owes,
        notes_pending=notes_owed and not notes_owed_now,
        findings_pending=findings_owed and not findings_owed_now,
    )
    if stats.changed:
        report.copies += 1
    if not owes and not any(pending_parts(data)) and run.sync_service is not None and plan.uploads:
        run.sync_service.drop_pending_for({source_id})
    return data


async def _fold_cloud_only(plan: MergePlan, run: _Pass, name: str) -> None:
    """Merge what the service holds for a share that has no folder here.

    Needs a usable Memory Sync. The import is recorded on the target's index
    entry before anything is written (``importing``; an interrupted import is
    repeated, which the whole-line rules make idempotent) and flips to
    ``imported`` once the target is verified. From then on the service's
    payload is never imported again: a refused upload is retried from the
    CURRENT target, through the strict readers. A verified absence is only
    remembered for this run.
    """
    share_id, store, report = plan.source.instance_id, run.memory_service._store, run.report
    target_id = plan.target.instance_id
    if run.state != SYNC_READY:
        return
    state = store.get_cloud_import(target_id, share_id) or {}
    if state.get("state") == "imported":
        if state.get("upload_pending") and plan.uploads and _queue_upload(
            run.sync_service, run.memory_service, plan
        ):
            store.set_cloud_import(target_id, share_id, "imported", False)
        return
    if share_id in run.absent and state.get("state") != "importing":
        return
    notes, findings = await run.read_remote(share_id, name)
    if notes.status == "unavailable" or findings.status == "unavailable":
        return
    if notes.status == "absent" and findings.status == "absent":
        run.absent.add(share_id)
        return
    store.set_cloud_import(target_id, share_id, "importing", plan.uploads)
    stats = run.merger.merge(
        plan.source, plan.target, source_label=plan.label, merged_on=run.merged_on,
        target_name=name, remote_notes=notes.text, remote_records=findings.records,
    )
    report.notes += stats.notes
    report.findings += stats.findings
    if not stats.verified:
        report.kept.append(share_id)
        return
    store.set_cloud_import(target_id, share_id, "imported", plan.uploads)
    report.copies += 1
    if plan.uploads and _queue_upload(run.sync_service, run.memory_service, plan):
        store.set_cloud_import(target_id, share_id, "imported", False)


async def merge_team_copies(
    memory_service: Any,
    sync_service: Any,
    rows: Sequence[Mapping[str, Any]],
    *,
    today: Optional[str] = None,
    absent_ids: Optional[Set[str]] = None,
) -> TeamMergeReport:
    """Fold every team copy of a server's memory into the user's own record.

    *rows* are the real records (never demo-redacted). Nothing is moved or
    deleted. With Memory Sync usable, each unmarked copy reads what the service
    holds for its share id (one pair of reads per id). A marker is written into
    the copy's folder once the copy's own data is verified in the target; it
    carries ``remote_pending`` when the service part was not read and settled
    (Memory Sync locked, or a read unavailable), and a later pass with Memory
    Sync usable completes it. A marked copy is never merged locally again. A
    share with no folder here is merged from the service alone and recorded on
    the target's index entry. *absent_ids* (kept by the caller for the run)
    remembers shares the service verifiably holds nothing for. A pass that
    finds another pass running on this computer returns a report with
    ``skipped`` set. One copy that fails never stops the others.
    """
    report = TeamMergeReport()
    lock = memory_service._store.merge_pass_lock()
    try:
        held = lock.try_acquire()
    except UnsafeLockError:
        held = False  # already warned about, once, by the lock
    except OSError as exc:
        logger.warning("Team copy merge skipped: its lock cannot be taken (%s)", type(exc).__name__)
        held = False
    if not held:
        logger.debug("Team copy merge skipped: another pass is running on this computer")
        report.skipped = True
        return report
    try:
        await _merge_pass(memory_service, sync_service, rows, report, today, absent_ids)
    finally:
        lock.release()
    return report


async def _merge_pass(
    memory_service: Any,
    sync_service: Any,
    rows: Sequence[Mapping[str, Any]],
    report: TeamMergeReport,
    today: Optional[str],
    absent_ids: Optional[Set[str]],
) -> None:
    """The plans of one pass, run while the machine-wide pass lock is held."""
    merger = TeamCopyMerger(memory_service)
    store = memory_service._store
    merged_on = today or datetime.now(tz=timezone.utc).date().isoformat()
    _record_identities(memory_service, rows)
    plans = plan_merges(rows, store.find_instance_dirs, store.get_cloud_import)
    plans = [p for p in plans if p.cloud_only or store.is_addressable(p.source.instance_id, p.source.provider)]
    run = _Pass(
        merger, memory_service, sync_service, sync_state(sync_service), merged_on, report,
        absent_ids if absent_ids is not None else set(),
    )
    for plan in plans:
        try:
            await _fold(plan, run)
        except _PLAN_ERRORS as exc:
            logger.warning("Team copy %s kept: %s", plan.source.instance_id, type(exc).__name__)
            report.kept.append(plan.source.instance_id)
