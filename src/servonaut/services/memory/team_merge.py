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
when it was removed and added again under a new id (see :func:`same_share`).
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from servonaut.services.memory.provider import (
    SHARED_MEMORY_PROVIDER,
    instance_provider,
    provider_slug,
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
        return (
            f"Merged {self.copies} team copies into your servers: "
            f"{self.notes} notes, {self.findings} findings."
        )


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
    if not wanted or wanted in own:
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


def copy_keys(row: Mapping[str, Any]) -> List[MemoryKey]:
    """Where a shared row's memory may be filed: under its team's label, as
    earlier releases did, and under the neutral slug."""
    share_id = str(row.get("id") or "")
    slugs = [provider_slug(str(row.get("provider") or "")), SHARED_MEMORY_PROVIDER]
    return [MemoryKey(slug, share_id) for slug in dict.fromkeys(slugs) if slug]


# ---------------------------------------------------------------------------
# One merge
# ---------------------------------------------------------------------------


class TeamCopyMerger:
    """Merges one memory record into another and checks the result.

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
    ) -> MergeStats:
        """Merge *source* into *target*; ``verified`` says nothing was lost."""
        stats = MergeStats()
        stats.modules = self._merge_modules(source, target)
        if stats.modules:
            self._list_target(target, target_name)
        stats.notes = self._merge_notes(source, target, source_label, merged_on)
        stats.findings = self._merge_findings(source, target)
        stats.verified = self.is_contained(source, target)
        return stats

    def is_contained(self, source: MemoryKey, target: MemoryKey) -> bool:
        """Whether everything *source* holds is in *target* (or superseded there by newer data)."""
        store = self._store
        for module, data in store.get_all_modules(source.instance_id, source.provider).items():
            kept = store.get_module(target.instance_id, module, target.provider)
            if kept is None or copy_module_wins(kept, data):
                return False
        wanted = store.read_annotations(source.instance_id, source.provider).strip()
        if wanted and wanted not in store.read_annotations(target.instance_id, target.provider):
            return False
        for record in store.list_findings(
            source.instance_id, source.provider, include_superseded=True
        ):
            if store.get_finding(target.instance_id, record["id"], target.provider) is None:
                return False
        return True

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

    def _merge_notes(
        self, source: MemoryKey, target: MemoryKey, label: str, merged_on: str
    ) -> int:
        store = self._store
        theirs = store.read_annotations(source.instance_id, source.provider)
        mine = store.read_annotations(target.instance_id, target.provider)
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

    def _merge_findings(self, source: MemoryKey, target: MemoryKey) -> int:
        records = self._store.list_findings(
            source.instance_id, source.provider, include_superseded=True
        )
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

    A shared row that :func:`own_twin` confirms as one of the user's own
    servers folds into that row. An index entry that recorded the identity of
    a share no row carries any more (the share was removed and added again
    under a new id) folds into the row that is now the same server, and into
    the user's own row when that is one. An entry matching several rows, or
    none, stays where it is; the count of ambiguous ones is returned.
    """
    plans: List[MergePlan] = []
    shared = [row for row in rows if is_shared_row(row) and row.get("id")]
    current = {str(row.get("id") or "") for row in rows}
    for row in shared:
        twin = own_twin(row, rows)
        if twin is None:
            continue
        for key in copy_keys(row):
            plans.append(MergePlan(key, own_key(twin), _label(row, False), twin, True))

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
        plans.append(
            MergePlan(source, own_key(target_row), _label(row, True), target_row, twin is not None)
        )
    return plans, undecided


# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------


async def _pull_copy(sync_service: Any, source: MemoryKey, name: str) -> None:
    """Pull what the service holds for the copy, before it is merged.

    UNVERIFIED: nothing in this client shows that the service keeps
    annotations or findings under a share id. The pulls are best effort; a
    refusal or an empty answer changes nothing.
    """
    if sync_service is None or not getattr(sync_service, "is_configured", False):
        return
    for pull in (sync_service.pull_annotations, sync_service.pull_findings):
        try:
            await pull(source.instance_id, name, source.provider)
        except Exception as exc:  # noqa: BLE001 — best effort, the local copy is merged anyway
            logger.warning("Team copy pull skipped for %s: %s", source.instance_id, exc)


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


async def merge_team_copies(
    memory_service: Any,
    sync_service: Any,
    rows: Sequence[Mapping[str, Any]],
    *,
    today: Optional[str] = None,
) -> TeamMergeReport:
    """Fold every team copy of a server's memory into the user's own record.

    *rows* are the real records (never demo-redacted). A copy is moved to a
    backup only after everything it held was read back from the target;
    until then, and whenever the read-back fails, it stays where it is.
    """
    report = TeamMergeReport()
    merger = TeamCopyMerger(memory_service)
    merged_on = today or datetime.now(tz=timezone.utc).date().isoformat()
    _record_identities(memory_service, rows)
    plans, report.undecided = plan_merges(rows, memory_service.list_all())
    for plan in plans:
        if not merger.has_copy(plan.source) or plan.source == plan.target:
            continue
        name = str(plan.target_row.get("name") or "")
        if memory_service.is_memory_disabled(plan.target.instance_id, name):
            report.kept.append(plan.source.instance_id)
            continue
        await _pull_copy(sync_service, plan.source, name)
        stats = merger.merge(
            plan.source, plan.target, source_label=plan.label,
            merged_on=merged_on, target_name=name,
        )
        if not stats.verified:
            logger.warning("Team copy %s kept: its data is not all in the target", plan.source.instance_id)
            report.kept.append(plan.source.instance_id)
            continue
        merger.back_up(plan.source)
        if sync_service is not None:
            sync_service.drop_pending_for({plan.source.instance_id})
        _upload_merged(sync_service, memory_service, plan, stats)
        report.copies += 1
        report.notes += stats.notes
        report.findings += stats.findings
        report.modules += stats.modules
    return report
