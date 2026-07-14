"""DB-credential vault coverage — Layer B4 of the DB-credential vault.

Pure (IO-free) helpers that answer "which instances have a stored DB
credential, and which don't?" across a fleet of hundreds — plus the
search/filter primitives the scale-management UI drives. The screen worker
fetches the live secret NAMES (``provider.list_secrets`` — never values)
and the instance list, then calls these to classify coverage.

An instance is COVERED when it has a :class:`DBProfile` AND that profile's
``password_secret`` name actually exists in the active store. A profile
whose secret has been deleted out-of-band is a GAP ("secret missing"), not
a false positive — the distinction matters when auditing hundreds of boxes.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List


@dataclass
class DbCoverageRow:
    """One (instance, site) DB-vault coverage row.

    An instance that hosts several DBs yields one row per labelled profile;
    an instance with no profile yields a single ``label=""`` gap row.
    """

    instance_id: str
    instance_name: str
    has_profile: bool
    secret_name: str
    secret_present: bool
    label: str = ""

    @property
    def covered(self) -> bool:
        return self.has_profile and self.secret_present

    @property
    def status(self) -> str:
        if not self.has_profile:
            return "no profile"
        if not self.secret_present:
            return "secret missing"
        return "covered"


def compute_db_coverage(
    instances: Iterable[Dict[str, Any]],
    config: Any,
    secret_names: Iterable[str],
) -> List[DbCoverageRow]:
    """Classify each instance's DB-vault coverage, one row per site.

    ``config`` is an :class:`AppConfig` (we call ``db_profiles_for``);
    ``secret_names`` is the active provider's name list. An instance that
    hosts several labelled DBs yields one row per profile; an instance with
    no profile yields a single ``label=""`` "no profile" gap row.
    """
    names = set(secret_names or [])
    rows: List[DbCoverageRow] = []
    for inst in instances:
        iid = str(inst.get("id") or inst.get("name") or "")
        iname = str(inst.get("name") or iid or "?")
        profiles = config.db_profiles_for(
            inst.get("id", ""), inst.get("name", ""),
        )
        if not profiles:
            rows.append(DbCoverageRow(
                instance_id=iid,
                instance_name=iname,
                has_profile=False,
                secret_name="",
                secret_present=False,
                label="",
            ))
            continue
        for profile in profiles:
            secret_name = profile.password_secret or ""
            secret_present = bool(secret_name) and secret_name in names
            rows.append(DbCoverageRow(
                instance_id=iid,
                instance_name=iname,
                has_profile=True,
                secret_name=secret_name,
                secret_present=secret_present,
                label=profile.label or "",
            ))
    return rows


def coverage_summary(rows: Iterable[DbCoverageRow]) -> Dict[str, int]:
    """``{covered, gap, total}`` counts for the header line."""
    rows = list(rows)
    covered = sum(1 for r in rows if r.covered)
    return {"covered": covered, "gap": len(rows) - covered, "total": len(rows)}


def filter_coverage(
    rows: Iterable[DbCoverageRow], query: str,
) -> List[DbCoverageRow]:
    """Substring filter over server name / id / site label / secret name."""
    q = (query or "").strip().lower()
    rows = list(rows)
    if not q:
        return rows
    return [
        r for r in rows
        if q in r.instance_name.lower()
        or q in r.instance_id.lower()
        or q in (r.label or "").lower()
        or q in (r.secret_name or "").lower()
    ]


def filter_names(names: Iterable[str], query: str) -> List[str]:
    """Substring filter over secret names (case-insensitive)."""
    q = (query or "").strip().lower()
    names = list(names)
    if not q:
        return names
    return [n for n in names if q in n.lower()]
