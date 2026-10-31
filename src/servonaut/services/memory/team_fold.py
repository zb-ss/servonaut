"""One memory record per server, whoever shares it.

A team's shared server that is also one of the user's own servers is the
same machine. The server list shows it once, as the user's own row
(:func:`~servonaut.services.shared_servers.fold_shared`); memory follows the
same rule everywhere it lists, probes or injects servers, so a fleet scan
probes the machine once and the chat sends one memory block for it.

Demo mode lists redacted rows, whose fake ids and addresses never match each
other. The twins are then found among the real records and the redacted rows
that stand for them are the ones left out.
"""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence, Set

from servonaut.services.shared_servers import (
    fold_shared_rows,
    is_shared_row,
    own_twin,
)


def absorbed_share_ids(rows: Sequence[Dict[str, Any]]) -> Set[str]:
    """Ids of the shared rows in *rows* that are one of the user's own servers."""
    kept = {id(row) for row in fold_shared_rows(rows)}
    return {
        str(row.get("id") or "")
        for row in rows
        if is_shared_row(row) and id(row) not in kept and row.get("id")
    }


def _real_id(app: Any, listed_id: str) -> str:
    """The real id behind a demo-redacted row id (the id itself otherwise)."""
    redaction = getattr(app, "redaction_service", None)
    resolve = getattr(redaction, "real_instance_id", None)
    if not callable(resolve):
        return listed_id
    try:
        real = resolve(listed_id)
    except Exception:  # noqa: BLE001 — a stand-in must never break a listing
        return listed_id
    return real if isinstance(real, str) and real else listed_id


def _real_rows(app: Any, listed: Sequence[Dict[str, Any]]) -> Optional[Sequence[Dict[str, Any]]]:
    """The real records behind *listed*: the rows themselves outside demo mode,
    the snapshot taken before redaction in demo mode, None when demo mode has
    no snapshot to read."""
    if not getattr(app, "demo_mode", False) or getattr(app, "redaction_service", None) is None:
        return listed
    pristine = getattr(app, "_instances_pristine", None)
    return pristine if isinstance(pristine, list) else None


def memory_fleet_rows(app: Any, rows: Optional[Sequence[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """*rows* (default: the app's listed servers) with the team twins of own servers left out.

    The rows returned are the listed ones, so demo mode keeps showing its
    redacted names. Without real records to fold against (demo mode with no
    snapshot) every row stays: showing a server twice is safer than hiding
    one.
    """
    listed = list(getattr(app, "instances", None) or [] if rows is None else rows)
    real = _real_rows(app, listed)
    if real is None:
        return listed
    if real is listed:
        return fold_shared_rows(listed)
    absorbed = absorbed_share_ids(list(real))
    return [
        row for row in listed
        if not (is_shared_row(row) and _real_id(app, str(row.get("id") or "")) in absorbed)
    ]


def folded_share_ids(app: Any) -> Set[str]:
    """Real ids of the app's shared rows that are one of the user's own servers.

    These ids are what a team copy's memory is filed under (see
    :mod:`~servonaut.services.memory.team_merge`). Empty when demo mode has
    no real records to fold against.
    """
    listed = list(getattr(app, "instances", None) or [])
    real = _real_rows(app, listed)
    return absorbed_share_ids(list(real)) if real is not None else set()


def own_row_for(app: Any, row: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    """The user's own row that the shared *row* is, as listed; None for any other row.

    Demo mode confirms the twin among the real records and returns the
    listed row standing for it.
    """
    if not is_shared_row(row):
        return None
    listed = list(getattr(app, "instances", None) or [])
    real = _real_rows(app, listed)
    if real is None:
        return None
    if real is listed:
        return own_twin(row, listed)
    pristine_row = next(
        (r for r in real if str(r.get("id") or "") == _real_id(app, str(row.get("id") or ""))),
        None,
    )
    twin = own_twin(pristine_row, real) if pristine_row is not None else None
    if twin is None:
        return None
    twin_id = str(twin.get("id") or "")
    return next((r for r in listed if _real_id(app, str(r.get("id") or "")) == twin_id), None)
