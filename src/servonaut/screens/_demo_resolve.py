"""Demo-mode resolution helpers for screens and widgets.

Demo mode redacts the instance list in place, so a screen's row may carry a
fake id and fake connection fields. ``ServonautApp.connection_instance`` /
``real_instance_id`` map them back to the pristine record; these wrappers
call them tolerantly so a screen keeps working against any app stand-in
(tests, previews) that does not implement them.
"""
from __future__ import annotations

import copy
from typing import Any, Dict, Iterable, List, Optional, Tuple


def connection_instance(app: Any, instance: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The real record behind *instance*, or *instance* itself."""
    if not isinstance(instance, dict):
        return instance
    resolver = getattr(app, "connection_instance", None)
    if not callable(resolver):
        return instance
    try:
        resolved = resolver(instance)
    except Exception:  # noqa: BLE001 — a stand-in app must never break a screen
        return instance
    return resolved if isinstance(resolved, dict) else instance


def real_instance_id(app: Any, instance_id: Optional[str]) -> Optional[str]:
    """The real id behind a demo-mode fake, or *instance_id* itself."""
    if not instance_id:
        return instance_id
    resolver = getattr(app, "real_instance_id", None)
    if not callable(resolver):
        return instance_id
    try:
        resolved = resolver(instance_id)
    except Exception:  # noqa: BLE001
        return instance_id
    return resolved if isinstance(resolved, str) else instance_id


def display_rows(
    app: Any, rows: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """Rows as a provider-manager table shows them, plus shown-id → real-id.

    The provider screens keep the rows they fetched untouched and derive
    what they draw from them, so a demo-mode toggle only has to redraw.
    Outside demo mode the copies equal the rows and the id map is empty.
    Redacting copies also keeps the fakes out of the provider service's
    own cache, which hands out the same dicts.
    """
    copies = [dict(row) for row in rows]
    redaction = getattr(app, "redaction_service", None)
    if not getattr(app, "demo_mode", False) or redaction is None:
        return copies, {}
    raw_ids = [str(row.get("id") or "") for row in copies]
    _register_real_ids(redaction, raw_ids)
    redaction.redact_instances(copies)
    api_ids = {
        str(row.get("id") or ""): raw for row, raw in zip(copies, raw_ids)
    }
    return copies, api_ids


class DemoRowsMixin:
    """Provider-manager screens: redraw fetched rows when demo mode flips.

    The screen keeps what it fetched in ``_raw_instances``; the rows it
    draws (``_instances``) and the shown-id -> real-id map (``_api_ids``)
    are derived from them. The host screen provides ``_render_table()``.
    """

    def _apply_display_rows(self) -> None:
        """Derive the drawn rows, and their real API ids, from the fetched ones."""
        self._instances, self._api_ids = display_rows(self.app, self._raw_instances)

    def refresh_after_demo_toggle(self) -> None:
        """Redraw the fetched rows for the new demo-mode state."""
        with keep_cursor(self):
            self._apply_display_rows()
            self._render_table()


class keep_cursor:  # noqa: N801 — reads as a statement: ``with keep_cursor(screen):``
    """Put each table's cursor back on the same row after a redraw.

    A demo-mode redraw rebuilds the rows in the same order, so the row
    index identifies the same record before and after.
    """

    def __init__(self, screen: Any) -> None:
        self._screen = screen
        self._rows: Dict[Any, int] = {}

    def __enter__(self) -> "keep_cursor":
        from textual.widgets import DataTable

        try:
            tables = list(self._screen.query(DataTable))
        except Exception:  # noqa: BLE001 — not mounted: nothing to keep
            tables = []
        self._rows = {table: table.cursor_row for table in tables}
        return self

    def __exit__(self, *exc_info: Any) -> None:
        for table, row in self._rows.items():
            if 0 < row < table.row_count:
                table.move_cursor(row=row)


# Which slice of the fleet a row belongs to. AWS rows carry no flag.
_SOURCE_FLAGS = {"custom": "is_custom", "ovh": "is_ovh", "hetzner": "is_hetzner"}


def row_source(row: Dict[str, Any]) -> str:
    """``"custom"``, ``"ovh"``, ``"hetzner"`` or ``"aws"``."""
    for source, flag in _SOURCE_FLAGS.items():
        if row.get(flag):
            return source
    return "aws"


def replace_instances(
    app: Any, source: Optional[str], rows: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Make *rows* (real, freshly fetched records) part of ``app.instances``.

    The single way to change the fleet, in or out of demo mode:

    * *source* names the slice the rows replace (``"aws"``, ``"custom"``,
      ``"ovh"``, ``"hetzner"``); ``None`` replaces the whole fleet;
    * the pre-redaction copy (``app._instances_pristine``) gets the real
      rows, so demo mode can always map a row back to its real record;
    * ``app.instances`` gets them as displayed — redacted in demo mode;
    * a row already listed for the same server keeps its dict, refilled in
      place, so a screen holding that dict follows the refresh.

    Returns the new ``app.instances``. The caller's dicts are never modified.
    """
    fresh = [copy.deepcopy(row) for row in rows]

    def kept(row: Dict[str, Any]) -> bool:
        return source is not None and row_source(row) != source

    pristine = getattr(app, "_instances_pristine", None)
    pristine = pristine if isinstance(pristine, list) else []
    app._instances_pristine = [row for row in pristine if kept(row)] + [
        copy.deepcopy(row) for row in fresh
    ]

    current = getattr(app, "instances", None)
    current = current if isinstance(current, list) else []
    redaction = getattr(app, "redaction_service", None)
    demo = bool(getattr(app, "demo_mode", False)) and redaction is not None
    listed: Dict[str, Dict[str, Any]] = {}
    for row in current:
        if not kept(row):
            listed.setdefault(_real_id(redaction if demo else None, row), row)
    displaced: Dict[str, str] = {}
    if demo:
        # Before anything is redacted: a new real id must never be taken for,
        # or handed out as, a stand-in.
        displaced = _register_real_ids(redaction, (row.get("id") for row in fresh))

    shown_rows: List[Dict[str, Any]] = []
    for real in fresh:
        shown = copy.deepcopy(real)
        if demo:
            redaction.redact_instance(shown)
        holder = listed.pop(str(real.get("id") or ""), None)
        if holder is not None:
            holder.clear()
            holder.update(shown)
            shown = holder
        shown_rows.append(shown)

    staying = [row for row in current if kept(row)]
    if displaced:
        _redraw_displaced(app, redaction, staying, displaced)
    app.instances = staying + shown_rows
    return app.instances


def _register_real_ids(redaction: Any, ids: Iterable[Any]) -> Dict[str, str]:
    """Tell the redactor these ids are real; ``{old stand-in: server}`` back."""
    register = getattr(redaction, "register_real_ids", None)
    if not callable(register):
        return {}
    displaced = register([str(value or "") for value in ids])
    return displaced if isinstance(displaced, dict) else {}


def _redraw_displaced(
    app: Any, redaction: Any, rows: List[Dict[str, Any]], displaced: Dict[str, str],
) -> None:
    """Refill the rows whose stand-in id now belongs to a real server's id."""
    pristine = {
        str(row.get("id") or ""): row
        for row in getattr(app, "_instances_pristine", None) or []
    }
    for row in rows:
        real = pristine.get(displaced.get(str(row.get("id") or ""), ""))
        if real is None:
            continue
        shown = copy.deepcopy(real)
        redaction.redact_instance(shown)
        row.clear()
        row.update(shown)


def _real_id(redaction: Any, row: Dict[str, Any]) -> str:
    shown = str(row.get("id") or "")
    if redaction is None:
        return shown
    real = redaction.real_instance_id(shown)
    return real if isinstance(real, str) else shown
