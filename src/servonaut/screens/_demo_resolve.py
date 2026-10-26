"""Demo-mode resolution helpers for screens and widgets.

Demo mode redacts the instance list in place, so a screen's row may carry a
fake id and fake connection fields. ``ServonautApp.connection_instance`` /
``real_instance_id`` map them back to the pristine record; these wrappers
call them tolerantly so a screen keeps working against any app stand-in
(tests, previews) that does not implement them.
"""
from __future__ import annotations

import copy
import re
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


def team_rows(app: Any) -> List[Dict[str, Any]]:
    """The team shared servers of the fleet, as their real records.

    What a connection to one of the user's own servers may fall back to
    (see ``shared_servers.team_key_fallback``). Demo mode redacts
    ``app.instances``, so the pre-redaction copy is read then.
    """
    from servonaut.services.shared_servers import is_shared_row

    demo = bool(getattr(app, "demo_mode", False)) and getattr(app, "redaction_service", None) is not None
    rows = getattr(app, "_instances_pristine", None) if demo else getattr(app, "instances", None)
    return [dict(row) for row in rows or [] if isinstance(row, dict) and is_shared_row(row)]


UNRESOLVED_MESSAGE = (
    "The real server behind this row is not known in demo mode, so nothing "
    "was sent. Press ctrl+shift+d to turn demo mode off and try again."
)


def refuse_unresolved(app: Any, instance: Optional[Dict[str, Any]]) -> bool:
    """True, after telling the user, when demo mode cannot name the real server.

    Every action that reaches a provider, SSH or a store checks this first:
    a stand-in with no real record behind it must never be sent anywhere.
    """
    check = getattr(app, "has_real_record", None)
    if not callable(check) or not isinstance(instance, dict):
        return False
    try:
        known = check(instance)
    except Exception:  # noqa: BLE001 — a stand-in app must never break a screen
        return False
    if known is not False:
        return False
    app.notify(UNRESOLVED_MESSAGE, severity="error", markup=False)
    return True


def display_text(app: Any, text: str) -> str:
    """*text* as demo mode may show it (see ``ServonautApp.redact_display_text``)."""
    redact = getattr(app, "redact_display_text", None)
    if not callable(redact):
        return text
    try:
        shown = redact(text)
    except Exception:  # noqa: BLE001 — a stand-in app must never break a screen
        return text
    return shown if isinstance(shown, str) else text


def display_username(app: Any, username: Optional[str]) -> Optional[str]:
    """*username* as demo mode shows it: the stand-in the server details show.

    Screens that hold a real login (one resolved from the real record or a
    connection profile) show it through this, so a server never shows two
    different logins on one recording. Outside demo mode, the login itself.
    """
    if not username or not getattr(app, "demo_mode", False):
        return username
    redact = getattr(getattr(app, "redaction_service", None), "redact_username", None)
    if not callable(redact):
        return username
    try:
        shown = redact(username)
    except Exception:  # noqa: BLE001 — a stand-in app must never break a screen
        return username
    return shown if isinstance(shown, str) and shown else username


def hide_login(app: Any, text: str, login: Optional[str]) -> str:
    """*text* with ``login@`` (how ssh quotes a login) shown as its stand-in.

    Only the ``login@`` form is swapped: a login is often a plain word
    ("admin", "deploy") that also appears in ordinary sentences.
    """
    shown = display_username(app, login)
    if not text or not login or not shown or shown == login:
        return text
    return re.sub(
        rf"(?<![\w.-]){re.escape(login)}@", lambda _match: f"{shown}@", text,
    )


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
    displaced = _register_real_ids(redaction, raw_ids)
    if displaced:
        # A fleet row whose stand-in is now one of these real ids gets a new
        # one, in place, so a screen holding that row does not turn into
        # the other server.
        fleet = getattr(app, "instances", None)
        if isinstance(fleet, list):
            _redraw_displaced(app, redaction, fleet, displaced)
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
_SOURCE_FLAGS = {
    "shared": "is_shared", "custom": "is_custom", "ovh": "is_ovh", "hetzner": "is_hetzner",
}


def row_source(row: Dict[str, Any]) -> str:
    """``"shared"``, ``"custom"``, ``"ovh"``, ``"hetzner"`` or ``"aws"``."""
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
      ``"ovh"``, ``"hetzner"``, ``"shared"``); ``None`` replaces the whole
      fleet, except the team shared servers when *rows* has none of them:
      those are fetched on their own (``"shared"``), so refreshing the
      user's own servers never drops them;
    * the pre-redaction copy (``app._instances_pristine``) gets the real
      rows, so demo mode can always map a row back to its real record;
    * ``app.instances`` gets them as displayed — redacted in demo mode;
    * a row already listed for the same server keeps its dict, refilled in
      place, so a screen holding that dict follows the refresh;
    * the slice stays where it was in the list (a provider listed for the
      first time goes last).

    Returns the new ``app.instances``. The caller's dicts are never modified.
    """
    fresh = [copy.deepcopy(row) for row in rows]
    keep_shared = source is None and not any(row_source(row) == "shared" for row in fresh)

    def kept(row: Dict[str, Any]) -> bool:
        if source is None:
            return keep_shared and row_source(row) == "shared"
        return row_source(row) != source

    pristine = getattr(app, "_instances_pristine", None)
    pristine = pristine if isinstance(pristine, list) else []
    app._instances_pristine = [row for row in pristine if kept(row)] + [
        copy.deepcopy(row) for row in fresh
    ]
    try:
        app._fleet_generation = int(getattr(app, "_fleet_generation", 0) or 0) + 1
    except (TypeError, ValueError):
        app._fleet_generation = 1

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
    # The slice keeps its place: refreshing one provider, or deleting one of
    # its servers, must not move that provider's servers below the others.
    # A provider listed for the first time goes after the user's own servers
    # but before the teams' shared servers, which always come last.
    first = next((i for i, row in enumerate(current) if not kept(row)), None)
    if first is None:
        first = len(current)
        if source != "shared":
            first = next(
                (i for i, row in enumerate(current) if row_source(row) == "shared"), first,
            )
    before = sum(1 for row in current[:first] if kept(row))
    app.instances = staying[:before] + shown_rows + staying[before:]
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
