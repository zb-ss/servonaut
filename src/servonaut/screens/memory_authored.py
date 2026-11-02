"""Notes and agent findings on the Memory screen, and the finding detail view.

Both are authored text (an operator's notes, an agent's or operator's
findings), possibly by someone else in a shared workspace. Everything here
renders it literally (``rich.text.Text``, never markup) and passes it
through the caller's demo-mode scrub first.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Static

from servonaut.services.memory.notes import notes_for_display
from servonaut.services.memory.trust_notices import FINDINGS_READER_NOTICE
from servonaut.styles import CSS_FILES as _APP_CSS_FILES
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar

Scrub = Callable[[str], str]

#: Memory modules that hold authored text rather than probe results. The
#: Memory screen shows them in their own panels, not in the module table.
AUTHORED_MODULES = frozenset({"annotations", "findings"})


def _keep(text: str) -> str:
    return text


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


def shared_notes_text(module: Optional[Dict[str, Any]]) -> str:
    """The notes text of a shared ``annotations`` module (``""`` if none)."""
    if not isinstance(module, dict):
        return ""
    content = module.get("content")
    if not isinstance(content, str):
        content = (module.get("observed") or {}).get("note")
    return content if isinstance(content, str) else ""


def notes_renderable(
    own: str,
    shared: str = "",
    shared_by: str = "",
    *,
    preview_lines: int,
    can_edit: bool,
    scrub: Scrub = _keep,
) -> Text:
    """The Notes panel: the user's notes, then a team's, or how to add some.

    Each part shows at most *preview_lines* lines, then how many more there
    are. A bare template counts as no notes.
    """
    own_text = notes_for_display(own)
    shared_text = notes_for_display(shared)
    out = Text()
    if own_text:
        out.append_text(_preview(scrub(own_text), preview_lines, can_edit))
    if shared_text:
        if out.plain:
            out.append("\n\n")
        out.append(f"Shared by {scrub(shared_by)} (read-only)\n", style="dim italic")
        out.append_text(_preview(scrub(shared_text), preview_lines, False))
    if not out.plain:
        message = "No notes yet. Press a to add some." if can_edit else "No notes shared."
        out.append(message, style="dim")
    return out


def _preview(text: str, preview_lines: int, can_edit: bool) -> Text:
    lines = text.splitlines()
    limit = max(1, preview_lines)
    shown = Text("\n".join(lines[:limit]))
    hidden = len(lines) - limit
    if hidden > 0:
        more = f"\n… {hidden} more line{'s' if hidden != 1 else ''}"
        more += ". Press a to read them all." if can_edit else "."
        shown.append(more, style="dim")
    return shown


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FindingRow:
    """One finding as the findings table shows it."""

    key: str
    cells: Tuple[Text, Text, Text, Text]
    record: Dict[str, Any]


def shared_findings(module: Optional[Dict[str, Any]], team: str) -> List[Dict[str, Any]]:
    """The finding records of a shared ``findings`` module, marked with *team*."""
    if not isinstance(module, dict):
        return []
    found = []
    for index, record in enumerate(module.get("findings") or [], 1):
        if isinstance(record, dict):
            item = dict(record)
        elif record:
            item = {"title": str(record)}
        else:
            continue
        item.setdefault("id", f"shared-{index}")
        item["_shared_by"] = team
        found.append(item)
    return found


def _date(value: Any) -> str:
    return str(value or "")[:16].replace("T", " ")


def _confidence(record: Dict[str, Any]) -> Optional[float]:
    try:
        return float(record.get("confidence"))
    except (TypeError, ValueError):
        return None


def confidence_label(record: Dict[str, Any], threshold: float) -> str:
    """The confidence, and "recall only" below the auto-inject threshold."""
    value = _confidence(record)
    if value is None:
        return "—"
    label = f"{value:.2f}"
    return f"{label} · recall only" if value < threshold else label


def source_label(record: Dict[str, Any], scrub: Scrub = _keep) -> str:
    source = str(record.get("source") or "unknown")
    team = record.get("_shared_by")
    return f"{source} · shared by {scrub(str(team))}" if team else source


def finding_rows(
    records: Sequence[Dict[str, Any]],
    *,
    threshold: float,
    show_superseded: bool,
    scrub: Scrub = _keep,
) -> List[FindingRow]:
    """The table rows, newest first; superseded ones only when asked for."""
    ordered = sorted(records, key=lambda r: str(r.get("created_at") or ""), reverse=True)
    rows = []
    for index, record in enumerate(ordered):
        superseded = bool(record.get("superseded_by"))
        if superseded and not show_superseded:
            continue
        style = "dim" if superseded else ""
        title = scrub(str(record.get("title") or "(untitled)"))
        if superseded:
            title = f"(superseded) {title}"
        team = record.get("_shared_by") or ""
        key = f"{team}::{record.get('id') or index}"
        rows.append(FindingRow(
            key=key,
            cells=(
                Text(title, style=style),
                Text(source_label(record, scrub), style=style),
                Text(confidence_label(record, threshold), style=style),
                Text(_date(record.get("created_at")), style=style),
            ),
            record=record,
        ))
    return rows


def findings_heading(active: int, superseded: int, show_superseded: bool) -> Text:
    """'Agent findings (N)', and how to show or hide the superseded ones."""
    heading = Text("Agent findings", style="bold")
    heading.append(f" ({active})")
    if superseded:
        verb = "hide" if show_superseded else "show"
        heading.append(
            f"  · {superseded} superseded — press f to {verb}", style="dim",
        )
    return heading


def supersede_chain(
    record: Dict[str, Any], records: Sequence[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """The findings *record* replaced (newest first) and the one that replaced it."""
    by_id = {r.get("id"): r for r in records if r.get("id")}
    older: List[Dict[str, Any]] = []
    seen = {record.get("id")}
    current = record
    while True:
        previous = next(
            (r for r in records
             if r.get("superseded_by") == current.get("id") and r.get("id") not in seen),
            None,
        )
        if previous is None:
            break
        older.append(previous)
        seen.add(previous.get("id"))
        current = previous
    newer = by_id.get(record.get("superseded_by")) if record.get("superseded_by") else None
    return older, newer


# ---------------------------------------------------------------------------
# Detail view
# ---------------------------------------------------------------------------


class MemoryFindingScreen(Screen):
    """One agent finding in full: body, tags and what it replaced (read-only)."""

    CSS_PATH = [*_APP_CSS_FILES]

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    def __init__(
        self,
        record: Dict[str, Any],
        records: Sequence[Dict[str, Any]],
        *,
        server_name: str,
        threshold: float,
        scrub: Scrub = _keep,
    ) -> None:
        super().__init__()
        self._record = record
        self._records = list(records)
        self._server_name = server_name
        self._threshold = threshold
        self._scrub = scrub

    def compose(self) -> ComposeResult:
        record, scrub = self._record, self._scrub
        title = scrub(str(record.get("title") or "(untitled)"))
        yield SafeHeader()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            with Container(id="memory-finding-container"):
                yield Static(
                    Text.assemble(("Agent finding: ", "bold"), (scrub(self._server_name), "bold")),
                    id="memory-finding-server",
                )
                yield Static(FINDINGS_READER_NOTICE, id="memory-finding-notice")
                with VerticalScroll(id="memory-finding-scroll"):
                    yield Static(Text(title, style="bold"), id="memory-finding-title")
                    yield Static(self._meta(), id="memory-finding-meta")
                    yield Static(Text(scrub(str(record.get("body") or ""))), id="memory-finding-body")
                    yield Static(self._chain(), id="memory-finding-chain")
                with Horizontal(id="memory-finding-actions"):
                    yield Button("Back", id="btn_memory_finding_back")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#memory-finding-scroll").focus()

    def _meta(self) -> Text:
        record, scrub = self._record, self._scrub
        value = _confidence(record)
        if value is None:
            context = "—"
        elif value >= self._threshold:
            context = f"{value:.2f} (added to AI context)"
        else:
            context = f"{value:.2f} (recall only: below {self._threshold:.2f})"
        lines = [
            ("Source", source_label(record, scrub)),
            ("Confidence", context),
            ("Created", _date(record.get("created_at")) or "—"),
            ("Updated", _date(record.get("updated_at")) or "—"),
            ("Tags", ", ".join(scrub(str(t)) for t in record.get("tags") or []) or "—"),
        ]
        out = Text()
        for index, (label, text) in enumerate(lines):
            if index:
                out.append("\n")
            out.append(f"{label}: ", style="bold")
            out.append(text)
        return out

    def _chain(self) -> Text:
        older, newer = supersede_chain(self._record, self._records)
        out = Text()
        if newer is not None:
            out.append("Superseded by: ", style="bold")
            out.append(self._line(newer))
        if older:
            if out.plain:
                out.append("\n")
            out.append("Replaces:", style="bold")
            for record in older:
                out.append("\n  ")
                out.append(self._line(record))
        return out

    def _line(self, record: Dict[str, Any]) -> str:
        title = self._scrub(str(record.get("title") or "(untitled)"))
        when = _date(record.get("created_at"))
        return f"{title} ({when})" if when else title

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_memory_finding_back":
            event.stop()
            self.action_back()

    def action_back(self) -> None:
        self.app.pop_screen()
