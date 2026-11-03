"""Notes and agent findings on the Memory screen, and the finding detail view.

Both are authored text (an operator's notes, an agent's or operator's
findings), possibly by someone else in a shared workspace. Everything here
renders it literally (``rich.text.Text``, never markup), passes it through
demo mode's redaction at display time, and takes no record's shape on trust.
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
from servonaut.utils.instance_resolver import display_name
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar

#: Memory modules that hold authored text rather than probe results. The
#: Memory screen shows them in their own panels, not in the module table.
AUTHORED_MODULES = frozenset({"annotations", "findings"})


def _keep(text: str) -> str:
    return text


@dataclass(frozen=True)
class Redact:
    """What demo mode hides: free text, and names (teams, servers)."""

    text: Callable[[str], str] = _keep
    name: Callable[[str], str] = _keep

    @classmethod
    def for_app(cls, app: Any) -> "Redact":
        """Demo mode's redaction when it is on, nothing otherwise."""
        redaction = getattr(app, "redaction_service", None)
        if getattr(app, "demo_mode", False) and redaction is not None:
            return cls(redaction.scrub_stream, redaction.redact_name)
        return cls()


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


def shared_notes_text(module: Optional[Dict[str, Any]]) -> str:
    """The notes text of a shared ``annotations`` module (``""`` if none)."""
    if not isinstance(module, dict):
        return ""
    content = module.get("content")
    if not isinstance(content, str):
        observed = module.get("observed")
        content = observed.get("note") if isinstance(observed, dict) else None
    return content if isinstance(content, str) else ""


def notes_renderable(
    own: str,
    shared: str = "",
    shared_by: str = "",
    *,
    preview_lines: int,
    can_edit: bool,
    redact: Redact = Redact(),
) -> Text:
    """The Notes panel: the user's notes, then a team's, or how to add some.

    Each part shows at most *preview_lines* lines, then how many more there
    are. A bare template counts as no notes.
    """
    own_text = notes_for_display(own)
    shared_text = notes_for_display(shared)
    out = Text()
    if own_text:
        out.append_text(_preview(redact.text(own_text), preview_lines, can_edit))
    if shared_text:
        if out.plain:
            out.append("\n\n")
        out.append(f"Shared by {redact.name(shared_by)} (read-only)\n", style="dim italic")
        out.append_text(_preview(redact.text(shared_text), preview_lines, False))
    if not out.plain:
        message = "No notes yet. Press a to add some." if can_edit else "No notes shared."
        out.append(message, style="dim")
    return out


def _preview(text: str, preview_lines: int, can_edit: bool) -> Text:
    lines = text.splitlines()
    limit = max(1, int(preview_lines))
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


def _text_or_none(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def display_record(record: Any, *, team: str = "") -> Optional[Dict[str, Any]]:
    """*record* in the shape the panels read, or ``None`` when it is not a finding.

    Findings a team shares are written by someone else and not validated on
    the way in, so every field is checked: wrong types become empty values
    instead of breaking the screen.
    """
    if isinstance(record, str) and record.strip():
        record = {"title": record}
    if not isinstance(record, dict):
        return None
    try:
        confidence: Optional[float] = float(record.get("confidence"))
    except (TypeError, ValueError):
        confidence = None
    tags = record.get("tags")
    return {
        "id": _text_or_none(record.get("id")) or "",
        "title": str(record.get("title") or "") or "(untitled)",
        "body": record.get("body") if isinstance(record.get("body"), str) else "",
        "source": _text_or_none(record.get("source")) or "unknown",
        "confidence": confidence,
        "tags": [t for t in tags if isinstance(t, str)] if isinstance(tags, list) else [],
        "created_at": _text_or_none(record.get("created_at")) or "",
        "updated_at": _text_or_none(record.get("updated_at")) or "",
        "superseded_by": _text_or_none(record.get("superseded_by")),
        "shared_by": team,
    }


def shared_findings(module: Optional[Dict[str, Any]], team: str) -> List[Dict[str, Any]]:
    """The findings of a shared ``findings`` module, as display records."""
    if not isinstance(module, dict) or not isinstance(module.get("findings"), list):
        return []
    found = (display_record(record, team=team) for record in module["findings"])
    return [record for record in found if record is not None]


@dataclass(frozen=True)
class FindingRow:
    """One finding as the findings table shows it."""

    cells: Tuple[Text, Text, Text, Text]
    record: Dict[str, Any]


def _date(value: Any) -> str:
    return str(value or "")[:16].replace("T", " ")


def confidence_label(record: Dict[str, Any], threshold: float) -> str:
    """The confidence, and "recall only" below the auto-inject threshold."""
    value = record.get("confidence")
    if value is None:
        return "—"
    return f"{value:.2f} · recall only" if value < threshold else f"{value:.2f}"


def source_label(record: Dict[str, Any], redact: Redact = Redact()) -> str:
    team = record.get("shared_by")
    source = record.get("source") or "unknown"
    return f"{source} · shared by {redact.name(team)}" if team else source


def finding_rows(
    records: Sequence[Dict[str, Any]],
    *,
    threshold: float,
    show_superseded: bool,
    redact: Redact = Redact(),
) -> List[FindingRow]:
    """The table rows, newest first; superseded ones only when asked for."""
    rows = []
    for record in sorted(records, key=lambda r: r["created_at"], reverse=True):
        superseded = bool(record["superseded_by"])
        if superseded and not show_superseded:
            continue
        style = "dim" if superseded else ""
        title = redact.text(record["title"])
        if superseded:
            title = f"(superseded) {title}"
        rows.append(FindingRow(
            cells=(
                Text(title, style=style),
                Text(source_label(record, redact), style=style),
                Text(confidence_label(record, threshold), style=style),
                Text(_date(record["created_at"]), style=style),
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
    older: List[Dict[str, Any]] = []
    seen = {record["id"]}
    current = record
    while current["id"]:
        previous = next(
            (r for r in records
             if r["superseded_by"] == current["id"] and r["id"] not in seen),
            None,
        )
        if previous is None:
            break
        older.append(previous)
        seen.add(previous["id"])
        current = previous
    newer = None
    if record["superseded_by"]:
        newer = next((r for r in records if r["id"] == record["superseded_by"]), None)
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
        instance: Dict[str, Any],
        threshold: float,
    ) -> None:
        super().__init__()
        self._record = record
        self._records = list(records)
        # The displayed row: the app redacts and restores it in place.
        self._instance = instance
        self._threshold = threshold

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            with Container(id="memory-finding-container"):
                yield Static("", id="memory-finding-server")
                yield Static(FINDINGS_READER_NOTICE, id="memory-finding-notice", markup=False)
                with VerticalScroll(id="memory-finding-scroll"):
                    yield Static("", id="memory-finding-title")
                    yield Static("", id="memory-finding-meta")
                    yield Static("", id="memory-finding-body")
                    yield Static("", id="memory-finding-chain")
                with Horizontal(id="memory-finding-actions"):
                    yield Button("Back", id="btn_memory_finding_back")
        yield Footer()

    def on_mount(self) -> None:
        self._show_redacted()
        self.query_one("#memory-finding-scroll").focus()

    def refresh_after_demo_toggle(self) -> None:
        """Draw the finding again for the new demo mode."""
        self._show_redacted()

    def _show_redacted(self) -> None:
        """Fill every field, through demo mode's redaction when it is on."""
        redact = Redact.for_app(self.app)
        record = self._record
        server = display_name(self._instance) or self._instance.get("id") or "server"
        self.query_one("#memory-finding-server", Static).update(
            Text.assemble(("Agent finding: ", "bold"), (str(server), "bold"))
        )
        self.query_one("#memory-finding-title", Static).update(
            Text(redact.text(record["title"]), style="bold")
        )
        self.query_one("#memory-finding-meta", Static).update(self._meta(redact))
        self.query_one("#memory-finding-body", Static).update(Text(redact.text(record["body"])))
        self.query_one("#memory-finding-chain", Static).update(self._chain(redact))

    def _meta(self, redact: Redact) -> Text:
        record = self._record
        value = record["confidence"]
        if value is None:
            context = "—"
        elif value >= self._threshold:
            context = f"{value:.2f} (added to AI context)"
        else:
            context = f"{value:.2f} (recall only: below {self._threshold:.2f})"
        lines = [
            ("Source", source_label(record, redact)),
            ("Confidence", context),
            ("Created", _date(record["created_at"]) or "—"),
            ("Updated", _date(record["updated_at"]) or "—"),
            ("Tags", ", ".join(redact.text(t) for t in record["tags"]) or "—"),
        ]
        out = Text()
        for index, (label, text) in enumerate(lines):
            if index:
                out.append("\n")
            out.append(f"{label}: ", style="bold")
            out.append(text)
        return out

    def _chain(self, redact: Redact) -> Text:
        older, newer = supersede_chain(self._record, self._records)
        out = Text()
        if newer is not None:
            out.append("Superseded by: ", style="bold")
            out.append(self._line(newer, redact))
        if older:
            if out.plain:
                out.append("\n")
            out.append("Replaces:", style="bold")
            for record in older:
                out.append("\n  ")
                out.append(self._line(record, redact))
        return out

    @staticmethod
    def _line(record: Dict[str, Any], redact: Redact) -> str:
        title = redact.text(record["title"])
        when = _date(record["created_at"])
        return f"{title} ({when})" if when else title

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_memory_finding_back":
            event.stop()
            self.action_back()

    def action_back(self) -> None:
        self.app.pop_screen()
