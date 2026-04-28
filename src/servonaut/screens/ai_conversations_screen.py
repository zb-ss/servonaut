"""Previous Chats — Servonaut hosted-AI conversation history screen.

Loads server-side conversation summaries via :class:`AIConversationsClient`
(Wave 1) and exposes the standard CRUD verbs (load, archive, delete, export).

Why a regular ``Screen`` and not a ``ModalScreen``: this is a content-heavy
panel with multiple action rows, a filter input, a paginated DataTable, and
multi-step flows (export prompts for a path, archive/delete confirms). The
``Sidebar`` widget MUST stay visible so users can navigate away mid-flow.
See the "ModalScreen vs Screen" rule in CLAUDE.md.

The screen is opened from :meth:`ChatPanel._toggle_history` *only* when the
user is signed in AND has the ``premium_ai`` entitlement; free / logged-out
users keep the local-session list. Wave 3 will fill in
``ChatPanel.load_remote_conversation`` (currently a stub) so selecting a
row here re-hydrates the active chat thread.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.markup import escape as _rich_escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Static

from servonaut.widgets.progress_indicator import ProgressIndicator
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


# Page size for the listing — matches the client default and stays well
# below the server-side max (100). Larger pages would defeat the purpose
# of the "load more" sentinel button.
_PAGE_LIMIT = 25


class _ExportPathModal(ModalScreen[Optional[str]]):
    """Single-field input prompting for the export Markdown filename.

    Returns the trimmed filename string on submit, or ``None`` on cancel.
    Path-traversal validation happens in
    :meth:`AIConversationsClient.export_md` — we only validate non-empty
    here so users can correct typos without a network round-trip.
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=True)]

    DEFAULT_CSS = """
    _ExportPathModal {
        align: center middle;
    }
    _ExportPathModal #export_modal {
        width: 70;
        height: auto;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }
    """

    def __init__(self, default_name: str) -> None:
        super().__init__()
        self._default = default_name

    def compose(self) -> ComposeResult:
        yield Container(
            Static("[bold cyan]Export Conversation to Markdown[/bold cyan]"),
            Static(
                "[dim]Path is resolved relative to the current directory. "
                "Must stay inside CWD or ~/Downloads.[/dim]"
            ),
            Input(value=self._default, id="export_path_input"),
            Horizontal(
                Button("Save", variant="primary", id="btn_export_save"),
                Button("Cancel", id="btn_export_cancel"),
            ),
            id="export_modal",
        )

    def on_mount(self) -> None:
        self.query_one("#export_path_input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "export_path_input":
            self._submit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_export_save":
            self._submit()
        else:
            self.dismiss(None)

    def _submit(self) -> None:
        value = self.query_one("#export_path_input", Input).value.strip()
        if not value:
            self.dismiss(None)
            return
        self.dismiss(value)

    def action_cancel(self) -> None:
        self.dismiss(None)


class _ConfirmModal(ModalScreen[bool]):
    """Lightweight yes/no confirmation for archive/delete.

    A separate (and smaller) modal than :class:`ConfirmActionScreen` because
    archiving is reversible and shouldn't require typing the title verbatim
    just to confirm — that level of friction is for genuinely destructive,
    irreversible ops.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
        Binding("y", "confirm", "Yes", show=False),
        Binding("n", "cancel", "No", show=False),
    ]

    DEFAULT_CSS = """
    _ConfirmModal { align: center middle; }
    _ConfirmModal #confirm_box {
        width: 60;
        height: auto;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }
    """

    def __init__(self, title: str, message: str, danger: bool = False) -> None:
        super().__init__()
        self._title = title
        self._message = message
        self._danger = danger

    def compose(self) -> ComposeResult:
        yield Container(
            Static(f"[bold cyan]{self._title}[/bold cyan]"),
            Static(self._message),
            Horizontal(
                Button(
                    "Confirm",
                    variant="error" if self._danger else "primary",
                    id="btn_yes",
                ),
                Button("Cancel", id="btn_no"),
            ),
            id="confirm_box",
        )

    def on_mount(self) -> None:
        self.query_one("#btn_no", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "btn_yes")

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


def _parse_iso(ts: str) -> Optional[datetime]:
    """Tolerant ISO-8601 parser — returns None on garbage rather than raising."""
    if not ts:
        return None
    try:
        # Trailing 'Z' is fromisoformat-friendly only on 3.11+; strip it.
        cleaned = ts.rstrip("Z")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


class AIConversationsScreen(Screen):
    """Server-backed list of the user's hosted-AI conversations.

    Loads ``ConversationSummary`` rows from
    :class:`AIConversationsClient`, groups them by recency, and offers
    archive / delete / export actions on the selected row.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("a", "archive", "Archive", show=True),
        Binding("d", "delete", "Delete", show=True),
        Binding("e", "export", "Export to MD", show=True),
        Binding("slash", "focus_filter", "Filter", show=True),
        Binding("enter", "open_selected", "Open", show=True),
    ]

    DEFAULT_CSS = """
    AIConversationsScreen #convs_status {
        margin: 0 1;
        color: $text-muted;
    }
    AIConversationsScreen #convs_filter {
        margin: 0 1 1 1;
    }
    AIConversationsScreen #convs_progress {
        margin: 1 1;
    }
    AIConversationsScreen .convs_group_header {
        text-style: bold;
        margin: 1 1 0 1;
    }
    AIConversationsScreen #convs_actions {
        height: auto;
        margin: 1 1 0 1;
    }
    AIConversationsScreen #convs_empty {
        margin: 2 1;
        color: $text-muted;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        # Full set of summaries currently loaded (across all pages).
        self._conversations: List[Any] = []
        # Cursor used for the *next* /api/ai/conversations call. We store the
        # oldest updated_at we've seen so far — the server returns rows
        # strictly older than this when paginating.
        self._before_cursor: Optional[str] = None
        self._loading: bool = False
        # Filter substring (case-insensitive). Empty = show everything.
        self._filter: str = ""
        # Sentinel: True once the server has indicated no more pages.
        self._exhausted: bool = False

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            with Vertical(id="convs_container"):
                yield Static(
                    "[bold cyan]Previous Chats[/bold cyan]",
                    id="convs_title",
                )
                yield Static(
                    "[dim]Your hosted-AI conversation history. "
                    "Use [bold]/[/bold] to filter, [bold]a[/bold] to archive, "
                    "[bold]d[/bold] to delete, [bold]e[/bold] to export.[/dim]",
                    id="convs_subtitle",
                )
                yield Input(
                    placeholder="Filter by title…",
                    id="convs_filter",
                )
                yield Static("", id="convs_status")
                yield ProgressIndicator()
                with VerticalScroll(id="convs_scroll"):
                    yield DataTable(
                        id="convs_table",
                        zebra_stripes=True,
                        cursor_type="row",
                    )
                    yield Static("", id="convs_empty")
                with Horizontal(id="convs_actions"):
                    yield Button(
                        "Open",
                        variant="primary",
                        id="btn_convs_open",
                    )
                    yield Button("Archive (a)", id="btn_convs_archive")
                    yield Button(
                        "Delete (d)",
                        variant="error",
                        id="btn_convs_delete",
                    )
                    yield Button("Export to MD (e)", id="btn_convs_export")
                    yield Button("Load More", id="btn_convs_more")
                    yield Button("Refresh (r)", id="btn_convs_refresh")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#convs_table", DataTable)
        table.add_columns("Title", "Last Activity", "Messages", "Model", "Status")
        # Hide the empty-state placeholder until we know the result count.
        self.query_one("#convs_empty", Static).update("")
        self.run_worker(self._load_page(), name="convs_load", exclusive=True)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _client(self):
        """Return the AIConversationsClient or None if unavailable."""
        return getattr(self.app, "ai_conversations_client", None)

    async def _load_page(
        self,
        *,
        before: Optional[str] = None,
        reset: bool = False,
    ) -> None:
        """Fetch one page of conversations.

        Args:
            before: ISO cursor — pass None to load the freshest page.
            reset: If True, clears the existing list before loading. Used by
                refresh and filter-induced reloads so stale rows don't linger.
        """
        if self._loading:
            return
        client = self._client()
        if client is None:
            self._set_status(
                "[red]AI conversations client is not available. "
                "Sign in to access hosted AI history.[/red]"
            )
            return

        self._loading = True
        progress = self.query_one(ProgressIndicator)
        progress.start("Loading conversations…")

        try:
            page = await client.list(limit=_PAGE_LIMIT, before=before, status="active")
        except Exception as exc:  # noqa: BLE001 — surface every backend error
            logger.exception("Failed to list AI conversations")
            # A5 — exc may carry a server-controlled APIError.message with
            # Rich markup. ``markup=False`` keeps it literal in the toast.
            # The status line below interpolates into Rich markup so it
            # uses ``_rich_escape`` instead.
            self.app.notify(
                f"Failed to load conversations: {self._short_err(exc)}",
                severity="error",
                markup=False,
            )
            self._set_status(
                f"[red]Failed to load conversations: "
                f"{_rich_escape(self._short_err(exc))}[/red]"
            )
            return
        finally:
            progress.stop()
            self._loading = False

        if reset or before is None:
            self._conversations = list(page)
        else:
            # Dedupe by id so a duplicate row never appears if the server
            # returns an overlap window between pages.
            seen = {c.id for c in self._conversations}
            self._conversations.extend(c for c in page if c.id not in seen)

        # Cursor is the oldest updated_at on this page.
        if page:
            oldest = min(
                (_parse_iso(c.updated_at) for c in page),
                key=lambda d: d or datetime.max.replace(tzinfo=timezone.utc),
                default=None,
            )
            if oldest is not None:
                self._before_cursor = oldest.isoformat()

        # Heuristic: if the server returned fewer than _PAGE_LIMIT, we're
        # at the tail. The client doesn't surface ``next_before``, so this
        # is the cheapest reliable signal.
        self._exhausted = len(page) < _PAGE_LIMIT

        self._render_table()
        self._update_status()

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render_table(self) -> None:
        table = self.query_one("#convs_table", DataTable)
        table.clear()

        items = self._filtered_items()
        if not items:
            self._show_empty()
            return

        # Hide the empty-state placeholder when we have rows.
        self.query_one("#convs_empty", Static).update("")

        groups = self._group_by_date(items)
        for group_name in ("Today", "Yesterday", "Earlier this week", "Older"):
            bucket = groups.get(group_name) or []
            if not bucket:
                continue
            # Group headers live in a sibling Static, not in the DataTable
            # (DataTable doesn't support section dividers natively). We tag
            # them with a hidden marker row to keep the visual order, but
            # render the actual labels above the screen container.
            for conv in bucket:
                table.add_row(
                    self._format_title_cell(conv, group_name),
                    self._format_age(conv.updated_at),
                    str(conv.message_count),
                    _rich_escape(conv.last_model or "—"),
                    self._format_status_cell(conv.status),
                    key=conv.id,
                )

    def _format_title_cell(self, conv: Any, group: str) -> str:
        """Compose the Title column with a leading group hint on first row.

        DataTable doesn't render group separators, so we surface the group
        as a dim prefix on the row's title. It's not perfect but it keeps
        the user oriented when paginating long lists.
        """
        title = _rich_escape(conv.title or "(untitled)")
        return f"[dim]{group}[/dim] · {title}" if group else title

    @staticmethod
    def _format_status_cell(status: str) -> str:
        if status == "active":
            return "[green]active[/green]"
        if status == "archived":
            return "[yellow]archived[/yellow]"
        if status == "deleted":
            return "[red]deleted[/red]"
        return _rich_escape(status or "—")

    @staticmethod
    def _format_age(ts: str) -> str:
        dt = _parse_iso(ts)
        if dt is None:
            return "—"
        now = datetime.now(tz=timezone.utc)
        delta = now - dt
        total = delta.total_seconds()
        if total < 60:
            return f"{int(total)}s ago"
        if total < 3600:
            return f"{int(total // 60)}m ago"
        if total < 86_400:
            return f"{int(total // 3600)}h ago"
        if total < 86_400 * 7:
            return f"{int(total // 86_400)}d ago"
        return dt.strftime("%Y-%m-%d")

    def _group_by_date(self, items: List[Any]) -> Dict[str, List[Any]]:
        """Bucket conversations by their ``updated_at`` recency."""
        groups: Dict[str, List[Any]] = {
            "Today": [],
            "Yesterday": [],
            "Earlier this week": [],
            "Older": [],
        }
        now = datetime.now(tz=timezone.utc)
        today = now.date()
        for conv in items:
            dt = _parse_iso(conv.updated_at)
            if dt is None:
                groups["Older"].append(conv)
                continue
            d = dt.date()
            if d == today:
                groups["Today"].append(conv)
            elif (today - d).days == 1:
                groups["Yesterday"].append(conv)
            elif (today - d).days <= 7:
                groups["Earlier this week"].append(conv)
            else:
                groups["Older"].append(conv)
        return groups

    def _filtered_items(self) -> List[Any]:
        if not self._filter:
            return list(self._conversations)
        needle = self._filter.lower()
        return [c for c in self._conversations if needle in (c.title or "").lower()]

    def _show_empty(self) -> None:
        empty = self.query_one("#convs_empty", Static)
        if not self._conversations:
            empty.update(
                "[dim italic]No previous chats yet — start one from the chat panel.[/dim italic]"
            )
        else:
            empty.update(
                "[dim italic]No conversations match your filter.[/dim italic]"
            )

    def _set_status(self, markup: str) -> None:
        try:
            self.query_one("#convs_status", Static).update(markup)
        except Exception:  # pragma: no cover — defensive
            pass

    def _update_status(self) -> None:
        n = len(self._conversations)
        shown = len(self._filtered_items())
        if n == 0:
            self._set_status("")
            return
        if shown == n:
            tail = "" if self._exhausted else " · more available — press [bold]Load More[/bold]"
            self._set_status(f"[dim]{n} conversation{'s' if n != 1 else ''}{tail}[/dim]")
        else:
            self._set_status(
                f"[dim]Showing {shown} of {n} (filtered)[/dim]"
            )

    @staticmethod
    def _short_err(exc: BaseException) -> str:
        """Trim exception strings so toasts stay one-line."""
        msg = str(exc) or exc.__class__.__name__
        return msg[:140] + ("…" if len(msg) > 140 else "")

    # ------------------------------------------------------------------
    # Selection helpers
    # ------------------------------------------------------------------

    def _selected_id(self) -> Optional[str]:
        try:
            table = self.query_one("#convs_table", DataTable)
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            if row_key is None:
                return None
            return str(row_key.value) if hasattr(row_key, "value") else str(row_key)
        except Exception:
            return None

    def _selected(self) -> Optional[Any]:
        sid = self._selected_id()
        if not sid:
            return None
        for c in self._conversations:
            if c.id == sid:
                return c
        return None

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        mapping = {
            "btn_convs_open": self.action_open_selected,
            "btn_convs_archive": self.action_archive,
            "btn_convs_delete": self.action_delete,
            "btn_convs_export": self.action_export,
            "btn_convs_more": self._load_more,
            "btn_convs_refresh": self.action_refresh,
        }
        handler = mapping.get(event.button.id or "")
        if handler is None:
            return
        result = handler()
        # async actions schedule themselves; nothing to await here.
        del result

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "convs_filter":
            self._filter = event.value or ""
            self._render_table()
            self._update_status()

    def action_focus_filter(self) -> None:
        try:
            self.query_one("#convs_filter", Input).focus()
        except Exception:
            pass

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self._before_cursor = None
        self._exhausted = False
        self.run_worker(self._load_page(reset=True), name="convs_load", exclusive=True)

    def _load_more(self) -> None:
        if self._exhausted:
            self.app.notify("No more conversations to load.", severity="information")
            return
        if self._before_cursor is None:
            return
        self.run_worker(
            self._load_page(before=self._before_cursor),
            name="convs_load",
            exclusive=True,
        )

    def action_open_selected(self) -> None:
        conv = self._selected()
        if conv is None:
            self.app.notify("Select a conversation first.", severity="warning")
            return
        # Wave 3 will wire the actual loading; for now we delegate to the
        # chat panel's stub so the user-visible behaviour is consistent
        # whether or not the panel is mounted.
        chat_panel = getattr(self.app, "chat_panel", None)
        if chat_panel is None:
            try:
                from servonaut.widgets.chat_panel import ChatPanel
                chat_panel = self.app.query_one(ChatPanel)
            except Exception:
                chat_panel = None
        if chat_panel is not None and hasattr(chat_panel, "load_remote_conversation"):
            chat_panel.load_remote_conversation(conv.id)
            self.app.notify(
                f"Opening conversation: {_rich_escape(conv.title or conv.id)}",
                severity="information",
            )
        else:
            self.app.notify(
                "Chat panel not mounted — open it with F2 first.",
                severity="warning",
            )

    def action_archive(self) -> None:
        conv = self._selected()
        if conv is None:
            self.app.notify("Select a conversation first.", severity="warning")
            return
        title = conv.title or conv.id
        self.app.push_screen(
            _ConfirmModal(
                title="Archive Conversation",
                message=(
                    f"Archive [bold]{_rich_escape(title)}[/bold]?\n"
                    "[dim]Archived conversations stay on the server but are "
                    "hidden from this list. You can restore them via the "
                    "API.[/dim]"
                ),
            ),
            callback=lambda ok: self._after_archive_confirm(conv, ok),
        )

    def _after_archive_confirm(self, conv: Any, ok: Optional[bool]) -> None:
        if not ok:
            return
        self.run_worker(self._do_archive(conv), name="convs_archive", exclusive=False)

    async def _do_archive(self, conv: Any) -> None:
        client = self._client()
        if client is None:
            return
        try:
            await client.patch(conv.id, status="archived")
        except Exception as exc:  # noqa: BLE001
            logger.exception("Archive failed")
            # A5 — short_err carries server-controlled APIError.message.
            self.app.notify(
                f"Archive failed: {self._short_err(exc)}",
                severity="error",
                markup=False,
            )
            return
        # Drop the row locally — server cache is already invalidated client-side.
        self._conversations = [c for c in self._conversations if c.id != conv.id]
        self._render_table()
        self._update_status()
        self.app.notify(
            f"Archived: {_rich_escape(conv.title or conv.id)}",
            severity="information",
        )

    def action_delete(self) -> None:
        conv = self._selected()
        if conv is None:
            self.app.notify("Select a conversation first.", severity="warning")
            return
        title = conv.title or conv.id
        self.app.push_screen(
            _ConfirmModal(
                title="Delete Conversation",
                message=(
                    f"Permanently delete [bold]{_rich_escape(title)}[/bold]?\n"
                    "[dim]This cannot be undone from the TUI.[/dim]"
                ),
                danger=True,
            ),
            callback=lambda ok: self._after_delete_confirm(conv, ok),
        )

    def _after_delete_confirm(self, conv: Any, ok: Optional[bool]) -> None:
        if not ok:
            return
        self.run_worker(self._do_delete(conv), name="convs_delete", exclusive=False)

    async def _do_delete(self, conv: Any) -> None:
        client = self._client()
        if client is None:
            return
        try:
            await client.delete(conv.id)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Delete failed")
            # A5 — short_err carries server-controlled APIError.message.
            self.app.notify(
                f"Delete failed: {self._short_err(exc)}",
                severity="error",
                markup=False,
            )
            return
        self._conversations = [c for c in self._conversations if c.id != conv.id]
        self._render_table()
        self._update_status()
        self.app.notify(
            f"Deleted: {_rich_escape(conv.title or conv.id)}",
            severity="information",
        )

    def action_export(self) -> None:
        conv = self._selected()
        if conv is None:
            self.app.notify("Select a conversation first.", severity="warning")
            return
        # Suggest a sensible default filename. The user can edit before submit.
        slug = self._slugify(conv.title or conv.id)
        default_name = f"{slug}.md"
        self.app.push_screen(
            _ExportPathModal(default_name=default_name),
            callback=lambda dest: self._after_export_input(conv, dest),
        )

    def _after_export_input(self, conv: Any, dest: Optional[str]) -> None:
        if not dest:
            return
        self.run_worker(
            self._do_export(conv, dest),
            name="convs_export",
            exclusive=False,
        )

    async def _do_export(self, conv: Any, dest_str: str) -> None:
        client = self._client()
        if client is None:
            return
        dest_path = Path(dest_str).expanduser()
        try:
            saved = await client.export_md(conv.id, dest_path)
        except ValueError as exc:
            # Path-traversal guard — surface to the user, don't crash.
            # A5 — exc message is local-validator output, but we keep the
            # ``markup=False`` policy uniform so future code paths can't
            # accidentally reintroduce the injection vector.
            self.app.notify(
                f"Export rejected: {self._short_err(exc)}",
                severity="error",
                markup=False,
            )
            return
        except FileExistsError as exc:
            self.app.notify(
                f"Export rejected: {self._short_err(exc)}",
                severity="warning",
                markup=False,
            )
            return
        except Exception as exc:  # noqa: BLE001
            logger.exception("Export failed")
            # A5 — APIError.message can carry server-controlled markup.
            self.app.notify(
                f"Export failed: {self._short_err(exc)}",
                severity="error",
                markup=False,
            )
            return
        self.app.notify(
            f"Exported to {saved}",
            severity="information",
            timeout=8,
            markup=False,
        )

    @staticmethod
    def _slugify(value: str) -> str:
        """Tame a title into a filesystem-safe filename stem."""
        cleaned = []
        for ch in value.strip().lower():
            if ch.isalnum():
                cleaned.append(ch)
            elif ch in (" ", "-", "_"):
                cleaned.append("-")
        slug = "".join(cleaned).strip("-") or "conversation"
        return slug[:60]

    # ------------------------------------------------------------------
    # DataTable selection — Enter == open
    # ------------------------------------------------------------------

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        # Override Enter behaviour to load the row instead of toggling.
        self.action_open_selected()
