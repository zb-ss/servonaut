"""Previous chats — Servonaut hosted-AI conversation history screen.

Loads server-side conversation summaries via :class:`AIConversationsClient`
(Wave 1) and exposes the standard CRUD verbs (load, archive, delete, export).

Why a regular ``Screen`` and not a ``ModalScreen``: this is a content-heavy
panel with multiple action rows, a filter input, a paginated DataTable, and
multi-step flows (export prompts for a path, archive/delete confirms). The
``Sidebar`` widget MUST stay visible so users can navigate away mid-flow.
Uses a ModalScreen for this brief blocking view (project convention).

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
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button, DataTable, Footer, Input, Static, TabbedContent, TabPane,
)

from servonaut.screens._compact_actions import sync_compact_buttons
from servonaut.utils.theme_text import themed_text
from servonaut.widgets.action_button import ActionButton, ActionRow
from servonaut.widgets.progress_indicator import ProgressIndicator
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.dialogs import (
    DialogActions, DialogBody, DialogFrame, DialogNotificationSpace,
)
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

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

    def __init__(self, default_name: str) -> None:
        super().__init__(classes="dialog-screen")
        self._default = default_name

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static("[bold $text-accent]Export conversation to Markdown[/bold $text-accent]"),
            body=DialogBody(Static(
                "[dim]Path is resolved relative to the current directory. "
                "Must stay inside CWD or ~/Downloads.[/dim]"
            )),
            status=Vertical(Input(value=self._default, id="export_path_input")),
            actions=DialogActions(
                Button("Save", variant="primary", id="btn_export_save"),
                Button("Cancel", id="btn_export_cancel"),
            ),
            id="export_modal",
            size="compact",
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

    def __init__(self, title: str, message: str, danger: bool = False) -> None:
        super().__init__(classes="dialog-screen")
        self._title = title
        self._message = message
        self._danger = danger

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static(f"[bold $text-accent]{self._title}[/bold $text-accent]"),
            body=DialogBody(Static(self._message)),
            actions=DialogActions(
                Button(
                    "Confirm",
                    variant="error" if self._danger else "primary",
                    id="btn_yes",
                ),
                Button("Cancel", id="btn_no"),
            ),
            id="confirm_box",
            size="compact",
            severity="danger" if self._danger else "neutral",
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


class AIConversationsScreen(WorkspaceScreen):
    """Server-backed list of the user's hosted-AI conversations.

    Loads ``ConversationSummary`` rows from
    :class:`AIConversationsClient`, groups them by recency, and offers
    archive / delete / export actions on the selected row.
    """

    CHAT_REFLOW = True
    CHAT_MIN_CONTENT_WIDTH = 94
    CONTENT_NARROW_WIDTH = 110

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("a", "archive", "Archive", show=True),
        Binding("d", "delete", "Delete", show=True),
        Binding("e", "export", "Export to Markdown", show=True),
        Binding("slash", "focus_filter", "Filter", show=True),
        Binding("enter", "open_selected", "Open", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        # Cloud-tab state (server-backed conversations).
        self._conversations: List[Any] = []
        self._before_cursor: Optional[str] = None
        self._loading: bool = False
        self._filter: str = ""
        self._exhausted: bool = False

        # Local-tab state (chat_service.list_sessions). Pagination is
        # client-side (manifest already lives in memory) so we just slice
        # by offset; the local store rarely has enough rows to make
        # streaming meaningful.
        self._local_sessions: List[Dict[str, Any]] = []
        self._local_filter: str = ""
        self._local_offset: int = 0
        self._local_exhausted: bool = False

        # Active tab — drives which collection the action handlers
        # (Open/Delete/Archive/Export) operate on. Default for hosted-AI
        # users is Cloud; free / logged-out users land on Local since
        # Cloud would render an inert "sign in" empty state.
        self._active_tab: str = "tab_cloud"

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _initial_tab(self) -> str:
        """Pick the initial tab based on auth state.

        Hosted-AI subscribers (signed in + ``premium_ai``) start on
        Cloud — their primary surface. Everyone else lands on Local so
        they don't open the screen and immediately see a "sign in to
        view AI history" empty state. The user can still flip tabs.
        """
        auth = getattr(self.app, "auth_service", None)
        if auth and auth.is_authenticated and auth.has_feature("premium_ai"):
            self._active_tab = "tab_cloud"
            return "tab_cloud"
        self._active_tab = "tab_local"
        return "tab_local"

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield WorkspaceControls("Previous chats")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            with Vertical(id="convs_container", classes="workspace-content"):
                yield Static(
                    "[bold $text-accent]Previous chats[/bold $text-accent]",
                    id="convs_title",
                )
                yield Static(
                    "Cloud chats are uploaded by Servonaut AI turns. "
                    "Local chats stay on this machine.",
                    id="convs_subtitle",
                )
                with TabbedContent(
                    initial=self._initial_tab(), id="convs_tabs",
                ):
                    with TabPane("Cloud", id="tab_cloud"):
                        with Horizontal(id="convs_search"):
                            yield Input(
                                placeholder="Filter by title…",
                                id="convs_filter",
                            )
                            yield ActionButton("Refresh", "r", id="btn_convs_refresh")
                        yield ProgressIndicator()
                        with Horizontal(id="convs_workspace"):
                            with Vertical(id="convs_listing"):
                                with VerticalScroll(id="convs_scroll"):
                                    yield DataTable(
                                        id="convs_table",
                                        zebra_stripes=True,
                                        cursor_type="row",
                                    )
                                    yield Static("", id="convs_empty")
                                with Horizontal(id="convs_pager"):
                                    yield Static("", id="convs_status")
                                    yield ActionButton("Load more", id="btn_convs_more")
                            with ActionRow(id="convs_actions"):
                                yield ActionButton("Open", "enter", role="primary", id="btn_convs_open")
                                yield ActionButton("Archive", "a", id="btn_convs_archive")
                                yield ActionButton("Delete", "d", role="error", id="btn_convs_delete")
                                yield ActionButton("Export to Markdown", "e", short="Export", id="btn_convs_export")
                    with TabPane("Local", id="tab_local"):
                        with Horizontal(id="local_search"):
                            yield Input(
                                placeholder="Filter by title…",
                                id="local_filter",
                            )
                            yield ActionButton("Refresh", "r", id="btn_local_refresh")
                        with Horizontal(id="local_workspace"):
                            with Vertical(id="local_listing"):
                                with VerticalScroll(id="local_scroll"):
                                    yield DataTable(
                                        id="local_table",
                                        zebra_stripes=True,
                                        cursor_type="row",
                                    )
                                    yield Static("", id="local_empty")
                                with Horizontal(id="local_pager"):
                                    yield Static("", id="local_status")
                                    yield ActionButton("Load more", id="btn_local_more")
                            with ActionRow(id="local_actions"):
                                yield ActionButton("Open", "enter", role="primary", id="btn_local_open")
                                yield ActionButton("Delete", "d", role="error", id="btn_local_delete")
        yield Footer()

    def sync_workspace_controls(self) -> None:
        super().sync_workspace_controls()
        sync_compact_buttons(self)

    def on_mount(self) -> None:
        sync_compact_buttons(self)
        self.query_one("#convs_scroll").border_title = "Cloud conversations"
        self.query_one("#local_scroll").border_title = "Local sessions"
        table = self.query_one("#convs_table", DataTable)
        table.add_columns("Title", "Last activity", "Messages", "Model", "Status")
        self.query_one("#convs_empty", Static).update("")

        # Local-tab columns. "Where" surfaces the paired/local distinction
        # so a user who hasn't read the subtitle still sees at a glance
        # whether a row is uploaded.
        local_table = self.query_one("#local_table", DataTable)
        local_table.add_columns(
            "Title", "Last activity", "Messages", "Provider", "Where",
        )
        self.query_one("#local_empty", Static).update("")

        # Cloud loads the first page eagerly because that's the default
        # tab and the network call is the slowest path. Local renders
        # immediately from the on-disk manifest.
        self.run_worker(self._load_page(), name="convs_load", exclusive=True)
        self._reload_local_table()

    def on_tabbed_content_tab_activated(
        self, event: TabbedContent.TabActivated,
    ) -> None:
        """Track which tab the user is on so action_* + button handlers
        operate on the matching collection. Refresh the manifest on
        every Local-tab activation — chats can grow while the screen is
        open (the chat panel keeps writing in the background) and the
        manifest is cheap to re-read."""
        tab_id = event.tab.id or ""
        if tab_id == "--content-tab-tab_cloud":
            self._active_tab = "tab_cloud"
        elif tab_id == "--content-tab-tab_local":
            self._active_tab = "tab_local"
            self._reload_local_table()

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
                "[$text-error]AI conversations client is not available. "
                "Sign in to access hosted AI history.[/$text-error]"
            )
            return

        self._loading = True
        progress = self.query_one(ProgressIndicator)
        progress.start("Loading conversations…")

        try:
            page = await client.list(limit=_PAGE_LIMIT, before=before, status="active")
        except Exception as exc:  # noqa: BLE001 — surface every backend error
            logger.exception("Failed to list AI conversations")
            # If the OAuth bearer is bad (401/403), tell the relay
            # manager so the sidebar indicator flips to "session
            # expired" immediately instead of waiting for the next
            # heartbeat to notice. The user's symptom was: 401 here
            # but the green dot stayed on for ~30s.
            self._maybe_notify_session_expired(exc)
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
                f"[$text-error]Failed to load conversations: "
                f"{_rich_escape(self._short_err(exc))}[/$text-error]"
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

        def _scrub(x: str) -> str:
            if self.app.demo_mode and self.app.redaction_service:
                return self.app.redaction_service.scrub_stream(x)
            return x

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
                # Scrub the conversation title — it may contain server names
                # or other PII the user typed as part of the chat topic.
                safe_conv_title = _scrub(conv.title or "(untitled)")
                scrubbed_conv = type("_SC", (), {
                    "title": safe_conv_title,
                    "updated_at": conv.updated_at,
                    "message_count": conv.message_count,
                    "last_model": conv.last_model,
                    "status": conv.status,
                    "id": conv.id,
                })()
                table.add_row(
                    self._format_title_cell(scrubbed_conv, group_name),
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

    def _format_status_cell(self, status: str) -> Text:
        tokens = {"active": "text-success", "archived": "text-warning", "deleted": "text-error"}
        return themed_text(self.app, status or "—", tokens.get(status, "text"))

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
            tail = "" if self._exhausted else " · more available — press [bold]Load more[/bold]"
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

    def _maybe_notify_session_expired(self, exc: BaseException) -> None:
        """Flip the sidebar indicator to "session expired" on 401/403.

        Reads ``status`` defensively — APIError carries it as an
        attribute but other exception types may not. Also tolerates
        the relay_manager being absent / not having the public hook
        wired (older app variants).
        """
        status = getattr(exc, "status", None)
        if status not in (401, 403):
            return
        manager = getattr(self.app, "relay_manager", None)
        if manager is None:
            return
        notify = getattr(manager, "notify_session_expired", None)
        if notify is None:
            return
        try:
            self.app.run_worker(
                notify(),
                name="relay_session_expired",
                exclusive=False,
            )
        except Exception:
            logger.debug(
                "Failed to schedule notify_session_expired",
                exc_info=True,
            )

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
            # Cloud
            "btn_convs_open": self.action_open_selected,
            "btn_convs_archive": self.action_archive,
            "btn_convs_delete": self.action_delete,
            "btn_convs_export": self.action_export,
            "btn_convs_more": self._load_more,
            "btn_convs_refresh": self.action_refresh,
            # Local
            "btn_local_open": self.action_open_local,
            "btn_local_delete": self.action_delete_local,
            "btn_local_more": self._local_load_more,
            "btn_local_refresh": self.action_refresh_local,
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
        elif event.input.id == "local_filter":
            self._local_filter = event.value or ""
            self._local_offset = 0
            self._render_local_table()
            self._update_local_status()

    def action_focus_filter(self) -> None:
        target_id = (
            "#local_filter" if self._active_tab == "tab_local"
            else "#convs_filter"
        )
        try:
            self.query_one(target_id, Input).focus()
        except Exception:
            pass

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        if self._active_tab == "tab_local":
            self.action_refresh_local()
            return
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
        if self._active_tab == "tab_local":
            self.action_open_local()
            return
        conv = self._selected()
        if conv is None:
            self.app.notify("Select a conversation first.", severity="warning")
            return
        # Walk the screen stack — `app.query_one()` only sees the active
        # screen, but the chat panel was mounted on whatever screen the
        # user pressed F2 on (now underneath this conversations screen).
        chat_panel = self._find_chat_panel()
        if chat_panel is not None and hasattr(chat_panel, "load_remote_conversation"):
            chat_panel.load_remote_conversation(conv.id)
            # Pop ourselves so the user lands back on the chat panel
            # after picking a conversation. Without this they'd still
            # be looking at the conversations list.
            try:
                self.app.pop_screen()
            except Exception:
                pass
            self.app.notify(
                f"Opening conversation: {_rich_escape(conv.title or conv.id)}",
                severity="information",
            )
        else:
            self.app.notify(
                "Chat panel not mounted — open it with F2 first.",
                severity="warning",
            )

    def _find_chat_panel(self):
        """Locate the ChatPanel across all mounted screens.

        The chat panel was mounted on the screen the user pressed F2 on,
        which is now below this AIConversationsScreen on the stack.
        ``app.query_one()`` only looks at the active screen, so we walk
        every screen in the stack and try each.
        """
        from servonaut.widgets.chat_panel import ChatPanel

        screens = []
        try:
            screens = list(getattr(self.app, "screen_stack", []) or [])
        except Exception:
            screens = []
        for screen in reversed(screens):
            if screen is self:
                continue
            try:
                return screen.query_one(ChatPanel)
            except Exception:
                continue
        # Last-resort fallback: the active screen (may already be in the
        # stack list above; harmless duplicate).
        try:
            return self.app.query_one(ChatPanel)
        except Exception:
            return None

    def action_archive(self) -> None:
        if self._active_tab == "tab_local":
            # Local-only feature parity decision: archive is a server
            # concept (hide-from-list), so on the Local tab the key
            # quietly no-ops with a hint instead of falling through.
            self.app.notify(
                "Archive is a Cloud-only feature.",
                severity="information",
            )
            return
        conv = self._selected()
        if conv is None:
            self.app.notify("Select a conversation first.", severity="warning")
            return
        title = conv.title or conv.id
        self.app.push_screen(
            _ConfirmModal(
                title="Archive conversation",
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
        if self._active_tab == "tab_local":
            self.action_delete_local()
            return
        conv = self._selected()
        if conv is None:
            self.app.notify("Select a conversation first.", severity="warning")
            return
        title = conv.title or conv.id
        self.app.push_screen(
            _ConfirmModal(
                title="Delete conversation",
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
        if self._active_tab == "tab_local":
            # Export hits the server's /api/ai/conversations/{id}/export
            # endpoint, which only knows about Cloud rows. Surface that
            # constraint instead of silently routing to /dev/null.
            self.app.notify(
                "Export is a Cloud-only feature.",
                severity="information",
            )
            return
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

    # ------------------------------------------------------------------
    # Local tab — chat_service.list_sessions + per-row open/delete.
    # ------------------------------------------------------------------

    def _chat_service(self):
        """Return the ChatService instance or None if unavailable."""
        return getattr(self.app, "chat_service", None)

    def _reload_local_table(self) -> None:
        """Re-read the manifest and re-render the Local tab.

        Cheap — manifest is one small JSON file. Triggered on mount,
        on tab activation, and after any local mutation (delete).
        """
        svc = self._chat_service()
        if svc is None:
            self._local_sessions = []
            self._render_local_table()
            self._update_local_status()
            return
        try:
            # Read the full manifest in one go, then paginate client-side.
            # If a user ever has tens of thousands of local sessions we
            # can revisit, but the manifest is sorted-on-load and
            # in-memory pagination is plenty fast for realistic counts.
            self._local_sessions = svc.list_sessions(limit=None, offset=0)
        except Exception:
            logger.exception("Failed to load local chat manifest")
            self._local_sessions = []
        self._render_local_table()
        self._update_local_status()

    def _local_filtered(self) -> List[Dict[str, Any]]:
        if not self._local_filter:
            return list(self._local_sessions)
        needle = self._local_filter.lower()
        return [
            s for s in self._local_sessions
            if needle in (s.get("title") or "").lower()
        ]

    def _local_visible_slice(self) -> List[Dict[str, Any]]:
        """Apply pagination to the filtered list."""
        items = self._local_filtered()
        end = self._local_offset + _PAGE_LIMIT
        self._local_exhausted = end >= len(items)
        return items[: end]  # offset is always 0 here; "Load more" grows it

    def _render_local_table(self) -> None:
        table = self.query_one("#local_table", DataTable)
        table.clear()

        items = self._local_visible_slice()
        if not items:
            empty = self.query_one("#local_empty", Static)
            empty.update(
                "[dim italic]No local sessions yet — start one from the chat panel.[/dim italic]"
                if not self._local_sessions else
                "[dim italic]No sessions match your filter.[/dim italic]"
            )
            return
        self.query_one("#local_empty", Static).update("")

        def _scrub(x: str) -> str:
            if self.app.demo_mode and self.app.redaction_service:
                return self.app.redaction_service.scrub_stream(x)
            return x

        for s in items:
            paired = bool(s.get("remote_conversation_id"))
            where = (
                themed_text(self.app, "uploaded", "text-accent") if paired
                else themed_text(self.app, "local only", "dim")
            )
            provider = s.get("last_provider") or "—"
            table.add_row(
                _rich_escape(_scrub(s.get("title") or "(untitled)")),
                self._format_age(s.get("updated_at") or ""),
                str(s.get("message_count", 0)),
                _rich_escape(provider),
                where,
                key=s.get("id") or "",
            )

    def _update_local_status(self) -> None:
        n = len(self._local_sessions)
        shown = len(self._local_visible_slice())
        if n == 0:
            self._set_local_status("")
            return
        tail = (
            "" if self._local_exhausted else
            " · more available — press [bold]Load more[/bold]"
        )
        if shown == n:
            self._set_local_status(
                f"[dim]{n} local session{'s' if n != 1 else ''}{tail}[/dim]"
            )
        else:
            self._set_local_status(
                f"[dim]Showing {shown} of {n} (filtered)[/dim]"
            )

    def _set_local_status(self, markup: str) -> None:
        try:
            self.query_one("#local_status", Static).update(markup)
        except Exception:
            pass

    def _selected_local_id(self) -> Optional[str]:
        try:
            table = self.query_one("#local_table", DataTable)
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            if row_key is None:
                return None
            return str(row_key.value) if hasattr(row_key, "value") else str(row_key)
        except Exception:
            return None

    def _selected_local(self) -> Optional[Dict[str, Any]]:
        sid = self._selected_local_id()
        if not sid:
            return None
        for s in self._local_sessions:
            if s.get("id") == sid:
                return s
        return None

    def action_open_local(self) -> None:
        row = self._selected_local()
        if row is None:
            self.app.notify("Select a session first.", severity="warning")
            return
        chat_panel = self._find_chat_panel()
        if chat_panel is None or not hasattr(chat_panel, "load_local_session"):
            self.app.notify(
                "Chat panel not mounted — open it with F2 first.",
                severity="warning",
            )
            return
        try:
            chat_panel.load_local_session(row["id"])
        except Exception:
            logger.exception("load_local_session raised")
            self.app.notify(
                "Failed to load local session.", severity="error",
                markup=False,
            )
            return
        try:
            self.app.pop_screen()
        except Exception:
            pass
        self.app.notify(
            f"Opening: {_rich_escape(row.get('title') or row['id'])}",
            severity="information",
        )

    def action_delete_local(self) -> None:
        row = self._selected_local()
        if row is None:
            self.app.notify("Select a session first.", severity="warning")
            return
        title = row.get("title") or row["id"]
        paired = bool(row.get("remote_conversation_id"))
        msg = (
            f"Permanently delete [bold]{_rich_escape(title)}[/bold]?\n"
            "[dim]Local file will be removed."
            + (
                " The paired Cloud conversation will also be deleted."
                if paired else ""
            )
            + "[/dim]"
        )
        self.app.push_screen(
            _ConfirmModal(
                title="Delete local session",
                message=msg,
                danger=True,
            ),
            callback=lambda ok: self._after_local_delete_confirm(row, ok),
        )

    def _after_local_delete_confirm(
        self, row: Dict[str, Any], ok: Optional[bool],
    ) -> None:
        if not ok:
            return
        self.run_worker(
            self._do_local_delete(row),
            name="local_delete",
            exclusive=False,
        )

    async def _do_local_delete(self, row: Dict[str, Any]) -> None:
        svc = self._chat_service()
        if svc is None:
            self.app.notify(
                "Chat service not available.", severity="error",
                markup=False,
            )
            return
        # Server delete first when paired — if it fails we still want
        # the local file gone (user explicitly asked) but we surface
        # the cloud-side failure as a non-fatal warning.
        remote_id = row.get("remote_conversation_id")
        if remote_id:
            client = self._client()
            if client is not None:
                try:
                    await client.delete(remote_id)
                except Exception as exc:  # noqa: BLE001
                    logger.exception("Paired remote delete failed")
                    self.app.notify(
                        "Local deleted; cloud delete failed: "
                        f"{self._short_err(exc)}",
                        severity="warning",
                        markup=False,
                    )
        try:
            svc.delete_session(row["id"])
        except Exception as exc:  # noqa: BLE001
            logger.exception("Local delete failed")
            self.app.notify(
                f"Delete failed: {self._short_err(exc)}",
                severity="error",
                markup=False,
            )
            return
        # Drop the cloud row too if we just deleted its pair, so the
        # Cloud tab doesn't show a stale row until the next refresh.
        if remote_id:
            self._conversations = [
                c for c in self._conversations if c.id != remote_id
            ]
            try:
                self._render_table()
                self._update_status()
            except Exception:
                pass
        self._reload_local_table()
        self.app.notify(
            f"Deleted: {_rich_escape(row.get('title') or row['id'])}",
            severity="information",
        )

    def action_refresh_local(self) -> None:
        self._local_offset = 0
        self._local_exhausted = False
        self._reload_local_table()

    def _local_load_more(self) -> None:
        if self._local_exhausted:
            self.app.notify(
                "No more local sessions to load.", severity="information",
            )
            return
        self._local_offset += _PAGE_LIMIT
        self._render_local_table()
        self._update_local_status()
