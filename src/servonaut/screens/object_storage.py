"""S3-compatible object storage manager screen for Servonaut.

Provides a full file-manager UI for any S3-compatible object storage
provider (AWS S3, Hetzner Object Storage, OVH Object Storage).  The
``provider`` constructor argument drives which service attribute is
resolved at runtime; a single ``ObjectStorageScreen`` class handles
all three providers (D3 in the architecture plan).

Navigation model:
    - **Buckets view**: lists all buckets; bucket row → opens objects view.
    - **Objects view**: lists folders (virtual prefixes) and objects inside
      the selected bucket; folder row → appends a segment to ``_prefix``.
    - ``Up`` strips the last prefix segment; ``Back`` from objects view
      returns to the buckets view.

Inline forms (hidden by default, shown one at a time):
    - New Bucket form
    - Upload form (local path → S3 key)
    - Download form (S3 key → local path)
    - Copy/Move form
    - Presigned-URL display (read-only)

Design follows ``ovh_storage.py``: ``round`` borders, inline show/hide
form mechanism, ``run_worker`` wrapper around every ``push_screen_wait``
call so Textual 8.x's ``NoActiveWorker`` constraint is respected.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Dict, List, Optional

from rich.markup import escape as markup_escape
from textual.app import ComposeResult
from servonaut.utils.formatting import escape_cell
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.widgets.sidebar import Sidebar

if TYPE_CHECKING:
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Provider-level display metadata
# ---------------------------------------------------------------------------

_PROVIDER_LABELS: Dict[str, str] = {
    "aws":      "AWS S3",
    "hetzner":  "Hetzner Object Storage",
    "ovh":      "OVH Object Storage",
}

# View identifiers
_VIEW_BUCKETS = "buckets"
_VIEW_OBJECTS = "objects"

# Default expiry for presigned URLs in seconds (1 hour).
# Update here to change the expiry shown to users and passed to the service.
_PRESIGNED_EXPIRES_IN = 3600


class ObjectStorageScreen(Screen):
    """S3-compatible object storage file-manager (provider-parameterised).

    Args:
        provider: One of ``"aws"``, ``"hetzner"``, ``"ovh"``.  Drives which
            service instance is resolved via
            ``getattr(app, f"{provider}_object_storage_service", None)``.
    """

    BINDINGS = [
        Binding("escape", "back", "Back",    show=True),
        Binding("r",      "refresh", "Refresh", show=True),
        Binding("u",      "up",     "Up",    show=True),
        Binding("o",      "open",   "Open",  show=True),
        Binding("d",      "delete", "Delete", show=True),
    ]

    @property
    def app(self) -> "ServonautApp":  # type: ignore[override]
        return super().app  # type: ignore[return-value]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    # ------------------------------------------------------------------
    # Construction / state
    # ------------------------------------------------------------------

    def __init__(self, provider: str) -> None:
        super().__init__()
        self._provider: str = provider
        self._view: str = _VIEW_BUCKETS
        self._current_bucket: str = ""
        self._prefix: str = ""
        self._buckets: List[Dict] = []
        self._folders: List[str] = []
        self._objects: List[Dict] = []

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        label = _PROVIDER_LABELS.get(self._provider, self._provider.upper())
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static(
                    f"[bold cyan]{label}[/bold cyan]",
                    id="s3_title",
                ),
                Static("", id="s3_breadcrumb"),
                DataTable(id="s3_table", cursor_type="row", zebra_stripes=True),
                Static("", id="s3_status"),
                Horizontal(
                    Button("Refresh (r)",      id="btn_s3_refresh",    variant="default"),
                    Button("New Bucket",       id="btn_s3_new_bucket", variant="primary"),
                    Button("Up (u)",           id="btn_s3_up",         variant="default"),
                    Button("Open (o)",         id="btn_s3_open",       variant="default"),
                    Button("Upload",           id="btn_s3_upload",     variant="default"),
                    Button("Download",         id="btn_s3_download",   variant="default"),
                    Button("Delete (d)",       id="btn_s3_delete",     variant="error"),
                    Button("Copy",             id="btn_s3_copy",       variant="default"),
                    Button("Move",             id="btn_s3_move",       variant="default"),
                    Button("Share URL",        id="btn_s3_share",      variant="default"),
                    Button("Back",             id="btn_s3_back",       variant="default"),
                    id="s3_actions",
                ),
                # ---- New Bucket form (hidden by default) ----
                Container(
                    Static("[bold]Create Bucket[/bold]", classes="section_header"),
                    Label("Bucket name:"),
                    Input(placeholder="my-bucket", id="s3_input_bucket_name"),
                    Horizontal(
                        Button("Create", id="btn_s3_save_bucket",   variant="primary"),
                        Button("Cancel", id="btn_s3_cancel_bucket", variant="default"),
                        classes="add_row",
                    ),
                    id="s3_new_bucket_form",
                ),
                # ---- Upload form (hidden by default) ----
                Container(
                    Static("[bold]Upload File[/bold]", classes="section_header"),
                    Label("Local file path:"),
                    Input(placeholder="/home/user/file.txt", id="s3_input_upload_path"),
                    Label("Object key (destination):"),
                    Input(placeholder="folder/file.txt", id="s3_input_upload_key"),
                    Horizontal(
                        Button("Upload", id="btn_s3_do_upload",     variant="primary"),
                        Button("Cancel", id="btn_s3_cancel_upload", variant="default"),
                        classes="add_row",
                    ),
                    id="s3_upload_form",
                ),
                # ---- Download form (hidden by default) ----
                Container(
                    Static("[bold]Download File[/bold]", classes="section_header"),
                    Label("Local destination path:"),
                    Input(placeholder="~/Downloads/file.txt", id="s3_input_download_path"),
                    Horizontal(
                        Button("Download", id="btn_s3_do_download",     variant="primary"),
                        Button("Cancel",   id="btn_s3_cancel_download", variant="default"),
                        classes="add_row",
                    ),
                    id="s3_download_form",
                ),
                # ---- Copy form (hidden by default) ----
                Container(
                    Static("[bold]Copy Object[/bold]", classes="section_header"),
                    Label("Destination bucket:"),
                    Input(placeholder="target-bucket", id="s3_input_copy_dst_bucket"),
                    Label("Destination key:"),
                    Input(placeholder="folder/copy.txt", id="s3_input_copy_dst_key"),
                    Horizontal(
                        Button("Copy",   id="btn_s3_do_copy",     variant="primary"),
                        Button("Cancel", id="btn_s3_cancel_copy", variant="default"),
                        classes="add_row",
                    ),
                    id="s3_copy_form",
                ),
                # ---- Move form (hidden by default) ----
                Container(
                    Static("[bold]Move Object[/bold]", classes="section_header"),
                    Label("Destination bucket:"),
                    Input(placeholder="target-bucket", id="s3_input_move_dst_bucket"),
                    Label("Destination key:"),
                    Input(placeholder="folder/moved.txt", id="s3_input_move_dst_key"),
                    Horizontal(
                        Button("Move",   id="btn_s3_do_move",     variant="primary"),
                        Button("Cancel", id="btn_s3_cancel_move", variant="default"),
                        classes="add_row",
                    ),
                    id="s3_move_form",
                ),
                # ---- Presigned-URL display (hidden by default) ----
                Container(
                    Static("[bold]Presigned URL[/bold]", classes="section_header"),
                    Static("", id="s3_presigned_url_display"),
                    Horizontal(
                        Button("Close", id="btn_s3_close_url", variant="default"),
                        classes="add_row",
                    ),
                    id="s3_url_display",
                ),
                id="s3_container",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._setup_table()
        self._hide_all_forms()
        self._refresh()

    def _setup_table(self) -> None:
        table = self.query_one("#s3_table", DataTable)
        table.clear(columns=True)
        table.add_columns("Type", "Name / Key", "Size", "Last Modified")

    def _hide_all_forms(self) -> None:
        for form_id in (
            "s3_new_bucket_form",
            "s3_upload_form",
            "s3_download_form",
            "s3_copy_form",
            "s3_move_form",
            "s3_url_display",
        ):
            self.query_one(f"#{form_id}").display = False

    # ------------------------------------------------------------------
    # Service accessor
    # ------------------------------------------------------------------

    def _get_storage_service(self):
        """Return the provider's ObjectStorageService, or None if unconfigured."""
        return getattr(self.app, f"{self._provider}_object_storage_service", None)

    # ------------------------------------------------------------------
    # Redaction helper
    # ------------------------------------------------------------------

    def scrub(self, x: str) -> str:
        """Scrub *x* via RedactionService when in demo mode."""
        if self.app.demo_mode and self.app.redaction_service:
            return self.app.redaction_service.scrub_stream(x)
        return x

    def scrub_name(self, x: str) -> str:
        """Scrub a resource name (bucket) via redact_name in demo mode."""
        if self.app.demo_mode and self.app.redaction_service:
            return self.app.redaction_service.redact_name(x)
        return x

    def scrub_key(self, key: str) -> str:
        """Scrub an object key by redacting each path segment individually.

        ``scrub_stream`` only catches IPs / ARNs / URLs / emails — a plain
        key like ``invoices/2026/acme-corp-contract.pdf`` would pass through
        unchanged.  Splitting on ``/`` and applying ``redact_name`` to each
        segment closes this gap without mangling the path separators.
        """
        if not (self.app.demo_mode and self.app.redaction_service):
            return key
        segments = key.split("/")
        redacted = [
            self.app.redaction_service.redact_name(seg) if seg else seg
            for seg in segments
        ]
        return "/".join(redacted)

    # ------------------------------------------------------------------
    # Status helper
    # ------------------------------------------------------------------

    def _set_status(self, text: str) -> None:
        """Update the status Static widget."""
        try:
            self.query_one("#s3_status", Static).update(text)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Refresh / load
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        """Kick off loading based on the current view."""
        svc = self._get_storage_service()
        if svc is None:
            label = _PROVIDER_LABELS.get(self._provider, self._provider)
            self._set_status(
                f"[yellow]{markup_escape(label)} is not configured. "
                "Add S3 credentials in Settings.[/yellow]"
            )
            return
        if self._view == _VIEW_BUCKETS:
            self.run_worker(
                self._load_buckets(),
                exclusive=True,
                name="s3_load_buckets",
            )
        else:
            self.run_worker(
                self._load_objects(),
                exclusive=True,
                name="s3_load_objects",
            )

    async def _load_buckets(self) -> None:
        """Load the bucket list and render the buckets view."""
        svc = self._get_storage_service()
        if svc is None:
            return

        self._set_status("[dim]Loading buckets…[/dim]")
        try:
            buckets = await svc.list_buckets()
        except Exception as err:
            logger.error("list_buckets failed: %s", err)
            err_msg = self.scrub(str(err))
            self._set_status(f"[red]Error loading buckets: {markup_escape(err_msg)}[/red]")
            self.app.notify(
                f"Failed to load buckets: {err_msg}",
                severity="error",
                markup=False,
            )
            return

        self._buckets = buckets
        self._render_buckets_table(buckets)
        self._update_breadcrumb()
        count = len(buckets)
        self._set_status(f"[dim]{count} bucket{'s' if count != 1 else ''}[/dim]")

    def _render_buckets_table(self, buckets: List[Dict]) -> None:
        """Populate the DataTable with bucket rows."""
        table = self.query_one("#s3_table", DataTable)
        table.clear(columns=True)
        table.add_columns("Type", "Bucket Name", "Created", "")
        for b in buckets:
            name = b.get("name", "")
            created = b.get("creation_date", "") or ""
            # Scrub first (demo-mode redaction), then escape markup so
            # cloud-origin names with '[' / ']' don't corrupt the table.
            display_name = escape_cell(self.scrub_name(name))
            table.add_row(
                "bucket",
                display_name,
                escape_cell(created),
                "",
                key=name,
            )

    async def _load_objects(self) -> None:
        """Load objects + folders for the current bucket/prefix."""
        svc = self._get_storage_service()
        if svc is None:
            return

        self._set_status("[dim]Loading objects…[/dim]")
        try:
            result = await svc.list_objects(
                self._current_bucket,
                prefix=self._prefix,
                delimiter="/",
            )
        except Exception as err:
            logger.error("list_objects failed for %s/%s: %s", self._current_bucket, self._prefix, err)
            err_msg = self.scrub(str(err))
            self._set_status(f"[red]Error: {markup_escape(err_msg)}[/red]")
            self.app.notify(
                f"Failed to list objects: {err_msg}",
                severity="error",
                markup=False,
            )
            return

        self._folders = result.get("folders", [])
        self._objects = result.get("objects", [])
        is_truncated = result.get("is_truncated", False)

        self._render_objects_table()
        self._update_breadcrumb()

        total = len(self._folders) + len(self._objects)
        suffix = " (showing first 1000 — paginated view coming soon)" if is_truncated else ""
        self._set_status(
            f"[dim]{len(self._folders)} folder(s), {len(self._objects)} object(s){suffix}[/dim]"
        )

    def _render_objects_table(self) -> None:
        """Populate the DataTable with folder and object rows."""
        table = self.query_one("#s3_table", DataTable)
        table.clear(columns=True)
        table.add_columns("Type", "Name / Key", "Size", "Last Modified")

        for folder in self._folders:
            # Strip the current prefix so only the segment is shown.
            # Scrub per-segment (demo-mode redaction), then escape markup.
            display_name = escape_cell(
                self.scrub_key(folder.removeprefix(self._prefix))
            )
            table.add_row(
                "[bold blue]folder[/bold blue]",
                display_name,
                "",
                "",
                key=f"folder:{folder}",
            )

        for obj in self._objects:
            key = obj.get("key", "")
            size_bytes = obj.get("size", 0)
            last_modified = obj.get("last_modified", "") or ""
            # Scrub per-segment (demo-mode redaction), then escape markup.
            display_key = escape_cell(self.scrub_key(key.removeprefix(self._prefix)))
            size_str = _format_size(size_bytes)
            table.add_row(
                "object",
                display_key,
                size_str,
                escape_cell(last_modified),
                key=f"object:{key}",
            )

    # ------------------------------------------------------------------
    # Breadcrumb
    # ------------------------------------------------------------------

    def _update_breadcrumb(self) -> None:
        """Render the navigation breadcrumb above the table."""
        try:
            breadcrumb_widget = self.query_one("#s3_breadcrumb", Static)
        except Exception:
            return

        if self._view == _VIEW_BUCKETS:
            breadcrumb_widget.update("[dim]/ (buckets)[/dim]")
            return

        # Objects view — show bucket + prefix path
        parts = [self.scrub_name(self._current_bucket)]
        if self._prefix:
            # Each prefix segment already ends with "/" — strip trailing
            segments = [seg for seg in self._prefix.split("/") if seg]
            for seg in segments:
                parts.append(self.scrub_key(seg))
        breadcrumb_widget.update("[dim]" + " / ".join(parts) + "[/dim]")

    # ------------------------------------------------------------------
    # Table selection helpers
    # ------------------------------------------------------------------

    def _get_selected_bucket_name(self) -> Optional[str]:
        """Return the raw (un-redacted) bucket name for the cursor row."""
        table = self.query_one("#s3_table", DataTable)
        if table.row_count == 0:
            return None
        try:
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
            return row_key  # bucket-view rows use raw bucket name as key
        except Exception:
            return None

    def _get_selected_object_info(self) -> Optional[Dict]:
        """Return a dict with type/key for the cursor row in objects view.

        Returns:
            ``{"type": "folder"|"object", "key": str}`` or None.
        """
        table = self.query_one("#s3_table", DataTable)
        if table.row_count == 0:
            return None
        try:
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
            if row_key and ":" in row_key:
                kind, _, key = row_key.partition(":")
                return {"type": kind, "key": key}
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Button handler (dict-dispatch pattern)
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        mapping = {
            "btn_s3_refresh":        self.action_refresh,
            "btn_s3_new_bucket":     self._show_new_bucket_form,
            "btn_s3_up":             self.action_up,
            "btn_s3_open":           self.action_open,
            "btn_s3_upload":         self._show_upload_form,
            "btn_s3_download":       self._show_download_form,
            "btn_s3_delete":         self.action_delete,
            "btn_s3_copy":           self._show_copy_form,
            "btn_s3_move":           self._show_move_form,
            "btn_s3_share":          self._action_share,
            "btn_s3_back":           self.action_back,
            # New-bucket form
            "btn_s3_save_bucket":    self._submit_new_bucket,
            "btn_s3_cancel_bucket":  self._hide_all_forms,
            # Upload form
            "btn_s3_do_upload":      self._submit_upload,
            "btn_s3_cancel_upload":  self._hide_all_forms,
            # Download form
            "btn_s3_do_download":    self._submit_download,
            "btn_s3_cancel_download": self._hide_all_forms,
            # Copy form
            "btn_s3_do_copy":        self._submit_copy,
            "btn_s3_cancel_copy":    self._hide_all_forms,
            # Move form
            "btn_s3_do_move":        self._submit_move,
            "btn_s3_cancel_move":    self._hide_all_forms,
            # URL display
            "btn_s3_close_url":      self._hide_all_forms,
        }
        handler = mapping.get(event.button.id or "")
        if handler is not None:
            handler()

    # ------------------------------------------------------------------
    # Bound actions
    # ------------------------------------------------------------------

    def action_back(self) -> None:
        """Navigate: objects → buckets, or buckets → previous screen."""
        if self._view == _VIEW_OBJECTS:
            self._navigate_to_buckets()
        else:
            self.app.pop_screen()

    def action_refresh(self) -> None:
        self._hide_all_forms()
        self._refresh()

    def action_up(self) -> None:
        """Strip the last prefix segment (go one folder level up)."""
        if self._view != _VIEW_OBJECTS or not self._prefix:
            return
        # Prefix ends with "/"; remove the trailing slash then last segment
        stripped = self._prefix.rstrip("/")
        if "/" in stripped:
            self._prefix = stripped.rsplit("/", 1)[0] + "/"
        else:
            self._prefix = ""
        self.run_worker(self._load_objects(), exclusive=True, name="s3_load_objects")

    def action_open(self) -> None:
        """Open the selected bucket or navigate into a folder."""
        if self._view == _VIEW_BUCKETS:
            self._open_bucket()
        else:
            self._open_folder()

    def action_delete(self) -> None:
        """Delete the selected object or bucket (with confirmation)."""
        if self._view == _VIEW_BUCKETS:
            self._action_delete_bucket()
        else:
            self._action_delete_object()

    # ------------------------------------------------------------------
    # Double-click / row navigation
    # ------------------------------------------------------------------

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Open bucket or navigate into folder on row double-click / Enter."""
        self.action_open()

    # ------------------------------------------------------------------
    # Bucket navigation
    # ------------------------------------------------------------------

    def _open_bucket(self) -> None:
        """Switch to objects view for the selected bucket."""
        bucket = self._get_selected_bucket_name()
        if bucket is None:
            self.app.notify("No bucket selected", severity="warning", markup=False)
            return
        self._current_bucket = bucket
        self._prefix = ""
        self._view = _VIEW_OBJECTS
        self.run_worker(self._load_objects(), exclusive=True, name="s3_load_objects")

    def _navigate_to_buckets(self) -> None:
        """Return to the buckets list view."""
        self._view = _VIEW_BUCKETS
        self._current_bucket = ""
        self._prefix = ""
        self.run_worker(self._load_buckets(), exclusive=True, name="s3_load_buckets")

    # ------------------------------------------------------------------
    # Folder navigation
    # ------------------------------------------------------------------

    def _open_folder(self) -> None:
        """Navigate into the selected folder (append prefix segment)."""
        info = self._get_selected_object_info()
        if info is None:
            return
        if info["type"] == "folder":
            self._prefix = info["key"]  # folder keys already end with "/"
            self.run_worker(self._load_objects(), exclusive=True, name="s3_load_objects")
        # object rows: open does nothing extra (download via button)

    # ------------------------------------------------------------------
    # Inline form helpers
    # ------------------------------------------------------------------

    def _show_new_bucket_form(self) -> None:
        self._hide_all_forms()
        self.query_one("#s3_input_bucket_name", Input).value = ""
        self.query_one("#s3_new_bucket_form").display = True
        self.query_one("#s3_input_bucket_name", Input).focus()

    def _show_upload_form(self) -> None:
        if self._view != _VIEW_OBJECTS:
            self.app.notify("Open a bucket first", severity="warning", markup=False)
            return
        self._hide_all_forms()
        self.query_one("#s3_input_upload_path", Input).value = ""
        # Pre-fill key with current prefix
        self.query_one("#s3_input_upload_key", Input).value = self._prefix
        self.query_one("#s3_upload_form").display = True
        self.query_one("#s3_input_upload_path", Input).focus()

    def _show_download_form(self) -> None:
        if self._view != _VIEW_OBJECTS:
            self.app.notify("Open a bucket first", severity="warning", markup=False)
            return
        info = self._get_selected_object_info()
        if info is None or info["type"] != "object":
            self.app.notify("Select an object to download", severity="warning", markup=False)
            return
        self._hide_all_forms()
        self.query_one("#s3_input_download_path", Input).value = "~/Downloads/"
        self.query_one("#s3_download_form").display = True
        self.query_one("#s3_input_download_path", Input).focus()

    def _show_copy_form(self) -> None:
        if self._view != _VIEW_OBJECTS:
            self.app.notify("Open a bucket first", severity="warning", markup=False)
            return
        info = self._get_selected_object_info()
        if info is None or info["type"] != "object":
            self.app.notify("Select an object to copy", severity="warning", markup=False)
            return
        self._hide_all_forms()
        # Pre-fill is a convenience; scrub_name/scrub_key are passthroughs
        # outside demo mode, so real copies still target the true key.
        self.query_one("#s3_input_copy_dst_bucket", Input).value = self.scrub_name(
            self._current_bucket
        )
        self.query_one("#s3_input_copy_dst_key", Input).value = self.scrub_key(info["key"])
        self.query_one("#s3_copy_form").display = True
        self.query_one("#s3_input_copy_dst_bucket", Input).focus()

    def _show_move_form(self) -> None:
        if self._view != _VIEW_OBJECTS:
            self.app.notify("Open a bucket first", severity="warning", markup=False)
            return
        info = self._get_selected_object_info()
        if info is None or info["type"] != "object":
            self.app.notify("Select an object to move", severity="warning", markup=False)
            return
        self._hide_all_forms()
        # Pre-fill is a convenience; scrub_name/scrub_key are passthroughs
        # outside demo mode, so real moves still target the true key.
        self.query_one("#s3_input_move_dst_bucket", Input).value = self.scrub_name(
            self._current_bucket
        )
        self.query_one("#s3_input_move_dst_key", Input).value = self.scrub_key(info["key"])
        self.query_one("#s3_move_form").display = True
        self.query_one("#s3_input_move_dst_bucket", Input).focus()

    # ------------------------------------------------------------------
    # New bucket
    # ------------------------------------------------------------------

    def _submit_new_bucket(self) -> None:
        name = self.query_one("#s3_input_bucket_name", Input).value.strip()
        if not name:
            self.app.notify("Bucket name is required", severity="error", markup=False)
            self.query_one("#s3_input_bucket_name", Input).focus()
            return
        self._hide_all_forms()
        self.run_worker(
            self._create_bucket(name),
            exclusive=False,
            name="s3_create_bucket",
        )

    async def _create_bucket(self, name: str) -> None:
        svc = self._get_storage_service()
        if svc is None:
            return
        try:
            await svc.create_bucket(name)
            self.app.notify(
                f"Bucket '{name}' created",
                severity="information",
                markup=False,
            )
            await self._load_buckets()
        except ValueError as err:
            self.app.notify(
                f"Invalid bucket name: {err}",
                severity="error",
                markup=False,
            )
        except Exception as err:
            logger.error("create_bucket failed: %s", err)
            err_msg = self.scrub(str(err))
            self.app.notify(
                f"Failed to create bucket: {err_msg}",
                severity="error",
                markup=False,
            )

    # ------------------------------------------------------------------
    # Delete bucket
    # ------------------------------------------------------------------

    def _action_delete_bucket(self) -> None:
        bucket = self._get_selected_bucket_name()
        if bucket is None:
            self.app.notify("No bucket selected", severity="warning", markup=False)
            return

        display_name = self.scrub_name(bucket)

        async def _confirm_and_delete() -> None:
            confirmed = await self.app.push_screen_wait(
                ConfirmActionScreen(
                    title="Delete Bucket",
                    description=f"Permanently delete bucket [bold]{markup_escape(display_name)}[/bold].",
                    consequences=[
                        "The bucket must be empty before it can be deleted",
                        "This operation is irreversible",
                    ],
                    confirm_text=display_name,
                    action_label="Delete Bucket",
                    severity="danger",
                )
            )
            if confirmed:
                await self._delete_bucket(bucket, display_name)

        self.run_worker(_confirm_and_delete(), exclusive=False, name="s3_delete_bucket")

    async def _delete_bucket(self, bucket: str, display_name: str) -> None:
        svc = self._get_storage_service()
        if svc is None:
            return
        try:
            await svc.delete_bucket(bucket)
            self.app.notify(
                f"Bucket '{display_name}' deleted",
                severity="information",
                markup=False,
            )
            await self._load_buckets()
        except Exception as err:
            logger.error("delete_bucket failed for %s: %s", bucket, err)
            err_msg = self.scrub(str(err))
            self.app.notify(
                f"Failed to delete bucket: {err_msg}",
                severity="error",
                markup=False,
            )

    # ------------------------------------------------------------------
    # Delete object
    # ------------------------------------------------------------------

    def _action_delete_object(self) -> None:
        info = self._get_selected_object_info()
        if info is None or info["type"] != "object":
            self.app.notify("Select an object to delete", severity="warning", markup=False)
            return

        key = info["key"]
        display_key = self.scrub_key(key)

        async def _confirm_and_delete() -> None:
            confirmed = await self.app.push_screen_wait(
                ConfirmActionScreen(
                    title="Delete Object",
                    description=f"Permanently delete [bold]{markup_escape(display_key)}[/bold].",
                    consequences=[
                        "The object will be permanently removed from the bucket",
                        "This operation is irreversible",
                    ],
                    confirm_text=display_key,
                    action_label="Delete Object",
                    severity="danger",
                )
            )
            if confirmed:
                await self._delete_object(self._current_bucket, key, display_key)

        self.run_worker(_confirm_and_delete(), exclusive=False, name="s3_delete_object")

    async def _delete_object(self, bucket: str, key: str, display_key: str) -> None:
        svc = self._get_storage_service()
        if svc is None:
            return
        try:
            await svc.delete_object(bucket, key)
            self.app.notify(
                f"Object '{display_key}' deleted",
                severity="information",
                markup=False,
            )
            await self._load_objects()
        except Exception as err:
            logger.error("delete_object failed for %s/%s: %s", bucket, key, err)
            err_msg = self.scrub(str(err))
            self.app.notify(
                f"Failed to delete object: {err_msg}",
                severity="error",
                markup=False,
            )

    # ------------------------------------------------------------------
    # Upload
    # ------------------------------------------------------------------

    def _submit_upload(self) -> None:
        local_path = self.query_one("#s3_input_upload_path", Input).value.strip()
        key = self.query_one("#s3_input_upload_key", Input).value.strip()
        if not local_path:
            self.app.notify("Local path is required", severity="error", markup=False)
            self.query_one("#s3_input_upload_path", Input).focus()
            return
        if not key:
            self.app.notify("Object key is required", severity="error", markup=False)
            self.query_one("#s3_input_upload_key", Input).focus()
            return
        self._hide_all_forms()
        self.run_worker(
            self._upload_object(self._current_bucket, key, local_path),
            exclusive=False,
            name="s3_upload",
        )

    async def _upload_object(self, bucket: str, key: str, local_path: str) -> None:
        svc = self._get_storage_service()
        if svc is None:
            return
        try:
            await svc.upload_object(bucket, key, local_path)
            display_key = self.scrub_key(key)
            self.app.notify(
                f"Uploaded to '{display_key}'",
                severity="information",
                markup=False,
            )
            await self._load_objects()
        except ValueError as err:
            self.app.notify(str(err), severity="error", markup=False)
        except Exception as err:
            logger.error("upload_object failed: %s", err)
            err_msg = self.scrub(str(err))
            self.app.notify(
                f"Upload failed: {err_msg}",
                severity="error",
                markup=False,
            )

    # ------------------------------------------------------------------
    # Download
    # ------------------------------------------------------------------

    def _submit_download(self) -> None:
        local_path = self.query_one("#s3_input_download_path", Input).value.strip()
        info = self._get_selected_object_info()
        if info is None or info["type"] != "object":
            self.app.notify("No object selected", severity="warning", markup=False)
            self._hide_all_forms()
            return
        if not local_path:
            self.app.notify("Download path is required", severity="error", markup=False)
            self.query_one("#s3_input_download_path", Input).focus()
            return
        key = info["key"]
        self._hide_all_forms()
        self.run_worker(
            self._download_object(self._current_bucket, key, local_path),
            exclusive=False,
            name="s3_download",
        )

    async def _download_object(self, bucket: str, key: str, local_path: str) -> None:
        svc = self._get_storage_service()
        if svc is None:
            return
        try:
            await svc.download_object(bucket, key, local_path)
            self.app.notify(
                f"Downloaded to '{local_path}'",
                severity="information",
                markup=False,
            )
        except ValueError as err:
            self.app.notify(str(err), severity="error", markup=False)
        except Exception as err:
            logger.error("download_object failed: %s", err)
            err_msg = self.scrub(str(err))
            self.app.notify(
                f"Download failed: {err_msg}",
                severity="error",
                markup=False,
            )

    # ------------------------------------------------------------------
    # Copy
    # ------------------------------------------------------------------

    def _submit_copy(self) -> None:
        info = self._get_selected_object_info()
        if info is None or info["type"] != "object":
            self.app.notify("No object selected", severity="warning", markup=False)
            self._hide_all_forms()
            return
        dst_bucket = self.query_one("#s3_input_copy_dst_bucket", Input).value.strip()
        dst_key = self.query_one("#s3_input_copy_dst_key", Input).value.strip()
        if not dst_bucket:
            self.app.notify("Destination bucket is required", severity="error", markup=False)
            self.query_one("#s3_input_copy_dst_bucket", Input).focus()
            return
        if not dst_key:
            self.app.notify("Destination key is required", severity="error", markup=False)
            self.query_one("#s3_input_copy_dst_key", Input).focus()
            return
        src_key = info["key"]
        self._hide_all_forms()
        self.run_worker(
            self._copy_object(self._current_bucket, src_key, dst_bucket, dst_key),
            exclusive=False,
            name="s3_copy",
        )

    async def _copy_object(
        self, src_bucket: str, src_key: str, dst_bucket: str, dst_key: str
    ) -> None:
        svc = self._get_storage_service()
        if svc is None:
            return
        try:
            await svc.copy_object(src_bucket, src_key, dst_bucket, dst_key)
            display_key = self.scrub_key(dst_key)
            self.app.notify(
                f"Copied to '{display_key}'",
                severity="information",
                markup=False,
            )
        except ValueError as err:
            self.app.notify(str(err), severity="error", markup=False)
        except Exception as err:
            logger.error("copy_object failed: %s", err)
            err_msg = self.scrub(str(err))
            self.app.notify(
                f"Copy failed: {err_msg}",
                severity="error",
                markup=False,
            )

    # ------------------------------------------------------------------
    # Move
    # ------------------------------------------------------------------

    def _submit_move(self) -> None:
        info = self._get_selected_object_info()
        if info is None or info["type"] != "object":
            self.app.notify("No object selected", severity="warning", markup=False)
            self._hide_all_forms()
            return
        dst_bucket = self.query_one("#s3_input_move_dst_bucket", Input).value.strip()
        dst_key = self.query_one("#s3_input_move_dst_key", Input).value.strip()
        if not dst_bucket:
            self.app.notify("Destination bucket is required", severity="error", markup=False)
            self.query_one("#s3_input_move_dst_bucket", Input).focus()
            return
        if not dst_key:
            self.app.notify("Destination key is required", severity="error", markup=False)
            self.query_one("#s3_input_move_dst_key", Input).focus()
            return
        src_key = info["key"]
        self._hide_all_forms()
        self.run_worker(
            self._move_object(self._current_bucket, src_key, dst_bucket, dst_key),
            exclusive=False,
            name="s3_move",
        )

    async def _move_object(
        self, src_bucket: str, src_key: str, dst_bucket: str, dst_key: str
    ) -> None:
        svc = self._get_storage_service()
        if svc is None:
            return
        try:
            await svc.move_object(src_bucket, src_key, dst_bucket, dst_key)
            display_key = self.scrub_key(dst_key)
            self.app.notify(
                f"Moved to '{display_key}'",
                severity="information",
                markup=False,
            )
            await self._load_objects()
        except ValueError as err:
            self.app.notify(str(err), severity="error", markup=False)
        except Exception as err:
            logger.error("move_object failed: %s", err)
            err_msg = self.scrub(str(err))
            self.app.notify(
                f"Move failed: {err_msg}",
                severity="error",
                markup=False,
            )

    # ------------------------------------------------------------------
    # Presigned URL
    # ------------------------------------------------------------------

    def _action_share(self) -> None:
        """Generate and display a presigned URL for the selected object."""
        if self._view != _VIEW_OBJECTS:
            self.app.notify("Open a bucket first", severity="warning", markup=False)
            return
        info = self._get_selected_object_info()
        if info is None or info["type"] != "object":
            self.app.notify("Select an object to share", severity="warning", markup=False)
            return
        key = info["key"]
        self.run_worker(
            self._generate_presigned_url(self._current_bucket, key),
            exclusive=False,
            name="s3_presign",
        )

    async def _generate_presigned_url(self, bucket: str, key: str) -> None:
        svc = self._get_storage_service()
        if svc is None:
            return
        try:
            url = await svc.generate_presigned_url(bucket, key)
            display_url = self.scrub(url)
            self._hide_all_forms()
            self.query_one("#s3_presigned_url_display", Static).update(
                markup_escape(display_url)
            )
            self.query_one("#s3_url_display").display = True
            self.app.notify(
                f"Presigned URL generated "
                f"(expires in {_PRESIGNED_EXPIRES_IN // 3600}h): {display_url}",
                severity="information",
                markup=False,
            )
        except ValueError as err:
            self.app.notify(str(err), severity="error", markup=False)
        except Exception as err:
            logger.error("generate_presigned_url failed: %s", err)
            err_msg = self.scrub(str(err))
            self.app.notify(
                f"Failed to generate presigned URL: {err_msg}",
                severity="error",
                markup=False,
            )


# ---------------------------------------------------------------------------
# Module-level utility
# ---------------------------------------------------------------------------

def _format_size(size_bytes: int) -> str:
    """Return a human-readable file size string.

    Uses float division so that partial units (e.g. 1536 bytes → 1.5 KB)
    are displayed with one decimal place of precision.  Whole-byte values
    are rendered as integers (e.g. 512 B, not 512.0 B).
    """
    if size_bytes == 0:
        return "0 B"
    value: float = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0:
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} PB"
