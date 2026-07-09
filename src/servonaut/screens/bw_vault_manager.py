"""Bitwarden SSH vault manager — fleet view of vault SSH keys.

The "manager panel like all providers" for the Bitwarden SSH picker: a
top-level screen (Header + Sidebar + DataTable + action toolbar, modeled on
:class:`servonaut.screens.aws_manager.AWSManagerScreen`) that lists the SSH-key
items in the Servonaut vault folder, **joined with the personal instances that
reference each one** and that instance's last verify status.

The join uses the *N-lookup* approach: ``list_personal_instances`` returns a
verify rollup but not each instance's ref ``item_id``, so we fan out one
``get_personal_instance_ref`` per personal instance (concurrently via
``asyncio.gather``) to learn which vault item each server points at, then group
servers under their item.

Everything is local: the item list comes from the ``bw`` CLI on this machine.
Gated to Solo / Teams.
"""

from __future__ import annotations

import asyncio
import logging
import webbrowser
from typing import Dict, List, Optional, TYPE_CHECKING

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Static

from servonaut.screens.bw_unlock_modal import BwUnlockModal
from servonaut.services.bw_errors import BwError
from servonaut.services.bw_session_service import BwAuthState, BwSessionService
from servonaut.widgets.sidebar import Sidebar

if TYPE_CHECKING:
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)

_ENTITLEMENT_FEATURE = "secrets_management"
_DEFAULT_VAULT_BASE = "https://vault.bitwarden.com"
_VERIFIED = "verified"
_FAILED_STATUSES = {"not_found", "auth_failed"}


class BwVaultManagerScreen(Screen):
    """Fleet view of Bitwarden SSH-key items joined with referencing servers."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("f5", "refresh", "Refresh", show=True),
        Binding("r", "refresh", "Refresh", show=False),
        Binding("o", "open_in_bw", "Open in BW", show=True),
        Binding("e", "edit_ref", "Manage ref", show=True),
        Binding("a", "import_keys", "Import keys", show=True),
    ]

    @property
    def app(self) -> "ServonautApp":  # type: ignore[override]
        return super().app  # type: ignore[return-value]

    def __init__(self, session_service: Optional[BwSessionService] = None) -> None:
        super().__init__()
        self._svc = session_service
        # One entry per vault item: {item_id, name, refs:[{provider, instance_id, name, verify_status}]}
        self._rows: List[dict] = []
        self._vault_base: str = _DEFAULT_VAULT_BASE
        self._loading: bool = False
        self._import_running: bool = False

    def _service(self) -> Optional[BwSessionService]:
        return self._svc or getattr(self.app, "bw_session_service", None)

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static("[bold cyan]Bitwarden SSH Vault[/bold cyan]", id="bw_vault_mgr_header"),
                Static(
                    "[dim]SSH-key items in your Servonaut vault folder, joined with the "
                    "servers that reference them. Local-only — your vault never leaves this "
                    "machine. [o] Open in Bitwarden · [e] Manage ref for the selected key.[/dim]",
                    id="bw_vault_mgr_hint",
                ),
                DataTable(id="bw_vault_mgr_table", zebra_stripes=True, cursor_type="row"),
                Static("", id="bw_vault_mgr_status"),
                Horizontal(
                    Button("Refresh (F5)", id="btn_bw_vault_refresh"),
                    Button("Open in BW (o)", id="btn_bw_vault_open"),
                    Button("Manage ref (e)", id="btn_bw_vault_edit"),
                    Button("Import keys (a)", id="btn_bw_vault_import"),
                    id="bw_vault_mgr_actions",
                ),
                id="bw_vault_mgr_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#bw_vault_mgr_table", DataTable)
        table.add_columns("Name", "Item ID", "Servers", "Verify")
        self._refresh()

    def _set_status(self, markup: str) -> None:
        try:
            self.query_one("#bw_vault_mgr_status", Static).update(markup)
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        if self._loading:
            return
        guard = getattr(self.app, "entitlement_guard", None)
        if guard is None:
            self._set_status(
                "[yellow]Sign in to Servonaut to use the Bitwarden SSH vault manager.[/yellow]"
            )
            return
        allowed, reason = guard.check(_ENTITLEMENT_FEATURE)
        if not allowed:
            self._set_status(
                f"[yellow]Upgrade required.[/yellow] The Bitwarden SSH vault is a Solo/Teams "
                f"feature. [dim]{escape(reason)}[/dim]"
            )
            return
        if self._service() is None:
            self._set_status("[red]Bitwarden session service unavailable.[/red]")
            return
        self._loading = True
        self._set_status("[dim]Loading vault items…[/dim]")
        self.run_worker(self._load(), group="bw_vault_mgr", exclusive=True, name="bw_vault_load")

    async def _load(self) -> None:
        svc = self._service()
        try:
            if svc is None:
                return
            state = await svc.status()
            if state is not BwAuthState.UNLOCKED:
                unlocked = await self.app.push_screen_wait(BwUnlockModal(svc))
                if not unlocked:
                    self._set_status("[yellow]Vault locked — unlock to view your SSH keys.[/yellow]")
                    return

            from servonaut.utils.bw_folder import resolved_bw_vault_folder
            folder = resolved_bw_vault_folder(self.app)
            folder_id = await svc.ensure_servonaut_folder(folder)
            items = await svc.list_items(folder_id=folder_id, ssh_only=True)

            refs_by_item = await self._join_referencing_instances()
            self._rows = [
                {
                    "item_id": item.id,
                    "name": item.name,
                    "refs": refs_by_item.get(item.id, []),
                }
                for item in items
            ]
            self._render_table()
            n = len(self._rows)
            linked = sum(1 for r in self._rows if r["refs"])
            self._set_status(
                f"[dim]{n} SSH key{'s' if n != 1 else ''} in “{escape(folder)}” · "
                f"{linked} referenced by a server.[/dim]"
            )
        except BwError as exc:
            self._set_status(f"[red]{escape(self._demo_safe(exc.message))}[/red]")
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load BW vault manager: %s", exc)
            self._set_status(
                f"[red]Failed to load vault items: {escape(self._demo_safe(str(exc)))}[/red]"
            )
        finally:
            self._loading = False

    def _demo_safe(self, text: str) -> str:
        """Scrub server/vault-origin error text in demo mode before display."""
        if getattr(self.app, "demo_mode", False) and getattr(self.app, "redaction_service", None):
            return self.app.redaction_service.scrub_stream(text)
        return text

    async def _join_referencing_instances(self) -> Dict[str, List[dict]]:
        """N-lookup: map each vault item_id to the personal instances referencing it.

        ``list_personal_instances`` yields a verify rollup without the ref
        ``item_id``, so we fan out one ``get_personal_instance_ref`` per instance
        (concurrently) and group the results by the resolved item id.
        """
        bw_cfg = getattr(self.app, "bw_ssh_config_service", None)
        if bw_cfg is None:
            return {}

        # Cache the vault base URL for the open-in-bw deep link while we're here.
        try:
            cfg = await bw_cfg.get_personal_config()
            if cfg:
                vault_url = (cfg.get("config") or {}).get("vault_url")
                if isinstance(vault_url, str) and vault_url.startswith(("http://", "https://")):
                    self._vault_base = vault_url.rstrip("/")
        except Exception as exc:  # noqa: BLE001
            logger.debug("vault base lookup failed: %s", exc)

        try:
            instances = await bw_cfg.list_personal_instances()
        except Exception as exc:  # noqa: BLE001
            logger.debug("list_personal_instances failed: %s", exc)
            return {}
        if not instances:
            return {}

        name_by_id = {
            str(i.get("id", "")): i.get("name", "") for i in getattr(self.app, "instances", [])
        }

        async def _ref_for(inst: dict) -> Optional[dict]:
            provider = str(inst.get("provider", "")).lower()
            instance_id = str(inst.get("instance_id", ""))
            if not provider or not instance_id:
                return None
            try:
                row = await bw_cfg.get_personal_instance_ref(provider, instance_id)
            except Exception as exc:  # noqa: BLE001
                logger.debug("ref lookup failed for %s/%s: %s", provider, instance_id, exc)
                return None
            if not row:
                return None
            ref = row.get("ssh_credential_ref") if isinstance(row, dict) else None
            item_id = ref.get("item_id") if isinstance(ref, dict) else None
            if not item_id:
                return None
            return {
                "item_id": str(item_id),
                "provider": provider,
                "instance_id": instance_id,
                "name": name_by_id.get(instance_id, instance_id),
                "verify_status": inst.get("ssh_verify_status"),
            }

        results = await asyncio.gather(*[_ref_for(i) for i in instances])
        grouped: Dict[str, List[dict]] = {}
        for ref in results:
            if ref is not None:
                grouped.setdefault(ref["item_id"], []).append(ref)
        return grouped

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render_table(self) -> None:
        try:
            table = self.query_one("#bw_vault_mgr_table", DataTable)
        except Exception:  # noqa: BLE001
            return
        table.clear()
        if not self._rows:
            table.add_row("[dim]No SSH-key items in this folder[/dim]", "", "", "", key="__empty__")
            return
        # Demo-mode: vault item names and server names can reveal real identity,
        # so scrub them before they reach the rendered row.
        demo = getattr(self.app, "demo_mode", False)
        redactor = getattr(self.app, "redaction_service", None) if demo else None
        for row in self._rows:
            name = row["name"] or ""
            if redactor is not None:
                name = redactor.scrub_stream(name) if name else name
            table.add_row(
                escape(name) or "[dim](unnamed)[/dim]",
                escape(self._short_id(row["item_id"])),
                self._servers_cell(row["refs"], redactor),
                self._verify_cell(row["refs"]),
                key=row["item_id"],
            )

    @staticmethod
    def _short_id(item_id: str) -> str:
        return f"{item_id[:8]}…" if len(item_id) > 9 else item_id

    @staticmethod
    def _servers_cell(refs: List[dict], redactor) -> str:  # noqa: ANN001
        if not refs:
            return "[dim]—[/dim]"
        names = []
        for ref in refs:
            n = ref.get("name") or ref.get("instance_id") or "?"
            if redactor is not None:
                n = redactor.scrub_stream(n)
            names.append(escape(str(n)))
        shown = ", ".join(names[:3])
        if len(names) > 3:
            shown += f" +{len(names) - 3}"
        return f"{len(refs)}: {shown}"

    @staticmethod
    def _verify_cell(refs: List[dict]) -> str:
        if not refs:
            return "[dim]—[/dim]"
        statuses = [r.get("verify_status") for r in refs]
        if all(s == _VERIFIED for s in statuses):
            return "[green]verified[/green]"
        failed = next((s for s in statuses if s in _FAILED_STATUSES), None)
        if failed is not None:
            return f"[red]{escape(str(failed))}[/red]"
        return "[yellow]unverified[/yellow]"

    # ------------------------------------------------------------------
    # Selection + actions
    # ------------------------------------------------------------------

    def _selected_row(self) -> Optional[dict]:
        try:
            table = self.query_one("#bw_vault_mgr_table", DataTable)
        except Exception:  # noqa: BLE001
            return None
        row = table.cursor_row
        if row < 0 or row >= len(self._rows):
            return None
        return self._rows[row]

    def on_button_pressed(self, event: Button.Pressed) -> None:
        mapping = {
            "btn_bw_vault_refresh": self.action_refresh,
            "btn_bw_vault_open": self.action_open_in_bw,
            "btn_bw_vault_edit": self.action_edit_ref,
            "btn_bw_vault_import": self.action_import_keys,
        }
        handler = mapping.get(event.button.id or "")
        if handler is not None:
            handler()

    def _notify_no_selection(self) -> None:
        if not self._rows:
            self.app.notify(
                "No SSH-key items to act on — add SSH keys to your vault folder, "
                "or pick one from a server's Manage/Verify SSH Ref screen.",
                severity="warning",
                markup=False,
            )
        else:
            self.app.notify("Select a key in the table first.", severity="warning", markup=False)

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self._refresh()

    def action_open_in_bw(self) -> None:
        row = self._selected_row()
        if row is None:
            self._notify_no_selection()
            return
        url = f"{self._vault_base}/#/vault?itemId={row['item_id']}"
        if not url.startswith(("http://", "https://")):
            self.app.notify(f"Open this item manually: {url}", markup=False)
            return
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            self.app.notify(f"Open this URL manually: {url}", markup=False)

    def action_edit_ref(self) -> None:
        row = self._selected_row()
        if row is None:
            self._notify_no_selection()
            return
        refs = row["refs"]
        if not refs:
            self.app.notify(
                "No server references this key yet. Attach it from a server's "
                "actions screen (Manage/Verify SSH Ref).",
                severity="warning",
                markup=False,
            )
            return
        # Manage the ref for the first referencing server.
        instance_id = refs[0]["instance_id"]
        instance = next(
            (i for i in getattr(self.app, "instances", []) if str(i.get("id", "")) == instance_id),
            None,
        )
        if instance is None:
            self.app.notify(
                "Referencing server is not in the current instance list — refresh it first.",
                severity="warning",
                markup=False,
            )
            return
        self.run_worker(self._do_edit_ref(instance), group="bw_vault_mgr", exclusive=True)

    def action_import_keys(self) -> None:
        # Same Solo/Teams gate as _refresh — the screen itself is reachable
        # from the sidebar unconditionally, so every data path must enforce it.
        guard = getattr(self.app, "entitlement_guard", None)
        if guard is None:
            self.app.notify(
                "Sign in to Servonaut to use the Bitwarden SSH vault manager.",
                severity="warning",
                markup=False,
            )
            return
        allowed, _reason = guard.check(_ENTITLEMENT_FEATURE)
        if not allowed:
            self.app.notify(
                "Upgrade required — the Bitwarden SSH vault is a Solo/Teams feature.",
                severity="warning",
                markup=False,
            )
            return
        if self._service() is None:
            self.app.notify(
                "Bitwarden session service unavailable.", severity="error", markup=False
            )
            return
        if self._import_running:
            return
        if self._loading:
            # _load may itself be resolving auth (and about to push its own
            # unlock modal); starting the import gate now would stack a second
            # unlock modal and skip the post-import refresh (_refresh
            # early-returns while _loading). Mirror of the _import_running
            # guard, in the other direction.
            self.app.notify(
                "Vault is still loading — try again in a moment.",
                severity="warning",
                markup=False,
            )
            return
        # Own group: sharing "bw_vault_mgr" with exclusive=True would cancel a
        # still-running _load, stranding an empty table on a "Loading…" status.
        self._import_running = True
        self.run_worker(self._do_import_keys(), group="bw_vault_import", exclusive=True)

    async def _do_import_keys(self) -> None:
        """Unlock → pick a directory → run the import modal → summarize."""
        from servonaut.screens.bw_dir_picker import BwDirPickerModal
        from servonaut.screens.bw_key_import import BwKeyImportModal

        try:
            svc = self._service()
            if svc is None:
                return
            state = await svc.status()
            if state is not BwAuthState.UNLOCKED:
                unlocked = await self.app.push_screen_wait(BwUnlockModal(svc))
                if not unlocked:
                    # Match the actual blocker — a fixed "locked" message would
                    # contradict the guidance the unlock modal just rendered
                    # for a missing CLI or a logged-out account.
                    if state is BwAuthState.NOT_INSTALLED:
                        message = (
                            "Bitwarden CLI not found — install it and ensure "
                            "`bw` is on your PATH to import keys."
                        )
                    elif state is BwAuthState.UNAUTHENTICATED:
                        message = (
                            "Not logged in to Bitwarden — run `bw login` in "
                            "your terminal, then retry."
                        )
                    else:
                        message = "Vault locked — unlock Bitwarden to import keys."
                    self.app.notify(message, severity="warning", markup=False)
                    return

            directory = await self.app.push_screen_wait(BwDirPickerModal())
            if directory is None:
                return

            result = await self.app.push_screen_wait(BwKeyImportModal(directory, svc))
            if result is None:
                return
            self.app.notify(
                f"Import finished: {result.get('imported', 0)} imported, "
                f"{result.get('duplicates', 0)} duplicate(s), "
                f"{result.get('skipped', 0)} skipped, "
                f"{result.get('failed', 0)} failed.",
                markup=False,
            )
            self._refresh()
        finally:
            self._import_running = False

    async def _do_edit_ref(self, instance: dict) -> None:
        from servonaut.screens.ssh_ref_editor import SshRefEditorModal

        provider = str(instance.get("provider", "aws")).lower()
        instance_id = str(instance.get("id", ""))
        bw_cfg = getattr(self.app, "bw_ssh_config_service", None)
        existing_ref = None
        if bw_cfg is not None:
            try:
                existing_ref = await bw_cfg.get_personal_instance_ref(provider, instance_id)
            except Exception as exc:  # noqa: BLE001
                logger.debug("existing ref lookup failed: %s", exc)
        changed = await self.app.push_screen_wait(
            SshRefEditorModal(instance, existing_ref=existing_ref)
        )
        if changed:
            self._refresh()
