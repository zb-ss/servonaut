"""SCP transfer screen for Servonaut v2.0."""

from __future__ import annotations
import logging
import asyncio
import posixpath
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical, Horizontal, VerticalScroll
from textual.content import Content
from textual.widgets import Footer, Static, Input, Button, RadioSet, RadioButton, LoadingIndicator
from textual.worker import Worker

from servonaut.services.bw_key_notice import BW_KEY_UNAVAILABLE, bw_key_notice, uses_bw_key
from servonaut.utils.ssh_utils import is_ssh_own_login_refusal
from servonaut.utils.markup import inert_text, single_line_text
from servonaut.utils.scp_client import remote_path_value, local_source_name
from servonaut.utils.ssh_names import SSHRefusal
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen
from servonaut.screens._demo_resolve import connection_instance, display_text, fleet_rows, team_rows
from servonaut.services.vault.display import terminal_safe
from servonaut.utils.instance_resolver import display_name
from servonaut.services.ssh_host_keys import (
    SCP_REFUSAL_EXIT_CODES,
    SSH_FAILURE_EXIT_CODE,
    HostKeyPolicy,
    HostKeyTarget,
    detect_host_key_problem,
)



def path_roles(is_upload: bool) -> tuple[str, str]:
    """The role each path plays: (this computer's, the remote server's)."""
    if is_upload:
        return "Source · This computer", "Destination · Remote server"
    return "Destination · This computer", "Source · Remote server"


logger = logging.getLogger(__name__)


def _ssh_failed(error: BaseException | None) -> bool:
    """Whether *error* is ssh failing on its own (exit 255), not a remote command."""
    return getattr(error, "returncode", None) == SSH_FAILURE_EXIT_CODE


@dataclass(frozen=True)
class FolderCollision:
    target: str
    kind: str


class SCPTransferScreen(WorkspaceScreen):
    """Screen for SCP file transfers (upload/download).

    Allows user to select direction and specify paths.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    AUTO_FOCUS = "#local_path_input"
    CHAT_REFLOW = True
    CHAT_MIN_CONTENT_WIDTH = 52
    CONTENT_NARROW_WIDTH = 88

    def __init__(self, instance: dict) -> None:
        """Initialize SCP transfer screen.

        Args:
            instance: Instance dictionary with connection details.
        """
        super().__init__()
        self._instance = instance
        self._transfer_direction = "upload"  # "upload" or "download"
        self._transfer_worker: Optional[Worker] = None
        self._status_message: str | None = None
        self._status_prefix = ''
        self._status_style = ''
        self._transfer_notice = ''

    def compose(self) -> ComposeResult:
        """Compose the SCP transfer UI."""
        yield SafeHeader()
        yield WorkspaceControls(self._workspace_context())
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            yield Container(
                Static(
                    self._banner_text(),
                    id="transfer_banner"
                ),
                Horizontal(
                    Vertical(
                        Static("Transfer direction", id="direction_label"),
                        RadioSet(
                            RadioButton("Upload (local → remote)", value=True, id="radio_upload"),
                            RadioButton("Download (remote → local)", id="radio_download"),
                            id="direction_selector"
                        ),
                        Vertical(
                            Vertical(
                                Horizontal(
                                    Static("Local path", id="local_path_label"),
                                    Static(path_roles(True)[0], id="local_path_role", classes="transfer-path-role"),
                                    classes="transfer-path-heading",
                                ),
                                Horizontal(
                                    Input(placeholder="/path/to/local/file", id="local_path_input"),
                                    Button('Browse...', id='local_path_browse'),
                                    classes='transfer-path-entry',
                                ),
                                Static('', id='local_path_summary', markup=False, classes='transfer-path-summary'),
                                id="local_path_group", classes="transfer-path-group",
                            ),
                            Vertical(
                                Horizontal(
                                    Static("Remote path", id="remote_path_label"),
                                    Static(path_roles(True)[1], id="remote_path_role", classes="transfer-path-role"),
                                    classes="transfer-path-heading",
                                ),
                                Horizontal(
                                    Input(placeholder="/path/to/remote/file", id="remote_path_input"),
                                    Button('Browse...', id='remote_path_browse'),
                                    classes='transfer-path-entry',
                                ),
                                Static('', id='remote_path_summary', markup=False, classes='transfer-path-summary'),
                                id="remote_path_group", classes="transfer-path-group",
                            ),
                            id="transfer_paths",
                        ),
                        Static(
                            "Review both paths, then choose Start transfer.",
                            id="transfer_manual_hint", markup=False,
                        ),
                        Horizontal(
                            Button("Start transfer", id="transfer_button", variant="primary"),
                            Button("Cancel", variant="default", id="cancel_button"),
                            id="button_container"
                        ),
                        id="transfer_form"
                    ),
                    VerticalScroll(
                        Static("Transfer status", id="transfer_status_title"),
                        LoadingIndicator(id="transfer_loading"),
                        Static(
                            "Ready to transfer.\n\nChoose a direction and enter both paths.",
                            id="status_output",
                        ),
                        id="transfer_result",
                    ),
                    id="transfer_workbench",
                ),
                id="transfer_container",
                classes="workspace-content",
            )
        yield Footer()

    def _display_identity(self, value: object) -> str:
        """Keep the displayed identity literal and safe when demo mode changes."""
        shown = display_text(self.app, str(value))
        redactor = getattr(self.app, "redaction_service", None)
        if getattr(self.app, "demo_mode", False) and redactor is not None:
            shown = str(redactor.scrub_stream(shown))
        return terminal_safe(shown)

    def _workspace_context(self) -> str:
        name = display_name(self._instance) or self._instance.get("id") or "server"
        return f"Transfer · {self._display_identity(name)}"

    def _banner_text(self) -> Content:
        name = self._instance.get("name") or self._instance.get("id")
        return Content.assemble(
            ('SCP file transfer', 'bold'), '\n',
            f'Instance: {self._display_identity(name)}',
        )

    def refresh_after_demo_toggle(self) -> None:
        """Redraw the existing identity widgets without rebuilding the form."""
        self.query_one("#transfer_banner", Static).update(self._banner_text())
        for controls in self.query(WorkspaceControls):
            controls.set_context(self._workspace_context())
        for side in ('local', 'remote'):
            field = self.query_one(f'#{side}_path_input', Input)
            field.password = bool(getattr(self.app, 'demo_mode', False)) or single_line_text(field.value) != field.value
        self._render_path_summaries()
        if self._status_message is not None:
            self._render_status()

    def _set_status(self, message: str, *, prefix: str = '', style: str = '') -> None:
        """Retain raw text so demo toggles can redraw without parsing markup."""
        self._status_message, self._status_prefix, self._status_style = message, prefix, style
        self._render_status()

    def _render_status(self) -> None:
        from servonaut.widgets.local_path_tree import local_display_text
        raw = self._status_message or ''
        notice = getattr(self, '_transfer_notice', '')
        if notice:
            raw += '\n\n' + notice
        shown = inert_text(self._display_identity(local_display_text(raw)))
        parts = (
            [(self._status_prefix, self._status_style), ' ', shown]
            if self._status_prefix else [(shown, self._status_style)]
        )
        self.query_one('#status_output', Static).update(Content.assemble(*parts))

    def _render_path_summaries(self) -> None:
        from servonaut.widgets.local_path_tree import local_display_path
        for side in ('local', 'remote'):
            field = self.query_one(f'#{side}_path_input', Input)
            value = field.value
            if side == 'local' and value:
                try:
                    value = local_display_path(Path(value).expanduser())
                except (ValueError, RuntimeError):
                    pass
            summary = self.query_one(f'#{side}_path_summary', Static)
            field.password = bool(getattr(self.app, 'demo_mode', False)) or single_line_text(field.value) != field.value
            summary.display = field.password
            summary.update(self.redact_path(value))

    def redact_path(self, value: str) -> str:
        """Keep display placeholders and demo redaction separate from raw paths."""
        from servonaut.widgets.local_path_tree import local_display_text
        return self._display_identity(single_line_text(local_display_text(value)))

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id in {'local_path_input', 'remote_path_input'}:
            self._render_path_summaries()

    def on_mount(self) -> None:
        """Focus local path input when mounted."""
        local_input = self.query_one("#local_path_input", Input)
        local_input.focus()
        self.refresh_after_demo_toggle()
        self._update_path_roles()

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Handle direction selection change.

        Args:
            event: RadioSet changed event.
        """
        if event.radio_set.id == "direction_selector":
            selected = event.pressed
            if selected.id == "radio_upload":
                self._transfer_direction = "upload"
                self.app.notify(f"Direction: {selected.label}", severity="information")
            elif selected.id == "radio_download":
                self._transfer_direction = "download"
                self.app.notify(f"Direction: {selected.label}", severity="information")
            self._update_path_roles()

    def _update_path_roles(self) -> None:
        upload = self._transfer_direction == 'upload'
        for side, role in zip(('local', 'remote'), path_roles(upload)):
            self.query_one(f'#{side}_path_role', Static).update(role)
            self.query_one(f'#{side}_path_browse', Button).tooltip = f'Browse {role}'
        source, destination = ('local', 'remote') if upload else ('remote', 'local')
        self.query_one('#transfer_paths').move_child(
            self.query_one(f'#{source}_path_group'), before=self.query_one(f'#{destination}_path_group'),
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events.

        Args:
            event: Button pressed event.
        """
        if event.button.id == "transfer_button":
            self._start_transfer()
        elif event.button.id == "cancel_button":
            self.action_back()
        elif event.button.id in {'local_path_browse', 'remote_path_browse'}:
            self._browse_path(event.button.id.split('_', 1)[0])

    def _set_form_busy(self, busy: bool) -> None:
        for selector in (
            '#local_path_input', '#remote_path_input', '#local_path_browse',
            '#remote_path_browse', '#direction_selector', '#transfer_button',
        ):
            self.query_one(selector).disabled = busy

    def _browse_path(self, side: str) -> None:
        from servonaut.screens.path_picker import LocalPathPickerModal
        field = self.query_one(f'#{side}_path_input', Input)
        source = (side == 'local') == (self._transfer_direction == 'upload')
        if side == 'local':
            self.app.push_screen(
                LocalPathPickerModal(field.value, source=source),
                lambda result: self._apply_picker_result(side, result),
            )
        else:
            self._transfer_notice = ''
            self._set_form_busy(True)
            self.query_one('#transfer_loading', LoadingIndicator).display = True
            self._set_status('Preparing remote browser...')
            self.run_worker(self._browse_remote(source, field.value), name='scp_browse', group='scp_browse', exclusive=True, exit_on_error=False)

    def _apply_picker_result(self, side: str, result: str | None) -> None:
        if self.is_attached:
            field = self.query_one(f'#{side}_path_input', Input)
            if result is not None:
                field.value = result
            self.call_after_refresh(field.focus)

    async def _browse_remote(self, source: bool, path: str) -> None:
        from servonaut.screens.path_picker import RemotePathPickerModal, remote_parent
        from servonaut.screens.file_browser import get_scan_paths_for_instance
        from servonaut.services.remote_paths import remote_path_kind
        conn = connection_instance(self.app, self._instance)
        options = await self._resolved_transfer_options(conn)
        root = path or get_scan_paths_for_instance(self.app.config_manager.get(), conn)[0]
        if path and await remote_path_kind(self.app, options, path) != 'directory':
            root = remote_parent(path)
        result = await self.app.push_screen_wait(RemotePathPickerModal(
            conn, source=source, root=root, options=options,
            bw_key_reason=getattr(self, "_bw_key_reason", None),
        ))
        self._set_form_busy(False)
        self._apply_picker_result('remote', result)

    def _start_transfer(self) -> None:
        """Start SCP transfer based on current form inputs."""
        import logging
        from pathlib import Path

        logger = logging.getLogger(__name__)
        local_path_input = self.query_one("#local_path_input", Input)
        remote_path_input = self.query_one("#remote_path_input", Input)

        local_path = local_path_input.value
        remote_path = remote_path_input.value
        self._transfer_notice = ''

        # Validate inputs
        if not local_path.strip():
            self.app.notify("Please enter a local path", severity="warning")
            local_path_input.focus()
            return

        if not remote_path.strip():
            self.app.notify("Please enter a remote path", severity="warning")
            remote_path_input.focus()
            return

        # For uploads, validate local path exists
        if self._transfer_direction == "upload":
            try:
                exists = Path(local_path).expanduser().exists()
            except (OSError, ValueError, RuntimeError):
                exists = False
            if not exists:
                shown = self.redact_path(local_path)
                self.app.notify(f"Local path not found: {shown}", severity="error", markup=False)
                logger.error("Upload failed: local path does not exist: %s", shown)
                self._set_status(f'Local path not found: {local_path}', prefix='Error:', style='$text-error')
                return

        # Update status
        self._set_status(f'Preparing {self._transfer_direction}...', style='$text-warning')

        # Demo mode redacts the row we display, so transfer against the real
        # record.
        conn = connection_instance(self.app, self._instance)

        # Execute transfer in worker
        self.query_one("#transfer_loading", LoadingIndicator).display = True
        self._set_form_busy(True)
        self._set_status('Checking source and destination...')
        self._transfer_worker = self.run_worker(
            self._transfer(conn, local_path, remote_path),
            name="scp_transfer",
            group='scp_transfer',
            exclusive=True,
            # A refused vault credential is reported as the worker's error.
            exit_on_error=False,
        )

    async def _transfer(self, conn: dict, local_path: str, remote_path: str):
        """Run the transfer with the server's vault credential when it has one."""
        from servonaut.services.remote_paths import remote_path_kind
        from servonaut.screens.scp_folder_confirm import SCPFolderConfirmModal
        remote_path = remote_path_value(remote_path)
        options = await self._resolved_transfer_options(conn)
        if self._transfer_direction == 'upload':
            local = Path(local_path).expanduser()
            recursive = await asyncio.to_thread(local.is_dir)
            if not recursive and not await asyncio.to_thread(local.is_file):
                raise ValueError('Choose a regular file or folder to upload')
        else:
            try:
                kind = await remote_path_kind(self.app, options, remote_path)
            except (OSError, RuntimeError) as error:
                logger.warning('Folder detection unavailable: %s', error)
                self._transfer_notice = 'Folder detection was unavailable. This copy uses single-file mode.'
                kind = 'file'
            if kind not in {'file', 'directory'}:
                raise ValueError(f'No such file or readable folder: {remote_path}')
            recursive = kind == 'directory'
        self._transfer_kind = 'folder' if recursive else 'file'
        self._set_status(f'Preparing {self._transfer_kind} transfer...')
        collision = await self._folder_collision(options, local_path, remote_path) if recursive else None
        if collision:
            if not await self.app.push_screen_wait(SCPFolderConfirmModal(target=collision.target, kind=collision.kind)):
                return None
        self._set_status(f'Transferring {self._transfer_kind}...')
        command = self._command_for(options, local_path, remote_path, recursive=recursive)
        return await self.app.scp_service.execute_transfer(command)

    async def _folder_collision(self, options: dict, local_path: str, remote_path: str) -> FolderCollision | None:
        from servonaut.services.remote_paths import remote_path_kind, remote_home_basename
        local = Path(local_path).expanduser()
        remote_path = remote_path_value(remote_path)
        if self._transfer_direction == 'upload':
            target = remote_path
            try:
                kind = await remote_path_kind(self.app, options, remote_path)
                if kind == 'directory':
                    target = posixpath.join(remote_path, local_source_name(local_path))
                    kind = await remote_path_kind(self.app, options, target)
                return None if kind == 'missing' else FolderCollision(target, kind)
            except (OSError, RuntimeError) as error:
                logger.warning('Could not inspect folder destination %s: %s', target, error)
                self._transfer_notice = 'Folder detection was unavailable. The destination could not be checked.'
                return FolderCollision(target, 'unknown')
        basename = posixpath.basename(remote_path.rstrip('/')) or '.'
        if remote_path.rstrip('/') in {'~', '$HOME', '${HOME}'}:
            try:
                basename = await remote_home_basename(self.app, options)
            except (OSError, RuntimeError) as error:
                logger.warning('Could not inspect source home folder: %s', error)
                self._transfer_notice = 'Folder detection was unavailable. The destination could not be checked.'
                return FolderCollision(str(local), 'unknown')
        def inspect() -> FolderCollision | None:
            target = local / basename if local.is_dir() else local
            if not target.exists() and not target.is_symlink():
                return None
            kind = 'directory' if target.is_dir() else 'file' if target.is_file() else 'other'
            return FolderCollision(str(target), kind)
        return await asyncio.to_thread(inspect)

    async def _vault_transfer_command(
        self, conn: dict, local_path: str, remote_path: str,
    ) -> List[str]:
        """:meth:`_build_transfer_command` with the server's vault credential applied.

        Raises:
            VaultCredentialError: the server's vault credential cannot be used.
        """
        return self._command_for(await self._resolved_transfer_options(conn), local_path, remote_path)

    async def _resolved_transfer_options(self, conn: dict) -> dict:
        """Resolve once for browsing, preflight checks and the actual copy."""
        from servonaut.services.ssh_credentials import resolve_with_vault, ssh_identity_kwargs

        options = self._transfer_options(conn)
        resolved = await resolve_with_vault(
            options, conn,
            vault_runtime=getattr(self.app, "vault_command_service", None),
            connection_service=self.app.connection_service,
            cache=getattr(self.app, "vault_lease_cache", None),
            team_rows=team_rows(self.app),
            rows=fleet_rows(self.app),
            bw_keys=getattr(self.app, "bw_ssh_keys", None),
        )
        self._bw_key_reason = resolved.get(BW_KEY_UNAVAILABLE)
        # Kept for a refused login (see _bw_auth_notice); never splatted into a builder.
        self._bw_resolved = dict(resolved)
        if resolved.get("identity_agent") is None:
            # No vault key for the server: its hop may still use the bastion's,
            # and its key may be the server's Bitwarden one.
            options = {**options, "proxy_args": resolved.get("proxy_args", options.get("proxy_args"))}
            if uses_bw_key(resolved):
                options["key_path"] = resolved.get("key_path")
            return options
        options = {
            **{key: resolved.get(key) for key in options},
            **{key: value for key, value in ssh_identity_kwargs(resolved).items() if value},
        }
        self._host_key_target = HostKeyTarget.for_connection(
            options['host'], options['port'], instance=conn,
            profile=self.app.connection_service.resolve_profile(conn),
        )
        return options

    def _bw_auth_notice(self, error_text: str, *, ssh_failed: bool) -> Optional[str]:
        """The Bitwarden cause when ssh refused the login and the server's Bitwarden key was not used.

        *ssh_failed*: ssh or scp exited with its own failure code; with it,
        only ssh's own refusal line counts (a remote error can contain the
        same words). A refusal of the server's Bitwarden key also has it read
        again on the next transfer (which resolves again).
        """
        if not is_ssh_own_login_refusal(error_text or "", ssh_failed=ssh_failed):
            return None
        key_refused = getattr(getattr(self.app, "bw_ssh_keys", None), "key_refused", None)
        if callable(key_refused):
            key_refused(getattr(self, "_bw_resolved", None) or {})
        return bw_key_notice(getattr(self, "_bw_key_reason", None))

    def _build_transfer_command(
        self, conn: dict, local_path: str, remote_path: str,
    ) -> List[str]:
        """Build the scp argv for *conn* in the selected direction (local keys).

        Custom servers use their own username, key and port, as the other
        connect paths do; everything else takes the username from the
        connection profile or the configured default.
        """
        return self._command_for(self._transfer_options(conn), local_path, remote_path)

    def _transfer_options(self, conn: dict) -> dict:
        """Host, user, key, proxy, port and options for *conn* (local keys)."""
        connection_service = self.app.connection_service
        profile = connection_service.resolve_profile(conn)

        if conn.get('is_shared') is True:
            from servonaut.services.shared_servers import shared_login

            username = shared_login(conn, profile, self.app.config_manager.get().default_username)
            key_path = None
        elif conn.get('is_custom'):
            username = conn.get('username') or 'root'
            key_path = conn.get('ssh_key') or None
        else:
            username = (
                (profile.username if profile else None)
                or self.app.config_manager.get().default_username
            )
            key_path = None
        # Per-instance / default key, then ~/.ssh discovery, as before.
        key_path = key_path or self.app.ssh_service.get_key_path(conn['id'])
        if not key_path and conn.get('key_name'):
            key_path = self.app.ssh_service.discover_key(conn['key_name'])

        options = {
            'host': connection_service.get_target_host(conn, profile),
            'username': username,
            'key_path': key_path,
            'proxy_args': connection_service.get_proxy_args(profile) if profile else [],
            'port': connection_service.get_target_port(conn),
            'extra_options': connection_service.get_extra_options(conn, profile),
        }
        # What a genuine host-key refusal for this transfer can name.
        self._host_key_target = HostKeyTarget.for_connection(
            options['host'], options['port'], instance=conn, profile=profile,
        )
        return options

    def _command_for(self, options: dict, local_path: str, remote_path: str, *, recursive: bool = False) -> List[str]:
        """The scp argv for *options* in the selected direction."""
        if recursive:
            options = {**options, 'recursive': True}
        if self._transfer_direction == "upload":
            return self.app.scp_service.build_upload_command(
                local_path=local_path, remote_path=remote_path, **options,
            )
        return self.app.scp_service.build_download_command(
            remote_path=remote_path, local_path=local_path, **options,
        )

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        """Handle worker state changes.

        Args:
            event: Worker state changed event.
        """
        if event.worker.name == 'scp_browse' and event.worker.is_finished:
            self._set_form_busy(False)
            self.query_one('#transfer_loading', LoadingIndicator).display = False
            from servonaut.services.remote_paths import path_error_message
            if event.worker.error:
                logger.warning('Remote browser preparation failed: %s', event.worker.error)
            if event.worker.error:
                status = self._bw_auth_notice(
                    str(event.worker.error), ssh_failed=_ssh_failed(event.worker.error),
                ) or path_error_message(str(event.worker.error))
            else:
                status = 'Ready to transfer.'
            self._set_status(status)
            self.query_one('#remote_path_input', Input).focus()
        if event.worker.name == "scp_transfer":
            # An exclusive restart cancels its predecessor. Only the active
            # worker may replace the new transfer's progress or result.
            if event.worker is not getattr(self, "_transfer_worker", event.worker):
                return
            if event.worker.is_finished:
                self._set_form_busy(False)
                self.query_one("#transfer_loading", LoadingIndicator).display = False
                if getattr(event.worker, "is_cancelled", False):
                    self._set_status('Transfer cancelled.')
                    return

                def _s(x: str) -> str:
                    return self.redact_path(x)

                if isinstance(event.worker.error, SSHRefusal):
                    # A connection Servonaut will not start: say why, as it is.
                    raw_error = str(event.worker.error)
                    error_msg = _s(raw_error)
                    logger.warning("SCP transfer refused: %s", error_msg)
                    self._set_status(raw_error, style='$text-error')
                    self.app.notify(error_msg, severity="error", markup=False)
                elif event.worker.error:
                    raw_error = str(event.worker.error)
                    raw_error = self._bw_auth_notice(
                        raw_error, ssh_failed=_ssh_failed(event.worker.error),
                    ) or raw_error
                    error_msg = _s(raw_error)
                    self._set_status(raw_error, prefix='Transfer failed:', style='$text-error')
                    self.app.notify(f"Transfer failed: {error_msg}", severity="error", markup=False)
                else:
                    if event.worker.result is None:
                        self._set_status('Transfer cancelled.')
                        return
                    returncode, stdout, stderr = event.worker.result

                    if returncode == 0:
                        kind = getattr(self, '_transfer_kind', 'file').capitalize()
                        self._set_status(f'{kind} transfer completed successfully!', style='$text-success')
                        self.app.notify("Transfer completed", severity="information")
                    else:
                        # A refused host key gets the one-line explanation
                        # instead of OpenSSH's full warning banner.
                        target = getattr(self, "_host_key_target", None)
                        # scp has no private log; legacy scp exits 1.
                        problem = target and detect_host_key_problem(
                            stderr or "", returncode, target,
                            HostKeyPolicy.from_ssh_config(self.app.config_manager.get().ssh),
                            stdout=stdout, exit_codes=SCP_REFUSAL_EXIT_CODES,
                        )
                        raw_error = problem.message if problem else (stderr or 'Unknown error')
                        if not problem:
                            raw_error = self._bw_auth_notice(
                                stderr or '', ssh_failed=returncode in SCP_REFUSAL_EXIT_CODES,
                            ) or raw_error
                        error_msg = _s(raw_error)
                        self._set_status(raw_error, prefix='Transfer failed:', style='$text-error')
                        self.app.notify(
                            f"Transfer failed: {error_msg}", severity="error", markup=False,
                        )

    def action_back(self) -> None:
        """Navigate back to previous screen."""
        self.app.pop_screen()
