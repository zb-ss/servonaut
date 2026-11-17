"""Native composite access dialogs with explicit, hermetic service boundaries."""

from __future__ import annotations

import asyncio
import hashlib
import socket
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, create_autospec

import keyring
import pytest
from textual.app import App, ComposeResult
from textual.pilot import Pilot
from textual.widgets import Button, Collapsible, DataTable, DirectoryTree, Input, SelectionList, Static
from textual.widgets._toast import Toast

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from servonaut.screens import bw_key_import, vault_import_modal
from servonaut.screens.bw_dir_picker import BwDirPickerModal
from servonaut.screens.bw_item_picker import BwItemPickerModal
from servonaut.screens.bw_key_import import BwKeyImportModal
from servonaut.screens.bw_passphrase_modal import BwPassphraseModal
from servonaut.screens.bw_unlock_modal import BwUnlockModal
from servonaut.screens.ssh_ref_editor import SshRefEditorModal
from servonaut.screens.vault_import_modal import VaultImportModal
from servonaut.services.api_client import APIError
from servonaut.services.auth_service import AuthService
from servonaut.services.bw_key_import import DecryptedKey, KeyImportError, ScannedKey, WrongPassphraseError
from servonaut.services.bw_resolver import BwResolver
from servonaut.services.bw_session_service import BwAuthState, BwItemSummary, BwSessionService
from servonaut.services.bw_ssh_config_service import BITWARDEN_PM_PROVIDER, BwSshConfigService
from servonaut.services.vault.command_service import VaultCommandService
from servonaut.styles import CSS_FILES
from servonaut.styles.themes import SERVONAUT_THEMES
from servonaut.widgets.dialogs import DialogFrame
from tests._async_bounds import wait_until


KINDS = ("directory", "picker", "bw_import", "reference", "vault_import")
THEMES = ("servonaut", "servonaut-light", "ansi-dark", "ansi-light")
SIZES = ((100, 30), (160, 50))
NAME = "café [literal] Ω"
ROW = {"id": "web-1", "name": NAME, "provider": "AWS"}
# Populate only from hash-bound original native observations.
ORIGINAL_FOCUS: dict[tuple[str, tuple[int, int]], str | None] | None = {
    ('directory', (100, 30)): 'bw_dir_tree',
    ('directory', (160, 50)): 'bw_dir_tree',
    ('picker', (100, 30)): 'bw_picker_search',
    ('picker', (160, 50)): 'bw_picker_search',
    ('bw_import', (100, 30)): 'bw_import_list',
    ('bw_import', (160, 50)): 'bw_import_list',
    ('reference', (100, 30)): 'pick_btn',
    ('reference', (160, 50)): 'pick_btn',
    ('vault_import', (100, 30)): 'vault_import_local',
    ('vault_import', (160, 50)): 'vault_import_local',
}
ORIGINAL_NOTICE_CONTROLS: dict[tuple[str, tuple[int, int]], bool] | None = {
    ('directory', (100, 30)): False,
    ('directory', (160, 50)): True,
    ('picker', (100, 30)): False,
    ('picker', (160, 50)): True,
    ('bw_import', (100, 30)): False,
    ('bw_import', (160, 50)): True,
    ('reference', (100, 30)): True,
    ('reference', (160, 50)): True,
    ('vault_import', (100, 30)): True,
    ('vault_import', (160, 50)): True,
}
_CANCEL = {"directory": "bw_dir_cancel_btn", "picker": "bw_picker_cancel", "bw_import": "bw_import_cancel_btn", "reference": "cancel_btn", "vault_import": "vault_import_cancel"}
_CONTROLS = {
    "directory": ("bw_dir_input", "bw_dir_cancel_btn", "bw_dir_select_btn"),
    "picker": ("bw_picker_search", "bw_picker_folder_toggle", "bw_picker_cancel"),
    "bw_import": ("bw_import_status", "bw_import_cancel_btn", "bw_import_btn"),
    "reference": ("pick_btn", "cancel_btn", "save_btn"),
    "vault_import": ("vault_import_local", "vault_import_bitwarden", "vault_import_status", "vault_import_cancel", "vault_import_confirm"),
}


def _refuse(trips: list[str], name: str):
    def refused(*_args, **_kwargs):
        trips.append(name)
        raise AssertionError("Unexpected access-dialog boundary: " + name)
    return refused


def _service(spec, trips: list[str]):
    """Default every real API method to refusal, rather than auto-mock success."""
    fake = create_autospec(spec, instance=True, spec_set=True)
    for name in dir(spec):
        member = getattr(fake, name, None)
        if isinstance(member, (AsyncMock, Mock)) and not name.startswith("__"):
            member.side_effect = _refuse(trips, spec.__name__ + "." + name)
    return fake


def _returns(method, value) -> None:
    method.side_effect = None
    method.return_value = value


@dataclass
class _Boundaries:
    home: Path
    bw: object
    refs: object
    vault: object
    resolver: object
    keys: list[ScannedKey]
    scans: dict[str, Mock]
    trips: list[str]
    gates: list[threading.Event] = field(default_factory=list)
    browsers: list[str] = field(default_factory=list)
    transient: list[bytearray] = field(default_factory=list)
    import_metadata: list[dict] = field(default_factory=list)


@pytest.fixture
def boundaries(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    trips: list[str] = []
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    for name in ("BW_SESSION", "NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / ".ssh").mkdir()
    # Native DirectoryTree can enumerate this isolated HOME, never the real home.
    for index in range(45):
        (tmp_path / f"directory-{index:02d}").mkdir()
    for name in ("get_password", "set_password", "delete_password", "get_credential"):
        monkeypatch.setattr(keyring, name, _refuse(trips, "keyring." + name))
    monkeypatch.setattr(subprocess, "run", _refuse(trips, "subprocess.run"))
    monkeypatch.setattr(subprocess, "Popen", _refuse(trips, "subprocess.Popen"))
    monkeypatch.setattr(socket, "create_connection", _refuse(trips, "socket.create_connection"))
    monkeypatch.setattr(socket.socket, "connect", _refuse(trips, "socket.connect"))
    monkeypatch.setattr(asyncio.BaseEventLoop, "create_connection", AsyncMock(side_effect=_refuse(trips, "loop.create_connection")))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(side_effect=_refuse(trips, "asyncio.process")))
    monkeypatch.setattr(ConfigManager, "load", _refuse(trips, "config.load"))
    for name in ("_load_token", "_load_token_from_disk_silent"):
        monkeypatch.setattr(AuthService, name, _refuse(trips, "auth." + name))
    import webbrowser
    monkeypatch.setattr(webbrowser, "open", _refuse(trips, "browser.open"))
    bw = _service(BwSessionService, trips)
    refs = _service(BwSshConfigService, trips)
    vault = _service(VaultCommandService, trips)
    resolver = _service(BwResolver, trips)
    monkeypatch.setattr(BwSessionService, "_run", AsyncMock(side_effect=_refuse(trips, "bw._run")))
    _returns(bw.status, BwAuthState.UNLOCKED)
    _returns(bw.ensure_servonaut_folder, "folder-1")
    _returns(bw.list_items, [BwItemSummary(id="item-1", name=NAME, type=5, has_ssh_key=True)])
    _returns(bw.sync_now, None)
    _returns(refs.get_personal_config, {"config": {}})
    keys = [ScannedKey(tmp_path / ".ssh" / f"key-{i:02d}", f"key-{i:02d} {NAME}", False, fingerprint=f"SHA256:fixture{i}") for i in range(45)]
    scans = {}
    for module in (bw_key_import, vault_import_modal):
        scanner = create_autospec(module.scan_directory, return_value=keys)
        scans[module.__name__] = scanner
        monkeypatch.setattr(module, "scan_directory", scanner)
        for name in ("read_key_bytes", "load_unencrypted_key", "decrypt_private_key"):
            monkeypatch.setattr(module, name, create_autospec(getattr(module, name), side_effect=_refuse(trips, module.__name__ + "." + name)))
    # Dedupe listing for BW import must be empty; individual picker hosts seed rows.
    _returns(bw.list_items, [])
    value = _Boundaries(tmp_path, bw, refs, vault, resolver, keys, scans, trips)
    yield value
    for gate in value.gates:
        gate.set()
    assert trips == [], "A swallowed boundary refusal occurred: " + repr(trips)


class _Host(App):
    CSS_PATH = CSS_FILES

    def __init__(self, boundaries: _Boundaries, theme: str = "servonaut") -> None:
        super().__init__()
        self.boundaries = boundaries
        self.bw_session_service = boundaries.bw
        self.bw_ssh_config_service = boundaries.refs
        self.entitlement_guard = SimpleNamespace(check=Mock(return_value=(True, "OK")))
        self.config_manager = SimpleNamespace(get=lambda: AppConfig(bw_vault_folder="Example"))
        self.demo_mode = False
        self.redaction_service = None
        for registered in SERVONAUT_THEMES:
            self.register_theme(registered)
        self.theme = theme
        self.animation_level = "none"

    def compose(self) -> ComposeResult:
        yield Input(id="origin")


def _modal(kind: str, b: _Boundaries):
    if kind == "directory":
        return BwDirPickerModal()
    if kind == "picker":
        _returns(b.bw.list_items, [BwItemSummary(id=f"item-{i:02d}", name=f"{NAME} {i:02d}", type=5, has_ssh_key=True) for i in range(45)])
        return BwItemPickerModal(session_service=b.bw)
    if kind == "bw_import":
        return BwKeyImportModal(b.home / ".ssh", session_service=b.bw)
    if kind == "reference":
        return SshRefEditorModal(ROW)
    return VaultImportModal(b.vault, "vault-1", b.home / ".ssh", session_service=b.bw, resolver=b.resolver)


async def _open(app: _Host, pilot: Pilot, screen, results: list) -> None:
    app.query_one("#origin", Input).focus()
    await app.push_screen(screen, results.append)
    if isinstance(screen, BwItemPickerModal):
        await wait_until(lambda: bool(screen.query("#bw_picker_table")) or bool(screen.query("#bw_picker_close")))
    if isinstance(screen, BwKeyImportModal):
        await wait_until(lambda: screen._scan_complete)
    await pilot.pause()


def _painted(app: App, widget) -> str:
    rows = app.screen._compositor.render_strips()
    region = widget.region.intersection(app.screen.region)
    return "\n".join(rows[y].crop(region.x, region.right).text for y in range(region.y, region.bottom))


def _exposed(app: App, screen, widget) -> None:
    """Full simultaneous native regions and row hits; never scroll each target."""
    frame = screen.query_one(DialogFrame)
    assert widget.region.width > 0 and widget.region.height > 0
    assert frame.content_region.contains_region(widget.region)
    assert screen.region.contains_region(widget.region)
    for y in range(widget.region.y, widget.region.bottom):
        hit = app.get_widget_at(widget.region.x + widget.region.width // 2, y)[0]
        assert hit is widget or widget in hit.ancestors
    if isinstance(widget, Button):
        assert widget.label.plain in _painted(app, widget)


def _controls(app: App, screen, kind: str) -> dict:
    widgets = [screen.query_one("#" + name) for name in _CONTROLS[kind]]
    for widget in widgets:
        _exposed(app, screen, widget)
    return {widget.id: widget.region for widget in widgets}


async def _click(app: App, pilot: Pilot, screen, widget_id: str) -> None:
    button = screen.query_one("#" + widget_id, Button)
    _exposed(app, screen, button)
    assert await pilot.click(button)
    await pilot.pause()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", SIZES)
async def test_native_long_body_keeps_controls_stationary_and_literal(kind, theme, size, boundaries):
    app = _Host(boundaries, theme)
    screen = _modal(kind, boundaries)
    async with app.run_test(size=size) as pilot:
        await _open(app, pilot, screen, [])
        if kind == "vault_import":
            await _click(app, pilot, screen, "vault_import_local")
            await wait_until(lambda: screen._source == "ssh" and not screen._loading)
        before = _controls(app, screen, kind)
        if kind == "reference":
            collapsible = screen.query_one(Collapsible)
            assert await pilot.click(collapsible.query_one("CollapsibleTitle"))
            await pilot.pause()
            body = screen.query_one("#ssh_ref_fields")
            fields = [screen.query_one("#" + name, Input) for name in ("item_id", "collection_id", "vault_url")]
            footer = {name: before[name] for name in ("cancel_btn", "save_btn")}
            body.focus()
            await pilot.press("home")
            await pilot.pause()
            start, maximum = body.scroll_y, body.max_scroll_y
            assert start == 0
            if maximum > 0:
                await pilot.press("end")
                await pilot.pause()
                assert body.scroll_y > start and body.scroll_y == maximum
                assert body.max_scroll_y == maximum
                _exposed(app, screen, fields[-1])
            else:
                assert size == (160, 50), "The narrow expanded form must exercise its native scroll path"
                for widget in fields:
                    _exposed(app, screen, widget)
            for name, region in footer.items():
                assert screen.query_one("#" + name).region == region
                _exposed(app, screen, screen.query_one("#" + name))
            # Tab, rather than direct field focus or per-field scroll calls,
            # must reveal the canonical inputs in their original order.
            for _ in range(16):
                await pilot.press("tab")
                await pilot.pause()
                if screen.focused is fields[0]:
                    break
            assert screen.focused is fields[0], "Native Tab never reached Item ID"
            for index, widget in enumerate(fields):
                if index:
                    await pilot.press("tab")
                    await pilot.pause()
                assert screen.focused is widget
                _exposed(app, screen, widget)
                for name, region in footer.items():
                    assert screen.query_one("#" + name).region == region
                    _exposed(app, screen, screen.query_one("#" + name))
        else:
            selector = {"directory": "#bw_dir_tree", "picker": "#bw_picker_table", "bw_import": "#bw_import_list", "vault_import": "#vault_import_list"}[kind]
            body = screen.query_one(selector)
            if kind == "directory":
                await wait_until(lambda: len(body.root.children) >= 45)
                body.root.expand()
                await pilot.pause()
            body.focus()
            await wait_until(lambda: app.focused is body)
            start = body.scroll_y
            # DataTable End moves horizontally; Ctrl+End reaches its last row.
            await pilot.press("ctrl+end" if kind == "picker" else "end")
            await pilot.pause()
            assert body.max_scroll_y > 0 and body.scroll_y > start
            assert body.scroll_y == body.max_scroll_y
            last = "directory-44" if kind == "directory" else (f"{NAME} 44" if kind == "picker" else f"key-44 {NAME}")
            assert last in _painted(app, body)
        # Pick remains inside the scrollable Ref body; footer actions never move.
        after = _controls(app, screen, kind) if kind != "reference" else {name: screen.query_one("#" + name).region for name in ("cancel_btn", "save_btn")}
        for name, region in after.items():
            assert region == before[name]
            _exposed(app, screen, screen.query_one("#" + name))


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("size", SIZES)
async def test_initial_focus_matches_hash_bound_original_native_record(kind, size, boundaries):
    assert ORIGINAL_FOCUS is not None, "Original focus must be qualified before claiming preservation"
    app = _Host(boundaries)
    screen = _modal(kind, boundaries)
    async with app.run_test(size=size) as pilot:
        await _open(app, pilot, screen, [])
        assert (screen.focused.id if screen.focused else None) == ORIGINAL_FOCUS[kind, size]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("size", SIZES)
async def test_original_notification_lane_does_not_hide_controls(kind, size, boundaries):
    assert ORIGINAL_NOTICE_CONTROLS is not None, "Characterize original Toast/control geometry before changing any lane"
    # Reference overlap was measured; current controls must remain exposed.
    assert isinstance(ORIGINAL_NOTICE_CONTROLS[kind, size], bool), "Qualify original notification geometry as boolean data"
    app = _Host(boundaries)
    screen = _modal(kind, boundaries)
    async with app.run_test(size=size, notifications=True) as pilot:
        await _open(app, pilot, screen, [])
        before = _controls(app, screen, kind)
        app.notify("Literal [notice] café Ω", markup=False, timeout=60)
        await wait_until(lambda: bool(app.screen.query(Toast)))
        await pilot.pause()
        assert _controls(app, screen, kind) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("mode", ["click", "escape"])
async def test_idle_cancel_returns_exact_result_and_restores_origin(kind, mode, boundaries):
    app = _Host(boundaries)
    screen = _modal(kind, boundaries)
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, screen, results)
        if mode == "click":
            await _click(app, pilot, screen, _CANCEL[kind])
        else:
            await pilot.press("escape")
        await wait_until(lambda: app.screen is not screen)
        assert results == [False if kind == "reference" else None]
        assert app.focused is app.query_one("#origin", Input)


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", ["", "missing-directory", "~nonexistent-example-user/path"])
async def test_invalid_directory_keeps_input_and_actions_visible(raw, boundaries):
    app = _Host(boundaries)
    screen = BwDirPickerModal()
    results = []
    async with app.run_test(size=(100, 30), notifications=True) as pilot:
        await _open(app, pilot, screen, results)
        screen.query_one("#bw_dir_input", Input).value = raw
        await _click(app, pilot, screen, "bw_dir_select_btn")
        await wait_until(lambda: bool(screen.query(Toast)))
        assert "Not a directory: " + (raw or "(empty)") in " ".join(_painted(app, screen.query_one(Toast)).split())
        _controls(app, screen, "directory")
        assert results == [] and app.screen is screen


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["enter", "click"])
async def test_native_directory_selection_retains_functional_path_in_demo(mode, boundaries):
    app = _Host(boundaries)
    app.demo_mode = True
    app.redaction_service = SimpleNamespace(scrub_stream=lambda value: value)
    screen = BwDirPickerModal()
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, screen, results)
        tree = screen.query_one(DirectoryTree)
        await wait_until(lambda: bool(tree.root.children))
        tree.focus()
        await pilot.press("home", "enter")
        await pilot.pause()
        path_input = screen.query_one("#bw_dir_input", Input)
        assert path_input.value == "~"
        _exposed(app, screen, path_input)
        if mode == "enter":
            path_input.focus()
            await pilot.press("enter")
        else:
            await _click(app, pilot, screen, "bw_dir_select_btn")
        await wait_until(lambda: bool(results))
        assert results == [boundaries.home]


@pytest.mark.asyncio
@pytest.mark.parametrize("allowed,available,failed", [(False, True, False), (True, False, False), (True, True, True)])
async def test_picker_gate_or_service_failure_has_native_close_without_mutation(allowed, available, failed, boundaries):
    app = _Host(boundaries)
    app.entitlement_guard.check.return_value = (allowed, "Example entitlement denied [literal]")
    if not available:
        app.bw_session_service = None
    if failed:
        boundaries.bw.status.side_effect = RuntimeError("status [literal] Ω")
    screen = BwItemPickerModal(session_service=boundaries.bw if available else None)
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, screen, results)
        assert not screen.query(DataTable)
        expected = "Upgrade required" if not allowed else ("status [literal] Ω" if failed else "session service unavailable")
        assert expected in _painted(app, screen.query_one("#bw_picker_body"))
        await _click(app, pilot, screen, "bw_picker_close")
        assert results == [None]
    boundaries.bw.create_ssh_key_item.assert_not_awaited()
    boundaries.bw.list_items.assert_not_awaited()


@pytest.mark.asyncio
async def test_picker_search_u_o_type_and_toggle_keep_exact_query_and_result(boundaries):
    app = _Host(boundaries)
    _returns(boundaries.bw.list_items, [BwItemSummary(id="item-1", name=NAME, type=5, has_ssh_key=True)])
    screen = BwItemPickerModal(default_collection_id="collection-1", default_vault_url="https://vault.example.test", session_service=boundaries.bw)
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, screen, results)
        search = screen.query_one("#bw_picker_search", Input)
        search.focus()
        await pilot.press("u", "o", "enter")
        await wait_until(lambda: boundaries.bw.list_items.await_count >= 2)
        assert search.value == "uo"
        boundaries.bw.list_items.assert_awaited_with(folder_id="folder-1", search="uo", ssh_only=True)
        await pilot.click(screen.query_one("#bw_picker_folder_toggle"))
        await wait_until(lambda: boundaries.bw.list_items.await_args.kwargs.get("folder_id") is None)
        boundaries.bw.list_items.assert_awaited_with(folder_id=None, search="uo", ssh_only=True)
        table = screen.query_one(DataTable)
        table.focus()
        await pilot.press("enter")
        await wait_until(lambda: bool(results))
        assert results == [{"item_id": "item-1", "item_name": NAME, "collection_id": "collection-1", "vault_url": "https://vault.example.test"}]


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [True, False])
async def test_reference_native_picker_return_preserves_draft_and_exact_save_target(cancel, boundaries):
    app = _Host(boundaries)
    _returns(boundaries.bw.list_items, [BwItemSummary(id="item-1", name=NAME, type=5, has_ssh_key=True)])
    _returns(boundaries.refs.put_personal_instance_ref, {})
    screen = SshRefEditorModal(ROW)
    results = []
    async with app.run_test(size=(160, 50)) as pilot:
        await _open(app, pilot, screen, results)
        collection = screen.query_one("#collection_id", Input)
        collection.value = "collection-1"
        await _click(app, pilot, screen, "pick_btn")
        await wait_until(lambda: isinstance(app.screen, BwItemPickerModal))
        child = app.screen
        await wait_until(lambda: bool(child.query(DataTable)))
        if cancel:
            await _click(app, pilot, child, "bw_picker_cancel")
        else:
            table = child.query_one(DataTable)
            table.focus()
            await pilot.press("enter")
        await wait_until(lambda: app.screen is screen)
        await pilot.pause()
        assert app.focused is screen.query_one("#pick_btn")
        assert collection.value == "collection-1" and results == []
        if cancel:
            assert screen.query_one("#item_id", Input).value == ""
            boundaries.refs.put_personal_instance_ref.assert_not_awaited()
        else:
            assert screen.query_one("#item_id", Input).value == "item-1"
            assert NAME in _painted(app, screen.query_one("#ssh_ref_selected"))
            await _click(app, pilot, screen, "save_btn")
            await wait_until(lambda: bool(results))
            assert results == [True]
            boundaries.refs.put_personal_instance_ref.assert_awaited_once_with(provider="aws", instance_id="web-1", ssh_credential_ref={"item_id": "item-1", "collection_id": "collection-1"}, ssh_credential_provider=BITWARDEN_PM_PROVIDER)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [402, 422, 500])
async def test_reference_failed_save_stays_open_with_literal_error_and_draft(status, boundaries):
    app = _Host(boundaries)
    boundaries.refs.put_personal_instance_ref.side_effect = APIError(code="example", message="save [literal] Ω", status=status)
    screen = SshRefEditorModal(ROW, existing_ref={"ssh_credential_ref": {"item_id": "item-1"}})
    results = []
    async with app.run_test(size=(100, 30), notifications=True) as pilot:
        await _open(app, pilot, screen, results)
        await _click(app, pilot, screen, "save_btn")
        await wait_until(lambda: bool(screen.query(Toast)))
        expected = {
            402: "Personal SSH refs require a paid plan. Upgrade at /pricing.",
            422: "save [literal] Ω",
            500: "Failed to save SSH ref: save [literal] Ω",
        }[status]
        toast = screen.query_one(Toast)
        # The toast's content region excludes its native border and padding.
        # Preserve all message characters; remove only right-edge ASCII cells
        # and rejoin this known sentence's native word-wrap boundary.
        content = toast.content_region
        assert content.width > 0 and content.height > 0
        assert screen.region.contains_region(content)
        rows = screen._compositor.render_strips()
        lines = [rows[y].crop(content.x, content.right).text for y in range(content.y, content.bottom)]
        assert " ".join(line.rstrip(" ") for line in lines) == expected
        for y in range(content.y, content.bottom):
            hit = app.get_widget_at(content.x + content.width // 2, y)[0]
            assert hit is toast or toast in hit.ancestors
        assert screen.query_one("#item_id", Input).value == "item-1" and results == []
        for name in ("cancel_btn", "delete_btn", "save_btn"):
            _exposed(app, screen, screen.query_one("#" + name))


@pytest.mark.asyncio
async def test_reference_existing_delete_returns_true_and_exact_captured_target(boundaries):
    app = _Host(boundaries)
    _returns(boundaries.refs.delete_personal_instance_ref, True)
    screen = SshRefEditorModal(ROW, existing_ref={"ssh_credential_ref": {"item_id": "item-1"}})
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, screen, results)
        await _click(app, pilot, screen, "delete_btn")
        await wait_until(lambda: bool(results))
        assert results == [True]
    boundaries.refs.delete_personal_instance_ref.assert_awaited_once_with(provider="aws", instance_id="web-1")
    boundaries.refs.put_personal_instance_ref.assert_not_awaited()


def _held_scan(boundaries: _Boundaries, module, monkeypatch: pytest.MonkeyPatch):
    entered = threading.Event()
    release = threading.Event()
    boundaries.gates.append(release)
    def scan(directory):
        assert directory == boundaries.home / ".ssh"
        entered.set()
        assert release.wait(10), "Fake scanner was not released"
        return boundaries.keys
    monkeypatch.setattr(module, "scan_directory", Mock(side_effect=scan))
    return entered, release


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["bw_import", "vault_import"])
async def test_loading_cancel_policy_uses_actual_held_scanner(kind, boundaries, monkeypatch):
    module = bw_key_import if kind == "bw_import" else vault_import_modal
    entered, release = _held_scan(boundaries, module, monkeypatch)
    app = _Host(boundaries)
    screen = _modal(kind, boundaries)
    results = []
    try:
        async with app.run_test(size=(100, 30)) as pilot:
            # BW scan is intentionally held before _open's completion wait.
            await app.push_screen(screen, results.append)
            if kind == "vault_import":
                await pilot.pause()
                await _click(app, pilot, screen, "vault_import_local")
            await wait_until(entered.is_set)
            await pilot.press("escape")
            await pilot.pause()
            if kind == "bw_import":
                assert results == [None] and app.screen is not screen
            else:
                assert app.screen is screen and results == []
                # Trim only native right-edge ASCII padding and rejoin the
                # known word-wrap boundary; preserve every interior character.
                lines = _painted(app, screen.query_one("#vault_import_status")).split("\n")
                assert " ".join(line.rstrip(" ") for line in lines) == "Still loading the key list: wait for it to finish before closing."
                assert screen.query_one("#vault_import_local", Button).disabled
                assert screen.query_one("#vault_import_bitwarden", Button).disabled
                release.set()
                await wait_until(lambda: not screen._loading)
                await _click(app, pilot, screen, "vault_import_cancel")
                assert results == [None]
            release.set()
    finally:
        release.set()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["picker", "vault_import"])
@pytest.mark.parametrize("cancel", [True, False])
async def test_real_nested_unlock_cancel_or_success_returns_once_to_parent(kind, cancel, boundaries):
    app = _Host(boundaries)
    _returns(boundaries.bw.status, BwAuthState.LOCKED)
    _returns(boundaries.bw.unlock, None)
    _returns(boundaries.bw.list_items, [BwItemSummary(id="item-1", name=NAME, type=5, has_ssh_key=True)])
    screen = BwItemPickerModal(session_service=boundaries.bw) if kind == "picker" else _modal(kind, boundaries)
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        await app.push_screen(screen, results.append)
        if kind == "vault_import":
            await pilot.pause()
            await _click(app, pilot, screen, "vault_import_bitwarden")
        await wait_until(lambda: isinstance(app.screen, BwUnlockModal))
        child = app.screen
        await wait_until(lambda: bool(child.query("#bw_master_pw")))
        await wait_until(lambda: child.query_one("#bw_unlock_btn", Button).region.height > 0)
        if cancel:
            await pilot.press("escape")
        else:
            child.query_one("#bw_master_pw", Input).value = "example unlock phrase"
            await _click(app, pilot, child, "bw_unlock_btn")
        await wait_until(lambda: app.screen is screen)
        if kind == "picker":
            await wait_until(lambda: bool(screen.query("#bw_picker_close" if cancel else "#bw_picker_table")))
        else:
            await wait_until(lambda: not screen._loading)
        await pilot.pause()
        assert results == [] and len(app.screen_stack) == 2
        if cancel:
            boundaries.bw.list_items.assert_not_awaited()
            boundaries.bw.unlock.assert_not_awaited()
        else:
            boundaries.bw.unlock.assert_awaited_once_with("example unlock phrase")
            listing = screen.query_one(DataTable if kind == "picker" else SelectionList)
            await wait_until(lambda: NAME in _painted(app, listing))
            assert NAME in _painted(app, listing)
        await _click(app, pilot, screen, ("bw_picker_close" if cancel else "bw_picker_cancel") if kind == "picker" else "vault_import_cancel")
        assert results == [None]


def _key_reader(monkeypatch: pytest.MonkeyPatch, module, *, encrypted: bool = False):
    # Deliberately not a parseable key; the consumer's crypto seams are fakes.
    decrypted = DecryptedKey("fixture transient text", "ssh-ed25519 fixture", "SHA256:fixture0", "ed25519")
    read = Mock(return_value=b"fixture transient bytes")
    load = Mock(return_value=decrypted)
    decrypt = Mock(side_effect=[WrongPassphraseError("Wrong passphrase."), decrypted] if encrypted else None, return_value=decrypted)
    monkeypatch.setattr(module, "read_key_bytes", read)
    monkeypatch.setattr(module, "load_unencrypted_key", load)
    monkeypatch.setattr(module, "decrypt_private_key", decrypt)
    return read, load, decrypt


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["bw_import", "vault_import"])
@pytest.mark.parametrize("skip", [True, False])
async def test_encrypted_key_native_retry_or_skip_retains_parent_selection(kind, skip, boundaries, monkeypatch):
    module = bw_key_import if kind == "bw_import" else vault_import_modal
    keys = [ScannedKey(boundaries.home / ".ssh" / "encrypted-key", NAME, True)]
    monkeypatch.setattr(module, "scan_directory", Mock(return_value=keys))
    _, _, decrypt = _key_reader(monkeypatch, module, encrypted=True)
    _returns(boundaries.bw.create_ssh_key_item, "created-1")
    _returns(boundaries.vault.import_keys, {"item_id": "created-1"})
    app = _Host(boundaries)
    screen = _modal(kind, boundaries)
    results = []
    async with app.run_test(size=(100, 30), notifications=True) as pilot:
        await _open(app, pilot, screen, results)
        if kind == "vault_import":
            await _click(app, pilot, screen, "vault_import_local")
            await wait_until(lambda: not screen._loading and bool(screen._local_keys))
        listing = screen.query_one(SelectionList)
        assert listing.selected == []
        listing.focus()
        await wait_until(lambda: app.focused is listing)
        # Dynamically added options retain highlighted=None until navigation.
        await pilot.press("home", "space")
        assert listing.highlighted == 0 and listing.selected == [0]
        await _click(app, pilot, screen, "bw_import_btn" if kind == "bw_import" else "vault_import_confirm")
        await wait_until(lambda: isinstance(app.screen, BwPassphraseModal))
        first = app.screen
        assert listing.selected == [0] and results == []
        await wait_until(lambda: bool(first.query("#bw_passphrase_input")))
        first.query_one("#bw_passphrase_input", Input).value = "wrong fixture phrase"
        await _click(app, pilot, first, "bw_passphrase_unlock_btn")
        await wait_until(lambda: isinstance(app.screen, BwPassphraseModal) and app.screen is not first)
        second = app.screen
        assert listing.selected == [0] and results == []
        assert len(app.screen_stack) == 3
        await wait_until(lambda: bool(second.query("#bw_passphrase_input")))
        if skip:
            await _click(app, pilot, second, "bw_passphrase_skip_btn")
        else:
            second.query_one("#bw_passphrase_input", Input).value = "  fixture phrase  "
            await _click(app, pilot, second, "bw_passphrase_unlock_btn")
        await wait_until(lambda: bool(results))
        assert len(results) == 1 and app.screen is not screen
        assert results[0]["skipped"] == int(skip) and results[0]["imported"] == int(not skip)
        assert decrypt.call_args_list[0].args[1] == "wrong fixture phrase"
        if not skip:
            assert decrypt.call_args_list[1].args[1] == "  fixture phrase  "
        if kind == "bw_import":
            boundaries.bw.sync_now.assert_awaited_once()
            assert results == [{"imported": int(not skip), "skipped": int(skip), "duplicates": 0, "failed": 0}]
        else:
            assert set(results[0]) == {"imported", "skipped", "failed", "imported_ids", "references"}


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["bw_import", "vault_import"])
async def test_import_in_flight_refuses_native_cancel_until_exact_completion(kind, boundaries, monkeypatch):
    module = bw_key_import if kind == "bw_import" else vault_import_modal
    monkeypatch.setattr(module, "scan_directory", Mock(return_value=boundaries.keys[:1]))
    _key_reader(monkeypatch, module)
    started = asyncio.Event()
    release = asyncio.Event()
    async def held_import(*args, **kwargs):
        started.set()
        await release.wait()
        return "created-1" if kind == "bw_import" else {"item_id": "created-1"}
    method = boundaries.bw.create_ssh_key_item if kind == "bw_import" else boundaries.vault.import_keys
    method.side_effect = held_import
    app = _Host(boundaries)
    screen = _modal(kind, boundaries)
    results = []
    try:
        async with app.run_test(size=(100, 30), notifications=True) as pilot:
            await _open(app, pilot, screen, results)
            if kind == "vault_import":
                await _click(app, pilot, screen, "vault_import_local")
                await wait_until(lambda: not screen._loading and bool(screen._local_keys))
            await _click(app, pilot, screen, "bw_import_btn" if kind == "bw_import" else "vault_import_confirm")
            await wait_until(started.is_set)
            await pilot.press("escape")
            await pilot.pause()
            assert app.screen is screen and results == []
            assert screen.query_one(SelectionList).selected == [0]
            if kind == "vault_import":
                assert "The import is still running: wait for it to finish before closing." in _painted(app, screen.query_one("#vault_import_status"))
                for name in ("vault_import_local", "vault_import_bitwarden", "vault_import_confirm"):
                    assert screen.query_one("#" + name, Button).disabled
            else:
                await wait_until(lambda: bool(screen.query(Toast)))
                assert "Import in progress — please wait." in _painted(app, screen.query_one(Toast))
            release.set()
            await wait_until(lambda: bool(results))
            assert results[0]["imported"] == 1 and len(results) == 1
            method.assert_awaited_once()
    finally:
        release.set()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["scan", "dedupe"])
async def test_bw_import_scan_or_dedupe_failure_blocks_upload_and_paints_guidance(failure, boundaries, monkeypatch):
    if failure == "scan":
        monkeypatch.setattr(bw_key_import, "scan_directory", Mock(side_effect=KeyImportError("unreadable fixture")))
    else:
        boundaries.bw.list_items.side_effect = RuntimeError("dedupe [literal] Ω")
    app = _Host(boundaries)
    screen = _modal("bw_import", boundaries)
    results = []
    async with app.run_test(size=(100, 30), notifications=True) as pilot:
        await _open(app, pilot, screen, results)
        expected = "Could not read directory" if failure == "scan" else "could not check the vault for duplicates, import is blocked"
        assert expected in " ".join(_painted(app, screen.query_one("#bw_import_status")).split())
        await _click(app, pilot, screen, "bw_import_btn")
        await pilot.pause()
        assert results == [] and app.screen is screen
        boundaries.bw.create_ssh_key_item.assert_not_awaited()
        _controls(app, screen, "bw_import")


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["ssh", "bitwarden"])
async def test_vault_import_result_metadata_targets_and_transient_wipe(source, boundaries, monkeypatch):
    app = _Host(boundaries)
    _returns(boundaries.bw.list_items, [BwItemSummary(id="item-1", name=NAME, type=5, has_ssh_key=True)])
    monkeypatch.setattr(vault_import_modal, "scan_directory", Mock(return_value=boundaries.keys[:1]))
    _key_reader(monkeypatch, vault_import_modal)
    _returns(boundaries.resolver.resolve_ssh_key, "fixture transient text")
    expected_digest = hashlib.sha256(b"fixture transient text").hexdigest()
    async def import_keys(**kwargs):
        private = kwargs.pop("private_key")
        assert isinstance(private, bytearray)
        # Snapshot only a digest and routing metadata before the modal zeroes it.
        boundaries.transient.append(private)
        boundaries.import_metadata.append({**kwargs, "digest": hashlib.sha256(private).hexdigest()})
        return {"item_id": "created-1", "name": "Stored example", "public_fingerprint": "SHA256:fixture0"}
    boundaries.vault.import_keys.side_effect = import_keys
    screen = _modal("vault_import", boundaries)
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, screen, results)
        if source == "ssh":
            await _click(app, pilot, screen, "vault_import_local")
            await wait_until(lambda: not screen._loading and bool(screen._local_keys))
        else:
            await _click(app, pilot, screen, "vault_import_bitwarden")
            await wait_until(lambda: not screen._loading and bool(screen._bw_items))
        listing = screen.query_one(SelectionList)
        if source == "bitwarden":
            listing.focus()
            await wait_until(lambda: app.focused is listing)
            await pilot.press("home", "space")
            assert listing.highlighted == 0
        assert listing.selected == [0]
        await _click(app, pilot, screen, "vault_import_confirm")
        await wait_until(lambda: bool(results))
        reference = {"vault_item_id": "created-1", "source": source, "source_ref": boundaries.keys[0].filename if source == "ssh" else "item-1", "name": "Stored example", "fingerprint": "SHA256:fixture0"}
        assert results == [{"imported": 1, "skipped": 0, "failed": 0, "imported_ids": ["created-1"], "references": [reference]}]
    assert boundaries.transient and all(not any(data) for data in boundaries.transient)
    expected = {"source": source, "vault_id": "vault-1", "digest": expected_digest}
    if source == "ssh":
        expected["path"] = str(boundaries.keys[0].path)
        boundaries.resolver.resolve_ssh_key.assert_not_called()
    else:
        expected.update(source_ref="item-1", name=NAME)
        boundaries.resolver.resolve_ssh_key.assert_called_once_with("item-1")
    assert boundaries.import_metadata == [expected]


@pytest.mark.asyncio
async def test_empty_picker_row_enter_stays_open_then_native_cancel_returns_none(boundaries):
    app = _Host(boundaries)
    screen = BwItemPickerModal(session_service=boundaries.bw)
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, screen, results)
        table = screen.query_one(DataTable)
        assert "No SSH-key items found" in _painted(app, table)
        table.focus()
        await pilot.press("enter")
        await pilot.pause()
        assert results == [] and app.screen is screen
        await _click(app, pilot, screen, "bw_picker_cancel")
        assert results == [None]


@pytest.mark.asyncio
async def test_reference_invalid_empty_item_keeps_advanced_inputs_and_footer_usable(boundaries):
    app = _Host(boundaries)
    screen = SshRefEditorModal(ROW)
    results = []
    async with app.run_test(size=(100, 30), notifications=True) as pilot:
        await _open(app, pilot, screen, results)
        await _click(app, pilot, screen, "save_btn")
        await wait_until(lambda: bool(screen.query(Toast)))
        assert results == [] and app.screen is screen
        assert "Pick an SSH key from your vault" in " ".join(_painted(app, screen.query_one(Toast)).split())
        boundaries.refs.put_personal_instance_ref.assert_not_awaited()
        for name in ("cancel_btn", "save_btn"):
            _exposed(app, screen, screen.query_one("#" + name))


@pytest.mark.asyncio
async def test_native_bw_selection_dedupe_counts_and_public_consistency(boundaries, monkeypatch):
    keys = [
        ScannedKey(boundaries.home / ".ssh" / "plain", NAME, False, fingerprint="SHA256:fixture0", public_key="ssh-ed25519 fixture comment"),
        ScannedKey(boundaries.home / ".ssh" / "duplicate", "duplicate", False, fingerprint="SHA256:duplicate"),
        ScannedKey(boundaries.home / ".ssh" / "broken", "broken", False, error="Unsupported fixture"),
    ]
    monkeypatch.setattr(bw_key_import, "scan_directory", Mock(return_value=keys))
    read, load, _ = _key_reader(monkeypatch, bw_key_import)
    _returns(boundaries.bw.list_items, [BwItemSummary(id="old-1", name="duplicate", type=5, has_ssh_key=True, fingerprint="SHA256:duplicate")])
    _returns(boundaries.bw.create_ssh_key_item, "created-1")
    app = _Host(boundaries)
    screen = _modal("bw_import", boundaries)
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        await _open(app, pilot, screen, results)
        listing = screen.query_one(SelectionList)
        assert listing.selected == [0]
        assert listing.get_option_at_index(1).disabled
        assert listing.get_option_at_index(2).disabled
        listing.focus()
        await wait_until(lambda: app.focused is listing)
        # Native End/Down skip both unavailable rows; Space here would toggle
        # the sole enabled first row, not the unreadable final row.
        await pilot.press("end")
        assert listing.highlighted == 0 and listing.selected == [0]
        await pilot.press("down")
        assert listing.highlighted == 0 and listing.selected == [0]
        await _click(app, pilot, screen, "bw_import_btn")
        await wait_until(lambda: bool(results))
        assert results == [{"imported": 1, "skipped": 0, "duplicates": 0, "failed": 0}]
    read.assert_called_once_with(keys[0].path)
    load.assert_called_once_with(b"fixture transient bytes")
    boundaries.bw.list_items.assert_awaited_once_with(folder_id=None, ssh_only=True)
    boundaries.bw.ensure_servonaut_folder.assert_awaited_once_with("Example")
    boundaries.bw.create_ssh_key_item.assert_awaited_once_with(name=NAME, private_key="fixture transient text", public_key="ssh-ed25519 fixture comment", key_fingerprint="SHA256:fixture0", folder_id="folder-1")
    boundaries.bw.sync_now.assert_awaited_once()
