"""Tests for :class:`servonaut.screens.bw_key_import.BwKeyImportModal`.

Covers the scan/populate pipeline (default selection: unencrypted ON, encrypted
OFF; already-in-vault and error rows disabled), the import worker (dedupe by
fingerprint, passphrase retry/skip loop, per-key failure isolation, summary
dict), and a ``run_test`` pilot smoke that the list renders centered.

No real key material is used anywhere — fingerprints are fake fixtures.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests._key_fixtures import openssh_armor
from servonaut.screens.bw_key_import import BwKeyImportModal
from servonaut.services.bw_errors import BwCreateError
from servonaut.services.bw_key_import import (
    DEFAULT_MAX_KEY_BYTES,
    DecryptedKey,
    KeyImportError,
    ScannedKey,
    WrongPassphraseError,
)
from servonaut.services.bw_session_service import BwItemSummary, BwSessionService


def _svc(**overrides):
    svc = MagicMock(spec=BwSessionService)
    svc.list_items = AsyncMock(return_value=[])
    svc.ensure_servonaut_folder = AsyncMock(return_value="fld-1")
    svc.create_ssh_key_item = AsyncMock(return_value="item-1")
    svc.sync_now = AsyncMock(return_value=None)
    for name, value in overrides.items():
        setattr(svc, name, value)
    return svc


def _keys(tmp_path: Path):
    """Real files with placeholder bytes — load/decrypt are patched in tests."""
    plain = tmp_path / "id_ed25519"
    plain.write_text("placeholder")
    enc = tmp_path / "id_rsa"
    enc.write_text("placeholder")
    dup = tmp_path / "old_key"
    dup.write_text("placeholder")
    return [
        ScannedKey(
            path=plain,
            filename="id_ed25519",
            encrypted=False,
            key_type="ed25519",
            fingerprint="SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            public_key="ssh-ed25519 AAAA fixture",
        ),
        ScannedKey(path=enc, filename="id_rsa", encrypted=True),
        ScannedKey(
            path=dup,
            filename="old_key",
            encrypted=False,
            key_type="rsa",
            fingerprint="SHA256:dupdupdupdupdupdupdupdupdupdupdupdupdupdupd",
            public_key="ssh-rsa BBBB fixture",
        ),
        ScannedKey(
            path=tmp_path / "broken",
            filename="broken",
            encrypted=False,
            error="Unsupported or corrupt key format.",
        ),
    ]


def _decrypted(fp: str = "SHA256:newnewnewnewnewnewnewnewnewnewnewnewnewnewn"):
    return DecryptedKey(
        private_key=openssh_armor("placeholder"),
        public_key="ssh-ed25519 CCCC fixture",
        fingerprint=fp,
        key_type="ed25519",
    )


def test_modal_optional_dict_typed():
    bases = [str(b) for b in getattr(BwKeyImportModal, "__orig_bases__", [])]
    assert any("dict" in b for b in bases)


def test_escape_binding_present():
    keys = [b.key for b in BwKeyImportModal.BINDINGS]
    assert "escape" in keys


class _ScreenHarness:
    """Build a screen with mocked app/status/dismiss for worker unit tests."""

    def __init__(self, keys, svc, existing=None, push_results=None):
        self.screen = BwKeyImportModal(Path("/tmp/unused"), session_service=svc)
        self.screen._keys = keys
        self.screen._existing = set(existing or [])
        # Harness default: the scan finished and the vault listing succeeded.
        self.screen._existing_ok = True
        self.screen._scan_complete = True
        self.screen._set_status = MagicMock()
        self.screen.dismiss = MagicMock()
        self.app = MagicMock()
        self.app.demo_mode = False
        # Folder lookup goes through config_manager.get() — pin the value so
        # the MagicMock app doesn't hand back a truthy auto-mock folder name.
        self.app.config_manager.get.return_value = SimpleNamespace(
            bw_vault_folder=None
        )
        if push_results is not None:
            self.app.push_screen_wait = AsyncMock(side_effect=push_results)
        self._patcher = patch.object(
            type(self.screen), "app", property(lambda _self: self.app)
        )
        self._patcher.start()

    def stop(self):
        self._patcher.stop()


class TestScanErrors:
    def test_unreadable_directory_sets_error_status(self):
        # An unreadable directory must surface as "could not read", never as
        # the misleading "No SSH private keys found" empty state.
        svc = _svc()
        harness = _ScreenHarness([], svc)
        harness.screen._scan_complete = False
        try:
            with patch(
                "servonaut.screens.bw_key_import.scan_directory",
                side_effect=KeyImportError("Could not read directory."),
            ):
                asyncio.run(harness.screen._scan())
        finally:
            harness.stop()

        assert harness.screen._scan_complete is True
        status = harness.screen._set_status.call_args.args[0]
        assert "Could not read directory" in status
        assert "No SSH private keys" not in status
        # The vault is not queried when the scan itself failed.
        svc.list_items.assert_not_awaited()


class TestDoImport:
    def test_imports_dedupes_and_summarizes(self, tmp_path):
        svc = _svc(
            list_items=AsyncMock(
                return_value=[
                    BwItemSummary(
                        id="i1",
                        name="old",
                        type=5,
                        has_ssh_key=True,
                        fingerprint="SHA256:dupdupdupdupdupdupdupdupdupdupdupdupdupdupd",
                    )
                ]
            )
        )
        keys = _keys(tmp_path)
        harness = _ScreenHarness(
            keys[:3],  # plain + encrypted + dup
            svc,
            existing={"SHA256:dupdupdupdupdupdupdupdupdupdupdupdupdupdupd"},
            push_results=["correct-passphrase"],
        )
        harness.screen._selected_indices = MagicMock(return_value=[0, 1, 2])
        try:
            with patch(
                # Same fingerprint as the scanned key: the file is unchanged,
                # so the scanned public line (with comment) must be preferred.
                "servonaut.screens.bw_key_import.load_unencrypted_key",
                return_value=_decrypted("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ), patch(
                "servonaut.screens.bw_key_import.decrypt_private_key",
                return_value=_decrypted("SHA256:encencencencencencencencencencencencencenc"),
            ):
                asyncio.run(harness.screen._do_import())
        finally:
            harness.stop()

        svc.ensure_servonaut_folder.assert_awaited_once_with("Servonaut")
        assert svc.create_ssh_key_item.await_count == 2
        svc.sync_now.assert_awaited_once()
        harness.screen.dismiss.assert_called_once_with(
            {"imported": 2, "skipped": 0, "duplicates": 1, "failed": 0}
        )
        # Vault item is named after the file; folder id is threaded through.
        first_call = svc.create_ssh_key_item.await_args_list[0]
        assert first_call.kwargs["name"] == "id_ed25519"
        assert first_call.kwargs["folder_id"] == "fld-1"
        # Scanned public line (with comment) preferred over the rebuilt one.
        assert first_call.kwargs["public_key"] == "ssh-ed25519 AAAA fixture"

    def test_skip_passphrase_counts_skipped(self, tmp_path):
        svc = _svc()
        keys = _keys(tmp_path)
        harness = _ScreenHarness(keys[:2], svc, push_results=[None])
        harness.screen._selected_indices = MagicMock(return_value=[1])
        try:
            asyncio.run(harness.screen._do_import())
        finally:
            harness.stop()
        svc.create_ssh_key_item.assert_not_awaited()
        harness.screen.dismiss.assert_called_once_with(
            {"imported": 0, "skipped": 1, "duplicates": 0, "failed": 0}
        )

    def test_post_decrypt_duplicate_not_created(self, tmp_path):
        svc = _svc()
        keys = _keys(tmp_path)
        harness = _ScreenHarness(
            keys[1:2],  # the encrypted key: fingerprint unknown until decrypt
            svc,
            existing={"SHA256:encencencencencencencencencencencencencenc"},
            push_results=["correct-passphrase"],
        )
        harness.screen._selected_indices = MagicMock(return_value=[0])
        try:
            with patch(
                "servonaut.screens.bw_key_import.decrypt_private_key",
                return_value=_decrypted("SHA256:encencencencencencencencencencencencencenc"),
            ):
                asyncio.run(harness.screen._do_import())
        finally:
            harness.stop()
        svc.create_ssh_key_item.assert_not_awaited()
        harness.screen.dismiss.assert_called_once_with(
            {"imported": 0, "skipped": 0, "duplicates": 1, "failed": 0}
        )

    def test_create_failure_continues_with_rest(self, tmp_path):
        svc = _svc(
            create_ssh_key_item=AsyncMock(
                side_effect=[BwCreateError("Could not create the Bitwarden item."), "item-2"]
            )
        )
        keys = _keys(tmp_path)
        # Two unencrypted keys with distinct fingerprints.
        harness = _ScreenHarness([keys[0], keys[2]], svc)
        harness.screen._selected_indices = MagicMock(return_value=[0, 1])
        try:
            with patch(
                "servonaut.screens.bw_key_import.load_unencrypted_key",
                side_effect=[
                    _decrypted("SHA256:one1one1one1one1one1one1one1one1one1one1one"),
                    _decrypted("SHA256:two2two2two2two2two2two2two2two2two2two2two"),
                ],
            ):
                asyncio.run(harness.screen._do_import())
        finally:
            harness.stop()
        harness.screen.dismiss.assert_called_once_with(
            {"imported": 1, "skipped": 0, "duplicates": 0, "failed": 1}
        )
        kwargs = harness.app.notify.call_args.kwargs
        assert kwargs.get("markup") is False

    def test_no_selection_warns_and_stays(self, tmp_path):
        svc = _svc()
        harness = _ScreenHarness(_keys(tmp_path), svc)
        harness.screen._selected_indices = MagicMock(return_value=[])
        try:
            asyncio.run(harness.screen._do_import())
        finally:
            harness.stop()
        harness.screen.dismiss.assert_not_called()
        assert harness.app.notify.called

    def test_rotated_file_uses_fresh_public_line(self, tmp_path):
        """Scan-time public line is dropped when the re-read key no longer matches."""
        svc = _svc()
        keys = _keys(tmp_path)
        harness = _ScreenHarness(keys[:1], svc)  # scanned fp: SHA256:aaa…
        harness.screen._selected_indices = MagicMock(return_value=[0])
        rotated = _decrypted("SHA256:rotatedrotatedrotatedrotatedrotatedrotated")
        try:
            with patch(
                "servonaut.screens.bw_key_import.load_unencrypted_key",
                return_value=rotated,
            ):
                asyncio.run(harness.screen._do_import())
        finally:
            harness.stop()
        kwargs = svc.create_ssh_key_item.await_args.kwargs
        # Public key, fingerprint both come from the fresh read — never a
        # stale scan-time public line paired with the new private key.
        assert kwargs["public_key"] == rotated.public_key
        assert kwargs["key_fingerprint"] == rotated.fingerprint

    def test_failed_vault_listing_blocks_import(self, tmp_path):
        svc = _svc()
        harness = _ScreenHarness(_keys(tmp_path), svc)
        harness.screen._existing_ok = False  # listing failed during the scan
        harness.screen._selected_indices = MagicMock(return_value=[0])
        try:
            asyncio.run(harness.screen._do_import())
        finally:
            harness.stop()
        svc.create_ssh_key_item.assert_not_awaited()
        harness.screen.dismiss.assert_not_called()
        args, kwargs = harness.app.notify.call_args
        assert "blocked" in args[0]
        assert kwargs.get("markup") is False


class TestWorkerIsolation:
    def test_scan_worker_uses_its_own_group(self):
        screen = BwKeyImportModal(Path("/tmp/unused"))
        screen.run_worker = MagicMock()
        screen.on_mount()
        kwargs = screen.run_worker.call_args.kwargs
        # Must differ from the import group, or an early Import click would
        # cancel the scan and strand the modal at "Scanning…".
        assert kwargs.get("group") == "bw_key_import_scan"
        coro = screen.run_worker.call_args.args[0]
        if asyncio.iscoroutine(coro):
            coro.close()

    def test_import_click_before_scan_completes_warns_and_no_worker(self, tmp_path):
        svc = _svc()
        harness = _ScreenHarness([], svc)
        harness.screen._scan_complete = False
        harness.screen.run_worker = MagicMock()
        try:
            harness.screen.on_button_pressed(
                SimpleNamespace(button=SimpleNamespace(id="bw_import_btn"))
            )
        finally:
            harness.stop()
        harness.screen.run_worker.assert_not_called()
        args, kwargs = harness.app.notify.call_args
        assert "Scan in progress" in args[0]
        assert kwargs.get("markup") is False


class TestResolveKey:
    def test_wrong_passphrase_reprompts_then_succeeds(self, tmp_path):
        svc = _svc()
        keys = _keys(tmp_path)
        harness = _ScreenHarness(
            keys, svc, push_results=["wrong-pass", "right-pass"]
        )
        try:
            with patch(
                "servonaut.screens.bw_key_import.decrypt_private_key",
                side_effect=[WrongPassphraseError("Wrong passphrase."), _decrypted()],
            ):
                outcome, decrypted = asyncio.run(harness.screen._resolve_key(keys[1]))
        finally:
            harness.stop()
        assert outcome == "ok"
        assert decrypted is not None
        assert harness.app.push_screen_wait.await_count == 2
        # The wrong-passphrase notify must be markup-safe.
        kwargs = harness.app.notify.call_args.kwargs
        assert kwargs.get("markup") is False

    def test_unreadable_file_is_failed(self, tmp_path):
        svc = _svc()
        missing = ScannedKey(
            path=tmp_path / "gone", filename="gone", encrypted=False
        )
        harness = _ScreenHarness([missing], svc)
        try:
            outcome, decrypted = asyncio.run(harness.screen._resolve_key(missing))
        finally:
            harness.stop()
        assert outcome == "failed"
        assert decrypted is None

    def test_oversized_reread_is_failed(self, tmp_path):
        # The scanner's size cap must also bound the import-time re-read: a
        # file replaced/grown after the scan is failed, never slurped whole.
        svc = _svc()
        grown = tmp_path / "id_grown"
        grown.write_bytes(b"x" * (DEFAULT_MAX_KEY_BYTES + 1))
        key = ScannedKey(path=grown, filename="id_grown", encrypted=False)
        harness = _ScreenHarness([key], svc)
        try:
            outcome, decrypted = asyncio.run(harness.screen._resolve_key(key))
        finally:
            harness.stop()
        assert outcome == "failed"
        assert decrypted is None
        kwargs = harness.app.notify.call_args.kwargs
        assert kwargs.get("markup") is False


class TestRowFor:
    def test_symlinked_row_shows_resolved_target(self, tmp_path):
        target = str(tmp_path / "elsewhere" / "real_key")
        key = ScannedKey(
            path=tmp_path / "deploy_key",
            filename="deploy_key",
            encrypted=False,
            key_type="ed25519",
            fingerprint="SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            resolved_target=target,
        )
        harness = _ScreenHarness([key], _svc())
        try:
            label, selectable, _initial = harness.screen._row_for(key)
        finally:
            harness.stop()
        # Provenance visible: the resolved origin rides the row label.
        assert target in label
        assert "→" in label
        assert selectable is True

    def test_regular_row_has_no_provenance_marker(self, tmp_path):
        keys = _keys(tmp_path)
        harness = _ScreenHarness(keys, _svc())
        try:
            label, _selectable, _initial = harness.screen._row_for(keys[0])
        finally:
            harness.stop()
        assert "→" not in label


@pytest.mark.asyncio
async def test_pilot_scan_populates_selection_list_centered(tmp_path):
    from textual.app import App
    from textual.widgets import SelectionList

    from servonaut.styles import CSS_FILES

    keys = _keys(tmp_path)
    svc = _svc(
        list_items=AsyncMock(
            return_value=[
                BwItemSummary(
                    id="i1",
                    name="old",
                    type=5,
                    has_ssh_key=True,
                    fingerprint="SHA256:dupdupdupdupdupdupdupdupdupdupdupdupdupdupd",
                )
            ]
        )
    )

    class _Host(App):
        CSS_PATH = CSS_FILES

        def on_mount(self) -> None:
            self.config_manager = SimpleNamespace(
                get=lambda: SimpleNamespace(bw_vault_folder="Servonaut")
            )
            self.push_screen(BwKeyImportModal(tmp_path, session_service=svc))

    with patch("servonaut.screens.bw_key_import.scan_directory", return_value=keys):
        app = _Host()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()
            sel_list = app.screen.query_one("#bw_import_list", SelectionList)
            assert sel_list.option_count == 4
            # Default selection: only the importable unencrypted key is ON.
            assert list(sel_list.selected) == [0]
            # Encrypted key is selectable but OFF by default.
            assert sel_list.get_option_at_index(1).disabled is False
            # Already-in-vault and error rows are disabled.
            assert sel_list.get_option_at_index(2).disabled is True
            assert sel_list.get_option_at_index(3).disabled is True

            region = app.screen.query_one("#bw_import_container").region
            assert abs(region.x - (120 - region.width) // 2) <= 1
            assert abs(region.y - (40 - region.height) // 2) <= 1

    # Vault fingerprints came from the whole vault, not the Servonaut folder.
    svc.list_items.assert_awaited_once_with(folder_id=None, ssh_only=True)
