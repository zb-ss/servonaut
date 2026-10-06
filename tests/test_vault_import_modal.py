"""Focused source-selection and privacy tests for the vault SSH import wizard."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.screens.bw_passphrase_modal import BwPassphraseModal
from servonaut.screens.vault_import_modal import VaultImportModal
from servonaut.services.bw_key_import import DecryptedKey, KeyImportError, ScannedKey
from servonaut.services.bw_session_service import BwAuthState, BwItemSummary
from tests._async_bounds import wait_until


class _List:
    def __init__(self, selected: list[int]) -> None:
        self.selected = selected


class _Harness:
    def __init__(self, modal: VaultImportModal) -> None:
        self.modal = modal
        self.app = MagicMock()
        self.app.demo_mode = False
        self.modal.dismiss = MagicMock()
        self.modal._confirm = MagicMock(return_value=MagicMock())
        self.modal._set_status = MagicMock()
        self._patcher = patch.object(type(modal), "app", property(lambda _modal: self.app))
        self._patcher.start()

    def close(self) -> None:
        self._patcher.stop()


def test_modal_is_optional_metadata_result() -> None:
    bases = [str(base) for base in getattr(VaultImportModal, "__orig_bases__", [])]

    assert any("ImportSummary" in base or "dict" in base for base in bases)
    assert {binding.key for binding in VaultImportModal.BINDINGS} == {"escape"}


def test_local_import_passes_normalized_transient_key_and_returns_bind_metadata(tmp_path: Path) -> None:
    service = MagicMock()
    service.import_keys = AsyncMock(return_value={"item_id": "vault-item-1"})
    modal = VaultImportModal(service, "vault-1", tmp_path)
    modal._source = "ssh"
    modal._local_keys = [
        ScannedKey(path=tmp_path / "id_ed25519", filename="id_ed25519", encrypted=False)
    ]
    modal._local_private_key = AsyncMock(return_value=bytearray(b"fixture-private"))
    modal._list = MagicMock(return_value=_List([0]))
    harness = _Harness(modal)
    try:
        asyncio.run(modal._import_selected())
    finally:
        harness.close()

    service.import_keys.assert_awaited_once()
    call = service.import_keys.await_args.kwargs
    assert call["source"] == "ssh"
    assert call["vault_id"] == "vault-1"
    assert call["path"].endswith("id_ed25519")
    harness.modal.dismiss.assert_called_once_with(
        {
            "imported": 1,
            "skipped": 0,
            "failed": 0,
            "imported_ids": ["vault-item-1"],
            "references": [
                {
                    "vault_item_id": "vault-item-1",
                    "source": "ssh",
                    "source_ref": "id_ed25519",
                }
            ],
        }
    )


def test_bitwarden_import_uses_item_uuid_reference_without_delete(tmp_path: Path) -> None:
    service = MagicMock()
    service.import_keys = AsyncMock(return_value={"item_id": "vault-item-2"})
    resolver = MagicMock()
    resolver.resolve_ssh_key.return_value = "fixture-private"
    modal = VaultImportModal(service, "vault-1", tmp_path, resolver=resolver)
    modal._source = "bitwarden"
    modal._bw_items = [
        BwItemSummary(id="item-uuid-1", name="Production key", type=5, has_ssh_key=True)
    ]
    modal._list = MagicMock(return_value=_List([0]))
    harness = _Harness(modal)

    async def immediate_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    try:
        with patch("servonaut.screens.vault_import_modal.asyncio.to_thread", new=immediate_thread):
            asyncio.run(modal._import_selected())
    finally:
        harness.close()

    resolver.resolve_ssh_key.assert_called_once_with("item-uuid-1")
    call = service.import_keys.await_args.kwargs
    assert call["source"] == "bitwarden"
    assert call["source_ref"] == "item-uuid-1"
    assert "delete" not in " ".join(name for name in dir(resolver) if "delete" in name)
    assert harness.modal.dismiss.call_args.args[0]["references"] == [
        {"vault_item_id": "vault-item-2", "source": "bitwarden", "source_ref": "item-uuid-1"}
    ]


def test_local_scan_failure_is_not_reported_as_empty_directory(tmp_path: Path) -> None:
    modal = VaultImportModal(MagicMock(), "vault-1", tmp_path)
    modal._show_options = MagicMock()
    harness = _Harness(modal)

    async def immediate_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    try:
        with patch(
            "servonaut.screens.vault_import_modal.scan_directory",
            side_effect=KeyImportError("unreadable"),
        ), patch("servonaut.screens.vault_import_modal.asyncio.to_thread", new=immediate_thread):
            asyncio.run(modal._load_local())
    finally:
        harness.close()

    assert modal._show_options.call_args.args == (
        [],
        "Could not scan the selected SSH directory.",
    )


def test_local_symlink_provenance_is_escaped_and_demo_redacted(tmp_path: Path) -> None:
    modal = VaultImportModal(MagicMock(), "vault-1", tmp_path)
    modal._show_options = MagicMock()
    harness = _Harness(modal)
    harness.app.demo_mode = True
    harness.app.redaction_service.scrub_stream.side_effect = lambda value: "redacted" if "/" in value else value

    async def immediate_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    key = ScannedKey(
        path=tmp_path / "key",
        filename="key",
        encrypted=False,
        resolved_target="/private/path/<key>",
    )
    try:
        with patch("servonaut.screens.vault_import_modal.scan_directory", return_value=[key]), patch(
            "servonaut.screens.vault_import_modal.asyncio.to_thread", new=immediate_thread
        ):
            asyncio.run(modal._load_local())
    finally:
        harness.close()

    options = modal._show_options.call_args.args[0]
    assert "redacted" in str(options[0].prompt)
    assert "/private/path" not in str(options[0].prompt)


def test_import_in_progress_cannot_switch_source(tmp_path: Path) -> None:
    modal = VaultImportModal(MagicMock(), "vault-1", tmp_path)
    modal._importing = True
    modal.run_worker = MagicMock()

    modal.on_button_pressed(MagicMock(button=MagicMock(id="vault_import_local")))
    modal.on_button_pressed(MagicMock(button=MagicMock(id="vault_import_bitwarden")))

    assert modal._source is None
    modal.run_worker.assert_not_called()


def test_encrypted_local_key_uses_masked_existing_passphrase_modal(tmp_path: Path) -> None:
    modal = VaultImportModal(MagicMock(), "vault-1", tmp_path)
    harness = _Harness(modal)
    harness.app.push_screen_wait = AsyncMock(return_value="correct-passphrase")
    expected = DecryptedKey("normalised", "ssh-ed25519 AAAA", "SHA256:fixture", "ed25519")

    async def immediate_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    try:
        with patch("servonaut.screens.vault_import_modal.asyncio.to_thread", new=immediate_thread), patch(
            "servonaut.screens.vault_import_modal.decrypt_private_key", return_value=expected
        ):
            result = asyncio.run(modal._decrypt_with_prompt(b"encrypted fixture", "id_rsa"))
    finally:
        harness.close()

    assert result is expected
    prompt = harness.app.push_screen_wait.await_args.args[0]
    assert isinstance(prompt, BwPassphraseModal)


@pytest.mark.asyncio
async def test_modal_journey_renders_source_choice_without_key_content(tmp_path: Path) -> None:
    from textual.app import App

    class Host(App):
        def on_mount(self) -> None:
            self.push_screen(VaultImportModal(MagicMock(), "vault-1", tmp_path))

    app = Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        assert app.screen.query_one("#vault_import_local").label == "Local SSH files"
        assert app.screen.query_one("#vault_import_bitwarden").label == "Bitwarden"
        assert "private" not in str(app.screen.query_one("#vault_import_intro").render()).lower()


@pytest.mark.asyncio
async def test_demo_toggle_redraws_import_status_without_exposing_source_metadata(tmp_path: Path) -> None:
    from textual.app import App
    from textual.widgets import Static

    class Redactor:
        def scrub_stream(self, _text: str) -> str:
            return "[redacted import status]"

    class Host(App):
        demo_mode = False
        redaction_service = Redactor()

        def on_mount(self) -> None:
            self.push_screen(VaultImportModal(MagicMock(), "vault-1", tmp_path))

    app = Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        modal = app.screen
        assert isinstance(modal, VaultImportModal)
        modal._set_status("Imported source: example-private-key")
        assert "example-private-key" in str(modal.query_one("#vault_import_status", Static).render())
        app.demo_mode = True
        modal.refresh_after_demo_toggle()
        assert "example-private-key" not in str(modal.query_one("#vault_import_status", Static).render())
        assert "redacted import status" in str(modal.query_one("#vault_import_status", Static).render())


@pytest.mark.asyncio
async def test_modal_local_and_bitwarden_source_journeys(tmp_path: Path) -> None:
    from textual.app import App
    from textual.widgets import SelectionList

    local = ScannedKey(
        path=tmp_path / "id_rsa",
        filename="id_rsa",
        encrypted=True,
        resolved_target="/home/example/.ssh/id_rsa",  # leak-guard:allow — generic test path
    )
    session = MagicMock()
    session.status = AsyncMock(return_value=BwAuthState.UNLOCKED)
    session.list_items = AsyncMock(
        return_value=[BwItemSummary(id="bw-item-1", name="Deploy key", type=5, has_ssh_key=True)]
    )

    class Host(App):
        def on_mount(self) -> None:
            self.push_screen(VaultImportModal(MagicMock(), "vault-1", tmp_path, session_service=session))

    async def immediate_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    with patch("servonaut.screens.vault_import_modal.scan_directory", return_value=[local]), patch(
        "servonaut.screens.vault_import_modal.asyncio.to_thread", new=immediate_thread
    ):
        app = Host()
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await pilot.click("#vault_import_local")
            await pilot.pause()
            await pilot.pause()
            listing = app.screen.query_one("#vault_import_list", SelectionList)
            assert listing.option_count == 1
            assert list(listing.selected) == []
            assert "→" in str(listing.get_option_at_index(0).prompt)

            await pilot.click("#vault_import_bitwarden")
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()
            listing = app.screen.query_one("#vault_import_list", SelectionList)
            assert listing.option_count == 1
            assert "Deploy key" in str(listing.get_option_at_index(0).prompt)

    session.list_items.assert_awaited_once_with(folder_id=None, ssh_only=True)


@pytest.mark.asyncio
async def test_narrow_import_picker_pins_actions_and_allows_pointer_cancel(tmp_path: Path) -> None:
    """The source picker must retain its action row after asynchronous lists arrive."""
    from textual.app import App
    from textual.widgets import Button, SelectionList

    local_key = ScannedKey(path=tmp_path / "id_ed25519", filename="id_ed25519", encrypted=False)
    local_started = asyncio.Event()
    release_local = asyncio.Event()

    async def delayed_local_scan(function, *args, **kwargs):
        local_started.set()
        await release_local.wait()
        return function(*args, **kwargs)

    class LocalHost(App):
        def on_mount(self) -> None:
            self.push_screen(VaultImportModal(MagicMock(), "vault-1", tmp_path))

    with patch("servonaut.screens.vault_import_modal.scan_directory", return_value=[local_key]), patch(
        "servonaut.screens.vault_import_modal.asyncio.to_thread", new=delayed_local_scan
    ):
        app = LocalHost()
        async with app.run_test(size=(100, 30)) as pilot:
            await wait_until(lambda: isinstance(app.screen, VaultImportModal))
            await pilot.click("#vault_import_local")
            await asyncio.wait_for(local_started.wait(), timeout=2)
            release_local.set()
            modal = app.screen
            listing = modal.query_one("#vault_import_list", SelectionList)
            await wait_until(lambda: listing.option_count == 1)

            for button_id in ("vault_import_cancel", "vault_import_confirm"):
                button = modal.query_one(f"#{button_id}", Button)
                assert button.region.y >= 0 and button.region.bottom <= app.size.height
                assert button.region.x >= 0 and button.region.right <= app.size.width
            await pilot.click("#vault_import_cancel")
            await wait_until(lambda: not isinstance(app.screen, VaultImportModal))

    bitwarden_started = asyncio.Event()
    release_bitwarden = asyncio.Event()
    session = MagicMock()

    async def delayed_bitwarden_list(*, folder_id, ssh_only):
        assert folder_id is None and ssh_only is True
        bitwarden_started.set()
        await release_bitwarden.wait()
        return [BwItemSummary(id="bw-item-1", name="Deploy key", type=5, has_ssh_key=True)]

    session.list_items = AsyncMock(side_effect=delayed_bitwarden_list)

    class BitwardenHost(App):
        async def push_screen_wait(self, _screen):
            return True

        def on_mount(self) -> None:
            self.push_screen(VaultImportModal(MagicMock(), "vault-1", tmp_path, session_service=session))

    app = BitwardenHost()
    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(lambda: isinstance(app.screen, VaultImportModal))
        await pilot.click("#vault_import_bitwarden")
        await asyncio.wait_for(bitwarden_started.wait(), timeout=2)
        release_bitwarden.set()
        modal = app.screen
        listing = modal.query_one("#vault_import_list", SelectionList)
        await wait_until(lambda: listing.option_count == 1)

        assert "Deploy key" in str(listing.get_option_at_index(0).prompt)
        for button_id in ("vault_import_cancel", "vault_import_confirm"):
            button = modal.query_one(f"#{button_id}", Button)
            assert button.region.y >= 0 and button.region.bottom <= app.size.height
        await pilot.click("#vault_import_cancel")
        await wait_until(lambda: not isinstance(app.screen, VaultImportModal))
