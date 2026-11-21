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
from servonaut.widgets.filterable_selection import FilterableSelection
from tests._async_bounds import wait_until


def _service(stored: dict | None = None) -> MagicMock:
    """A vault service double whose listing of existing keys succeeds."""
    service = MagicMock()
    service.stored_keys = AsyncMock(return_value=stored or {})
    return service


class _List:
    def __init__(self, selected: list[int]) -> None:
        self.selected = selected


class _Harness:
    def __init__(self, modal: VaultImportModal) -> None:
        self.modal = modal
        self.app = MagicMock()
        self.app.demo_mode = False
        self.modal.dismiss = MagicMock()
        self.modal._existing_ok = True
        self.modal._confirm = MagicMock(return_value=MagicMock())
        self.modal._set_status = MagicMock()
        self._patcher = patch.object(type(modal), "app", property(lambda _modal: self.app))
        self._patcher.start()

    def close(self) -> None:
        self._patcher.stop()


def test_modal_is_optional_metadata_result() -> None:
    bases = [str(base) for base in getattr(VaultImportModal, "__orig_bases__", [])]

    assert any("ImportSummary" in base or "dict" in base for base in bases)
    assert "escape" in {binding.key for binding in VaultImportModal.BINDINGS}


def test_local_import_passes_normalized_transient_key_and_returns_bind_metadata(tmp_path: Path) -> None:
    service = _service()
    service.import_keys = AsyncMock(return_value={"item_id": "vault-item-1", "name": "Stored local key", "public_fingerprint": "SHA256:local"})
    modal = VaultImportModal(service, "vault-1", tmp_path)
    modal._source = "ssh"
    modal._local_keys = [
        ScannedKey(path=tmp_path / "id_ed25519", filename="id_ed25519", encrypted=False)
    ]
    modal._local_private_key = AsyncMock(return_value=bytearray(b"fixture-private"))
    modal._picker = MagicMock(return_value=_List([0]))
    harness = _Harness(modal)
    try:
        asyncio.run(modal._import_selected())
    finally:
        harness.close()

    service.import_keys.assert_awaited_once()
    call = service.import_keys.await_args.kwargs
    assert call["source"] == "ssh"
    assert call["vault_id"] == "vault-1"
    assert "known_keys" in call
    assert call["path"].endswith("id_ed25519")
    harness.modal.dismiss.assert_called_once_with(
        {
            "imported": 1,
            "skipped": 0,
            "failed": 0,
            "duplicates": 0,
            "imported_ids": ["vault-item-1"],
            "references": [
                {
                    "vault_item_id": "vault-item-1",
                    "source": "ssh",
                    "source_ref": "id_ed25519",
                    "name": "Stored local key",
                    "fingerprint": "SHA256:local",
                }
            ],
        }
    )


def test_bitwarden_import_uses_item_uuid_reference_without_delete(tmp_path: Path) -> None:
    service = _service()
    service.import_keys = AsyncMock(return_value={"item_id": "vault-item-2", "name": "Stored Bitwarden key", "public_fingerprint": "SHA256:bitwarden"})
    resolver = MagicMock()
    resolver.resolve_ssh_key.return_value = "fixture-private"
    modal = VaultImportModal(service, "vault-1", tmp_path, resolver=resolver)
    modal._source = "bitwarden"
    modal._bw_items = [
        BwItemSummary(id="item-uuid-1", name="Production key", type=5, has_ssh_key=True)
    ]
    modal._picker = MagicMock(return_value=_List([0]))
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
    assert "known_keys" in call
    assert "delete" not in " ".join(name for name in dir(resolver) if "delete" in name)
    assert harness.modal.dismiss.call_args.args[0]["references"] == [
        {"vault_item_id": "vault-item-2", "source": "bitwarden", "source_ref": "item-uuid-1",
         "name": "Stored Bitwarden key", "fingerprint": "SHA256:bitwarden"}
    ]


def test_local_scan_failure_is_not_reported_as_empty_directory(tmp_path: Path) -> None:
    modal = VaultImportModal(_service(), "vault-1", tmp_path)
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
    modal = VaultImportModal(_service(), "vault-1", tmp_path)
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
    assert "redacted" in str(options[0].label)
    assert "/private/path" not in str(options[0].label)


def test_import_in_progress_cannot_switch_source(tmp_path: Path) -> None:
    modal = VaultImportModal(_service(), "vault-1", tmp_path)
    modal._importing = True
    modal.run_worker = MagicMock()

    modal.on_button_pressed(MagicMock(button=MagicMock(id="vault_import_local")))
    modal.on_button_pressed(MagicMock(button=MagicMock(id="vault_import_bitwarden")))

    assert modal._source is None
    modal.run_worker.assert_not_called()


def test_encrypted_local_key_uses_masked_existing_passphrase_modal(tmp_path: Path) -> None:
    modal = VaultImportModal(_service(), "vault-1", tmp_path)
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
            self.push_screen(VaultImportModal(_service(), "vault-1", tmp_path))

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
            self.push_screen(VaultImportModal(_service(), "vault-1", tmp_path))

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
            self.push_screen(VaultImportModal(_service(), "vault-1", tmp_path, session_service=session))

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
            self.push_screen(VaultImportModal(_service(), "vault-1", tmp_path))

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
            self.push_screen(VaultImportModal(_service(), "vault-1", tmp_path, session_service=session))

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


def test_bitwarden_unreadable_material_keeps_fixed_tui_notice_and_wipes_buffer(tmp_path: Path) -> None:
    from types import SimpleNamespace
    from servonaut.services.vault.command_service import VaultCommandService

    core = VaultCommandService.__new__(VaultCommandService)
    core.items = SimpleNamespace(write_item=AsyncMock())
    service = _service()
    service.import_keys = AsyncMock(side_effect=core.import_keys)
    resolver = MagicMock()
    resolver.resolve_ssh_key.return_value = "unreadable key material"
    modal = VaultImportModal(service, "vault-1", tmp_path, resolver=resolver)
    modal._source = "bitwarden"
    modal._bw_items = [BwItemSummary(id="item-1", name="web-1", type=5, has_ssh_key=True)]
    modal._picker = MagicMock(return_value=_List([0]))
    harness = _Harness(modal)
    try:
        asyncio.run(modal._import_selected())
    finally:
        harness.close()
    harness.app.notify.assert_called_once_with(
        "Could not import the selected Bitwarden SSH key.", severity="error", markup=False,
    )
    assert modal.dismiss.call_args.args[0]["failed"] == 1
    assert service.import_keys.await_args.kwargs["private_key"] == bytearray(len("unreadable key material"))
    core.items.write_item.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("name, fingerprint", [
    ("[1st key", "SHA256:fixture"), ("\x1b[31mred-key", "key [3"),
    ("x\\[y", "trailing\\"),
])
async def test_bitwarden_labels_render_hostile_brackets_literally(tmp_path: Path, name: str, fingerprint: str) -> None:
    from textual.app import App
    from textual.widgets import SelectionList
    from servonaut.services.vault.display import terminal_safe

    class Host(App):
        def on_mount(self) -> None:
            self.push_screen(VaultImportModal(_service(), "vault-1", tmp_path))

    app = Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(lambda: bool(app.screen.query("#vault_import_list")))
        modal = app.screen
        modal._bw_items = [BwItemSummary(id="item-1", name=name, type=5, has_ssh_key=True, fingerprint=fingerprint)]
        modal._show_bitwarden_options()
        listing = modal.query_one("#vault_import_list", SelectionList)
        await wait_until(lambda: listing.option_count == 1)
        plain = listing.get_option_at_index(0).prompt.plain
        assert terminal_safe(name) in plain and terminal_safe(fingerprint) in plain
        assert "\x1b" not in plain
        await pilot.pause()


@pytest.mark.asyncio
async def test_local_filename_and_target_render_unclosed_brackets_and_trailing_backslash(tmp_path: Path) -> None:
    from textual.app import App
    from textual.widgets import SelectionList

    class Host(App):
        def on_mount(self) -> None:
            self.push_screen(VaultImportModal(_service(), "vault-1", tmp_path))

    app = Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(lambda: bool(app.screen.query("#vault_import_list")))
        modal = app.screen
        modal._local_keys = [ScannedKey(path=tmp_path / "key", filename="key [3", encrypted=False,
                                        resolved_target="target [old\\")]
        modal._show_local_options()
        listing = modal.query_one("#vault_import_list", SelectionList)
        await wait_until(lambda: listing.option_count == 1)
        plain = listing.get_option_at_index(0).prompt.plain
        assert plain == "key [3  → target [old\\ "
        await pilot.pause()


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["id [old", "x\\[y", "trailing\\"])
async def test_encrypted_key_passphrase_modal_renders_filename_literally(name: str) -> None:
    from textual.app import App
    from textual.content import Content
    from textual.markup import to_content
    from textual.widgets import Static

    class Host(App):
        def on_mount(self) -> None:
            self.push_screen(BwPassphraseModal(name))

    app = Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(lambda: bool(app.screen.query("#bw_passphrase_prompt")))
        content = app.screen.query_one("#bw_passphrase_prompt", Static).content
        plain = content.plain if isinstance(content, Content) else to_content(str(content)).plain
        assert plain == f"Enter the passphrase for {name} to decrypt it for import. Skip to leave this key out."
        await pilot.press("escape")


@pytest.mark.parametrize("name", [None, 7, "", "Stored [1st key"])
def test_import_reference_only_copies_nonempty_string_name(name: object) -> None:
    summary = {"imported": 0, "failed": 0, "imported_ids": [], "references": []}
    VaultImportModal._record_import(summary, {"item_id": "key-1", "name": name}, "ssh", "source-1")
    expected = {"vault_item_id": "key-1", "source": "ssh", "source_ref": "source-1"}
    if isinstance(name, str) and name:
        expected["name"] = name
    assert summary["references"] == [expected]


@pytest.mark.parametrize("fingerprint", [None, 7, "", "SHA256:fixture"])
def test_import_reference_only_includes_string_fingerprint(fingerprint: object) -> None:
    summary = {"imported": 0, "failed": 0, "imported_ids": [], "references": []}
    VaultImportModal._record_import(
        summary, {"item_id": "key-1", "name": "id_key", "public_fingerprint": fingerprint}, "ssh", "id_key",
    )
    reference = summary["references"][0]
    assert reference["name"] == "id_key"
    if isinstance(fingerprint, str):
        assert reference["fingerprint"] == fingerprint
    else:
        assert "fingerprint" not in reference


# --- keys the vault already holds -------------------------------------------

_FP = "SHA256:fixture-dup"


def _local_modal(tmp_path: Path, stored: dict | None, **service_extra) -> tuple[VaultImportModal, MagicMock]:
    service = _service(stored)
    for name, value in service_extra.items():
        setattr(service, name, value)
    modal = VaultImportModal(service, "vault-1", tmp_path)
    modal._source = "ssh"
    modal._local_keys = [
        ScannedKey(path=tmp_path / "id_a", filename="id_a", encrypted=False, fingerprint=_FP),
        ScannedKey(path=tmp_path / "id_b", filename="id_b", encrypted=False, fingerprint="SHA256:other"),
    ]
    return modal, service




def test_local_row_already_in_vault_is_disabled_and_named(tmp_path: Path) -> None:
    modal, _ = _local_modal(tmp_path, {_FP: {"item_id": "i-1", "name": "key [1]"}})
    modal._existing_ok = True
    modal._existing = {_FP: {"item_id": "i-1", "name": "key [1]"}}
    modal._show_options = MagicMock()
    harness = _Harness(modal)
    try:
        modal._show_local_options()
    finally:
        harness.close()
    options, message = modal._show_options.call_args.args
    assert options[0].disabled and options[0].selected is False
    assert not options[1].disabled
    assert "already in this vault as" in str(options[0].label)
    assert "as key [1]" in options[0].search_text
    assert message.endswith("1 already in this vault.")


def test_local_row_without_stored_name_says_only_already_in_vault(tmp_path: Path) -> None:
    modal, _ = _local_modal(tmp_path, None)
    modal._existing_ok = True
    modal._existing = {_FP: {"item_id": "i-1", "name": None}}
    modal._show_options = MagicMock()
    harness = _Harness(modal)
    try:
        modal._show_local_options()
    finally:
        harness.close()
    prompt = str(modal._show_options.call_args.args[0][0].label)
    assert "already in this vault" in prompt and " as " not in prompt


def test_bitwarden_row_already_in_vault_is_disabled(tmp_path: Path) -> None:
    modal = VaultImportModal(_service(), "vault-1", tmp_path)
    modal._existing_ok = True
    modal._existing = {_FP: {"item_id": "i-1", "name": "stored-key"}}
    modal._bw_items = [
        BwItemSummary(id="bw-1", name="a", type=5, has_ssh_key=True, fingerprint=_FP),
        BwItemSummary(id="bw-2", name="b", type=5, has_ssh_key=True, fingerprint="SHA256:other"),
    ]
    modal._show_options = MagicMock()
    harness = _Harness(modal)
    try:
        modal._show_bitwarden_options()
    finally:
        harness.close()
    options, _message = modal._show_options.call_args.args
    assert options[0].disabled and not options[1].disabled
    assert "already in this vault as stored-key" in str(options[0].label)


def test_failed_vault_listing_names_the_reason_and_logs_it(tmp_path: Path, caplog) -> None:
    from servonaut.services.api_client import APIError

    refusal = APIError(code="rate_limited", message="private-detail", status=429)
    modal, _service = _local_modal(tmp_path, None, stored_keys=AsyncMock(side_effect=refusal))
    harness = _Harness(modal)
    try:
        with caplog.at_level("WARNING"):
            asyncio.run(modal._load_existing())
        message = modal._found_message("Found 2 local SSH key candidate(s).", 0)
    finally:
        harness.close()
    assert "HTTP 429, rate_limited" in message and "import is blocked" in message
    assert "private-detail" not in message
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert warnings == ["Could not read the vault's existing keys (APIError: HTTP 429, rate_limited)"]


def test_failed_vault_listing_blocks_the_import(tmp_path: Path) -> None:
    modal, service = _local_modal(tmp_path, None, stored_keys=AsyncMock(side_effect=RuntimeError("boom")))
    modal._picker = MagicMock(return_value=_List([0]))
    harness = _Harness(modal)
    harness.modal._existing_ok = False
    try:
        asyncio.run(modal._load_existing())
        assert modal._existing_ok is False and modal._existing == {}
        modal._show_options = VaultImportModal._show_options.__get__(modal)
        asyncio.run(modal._import_selected())
        message = modal._found_message("Found 2 local SSH key candidate(s).", 0)
    finally:
        harness.close()
    service.import_keys.assert_not_called()
    harness.app.notify.assert_called_once()
    assert harness.app.notify.call_args.kwargs == {"severity": "error", "markup": False}
    assert "import is blocked" in message and "boom" not in message
    modal.dismiss.assert_not_called()


def test_duplicate_found_at_import_time_counts_as_duplicate_and_wipes_buffer(tmp_path: Path, caplog) -> None:
    from servonaut.services.vault.errors import VaultDuplicateKey

    private = bytearray(b"fixture-private")
    exc = VaultDuplicateKey(
        existing_item_id="3f2a1b4c-0000-4000-8000-000000000001", existing_name="stored-key", fingerprint=_FP,  # synthetic fixture  leak-guard:allow
    )
    modal, service = _local_modal(tmp_path, None, import_keys=AsyncMock(side_effect=exc))
    modal._local_private_key = AsyncMock(return_value=private)
    modal._picker = MagicMock(return_value=_List([0]))
    harness = _Harness(modal)
    modal._source = "ssh"
    try:
        with caplog.at_level("INFO", logger="servonaut.screens.vault_import_modal"):
            asyncio.run(modal._import_selected())
    finally:
        harness.close()
    summary = modal.dismiss.call_args.args[0]
    assert summary["duplicates"] == 1 and summary["failed"] == 0 and summary["imported"] == 0
    assert private == bytearray(len(b"fixture-private"))
    assert modal._existing[_FP]["name"] == "stored-key"
    harness.app.notify.assert_called_once_with(
        "id_a: already in this vault as stored-key; skipped.", severity="warning", markup=False,
    )
    lines = [r.getMessage() for r in caplog.records if r.name == "servonaut.screens.vault_import_modal"]
    assert lines == ["Vault key import (ssh) into vault vault-1: 0 imported, 1 already in the vault, 0 failed"]
    assert "fixture-private" not in caplog.text


def test_second_copy_of_an_imported_key_is_a_duplicate(tmp_path: Path) -> None:
    modal = VaultImportModal(_service(), "vault-1", tmp_path)
    modal._remember_import({"item_id": "i-1", "name": "stored", "public_fingerprint": _FP})
    assert modal._existing[_FP] == {"item_id": "i-1", "name": "stored"}


def test_vault_screen_status_reports_skipped_duplicates() -> None:
    from servonaut.screens.vault import VaultScreen

    screen = VaultScreen.__new__(VaultScreen)
    screen._status = MagicMock()
    screen.run_worker = MagicMock()
    screen._refresh_imported_vault_metadata = MagicMock()
    VaultScreen._handle_import_result(
        screen, "vault-1", {"imported": 2, "failed": 1, "duplicates": 3, "references": []},
    )
    screen._status.assert_called_once_with("SSH key import complete: 2 imported, 1 failed, 3 skipped: already in vault.")
    assert screen._refresh_imported_vault_metadata.call_args.args[-1] == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["local", "bitwarden"])
async def test_a_stored_name_ending_in_a_backslash_keeps_the_row_closed(tmp_path: Path, source: str) -> None:
    from textual.app import App
    from textual.widgets import SelectionList

    class Host(App):
        def on_mount(self) -> None:
            self.push_screen(VaultImportModal(_service(), "vault-1", tmp_path))

    app = Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(lambda: bool(app.screen.query("#vault_import_list")))
        modal = app.screen
        modal._existing_ok = True
        modal._existing = {_FP: {"item_id": "i-1", "name": "deploy\\"}}
        if source == "local":
            modal._local_keys = [ScannedKey(path=tmp_path / "id_a", filename="id_a", encrypted=False, fingerprint=_FP)]
            modal._show_local_options()
        else:
            modal._bw_items = [BwItemSummary(id="bw-1", name="a", type=5, has_ssh_key=True, fingerprint=_FP)]
            modal._show_bitwarden_options()
        listing = modal.query_one("#vault_import_list", SelectionList)
        await wait_until(lambda: listing.option_count == 1)
        plain = listing.get_option_at_index(0).prompt.plain
        assert plain.rstrip().endswith("already in this vault as deploy\\")
        assert "[/dim]" not in plain
        await pilot.pause()


@pytest.mark.asyncio
async def test_the_key_list_keeps_rows_on_a_short_terminal(tmp_path: Path) -> None:
    """At 100x30 the dialog gives up spacing so the list still shows keys and Import stays on screen."""
    from textual.app import App
    from textual.widgets import SelectionList

    from servonaut.styles import CSS_FILES

    class Host(App):
        CSS_PATH = CSS_FILES

        def on_mount(self) -> None:
            self.push_screen(VaultImportModal(_service(), "vault-1", tmp_path))

    app = Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(lambda: bool(app.screen.query("#vault_import_list")))
        modal = app.screen
        modal._local_keys = [
            ScannedKey(path=tmp_path / f"id_{n}", filename=f"id_{n}", encrypted=False, fingerprint=f"SHA256:k{n}")
            for n in range(3)
        ]
        modal._show_local_options()
        listing = modal.query_one("#vault_import_list", SelectionList)
        await wait_until(lambda: listing.option_count == 3)
        await wait_until(lambda: listing.content_region.height >= 3)
        confirm = modal.query_one("#vault_import_confirm")
        assert confirm.region.height > 0 and confirm.region.bottom <= 30
        await pilot.pause()



# --- filterable list ----------------------------------------------------------

_STORED_FP = "SHA256:stored-fixture"


class _Redactor:
    """Demo-mode stand-in that hides every real key name."""

    def scrub_stream(self, text: str) -> str:
        return text.replace("alpha_key", "hidden-1").replace("beta_key", "hidden-2")


def _picker_host(tmp_path: Path, source: str, *, stored: dict | None = None, listing_fails: bool = False):
    from textual.app import App

    local = [
        ScannedKey(path=tmp_path / "alpha_key", filename="alpha_key", encrypted=False, fingerprint="SHA256:aaa111"),
        ScannedKey(path=tmp_path / "beta_key", filename="beta_key", encrypted=False, fingerprint="SHA256:bbb222"),
        ScannedKey(path=tmp_path / "stored_copy", filename="stored_copy", encrypted=False, fingerprint=_STORED_FP),
        ScannedKey(path=tmp_path / "gamma_key", filename="gamma_key", encrypted=False, fingerprint="SHA256:ccc333"),
    ]
    items = [
        BwItemSummary(id="bw-1", name="alpha_key", type=5, has_ssh_key=True, fingerprint="SHA256:aaa111"),
        BwItemSummary(id="bw-2", name="beta_key", type=5, has_ssh_key=True, fingerprint="SHA256:bbb222"),
        BwItemSummary(id="bw-3", name="stored_copy", type=5, has_ssh_key=True, fingerprint=_STORED_FP),
        BwItemSummary(id="bw-4", name="gamma_key", type=5, has_ssh_key=True, fingerprint="SHA256:ccc333"),
    ]
    service = _service(stored if stored is not None else {_STORED_FP: {"item_id": "i-1", "name": "stored-key"}})
    if listing_fails:
        service.stored_keys = AsyncMock(side_effect=RuntimeError("boom"))
    session = MagicMock()
    session.list_items = AsyncMock(return_value=items)
    redactor = _Redactor()

    class Host(App):
        demo_mode = False
        redaction_service = redactor

        async def push_screen_wait(self, _screen):
            return True

        def on_mount(self) -> None:
            self.push_screen(VaultImportModal(service, "vault-1", tmp_path, session_service=session))

    async def immediate_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    patches = (
        patch("servonaut.screens.vault_import_modal.scan_directory", return_value=local),
        patch("servonaut.screens.vault_import_modal.asyncio.to_thread", new=immediate_thread),
    )
    return Host(), patches, service


async def _open_picker(app, pilot, source: str):
    from textual.widgets import SelectionList

    await wait_until(lambda: isinstance(app.screen, VaultImportModal))
    await pilot.click("#vault_import_local" if source == "local" else "#vault_import_bitwarden")
    modal = app.screen
    listing = modal.query_one("#vault_import_list", SelectionList)
    await wait_until(lambda: listing.option_count == 4 and not modal._loading)
    return modal, listing


async def _press(app, pilot, selector: str) -> None:
    """Click a button once its previous press effect has ended (a busy button ignores clicks)."""
    button = app.screen.query_one(selector)
    await wait_until(lambda: not button.has_class("-active"))
    await pilot.click(selector)


def _shown(listing) -> list[int]:
    return [listing.get_option_at_index(i).value for i in range(listing.option_count)]


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["local", "bitwarden"])
async def test_search_filters_by_name_and_fingerprint(tmp_path: Path, source: str) -> None:
    app, patches, _service_double = _picker_host(tmp_path, source)
    with patches[0], patches[1]:
        async with app.run_test(size=(160, 50)) as pilot:
            modal, listing = await _open_picker(app, pilot, source)
            search = modal.query_one("#vault_import_search")
            search.focus()
            await pilot.press(*"BETA")
            await wait_until(lambda: _shown(listing) == [1])
            search.value = ""
            await wait_until(lambda: len(_shown(listing)) == 4)
            search.value = "ccc333"
            await wait_until(lambda: _shown(listing) == [3])


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["local", "bitwarden"])
async def test_select_all_skips_the_stored_row_under_filter_and_sort(tmp_path: Path, source: str) -> None:
    app, patches, _service_double = _picker_host(tmp_path, source)
    with patches[0], patches[1]:
        async with app.run_test(size=(160, 50)) as pilot:
            modal, listing = await _open_picker(app, pilot, source)
            picker = modal.query_one(FilterableSelection)
            await _press(app, pilot, "#vault_import_none")
            await wait_until(lambda: picker.selected == [])
            await _press(app, pilot, "#vault_import_all")
            await wait_until(lambda: picker.selected == [0, 1, 3])
            assert 2 not in listing.selected
            assert "already in this vault as" in str(listing.get_option_at_index(_shown(listing).index(2)).prompt)

            modal.query_one("#vault_import_search").value = "stored"
            await wait_until(lambda: _shown(listing) == [2])
            await _press(app, pilot, "#vault_import_all")
            # Only a disabled row is shown, so the press changes nothing; showing
            # every row again exposes the final state.
            modal.query_one("#vault_import_search").value = ""
            await wait_until(lambda: picker.shown == picker.total)
            assert picker.selected == [0, 1, 3]
            assert listing.get_option_at_index(_shown(listing).index(2)).disabled

            await _press(app, pilot, "#vault_import_sort")
            await wait_until(lambda: str(modal.query_one("#vault_import_sort").label).endswith("Name"))
            assert 2 not in picker.selected and listing.get_option_at_index(_shown(listing).index(2)).disabled
            assert "already in this vault as" in str(listing.get_option_at_index(_shown(listing).index(2)).prompt)


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["local", "bitwarden"])
async def test_hidden_selection_is_imported_in_list_order(tmp_path: Path, source: str) -> None:
    app, patches, service = _picker_host(tmp_path, source)
    service.import_keys = AsyncMock(side_effect=lambda **kw: {"item_id": "x", "name": "n", "public_fingerprint": kw.get("path", "") + kw.get("source_ref", "")})
    with patches[0], patches[1]:
        async with app.run_test(size=(160, 50)) as pilot:
            modal, listing = await _open_picker(app, pilot, source)
            picker = modal.query_one(FilterableSelection)
            await _press(app, pilot, "#vault_import_none")
            await wait_until(lambda: picker.selected == [])
            modal.query_one("#vault_import_search").value = "gamma"
            await wait_until(lambda: _shown(listing) == [3])
            await _press(app, pilot, "#vault_import_all")
            await wait_until(lambda: picker.selected == [3])
            modal.query_one("#vault_import_search").value = "alpha"
            await wait_until(lambda: _shown(listing) == [0])
            await _press(app, pilot, "#vault_import_all")
            await wait_until(lambda: picker.selected == [0, 3])
            modal.query_one("#vault_import_search").value = "beta"
            await wait_until(lambda: _shown(listing) == [1])
            assert picker.selected == [0, 3]
            if source == "local":
                modal._local_private_key = AsyncMock(side_effect=lambda key: bytearray(b"x"))
            else:
                modal._resolver = MagicMock()
                modal._resolver.resolve_ssh_key.return_value = "x"
            await pilot.click("#vault_import_confirm")
            await wait_until(lambda: service.import_keys.await_count == 2)
    refs = [
        (kw.get("path") or "").rsplit("/", 1)[-1] or kw.get("source_ref")
        for kw in (call.kwargs for call in service.import_keys.await_args_list)
    ]
    assert refs == (["alpha_key", "gamma_key"] if source == "local" else ["bw-1", "bw-4"])


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["local", "bitwarden"])
async def test_failed_vault_listing_blocks_import_in_the_dialog(tmp_path: Path, source: str) -> None:
    from textual.widgets import Static

    app, patches, _service_double = _picker_host(tmp_path, source, listing_fails=True)
    with patches[0], patches[1]:
        async with app.run_test(size=(160, 50)) as pilot:
            modal, _listing = await _open_picker(app, pilot, source)
            assert modal.query_one("#vault_import_confirm").disabled
            assert "import is blocked" in str(modal.query_one("#vault_import_status", Static).render())


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["local", "bitwarden"])
async def test_demo_toggle_keeps_selection_filter_and_hides_real_names(tmp_path: Path, source: str) -> None:
    app, patches, _service_double = _picker_host(tmp_path, source)
    with patches[0], patches[1]:
        async with app.run_test(size=(160, 50)) as pilot:
            modal, listing = await _open_picker(app, pilot, source)
            picker = modal.query_one(FilterableSelection)
            await _press(app, pilot, "#vault_import_none")
            modal.query_one("#vault_import_search").value = "e"
            await wait_until(lambda: len(_shown(listing)) == 4)
            await _press(app, pilot, "#vault_import_all")
            await wait_until(lambda: picker.selected == [0, 1, 3])
            await _press(app, pilot, "#vault_import_none")
            picker.select_values([1])
            await wait_until(lambda: picker.selected == [1])

            app.demo_mode = True
            modal.refresh_after_demo_toggle()
            await wait_until(lambda: "hidden-2" in str(listing.get_option_at_index(_shown(listing).index(1)).prompt))
            assert picker.selected == [1]
            assert modal.query_one("#vault_import_search").value == "e"
            assert "beta_key" not in str(listing.get_option_at_index(_shown(listing).index(1)).prompt)

            modal.query_one("#vault_import_search").value = "beta_key"
            await wait_until(lambda: _shown(listing) == [])
            modal.query_one("#vault_import_search").value = "hidden-2"
            await wait_until(lambda: _shown(listing) == [1])


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["local", "bitwarden"])
async def test_markup_in_a_name_is_shown_literally(tmp_path: Path, source: str) -> None:
    app, patches, _service_double = _picker_host(tmp_path, source)
    hostile = "[bold]x[/bold]"
    with patches[0], patches[1]:
        async with app.run_test(size=(160, 50)) as pilot:
            modal, listing = await _open_picker(app, pilot, source)
            if source == "local":
                modal._local_keys[0] = ScannedKey(path=tmp_path / "k", filename=hostile, encrypted=False, fingerprint="SHA256:aaa111")
                modal._show_local_options()
            else:
                modal._bw_items[0] = BwItemSummary(id="bw-1", name=hostile, type=5, has_ssh_key=True, fingerprint="SHA256:aaa111")
                modal._show_bitwarden_options()
            await wait_until(lambda: hostile in listing.get_option_at_index(0).prompt.plain)


@pytest.mark.asyncio
async def test_escape_does_not_close_while_loading_or_importing(tmp_path: Path) -> None:
    app, patches, _service_double = _picker_host(tmp_path, "local")
    with patches[0], patches[1]:
        async with app.run_test(size=(160, 50)) as pilot:
            modal, _listing = await _open_picker(app, pilot, "local")
            for flag, text in (("_loading", "Still loading"), ("_importing", "still running")):
                setattr(modal, flag, True)
                await pilot.press("escape")
                await wait_until(lambda: text in str(modal.query_one("#vault_import_status").render()))
                assert app.screen is modal
                setattr(modal, flag, False)
            await pilot.press("escape")
            await wait_until(lambda: not isinstance(app.screen, VaultImportModal))


@pytest.mark.asyncio
async def test_ctrl_f_focuses_the_search_box(tmp_path: Path) -> None:
    app, patches, _service_double = _picker_host(tmp_path, "local")
    with patches[0], patches[1]:
        async with app.run_test(size=(160, 50)) as pilot:
            modal, listing = await _open_picker(app, pilot, "local")
            listing.focus()
            await pilot.press("ctrl+f")
            await wait_until(lambda: app.focused is modal.query_one("#vault_import_search"))


def _many_host(tmp_path: Path, count: int = 12):
    """A host whose local files and Bitwarden items are ``key-1`` .. ``key-N``."""
    from textual.app import App

    local = [
        ScannedKey(
            path=tmp_path / f"key-{n}", filename=f"key-{n}", encrypted=False,
            key_type="ssh-ed25519", fingerprint=f"SHA256:fp{n}",
        )
        for n in range(1, count + 1)
    ]
    items = [
        BwItemSummary(id=f"bw-{n}", name=f"key-{n}", type=5, has_ssh_key=True, fingerprint=f"SHA256:fp{n}")
        for n in range(1, count + 1)
    ]
    session = MagicMock()
    session.list_items = AsyncMock(return_value=items)
    service = _service()

    class Host(App):
        async def push_screen_wait(self, _screen):
            return True

        def on_mount(self) -> None:
            self.push_screen(VaultImportModal(service, "vault-1", tmp_path, session_service=session))

    async def immediate_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    patches = (
        patch("servonaut.screens.vault_import_modal.scan_directory", return_value=local),
        patch("servonaut.screens.vault_import_modal.asyncio.to_thread", new=immediate_thread),
    )
    return Host(), patches


async def _open_many(app, pilot, source: str, count: int):
    await wait_until(lambda: isinstance(app.screen, VaultImportModal))
    await pilot.click("#vault_import_local" if source == "local" else "#vault_import_bitwarden")
    modal = app.screen
    picker = modal.query_one(FilterableSelection)
    await wait_until(lambda: picker.total == count and not modal._loading)
    return modal, picker


@pytest.mark.asyncio
async def test_import_button_counts_selected_keys_hidden_by_the_filter(tmp_path: Path) -> None:
    from textual.widgets import Button

    app, patches = _many_host(tmp_path)
    with patches[0], patches[1]:
        async with app.run_test(size=(160, 50)) as pilot:
            modal, picker = await _open_many(app, pilot, "local", 12)
            button = modal.query_one("#vault_import_confirm", Button)
            assert button.label.plain == "Import selected (12)"
            modal.query_one("#vault_import_search").value = "key-7"
            await wait_until(lambda: picker.shown == 1)
            assert button.label.plain == "Import selected (12)"
            await _press(app, pilot, "#vault_import_none")
            await wait_until(lambda: button.label.plain == "Import selected (11)")
            modal.query_one("#vault_import_search").value = ""
            await _press(app, pilot, "#vault_import_none")
            await wait_until(lambda: button.disabled and button.label.plain == "Import selected (0)")


@pytest.mark.asyncio
async def test_changing_the_source_clears_the_search_text(tmp_path: Path) -> None:
    app, patches = _many_host(tmp_path)
    with patches[0], patches[1]:
        async with app.run_test(size=(160, 50)) as pilot:
            modal, picker = await _open_many(app, pilot, "local", 12)
            search = modal.query_one("#vault_import_search")
            search.value = "key-7"
            await wait_until(lambda: picker.shown == 1)
            await _press(app, pilot, "#vault_import_bitwarden")
            await wait_until(lambda: modal._source == "bitwarden" and not modal._loading and picker.shown == 12)
            assert search.value == "" and picker.query_text == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["local", "bitwarden"])
async def test_the_fingerprint_algorithm_prefix_does_not_match_every_row(tmp_path: Path, source: str) -> None:
    app, patches = _many_host(tmp_path, 40)
    with patches[0], patches[1]:
        async with app.run_test(size=(160, 50)) as pilot:
            modal, picker = await _open_many(app, pilot, source, 40)
            search = modal.query_one("#vault_import_search")
            search.value = "25"
            await wait_until(lambda: picker.shown == 1)
            assert picker.listing.get_option_at_index(0).value == 24
            search.value = "sha"
            await wait_until(lambda: picker.shown == 0)


@pytest.mark.asyncio
async def test_the_key_type_is_not_searchable_when_the_row_does_not_show_it(tmp_path: Path) -> None:
    app, patches = _many_host(tmp_path, 3)
    with patches[0], patches[1]:
        async with app.run_test(size=(160, 50)) as pilot:
            modal, picker = await _open_many(app, pilot, "local", 3)
            modal.query_one("#vault_import_search").value = "ed25519"
            await wait_until(lambda: picker.shown == 0)
