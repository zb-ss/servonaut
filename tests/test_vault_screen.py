"""Small structural tests for the vault TUI surface."""
from __future__ import annotations

import asyncio
from html import unescape
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from textual.app import App, ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, DataTable, Input, Static

from servonaut.screens.ca import CaScreen
from servonaut.screens.vault import (
    VaultImportedReferenceModal,
    VaultPendingDeviceModal,
    VaultRecoveryConfirmModal,
    VaultScreen,
    show_pending_device,
)
from servonaut.services.api_client import APIError, FeatureDisabledError
from servonaut.services.vault.errors import SSH_CA_COMING_SOON
from servonaut.styles import CSS_FILES
from tests._async_bounds import wait_until

def test_vault_screen_exposes_safe_metadata_actions() -> None:
    actions = {binding.action for binding in VaultScreen.BINDINGS}

    assert {"back", "refresh", "reveal", "exposures"}.issubset(actions)


def test_vault_screen_rotates_exposures_with_per_host_results() -> None:
    source = Path("src/servonaut/screens/vault.py").read_text()

    assert '"rotate_ssh_key"' in source
    assert 'table.add_columns("Server", "Status", "Detail")' in source
    assert '"ROTATE"' in source


def test_vault_screen_uses_verified_device_callbacks_and_reset_polling() -> None:
    source = Path("src/servonaut/screens/vault.py").read_text()

    assert "async def show_pending_device" in source
    assert "VaultPendingDeviceModal(device)" in source
    assert '"drain_device_pending_events"' in source
    assert '"poll_reset_identity"' in source
    assert '"approval_poll_delay"' in source


class _VaultStatusService:
    def __init__(self, *, remote_identity, local_identity=None, unlock=False, unlock_error=False) -> None:
        self._status = {"remote": {"identity": remote_identity}, "local_identity": local_identity}
        self._unlock = unlock
        self._unlock_error = unlock_error
        self.list_calls = 0
        self.device_calls = 0

    async def status(self):
        return self._status

    def unlock_existing_identity(self):
        if self._unlock_error:
            raise RuntimeError("custody detail must not render")
        return self._unlock

    async def list_vaults(self):
        self.list_calls += 1
        return []

    async def list_devices(self):
        self.device_calls += 1
        return []


class _VaultHost(App):
    def __init__(self, service) -> None:
        self.vault_command_service = service
        self.vault_available = True
        super().__init__()

    def on_mount(self) -> None:
        self.push_screen(VaultScreen())


class _StyledVaultHost(_VaultHost):
    """Load product styles so compact-layout geometry is tested as users see it."""

    CSS_PATH = CSS_FILES


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("size", "remote_identity", "expected", "enabled"),
    [
        ((160, 50), None, "No vault identity exists yet", {"vault_setup"}),
        ((70, 30), {"identity_id": "remote-only"}, "vault identity on another device", {"vault_recover", "vault_add_device"}),
    ],
)
async def test_status_first_vault_flow_only_enables_safe_next_action(
    size, remote_identity, expected, enabled,
) -> None:
    service = _VaultStatusService(remote_identity=remote_identity)
    app = _VaultHost(service)

    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, VaultScreen)
        assert expected in str(screen.query_one("#vault_status", Static).render())
        assert service.list_calls == 0
        screen.action_devices()
        await pilot.pause()
        assert service.device_calls == 0
        action_ids = set(VaultScreen._READY_ACTIONS) | {"vault_setup", "vault_recover", "vault_add_device"}
        for button_id in action_ids:
            assert screen.query_one(f"#{button_id}", Button).disabled is (button_id not in enabled)


@pytest.mark.asyncio
async def test_locked_or_foreign_custody_does_not_become_a_first_user() -> None:
    service = _VaultStatusService(remote_identity=None, unlock_error=True)
    app = _VaultHost(service)

    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, VaultScreen)
        status = str(screen.query_one("#vault_status", Static).render())
        assert "could not be unlocked" in status
        assert "custody detail" not in status
        assert service.list_calls == 0
        for button_id in set(VaultScreen._READY_ACTIONS) | {"vault_setup", "vault_recover", "vault_add_device"}:
            assert screen.query_one(f"#{button_id}", Button).disabled


@pytest.mark.asyncio
async def test_unlocked_local_identity_is_the_only_state_that_reads_vaults() -> None:
    service = _VaultStatusService(remote_identity={"identity_id": "remote"}, local_identity="local-fingerprint")
    app = _VaultHost(service)

    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, VaultScreen)
        assert "Identity fingerprint: local-fingerprint" in str(screen.query_one("#vault_status", Static).render())
        assert service.list_calls == 1
        assert not screen.query_one("#vault_items", Button).disabled
        assert screen.query_one("#vault_setup", Button).disabled
        assert screen.query_one("#vault_recover", Button).disabled


@pytest.mark.asyncio
async def test_narrow_vault_keeps_metadata_visible_and_scrolls_clear_actions() -> None:
    class DelayedService(_VaultStatusService):
        def __init__(self) -> None:
            super().__init__(remote_identity={"identity_id": "remote"}, local_identity="local-fingerprint")
            self.metadata_requested = asyncio.Event()
            self.release_metadata = asyncio.Event()

        async def list_vaults(self):
            self.metadata_requested.set()
            await self.release_metadata.wait()
            return [{
                "name": "Narrow metadata vault",
                "kind": "personal",
                "vault_id": "vault-narrow",
                "counts": {"items": 1, "open_exposures": 0},
            }]

    service = DelayedService()
    app = _StyledVaultHost(service)

    async with app.run_test(size=(100, 30)) as pilot:
        await asyncio.wait_for(service.metadata_requested.wait(), timeout=2)
        service.release_metadata.set()
        table = app.screen.query_one("#vault_table", DataTable)
        await wait_until(lambda: table.row_count == 1)

        screen = app.screen
        assert isinstance(screen, VaultScreen)
        assert screen.has_class("-narrow") and screen.has_class("-short")
        assert table.region.height >= 7
        await pilot.pause()
        screenshot = unescape(app.export_screenshot(simplify=True))
        assert "Name" in screenshot
        assert all(fragment in screenshot for fragment in ("Narrow", "metadata", "vault"))

        action_scroll = screen.query_one("#vault_action_scroll", VerticalScroll)
        assert action_scroll.region.height <= 8
        assert str(screen.query_one("#vault_rotate_exposure", Button).label) == "Rotate exposed SSH key"
        assert str(screen.query_one("#vault_rotate", Button).label) == "Rotate vault key"

        first = screen.query_one("#vault_refresh", Button)
        last = screen.query_one("#vault_rotate", Button)
        first.focus()
        for _ in range(20):
            if last.has_focus:
                break
            await pilot.press("tab")
        assert last.has_focus
        assert action_scroll.scroll_y > 0


@pytest.mark.asyncio
async def test_import_refreshes_selected_vault_counts_before_bitwarden_binding_offer() -> None:
    class DelayedImportService(_VaultStatusService):
        def __init__(self) -> None:
            super().__init__(remote_identity={"identity_id": "remote"}, local_identity="local-fingerprint")
            self.refresh_requested = asyncio.Event()
            self.release_refresh = asyncio.Event()

        async def list_vaults(self):
            self.list_calls += 1
            if self.list_calls == 1:
                return [
                    {"name": "Other vault", "kind": "personal", "vault_id": "vault-other", "counts": {"items": 0, "open_exposures": 0}},
                    {"name": "Imported vault", "kind": "team", "vault_id": "vault-imported", "counts": {"items": 0, "open_exposures": 0}},
                ]
            self.refresh_requested.set()
            await self.release_refresh.wait()
            return [
                {"name": "Other vault", "kind": "personal", "vault_id": "vault-other", "counts": {"items": 0, "open_exposures": 0}},
                {"name": "Imported vault", "kind": "team", "vault_id": "vault-imported", "counts": {"items": 2, "open_exposures": 0}},
            ]

    service = DelayedImportService()
    app = _StyledVaultHost(service)

    async with app.run_test(size=(100, 30)) as pilot:
        table = app.screen.query_one("#vault_table", DataTable)
        await wait_until(lambda: table.row_count == 2)
        table.move_cursor(row=1)
        screen = app.screen
        assert isinstance(screen, VaultScreen)
        offered = AsyncMock()
        screen._offer_imported_bitwarden_binding = offered
        modal_callback = {}
        app.push_screen = lambda _modal, callback: modal_callback.setdefault("imported", callback)
        screen.action_import()
        modal_callback["imported"]({
            "imported": 2,
            "failed": 0,
            "references": [{"source": "bitwarden", "vault_item_id": "item-1", "source_ref": "bw-1"}],
        })
        await asyncio.wait_for(service.refresh_requested.wait(), timeout=2)
        service.release_refresh.set()
        await wait_until(lambda: table.cursor_row == 1 and offered.await_count == 1)

        assert screen._selected_vault_id == "vault-imported"
        assert "2 imported, 0 failed" in str(screen.query_one("#vault_status", Static).render())
        assert "2" in str(table.get_row_at(1))
        offered.assert_awaited_once_with("vault-imported", [{"source": "bitwarden", "vault_item_id": "item-1", "source_ref": "bw-1"}])


@pytest.mark.asyncio
async def test_setup_result_is_purposeful_metadata_not_raw_identity_payload() -> None:
    class Service(_OnboardingService):
        def __init__(self) -> None:
            super().__init__(trust="pending_confirmation")
            self.enrolled = False

        async def status(self):
            if not self.enrolled:
                return {"remote": {"identity": None}, "local_identity": None}
            return await super().status()

        async def setup(self, **_kwargs):
            self.enrolled = True
            return {"identity": {"identity_id": "not-for-status", "sig_public_key": "public-data"},
                    "confirmation": {"state": "pending_confirmation"}}

    app = _VaultHost(Service())
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        assert isinstance(screen, VaultScreen)
        await wait_until(lambda: "No vault identity exists yet" in _status_text(screen))
        await screen._setup(lambda _key: True)
        status = _status_text(screen)
        # Setup goes straight on to the next step instead of asking for a refresh.
        assert "Confirm your vault identity" in status
        assert "not-for-status" not in status
        assert not screen.query_one("#vault_items", Button).disabled


@pytest.mark.asyncio
async def test_demo_toggle_redraws_cached_vault_metadata_without_fetching_again() -> None:
    class Redactor:
        def scrub_stream(self, _text: str) -> str:
            return "redacted"

    service = _VaultStatusService(remote_identity={"identity_id": "remote"}, local_identity="local")
    service.list_vaults = AsyncMock(return_value=[{"name": "private-vault-name", "kind": "personal", "vault_id": "vault-private", "counts": {}}])
    app = _VaultHost(service)
    app.demo_mode = False
    app.redaction_service = Redactor()

    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, VaultScreen)
        assert "private-vault-name" in str(screen.query_one("#vault_table", DataTable).get_row_at(0))
        app.demo_mode = True
        screen.refresh_after_demo_toggle()
        assert "private-vault-name" not in str(screen.query_one("#vault_table", DataTable).get_row_at(0))
        assert "redacted" in str(screen.query_one("#vault_table", DataTable).get_row_at(0))
        assert service.list_vaults.await_count == 1


@pytest.mark.asyncio
async def test_demo_mode_redacts_ca_status_and_repaints_cached_value() -> None:
    class Redactor:
        def scrub_stream(self, _text: str) -> str:
            return "redacted CA status"

    class Service:
        async def ca_status(self, *, team: str):
            assert team == "private-team"
            return {"hostname": "private-ca-host", "enabled": True}

    class Host(App):
        demo_mode = True
        redaction_service = Redactor()
        vault_command_service = Service()

        def on_mount(self) -> None:
            self.push_screen(CaScreen())

    app = Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, CaScreen)
        await screen._load("private-team")
        rendered = str(screen.query_one("#ca_status", Static).render())
        assert "private-ca-host" not in rendered
        assert "redacted CA status" in rendered
        app.demo_mode = False
        screen.refresh_after_demo_toggle()
        assert "private-ca-host" in str(screen.query_one("#ca_status", Static).render())


_CA_ACTIONS = ("#ca_audit", "#ca_enroll", "#ca_krl", "#ca_break_glass_scan")


class _SwitchableCaService:
    """CA calls answered the way a service without SSH certificates answers, until switched on."""

    def __init__(self) -> None:
        self.switched_on = False
        self.audits = 0

    def _refuse(self) -> None:
        if not self.switched_on:
            raise FeatureDisabledError(
                code="feature_disabled", message="server text", status=503, details={"feature": "ssh_ca"},
            )

    async def ca_status(self, *, team: str):
        self._refuse()
        return {"team": team, "enabled": True}

    async def ca_audit(self, *, team: str):
        self.audits += 1
        self._refuse()
        return {"ok": True}


class _CaHost(App):
    def __init__(self, service: _SwitchableCaService) -> None:
        super().__init__()
        self.vault_command_service = service
        self.notes: list[tuple[str, dict]] = []

    def notify(self, message: str, **kwargs) -> None:
        self.notes.append((message, kwargs))

    def on_mount(self) -> None:
        self.push_screen(CaScreen())


def _ca_actions_disabled(screen: Screen) -> list[bool]:
    return [screen.query_one(selector, Button).disabled for selector in _CA_ACTIONS]


@pytest.mark.asyncio
async def test_switched_off_certificates_show_coming_soon_and_hold_back_ca_actions() -> None:
    service = _SwitchableCaService()
    app = _CaHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, CaScreen)
        status = screen.query_one("#ca_status", Static)
        screen.query_one("#ca_team", Input).value = "ops"
        await pilot.click("#ca_refresh")
        await wait_until(lambda: "coming soon" in str(status.render()))

        assert str(status.render()) == SSH_CA_COMING_SOON
        assert "Could not load" not in str(status.render())
        assert _ca_actions_disabled(screen) == [True, True, True, True]
        assert screen.query_one("#ca_refresh", Button).disabled is False
        assert app.notes == []

        await pilot.click("#ca_audit")
        await pilot.pause()
        assert service.audits == 0

        service.switched_on = True
        await pilot.click("#ca_refresh")
        await wait_until(lambda: "enabled: True" in str(status.render()))
        assert _ca_actions_disabled(screen) == [False, False, False, False]


@pytest.mark.asyncio
async def test_another_team_offers_the_ca_actions_again() -> None:
    app = _CaHost(_SwitchableCaService())
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        screen = app.screen
        team = screen.query_one("#ca_team", Input)
        team.value = "ops"
        await screen._load("ops")
        assert _ca_actions_disabled(screen) == [True, True, True, True]

        team.value = "ops "
        await pilot.pause()
        assert _ca_actions_disabled(screen) == [True, True, True, True]

        team.value = "platform"
        await wait_until(lambda: _ca_actions_disabled(screen) == [False, False, False, False])


@pytest.mark.asyncio
async def test_an_action_that_meets_switched_off_certificates_informs_instead_of_failing() -> None:
    service = _SwitchableCaService()
    app = _CaHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        screen = app.screen
        screen.query_one("#ca_team", Input).value = "ops"
        await pilot.click("#ca_audit")
        await wait_until(lambda: bool(app.notes))

        assert service.audits == 1
        assert app.notes == [(SSH_CA_COMING_SOON, {"severity": "information", "markup": False})]
        assert str(screen.query_one("#ca_status", Static).render()) == SSH_CA_COMING_SOON
        assert _ca_actions_disabled(screen) == [True, True, True, True]


@pytest.mark.asyncio
async def test_other_ca_action_failures_still_notify_an_error() -> None:
    class Service:
        async def ca_audit(self, *, team: str):
            raise APIError(code="ssh_ca_unavailable", message="server text", status=503)

    app = _CaHost(Service())  # type: ignore[arg-type]
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        screen = app.screen
        await screen._audit("ops")

        [(message, kwargs)] = app.notes
        assert message.startswith("CA audit failed (the Servonaut service cannot issue SSH certificates")
        assert kwargs == {"severity": "error", "markup": False}
        assert _ca_actions_disabled(screen) == [False, False, False, False]


@pytest.mark.asyncio
async def test_pending_device_modal_is_presented_while_fleet_is_active() -> None:
    class FleetScreen(Screen):
        def compose(self) -> ComposeResult:
            yield Static("Fleet", id="fleet_label")

    class Host(App):
        def on_mount(self) -> None:
            self.push_screen(FleetScreen())

    app = Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, FleetScreen)
        presenter = asyncio.create_task(
            show_pending_device(
                app,
                object(),
                {"device_id": "device-1", "name": "New laptop", "platform": "linux"},
            )
        )
        await pilot.pause()
        assert isinstance(app.screen, VaultPendingDeviceModal)
        await pilot.click("#vault_pending_device_later")
        await presenter
        assert isinstance(app.screen, FleetScreen)


@pytest.mark.asyncio
async def test_imported_bitwarden_reference_requires_explicit_tui_selection() -> None:
    reference = {"vault_item_id": "vault-item-1", "source_ref": "bitwarden-item-1"}

    class Host(App):
        selected = None

        def on_mount(self) -> None:
            self.run_worker(self.choose())

        async def choose(self) -> None:
            self.selected = await self.push_screen_wait(VaultImportedReferenceModal([reference]))

    app = Host()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, VaultImportedReferenceModal)
        await pilot.click("#vault_import_bind_continue")
        await pilot.pause()
        assert app.selected == reference


def test_ca_screen_exposes_refresh() -> None:
    actions = {binding.action for binding in CaScreen.BINDINGS}

    assert {"back", "refresh"}.issubset(actions)


def test_native_server_action_passes_public_identity_file() -> None:
    source = Path("src/servonaut/screens/server_actions.py").read_text()

    assert 'identity_file=getattr(resolved, "identity_file", None)' in source
    assert 'not getattr(resolved, "identity_file", None)' in source
    assert '"servonaut_vault": "Servonaut Vault"' in source


def test_recovery_modal_challenges_only_secret_groups(monkeypatch) -> None:
    candidate_indices: list[int] = []

    def sample(_self, population, _count):
        candidate_indices.extend(population)
        return [1, 2]

    monkeypatch.setattr("servonaut.screens.vault.secrets.SystemRandom.sample", sample)

    modal = VaultRecoveryConfirmModal("SVRK1-ABCDE-FGHIJ")

    assert candidate_indices == [1, 2]
    assert modal._checks == [1, 2]


def test_recovery_modal_requires_two_secret_groups() -> None:
    assert VaultRecoveryConfirmModal("SVRK1-ABCDE")._checks == []


def test_rotation_summary_says_what_happened_to_the_exposure() -> None:
    from servonaut.screens.vault import _rotation_summary

    assert _rotation_summary({"resolved": ["e-1"], "needs_owner": False, "failed": []}).endswith(
        "1 exposure resolved as rotated."
    )
    assert "Ask an owner or admin to resolve the exposure." in _rotation_summary(
        {"resolved": [], "needs_owner": True, "failed": []}
    )
    assert "could not be marked resolved (HTTP 500)" in _rotation_summary(
        {"resolved": [], "needs_owner": False, "failed": [{"exposure_id": "e-1", "reason": "HTTP 500"}]}
    )
    assert _rotation_summary(None) == "SSH key rotation completed on all selected hosts."


@pytest.mark.asyncio
async def test_exposure_table_notes_a_key_replaced_in_the_vault() -> None:
    class Service(_VaultStatusService):
        async def list_exposures(self, *, vault_id):
            return {"data": [
                {"exposure_id": "e-1", "item_id": "i", "subject": "member", "reason": "member_removed", "key_replaced": True},
                {"exposure_id": "e-2", "item_id": "j", "subject": "member", "reason": "member_removed", "key_replaced": False},
            ]}

    service = Service(remote_identity={"identity_id": "remote"}, local_identity="local-fingerprint")
    app = _VaultHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await wait_until(lambda: "Identity fingerprint" in str(screen.query_one("#vault_status", Static).render()))
        screen._selected_vault_id = "vault-1"
        await screen._load_exposures()
        table = screen.query_one("#vault_table", DataTable)
        rows = [table.get_row_at(index) for index in range(table.row_count)]

    assert rows[0][2] == "Key replaced in vault; old key may still be on servers"
    assert rows[1][2] == ""


class _OnboardingService:
    """A signed-in user with a local identity, for the onboarding steps."""

    def __init__(self, *, trust="confirmed", vaults=None, can_create_personal=True, options=None, confirm_state="confirmed"):
        self.trust = trust
        self.vaults = list(vaults or [])
        self.can_create = can_create_personal
        self.options = list(options if options is not None else [{"team": None, "label": "Personal vault"}])
        self.confirm_state = confirm_state
        self.created: list[dict] = []
        self.item_calls = 0

    async def status(self):
        return {"remote": {"identity": {"identity_id": "i", "trust_status": self.trust}},
                "local_identity": "local-fingerprint", "fingerprint": "local-fingerprint"}

    async def list_vaults(self):
        return list(self.vaults)

    def can_create_personal_vault(self):
        return self.can_create

    async def confirm_identity(self):
        if self.confirm_state == "confirmed":
            self.trust = "confirmed"
        return {"confirmation": {"state": self.confirm_state, "expires_at": None}}

    async def creatable_vaults(self, *, vaults):
        return list(self.options)

    async def create_vault(self, *, team, name, grant_policy):
        self.created.append({"team": team, "name": name, "grant_policy": grant_policy})
        self.vaults.append({"vault_id": "v-new", "kind": "personal", "name": "Personal", "my_role": "owner",
                            "my_grant": {"version": 1}, "counts": {"items": 0, "open_exposures": 0}})
        return self.vaults[-1]

    async def list_items(self, **_kwargs):
        self.item_calls += 1
        return {"data": []}


def _status_text(screen) -> str:
    return str(screen.query_one("#vault_status", Static).render())


@pytest.mark.asyncio
async def test_unconfirmed_identity_shows_how_to_confirm_it_and_confirms_here() -> None:
    service = _OnboardingService(trust="pending_confirmation")
    app = _VaultHost(service)

    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await wait_until(lambda: "Confirm your vault identity" in _status_text(screen))
        assert not screen.query_one("#vault_confirm_identity", Button).disabled

        screen.query_one("#vault_confirm_identity", Button).press()

        await wait_until(lambda: "Confirm your vault identity" not in _status_text(screen)
                         and "Create your personal vault" in _status_text(screen))


@pytest.mark.asyncio
async def test_confirmation_by_e_mail_says_to_open_the_link_then_refresh() -> None:
    service = _OnboardingService(trust="pending_confirmation", confirm_state="email_sent")
    app = _VaultHost(service)

    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await wait_until(lambda: "Confirm your vault identity" in _status_text(screen))

        screen.query_one("#vault_confirm_identity", Button).press()

        await wait_until(lambda: "We e-mailed you a new confirmation link" in _status_text(screen))


@pytest.mark.asyncio
async def test_create_vault_offers_the_personal_vault_and_creates_it() -> None:
    from servonaut.screens.vault import VaultCreateModal

    service = _OnboardingService()
    app = _VaultHost(service)

    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await wait_until(lambda: "Create your personal vault" in _status_text(screen))

        screen.query_one("#vault_create", Button).press()
        # The modal focuses its picker once its widgets are mounted; press, not
        # click, because a click aimed while it lays out can land elsewhere.
        await wait_until(lambda: isinstance(app.screen, VaultCreateModal) and app.screen.focused is not None
                         and app.screen.focused.id == "vault_create_target")
        app.screen.query_one("#vault_create_confirm", Button).press()

        await wait_until(lambda: service.created == [{"team": None, "name": None, "grant_policy": "auto"}])
        await wait_until(lambda: app.screen is screen and screen.query_one("#vault_table", DataTable).row_count == 1)
        assert "Create your personal vault" not in _status_text(screen)


@pytest.mark.asyncio
async def test_create_vault_with_nothing_to_create_explains_why() -> None:
    service = _OnboardingService(options=[], vaults=[{"vault_id": "v", "kind": "personal", "my_grant": {"version": 1}}])
    app = _VaultHost(service)

    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await wait_until(lambda: "Identity fingerprint" in _status_text(screen))

        screen.query_one("#vault_create", Button).press()

        await wait_until(lambda: "There is no vault to create" in _status_text(screen))
        assert service.created == []


@pytest.mark.asyncio
async def test_member_without_a_grant_is_told_access_is_pending_instead_of_a_refusal() -> None:
    vault_row = {"vault_id": "team-v", "kind": "team", "name": "Ops", "my_role": "member", "my_grant": None,
                 "counts": {"items": 2, "open_exposures": 0}}
    service = _OnboardingService(vaults=[vault_row])
    app = _VaultHost(service)

    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await wait_until(lambda: "Waiting for access to your team's vault" in _status_text(screen))
        await wait_until(lambda: screen.query_one("#vault_table", DataTable).row_count == 1)

        await pilot.click("#vault_items")
        await pilot.pause()

        assert "Waiting for access to your team's vault" in _status_text(screen)
        assert service.item_calls == 0


@pytest.mark.asyncio
async def test_pressing_setup_twice_keeps_one_setup_and_one_recovery_dialog() -> None:
    from servonaut.screens.vault import VaultRecoveryConfirmModal

    class Service(_VaultStatusService):
        def __init__(self) -> None:
            super().__init__(remote_identity=None)
            self.setup_calls = 0
            self.outcomes: list[bool] = []

        async def setup(self, *, device_name, platform, recovery_confirmation):
            self.setup_calls += 1
            confirmed = await recovery_confirmation("SVRK1-AAAAA-BBBBB-CCCCC")
            self.outcomes.append(confirmed)
            if not confirmed:
                raise RuntimeError("recovery key was not confirmed")
            return {"confirmation": {"state": "confirmed"}}

    service = Service()
    app = _VaultHost(service)

    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await wait_until(lambda: "No vault identity exists yet" in _status_text(screen))
        setup = screen.query_one("#vault_setup", Button)

        setup.press()
        setup.press()
        await wait_until(lambda: isinstance(app.screen, VaultRecoveryConfirmModal))
        await pilot.pause()

        assert service.setup_calls == 1
        assert sum(isinstance(item, VaultRecoveryConfirmModal) for item in app.screen_stack) == 1
        app.screen.dismiss(False)
        await wait_until(lambda: service.outcomes == [False])
        # Once that setup has finished, Setup works again.
        await wait_until(lambda: not screen._setup_running)
        setup.press()
        await wait_until(lambda: service.setup_calls == 2)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_recovery_key_breaks_only_between_groups(size) -> None:
    from servonaut.screens.vault import VaultRecoveryConfirmModal
    from servonaut.services.vault.crypto import format_recovery_key

    key = format_recovery_key(bytes(range(32)))

    class Host(App):
        CSS_PATH = CSS_FILES

        def on_mount(self) -> None:
            self.push_screen(VaultRecoveryConfirmModal(key))

    app = Host()
    async with app.run_test(size=size) as pilot:
        await wait_until(lambda: isinstance(app.screen, VaultRecoveryConfirmModal))
        await pilot.pause()
        shown = app.screen.query_one("#vault_recovery_key", Static)
        rows = ["".join(segment.text for segment in line) for line in shown.render_lines(shown.region.reset_offset)]
        text_rows = [row.strip("│ ") for row in rows if any(character.isalnum() for character in row)]
        groups = key.split("-")
        assert "".join(text_rows) == key
        for row in text_rows:
            # Every visual line holds whole groups only.
            assert all(part in groups for part in row.strip("-").split("-")), row
