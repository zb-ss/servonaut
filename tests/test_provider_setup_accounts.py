"""The Hetzner and OVH setup wizards: the primary account and extra ones.

The wizards run in a small host app with a real ConfigManager in a temp
directory. The provider services are stand-ins whose connection test passes
or fails on demand, so nothing reaches a provider. Checked: an extra
account is tested before it is saved and never with the primary account's
ambient credentials, saving keeps every other account, the accounts are
reloaded instead of services being swapped on the app, and secrets never
render.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional
from unittest.mock import MagicMock

import pytest
from textual.app import App
from textual.screen import Screen
from textual.widgets import Button, Input, Select

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import (
    AppConfig,
    HetznerAccount,
    HetznerConfig,
    ObjectStorageConfig,
    OVHAccount,
    OVHConfig,
)
from servonaut.screens.hetzner_setup import HetznerSetupScreen
from servonaut.screens.ovh_setup import OVHSetupScreen
from servonaut.styles import CSS_FILES

pytestmark = pytest.mark.asyncio

PRIMARY_TOKEN = "hz-primary-token-0001"
EXTRA_TOKEN = "hz-extra-token-0002"
OVH_APP_SECRET = "ovh-app-secret-0003"
OVH_CLIENT_SECRET = "ovh-client-secret-0004"


class Inventory:
    def __init__(self, rows: List[dict]) -> None:
        self.rows = rows
        self.fetches = 0
        self.last_fetch_error: Optional[str] = None

    def get_cached_instances(self) -> List[dict]:
        return list(self.rows)

    async def fetch_instances_cached(self, force_refresh: bool = False) -> List[dict]:
        self.fetches += 1
        return list(self.rows)


class Host(App):
    """Opens one wizard over a blank screen; records account reloads."""

    CSS_PATH = CSS_FILES

    def __init__(self, manager: ConfigManager, wizard: Callable[[], Screen]) -> None:
        super().__init__()
        self.config_manager = manager
        self._wizard = wizard
        self.accounts = MagicMock()
        self.accounts.unavailable = {}
        self.rebuilds = 0
        self.inventory = Inventory([
            {"id": "1", "name": "web-1", "account": "hetzner", "is_hetzner": True},
            {"id": "2", "name": "web-2", "account": "staging", "is_hetzner": True},
        ])
        self.instances: List[dict] = []
        self._instances_pristine: List[dict] = []
        self.demo_mode = False
        self.redaction_service = None
        self.auth_service = MagicMock(is_authenticated=False)
        # Sentinels: the wizards must not swap provider services themselves.
        self.hetzner_service = "untouched"
        self.ovh_service = "untouched"
        self.aws_object_storage_service = None
        self.hetzner_object_storage_service = None
        self.ovh_object_storage_service = None
        self.messages: List[str] = []

    def rebuild_accounts(self) -> None:
        self.rebuilds += 1

    def provider_inventory(self, provider: str):
        return self.inventory

    def notify(self, message: str, **kwargs: Any) -> None:  # type: ignore[override]
        self.messages.append(str(message))

    def on_mount(self) -> None:
        self.push_screen(self._wizard())


def _manager(tmp_path, config: AppConfig) -> ConfigManager:
    manager = ConfigManager()
    manager._config_path = tmp_path / "config.json"  # type: ignore[attr-defined]
    manager._config = config  # type: ignore[attr-defined]
    manager.save(config)
    return manager


def _reread(tmp_path) -> AppConfig:
    manager = ConfigManager()
    manager._config_path = tmp_path / "config.json"  # type: ignore[attr-defined]
    return manager.load()


async def _settle(pilot) -> None:
    await pilot.pause()
    await pilot.app.workers.wait_for_complete()
    await pilot.pause()


def _fill(screen: Screen, values: Dict[str, str]) -> None:
    for field_id, value in values.items():
        screen.query_one(f"#{field_id}", Input).value = value


# ---------------------------------------------------------------------------
# Hetzner
# ---------------------------------------------------------------------------


class FakeHetznerService:
    """Stand-in for HetznerService: records how it was built."""

    built: List[Dict[str, Any]] = []
    succeed = True

    def __init__(self, config, allow_ambient_token: bool = True) -> None:
        FakeHetznerService.built.append(
            {"token": config.api_token, "ambient": allow_ambient_token}
        )

    async def test_connection(self) -> dict:
        if FakeHetznerService.succeed:
            return {"success": True, "message": "Connected. 1 server(s) in project."}
        return {"success": False, "message": "Authentication failed: unauthorized"}

    async def list_ssh_keys(self) -> List[dict]:
        return [{"name": "deploy", "fingerprint": "aa:bb"}]

    async def list_server_types(self) -> List[dict]:
        return [{"name": "cx23"}]

    async def list_images(self) -> List[dict]:
        return [{"name": "ubuntu-22.04"}]

    async def list_locations(self) -> List[dict]:
        return [{"name": "fsn1"}]


@pytest.fixture
def hetzner_service(monkeypatch):
    import servonaut.services.hetzner_service as module

    async def installed(self) -> bool:
        return True

    FakeHetznerService.built = []
    FakeHetznerService.succeed = True
    monkeypatch.setattr(module, "HetznerService", FakeHetznerService)
    monkeypatch.setattr(HetznerSetupScreen, "_install_hcloud_if_needed", installed)
    return FakeHetznerService


def _hetzner_config(**extra: Any) -> AppConfig:
    return AppConfig(
        hetzner=HetznerConfig(
            enabled=True,
            api_token=PRIMARY_TOKEN,
            cost_alert_threshold=25.0,
            **extra,
        )
    )


class TestHetznerAddProject:
    async def test_a_working_token_is_saved_as_a_new_project(
        self, tmp_path, hetzner_service
    ) -> None:
        app = Host(_manager(tmp_path, _hetzner_config()), lambda: HetznerSetupScreen(add_extra=True))
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            screen = app.screen
            # Provider-wide create defaults belong to the primary project.
            assert not screen.query("#hetzner_select_image")
            assert not screen.query("#btn_hetzner_disable")
            _fill(screen, {
                "hetzner_input_label": "staging",
                "hetzner_input_token": "$HCLOUD_TOKEN_STAGING",
            })
            screen.query_one("#btn_hetzner_save", Button).press()
            await _settle(pilot)

            assert hetzner_service.built == [
                {"token": "$HCLOUD_TOKEN_STAGING", "ambient": False}
            ]
            assert app.rebuilds == 1
            assert app.inventory.fetches == 1
            assert not isinstance(app.screen, HetznerSetupScreen)
            assert "Hetzner project 'staging' saved." in app.messages
            assert "Hetzner project 'staging': 1 server(s) loaded." in app.messages
            assert app.hetzner_service == "untouched"
        hetzner = _reread(tmp_path).hetzner
        assert hetzner.api_token == PRIMARY_TOKEN
        (project,) = hetzner.accounts
        assert (project.label, project.api_token) == ("staging", "$HCLOUD_TOKEN_STAGING")
        assert project.default_hetzner_ssh_key == "deploy"
        # An empty username inherits the primary project's.
        assert project.default_username == ""

    async def test_a_refused_token_is_not_saved(self, tmp_path, hetzner_service) -> None:
        hetzner_service.succeed = False
        app = Host(_manager(tmp_path, _hetzner_config()), lambda: HetznerSetupScreen(add_extra=True))
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            _fill(app.screen, {"hetzner_input_label": "staging", "hetzner_input_token": EXTRA_TOKEN})
            app.screen.query_one("#btn_hetzner_save", Button).press()
            await _settle(pilot)
            assert isinstance(app.screen, HetznerSetupScreen)
            assert app.rebuilds == 0
            assert "The project was not saved: its token does not work." in app.messages
        assert _reread(tmp_path).hetzner.accounts == []

    @pytest.mark.parametrize(
        "label, token, message",
        [
            ("hetzner", EXTRA_TOKEN, "already used by Hetzner · hetzner"),
            ("custom", EXTRA_TOKEN, "is reserved"),
            ("", EXTRA_TOKEN, "label is required"),
            ("staging", "", "Enter an API token"),
        ],
    )
    async def test_an_invalid_project_is_not_tested_or_saved(
        self, tmp_path, hetzner_service, label, token, message
    ) -> None:
        app = Host(_manager(tmp_path, _hetzner_config()), lambda: HetznerSetupScreen(add_extra=True))
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            _fill(app.screen, {"hetzner_input_label": label, "hetzner_input_token": token})
            app.screen.query_one("#btn_hetzner_save", Button).press()
            await _settle(pilot)
            assert hetzner_service.built == []
            assert any(message in m for m in app.messages), app.messages
        assert _reread(tmp_path).hetzner.accounts == []

    async def test_a_plain_test_never_uses_the_primary_token(
        self, tmp_path, hetzner_service
    ) -> None:
        app = Host(_manager(tmp_path, _hetzner_config()), lambda: HetznerSetupScreen(add_extra=True))
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            _fill(app.screen, {"hetzner_input_token": "$UNSET_VARIABLE"})
            app.screen.query_one("#btn_hetzner_test", Button).press()
            await _settle(pilot)
            assert hetzner_service.built[-1]["ambient"] is False
            # Testing alone saves nothing.
            assert app.rebuilds == 0

    async def test_editing_a_project_keeps_its_place_and_storage(
        self, tmp_path, hetzner_service
    ) -> None:
        config = _hetzner_config(
            accounts=[
                HetznerAccount(
                    label="staging",
                    api_token=EXTRA_TOKEN,
                    default_username="deploy",
                    object_storage=ObjectStorageConfig(access_key="AK", secret_key="SK"),
                ),
                HetznerAccount(label="lab", api_token="$LAB"),
            ]
        )
        app = Host(_manager(tmp_path, config), lambda: HetznerSetupScreen(extra=0))
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert screen.query_one("#hetzner_input_label", Input).value == "staging"
            token = screen.query_one("#hetzner_input_token", Input)
            assert token.value == EXTRA_TOKEN and token.password
            assert EXTRA_TOKEN not in app.export_screenshot()
            _fill(screen, {"hetzner_input_label": "stage", "hetzner_input_username": "ops"})
            screen.query_one("#btn_hetzner_save", Button).press()
            await _settle(pilot)
            assert app.rebuilds == 1
        accounts = _reread(tmp_path).hetzner.accounts
        assert [(a.label, a.default_username) for a in accounts] == [
            ("stage", "ops"), ("lab", ""),
        ]
        assert accounts[0].object_storage.access_key == "AK"
        assert accounts[0].api_token == EXTRA_TOKEN


class TestHetznerPrimary:
    async def test_saving_keeps_the_extra_projects_and_reloads_accounts(
        self, tmp_path, hetzner_service
    ) -> None:
        config = _hetzner_config(
            label="main", accounts=[HetznerAccount(label="staging", api_token=EXTRA_TOKEN)]
        )
        app = Host(_manager(tmp_path, config), HetznerSetupScreen)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            screen = app.screen
            # Several projects: the primary's label is on the form.
            assert screen.query_one("#hetzner_input_label", Input).value == "main"
            assert PRIMARY_TOKEN not in app.export_screenshot()
            _fill(screen, {"hetzner_input_username": "admin"})
            screen.query_one("#btn_hetzner_save", Button).press()
            await _settle(pilot)
            assert app.rebuilds == 1
            assert app.inventory.fetches == 1
            assert "Hetzner enabled — 2 server(s) loaded." in app.messages
            assert app.hetzner_service == "untouched"
        hetzner = _reread(tmp_path).hetzner
        assert hetzner.default_username == "admin"
        assert hetzner.label == "main"
        assert hetzner.cost_alert_threshold == 25.0
        assert [a.label for a in hetzner.accounts] == ["staging"]
        assert hetzner.accounts[0].api_token == EXTRA_TOKEN

    async def test_a_single_project_setup_looks_as_before(self, tmp_path, hetzner_service) -> None:
        app = Host(_manager(tmp_path, _hetzner_config()), HetznerSetupScreen)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            assert not app.screen.query("#hetzner_label_row")
            assert app.screen.query("#hetzner_select_image")
            # Hetzner is set up, so another project can be added.
            assert app.screen.query_one("#btn_hetzner_add_project", Button).display

    async def test_another_project_needs_hetzner_enabled(self, tmp_path, hetzner_service) -> None:
        config = AppConfig(hetzner=HetznerConfig(enabled=False))
        app = Host(_manager(tmp_path, config), HetznerSetupScreen)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            assert not app.screen.query_one("#btn_hetzner_add_project", Button).display

    async def test_add_another_project_switches_the_wizard(self, tmp_path, hetzner_service) -> None:
        app = Host(_manager(tmp_path, _hetzner_config()), HetznerSetupScreen)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            app.screen.query_one("#btn_hetzner_add_project", Button).press()
            await pilot.pause()
            await pilot.pause()
            assert isinstance(app.screen, HetznerSetupScreen) and app.screen._add_extra
            assert app.screen.query_one("#hetzner_input_token", Input).value == ""

    async def test_renaming_to_a_taken_label_is_refused(self, tmp_path, hetzner_service) -> None:
        config = _hetzner_config(accounts=[HetznerAccount(label="staging", api_token="x")])
        app = Host(_manager(tmp_path, config), lambda: HetznerSetupScreen(show_label=True))
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            _fill(app.screen, {"hetzner_input_label": "Staging"})
            app.screen.query_one("#btn_hetzner_save", Button).press()
            await _settle(pilot)
            assert app.rebuilds == 0
            assert any("already used by Hetzner · staging" in m for m in app.messages)
        assert _reread(tmp_path).hetzner.label == ""

    async def test_disabling_keeps_the_projects_and_reloads(self, tmp_path, hetzner_service) -> None:
        config = _hetzner_config(accounts=[HetznerAccount(label="staging", api_token="x")])
        app = Host(_manager(tmp_path, config), HetznerSetupScreen)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            app.screen.query_one("#btn_hetzner_disable", Button).press()
            await _settle(pilot)
            assert app.rebuilds == 1
            assert app.hetzner_service == "untouched"
        hetzner = _reread(tmp_path).hetzner
        assert hetzner.enabled is False and [a.label for a in hetzner.accounts] == ["staging"]


# ---------------------------------------------------------------------------
# OVH
# ---------------------------------------------------------------------------


class FakeOVHService:
    built: List[Dict[str, str]] = []
    succeed = True

    def __init__(self, config, cache_path=None) -> None:
        FakeOVHService.built.append({
            "application_key": config.application_key,
            "consumer_key": config.consumer_key,
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "endpoint": config.endpoint,
        })

    async def test_connection(self) -> dict:
        if FakeOVHService.succeed:
            return {"success": True, "account": "ab12345-ovh", "message": "Connected"}
        return {"success": False, "account": "", "message": "Authentication failed."}

    async def request_consumer_key(self) -> dict:
        return {"consumerKey": "ck-new", "validationUrl": "https://example.com/validate"}


@pytest.fixture
def ovh_service(monkeypatch):
    import servonaut.services.ovh_service as module

    async def installed(self) -> bool:
        return True

    FakeOVHService.built = []
    FakeOVHService.succeed = True
    monkeypatch.setattr(module, "OVHService", FakeOVHService)
    monkeypatch.setattr(OVHSetupScreen, "_install_ovh_if_needed", installed)
    return FakeOVHService


def _ovh_config(**extra: Any) -> AppConfig:
    return AppConfig(
        ovh=OVHConfig(
            enabled=True,
            application_key="ak-primary",
            application_secret=OVH_APP_SECRET,
            consumer_key="ck-primary",
            client_id="cid-primary",
            ovh_audit_path="~/audit/ovh.json",
            cost_alert_threshold=40.0,
            **extra,
        )
    )


class TestOvhAddAccount:
    async def test_an_application_key_account_is_tested_then_saved(
        self, tmp_path, ovh_service
    ) -> None:
        app = Host(_manager(tmp_path, _ovh_config()), lambda: OVHSetupScreen(add_extra=True))
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert not screen.query_one("#ovh_input_client_id", Input).parent.display
            _fill(screen, {
                "ovh_input_label": "client-a",
                "ovh_input_endpoint": "ovh-ca",
                "ovh_input_app_key": "ak-a",
                "ovh_input_app_secret": "$OVH_A_SECRET",
                "ovh_input_consumer_key": "$OVH_A_CK",
                "ovh_input_project_ids": "p1, p2",
            })
            screen.query_one("#btn_ovh_save", Button).press()
            await _settle(pilot)
            assert ovh_service.built[-1]["application_key"] == "ak-a"
            assert ovh_service.built[-1]["client_id"] == ""
            assert app.rebuilds == 1 and app.inventory.fetches == 1
            assert not isinstance(app.screen, OVHSetupScreen)
            assert app.ovh_service == "untouched"
        ovh = _reread(tmp_path).ovh
        (account,) = ovh.accounts
        assert (account.label, account.endpoint, account.application_key) == (
            "client-a", "ovh-ca", "ak-a",
        )
        assert account.cloud_project_ids == ["p1", "p2"]
        assert ovh.application_key == "ak-primary"

    async def test_an_oauth2_account_keeps_only_the_client_credentials(
        self, tmp_path, ovh_service
    ) -> None:
        app = Host(_manager(tmp_path, _ovh_config()), lambda: OVHSetupScreen(add_extra=True))
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            screen = app.screen
            _fill(screen, {"ovh_input_label": "client-b", "ovh_input_app_key": "typed-first"})
            screen.query_one("#ovh_select_auth", Select).value = "oauth"
            await pilot.pause()
            assert not screen.query_one("#ovh_input_app_key", Input).parent.display
            assert not screen.query_one("#btn_ovh_request_ck", Button).display
            _fill(screen, {
                "ovh_input_client_id": "cid-b",
                "ovh_input_client_secret": OVH_CLIENT_SECRET,
            })
            assert OVH_CLIENT_SECRET not in app.export_screenshot()
            screen.query_one("#btn_ovh_save", Button).press()
            await _settle(pilot)
            assert ovh_service.built[-1]["client_id"] == "cid-b"
            assert ovh_service.built[-1]["application_key"] == ""
        (account,) = _reread(tmp_path).ovh.accounts
        assert (account.client_id, account.client_secret) == ("cid-b", OVH_CLIENT_SECRET)
        assert account.application_key == ""

    async def test_an_incomplete_oauth2_account_is_not_tested(self, tmp_path, ovh_service) -> None:
        app = Host(_manager(tmp_path, _ovh_config()), lambda: OVHSetupScreen(add_extra=True))
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            _fill(app.screen, {"ovh_input_label": "client-b", "ovh_input_client_id": "cid"})
            app.screen.query_one("#ovh_select_auth", Select).value = "oauth"
            await pilot.pause()
            app.screen.query_one("#btn_ovh_save", Button).press()
            await _settle(pilot)
            assert ovh_service.built == []
            assert "Enter the Client ID and Client Secret to test." in app.messages

    async def test_refused_credentials_are_not_saved(self, tmp_path, ovh_service) -> None:
        ovh_service.succeed = False
        app = Host(_manager(tmp_path, _ovh_config()), lambda: OVHSetupScreen(add_extra=True))
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            _fill(app.screen, {"ovh_input_label": "client-a", "ovh_input_app_key": "ak-a"})
            app.screen.query_one("#btn_ovh_save", Button).press()
            await _settle(pilot)
            assert isinstance(app.screen, OVHSetupScreen)
            assert app.rebuilds == 0
        assert _reread(tmp_path).ovh.accounts == []

    async def test_a_consumer_key_can_be_requested_for_a_new_account(
        self, tmp_path, ovh_service
    ) -> None:
        app = Host(_manager(tmp_path, _ovh_config()), lambda: OVHSetupScreen(add_extra=True))
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            _fill(app.screen, {"ovh_input_app_key": "ak-a", "ovh_input_app_secret": "as-a"})
            app.screen.query_one("#btn_ovh_request_ck", Button).press()
            await _settle(pilot)
            assert app.screen.query_one("#ovh_input_consumer_key", Input).value == "ck-new"

    async def test_editing_an_oauth2_account_shows_its_credential_set(
        self, tmp_path, ovh_service
    ) -> None:
        config = _ovh_config(accounts=[
            OVHAccount(label="client-b", client_id="cid-b", client_secret=OVH_CLIENT_SECRET),
        ])
        app = Host(_manager(tmp_path, config), lambda: OVHSetupScreen(extra=0))
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert screen.query_one("#ovh_select_auth", Select).value == "oauth"
            assert screen.query_one("#ovh_input_label", Input).value == "client-b"
            secret = screen.query_one("#ovh_input_client_secret", Input)
            assert secret.value == OVH_CLIENT_SECRET and secret.password
            assert OVH_CLIENT_SECRET not in app.export_screenshot()


class TestOvhPrimary:
    async def test_saving_keeps_what_the_form_does_not_show(self, tmp_path, ovh_service) -> None:
        config = _ovh_config(
            client_secret=OVH_CLIENT_SECRET,
            accounts=[OVHAccount(label="client-b", client_id="c", client_secret="s")],
        )
        app = Host(_manager(tmp_path, config), OVHSetupScreen)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            assert OVH_APP_SECRET not in app.export_screenshot()
            _fill(app.screen, {"ovh_input_default_username": "debian"})
            app.screen.query_one("#btn_ovh_save", Button).press()
            await _settle(pilot)
            assert app.rebuilds == 1 and app.inventory.fetches == 1
            assert "OVH enabled — 2 instances loaded." in app.messages
            assert app.ovh_service == "untouched"
        ovh = _reread(tmp_path).ovh
        assert ovh.default_username == "debian"
        assert (ovh.client_id, ovh.client_secret) == ("cid-primary", OVH_CLIENT_SECRET)
        assert ovh.ovh_audit_path == "~/audit/ovh.json" and ovh.cost_alert_threshold == 40.0
        assert [a.label for a in ovh.accounts] == ["client-b"]

    async def test_a_single_account_setup_has_no_label_or_oauth_rows(
        self, tmp_path, ovh_service
    ) -> None:
        app = Host(_manager(tmp_path, _ovh_config()), OVHSetupScreen)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            for selector in ("#ovh_label_row", "#ovh_auth_row", "#ovh_input_client_id"):
                assert not app.screen.query(selector), selector
            assert app.screen.query_one("#btn_ovh_add_account", Button).display
            app.screen.query_one("#btn_ovh_add_account", Button).press()
            await pilot.pause()
            await pilot.pause()
            assert isinstance(app.screen, OVHSetupScreen) and app.screen._add_extra

    async def test_disabling_reloads_the_accounts(self, tmp_path, ovh_service) -> None:
        app = Host(_manager(tmp_path, _ovh_config()), OVHSetupScreen)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            app.screen.query_one("#btn_ovh_disable", Button).press()
            await _settle(pilot)
            assert app.rebuilds == 1 and app.ovh_service == "untouched"
        assert _reread(tmp_path).ovh.enabled is False

