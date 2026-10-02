"""The Accounts sections of the AWS, Hetzner and OVH settings panels.

Each test mounts one real panel in a small host app backed by a real
ConfigManager in a temp directory, drives the section as a user would
(buttons, inputs, the confirmation dialog) and checks what was saved, that
the accounts were reloaded, and what the screen shows — never a secret, and
stand-ins in demo mode.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Type
from unittest.mock import MagicMock

import boto3
import pytest
from textual.app import App
from textual.widgets import Button, DataTable, Input, Select, Static

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import (
    AppConfig,
    AWSAccount,
    AWSConfig,
    HetznerAccount,
    HetznerConfig,
    OVHAccount,
    OVHConfig,
)
from servonaut.screens.settings.base import SettingsPanel
from servonaut.screens.settings.panels.aws import AwsPanel
from servonaut.screens.settings.panels.hetzner import HetznerPanel
from servonaut.screens.settings.panels.ovh import OvhPanel
from servonaut.services.redaction_service import RedactionService
from servonaut.styles import CSS_FILES

pytestmark = pytest.mark.asyncio

# Secrets that must never reach the screen.
HETZNER_TOKEN = "hz-secret-token-value-0001"
OVH_SECRET = "ovh-secret-value-0002"
OVH_CLIENT_SECRET = "ovh-client-secret-0003"


class FakeInventory:
    """One provider's accounts as the fleet table reads them."""

    def __init__(self, rows: Optional[List[dict]] = None) -> None:
        self.rows = rows or []
        self.fetches = 0
        self.last_fetch_error: Optional[str] = None
        self.duplicate_accounts: Dict[str, str] = {}
        self.refs = [object()]

    def get_cached_instances(self) -> List[dict]:
        return list(self.rows)

    async def fetch_instances_cached(self, force_refresh: bool = False) -> List[dict]:
        self.fetches += 1
        return list(self.rows)


class Host(App):
    """Mounts one settings panel; records account reloads."""

    CSS_PATH = CSS_FILES

    def __init__(
        self,
        panel_cls: Type[SettingsPanel],
        manager: ConfigManager,
        *,
        demo: bool = False,
        unavailable: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__()
        self._panel_cls = panel_cls
        self.config_manager = manager
        self.accounts = MagicMock()
        self.accounts.unavailable = dict(unavailable or {})
        self.rebuilds = 0
        self.inventories: Dict[str, FakeInventory] = {
            "aws": FakeInventory(), "hetzner": FakeInventory(), "ovh": FakeInventory(),
        }
        self.instances: List[dict] = []
        self._instances_pristine: List[dict] = []
        self.demo_mode = demo
        self.redaction_service = RedactionService()
        self.auth_service = MagicMock(is_authenticated=False)
        self.aws_object_storage_service = None
        self.hetzner_object_storage_service = None
        self.ovh_object_storage_service = None
        self.pushed: List[object] = []
        self.panel: Optional[SettingsPanel] = None

    def rebuild_accounts(self) -> None:
        self.rebuilds += 1

    def provider_inventory(self, provider: str):
        return self.inventories.get(provider)

    def on_mount(self) -> None:
        self.panel = self._panel_cls()
        self.mount(self.panel)


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


def _table_rows(panel, provider: str) -> List[List[str]]:
    table = panel.query_one(f"#{provider}_accounts_table", DataTable)
    return [[str(cell) for cell in table.get_row_at(i)] for i in range(table.row_count)]


def _problems(panel, provider: str) -> str:
    widget = panel.query_one(f"#{provider}_accounts_problems", Static)
    return str(widget.render()) if widget.display else ""


def _screen_text(app: App) -> str:
    """Everything the panel draws, as text (tables, statics, inputs)."""
    parts: List[str] = []
    for widget in app.screen.walk_children():
        if isinstance(widget, DataTable):
            for i in range(widget.row_count):
                parts.extend(str(c) for c in widget.get_row_at(i))
        elif isinstance(widget, Static):
            parts.append(str(widget.render()))
    return "\n".join(parts)


async def _press(pilot, panel, button_id: str) -> None:
    panel.query_one(f"#{button_id}", Button).press()
    await pilot.pause()


async def _select_row(pilot, panel, provider: str, row: int) -> None:
    table = panel.query_one(f"#{provider}_accounts_table", DataTable)
    table.move_cursor(row=row)
    await pilot.pause()


def _profiles(monkeypatch, names: List[str]) -> None:
    """Pretend ~/.aws/config holds the profiles *names*."""
    monkeypatch.setattr(
        boto3.session.Session, "available_profiles", property(lambda self: list(names))
    )


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------


def _aws_config() -> AppConfig:
    return AppConfig(
        aws=AWSConfig(
            accounts=[AWSAccount(label="prod", profile="prod-admin", regions=["eu-west-1"])]
        )
    )


async def _fill_aws_form(pilot, panel, label: str, profile: str, regions: str = "") -> None:
    panel.query_one("#aws_account_label", Input).value = label
    panel.query_one("#aws_account_profile", Input).value = profile
    panel.query_one("#aws_account_regions", Input).value = regions
    await pilot.pause()


def _form_error(panel) -> str:
    widget = panel.query_one("#aws_account_form_error", Static)
    return str(widget.render()) if widget.display else ""


class TestAwsAccounts:
    async def test_the_table_lists_the_primary_and_the_extra_accounts(self, tmp_path) -> None:
        app = Host(AwsPanel, _manager(tmp_path, _aws_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            assert _table_rows(app.panel, "aws") == [
                ["aws", "primary", "default credentials", "all enabled"],
                ["prod", "active", "prod-admin", "eu-west-1"],
            ]
            assert not app.panel.query_one("#aws_account_form").display
            assert _problems(app.panel, "aws") == ""

    async def test_adding_an_account_saves_it_and_reloads_the_fleet(
        self, tmp_path, monkeypatch
    ) -> None:
        _profiles(monkeypatch, ["prod-admin", "staging-ro"])
        app = Host(AwsPanel, _manager(tmp_path, _aws_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _press(pilot, app.panel, "btn_aws_account_add")
            assert app.panel.query_one("#aws_account_form").display
            await _fill_aws_form(pilot, app.panel, "staging", "staging-ro", "us-east-1, eu-west-1")
            await _press(pilot, app.panel, "btn_aws_account_save")
            await pilot.pause()

            assert app.rebuilds == 1
            assert app.inventories["aws"].fetches == 1
            assert not app.panel.query_one("#aws_account_form").display
            assert _table_rows(app.panel, "aws")[-1] == [
                "staging", "active", "staging-ro", "us-east-1, eu-west-1",
            ]
        saved = _reread(tmp_path).aws.accounts
        assert [(a.label, a.profile, a.regions) for a in saved] == [
            ("prod", "prod-admin", ["eu-west-1"]),
            ("staging", "staging-ro", ["us-east-1", "eu-west-1"]),
        ]

    @pytest.mark.parametrize(
        "label, profile, regions, field, message",
        [
            ("bad label", "staging-ro", "", "aws_account_label", "must start with a letter"),
            ("custom", "staging-ro", "", "aws_account_label", "is reserved"),
            ("PROD", "staging-ro", "", "aws_account_label", "already used by AWS · prod"),
            ("OVH", "staging-ro", "", "aws_account_label", "already used by OVH · ovh"),
            ("", "staging-ro", "", "aws_account_label", "label is required"),
            ("staging", "", "", "aws_account_profile", "needs a named profile"),
            ("staging", "nope", "", "aws_account_profile", "No profile named 'nope'"),
            ("staging", "prod-admin", "", "aws_account_profile", "already the account 'prod'"),
            ("staging", "staging-ro", "europe", "aws_account_regions", "not an AWS region"),
        ],
    )
    async def test_an_invalid_account_is_not_saved(
        self, tmp_path, monkeypatch, label, profile, regions, field, message
    ) -> None:
        _profiles(monkeypatch, ["prod-admin", "staging-ro"])
        app = Host(AwsPanel, _manager(tmp_path, _aws_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _press(pilot, app.panel, "btn_aws_account_add")
            await _fill_aws_form(pilot, app.panel, label, profile, regions)
            await _press(pilot, app.panel, "btn_aws_account_save")
            assert message in _form_error(app.panel)
            assert app.panel.query_one(f"#{field}", Input).has_class("field-error")
            assert app.panel.query_one("#aws_account_form").display
            assert app.rebuilds == 0
        assert len(_reread(tmp_path).aws.accounts) == 1

    async def test_editing_the_primary_sets_its_label_profile_and_regions(
        self, tmp_path, monkeypatch
    ) -> None:
        _profiles(monkeypatch, ["prod-admin", "work"])
        app = Host(AwsPanel, _manager(tmp_path, _aws_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _select_row(pilot, app.panel, "aws", 0)
            await _press(pilot, app.panel, "btn_aws_account_edit")
            # Empty fields mean the defaults, so the primary may keep them.
            assert app.panel.query_one("#aws_account_label", Input).value == ""
            await _fill_aws_form(pilot, app.panel, "main", "work", "eu-central-1")
            await _press(pilot, app.panel, "btn_aws_account_save")
            assert app.rebuilds == 1
            assert _table_rows(app.panel, "aws")[0] == ["main", "primary", "work", "eu-central-1"]
        aws = _reread(tmp_path).aws
        assert (aws.label, aws.profile, aws.regions) == ("main", "work", ["eu-central-1"])
        assert [a.label for a in aws.accounts] == ["prod"]

    async def test_editing_an_extra_account_keeps_its_own_label(self, tmp_path, monkeypatch) -> None:
        _profiles(monkeypatch, ["prod-admin"])
        app = Host(AwsPanel, _manager(tmp_path, _aws_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _select_row(pilot, app.panel, "aws", 1)
            await _press(pilot, app.panel, "btn_aws_account_edit")
            assert app.panel.query_one("#aws_account_profile", Input).value == "prod-admin"
            app.panel.query_one("#aws_account_regions", Input).value = "us-west-2"
            await _press(pilot, app.panel, "btn_aws_account_save")
            assert _form_error(app.panel) == ""
        assert _reread(tmp_path).aws.accounts[0].regions == ["us-west-2"]

    async def test_removing_an_extra_account_asks_first(self, tmp_path) -> None:
        app = Host(AwsPanel, _manager(tmp_path, _aws_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _select_row(pilot, app.panel, "aws", 1)
            await _press(pilot, app.panel, "btn_aws_account_remove")
            assert type(app.screen).__name__ == "SimpleConfirmModal"
            app.screen.query_one("#confirm_yes_btn", Button).press()
            await pilot.pause()
            await pilot.pause()
            assert app.rebuilds == 1
            assert [row[0] for row in _table_rows(app.panel, "aws")] == ["aws"]
        assert _reread(tmp_path).aws.accounts == []

    async def test_declining_the_removal_keeps_the_account(self, tmp_path) -> None:
        app = Host(AwsPanel, _manager(tmp_path, _aws_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _select_row(pilot, app.panel, "aws", 1)
            await _press(pilot, app.panel, "btn_aws_account_remove")
            app.screen.query_one("#confirm_no_btn", Button).press()
            await pilot.pause()
            assert app.rebuilds == 0
        assert len(_reread(tmp_path).aws.accounts) == 1

    async def test_the_primary_account_cannot_be_removed(self, tmp_path) -> None:
        app = Host(AwsPanel, _manager(tmp_path, _aws_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _select_row(pilot, app.panel, "aws", 0)
            await _press(pilot, app.panel, "btn_aws_account_remove")
            assert type(app.screen).__name__ != "SimpleConfirmModal"
            assert app.rebuilds == 0

    async def test_detected_profiles_offer_only_new_ones(self, tmp_path, monkeypatch) -> None:
        monkeypatch.delenv("AWS_PROFILE", raising=False)
        _profiles(monkeypatch, ["default", "prod-admin", "team a", "custom"])
        app = Host(AwsPanel, _manager(tmp_path, _aws_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _press(pilot, app.panel, "btn_aws_account_add_profile")
            picker = app.panel.query_one("#aws_account_detected", Select)
            assert app.panel.query_one("#aws_account_detected_row").display
            # "default" is the primary account's credentials; prod-admin is
            # already the "prod" account.
            offered = [value for _, value in picker._options if isinstance(value, str)]
            assert offered == ["custom", "team a"]
            picker.value = "team a"
            await pilot.pause()
            assert app.panel.query_one("#aws_account_profile", Input).value == "team a"
            assert app.panel.query_one("#aws_account_label", Input).value == "team-a"
            picker.value = "custom"
            await pilot.pause()
            # The suggested label follows the pick; "custom" is reserved.
            label = app.panel.query_one("#aws_account_label", Input).value
            assert label.startswith("custom") and label != "custom"
            await _press(pilot, app.panel, "btn_aws_account_save")
            assert app.rebuilds == 1
        assert [(a.label, a.profile) for a in _reread(tmp_path).aws.accounts][-1] == (
            label, "custom",
        )

    async def test_a_typed_label_survives_picking_a_profile(self, tmp_path, monkeypatch) -> None:
        _profiles(monkeypatch, ["dev-1", "dev-2"])
        app = Host(AwsPanel, _manager(tmp_path, _aws_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _press(pilot, app.panel, "btn_aws_account_add_profile")
            app.panel.query_one("#aws_account_label", Input).value = "sandbox"
            app.panel.query_one("#aws_account_detected", Select).value = "dev-2"
            await pilot.pause()
            assert app.panel.query_one("#aws_account_label", Input).value == "sandbox"

    async def test_no_new_profiles_says_so(self, tmp_path, monkeypatch) -> None:
        _profiles(monkeypatch, ["prod-admin"])
        app = Host(AwsPanel, _manager(tmp_path, _aws_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _press(pilot, app.panel, "btn_aws_account_add_profile")
            assert not app.panel.query_one("#aws_account_form").display

    async def test_a_skipped_account_says_why(self, tmp_path) -> None:
        config = _aws_config()
        config.aws.accounts.append(AWSAccount(label="broken"))
        app = Host(AwsPanel, _manager(tmp_path, config))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            assert _table_rows(app.panel, "aws")[-1] == ["broken", "skipped", "missing", "all enabled"]
            assert "AWS account 'broken' is skipped: needs a named AWS profile" in _problems(
                app.panel, "aws"
            )

    async def test_the_save_dock_keeps_the_accounts(self, tmp_path) -> None:
        app = Host(AwsPanel, _manager(tmp_path, _aws_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            app.panel.query_one("#aws_default_region", Input).value = "eu-west-2"
            app.panel.persist()
            await pilot.pause()
            assert app.rebuilds == 1
        aws = _reread(tmp_path).aws
        assert aws.default_region == "eu-west-2"
        assert [a.label for a in aws.accounts] == ["prod"]


class TestAwsAccountsDemoMode:
    def _config(self) -> AppConfig:
        return AppConfig(
            aws=AWSConfig(
                label="northwind",
                profile="northwind-admin",
                accounts=[AWSAccount(label="contoso", profile="contoso-ops")],
            )
        )

    async def test_labels_and_profiles_show_stand_ins(self, tmp_path) -> None:
        app = Host(AwsPanel, _manager(tmp_path, self._config()), demo=True)
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            text = _screen_text(app).lower()
            assert "northwind" not in text and "contoso" not in text
            rows = _table_rows(app.panel, "aws")
            assert rows[1][0] == app.redaction_service.redact_account_label("contoso")
            assert rows[1][2] == app.redaction_service.redact_name("contoso-ops")

    async def test_editing_and_profile_listing_are_refused(self, tmp_path, monkeypatch) -> None:
        _profiles(monkeypatch, ["fabrikam"])
        app = Host(AwsPanel, _manager(tmp_path, self._config()), demo=True)
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _select_row(pilot, app.panel, "aws", 1)
            await _press(pilot, app.panel, "btn_aws_account_edit")
            assert not app.panel.query_one("#aws_account_form").display
            await _press(pilot, app.panel, "btn_aws_account_add_profile")
            assert not app.panel.query_one("#aws_account_form").display
            assert "fabrikam" not in _screen_text(app)

    async def test_a_problem_sentence_hides_the_names(self, tmp_path) -> None:
        config = self._config()
        config.aws.accounts.append(AWSAccount(label="Contoso", profile="x"))
        app = Host(AwsPanel, _manager(tmp_path, config), demo=True)
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            problems = _problems(app.panel, "aws")
            assert "already used" in problems and "contoso" not in problems.lower()

    async def test_toggling_demo_mode_redraws_and_closes_the_form(self, tmp_path) -> None:
        app = Host(AwsPanel, _manager(tmp_path, self._config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _select_row(pilot, app.panel, "aws", 1)
            await _press(pilot, app.panel, "btn_aws_account_edit")
            assert app.panel.query_one("#aws_account_form").display
            app.demo_mode = True
            app.panel.refresh_after_demo_toggle()
            await pilot.pause()
            assert not app.panel.query_one("#aws_account_form").display
            assert "contoso" not in _screen_text(app).lower()
            app.demo_mode = False
            app.panel.refresh_after_demo_toggle()
            await pilot.pause()
            assert _table_rows(app.panel, "aws")[1][0] == "contoso"

    async def test_an_account_added_in_demo_mode_shows_as_typed(
        self, tmp_path, monkeypatch
    ) -> None:
        _profiles(monkeypatch, ["demo-profile"])
        app = Host(AwsPanel, _manager(tmp_path, self._config()), demo=True)
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _press(pilot, app.panel, "btn_aws_account_add")
            await _fill_aws_form(pilot, app.panel, "sandbox", "demo-profile")
            await _press(pilot, app.panel, "btn_aws_account_save")
            assert _table_rows(app.panel, "aws")[-1][:3] == ["sandbox", "active", "demo-profile"]


# ---------------------------------------------------------------------------
# Hetzner
# ---------------------------------------------------------------------------


def _hetzner_config(enabled: bool = True) -> AppConfig:
    return AppConfig(
        hetzner=HetznerConfig(
            enabled=enabled,
            api_token=HETZNER_TOKEN,
            accounts=[
                HetznerAccount(label="staging", api_token="$HCLOUD_TOKEN_STAGING"),
                HetznerAccount(label="lab", api_token=""),
            ],
        )
    )


class TestHetznerAccounts:
    async def test_the_table_shows_whether_tokens_are_set_never_their_values(
        self, tmp_path
    ) -> None:
        app = Host(
            HetznerPanel,
            _manager(tmp_path, _hetzner_config()),
            unavailable={"hetzner:staging": "No API token resolved for this Hetzner project."},
        )
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            assert _table_rows(app.panel, "hetzner") == [
                ["hetzner", "primary", "set"],
                ["staging", "unavailable", "set (variable)"],
                ["lab", "skipped", "missing"],
            ]
            problems = _problems(app.panel, "hetzner")
            assert "Hetzner account 'lab' is skipped: needs its own API token" in problems
            assert "Hetzner account 'staging' is not available: No API token" in problems
            assert HETZNER_TOKEN not in _screen_text(app)

    async def test_a_disabled_provider_is_marked(self, tmp_path) -> None:
        app = Host(HetznerPanel, _manager(tmp_path, _hetzner_config(enabled=False)))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            assert {row[1] for row in _table_rows(app.panel, "hetzner")} == {"provider off"}

    async def test_adding_a_project_opens_the_wizard(self, tmp_path) -> None:
        from servonaut.screens.hetzner_setup import HetznerSetupScreen

        app = Host(HetznerPanel, _manager(tmp_path, _hetzner_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _press(pilot, app.panel, "btn_hetzner_account_add")
            await pilot.pause()
            assert isinstance(app.screen, HetznerSetupScreen)
            assert app.screen._add_extra and app.screen._account_mode

    async def test_adding_needs_hetzner_set_up_first(self, tmp_path) -> None:
        app = Host(HetznerPanel, _manager(tmp_path, _hetzner_config(enabled=False)))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _press(pilot, app.panel, "btn_hetzner_account_add")
            assert type(app.screen).__name__ != "HetznerSetupScreen"

    @pytest.mark.parametrize("row, extra, show_label", [(0, None, True), (1, 0, False)])
    async def test_editing_opens_the_wizard_for_that_project(
        self, tmp_path, row, extra, show_label
    ) -> None:
        from servonaut.screens.hetzner_setup import HetznerSetupScreen

        app = Host(HetznerPanel, _manager(tmp_path, _hetzner_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _select_row(pilot, app.panel, "hetzner", row)
            await _press(pilot, app.panel, "btn_hetzner_account_edit")
            await pilot.pause()
            assert isinstance(app.screen, HetznerSetupScreen)
            assert app.screen._extra_index == extra
            assert app.screen._show_label is show_label

    async def test_removing_a_project(self, tmp_path) -> None:
        app = Host(HetznerPanel, _manager(tmp_path, _hetzner_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _select_row(pilot, app.panel, "hetzner", 1)
            await _press(pilot, app.panel, "btn_hetzner_account_remove")
            app.screen.query_one("#confirm_yes_btn", Button).press()
            await pilot.pause()
            await pilot.pause()
            assert app.rebuilds == 1
            assert app.inventories["hetzner"].fetches == 1
        hetzner = _reread(tmp_path).hetzner
        assert [a.label for a in hetzner.accounts] == ["lab"]
        assert hetzner.api_token == HETZNER_TOKEN

    async def test_returning_from_the_wizard_shows_what_it_saved(self, tmp_path) -> None:
        manager = _manager(tmp_path, _hetzner_config(enabled=False))
        app = Host(HetznerPanel, manager)
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            config = manager.get()
            config.hetzner.enabled = True
            config.hetzner.accounts.append(HetznerAccount(label="edge", api_token="x"))
            manager.save(config)
            app.panel.refresh_external_state()
            await pilot.pause()
            from textual.widgets import Switch

            assert app.panel.query_one("#hetzner_enabled", Switch).value is True
            assert _table_rows(app.panel, "hetzner")[-1] == ["edge", "active", "set"]
            # A later Save keeps what the wizard enabled.
            app.panel.persist()
        assert _reread(tmp_path).hetzner.enabled is True

    async def test_switching_hetzner_on_in_the_save_dock_lists_it(self, tmp_path) -> None:
        from textual.widgets import Switch

        app = Host(HetznerPanel, _manager(tmp_path, _hetzner_config(enabled=False)))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            app.panel.query_one("#hetzner_enabled", Switch).value = True
            await pilot.pause()
            app.panel.persist()
            await pilot.pause()
            await pilot.pause()
            # Extra projects inherit the provider settings, so every save
            # reloads the accounts; switching the provider on lists it.
            assert app.rebuilds == 1
            assert app.inventories["hetzner"].fetches == 1
            assert _table_rows(app.panel, "hetzner")[0][1] == "primary"
            app.panel.query_one("#hetzner_cache_ttl", Input).value = "600"
            app.panel.persist()
            await pilot.pause()
            assert app.rebuilds == 2
            assert app.inventories["hetzner"].fetches == 1

    async def test_demo_mode_hides_project_labels(self, tmp_path) -> None:
        config = _hetzner_config()
        config.hetzner.accounts[0].label = "northwind"
        app = Host(HetznerPanel, _manager(tmp_path, config), demo=True)
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            assert "northwind" not in _screen_text(app)
            await _select_row(pilot, app.panel, "hetzner", 1)
            await _press(pilot, app.panel, "btn_hetzner_account_edit")
            assert type(app.screen).__name__ != "HetznerSetupScreen"


# ---------------------------------------------------------------------------
# OVH
# ---------------------------------------------------------------------------


def _ovh_config() -> AppConfig:
    return AppConfig(
        ovh=OVHConfig(
            enabled=True,
            application_key="ak",
            application_secret=OVH_SECRET,
            consumer_key="ck",
            cloud_project_ids=["p1", "p2"],
            accounts=[
                OVHAccount(
                    label="client-a",
                    endpoint="ovh-ca",
                    client_id="cid",
                    client_secret=OVH_CLIENT_SECRET,
                ),
            ],
        )
    )


class TestOvhAccounts:
    async def test_the_table_shows_endpoint_auth_and_projects(self, tmp_path) -> None:
        app = Host(OvhPanel, _manager(tmp_path, _ovh_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            assert _table_rows(app.panel, "ovh") == [
                ["ovh", "primary", "ovh-eu", "application key", "2"],
                ["client-a", "active", "ovh-ca", "OAuth2", "none"],
            ]
            text = _screen_text(app)
            assert OVH_SECRET not in text and OVH_CLIENT_SECRET not in text

    async def test_adding_and_editing_open_the_wizard(self, tmp_path) -> None:
        from servonaut.screens.ovh_setup import OVHSetupScreen

        app = Host(OvhPanel, _manager(tmp_path, _ovh_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _press(pilot, app.panel, "btn_ovh_account_add")
            await pilot.pause()
            assert isinstance(app.screen, OVHSetupScreen) and app.screen._add_extra
            app.pop_screen()
            await pilot.pause()
            await _select_row(pilot, app.panel, "ovh", 1)
            await _press(pilot, app.panel, "btn_ovh_account_edit")
            await pilot.pause()
            assert isinstance(app.screen, OVHSetupScreen) and app.screen._extra_index == 0

    async def test_removing_an_account(self, tmp_path) -> None:
        app = Host(OvhPanel, _manager(tmp_path, _ovh_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            await _select_row(pilot, app.panel, "ovh", 1)
            await _press(pilot, app.panel, "btn_ovh_account_remove")
            app.screen.query_one("#confirm_yes_btn", Button).press()
            await pilot.pause()
            await pilot.pause()
            assert app.rebuilds == 1
        ovh = _reread(tmp_path).ovh
        assert ovh.accounts == [] and ovh.application_secret == OVH_SECRET


# ---------------------------------------------------------------------------
# One place per setting: account fields live only in the account form
# ---------------------------------------------------------------------------


_ACCOUNT_FORM_FIELDS = {
    "ovh": (
        "ovh_endpoint", "ovh_client_id", "ovh_default_ssh_key", "ovh_default_username",
        "ovh_include_dedicated", "ovh_include_vps", "ovh_include_cloud",
        "ovh_cloud_project_ids", "ovh_s3_access_key", "ovh_s3_secret_key",
        "ovh_s3_region", "ovh_s3_endpoint_url",
    ),
    "hetzner": (
        "hetzner_default_hetzner_ssh_key", "hetzner_default_local_ssh_key",
        "hetzner_default_username", "hetzner_default_image",
        "hetzner_default_server_type", "hetzner_default_location",
        "hetzner_s3_access_key", "hetzner_s3_secret_key", "hetzner_s3_region",
        "hetzner_s3_endpoint_url",
    ),
}


class TestOnePlacePerSetting:
    async def test_ovh_panel_keeps_only_provider_wide_settings(self, tmp_path) -> None:
        app = Host(OvhPanel, _manager(tmp_path, _ovh_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            for field_id in _ACCOUNT_FORM_FIELDS["ovh"]:
                assert not app.panel.query(f"#{field_id}"), field_id
            for field_id in ("ovh_enabled", "ovh_audit_path", "ovh_cost_threshold",
                             "ovh_cost_currency", "ovh_btn_setup"):
                assert app.panel.query(f"#{field_id}"), field_id

    async def test_hetzner_panel_keeps_only_provider_wide_settings(self, tmp_path) -> None:
        app = Host(HetznerPanel, _manager(tmp_path, _hetzner_config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            for field_id in _ACCOUNT_FORM_FIELDS["hetzner"]:
                assert not app.panel.query(f"#{field_id}"), field_id
            for field_id in ("hetzner_enabled", "hetzner_require_ssh_keys",
                             "hetzner_cache_ttl", "hetzner_cache_path",
                             "hetzner_audit_path", "hetzner_cost_alert_threshold",
                             "btn_hetzner_setup"):
                assert app.panel.query(f"#{field_id}"), field_id


# ---------------------------------------------------------------------------
# One Save, one save: panels that extend on_button_pressed call the base
# handler through super(), and Textual must not run it a second time.
# ---------------------------------------------------------------------------


class TestSaveRunsOnce:
    @pytest.mark.parametrize("panel_cls, config, field_id, value", [
        (OvhPanel, _ovh_config, "ovh_cost_currency", "USD"),
        (HetznerPanel, _hetzner_config, "hetzner_cache_ttl", "600"),
    ])
    async def test_one_click_persists_once(
        self, tmp_path, panel_cls, config, field_id, value
    ) -> None:
        app = Host(panel_cls, _manager(tmp_path, config()))
        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause()
            panel = app.panel
            saves = []
            real_persist = panel.persist
            panel.persist = lambda: (saves.append(1), real_persist())
            panel.query_one(f"#{field_id}", Input).value = value
            await pilot.click(f"#save_{panel.PANEL_ID}")
            await pilot.pause()
            await pilot.pause()
            assert len(saves) == 1
