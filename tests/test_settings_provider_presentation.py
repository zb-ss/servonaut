"""Provider scalar rows retain native fields, inline forms and save ownership."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import asdict
from pathlib import Path
from unittest.mock import Mock

import pytest
from textual.pilot import Pilot
from textual.widget import Widget
from textual.widgets import Button, DataTable, Input, Static, TextArea
from textual.widgets.text_area import Selection

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import (
    AppConfig, AWSAccount, AWSConfig, HetznerAccount, HetznerConfig,
    ObjectStorageConfig, OVHAccount, OVHConfig,
)
from servonaut.screens.settings.base import SettingsPanel
from servonaut.screens.settings.widgets import EnvVarInput
from servonaut.services.object_storage_regions import AWS_S3_DEFAULT_REGION
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import collapse_chat, content, open_chat
from tests.test_settings_credentials_presentation import _CredentialsApp, _ready
from tests.test_settings_presentation import _tab_to
from tests.test_workspace_pilot import _click
from tests.test_workspace_reflow import _painted


ROWS = {
    "aws": (
        ("aws_enabled", "AWS enabled"),
        ("aws_default_region", "Default region"),
        ("aws_cache_ttl", "Cache TTL (seconds)"),
        ("aws_cache_path", "Cache path"),
        ("aws_audit_path", "Audit path"),
        ("aws_s3_access_key", "Access key"),
        ("aws_s3_secret_key", "Secret key"),
        ("aws_s3_region", "S3 region"),
        ("aws_s3_endpoint_url", "S3 endpoint URL"),
        ("aws_ctrl_role_arn", "Role ARN"),
        ("aws_ctrl_external_id", "External ID"),
        ("aws_ctrl_session_name", "Session name"),
        ("aws_mutate_role_arn", "Mutate role ARN"),
    ),
    "hetzner": (
        ("hetzner_enabled", "Enabled"),
        ("hetzner_require_ssh_keys", "Require SSH keys on create"),
        ("hetzner_cache_ttl", "Cache TTL (seconds)"),
        ("hetzner_cache_path", "Cache path"),
        ("hetzner_audit_path", "Audit log path"),
        ("hetzner_cost_alert_threshold", "Cost alert threshold (0 = disabled)"),
    ),
    "ovh": (
        ("ovh_enabled", "Enable OVHcloud"),
        ("ovh_audit_path", "Audit log path"),
        ("ovh_cost_threshold", "Cost alert threshold"),
        ("ovh_cost_currency", "Cost alert currency"),
    ),
}
EDIT = {
    "aws": ("aws_cache_ttl", "-1", "601", "cache_ttl_seconds", 601),
    "hetzner": ("hetzner_cache_ttl", "bad", "601", "cache_ttl_seconds", 601),
    "ovh": ("ovh_cost_threshold", "bad", "12.5", "cost_alert_threshold", 12.5),
}


@pytest.fixture(autouse=True)
def _no_external_work(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("load_secrets_env", "_migrate_legacy_paths", "_ensure_config_dir"):
        monkeypatch.setattr(f"servonaut.config.manager.{name}", lambda: None)
    monkeypatch.setattr(
        "servonaut.screens.settings.aws_accounts.detected_aws_profiles", lambda: [],
    )
    monkeypatch.setattr(
        "servonaut.widgets.chat_panel.ChatPanel.on_mount", lambda self: None,
    )
    trip = Mock(side_effect=AssertionError("Unexpected external provider operation"))
    for target in (
        "subprocess.Popen", "subprocess.run", "socket.create_connection",
        "asyncio.open_connection", "webbrowser.open", "boto3.session.Session",
        "keyring.get_password", "keyring.set_password", "keyring.delete_password",
    ):
        monkeypatch.setattr(target, trip)
    for module in ("accounts", "panels.aws", "panels.hetzner", "panels.ovh"):
        for name in ("rebuild_accounts", "refresh_provider_fleet"):
            monkeypatch.setattr(f"servonaut.screens.settings.{module}.{name}", trip)
    yield
    trip.assert_not_called()


@pytest.fixture
def manager(tmp_path: Path) -> ConfigManager:
    config = AppConfig(aws=AWSConfig(accounts=[
        AWSAccount(label="secondary", profile="secondary"),
    ]))
    # Seed the picker default explicitly so this suite isolates scalar edits.
    config.aws.object_storage.region = AWS_S3_DEFAULT_REGION
    # These are inert test values, never resolved or passed to a provider.
    config.hetzner = HetznerConfig(
        label="primary-project", api_token="example-primary-token",
        default_hetzner_ssh_key="primary-cloud-key",
        default_local_ssh_key=str(tmp_path / "primary-project-key"),
        default_username="deployer", default_image="image-example",
        default_server_type="type-example", default_location="region-example",
        object_storage=ObjectStorageConfig(
            access_key="example-project-access", secret_key="example-project-secret",
            region="region-primary", endpoint_url="https://storage.example.com",
        ),
        accounts=[HetznerAccount(
            label="project-extra", api_token="example-extra-token",
            default_hetzner_ssh_key="extra-cloud-key",
            default_local_ssh_key=str(tmp_path / "extra-project-key"),
            default_username="backup-user",
            object_storage=ObjectStorageConfig(
                access_key="example-extra-access", secret_key="example-extra-secret",
                region="region-extra", endpoint_url="https://backup.example.com",
            ),
        )],
    )
    config.ovh = OVHConfig(
        label="primary-account", endpoint="ovh-ca",
        application_key="example-app-key", application_secret="example-app-secret",
        consumer_key="example-consumer-key", cloud_project_ids=["project-one"],
        include_dedicated=False, include_cloud=False,
        default_ssh_key=str(tmp_path / "primary-account-key"),
        default_username="operator", ovh_audit_path=str(tmp_path / "audit.json"),
        object_storage=ObjectStorageConfig(
            access_key="example-account-access", secret_key="example-account-secret",
            region="region-primary", endpoint_url="https://objects.example.com",
        ),
        accounts=[OVHAccount(
            label="account-extra", endpoint="ovh-us",
            client_id="example-client", client_secret="example-client-secret",
            cloud_project_ids=["project-extra"], include_dedicated=False,
            include_vps=False, default_ssh_key=str(tmp_path / "extra-account-key"),
            default_username="backup-user",
            object_storage=ObjectStorageConfig(
                access_key="example-oauth-access", secret_key="example-oauth-secret",
                region="region-extra", endpoint_url="https://archive.example.com",
            ),
        )],
    )
    seeded = {
        provider: asdict(getattr(config, provider))
        for provider in ("hetzner", "ovh")
    }
    manager = ConfigManager(config_path=tmp_path / "config.json")
    manager.save(config)
    manager.load()
    for provider, expected in seeded.items():
        assert asdict(getattr(manager.get(), provider)) == expected
    return manager


def _app(
    manager: ConfigManager, panel_id: str, navigation_visible: bool = False,
) -> _CredentialsApp:
    app = _CredentialsApp(manager, panel_id, navigation_visible)
    app.theme = "servonaut"
    return app


def _assert_hit(app: _CredentialsApp, widget: Widget) -> None:
    assert widget.region.width and widget.region.height
    assert app.screen.region.contains_region(widget.region)
    for y in range(widget.region.y, widget.region.bottom):
        for x in range(widget.region.x, widget.region.right):
            hit = app.get_widget_at(x, y)[0]
            assert hit is widget or widget in hit.ancestors


async def _expose(app: _CredentialsApp, pilot: Pilot, widget: Widget) -> None:
    widget.scroll_visible(animate=False, immediate=True)
    await pilot.pause()
    _assert_hit(app, widget)


async def _type(
    app: _CredentialsApp, pilot: Pilot, field: Input, value: str,
) -> None:
    await _expose(app, pilot, field)
    assert await pilot.click(field)
    # Textual Input binds select_all to this key; Ctrl+A is Home.
    await pilot.press("ctrl+shift+a", *value)
    await wait_until(lambda: field.value == value)


async def _press(app: _CredentialsApp, pilot: Pilot, selector: str) -> None:
    await _expose(app, pilot, app.screen.query_one(selector, Button))
    await _click(pilot, selector)
    await pilot.pause()


async def _assert_row(
    app: _CredentialsApp, pilot: Pilot, panel: SettingsPanel,
    field_id: str, expected_label: str,
) -> None:
    field = panel.query_one("#" + field_id)
    row = field.parent
    assert row.has_class("settings-scalar-row")
    await _expose(app, pilot, row)
    label = row.query_one(".label", Static)
    assert label.render().plain == expected_label
    body = panel.query_one(".panel-body")
    for target in (label, field):
        assert body.scrollable_content_region.contains_region(target.region)
        _assert_hit(app, target)
    # Labels may wrap; final compositor paint must retain every word.
    painted = " ".join(_painted(app, label).split())
    assert expected_label in painted
    if isinstance(field, EnvVarInput):
        hint = field.query_one(".envvar-hint", Static)
        if hint.display:
            assert hint.region.y >= field.query_one(Input).region.bottom


@pytest.mark.asyncio
@pytest.mark.parametrize("panel_id", list(ROWS))
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_provider_scalar_rows_keep_fields_labels_and_pinned_save(
    manager: ConfigManager, panel_id: str, size: tuple[int, int],
    navigation_visible: bool,
) -> None:
    app = _app(manager, panel_id, navigation_visible)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        before = panel.current_values()
        save = panel.query_one("#save_" + panel_id, Button)
        save_region = save.region
        for field_id, label in ROWS[panel_id]:
            await _assert_row(app, pilot, panel, field_id, label)
            assert save.region == save_region
            _assert_hit(app, save)
        assert panel.current_values() == before and not panel.is_dirty()
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("panel_id", list(EDIT))
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_scalar_validation_and_save_keep_existing_provider_ownership(
    manager: ConfigManager, panel_id: str, size: tuple[int, int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rebuild, refresh = Mock(return_value=True), Mock()
    prefix = "servonaut.screens.settings.panels." + panel_id + "."
    monkeypatch.setattr(prefix + "rebuild_accounts", rebuild)
    monkeypatch.setattr(prefix + "refresh_provider_fleet", refresh)
    app = _app(manager, panel_id)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        before = asdict(manager.get())
        field_id, invalid, valid, key, expected = EDIT[panel_id]
        field = panel.query_one("#" + field_id, Input)
        await _type(app, pilot, field, invalid)
        await _press(app, pilot, "#save_" + panel_id)
        await wait_until(lambda: field.has_class("field-error"))
        assert app.focused is field and field.value == invalid
        assert panel.query_one("#status_" + panel_id, Static).render().plain
        assert asdict(manager.get()) == before
        rebuild.assert_not_called()
        refresh.assert_not_called()
        await _type(app, pilot, field, valid)
        await _press(app, pilot, "#save_" + panel_id)
        await wait_until(lambda: not panel.is_dirty())
        before[panel_id][key] = expected
        assert asdict(manager.get()) == before
        rebuild.assert_called_once_with(app)
        refresh.assert_not_called()
        assert not field.has_class("field-error") and app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_aws_inline_rows_keep_native_tab_collision_and_cancel(
    manager: ConfigManager, size: tuple[int, int], navigation_visible: bool,
) -> None:
    app = _app(manager, "aws", navigation_visible)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        before = asdict(manager.get())
        await _press(app, pilot, "#btn_aws_account_add")
        await wait_until(lambda: panel.query_one("#aws_account_form").display)
        detected = panel.query_one("#aws_account_detected_row")
        assert detected.has_class("setting_row")
        assert not detected.has_class("settings-scalar-row")
        for name in ("label", "profile", "regions"):
            await _assert_row(app, pilot, panel, "aws_account_" + name, name.title())
        label = panel.query_one("#aws_account_label", Input)
        profile = panel.query_one("#aws_account_profile", Input)
        regions = panel.query_one("#aws_account_regions", Input)
        await _type(app, pilot, label, "secondary")
        await pilot.press("tab")
        assert app.focused is profile
        await pilot.press(*"new-profile", "tab")
        assert app.focused is regions and profile.value == "new-profile"
        await pilot.press(*"eu-west-1")
        assert regions.value == "eu-west-1"
        await _press(app, pilot, "#btn_aws_account_save")
        await wait_until(lambda: label.has_class("field-error"))
        assert app.focused is label and asdict(manager.get()) == before
        assert panel.query_one("#aws_account_form_error", Static).render().plain
        await _press(app, pilot, "#btn_aws_account_cancel")
        await wait_until(lambda: not panel.query_one("#aws_account_form").display)
        assert all(field.value == "" for field in (label, profile, regions))
        assert asdict(manager.get()) == before and app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("panel_id", list(EDIT))
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_provider_draft_and_native_targets_survive_chat_replacement(
    manager: ConfigManager, panel_id: str, navigation_visible: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(manager, panel_id, navigation_visible)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        saved = asdict(manager.get())
        field_id, _, value, _, _ = EDIT[panel_id]
        field = panel.query_one("#" + field_id, Input)
        await _type(app, pilot, field, value)
        await pilot.press("home", "right", "shift+right")
        await pilot.pause()
        assert (field.selection.start, field.selection.end) == (1, 2)
        field_state = (field.value, field.cursor_position, field.selection)
        await wait_until(panel.is_dirty)
        table = panel.query_one("#" + panel_id + "_accounts_table", DataTable)
        assert table.row_count == 2 and table.cursor_type == "row"
        table.move_cursor(row=0)
        selected_messages = Mock(wraps=table.post_message)
        monkeypatch.setattr(table, "post_message", selected_messages)
        await _tab_to(pilot, table)
        await pilot.press("down", "enter")
        await wait_until(lambda: table.cursor_row == 1)
        await pilot.pause()
        selected = [call.args[0] for call in selected_messages.call_args_list
                    if call.args and isinstance(call.args[0], DataTable.RowSelected)]
        assert len(selected) == 1 and selected[0].cursor_row == 1
        selected_key = selected[0].row_key
        selected_row = tuple(table.get_row(selected_key))
        assert selected_row[0] == saved[panel_id]["accounts"][0]["label"]
        assert (field.value, field.cursor_position, field.selection) == field_state
        assert app.focused is table
        table_state = (table.cursor_coordinate, tuple(table.rows))
        before = panel.current_values()
        screen = app.screen
        chat = await open_chat(app, pilot, screen)
        editor = chat.query_one("#chat-input", TextArea)
        draft = "Keep the provider draft\nSecond line café Ω"
        editor.load_text(draft)
        editor.selection = Selection((0, 5), (1, 6))
        await pilot.pause()
        document, selection = editor.document, editor.selection
        chat_cursor = editor.cursor_location
        assert selection.start != selection.end and chat_cursor == (1, 6)
        assert not content(screen).display
        await collapse_chat(app, pilot, screen)
        await wait_until(lambda: app.focused is table)
        assert content(screen).display and screen._current_panel() is panel
        assert panel.query_one("#" + field_id) is field
        assert panel.current_values() == before and panel.is_dirty()
        assert field.value == value and editor.document is document
        assert editor.text == draft and editor.selection == selection
        assert editor.cursor_location == chat_cursor
        assert (field.value, field.cursor_position, field.selection) == field_state
        assert (table.cursor_coordinate, tuple(table.rows)) == table_state
        current_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        assert current_key == selected_key
        assert tuple(table.get_row(selected_key)) == selected_row
        assert asdict(manager.get()) == saved
        await _tab_to(pilot, field)
        await pilot.pause()
        # Native Input focus selects all; the parked selection was checked first.
        assert (field.selection.start, field.selection.end) == (0, len(value))
        assert field.cursor_position == len(value)
        assert editor.selection == selection and editor.document is document
        _assert_hit(app, field)
        assert app._exception is None
