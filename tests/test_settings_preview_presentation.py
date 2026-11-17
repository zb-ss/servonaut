"""Preview provider forms keep native list editing and per-panel save behavior."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest
from textual.containers import VerticalScroll
from textual.pilot import Pilot
from textual.widget import Widget
from textual.widgets import Button, Input, Static, Switch

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from servonaut.screens.settings.base import SettingsPanel
from servonaut.screens.settings.shell import DiscardChangesModal
from servonaut.screens.settings.widgets import PreviewBanner, StringListEditor
from servonaut.services.azure_service import AzureService
from servonaut.services.gcp_service import GCPService
from tests._async_bounds import wait_until
from tests.test_settings_credentials_presentation import _CredentialsApp, _ready
from tests.test_settings_presentation import _painted_label, _tab_to


EDITORS = (
    ("gcp", "gcp_project_ids", "project-extra"),
    ("gcp", "gcp_zones", "us-central1-c"),
    ("azure", "azure_subscription_ids", "subscription-extra"),
    ("azure", "azure_resource_groups", "group-extra"),
)


@pytest.fixture(autouse=True)
def _no_external_discovery(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    # Install guards before constructing/mounting the real Settings host.
    # Optional SDK imports occur inside these methods and must stay unreachable.
    for name in ("load_secrets_env", "_migrate_legacy_paths", "_ensure_config_dir"):
        monkeypatch.setattr(f"servonaut.config.manager.{name}", lambda: None)
    probes: list[Mock] = []
    for service in (GCPService, AzureService):
        fetch = AsyncMock(side_effect=AssertionError("Unexpected provider fetch"))
        load = Mock(side_effect=AssertionError("Unexpected credential loading"))
        monkeypatch.setattr(service, "fetch_instances", fetch)
        monkeypatch.setattr(service, "_fetch_sync", load)
        probes.extend((fetch, load))
    profiles = Mock(return_value=[])
    monkeypatch.setattr(
        "servonaut.screens.settings.aws_accounts.detected_aws_profiles", profiles,
    )
    yield
    for probe in probes:
        probe.assert_not_called()
    profiles.assert_not_called()


@pytest.fixture
def manager(tmp_path: Path) -> ConfigManager:
    config = AppConfig()
    config.gcp = replace(
        config.gcp, project_ids=["project-one", "project-two"],
        zones=["us-central1-a", "us-central1-b"], credentials_path="",
    )
    config.azure = replace(
        config.azure, subscription_ids=["subscription-one", "subscription-two"],
        resource_groups=["group-one", "group-two"],
    )
    manager = ConfigManager(config_path=tmp_path / "config.json")
    manager.save(config)
    manager.load()
    return manager


def _app(
    manager: ConfigManager, panel_id: str, navigation_visible: bool = False,
) -> _CredentialsApp:
    app = _CredentialsApp(manager, panel_id, navigation_visible)
    app.theme = "servonaut"
    return app


async def _expose(app: _CredentialsApp, pilot: Pilot, widget: Widget) -> None:
    widget.scroll_visible(animate=False, immediate=True)
    await pilot.pause()
    assert widget.region.width > 0 and widget.region.height > 0
    assert app.screen.region.contains_region(widget.region)
    hit = app.get_widget_at(*widget.region.center)[0]
    assert hit is widget or widget in hit.ancestors


async def _click(app: _CredentialsApp, pilot: Pilot, button: Widget) -> None:
    await wait_until(lambda: not button.has_class("-active"))
    await _expose(app, pilot, button)
    assert await pilot.click(button)
    await pilot.pause()


async def _add(
    app: _CredentialsApp, pilot: Pilot, editor: StringListEditor, value: str,
) -> None:
    field = editor.query_one(".list-new", Input)
    await _expose(app, pilot, field)
    assert await pilot.click(field)
    await pilot.press(*value)
    await _click(app, pilot, editor.query_one(".list-add", Button))
    await wait_until(lambda: value in editor.get_values())
    assert field.value == ""


def _marker(panel: SettingsPanel) -> str:
    return str(panel.query_one(f"#dirty_{panel.PANEL_ID}", Static).render())


@pytest.mark.asyncio
@pytest.mark.parametrize("panel_id", ["gcp", "azure"])
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_preview_scalar_rows_leave_collections_full_width_and_actions_reachable(
    manager: ConfigManager, panel_id: str, size: tuple[int, int],
    navigation_visible: bool,
) -> None:
    app = _app(manager, panel_id, navigation_visible)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        body = panel.query_one(".panel-body", VerticalScroll)
        banner = panel.query_one(PreviewBanner)
        await _expose(app, pilot, banner)
        banner_copy = "\n".join(
            strip.text for strip in banner.render_lines(
                banner.content_region - banner.region.offset,
            )
        )
        assert "isn't live yet" in " ".join(banner_copy.split())
        controls: list[Widget] = [panel.query_one(f"#{panel_id}_enabled", Switch)]
        if panel_id == "gcp":
            controls.append(panel.query_one("#gcp_credentials_path", Input))
        for control in controls:
            label = control.parent.query_one(".label", Static)
            await _expose(app, pilot, control)
            assert str(label.render()) in _painted_label(label)[0]
            if app.screen.has_class("-content-narrow"):
                assert label.region.bottom <= control.region.y
            else:
                assert label.region.right <= control.region.x
        for editor in panel.query(StringListEditor):
            # Provider sections group the list without consuming horizontal width.
            section = editor.parent
            assert section is not None and section.has_class("settings-provider-section")
            assert section.has_class("settings-form-section") and section.parent is body
            assert section.region.x == body.scrollable_content_region.x
            assert section.region.right == body.scrollable_content_region.right
            assert section.scrollable_content_region.x == section.region.x
            assert section.scrollable_content_region.right == section.region.right
            assert editor.region.x == body.scrollable_content_region.x
            assert editor.region.right == body.scrollable_content_region.right
            for selector in (".list-new", ".list-add", ".list-remove"):
                control = editor.query_one(selector)
                await _expose(app, pilot, control)
                if isinstance(control, Button):
                    assert control.label.plain in _painted_label(control)[0]
        save = panel.query_one(f"#save_{panel_id}", Button)
        await _tab_to(pilot, save)
        await _expose(app, pilot, save)
        assert app.focused is save
        assert not panel.is_dirty() and "unsaved" not in _marker(panel)


@pytest.mark.asyncio
@pytest.mark.parametrize("panel_id,editor_id,extra", EDITORS)
async def test_native_list_add_and_remove_update_dirty_marker_without_saving(
    manager: ConfigManager, panel_id: str, editor_id: str, extra: str,
) -> None:
    app = _app(manager, panel_id)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        editor = panel.query_one(f"#{editor_id}", StringListEditor)
        original = editor.get_values()
        saved = replace(getattr(manager.get(), panel_id))
        await _add(app, pilot, editor, extra)
        assert editor.get_values() == original + [extra]
        assert panel.is_dirty() and "unsaved" in _marker(panel)
        remove = list(editor.query(".list-remove"))[-1]
        await _click(app, pilot, remove)
        await wait_until(lambda: editor.get_values() == original)
        assert not panel.is_dirty() and "unsaved" not in _marker(panel)
        await _click(app, pilot, editor.query_one(".list-remove", Button))
        await wait_until(lambda: editor.get_values() == original[1:])
        assert panel.is_dirty() and "unsaved" in _marker(panel)
        assert getattr(manager.get(), panel_id) == saved


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "editor_id", ["azure_subscription_ids", "azure_resource_groups"],
)
async def test_azure_native_remove_and_append_reordering_is_clean(
    manager: ConfigManager, editor_id: str,
) -> None:
    app = _app(manager, "azure")
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        editor = panel.query_one(f"#{editor_id}", StringListEditor)
        original = editor.get_values()
        await _click(app, pilot, editor.query_one(".list-remove", Button))
        await wait_until(lambda: editor.get_values() == original[1:])
        assert panel.is_dirty() and "unsaved" in _marker(panel)
        await _add(app, pilot, editor, original[0])
        assert editor.get_values() == original[1:] + original[:1]
        assert not panel.is_dirty() and "unsaved" not in _marker(panel)
        assert panel.current_values()[editor_id.removeprefix("azure_")] != original


@pytest.mark.asyncio
@pytest.mark.parametrize("panel_id,editor_id,extra", [EDITORS[0], EDITORS[2]])
async def test_preview_panel_save_commits_list_once_and_keeps_preview_banner(
    manager: ConfigManager, panel_id: str, editor_id: str, extra: str,
) -> None:
    app = _app(manager, panel_id)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        editor = panel.query_one(f"#{editor_id}", StringListEditor)
        original = editor.get_values()
        await _add(app, pilot, editor, extra)
        await _click(app, pilot, panel.query_one(f"#{panel_id}_enabled", Switch))
        with patch.object(manager, "update", wraps=manager.update) as update:
            await _click(app, pilot, panel.query_one(f"#save_{panel_id}", Button))
        update.assert_called_once()
        config = manager.get()
        field = editor_id.removeprefix(f"{panel_id}_")
        assert getattr(getattr(config, panel_id), field) == original + [extra]
        assert getattr(config, panel_id).enabled
        assert panel.query_one(PreviewBanner).is_attached
        assert not panel.is_dirty() and "unsaved" not in _marker(panel)
        assert app.notes[-1] == (
            "GCP settings saved (provider enabled)" if panel_id == "gcp" else "Saved"
        )
    restored = ConfigManager(config_path=manager._config_path).load()
    assert getattr(getattr(restored, panel_id), field) == original + [extra]


@pytest.mark.asyncio
@pytest.mark.parametrize("panel_id,editor_id,extra", [EDITORS[0], EDITORS[2]])
async def test_cancel_back_guard_keeps_native_list_edits_without_persisting(
    manager: ConfigManager, panel_id: str, editor_id: str, extra: str,
) -> None:
    app = _app(manager, panel_id)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        editor = panel.query_one(f"#{editor_id}", StringListEditor)
        original = editor.get_values()
        await _add(app, pilot, editor, extra)
        settings = app.screen
        await _click(app, pilot, settings.query_one("#settings-back", Button))
        await wait_until(lambda: isinstance(app.screen, DiscardChangesModal))
        await _click(app, pilot, app.screen.query_one("#discard-cancel", Button))
        await wait_until(lambda: app.screen is settings)
        assert editor.get_values() == original + [extra]
        assert panel.is_dirty()
        field = editor_id.removeprefix(f"{panel_id}_")
        assert getattr(getattr(manager.get(), panel_id), field) == original


@pytest.mark.asyncio
@pytest.mark.parametrize("panel_id", ["gcp", "azure"])
async def test_preview_save_rejects_invalid_field_and_focuses_editable_control(
    manager: ConfigManager, panel_id: str,
) -> None:
    app = _app(manager, panel_id)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        if panel_id == "gcp":
            field = owner = panel.query_one("#gcp_credentials_path", Input)
            # Pin the path sanity check without opening a credentials file.
            field.value = "invalid\x00path"
            expected = "invalid characters"
        else:
            owner = panel.query_one("#azure_subscription_ids", StringListEditor)
            field = owner.query_one(".list-row Input", Input)
            field.value = "invalid subscription"
            expected = "must not contain spaces"
        await pilot.pause()
        with patch.object(manager, "update", wraps=manager.update) as update:
            await _click(app, pilot, panel.query_one(f"#save_{panel_id}", Button))
        update.assert_not_called()
        assert owner.has_class("field-error")
        status = panel.query_one(f"#status_{panel_id}", Static)
        assert expected in str(status.render())
        assert app.focused is field
        await _expose(app, pilot, field)
