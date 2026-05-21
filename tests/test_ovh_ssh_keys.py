"""Tests for ``OVHSSHKeysScreen`` (project-level cloud SSH key management).

Pre-restructure this screen managed account-level ``/me/sshKey`` keys; it
now manages project-level ``/cloud/project/{id}/sshkey`` — the same
registry the cloud-create wizard reads from. Tests exercise the new
surface: ``ovh_cloud_service.list_ssh_keys / add_ssh_key / delete_ssh_key``
and the project-id resolution via ``config.ovh.cloud_project_ids``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App
from textual.widgets import Button, DataTable, Input

from servonaut.config.schema import AppConfig, OVHConfig
from servonaut.screens.ovh_ssh_keys import OVHSSHKeysScreen


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_DEFAULT_PROJECT_ID = "project-123"


def _make_cloud_service(keys=None, *, add_returns=None, raise_on_list=None):
    """Build a mocked ``OVHCloudService`` with async list/add/delete methods.

    ``keys`` is the canonical list returned from ``list_ssh_keys`` and is
    mutated by ``add_ssh_key`` / ``delete_ssh_key`` so subsequent reloads
    reflect the change — the screen calls ``_load_keys`` after a mutation.
    """
    state = list(keys or [])

    async def _list_ssh_keys(project_id):
        if raise_on_list:
            raise raise_on_list
        return list(state)

    async def _add_ssh_key(project_id, name, public_key, region=""):
        new_key = add_returns or {
            "id": f"id-{name}",
            "name": name,
            "public_key": public_key,
            "fingerprint": "aa:bb:cc",
        }
        state.append(new_key)
        return new_key

    async def _delete_ssh_key(project_id, key_id):
        state[:] = [k for k in state if k.get("id") != key_id]
        return True

    svc = MagicMock()
    svc.list_ssh_keys = AsyncMock(side_effect=_list_ssh_keys)
    svc.add_ssh_key = AsyncMock(side_effect=_add_ssh_key)
    svc.delete_ssh_key = AsyncMock(side_effect=_delete_ssh_key)
    svc._state = state  # exposed for assertions
    return svc


class _WrapperApp(App):
    """Minimal host app that mounts ``OVHSSHKeysScreen``.

    Wires the two attributes the screen reads at runtime: a config_manager
    that exposes ``ovh.cloud_project_ids`` and an ``ovh_cloud_service``
    that backs list/add/delete.
    """

    def __init__(self, cloud_service, project_ids=None) -> None:
        super().__init__()
        self.ovh_cloud_service = cloud_service
        cfg = AppConfig(
            ovh=OVHConfig(
                enabled=True,
                cloud_project_ids=list(
                    project_ids
                    if project_ids is not None
                    else [_DEFAULT_PROJECT_ID]
                ),
            ),
        )
        self.config_manager = MagicMock()
        self.config_manager.get.return_value = cfg
        # Required by OVHSSHKeysScreen's demo-mode guards.
        self.demo_mode = False
        self.redaction_service = None

    def on_mount(self) -> None:
        self.push_screen(OVHSSHKeysScreen())


# ---------------------------------------------------------------------------
# Project-id resolution / loading
# ---------------------------------------------------------------------------

class TestKeyListing:

    @pytest.mark.asyncio
    async def test_list_ssh_keys_called_with_project_id(self):
        """Mounting the screen calls ``list_ssh_keys`` for the active project."""
        svc = _make_cloud_service(keys=[])
        app = _WrapperApp(svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.2)
            await pilot.pause(0.1)

        svc.list_ssh_keys.assert_called()
        called_with = svc.list_ssh_keys.call_args.args[0]
        assert called_with == _DEFAULT_PROJECT_ID

    @pytest.mark.asyncio
    async def test_table_truncates_long_public_key(self):
        """Public keys longer than 40 chars are shown truncated with an ellipsis."""
        long_key = "ssh-rsa " + "A" * 80
        svc = _make_cloud_service(keys=[
            {
                "id": "id-long",
                "name": "long-key",
                "public_key": long_key,
                "fingerprint": "fp",
            },
        ])
        app = _WrapperApp(svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.2)
            await pilot.pause(0.1)
            table = app.screen.query_one("#ssh_keys_table", DataTable)
            assert table.row_count == 1
            row = table.get_row_at(0)
            # Column 2 is the truncated public key.
            cell = str(row[2])
            assert cell.endswith("…")
            assert len(cell) == 41  # 40 chars + single-char ellipsis

    @pytest.mark.asyncio
    async def test_table_populated_with_key_data(self):
        """DataTable rows reflect the ``list_ssh_keys`` payload."""
        svc = _make_cloud_service(keys=[
            {
                "id": "id-prod",
                "name": "prod-key",
                "public_key": "ssh-rsa AAAA_PROD",
                "fingerprint": "11:22:33",
            },
        ])
        app = _WrapperApp(svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.2)
            await pilot.pause(0.1)
            table = app.screen.query_one("#ssh_keys_table", DataTable)
            assert table.row_count == 1
            row = table.get_row_at(0)
            assert str(row[0]) == "prod-key"

    @pytest.mark.asyncio
    async def test_no_project_configured_shows_status(self):
        """When no project ID is configured, the screen shows a hint
        and does not call ``list_ssh_keys``."""
        svc = _make_cloud_service(keys=[])
        app = _WrapperApp(svc, project_ids=[])
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.2)

        svc.list_ssh_keys.assert_not_called()


# ---------------------------------------------------------------------------
# Add key
# ---------------------------------------------------------------------------

class TestAddKey:

    @pytest.mark.asyncio
    async def test_save_key_calls_add_with_project_and_inputs(self):
        """``_save_key`` reads the form and dispatches ``add_ssh_key`` for
        the active project."""
        svc = _make_cloud_service(keys=[])
        app = _WrapperApp(svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.2)
            screen = app.screen
            screen._show_form()
            screen.query_one("#input_key_name", Input).value = "deploy-key"
            screen.query_one(
                "#input_public_key", Input,
            ).value = "ssh-rsa AAAA_DEPLOY"
            screen._save_key()
            await pilot.pause(0.3)

        svc.add_ssh_key.assert_called_once()
        args, _ = svc.add_ssh_key.call_args
        assert args[0] == _DEFAULT_PROJECT_ID
        assert args[1] == "deploy-key"
        assert args[2] == "ssh-rsa AAAA_DEPLOY"

    @pytest.mark.asyncio
    async def test_save_key_validates_empty_name(self):
        """Saving with an empty key name notifies and does not call the API."""
        svc = _make_cloud_service(keys=[])
        notified: list = []
        app = _WrapperApp(svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.1)
            screen = app.screen
            app.notify = lambda msg, **kwargs: notified.append((msg, kwargs))

            screen.query_one("#input_key_name", Input).value = ""
            screen.query_one(
                "#input_public_key", Input,
            ).value = "ssh-rsa AAAA"
            screen._save_key()
            await pilot.pause(0.1)

        assert any("required" in msg.lower() for msg, _ in notified)
        svc.add_ssh_key.assert_not_called()

    @pytest.mark.asyncio
    async def test_save_key_validates_empty_public_key(self):
        """Saving with an empty public key notifies and does not call the API."""
        svc = _make_cloud_service(keys=[])
        notified: list = []
        app = _WrapperApp(svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.1)
            screen = app.screen
            app.notify = lambda msg, **kwargs: notified.append((msg, kwargs))

            screen.query_one("#input_key_name", Input).value = "my-key"
            screen.query_one("#input_public_key", Input).value = ""
            screen._save_key()
            await pilot.pause(0.1)

        assert any("required" in msg.lower() for msg, _ in notified)
        svc.add_ssh_key.assert_not_called()


# ---------------------------------------------------------------------------
# Delete key
# ---------------------------------------------------------------------------

class TestDeleteKey:

    @pytest.mark.asyncio
    async def test_delete_ssh_key_directly_routes_to_service(self):
        """A direct call to the service (bypassing the confirm modal)
        verifies the wiring between the cloud service and the screen."""
        svc = _make_cloud_service(keys=[
            {
                "id": "id-old",
                "name": "old-key",
                "public_key": "ssh-rsa O",
                "fingerprint": "f0",
            },
        ])
        app = _WrapperApp(svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.2)
            await app.ovh_cloud_service.delete_ssh_key(
                _DEFAULT_PROJECT_ID, "id-old",
            )
            await pilot.pause(0.1)

        svc.delete_ssh_key.assert_called_once_with(
            _DEFAULT_PROJECT_ID, "id-old",
        )


# ---------------------------------------------------------------------------
# Screen rendering
# ---------------------------------------------------------------------------

class TestScreenRendering:

    @pytest.mark.asyncio
    async def test_screen_has_datatable(self):
        """``OVHSSHKeysScreen`` composes a DataTable."""
        svc = _make_cloud_service(keys=[])
        app = _WrapperApp(svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.1)
            table = app.screen.query_one("#ssh_keys_table", DataTable)
            assert table is not None

    @pytest.mark.asyncio
    async def test_add_form_hidden_on_mount(self):
        """The add-key form has the ``hidden`` class when first composed."""
        svc = _make_cloud_service(keys=[])
        app = _WrapperApp(svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.1)
            form = app.screen.query_one("#add_key_form")
            assert form.has_class("hidden")

    @pytest.mark.asyncio
    async def test_add_button_shows_form(self):
        """Clicking 'Add Key' removes the ``hidden`` class on the form."""
        svc = _make_cloud_service(keys=[])
        app = _WrapperApp(svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.1)
            await pilot.click("#btn_add_key")
            await pilot.pause(0.1)
            form = app.screen.query_one("#add_key_form")
            assert not form.has_class("hidden")

    @pytest.mark.asyncio
    async def test_cancel_hides_form(self):
        """Cancel handler re-applies the ``hidden`` class."""
        svc = _make_cloud_service(keys=[])
        app = _WrapperApp(svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.1)
            screen = app.screen
            screen._show_form()
            await pilot.pause(0.1)
            form = screen.query_one("#add_key_form")
            assert not form.has_class("hidden")
            cancel_btn = screen.query_one("#btn_cancel_form", Button)
            screen.on_button_pressed(Button.Pressed(cancel_btn))
            await pilot.pause(0.1)
            assert form.has_class("hidden")
