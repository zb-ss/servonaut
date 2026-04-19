"""Tests for OVHSSHKeysScreen."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from textual.app import App
from textual.widgets import Button, DataTable, Input

from servonaut.screens.ovh_ssh_keys import OVHSSHKeysScreen


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_mock_client(key_names=None, key_details=None):
    """Build a mock OVH client that returns canned responses."""
    client = MagicMock()
    if key_names is None:
        key_names = []
    if key_details is None:
        key_details = {}

    def _get(path):
        if path == "/me/sshKey":
            return key_names
        for name in key_names:
            if path == f"/me/sshKey/{name}":
                return key_details.get(name, {"keyName": name, "key": "ssh-rsa AAAA", "default": False})
        raise ValueError(f"Unexpected GET: {path}")

    client.get.side_effect = _get
    client.post.return_value = {}
    client.delete.return_value = {}
    return client


class _WrapperApp(App):
    """Minimal host app that mounts OVHSSHKeysScreen with a mocked ovh_service."""

    def __init__(self, ovh_client) -> None:
        super().__init__()
        self._ovh_client = ovh_client
        # Provide minimal service stubs expected by Sidebar and other widgets
        self.ovh_service = MagicMock()
        self.ovh_service.client = ovh_client

    def on_mount(self) -> None:
        self.push_screen(OVHSSHKeysScreen())


# ---------------------------------------------------------------------------
# Key listing / parsing
# ---------------------------------------------------------------------------

class TestKeyListing:

    @pytest.mark.asyncio
    async def test_lists_key_names_from_api(self):
        """GET /me/sshKey response is used to enumerate keys."""
        client = _make_mock_client(
            key_names=["key-alpha", "key-beta"],
            key_details={
                "key-alpha": {"keyName": "key-alpha", "key": "ssh-rsa AAAA_ALPHA", "default": True},
                "key-beta": {"keyName": "key-beta", "key": "ssh-rsa AAAA_BETA", "default": False},
            },
        )
        app = _WrapperApp(client)
        async with app.run_test(headless=True) as pilot:
            # Allow workers to complete
            await pilot.pause(0.2)
            await pilot.pause(0.1)

        assert client.get.call_args_list[0] == call("/me/sshKey")

    @pytest.mark.asyncio
    async def test_fetches_detail_for_each_key(self):
        """Each key name triggers a GET /me/sshKey/{name} call."""
        client = _make_mock_client(
            key_names=["my-key"],
            key_details={
                "my-key": {"keyName": "my-key", "key": "ssh-rsa AAAA_X", "default": False},
            },
        )
        app = _WrapperApp(client)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.2)
            await pilot.pause(0.1)

        paths_called = [c.args[0] for c in client.get.call_args_list]
        assert "/me/sshKey/my-key" in paths_called

    @pytest.mark.asyncio
    async def test_table_truncates_long_public_key(self):
        """Public keys longer than 40 chars are shown truncated with '...'."""
        long_key = "ssh-rsa " + "A" * 80
        client = _make_mock_client(
            key_names=["long-key"],
            key_details={
                "long-key": {"keyName": "long-key", "key": long_key, "default": False},
            },
        )
        app = _WrapperApp(client)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.2)
            await pilot.pause(0.1)
            table = app.screen.query_one("#ssh_keys_table", DataTable)
            assert table.row_count == 1
            row = table.get_row_at(0)
            assert str(row[1]).endswith("...")
            assert len(str(row[1])) == 43  # 40 chars + "..."

    @pytest.mark.asyncio
    async def test_default_flag_displayed_correctly(self):
        """'default' field is shown as 'Yes'/'No' in the table."""
        client = _make_mock_client(
            key_names=["default-key", "normal-key"],
            key_details={
                "default-key": {"keyName": "default-key", "key": "ssh-rsa X", "default": True},
                "normal-key": {"keyName": "normal-key", "key": "ssh-rsa Y", "default": False},
            },
        )
        app = _WrapperApp(client)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.2)
            await pilot.pause(0.1)
            table = app.screen.query_one("#ssh_keys_table", DataTable)
            assert table.row_count == 2
            defaults = {str(table.get_row_at(i)[0]): str(table.get_row_at(i)[2]) for i in range(2)}
        assert defaults["default-key"] == "Yes"
        assert defaults["normal-key"] == "No"


# ---------------------------------------------------------------------------
# Add key
# ---------------------------------------------------------------------------

class TestAddKey:

    @pytest.mark.asyncio
    async def test_add_key_calls_post_with_correct_params(self):
        """_add_key must POST to /me/sshKey with keyName and key."""
        client = _make_mock_client(key_names=[])
        app = _WrapperApp(client)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.1)

            screen = app.screen
            await screen._add_key("deploy-key", "ssh-rsa AAAA_DEPLOY")
            await pilot.pause(0.1)

        client.post.assert_called_once_with(
            "/me/sshKey",
            keyName="deploy-key",
            key="ssh-rsa AAAA_DEPLOY",
        )

    @pytest.mark.asyncio
    async def test_save_key_validates_empty_name(self):
        """Saving with no key name must notify an error and not call POST."""
        client = _make_mock_client(key_names=[])
        notified: list = []
        app = _WrapperApp(client)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.1)
            screen = app.screen
            # Patch notify to capture calls
            app.notify = lambda msg, **kwargs: notified.append((msg, kwargs))

            screen.query_one("#input_key_name", Input).value = ""
            screen.query_one("#input_public_key", Input).value = "ssh-rsa AAAA"
            screen._save_key()
            await pilot.pause(0.1)

        assert any("required" in msg.lower() for msg, _ in notified)
        client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_save_key_validates_empty_public_key(self):
        """Saving with no public key must notify an error and not call POST."""
        client = _make_mock_client(key_names=[])
        notified: list = []
        app = _WrapperApp(client)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.1)
            screen = app.screen
            app.notify = lambda msg, **kwargs: notified.append((msg, kwargs))

            screen.query_one("#input_key_name", Input).value = "my-key"
            screen.query_one("#input_public_key", Input).value = ""
            screen._save_key()
            await pilot.pause(0.1)

        assert any("required" in msg.lower() for msg, _ in notified)
        client.post.assert_not_called()


# ---------------------------------------------------------------------------
# Delete key
# ---------------------------------------------------------------------------

class TestDeleteKey:

    @pytest.mark.asyncio
    async def test_delete_key_calls_delete_endpoint(self):
        """_delete_key must call DELETE /me/sshKey/{keyName}."""
        client = _make_mock_client(key_names=[])
        app = _WrapperApp(client)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.1)
            screen = app.screen
            await screen._delete_key("old-key")
            await pilot.pause(0.1)

        client.delete.assert_called_once_with("/me/sshKey/old-key")

    @pytest.mark.asyncio
    async def test_delete_key_refreshes_table(self):
        """After deletion the table is reloaded."""
        initial_names = ["keep-key", "gone-key"]
        call_count = {"n": 0}
        remaining = list(initial_names)

        client = MagicMock()

        def _get(path):
            if path == "/me/sshKey":
                return list(remaining)
            for name in initial_names:
                if path == f"/me/sshKey/{name}":
                    return {"keyName": name, "key": "ssh-rsa K", "default": False}
            return []

        def _delete(path):
            name = path.split("/")[-1]
            if name in remaining:
                remaining.remove(name)
            return {}

        client.get.side_effect = _get
        client.delete.side_effect = _delete
        client.post.return_value = {}

        app = _WrapperApp(client)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.2)
            screen = app.screen
            # Confirm 2 keys initially
            table = screen.query_one("#ssh_keys_table", DataTable)
            assert table.row_count == 2

            await screen._delete_key("gone-key")
            await pilot.pause(0.2)
            # Table should now have 1 key
            assert table.row_count == 1
            row = table.get_row_at(0)
            assert str(row[0]) == "keep-key"


# ---------------------------------------------------------------------------
# Screen rendering
# ---------------------------------------------------------------------------

class TestScreenRendering:

    @pytest.mark.asyncio
    async def test_screen_has_datatable(self):
        """OVHSSHKeysScreen composes a DataTable."""
        client = _make_mock_client(key_names=[])
        app = _WrapperApp(client)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.1)
            table = app.screen.query_one("#ssh_keys_table", DataTable)
            assert table is not None

    @pytest.mark.asyncio
    async def test_add_form_hidden_on_mount(self):
        """The add-key form is hidden when the screen first loads."""
        client = _make_mock_client(key_names=[])
        app = _WrapperApp(client)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.1)
            form = app.screen.query_one("#add_key_form")
            assert form.display is False

    @pytest.mark.asyncio
    async def test_add_button_shows_form(self):
        """Clicking 'Add Key' reveals the add form."""
        client = _make_mock_client(key_names=[])
        app = _WrapperApp(client)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.1)
            await pilot.click("#btn_add_key")
            await pilot.pause(0.1)
            form = app.screen.query_one("#add_key_form")
            assert form.display is True

    @pytest.mark.asyncio
    async def test_cancel_hides_form(self):
        """Cancel button handler hides the add form."""
        client = _make_mock_client(key_names=[])
        app = _WrapperApp(client)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.1)
            screen = app.screen
            # Show the form directly
            screen._show_form()
            await pilot.pause(0.1)
            form = screen.query_one("#add_key_form")
            assert form.display is True
            # Trigger cancel via handler (form may be off-screen in headless viewport)
            cancel_btn = screen.query_one("#btn_cancel_form", Button)
            screen.on_button_pressed(Button.Pressed(cancel_btn))
            await pilot.pause(0.1)
            assert form.display is False

    @pytest.mark.asyncio
    async def test_table_populated_with_key_data(self):
        """DataTable rows reflect data returned by the OVH API."""
        client = _make_mock_client(
            key_names=["prod-key"],
            key_details={
                "prod-key": {"keyName": "prod-key", "key": "ssh-rsa AAAA_PROD", "default": False},
            },
        )
        app = _WrapperApp(client)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.2)
            await pilot.pause(0.1)
            table = app.screen.query_one("#ssh_keys_table", DataTable)
            assert table.row_count == 1
            row = table.get_row_at(0)
            assert str(row[0]) == "prod-key"
