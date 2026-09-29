"""SSH parameters for a server row of any provider (MCP tools and relay)."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from servonaut.services.connection_service import server_connection


@pytest.fixture
def connection():
    service = MagicMock()
    service.resolve_profile.return_value = None
    service.get_target_host.side_effect = lambda row, profile: row.get("public_ip") or ""
    service.get_extra_options.return_value = ["-o", "X=1"]
    service.resolve_ovh_connection.return_value = {"username": "debian", "key_path": "~/.ssh/ovh2"}
    return service


@pytest.fixture
def ssh():
    service = MagicMock()
    service.get_key_path.return_value = None
    service.discover_key.return_value = "~/.ssh/web-key.pem"
    return service


def test_aws_row_uses_the_instance_key_pair(connection, ssh):
    row = {"id": "i-1", "public_ip": "9.9.9.9", "key_name": "web-key"}
    conn = server_connection(row, connection, ssh, "ec2-user")
    assert (conn["host"], conn["username"], conn["key_path"], conn["port"]) == (
        "9.9.9.9", "ec2-user", "~/.ssh/web-key.pem", None,
    )
    assert conn["extra_options"] == ["-o", "X=1"]


def test_ovh_row_uses_its_accounts_defaults(connection, ssh):
    row = {"id": "vps-1", "public_ip": "1.1.1.1", "is_ovh": True, "account": "backup"}
    conn = server_connection(row, connection, ssh, "ec2-user")
    connection.resolve_ovh_connection.assert_called_once_with(row)
    assert (conn["username"], conn["key_path"]) == ("debian", "~/.ssh/ovh2")


def test_hetzner_row_uses_the_projects_defaults(connection, ssh):
    row = {"id": "4", "public_ip": "8.8.8.8", "is_hetzner": True,
           "username": "admin", "ssh_key": "~/.ssh/staging"}
    conn = server_connection(row, connection, ssh, "ec2-user")
    assert (conn["username"], conn["key_path"]) == ("admin", "~/.ssh/staging")
    bare = server_connection({"id": "5", "is_hetzner": True}, connection, ssh, "")
    assert (bare["username"], bare["key_path"]) == ("root", None)


def test_custom_row_keeps_its_port(connection, ssh):
    row = {"id": "custom-a", "is_custom": True, "public_ip": "10.0.0.5",
           "username": "deploy", "ssh_key": "~/.ssh/a", "port": 2222}
    conn = server_connection(row, connection, ssh, "ec2-user")
    assert (conn["username"], conn["key_path"], conn["port"]) == ("deploy", "~/.ssh/a", 2222)
