"""Verify setup grants the writes used by supported OVH service actions."""

from __future__ import annotations

import asyncio
from fnmatch import fnmatchcase
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from servonaut.config.schema import OVHConfig
from servonaut.services.ovh_ip_service import OVHIPService
from servonaut.services.ovh_service import OVHService
from servonaut.services.ovh_snapshot_service import OVHSnapshotService
from servonaut.services.ovh_storage_service import OVHStorageService
from servonaut.services.ovh_vps_service import OVHVPSService


@pytest.mark.parametrize("service_type,method,args", [
    (OVHIPService, "set_reverse_dns", ("192.0.2.1", "192.0.2.1", "web.example.net")),
    (OVHIPService, "delete_reverse_dns", ("192.0.2.1", "192.0.2.1")),
    (OVHIPService, "add_firewall_rule", (
        "192.0.2.1", {"sequence": 1, "action": "deny", "protocol": "tcp"},
    )),
    (OVHVPSService, "set_reverse_dns", ("vps-example", "192.0.2.1", "web.example.net")),
    (OVHSnapshotService, "create_vps_snapshot", ("vps-example", "example")),
    (OVHSnapshotService, "restore_vps_backup", ("vps-example", "2026-01-01")),
    (OVHSnapshotService, "create_cloud_snapshot", ("project", "instance", "example")),
    (OVHStorageService, "create_volume_snapshot", ("project", "volume", "example")),
])
def test_requested_permissions_cover_service_write(
    service_type: type, method: str, args: tuple[Any, ...],
) -> None:
    """Capture the actual SDK request instead of duplicating endpoint strings."""
    module = MagicMock()
    ovh_service = OVHService(OVHConfig())
    client = MagicMock()
    ovh_service._client = client

    async def exercise() -> None:
        with patch.dict("sys.modules", {"ovh": module}):
            await ovh_service.request_consumer_key()
        await getattr(service_type(ovh_service), method)(*args)

    asyncio.run(exercise())
    rules = module.Client.return_value.request_consumerkey.call_args.args[0]
    writes = [call for call in client.mock_calls if call[0] in ("post", "put", "delete")]
    assert len(writes) == 1
    call = writes[0]
    assert any(rule["method"] == call[0].upper()
               and fnmatchcase(call.args[0], rule["path"]) for rule in rules)
