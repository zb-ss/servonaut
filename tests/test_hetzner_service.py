"""Unit tests for HetznerService — mocked hcloud client.

Cover happy path, error paths, cache TTL, audit-trail, and instance-dict
shape so the rest of the system (TUI, MCP tools, CLI) can rely on the
contract.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import HetznerConfig
from servonaut.services.hetzner_service import (
    HetznerError,
    HetznerNotConfiguredError,
    HetznerSDKMissingError,
    HetznerService,
    _validate_resource_name,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(tmp_path: Path, **overrides) -> HetznerConfig:
    base = dict(
        enabled=True,
        api_token="t",
        cache_path=str(tmp_path / "hcache.json"),
        audit_path=str(tmp_path / "haudit.jsonl"),
        cache_ttl_seconds=120,
        # Disable the no-keys footgun guard for the unit tests that
        # exercise create() without supplying SSH keys. Tests that
        # specifically exercise the guard set this back to True.
        require_ssh_keys_on_create=False,
    )
    base.update(overrides)
    return HetznerConfig(**base)


def _bound_server(
    *, server_id=1, name="srv", status="running",
    ipv4="1.2.3.4", server_type="cx22", location="fsn1",
):
    """Construct a SimpleNamespace mimicking ``hcloud`` BoundServer enough."""
    public_net = SimpleNamespace(ipv4=SimpleNamespace(ip=ipv4))
    return SimpleNamespace(
        id=server_id,
        name=name,
        status=status,
        public_net=public_net,
        server_type=SimpleNamespace(name=server_type),
        datacenter=SimpleNamespace(location=SimpleNamespace(name=location)),
        created=datetime(2026, 5, 9, 0, 0, 0),
        labels={},
    )


# ---------------------------------------------------------------------------
# _validate_resource_name
# ---------------------------------------------------------------------------

class TestValidateResourceName:
    def test_accepts_alphanumeric(self):
        assert _validate_resource_name("ok-1.test_2") == "ok-1.test_2"

    @pytest.mark.parametrize("bad", ["", "  ", "a/b", "a b", "a;b", "$inj"])
    def test_rejects_dangerous_chars(self, bad):
        with pytest.raises(ValueError):
            _validate_resource_name(bad)

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            _validate_resource_name("")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError):
            _validate_resource_name("a" * 254)

    def test_rejects_non_string(self):
        with pytest.raises(ValueError):
            _validate_resource_name(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Lazy client init
# ---------------------------------------------------------------------------

class TestClientInit:
    def test_lazy_init_calls_resolve_token(self, tmp_path, monkeypatch):
        monkeypatch.delenv("HCLOUD_TOKEN", raising=False)
        svc = HetznerService(_make_config(tmp_path, api_token=""))
        # Repoint default fallback file off-disk.
        monkeypatch.setattr(
            "servonaut.services.hetzner_service._HCLOUD_DEFAULT_TOKEN_FILE",
            tmp_path / "absent",
        )
        with pytest.raises(HetznerNotConfiguredError):
            svc._get_client()

    def test_sdk_missing_raises_friendly_error(self, tmp_path, monkeypatch):
        svc = HetznerService(_make_config(tmp_path, api_token="t"))
        # Patch resolve_token to succeed without a real token chain.
        monkeypatch.setattr(svc, "resolve_token", lambda: "t")
        with patch.dict("sys.modules", {"hcloud": None}):
            with pytest.raises(HetznerSDKMissingError):
                svc._get_client()


# ---------------------------------------------------------------------------
# fetch_instances + cache
# ---------------------------------------------------------------------------

class TestFetchInstances:
    def test_happy_path_shapes_instance_dict(self, tmp_path, monkeypatch):
        svc = HetznerService(_make_config(tmp_path))
        fake_client = MagicMock()
        fake_client.servers.get_all.return_value = [
            _bound_server(server_id=42, name="web1"),
        ]
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        out = asyncio.run(svc.fetch_instances())
        assert len(out) == 1
        inst = out[0]
        assert inst["id"] == "42"
        assert inst["name"] == "web1"
        assert inst["provider"] == "hetzner"
        assert inst["is_hetzner"] is True
        assert inst["public_ip"] == "1.2.3.4"
        assert inst["region"] == "fsn1"
        assert inst["state"] == "running"
        assert inst["owned_by_servonaut"] is True
        assert inst["disposable"] is True

    def test_status_mapping(self, tmp_path, monkeypatch):
        svc = HetznerService(_make_config(tmp_path))
        cases = [("starting", "pending"), ("off", "stopped"), ("unknown", "unknown")]
        for raw, expected in cases:
            fake_client = MagicMock()
            fake_client.servers.get_all.return_value = [
                _bound_server(status=raw),
            ]
            monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
            out = asyncio.run(svc.fetch_instances())
            assert out[0]["state"] == expected, raw

    def test_cache_hit_skips_api(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        # Pre-populate cache.
        Path(cfg.cache_path).write_text(json.dumps({
            "timestamp": datetime.now().isoformat(),
            "instances": [{"id": "1", "name": "cached"}],
        }))
        fake_client = MagicMock()
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        out = asyncio.run(svc.fetch_instances_cached())
        assert out == [{"id": "1", "name": "cached"}]
        fake_client.servers.get_all.assert_not_called()

    def test_force_refresh_bypasses_cache(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        Path(cfg.cache_path).write_text(json.dumps({
            "timestamp": datetime.now().isoformat(),
            "instances": [{"id": "old"}],
        }))
        fake_client = MagicMock()
        fake_client.servers.get_all.return_value = []
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        out = asyncio.run(svc.fetch_instances_cached(force_refresh=True))
        assert out == []
        fake_client.servers.get_all.assert_called_once()

    def test_expired_cache_refetches(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path, cache_ttl_seconds=10)
        svc = HetznerService(cfg)
        old_ts = (datetime.now() - timedelta(minutes=5)).isoformat()
        Path(cfg.cache_path).write_text(json.dumps({
            "timestamp": old_ts,
            "instances": [{"id": "stale"}],
        }))
        fake_client = MagicMock()
        fake_client.servers.get_all.return_value = []
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        out = asyncio.run(svc.fetch_instances_cached())
        assert out == []
        fake_client.servers.get_all.assert_called_once()

    def test_cache_file_has_owner_only_perms(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        fake_client = MagicMock()
        fake_client.servers.get_all.return_value = []
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        asyncio.run(svc.fetch_instances_cached(force_refresh=True))
        mode = Path(cfg.cache_path).stat().st_mode & 0o777
        assert mode == 0o600

    def test_get_cached_instances_ignores_ttl(self, tmp_path):
        cfg = _make_config(tmp_path, cache_ttl_seconds=1)
        svc = HetznerService(cfg)
        old_ts = (datetime.now() - timedelta(minutes=5)).isoformat()
        Path(cfg.cache_path).write_text(json.dumps({
            "timestamp": old_ts,
            "instances": [{"id": "stale-but-shown"}],
        }))
        out = svc.get_cached_instances()
        assert out == [{"id": "stale-but-shown"}]


# ---------------------------------------------------------------------------
# create_server
# ---------------------------------------------------------------------------

class TestCreateServer:
    def test_validates_name_before_calling_api(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        with pytest.raises(ValueError):
            asyncio.run(svc.create_server(name="bad name with spaces"))
        # Audit row written for validation failure (forensic trail
        # captures every attempt, including rejected ones).
        rows = Path(cfg.audit_path).read_text().strip().splitlines()
        assert len(rows) == 1
        row = json.loads(rows[0])
        assert row["success"] is False
        assert "validation" in row["reason"]

    def test_happy_path_audit_and_dict(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path, default_hetzner_ssh_key="default-key")
        svc = HetznerService(cfg)
        new_server = _bound_server(server_id=999, name="demo-1")
        response = SimpleNamespace(
            server=new_server, action=None, root_password=None,
            next_actions=None,
        )
        fake_client = MagicMock()
        fake_client.servers.create.return_value = response
        # _resolve_ssh_keys: key by name resolves to a SimpleNamespace
        fake_client.ssh_keys.get_by_name.return_value = SimpleNamespace(id=1)
        # _wait_until_running re-fetches the server.
        fake_client.servers.get_by_id.return_value = new_server
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        out = asyncio.run(svc.create_server(
            name="demo-1", server_type="cx22", image="ubuntu-22.04",
            location="fsn1",
        ))
        assert out["id"] == "999"
        assert out["name"] == "demo-1"
        assert out["state"] == "running"
        assert out["provider"] == "hetzner"
        # Audit row appended
        rows = Path(cfg.audit_path).read_text().strip().splitlines()
        assert len(rows) == 1
        row = json.loads(rows[0])
        assert row["action"] == "create_server"
        assert row["target"] == "demo-1"
        assert row["success"] is True

    def test_unknown_ssh_key_raises_before_create(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        fake_client = MagicMock()
        fake_client.ssh_keys.get_by_name.return_value = None
        # ssh_keys.get_by_id can also return None.
        fake_client.ssh_keys.get_by_id.return_value = None
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        with pytest.raises(HetznerError, match="SSH key not found"):
            asyncio.run(svc.create_server(
                name="x", ssh_keys=["nonexistent-key"],
            ))
        # servers.create must NOT have been called.
        fake_client.servers.create.assert_not_called()
        # Audit row MUST be written even on this pre-API failure path —
        # otherwise the SSH-key-typo failure mode goes unrecorded.
        rows = Path(cfg.audit_path).read_text().strip().splitlines()
        assert len(rows) == 1
        row = json.loads(rows[0])
        assert row["action"] == "create_server"
        assert row["target"] == "x"
        assert row["success"] is False
        assert "ssh_key_resolution_failed" in row["reason"]

    def test_no_keys_footgun_guard(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path, require_ssh_keys_on_create=True)
        svc = HetznerService(cfg)
        fake_client = MagicMock()
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        with pytest.raises(HetznerError, match="without SSH keys"):
            asyncio.run(svc.create_server(name="demo"))
        fake_client.servers.create.assert_not_called()
        rows = Path(cfg.audit_path).read_text().strip().splitlines()
        assert json.loads(rows[0])["success"] is False
        assert "footgun" in json.loads(rows[0])["reason"]

    def test_no_keys_allowed_via_explicit_override(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path, require_ssh_keys_on_create=True)
        svc = HetznerService(cfg)
        new_server = _bound_server(server_id=1, name="demo")
        fake_client = MagicMock()
        fake_client.servers.create.return_value = SimpleNamespace(
            server=new_server, action=None, root_password="random-pw",
            next_actions=None,
        )
        fake_client.servers.get_by_id.return_value = new_server
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        out = asyncio.run(svc.create_server(
            name="demo", allow_no_ssh_keys=True,
        ))
        assert out["id"] == "1"
        fake_client.servers.create.assert_called_once()

    def test_api_error_wrapped(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        fake_client = MagicMock()
        fake_client.servers.create.side_effect = RuntimeError("boom")
        # No SSH keys requested → resolve returns []
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        with pytest.raises(HetznerError, match="Failed to create"):
            asyncio.run(svc.create_server(name="x"))
        # Failure audit row
        rows = Path(cfg.audit_path).read_text().strip().splitlines()
        assert len(rows) == 1
        row = json.loads(rows[0])
        assert row["success"] is False


# ---------------------------------------------------------------------------
# delete_server
# ---------------------------------------------------------------------------

class TestDeleteServer:
    def test_not_found_raises(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        fake_client = MagicMock()
        fake_client.servers.get_by_name.return_value = None
        fake_client.servers.get_by_id.return_value = None
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        with pytest.raises(HetznerError):
            asyncio.run(svc.delete_server("ghost"))
        # Delete must NOT have been called.
        fake_client.servers.delete.assert_not_called()
        # Failure audit recorded.
        rows = Path(cfg.audit_path).read_text().strip().splitlines()
        assert len(rows) == 1
        row = json.loads(rows[0])
        assert row["action"] == "delete_server"
        assert row["success"] is False

    def test_happy_path(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        srv = _bound_server(server_id=42, name="dead")
        fake_client = MagicMock()
        fake_client.servers.get_by_name.return_value = srv
        fake_client.servers.delete.return_value = SimpleNamespace(id=1)
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        ok = asyncio.run(svc.delete_server("dead"))
        assert ok is True
        fake_client.servers.delete.assert_called_once_with(srv)
        rows = Path(cfg.audit_path).read_text().strip().splitlines()
        assert json.loads(rows[0])["success"] is True

    def test_numeric_id_lookup(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        srv = _bound_server(server_id=7)
        fake_client = MagicMock()
        fake_client.servers.get_by_id.return_value = srv
        fake_client.servers.delete.return_value = SimpleNamespace(id=1)
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        asyncio.run(svc.delete_server("7"))
        fake_client.servers.get_by_id.assert_called_once_with(7)
        fake_client.servers.get_by_name.assert_not_called()

    def test_empty_identifier_rejected(self, tmp_path):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        with pytest.raises(ValueError):
            asyncio.run(svc.delete_server(""))
        rows = Path(cfg.audit_path).read_text().strip().splitlines()
        assert json.loads(rows[0])["success"] is False
        assert "validation" in json.loads(rows[0])["reason"]

    def test_malformed_identifier_rejected(self, tmp_path):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        with pytest.raises(ValueError, match="Invalid identifier"):
            asyncio.run(svc.delete_server("bad/identifier"))
        rows = Path(cfg.audit_path).read_text().strip().splitlines()
        row = json.loads(rows[0])
        assert row["success"] is False
        assert "validation" in row["reason"]


# ---------------------------------------------------------------------------
# Lifecycle: power_on / power_off / shutdown / reboot
# ---------------------------------------------------------------------------

class TestLifecycleActions:
    """Cover the four power-management methods + their shared helper.

    The helper (:meth:`HetznerService._lifecycle_action`) is the
    actually interesting code — the four public methods are one-liners.
    We assert: each public method dispatches to the right hcloud SDK
    call, validation errors short-circuit before the network, the
    audit trail captures every outcome, and not-found surfaces as
    :class:`HetznerError` with a useful audit row.
    """

    @pytest.mark.parametrize("method,sdk_attr", [
        ("power_on", "power_on"),
        ("power_off", "power_off"),
        ("shutdown", "shutdown"),
        ("reboot", "reboot"),
    ])
    def test_dispatches_to_correct_sdk_call(
        self, tmp_path, monkeypatch, method, sdk_attr,
    ):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        srv = _bound_server(server_id=11, name="srv")
        fake_client = MagicMock()
        fake_client.servers.get_by_name.return_value = srv
        getattr(fake_client.servers, sdk_attr).return_value = SimpleNamespace(id=1)
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)

        ok = asyncio.run(getattr(svc, method)("srv"))
        assert ok is True
        getattr(fake_client.servers, sdk_attr).assert_called_once_with(srv)

        rows = Path(cfg.audit_path).read_text().strip().splitlines()
        last = json.loads(rows[-1])
        assert last["action"] == method
        assert last["success"] is True

    def test_not_found_raises_and_audits(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        fake_client = MagicMock()
        fake_client.servers.get_by_name.return_value = None
        fake_client.servers.get_by_id.return_value = None
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)

        with pytest.raises(HetznerError):
            asyncio.run(svc.power_on("ghost"))

        # power_on must NOT have been called against the SDK.
        fake_client.servers.power_on.assert_not_called()
        rows = Path(cfg.audit_path).read_text().strip().splitlines()
        last = json.loads(rows[-1])
        assert last["action"] == "power_on"
        assert last["success"] is False

    def test_validation_short_circuits_before_network(
        self, tmp_path, monkeypatch,
    ):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        fake_client = MagicMock()
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)

        with pytest.raises(ValueError):
            asyncio.run(svc.shutdown(""))

        # Client must NOT have been touched.
        fake_client.servers.shutdown.assert_not_called()
        fake_client.servers.get_by_name.assert_not_called()

        rows = Path(cfg.audit_path).read_text().strip().splitlines()
        row = json.loads(rows[-1])
        assert row["action"] == "shutdown"
        assert row["success"] is False
        assert "validation" in row["reason"]

    def test_api_error_wrapped(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        srv = _bound_server(server_id=11, name="srv")
        fake_client = MagicMock()
        fake_client.servers.get_by_name.return_value = srv
        fake_client.servers.reboot.side_effect = RuntimeError("boom")
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)

        with pytest.raises(HetznerError, match="Failed to reboot"):
            asyncio.run(svc.reboot("srv"))

        rows = Path(cfg.audit_path).read_text().strip().splitlines()
        last = json.loads(rows[-1])
        assert last["action"] == "reboot"
        assert last["success"] is False
        assert "boom" in last["reason"]


# ---------------------------------------------------------------------------
# SSH keys
# ---------------------------------------------------------------------------

class TestSSHKeys:
    def test_list(self, tmp_path, monkeypatch):
        svc = HetznerService(_make_config(tmp_path))
        fake_client = MagicMock()
        fake_client.ssh_keys.get_all.return_value = [
            SimpleNamespace(
                id=1, name="ed25519-laptop", fingerprint="aa:bb:cc",
                public_key="ssh-ed25519 AAAA...", labels={},
            ),
        ]
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        out = asyncio.run(svc.list_ssh_keys())
        assert out == [{
            "id": "1", "name": "ed25519-laptop",
            "fingerprint": "aa:bb:cc",
            "public_key": "ssh-ed25519 AAAA...", "labels": {},
        }]

    def test_create_validates_prefix(self, tmp_path, monkeypatch):
        svc = HetznerService(_make_config(tmp_path))
        with pytest.raises(ValueError, match="public_key must start"):
            asyncio.run(svc.create_ssh_key("mykey", "not-an-ssh-key"))

    def test_create_validates_name(self, tmp_path, monkeypatch):
        svc = HetznerService(_make_config(tmp_path))
        with pytest.raises(ValueError):
            asyncio.run(svc.create_ssh_key("bad name", "ssh-ed25519 AAAA"))

    def test_create_happy_path(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        fake_client = MagicMock()
        fake_client.ssh_keys.create.return_value = SimpleNamespace(
            id=42, name="laptop", fingerprint="aa:bb",
        )
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        out = asyncio.run(svc.create_ssh_key("laptop", "ssh-ed25519 AAAA..."))
        assert out == {"id": "42", "name": "laptop", "fingerprint": "aa:bb"}
        rows = Path(cfg.audit_path).read_text().strip().splitlines()
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# server_types
# ---------------------------------------------------------------------------

class TestServerTypes:
    def test_normalisation(self, tmp_path, monkeypatch):
        svc = HetznerService(_make_config(tmp_path))
        fake_client = MagicMock()
        fake_client.server_types.get_all.return_value = [
            SimpleNamespace(
                id=1, name="cx22", description="CX 22",
                cores=2, memory=4, disk=40, architecture="x86",
                prices=[{
                    "location": "fsn1",
                    "price_hourly": {"gross": "0.0050000000000000"},
                    "price_monthly": {"gross": "3.7900000000000000"},
                }],
            ),
            SimpleNamespace(
                id=2, name="custom", description="",
                cores=0, memory=0, disk=0, architecture="",
                prices=None,
            ),
        ]
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        out = asyncio.run(svc.list_server_types())
        assert out[0]["hourly_price_gross"] == "0.0050"
        assert out[0]["monthly_price_gross"] == "3.79"
        assert out[0]["currency"] == "EUR"
        assert out[1]["hourly_price_gross"] == ""


# ---------------------------------------------------------------------------
# list_locations
# ---------------------------------------------------------------------------

class TestListLocations:
    def test_normalisation(self, tmp_path, monkeypatch):
        svc = HetznerService(_make_config(tmp_path))
        fake_client = MagicMock()
        fake_client.locations.get_all.return_value = [
            SimpleNamespace(
                id=1, name="fsn1", description="Falkenstein DC Park 1",
                country="DE", city="Falkenstein", network_zone="eu-central",
            ),
            SimpleNamespace(
                id=2, name="ash", description=None,
                country=None, city=None, network_zone="us-east",
            ),
        ]
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        out = asyncio.run(svc.list_locations())
        assert out[0] == {
            "id": "1", "name": "fsn1",
            "description": "Falkenstein DC Park 1",
            "country": "DE", "city": "Falkenstein",
            "network_zone": "eu-central",
        }
        # ``None`` attributes collapse to empty strings — UI never has
        # to None-guard a row.
        assert out[1]["description"] == ""
        assert out[1]["country"] == ""
        assert out[1]["city"] == ""


# ---------------------------------------------------------------------------
# list_images
# ---------------------------------------------------------------------------

class TestListImages:
    def test_only_system_type_requested(self, tmp_path, monkeypatch):
        svc = HetznerService(_make_config(tmp_path))
        fake_client = MagicMock()
        fake_client.images.get_all.return_value = [
            SimpleNamespace(
                id=1, name="ubuntu-22.04", description="Ubuntu 22.04",
                os_flavor="ubuntu", os_version="22.04", architecture="x86",
            ),
        ]
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        out = asyncio.run(svc.list_images())
        # Caller never has to pass ``type`` explicitly — the service
        # always pins it to ``system`` so snapshots/backups don't leak
        # into the wizard surface.
        kwargs = fake_client.images.get_all.call_args.kwargs
        assert kwargs.get("type") == ["system"]
        assert "architecture" not in kwargs
        assert out[0]["name"] == "ubuntu-22.04"
        assert out[0]["architecture"] == "x86"

    def test_architecture_filter_passed_through(self, tmp_path, monkeypatch):
        svc = HetznerService(_make_config(tmp_path))
        fake_client = MagicMock()
        fake_client.images.get_all.return_value = []
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        asyncio.run(svc.list_images(architecture="arm"))
        kwargs = fake_client.images.get_all.call_args.kwargs
        assert kwargs.get("architecture") == ["arm"]

    def test_legacy_sdk_falls_back_to_client_side_filter(
        self, tmp_path, monkeypatch,
    ):
        """Older hcloud-python (<1.30) lacks the ``architecture`` kwarg;
        the service must catch that, retry without it, then filter
        client-side. Otherwise a fresh wizard load on a stale SDK
        would 500."""
        svc = HetznerService(_make_config(tmp_path))
        fake_client = MagicMock()

        def _selective_get_all(*, type, **kwargs):
            if "architecture" in kwargs:
                raise TypeError("unexpected keyword argument 'architecture'")
            return [
                SimpleNamespace(
                    id=1, name="x86-img", description="",
                    os_flavor="", os_version="", architecture="x86",
                ),
                SimpleNamespace(
                    id=2, name="arm-img", description="",
                    os_flavor="", os_version="", architecture="arm",
                ),
            ]
        fake_client.images.get_all.side_effect = _selective_get_all
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)

        out = asyncio.run(svc.list_images(architecture="arm"))
        assert [i["name"] for i in out] == ["arm-img"]


# ---------------------------------------------------------------------------
# test_connection
# ---------------------------------------------------------------------------

class TestTestConnection:
    def test_success(self, tmp_path, monkeypatch):
        svc = HetznerService(_make_config(tmp_path))
        fake_client = MagicMock()
        fake_client.servers.get_all.return_value = [_bound_server()]
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        out = asyncio.run(svc.test_connection())
        assert out["success"] is True
        assert out["server_count"] == 1

    def test_invalid_token_returns_failure(self, tmp_path, monkeypatch):
        svc = HetznerService(_make_config(tmp_path))
        fake_client = MagicMock()
        fake_client.servers.get_all.side_effect = RuntimeError("401")
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        out = asyncio.run(svc.test_connection())
        assert out["success"] is False
        assert "Authentication failed" in out["message"]

    def test_not_configured_returns_failure(self, tmp_path, monkeypatch):
        monkeypatch.delenv("HCLOUD_TOKEN", raising=False)
        monkeypatch.setattr(
            "servonaut.services.hetzner_service._HCLOUD_DEFAULT_TOKEN_FILE",
            tmp_path / "absent",
        )
        svc = HetznerService(_make_config(tmp_path, api_token=""))
        out = asyncio.run(svc.test_connection())
        assert out["success"] is False
        assert "No Hetzner Cloud API token" in out["message"]


# ---------------------------------------------------------------------------
# Cache invalidation on mutation
# ---------------------------------------------------------------------------

class TestCacheInvalidation:
    def test_create_invalidates_cache(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        Path(cfg.cache_path).write_text(json.dumps({
            "timestamp": datetime.now().isoformat(),
            "instances": [{"id": "stale"}],
        }))
        new_server = _bound_server(server_id=999, name="fresh")
        fake_client = MagicMock()
        fake_client.servers.create.return_value = SimpleNamespace(
            server=new_server, action=None, root_password=None, next_actions=None,
        )
        fake_client.servers.get_by_id.return_value = new_server
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        asyncio.run(svc.create_server(name="fresh", allow_no_ssh_keys=True))
        assert not Path(cfg.cache_path).exists(), "cache should have been busted"

    def test_delete_invalidates_cache(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        Path(cfg.cache_path).write_text(json.dumps({
            "timestamp": datetime.now().isoformat(),
            "instances": [{"id": "1"}],
        }))
        srv = _bound_server(server_id=1)
        fake_client = MagicMock()
        fake_client.servers.get_by_name.return_value = srv
        fake_client.servers.delete.return_value = SimpleNamespace(id=1)
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        asyncio.run(svc.delete_server("server-name"))
        assert not Path(cfg.cache_path).exists()


# ---------------------------------------------------------------------------
# Audit file permissions
# ---------------------------------------------------------------------------

class TestAuditPerms:
    def test_audit_file_owner_only(self, tmp_path, monkeypatch):
        cfg = _make_config(tmp_path)
        svc = HetznerService(cfg)
        # Trigger a deliberate audit write via a delete-of-nonexistent.
        fake_client = MagicMock()
        fake_client.servers.get_by_name.return_value = None
        fake_client.servers.get_by_id.return_value = None
        monkeypatch.setattr(svc, "_get_client", lambda: fake_client)
        with pytest.raises(HetznerError):
            asyncio.run(svc.delete_server("ghost"))
        mode = Path(cfg.audit_path).stat().st_mode & 0o777
        assert mode == 0o600
