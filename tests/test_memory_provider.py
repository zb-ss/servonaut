"""Memory records are filed under the instance's real provider.

AWS instance dicts carry no ``provider`` key, so memory used to default
them to ``"custom"``. These tests pin the provider derivation for AWS, OVH,
Hetzner and custom servers, prove that AWS memory written by earlier
releases under ``custom/`` still loads, and check the provider sent to the
sync server.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory.interfaces import ModuleProberInterface, ModuleResult
from servonaut.services.memory.provider import instance_provider, provider_slug
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.status import STATUS_FRESH, STATUS_STALE, compute_memory_status
from servonaut.services.memory.store import MemoryStore

# Shapes as each provider service produces them (AWS has no provider key).
AWS_INSTANCE = {"id": "i-0123456789abcdef0", "name": "web-1", "region": "eu-west-1"}
OVH_INSTANCE = {"id": "ovh-1", "name": "web-2", "provider": "OVH"}
HETZNER_INSTANCE = {"id": "123456", "name": "web-3", "provider": "hetzner"}
CUSTOM_INSTANCE = {"id": "web-4", "name": "web-4", "provider": "custom", "is_custom": True}


class _OsProber(ModuleProberInterface):
    name = "os"
    ttl_seconds = 3600

    async def probe(self, ssh_runner: Any) -> ModuleResult:
        return ModuleResult(
            module="os",
            instance_id="",
            observed={"distro": "ubuntu"},
            probed_at="2026-01-01T00:00:00+00:00",
            ttl_seconds=self.ttl_seconds,
        )


def _service(root: Path) -> MemoryService:
    return MemoryService(
        store=MemoryStore(root=root), config=MemoryConfig(), probers=[_OsProber()],
    )


class TestInstanceProvider:
    @pytest.mark.parametrize("instance,expected", [
        (AWS_INSTANCE, "aws"),
        (OVH_INSTANCE, "ovh"),
        (HETZNER_INSTANCE, "hetzner"),
        (CUSTOM_INSTANCE, "custom"),
        ({"id": "web-5", "provider": "DigitalOcean", "is_custom": True}, "digitalocean"),
        ({"id": "web-6", "is_custom": True}, "custom"),
    ])
    def test_slug_per_provider(self, instance, expected):
        assert instance_provider(instance) == expected

    def test_provider_slug_is_idempotent(self):
        for label in ("AWS", "OVH", "hetzner", "custom", ""):
            assert provider_slug(provider_slug(label)) == provider_slug(label)


class TestBuildFilesUnderRealProvider:
    @pytest.mark.parametrize("instance,slug", [
        (AWS_INSTANCE, "aws"),
        (OVH_INSTANCE, "ovh"),
        (HETZNER_INSTANCE, "hetzner"),
    ])
    def test_build_writes_provider_dir_and_index(self, tmp_path, instance, slug):
        svc = _service(tmp_path)
        asyncio.run(svc.build(instance))

        assert (tmp_path / slug / instance["id"] / "os.json").is_file()
        assert not (tmp_path / "custom" / instance["id"]).exists()
        index = json.loads((tmp_path / "index.json").read_text())
        assert index["instances"][instance["id"]]["provider"] == slug

    def test_status_reads_what_build_wrote(self, tmp_path):
        svc = _service(tmp_path)
        asyncio.run(svc.build(AWS_INSTANCE))
        assert compute_memory_status(AWS_INSTANCE, svc) in (STATUS_FRESH, STATUS_STALE)


class TestLegacyCustomDirStillLoads:
    """AWS memory written by earlier releases lives under ``custom/<id>``."""

    @pytest.fixture
    def legacy_root(self, tmp_path: Path) -> Path:
        legacy = tmp_path / "custom" / AWS_INSTANCE["id"]
        legacy.mkdir(parents=True)
        (legacy / "os.json").write_text(json.dumps({
            "observed": {"distro": "debian"},
            "probed_at": "2026-01-01T00:00:00+00:00",
            "ttl_seconds": 3600,
        }))
        (legacy / "annotations.md").write_text("runs the billing cron\n")
        return tmp_path

    def test_modules_and_annotations_load(self, legacy_root):
        svc = _service(legacy_root)
        provider = instance_provider(AWS_INSTANCE)

        modules = svc.get_all_modules(AWS_INSTANCE["id"], provider)
        assert modules["os"]["observed"] == {"distro": "debian"}
        assert "billing cron" in svc.read_annotations(AWS_INSTANCE["id"], provider)

    def test_rebuild_keeps_one_directory(self, legacy_root):
        """A rebuild updates the legacy directory in place — no split history."""
        svc = _service(legacy_root)
        asyncio.run(svc.build(AWS_INSTANCE))

        assert not (legacy_root / "aws" / AWS_INSTANCE["id"]).exists()
        data = json.loads(
            (legacy_root / "custom" / AWS_INSTANCE["id"] / "os.json").read_text()
        )
        assert data["observed"] == {"distro": "ubuntu"}
        assert "billing cron" in svc.read_annotations(AWS_INSTANCE["id"], "aws")

    def test_legacy_index_entry_still_resolves(self, legacy_root):
        """An index entry written as ``custom`` keeps pointing at its data."""
        svc = _service(legacy_root)
        assert "os" in svc.get_all_modules(AWS_INSTANCE["id"], "custom")


class TestSyncUpsertProvider:
    @pytest.mark.parametrize("instance,expected", [
        (AWS_INSTANCE, "aws"),
        (OVH_INSTANCE, "ovh"),
        (HETZNER_INSTANCE, "hetzner"),
        (CUSTOM_INSTANCE, "custom"),
        ({"id": "web-5", "provider": "DigitalOcean", "is_custom": True}, "custom"),
    ])
    @pytest.mark.asyncio
    async def test_upsert_sends_server_accepted_slug(self, instance, expected):
        from servonaut.services.api_client import APIClient
        from servonaut.services.memory.rate_limiter import RateLimiter
        from servonaut.services.memory.sync_service import MemorySyncService

        api = MagicMock(spec=APIClient)
        api.post = AsyncMock(return_value={"instance_id": instance["id"]})
        memory_service = MagicMock()
        memory_service.is_memory_disabled.return_value = False
        svc = MemorySyncService(
            api_client=api,
            crypto=MagicMock(),
            memory_service=memory_service,
            config_manager=MagicMock(),
            auth_service=MagicMock(),
            rate_limiter=RateLimiter(),
        )
        await svc.upsert_instance(instance)

        payload = api.post.call_args.kwargs["json"]
        assert payload["provider"] == expected


class TestIndexRowProvider:
    """Index rows written before AWS had its own provider say "custom"."""

    @pytest.mark.parametrize("entry,expected", [
        ({"instance_id": "i-0123456789abcdef0", "provider": "custom"}, "aws"),   # legacy AWS row
        ({"instance_id": "i-01234567", "provider": "custom"}, "aws"),            # short EC2 id
        ({"instance_id": "i-0123456789abcdef0", "provider": "aws"}, "aws"),
        ({"instance_id": "custom-web-4", "provider": "custom"}, "custom"),
        ({"instance_id": "custom-i-01234567", "provider": "custom"}, "custom"),
        ({"instance_id": "ovh-1", "provider": "OVH"}, "ovh"),
        ({"instance_id": "123456", "provider": "hetzner"}, "hetzner"),
    ])
    def test_index_entry_provider(self, entry, expected):
        from servonaut.services.memory.provider import index_entry_provider
        assert index_entry_provider(entry) == expected


def _sync_service(index_rows):
    from servonaut.services.api_client import APIClient
    from servonaut.services.memory.rate_limiter import RateLimiter
    from servonaut.services.memory.sync_service import MemorySyncService

    api = MagicMock(spec=APIClient)
    api.post = AsyncMock(return_value={})
    memory_service = MagicMock()
    memory_service.is_memory_disabled.return_value = False
    memory_service.list_all.return_value = index_rows
    svc = MemorySyncService(
        api_client=api,
        crypto=MagicMock(),
        memory_service=memory_service,
        config_manager=MagicMock(),
        auth_service=MagicMock(),
        rate_limiter=RateLimiter(),
    )
    return svc, api


class TestSyncProviderIsStable:
    """Legacy "custom" rows must register AWS instances as "aws", like new rows."""

    @pytest.mark.asyncio
    async def test_upsert_all_instances(self):
        svc, api = _sync_service([
            {"instance_id": "i-0123456789abcdef0", "name": "web-1", "provider": "custom"},
            {"instance_id": "custom-web-4", "name": "web-4", "provider": "custom"},
        ])
        await svc.upsert_all_instances()

        sent = {c.kwargs["json"]["instance_id"]: c.kwargs["json"]["provider"]
                for c in api.post.call_args_list}
        assert sent == {"i-0123456789abcdef0": "aws", "custom-web-4": "custom"}

    def test_lookup_local_metadata(self):
        svc, _ = _sync_service([
            {"instance_id": "i-0123456789abcdef0", "name": "web-1", "provider": "custom"},
        ])
        assert svc._lookup_local_metadata("i-0123456789abcdef0") == ("web-1", "aws")
        # No local row: derived from the id alone, same answer as with a row.
        assert svc._lookup_local_metadata("i-0fedcba9876543210") == ("i-0fedcba9876543210", "aws")
        assert svc._lookup_local_metadata("custom-web-9") == ("custom-web-9", "custom")
