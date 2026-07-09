"""Tests for BwSshConfigService.get_personal_instance_ref (new method).

Separate file to keep the locked-contract tests in test_bw_ssh_config_service.py
untouched while adding the new-method coverage cleanly.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.api_client import APIClient, APIError
from servonaut.services.bw_ssh_config_service import BwSshConfigService


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


def _api_error(status: int, code: str = "not_found") -> APIError:
    return APIError(code=code, message="boom", status=status)


@pytest.fixture
def mock_api():
    api = MagicMock(spec=APIClient)
    api.get = AsyncMock(return_value={})
    api.put = AsyncMock(return_value={})
    api.post = AsyncMock(return_value={})
    api.delete = AsyncMock(return_value={})
    return api


@pytest.fixture
def service(mock_api, tmp_path):
    # tmp cache path: the ref mirror must never touch the real ~/.servonaut in tests
    return BwSshConfigService(mock_api, refs_cache_path=tmp_path / "bw_ssh_refs.json")


class TestGetPersonalInstanceRef:
    def test_returns_payload_on_200(self, service, mock_api):
        """200 response is returned as-is."""
        payload = {
            "ssh_credential_provider": "bitwarden_pm",
            "ssh_credential_ref": {
                "item_id": "uuid-abc",
                "vault_url": "https://vault.bitwarden.com",
                "collection_id": "col-xyz",
            },
        }
        mock_api.get.return_value = payload
        result = _run(service.get_personal_instance_ref("aws", "i-0abc"))
        assert result is not None
        assert result["ssh_credential_ref"]["item_id"] == "uuid-abc"
        mock_api.get.assert_awaited_once_with(
            "/api/v1/me/instances/aws/i-0abc/ssh-ref"
        )

    def test_returns_none_on_404(self, service, mock_api):
        """404 → None (no ref stored, not an error)."""
        mock_api.get.side_effect = _api_error(404)
        result = _run(service.get_personal_instance_ref("aws", "i-0abc"))
        assert result is None

    def test_raises_on_non_404_errors(self, service, mock_api):
        """Non-404 API errors (e.g. 403, 500) propagate to the caller."""
        mock_api.get.side_effect = _api_error(403, "forbidden")
        with pytest.raises(APIError) as exc_info:
            _run(service.get_personal_instance_ref("aws", "i-0abc"))
        assert exc_info.value.status == 403

    def test_builds_correct_path_for_ovh(self, service, mock_api):
        mock_api.get.return_value = {
            "ssh_credential_provider": "bitwarden_pm",
            "ssh_credential_ref": {"item_id": "uuid-1"},
        }
        _run(service.get_personal_instance_ref("ovh", "server-001"))
        mock_api.get.assert_awaited_once_with(
            "/api/v1/me/instances/ovh/server-001/ssh-ref"
        )

    def test_payload_without_collection_id_is_valid(self, service, mock_api):
        """collection_id is optional — payload without it must not crash."""
        mock_api.get.return_value = {
            "ssh_credential_provider": "bitwarden_pm",
            "ssh_credential_ref": {"item_id": "uuid-only"},
        }
        result = _run(service.get_personal_instance_ref("hetzner", "htz-999"))
        assert result["ssh_credential_ref"]["item_id"] == "uuid-only"
        assert "collection_id" not in result["ssh_credential_ref"]


class TestRefRouteWithout405Fallback:
    """Servers that expose only PUT/DELETE on the ssh-ref route answer GET
    with 405 — reads must fall back to the local mirror, then the roll-up."""

    REF = {"item_id": "uuid-abc", "collection_id": "col-1"}

    def test_put_mirrors_ref_to_local_cache(self, service, mock_api, tmp_path):
        _run(service.put_personal_instance_ref(
            provider="ovh", instance_id="custom-web-1", ssh_credential_ref=dict(self.REF),
        ))
        cache_file = tmp_path / "bw_ssh_refs.json"
        assert cache_file.exists()
        import json
        cached = json.loads(cache_file.read_text())
        assert cached["ovh/custom-web-1"]["ssh_credential_ref"] == self.REF

    def test_get_405_returns_cached_ref_after_save(self, service, mock_api):
        _run(service.put_personal_instance_ref(
            provider="ovh", instance_id="custom-web-1", ssh_credential_ref=dict(self.REF),
        ))
        mock_api.get.side_effect = _api_error(405, "method_not_allowed")
        result = _run(service.get_personal_instance_ref("ovh", "custom-web-1"))
        assert result is not None
        assert result["ssh_credential_ref"]["item_id"] == "uuid-abc"

    def test_get_405_without_cache_uses_list_rollup(self, service, mock_api):
        """No local mirror → roll-up proves existence, ref is None (partial row)."""
        def _get(path):
            if path.endswith("/ssh-ref"):
                raise _api_error(405, "method_not_allowed")
            return {"instances": [
                {"provider": "ovh", "instance_id": "custom-web-1",
                 "ssh_credential_provider": "bitwarden_pm",
                 "ssh_verify_status": "verified"},
            ]}
        mock_api.get.side_effect = _get
        result = _run(service.get_personal_instance_ref("ovh", "custom-web-1"))
        assert result is not None
        assert result["ssh_credential_provider"] == "bitwarden_pm"
        assert result["ssh_credential_ref"] is None

    def test_get_405_nothing_anywhere_returns_none(self, service, mock_api):
        def _get(path):
            if path.endswith("/ssh-ref"):
                raise _api_error(405, "method_not_allowed")
            return {"instances": []}
        mock_api.get.side_effect = _get
        assert _run(service.get_personal_instance_ref("aws", "i-0abc")) is None

    def test_get_404_invalidates_stale_cache(self, service, mock_api):
        """Server says no ref → any stale local mirror is dropped."""
        _run(service.put_personal_instance_ref(
            provider="aws", instance_id="i-0abc", ssh_credential_ref=dict(self.REF),
        ))
        mock_api.get.side_effect = _api_error(404)
        assert _run(service.get_personal_instance_ref("aws", "i-0abc")) is None
        # subsequent 405 must NOT resurrect the dropped ref from the cache
        def _get(path):
            if path.endswith("/ssh-ref"):
                raise _api_error(405, "method_not_allowed")
            return {"instances": []}
        mock_api.get.side_effect = _get
        assert _run(service.get_personal_instance_ref("aws", "i-0abc")) is None

    def test_delete_removes_cached_ref(self, service, mock_api):
        _run(service.put_personal_instance_ref(
            provider="aws", instance_id="i-0abc", ssh_credential_ref=dict(self.REF),
        ))
        mock_api.delete.return_value = {"deleted": True}
        _run(service.delete_personal_instance_ref("aws", "i-0abc"))
        mock_api.get.side_effect = _api_error(405, "method_not_allowed")

        def _get(path):
            if path.endswith("/ssh-ref"):
                raise _api_error(405, "method_not_allowed")
            return {"instances": []}
        mock_api.get.side_effect = _get
        assert _run(service.get_personal_instance_ref("aws", "i-0abc")) is None


class TestHeadless401Fallback:
    """Headless surfaces (MCP server, relay listener) have no interactive
    login, so ref reads can 401 — they must fall back to the device-local
    mirror. The vault unlock is still required to obtain key material, so
    the fallback leaks nothing."""

    REF = {"item_id": "uuid-abc", "collection_id": "col-1"}

    def test_get_401_returns_cached_ref_after_save(self, service, mock_api):
        _run(service.put_personal_instance_ref(
            provider="aws", instance_id="i-0abc", ssh_credential_ref=dict(self.REF),
        ))
        mock_api.get.side_effect = _api_error(401, "unauthenticated")
        result = _run(service.get_personal_instance_ref("aws", "i-0abc"))
        assert result is not None
        assert result["ssh_credential_ref"]["item_id"] == "uuid-abc"

    def test_get_401_without_cache_guards_list_call(self, service, mock_api):
        """Both the ssh-ref GET and the /me/instances roll-up 401 — the
        guarded list call is treated as an empty roll-up, never raised."""
        mock_api.get.side_effect = _api_error(401, "unauthenticated")
        assert _run(service.get_personal_instance_ref("aws", "i-0abc")) is None

    def test_get_405_with_list_401_returns_none(self, service, mock_api):
        """Mixed failure: ssh-ref GET 405s and the roll-up 401s — still None,
        not an exception."""
        def _get(path):
            if path.endswith("/ssh-ref"):
                raise _api_error(405, "method_not_allowed")
            raise _api_error(401, "unauthenticated")
        mock_api.get.side_effect = _get
        assert _run(service.get_personal_instance_ref("aws", "i-0abc")) is None

    def test_get_404_stays_authoritative_and_invalidates_mirror(self, service, mock_api):
        """404 is still authoritative-none: the mirror is dropped and a later
        401 must not resurrect it."""
        _run(service.put_personal_instance_ref(
            provider="aws", instance_id="i-0abc", ssh_credential_ref=dict(self.REF),
        ))
        mock_api.get.side_effect = _api_error(404)
        assert _run(service.get_personal_instance_ref("aws", "i-0abc")) is None
        mock_api.get.side_effect = _api_error(401, "unauthenticated")
        assert _run(service.get_personal_instance_ref("aws", "i-0abc")) is None


class TestMirrorWriteDurability:
    """The mirror file is shared by up to three long-running processes (TUI,
    MCP server, relay listener) and — against 405-only servers — is the ONLY
    source of the full ref on this device. Writes must therefore be atomic
    (readers never see a truncated file, a crash never empties the mirror)
    and read-modify-writes must be serialised so concurrent saves cannot
    drop each other's entries."""

    REF = {"item_id": "uuid-abc", "collection_id": "col-1"}

    def _row(self, item_id: str) -> dict:
        return {
            "ssh_credential_provider": "bitwarden_pm",
            "ssh_credential_ref": {"item_id": item_id},
        }

    def test_mirror_file_is_0600(self, service, tmp_path):
        import stat

        service._cache_store("aws", "i-0abc", self._row("uuid-1"))
        mode = stat.S_IMODE((tmp_path / "bw_ssh_refs.json").stat().st_mode)
        assert mode == 0o600

    def test_no_temp_files_left_behind(self, service, tmp_path):
        service._cache_store("aws", "i-0abc", self._row("uuid-1"))
        service._cache_remove("aws", "i-0abc")
        leftovers = [p.name for p in tmp_path.iterdir() if p.suffix == ".tmp"]
        assert leftovers == []

    def test_failed_replace_keeps_previous_mirror_intact(self, service, tmp_path):
        """A crash mid-write (simulated: os.replace fails) must leave the
        previous mirror byte-for-byte intact — never truncated/empty — and
        must not leak the temp file or raise out of the cache layer."""
        import json
        from unittest.mock import patch as _patch

        service._cache_store("aws", "i-0abc", self._row("uuid-1"))
        before = (tmp_path / "bw_ssh_refs.json").read_text()

        with _patch(
            "servonaut.services.bw_ssh_config_service.os.replace",
            side_effect=OSError("disk full"),
        ):
            service._cache_store("aws", "i-0def", self._row("uuid-2"))

        assert (tmp_path / "bw_ssh_refs.json").read_text() == before
        assert json.loads(before)["aws/i-0abc"]["ssh_credential_ref"]["item_id"] == "uuid-1"
        assert [p.name for p in tmp_path.iterdir() if p.suffix == ".tmp"] == []

    def test_remove_without_entry_does_not_rewrite(self, service, tmp_path):
        service._cache_store("aws", "i-0abc", self._row("uuid-1"))
        mtime = (tmp_path / "bw_ssh_refs.json").stat().st_mtime_ns
        service._cache_remove("aws", "i-does-not-exist")
        assert (tmp_path / "bw_ssh_refs.json").stat().st_mtime_ns == mtime

    def test_concurrent_stores_do_not_lose_entries(self, service, tmp_path):
        """Interleaved read-modify-writes from multiple threads (standing in
        for the TUI / MCP / relay processes — flock serialises across both)
        must preserve every entry: no last-writer-wins dropout."""
        import json
        from concurrent.futures import ThreadPoolExecutor

        ids = [f"i-{n:04d}" for n in range(24)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(
                lambda i: service._cache_store("aws", i, self._row(f"uuid-{i}")),
                ids,
            ))

        cache = json.loads((tmp_path / "bw_ssh_refs.json").read_text())
        assert {f"aws/{i}" for i in ids} <= set(cache.keys())
