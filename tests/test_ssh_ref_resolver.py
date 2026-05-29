"""Tests for SshRefResolver — three-tier SSH credential resolution chain."""

from __future__ import annotations

import asyncio
import logging
from typing import List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.api_client import APIClient, APIError
from servonaut.services.bw_ssh_config_service import BwSshConfigService
from servonaut.services.team_service import TeamService
from servonaut.services.ssh_ref_resolver import ResolvedSshRef, SshRefResolver


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


def _api_error(status: int, code: str = "not_found") -> APIError:
    return APIError(code=code, message="boom", status=status)


def _aws_instance(iid: str = "i-0abc", key_name: str = "my-key") -> dict:
    return {
        "id": iid,
        "name": "prod-server",
        "provider": "aws",
        "key_name": key_name,
        "public_ip": "1.2.3.4",
    }


def _shared_instance(
    iid: str = "srv-1",
    slug: str = "my-team",
    server_id: str = "srv-1",
) -> dict:
    return {
        "id": iid,
        "name": "shared-server",
        "provider": "aws",
        "is_shared": True,
        "team_slug": slug,
        "shared_server_id": server_id,
        "public_ip": "2.3.4.5",
    }


def _make_resolver(
    bw_get_ref=None,
    team_get_ref=None,
    ssh_key_path: Optional[str] = None,
    ssh_discover: Optional[str] = None,
    teams: Optional[List[dict]] = None,
) -> SshRefResolver:
    """Build a SshRefResolver with mocked sub-services."""
    bw_svc = MagicMock(spec=BwSshConfigService)
    bw_svc.get_personal_instance_ref = AsyncMock(
        return_value=bw_get_ref if bw_get_ref is not None else None
    )

    team_svc = MagicMock(spec=TeamService)
    team_svc.get_team_server_ssh_ref = AsyncMock(
        return_value=team_get_ref if team_get_ref is not None else None
    )

    ssh_svc = MagicMock()
    ssh_svc.get_key_path = MagicMock(return_value=ssh_key_path)
    ssh_svc.discover_key = MagicMock(return_value=ssh_discover)

    teams_supplier = (lambda: teams) if teams is not None else None

    return SshRefResolver(
        bw_ssh_config_service=bw_svc,
        team_service=team_svc,
        ssh_service=ssh_svc,
        teams_supplier=teams_supplier,
    )


# ---------------------------------------------------------------------------
# Tier 1 — personal
# ---------------------------------------------------------------------------

class TestPersonalTier:
    def test_personal_hit_returns_resolved_ref_with_item_id(self):
        """Personal tier hit → ResolvedSshRef(source='personal', item_id=…)."""
        payload = {
            "ssh_credential_provider": "bitwarden_pm",
            "ssh_credential_ref": {
                "item_id": "uuid-personal",
                "vault_url": "https://vault.bitwarden.com",
                "collection_id": "col-1",
            },
        }
        resolver = _make_resolver(bw_get_ref=payload)
        result = _run(resolver.resolve(_aws_instance()))
        assert result is not None
        assert result.source == "personal"
        assert result.item_id == "uuid-personal"
        assert result.vault_url == "https://vault.bitwarden.com"
        assert result.collection_id == "col-1"
        assert result.local_key_path is None
        assert result.team_slug is None

    def test_personal_404_cascades_to_next_tier(self):
        """Personal tier returning None (404) → falls through to local tier."""
        resolver = _make_resolver(
            bw_get_ref=None,  # simulates 404
            ssh_key_path="/home/user/.ssh/my-key.pem",
        )
        result = _run(resolver.resolve(_aws_instance()))
        assert result is not None
        assert result.source == "local"
        assert result.local_key_path == "/home/user/.ssh/my-key.pem"

    def test_personal_api_error_logs_warning_and_cascades(self, caplog):
        """403/5xx from personal tier: logs WARNING, chain continues."""
        bw_svc = MagicMock(spec=BwSshConfigService)
        bw_svc.get_personal_instance_ref = AsyncMock(
            side_effect=_api_error(403, "forbidden")
        )
        ssh_svc = MagicMock()
        ssh_svc.get_key_path = MagicMock(return_value="/ssh/fallback-key")
        ssh_svc.discover_key = MagicMock(return_value=None)

        resolver = SshRefResolver(
            bw_ssh_config_service=bw_svc,
            team_service=MagicMock(spec=TeamService),
            ssh_service=ssh_svc,
            teams_supplier=None,
        )

        with caplog.at_level(logging.WARNING, logger="servonaut.services.ssh_ref_resolver"):
            result = _run(resolver.resolve(_aws_instance()))

        assert result is not None
        assert result.source == "local"
        # A WARNING must have been emitted for the 403
        warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert any("403" in r.message or "personal" in r.message.lower() for r in warning_records), \
            f"Expected a warning about the 403; got: {[r.message for r in warning_records]}"

    def test_custom_server_no_provider_skips_personal_tier(self):
        """Custom servers (no 'provider' key) silently skip personal tier."""
        custom_inst = {
            "id": "my-vps",
            "name": "vps-1",
            "is_custom": True,
            "public_ip": "3.4.5.6",
        }
        resolver = _make_resolver(
            bw_get_ref={"ssh_credential_ref": {"item_id": "should-not-be-used"}},
            ssh_key_path="/ssh/vps-key",
        )
        # bw service should NOT be called for custom instance
        result = _run(resolver.resolve(custom_inst))
        assert result is not None
        assert result.source == "local"
        resolver._bw.get_personal_instance_ref.assert_not_awaited()

    def test_invalid_provider_skips_personal_tier_no_propagation(self):
        """Unknown provider (e.g. 'gcp') → validation silently skips tier."""
        gcp_inst = {
            "id": "gcp-1234",
            "name": "gcp-instance",
            "provider": "gcp",  # not in {aws, ovh, hetzner}
            "public_ip": "5.6.7.8",
        }
        resolver = _make_resolver(ssh_key_path="/ssh/gcp-key")
        result = _run(resolver.resolve(gcp_inst))
        assert result is not None
        assert result.source == "local"
        resolver._bw.get_personal_instance_ref.assert_not_awaited()

    def test_invalid_instance_id_skips_personal_tier_no_propagation(self):
        """Invalid instance_id (path-traversal chars) → validation skips tier."""
        bad_inst = {
            "id": "../../etc/passwd",
            "name": "bad-instance",
            "provider": "aws",
            "public_ip": "1.2.3.4",
        }
        resolver = _make_resolver(ssh_key_path="/ssh/local-key")
        result = _run(resolver.resolve(bad_inst))
        # Should not crash, should fall through to local
        assert result is not None
        assert result.source == "local"
        resolver._bw.get_personal_instance_ref.assert_not_awaited()


# ---------------------------------------------------------------------------
# Tier 2 — team
# ---------------------------------------------------------------------------

class TestTeamTier:
    def test_team_hit_when_instance_is_shared(self):
        """Shared instance with team BW ref → ResolvedSshRef(source='team')."""
        payload = {
            "ssh_credential_ref": {
                "item_id": "uuid-team",
                "vault_url": "https://vault.bitwarden.com",
            }
        }
        inst = _shared_instance(slug="my-team", server_id="srv-1")
        teams = [{"slug": "my-team"}]
        resolver = _make_resolver(
            bw_get_ref=None,  # personal 404
            team_get_ref=payload,
            teams=teams,
        )
        result = _run(resolver.resolve(inst))
        assert result is not None
        assert result.source == "team"
        assert result.item_id == "uuid-team"
        assert result.team_slug == "my-team"
        assert result.server_id == "srv-1"

    def test_team_tier_skipped_when_teams_supplier_is_none(self):
        """No teams_supplier → team tier entirely skipped."""
        inst = _shared_instance()
        resolver = _make_resolver(
            bw_get_ref=None,
            team_get_ref={"ssh_credential_ref": {"item_id": "uuid-team"}},
            ssh_key_path="/local/key",
            teams=None,  # no supplier
        )
        result = _run(resolver.resolve(inst))
        # Should skip team, fall through to local
        assert result is not None
        assert result.source == "local"
        resolver._team_svc.get_team_server_ssh_ref.assert_not_awaited()

    def test_team_tier_walks_multiple_teams_first_match_wins(self):
        """Multiple teams: first team with a hit wins; others not consulted."""
        payload = {
            "ssh_credential_ref": {"item_id": "uuid-team-b"}
        }
        inst = _shared_instance(slug="team-b", server_id="s-99")
        teams = [{"slug": "team-a"}, {"slug": "team-b"}, {"slug": "team-c"}]

        # Only team-b has a ref
        team_svc = MagicMock(spec=TeamService)
        team_svc.get_team_server_ssh_ref = AsyncMock(
            side_effect=lambda slug, sid: (
                payload if slug == "team-b" else None
            )
        )

        bw_svc = MagicMock(spec=BwSshConfigService)
        bw_svc.get_personal_instance_ref = AsyncMock(return_value=None)

        ssh_svc = MagicMock()
        ssh_svc.get_key_path = MagicMock(return_value=None)
        ssh_svc.discover_key = MagicMock(return_value=None)

        resolver = SshRefResolver(
            bw_ssh_config_service=bw_svc,
            team_service=team_svc,
            ssh_service=ssh_svc,
            teams_supplier=lambda: teams,
        )
        result = _run(resolver.resolve(inst))
        assert result is not None
        assert result.source == "team"
        assert result.item_id == "uuid-team-b"
        assert result.team_slug == "team-b"

    def test_team_tier_not_attempted_for_non_shared_instance(self):
        """Non-shared instances skip the team tier entirely."""
        inst = _aws_instance()  # not shared
        resolver = _make_resolver(
            bw_get_ref=None,
            team_get_ref={"ssh_credential_ref": {"item_id": "should-not-be-called"}},
            ssh_key_path="/local/key",
            teams=[{"slug": "some-team"}],
        )
        result = _run(resolver.resolve(inst))
        assert result is not None
        assert result.source == "local"
        resolver._team_svc.get_team_server_ssh_ref.assert_not_awaited()


# ---------------------------------------------------------------------------
# Tier 3 — local
# ---------------------------------------------------------------------------

class TestLocalTier:
    def test_local_fallback_when_both_api_tiers_return_none(self):
        """When personal and team return None, local tier is used."""
        resolver = _make_resolver(
            bw_get_ref=None,
            ssh_key_path="/home/user/.ssh/id_rsa",
        )
        result = _run(resolver.resolve(_aws_instance()))
        assert result is not None
        assert result.source == "local"
        assert result.local_key_path == "/home/user/.ssh/id_rsa"
        assert result.item_id is None

    def test_local_discover_key_used_when_get_key_path_is_none(self):
        """discover_key() is tried when get_key_path() returns None."""
        resolver = _make_resolver(
            bw_get_ref=None,
            ssh_key_path=None,
            ssh_discover="/home/user/.ssh/my-key.pem",
        )
        inst = _aws_instance(key_name="my-key")
        result = _run(resolver.resolve(inst))
        assert result is not None
        assert result.source == "local"
        assert result.local_key_path == "/home/user/.ssh/my-key.pem"

    def test_returns_none_when_no_tier_resolves(self):
        """All tiers return None → resolve() returns None."""
        resolver = _make_resolver(
            bw_get_ref=None,
            ssh_key_path=None,
            ssh_discover=None,
        )
        result = _run(resolver.resolve(_aws_instance()))
        assert result is None

    def test_custom_server_may_match_local_tier(self):
        """Custom server without provider skips personal, but local still works."""
        custom_inst = {
            "id": "my-vps",
            "name": "vps-1",
            "is_custom": True,
            "public_ip": "3.4.5.6",
        }
        resolver = _make_resolver(
            bw_get_ref=None,
            ssh_key_path="/ssh/vps-key",
        )
        result = _run(resolver.resolve(custom_inst))
        assert result is not None
        assert result.source == "local"
        assert result.local_key_path == "/ssh/vps-key"

    def test_instance_ssh_key_used_when_path_exists(self, tmp_path):
        """Custom-server ``instance['ssh_key']`` resolves directly when on disk.

        Regression: custom servers stash the key path in ``ssh_key`` and
        ``key_name`` both, but ``key_name`` is the full path — not an AWS
        key-pair name — so ``discover_key`` can't find it.  The resolver
        must consult ``instance['ssh_key']`` before falling through.
        """
        key_file = tmp_path / "vps.pem"
        key_file.write_text("FAKE KEY")

        custom_inst = {
            "id": "custom-vps-1",
            "name": "vps-1",
            "provider": "custom",
            "is_custom": True,
            "ssh_key": str(key_file),
            "key_name": str(key_file),
            "public_ip": "3.4.5.6",
        }
        resolver = _make_resolver(
            bw_get_ref=None,
            ssh_key_path=None,
            ssh_discover=None,
        )
        result = _run(resolver.resolve(custom_inst))
        assert result is not None
        assert result.source == "local"
        assert result.local_key_path == str(key_file)

    def test_instance_ssh_key_skipped_when_path_missing(self):
        """Non-existent ``instance['ssh_key']`` falls through to other lookups."""
        custom_inst = {
            "id": "custom-vps-1",
            "name": "vps-1",
            "provider": "custom",
            "is_custom": True,
            "ssh_key": "/nonexistent/path/to/key.pem",
            "public_ip": "3.4.5.6",
        }
        resolver = _make_resolver(
            bw_get_ref=None,
            ssh_key_path="/configured/default-key",
        )
        result = _run(resolver.resolve(custom_inst))
        assert result is not None
        assert result.source == "local"
        assert result.local_key_path == "/configured/default-key"

    def test_instance_ssh_key_expands_user(self, tmp_path, monkeypatch):
        """``~``-prefixed ``ssh_key`` paths are expanded before existence check."""
        monkeypatch.setenv("HOME", str(tmp_path))
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        key_file = ssh_dir / "vps.pem"
        key_file.write_text("FAKE KEY")

        custom_inst = {
            "id": "custom-vps-1",
            "name": "vps-1",
            "provider": "custom",
            "is_custom": True,
            "ssh_key": "~/.ssh/vps.pem",
            "public_ip": "3.4.5.6",
        }
        resolver = _make_resolver(bw_get_ref=None, ssh_key_path=None)
        result = _run(resolver.resolve(custom_inst))
        assert result is not None
        assert result.source == "local"
        assert result.local_key_path == str(key_file)
