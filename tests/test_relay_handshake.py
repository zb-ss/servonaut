"""Tests for wire format v1.0 handshake and heartbeat messages.

Assertions:
- Handshake shape matches v1.0 exactly
- providers_configured reflects app state
- cli_release_channel reflects env var with dev/stable fallback
- version matches __version__
- Heartbeat is the minimal shape
"""
from __future__ import annotations

import asyncio
import os
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import servonaut
from servonaut.services.relay_listener import (
    RelayListener,
    _resolve_providers_configured,
    _resolve_release_channel,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_listener(
    providers: Optional[list] = None,
) -> RelayListener:
    """Create a RelayListener with all external deps mocked."""
    executors = MagicMock()
    listener = RelayListener(
        executors=executors,
        base_url="https://api.example.com",
        mercure_url="https://example.com/.well-known/mercure",
        auth_token="test-token",
        user_id="42",
        heartbeat_interval=30,
        providers_configured=providers,
    )
    return listener


# ---------------------------------------------------------------------------
# _resolve_release_channel
# ---------------------------------------------------------------------------

class TestResolveReleaseChannel:
    def test_env_var_stable(self, monkeypatch):
        monkeypatch.setenv("SERVONAUT_RELEASE_CHANNEL", "stable")
        assert _resolve_release_channel() == "stable"

    def test_env_var_beta(self, monkeypatch):
        monkeypatch.setenv("SERVONAUT_RELEASE_CHANNEL", "beta")
        assert _resolve_release_channel() == "beta"

    def test_env_var_dev(self, monkeypatch):
        monkeypatch.setenv("SERVONAUT_RELEASE_CHANNEL", "dev")
        assert _resolve_release_channel() == "dev"

    def test_env_var_unknown_falls_back_to_stable(self, monkeypatch):
        monkeypatch.setenv("SERVONAUT_RELEASE_CHANNEL", "nightly")
        # Unknown value — falls through to install detection → stable in test env
        result = _resolve_release_channel()
        assert result in ("stable", "dev")

    def test_env_var_unset_returns_stable_or_dev(self, monkeypatch):
        monkeypatch.delenv("SERVONAUT_RELEASE_CHANNEL", raising=False)
        result = _resolve_release_channel()
        assert result in ("stable", "dev")

    def test_env_var_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("SERVONAUT_RELEASE_CHANNEL", "STABLE")
        assert _resolve_release_channel() == "stable"


# ---------------------------------------------------------------------------
# _resolve_providers_configured
# ---------------------------------------------------------------------------

class TestResolveProvidersConfigured:
    def test_no_app_returns_empty(self):
        assert _resolve_providers_configured(None) == []

    def test_aws_service_present(self):
        app = MagicMock()
        app.aws_service = MagicMock()
        app.aws_object_storage_service = None
        app.hetzner_service = None
        app.hetzner_object_storage_service = None
        app.ovh_service = None
        app.ovh_object_storage_service = None
        result = _resolve_providers_configured(app)
        assert result == ["aws"]

    def test_aws_object_storage_only(self):
        app = MagicMock()
        app.aws_service = None
        app.aws_object_storage_service = MagicMock()
        app.hetzner_service = None
        app.hetzner_object_storage_service = None
        app.ovh_service = None
        app.ovh_object_storage_service = None
        result = _resolve_providers_configured(app)
        assert result == ["aws"]

    def test_hetzner_and_ovh(self):
        app = MagicMock()
        app.aws_service = None
        app.aws_object_storage_service = None
        app.hetzner_service = MagicMock()
        app.hetzner_object_storage_service = None
        app.ovh_service = MagicMock()
        app.ovh_object_storage_service = None
        result = _resolve_providers_configured(app)
        assert result == ["hetzner", "ovh"]

    def test_all_providers_sorted_alphabetically(self):
        app = MagicMock()
        app.aws_service = MagicMock()
        app.aws_object_storage_service = None
        app.hetzner_service = MagicMock()
        app.hetzner_object_storage_service = None
        app.ovh_service = MagicMock()
        app.ovh_object_storage_service = None
        result = _resolve_providers_configured(app)
        assert result == ["aws", "hetzner", "ovh"]
        assert result == sorted(result)

    def test_no_services_returns_empty(self):
        app = MagicMock()
        app.aws_service = None
        app.aws_object_storage_service = None
        app.hetzner_service = None
        app.hetzner_object_storage_service = None
        app.ovh_service = None
        app.ovh_object_storage_service = None
        result = _resolve_providers_configured(app)
        assert result == []


# ---------------------------------------------------------------------------
# _build_handshake
# ---------------------------------------------------------------------------

class TestBuildHandshake:
    def test_handshake_type(self):
        listener = _make_listener(providers=["aws"])
        hs = listener._build_handshake()
        assert hs["type"] == "cli.handshake"

    def test_handshake_version_matches_package(self):
        listener = _make_listener()
        hs = listener._build_handshake()
        assert hs["version"] == servonaut.__version__

    def test_handshake_providers_configured(self):
        listener = _make_listener(providers=["aws", "hetzner"])
        hs = listener._build_handshake()
        assert hs["providers_configured"] == ["aws", "hetzner"]

    def test_handshake_providers_empty_by_default(self):
        listener = _make_listener(providers=None)
        hs = listener._build_handshake()
        assert hs["providers_configured"] == []

    def test_handshake_capabilities_supports_dynamic_catalog_true(self):
        # v2.15.0 — capability bit flipped True when PR5' landed.
        listener = _make_listener()
        hs = listener._build_handshake()
        assert hs["capabilities"] == {"supports_dynamic_catalog": True}

    def test_handshake_cli_release_channel_present(self):
        listener = _make_listener()
        hs = listener._build_handshake()
        assert hs["cli_release_channel"] in ("stable", "beta", "dev")

    def test_handshake_env_var_release_channel(self, monkeypatch):
        monkeypatch.setenv("SERVONAUT_RELEASE_CHANNEL", "beta")
        listener = _make_listener()
        # Release channel is resolved at construction time
        hs = listener._build_handshake()
        assert hs["cli_release_channel"] == "beta"

    def test_handshake_includes_client_id(self):
        listener = _make_listener()
        hs = listener._build_handshake()
        assert "client_id" in hs
        assert hs["client_id"] == listener.client_id

    def test_handshake_providers_are_sorted(self):
        # Supply in reverse order — listener must sort them at construction.
        listener = _make_listener(providers=["ovh", "hetzner", "aws"])
        hs = listener._build_handshake()
        assert hs["providers_configured"] == sorted(hs["providers_configured"])


# ---------------------------------------------------------------------------
# _build_heartbeat
# ---------------------------------------------------------------------------

class TestBuildHeartbeat:
    def test_heartbeat_type(self):
        listener = _make_listener(providers=["aws"])
        hb = listener._build_heartbeat()
        assert hb["type"] == "cli.heartbeat"

    def test_heartbeat_providers_configured(self):
        listener = _make_listener(providers=["aws", "ovh"])
        hb = listener._build_heartbeat()
        assert hb["providers_configured"] == ["aws", "ovh"]

    def test_heartbeat_includes_client_id(self):
        listener = _make_listener()
        hb = listener._build_heartbeat()
        assert "client_id" in hb
        assert hb["client_id"] == listener.client_id

    def test_heartbeat_no_version_or_capabilities(self):
        """Heartbeat is minimal — no version/capabilities/release_channel."""
        listener = _make_listener()
        hb = listener._build_heartbeat()
        assert "version" not in hb
        assert "capabilities" not in hb
        assert "cli_release_channel" not in hb


# ---------------------------------------------------------------------------
# _heartbeat_loop sends handshake first, then heartbeat
# ---------------------------------------------------------------------------

class TestHeartbeatLoopPayloads:
    def test_first_post_is_handshake(self):
        """First iteration of _heartbeat_loop POSTs the handshake payload."""
        listener = _make_listener(providers=["aws"])

        posted_bodies: list = []

        async def run():
            listener._running = True
            import httpx

            async with httpx.AsyncClient() as client:
                listener._client = client
                # Patch authed_request to capture payloads and stop after 2 ticks
                call_count = 0

                async def patched_authed(method, url, **kwargs):
                    nonlocal call_count
                    posted_bodies.append(kwargs.get("json", {}))
                    call_count += 1
                    if call_count >= 2:
                        listener._running = False
                    resp = MagicMock()
                    resp.status_code = 200
                    return resp

                listener._authed_request = patched_authed
                listener._heartbeat_interval = 0
                await asyncio.wait_for(listener._heartbeat_loop(), timeout=3)

        asyncio.run(run())

        assert len(posted_bodies) >= 2
        # First payload must be the handshake
        assert posted_bodies[0]["type"] == "cli.handshake"
        assert posted_bodies[0]["capabilities"] == {"supports_dynamic_catalog": True}
        # Second payload must be the minimal heartbeat
        assert posted_bodies[1]["type"] == "cli.heartbeat"
        assert "capabilities" not in posted_bodies[1]
        assert "version" not in posted_bodies[1]

    def test_handshake_sent_flag(self):
        listener = _make_listener()
        assert listener._handshake_sent is False
        # After one build_handshake is called manually (simulating the loop)
        listener._build_handshake()
        # The flag itself isn't set by _build_handshake — it's set in the loop
        # but we can verify it starts False.
        assert listener._handshake_sent is False
