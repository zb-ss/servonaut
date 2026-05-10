"""Tests for HetznerConfig dataclass + HetznerService token-resolution chain."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from servonaut.config.schema import AppConfig, HetznerConfig
from servonaut.services.hetzner_service import (
    HetznerNotConfiguredError,
    HetznerService,
)


class TestHetznerConfigDefaults:
    def test_disabled_by_default(self):
        cfg = HetznerConfig()
        assert cfg.enabled is False
        assert cfg.api_token == ""
        assert cfg.default_hetzner_ssh_key == ""
        assert cfg.default_local_ssh_key == ""
        assert cfg.default_username == "root"
        assert cfg.default_image == "ubuntu-22.04"
        # Pin the current canonical defaults. When Hetzner deprecates
        # ``cx23`` in fsn1 (every ~18 months), the same commit that
        # updates the schema default should also update this test —
        # a deliberate "loud failure" so the README/docs/demo script
        # stay in sync rather than silently drifting.
        assert cfg.default_server_type == "cx23"
        assert cfg.default_location == "fsn1"
        assert cfg.cache_ttl_seconds == 300
        assert cfg.require_ssh_keys_on_create is True

    def test_attached_to_appconfig(self):
        ac = AppConfig()
        assert isinstance(ac.hetzner, HetznerConfig)
        assert ac.hetzner.enabled is False

    def test_repr_redacts_api_token(self):
        cfg = HetznerConfig(api_token="super-secret-token-abc123")
        rendered = repr(cfg)
        assert "super-secret-token-abc123" not in rendered
        # Still informative: caller can tell whether the token IS set.
        assert "<set>" in rendered

    def test_repr_empty_token(self):
        cfg = HetznerConfig(api_token="")
        rendered = repr(cfg)
        assert "<set>" not in rendered
        assert "api_token=''" in rendered


class TestTokenResolution:
    """Token chain: config.api_token → $HCLOUD_TOKEN → ~/.config/hcloud/token."""

    def _make_service(self, **kwargs) -> HetznerService:
        return HetznerService(HetznerConfig(**kwargs))

    def test_config_token_wins_over_env(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HCLOUD_TOKEN", "envtoken")
        svc = self._make_service(api_token="config-tok")
        assert svc.resolve_token() == "config-tok"

    def test_env_token_used_when_config_empty(self, monkeypatch):
        monkeypatch.setenv("HCLOUD_TOKEN", "envtoken")
        svc = self._make_service(api_token="")
        assert svc.resolve_token() == "envtoken"

    def test_env_var_syntax_in_config(self, monkeypatch):
        monkeypatch.setenv("MY_TOKEN", "deref-target")
        svc = self._make_service(api_token="$MY_TOKEN")
        assert svc.resolve_token() == "deref-target"

    def test_file_syntax_in_config(self, tmp_path, monkeypatch):
        f = tmp_path / "tok"
        f.write_text("file-derived-token\n")
        monkeypatch.delenv("HCLOUD_TOKEN", raising=False)
        svc = self._make_service(api_token=f"file:{f}")
        assert svc.resolve_token() == "file-derived-token"

    def test_default_file_fallback(self, tmp_path, monkeypatch):
        # Redirect the default fallback path to a temp file.
        fake = tmp_path / "token"
        fake.write_text("disk-token\n")
        monkeypatch.setattr(
            "servonaut.services.hetzner_service._HCLOUD_DEFAULT_TOKEN_FILE",
            fake,
        )
        monkeypatch.delenv("HCLOUD_TOKEN", raising=False)
        svc = self._make_service(api_token="")
        assert svc.resolve_token() == "disk-token"

    def test_raises_when_nothing_configured(self, monkeypatch, tmp_path):
        monkeypatch.delenv("HCLOUD_TOKEN", raising=False)
        # Repoint default file to a non-existent path so the chain
        # cannot resolve anything.
        monkeypatch.setattr(
            "servonaut.services.hetzner_service._HCLOUD_DEFAULT_TOKEN_FILE",
            tmp_path / "absent",
        )
        svc = self._make_service(api_token="")
        with pytest.raises(HetznerNotConfiguredError):
            svc.resolve_token()
