"""Tests for home-relative config path normalisation (tildify)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from servonaut.config import paths as config_paths
from servonaut.config.manager import ConfigManager
from servonaut.config.paths import normalize_config_paths, tildify
from servonaut.config.schema import (
    AppConfig,
    ConnectionProfile,
    CustomServer,
)


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """Pin ``Path.home()`` to a temp dir for deterministic tildify tests."""
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    monkeypatch.setattr(config_paths.Path, "home", classmethod(lambda cls: home))
    return home


class TestTildify:
    def test_collapses_path_under_home(self, fake_home):
        abs_path = str(fake_home / ".ssh" / "id_rsa")
        assert tildify(abs_path) == "~/.ssh/id_rsa"

    def test_leaves_already_tilde_unchanged(self, fake_home):
        assert tildify("~/.ssh/id_rsa") == "~/.ssh/id_rsa"

    def test_leaves_env_var_unchanged(self, fake_home):
        assert tildify("$HOME/.ssh/id_rsa") == "$HOME/.ssh/id_rsa"

    def test_leaves_file_ref_unchanged(self, fake_home):
        assert tildify("file:/run/secrets/key") == "file:/run/secrets/key"

    def test_leaves_path_outside_home_absolute(self, fake_home):
        assert tildify("/etc/ssh/keys/foo") == "/etc/ssh/keys/foo"

    def test_empty_string_unchanged(self, fake_home):
        assert tildify("") == ""

    def test_home_root_itself(self, fake_home):
        assert tildify(str(fake_home)) == "~"

    def test_windows_style_path_uses_forward_slashes(self, monkeypatch):
        """A Windows home path must serialise with forward slashes."""
        win_home = "C:/Users/alice"
        monkeypatch.setattr(
            config_paths.Path, "home", classmethod(lambda cls: Path(win_home))
        )
        # PurePosixPath stand-in: on a POSIX test host, Path is PosixPath, so a
        # value like "C:/Users/alice/.ssh/id_rsa" is treated as a normal path
        # under the (also POSIX-rendered) home and collapses with "/" output.
        result = tildify("C:/Users/alice/.ssh/id_rsa")
        assert result == "~/.ssh/id_rsa"
        assert "\\" not in result

    def test_home_unresolvable_returns_original(self, monkeypatch):
        def _boom(cls):
            raise OSError("no home")

        monkeypatch.setattr(config_paths.Path, "home", classmethod(_boom))
        assert tildify("/some/abs/path") == "/some/abs/path"


class TestNormalizeConfigPaths:
    def test_normalizes_all_user_path_fields(self, fake_home):
        key = str(fake_home / ".ssh" / "id_rsa")
        bastion = str(fake_home / ".ssh" / "bastion")
        custom = str(fake_home / "keys" / "srv")
        data = {
            "default_key": key,
            "instance_keys": {"i-abc": key, "i-def": "/etc/ssh/x"},
            "connection_profiles": [{"name": "p", "bastion_key": bastion}],
            "custom_servers": [{"name": "s", "ssh_key": custom}],
            "hetzner": {"default_local_ssh_key": key, "default_hetzner_ssh_key": "my-hz-key"},
            "ovh": {"default_ssh_key": key},
        }
        normalize_config_paths(data)

        assert data["default_key"] == "~/.ssh/id_rsa"
        assert data["instance_keys"]["i-abc"] == "~/.ssh/id_rsa"
        assert data["instance_keys"]["i-def"] == "/etc/ssh/x"  # outside home
        assert data["connection_profiles"][0]["bastion_key"] == "~/.ssh/bastion"
        assert data["custom_servers"][0]["ssh_key"] == "~/keys/srv"
        assert data["hetzner"]["default_local_ssh_key"] == "~/.ssh/id_rsa"
        # Hetzner-side identifier must NOT be touched.
        assert data["hetzner"]["default_hetzner_ssh_key"] == "my-hz-key"
        assert data["ovh"]["default_ssh_key"] == "~/.ssh/id_rsa"

    def test_tolerates_missing_and_malformed_sections(self, fake_home):
        # Should not raise on empty / wrong-typed sections.
        normalize_config_paths({})
        normalize_config_paths({"connection_profiles": None, "custom_servers": None})
        normalize_config_paths({"default_key": None})
        normalize_config_paths({"instance_keys": "not-a-dict"})


class TestSaveIntegration:
    def test_save_writes_tildified_paths(self, tmp_path, fake_home):
        manager = ConfigManager()
        manager._config_path = tmp_path / "config.json"

        key = str(fake_home / ".ssh" / "id_rsa")
        config = AppConfig(
            default_key=key,
            connection_profiles=[ConnectionProfile(name="p", bastion_key=key)],
            custom_servers=[CustomServer(name="s", host="h", ssh_key=key)],
        )
        manager.save(config)

        on_disk = json.loads((tmp_path / "config.json").read_text())
        assert on_disk["default_key"] == "~/.ssh/id_rsa"
        assert on_disk["connection_profiles"][0]["bastion_key"] == "~/.ssh/id_rsa"
        assert on_disk["custom_servers"][0]["ssh_key"] == "~/.ssh/id_rsa"
