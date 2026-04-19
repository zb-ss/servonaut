"""Tests for ConfigManager local backup rotation and restore."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from servonaut.config import manager as manager_module
from servonaut.config.manager import ConfigManager, MAX_BACKUPS
from servonaut.config.schema import AppConfig


@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    """Redirect all config paths into tmp_path so tests don't touch ~/.servonaut/."""
    config_dir = tmp_path / "servonaut"
    config_path = config_dir / "config.json"
    backup_dir = config_dir / "backups"

    monkeypatch.setattr(manager_module, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(manager_module, "CONFIG_PATH", config_path)
    monkeypatch.setattr(manager_module, "BACKUP_DIR", backup_dir)
    # load_secrets_env might touch disk — stub it out
    monkeypatch.setattr(manager_module, "load_secrets_env", lambda *a, **kw: None)
    # Prevent legacy migration from running against real ~/.ec2_ssh_*
    monkeypatch.setattr(manager_module, "_migrate_legacy_paths", lambda: None)

    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir, config_path, backup_dir


class TestBackupCreation:
    def test_first_save_creates_no_backup(self, isolated_config):
        _, config_path, backup_dir = isolated_config
        cm = ConfigManager()
        cm.save(AppConfig(default_username="alice"))
        assert config_path.exists()
        # No backups on first save because there was nothing to back up
        assert not backup_dir.exists() or list(backup_dir.iterdir()) == []

    def test_second_save_creates_backup(self, isolated_config):
        _, config_path, backup_dir = isolated_config
        cm = ConfigManager()
        cm.save(AppConfig(default_username="alice"))
        cm.save(AppConfig(default_username="bob"))

        backups = list(backup_dir.glob("config-*.json"))
        assert len(backups) == 1
        # Backup contains the PRIOR state (alice), not the new one (bob)
        with open(backups[0]) as f:
            data = json.load(f)
        assert data["default_username"] == "alice"

        # Current file is the new one
        with open(config_path) as f:
            current = json.load(f)
        assert current["default_username"] == "bob"

    def test_backup_failure_does_not_block_save(self, isolated_config, monkeypatch):
        """If backup fails (e.g. disk full), save must still succeed."""
        _, config_path, _ = isolated_config
        cm = ConfigManager()
        cm.save(AppConfig(default_username="first"))

        # Force _create_backup to fail
        def raise_error(*_a, **_kw):
            raise OSError("simulated disk full")

        monkeypatch.setattr(manager_module.shutil, "copy2", raise_error)
        cm.save(AppConfig(default_username="second"))  # must not raise

        with open(config_path) as f:
            assert json.load(f)["default_username"] == "second"


class TestBackupRotation:
    def test_pruning_keeps_max_backups_most_recent(self, isolated_config):
        _, _, backup_dir = isolated_config
        cm = ConfigManager()
        # Prime with an initial save so there's something to back up
        cm.save(AppConfig(default_username="user-0"))
        for i in range(1, MAX_BACKUPS + 4):
            # A brief sleep ensures distinct timestamps
            time.sleep(0.01)
            cm.save(AppConfig(default_username=f"user-{i}"))

        backups = sorted(backup_dir.glob("config-*.json"))
        assert len(backups) == MAX_BACKUPS

    def test_list_backups_returns_newest_first(self, isolated_config):
        _, _, _ = isolated_config
        cm = ConfigManager()
        cm.save(AppConfig(default_username="oldest"))
        time.sleep(0.01)
        cm.save(AppConfig(default_username="middle"))
        time.sleep(0.01)
        cm.save(AppConfig(default_username="newest"))

        backups = cm.list_backups()
        assert len(backups) == 2  # first save doesn't produce a backup
        # Newest first means the "middle" save (which backed up "oldest") is older than "newest" save
        assert backups[0]["timestamp"] >= backups[1]["timestamp"]


class TestBackupRestore:
    def test_restore_applies_backup_and_backs_up_current(self, isolated_config):
        _, config_path, backup_dir = isolated_config
        cm = ConfigManager()
        cm.save(AppConfig(default_username="first"))
        time.sleep(0.01)
        cm.save(AppConfig(default_username="second"))

        backups = cm.list_backups()
        assert len(backups) == 1
        backup_path = backups[0]["path"]

        # Restore the "first" state
        restored = cm.restore_backup(backup_path)
        assert restored.default_username == "first"

        # config.json now matches the backup
        with open(config_path) as f:
            assert json.load(f)["default_username"] == "first"

        # And a NEW backup was created containing "second" (the pre-restore state),
        # so the restore is itself reversible.
        backups_after = cm.list_backups()
        assert len(backups_after) >= 2

    def test_restore_missing_file_raises(self, isolated_config):
        _, _, backup_dir = isolated_config
        cm = ConfigManager()
        cm.save(AppConfig())
        fake = backup_dir / "config-does-not-exist.json"
        with pytest.raises(FileNotFoundError):
            cm.restore_backup(fake)

    def test_restore_rejects_path_outside_backup_dir(self, isolated_config, tmp_path):
        cm = ConfigManager()
        cm.save(AppConfig())
        # Create a rogue file outside the backup dir
        rogue = tmp_path / "rogue.json"
        rogue.write_text(json.dumps({"version": 2}))
        with pytest.raises(ValueError, match="outside"):
            cm.restore_backup(rogue)
