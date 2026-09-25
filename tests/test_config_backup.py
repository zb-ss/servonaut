"""Tests for ConfigManager local backup rotation and restore."""
from __future__ import annotations

import json
import os
import stat
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
        """If backup fails (e.g. unwritable backup dir), save must still succeed."""
        config_dir, config_path, _ = isolated_config
        cm = ConfigManager()
        cm.save(AppConfig(default_username="first"))

        # A regular file where the backups directory should be makes every
        # backup write fail with an OSError.
        blocked = config_dir / "not-a-directory"
        blocked.write_text("")
        monkeypatch.setattr(manager_module, "BACKUP_DIR", blocked)
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


# ---------------------------------------------------------------------------
# Pre-upgrade backups: the copy taken before a schema migration
# ---------------------------------------------------------------------------


def _write_raw_config(config_path: Path, data: dict) -> bytes:
    payload = json.dumps(data).encode("utf-8")
    config_path.write_bytes(payload)
    return payload


def _upgrade_backups(cm: ConfigManager) -> list:
    return [entry for entry in cm.list_backups() if entry["kind"] == "pre-upgrade"]


class TestPreUpgradeBackup:
    def test_migration_backup_is_listed_and_named_by_source_schema(self, isolated_config):
        _, config_path, backup_dir = isolated_config
        original = _write_raw_config(config_path, {"version": 4, "default_username": "carol"})

        ConfigManager().load()

        backups = _upgrade_backups(ConfigManager())
        assert len(backups) == 1
        entry = backups[0]
        assert entry["from_version"] == 4
        assert entry["path"].parent == backup_dir
        assert entry["path"].name.startswith("pre-upgrade-v4-")
        assert entry["path"].name.endswith(".json")
        assert entry["path"].read_bytes() == original
        # Nothing is left behind next to config.json any more.
        assert list(config_path.parent.glob("config.v*.bak.*")) == []

    def test_config_without_version_is_backed_up_as_v1(self, isolated_config):
        _, config_path, _ = isolated_config
        _write_raw_config(config_path, {"default_username": "legacy"})

        ConfigManager().load()

        backups = _upgrade_backups(ConfigManager())
        assert [entry["from_version"] for entry in backups] == [1]
        assert backups[0]["path"].name.startswith("pre-upgrade-v1-")

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
    def test_migration_backup_is_owner_only_even_from_a_readable_config(self, isolated_config):
        _, config_path, _ = isolated_config
        _write_raw_config(config_path, {"version": 3})
        config_path.chmod(0o644)

        ConfigManager().load()

        (entry,) = _upgrade_backups(ConfigManager())
        assert stat.S_IMODE(entry["path"].stat().st_mode) == 0o600

    def test_migration_backup_survives_save_rotation(self, isolated_config):
        _, config_path, _ = isolated_config
        _write_raw_config(config_path, {"version": 4, "default_username": "carol"})
        cm = ConfigManager()
        cm.load()

        for i in range(MAX_BACKUPS + 2):
            time.sleep(0.01)
            cm.save(AppConfig(default_username=f"user-{i}"))

        backups = cm.list_backups()
        assert len([e for e in backups if e["kind"] == "save"]) == MAX_BACKUPS
        (upgrade,) = [e for e in backups if e["kind"] == "pre-upgrade"]
        assert json.loads(upgrade["path"].read_text())["default_username"] == "carol"

    def test_pre_upgrade_backup_can_be_restored(self, isolated_config):
        _, config_path, _ = isolated_config
        _write_raw_config(config_path, {"version": 4, "default_username": "carol"})
        cm = ConfigManager()
        cm.load()
        cm.save(AppConfig(default_username="changed-after-upgrade"))

        (upgrade,) = _upgrade_backups(cm)
        restored = cm.restore_backup(upgrade["path"])

        assert restored.default_username == "carol"


class TestLegacyPreUpgradeBackups:
    """Older releases wrote ``config.v1.bak.<stamp>`` beside config.json."""

    def test_legacy_backup_is_listed_with_its_real_schema(self, isolated_config):
        config_dir, config_path, _ = isolated_config
        _write_raw_config(config_path, {"version": 6})
        legacy = config_dir / "config.v1.bak.20260101_120000"
        legacy.write_text(json.dumps({"version": 3, "default_username": "dave"}))

        backups = _upgrade_backups(ConfigManager())

        assert [entry["path"] for entry in backups] == [legacy]
        assert backups[0]["from_version"] == 3

    def test_legacy_backup_can_be_restored(self, isolated_config):
        config_dir, config_path, _ = isolated_config
        ConfigManager().save(AppConfig(default_username="current"))
        legacy = config_dir / "config.v1.bak.20260101_120000"
        legacy.write_text(json.dumps({"version": 3, "default_username": "dave"}))

        restored = ConfigManager().restore_backup(legacy)

        assert restored.default_username == "dave"

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
    def test_readable_legacy_backup_is_narrowed_to_owner(self, isolated_config):
        config_dir, _, _ = isolated_config
        legacy = config_dir / "config.v1.bak.20260101_120000"
        legacy.write_text(json.dumps({"version": 3}))
        legacy.chmod(0o664)

        ConfigManager().list_backups()

        assert stat.S_IMODE(legacy.stat().st_mode) == 0o600

    def test_other_files_beside_config_are_not_restorable(self, isolated_config):
        config_dir, _, _ = isolated_config
        ConfigManager().save(AppConfig())
        other = config_dir / "cache.json"
        other.write_text(json.dumps({"version": 6}))

        with pytest.raises(ValueError, match="outside"):
            ConfigManager().restore_backup(other)


class TestRestoreValidation:
    def test_corrupt_backup_is_refused_and_config_kept(self, isolated_config):
        _, config_path, _ = isolated_config
        cm = ConfigManager()
        cm.save(AppConfig(default_username="first"))
        cm.save(AppConfig(default_username="second"))
        (entry,) = cm.list_backups()
        entry["path"].write_text("{not json")

        with pytest.raises(ValueError, match="not a valid config"):
            cm.restore_backup(entry["path"])

        assert json.loads(config_path.read_text())["default_username"] == "second"

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
    def test_restored_config_is_owner_only(self, isolated_config):
        _, config_path, _ = isolated_config
        cm = ConfigManager()
        cm.save(AppConfig(default_username="first"))
        cm.save(AppConfig(default_username="second"))
        (entry,) = cm.list_backups()
        entry["path"].chmod(0o644)

        cm.restore_backup(entry["path"])

        assert stat.S_IMODE(config_path.stat().st_mode) == 0o600


# ---------------------------------------------------------------------------
# CLI: --list-backups / --restore-backup
# ---------------------------------------------------------------------------


def _run_cli(monkeypatch, *argv: str) -> int:
    """Run the servonaut CLI in-process; return its exit code."""
    import servonaut.main as main_mod

    monkeypatch.setattr(main_mod, "_prune_empty_env", lambda: None)
    monkeypatch.setattr(main_mod.sys, "argv", ["servonaut", *argv])
    try:
        main_mod._main()
    except SystemExit as exc:
        return 0 if exc.code is None else exc.code
    return 0


def _no_prompt(monkeypatch) -> None:
    def fail(*_a, **_kw):
        raise AssertionError("the CLI must not prompt here")

    monkeypatch.setattr("builtins.input", fail)


@pytest.fixture
def two_backups(isolated_config):
    _, config_path, _ = isolated_config
    cm = ConfigManager()
    cm.save(AppConfig(default_username="first"))
    time.sleep(0.01)
    cm.save(AppConfig(default_username="second"))
    time.sleep(0.01)
    cm.save(AppConfig(default_username="third"))
    return config_path


class TestRestoreBackupCli:
    def test_unknown_number_is_an_error(self, two_backups, monkeypatch, capsys):
        _no_prompt(monkeypatch)
        before = two_backups.read_bytes()

        code = _run_cli(monkeypatch, "--restore-backup", "9")

        assert code == 1
        err = capsys.readouterr().err
        assert "No backup #9" in err
        assert "--list-backups" in err
        assert two_backups.read_bytes() == before

    @pytest.mark.parametrize("number", ["0", "-1", "-5"])
    def test_non_positive_number_is_rejected(self, two_backups, monkeypatch, capsys, number):
        _no_prompt(monkeypatch)
        before = two_backups.read_bytes()

        code = _run_cli(monkeypatch, "--restore-backup", number)

        assert code != 0
        assert "--restore-backup" in capsys.readouterr().err
        assert two_backups.read_bytes() == before

    def test_no_backups_is_an_error(self, isolated_config, monkeypatch, capsys):
        _no_prompt(monkeypatch)

        code = _run_cli(monkeypatch, "--restore-backup", "1")

        assert code == 1
        assert "No local backups" in capsys.readouterr().err

    def test_valid_number_restores_and_exits_zero(self, two_backups, monkeypatch, capsys):
        _no_prompt(monkeypatch)

        code = _run_cli(monkeypatch, "--restore-backup", "2")

        assert code == 0
        assert "Restored from" in capsys.readouterr().out
        assert json.loads(two_backups.read_text())["default_username"] == "first"

    def test_failed_restore_is_an_error(self, two_backups, monkeypatch, capsys):
        _no_prompt(monkeypatch)
        newest = ConfigManager().list_backups()[0]["path"]
        newest.write_text("{not json")

        code = _run_cli(monkeypatch, "--restore-backup", "1")

        assert code == 1
        assert "Restore failed" in capsys.readouterr().err

    @pytest.mark.parametrize(
        ("answer", "message"),
        [("9", "No backup #9"), ("0", "No backup #0"), ("-1", "No backup #-1"),
         ("two", "Invalid choice 'two'")],
    )
    def test_interactive_invalid_choice_is_an_error(
        self, two_backups, monkeypatch, capsys, answer, message
    ):
        monkeypatch.setattr("builtins.input", lambda *_a: answer)
        before = two_backups.read_bytes()

        code = _run_cli(monkeypatch, "--restore-backup")

        assert code == 1
        assert message in capsys.readouterr().err
        assert two_backups.read_bytes() == before

    @pytest.mark.parametrize("error", [None, EOFError])
    def test_interactive_cancel_restores_nothing_and_exits_nonzero(
        self, two_backups, monkeypatch, capsys, error
    ):
        def answer(*_a):
            if error is not None:
                raise error()
            return ""

        monkeypatch.setattr("builtins.input", answer)
        before = two_backups.read_bytes()

        code = _run_cli(monkeypatch, "--restore-backup")

        assert code == 1
        assert "Cancelled" in capsys.readouterr().err
        assert two_backups.read_bytes() == before

    def test_interactive_valid_choice_restores(self, two_backups, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda *_a: "2")

        code = _run_cli(monkeypatch, "--restore-backup")

        assert code == 0
        assert json.loads(two_backups.read_text())["default_username"] == "first"


class TestPreUpgradeBackupCli:
    def test_pre_upgrade_backup_is_listed_and_restorable_from_the_cli(
        self, isolated_config, monkeypatch, capsys
    ):
        _no_prompt(monkeypatch)
        _, config_path, _ = isolated_config
        _write_raw_config(config_path, {"version": 4, "default_username": "carol"})
        cm = ConfigManager()
        cm.load()
        cm.save(AppConfig(default_username="changed-after-upgrade"))

        assert _run_cli(monkeypatch, "--list-backups") == 0
        listing = capsys.readouterr().out
        rows = [line for line in listing.splitlines() if "pre-upgrade" in line]
        assert len(rows) == 1
        assert "v4" in rows[0]
        number = rows[0].split()[0]

        assert _run_cli(monkeypatch, "--restore-backup", number) == 0
        assert ConfigManager().load().default_username == "carol"
