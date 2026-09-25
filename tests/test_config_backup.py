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


class TestPreUpgradeBackupGrowth:
    def test_restoring_a_pre_upgrade_backup_does_not_copy_it_again(self, isolated_config):
        _, config_path, _ = isolated_config
        _write_raw_config(config_path, {"version": 4, "default_username": "carol"})
        cm = ConfigManager()
        cm.load()
        (upgrade,) = _upgrade_backups(cm)

        cm.restore_backup(upgrade["path"])  # re-migrates the restored v4 config

        assert [e["path"] for e in _upgrade_backups(cm)] == [upgrade["path"]]

    def test_failing_migration_leaves_config_and_backups_alone(self, isolated_config, monkeypatch):
        _, config_path, _ = isolated_config
        original = _write_raw_config(config_path, {"version": 4, "default_username": "carol"})

        def broken(_data):
            raise RuntimeError("simulated migration bug")

        monkeypatch.setattr(manager_module, "migrate_to_latest", broken)
        for _ in range(3):
            ConfigManager().load()

        assert config_path.read_bytes() == original
        assert len(_upgrade_backups(ConfigManager())) <= 1

    @pytest.mark.parametrize("version", ["abc", "5.0", 1, 0])
    def test_unrecognised_version_is_left_alone_with_a_warning(
        self, isolated_config, caplog, version
    ):
        _, config_path, _ = isolated_config
        original = _write_raw_config(config_path, {"version": version, "default_username": "carol"})

        for _ in range(3):
            caplog.clear()
            with caplog.at_level("INFO", logger=manager_module.logger.name):
                assert ConfigManager().load().default_username == "carol"
            messages = [r.getMessage() for r in caplog.records]
            assert not any("Migrating" in m for m in messages)
            assert sum("not a schema version" in m for m in messages) == 1

        assert config_path.read_bytes() == original
        assert _upgrade_backups(ConfigManager()) == []

    def test_string_version_migrates_once(self, isolated_config):
        _, config_path, _ = isolated_config
        _write_raw_config(config_path, {"version": "5", "default_username": "carol"})

        for _ in range(3):
            assert ConfigManager().load().default_username == "carol"

        assert json.loads(config_path.read_text())["version"] == manager_module.CONFIG_VERSION
        assert [e["from_version"] for e in _upgrade_backups(ConfigManager())] == [5]

    def test_only_the_newest_pre_upgrade_backups_are_kept(self, isolated_config):
        _, config_path, _ = isolated_config
        for i in range(manager_module.MAX_UPGRADE_BACKUPS + 2):
            time.sleep(0.01)
            _write_raw_config(config_path, {"version": 4, "default_username": f"user-{i}"})
            ConfigManager().load()

        kept = [
            json.loads(e["path"].read_text())["default_username"]
            for e in _upgrade_backups(ConfigManager())
        ]
        newest = manager_module.MAX_UPGRADE_BACKUPS + 1
        assert kept == [f"user-{i}" for i in range(newest, 1, -1)]


class TestConfigFilePermissions:
    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
    def test_readable_config_is_owner_only_after_load(self, isolated_config):
        _, config_path, _ = isolated_config
        _write_raw_config(config_path, {"version": 4, "default_username": "carol"})
        config_path.chmod(0o644)

        cm = ConfigManager()
        cm.load()

        assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
        (upgrade,) = _upgrade_backups(cm)
        assert stat.S_IMODE(upgrade["path"].stat().st_mode) == 0o600

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
    def test_current_readable_config_is_tightened_without_migrating(self, isolated_config):
        _, config_path, _ = isolated_config
        _write_raw_config(config_path, {"version": 6, "default_username": "carol"})
        config_path.chmod(0o664)

        ConfigManager().load()

        assert stat.S_IMODE(config_path.stat().st_mode) == 0o600

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
    def test_save_backups_are_owner_only_from_a_readable_config(self, isolated_config):
        _, config_path, _ = isolated_config
        _write_raw_config(config_path, {"version": 6})
        config_path.chmod(0o644)
        cm = ConfigManager()

        cm.save(AppConfig(default_username="next"))

        (entry,) = cm.list_backups()
        assert stat.S_IMODE(entry["path"].stat().st_mode) == 0o600

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
    def test_no_tightening_on_windows(self, isolated_config, monkeypatch):
        """Windows reports every file as 0o666; tightening would fail on each load."""
        _, config_path, _ = isolated_config
        _write_raw_config(config_path, {"version": 6})
        config_path.chmod(0o644)
        calls = []
        monkeypatch.setattr(manager_module.os, "fchmod", lambda *a: calls.append(a), raising=False)

        with monkeypatch.context() as windows:
            windows.setattr(manager_module.os, "name", "nt")
            manager_module._restrict_to_owner(config_path)

        assert calls == []
        assert stat.S_IMODE(config_path.stat().st_mode) == 0o644

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
    def test_symlinked_config_is_not_chmodded(self, isolated_config, tmp_path):
        _, config_path, _ = isolated_config
        target = tmp_path / "shared-config.json"
        target.write_text(json.dumps({"version": 6, "default_username": "carol"}))
        target.chmod(0o644)
        config_path.symlink_to(target)

        assert ConfigManager().load().default_username == "carol"

        assert stat.S_IMODE(target.stat().st_mode) == 0o644


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
    def test_readable_legacy_backup_is_narrowed_to_owner_on_load(self, isolated_config):
        config_dir, config_path, _ = isolated_config
        _write_raw_config(config_path, {"version": 6})
        legacy = config_dir / "config.v1.bak.20260101_120000"
        legacy.write_text(json.dumps({"version": 3}))
        legacy.chmod(0o664)

        ConfigManager().list_backups()
        assert stat.S_IMODE(legacy.stat().st_mode) == 0o664  # listing changes nothing

        ConfigManager().load()
        assert stat.S_IMODE(legacy.stat().st_mode) == 0o600

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
    def test_symlinked_legacy_backup_is_ignored_and_never_chmodded(
        self, isolated_config, tmp_path
    ):
        config_dir, config_path, _ = isolated_config
        _write_raw_config(config_path, {"version": 6})
        target = tmp_path / "elsewhere.json"
        target.write_text(json.dumps({"version": 3}))
        target.chmod(0o644)
        link = config_dir / "config.v1.bak.20260101_120000"
        link.symlink_to(target)

        cm = ConfigManager()
        cm.load()

        assert cm.list_backups() == []
        assert stat.S_IMODE(target.stat().st_mode) == 0o644
        with pytest.raises(ValueError, match="outside"):
            cm.restore_backup(link)

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

    def test_structurally_invalid_backup_is_refused(self, isolated_config):
        _, config_path, _ = isolated_config
        cm = ConfigManager()
        cm.save(AppConfig(default_username="first"))
        cm.save(AppConfig(default_username="second"))
        (entry,) = cm.list_backups()
        entry["path"].write_text(json.dumps({"version": 6, "custom_servers": "oops"}))

        with pytest.raises(ValueError, match="not a valid config"):
            cm.restore_backup(entry["path"])

        assert json.loads(config_path.read_text())["default_username"] == "second"

    def test_backup_with_a_byte_order_mark_is_refused(self, isolated_config):
        """load() reads config.json as plain text, where a BOM is invalid JSON."""
        _, config_path, _ = isolated_config
        cm = ConfigManager()
        cm.save(AppConfig(default_username="first"))
        cm.save(AppConfig(default_username="second"))
        (entry,) = cm.list_backups()
        entry["path"].write_bytes(
            b"\xef\xbb\xbf" + json.dumps({"version": 6, "default_username": "bom"}).encode()
        )

        with pytest.raises(ValueError, match="not a valid config"):
            cm.restore_backup(entry["path"])

        assert json.loads(config_path.read_text())["default_username"] == "second"

    def test_failed_restore_write_keeps_the_chosen_backup(self, isolated_config, monkeypatch):
        _, config_path, _ = isolated_config
        cm = ConfigManager()
        for i in range(MAX_BACKUPS + 1):
            time.sleep(0.01)
            cm.save(AppConfig(default_username=f"user-{i}"))
        oldest = cm.list_backups()[-1]["path"]
        real_write = manager_module._write_bytes_secure

        def disk_full_for_config(target, payload):
            if Path(target) == config_path:
                raise OSError("simulated disk full")
            real_write(target, payload)

        monkeypatch.setattr(manager_module, "_write_bytes_secure", disk_full_for_config)
        with pytest.raises(OSError, match="disk full"):
            cm.restore_backup(oldest)

        assert oldest.exists()
        assert json.loads(oldest.read_text())["default_username"] == "user-0"

    @pytest.mark.skipif(
        os.name == "nt" or getattr(os, "geteuid", lambda: 1)() == 0,
        reason="needs POSIX permissions enforced for a non-root user",
    )
    def test_restore_aborts_when_the_current_config_cannot_be_backed_up(
        self, isolated_config
    ):
        _, config_path, backup_dir = isolated_config
        cm = ConfigManager()
        cm.save(AppConfig(default_username="first"))
        cm.save(AppConfig(default_username="second"))
        (entry,) = cm.list_backups()
        before = config_path.read_bytes()

        backup_dir.chmod(0o500)  # listable, but no new snapshot can be written
        try:
            with pytest.raises(OSError, match="nothing was changed"):
                cm.restore_backup(entry["path"])
        finally:
            backup_dir.chmod(0o700)

        assert config_path.read_bytes() == before

    def test_restoring_the_oldest_backup_when_the_rotation_is_full(self, isolated_config):
        _, config_path, _ = isolated_config
        cm = ConfigManager()
        for i in range(MAX_BACKUPS + 1):
            time.sleep(0.01)
            cm.save(AppConfig(default_username=f"user-{i}"))
        backups = cm.list_backups()
        assert len(backups) == MAX_BACKUPS
        oldest = backups[-1]

        restored = cm.restore_backup(oldest["path"])

        assert restored.default_username == "user-0"
        assert json.loads(config_path.read_text())["default_username"] == "user-0"

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
    def test_symlinked_save_backup_is_not_listed_or_restorable(
        self, isolated_config, tmp_path
    ):
        _, _, backup_dir = isolated_config
        cm = ConfigManager()
        cm.save(AppConfig(default_username="first"))
        cm.save(AppConfig(default_username="second"))
        target = tmp_path / "outside.json"
        target.write_text(json.dumps({"version": 6, "default_username": "mallory"}))
        link = backup_dir / "config-20990101T000000.json"
        link.symlink_to(target)

        assert link not in [e["path"] for e in cm.list_backups()]
        with pytest.raises(ValueError, match="outside"):
            cm.restore_backup(link)

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

    def test_structurally_invalid_backup_exits_nonzero(self, two_backups, monkeypatch, capsys):
        _no_prompt(monkeypatch)
        newest = ConfigManager().list_backups()[0]["path"]
        newest.write_text(json.dumps({"version": 6, "custom_servers": "oops"}))
        before = two_backups.read_bytes()

        code = _run_cli(monkeypatch, "--restore-backup", "1")

        assert code == 1
        assert "Restore failed" in capsys.readouterr().err
        assert two_backups.read_bytes() == before

    def test_config_flag_selects_the_config_to_restore(
        self, isolated_config, monkeypatch, capsys, tmp_path
    ):
        _no_prompt(monkeypatch)
        _, default_config, _ = isolated_config
        _write_raw_config(default_config, {"version": 6, "default_username": "default"})
        alt = tmp_path / "alt" / "recording.json"
        alt.parent.mkdir()
        _write_raw_config(alt, {"version": 6, "default_username": "alt-now"})
        legacy = alt.parent / "recording.v1.bak.20260101_120000"
        legacy.write_text(json.dumps({"version": 6, "default_username": "alt-before"}))

        assert _run_cli(monkeypatch, "--config", str(alt), "--list-backups") == 0
        assert str(legacy) in capsys.readouterr().out

        assert _run_cli(monkeypatch, "--config", str(alt), "--restore-backup", "1") == 0
        assert json.loads(alt.read_text())["default_username"] == "alt-before"
        assert json.loads(default_config.read_text())["default_username"] == "default"

    def test_help_documents_the_exit_codes(self, monkeypatch, capsys):
        assert _run_cli(monkeypatch, "--help") == 0
        help_text = " ".join(capsys.readouterr().out.split())
        for code in ("0 restored", "1 nothing restored", "2 bad argument", "130 interrupted"):
            assert code in help_text

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


class TestBackupLocation:
    """Backups belong to the config file a manager was built for."""

    @staticmethod
    def _seed_default_backups(backup_dir: Path, count: int) -> dict:
        backup_dir.mkdir(parents=True, exist_ok=True)
        seeded = {}
        for index in range(count):
            path = backup_dir / f"config-20200101T00000{index}.json"
            path.write_text(json.dumps({"version": 2, "default_username": f"real-{index}"}))
            seeded[path.name] = path.read_text()
        return seeded

    def test_default_manager_keeps_backups_in_the_default_directory(self, isolated_config):
        config_dir, _, backup_dir = isolated_config
        assert ConfigManager()._backup_dir() == backup_dir == config_dir / "backups"

    def test_custom_config_writes_lists_and_prunes_only_its_own_backups(
        self, isolated_config, tmp_path
    ):
        _, default_config_path, default_backup_dir = isolated_config
        # More than MAX_BACKUPS, so a prune of the wrong directory would show.
        seeded = self._seed_default_backups(default_backup_dir, MAX_BACKUPS + 2)
        custom_path = tmp_path / "elsewhere" / "recording.json"

        cm = ConfigManager(config_path=custom_path)
        assert cm._backup_dir() == custom_path.parent / "backups"
        cm.save(AppConfig(default_username="user-0"))
        for index in range(1, MAX_BACKUPS + 4):
            time.sleep(0.01)
            cm.save(AppConfig(default_username=f"user-{index}"))

        custom_backups = sorted(cm._backup_dir().glob("config-*.json"))
        assert len(custom_backups) == MAX_BACKUPS
        listed = cm.list_backups()
        assert {entry["path"] for entry in listed} == set(custom_backups)
        assert all(entry["path"].parent == cm._backup_dir() for entry in listed)

        # The default config's backups are neither added to nor pruned.
        remaining = {path.name: path.read_text() for path in default_backup_dir.iterdir()}
        assert remaining == seeded
        assert not default_config_path.exists()

    def test_custom_config_restores_only_from_its_own_backups(
        self, isolated_config, tmp_path
    ):
        _, _, default_backup_dir = isolated_config
        seeded = self._seed_default_backups(default_backup_dir, 1)
        cm = ConfigManager(config_path=tmp_path / "elsewhere" / "recording.json")
        cm.save(AppConfig(default_username="first"))
        time.sleep(0.01)
        cm.save(AppConfig(default_username="second"))

        foreign = default_backup_dir / next(iter(seeded))
        with pytest.raises(ValueError, match="outside"):
            cm.restore_backup(foreign)

        own = cm.list_backups()[0]["path"]
        assert cm.restore_backup(own).default_username == "first"
