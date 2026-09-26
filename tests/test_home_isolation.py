"""The unit suite runs against a throwaway home and cannot write the real one."""
from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from . import _home_isolation


def _under(path: Path, root: Path) -> bool:
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
    except ValueError:
        return False
    return True


def test_home_is_the_session_throwaway_directory() -> None:
    isolation = _home_isolation.current()
    assert Path.home() == isolation.temp_home
    assert Path(os.path.expanduser("~")) == isolation.temp_home
    if isolation.real_home is not None:
        assert not _under(Path.home(), isolation.real_home)


def test_import_time_runtime_paths_resolve_inside_the_throwaway_home() -> None:
    from servonaut.config import manager
    from servonaut.services import auth_service, relay_lock, ssh_service
    from servonaut.services.cache_service import CacheService
    from servonaut.services.memory import store

    paths = [
        manager.CONFIG_DIR,
        manager.CONFIG_PATH,
        manager.BACKUP_DIR,
        auth_service.AUTH_FILE,
        relay_lock.DEFAULT_LOCK_PATH,
        ssh_service.PROVIDER_KEYS_DIR,
        CacheService.CACHE_PATH,
        store.MEMORY_ROOT,
    ]
    temp_home = _home_isolation.current().temp_home
    outside = [path for path in paths if not _under(path, temp_home)]
    assert outside == []


def test_guard_refuses_a_write_under_the_real_home() -> None:
    if not _home_isolation.is_armed():
        pytest.skip("no real home directory to guard")
    real_home = _home_isolation.current().real_home
    probe = real_home / f".servonaut-test-guard-probe-{uuid.uuid4().hex}"
    try:
        with _home_isolation.expect_refused_writes() as refused:
            with pytest.raises(PermissionError):
                probe.write_text("must not be written")
            with pytest.raises(PermissionError):
                probe.mkdir()
        assert not probe.exists()
        assert [event for event, _ in refused] == ["open", "os.mkdir"]
    finally:
        if probe.is_dir():
            probe.rmdir()
        elif probe.exists():
            probe.unlink()


def test_guard_allows_writes_to_temporary_directories(tmp_path) -> None:
    target = tmp_path / "allowed.txt"
    target.write_text("ok")
    assert target.read_text() == "ok"
