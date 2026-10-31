"""The sync service's pin store waits as long as the memory settings say."""
from __future__ import annotations

from servonaut.config.schema import MemoryConfig
from tests.test_memory_sync_service import _make_config_manager, _make_service


def test_the_pin_store_uses_the_configured_record_lock_wait(tmp_path):
    cfg = _make_config_manager()
    cfg.get.return_value.memory = MemoryConfig(
        record_lock_timeout_seconds=0.07, record_lock_poll_seconds=0.011
    )
    svc = _make_service(config_manager=cfg, tmp_path=tmp_path)
    assert svc._pin_store()._wait() == (0.07, 0.011)


def test_an_unusable_setting_falls_back_to_the_default_wait(tmp_path):
    svc = _make_service(config_manager=_make_config_manager(), tmp_path=tmp_path)
    assert svc._pin_store()._wait() == MemoryConfig().record_lock_wait()
