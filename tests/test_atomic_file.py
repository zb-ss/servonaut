"""Atomic JSON writes, and the instance caches that use them."""
from __future__ import annotations

import json
import os
import stat
import threading
from pathlib import Path

import pytest

from servonaut.config.schema import HetznerConfig, OVHConfig
from servonaut.services.cache_service import CacheService
from servonaut.services.hetzner_service import HetznerService
from servonaut.services.ovh_service import OVHService
from servonaut.utils.atomic_file import write_json_atomic


def _leftovers(directory: Path, target: Path) -> list:
    return [p.name for p in directory.iterdir() if p != target]


def test_writes_the_json_owner_only_and_leaves_nothing_behind(tmp_path):
    target = tmp_path / "sub" / "cache.json"

    write_json_atomic(target, {"instances": [1, 2]})

    assert json.loads(target.read_text()) == {"instances": [1, 2]}
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    assert _leftovers(target.parent, target) == []


def test_a_failed_write_keeps_the_previous_file(tmp_path):
    target = tmp_path / "cache.json"
    write_json_atomic(target, {"v": 1})

    with pytest.raises(TypeError):
        write_json_atomic(target, {"v": object()})

    assert json.loads(target.read_text()) == {"v": 1}
    assert _leftovers(tmp_path, target) == []


@pytest.mark.skipif(os.name == "nt", reason="creating a symlink needs extra rights on Windows")
def test_an_existing_link_at_the_target_is_replaced_not_followed(tmp_path):
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text("keep")
    target = tmp_path / "cache.json"
    target.symlink_to(elsewhere)

    write_json_atomic(target, {"v": 1})

    assert elsewhere.read_text() == "keep"
    assert not target.is_symlink() and json.loads(target.read_text()) == {"v": 1}


def _savers(tmp_path):
    """Each cache's save and load, as two processes sharing it would call them."""
    aws_path = tmp_path / "cache.json"
    hetzner_config = HetznerConfig(enabled=True, api_token="t",
                                   cache_path=str(tmp_path / "hetzner_cache.json"))
    ovh_path = tmp_path / "ovh_cache.json"
    return {
        "aws": (
            lambda rows: CacheService(cache_path=aws_path).save(rows),
            lambda: CacheService(cache_path=aws_path).load_any(),
        ),
        "hetzner": (
            lambda rows: HetznerService(hetzner_config)._save_cache(rows),
            lambda: HetznerService(hetzner_config)._load_cache(ignore_ttl=True),
        ),
        "ovh": (
            lambda rows: OVHService(OVHConfig(), cache_path=ovh_path)._save_cache(rows),
            lambda: OVHService(OVHConfig(), cache_path=ovh_path)._load_cache(ignore_ttl=True),
        ),
    }


@pytest.mark.parametrize("provider", ["aws", "hetzner", "ovh"])
def test_concurrent_cache_saves_never_tear_the_file(tmp_path, provider):
    save, load = _savers(tmp_path)[provider]
    payloads = [[{"id": f"{writer}-{n}", "name": "x" * 2000} for n in range(50)]
                for writer in range(4)]
    save(payloads[0])
    stop = threading.Event()
    torn = []

    def read():
        while not stop.is_set():
            rows = load()
            if rows is None or rows not in payloads:
                torn.append(rows)

    def write(rows):
        for _ in range(25):
            save(rows)

    reader = threading.Thread(target=read)
    writers = [threading.Thread(target=write, args=(rows,)) for rows in payloads]
    reader.start()
    for thread in writers:
        thread.start()
    for thread in writers:
        thread.join()
    stop.set()
    reader.join()

    assert torn == []
    assert load() in payloads
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []
