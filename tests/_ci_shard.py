"""Pytest plugin that runs one deterministic slice of the collected tests.

Load it with ``-p tests._ci_shard`` and set ``SERVONAUT_TEST_SHARD=i/N``
(1-based). Each test lands in exactly one shard, chosen by a hash of its node
id, so every xdist worker collects the same set and the N shards together
cover the whole suite. Without the variable the plugin does nothing.
"""

from __future__ import annotations

import os
import zlib

import pytest

SHARD_ENV = "SERVONAUT_TEST_SHARD"


def parse_shard(value: str) -> tuple[int, int]:
    """Return ``(index, count)`` for ``"i/N"``, or raise ``pytest.UsageError``."""
    index_text, separator, count_text = value.partition("/")
    try:
        index, count = int(index_text), int(count_text)
    except ValueError:
        index = count = 0
    if not separator or count < 1 or not 1 <= index <= count:
        raise pytest.UsageError(f"{SHARD_ENV} must look like 'i/N' with 1 <= i <= N, got {value!r}")
    return index, count


def shard_of(node_id: str, count: int) -> int:
    """Zero-based shard that owns ``node_id``."""
    return zlib.crc32(node_id.encode()) % count


def pytest_collection_modifyitems(config, items) -> None:
    value = os.environ.get(SHARD_ENV)
    if value is None:
        return
    index, count = parse_shard(value)
    kept, dropped = [], []
    for item in items:
        (kept if shard_of(item.nodeid, count) == index - 1 else dropped).append(item)
    if dropped:
        config.hook.pytest_deselected(items=dropped)
    items[:] = kept
