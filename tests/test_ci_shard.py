"""The CI shard plugin splits the suite into disjoint, complete slices."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tests import _ci_shard


class _Hook:
    def __init__(self) -> None:
        self.deselected: list = []

    def pytest_deselected(self, items) -> None:
        self.deselected.extend(items)


def _config() -> SimpleNamespace:
    return SimpleNamespace(hook=_Hook())


def _items(total: int = 200) -> list:
    return [SimpleNamespace(nodeid=f"tests/test_sample.py::test_case[{n}]") for n in range(total)]


def _run(monkeypatch, value: str | None, items: list) -> tuple[list, _Hook]:
    if value is None:
        monkeypatch.delenv(_ci_shard.SHARD_ENV, raising=False)
    else:
        monkeypatch.setenv(_ci_shard.SHARD_ENV, value)
    config = _config()
    _ci_shard.pytest_collection_modifyitems(config, items)
    return items, config.hook


def test_four_shards_are_disjoint_and_complete(monkeypatch) -> None:
    everything = {item.nodeid for item in _items()}
    seen: list[str] = []
    for index in range(1, 5):
        kept, hook = _run(monkeypatch, f"{index}/4", _items())
        assert kept, "every shard should receive some tests"
        assert len(kept) + len(hook.deselected) == len(everything)
        seen.extend(item.nodeid for item in kept)
    assert len(seen) == len(set(seen))
    assert set(seen) == everything


def test_assignment_is_deterministic(monkeypatch) -> None:
    first, _ = _run(monkeypatch, "2/4", _items())
    second, _ = _run(monkeypatch, "2/4", _items())
    assert [item.nodeid for item in first] == [item.nodeid for item in second]


def test_unset_keeps_everything(monkeypatch) -> None:
    kept, hook = _run(monkeypatch, None, _items())
    assert len(kept) == 200
    assert hook.deselected == []


@pytest.mark.parametrize("value", ["", "3", "a/4", "1/b", "0/4", "5/4", "1/0", "-1/4", "1/-4"])
def test_malformed_value_is_a_usage_error(monkeypatch, value: str) -> None:
    with pytest.raises(pytest.UsageError):
        _run(monkeypatch, value, _items())
