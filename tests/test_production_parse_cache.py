"""Production stylesheet sharing preserves theme values and upstream contracts."""

from __future__ import annotations

import ast
import hashlib
import inspect
import textwrap
from pathlib import Path
from typing import Any

import pytest
from textual.app import App, ComposeResult
from textual.cache import LRUCache
from textual.color import Color
from textual.css.model import RuleSet
from textual.css.stylesheet import Stylesheet
from textual.theme import Theme
from textual.widgets import Static

from servonaut.styles import parse_cache as cache


# Reviewed Textual 8.2.8 source: re-check sharing/mutation/invalidation on change.
_UPSTREAM = {
    "__init__": "2a823efb65d42db8dbeaa7fbcf2d0a03e1d87552dc0ee95098653ee4d0071adc",
    "set_variables": "6f370c03ccdae2ea1806b37ef59785417ab19f187914a2d93d5fb524f2323ae1",
    "parse": "ce97f77200610da568fb9608a0f2c5c785d9395051f81253fa1c4c12f5701752",
    "reparse": "d84aac4b3e199dd5f904cf65406f9f30e87382ad93b74982a73fecfe8943e795",
    "apply": "f5f6f297e1c7cd0fad97c4a4fbe0cd9393c1be926fa742aa1fb1c1919c07d22c",
    "_parse_rules": "fee32450f1a7cb3554ea72441a516e5b1e3499bacfc5c97518873443432cb609",
    "_variable_tokens": "1afef9d80708824d711aa03862effa2b42cc125942efec2fb044e9de220f232c",
    "rules_map": "598edb2e73dab9cb08a0f06c0f209d1de5c63f4438eda74179d96b2e74f3fb64",
    "RuleSet": "3560eaf8785693d4c7883d7326bd12285b5caf9c0232c5f80d6d53a81eb7b40f",
    "LRUCache.__init__": "9af18773163e20d0f9c4ee6a974cd8e93a7ff7992343b5a60d0f8bbddb3a4878",
    "LRUCache.get": "45a6e1cc3607ab5efdb87bf10c0d58128aa0f80c0c9a3c33affffffb1f342df3",
    "LRUCache.set": "518baa5db6f1191653b9dab787c06ba5e0c1d7e55dd10bb1cda1ba4962d3a2ee",
    "LRUCache.__contains__": "e481d06bee8dec9cb91727c6a640591a0e022843a2787f90526ceb02a20cb254",
    "LRUCache.__getitem__": "a16d09eecda1a4c77e47d58f71ace5bf308c7937dc17ce16789a47a30c89a0ec",
}


@pytest.mark.parametrize("name,digest", _UPSTREAM.items())
def test_upstream_cache_contract_is_still_reviewed(name: str, digest: str) -> None:
    if name == "_parse_rules":
        member = cache._original_parse
    elif name == "RuleSet":
        member = RuleSet
    elif name.startswith("LRUCache."):
        member = getattr(LRUCache, name.split(".", 1)[1])
    else:
        member = getattr(Stylesheet, name)
        if isinstance(member, property):
            member = member.fget
    source = textwrap.dedent(inspect.getsource(member))
    assert hashlib.sha256(source.encode()).hexdigest() == digest, (
        f"Textual {name} changed; review parse sharing, variable invalidation, "
        "rule mutation and hash semantics before updating this fingerprint."
    )


@pytest.fixture
def fresh_cache(monkeypatch: pytest.MonkeyPatch) -> LRUCache:
    # A small test-local bound makes eviction observable without a large fixture.
    shared = LRUCache(3)
    monkeypatch.setattr(cache, "_shared", shared)
    return shared


def _rules(**changes: Any) -> list[RuleSet]:
    arguments = {
        "css": ".box { color: $primary; }",
        "read_from": ("test", "production-cache"),
        "is_default_rules": False, "tie_breaker": 0, "scope": "",
    }
    variables = changes.pop("variables", {"primary": "red"})
    arguments.update(changes)
    return Stylesheet(variables=variables)._parse_rules(**arguments)


@pytest.mark.parametrize("change", [
    {"css": ".box { color: blue; }"},
    {"read_from": ("test", "another-source")},
    {"is_default_rules": True}, {"tie_breaker": 1}, {"scope": "Static"},
    {"variables": {"primary": "blue"}},
    {"variables": {"primary": "red", "unused": "changed"}},
])
def test_every_parse_input_partitions_the_cache(fresh_cache: LRUCache, change: dict) -> None:
    first = _rules()
    assert _rules() is first
    assert _rules(**change) is not first


def test_variable_refresh_reparses_with_new_values(fresh_cache: LRUCache) -> None:
    stylesheet = Stylesheet(variables={"primary": "red"})
    stylesheet.add_source(".box { color: $primary; }", read_from=("test", "theme"))
    stylesheet.parse()
    red = stylesheet.rules[0]
    stylesheet.set_variables({"primary": "blue"})
    stylesheet.reparse()
    assert stylesheet.rules[0] is not red
    assert stylesheet.rules[0].styles.color == Color.parse("blue")
    assert red.styles.color == Color.parse("red")


def test_lru_evicts_the_least_recently_used_source(fresh_cache: LRUCache) -> None:
    first = _rules(tie_breaker=1)
    second = _rules(tie_breaker=2)
    _rules(tie_breaker=3)
    assert _rules(tie_breaker=1) is first
    _rules(tie_breaker=4)
    assert _rules(tie_breaker=1) is first
    assert _rules(tie_breaker=2) is not second
    for index in range(20):
        _rules(tie_breaker=index)
        assert len(fresh_cache) <= fresh_cache.maxsize == 3


@pytest.mark.parametrize("attribute", ["_variables", "_parse_cache"])
def test_missing_private_attribute_keeps_stock_methods(
    monkeypatch: pytest.MonkeyPatch, attribute: str,
) -> None:
    monkeypatch.setattr(Stylesheet, "_parse_rules", cache._original_parse)
    monkeypatch.setattr(RuleSet, "__hash__", cache._original_hash)
    stylesheet = Stylesheet()
    delattr(stylesheet, attribute)
    assert not cache.install_shared_parse_cache(stylesheet)
    assert Stylesheet._parse_rules is cache._original_parse
    assert RuleSet.__hash__ is cache._original_hash


def test_unknown_parse_method_is_not_replaced(monkeypatch: pytest.MonkeyPatch) -> None:
    def other_parser(self: Stylesheet, css: str) -> list[RuleSet]:
        return []

    monkeypatch.setattr(Stylesheet, "_parse_rules", other_parser)
    assert not cache.install_shared_parse_cache()
    assert Stylesheet._parse_rules is other_parser


def test_unknown_hash_method_keeps_stock_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Stylesheet, "_parse_rules", cache._original_parse)
    monkeypatch.setattr(RuleSet, "__hash__", lambda self: 0)
    assert not cache.install_shared_parse_cache()
    assert Stylesheet._parse_rules is cache._original_parse


def test_zero_capacity_keeps_stock_methods(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Stylesheet, "_parse_rules", cache._original_parse)
    monkeypatch.setattr(RuleSet, "__hash__", cache._original_hash)
    monkeypatch.setattr(cache, "_capacity", 0)
    assert not cache.install_shared_parse_cache()
    assert Stylesheet._parse_rules is cache._original_parse
    assert RuleSet.__hash__ is cache._original_hash


def test_private_attributes_and_local_cache_write_contract() -> None:
    stylesheet = Stylesheet(variables={"primary": "red"})
    assert stylesheet._variables == {"primary": "red"}
    assert isinstance(stylesheet._parse_cache, LRUCache)
    assert LRUCache.__setitem__ is LRUCache.set
    assert cache._compatible(stylesheet)


def test_stock_scope_blocks_product_install_and_restores_methods() -> None:
    before = Stylesheet._parse_rules, RuleSet.__hash__
    with cache.stock_parse_cache():
        assert not cache.install_shared_parse_cache()
        assert Stylesheet._parse_rules is cache._original_parse
        assert RuleSet.__hash__ is cache._original_hash
    assert (Stylesheet._parse_rules, RuleSet.__hash__) == before


def test_capacity_override_does_not_require_the_packaged_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(self: Path, **kwargs: Any) -> str:
        raise FileNotFoundError("default unavailable")

    monkeypatch.setattr(Path, "read_text", unavailable)
    monkeypatch.setenv("SERVONAUT_STYLE_CACHE_SIZE", "12")
    assert cache._configured_capacity() == 12
    monkeypatch.delenv("SERVONAUT_STYLE_CACHE_SIZE")
    assert cache._configured_capacity() == 0


def test_nested_cache_scope_restores_after_an_exception() -> None:
    before = Stylesheet._parse_rules, RuleSet.__hash__
    with pytest.raises(RuntimeError, match="fixture failure"):
        with cache.shared_parse_cache():
            with cache.shared_parse_cache():
                raise RuntimeError("fixture failure")
    assert (Stylesheet._parse_rules, RuleSet.__hash__) == before


def test_test_helper_is_only_the_product_import() -> None:
    from tests._shared_parse_cache import shared_parse_cache

    assert shared_parse_cache is cache.shared_parse_cache


@pytest.mark.parametrize("launcher", ["desktop_shell", "standalone_cli"])
def test_packaged_launchers_collect_the_cache_defaults(launcher: str) -> None:
    root = Path(__file__).resolve().parents[1]
    hook = root / "packaging" / launcher / "hooks" / "hook-servonaut.py"
    tree = ast.parse(hook.read_text(encoding="utf-8"))
    collect = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "collect_data_files"
    )
    patterns = ast.literal_eval(next(
        keyword.value for keyword in collect.keywords if keyword.arg == "includes"
    ))
    package = root / "src" / "servonaut"
    resources = {path for pattern in patterns for path in package.glob(pattern)}
    assert Path(cache.__file__).with_name("cache.json") in resources


@pytest.mark.parametrize("value,expected", [("2", 2), ("0", 0), ("-1", 0), ("invalid", 0)])
def test_process_capacity_override(
    monkeypatch: pytest.MonkeyPatch, value: str, expected: int,
) -> None:
    monkeypatch.setenv("SERVONAUT_STYLE_CACHE_SIZE", value)
    assert cache._configured_capacity() == expected


class _ThemeApp(App):
    CSS = "#sample { color: $primary; }"

    def compose(self) -> ComposeResult:
        yield Static("Theme sample", id="sample")


@pytest.mark.asyncio
async def test_runtime_theme_switch_restyles_and_can_return_to_cached_theme() -> None:
    app = _ThemeApp()
    for name, primary in (("cache-red", "#FF0000"), ("cache-blue", "#0000FF")):
        app.register_theme(Theme(name=name, primary=primary))
    app.theme = "cache-red"
    async with app.run_test() as pilot:
        await pilot.pause()
        sample = app.query_one("#sample", Static)
        red = Color.parse(app.get_css_variables()["primary"])
        assert sample.styles.color == red
        app.theme = "cache-blue"
        await pilot.pause()
        blue = Color.parse(app.get_css_variables()["primary"])
        assert blue != red
        assert sample.styles.color == blue
        app.theme = "cache-red"
        await pilot.pause()
        assert Color.parse(app.get_css_variables()["primary"]) == red
        assert sample.styles.color == red
