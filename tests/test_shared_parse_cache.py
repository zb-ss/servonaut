"""Parsed CSS is shared between the apps one test process starts."""

from __future__ import annotations

from unittest import mock

import pytest
from textual.app import App
from textual.css import stylesheet as css_stylesheet
from textual.css.stylesheet import Stylesheet

SOURCE = ("test", "shared")
CSS = ".box { color: $primary; }"


def _parse_calls(variables: dict[str, str] | None = None) -> int:
    stylesheet = Stylesheet(variables=variables)
    stylesheet.add_source(CSS, read_from=SOURCE)
    with mock.patch.object(css_stylesheet, "parse", wraps=css_stylesheet.parse) as parse:
        stylesheet.parse()
    return parse.call_count


def _rule_text(variables: dict[str, str]) -> str:
    stylesheet = Stylesheet(variables=variables)
    stylesheet.add_source(CSS, read_from=SOURCE)
    stylesheet.parse()
    return repr(stylesheet.rules[0].styles.color)


@pytest.mark.asyncio
async def test_second_app_parses_unchanged_sources_once_in_total() -> None:
    async with App().run_test():
        pass
    with mock.patch.object(css_stylesheet, "parse", wraps=css_stylesheet.parse) as parse:
        async with App().run_test():
            pass
    assert parse.call_count == 0


def test_same_variables_reuse_the_parsed_rules() -> None:
    variables = {"primary": "red"}
    _parse_calls(variables)
    assert _parse_calls(dict(variables)) == 0


def test_different_variables_never_reuse_rules() -> None:
    red = _rule_text({"primary": "red"})
    blue = _rule_text({"primary": "blue"})
    assert red != blue
    assert _parse_calls({"primary": "green"}) == 1


@pytest.mark.stock_parse_cache
def test_stock_parse_cache_marker_opts_out_of_sharing() -> None:
    assert _parse_calls({"primary": "red"}) == 1
    assert _parse_calls({"primary": "red"}) == 1


def test_rule_sets_hash_by_identity_through_the_fast_slot() -> None:
    from textual.css.model import RuleSet

    first, second = RuleSet(), RuleSet()
    assert RuleSet.__hash__ is object.__hash__
    assert len({first, second, first}) == 2


@pytest.mark.stock_parse_cache
def test_stock_parse_cache_marker_keeps_the_stock_rule_set_hash() -> None:
    from textual.css.model import RuleSet

    assert RuleSet.__hash__ is not object.__hash__
