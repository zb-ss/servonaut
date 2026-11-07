"""The app's stylesheet keeps every parsed CSS source between re-parses.

Textual re-parses all sources whenever a widget class adds its DEFAULT_CSS.
With its stock 64-entry parse cache, an app that holds more sources than that
parses the whole bundle again each time (several seconds at start-up).
"""
from __future__ import annotations

from unittest import mock

from textual.css import stylesheet as css_stylesheet
from textual.css.stylesheet import Stylesheet

from servonaut.app import ServonautApp
from servonaut.styles import widen_parse_cache

# More sources than Textual's default cache holds.
SOURCE_COUNT = 100


def _stylesheet_with_sources(count: int) -> Stylesheet:
    stylesheet = Stylesheet()
    widen_parse_cache(stylesheet)
    for index in range(count):
        stylesheet.add_source(f".item-{index} {{ color: red; }}", read_from=("test", str(index)))
    stylesheet.parse()
    return stylesheet


def test_reparse_only_parses_new_sources() -> None:
    stylesheet = _stylesheet_with_sources(SOURCE_COUNT)
    stylesheet.add_source(".extra { color: red; }", read_from=("test", "extra"))

    with mock.patch.object(css_stylesheet, "parse", wraps=css_stylesheet.parse) as parse:
        stylesheet.parse()

    assert parse.call_count == 1


def test_app_stylesheet_keeps_a_parsed_entry_per_source() -> None:
    app = ServonautApp()

    assert app.stylesheet._parse_cache.maxsize > 64
