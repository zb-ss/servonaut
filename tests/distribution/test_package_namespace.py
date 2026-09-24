"""Tests for the scripts.distribution package namespace."""

from __future__ import annotations

import importlib
import inspect

import pytest

_SUBMODULES = (
    "notarize_macos",
    "package_cli",
    "package_deb",
    "package_macos",
    "package_windows",
    "sign_macos",
    "sign_windows",
    "webview2_detect",
)


@pytest.mark.parametrize("name", _SUBMODULES)
def test_package_attribute_is_the_submodule(name: str) -> None:
    module = importlib.import_module(f"scripts.distribution.{name}")
    package = importlib.import_module("scripts.distribution")

    assert inspect.ismodule(getattr(package, name))
    assert getattr(package, name) is module


def test_channel_for_tag_is_still_exported() -> None:
    package = importlib.import_module("scripts.distribution")
    release_candidate = importlib.import_module("scripts.distribution.release_candidate")

    assert package.channel_for_tag is release_candidate.channel_for_tag
