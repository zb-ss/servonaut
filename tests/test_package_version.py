"""The dependency-free version order must match PEP 440 as ``packaging`` applies it."""

from __future__ import annotations

import itertools

import pytest

from servonaut.utils.package_version import PackageVersion

packaging_version = pytest.importorskip("packaging.version")

CORPUS = [
    "1.0",
    "1.0.0",
    "1.0.0.dev1",
    "1.0.0a1.dev1",
    "1.0.0a1",
    "1.0.0a2",
    "1.0.0b1",
    "1.0.0rc1",
    "1.0.0rc1.post1",
    "1.0.0rc2",
    "1.0.0.post1.dev1",
    "1.0.0.post1",
    "1.0.1rc1",
    "1.0.1",
    "1.1",
    "1.10.0",
    "2.27.0",
    "2.28.0rc1",
    "2.28.0rc10",
    "2.28.0",
    "10.0",
]


def test_every_corpus_version_parses():
    for text in CORPUS:
        assert PackageVersion.parse(text) is not None, text


def test_order_matches_packaging() -> None:
    for left, right in itertools.permutations(CORPUS, 2):
        ours = PackageVersion.parse(left), PackageVersion.parse(right)
        theirs = packaging_version.Version(left), packaging_version.Version(right)
        pair = (left, right)
        assert (ours[0] < ours[1]) == (theirs[0] < theirs[1]), pair
        assert (ours[0] == ours[1]) == (theirs[0] == theirs[1]), pair
        assert (ours[0] > ours[1]) == (theirs[0] > theirs[1]), pair


@pytest.mark.parametrize("text", CORPUS)
def test_prerelease_flag_matches_packaging(text: str) -> None:
    ours = PackageVersion.parse(text)
    assert ours is not None
    assert ours.is_prerelease == packaging_version.Version(text).is_prerelease


@pytest.mark.parametrize(
    "text",
    ["", "v1.0", "1.0-rc1", "1.0RC1", "1!1.0", "1.0+local", "1.0.", "latest", None, 1.0],
)
def test_versions_outside_the_supported_form_do_not_parse(text: object) -> None:
    assert PackageVersion.parse(text) is None


def test_equal_versions_hash_alike() -> None:
    assert len({PackageVersion.parse("1.0"), PackageVersion.parse("1.0.0")}) == 1
