"""The release cache: which published releases the upgrade journeys start from.

``e2e/tools/fetch_previous_release.py`` picks them before the suite runs; the
choice itself needs no network, so it is checked here.
"""

from __future__ import annotations

import pytest

from e2e.harness import installs as installs_module
from e2e.tools import fetch_previous_release as fetcher

pytestmark = [pytest.mark.e2e_pr]


def test_the_previous_release_is_the_newest_at_or_below_the_checkout():
    tags = ["2.26.3", "2.26.10", "2.27.0", "2.27.1", "2.26.11rc1", "nightly"]
    # Between releases the checkout carries the latest release's version.
    assert fetcher.previous_version("2.27.0", tags, []) == "2.27.0"
    assert fetcher.previous_version("2.26.99", tags, []) == "2.26.10"
    # Without Git tags (a shallow CI checkout) the index decides.
    assert fetcher.previous_version("2.27.0", [], ["2.25.4", "2.26.3", "2.28.0"]) == "2.26.3"
    with pytest.raises(fetcher.FetchError):
        fetcher.previous_version("2.0.0", ["2.1.0"], [])


def test_every_older_config_schema_has_a_release_to_upgrade_from():
    from servonaut import __version__ as current
    from servonaut.config.schema import CONFIG_VERSION

    assert fetcher.checkout_schema() == CONFIG_VERSION
    assert fetcher.checkout_version() == current
    # Once the previous release shares this schema, the schema before it
    # needs a boundary release. A change that raises CONFIG_VERSION adds one
    # for the schema it replaces: the latest release, which was its last.
    roles = fetcher.choose_roles(current, CONFIG_VERSION, current, CONFIG_VERSION)
    assert f"schema-{CONFIG_VERSION - 1}" in roles


def test_a_schema_bump_is_covered_once_the_latest_release_is_added(monkeypatch):
    from servonaut import __version__ as current
    from servonaut.config.schema import CONFIG_VERSION

    # The checkout raises the schema while it still carries the version of
    # the latest release, which wrote the old schema.
    bumped = CONFIG_VERSION + 1
    with pytest.raises(fetcher.FetchError, match=f"config schema {CONFIG_VERSION} has no"):
        fetcher.choose_roles(current, bumped, current, bumped)

    # The documented step: add that release to the table. From then on it
    # is an upgrade source, both now and once the previous release moves on.
    monkeypatch.setitem(
        fetcher.SCHEMA_BOUNDARY_RELEASES,
        CONFIG_VERSION,
        fetcher.PinnedRelease(current, "0" * 64),
    )
    for previous_schema in (CONFIG_VERSION, bumped):
        roles = fetcher.choose_roles(current, bumped, current, previous_schema)
        assert roles[f"schema-{CONFIG_VERSION}"] == current
        assert roles["previous"] == current
    assert f"schema-{CONFIG_VERSION}" in fetcher.boundary_roles()
    assert fetcher.pinned_sha256(f"schema-{CONFIG_VERSION}") == "0" * 64


def test_overlay_sources_include_inherited_distribution_paths(monkeypatch, journey):
    """Offline installs retain dependencies from inherited ``dist-packages``."""
    workspace = journey.directory / "overlay-source-fixture"
    purelib = workspace / "venv" / "site-packages"
    inherited = workspace / "system" / "dist-packages"
    metadata_only = workspace / "metadata" / "site-packages"
    for path in (purelib, inherited, metadata_only):
        path.mkdir(parents=True)

    class Distribution:
        def locate_file(self, name: str):
            assert name == ""
            return metadata_only

    monkeypatch.setattr(
        installs_module.sysconfig,
        "get_paths",
        lambda: {"purelib": str(purelib), "platlib": str(purelib)},
    )
    monkeypatch.setattr(installs_module.sys, "path", [str(inherited)])
    monkeypatch.setattr(installs_module.metadata, "distributions", lambda: [Distribution()])

    assert installs_module.environment_site_dirs() == [
        purelib.resolve(),
        inherited.resolve(),
        metadata_only.resolve(),
    ]


def test_overlay_prefers_the_first_visible_distribution(monkeypatch, journey):
    """An inherited older dist-info cannot override the active dependency."""
    workspace = journey.directory / "overlay-precedence-fixture"
    active = workspace / "venv" / "site-packages"
    inherited = workspace / "system" / "dist-packages"
    active.mkdir(parents=True)
    inherited.mkdir(parents=True)
    (active / "rich").mkdir()
    for directory, version in ((active, "15.0.0"), (inherited, "13.9.4")):
        info = directory / f"rich-{version}.dist-info"
        info.mkdir()
        (info / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: rich\nVersion: {version}\n",
            encoding="utf-8",
        )
    monkeypatch.setattr(installs_module, "environment_site_dirs", lambda: [active, inherited])

    overlay = installs_module.build_overlay(workspace / "overlay")

    assert (overlay / "rich").resolve() == (active / "rich").resolve()
    assert (overlay / "rich-15.0.0.dist-info").is_symlink()
    assert not (overlay / "rich-13.9.4.dist-info").exists()
