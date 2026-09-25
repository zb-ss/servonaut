"""The release cache: which published releases the upgrade journeys start from.

``e2e/tools/fetch_previous_release.py`` picks them before the suite runs; the
choice itself needs no network, so it is checked here.
"""

from __future__ import annotations

import pytest

from e2e.tools import fetch_previous_release as fetcher

pytestmark = [pytest.mark.e2e_pr]


def test_the_previous_release_is_the_newest_older_one():
    tags = ["2.26.3", "2.26.10", "2.27.0", "2.27.1", "2.26.11rc1", "nightly"]
    assert fetcher.previous_version("2.27.0", tags, []) == "2.26.10"
    # Without Git tags (a shallow CI checkout) the index decides.
    assert fetcher.previous_version("2.27.0", [], ["2.25.4", "2.26.3"]) == "2.26.3"
    with pytest.raises(fetcher.FetchError):
        fetcher.previous_version("2.0.0", ["2.0.0", "2.1.0"], [])


def test_every_older_config_schema_has_a_release_to_upgrade_from():
    from servonaut import __version__ as current
    from servonaut.config.schema import CONFIG_VERSION

    assert fetcher.checkout_schema() == CONFIG_VERSION
    assert fetcher.checkout_version() == current
    # Once the previous release shares this schema, the schema before it
    # needs a boundary release. A change that raises CONFIG_VERSION adds one
    # for the schema it replaces: the latest release, which was its last.
    roles = fetcher.choose_roles(current, CONFIG_VERSION, "0.0.1", CONFIG_VERSION)
    assert f"schema-{CONFIG_VERSION - 1}" in roles
    # Right after a schema bump the previous release covers the old schema...
    bumped = CONFIG_VERSION + 1
    roles = fetcher.choose_roles("99.0.0", bumped, "98.0.0", CONFIG_VERSION)
    assert roles["previous"] == "98.0.0"
    # ...and once it has moved on, the old schema needs a boundary release.
    with pytest.raises(fetcher.FetchError, match=f"config schema {CONFIG_VERSION} has no"):
        fetcher.choose_roles("99.1.0", bumped, "99.0.0", bumped)
