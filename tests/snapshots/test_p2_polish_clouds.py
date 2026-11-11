"""Layout defects on the multi-account cloud screens, as geometry checks."""

from __future__ import annotations

from typing import Any

import pytest

from . import _geometry
from .test_multi_account_cloud_screens import (  # noqa: F401  (the fixture is autouse)
    CloudAccountsSnapshotApp,
    _hetzner_manager,
    _ovh_ssh_keys,
    _run,
    two_accounts_each,
)

sizes = pytest.mark.parametrize("size", ["160x50", "100x30"])


def run(scenario: Any, size: str, check: Any, name: str) -> None:
    _geometry.run(
        _run(scenario), size, check, name=name, wait_for_fleet=False,
        app=CloudAccountsSnapshotApp(),
    )


@sizes
def test_ovh_ssh_keys_title_is_shared(size: str) -> None:
    def check(pilot: Any) -> None:
        title = pilot.app.screen.query_one("#ovh_ssh_keys_header")
        assert title.has_class("screen-title")
        assert not [s for s in title.visual.spans if "accent" in str(s.style)]

    run(_ovh_ssh_keys, size, check, "title-ovh-ssh-keys")
