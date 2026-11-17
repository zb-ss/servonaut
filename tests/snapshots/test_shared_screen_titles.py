"""Every full screen titles itself with the shared screen-title style."""

from __future__ import annotations

from typing import Any

import pytest

from . import _geometry, test_memory_bulk_share as bulk
from . import test_memory_family as family
from . import test_memory_key_change as key_change
from . import test_memory_share as share


def _titles_are_shared(title_id: str):
    def check(pilot: Any) -> None:
        title = pilot.app.screen.query_one(f"#{title_id}")
        assert title.has_class("screen-title")
        # No colour of its own: the shared style sets it.
        assert not [s for s in title.visual.spans if "accent" in str(s.style)]

    return check


@pytest.mark.parametrize("size", ["160x50", "100x30"])
@pytest.mark.parametrize(
    "name,scenario,title_id",
    [
        ("share", share._shared_form, "share-title"),
        ("bulk", bulk._bulk_form, "bulk-title"),
        ("drift", family._drift, "drift-title"),
        ("findings", family._findings, "findings_title"),
        ("keychange", key_change._screen("share"), "keychange-title"),
    ],
)
def test_memory_screens_use_the_shared_title(name: str, scenario: Any, title_id: str, size: str) -> None:
    _geometry.run(scenario, size, _titles_are_shared(title_id), name=f"title-{name}")
