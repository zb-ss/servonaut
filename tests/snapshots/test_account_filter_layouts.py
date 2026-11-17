"""Layout defects on the multi-account screens, as geometry checks.

Same two-account setup and scenarios as ``test_multi_account_screens``.
"""

from __future__ import annotations

from typing import Any, List

import pytest
from textual.widgets import Input, Label, Select

from . import _geometry
from .test_multi_account_screens import (  # noqa: F401  (the fixture is autouse)
    _cloudtrail,
    _cloudwatch,
    _run,
    two_aws_accounts,
)

sizes = pytest.mark.parametrize("size", ["160x50", "100x30"])


def _cut_texts(bar: Any, *, hints: bool = False) -> List[str]:
    """Texts in a filter bar that are wider than the control that shows them."""
    cut: List[str] = []
    for label in bar.query(Label):
        text = label.visual.plain
        if len(text) > label.content_size.width:
            cut.append(f"label {text!r}")
    for field in bar.query(Input):
        if not field.value and len(field.placeholder) > field.content_size.width:
            cut.append(f"placeholder {field.placeholder!r}")
    for select in bar.query(Select):
        shown = select.query_one("SelectCurrent Static#label")
        text = shown.visual.plain
        if len(text) > shown.content_size.width:
            cut.append(f"select {text!r}")
    from servonaut.widgets.action_button import ActionButton

    for button in bar.query(ActionButton) if hints else ():
        if button._key and "\u2590" not in button.label.plain:
            cut.append(f"the key hint of {button.words!r}")
    return cut


def _check(bar_id: str, *, hints: bool = False):
    def check(pilot: Any) -> None:
        bar = pilot.app.screen.query_one(bar_id)
        assert _cut_texts(bar, hints=hints) == []
    return check


@sizes
def test_cloudwatch_filters_show_every_label_with_two_accounts(size: str) -> None:
    _geometry.run(
        _run(_cloudwatch), size, _check("#cloudwatch_filter_bar", hints=size == "160x50"),
        name="cloudwatch-accounts", wait_for_fleet=False,
    )


@sizes
def test_cloudtrail_filters_show_every_label_with_two_accounts(size: str) -> None:
    _geometry.run(
        _run(_cloudtrail), size, _check("#cloudtrail_filters", hints=size == "160x50"),
        name="cloudtrail-accounts", wait_for_fleet=False,
    )
