"""Run a screenshot scenario and inspect the mounted screen instead of the SVG.

Geometry assertions (nothing clipped, nothing scrolled out of view) are a
better regression guard than a pixel comparison for layout defects: they name
the widget that is wrong. Set ``GEOMETRY_SVG_DIR`` to also write the
rendering of every run there, to look at it.

This module has no ``test_`` prefix and is not collected.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Awaitable, Callable, Iterable, List

from textual.widget import Widget

from . import _harness

Scenario = Callable[[Any], Awaitable[None]]
Check = Callable[[Any], None]

_SVG_DIR_VARIABLE = "GEOMETRY_SVG_DIR"


async def settle(pilot: Any, app: Any, *, attempts: int = 30) -> None:
    """Wait until two exports of the screen, a frame apart, are identical."""
    previous = None
    for _ in range(attempts):
        await pilot.wait_for_scheduled_animations()
        await pilot.pause(0.1)
        current = app.export_screenshot(simplify=True)
        if current == previous:
            return
        previous = current
    raise AssertionError("the screen was still changing after the scenario")


def run(
    scenario: Scenario,
    size: Any,
    check: Check,
    *,
    name: str = "",
    demo: bool = False,
    wait_for_fleet: bool = True,
    app: Any = None,
) -> None:
    """Open the fleet (unless the scenario does), run *scenario*, let the screen settle and call *check*."""

    async def main() -> None:
        shown_app = app if app is not None else _harness.SnapshotApp(demo=demo)
        async with shown_app.run_test(size=_harness.SIZES[size] if isinstance(size, str) else size) as pilot:
            if wait_for_fleet:
                await _harness.wait_for_fleet(pilot)
            await scenario(pilot)
            await settle(pilot, shown_app)
            _harness.freeze_cursors(shown_app)
            target = os.environ.get(_SVG_DIR_VARIABLE)
            if target and name:
                Path(target).mkdir(parents=True, exist_ok=True)
                (Path(target) / f"{name}-{size if isinstance(size, str) else 'x'.join(map(str, size))}.svg").write_text(
                    shown_app.export_screenshot(simplify=True), encoding="utf-8"
                )
            check(pilot)

    asyncio.run(main())


def visible_rows(widget: Widget) -> range:
    """The screen rows *widget* covers."""
    region = widget.region
    return range(region.y, region.y + region.height)


def inside_screen(pilot: Any, widget: Widget) -> bool:
    """True when every cell of *widget* is on the screen (not scrolled away)."""
    screen_region = pilot.app.screen.region
    return screen_region.contains_region(widget.region) and widget.region.height > 0


def clipped_labels(widgets: Iterable[Widget]) -> List[str]:
    """Labels whose text is wider than the widget that shows it."""
    clipped = []
    for widget in widgets:
        text = str(getattr(widget, "label", "") or "")
        if text and widget.content_size.width < len(text):
            clipped.append(text)
    return clipped


def ovh_keys_panel_problems(screen: Any) -> list:
    """What of the OVH keys screen is out of view: title, scope, panel border and heading, help text."""
    document = screen.query_one("#ovh_ssh_keys_document")
    visible = document.region
    problems = []
    for name, widget_id in (("title", "#ovh_ssh_keys_header"), ("scope", "#ovh_ssh_keys_scope")):
        if not screen.region.contains_region(screen.query_one(widget_id).region):
            problems.append(f"the {name} is out of view")
    catalog = screen.query_one(".provider_key_catalog")
    if catalog.region.y < visible.y:
        problems.append("the panel's top border is scrolled out")
    heading = screen.query_one(".provider_catalog_heading")
    if not visible.contains_region(heading.region):
        problems.append("the panel heading is out of view")
    help_text = screen.query_one(".provider-key-context .note")
    if help_text.region.y < visible.y:
        problems.append("the first line of the help text is cut")
    return problems


