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


def run(
    scenario: Scenario,
    size: str,
    check: Check,
    *,
    name: str = "",
    demo: bool = False,
    wait_for_fleet: bool = True,
) -> None:
    """Open the fleet (unless the scenario does), run *scenario*, let the screen settle and call *check*."""

    async def main() -> None:
        app = _harness.SnapshotApp(demo=demo)
        async with app.run_test(size=_harness.SIZES[size]) as pilot:
            if wait_for_fleet:
                await _harness.wait_for_fleet(pilot)
            await scenario(pilot)
            await pilot.pause()
            await pilot.wait_for_scheduled_animations()
            await pilot.pause(0.3)
            _harness.freeze_cursors(app)
            target = os.environ.get(_SVG_DIR_VARIABLE)
            if target and name:
                Path(target).mkdir(parents=True, exist_ok=True)
                (Path(target) / f"{name}-{size}.svg").write_text(
                    app.export_screenshot(simplify=True), encoding="utf-8"
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
