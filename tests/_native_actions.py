"""Reach scrolled actions through native focus before exercising mouse input."""

from textual.pilot import Pilot
from textual.widgets import Button


async def click_action(pilot: Pilot, selector: str) -> None:
    """Tab to an enabled action, then verify and click its visible center."""
    app = pilot.app
    target = app.screen.query_one(selector, Button)
    for _ in range(len(app.screen.focus_chain) + 1):
        if app.focused is target:
            break
        await pilot.press("tab")
    assert app.focused is target, f"Tab did not reach {selector}"
    await pilot.wait_for_scheduled_animations()
    assert app.screen.region.contains_region(target.region)
    hit = app.get_widget_at(*target.content_region.center)[0]
    assert hit is target or target in hit.ancestors, (selector, hit, target.region)
    center_x, center_y = target.content_region.center
    offset = (center_x - target.region.x, center_y - target.region.y)
    assert await pilot.click(target, offset=offset), selector
