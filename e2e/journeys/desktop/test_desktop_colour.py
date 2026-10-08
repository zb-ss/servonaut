"""Journey: the desktop window draws the app in full colour.

The window's terminal shows 24-bit colour. A launch from a desktop menu sets
neither TERM nor COLORTERM, and the app used to guess its colours from them:
every theme came out squeezed into 16 colours. The real desktop child now
draws the theme's exact colours whatever the window was started with.

The terminal grid rarely fills the window exactly. The strip it leaves at
the edges takes the colour the app paints its screens with, and follows the
theme when the user switches it.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.desktop import desktop_child, open_session, wait_until

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_browser, pytest.mark.asyncio]

# The Servonaut theme's card colour (#111827), which screens are painted
# with, as a 24-bit background colour.
SERVONAUT_SURFACE = b"48;2;17;24;39"


@pytest.mark.parametrize("term", [None, "xterm-256color"], ids=["menu-launch", "256-colour-term"])
async def test_the_child_draws_the_theme_in_24_bit_colour(desktop, term):
    sandbox = desktop.child_sandbox()
    env = desktop.child_env(sandbox)
    env.pop("COLORTERM", None)
    env.pop("TEXTUAL_COLOR_SYSTEM", None)
    if term is None:
        env.pop("TERM", None)
    else:
        env["TERM"] = term

    received: list[bytes] = []

    def record(socket_) -> None:
        socket_.on(
            "framereceived",
            lambda payload: received.append(payload) if isinstance(payload, bytes) else None,
        )

    async with desktop_child(
        sandbox, env=env, armed_log=desktop.journey.armed_log
    ) as child, desktop.browser() as browser:
        page = await browser.new_page()
        page.page.on("websocket", record)
        assert await page.open(child.origin) == 200
        await page.start_session(child.token.encoded_value())
        await page.wait_for_text(fleet.AWS_FLEET[0].name)
        await wait_until(
            lambda: SERVONAUT_SURFACE in b"".join(received),
            desc="the Servonaut surface in 24-bit colour",
        )
        output = b"".join(received)
        # No colour was rounded to the 256-colour palette.
        assert b"48;5;" not in output and b"38;5;" not in output
        assert page.errors() == []



async def _page_colour(page) -> str:
    """Background of the page and of the terminal's viewport, as CSS rgb()."""
    return await page.page.evaluate(
        "() => [document.body, document.querySelector('.xterm-viewport')]"
        ".map((element) => getComputedStyle(element).backgroundColor).join(' ')"
    )


async def _wait_for_page_colour(page, rgb: str) -> None:
    expected = f"{rgb} {rgb}"
    for _ in range(200):
        if await _page_colour(page) == expected:
            return
        await page.page.wait_for_timeout(50)
    assert await _page_colour(page) == expected


async def _palette_highlights(app, wanted: str) -> None:
    from textual.command import CommandList

    command_list = app.tui.on_screen(CommandList)

    def highlighted() -> bool:
        index = command_list.highlighted
        if index is None:
            return False
        prompt = command_list.get_option_at_index(index).prompt
        return getattr(prompt, "plain", str(prompt)).startswith(wanted)

    await app.tui.wait_until(highlighted, desc=f"palette entry {wanted!r}")


async def test_the_page_around_the_terminal_follows_the_theme(desktop, seed):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    async with desktop.in_process() as app, desktop.browser() as browser:
        page = await open_session(browser, app)
        await page.wait_for_text(fleet.AWS_FLEET[0].name)
        # The Servonaut theme paints its screens #111827.
        await _wait_for_page_colour(page, "rgb(17, 24, 39)")

        await page.press("Control+p")
        await app.tui.wait_for_screen("CommandPalette")
        await page.type("theme")
        await _palette_highlights(app, "Theme")
        await page.press("Enter")
        await app.tui.wait_until(
            lambda: "theme" in app.app.screen.query_one("Input").placeholder.lower(),
            desc="theme search open",
        )
        await page.type("servonaut-light")
        await _palette_highlights(app, "servonaut-light")
        await page.press("Enter")
        await app.tui.wait_until(lambda: app.app.theme == "servonaut-light", desc="theme switched")

        # Servonaut Light paints its screens #EEF2F7.
        await _wait_for_page_colour(page, "rgb(238, 242, 247)")
        assert page.errors() == []
