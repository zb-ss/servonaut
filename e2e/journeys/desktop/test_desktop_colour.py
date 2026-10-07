"""Journey: the desktop window draws the app in full colour.

The window's terminal shows 24-bit colour. A launch from a desktop menu sets
neither TERM nor COLORTERM, and the app used to guess its colours from them:
every theme came out squeezed into 16 colours. The real desktop child now
draws the theme's exact colours whatever the window was started with.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.desktop import desktop_child, wait_until

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
