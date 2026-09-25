"""Journey: build, refresh, export and clear a server's memory.

``m`` on ``web-1`` opens its memory screen. With nothing stored yet, "Probe
server now" runs every prober over real SSH and the table fills with what
the server reports (its ``/etc/os-release``, its services and containers).
After the server changes, refreshing one module picks up the change;
exporting writes a Markdown summary; clearing a module removes its rows.
Annotating opens ``$EDITOR`` on the server's notes.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from textual.app import SuspendNotSupported

from e2e.harness import remote_fleet
from e2e.harness.remote_root import OS_RELEASE

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd, pytest.mark.asyncio]

WEB_1 = remote_fleet.fleet.WEB_1
NOTE = "Serves the fixture site."


def _rows(t) -> list[list[str]]:
    return t.table_rows("#memory-table")


def _observed(t, module: str) -> dict[str, str]:
    return {row[1]: row[2] for row in _rows(t) if row[0] == module}


async def _cursor_to_row(t, key: str) -> None:
    """Click the table row *key*, scrolling it into view first like a mouse wheel."""
    table = t.on_screen("#memory-table")
    target = [row_key.value for row_key in table.rows].index(key)
    table.scroll_to(y=max(0, target - 2), animate=False, immediate=True)
    await t.settle()
    header = table.header_height if table.show_header else 0
    await t.pilot.click(table, offset=(2, header + target - round(table.scroll_y)))
    await t.wait_until(lambda: table.cursor_row == target, desc=f"cursor on {key}")


async def _open_memory(t) -> None:
    await t.wait_until(lambda: WEB_1.name in [r[1] for r in t.table_rows("InstanceTable")])
    await t.select_instance(WEB_1.name)
    await t.press("m")
    await t.wait_for_screen("MemoryScreen")


async def test_build_refresh_export_and_clear(tui, seed, journey, sshd):
    remote_fleet.seed_web_1(sshd, seed, seed.home)
    seed.cache([], fresh=True)
    remote = sshd.target.remote

    async with tui() as t:
        await _open_memory(t)
        await t.click("#btn_empty_probe")
        await t.wait_for_toast(r"^Memory refreshed\.$")
        assert _observed(t, "os")["pretty_name"] == "E2E Linux 12 (fixture)"
        assert "web-app" in " ".join(_observed(t, "containers").values())
        assert "nginx" in " ".join(_observed(t, "services").values())

        remote.write("/etc/os-release", OS_RELEASE.replace("12 (fixture)", "13 (fixture)"))
        probes = sshd.target.commands().count("cat /etc/os-release")
        await _cursor_to_row(t, "os::pretty_name")
        await t.press("m")
        await t.wait_for_toast(r"^Module 'os' refreshed\.$")
        await t.wait_until(
            lambda: _observed(t, "os").get("pretty_name") == "E2E Linux 13 (fixture)",
            desc="refreshed value",
        )
        assert sshd.target.commands().count("cat /etc/os-release") == probes + 1

        await t.press("e")
        exported = await t.wait_for_toast("^Exported to ")
        summary = Path(exported.removeprefix("Exported to "))
        assert summary.is_file()
        assert "E2E Linux 13 (fixture)" in summary.read_text(encoding="utf-8")

        await _cursor_to_row(t, "os::pretty_name")
        await t.press("c")
        await t.wait_for_screen("SimpleConfirmModal")
        await t.click("#confirm_yes_btn")
        await t.wait_for_toast(r"^Module 'os' cleared\.$")
        await t.wait_for_screen("MemoryScreen")
        assert _observed(t, "os") == {}
        assert "services" in {row[0] for row in _rows(t)}


@pytest.mark.xfail(
    strict=True,
    raises=SuspendNotSupported,
    reason="annotating from the memory screen stops the app when the terminal cannot be "
    "handed to an editor (no suspend support, as in the desktop window)",
)
async def test_annotate_the_server_notes(tui, seed, journey, sshd):
    remote_fleet.seed_web_1(sshd, seed, seed.home)
    seed.cache([], fresh=True)
    editor = journey.shims.path_of("editor")
    editor.write_text(f"#!/bin/sh\nprintf '%s\\n' '{NOTE}' >> \"$1\"\n", encoding="utf-8")

    async with tui() as t:
        await _open_memory(t)
        await t.click("#btn_empty_probe")
        await t.wait_for_toast(r"^Memory refreshed\.$")
        await t.press("a")
        notes = seed.data_dir / "memory"
        # Either the notes were edited, or the user is told why they cannot be.
        await t.wait_until(
            lambda: any(NOTE in p.read_text() for p in notes.rglob("annotations.md"))
            or any(level in ("warning", "error") for level, _ in t.toasts()),
            desc="notes saved or an explanation",
        )
        assert t.screen_name() == "MemoryScreen"
