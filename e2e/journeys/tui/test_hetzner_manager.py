"""Journey: manage Hetzner Cloud servers from the Hetzner Manager screen.

The manager lists the project's servers with their state and address. Start
acts on the selected server straight away; Shutdown, Power off and Reboot ask
a yes/no question first, with No selected, and declining sends nothing. Each
action sends exactly one request to the Hetzner API; the row then shows the
new state, and only the buttons that fit
that state are enabled. Deleting a server asks for the word "delete" first:
cancelling or a wrong word sends nothing, the right word sends exactly one
delete and the row disappears. Every change is written to the Hetzner audit
file.
"""

from __future__ import annotations

import json
import re

import pytest

from e2e.harness import fleet
from e2e.harness.known_bugs import ProductBug

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

TABLE = "#hetzner_mgr_table"
POWER_BUTTONS = (
    "#btn_hetzner_mgr_power_on",
    "#btn_hetzner_mgr_shutdown",
    "#btn_hetzner_mgr_power_off",
    "#btn_hetzner_mgr_reboot",
)
_MARKUP = re.compile(r"\[/?[a-z ]+\]")


class HetznerLocationMissing(ProductBug):
    """Every Hetzner server shows an empty location."""


def _seed(seed, providers) -> None:
    seed.config(hetzner=seed.hetzner_config())
    seed.cache(fleet.cache_rows(fleet.APP_1), fresh=True)
    providers.hetzner.seed_servers(fleet.HETZNER_FLEET)


def _rows(t) -> dict[str, dict[str, str]]:
    """Manager rows by server name: id, type, state (without colour), address."""
    out = {}
    for row in t.table_rows(TABLE):
        out[row[1]] = {
            "id": row[2],
            "type": row[3],
            "state": _MARKUP.sub("", row[4]),
            "public_ip": row[5],
            "region": row[6],
        }
    return out


async def _open_manager(t) -> None:
    await t.nav("nav_hetzner_manage")
    await t.wait_for_screen("HetznerManagerScreen")
    await t.wait_until(
        lambda: set(_rows(t)) == {h.name for h in fleet.HETZNER_FLEET}, desc="manager rows"
    )


async def _select(t, name: str) -> None:
    """Move the manager's cursor to *name* with the keyboard."""
    table = t.on_screen(TABLE)
    if not table.has_focus:
        await t.click(table)
        await t.wait_until(lambda: table.has_focus, desc="manager table focus")
    names = list(_rows(t))
    target = names.index(name)
    for _ in range(len(names) + 1):
        if table.cursor_row == target:
            break
        await t.press("down" if table.cursor_row < target else "up")
    await t.wait_until(lambda: table.cursor_row == target, desc=f"cursor on {name}")
    await t.settle()


def _enabled(t, selector: str) -> bool:
    return not t.on_screen(selector).disabled


def _actions(providers, server_id: int) -> list[str]:
    return [
        entry["api_path"].rsplit("/", 1)[-1]
        for entry in providers.requests(
            "hetzner", method="POST", path=rf"/servers/{server_id}/actions/\w+"
        )
    ]


def _audit(seed) -> list[dict]:
    path = seed.data_dir / "hetzner_audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


async def _answer_power_prompt(t, *, confirm: bool) -> None:
    """Answer the power question; No has the focus, so Enter declines."""
    await t.wait_for_screen("PowerActionConfirmModal")
    await t.wait_until(
        lambda: t.focused_id() == "btn_power_confirm_no", desc="No focused"
    )
    if confirm:
        await t.click("#btn_power_confirm_yes")
    else:
        await t.press("enter")
    await t.wait_for_screen("HetznerManagerScreen")


async def _power(
    t, providers, button: str, server, verb: str, toast: str, state: str, *, asks: bool = True
) -> None:
    """Press a power button and check the one request, the toast and the new state."""
    before = len(_actions(providers, server.server_id))
    await t.click(button)
    if asks:
        await _answer_power_prompt(t, confirm=True)
    await t.wait_for_toast(rf"^Server {server.server_id}: {toast}\.$")
    await t.wait_until(
        lambda: _rows(t)[server.name]["state"] == state, desc=f"{server.name} {state}"
    )
    assert t.screen_name() == "HetznerManagerScreen"
    assert _actions(providers, server.server_id)[before:] == [verb]


async def test_power_actions_hit_the_api_once_each(tui, seed, providers):
    _seed(seed, providers)
    cache, build = fleet.HZ_CACHE_1, fleet.HZ_BUILD_1

    async with tui() as t:
        await _open_manager(t)
        rows = _rows(t)
        assert {k: v for k, v in rows[cache.name].items() if k != "region"} == {
            "id": str(cache.server_id),
            "type": cache.server_type,
            "state": "running",
            "public_ip": cache.public_ip,
        }
        assert rows[build.name]["state"] == "stopped"

        # A stopped server can only be started (or deleted).
        await _select(t, build.name)
        assert [_enabled(t, b) for b in POWER_BUTTONS] == [True, False, False, False]
        await _power(
            t, providers, "#btn_hetzner_mgr_power_on", build, "poweron", "started", "running",
            asks=False,
        )

        # A running server can be shut down, powered off or rebooted, not started.
        await _select(t, cache.name)
        assert [_enabled(t, b) for b in POWER_BUTTONS] == [False, True, True, True]
        # The keyboard shortcut works like the button; declining sends nothing.
        before = len(_actions(providers, cache.server_id))
        await t.press("b")
        await _answer_power_prompt(t, confirm=False)
        await t.settle()
        assert len(_actions(providers, cache.server_id)) == before
        await t.press("b")
        await _answer_power_prompt(t, confirm=True)
        await t.wait_for_toast(rf"^Server {cache.server_id}: reboot sent\.$")
        await t.wait_until(
            lambda: len(_actions(providers, cache.server_id)) > before, desc="reboot request"
        )
        await t.settle()
        assert _actions(providers, cache.server_id)[before:] == ["reboot"]
        assert _rows(t)[cache.name]["state"] == "running"

        await _select(t, cache.name)
        await _power(t, providers, "#btn_hetzner_mgr_shutdown", cache, "shutdown", "shutdown sent", "stopped")
        await _select(t, build.name)
        await _power(t, providers, "#btn_hetzner_mgr_power_off", build, "poweroff", "powered off", "stopped")

    assert providers.hetzner.server(cache.server_id)["status"] == "off"
    assert providers.hetzner.server(build.server_id)["status"] == "off"
    # Only the four actions changed anything; nothing was deleted or created.
    assert [e["api_path"] for e in providers.mutations("hetzner")] == [
        f"/servers/{build.server_id}/actions/poweron",
        f"/servers/{cache.server_id}/actions/reboot",
        f"/servers/{cache.server_id}/actions/shutdown",
        f"/servers/{build.server_id}/actions/poweroff",
    ]
    audit = [(row["action"], row["target"], row["success"]) for row in _audit(seed)]
    assert audit == [
        ("power_on", str(build.server_id), True),
        ("reboot", str(cache.server_id), True),
        ("shutdown", str(cache.server_id), True),
        ("power_off", str(build.server_id), True),
    ]


async def test_delete_needs_the_typed_word(tui, seed, providers):
    _seed(seed, providers)
    doomed = fleet.HZ_CACHE_1

    def deletes() -> list[dict]:
        return providers.requests("hetzner", method="DELETE")

    async with tui() as t:
        await _open_manager(t)
        await _select(t, doomed.name)

        # Escape backs out without deleting anything.
        await t.click("#btn_hetzner_mgr_delete")
        await t.wait_for_screen("ConfirmActionScreen")
        text = t.rendered_text()
        assert "Delete Hetzner Server" in text
        assert doomed.name in text
        assert not _enabled(t, "#btn_confirm")
        await t.press("escape")
        await t.wait_for_screen("HetznerManagerScreen")
        await t.settle()
        assert deletes() == []

        # A wrong word keeps the button disabled; Cancel backs out.
        await t.click("#btn_hetzner_mgr_delete")
        await t.wait_for_screen("ConfirmActionScreen")
        await t.fill("#confirm_input", "Delete")
        assert not _enabled(t, "#btn_confirm")
        await t.fill("#confirm_input", "delete ")
        assert not _enabled(t, "#btn_confirm")
        await t.click("#btn_cancel")
        await t.wait_for_screen("HetznerManagerScreen")
        await t.settle()
        assert deletes() == []
        assert doomed.name in _rows(t)

        # The exact word enables the button, and one delete is sent.
        await t.click("#btn_hetzner_mgr_delete")
        await t.wait_for_screen("ConfirmActionScreen")
        await t.fill("#confirm_input", "delete")
        await t.wait_until(lambda: _enabled(t, "#btn_confirm"), desc="confirm enabled")
        await t.click("#btn_confirm")
        await t.wait_for_screen("HetznerManagerScreen")
        await t.wait_for_toast(rf"^Server {doomed.server_id} deleted\.$")
        await t.wait_until(lambda: doomed.name not in _rows(t), desc="row removed")
        assert set(_rows(t)) == {fleet.HZ_BUILD_1.name}

    assert [e["api_path"] for e in deletes()] == [f"/servers/{doomed.server_id}"]
    assert providers.hetzner.server(doomed.server_id) is None
    assert providers.hetzner.server(fleet.HZ_BUILD_1.server_id) is not None
    assert [(r["action"], r["success"]) for r in _audit(seed)] == [("delete_server", True)]


async def test_manager_shows_each_servers_location(tui, seed, providers):
    _seed(seed, providers)

    async with tui() as t:
        await _open_manager(t)
        regions = {name: row["region"] for name, row in _rows(t).items()}
    expected = {host.name: host.location for host in fleet.HETZNER_FLEET}
    if regions != expected and not any(regions.values()):
        raise HetznerLocationMissing(f"regions shown: {regions}")
    assert regions == expected


async def test_manager_reports_a_refused_token(tui, seed, providers):
    _seed(seed, providers)
    providers.hetzner.fail_with = "unauthorized"

    async with tui() as t:
        await t.nav("nav_hetzner_manage")
        await t.wait_for_screen("HetznerManagerScreen")
        status = t.on_screen("#hetzner_mgr_status")
        await t.wait_until(
            lambda: "Failed to load servers" in str(status.render()), desc="error status"
        )
        assert "unable to authenticate" in str(status.render())
        assert t.table_rows(TABLE) == []
    assert providers.mutations("hetzner") == []
