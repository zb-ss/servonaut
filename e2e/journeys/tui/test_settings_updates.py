"""Journey: Settings → Updates states, postpone, manual pin, and channel save.

Exercises the real Servonaut TUI at 160x50 against seeded local updater files
(``state.json``, ``preferences.json``, ``leases.json``):

- up to date on a pipx install;
- a ready update with an active MCP lease showing the old-session notice, then
  one-shot Postpone 24 h hiding the button and displaying the postpone deadline;
- a manual install pin rendered neutrally with no Postpone button;
- switching to Release candidates, saving through the Settings dock, and
  preserving the saved channel across a restart.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import pytest
from textual.widgets import RadioButton, Static, Switch

from e2e.harness import fleet
from servonaut import get_version
from servonaut.screens.settings.panels.updates import UpdatesPanel
from servonaut.updates import status as updates_status
from servonaut.utils.package_version import PackageVersion

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]


def _installed_and_next_version() -> tuple[str, str]:
    """Return the running version and a strictly newer public version string."""
    installed = get_version()
    parsed = PackageVersion.parse_installed(installed)
    if parsed is not None and len(parsed.release) >= 2:
        major, minor = parsed.release[0], parsed.release[1]
        return installed, f"{major}.{minor + 1}.0"
    return installed, "99.0.0"


def _seed_pipx_state(
    seed: Any,
    monkeypatch: pytest.MonkeyPatch,
    *,
    state: Optional[dict[str, Any]] = None,
    preferences: Optional[dict[str, Any]] = None,
    leases: Optional[dict[str, Any]] = None,
) -> Path:
    """Seed a pipx install anchor and real updater JSON files inside the sandbox home."""
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    monkeypatch.delenv("SERVONAUT_SKIP_AUTO_APPLY", raising=False)

    anchor = seed.home / "pipx" / "venvs" / "servonaut"
    anchor.mkdir(parents=True, exist_ok=True)
    (anchor / updates_status.PIPX_METADATA).write_text("{}", encoding="utf-8")
    monkeypatch.setattr(updates_status.sys, "prefix", str(anchor))

    directory = updates_status.storage_for(anchor)
    with updates_status.update_gate(directory, 2.0):
        if state is not None:
            updates_status.write_json(directory / "state.json", state)
        if preferences is not None:
            updates_status.write_json(directory / "preferences.json", preferences)
        if leases is not None:
            updates_status.write_json(directory / "leases.json", leases)
    return directory


async def _open_updates_settings(t: Any) -> UpdatesPanel:
    """Navigate to Settings → Updates like a user and wait until settled."""
    await t.nav("nav_settings")
    await t.wait_for_screen("SettingsScreen")
    await t.click("#navbtn_updates")
    await t.wait_until(
        lambda: isinstance(t.screen._current_panel(), UpdatesPanel)
        and t.screen._current_panel()._loaded
        and not t.screen._current_panel()._settling,
        desc="Updates panel loaded",
    )
    panel = t.screen._current_panel()
    assert isinstance(panel, UpdatesPanel)
    return panel


def _dirty_marker(t: Any) -> str:
    return str(t.on_screen("#dirty_updates", Static).render())


async def test_updates_panel_up_to_date(tui, seed, monkeypatch):
    installed, _ = _installed_and_next_version()
    _seed_pipx_state(
        seed,
        monkeypatch,
        state={"status": "up_to_date"},
        preferences={"channel": "stable"},
    )

    async with tui() as t:
        panel = await _open_updates_settings(t)
        await t.wait_for_text(
            installed,
            "installed with pipx",
            "Up to date",
            "Check now",
            "Stable",
            "Release candidates",
        )
        assert t.on_screen("#updates_btn_check").display is True
        assert t.on_screen("#updates_btn_postpone").display is False
        assert t.on_screen("#updates_btn_try").display is False
        assert t.on_screen("#updates_btn_update").display is False
        assert list(panel.query(Switch)) == []


async def test_updates_panel_ready_with_mcp_lease_and_postpone(tui, seed, monkeypatch):
    installed, next_version = _installed_and_next_version()
    directory = _seed_pipx_state(
        seed,
        monkeypatch,
        state={"status": "ready", "offered": next_version},
        preferences={"channel": "stable"},
        leases={"101": {"role": "mcp", "version": installed}},
    )

    async with tui() as t:
        await _open_updates_settings(t)
        await t.wait_for_text(
            f"{next_version} is ready",
            "starts the next time you open Servonaut",
            f"1 MCP server keeps {installed} until your agent restarts it",
            f"What's new in {next_version}",
            "Postpone 24 h",
        )
        assert t.on_screen("#updates_btn_postpone").display is True

        await t.click("#updates_btn_postpone")
        await t.wait_until(
            lambda: not t.on_screen("#updates_btn_postpone").display,
            desc="Postpone button hidden after postponing",
        )
        await t.wait_for_text(
            "Postponed until",
            "installs at the next start after that",
        )

    saved_state = json.loads((directory / "state.json").read_text(encoding="utf-8"))
    assert next_version in saved_state.get("postponed", {})


async def test_updates_panel_manual_pin_is_neutral_without_postpone(tui, seed, monkeypatch):
    installed, next_version = _installed_and_next_version()
    _seed_pipx_state(
        seed,
        monkeypatch,
        state={
            "status": "ready",
            "offered": next_version,
            "pin": {"version": installed, "from": next_version},
        },
        preferences={"channel": "stable"},
    )

    async with tui() as t:
        await _open_updates_settings(t)
        await t.wait_for_text(
            f"Pinned to {installed} by a manual install",
            f"newer than {next_version}",
        )
        primary = t.on_screen("#updates_status_primary", Static)
        assert not primary.has_class("-error")
        assert not primary.has_class("-warning")
        assert t.on_screen("#updates_btn_postpone").display is False
        assert t.on_screen("#updates_btn_try").display is False


async def test_updates_panel_channel_switch_saves_and_survives_restart(tui, seed, monkeypatch):
    directory = _seed_pipx_state(
        seed,
        monkeypatch,
        state={"status": "up_to_date", "checked_at": 12345},
        preferences={"channel": "stable"},
    )

    async with tui() as t:
        await _open_updates_settings(t)
        assert t.on_screen("#updates_channel_stable", RadioButton).value is True
        assert "unsaved" not in _dirty_marker(t)

        await t.click("#updates_channel_rc")
        await t.wait_until(
            lambda: "unsaved" in _dirty_marker(t),
            desc="unsaved marker after channel change",
        )
        await t.click("#save_updates")
        await t.wait_for_toast(r"Release channel saved")
        await t.wait_until(
            lambda: "unsaved" not in _dirty_marker(t),
            desc="unsaved marker cleared after save",
        )

    prefs = json.loads((directory / "preferences.json").read_text(encoding="utf-8"))
    state = json.loads((directory / "state.json").read_text(encoding="utf-8"))
    assert prefs["channel"] == "rc"
    assert state["checked_at"] == 0

    async with tui() as t:
        await _open_updates_settings(t)
        await t.wait_until(
            lambda: t.on_screen("#updates_channel_rc", RadioButton).value is True,
            desc="Release candidates still selected after restart",
        )
        assert "unsaved" not in _dirty_marker(t)

    prefs_after = json.loads((directory / "preferences.json").read_text(encoding="utf-8"))
    assert prefs_after["channel"] == "rc"
