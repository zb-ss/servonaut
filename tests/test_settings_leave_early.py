"""Leaving Settings right after opening it must not crash the app.

Opening Settings mounts its first panel, which re-baselines its unsaved-changes
snapshot from deferred ``call_after_refresh`` callbacks. If the user switches
away before those callbacks run, the panel's fields are already torn down; the
callback used to query them anyway and crashed the app with ``NoMatches``.
"""
from __future__ import annotations

import pytest

from servonaut.screens.settings.registry import PANELS
from tests._hermetic_app import run_hermetic_app
from tests.test_settings_shell_boot import _SettingsBootApp

# Seconds spent on the Settings screen before clicking Instances. The short
# ones usually land inside the panel's re-baseline window; 1.0 s is past it.
DWELLS = ("0", "0.05", "0.3", "1.0")


def test_deferred_rebaseline_after_leaving_settings_does_not_crash(tmp_path):
    """Real app: the re-baseline fires after Settings was switched away.

    The scenario holds the deferred callbacks and releases them only once the
    Settings screen is gone, so this reproduces the crash on every run rather
    than depending on how fast the machine renders frames.
    """
    report = run_hermetic_app(tmp_path, "leave-settings-before-rebaseline")

    assert report["error"] is None, f"{report['error']}\n{report['stderr']}"
    outcome = report["result"]
    assert outcome["released"] >= 1, "no re-baseline was pending when Settings closed"
    assert outcome["error"] is None, outcome["error"]
    assert outcome["final_screen"] == "InstanceListScreen"
    assert report["home_accesses"] == []
    assert report["network_attempts"] == []


def test_sidebar_round_trip_through_settings_smoke(tmp_path):
    """Smoke test: sidebar Settings, then Instances, at several dwells.

    Timing-dependent, so it cannot guard the deferred re-baseline on its own
    (the test above does); it catches other crashes while a screen is still
    mounting or tearing down.
    """
    report = run_hermetic_app(tmp_path, "settings-round-trips", *DWELLS)

    assert report["error"] is None, f"{report['error']}\n{report['stderr']}"
    outcomes = {entry["dwell"]: entry for entry in report["result"]}
    assert sorted(outcomes) == sorted(float(d) for d in DWELLS)
    for dwell, outcome in outcomes.items():
        assert outcome["error"] is None, f"dwell {dwell}s: {outcome['error']}"
        assert outcome["final_screen"] == "InstanceListScreen", f"dwell {dwell}s"
    assert report["home_accesses"] == []
    assert report["network_attempts"] == []


@pytest.mark.asyncio
async def test_rebaseline_is_a_no_op_once_the_fields_are_gone():
    """Mid-teardown: the panel is still linked but its fields were removed."""
    app = _SettingsBootApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        panel = app.screen._panels[PANELS[0].id]
        await panel.query_one("#general_username").remove()

        panel._rebaseline_after_refresh(1)


@pytest.mark.asyncio
async def test_rebaseline_is_a_no_op_on_a_detached_panel():
    """After teardown: the panel is no longer attached to the app."""
    app = _SettingsBootApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        panel = app.screen._panels[PANELS[0].id]
        await panel.remove()

        panel._rebaseline_after_refresh(1)
