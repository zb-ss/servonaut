"""Journey: update Servonaut from inside Servonaut.

``servonaut --update`` asks the package index for the latest version and,
when it is newer, upgrades the install it runs from: pip upgrades a venv
install, pipx upgrades a pipx install. Here the index is FakeCloud, serving
the checkout rebuilt as the next patch release, and the upgrade is real: the
next ``servonaut --version`` reports the new version. A version that is the
same or older is never installed.

In the TUI, installed or run from the checkout, a newer version shows an
"Update to v…" button in the sidebar (and a notification); from a source
checkout the button explains how to update instead of running pip.
"""

from __future__ import annotations

import re

import pytest

from e2e.harness import fleet
from e2e.harness.bootstrap import DEAD_HTTPS_URL
from e2e.harness.installs import ENV_PYPI_URL
from e2e.journeys.packaged import support

pytestmark = [pytest.mark.e2e_pr, pytest.mark.timeout(300)]


def _installed_from_the_index(fake_cloud, wheel) -> bool:
    return any(entry["status"] == 200 for entry in fake_cloud.requests(f"/packages/{wheel.name}"))


def test_update_upgrades_a_pip_install(
    journey, installs, fake_cloud, current_wheel, build_version, newer_wheel, newer_version
):
    sandbox, venv = support.pip_install_current(journey, installs, current_wheel, build_version)
    installs.offer(newer_wheel, version=newer_version)
    # The installed TUI notices it on its own and offers the button.
    support.boot_tui(installs, sandbox, venv.console, [f"Update to v{newer_version}"])

    update = support.ok(venv.run(sandbox, "--update", timeout=180))
    assert f"Current version: {build_version}" in update.stdout
    assert f"New version available: {newer_version}" in update.stdout
    assert "Install method: pip" in update.stdout
    assert f"Running: {venv.python} -m pip install --upgrade servonaut" in update.stdout
    assert f"Updated v{build_version} → v{newer_version}. Restart" in update.stdout
    assert _installed_from_the_index(fake_cloud, newer_wheel)
    assert support.reported_version(venv, sandbox) == newer_version


def test_update_upgrades_a_pipx_install(
    journey,
    installs,
    fake_cloud,
    current_wheel,
    build_version,
    newer_wheel,
    newer_version,
    pipx_available,
):
    sandbox = journey.new_sandbox()
    installs.offer(current_wheel, version=build_version)
    pipx = installs.pipx(sandbox)
    support.ok(pipx.install(sandbox))
    installs.offer(newer_wheel, version=newer_version)

    update = support.ok(pipx.run(sandbox, "--update", timeout=180))
    assert "Install method: pipx" in update.stdout
    assert f"Running: {pipx.wrapper} upgrade servonaut" in update.stdout
    assert f"Updated v{build_version} → v{newer_version}. Restart" in update.stdout
    assert _installed_from_the_index(fake_cloud, newer_wheel)
    assert f"servonaut {newer_version}" in support.ok(pipx.pipx(sandbox, "list", "--short")).stdout
    assert support.reported_version(pipx, sandbox) == newer_version


@pytest.mark.parametrize("latest", ["same", "older"])
def test_update_never_reinstalls_or_downgrades(
    latest, journey, installs, fake_cloud, current_wheel, build_version
):
    sandbox, venv = support.pip_install_current(journey, installs, current_wheel, build_version)
    fake_cloud.reset()  # forget the install's requests
    # The index reports this version, or an older one; had pip run, the
    # index log would show it.
    installs.offer(current_wheel, version=build_version if latest == "same" else "0.0.1")

    update = support.ok(venv.run(sandbox, "--update"))
    assert "Already up to date!" in update.stdout
    assert "Running:" not in update.stdout
    assert fake_cloud.requests("/pypi/servonaut/json")
    assert not [e for e in fake_cloud.requests() if e["path"].startswith("/simple/")]
    assert support.reported_version(venv, sandbox) == build_version


def test_update_says_when_the_index_cannot_be_reached(
    journey, installs, current_wheel, build_version
):
    sandbox, venv = support.pip_install_current(journey, installs, current_wheel, build_version)
    installs.extra_env[ENV_PYPI_URL] = f"{DEAD_HTTPS_URL}/pypi/servonaut/json"

    update = support.ok(venv.run(sandbox, "--update"))
    assert "Could not check for updates (offline)." in update.stdout
    assert "Already up to date" not in update.stdout
    assert "Running:" not in update.stdout
    assert support.reported_version(venv, sandbox) == build_version


@pytest.mark.asyncio
async def test_tui_offers_the_newer_version(tui, seed, fake_cloud, newer_version):
    from servonaut import __version__ as current

    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    fake_cloud.configure(pypi_version=newer_version)

    async with tui() as t:
        # This process runs from a source checkout.
        assert t.app.update_service.runtime.kind.value == "source"
        await t.wait_for_toast(
            rf"^Update available: v{re.escape(newer_version)} \(you have v{re.escape(current)}\)$"
        )
        await t.wait_until(lambda: t.nav_reachable("nav_update"), desc="update button")
        assert str(t.nav_button("nav_update").label).endswith(f"Update to v{newer_version}")

        await t.nav("nav_update")
        await t.wait_for_toast(r"^Updating Servonaut\.\.\.$")
        # A source checkout cannot update itself: it explains, and installs nothing.
        await t.wait_for_toast(r"running from a source installation", severity="error")
        await t.wait_until(lambda: not t.nav_button("nav_update").disabled, desc="button enabled")
    assert not [e for e in fake_cloud.requests() if e["path"].startswith("/simple/")]
