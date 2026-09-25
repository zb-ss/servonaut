"""Journey: upgrade from a published release and keep everything.

A user on a published release upgrades with ``pip install --upgrade
servonaut``: from the release before this checkout, and from the newest
release of each earlier config schema. The old release writes the home
itself (settings, a custom server, a connection profile, an API key given
as an environment reference, the instance cache, scan results and command
history). On the first launch of the new version:

- a config from an older schema is migrated and the file it replaced is kept
  as a backup, byte for byte; a config of the current schema is left alone;
- the TUI shows the cached fleet and the custom server;
- the cache, the scan results and the command history are untouched, and
  nothing the user set is lost.

Rolling back to the previous release afterwards reads the upgraded home
without changing it.

The published wheels come from the release cache, which
``e2e/tools/fetch_previous_release.py`` fills before the suite runs.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.releases import PREVIOUS, ROLES
from e2e.journeys.packaged import support

pytestmark = [pytest.mark.e2e_pr, pytest.mark.timeout(300)]

# What a migration may change in a config the user wrote: the schema number,
# and the CloudTrail cap the v6 schema raises from the old default.
MIGRATED_VALUES = {"version", "cloudtrail_max_events"}


def _install_release_and_use_it(installs, sandbox, release):
    """The user installs *release* from the index and uses it for a while."""
    installs.offer(release.wheel, version=release.version)
    venv = installs.venv(sandbox)
    support.ok(venv.pip(sandbox, "install", f"servonaut=={release.version}"))
    assert support.reported_version(venv, sandbox) == release.version
    seeded = support.seed(installs, sandbox, venv.python)
    assert seeded == {
        "version": release.version,
        "config_version": release.config_schema,
        "skipped": [],
    }
    return venv


def _upgrade_and_launch(installs, sandbox, venv, wheel, version):
    installs.offer(wheel, version=version)
    support.ok(venv.pip(sandbox, "install", "--upgrade", "servonaut"))
    assert support.reported_version(venv, sandbox) == version
    support.boot_tui(installs, sandbox, venv.console, support.fleet_names())


def _assert_settings_kept(config):
    from servonaut.config.schema import AIProviderConfig

    web = fleet.WEB_1
    [server] = config["custom_servers"]
    assert (server["name"], server["host"], server["port"]) == (web.name, web.host, web.port)
    assert (server["username"], server["ssh_key"], server["tags"]) == (
        web.username,
        web.ssh_key,
        {"role": "web"},
    )
    assert [p["name"] for p in config["connection_profiles"]] == [fleet.BASTION_PROFILE]
    assert config["default_username"] == "ops"
    # The key still reaches the provider it was entered for, whichever field
    # the release that wrote it used.
    provider = AIProviderConfig(**config["ai_provider"])
    assert provider.key_for("anthropic") == support.AI_KEY_REFERENCE


@pytest.mark.parametrize("role", ROLES)
def test_upgrade_keeps_the_users_data(role, journey, installs, current_wheel, release_cache):
    from servonaut import __version__ as current
    from servonaut.config.schema import CONFIG_VERSION

    sandbox = journey.new_sandbox()
    release = release_cache.release(role, journey.directory / "releases")
    venv = _install_release_and_use_it(installs, sandbox, release)
    before = support.snapshot(sandbox)
    old_config = support.read_config(sandbox)

    _upgrade_and_launch(installs, sandbox, venv, current_wheel, current)

    after = support.snapshot(sandbox)
    for name in ("cache.json", "keywords.json", "command_history.json"):
        assert after[name] == before[name], f"the first launch changed {name}"
    config = support.read_config(sandbox)
    assert config["version"] == CONFIG_VERSION
    _assert_settings_kept(config)
    backups = sorted(support.data_dir(sandbox).glob("config.*.bak.*"))
    if release.config_schema < CONFIG_VERSION:
        assert set(support.changed_values(old_config, config)) <= MIGRATED_VALUES
        assert [backup.read_bytes() for backup in backups] == [before["config.json"]]
    else:
        assert after["config.json"] == before["config.json"]
        assert backups == []


def test_rolling_back_to_the_previous_release_keeps_the_upgraded_home(
    journey, installs, current_wheel, release_cache
):
    from servonaut import __version__ as current

    sandbox = journey.new_sandbox()
    release = release_cache.release(PREVIOUS, journey.directory / "releases")
    venv = _install_release_and_use_it(installs, sandbox, release)
    _upgrade_and_launch(installs, sandbox, venv, current_wheel, current)
    upgraded = support.snapshot(sandbox)

    # Something is wrong with the new version: the user goes back one release.
    installs.offer(release.wheel, version=release.version)
    support.ok(venv.pip(sandbox, "install", f"servonaut=={release.version}"))
    assert support.reported_version(venv, sandbox) == release.version
    support.boot_tui(installs, sandbox, venv.console, support.fleet_names())

    assert support.snapshot(sandbox) == upgraded
    _assert_settings_kept(support.read_config(sandbox))
