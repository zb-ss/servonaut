"""Journey: config backups, from saves and from an upgrade.

Every save keeps the config it replaces in ``~/.servonaut/backups``;
``servonaut --list-backups`` lists them newest first and
``servonaut --restore-backup [N]`` puts one back (keeping the config it
replaces, so a restore can be undone). Without a number it asks which one.

A first launch that migrates a config from an older schema keeps the file it
replaced next to the config, byte for byte and readable by the owner only.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path

import pytest

from e2e.harness import fleet
from e2e.harness.seed import HomeSeeder
from e2e.journeys.packaged import support

pytestmark = [pytest.mark.e2e_pr, pytest.mark.timeout(300)]

_LISTED = re.compile(r"^\s*(\d+)\s+\S+ \S+\s+\S+ K?B\s+(\S+)$", re.MULTILINE)


def _listed(venv, sandbox) -> list[str]:
    """The backup paths ``--list-backups`` shows, in its order."""
    listing = support.ok(venv.run(sandbox, "--list-backups")).stdout
    rows = _LISTED.findall(listing)
    assert [int(index) for index, _ in rows] == list(range(1, len(rows) + 1)), listing
    return [path for _, path in rows]


def _username(sandbox) -> str:
    return support.read_config(sandbox)["default_username"]


def test_backups_are_listed_and_restored(journey, installs, current_wheel, build_version):
    sandbox, venv = support.pip_install_current(journey, installs, current_wheel, build_version)
    assert support.ok(venv.run(sandbox, "--list-backups")).stdout.strip() == "No local backups yet."

    support.seed(installs, sandbox, venv.python, default_username="ops")
    support.seed(installs, sandbox, venv.python, default_username="admin")
    [kept] = _listed(venv, sandbox)
    assert Path(kept).parent == support.data_dir(sandbox) / "backups"
    assert stat.S_IMODE(Path(kept).stat().st_mode) == 0o600

    restored = support.ok(venv.run(sandbox, "--restore-backup", "1"))
    assert f"Restored from {kept}" in restored.stdout
    assert _username(sandbox) == "ops"
    assert len(_listed(venv, sandbox)) == 2  # the replaced config was kept

    # Without a number it asks; an empty answer changes nothing.
    cancelled = support.ok(venv.run(sandbox, "--restore-backup", stdin="\n"))
    assert "Enter number to restore" in cancelled.stdout
    assert "Cancelled." in cancelled.stdout
    assert _username(sandbox) == "ops"
    # Choosing the newest one undoes the restore.
    support.ok(venv.run(sandbox, "--restore-backup", stdin="1\n"))
    assert _username(sandbox) == "admin"


_EXIT_GAP = "--restore-backup exits 0 when no backup has that number"


@pytest.mark.xfail(strict=True, raises=support.KnownGap, reason=_EXIT_GAP)
def test_restoring_a_backup_that_does_not_exist_fails(
    journey, installs, current_wheel, build_version
):
    sandbox, venv = support.pip_install_current(journey, installs, current_wheel, build_version)
    support.seed(installs, sandbox, venv.python, default_username="ops")
    support.seed(installs, sandbox, venv.python, default_username="admin")

    result = venv.run(sandbox, "--restore-backup", "7")
    assert "out of range" in result.stdout + result.stderr, result.describe()
    assert _username(sandbox) == "admin"
    support.expect_fixed(result.returncode != 0, _EXIT_GAP)


def _migrating_first_launch(journey, installs, current_wheel, build_version, fake_cloud):
    """A config from the previous schema, then the first launch of this version."""
    from servonaut.config.schema import CONFIG_VERSION, CustomServer

    sandbox, venv = support.pip_install_current(journey, installs, current_wheel, build_version)
    support.seed(installs, sandbox, venv.python)
    web = fleet.WEB_1
    HomeSeeder(sandbox.home, api_url=fake_cloud.url).previous_version_config(
        default_username="ops",
        custom_servers=[
            CustomServer(name=web.name, host=web.host, username=web.username, port=web.port)
        ],
    )
    before = (support.data_dir(sandbox) / "config.json").read_bytes()
    support.boot_tui(installs, sandbox, venv.console, support.fleet_names())
    assert support.read_config(sandbox)["version"] == CONFIG_VERSION
    return sandbox, venv, before


def test_a_migration_keeps_the_replaced_config_privately(
    journey, installs, current_wheel, build_version, fake_cloud
):
    sandbox, _venv, before = _migrating_first_launch(
        journey, installs, current_wheel, build_version, fake_cloud
    )
    assert support.is_private(support.backup_of(sandbox, before))


_LISTING_GAP = (
    "the config backup a migration writes is not offered by --list-backups, "
    "so --restore-backup cannot bring back the pre-upgrade config"
)


@pytest.mark.xfail(strict=True, raises=support.KnownGap, reason=_LISTING_GAP)
def test_the_pre_upgrade_config_can_be_restored(
    journey, installs, current_wheel, build_version, fake_cloud
):
    sandbox, venv, before = _migrating_first_launch(
        journey, installs, current_wheel, build_version, fake_cloud
    )

    listed = _listed(venv, sandbox)
    matches = [i for i, path in enumerate(listed, start=1) if Path(path).read_bytes() == before]
    support.expect_fixed(bool(matches), _LISTING_GAP)
    # Once it is listed, restoring it brings the old config back.
    support.ok(venv.run(sandbox, "--restore-backup", str(matches[0])))
    assert (support.data_dir(sandbox) / "config.json").read_bytes() == before
