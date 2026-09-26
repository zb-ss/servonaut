"""Journey: config backups, from saves and from an upgrade.

Every save keeps the config it replaces in ``~/.servonaut/backups``;
``servonaut --list-backups`` lists them newest first, with their kind, and
``servonaut --restore-backup [N]`` puts one back (keeping the config it
replaces, so a restore can be undone). Without a number it asks which one.
It exits 0 only when something was restored: 1 when nothing was, 2 for a
number that cannot be one.

A first launch that migrates a config from an older schema keeps the file it
replaced as ``backups/pre-upgrade-v<schema>-<time>.json``, byte for byte and
readable by the owner only, and offers it for restore like any other backup.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.seed import HomeSeeder
from e2e.journeys.packaged import support

pytestmark = [pytest.mark.e2e_pr, pytest.mark.timeout(300)]


def _username(sandbox) -> str:
    return support.read_config(sandbox)["default_username"]


def _saved_twice(journey, installs, current_wheel, build_version):
    """An install whose config was saved as "ops", then as "admin"."""
    sandbox, venv = support.pip_install_current(journey, installs, current_wheel, build_version)
    support.seed(installs, sandbox, venv.python, default_username="ops")
    support.seed(installs, sandbox, venv.python, default_username="admin")
    return sandbox, venv


def test_backups_are_listed_and_restored(journey, installs, current_wheel, build_version):
    sandbox, venv = support.pip_install_current(journey, installs, current_wheel, build_version)
    assert support.ok(venv.run(sandbox, "--list-backups")).stdout.strip() == "No local backups yet."
    support.seed(installs, sandbox, venv.python, default_username="ops")
    support.seed(installs, sandbox, venv.python, default_username="admin")

    [(kind, kept)] = support.listed_backups(venv, sandbox)
    assert kind == "on save"
    assert kept.parent == support.backups_dir(sandbox)
    assert support.is_private(kept)

    restored = support.ok(venv.run(sandbox, "--restore-backup", "1"))
    assert f"Restored from {kept}" in restored.stdout
    assert _username(sandbox) == "ops"
    assert support.is_private(support.data_dir(sandbox) / "config.json")
    # The replaced config was kept, so the restore can be undone.
    assert len(support.listed_backups(venv, sandbox)) == 2

    # Without a number it asks; an empty answer restores nothing.
    cancelled = venv.run(sandbox, "--restore-backup", stdin="\n")
    assert cancelled.returncode == 1, cancelled.describe()
    assert "Enter number to restore" in cancelled.stdout
    assert "Cancelled; nothing was restored." in cancelled.stderr
    assert _username(sandbox) == "ops"
    # Choosing the newest one undoes the restore.
    support.ok(venv.run(sandbox, "--restore-backup", stdin="1\n"))
    assert _username(sandbox) == "admin"


def test_a_backup_that_does_not_exist_restores_nothing(
    journey, installs, current_wheel, build_version
):
    sandbox, venv = _saved_twice(journey, installs, current_wheel, build_version)

    missing = venv.run(sandbox, "--restore-backup", "7")
    assert missing.returncode == 1, missing.describe()
    assert "No backup #7: there is 1 backup (1-1)." in missing.stderr
    impossible = venv.run(sandbox, "--restore-backup", "0")
    assert impossible.returncode == 2, impossible.describe()
    assert "expected a backup number" in impossible.stderr
    assert _username(sandbox) == "admin"


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


def test_the_pre_upgrade_config_is_kept_and_can_be_restored(
    journey, installs, current_wheel, build_version, fake_cloud
):
    from servonaut.config.schema import CONFIG_VERSION

    sandbox, venv, before = _migrating_first_launch(
        journey, installs, current_wheel, build_version, fake_cloud
    )
    backup = support.backup_of(sandbox, before)
    assert backup.parent == support.backups_dir(sandbox)
    assert backup.name.startswith(f"pre-upgrade-v{CONFIG_VERSION - 1}-")
    assert support.is_private(backup)

    pre_upgrade = (f"pre-upgrade v{CONFIG_VERSION - 1}", backup)
    assert support.listed_backups(venv, sandbox) == [pre_upgrade]

    # After later changes, the user brings the pre-upgrade settings back.
    support.seed(installs, sandbox, venv.python, default_username="changed")
    listed = support.listed_backups(venv, sandbox)
    assert listed[0][0] == "on save"
    support.ok(venv.run(sandbox, "--restore-backup", str(listed.index(pre_upgrade) + 1)))
    restored = support.read_config(sandbox)
    assert restored["default_username"] == "ops"
    # The restored file is from the previous schema, so it is upgraded again.
    assert restored["version"] == CONFIG_VERSION
    assert support.is_private(support.data_dir(sandbox) / "config.json")
