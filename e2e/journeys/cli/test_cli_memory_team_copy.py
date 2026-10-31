"""Journey: ``servonaut memory`` merges a team's copy of a server's notes first.

Signed in as a member of the team Ops, which shares the user's own app-1 as
``app-1-team``, a note and a probed module the team filed under its own copy of that
server are merged into the user's own app-1 record the first time a ``memory`` command
touches it: the note shows up in ``memory show``, stderr says what was merged
(``--json`` stdout stays data), and a second command merges nothing. The
command never unlocks Memory Sync, so a computer that has set it up keeps the
service's part marked as owed, and one that has not owes nothing.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness import fleet
from e2e.harness.team_agent_rules import SLUG, TEAM_ID, TEAM_NAME
from e2e.harness.team_copy_memory import SHARED_APP_1, TEAM_DISTRO, TEAM_NOTE, marker, own_notes, seed_team_copy

pytestmark = [pytest.mark.e2e_pr]

TEAM = {"id": TEAM_ID, "slug": SLUG, "name": TEAM_NAME, "role": "member", "member_count": 2}


def _share_app_1(fake_cloud) -> None:
    fake_cloud.configure(plan="teams")
    fake_cloud.account.configure(teams=[TEAM], shared_servers={SLUG: [dict(SHARED_APP_1)]})


def test_show_merges_the_teams_note_into_the_own_record_once(fake_cloud, cli, account_home):
    _share_app_1(fake_cloud)
    home = account_home("cli-team-copy")
    copy = seed_team_copy(home.home)

    first = cli(home, "memory", "show", fleet.APP_1.name, "--format", "json")
    assert first.returncode == 0, first.describe()
    assert "Merged 1 team copy into your servers" in first.stderr, first.describe()
    assert TEAM_NOTE in own_notes(home.home)
    assert json.loads(first.stdout)["os"]["observed"]["distro"] == TEAM_DISTRO
    assert marker(copy)["target_id"] == fleet.APP_1.instance_id

    second = cli(home, "memory", "show", fleet.APP_1.name)
    assert second.returncode == 0, second.describe()
    assert "Merged" not in second.stderr, second.describe()
    assert TEAM_NOTE in second.stdout, second.describe()


def test_a_note_deleted_from_the_own_record_does_not_come_back(fake_cloud, cli, account_home):
    _share_app_1(fake_cloud)
    home = account_home("cli-team-copy-deleted")
    seed_team_copy(home.home)
    assert cli(home, "memory", "show", fleet.APP_1.name).returncode == 0
    notes = home.home / ".servonaut" / "memory" / "aws" / fleet.APP_1.instance_id / "annotations.md"
    notes.write_text("", encoding="utf-8")

    again = cli(home, "memory", "show", fleet.APP_1.name)

    assert again.returncode == 0, again.describe()
    assert own_notes(home.home) == ""


def test_signed_out_merges_nothing(fake_cloud, cli, account_home):
    _share_app_1(fake_cloud)
    home = account_home("cli-team-copy-out", signed_in=False)
    seed_team_copy(home.home)

    result = cli(home, "memory", "show", fleet.APP_1.name)

    assert result.returncode == 0, result.describe()
    assert "Merged" not in result.stderr and own_notes(home.home) == ""


def test_a_set_up_but_locked_memory_sync_leaves_the_service_part_owed(fake_cloud, cli, account_home):
    _share_app_1(fake_cloud)
    home = account_home("cli-team-copy-locked")
    copy = seed_team_copy(home.home)
    cache = home.home / ".servonaut" / "memory" / "keys.json"
    cache.write_text("{}", encoding="utf-8")

    result = cli(home, "memory", "show", fleet.APP_1.name)

    assert result.returncode == 0, result.describe()
    assert TEAM_NOTE in own_notes(home.home)
    assert marker(copy)["remote_pending"] is True


def test_clear_does_not_merge_first(fake_cloud, cli, account_home):
    _share_app_1(fake_cloud)
    home = account_home("cli-team-copy-clear")
    copy = seed_team_copy(home.home)

    result = cli(home, "memory", "clear", fleet.APP_1.name, "--force")

    assert "Merged" not in result.stderr, result.describe()
    assert marker(copy) is None
