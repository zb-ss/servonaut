"""Journey: client-version gate behavior in the CLI (enforce vs log mode).

Under ``mode="enforce"`` with a server minimum newer than the running client:
- cloud commands (``ai conversations list``, ``team rules``) exit
  non-zero and print the update-required guidance naming the required floor
  on stderr;
- exempt endpoints (``ai quota --json`` via ``/api/entitlements`` and
  ``logout`` via ``/api/oauth/revoke``) and local commands (``--version``)
  keep working.

Under ``mode="log"`` with the same minimum, cloud commands succeed with zero
HTTP 426 responses.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness.fake_cloud.routes_ai import CONVERSATIONS_PATH
from e2e.harness.session_seed import read_session
from servonaut.services.version_policy import parse_client_signal

pytestmark = [pytest.mark.e2e_pr]

MINIMUM_VERSION = "99.0.0"


def test_cli_cloud_commands_report_update_required_while_exempt_and_local_work(
    journey, fake_cloud, cli, account_home,
):
    fake_cloud.configure(
        plan="teams",
        client_version_mode="enforce",
        client_minimum_version=MINIMUM_VERSION,
    )
    home = account_home("cli-version-gate-enforce")

    # Gated AI command fails cleanly with update-required copy on stderr.
    convs = cli(home, "ai", "conversations", "list")
    assert convs.returncode != 0, convs.describe()
    assert "too old for team and cloud features" in convs.stderr
    assert MINIMUM_VERSION in convs.stderr
    conv_reqs = fake_cloud.requests(CONVERSATIONS_PATH)
    assert conv_reqs and conv_reqs[-1]["status"] == 426
    assert parse_client_signal(conv_reqs[-1]["client_header"])[2] == "cli"

    # Gated team command also surfaces the 426 update-required message.
    team = cli(home, "team", "rules", "ops")
    assert team.returncode != 0, team.describe()
    assert "too old for team and cloud features" in team.stderr
    assert MINIMUM_VERSION in team.stderr
    assert fake_cloud.statuses("/api/v1/teams") == [200]
    assert fake_cloud.statuses("/api/v1/teams/ops/servers") == [426]

    # Local commands stay unaffected.
    version = cli(home, "--version")
    assert version.returncode == 0, version.describe()
    assert "servonaut" in version.stdout.lower()

    # Exempt /api/entitlements still works under enforce.
    quota = cli(home, "ai", "quota", "--json")
    assert quota.returncode == 0, quota.describe()
    assert json.loads(quota.stdout)["tokens_used"] == 1200
    assert fake_cloud.statuses("/api/entitlements")[-1] == 200

    # Exempt /api/oauth/revoke still lets the user sign out cleanly.
    logged_out = cli(home, "logout")
    assert logged_out.returncode == 0, logged_out.describe()
    assert read_session(home.home) is None
    assert fake_cloud.statuses("/api/oauth/revoke") == [200]


def test_cli_log_mode_allows_cloud_commands(journey, fake_cloud, cli, account_home):
    fake_cloud.configure(
        plan="teams",
        client_version_mode="log",
        client_minimum_version=MINIMUM_VERSION,
    )
    fake_cloud.ai.configure(
        conversations=[
            {
                "id": "conv-e2e-log-1",
                "title": "Health check on web-1",
                "status": "active",
                "created_at": "2030-01-01T09:00:00+00:00",
                "updated_at": "2030-01-01T09:05:00+00:00",
                "message_count": 2,
                "last_model": "",
            },
        ]
    )
    home = account_home("cli-version-gate-log")

    listed = cli(home, "ai", "conversations", "list")
    assert listed.returncode == 0, listed.describe()
    assert "conv-e2e-log-1" in listed.stdout
    (request,) = fake_cloud.requests(CONVERSATIONS_PATH)
    assert request["status"] == 200 and request["below_minimum"] is True
    assert parse_client_signal(request["client_header"])[2] == "cli"
    assert not any(req["status"] == 426 for req in fake_cloud.requests())
