"""SSH certificates on a service that has them switched off read as coming soon.

Real child commands run against the hermetic FakeCloud answering like the
hosted service before its signer is in place: every ``/ssh-ca`` route but the
KRL reads is a 503 ``feature_disabled`` naming ``ssh_ca``.
"""
from __future__ import annotations

import json

import pytest

from e2e.journeys.vault.test_cli_vault import (
    _VAULT_TEAM,
    _assert_only_getpass_tty_access,
    _configure_test_custody,
    _setup_with_recovery_confirmation,
)
from servonaut.services.vault.errors import SSH_CA_COMING_SOON

pytestmark = [pytest.mark.e2e_pr]


def test_ca_commands_say_coming_soon_and_change_nothing(journey, fake_cloud, cli, account_home, servonaut_cmd):
    fake_cloud.account.configure(teams=[_VAULT_TEAM])
    _configure_test_custody(journey)
    home = account_home("ca-coming-soon")
    setup, _ = _setup_with_recovery_confirmation(journey, home, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    fake_cloud.switch_off_ssh_ca()

    status = cli(home, "ca", "status", "--team", "example-team")
    assert status.returncode == 0, status.describe()
    assert status.stdout.strip() == SSH_CA_COMING_SOON
    assert "failed" not in status.stderr

    as_json = cli(home, "ca", "status", "--team", "example-team", "--json")
    assert as_json.returncode == 0, as_json.describe()
    assert json.loads(as_json.stdout) == {
        "enabled": False, "available": False, "reason": "feature_disabled", "message": SSH_CA_COMING_SOON,
    }

    enable = cli(home, "ca", "enable", "--team", "example-team", "--yes")
    assert enable.returncode == 1
    assert enable.stderr.strip() == f"{SSH_CA_COMING_SOON} Nothing was changed."
    assert "server text" not in enable.stderr and "not available right now" not in enable.stderr
    assert fake_cloud.statuses("/api/v1/teams/example-team/ssh-ca") == [503, 503, 503]
