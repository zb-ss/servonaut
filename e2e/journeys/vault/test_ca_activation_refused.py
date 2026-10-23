"""A refused switch-on of SSH certificates says why, in the client's own words.

Real child commands run against the hermetic FakeCloud answering like the
hosted service when switching certificates on is paused, or while another
switch-on holds the service's activation lock.
"""
from __future__ import annotations

import pytest

from e2e.harness.fake_cloud.routes_vault import TEAM_SLUG
from e2e.journeys.vault.test_cli_vault import (
    _VAULT_TEAM,
    _assert_only_getpass_tty_access,
    _configure_test_custody,
    _setup_with_recovery_confirmation,
)

pytestmark = [pytest.mark.e2e_pr]


@pytest.mark.parametrize(("refusal", "status", "reason"), [
    ("frozen", 409, "switching on SSH certificates is paused on the Servonaut service for now; nothing is wrong "
                    "with your setup, so contact support at https://servonaut.dev/contact to ask for them for your team"),
    ("busy", 503, "the Servonaut service is busy switching on SSH certificates; nothing is wrong with your setup, "
                  "so try again in a minute"),
])
def test_ca_enable_explains_a_refused_switch_on_and_changes_nothing(
    journey, fake_cloud, cli, account_home, servonaut_cmd, refusal, status, reason,
):
    fake_cloud.account.configure(teams=[_VAULT_TEAM])
    _configure_test_custody(journey)
    home = account_home(f"ca-enable-{refusal}")
    setup, _ = _setup_with_recovery_confirmation(journey, home, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    fake_cloud.vault.refuse_ca_activation(refusal)

    enable = cli(home, "ca", "enable", "--team", TEAM_SLUG, "--yes")

    assert enable.returncode == 1, enable.describe()
    assert enable.stderr.strip() == f"CA request failed ({reason}).", enable.describe()
    assert "Try again shortly" not in enable.stderr and "Contact support." not in enable.stderr
    assert fake_cloud.statuses(f"/api/v1/teams/{TEAM_SLUG}/ssh-ca") == [status]
    assert fake_cloud.vault.ca_payload(TEAM_SLUG)["enabled"] is False

    # Once the service lets it through, the same command switches certificates on.
    fake_cloud.vault.refuse_ca_activation(None)
    again = cli(home, "ca", "enable", "--team", TEAM_SLUG, "--yes")
    assert again.returncode == 0, again.describe()
    assert fake_cloud.vault.ca_payload(TEAM_SLUG)["enabled"] is True
