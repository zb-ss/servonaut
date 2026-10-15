"""Journey: ``servonaut secrets`` against a fake Bitwarden Secrets Manager.

A signed-in Solo user with the ``bws`` CLI (a scripted stand-in) and an
access token in ``BWS_ACCESS_TOKEN`` runs ``servonaut secrets setup --yes``:
the only visible project is picked by name, the connection is tested by
listing its secrets, and the choice is saved to the (fake) service as a
pointer: the project id and the *name* of the token variable. The token
reaches ``bws`` through the environment only, never on its command line,
in a request or in the output. ``secrets status`` then says secrets are kept in
Bitwarden. Signed out, setup asks for a sign-in and never runs
``bws``.

``--token-env`` names another variable for the token; ``bws`` only reads
``BWS_ACCESS_TOKEN``, so that path is a known gap.
"""

from __future__ import annotations

import pytest

from e2e.harness.bitwarden import FakeBitwarden
from e2e.harness.fake_cloud.wire import expected
from e2e.harness.known_gap import KnownGap

pytestmark = [pytest.mark.e2e_pr]

TOKEN_VARIABLE = "BWS_ACCESS_TOKEN"
CUSTOM_VARIABLE = "E2E_BWS_TOKEN"
SECRET_VALUE = "fabricated-db-value-5c1e"


def _vault(journey) -> tuple[FakeBitwarden, str]:
    vault = FakeBitwarden(journey.shims, tools=("bws",))
    project = vault.add_project("servers")
    vault.add_secret(project, "db/app-1", SECRET_VALUE)
    return vault, project


def _assert_token_kept_out(vault, fake_cloud, *results) -> None:
    """The token and the stored secret reach neither the service nor the output."""
    for call in vault.calls("bws"):
        assert vault.access_token not in call.joined
    fake_cloud.assert_absent_on_wire(vault.access_token, SECRET_VALUE)
    for result in results:
        assert vault.access_token not in result.stdout + result.stderr
        assert SECRET_VALUE not in result.stdout + result.stderr


def test_setup_saves_a_pointer_and_status_reports_it(journey, fake_cloud, cli, account_home):
    vault, project = _vault(journey)
    journey.env_overrides[TOKEN_VARIABLE] = vault.access_token
    home = account_home("secrets-setup")

    before = cli(home, "secrets", "status")
    assert before.returncode == 0, before.describe()
    assert "Signed in on the Solo plan." in before.stdout
    assert "Secrets are kept in the local secret store (~/.servonaut/secrets.json)" in before.stdout
    assert "run `servonaut secrets setup`" in before.stdout

    setup = cli(home, "secrets", "setup", "--yes")
    assert setup.returncode == 0, setup.describe()
    out = setup.stdout
    assert f"1) servers  [{project}]" in out
    assert "Auto-selecting the only visible project: servers" in out
    assert "Connection OK — resolved 1 secret(s) in the project." in out
    assert "Your personal secret store is now Bitwarden." in out

    # bws was asked for the projects, then for this project's secrets, with
    # the token in its environment.
    calls = vault.calls("bws")
    assert [call.argv for call in calls] == [
        ["--output", "json", "project", "list"],
        ["--output", "json", "secret", "list", project],
    ]
    assert all(call.env[TOKEN_VARIABLE] for call in calls)

    saved = fake_cloud.secrets.personal()
    assert saved["provider"] == "bitwarden"
    assert saved["config"] == {"project_id": project, "token_env_var": TOKEN_VARIABLE}
    assert SECRET_VALUE not in out

    after = cli(home, "secrets", "status")
    assert after.returncode == 0, after.describe()
    assert (
        f"Secrets are kept in Bitwarden Secrets Manager (project {project}), chosen by you."
        in after.stdout
    )
    assert f"The access token is read from {TOKEN_VARIABLE}, which is set." in after.stdout
    assert "The bws program is not installed" not in after.stdout
    _assert_token_kept_out(vault, fake_cloud, before, setup, after)
    fake_cloud.assert_no_unexpected_errors(*expected("no secret store on file"))


def test_setup_signed_out_asks_for_login(journey, fake_cloud, cli, account_home):
    vault, _ = _vault(journey)
    journey.env_overrides[TOKEN_VARIABLE] = vault.access_token
    home = account_home("secrets-signed-out", signed_in=False)

    result = cli(home, "secrets", "setup", "--yes")
    assert result.returncode != 0, result.describe()
    assert "Sign in first with `servonaut login`" in result.stdout
    assert vault.calls("bws") == []
    assert fake_cloud.requests() == []


def test_setup_on_the_free_plan_names_the_plan_it_needs(journey, fake_cloud, cli, account_home):
    """A Free user is told which plan secrets need and where to upgrade, in words."""
    vault, _ = _vault(journey)
    journey.env_overrides[TOKEN_VARIABLE] = vault.access_token
    fake_cloud.configure(plan="free")
    home = account_home("secrets-free-plan")

    result = cli(home, "secrets", "setup", "--yes")
    assert result.returncode != 0, result.describe()
    assert result.stdout.strip() == (
        "Secrets management needs the Solo plan. "
        "Compare plans and upgrade at https://servonaut.dev/pricing."
    ), result.describe()
    assert vault.calls("bws") == []


def test_status_on_the_free_plan_points_at_the_plans(journey, fake_cloud, cli, account_home):
    """A Free user's status says where SSH keys come from and links the plans."""
    fake_cloud.configure(plan="free")
    home = account_home("secrets-free-status")

    result = cli(home, "secrets", "status")
    assert result.returncode == 0, result.describe()
    assert result.stdout.strip().splitlines() == [
        "Signed in on the Free plan.",
        "Your plan has no secret store (Solo and Teams plans do), so SSH keys "
        "are looked up in ~/.ssh.",
        "Plans: https://servonaut.dev/pricing",
    ], result.describe()


def test_setup_with_a_custom_token_variable(journey, fake_cloud, cli, account_home):
    vault, project = _vault(journey)
    journey.env_overrides[CUSTOM_VARIABLE] = vault.access_token
    home = account_home("secrets-custom-variable")

    setup = cli(home, "secrets", "setup", "--yes", "--token-env", CUSTOM_VARIABLE)
    calls = vault.calls("bws")
    if (
        setup.returncode != 0
        and "Missing access token" in setup.stdout
        and calls
        and not calls[0].env[TOKEN_VARIABLE]
    ):
        raise KnownGap("bws was run without BWS_ACCESS_TOKEN, so it saw no token")
    assert setup.returncode == 0, setup.describe()
    assert fake_cloud.secrets.personal()["config"] == {
        "project_id": project,
        "token_env_var": CUSTOM_VARIABLE,
    }
    _assert_token_kept_out(vault, fake_cloud, setup)
