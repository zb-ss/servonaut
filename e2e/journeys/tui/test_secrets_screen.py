"""Journey: the Secrets screen with Bitwarden stores, personal and team.

The (fake) service holds the user's personal secret-store choice: a
Bitwarden project and the name of the token variable. On the Secrets screen
a refresh reads it, and the screen reports Bitwarden as active with the
token set and ``bws`` installed (a scripted stand-in). The list shows the
project's secret *names* only (never a value) and filters them.

On a Teams plan the team's store wins over the personal one, which the
screen shows as shadowed. Clearing the cached team config falls back to
the personal store until the next refresh brings the team's back.
"""

from __future__ import annotations

import pytest
from rich.text import Text

from e2e.harness import fleet
from e2e.harness.bitwarden import FakeBitwarden
from e2e.harness.fake_cloud.wire import expected
from e2e.harness.session_seed import seed_session

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

TOKEN_VARIABLE = "BWS_ACCESS_TOKEN"
SECRETS = {
    "db/app-1": "fabricated-db-value-91d2",
    "hooks/deploy": "fabricated-hook-value-0b77",
}


def _seed(seed, fake_cloud, journey, monkeypatch) -> tuple[FakeBitwarden, str]:
    fake_cloud.configure(mcp_connections=0)
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    seed_session(seed.home, fake_cloud)
    vault = FakeBitwarden(journey.shims, tools=("bws",))
    project = vault.add_project("servers")
    for key, value in SECRETS.items():
        vault.add_secret(project, key, value)
    fake_cloud.secrets.set_personal(
        "bitwarden", {"project_id": project, "token_env_var": TOKEN_VARIABLE}
    )
    monkeypatch.setenv(TOKEN_VARIABLE, vault.access_token)
    return vault, project


def _pill(t) -> str:
    return Text.from_markup(str(t.on_screen("#secrets_status_pill").render())).plain


def _names(t) -> list[str]:
    return [str(w.render()) for w in t.find(".secrets_list_name")]


async def _refresh(t, count: int) -> None:
    await t.press("r")
    await t.wait_until(
        lambda: sum(m == "Secrets config refreshed." for _, m in t.toasts()) == count,
        desc=f"refresh #{count}",
    )


async def test_bitwarden_store_list_and_clear(tui, seed, fake_cloud, journey, monkeypatch):
    vault, project = _seed(seed, fake_cloud, journey, monkeypatch)
    async with tui() as t:
        await t.nav("nav_secrets")
        await t.wait_for_screen("SecretsScreen")
        await _refresh(t, 1)
        await t.wait_until(
            lambda: _pill(t) == "● Bitwarden (personal) — active", desc="Bitwarden active"
        )
        text = await t.wait_for_text(project, f"{TOKEN_VARIABLE} (set)")
        assert "not installed" not in text

        # Names only, never values.
        await t.press("l")
        await t.wait_for_screen("SecretsListScreen")
        await t.wait_until(lambda: sorted(_names(t)) == sorted(SECRETS), desc="secret names")
        text = await t.wait_for_text("bitwarden — 2 secrets")
        for value in SECRETS.values():
            assert value not in text
        await t.fill("#secrets_list_filter", "db/")
        await t.wait_until(lambda: _names(t) == ["db/app-1"], desc="filtered names")
        await t.wait_for_text("(showing 1 of 2)")
        calls = vault.calls("bws")
        assert calls and all(c.argv[-3:] == ["secret", "list", project] for c in calls)
        assert all(c.env[TOKEN_VARIABLE] and vault.access_token not in c.joined for c in calls)
    fake_cloud.assert_absent_on_wire(vault.access_token, *SECRETS.values())
    fake_cloud.assert_no_unexpected_errors(*expected("no secret store on file"))


async def test_team_store_shadows_personal_until_cleared(
    tui, seed, fake_cloud, journey, monkeypatch
):
    fake_cloud.configure(plan="teams")
    vault, personal = _seed(seed, fake_cloud, journey, monkeypatch)
    team = vault.add_project("team-servers")
    fake_cloud.secrets.set_team(
        "ops", "bitwarden", {"project_id": team, "token_env_var": TOKEN_VARIABLE}
    )
    async with tui() as t:
        await t.nav("nav_secrets")
        await t.wait_for_screen("SecretsScreen")
        await _refresh(t, 1)
        # The team's store wins; the personal one is shown as shadowed.
        await t.wait_until(
            lambda: _pill(t) == "● Bitwarden (team) — active", desc="team store active"
        )
        await t.wait_for_text(team, personal, "hidden by team config")

        await t.press("c")
        await t.wait_for_screen("ConfirmClearCacheModal")
        await t.click("#confirm_clear_yes")
        await t.wait_for_toast(r"^Secrets cache cleared\.$")
        await t.wait_until(
            lambda: _pill(t) == "● Bitwarden (personal) — active", desc="personal store"
        )

        await _refresh(t, 2)
        await t.wait_until(
            lambda: _pill(t) == "● Bitwarden (team) — active", desc="team store restored"
        )
    fake_cloud.assert_absent_on_wire(vault.access_token)
    fake_cloud.assert_no_unexpected_errors()
