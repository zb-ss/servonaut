"""Journeys: SSH verify while signed out, and reporting a bug.

Verify SSH needs a Servonaut account: signed out, the action explains that
and probes nothing. Reporting a bug starts with a consent dialog, collects
diagnostics with secrets scrubbed (API keys removed from the config
snapshot, passwords masked in the log excerpt), shows the exact report
before anything is sent, and then either opens a prefilled GitHub issue in
the browser or submits the report to the Servonaut API.
"""

from __future__ import annotations

import urllib.parse

import pytest

from e2e.harness import fleet
from e2e.harness.fake_cloud.routes_misc import BUG_REPORT_PREFIX
from e2e.harness.known_bugs import ProductBug

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

WEB_1 = fleet.WEB_1
# Fabricated secrets planted in the config and the log: neither may leave the machine.
API_KEY = "e2e-secret-value-0001"
LOG_PASSWORD = "e2e-pass-0001"
TITLE = "Fleet table stops refreshing"


class BugReportCarriesServerInventory(ProductBug):
    """The public GitHub issue draft carries the user's server hosts and logins."""


def _seed_home(seed) -> None:
    from servonaut.config.schema import CustomServer

    config = seed.build_config(
        custom_servers=[
            CustomServer(
                name=WEB_1.name,
                host=WEB_1.host,
                username=WEB_1.username,
                port=WEB_1.port,
                ssh_key=WEB_1.ssh_key,
            )
        ]
    )
    config.ai_provider.openai_api_key = API_KEY
    seed.data_dir.mkdir(parents=True, exist_ok=True)
    from servonaut.config.manager import ConfigManager

    ConfigManager(config_path=seed.config_path).save(config)
    seed.cache(fleet.cache_rows(), fresh=True)
    logs = seed.data_dir / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "servonaut.log").write_text(
        "2026-01-05 10:00:00 INFO servonaut.app: started\n"
        f"2026-01-05 10:00:01 ERROR servonaut.db: login refused password={LOG_PASSWORD}\n",
        encoding="utf-8",
    )


async def _collect(t, *, backend: bool = False, include_config: bool = True) -> str:
    """Open the report, answer the consent dialog, return the preview text."""
    await t.nav("nav_bug_report")
    await t.wait_for_screen("BugReportConsentModal")
    if backend:
        await t.click("#radio-backend")
        await t.wait_until(lambda: t.on_screen("#radio-backend").value, desc="backend chosen")
    if not include_config:
        await t.click("#chk-include-config")
        await t.wait_until(
            lambda: not t.on_screen("#chk-include-config").value, desc="config unchecked"
        )
    await t.click("#continue")
    await t.wait_for_screen("BugReportScreen")
    await t.wait_until(
        lambda: "collected" in str(t.on_screen("#diagnostics-status").render()),
        desc="diagnostics collected",
    )
    await t.wait_until(lambda: not t.on_screen("#submit").disabled, desc="submit enabled")
    return str(t.on_screen("#preview").render())


async def _submit(t) -> None:
    await t.fill("#title", TITLE)
    await t.click("#submit")
    await t.wait_until(
        lambda: "submitted" in str(t.on_screen("#diagnostics-status").render()),
        desc="report submitted",
    )


def _github_url(journey) -> str:
    calls = journey.shims.calls("browser")
    assert len(calls) == 1, calls
    return calls[0].argv[-1]


async def test_verify_ssh_asks_to_sign_in_first(tui, seed, journey):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)

    async with tui() as t:
        # From the fleet table, "v" opens the server's actions and starts verify.
        await t.select_instance(fleet.APP_1.name)
        await t.press("v")
        await t.wait_for_screen("ServerActionsScreen")
        await t.wait_for_toast(r"SSH verify requires a Servonaut account", severity="warning")

        # The same key on the actions screen answers the same way.
        before = len(t.toasts())
        await t.press("v")
        await t.wait_until(
            lambda: any(
                "SSH verify requires a Servonaut account" in message
                for _, message in t.toasts()[before:]
            ),
            desc="second sign-in notice",
        )
        assert t.screen_name() == "ServerActionsScreen"
    assert journey.shims.calls("ssh") == []


async def test_bug_report_preview_scrubs_secrets_and_opens_a_github_draft(tui, seed, journey):
    _seed_home(seed)

    async with tui() as t:
        preview = await _collect(t)
        # The config snapshot keeps the key's name but not its value; the log
        # excerpt keeps the line but masks the password.
        assert API_KEY not in preview
        assert '"openai_api_key": "<removed:secret-key>"' in preview
        assert LOG_PASSWORD not in preview
        assert "login refused password=<redacted:password>" in preview
        assert str(seed.home) not in preview
        # Nothing has been sent yet.
        assert journey.shims.calls("browser") == []

        await _submit(t)
        await t.wait_for_toast("Opened GitHub issue draft in your browser")
        await t.wait_until(lambda: journey.shims.calls("browser"), desc="browser opened")

    url = _github_url(journey)
    parsed = urllib.parse.urlsplit(url)
    assert (parsed.scheme, parsed.netloc, parsed.path) == (
        "https", "github.com", "/zb-ss/servonaut/issues/new"
    )
    query = urllib.parse.parse_qs(parsed.query)
    assert query["title"] == [TITLE]
    body = query["body"][0]
    assert body.startswith(f"# {TITLE}")
    for secret in (API_KEY, LOG_PASSWORD, str(seed.home)):
        assert secret not in body


async def test_github_draft_leaves_out_the_server_inventory(tui, seed, journey):
    _seed_home(seed)

    async with tui() as t:
        await _collect(t)
        await _submit(t)
        await t.wait_until(lambda: journey.shims.calls("browser"), desc="browser opened")

    body = urllib.parse.parse_qs(urllib.parse.urlsplit(_github_url(journey)).query)["body"][0]
    leaked = [value for value in (WEB_1.host, WEB_1.username) if value in body]
    if leaked:
        raise BugReportCarriesServerInventory(f"issue draft contains {leaked}")


async def test_bug_report_submitted_to_the_api_without_the_config(tui, seed, journey, fake_cloud):
    _seed_home(seed)

    async with tui() as t:
        preview = await _collect(t, backend=True, include_config=False)
        assert "## Config snapshot" not in preview
        assert WEB_1.host not in preview
        await _submit(t)
        message = await t.wait_for_toast(rf"Submitted as report {BUG_REPORT_PREFIX}\d+")
        assert f"{fake_cloud.url}/bug-reports/" in message

    posts = fake_cloud.requests("/api/v1/bug-reports", method="POST")
    assert len(posts) == 1
    sent = posts[0]["body"]
    assert sent["title"] == TITLE
    assert sent["payload"]["config_snapshot"] is None
    assert sent["payload"]["auth_state"] == "anonymous"
    assert LOG_PASSWORD not in str(sent)
    assert journey.shims.calls("browser") == []
