"""Journey: the findings inbox and a gated, reversible remediation.

A signed-in Solo user opens Findings and sees what the (fake) service
detected. They open a request flood against edge-1 and run "Block the
source address": the server-signed preview shows the exact command under a
LIVE banner; they ask for a dry run first, type RUN, and the dry run passes
without touching the finding. Then the live run: Execute stays disarmed
until RUN is typed exactly, the client polls while the finding is
remediating, and it settles as resolved. The applied ban can be undone the
same way (preview, RUN, poll).

The confirmation gate holds: with anything but RUN typed, neither Enter
nor Execute sends anything, and Escape backs out without a request. A
preview already confirmed elsewhere is refused by the service, and the
user is told to start a fresh one.

Nothing runs anywhere: FakeCloud only records what was confirmed, with the
single-use token its preview signed for exactly that variant.
"""

from __future__ import annotations

import pytest
from rich.text import Text

from e2e.harness import fleet
from e2e.harness.fake_cloud.routes_findings import block_ip_remediation
from e2e.harness.fake_cloud.wire import expected
from e2e.harness.session_seed import seed_session

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

# A neutral public address as the flood's source (never one of the fleet's).
SOURCE_IP = "8.8.8.8"
FLOOD = "Request flood from one address"
CERT = "TLS certificate expires in 12 days"


def _seed(seed, fake_cloud) -> str:
    from servonaut.config.schema import IPBanConfig

    fake_cloud.configure(mcp_connections=0)
    seed.config(
        ip_ban_configs=[
            IPBanConfig(
                name="edge-waf",
                method="waf",
                region="us-east-1",
                ip_set_id="ipset-e2e",
                ip_set_name="e2e-blocklist",
            )
        ]
    )
    seed.cache(fleet.cache_rows(), fresh=True)
    seed_session(seed.home, fake_cloud)
    flood = fake_cloud.findings.add(
        instance_id=fleet.EDGE_1.instance_id,
        detector="web_traffic",
        rule="request_flood",
        title=FLOOD,
        description="One address sent most of the requests in the last five minutes.",
        severity="high",
        evidence={"source_ip": SOURCE_IP, "requests_5m": 4200},
        remediations=[block_ip_remediation()],
    )
    fake_cloud.findings.add(
        instance_id=fleet.APP_1.instance_id,
        detector="tls",
        rule="cert_expiry",
        title=CERT,
        severity="low",
        status="acked",
        remediations=[
            {
                "action": "investigate",
                "label": "Check the renewal job",
                "risk_tier": "none",
                "reversible": True,
            }
        ],
    )
    return flood


def _plain(value: object) -> str:
    return Text.from_markup(str(value)).plain


def _text(t, selector: str) -> str:
    return _plain(t.on_screen(selector).render())


async def _in_view(t, selector: str) -> None:
    """Scroll a freshly rendered button into view, as a user would."""
    screen = t.app.screen.region

    def visible() -> bool:
        widget = t.on_screen(selector)
        widget.scroll_visible(animate=False, immediate=True)
        return widget.region.height > 0 and screen.contains_region(widget.region)

    await t.wait_until(visible, desc=f"{selector} in view")


async def _open_preview(t, button: str, banner: str) -> None:
    await _in_view(t, button)
    await t.click(button)
    await t.wait_for_screen("RemediationConfirmModal")
    await t.wait_until(
        lambda: banner in _text(t, "#remediation_confirm_header"), desc=f"{banner} banner"
    )


def _posts(fake_cloud, finding: str) -> list[dict]:
    """Remediation and revert requests sent for *finding*."""
    return [
        r for r in fake_cloud.requests()
        if r["method"] == "POST" and r["path"].startswith(f"/api/v1/findings/{finding}/")
    ]


async def _open_flood(t) -> None:
    await t.nav("nav_findings")
    await t.wait_for_screen("FindingsScreen")
    await t.wait_until(lambda: t.table_rows("#findings_table"), desc="findings")
    # Click the flood's row (the first one, under the header).
    assert await t.pilot.click("#findings_table", offset=(2, 1))
    await t.wait_for_screen("FindingDetailScreen")


async def _confirm(t) -> None:
    """Type RUN and press Execute, as the modal requires."""
    await t.fill("#remediation_confirm_input", "RUN")
    await t.wait_until(lambda: not t.on_screen("#remediation_confirm_run").disabled, desc="armed")
    await t.click("#remediation_confirm_run")
    await t.wait_for_screen("FindingDetailScreen")


async def test_inbox_dry_run_remediate_and_undo(tui, seed, fake_cloud):
    flood = _seed(seed, fake_cloud)
    async with tui() as t:
        await t.nav("nav_findings")
        await t.wait_for_screen("FindingsScreen")
        rows = await t.wait_until(lambda: t.table_rows("#findings_table"), desc="findings")
        assert [[_plain(cell) for cell in row[:5]] for row in rows] == [
            ["high", "detected", "edge-1", "web_traffic", FLOOD],
            ["low", "acked", "app-1", "tls", CERT],
        ]

        await _open_flood(t)
        assert _text(t, "#finding_detail_pill") == "high · detected · personal"
        await t.wait_for_text(f"source_ip: {SOURCE_IP}")

        # The live preview offers a dry run first.
        await _open_preview(t, "#btn_finding_remediate_0", "LIVE EXECUTION")
        command = _text(t, "#remediation_confirm_command")
        assert f"ban {SOURCE_IP} via waf" in command
        await t.click("#remediation_confirm_dry_run")
        await t.wait_until(
            lambda: "DRY RUN" in _text(t, "#remediation_confirm_header"), desc="dry-run preview"
        )
        await _confirm(t)
        await t.wait_for_toast(r"^Dry run passed — the live remediation should work\.")
        assert fake_cloud.findings.get(flood)["status"] == "detected"
        assert _text(t, "#finding_detail_pill") == "high · detected · personal"

        # Live: Execute stays disarmed until RUN is typed exactly.
        fake_cloud.findings.hold_next_run(flood)
        await _open_preview(t, "#btn_finding_remediate_0", "LIVE EXECUTION")
        await t.fill("#remediation_confirm_input", "run")
        assert t.on_screen("#remediation_confirm_run").disabled
        await _confirm(t)
        await t.wait_for_toast(r"^Remediation is running server-side")
        await t.wait_for_toast(r"^Remediation succeeded — finding resolved\.$")
        # The client polled while the finding was remediating.
        assert fake_cloud.findings.served_statuses(flood)[-2:] == ["remediating", "resolved"]
        await t.wait_until(
            lambda: _text(t, "#finding_detail_pill") == "high · resolved · personal",
            desc="resolved pill",
        )
        # A resolved finding offers no further Run, only the Undo.
        await t.wait_until(lambda: not t.find("#btn_finding_remediate_0"), desc="no Run")

        # The ban left a revertible handle: undo it.
        await _open_preview(t, "#btn_finding_revert", "LIVE EXECUTION")
        assert f"unban {SOURCE_IP} via waf" in _text(t, "#remediation_confirm_command")
        await _confirm(t)
        await t.wait_for_toast(r"^Undo succeeded — the IP is no longer blocked\.$")

    assert fake_cloud.findings.executed() == [
        {"finding_id": flood, "kind": "remediate", "action": "block_ip",
         "dry_run": True, "method": "waf"},
        {"finding_id": flood, "kind": "remediate", "action": "block_ip",
         "dry_run": False, "method": "waf"},
        {"finding_id": flood, "kind": "revert", "action": "unblock_ip",
         "dry_run": False, "method": "waf"},
    ]
    final = fake_cloud.findings.get(flood)
    assert final["status"] == "resolved"
    assert final["last_revert"]["status"] == "succeeded"
    # Each confirmation spent its own single-use token.
    posts = _posts(fake_cloud, flood)
    assert [r["status"] for r in posts] == [202, 202, 202]
    tokens = [r["body"]["confirm_token"] for r in posts]
    assert len(set(tokens)) == 3
    fake_cloud.assert_no_unexpected_errors(*expected("no secret store on file"))


async def test_nothing_runs_without_a_valid_confirmation(tui, seed, fake_cloud):
    flood = _seed(seed, fake_cloud)
    async with tui() as t:
        await _open_flood(t)

        # Anything but RUN: neither Enter nor Execute sends a request.
        await _open_preview(t, "#btn_finding_remediate_0", "LIVE EXECUTION")
        await t.fill("#remediation_confirm_input", "run")
        await t.press("enter")
        execute = t.on_screen("#remediation_confirm_run")
        assert execute.disabled
        await t.pilot.click(execute)
        await t.settle()
        assert t.screen_name() == "RemediationConfirmModal"
        assert _posts(fake_cloud, flood) == []

        # Escape backs out without a request.
        await t.press("escape")
        await t.wait_for_screen("FindingDetailScreen")
        await t.settle()
        assert _posts(fake_cloud, flood) == []

        # A preview confirmed elsewhere in the meantime is refused.
        await _open_preview(t, "#btn_finding_remediate_0", "LIVE EXECUTION")
        # Spends this preview's token and the abandoned one's.
        assert fake_cloud.findings.consume_open_previews(flood) == 2
        await _confirm(t)
        await t.wait_for_toast(
            r"^This remediation preview was already used\. Re-open the finding to start "
            r"a fresh preview\.$",
            severity="warning",
        )
        assert [r["status"] for r in _posts(fake_cloud, flood)] == [409]
        assert _text(t, "#finding_detail_pill") == "high · detected · personal"

    assert fake_cloud.findings.executed() == []
    assert fake_cloud.findings.get(flood)["status"] == "detected"
    fake_cloud.assert_no_unexpected_errors(
        *expected("no secret store on file"),
        ("POST", f"/api/v1/findings/{flood}/remediate", 409),
    )
