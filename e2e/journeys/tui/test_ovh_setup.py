"""Journey: connect OVHcloud from Settings with the setup wizard.

A user without OVH opens Settings, the OVHcloud panel and its setup
wizard. Testing the connection needs credentials, reports a refused key
as a failure and a working one with the account's handle. Saving enables
the provider at once, without a restart: the OVH servers join the fleet
and the OVH sections appear in the sidebar. Nothing at OVH is changed.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.fake_providers.ovh import NIC_HANDLE
from e2e.journeys.tui.ovh_ui import press

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]


async def _open_settings_panel(t, panel_id: str) -> None:
    """Expand the panel's group in the Settings rail if needed, then open it."""
    from servonaut.widgets.sidebar_section import SidebarSection

    button = t.on_screen(f"#navbtn_{panel_id}")
    section = next(node for node in button.ancestors if isinstance(node, SidebarSection))
    if section.collapsed:
        await t.click(section.query_one("Button.section-header"))
        await t.wait_until(lambda: not section.collapsed, desc=f"{panel_id} group expanded")
    await press(t, button)


async def test_setup_wizard_tests_and_enables_ovh(tui, seed, providers):
    seed.config()
    seed.cache(fleet.cache_rows(fleet.APP_1), fresh=True)
    fleet.seed_provider_fleet(providers, hetzner=False)

    async with tui() as t:
        assert not t.nav_reachable("nav_ovh_manage")
        await t.nav("nav_settings")
        await t.wait_for_screen("SettingsScreen")
        await _open_settings_panel(t, "ovh")
        await t.wait_until(
            lambda: "Status: Not configured" in str(t.on_screen("#ovh_status_display").render()),
            desc="OVH panel",
        )
        await press(t, "#ovh_btn_setup")
        await t.wait_for_screen("OVHSetupScreen")
        assert t.on_screen("#ovh_input_endpoint").value == "ovh-eu"

        await press(t, "#btn_ovh_test")
        await t.wait_for_toast(
            "Enter at least Application Key and Consumer Key", severity="warning"
        )
        assert not providers.requests("ovh")

        await t.fill("#ovh_input_app_key", "ak-fake")
        await t.fill("#ovh_input_app_secret", "as-fake")
        await t.fill("#ovh_input_consumer_key", "ck-fake")
        await t.fill("#ovh_input_project_ids", fleet.OVH_PROJECT_ID)

        providers.ovh.fail_with = "INVALID_CREDENTIAL"
        await press(t, "#btn_ovh_test")
        await t.wait_for_toast("OVH connection failed: Authentication failed", severity="error")
        result = t.on_screen("#ovh_test_result")
        await t.wait_until(
            lambda: "Connection failed" in str(result.render()), desc="failure shown"
        )

        providers.ovh.fail_with = None
        await press(t, "#btn_ovh_test")
        await t.wait_until(
            lambda: len(providers.requests("ovh", method="GET", path="/me")) == 2,
            desc="second connection test sent",
        )
        await t.wait_for_toast(f"OVH connected as: {NIC_HANDLE}")
        assert f"Connection successful! Account: {NIC_HANDLE}" in t.rendered_text()
        assert len(providers.requests("ovh", method="GET", path="/me")) == 2

        await press(t, "#btn_ovh_save")
        await t.wait_for_toast("OVH configuration saved")
        await t.wait_for_toast(r"OVH enabled — 5 instances loaded")
        await t.wait_for_screen("SettingsScreen")

        saved = seed.read_config()["ovh"]
        assert saved["enabled"] is True
        assert saved["application_key"] == "ak-fake"
        assert saved["cloud_project_ids"] == [fleet.OVH_PROJECT_ID]

        # Live at once: the fleet lists the OVH servers and the sidebar offers OVH.
        await t.nav("nav_list")
        await t.wait_for_screen("InstanceListScreen")
        await t.wait_until(
            lambda: {fleet.OVH_VPS_MAIL_1.display_name, fleet.OVH_BATCH_1.name}
            <= {row[1] for row in t.table_rows("InstanceTable")},
            desc="OVH servers in the fleet",
        )
        assert t.nav_reachable("nav_ovh_manage")

    assert providers.mutations("ovh") == []
