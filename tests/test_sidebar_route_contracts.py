"""Compact navigation retains independent provider and entitlement gates."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from textual.widgets import Button

from servonaut.config.schema import AppConfig
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.sidebar_section import SidebarSection
from tests.test_sidebar_presentation import _SidebarHost

# These destination sets pin the publicly reachable controls for each provider.
COMPUTE_ROUTES = {
    "ovh": {
        "nav_ovh_manage", "nav_ovh_dns", "nav_ovh_ips", "nav_ovh_storage",
        "nav_ovh_billing", "nav_ovh_ssh_keys",
    },
    "hetzner": {"nav_hetzner_manage", "nav_hetzner_ssh_keys"},
}
AWS_ROUTES = {"nav_aws_manage", "nav_cloudwatch", "nav_ip_ban", "nav_cloudtrail"}


def _reachable_routes(section: SidebarSection) -> set[str]:
    if not section.display:
        return set()
    section.expand()
    return {
        button.id for button in section.query(".nav-button")
        if button.display and button.id is not None
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["ovh", "hetzner"])
@pytest.mark.parametrize(
    "compute,s3", [(False, False), (True, False), (False, True), (True, True)],
)
async def test_compute_and_object_storage_independently_gate_destinations(
    provider: str, compute: bool, s3: bool,
) -> None:
    app = _SidebarHost(all_providers=False)
    setattr(app, f"{provider}_service", object() if compute else None)
    setattr(app, f"{provider}_object_storage_service", object() if s3 else None)
    expected = set(COMPUTE_ROUTES[provider]) if compute else set()
    if s3:
        expected.add(f"nav_{provider}_s3")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        section = app.screen.query_one(f"#section_{provider}", SidebarSection)
        assert _reachable_routes(section) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "enabled,s3", [(False, False), (False, True), (True, False), (True, True)],
)
async def test_aws_switch_and_object_storage_keep_distinct_gates(
    enabled: bool, s3: bool,
) -> None:
    app = _SidebarHost(all_providers=False)
    config = AppConfig()
    config.aws.enabled = enabled
    app.config_manager = SimpleNamespace(get=lambda: config)
    app.aws_object_storage_service = object() if s3 else None
    expected = set(AWS_ROUTES) if enabled else set()
    if enabled and s3:
        expected.add("nav_aws_s3")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        section = app.screen.query_one("#section_aws", SidebarSection)
        assert _reachable_routes(section) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "entitled,configured", [(False, False), (True, False), (True, True)],
)
async def test_optional_account_routes_keep_entitlement_and_sync_gates(
    entitled: bool, configured: bool,
) -> None:
    app = _SidebarHost()
    app.auth_service = SimpleNamespace(
        is_authenticated=entitled, has_feature=lambda _feature: entitled,
    )
    app.memory_sync_service = SimpleNamespace(is_configured=configured)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        sidebar = app.screen.query_one(Sidebar)
        expected = {
            "nav_teams": entitled,
            "nav_sync_config": entitled,
            "nav_drift": entitled and configured,
            "nav_memory_export": entitled and configured,
            "nav_memory_sync": True,
        }
        assert {
            route: sidebar.query_one(f"#{route}", Button).display for route in expected
        } == expected
