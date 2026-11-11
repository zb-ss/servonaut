"""Layout defects found when every screen was looked at, as geometry checks.

Each test runs the same scenario as the screenshot of that screen, with the
real stylesheets, and asserts what a user would see: nothing clipped, nothing
scrolled out of view.
"""

from __future__ import annotations

from typing import Any

import pytest
from textual.widgets import Tree

from . import _geometry, test_screens

sizes = pytest.mark.parametrize("size", ["160x50", "100x30"])


@sizes
def test_help_topics_show_whole_labels_without_sideways_scroll(size: str) -> None:
    def check(pilot: Any) -> None:
        tree = pilot.app.screen.query_one("#help_topics Tree", Tree)
        assert tree.max_scroll_x == 0, "the topic list scrolls sideways"
    _geometry.run(test_screens._help, size, check, name="help")


def _strip_problems(pilot: Any) -> list:
    """Values the one-line details strip cuts, loses off its edge, or scrolls to."""
    from servonaut.widgets.fleet_values import FleetValueLine, ValueRow

    strip = pilot.app.screen.query_one(FleetValueLine)
    problems = []
    if strip.max_scroll_y or strip.max_scroll_x:
        problems.append("the strip scrolls")
    for row in strip.query(ValueRow):
        if not row.display:
            continue
        if not strip.region.contains_region(row.region):
            problems.append(f"{row.field} is beyond the strip")
        elif row.value_widget.content_size.width < len(row.value) and not strip.has_class("-flexible"):
            problems.append(f"{row.field} is cut")
    return problems


def _select(name: str):
    from . import _harness

    async def scenario(pilot: Any) -> None:
        await _harness.select_fleet_row(pilot, name)

    return scenario


@pytest.mark.parametrize("name", ["app-1", "web-1", "mail-1", "cache-1"])
def test_fleet_details_strip_shows_every_value_whole_at_100x30(name: str) -> None:
    def check(pilot: Any) -> None:
        assert _strip_problems(pilot) == []

    _geometry.run(_select(name), "100x30", check, name=f"fleet-strip-{name}")


async def _secrets_hub_unscrolled(pilot: Any) -> None:
    from tests.test_secrets_screen import _mock_auth, _mock_guard

    from . import _harness
    from .test_screens import _navigate

    pilot.app.auth_service = _mock_auth(plan="solo")
    pilot.app.entitlement_guard = _mock_guard(allow_secrets=True)
    screen = await _navigate(pilot, "nav_secrets", "SecretsScreen")
    await _harness.wait_until(
        pilot, lambda: bool(screen.query("ActionButton")), "the secrets actions",
    )


def test_secrets_hub_fits_its_cards_without_scrolling_at_100x30() -> None:
    def check(pilot: Any) -> None:
        body = pilot.app.screen.query_one("#secrets_body")
        cards = list(body.query(".secrets_card"))
        assert cards
        assert body.max_scroll_y == 0, "the cards need scrolling"
        for card in cards:
            assert body.region.contains_region(card.region), "a card is cut"

    _geometry.run(_secrets_hub_unscrolled, "100x30", check, name="secrets-hub")


@pytest.mark.parametrize("rules", ["in_force", "fallback"])
def test_team_cards_end_above_the_return_lane_at_100x30(rules: str) -> None:
    from . import test_teams

    scenario = test_teams._agent_rules_card(
        test_teams._RULES if rules == "in_force" else None, signed=rules == "in_force",
    )

    def check(pilot: Any) -> None:
        screen = pilot.app.screen
        back_row = screen.query_one("#team_return_actions")
        for card_id in ("configs_section", "agent_rules_section"):
            card = screen.query_one(f"#{card_id}")
            assert card.region.bottom <= back_row.region.y, f"{card_id} runs under the Back row"

    _geometry.run(scenario, "100x30", check, name=f"teams-{rules}")


def test_appearance_footer_ends_on_whole_labels_at_100x30() -> None:
    from textual.widgets import Footer

    from . import test_settings_appearance as appearance

    appearance._write_user_themes()

    async def scenario(pilot: Any) -> None:
        await appearance._open_appearance(pilot)
        pilot.app.screen.query_one("#theme_card_paper").focus()
        await pilot.pause()

    def check(pilot: Any) -> None:
        from textual.widgets._footer import FooterKey

        footer = pilot.app.screen.query_one(Footer)
        keys = list(footer.query(FooterKey))
        assert "Help" in [key.description for key in keys]
        for key in keys:
            assert key.region.right <= key.parent.region.right, f"{key.description!r} is cut"

    _geometry.run(scenario, "100x30", check, name="appearance-footer")


def test_ip_ban_banner_names_the_settings_category_in_sentence_case() -> None:
    from textual.widgets import Static

    def check(pilot: Any) -> None:
        hint = pilot.app.screen.query_one("#ip_ban_empty_hint", Static)
        assert "Settings → IP ban" in hint.visual.plain

    _geometry.run(test_screens._ip_ban, "100x30", check, name="ip-ban-banner")


def test_settings_help_text_has_no_title_case_leftovers() -> None:
    from servonaut.screens.settings.panels import ssh_keys

    assert "SSH keys screen" in ssh_keys._INFO_TEXT
    assert "Key Management" not in ssh_keys._INFO_TEXT


_LONG_SERVER = {
    "id": "i-0123456789abcdef0", "name": "a-rather-long-server-name-for-the-fleet-1",
    "type": "m7i-flex.metal-48xl", "state": "running", "public_ip": "9.9.9.9",
    "private_ip": "10.0.1.21", "region": "ap-southeast-2",
    "key_name": "a-long-key-pair-name-for-deploys", "provider": "AWS",
}


@pytest.mark.parametrize("size", [(100, 30), (80, 24)])
def test_fleet_details_strip_keeps_long_values_on_screen(size: tuple) -> None:
    from servonaut.widgets.fleet_values import FleetValueLine

    async def scenario(pilot: Any) -> None:
        strip = pilot.app.screen.query_one(FleetValueLine)
        strip.set_instance(dict(_LONG_SERVER))
        await pilot.pause()

    def check(pilot: Any) -> None:
        assert _strip_problems(pilot) == []

    _geometry.run(scenario, size, check, name="fleet-strip-long")


@pytest.mark.parametrize("size", [(100, 30), (80, 24)])
def test_fleet_details_strip_keeps_ordinary_values_on_screen(size: tuple) -> None:
    from servonaut.widgets.fleet_values import FleetValueLine

    async def scenario(pilot: Any) -> None:
        pilot.app.screen.query_one(FleetValueLine).set_instance(dict(_LONG_SERVER, name="app-1", key_name="deploy-key", type="t3.micro", region="us-east-1"))
        await pilot.pause()

    _geometry.run(scenario, size, lambda pilot: _assert_empty(_strip_problems(pilot)), name="fleet-strip-plain")


def _assert_empty(problems: list) -> None:
    assert problems == []


@pytest.mark.parametrize("nav_id,screen_name,table_id,title_id,rows", [
    ("nav_aws_manage", "AWSManagerScreen", "aws_mgr_table", "aws_mgr_header", 3),
    ("nav_ovh_manage", "OVHManagerScreen", "ovh_mgr_table", "ovh_mgr_header", 2),
    ("nav_hetzner_manage", "HetznerManagerScreen", "hetzner_mgr_table", "hetzner_mgr_header", 1),
])
def test_provider_managers_keep_title_and_table_in_view_at_100x30(
    nav_id: str, screen_name: str, table_id: str, title_id: str, rows: int,
) -> None:
    from .test_screens import _manager_of

    async def scenario(pilot: Any) -> None:
        await _manager_of(nav_id, screen_name, table_id, rows, 0)(pilot)
        pilot.app.screen.query_one(f"#{table_id}").focus()
        await pilot.pause()

    def check(pilot: Any) -> None:
        screen = pilot.app.screen
        assert screen.region.contains_region(screen.query_one(f"#{title_id}").region), "title out of view"
        container = screen.query_one(f"#{title_id.replace('header', 'container')}")
        assert container.region.contains_region(screen.query_one(f"#{table_id}").region)

    _geometry.run(scenario, "100x30", check, name=f"manager-{screen_name}")


@pytest.mark.parametrize("size", [(130, 40), (140, 40)])
def test_help_lists_its_topics_beside_the_manual_from_100_content_cells(size: tuple) -> None:
    def check(pilot: Any) -> None:
        screen = pilot.app.screen
        topics = screen.query_one("#help_topics")
        content = screen.query_one("#help_content")
        assert topics.region.height > 15, "the topic list is squeezed above the manual"
        assert topics.region.right <= content.region.x + 1
        assert screen.query_one("#help_topics Tree", Tree).max_scroll_x == 0

    _geometry.run(test_screens._help, size, check, name="help-wide")


def test_a_footer_shortcut_dropped_to_fit_still_works() -> None:
    from . import test_settings_appearance as appearance

    appearance._write_user_themes()

    async def scenario(pilot: Any) -> None:
        await appearance._open_appearance(pilot)
        pilot.app.screen.query_one("#theme_card_paper").focus()
        await pilot.pause()
        pilot.app.screen.refresh_bindings()
        await pilot.pause()

    def check(pilot: Any) -> None:
        bindings = pilot.app.screen.active_bindings
        hidden = [a for a in bindings.values() if not a.binding.show and a.binding.action == "open_folder"]
        assert hidden, "the open-folder key is no longer bound"
        assert any(a.binding.key == "o" for a in hidden)

    _geometry.run(scenario, "100x30", check, name="footer-dropped-key")
