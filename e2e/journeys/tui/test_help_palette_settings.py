"""Journeys: keyboard help, provider entries in the command palette, and two
settings panels.

``?`` opens the help from any screen and returns to where the user was.
The command palette offers the Hetzner and OVH destinations only when that
provider is configured, and they lead to the right screens. Vault entries
appear, in the palette and in the sidebar already on screen, once discovery
finishes. In Settings, the
search box finds a panel by keyword; the IP Lookup panel stores an AbuseIPDB
key as an environment-variable reference (showing whether it is set, never
its value), and choosing the MCP "Dangerous" guard level warns before it is
saved.
"""

from __future__ import annotations

import pytest
from textual.command import CommandList, CommandPalette

from e2e.harness import fleet
from e2e.harness.session_seed import seed_session

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

# Palette queries that only a configured provider can match (the letter z
# appears in no other command title).
PROVIDER_QUERIES = {
    "Hetzner Manage": "HetznerManagerScreen",
    "OVH DNS Zones": "OVHDNSScreen",
}

VAULT_PALETTE_DESTINATIONS = {
    "Go to Vault": "VaultScreen",
    "Go to SSH Certificates": "CaScreen",
}


async def _palette_results(t, query: str) -> list[str]:
    """Return filtered palette labels after Textual has finished its command search."""
    await t.press("ctrl+p")
    await t.wait_for_screen("CommandPalette")
    await t.type(query)
    command_list = t.on_screen(CommandList)

    def search_finished() -> bool:
        searching = any(
            worker.group == CommandPalette._GATHER_COMMANDS_GROUP and not worker.is_finished
            for worker in t.app.workers
        )
        return not searching and command_list.option_count > 0

    await t.wait_until(search_finished, desc=f"palette search for {query!r}")
    return [
        getattr(command_list.get_option_at_index(i).prompt, "plain", str(command_list.get_option_at_index(i).prompt))
        for i in range(command_list.option_count)
    ]


async def _palette_has_no_match(t, query: str) -> None:
    """Type *query* into the palette and require its "No matches found" result."""
    prompts = await _palette_results(t, query)
    assert len(prompts) == 1 and "No matches found" in prompts[0]

    await t.press("escape")
    await t.wait_until(lambda: t.screen_name() != "CommandPalette", desc="palette closed")


async def _palette_omits_native_vault(t) -> None:
    """The legacy BW destination may match ``Vault`` but native Vault may not."""
    prompts = await _palette_results(t, "Vault")
    assert "Go to Vault" not in prompts
    await t.press("escape")
    await t.wait_until(lambda: t.screen_name() != "CommandPalette", desc="palette closed")


async def test_provider_palette_entries_are_hidden_without_providers(tui, seed):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)

    async with tui() as t:
        for query in PROVIDER_QUERIES:
            await _palette_has_no_match(t, query)
        assert t.screen_name() == "InstanceListScreen"


async def test_vault_palette_entries_wait_for_discovery_and_open_native_screens(tui, seed, fake_cloud):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    seed_session(seed.home, fake_cloud)

    async with tui(size=(100, 30)) as t:
        await t.wait_until(lambda: t.app.vault_available, desc="Vault feature discovery")
        for command, screen in VAULT_PALETTE_DESTINATIONS.items():
            await t.palette(command)
            await t.wait_for_screen(screen)


async def test_vault_sidebar_entries_appear_on_the_open_screen_after_discovery(tui, seed, fake_cloud):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    seed_session(seed.home, fake_cloud)
    # A slow API makes discovery answer after the instance list is on screen,
    # which is the order a real network produces.
    fake_cloud.slow_down(1.0)

    async with tui() as t:
        first = await t.wait_for_screen("InstanceListScreen")
        assert not t.app.vault_available, "discovery answered before the first screen was up"
        assert not t.nav_reachable("nav_vault")

        await t.wait_until(lambda: t.app.vault_available, desc="Vault feature discovery")
        await t.wait_until(
            lambda: t.nav_reachable("nav_vault") and t.nav_reachable("nav_ca"),
            desc="Vault entries in the sidebar already on screen",
        )
        assert t.screen is first
        await t.nav("nav_vault")
        await t.wait_for_screen("VaultScreen")


async def test_vault_palette_entries_are_hidden_when_vault_is_unavailable(tui, seed):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)

    async with tui() as t:
        assert not t.app.vault_available
        await _palette_omits_native_vault(t)
        await _palette_has_no_match(t, "Go to SSH Certificates")


async def test_provider_palette_entries_lead_to_their_screens(tui, seed, providers):
    seed.config(hetzner=seed.hetzner_config(), ovh=seed.ovh_config())
    seed.cache(fleet.cache_rows(), fresh=True)
    fleet.seed_provider_fleet(providers)

    async with tui() as t:
        await t.palette("Go to Hetzner Manage")
        await t.wait_for_screen("HetznerManagerScreen")
        await t.wait_until(
            lambda: {host.name for host in fleet.HETZNER_FLEET}
            <= {row[1] for row in t.table_rows("#hetzner_mgr_table")},
            desc="Hetzner servers listed",
        )
        await t.palette("Go to OVH DNS Zones")
        await t.wait_for_screen("OVHDNSScreen")
    # Opening the screens only read from the providers.
    assert providers.mutations() == []


async def test_help_opens_from_a_provider_screen_and_returns_there(tui, seed, providers):
    seed.config(hetzner=seed.hetzner_config())
    seed.cache(fleet.cache_rows(), fresh=True)
    fleet.seed_provider_fleet(providers, ovh=False)

    async with tui() as t:
        await t.nav("nav_hetzner_manage")
        await t.wait_for_screen("HetznerManagerScreen")
        await t.press("question_mark")
        await t.wait_for_screen("HelpScreen")
        await t.wait_for_text("Servonaut — Help", "Instance List")
        await t.press("escape")
        await t.wait_for_screen("HetznerManagerScreen")


async def _open_settings_panel(t, search: str, panel_id: str) -> None:
    await t.nav("nav_settings")
    await t.wait_for_screen("SettingsScreen")
    await t.fill("#settings-search", search)
    button = t.on_screen(f"#navbtn_{panel_id}")
    await t.wait_until(lambda: t.is_reachable(button), desc=f"{panel_id} found by search")
    await t.click(button)
    await t.wait_until(
        lambda: t.is_reachable(t.on_screen(f"#save_{panel_id}")), desc=f"{panel_id} panel shown"
    )


async def test_ip_lookup_key_is_saved_as_an_env_reference(tui, seed):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)

    async with tui() as t:
        await _open_settings_panel(t, "abuse", "ip_lookup")
        await t.fill("#ip_lookup_abuseipdb_key Input", "$ABUSEIPDB_API_KEY")
        hint = t.on_screen("#ip_lookup_abuseipdb_key .envvar-hint")
        await t.wait_until(
            lambda: "$ABUSEIPDB_API_KEY → MISSING" in str(hint.render()),
            desc="environment variable reported missing",
        )
        await t.click("#save_ip_lookup")
        await t.wait_for_toast(r"^Saved$")

    assert seed.read_config()["abuseipdb_api_key"] == "$ABUSEIPDB_API_KEY"


async def test_dangerous_mcp_guard_level_warns_and_is_saved(tui, seed):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    assert seed.read_config()["mcp"]["guard_level"] == "standard"

    async with tui() as t:
        await _open_settings_panel(t, "guard", "mcp")
        select = t.on_screen("#mcp_guard_level")
        warning = t.on_screen("#mcp_guard_warn")
        assert "Dangerous" not in str(warning.render())
        # Tab to the guard level and open its list with Enter. (A mouse click
        # opens the list on press, so the release lands on the list itself.)
        for _ in range(12):
            if select.has_focus:
                break
            await t.press("tab")
        assert select.has_focus, t.focused_id()
        await t.press("enter")
        await t.wait_until(lambda: select.expanded, desc="guard level list open")
        await t.press("down", "enter")
        await t.wait_until(lambda: select.value == "dangerous", desc="Dangerous chosen")
        await t.wait_until(
            lambda: "'Dangerous' tier grants the MCP client elevated tool access"
            in str(warning.render()),
            desc="dangerous-level warning",
        )
        await t.click("#save_mcp")
        await t.wait_for_toast(r"^Saved$")

    assert seed.read_config()["mcp"]["guard_level"] == "dangerous"
