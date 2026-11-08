"""Ordered list of stylesheet files that compose the Servonaut CSS bundle.

CSS_FILES is the single source of truth for the load order — import it from
app.py, memory.py, fleet_memory.py, and any test host that needs the full
stylesheet.  Textual evaluates CSS_PATH entries in sequence, so the list
order is the cascade order.  ``widen_parse_cache`` sizes Textual's parse
cache for a bundle this large.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from textual.css.stylesheet import Stylesheet

_S = Path(__file__).parent

# Textual keeps parsed rule sets in an LRU cache of 64 entries.  The bundle
# plus the DEFAULT_CSS of every widget class is well past that, so each
# parse after a widget class adds its DEFAULT_CSS (one per newly mounted class)
# evicted entries it was about to need and parsed the whole bundle again.
PARSE_CACHE_SIZE = 1024


def widen_parse_cache(stylesheet: Stylesheet) -> None:
    """Let *stylesheet* keep a parsed rule set for every CSS source it holds.

    Grows Textual's own cache in place, so a larger stock size is never
    shrunk. Does nothing if Textual stops exposing it, which only costs speed.
    A stylesheet copied by Textual's CSS live reload gets a stock cache again.
    """
    grow = getattr(getattr(stylesheet, "_parse_cache", None), "grow", None)
    if grow is not None:
        grow(PARSE_CACHE_SIZE)


CSS_FILES = [
    _S / "base.tcss",
    _S / "screens/main_menu.tcss",
    _S / "screens/instance_list.tcss",
    _S / "screens/server_actions.tcss",
    _S / "screens/settings.tcss",
    _S / "screens/settings_analysis.tcss",
    _S / "screens/settings_access.tcss",
    _S / "screens/settings_operations.tcss",
    _S / "screens/settings_appearance.tcss",
    _S / "screens/file_browser.tcss",
    _S / "screens/command_overlay.tcss",
    _S / "screens/settings_shared.tcss",
    _S / "screens/key_management.tcss",
    _S / "screens/scp_transfer.tcss",
    _S / "screens/scan_results.tcss",
    _S / "screens/command_picker.tcss",
    _S / "screens/log_picker.tcss",
    _S / "base_containers.tcss",
    _S / "widgets/static_text.tcss",
    _S / "screens/help.tcss",
    _S / "screens/log_viewer.tcss",
    _S / "screens/cloudtrail.tcss",
    _S / "screens/cloudwatch.tcss",
    _S / "screens/custom_servers.tcss",
    _S / "screens/ip_ban.tcss",
    _S / "screens/ai.tcss",
    _S / "screens/analysis_workspaces.tcss",
    _S / "base_dashboard.tcss",
    _S / "screens/instance_list_2.tcss",
    _S / "providers/_shared.tcss",
    _S / "screens/provider_managers.tcss",
    _S / "screens/compute_forms.tcss",
    _S / "screens/backup_workspaces.tcss",
    _S / "screens/resource_workspaces.tcss",
    _S / "screens/provider_account_resources.tcss",
    _S / "screens/provider_access.tcss",
    _S / "screens/provider_key_registry.tcss",
    _S / "screens/provider_lifecycle.tcss",
    _S / "screens/login.tcss",
    _S / "screens/ai_banners.tcss",
    _S / "screens/memory.tcss",
    _S / "screens/memory_bulk_share.tcss",
    _S / "screens/memory_finding.tcss",
    _S / "screens/secrets.tcss",
    _S / "screens/vault.tcss",
    _S / "screens/team_access.tcss",
    _S / "screens/bug_report_workspace.tcss",
    _S / "screens/db_vault.tcss",
    _S / "screens/findings.tcss",
    _S / "screens/memory_key_change.tcss",
    _S / "components/workspace.tcss",
    _S / "components/sidebar.tcss",
    _S / "components/dialogs.tcss",
    _S / "screens/credential_workspaces.tcss",
    _S / "screens/ai_choice_dialogs.tcss",
]
