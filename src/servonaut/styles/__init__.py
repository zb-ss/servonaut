"""Ordered list of stylesheet files that compose the Servonaut CSS bundle.

CSS_FILES is the single source of truth for the load order — import it from
app.py, memory.py, fleet_memory.py, and any test host that needs the full
stylesheet.  Textual evaluates CSS_PATH entries in sequence, so the list
order is the cascade order.
"""
from pathlib import Path

_S = Path(__file__).parent

CSS_FILES = [
    _S / "base.tcss",
    _S / "screens/main_menu.tcss",
    _S / "screens/instance_list.tcss",
    _S / "screens/server_actions.tcss",
    _S / "screens/settings.tcss",
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
    _S / "base_dashboard.tcss",
    _S / "screens/instance_list_2.tcss",
    _S / "providers/_shared.tcss",
    _S / "screens/login.tcss",
    _S / "screens/ai_banners.tcss",
    _S / "screens/memory.tcss",
    _S / "screens/secrets.tcss",
    _S / "screens/db_vault.tcss",
]
