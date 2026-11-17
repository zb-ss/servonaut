"""A key cap takes no more room than the plain key hint did.

For each screen and size, the buttons that show their key, the buttons that
use their short words, and the number of lines of each action row are the
ones the screens had before key caps (recorded values).
"""

from __future__ import annotations

import pytest

from servonaut.widgets.action_button import ActionButton, ActionRow

from . import _geometry, _harness, test_screens as screens

_EXPECTED = {'manager_aws-100x30': {'hinted': ['btn_aws_mgr_new', 'btn_aws_mgr_reboot', 'btn_aws_mgr_refresh',
                                   'btn_aws_mgr_start', 'btn_aws_mgr_stop',
                                   'btn_aws_mgr_terminate'],
                        'rows': [1, 1, 1],
                        'short': []},
 'manager_aws-160x50': {'hinted': ['btn_aws_mgr_new', 'btn_aws_mgr_reboot', 'btn_aws_mgr_refresh',
                                   'btn_aws_mgr_start', 'btn_aws_mgr_stop',
                                   'btn_aws_mgr_terminate'],
                        'rows': [1, 1, 1],
                        'short': []},
 'manager_hetzner-100x30': {'hinted': ['btn_hetzner_mgr_delete', 'btn_hetzner_mgr_new',
                                       'btn_hetzner_mgr_power_on', 'btn_hetzner_mgr_reboot',
                                       'btn_hetzner_mgr_refresh', 'btn_hetzner_mgr_shutdown'],
                            'rows': [1, 1, 1],
                            'short': []},
 'manager_hetzner-160x50': {'hinted': ['btn_hetzner_mgr_delete', 'btn_hetzner_mgr_new',
                                       'btn_hetzner_mgr_power_on', 'btn_hetzner_mgr_reboot',
                                       'btn_hetzner_mgr_refresh', 'btn_hetzner_mgr_shutdown'],
                            'rows': [1, 1, 2],
                            'short': ['btn_hetzner_mgr_power_off', 'btn_hetzner_mgr_power_on',
                                      'btn_hetzner_mgr_reboot', 'btn_hetzner_mgr_shutdown']},
 'manager_ovh-100x30': {'hinted': ['btn_ovh_mgr_delete', 'btn_ovh_mgr_new', 'btn_ovh_mgr_reboot',
                                   'btn_ovh_mgr_refresh', 'btn_ovh_mgr_start', 'btn_ovh_mgr_stop'],
                        'rows': [1, 1, 1],
                        'short': []},
 'manager_ovh-160x50': {'hinted': ['btn_ovh_mgr_delete', 'btn_ovh_mgr_new', 'btn_ovh_mgr_reboot',
                                   'btn_ovh_mgr_refresh', 'btn_ovh_mgr_start', 'btn_ovh_mgr_stop'],
                        'rows': [1, 1, 1],
                        'short': []},
 'memory-100x30': {'hinted': ['btn_annotate', 'btn_build_ai', 'btn_clear_module', 'btn_enhance_ai',
                              'btn_export', 'btn_pin_key', 'btn_refresh_all', 'btn_refresh_module',
                              'btn_sync_now', 'btn_view_summary'],
                   'rows': [1, 1, 2, 2],
                   'short': ['btn_annotate', 'btn_build_ai', 'btn_clear_module', 'btn_enhance_ai',
                             'btn_export', 'btn_pin_key', 'btn_refresh_all', 'btn_refresh_module',
                             'btn_view_summary']},
 'memory-160x50': {'hinted': ['btn_annotate', 'btn_build_ai', 'btn_clear_module', 'btn_enhance_ai',
                              'btn_export', 'btn_pin_key', 'btn_refresh_all', 'btn_refresh_module',
                              'btn_sync_now', 'btn_view_summary'],
                   'rows': [1, 1, 1, 1],
                   'short': ['btn_build_ai', 'btn_enhance_ai']},
 'server_actions-100x30': {'hinted': ['btn_ai_analysis', 'btn_back', 'btn_ban_ip', 'btn_browse',
                                      'btn_command', 'btn_live', 'btn_logs', 'btn_scan', 'btn_scp',
                                      'btn_ssh'],
                           'rows': [1, 1, 1, 1, 1, 1],
                           'short': ['btn_db_creds', 'btn_findings', 'btn_manage_ssh_ref',
                                     'btn_memory', 'btn_use_vault_key', 'btn_verify_ssh']},
 'server_actions-160x50': {'hinted': ['btn_ai_analysis', 'btn_back', 'btn_ban_ip', 'btn_browse',
                                      'btn_command', 'btn_db_creds', 'btn_findings', 'btn_live',
                                      'btn_logs', 'btn_manage_ssh_ref', 'btn_memory', 'btn_scan',
                                      'btn_scp', 'btn_ssh', 'btn_use_vault_key', 'btn_verify_ssh'],
                           'rows': [1, 1, 1, 1, 1, 1],
                           'short': ['btn_manage_ssh_ref', 'btn_use_vault_key', 'btn_verify_ssh']},
 'server_actions_custom-100x30': {'hinted': ['btn_ai_analysis', 'btn_back', 'btn_ban_ip',
                                             'btn_browse', 'btn_command', 'btn_live', 'btn_logs',
                                             'btn_scan', 'btn_scp', 'btn_ssh'],
                                  'rows': [1, 1, 1, 1, 1, 1],
                                  'short': ['btn_db_creds', 'btn_findings', 'btn_manage_ssh_ref',
                                            'btn_memory', 'btn_use_vault_key', 'btn_verify_ssh']},
 'server_actions_custom-160x50': {'hinted': ['btn_ai_analysis', 'btn_back', 'btn_ban_ip',
                                             'btn_browse', 'btn_command', 'btn_db_creds',
                                             'btn_findings', 'btn_live', 'btn_logs',
                                             'btn_manage_ssh_ref', 'btn_memory', 'btn_scan',
                                             'btn_scp', 'btn_ssh', 'btn_use_vault_key',
                                             'btn_verify_ssh'],
                                  'rows': [1, 1, 1, 1, 1, 1],
                                  'short': ['btn_manage_ssh_ref', 'btn_use_vault_key',
                                            'btn_verify_ssh']}}

_CASES = {
    "server_actions": screens._server_actions,
    "server_actions_custom": screens._server_actions_of(_harness.CUSTOM_SERVERS[0].name),
    "memory": screens._memory,
    "manager_aws": screens._manager_of(
        "nav_aws_manage", "AWSManagerScreen", "aws_mgr_table", len(_harness.AWS_ROWS), 1),
    "manager_ovh": screens._manager_of(
        "nav_ovh_manage", "OVHManagerScreen", "ovh_mgr_table", len(_harness.OVH_ROWS), 0),
    "manager_hetzner": screens._manager_of(
        "nav_hetzner_manage", "HetznerManagerScreen", "hetzner_mgr_table", len(_harness.HETZNER_ROWS), 0),
}


@pytest.mark.parametrize("size", ["160x50", "100x30"])
@pytest.mark.parametrize("case", list(_CASES))
def test_buttons_keep_their_keys_and_rows(case: str, size: str) -> None:
    seen = {}

    def check(pilot) -> None:
        screen = pilot.app.screen
        shown = [b for b in screen.query(ActionButton) if b.display and b.region.height]
        seen["hinted"] = sorted(b.id or b.words for b in shown if b._key and b._hint)
        seen["short"] = sorted(b.id or b.words for b in shown if b._use_short)
        seen["rows"] = sorted(
            len({b.region.y for b in row.query(ActionButton) if b.display and b.region.height})
            for row in screen.query(ActionRow) if row.display and row.region.height
        )

    _geometry.run(_CASES[case], size, check, name=f"hints-{case}")
    assert seen == _EXPECTED[f"{case}-{size}"]
