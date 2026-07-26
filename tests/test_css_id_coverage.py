"""CSS-ID coverage sanity test.

For every ``id="..."`` literal in ``src/servonaut/screens/**/*.py``, asserts
that the ``src/servonaut/styles/`` CSS bundle contains at least one ``#id`` CSS selector
(anchored on following whitespace or punctuation so ``#foo_bar`` does not
match ``#foo_bar_baz``).

IDs that intentionally rely on global widget styling (Button, Input,
DataTable default rules, etc.) are listed in ``ACCEPTABLE_UNSTYLED`` with a
one-line reason comment.  Do NOT add IDs here silently — use a reason comment
that distinguishes "intentionally inherits global" from a genuine oversight.
"""
from __future__ import annotations

import pathlib
import re

from servonaut.styles import CSS_FILES

SCREENS_DIR = (
    pathlib.Path(__file__).parent.parent / "src" / "servonaut" / "screens"
)

# ---------------------------------------------------------------------------
# IDs that intentionally rely on global widget or container styling.
# ---------------------------------------------------------------------------
ACCEPTABLE_UNSTYLED: frozenset[str] = frozenset(
    [
        # ---- Account / profile widgets ----
        "account_info",         # Reason: Static label; inherits global Static styling
        "account_info_header",  # Reason: Static header; inherits global Static styling
        # ---- Add-rule / add-path inline forms ----
        "add_rule_title",       # Reason: Static title inside inline form; no special styling needed
        # ---- AI screens — empty-state, fallback, picker, topup modals ----
        # All are VerticalScroll/Vertical containers or Static labels within
        # ModalScreen/Screen widgets that are fully styled by the surrounding
        # screen CSS.  No per-ID rule is needed.
        "ai_empty_body",
        "ai_empty_buttons",
        "ai_empty_container",
        "ai_empty_title",
        "ai_fallback_body",
        "ai_fallback_buttons",
        "ai_fallback_container",
        "ai_fallback_keep",
        "ai_fallback_no_alternate",
        "ai_fallback_reason",
        "ai_fallback_title",
        "ai_picker_body",
        "ai_picker_buttons",
        "ai_picker_container",
        "ai_picker_existing",
        "ai_picker_title",
        "ai_status",            # Reason: Dynamic status Static; styled by content text color
        "ai_topup_body",
        "ai_topup_buttons",
        "ai_topup_cancel",
        "ai_topup_container",
        "ai_topup_reason",
        "ai_topup_title",
        # ---- Attach-volume form ----
        "attach_vol_form",      # Reason: Form container; inherits .ip_form_panel-style via parent
        # ---- AWS create wizard sub-tables ----
        # Styled via the container rule (#aws_create_container DataTable) in CSS.
        "aws_amis_table",
        "aws_input_ami_search", # Reason: Input; inherits global Input + .setting_row Input
        "aws_input_name",       # Reason: Input; inherits global Input styling
        "aws_keys_table",       # Reason: DataTable; styled via #aws_create_container DataTable
        "aws_regions_table",    # Reason: DataTable; styled via #aws_create_container DataTable
        "aws_sg_table",         # Reason: DataTable; styled via #aws_create_container DataTable
        "aws_status_label",     # Reason: Dynamic status Static; updated at runtime, no static style
        "aws_subnets_table",    # Reason: DataTable; styled via #aws_create_container DataTable
        "aws_types_table",      # Reason: DataTable; styled via #aws_create_container DataTable
        # ---- Generic button IDs ----
        # All Button widgets inherit Textual's default Button styling + any
        # container-scoped rules (e.g. #s3_actions Button).  Per-button ID
        # rules are only added when a button needs a distinct appearance.
        "back",
        "backup_section_title", # Reason: Static section title; inherits global .section_header
        "backup_status",        # Reason: Dynamic status Static; no static styling
        "billing_title",        # Reason: Static title; inherits global heading style
        "btn_add",
        "btn_add_agent",
        "btn_add_key",
        "btn_add_mapping",
        "btn_add_path",
        "btn_add_rule",
        "btn_add_server",
        "btn_ai_analysis",
        "btn_ai_provider_reset",
        "btn_ai_servonaut_upgrade",
        "btn_allow",
        "btn_analyze",
        "btn_annotate",
        "btn_attach",
        "btn_aws_create_back",
        "btn_aws_create_submit",
        "btn_aws_mgr_new",
        "btn_aws_mgr_reboot",
        "btn_aws_mgr_refresh",
        "btn_aws_mgr_start",
        "btn_aws_mgr_stop",
        "btn_aws_mgr_terminate",
        "btn_back",
        "btn_backup_restore",
        "btn_ban",
        "btn_ban_ip",
        "btn_bkp_no",
        "btn_bkp_refresh",
        "btn_bkp_restore",
        "btn_bkp_yes",
        "btn_browse",
        "btn_build_ai",
        "btn_cancel",
        "btn_cancel_attach",
        "btn_cancel_form",
        "btn_cancel_login",
        "btn_cancel_snapshot",
        "btn_clear",
        "btn_clear_module",
        "btn_close",
        "btn_command",
        "btn_configure_backup",
        "btn_confirm",
        "btn_confirm_attach",
        "btn_confirm_no",
        "btn_confirm_snapshot",
        "btn_confirm_yes",
        "btn_convs_archive",
        "btn_convs_delete",
        "btn_convs_export",
        "btn_convs_more",
        "btn_convs_open",
        "btn_convs_refresh",
        "btn_create",
        "btn_create_team",
        "btn_dangerous_cancel",
        "btn_dangerous_confirm",
        "btn_delete",
        "btn_delete_key",
        "btn_delete_rule",
        "btn_deny",
        "btn_detach",
        "btn_details",
        "btn-drift-ack",        # Reason: Button; inherits global Button styling
        "btn-drift-refresh",    # Reason: Button; inherits global Button styling
        "btn-drift-unack",      # Reason: Button; inherits global Button styling
        "btn_edit",
        "btn_empty_add_key",
        "btn_empty_ollama",
        "btn_empty_probe",
        "btn_empty_subscribe",
        "btn_export",
        "btn-export-back",      # Reason: Button; inherits global Button styling
        "btn_export_cancel",
        "btn_export_save",
        "btn-export-start",     # Reason: Button; inherits global Button styling
        "btn_fallback_keep",
        "btn_fetch_logs",
        "btn_filter_apply",
        "btn_filter_clear",
        # ---- Findings screens (proactive monitoring) ----
        # All Buttons; styled by the #findings_actions / #finding_detail_actions
        # container rules + global Button styling.
        "btn_finding_ack",
        "btn_finding_back",
        "btn_finding_resolve",
        "btn_finding_revert",   # Undo button; inherits .finding_remediation_run + global Button styling
        "btn_finding_suppress",
        "btn_findings",         # Reason: server-actions rail Button; inherits #action_buttons styling
        "btn_findings_open",
        "btn_findings_refresh",
        "btn_findings_scan",
        "btn_findings_severity_filter",
        "btn_findings_status_filter",
        "btn_hetzner_back",
        "btn_hetzner_create_back",
        "btn_hetzner_create_submit",
        "btn_hetzner_disable",
        "btn_hetzner_mgr_delete",
        "btn_hetzner_mgr_new",
        "btn_hetzner_mgr_power_off",
        "btn_hetzner_mgr_power_on",
        "btn_hetzner_mgr_reboot",
        "btn_hetzner_mgr_refresh",
        "btn_hetzner_mgr_shutdown",
        "btn_hetzner_save",
        "btn_hetzner_setup",
        "btn_hetzner_ssh_add",
        "btn_hetzner_ssh_back",
        "btn_hetzner_ssh_cancel",
        "btn_hetzner_ssh_delete",
        "btn_hetzner_ssh_refresh",
        "btn_hetzner_ssh_save",
        "btn_hetzner_test",
        "btn_invite",
        "btn_ipban_add",
        "btn_ipban_cancel",
        "btn_ipban_discover",
        "btn_ipban_edit",
        "btn_ipban_remove",
        "btn_ipban_save",
        "btn_label_cancel",
        "btn_label_save",
        "btn_list_agent",
        "btn_local_delete",
        "btn_local_more",
        "btn_local_open",
        "btn_local_refresh",
        "btn_logs",
        "btn_memory",
        "btn_move",
        "btn_move_confirm",
        "btn_msync_reload",
        "btn_msync_save",
        "btn_next_page",
        "btn_no",
        "btn_open",
        "btn_open_memory_sync_setup",
        "btn_ovh_back",
        "btn_ovh_disable",
        "btn_ovh_firewall",
        "btn_ovh_mgr_delete",
        "btn_ovh_mgr_new",
        "btn_ovh_mgr_reboot",
        "btn_ovh_mgr_refresh",
        "btn_ovh_mgr_start",
        "btn_ovh_mgr_stop",
        "btn_ovh_monitoring",
        "btn_ovh_reinstall",
        "btn_ovh_request_ck",
        "btn_ovh_resize",
        "btn_ovh_save",
        "btn_ovh_setup",
        "btn_ovh_snapshots",
        "btn_ovh_test",
        "btn_passphrase_cancel",
        "btn_passphrase_ok",
        "btn_pick_existing",
        "btn_pick_servonaut",
        "btn_pin_key",
        "btn_prev_page",
        "btn_pull_latest",
        "btn_push_new",
        "btn_rdns",
        "btn_rdns_cancel",
        "btn_rdns_delete",
        "btn_rdns_edit",
        "btn_rdns_reload",
        "btn_rdns_save",
        "btn_rdns_set",
        "btn_refresh",
        "btn_refresh_all",
        "btn_refresh_module",
        "btn_refresh_stale",
        "btn_refresh_view",
        "btn_refresh_zone",
        "btn_reinstall",
        "btn_remove",
        "btn_remove_server",
        "btn_rename",
        "btn_restore",
        "btn-row",              # Reason: Horizontal layout row for buttons; inherits layout
        "btn_row",              # Reason: Horizontal layout row for buttons; inherits layout
        "btn_s3_back",
        "btn_s3_cancel_bucket",
        "btn_s3_cancel_copy",
        "btn_s3_cancel_download",
        "btn_s3_cancel_move",
        "btn_s3_cancel_upload",
        "btn_s3_close_url",
        "btn_s3_copy",
        "btn_s3_delete",
        "btn_s3_do_copy",
        "btn_s3_do_download",
        "btn_s3_do_move",
        "btn_s3_do_upload",
        "btn_s3_download",
        "btn_s3_move",
        "btn_s3_new_bucket",
        "btn_s3_open",
        "btn_s3_refresh",
        "btn_s3_save_bucket",
        "btn_s3_share",
        "btn_s3_up",
        "btn_s3_upload",
        "btn_save",
        "btn_save_key",
        "btn_save_rule",
        "btn_save_server",
        "btn_save_team",
        "btn_save_vol",
        "btn_scan",
        "btn_scan_all",
        "btn_scp",
        "btn_send_invite",
        "btn_set_default",
        "btn_settings_back", # Reason: Button; .settings_save_row Button rule covers it
        "btn_settings_save", # Reason: Button; .settings_save_row Button rule covers it
        "btn_share",
        "btn_snapshot",
        "btn_snapshot_manager",
        "btn_ssh",
        "btn_sync_now",
        "btn_toggle",
        "btn_toggle_auto_scan",
        "btn_tool_cancel",
        "btn_tool_confirm",
        "btn_topup_cancel",
        "btn_topup_large",
        "btn_topup_medium",
        "btn_topup_small",
        "btn_unban",
        "btn_upgrade",
        "btn_view_team",
        "btn_yes",
        # ---- Bug report modal ----
        "bug-report-content",   # Reason: Static/RichLog; inherits global text styling
        "bug-title-header",     # Reason: Static; inherits global heading style
        # ---- Generic cancel/confirm buttons ----
        "cancel",
        "cancel_button",
        "continue",
        "submit",
        # ---- Card layout widgets (action-list screen) ----
        "card_cloudtrail",      # Reason: Button/container card; styled via parent
        "card_cloudwatch",      # Reason: Button/container card; styled via parent
        "card_custom_servers",  # Reason: Button/container card; styled via parent
        "card_ip_ban",          # Reason: Button/container card; styled via parent
        "card_list",            # Reason: Button/container card; styled via parent
        "card_scan",            # Reason: Button/container card; styled via parent
        # ---- Channel selector (memory / notification) ----
        "channel-label",        # Reason: Static label; inherits global Static
        "channel-selector",     # Reason: Select widget; inherits global Select styling
        # ---- Checkboxes / toggles ----
        "checkboxes",           # Reason: Container; inherits layout
        "chk-include-config",   # Reason: Checkbox; inherits global Checkbox styling
        "chk-include-logs",     # Reason: Checkbox; inherits global Checkbox styling
        "chk-include-telemetry", # Reason: Checkbox; inherits global Checkbox styling
        # ---- Cloud-create screen ----
        "cloud_create_title",   # Reason: Static title; styled by ancestor container rule
        # ---- CloudWatch detail panel ----
        "cloudwatch_detail_text", # Reason: Static/RichLog inside styled #cloudwatch_detail
        # ---- Confirm/dialog modals ----
        "confirm_box",
        "confirm_btn_row",
        "confirm_clear_no",
        "confirm_clear_yes",
        "confirm_input",
        "confirm_message",
        "confirm_no_btn",
        "confirm_prompt",
        "confirm_yes_btn",
        # ---- Remediation confirm modal (Phase 3) ----
        # All three Buttons are styled by the descendant rule
        # ``#remediation_confirm_buttons Button`` in findings.tcss.
        "remediation_confirm_cancel",
        "remediation_confirm_dry_run",
        "remediation_confirm_run",
        # ---- Consent screens ----
        "consent_body",
        "consent_buttons",
        "consent-container",    # Reason: Container; styled by parent screen
        "consent_container",
        "consent-copy",         # Reason: Static; inherits global Static
        "consent_details",
        "consent-title",        # Reason: Static; inherits global heading style
        "consent_title",
        "consequences_label",   # Reason: Static warning label; content-driven color
        # ---- Conversations screen ----
        "convs_actions",
        "convs_container",
        "convs_empty",
        "convs_filter",
        "convs_scroll",
        "convs_status",
        "convs_subtitle",
        "convs_table",
        "convs_tabs",
        "convs_title",
        # ---- Copy-mode overlay ----
        "copy-mode-container",  # Reason: Container; styled by parent screen
        "copy-mode-hint",       # Reason: Static hint; inherits global Static
        "copy-mode-text",       # Reason: Static; inherits global Static
        # ---- Stats widgets ----
        "cpu_data",             # Reason: Static; inherits global Static
        "ram_data",
        "net_data",
        # ---- Team / invite forms ----
        "create_team_form",     # Reason: Form container; inherits layout
        "create_vol_form",      # Reason: Form container; inherits layout
        # ---- CloudTrail filter inputs ----
        "ct_btn_back",
        "ct_btn_fetch",
        "ct_btn_next",
        "ct_btn_prev",
        "ct_filter_event_name",   # Reason: Filter row; inherits layout
        "ct_filter_resource_type",
        "ct_filter_time_range",
        "ct_filter_username",
        "ct_input_event_name",    # Reason: Input; inherits global Input styling
        "ct_input_resource_type",
        "ct_input_username",
        "ct_select_region",       # Reason: Select; inherits global Select styling
        "ct_select_time_range",
        "current_usage",          # Reason: Static usage label; inherits global Static
        # ---- CloudWatch filter inputs ----
        "cw_btn_back",
        "cw_btn_ban_ip",
        "cw_btn_fetch",
        "cw_btn_next",
        "cw_btn_prev",
        "cw_filter_pattern",
        "cw_filter_time_range",
        "cw_input_filter_pattern", # Reason: Input; inherits global Input styling
        "cw_select_log_group",
        "cw_select_region",
        "cw_select_time_range",
        # ---- Dangerous-confirm modal ----
        "dangerous_confirm_args",
        "dangerous_confirm_body",
        "dangerous_confirm_buttons",
        "dangerous_confirm_container",
        "dangerous_confirm_error",  # Reason: styled in DangerousToolConfirmModal.DEFAULT_CSS (hidden until .visible)
        "dangerous_confirm_input",
        "dangerous_confirm_title",
        # ---- Generic description/text ----
        "description",          # Reason: Static description; inherits global Static
        "diagnostics-status",   # Reason: Static status; inherits global Static
        # ---- DNS screen ----
        "dns_title",            # Reason: Static title; styled by ancestor container
        "domains_section_header", # Reason: Static section header; inherits .section_header
        # ---- Drift screen ----
        "drift-diff-close",     # Reason: Button; inherits global Button styling
        "drift-diff-content",   # Reason: Static/RichLog inside styled container
        "drift-table",          # Reason: DataTable; styled via ancestor container rule
        # ---- Edit consent ----
        "edit-consent",         # Reason: Button; inherits global Button styling
        "enrol-btn-confirm",    # Reason: Button; inherits global Button styling
        "enrol-remember",       # Reason: Switch; inherits global Switch styling (row/label have #rules)
        "event_detail_text",    # Reason: Static inside styled #event_detail
        # ---- Export screen ----
        "export-from-input",    # Reason: Input; inherits global Input styling
        "export_modal",         # Reason: ModalScreen container; inherits modal styling
        "export_path_input",    # Reason: Input; inherits global Input styling
        "export-to-input",      # Reason: Input; inherits global Input styling
        # ---- Firewall screen ----
        "firewall_actions",     # Reason: Action row; inherits layout
        "firewall_status",      # Reason: Static status; inherits global Static
        "firewall_title",       # Reason: Static title; inherits global heading style
        # ---- Flavor table (Hetzner create) ----
        "flavors_table",        # Reason: DataTable; styled via #hetzner_create_container DataTable
        # ---- Fleet scan modal ----
        "fleet-scan-body",      # Reason: Static; inherits global Static
        "fleet-scan-failures",  # Reason: Static; inherits global Static
        "fleet-scan-modal",     # Reason: Modal container; inherits modal styling
        "fleet-scan-title",     # Reason: Static title; inherits global heading style
        # ---- Footer buttons row ----
        "footer-buttons",       # Reason: Horizontal layout row; inherits layout
        # ---- Hetzner create screen ----
        "hetzner_create_title",  # Reason: Static title; styled by ancestor container
        "hetzner_images_table",  # Reason: DataTable; styled via container rule
        "hetzner_input_local_ssh_key", # Reason: Input; inherits global Input styling
        "hetzner_input_name",
        "hetzner_input_s3_access_key", # Reason: Input; inherits global Input + .setting_row Input
        "hetzner_input_s3_endpoint_url",
        "hetzner_input_s3_region",
        "hetzner_input_s3_secret_key",
        "hetzner_input_token",
        "hetzner_input_username",
        "hetzner_keys_table",    # Reason: DataTable; styled via container rule
        "hetzner_locations_table",
        # hetzner_not_configured_error is now styled — shares a selector group
        # with #aws_not_configured_error in the styles bundle (round $error border).
        "hetzner_select_image",  # Reason: Select; inherits global Select styling
        "hetzner_select_location",
        "hetzner_select_remote_ssh_key",
        "hetzner_select_server_type",
        "hetzner_setup_header",  # Reason: Static; inherits global heading style
        "hetzner_ssh_input_name",
        "hetzner_ssh_input_public_key",
        "hetzner_status_label",  # Reason: Dynamic status; inherits global Static
        "hetzner_test_result",   # Reason: Static test output; inherits global Static
        "hetzner_types_table",   # Reason: DataTable; styled via container rule
        "images_table",          # Reason: DataTable; styled via container rule
        # ---- Settings Input widgets ----
        # All these are inside .setting_row containers which apply width/margin
        # via the .setting_row Input rule.  No per-input-ID rule needed.
        "input_abuseipdb_key",
        "input_action",
        "input_agent_key",
        "input_ai_anthropic_key",
        "input_ai_base_url",
        "input_ai_gemini_key",
        "input_ai_max_tokens",
        "input_ai_model",
        "input_ai_ollama_key",
        "input_ai_openai_key",
        "input_ai_provider",
        "input_ai_provider_preference",
        "input_ai_servonaut_status",
        "input_ai_temperature",
        "input_attach_instance_id",
        "input_aws_default_region",
        "input_aws_s3_access_key",
        "input_aws_s3_endpoint_url",
        "input_aws_s3_region",
        "input_aws_s3_secret_key",
        "input_cache_ttl",
        "input_default_key",
        "input_extra_ssh_options",
        "input_group",
        "input_host",
        "input_invite_email",
        "input_invite_role",
        "input_key_name",
        "input_mapping_instance",
        "input_mapping_key",
        "input_move_target",
        "input_name",
        "input_new_path",
        "input_port",
        "input_protocol",
        "input_provider",
        "input_public_key",
        "input_rdns",
        "input_rdns_hostname",
        "input_region",
        "input_sequence",
        "input_snapshot_name",
        "input_source",
        "input_ssh_key",
        "input_subdomain",
        "input_target",
        "input_team_name",
        "input_terminal",
        "input_theme",
        "input_ttl",
        "input_type",
        "input_username",
        "input_vol_name",
        "input_vol_region",
        "input_vol_size",
        "input_vol_type",
        # ---- Invite form ----
        "invite_form",          # Reason: Form container; inherits layout
        # ---- IP ban form fields ----
        "ipban_input_ip_set_id",
        "ipban_input_ip_set_name",
        "ipban_input_nacl_id",
        "ipban_input_name",
        "ipban_input_rule_number_start",
        "ipban_input_sg_id",
        "ipban_select_ip_set",
        "ipban_select_method",
        "ipban_select_nacl",
        "ipban_select_region",
        "ipban_select_sg",
        "ipban_select_waf_scope",
        "ip_mgmt_title",        # Reason: Static title; inherits global heading style
        # ---- Keys screen ----
        "keys_hint",            # Reason: Static hint; inherits global Static
        "keys_table",           # Reason: DataTable; styled via ancestor container
        # ---- Local snapshots screen ----
        "local_actions",
        "local_empty",
        "local_filter",
        "local_scroll",
        "local_status",
        "local_table",
        # ---- Login screen sub-containers ----
        "logged_in_container",  # Reason: Container; layout-only
        "logged_out_container", # Reason: Container; layout-only
        # ---- Manage-paths screen ----
        "manage_add_dir",
        "manage_add_file",
        "manage_browse",
        "manage_close",
        "manage_edit",
        "manage_remove",
        # ---- Team management ----
        "member_actions_row",   # Reason: Horizontal layout row; inherits layout
        "members_table",        # Reason: DataTable; styled via ancestor container
        # ---- Memory screens ----
        "memory-empty-state",       # Reason: Static; inherits global Static
        "memory-empty-state-label", # Reason: Static; inherits global Static
        "memory-opt-out-banner",    # Reason: Static; inherits global Static
        "memory-table",             # Reason: DataTable; styled via ancestor container
        # ---- Generic modal containers ----
        "modal_container",      # Reason: Modal container; styled by parent ModalScreen
        "modal_description",    # Reason: Static; inherits global Static
        "modal_title",          # Reason: Static; inherits global heading style
        "models_table",         # Reason: DataTable; styled via ancestor container
        "monitoring_title",     # Reason: Static title; inherits global heading style
        # ---- Move form panel ----
        "move_form_panel",      # Reason: Form container; inherits .ip_form_panel parent
        "move_form_title",      # Reason: Static title; inherits global heading style
        # ---- Memory sync screen buttons ----
        "msync_btn_billing",
        "msync_btn_compare",
        "msync_btn_disable",
        "msync_btn_learn",
        "msync_btn_login",
        "msync_btn_forget",
        "msync_btn_rotate",
        "msync_btn_setup",
        "msync_btn_sync_now",
        # ---- No-auth / no-httpx notices ----
        "no_auth_notice",       # Reason: Static notice; inherits global Static
        "no_httpx_notice",      # Reason: Static notice; inherits global Static
        "no_project_error",     # Reason: Static error; inherits global Static
        # ---- OVH settings inputs ----
        "ovh_input_app_key",
        "ovh_input_app_secret",
        "ovh_input_consumer_key",
        "ovh_input_default_ssh_key",
        "ovh_input_default_username",
        "ovh_input_endpoint",
        "ovh_input_include_cloud",
        "ovh_input_include_dedicated",
        "ovh_input_include_vps",
        "ovh_input_project_ids",
        "ovh_input_s3_access_key", # Reason: Input; inherits global Input + .setting_row Input
        "ovh_input_s3_endpoint_url",
        "ovh_input_s3_region",
        "ovh_input_s3_secret_key",
        "ovh_setup_header",     # Reason: Static; inherits global heading style
        "ovh_ssh_keys_header",  # Reason: Static; styled by ancestor container rule
        "ovh_ssh_keys_project_label", # Reason: Static label; inherits global Static
        "ovh_status_label",     # Reason: Dynamic status; inherits global Static
        "ovh_test_result",      # Reason: Static test output; inherits global Static
        "ovh_validation_url",   # Reason: Static URL; inherits global Static
        # ---- Period selector ----
        "period_selector",      # Reason: Select; inherits global Select styling
        # ---- PIN modal ----
        "pin_btn_cancel",
        "pin_btn_confirm",
        "pin_btn_row",
        "pin_modal_container",  # Reason: Modal container; styled by parent ModalScreen
        "pin_modal_field",      # Reason: Input; inherits global Input styling
        "pin_modal_title",      # Reason: Static; inherits global heading style
        "pin_value_input",      # Reason: Input; inherits global Input styling
        "plan_info",            # Reason: Static; inherits global Static
        # ---- Preview widgets ----
        "preview",              # Reason: RichLog/Static; inherits global text styling
        "preview-scroll",       # Reason: ScrollableContainer; inherits layout
        # ---- Radio buttons ----
        "radio-backend",        # Reason: RadioButton; inherits global RadioButton styling
        "radio_download",
        "radio-github",
        "radio_upload",
        # ---- RDNS screen ----
        "rdns_btn_row",
        "rdns_form",
        "rdns_form_ip_label",
        "rdns_form_panel",
        "rdns_form_title",
        "rdns_section_header",  # Reason: Static section header; inherits .section_header
        # ---- Receipt / billing rows ----
        "receipt-row",          # Reason: Horizontal layout row; inherits layout
        # ---- Record / DNS forms ----
        "record_form",
        "records_section_header", # Reason: Static section header; inherits .section_header
        # ---- Redact warning ----
        "redact-warning",       # Reason: Static warning; inherits global Static
        "refresh-preview",      # Reason: Button; inherits global Button styling
        # ---- Reinstall screen ----
        "reinstall_actions",
        "reinstall_description",
        "reinstall_hint",
        "reinstall_title",
        # ---- Resize screen ----
        "resize_actions",
        "resize_description",
        "resize_hint",
        "resize_title",
        # ---- Team management section labels ----
        "section_members",      # Reason: Static; inherits global Static
        "section_servers",
        "section_teams",
        "selected_zone",        # Reason: Static; inherits global Static
        "server_actions_row",   # Reason: Horizontal row; inherits layout
        "servers_table",        # Reason: DataTable; styled via ancestor container
        # ---- Settings toggle widgets ----
        "settings_chat_inject_server_memory", # Reason: Switch; inherits global Switch styling
        "settings_chat_keep_tool_results",
        "settings_msync_ai_mode",
        "settings_msync_auto_sync",
        "settings_msync_digest",
        "settings_msync_mercure",
        "settings_msync_status", # Reason: Static status; inherits global Static
        "severity_message",     # Reason: Static; inherits global Static
        # ---- Share screen ----
        "share-btn-confirm",
        "share-modules-list",   # Reason: ListView; inherits layout
        "share_outer",          # Reason: Container; layout-only
        "share-role-select",    # Reason: Select; inherits global Select styling
        "share-team-select",
        # ---- Snapshot form ----
        "snapshot_form",        # Reason: Form container; inherits layout
        "snapshots_title",      # Reason: Static title; inherits global heading style
        "spend_history",        # Reason: Static; inherits global Static
        # ---- Stats badges ----
        "stat-running",         # Reason: Static badge; styled by content text
        "stat-stopped",
        "stat-total",
        # ---- Storage screen ----
        "storage_actions",      # Reason: Action row; inherits layout
        "storage_title",        # Reason: Static title; inherits global heading style
        # ---- Submission error ----
        "submission-error",     # Reason: Static; inherits global Static
        # ---- Tab widgets ----
        "tab_cloud",            # Reason: Tab; inherits global Tab styling
        "tab_local",
        # ---- Team screen ----
        "team_actions_row",     # Reason: Horizontal row; inherits layout
        "team_header",          # Reason: Static; inherits global heading style
        "teams_table",          # Reason: DataTable; styled via ancestor container
        "title",                # Reason: Static title; inherits global heading style
        # ---- Tool-confirm modal ----
        "tool_confirm_args",
        "tool_confirm_body",
        "tool_confirm_buttons",
        "tool_confirm_container", # Reason: Modal container; styled by parent ModalScreen
        "tool_confirm_title",
        # ---- Transfer widgets ----
        "transfer_button",      # Reason: Button; inherits global Button styling
        # ---- Volumes table ----
        "volumes_table",        # Reason: DataTable; styled via ancestor container
        # ---- Team management (PR #26) ----
        # Widgets inside TeamManagementScreen / inline forms / modal dialogs;
        # all inherit Button, Input, Static, Select, or container styling
        # from their parent screen rules. None require per-ID overrides.
        "btn_cancel_change_role",
        "btn_cancel_create_team",
        "btn_cancel_invite",
        "btn_cancel_share",
        "btn_change_role",
        "btn_confirm_share",
        "btn_copy_url",
        "btn_resend",
        "btn_save_role",
        "btn_share_all",
        "cancel_btn",
        "change_role_header",
        "delete_btn",
        "input_share_port",
        "input_share_username",
        "members_section",
        "save_btn",
        "select_change_role",
        "select_invite_role",
        "select_share_instance",
        "servers_section",
        "team_mgmt_header",
        "teams_section",
        # ---- BW SSH / SSH-ref integration (PR #27) ----
        # Bitwarden vault + SSH ref editor + verify modal. All inherit
        # parent screen / modal styling.
        "btn_bw_ssh_cancel",
        "btn_bw_ssh_edit",
        "btn_bw_ssh_save",
        "btn_manage_ssh_ref",
        "btn_ssh_verify_cancel",
        "btn_ssh_verify_confirm",
        "btn_verify_ssh",
        "bw_ssh_default_collection_id",
        "bw_ssh_vault_actions",
        "bw_ssh_vault_status",
        "bw_ssh_vault_title",
        "bw_ssh_vault_url",
        "collection_id",
        "item_id",
        "ssh_ref_editor_help",
        "ssh_ref_editor_title",
        "ssh_ref_fields",
        "vault_url",
        # ---- Config sync push/pull screens (PR #26 — companion to teams) ----
        "btn_cancel_pull_config",
        "btn_cancel_push_config",
        "btn_confirm_pull_config",
        "btn_confirm_push_config",
        "btn_pull_config",
        "btn_push_config",
        "config_actions_row",
        "configs_hint",
        "configs_section",
        "configs_table",
        "input_push_description",
        "pull_config_form",
        "pull_config_preview",
        "pull_config_warning",
        "push_config_form",
        "push_config_preview",
        "section_configs",
        # ---- Settings refactor (master/detail panels, screens/settings/**) ----
        # Panel root containers carry the .settings-panel class (styled in
        # app.css); form Inputs/Selects/Switches sit in .setting_row and inherit
        # global widget styling; Buttons inherit global Button styling; dynamic
        # status/label Statics are content-styled. Panel-scoped layout rules live
        # in each panel class DEFAULT_CSS. None require a per-ID app.css rule.
        'ai_chat',
        'ai_chat_chat_system_prompt',
        'ai_chat_chunk_size',
        'ai_chat_guard_warning',
        'ai_chat_inject_server_memory',
        'ai_chat_keep_tool_results',
        'ai_chat_max_history_messages',
        'ai_chat_max_tool_iterations',
        'ai_chat_max_tool_rounds',
        'ai_chat_system_prompt',
        'ai_chat_tool_guard_level',
        'ai_provider',
        'ai_provider_anthropic_key',
        'ai_provider_base_url',
        'ai_provider_gemini_key',
        'ai_provider_max_tokens',
        'ai_provider_model',
        'ai_provider_ollama_key',
        'ai_provider_openai_key',
        'ai_provider_pref_select',
        'ai_provider_provider',
        'ai_provider_servonaut_status',
        'ai_provider_temperature',
        'ai_provider_upgrade',
        'aws',
        'aws_audit_path',
        'aws_cache_path',
        'aws_cache_ttl',
        'aws_ctrl_external_id',
        'aws_ctrl_role_arn',
        'aws_ctrl_session_name',
        'aws_default_region',
        'aws_enabled',
        'aws_mutate_role_arn',
        'aws_s3_access_key',
        'aws_s3_endpoint_url',
        'aws_s3_region',
        'aws_s3_secret_key',
        'azure',
        'azure_enabled',
        'azure_resource_groups',
        'azure_subscription_ids',
        'backups',
        'backups_open_restore',
        'backups_open_snapshots',
        'btn_profile_add',
        'btn_profile_cancel',
        'btn_profile_edit',
        'btn_profile_remove',
        'btn_profile_save',
        'btn_rule_add',
        'btn_rule_cancel',
        'btn_rule_edit',
        'btn_rule_remove',
        'btn_rule_save',
        'bw_ssh',
        'bw_ssh_status',
        'cloudtrail',
        'cloudtrail_default_lookback_hours',
        'cloudtrail_default_lookback_minutes',
        'cloudtrail_default_region',
        'cloudtrail_max_events',
        'cloudwatch',
        'cloudwatch_default_region',
        'cloudwatch_log_group_prefix',
        'cloudwatch_max_events',
        'conn_profiles_table',
        'conn_rules_table',
        'connections',
        'custom_servers',
        'custom_servers_count',
        'discard-cancel',
        'discard-confirm',
        'discard-message',
        'gcp',
        'gcp_credentials_path',
        'gcp_enabled',
        'gcp_project_ids',
        'gcp_zones',
        'general',
        'general_cache_ttl',
        'general_default_key',
        'general_terminal',
        'general_theme',
        'general_username',
        'hetzner',
        'hetzner_audit_path',
        'hetzner_cache_path',
        'hetzner_cache_ttl',
        'hetzner_cost_alert_threshold',
        'hetzner_default_hetzner_ssh_key',
        'hetzner_default_image',
        'hetzner_default_local_ssh_key',
        'hetzner_default_location',
        'hetzner_default_server_type',
        'hetzner_default_username',
        'hetzner_enabled',
        'hetzner_require_ssh_keys',
        'hetzner_s3_access_key',
        'hetzner_s3_endpoint_url',
        'hetzner_s3_region',
        'hetzner_s3_secret_key',
        'history_paths',
        'hp_chat_history_path',
        'hp_command_history_path',
        'hp_keyword_store_path',
        'hp_max_command_history',
        'ip_ban',
        'ip_lookup',
        'ip_lookup_abuseipdb_key',
        'log_viewer',
        'lv_custom_paths',
        'lv_default_paths',
        'lv_max_lines',
        'lv_scan_directories',
        'lv_scan_max_depth',
        'lv_tail_lines',
        'mcp',
        'mcp_allow_destructive',
        'mcp_allowlist',
        'mcp_audit_path',
        'mcp_blocklist',
        'mcp_blocklist_warn',
        'mcp_destructive_warn',
        'mcp_guard_level',
        'mcp_guard_warn',
        'mcp_max_output_lines',
        'memory',
        'memory_auto_scan_enabled',
        'memory_auto_scan_interval',
        'memory_disabled_modules',
        'memory_enabled',
        'memory_findings_confidence',
        'memory_findings_index_char_cap',
        'memory_findings_sync',
        'memory_first_connect_reprompt',
        'memory_per_server_summary',
        'memory_redaction_enabled',
        'memory_snapshot_stale',
        'memory_sync',
        'memory_sync_encryption',
        'memory_ttl_overrides',
        'msync_ai_mode',
        'msync_digest',
        'msync_mercure',
        'msync_status_note',
        'open_custom_servers',
        'ovh',
        'ovh_audit_path',
        'ovh_btn_setup',
        'ovh_client_id',
        'ovh_cloud_project_ids',
        'ovh_cost_currency',
        'ovh_cost_threshold',
        'ovh_default_ssh_key',
        'ovh_default_username',
        'ovh_enabled',
        'ovh_endpoint',
        'ovh_include_cloud',
        'ovh_include_dedicated',
        'ovh_include_vps',
        'ovh_s3_access_key',
        'ovh_s3_endpoint_url',
        'ovh_s3_region',
        'ovh_s3_secret_key',
        'ovh_status_display',
        'pf_bastion_host',
        'pf_bastion_key',
        'pf_bastion_user',
        'pf_extra_ssh_options',
        'pf_name',
        'pf_proxy_command',
        'pf_ssh_port',
        'pf_username',
        'profile_form',
        'profile_form_title',
        'relay',
        'relay_ai_tool_auto_approve',
        'relay_auto_approve_warn',
        'relay_base_url',
        'relay_heartbeat_interval',
        'relay_mercure_url',
        'rl_match_conditions',
        'rl_name',
        'rl_profile_name',
        'rule_form',
        'rule_form_title',
        'scan',
        'scan_btn_add_rule',
        'scan_default_paths_editor',
        'scan_new_rule_name',
        'scan_rules_container',
        'ssh_keys',
        'ssh_keys_count',
        'ssh_keys_open',
        'voice',
        'voice_auto_submit',
        'voice_btn_copy_install',
        'voice_btn_copy_portaudio',
        'voice_btn_download',
        'voice_btn_install',
        'voice_btn_recheck',
        'voice_btn_remove_model',
        'voice_enabled',
        'voice_input_device',
        'voice_language',
        'voice_max_recording_seconds',
        'voice_model_size',
        # Reason: readiness rows are mounted at runtime and styled by the
        # .voice-req-* / .voice-action-row classes in VoicePanel.DEFAULT_CSS.
        'voice_requirements',
        # ---- Bitwarden SSH picker / unlock modals ----
        # Buttons inherit global Button styling; Inputs inherit global Input
        # styling; the Checkboxes inherit global Checkbox styling; the dynamic
        # Static lines are content-colored at runtime. The structural
        # containers/titles/body/table DO have #id rules in secrets.tcss.
        'btn_bw_unlock',          # Reason: Button; inherits global Button styling
        'bw_cancel_btn',          # Reason: Button; inherits global Button styling
        'bw_close_btn',           # Reason: Button; inherits global Button styling
        'bw_unlock_btn',          # Reason: Button; inherits global Button styling
        'bw_picker_cancel',       # Reason: Button; inherits global Button styling
        'bw_picker_close',        # Reason: Button; inherits global Button styling
        'bw_master_pw',           # Reason: Input; inherits global Input styling
        'bw_picker_search',       # Reason: Input; inherits global Input styling
        'bw_ssh_vault_folder',    # Reason: Input; inherits global Input styling (.setting_row)
        'bw_remember',            # Reason: Checkbox; inherits global Checkbox styling
        'bw_picker_folder_toggle',  # Reason: Checkbox; inherits global Checkbox styling
        'bw_session_status',      # Reason: Dynamic status Static; content-colored at runtime
        'ssh_ref_selected',       # Reason: Dynamic Static; content-colored at runtime
        'pick_btn',               # Reason: Button; inherits global Button styling
        'ssh_ref_advanced',       # Reason: Collapsible; inherits global Collapsible styling
        'btn_bw_vault_refresh',   # Reason: Button; styled via #bw_vault_mgr_actions Button
        'btn_bw_vault_open',      # Reason: Button; styled via #bw_vault_mgr_actions Button
        'btn_bw_vault_edit',      # Reason: Button; styled via #bw_vault_mgr_actions Button
        'btn_bw_vault_import',    # Reason: Button; styled via #bw_vault_mgr_actions Button
        # ---- Bitwarden key-import flow modals ----
        'bw_dir_input',           # Reason: Input; inherits global Input styling
        'bw_dir_select_btn',      # Reason: Button; styled via .bw_dir_actions Button
        'bw_dir_cancel_btn',      # Reason: Button; styled via .bw_dir_actions Button
        'bw_passphrase_input',    # Reason: Input; inherits global Input styling
        'bw_passphrase_unlock_btn',  # Reason: Button; styled via .bw_passphrase_actions Button
        'bw_passphrase_skip_btn',    # Reason: Button; styled via .bw_passphrase_actions Button
        'bw_import_btn',          # Reason: Button; styled via .bw_import_actions Button
        'bw_import_cancel_btn',   # Reason: Button; styled via .bw_import_actions Button
        # ---- DB-vault management modals (label prompt + remove confirm) ----
        # Containers + button rows are styled in each modal's DEFAULT_CSS; these
        # leaf widgets inherit global Button/Input/Static/Checkbox styling.
        'db_label_modal_title',   # Reason: Static title; inherits global Static styling
        'db_label_modal_hint',    # Reason: Static hint; inherits global Static styling
        'db_label_input',         # Reason: Input; inherits global Input styling
        'btn_db_label_store',     # Reason: Button; styled via #db_label_modal_buttons Button
        'btn_db_label_cancel',    # Reason: Button; styled via #db_label_modal_buttons Button
        'db_remove_modal_title',  # Reason: Static title; inherits global Static styling
        'db_remove_modal_body',   # Reason: Static body; inherits global Static styling
        'db_remove_delete_secret',  # Reason: Checkbox; inherits global Checkbox styling
        'btn_db_remove_confirm',  # Reason: Button; styled via #db_remove_buttons Button
        'btn_db_remove_cancel',   # Reason: Button; styled via #db_remove_buttons Button
    ]
)


def _collect_screen_ids() -> list[str]:
    """Return all ``id="..."`` values found in screen Python files."""
    id_pattern = re.compile(r'id="([^"]+)"')
    ids: set[str] = set()
    for py_file in SCREENS_DIR.rglob("*.py"):
        text = py_file.read_text(encoding="utf-8")
        ids.update(id_pattern.findall(text))
    return sorted(ids)


def _css_text() -> str:
    """Return the full stylesheet bundle plus any per-widget ``DEFAULT_CSS`` declared in screens.

    The settings panels (``screens/settings/**``) deliberately keep their
    panel-scoped rules in each class's ``DEFAULT_CSS`` rather than the main
    stylesheet, to avoid edit contention on the shared stylesheet.  Those
    blocks are valid CSS coverage, so we concatenate them here before checking
    for ``#id`` rules.
    """
    parts = [f.read_text(encoding="utf-8") for f in CSS_FILES]
    for py_file in SCREENS_DIR.rglob("*.py"):
        text = py_file.read_text(encoding="utf-8")
        for match in re.finditer(r'DEFAULT_CSS\s*=\s*("""|\'\'\')', text):
            quote = match.group(1)
            start = match.end()
            end = text.find(quote, start)
            if end != -1:
                parts.append(text[start:end])
    return "\n".join(parts)


def test_css_covers_all_screen_widget_ids() -> None:
    """Every widget ID used in screens must have a CSS rule OR be in ACCEPTABLE_UNSTYLED."""
    css = _css_text()
    screen_ids = _collect_screen_ids()

    missing: list[str] = []
    for wid in screen_ids:
        if wid in ACCEPTABLE_UNSTYLED:
            continue
        # Check for #id followed by CSS-selector punctuation.
        pattern = r"#" + re.escape(wid) + r"[\s,{:.>\[~]"
        if not re.search(pattern, css):
            missing.append(wid)

    assert not missing, (
        f"{len(missing)} widget ID(s) have no CSS rule and are not in "
        f"ACCEPTABLE_UNSTYLED:\n"
        + "\n".join(f"  {m}" for m in missing)
    )
