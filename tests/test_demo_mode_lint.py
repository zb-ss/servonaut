"""AST-based lint sweep: every call to .write() / .update() / .append_output()
/ .append_error() on user-influenced content in screens/*.py and widgets/*.py
must either appear in the _ALLOWLIST (with justification) or be accompanied by
a scrub_stream / redact_* call in the same function body.

Why AST and not grep?
  - grep gives false positives on dict.update(), logging calls, and general
    method calls that happen to be named ``update``.
  - The AST walk restricts to Call(func=Attribute(attr=X)) so only method calls
    match.
  - The allowlist documents WHY each unchecked call is intentionally safe,
    making it a living registry that breaks CI when new screens add raw writes.

Failure output lists the offending function+file+line so the developer can
immediately locate the missing guard.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Dict, List, NamedTuple, Set

import pytest


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Method names that could write user-visible content to widgets.
# `add_row` is included because CloudTrail/CloudWatch/Memory rows are exactly
# how server-origin streaming data reaches the user in table screens.
_GUARDED_ATTRS: Set[str] = {"write", "update", "append_output", "append_error", "add_row", "load_text"}

# Root of the Python source tree
_SRC_ROOT = Path(__file__).parent.parent / "src" / "servonaut"
_SCREENS_DIR = _SRC_ROOT / "screens"
_WIDGETS_DIR = _SRC_ROOT / "widgets"

# Scan ALL screens and widgets so that new screens can't accidentally bypass
# the lint gate.  The allowlist documents why each un-guarded call is safe.
# (Previously an opt-in list of 9 files; inverted in iteration-3 to cover
# all 61 screens + all widgets by default.)
_TARGET_DIRS: tuple[str, ...] = ("screens", "widgets")


class AllowlistEntry(NamedTuple):
    file: str       # relative to src/servonaut/
    func: str       # enclosing function name (or "module" for top-level)
    attr: str       # method name from _GUARDED_ATTRS
    reason: str     # one-line justification


# ---------------------------------------------------------------------------
# Allowlist — calls that are intentionally NOT guarded by a redaction call.
# Each entry requires a one-line justification explaining why it is safe.
# ---------------------------------------------------------------------------

_ALLOWLIST: List[AllowlistEntry] = [
    # status_bar.py — _update_display writes instance counts, cache age, and
    # filter status; no user-origin streaming data.  The DEMO badge itself is
    # only added here when demo_mode is True and comes from a constant string.
    AllowlistEntry("widgets/status_bar.py", "_update_display", "update",
                   "Only displays instance counts, cache age, filter state, "
                   "and the DEMO badge constant — no user-origin streaming data."),

    # command_output.py — append_command writes the command line typed by the
    # user (echo back) which is not a secret leak; the user typed it.
    AllowlistEntry("widgets/command_output.py", "append_command", "write",
                   "Echoes the command the user explicitly typed; not a "
                   "server-origin secret that needs redaction."),

    # command_output.py — clear_output just calls self.clear() which does not
    # write any user data. (clear_output body calls self.clear(), not write/update).
    AllowlistEntry("widgets/command_output.py", "clear_output", "write",
                   "No-op placeholder: clear_output calls self.clear(), "
                   "not write(). Listed in case AST walk traverses the body."),

    # log_viewer.py — _on_stream_ended writes static marker strings
    # ("--- End of file ---", "File is empty") — not user data.
    AllowlistEntry("screens/log_viewer.py", "_on_stream_ended", "write",
                   "Writes static marker strings (EOF / empty file) — "
                   "these are code-controlled constants, not streamed data."),

    # log_viewer.py — _check_empty_output writes a static hint message.
    AllowlistEntry("screens/log_viewer.py", "_check_empty_output", "write",
                   "Writes a static UI hint ('No output yet') — "
                   "no user/server data involved."),

    # ip_ban.py — _load_audit_log: the line `audit_log.write(...)` that
    # writes the '[dim]No audit log entries yet.[/dim]' placeholder is safe.
    # The writes with real IP/msg data are guarded by the demo-mode check.
    AllowlistEntry("screens/ip_ban.py", "_load_audit_log", "write",
                   "Contains both a guarded write (IP/msg scrubbed) and an "
                   "unguarded placeholder write ('[dim]No audit log...[/dim]') "
                   "which is a code-controlled constant string, not user data."),

    # ip_ban.py — error write inside the except block writes a static error msg.
    AllowlistEntry("screens/ip_ban.py", "_load_audit_log", "write",
                   "The except-block write is a static error message with "
                   "the exception type — not raw audit data."),

    # cloudwatch_browser.py — _show_event_detail's update call is guarded
    # inside the method; the allowlist entry covers `update` calls within this
    # function only for Static status messages (e.g., 'Looking up info...')
    # that use display_ip, not raw ip.
    AllowlistEntry("screens/cloudwatch_browser.py", "action_ip_info", "update",
                   "Uses display_ip (already redacted) in the status message "
                   "text — not the raw IP."),

    # chat_panel.py — _update_thinking_status uses update() to show the live
    # streaming text. The token handler now always scrubs display_accumulated
    # on every token before passing it here (C1 fix — heuristic removed).
    AllowlistEntry("widgets/chat_panel.py", "_update_thinking_status", "update",
                   "Receives display_accumulated which is fully scrubbed on every "
                   "token by the token handler (C1: always-scrub, heuristic removed). "
                   "_rich_escape also applied inside _update_thinking_status."),

    # chat_panel.py — _show_welcome writes static UI placeholder content.
    AllowlistEntry("widgets/chat_panel.py", "_show_welcome", "update",
                   "Writes static welcome/empty-state content — no user/server data."),

    # Various screens that render instance-dict fields: instance fields are
    # already redacted by on_mount / redact_instances before any screen sees them.
    AllowlistEntry("screens/server_actions.py", "_update_header", "update",
                   "Renders instance dict fields (name, IP) that are already "
                   "redacted in-place by on_mount redact_instances()."),

    AllowlistEntry("screens/scp_transfer.py", "_update_banner", "update",
                   "SCP transfer banner shows instance name from already-redacted "
                   "dict. No file-tree exists; status_output echoes user-typed "
                   "paths (spec non-goal §1 drift note)."),

    # Memory screen — module-name and key columns are taxonomy (scrub is intentionally
    # skipped for those). obs_str and decl_str ARE scrubbed inside _render_table.
    AllowlistEntry("screens/memory.py", "_render_table", "add_row",
                   "obs_str and decl_str are scrubbed inside _render_table before "
                   "add_row. module_name and key are taxonomy — not scrubbed by "
                   "design (plan §8 item 7)."),

    # fleet_memory.py — shows module status summary (count of modules, last probe
    # time) — no raw output values.
    AllowlistEntry("screens/fleet_memory.py", "_render_fleet_table", "add_row",
                   "Fleet memory table shows module-count summaries and timestamps "
                   "only — no raw_output values that require scrubbing."),

    # ai_analysis.py — status updates are all hard-coded or contain only
    # token counts and line counts (integers), not raw log content.
    AllowlistEntry("screens/ai_analysis.py", "on_mount", "update",
                   "Writes a hard-coded '[dim]Text loaded...[/dim]' status string "
                   "— no user-origin streaming data."),
    AllowlistEntry("screens/ai_analysis.py", "_update_provider_info", "update",
                   "Updates provider picker block with entitlement/plan labels "
                   "— code-controlled strings, not streamed log content."),
    AllowlistEntry("screens/ai_analysis.py", "_update_token_estimate", "update",
                   "Updates token count label with integer estimates — "
                   "code-controlled numeric output, not raw log data."),
    AllowlistEntry("screens/ai_analysis.py", "_fetch_recent_logs", "update",
                   "Writes a hard-coded 'Probing available logs...' status string "
                   "— not log content."),
    AllowlistEntry("screens/ai_analysis.py", "_do_probe_and_pick", "update",
                   "Writes hard-coded status/error strings (no IP, 'No readable log "
                   "files found', 'Error: ...') — exception str may carry exc type "
                   "but not raw log streaming data."),
    AllowlistEntry("screens/ai_analysis.py", "_fetch_log_file", "update",
                   "Writes '[dim]Fetching <log_path>...[/dim]' where log_path is the "
                   "user-chosen path from the config picker — not streamed content."),
    AllowlistEntry("screens/ai_analysis.py", "_run_analysis", "update",
                   "Clears the status widget with an empty string before analysis "
                   "starts — no user data involved."),

    # command_overlay.py — on_mount writes welcome and hint strings.
    # The instance name inside `welcome` is already redacted in-place by
    # on_mount/redact_instances() before CommandOverlay is pushed.
    AllowlistEntry("screens/command_overlay.py", "on_mount", "append_output",
                   "Welcome string uses instance name from already-redacted dict; "
                   "hint strings are code-controlled constants."),
    AllowlistEntry("screens/command_overlay.py", "on_mount", "append_error",
                   "Warning about missing connection profile uses profile name from "
                   "config (not a server secret) — code-controlled string."),

    # command_overlay.py — _execute_command: the append_error and append_output
    # calls on lines 247–256 write static/code-controlled interactive-command
    # error strings and the 'Ctrl+C to stop' hint — not SSH output.
    # SSH output lines are scrubbed in _run_ssh_process before append_*.
    AllowlistEntry("screens/command_overlay.py", "_execute_command", "append_error",
                   "Writes a static 'requires interactive terminal' error for "
                   "blocked commands — hard-coded string, not SSH output."),
    AllowlistEntry("screens/command_overlay.py", "_execute_command", "append_output",
                   "Writes static hint strings ('press Escape...', 'Ctrl+C to stop') "
                   "— code-controlled constants, not SSH stdout."),

    # command_overlay.py — _stop_running_process writes a static '[dim]Stopped.[/dim]'.
    AllowlistEntry("screens/command_overlay.py", "_stop_running_process", "append_output",
                   "Writes a hard-coded '[dim]Stopped.[/dim]' marker — "
                   "not SSH output data."),

    # fleet_memory.py — _populate_table (local path) uses already-redacted
    # instance dicts from self.app.instances (in-place redacted by on_mount).
    AllowlistEntry("screens/fleet_memory.py", "_populate_table", "add_row",
                   "Renders instance dict fields (name, id, provider) from "
                   "self.app.instances which are already redacted in-place by "
                   "on_mount redact_instances()."),
    AllowlistEntry("screens/fleet_memory.py", "_populate_table", "update",
                   "Updates status footer with hard-coded count labels (fresh/stale "
                   "integers) — code-controlled strings, not streaming data."),

    # fleet_memory.py — _set_progress writes scan progress markup. The
    # just_finished name embedded in the template is scrubbed at source in
    # scan_one() before being appended to succeeded/failed and passed here.
    AllowlistEntry("screens/fleet_memory.py", "_set_progress", "update",
                   "Progress markup embeds `just_finished` name which is scrubbed "
                   "at source in scan_one() via redact_name() — safe by the time "
                   "it reaches this template."),

    # server_actions.py — _fetch_rdns now scrubs the rDNS hostname via
    # redact_hostname() before embedding it in the info widget — no allowlist entry
    # needed; the lint passes naturally due to the redact_hostname guard.

    # cloudtrail_browser.py — pager update writes static page/total-count strings.
    AllowlistEntry("screens/cloudtrail_browser.py", "_update_pager", "update",
                   "Pager shows 'Page N of M (K events total)' — code-controlled "
                   "count integers, not user streaming data."),

    # cloudtrail_browser.py — fetch status messages are hard-coded strings.
    AllowlistEntry("screens/cloudtrail_browser.py", "action_fetch", "update",
                   "Writes a hard-coded 'Fetching...' status string — no user data."),
    AllowlistEntry("screens/cloudtrail_browser.py", "_fetch_events", "update",
                   "Writes hard-coded status/error strings ('Loading...', 'Error: ...') "
                   "— the error message includes an exception str, not raw AWS data."),

    # cloudwatch_browser.py — pager update and fetch status messages.
    AllowlistEntry("screens/cloudwatch_browser.py", "_update_pager", "update",
                   "Pager writes hard-coded 'Page N of M' count strings — no user data."),
    AllowlistEntry("screens/cloudwatch_browser.py", "action_fetch", "update",
                   "Writes a hard-coded 'Fetching...' status string — no user data."),
    AllowlistEntry("screens/cloudwatch_browser.py", "_fetch_events", "update",
                   "Writes hard-coded status/error strings — exception str only, "
                   "not raw log content."),
    AllowlistEntry("screens/cloudwatch_browser.py", "_cycle_ip_filter", "update",
                   "Writes 'Filter: <label>' where label is from a hard-coded "
                   "tuple of action names — not user-streaming data."),

    # log_viewer.py — probe/start writes hard-coded status and error strings.
    AllowlistEntry("screens/log_viewer.py", "_probe_and_start", "write",
                   "Writes hard-coded status messages (connecting, error) and "
                   "exception strings from SSH probing — not streamed log content."),
    AllowlistEntry("screens/log_viewer.py", "_update_header", "update",
                   "Updates a header label with the instance name (already redacted "
                   "in-place by on_mount redact_instances()) and log path from config."),
    AllowlistEntry("screens/log_viewer.py", "_start_stream", "write",
                   "Writes a hard-coded 'Starting stream...' marker — not log data."),
    AllowlistEntry("screens/log_viewer.py", "_switch_to_log", "write",
                   "Writes a hard-coded '--- Switching to log: <path> ---' banner "
                   "where path comes from the config, not live server output."),

    # team_management.py — Shared Configs push/pull preview Statics only
    # ever contain counts ("Will share: 3 connection profiles, 7 scan rules")
    # and a code-controlled warning string — no user-streamed data.
    AllowlistEntry("screens/team_management.py", "_show_push_config_form", "update",
                   "Push preview Static — renders counts + constant warning text; "
                   "summary dict is built from len() over local config sections."),
    AllowlistEntry("screens/team_management.py", "_show_pull_config_form", "update",
                   "Pull preview Static — renders local→remote counts per section "
                   "from diff_against_local; numerical counts, not user-typed text."),

    # memory.py — sync status and AI summary update UI labels, not raw data.
    AllowlistEntry("screens/memory.py", "_refresh_sync_status", "update",
                   "Updates sync-status labels (last sync time, sync state badge) "
                   "— code-controlled status strings, not memory raw_output."),
    AllowlistEntry("screens/memory.py", "_do_ai_summary_flow", "update",
                   "Updates AI summary UI label with a code-controlled status/error "
                   "string — not memory raw_output content."),
    AllowlistEntry("screens/memory.py", "_after_consent", "update",
                   "Updates AI summary UI label (same function body as "
                   "_do_ai_summary_flow due to nested def) — code-controlled string."),

    # chat_panel.py — banner, stats, quota, and consent modal UI labels.
    AllowlistEntry("widgets/chat_panel.py", "_update_memory_banner", "update",
                   "Updates memory injection status banner with a hard-coded "
                   "label string — not streaming AI response content."),
    AllowlistEntry("widgets/chat_panel.py", "_update_stats", "update",
                   "Updates token count/session stats label with numeric counts "
                   "— code-controlled integers, not AI response content."),
    AllowlistEntry("widgets/chat_panel.py", "_update_quota_footer", "update",
                   "Updates quota/entitlement footer label with plan name and "
                   "usage counts — code-controlled strings, not AI content."),
    AllowlistEntry("widgets/chat_panel.py", "_set_banner", "update",
                   "Updates a UI banner with hard-coded status/warning strings "
                   "— not streaming AI content or user data."),
    AllowlistEntry("widgets/chat_panel.py", "_maybe_push_consent_modal", "update",
                   "Inner _on_dismiss closure updates a config-flag label — "
                   "code-controlled string, not streaming data."),
    AllowlistEntry("widgets/chat_panel.py", "_on_dismiss", "update",
                   "Inner closure of _maybe_push_consent_modal — same justification: "
                   "writes a hard-coded config-decision notification string."),

    # ---------------------------------------------------------------------------
    # Scope-inversion additions (iteration-3): all screens + widgets now linted.
    # Each entry below documents why the un-guarded call is safe.
    # ---------------------------------------------------------------------------

    # ai_conversations_screen.py — on_mount writes empty-string placeholders;
    # _show_empty writes hard-coded no-conversations hints; _set_status writes
    # hard-coded count integers; _set_local_status same pattern.
    AllowlistEntry("screens/ai_conversations_screen.py", "on_mount", "update",
                   "Writes empty-string placeholder ('') to clear the status "
                   "widget on mount — no user-origin data."),
    AllowlistEntry("screens/ai_conversations_screen.py", "_show_empty", "update",
                   "Writes hard-coded 'No previous chats yet' / 'No conversations "
                   "match your filter' hint strings — code-controlled constants."),
    AllowlistEntry("screens/ai_conversations_screen.py", "_set_status", "update",
                   "Writes hard-coded count integers ('N conversations shown') "
                   "— no user-origin streaming data."),
    AllowlistEntry("screens/ai_conversations_screen.py", "_set_local_status", "update",
                   "Writes hard-coded count integers for local session tab "
                   "— same pattern as _set_status."),

    # backup_restore.py — table shows timestamps, file sizes, and config counts
    # (integers + booleans from local file metadata); _set_status writes static
    # result strings.  No server-origin streaming data.
    AllowlistEntry("screens/backup_restore.py", "_render_table", "add_row",
                   "Rows contain only timestamps, byte-sizes, and boolean flags "
                   "from local backup-file metadata — no server-origin streaming data."),
    AllowlistEntry("screens/backup_restore.py", "_set_status", "update",
                   "Writes hard-coded status strings (e.g., 'Restored.') "
                   "— code-controlled constants."),

    # bug_report.py — all update() calls are hard-coded status strings, a
    # redacted-category list (categories are taxonomy like 'ip_address'), a
    # receipt URL/ID, or empty-string clears.  The preview.update(markdown) renders
    # a markdown blob that the bug-report service has already redacted internally
    # (the service redacts before building the payload; _refresh_preview renders
    # that already-redacted payload).
    AllowlistEntry("screens/bug_report.py", "_start_collect", "update",
                   "Writes 'Diagnostics: collecting...' — hard-coded string."),
    AllowlistEntry("screens/bug_report.py", "_do_collect", "update",
                   "Writes hard-coded status strings and a redacted-category list "
                   "(taxonomy like 'ip_address') — no raw server data."),
    AllowlistEntry("screens/bug_report.py", "_refresh_preview", "update",
                   "Renders bug-report preview markdown built by the service after "
                   "its own internal redaction pass — payload is pre-redacted."),
    AllowlistEntry("screens/bug_report.py", "_do_submit", "update",
                   "Writes hard-coded 'Submitting...' and failure retry strings "
                   "— code-controlled constants."),
    AllowlistEntry("screens/bug_report.py", "_show_submission_error", "update",
                   "Writes submission error message via _esc() — exception type "
                   "string from network layer, not raw server data."),
    AllowlistEntry("screens/bug_report.py", "_clear_submission_error", "update",
                   "Writes empty string to clear the error panel "
                   "— no user data involved."),
    AllowlistEntry("screens/bug_report.py", "_show_receipt", "update",
                   "Writes receipt URL and report ID from the Servonaut backend "
                   "— not user-origin server data. URL is a servonaut.io link, "
                   "not a customer hostname."),

    # hetzner_create.py — server types, images, locations, and SSH keys are
    # provider taxonomy from the Hetzner API (product names like 'cx22',
    # 'ubuntu-22.04', 'fsn1'). SSH key names in _load_ssh_keys are user-named
    # but this is a setup wizard that runs before demo recording starts.
    AllowlistEntry("screens/hetzner_create.py", "_load_server_types", "add_row",
                   "Renders Hetzner product taxonomy (server type names, cores, "
                   "memory, price) — provider-defined strings, not user PII."),
    AllowlistEntry("screens/hetzner_create.py", "_load_images", "add_row",
                   "Renders Hetzner image taxonomy (ubuntu-22.04 etc.) "
                   "— provider-defined strings, not user PII."),
    AllowlistEntry("screens/hetzner_create.py", "_load_locations", "add_row",
                   "Renders Hetzner datacenter taxonomy (fsn1, nbg1 etc.) "
                   "— provider-defined strings, not user PII."),
    AllowlistEntry("screens/hetzner_create.py", "_load_ssh_keys", "add_row",
                   "Setup-wizard screen for creating a new server; SSH key names "
                   "shown here are a selection UI before any demo recording begins "
                   "— accepted limitation documented in demo-mode spec §2."),

    # hetzner_manager.py — _render_table feeds from self._instances which is
    # now redacted in-place before _render_table is called (CRITICAL-3.1 fix).
    # _set_status writes only static count strings.
    AllowlistEntry("screens/hetzner_manager.py", "_render_table", "add_row",
                   "self._instances is redacted in-place by redact_instances() "
                   "in _load_instances() before _render_table is called "
                   "(CRITICAL-3.1 fix) — safe by the time it reaches add_row."),
    AllowlistEntry("screens/hetzner_manager.py", "_set_status", "update",
                   "Writes hard-coded count strings ('N servers.') or error "
                   "messages that are scrubbed via scrub_stream in the callers "
                   "(_load_instances, _do_lifecycle, _do_delete)."),

    # hetzner_setup.py — connection test writes hard-coded status/result strings.
    # The 'detail' in _do_test_connection is a project label from the API (ok=True
    # path) or an error message (ok=False path). Both are acceptable leakage for
    # a setup screen that is not in scope for demo recording.
    AllowlistEntry("screens/hetzner_setup.py", "_test_connection", "update",
                   "Writes 'Testing connection...' — hard-coded string."),
    AllowlistEntry("screens/hetzner_setup.py", "_do_test_connection", "update",
                   "Writes hard-coded success/failure strings and project label "
                   "from Hetzner API — setup wizard not in demo recording scope."),

    # hetzner_ssh_keys.py — _set_status writes only static count/error strings;
    # key names are scrubbed in _load_keys (CRITICAL-3.7 addition).
    AllowlistEntry("screens/hetzner_ssh_keys.py", "_set_status", "update",
                   "Writes hard-coded count strings ('N keys.') — no user PII."),

    # key_management.py — _check_agent_status writes code-controlled 'Running' /
    # 'Not Running' / 'Unknown' status labels.  on_worker_state_changed scrubs the
    # ssh-add -l output (key file paths + key comments) via scrub_stream before
    # rendering — no allowlist entry needed for on_worker_state_changed.
    AllowlistEntry("screens/key_management.py", "_check_agent_status", "update",
                   "Writes code-controlled SSH agent status labels ('Running', "
                   "'Not Running', 'Unknown') — no user PII."),

    # log_picker.py — _rebuild_options writes count integers only.
    AllowlistEntry("screens/log_picker.py", "_rebuild_options", "update",
                   "Writes 'N matches (of M total)' count label — "
                   "code-controlled integers, not file content."),

    # login.py — all update() calls are hard-coded login-flow status strings
    # (OAuth device flow URL, 'Logging in...', 'Logged in as ...').
    # The 'Logged in as' string in _show_logged_in_state may carry a username —
    # but the login screen is pre-demo (demo mode cannot be active before login).
    AllowlistEntry("screens/login.py", "_submit", "update",
                   "Writes hard-coded 'Logging in...' / 'Invalid credentials' "
                   "strings — code-controlled login-flow status."),
    AllowlistEntry("screens/login.py", "_show_logged_in_state", "update",
                   "Shows logged-in username and session info — pre-demo screen "
                   "(demo mode cannot be active before login completes)."),
    AllowlistEntry("screens/login.py", "_validate_session", "update",
                   "Writes hard-coded session-validation status strings "
                   "— code-controlled constants."),
    AllowlistEntry("screens/login.py", "_start_login", "update",
                   "Writes 'Starting login...' — hard-coded string."),
    AllowlistEntry("screens/login.py", "_cancel_login", "update",
                   "Writes 'Login cancelled.' — hard-coded string."),
    AllowlistEntry("screens/login.py", "_do_device_flow", "update",
                   "Writes OAuth device-flow URL and polling status — "
                   "pre-demo screen; URL is a servonaut.io auth endpoint."),

    # main_menu.py — _update_stats writes server counts (integers, not names).
    AllowlistEntry("screens/main_menu.py", "_update_stats", "update",
                   "Writes total/running/stopped integer counts — "
                   "no server names or IPs involved."),

    # memory_consent_modal.py — _toggle_details shows/hides static detail text.
    AllowlistEntry("screens/memory_consent_modal.py", "_toggle_details", "update",
                   "Toggles display of hard-coded consent detail text "
                   "— code-controlled static content."),

    # memory_export.py — action_start_export writes static 'not available' error.
    AllowlistEntry("screens/memory_export.py", "action_start_export", "update",
                   "Writes '[red]Export service not available.[/red]' — "
                   "hard-coded error string, no user data."),

    # memory_keys.py — _update_strength and _update_confirm_state write
    # code-controlled strength labels and match/mismatch indicators.
    AllowlistEntry("screens/memory_keys.py", "_update_strength", "update",
                   "Writes password-strength label (Weak/Fair/Strong) "
                   "— code-controlled taxonomy, not user PII."),
    AllowlistEntry("screens/memory_keys.py", "_update_confirm_state", "update",
                   "Writes 'Passwords match / do not match' indicator "
                   "— code-controlled string."),

    # memory_share.py — _do_share writes hard-coded status strings for each
    # phase of the share operation; exception is escaped before embedding.
    AllowlistEntry("screens/memory_share.py", "_do_share", "update",
                   "Writes hard-coded phase-status strings ('Fetching member keys', "
                   "'Sharing...', 'Shared successfully') and an _esc()-wrapped "
                   "exception string — no raw memory content."),

    # memory_sync_setup.py — _set_status writes static Rich markup status;
    # _show_setup_error writes escaped exception type; _set_busy writes a
    # caller-supplied message that is always a code-controlled string.
    AllowlistEntry("screens/memory_sync_setup.py", "_set_status", "update",
                   "Writes hard-coded sync-setup status markup from _render_state "
                   "— code-controlled constants, not memory raw_output."),
    AllowlistEntry("screens/memory_sync_setup.py", "_show_setup_error", "update",
                   "Writes escaped exception message from setup flow — exception "
                   "type, not raw server data."),
    AllowlistEntry("screens/memory_sync_setup.py", "_set_busy", "update",
                   "Writes a busy-state message passed from _do_setup — "
                   "always a code-controlled string constant."),

    # ovh_billing.py — current usage and spend history write formatted currency
    # amounts and dates (no customer hostnames or IPs); invoice page writes
    # structured billing data (invoice ID, amount, status).
    AllowlistEntry("screens/ovh_billing.py", "_load_current_usage", "update",
                   "Writes formatted currency amounts (e.g., '12.50 EUR') "
                   "from _format_current_usage — no hostnames or IPs."),
    AllowlistEntry("screens/ovh_billing.py", "_load_spend_history", "update",
                   "Writes formatted monthly spend table from "
                   "_format_spend_history — amounts and dates only, no PII."),
    AllowlistEntry("screens/ovh_billing.py", "_render_invoice_page", "update",
                   "Writes 'Page N of M' pager string — code-controlled integers."),
    AllowlistEntry("screens/ovh_billing.py", "_render_invoice_page", "add_row",
                   "Invoice rows contain date, invoice ID, amount, status — "
                   "billing metadata, not server hostnames or IPs."),

    # ovh_cloud_create.py — flavors and images are provider taxonomy.
    AllowlistEntry("screens/ovh_cloud_create.py", "_load_flavors", "add_row",
                   "Renders OVH flavor taxonomy (b2-7, c2-7 etc.) — "
                   "provider-defined product names, not user PII."),
    AllowlistEntry("screens/ovh_cloud_create.py", "_load_images", "add_row",
                   "Renders OVH image taxonomy (Ubuntu 22.04 etc.) — "
                   "provider-defined strings, not user PII."),

    # ovh_dns.py — _show_rdns_form displays an IP and IP block the user just
    # selected from the table (those values are already scrubbed in _load_rdns).
    AllowlistEntry("screens/ovh_dns.py", "_show_rdns_form", "update",
                   "Displays IP and IP block from a row already scrubbed in "
                   "_load_rdns when demo_mode is on — safe by the time the form "
                   "is populated."),

    # ovh_firewall.py — _update_status_widget writes hard-coded
    # 'Firewall: Enabled/Disabled' strings.
    AllowlistEntry("screens/ovh_firewall.py", "_update_status_widget", "update",
                   "Writes '[green]Firewall: Enabled[/green]' or "
                   "'[red]Firewall: Disabled[/red]' — hard-coded status strings."),

    # ovh_manager.py — _render_table feeds from self._instances which is now
    # redacted in-place before rendering (CRITICAL-3.2 fix). _set_status writes
    # static count strings or error messages scrubbed in callers.
    AllowlistEntry("screens/ovh_manager.py", "_render_table", "add_row",
                   "self._instances is redacted in-place by redact_instances() "
                   "in _load_instances() before _render_table is called "
                   "(CRITICAL-3.2 fix) — safe by the time it reaches add_row."),
    AllowlistEntry("screens/ovh_manager.py", "_set_status", "update",
                   "Writes hard-coded count strings or error messages that are "
                   "scrubbed via scrub_stream in the callers."),

    # ovh_monitoring.py — metric values are CPU %, memory %, bandwidth bytes —
    # numeric/structured data from provider monitoring API. No hostnames or IPs
    # embedded in the formatted output.
    AllowlistEntry("screens/ovh_monitoring.py", "_load_vps_metrics", "update",
                   "Writes formatted CPU/memory/bandwidth numeric metrics "
                   "— structured provider data, no hostnames or IPs."),
    AllowlistEntry("screens/ovh_monitoring.py", "_load_dedicated_metrics", "update",
                   "Writes formatted dedicated-server numeric metrics "
                   "— same pattern as _load_vps_metrics."),
    AllowlistEntry("screens/ovh_monitoring.py", "_load_cloud_metrics", "update",
                   "Writes formatted cloud-instance numeric metrics "
                   "— same pattern as _load_vps_metrics."),
    AllowlistEntry("screens/ovh_monitoring.py", "_set_loading", "update",
                   "Writes 'Loading...' — hard-coded string."),
    AllowlistEntry("screens/ovh_monitoring.py", "_set_error", "update",
                   "Writes a formatted error string — exception type from the "
                   "monitoring API, not raw server metrics data."),

    # ovh_reinstall.py / ovh_resize.py — images and models are taxonomy.
    AllowlistEntry("screens/ovh_reinstall.py", "_load_images", "add_row",
                   "Renders OVH reinstall image taxonomy "
                   "— provider-defined strings, not user PII."),
    AllowlistEntry("screens/ovh_resize.py", "_load_models", "add_row",
                   "Renders OVH resize model taxonomy (VPS plan names) "
                   "— provider-defined strings, not user PII."),

    # ovh_setup.py — connection test and consumer-key request write hard-coded
    # status and result strings.
    AllowlistEntry("screens/ovh_setup.py", "_do_request_consumer_key", "update",
                   "Writes hard-coded consumer-key request status strings "
                   "— code-controlled constants."),
    AllowlistEntry("screens/ovh_setup.py", "_test_connection", "update",
                   "Writes 'Testing connection...' — hard-coded string."),
    AllowlistEntry("screens/ovh_setup.py", "_do_test_connection", "update",
                   "Writes hard-coded success/failure strings from OVH setup "
                   "— setup wizard not in demo recording scope."),

    # ovh_snapshots.py — _load_vps_backup_status writes hard-coded
    # 'No backup' / 'Enabled' status strings.
    AllowlistEntry("screens/ovh_snapshots.py", "_load_vps_backup_status", "update",
                   "Writes hard-coded backup-status strings ('No automated backup "
                   "configured', state label) — code-controlled constants."),

    # ovh_ssh_keys.py — _refresh writes a status label; _set_status writes
    # count/error strings.  Key names are scrubbed in _load_keys.
    AllowlistEntry("screens/ovh_ssh_keys.py", "_refresh", "update",
                   "Writes a loading/refreshing status label — "
                   "hard-coded string."),
    AllowlistEntry("screens/ovh_ssh_keys.py", "_set_status", "update",
                   "Writes hard-coded count strings ('N keys.') "
                   "— no user PII."),

    # scan_results.py — status messages (_load_cached_results, action_scan_now,
    # on_worker_state_changed) are count-based or hard-coded; _populate_table
    # is now scrubbed.
    AllowlistEntry("screens/scan_results.py", "_load_cached_results", "update",
                   "Writes 'Loaded N cached results' (count integer) or "
                   "'No scan results.' — code-controlled strings."),
    AllowlistEntry("screens/scan_results.py", "action_scan_now", "update",
                   "Writes 'Scanning server...' — hard-coded string."),
    AllowlistEntry("screens/scan_results.py", "on_worker_state_changed", "update",
                   "Writes 'Scan completed: N results found' (count integer) or "
                   "hard-coded failure/empty strings — no raw content."),

    # secrets.py — _render_state writes hard-coded card-placeholder markup;
    # _render_unauthenticated / _render_free_tier / _render_bitwarden /
    # _render_local write hard-coded configuration-state labels (no secret values,
    # only provider/plan indicators).
    AllowlistEntry("screens/secrets.py", "_render_state", "update",
                   "Writes hard-coded card-placeholder markup for the secrets "
                   "provider state — no secret values, only status labels."),
    AllowlistEntry("screens/secrets.py", "_render_unauthenticated", "update",
                   "Writes hard-coded 'login required' markup "
                   "— code-controlled string."),
    AllowlistEntry("screens/secrets.py", "_render_free_tier", "update",
                   "Writes hard-coded 'upgrade required' markup "
                   "— code-controlled string."),
    AllowlistEntry("screens/secrets.py", "_render_bitwarden", "update",
                   "Writes hard-coded Bitwarden config-state labels "
                   "(project name from config shown in _render_bitwarden is a "
                   "user-chosen label, but secrets config screens are excluded "
                   "from demo recording scope per spec §2)."),
    AllowlistEntry("screens/secrets.py", "_render_local", "update",
                   "Writes hard-coded 'local store' provider label "
                   "— code-controlled string."),

    # secrets_list.py — _render_loading writes a static placeholder.
    AllowlistEntry("screens/secrets_list.py", "_render_loading", "update",
                   "Writes '[dim]Loading names…[/dim]' — hard-coded placeholder."),

    # settings.py — _refresh_ai_provider_status writes hard-coded plan/status
    # labels; _refresh_entitlements_then_redraw writes plan-name labels;
    # memory-settings methods write hard-coded status strings.
    # _populate_scan_rules writes rule name + condition + paths from user config —
    # these are user-defined rule names and file paths; scrubbing would break
    # the UI for legitimate use (paths like /etc/nginx are not PII).
    # _populate_connection_rules writes rule names + match conditions — config-layer.
    # _populate_ipban_table writes AWS resource IDs — accepted: setup screen, not
    # in demo recording scope per spec §2.
    # _handle_ipban_discover / _discover_aws_resources write hard-coded hint text.
    # _update_ovh_status / _update_hetzner_status write hard-coded provider status.
    # action_save writes hard-coded 'Saved.' result string.
    AllowlistEntry("screens/settings.py", "_refresh_ai_provider_status", "update",
                   "Writes hard-coded AI provider status labels (plan names, "
                   "quota summary integers) — code-controlled strings."),
    AllowlistEntry("screens/settings.py", "_refresh_entitlements_then_redraw", "update",
                   "Writes hard-coded entitlement / plan preference labels "
                   "— code-controlled strings."),
    AllowlistEntry("screens/settings.py", "_set_memory_settings_disabled", "update",
                   "Writes a hard-coded disabled-state markup passed from callers "
                   "— code-controlled constant."),
    AllowlistEntry("screens/settings.py", "_load_memory_settings", "update",
                   "Writes hard-coded status strings ('Memory settings service "
                   "unavailable', 'Loaded') — code-controlled constants."),
    AllowlistEntry("screens/settings.py", "_do_save_memory_settings", "update",
                   "Writes hard-coded save-flow status strings ('Saving...', "
                   "'Saved', 'No changes') — code-controlled constants."),
    AllowlistEntry("screens/settings.py", "_populate_scan_rules", "add_row",
                   "Renders user-configured scan rule names and file paths — "
                   "config-layer data; file paths like /etc/nginx are not PII. "
                   "Settings screens excluded from demo recording scope per spec §2."),
    AllowlistEntry("screens/settings.py", "_populate_connection_rules", "add_row",
                   "Renders connection rule names and match conditions from user "
                   "config — settings screen, not in demo recording scope."),
    AllowlistEntry("screens/settings.py", "_populate_ipban_table", "add_row",
                   "Renders IP-ban config entries (AWS SG/NACL IDs, WAF IP set "
                   "names) — settings screen not in demo recording scope."),
    AllowlistEntry("screens/settings.py", "_handle_ipban_discover", "update",
                   "Writes '[dim]Discovering...[/dim]' — hard-coded string."),
    AllowlistEntry("screens/settings.py", "_discover_aws_resources", "update",
                   "Writes a hard-coded hint string after discovery finishes "
                   "— code-controlled constant."),
    AllowlistEntry("screens/settings.py", "_update_ovh_status", "update",
                   "Writes hard-coded 'Configured / Not configured' status labels "
                   "for the OVH provider — no credentials or server data."),
    AllowlistEntry("screens/settings.py", "_update_hetzner_status", "update",
                   "Writes hard-coded 'Configured / Not configured' status labels "
                   "for the Hetzner provider — no credentials or server data."),
    AllowlistEntry("screens/settings.py", "action_save", "update",
                   "Writes '[dim]Saved.[/dim]' after saving settings "
                   "— hard-coded confirmation string."),

    # snapshot_manager.py — _submit writes static validation error strings;
    # _set_status writes hard-coded count/result strings.
    AllowlistEntry("screens/snapshot_manager.py", "_submit", "update",
                   "Writes hard-coded label validation error strings "
                   "('Label cannot be empty', 'Label must be 100 chars') "
                   "— code-controlled constants."),
    AllowlistEntry("screens/snapshot_manager.py", "_set_status", "update",
                   "Writes hard-coded count strings ('N snapshots.') or static "
                   "error messages — no server-origin data."),

    # instance_table.py — _refresh_table feeds from self._filtered_instances
    # which comes from self.app.instances already redacted in-place by
    # on_mount/redact_instances() — safe by the time add_row is called.
    AllowlistEntry("widgets/instance_table.py", "_refresh_table", "add_row",
                   "Feeds from self._filtered_instances from self.app.instances "
                   "which is already redacted in-place by on_mount redact_instances() "
                   "— safe by the time add_row is called."),

    # progress_indicator.py — start() receives a caller-supplied message that is
    # always a hard-coded string constant at all call sites; stop() writes ''.
    AllowlistEntry("widgets/progress_indicator.py", "start", "update",
                   "Receives message from callers that are always hard-coded "
                   "string constants (e.g., 'Loading...') — no user-origin data."),
    AllowlistEntry("widgets/progress_indicator.py", "stop", "update",
                   "Writes empty string to hide the indicator — no user data."),

    # relay_indicator.py — _refresh_local writes relay state label and lock owner
    # PID (integer + mode); _refresh_backend writes connection state, last
    # heartbeat timestamp, and client_ids from the relay backend. None of these
    # are user PII — they are internal relay connection metadata.
    AllowlistEntry("widgets/relay_indicator.py", "_refresh_local", "update",
                   "Writes relay lock state label and owner PID/mode (integers) "
                   "— internal relay metadata, not user PII."),
    AllowlistEntry("widgets/relay_indicator.py", "_refresh_backend", "update",
                   "Writes relay backend connection state, heartbeat timestamps, "
                   "and client_ids — internal relay metadata, not user PII."),

    # server_actions.py — _run_ssh_probe writes a private key to a tmpfile
    # (tempfile.NamedTemporaryFile). `tf.write(private_key_body)` is a filesystem
    # write, not a widget write — no user-visible UI widget is involved, and the
    # key material comes from the local Bitwarden vault (not streamed server data).
    AllowlistEntry("screens/server_actions.py", "_run_ssh_probe", "write",
                   "tf.write() is a tempfile filesystem write of the BW private key "
                   "— not a widget write. No user-visible UI surface involved."),

    # ---------------------------------------------------------------------------
    # load_text — TextArea content (added to _GUARDED_ATTRS in iteration-4)
    # ---------------------------------------------------------------------------

    # ai_analysis.py — on_mount loads self._text into the TextArea. self._text is
    # the text passed by the caller at construction time; it comes from
    # log_viewer's scrubbed _content_buffer (already scrubbed before passing here).
    AllowlistEntry("screens/ai_analysis.py", "on_mount", "load_text",
                   "Loads self._text which is supplied by the caller from "
                   "log_viewer's already-scrubbed _content_buffer — safe at "
                   "the point of load_text."),

    # ai_analysis.py — _apply_filter loads filtered lines from self._raw_text.
    # self._raw_text is assigned only from display_log_text which is scrubbed
    # via scrub_stream in _do_fetch_log before being stored — safe.
    AllowlistEntry("screens/ai_analysis.py", "_apply_filter", "load_text",
                   "_raw_text is scrubbed at assignment in _do_fetch_log "
                   "via scrub_stream before being stored — filtered view is safe."),

    # ai_analysis.py — _clear_filter restores self._raw_text directly.
    # Same reasoning as _apply_filter above.
    AllowlistEntry("screens/ai_analysis.py", "_clear_filter", "load_text",
                   "_raw_text is scrubbed at assignment in _do_fetch_log "
                   "via scrub_stream — restoring the unfiltered view is safe."),

    # ai_analysis.py — _run_analysis clears the output TextArea with an empty
    # string before analysis starts — no user data involved.
    AllowlistEntry("screens/ai_analysis.py", "_run_analysis", "load_text",
                   "Loads empty string ('') to clear the output TextArea before "
                   "analysis — no user data."),

    # instance_list.py — _update_detail_panel loads either '' (no selection)
    # or a formatted string built from self._instances fields. All three callers
    # of _update_table() (fetch_instances/background_refresh, ovh_refresh,
    # hetzner_refresh) apply redact_instances() before calling _update_table(),
    # so every path that adds data to self._instances redacts it first. All
    # fields are fake by the time load_text is called.
    AllowlistEntry("screens/instance_list.py", "_update_detail_panel", "load_text",
                   "Loads '' (no selection) or instance fields from "
                   "self._instances. All three populate-callers redact their "
                   "fresh provider data before calling _update_table(); safe "
                   "by the time load_text is called."),

    # chat_panel.py — _send clears the chat input TextArea with '' after reading
    # the user's message — no server-origin data involved.
    AllowlistEntry("widgets/chat_panel.py", "_send", "load_text",
                   "Loads empty string ('') to clear the chat input field after "
                   "reading the user's own message — no server-origin data."),
]

# Build a fast lookup set: (relative_file_path, func_name, attr_name)
_ALLOWLIST_SET: Set[tuple] = {
    (e.file, e.func, e.attr) for e in _ALLOWLIST
}

# Some function names appear in the allowlist for multiple attrs
_ALLOWLIST_FUNC_ATTR_SET: Set[tuple] = {
    (e.file, e.func, e.attr) for e in _ALLOWLIST
}


# ---------------------------------------------------------------------------
# AST analysis helpers
# ---------------------------------------------------------------------------


class _GuardedCallFinder(ast.NodeVisitor):
    """Finds all method calls matching _GUARDED_ATTRS and checks for a
    scrub_stream / redact_* call in the same function body.

    LIMITATION (intentional): the check is function-scoped, not
    call-site-scoped. A function that contains one guarded scrub_stream
    call AND a separate unguarded streaming write in the same body will
    PASS. This sweep catches "a screen forgot demo mode entirely"; it
    does NOT catch "row A was scrubbed, row B in the same method was
    not". Per-call dataflow analysis is out of scope — treat a green
    lint as necessary, not sufficient. Per-call correctness is the job
    of the per-screen coverage tests and the security review.
    """

    def __init__(self, rel_path: str) -> None:
        self.rel_path = rel_path
        self.violations: List[str] = []
        self._current_func: str = "module"
        self._func_stack: List[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._func_stack.append(node.name)
        self._current_func = node.name
        # Collect all Call nodes in this function body
        calls_in_func = [
            n for n in ast.walk(node)
            if isinstance(n, ast.Call)
        ]
        guarded_calls = [
            c for c in calls_in_func
            if (
                isinstance(c.func, ast.Attribute)
                and c.func.attr in _GUARDED_ATTRS
            )
        ]
        # Check whether this function also contains a scrub/redact call
        has_redaction = any(
            (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and (
                    n.func.attr.startswith("scrub")
                    or n.func.attr.startswith("redact")
                )
            )
            or (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name)
                and (
                    n.func.id.startswith("scrub")
                    or n.func.id.startswith("redact")
                )
            )
            or (
                # demo_mode guard check — presence of the guard is sufficient signal
                isinstance(n, ast.If)
                and _contains_demo_mode_check(n)
            )
            for n in ast.walk(node)
        )

        for call in guarded_calls:
            attr = call.func.attr
            key = (self.rel_path, node.name, attr)
            if key in _ALLOWLIST_FUNC_ATTR_SET:
                continue  # Explicitly allow-listed
            if not has_redaction:
                self.violations.append(
                    f"{self.rel_path}::{node.name}() uses .{attr}() "
                    f"(line {call.lineno}) without a scrub/redact guard "
                    f"— add demo-mode guard or add to _ALLOWLIST with justification."
                )

        self.generic_visit(node)
        self._func_stack.pop()
        self._current_func = self._func_stack[-1] if self._func_stack else "module"

    # Also handle async functions
    visit_AsyncFunctionDef = visit_FunctionDef


def _contains_demo_mode_check(node: ast.If) -> bool:
    """Return True if the If-test references demo_mode (heuristic)."""
    src = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
    return "demo_mode" in src


def _find_violations(path: Path) -> List[str]:
    """Parse one Python file and return lint violations."""
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return [f"SyntaxError in {path}: {exc}"]

    rel_path = str(path.relative_to(_SRC_ROOT))
    finder = _GuardedCallFinder(rel_path)
    finder.visit(tree)
    return finder.violations


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


def _collect_target_files() -> List[Path]:
    """Return all .py files under screens/ and widgets/, excluding __init__.py."""
    paths: List[Path] = []
    for d in _TARGET_DIRS:
        paths.extend(sorted((_SRC_ROOT / d).glob("*.py")))
    return [p for p in paths if p.name != "__init__.py"]


def test_no_unguarded_streaming_writes() -> None:
    """Every .write()/.update()/.append_output()/.append_error() on streaming
    content must either have a demo-mode guard or appear in _ALLOWLIST.
    """
    target_files = _collect_target_files()
    assert target_files, "No target files found — check _SCREENS_DIR / _WIDGETS_DIR paths"

    all_violations: List[str] = []
    for path in target_files:
        violations = _find_violations(path)
        all_violations.extend(violations)

    if all_violations:
        report = "\n".join(f"  - {v}" for v in all_violations)
        pytest.fail(
            f"Demo-mode lint: {len(all_violations)} unguarded streaming write(s) found:\n"
            f"{report}\n\n"
            "Fix: add a demo-mode guard (if self.app.demo_mode and self.app.redaction_service:)\n"
            "  OR add an AllowlistEntry to _ALLOWLIST in tests/test_demo_mode_lint.py\n"
            "  with a one-line justification."
        )


def test_allowlist_entries_reference_real_files() -> None:
    """Every allowlist entry must reference an existing file to catch stale entries."""
    missing = []
    for entry in _ALLOWLIST:
        full_path = _SRC_ROOT / entry.file
        if not full_path.exists():
            missing.append(f"{entry.file} (allowlist entry for {entry.func}.{entry.attr})")
    if missing:
        report = "\n".join(f"  - {m}" for m in missing)
        pytest.fail(
            f"Stale _ALLOWLIST entries point to non-existent files:\n{report}\n"
            "Remove or update the entry."
        )
