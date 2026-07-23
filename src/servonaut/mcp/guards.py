"""Guard system for MCP server command safety."""
from __future__ import annotations

import re
import logging
from typing import List, Tuple

logger = logging.getLogger(__name__)


class GuardLevel:
    READONLY = "readonly"
    STANDARD = "standard"
    DANGEROUS = "dangerous"


class CommandGuard:
    """Validates commands against guard level and blocklist/allowlist."""

    def __init__(self, config, config_manager=None) -> None:
        """config is MCPConfig instance. config_manager enables live config reload."""
        self._level = config.guard_level
        self._blocklist = [re.compile(p) for p in config.command_blocklist]
        self._allowlist = config.command_allowlist
        self._config_manager = config_manager

    def _get_allowlist(self) -> List[str]:
        """Get current allowlist, re-reading from config if manager available."""
        if self._config_manager:
            return self._config_manager.get().mcp.command_allowlist
        return self._allowlist

    def check_command(self, command: str) -> Tuple[bool, str]:
        """Check if command is allowed. Returns (allowed: bool, reason: str)."""
        # Blocklist ALWAYS enforced, even in dangerous mode
        for pattern in self._blocklist:
            if pattern.search(command):
                return False, f"Command matches blocklist pattern: {pattern.pattern}"

        if self._level == GuardLevel.READONLY:
            return False, "Command execution not allowed in readonly mode"

        if self._level == GuardLevel.STANDARD:
            # Check if command starts with an allowed command
            cmd_base = command.strip().split()[0] if command.strip() else ""
            # Handle sudo prefix
            if cmd_base == "sudo" and len(command.strip().split()) > 1:
                cmd_base = command.strip().split()[1]
            if cmd_base not in self._get_allowlist():
                return False, f"Command '{cmd_base}' not in allowlist for standard mode"

        # Dangerous mode: allowed (passed blocklist check)
        return True, "OK"

    def check_tool(self, tool_name: str) -> Tuple[bool, str]:
        """Check if a tool is allowed at current guard level. Returns (allowed, reason)."""
        readonly_tools = {
            'list_instances', 'check_status', 'get_server_info',
            'ovh_monitoring', 'ovh_list_ips', 'ovh_firewall_rules',
            'ovh_ssh_keys', 'ovh_snapshots', 'ovh_dns_records',
            'ovh_billing', 'ovh_invoices',
            # Session / backend introspection — never mutates anything and
            # never reveals the OAuth bearer, so it's safe at every level.
            'whoami', 'relay_status',
            # Server memory — reads from disk cache only; no SSH round-trip.
            'get_server_memory', 'list_server_memories',
            # recall_server_findings: reads persisted findings from disk; no SSH.
            'recall_server_findings',
            # Hetzner — readonly catalogue / inventory queries.
            'hetzner_list_servers', 'hetzner_list_server_types',
            'hetzner_list_ssh_keys',
            # AWS CloudWatch Logs / CloudTrail — purely read-only AWS API
            # queries (describe / filter / lookup); they mutate nothing.
            'cloudwatch_list_log_groups', 'cloudwatch_get_log_events',
            'cloudwatch_top_ips', 'cloudwatch_insights', 'cloudtrail_lookup_events',
            # Generic AWS read passthrough — verb-allowlisted to Describe/Get/
            # List/Filter/Lookup at the tool layer, IAM is the real backstop.
            # Read posture, so available at readonly tier like cloudwatch_*.
            # The mutating path is gated separately via 'aws_call_mutate'.
            'aws_call',
            # IP ban inventory — reads existing WAF/SG/NACL state only.
            'ip_ban_list_configs', 'ip_ban_list_banned',
            # AWS — readonly catalogue / inventory queries.
            'aws_list_regions', 'aws_list_amis', 'aws_list_instance_types',
            'aws_list_key_pairs', 'aws_list_subnets', 'aws_list_security_groups',
            # S3 — read tools (provider-parameterised).
            's3_list_buckets', 's3_list_objects',
            # Incident-response read-only probes. web_traffic_summary and
            # fleet_health_snapshot run SSH info-gathering commands — same
            # read-only posture as get_server_info (also readonly). enrich_ips
            # is network-only (rDNS / ASN / abuse lookups).
            'web_traffic_summary', 'fleet_health_snapshot', 'enrich_ips',
            # describe_ingress_path is boto3 elbv2/wafv2/ec2 Describe — pure
            # read-only AWS topology, same posture as cloudwatch_* / cloudtrail_*.
            'describe_ingress_path',
            # rds_metrics is boto3 cloudwatch:GetMetricStatistics — read-only.
            'rds_metrics',
            # Docker container probes — read-only `docker ps/stats/logs/
            # events` over SSH (sudo -n fallback, never prompts). Same
            # posture as fleet_health_snapshot; feeds container-aware
            # proactive monitoring.
            'docker_ps', 'docker_stats', 'docker_logs',
            'docker_events_summary', 'docker_log_summary',
            # System-health probes — journald error/OOM/restart
            # aggregation, TLS cert expiry discovery, and SSH auth-log
            # summaries. Read-only over SSH with sudo -n fallback.
            'journal_errors', 'tls_cert_check', 'auth_log_summary',
            'disk_usage', 'pending_updates', 'security_audit',
            'disk_usage', 'pending_updates', 'service_state',
        }
        standard_tools = readonly_tools | {
            'run_command', 'get_logs',
            # Authenticated REST calls go through the backend's own authz,
            # so "standard" is the right level: run_command equivalent but
            # targeting the servonaut.dev API. Not readonly because agents
            # could POST state-changing payloads through it.
            'api_request', 'mcp_tool_call', 'relay_reconnect',
            # build/refresh_server_memory trigger SSH probing — side-effectful.
            'build_server_memory', 'refresh_server_memory',
            # remember_server_finding writes to disk + queues for sync — standard tier.
            'remember_server_finding',
            # Hetzner — registers an SSH key but spawns no servers, so
            # "standard" is the appropriate floor.
            'hetzner_create_ssh_key',
            # Hetzner power management — boots / halts an existing server.
            # No data destruction, no new billing entity. Standard mode is
            # the right tier so an agent can recover a stuck server
            # without escalating to "dangerous".
            'hetzner_power_on', 'hetzner_power_off',
            'hetzner_shutdown', 'hetzner_reboot',
            # OVH lifecycle on existing instances — analogous to Hetzner
            # power management. start_instance is the most "expensive"
            # of the three (resumes Cloud billing) but doesn't allocate
            # a new server, so standard is still appropriate.
            'ovh_start_instance', 'ovh_stop_instance', 'ovh_reboot_instance',
            # AWS power management on existing instances.
            'aws_start_instance', 'aws_stop_instance', 'aws_reboot_instance',
            # S3 read-to-local — analogous to get_logs / transfer_file (download).
            's3_download_object',
            # DB introspection — read-only queries, but they execute a DB
            # client on the box using stored credentials, so they sit at the
            # standard tier (alongside run_command) rather than readonly.
            'db_processlist', 'db_top_queries',
            # DB credential setup: scan reads secrets on the box (side-effectful
            # SSH); save writes the secret store + local config. Neither touches
            # a cloud resource, so standard (not dangerous) — the staging-token
            # design keeps the plaintext out of the model context regardless.
            'db_setup_scan', 'db_setup_save', 'db_setup_remove',
        }
        dangerous_tools = standard_tools | {
            'transfer_file',
            # IP ban mutation — adds/removes a deny rule in WAF, a security
            # group, or a NACL. Security-sensitive and immediately affects
            # live traffic, so it stays at the dangerous tier.
            'ip_ban_set',
            # Group C WAF mitigation — mutate live WebACL rules / firewall.
            'waf_rate_rule_set', 'block_ip',
            # Mutating tools that cost money / cannot be undone without
            # re-creating from scratch. Reserved for dangerous mode.
            'hetzner_create_server', 'hetzner_delete_server',
            'ovh_create_instance', 'ovh_delete_instance',
            # Removing an SSH key from the project registry: the
            # asymmetric counterpart to ``create_ssh_key`` (standard
            # tier) — kept at dangerous because losing the registry
            # entry means future create_server calls referencing it
            # by name will fail and the key has to be re-uploaded.
            'hetzner_delete_ssh_key',
            # AWS — costs money / irreversible.
            'aws_terminate_instance', 'aws_run_instances',
            # Generic AWS mutate passthrough — the write half of aws_call.
            # Pseudo-tool checked only when aws_call is invoked with mutate=true,
            # so arbitrary state changes require the dangerous tier (destructive
            # delete/terminate verbs are still hard-refused at the tool layer).
            'aws_call_mutate',
            # S3 — every mutation + presigned URL (URL is a bearer secret).
            's3_create_bucket', 's3_delete_bucket', 's3_upload_object',
            's3_delete_object', 's3_copy_object', 's3_move_object',
            's3_generate_presigned_url',
        }

        if self._level == GuardLevel.READONLY:
            if tool_name not in readonly_tools:
                return False, f"Tool '{tool_name}' not available in readonly mode"
        elif self._level == GuardLevel.STANDARD:
            if tool_name not in standard_tools:
                return False, f"Tool '{tool_name}' not available in standard mode"
        # Dangerous: all tools allowed

        return True, "OK"
