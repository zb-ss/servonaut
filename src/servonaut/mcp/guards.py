"""Guard system for MCP server command safety."""
from __future__ import annotations

import re
import logging
import shlex
from typing import Callable, Dict, FrozenSet, List, Sequence, Tuple

logger = logging.getLogger(__name__)

# The standard tier runs single read-only commands, optionally piped into
# other allowlisted commands. These sequences start a command substitution or
# end the command line, so they are refused anywhere in the string, including
# inside quotes.
_FORBIDDEN_SEQUENCES: Tuple[str, ...] = ("\n", "\r", "\x00", "`", "$(", "${")
_PIPE = "|"
_REPORTED_NAME_LIMIT = 64

# Options that turn an otherwise read-only allowlisted command into one that
# writes files, runs other programs or changes system state. They apply to the
# default allowlist; commands a user adds to the allowlist only get the
# operator checks.
_FIND_ACTIONS: FrozenSet[str] = frozenset({
    "-exec", "-execdir", "-ok", "-okdir", "-delete",
    "-fprint", "-fprint0", "-fprintf", "-fls",
})
# ``ip OBJECT [VERB ...]``: only these full verbs are accepted, because ip
# resolves abbreviated verbs itself (a one-letter verb can mean delete).
_IP_READ_VERBS: FrozenSet[str] = frozenset({"show", "list", "lst", "ls", "get", "help"})
# Global ip options that consume the next word as their value.
_IP_VALUE_OPTIONS: FrozenSet[str] = frozenset({
    "-f", "-family", "-n", "-netns", "-l", "-loops", "-rc", "-rcvbuf",
})
_IFCONFIG_READ_FLAGS: FrozenSet[str] = frozenset({"-a", "-s", "-v"})
_HOSTNAME_READ_FLAGS: FrozenSet[str] = frozenset({
    "-s", "--short", "-f", "--fqdn", "--long", "-d", "--domain",
    "-i", "--ip-address", "-I", "--all-ip-addresses", "-A", "--all-fqdns",
    "-a", "--alias", "-y", "--yp", "--nis", "-V", "--version", "-h", "--help",
})
_DATE_SET_OPERAND = re.compile(r"^[0-9.]{6,}$")


def _short_flags(arg: str) -> str:
    """Letters of a bundled short-option token such as ``-tK``, else ''."""
    if arg.startswith("-") and not arg.startswith("--") and len(arg) > 1:
        return arg[1:]
    return ""


def _long_option_matches(arg: str, name: str) -> bool:
    """GNU tools accept any unambiguous prefix of a long option (``--outp``)."""
    if not arg.startswith("--") or len(arg) <= 2:
        return False
    return name.startswith(arg.split("=", 1)[0])


def _has_option(args: Sequence[str], short: str, long: str) -> bool:
    return any(
        _long_option_matches(arg, long) or (short and short in _short_flags(arg))
        for arg in args
    )


def _find_reason(args: Sequence[str]) -> str:
    if any(arg in _FIND_ACTIONS for arg in args):
        return "find actions that run programs, delete or write files are not allowed"
    return ""


def _sort_reason(args: Sequence[str]) -> str:
    if _has_option(args, "o", "--output"):
        return "sort output files are not allowed"
    if _has_option(args, "", "--compress-program"):
        return "sort helper programs are not allowed"
    return ""


def _date_reason(args: Sequence[str]) -> str:
    sets_clock = any(
        _long_option_matches(arg, "--set")
        or (not arg.startswith("-I") and "s" in _short_flags(arg))
        or _DATE_SET_OPERAND.match(arg)
        for arg in args
    )
    return "setting the date is not allowed" if sets_clock else ""


def _ss_reason(args: Sequence[str]) -> str:
    if _has_option(args, "K", "--kill"):
        return "closing sockets is not allowed"
    if _has_option(args, "D", "--diag"):
        return "writing socket dumps is not allowed"
    return ""


def _file_reason(args: Sequence[str]) -> str:
    if _has_option(args, "C", "--compile"):
        return "compiling magic files is not allowed"
    return ""


def _ping_reason(args: Sequence[str]) -> str:
    if any("f" in _short_flags(arg) for arg in args):
        return "flood ping is not allowed"
    return ""


def _ip_positionals(args: Sequence[str]) -> List[str]:
    words: List[str] = []
    skip_value = False
    for arg in args:
        if skip_value:
            skip_value = False
        elif arg.startswith("-"):
            skip_value = arg in _IP_VALUE_OPTIONS
        else:
            words.append(arg)
    return words


def _ip_reason(args: Sequence[str]) -> str:
    if any(arg.startswith(("-b", "-for")) for arg in args):
        return "ip batch and force options are not allowed"
    words = _ip_positionals(args)
    if len(words) >= 2 and words[1] not in _IP_READ_VERBS:
        return "only ip show, list and get are allowed"
    return ""


def _ifconfig_reason(args: Sequence[str]) -> str:
    operands = [arg for arg in args if arg not in _IFCONFIG_READ_FLAGS]
    if len(operands) > 1 or any(arg.startswith("-") for arg in operands):
        return "ifconfig may only show interfaces"
    return ""


def _hostname_reason(args: Sequence[str]) -> str:
    if any(arg not in _HOSTNAME_READ_FLAGS for arg in args):
        return "hostname may only print names and addresses"
    return ""


_ARGUMENT_RULES: Dict[str, Callable[[Sequence[str]], str]] = {
    "find": _find_reason,
    "sort": _sort_reason,
    "date": _date_reason,
    "ss": _ss_reason,
    "file": _file_reason,
    "ping": _ping_reason,
    "ip": _ip_reason,
    "ifconfig": _ifconfig_reason,
    "hostname": _hostname_reason,
}


# Tokens made only of these characters reach the remote shell unquoted, so
# paths, globs and a leading ``~`` keep working. Every other token is quoted.
_PLAIN_TOKEN = re.compile(r"^[A-Za-z0-9_@%+=:,./*?~\[\]-]+$")


def _tokenize(command: str) -> List[str]:
    """Split like a POSIX shell, keeping operators outside quotes as tokens."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def _pipeline_segments(tokens: Sequence[str]) -> List[List[str]]:
    segments: List[List[str]] = [[]]
    for token in tokens:
        if token == _PIPE:
            segments.append([])
        else:
            segments[-1].append(token)
    return segments


def _is_operator(token: str) -> bool:
    return bool(token) and all(char in "();<>|&" for char in token)


def _reported(name: str) -> str:
    return name[:_REPORTED_NAME_LIMIT]


def _check_segment(segment: List[str], allowlist: Sequence[str]) -> Tuple[bool, str]:
    if not segment:
        return False, "Empty pipeline segment is not allowed in standard mode"
    words = segment[1:] if segment[0] == "sudo" else segment
    if not words:
        return False, "sudo must be followed by an allowlisted command"
    if words[0].startswith("-"):
        return False, "sudo options are not allowed in standard mode"
    command, args = words[0], words[1:]
    if command not in allowlist:
        return False, f"Command '{_reported(command)}' not in allowlist for standard mode"
    rule = _ARGUMENT_RULES.get(command)
    reason = rule(args) if rule else ""
    if reason:
        return False, f"Not allowed in standard mode: {reason}"
    return True, "OK"


def _render_token(token: str) -> str:
    return token if _PLAIN_TOKEN.match(token) else shlex.quote(token)


def render_standard_command(command: str) -> str:
    """Rebuild an accepted standard-tier command from its checked tokens.

    The remote login shell then sees exactly the words that were checked:
    pipes between segments and literal arguments, whatever shell it is.
    """
    segments = _pipeline_segments(_tokenize(command))
    return " | ".join(
        " ".join(_render_token(token) for token in segment) for segment in segments
    )


def check_standard_command(command: str, allowlist: Sequence[str]) -> Tuple[bool, str]:
    """Allow read-only allowlisted commands, optionally piped, and nothing else."""
    if any(sequence in command for sequence in _FORBIDDEN_SEQUENCES):
        return False, "Command substitution and multiple lines are not allowed in standard mode"
    try:
        tokens = _tokenize(command)
    except ValueError:
        return False, "Command has unbalanced quotes"
    if not tokens:
        return False, "Empty command is not allowed"
    for token in tokens:
        if _is_operator(token) and token != _PIPE:
            return False, (
                "Only single pipes between allowlisted commands are allowed in standard mode; "
                "use the dangerous tier for command lists, redirects or subshells"
            )
    for segment in _pipeline_segments(tokens):
        allowed, reason = _check_segment(segment, allowlist)
        if not allowed:
            return False, reason
    return True, "OK"


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
            return check_standard_command(command, self._get_allowlist())

        # Dangerous mode: allowed (passed blocklist check)
        return True, "OK"

    def command_for_execution(self, command: str) -> str:
        """The string to run after ``check_command`` accepted ``command``.

        At the standard tier the command is rebuilt from its checked tokens so
        the remote shell cannot parse it differently; other tiers run it as is.
        """
        if self._level == GuardLevel.STANDARD:
            return render_standard_command(command)
        return command

    def check_tool(self, tool_name: str) -> Tuple[bool, str]:
        """Check if a tool is allowed at current guard level. Returns (allowed, reason)."""
        readonly_tools = {
            'list_instances', 'check_status', 'get_server_info',
            'ovh_list_ips', 'ovh_firewall_rules',
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
            'service_state',
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
