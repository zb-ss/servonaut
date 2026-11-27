"""Classification and origin helpers for MCP / Agent audit entries.

Classifies every tool invocation by:
- ``op_class``: broad execution scope (``remote_command``, ``remote_probe``,
  ``remote_transfer``, ``remote_db``, ``cloud_api``, ``local_or_meta``)
- ``remote_exec``: whether the tool executes on or transfers to/from a remote host
- ``command_category``: finer-grained intent for shell commands run on remotes
  (``readonly_inspect``, ``service_control``, ``file_write``, ``package_deploy``,
  ``network_firewall``, ``user_privilege``, ``other_mutating``, ``blocked``), or
  ``op_class`` for non-shell tools
- ``command_stems`` & ``used_sudo``: parsed command names and sudo usage for
  ``run_command`` entries

Pure Python with no I/O so it is safe to run both on the write path and as a
read-time fallback for historical pre-enrichment audit rows.
"""
from __future__ import annotations

import re
import shlex
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

from servonaut.mcp.guards import (
    _ARGUMENT_RULES,
    _FORBIDDEN_SEQUENCES,
    _PIPE,
    _is_operator,
    _pipeline_segments,
    _tokenize,
)

# Canonical origin values displayed in the TUI and CLI.
VALID_ORIGINS: FrozenSet[str] = frozenset({"mcp", "ui", "relay", "proactive"})

# Canonical operation classes.
OP_REMOTE_COMMAND = "remote_command"
OP_REMOTE_PROBE = "remote_probe"
OP_REMOTE_TRANSFER = "remote_transfer"
OP_REMOTE_DB = "remote_db"
OP_CLOUD_API = "cloud_api"
OP_LOCAL_OR_META = "local_or_meta"

# Canonical shell command categories (for run_command).
CMD_READONLY_INSPECT = "readonly_inspect"
CMD_SERVICE_CONTROL = "service_control"
CMD_FILE_WRITE = "file_write"
CMD_PACKAGE_DEPLOY = "package_deploy"
CMD_NETWORK_FIREWALL = "network_firewall"
CMD_USER_PRIVILEGE = "user_privilege"
CMD_OTHER_MUTATING = "other_mutating"
CMD_BLOCKED = "blocked"

ALL_CATEGORIES: Tuple[str, ...] = (
    CMD_READONLY_INSPECT,
    CMD_SERVICE_CONTROL,
    CMD_FILE_WRITE,
    CMD_PACKAGE_DEPLOY,
    CMD_NETWORK_FIREWALL,
    CMD_USER_PRIVILEGE,
    CMD_OTHER_MUTATING,
    CMD_BLOCKED,
    OP_REMOTE_PROBE,
    OP_REMOTE_TRANSFER,
    OP_REMOTE_DB,
    OP_CLOUD_API,
    OP_LOCAL_OR_META,
)

# Tools that execute built-in read-only probes over SSH on remote hosts.
_REMOTE_PROBE_TOOLS: FrozenSet[str] = frozenset({
    "get_server_info",
    "get_logs",
    "web_traffic_summary",
    "fleet_health_snapshot",
    "disk_usage",
    "docker_ps",
    "docker_stats",
    "docker_logs",
    "docker_events_summary",
    "docker_log_summary",
    "journal_errors",
    "tls_cert_check",
    "auth_log_summary",
    "pending_updates",
    "security_audit",
    "service_state",
    "build_server_memory",
    "refresh_server_memory",
    "inspect_logs",
    "tail_log",
})

_REMOTE_TRANSFER_TOOLS: FrozenSet[str] = frozenset({
    "transfer_file",
})

_REMOTE_DB_TOOLS: FrozenSet[str] = frozenset({
    "db_processlist",
    "db_top_queries",
    "db_setup_scan",
})

_REMOTE_COMMAND_TOOLS: FrozenSet[str] = frozenset({
    "run_command",
    "ssh_exec",
    "ssh_exec_readonly",
})

_CLOUD_API_PREFIXES: Tuple[str, ...] = (
    "aws_",
    "ovh_",
    "hetzner_",
    "cloudwatch_",
    "cloudtrail_",
    "s3_",
    "ip_ban_",
    "waf_",
)

_CLOUD_API_EXACT: FrozenSet[str] = frozenset({
    "block_ip",
    "describe_ingress_path",
    "rds_metrics",
})

# Default read-only command stems (matches MCPConfig.command_allowlist + common
# safe inspection binaries whose read-only subcommands are checked below).
_READONLY_STEMS: FrozenSet[str] = frozenset({
    "ls", "cat", "grep", "egrep", "fgrep", "rg", "zgrep", "zcat",
    "ps", "df", "du", "top", "htop", "free", "uptime", "whoami", "id",
    "hostname", "uname", "date", "w", "who", "last", "netstat", "ss",
    "ip", "ifconfig", "ping", "dig", "nslookup", "host", "traceroute",
    "head", "tail", "wc", "sort", "uniq", "cut", "awk", "tr", "find",
    "file", "stat", "lsof", "lsblk", "blkid", "mount", "dmesg", "env",
    "printenv", "which", "readlink", "realpath", "journalctl", "timedatectl",
    "hostnamectl", "loginctl", "nproc", "vmstat", "iostat", "mpstat", "sar",
    "openssl", "md5sum", "sha256sum", "cksum", "diff", "less", "more",
    "strings", "echo", "printf", "test", "true", "false", "pwd", "tree",
    "crontab", "apachectl", "apache2ctl", "nginx", "php", "python", "python3",
})

_SERVICE_CONTROL_STEMS: FrozenSet[str] = frozenset({
    "systemctl", "service", "supervisorctl", "pm2", "initctl", "rc-service",
    "sv", "kill", "pkill", "killall", "reboot", "shutdown", "halt", "poweroff",
})
_SYSTEMCTL_READ_VERBS: FrozenSet[str] = frozenset({
    "status", "is-active", "is-enabled", "is-failed", "show", "cat",
    "list-units", "list-unit-files", "list-timers", "list-sockets",
    "list-dependencies", "help",
})
_DOCKER_READ_VERBS: FrozenSet[str] = frozenset({
    "ps", "stats", "logs", "inspect", "images", "info", "version",
    "events", "top", "port", "diff", "history", "network", "volume",
})
_DOCKER_WRITE_VERBS: FrozenSet[str] = frozenset({
    "restart", "stop", "start", "kill", "rm", "rmi", "up", "down",
    "exec", "run", "build", "pull", "push", "prune", "pause", "unpause",
    "update", "rename", "cp",
})
_PACKAGE_DEPLOY_STEMS: FrozenSet[str] = frozenset({
    "apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "apk", "pacman",
    "snap", "pip", "pip3", "uv", "npm", "npx", "yarn", "pnpm", "composer",
    "gem", "cargo", "go", "git", "rsync", "tar", "unzip", "gunzip", "gzip",
    "make", "cmake", "ansible", "terraform", "helm", "kubectl",
})
_FILE_WRITE_STEMS: FrozenSet[str] = frozenset({
    "rm", "mv", "cp", "mkdir", "rmdir", "touch", "tee", "truncate",
    "ln", "chmod", "chown", "chgrp", "dd", "mkfs", "fdisk", "parted",
    "install", "patch", "ed", "ex", "vi", "vim", "nano",
})
_NETWORK_FIREWALL_STEMS: FrozenSet[str] = frozenset({
    "iptables", "ip6tables", "nft", "ufw", "firewall-cmd", "fail2ban-client",
    "curl", "wget", "nc", "ncat", "socat", "route", "tc", "ethtool",
    "nmcli", "wg", "wg-quick",
})
_USER_PRIVILEGE_STEMS: FrozenSet[str] = frozenset({
    "useradd", "usermod", "userdel", "groupadd", "groupmod", "groupdel",
    "adduser", "deluser", "passwd", "chpasswd", "visudo", "su", "chage",
    "setfacl", "usermod",
})

# Priority order when a pipeline/compound command mixes categories.
_CATEGORY_PRIORITY: Dict[str, int] = {
    CMD_USER_PRIVILEGE: 70,
    CMD_NETWORK_FIREWALL: 60,
    CMD_FILE_WRITE: 50,
    CMD_SERVICE_CONTROL: 45,
    CMD_PACKAGE_DEPLOY: 40,
    CMD_OTHER_MUTATING: 30,
    CMD_READONLY_INSPECT: 10,
}

_REDIRECT_RE = re.compile(r"(^|[^0-9])(>>?|<<?)")
_SED_INPLACE_RE = re.compile(r"(^|\s)-i(\S*|\s|$)")
_BLOCKED_REASON_MARKERS: Tuple[str, ...] = (
    "team_rule",
    "blocklist",
    "not in allowlist",
    "not allowed",
    "readonly mode",
    "standard mode",
    "user_declined",
    "confirm_denied",
    "denied",
    "blocked",
    "aws_switched_off",
    "forbidden",
)


def infer_origin(entry: Mapping[str, Any]) -> str:
    """Resolve an entry's origin (``mcp``, ``ui``, ``relay``, ``proactive``).

    Explicit ``origin`` wins; older entries without ``origin`` fall back to
    ``source`` so historical logs render accurately.
    """
    explicit = str(entry.get("origin") or "").strip().lower()
    if explicit:
        return explicit
    source = str(entry.get("source") or "").strip().lower()
    if source == "proactive":
        return "proactive"
    if source == "ai_chat":
        return "ui"
    if source in ("", "mcp"):
        return "mcp"
    return source


def infer_transport(entry: Mapping[str, Any]) -> str:
    """Resolve an entry's transport (``ssh``, ``ssm``, ``scp``, or ``""``)."""
    used = str(entry.get("transport_used") or "").strip().lower()
    if used:
        return used
    tool = str(entry.get("tool") or "")
    args = entry.get("args") if isinstance(entry.get("args"), Mapping) else {}
    if tool in _REMOTE_TRANSFER_TOOLS:
        return "scp"
    if tool in _REMOTE_COMMAND_TOOLS:
        req = str(args.get("transport") or "").strip().lower()
        if req in ("ssh", "ssm"):
            return req
        reason = str(entry.get("reason") or "").lower()
        if reason.startswith("ssm"):
            return "ssm"
        if reason.startswith("ssh") or "ssh" in reason:
            return "ssh"
        return "auto" if req == "auto" else ""
    if tool in _REMOTE_PROBE_TOOLS or tool in _REMOTE_DB_TOOLS:
        return "ssh"
    return ""


def _extract_segments(command: str) -> Tuple[List[List[str]], bool, bool]:
    """Split *command* into command segments, noting sudo and redirect/compound ops.

    Returns ``(segments, used_sudo, has_write_operator)``.
    """
    used_sudo = False
    has_write_op = False
    try:
        tokens = _tokenize(command)
    except ValueError:
        # Unbalanced quotes — fall back to simple whitespace split.
        tokens = command.split()

    segments: List[List[str]] = [[]]
    for token in tokens:
        if token in (">", ">>", "2>", "2>>", "&>", "&>>", ">|"):
            has_write_op = True
            segments.append([])
        elif token == _PIPE or _is_operator(token):
            segments.append([])
        else:
            segments[-1].append(token)

    cleaned: List[List[str]] = []
    for seg in segments:
        if not seg:
            continue
        idx = 0
        # Skip leading KEY=VAL env assignments.
        while idx < len(seg) and "=" in seg[idx] and not seg[idx].startswith("-"):
            idx += 1
        words = seg[idx:]
        if not words:
            continue
        if words[0] == "sudo":
            used_sudo = True
            # Skip sudo flags (e.g. -n, -u root).
            w_idx = 1
            while w_idx < len(words) and words[w_idx].startswith("-"):
                flag = words[w_idx]
                w_idx += 2 if flag in ("-u", "-g", "-C", "-h", "-p", "-r", "-t") else 1
            words = words[w_idx:]
        if words:
            cleaned.append(words)
    return cleaned, used_sudo, has_write_op


def _classify_segment(words: List[str]) -> str:
    """Classify one parsed command segment (after stripping sudo)."""
    stem = words[0].rsplit("/", 1)[-1]
    args = words[1:]

    if stem in _USER_PRIVILEGE_STEMS:
        return CMD_USER_PRIVILEGE

    if stem in _NETWORK_FIREWALL_STEMS:
        if stem in ("curl", "wget"):
            # Read-only GET without output file vs writing/mutating request.
            if any(a in ("-o", "-O", "--output", "-X", "--request", "-d", "--data", "--data-raw", "-F", "--form") for a in args):
                return CMD_NETWORK_FIREWALL
            return CMD_READONLY_INSPECT
        if stem == "ufw" and args and args[0] == "status":
            return CMD_READONLY_INSPECT
        if stem == "iptables" and any(a in ("-L", "-S", "--list", "--list-rules") for a in args):
            return CMD_READONLY_INSPECT
        return CMD_NETWORK_FIREWALL

    if stem == "ip":
        rule = _ARGUMENT_RULES.get("ip")
        return CMD_READONLY_INSPECT if (rule and not rule(args)) else CMD_NETWORK_FIREWALL

    if stem == "ifconfig":
        rule = _ARGUMENT_RULES.get("ifconfig")
        return CMD_READONLY_INSPECT if (rule and not rule(args)) else CMD_NETWORK_FIREWALL

    if stem == "systemctl":
        verb = next((a for a in args if not a.startswith("-")), "")
        if verb in _SYSTEMCTL_READ_VERBS:
            return CMD_READONLY_INSPECT
        return CMD_SERVICE_CONTROL

    if stem == "service":
        if len(args) >= 2 and args[1] == "status":
            return CMD_READONLY_INSPECT
        return CMD_SERVICE_CONTROL

    if stem == "docker":
        sub = next((a for a in args if not a.startswith("-")), "")
        if sub == "compose":
            sub2 = next((a for a in args[args.index(sub) + 1:] if not a.startswith("-")), "")
            if sub2 in ("ps", "logs", "config", "images", "ls", "top", "version"):
                return CMD_READONLY_INSPECT
            return CMD_SERVICE_CONTROL
        if sub in _DOCKER_READ_VERBS:
            if sub in ("network", "volume"):
                sub2 = next((a for a in args[args.index(sub) + 1:] if not a.startswith("-")), "")
                return CMD_READONLY_INSPECT if sub2 in ("ls", "inspect") else CMD_SERVICE_CONTROL
            return CMD_READONLY_INSPECT
        if sub in _DOCKER_WRITE_VERBS:
            return CMD_SERVICE_CONTROL
        return CMD_OTHER_MUTATING

    if stem in _SERVICE_CONTROL_STEMS:
        return CMD_SERVICE_CONTROL

    if stem in _FILE_WRITE_STEMS:
        return CMD_FILE_WRITE

    if stem == "sed":
        if any(a == "-i" or a.startswith("-i") or a == "--in-place" or a.startswith("--in-place=") for a in args):
            return CMD_FILE_WRITE
        return CMD_READONLY_INSPECT

    if stem in _PACKAGE_DEPLOY_STEMS:
        if stem == "git":
            sub = next((a for a in args if not a.startswith("-")), "")
            if sub in ("status", "log", "diff", "show", "branch", "rev-parse", "describe", "tag"):
                return CMD_READONLY_INSPECT
        if stem in ("apt", "apt-get", "dpkg", "rpm", "yum", "dnf"):
            sub = next((a for a in args if not a.startswith("-")), "")
            if sub in ("list", "show", "search", "policy", "info", "check-update", "-l", "-q", "-qa"):
                return CMD_READONLY_INSPECT
        return CMD_PACKAGE_DEPLOY

    if stem in _ARGUMENT_RULES:
        reason = _ARGUMENT_RULES[stem](args)
        if reason:
            return CMD_FILE_WRITE if stem in ("find", "sort", "file") else CMD_OTHER_MUTATING
        return CMD_READONLY_INSPECT

    if stem == "crontab":
        return CMD_READONLY_INSPECT if "-l" in args else CMD_FILE_WRITE

    if stem in ("nginx", "apachectl", "apache2ctl"):
        if any(a in ("-t", "-T", "-v", "-V", "-S", "-M", "configtest", "status") for a in args):
            return CMD_READONLY_INSPECT
        return CMD_SERVICE_CONTROL

    if stem in _READONLY_STEMS:
        return CMD_READONLY_INSPECT

    return CMD_OTHER_MUTATING


def classify_shell_command(command: str, *, allowed: bool = True, reason: str = "") -> Dict[str, Any]:
    """Classify a shell command string passed to ``run_command``.

    Returns ``{command_category, command_stems, used_sudo}``.
    """
    cmd = (command or "").strip()
    if not cmd:
        return {
            "command_category": CMD_BLOCKED if not allowed else CMD_OTHER_MUTATING,
            "command_stems": [],
            "used_sudo": False,
        }

    segments, used_sudo, has_write_op = _extract_segments(cmd)
    stems: List[str] = []
    seen = set()
    best_cat = CMD_READONLY_INSPECT
    best_prio = -1

    for words in segments:
        stem = words[0].rsplit("/", 1)[-1]
        if stem and stem not in seen:
            seen.add(stem)
            stems.append(stem[:48])
        cat = _classify_segment(words)
        prio = _CATEGORY_PRIORITY.get(cat, 0)
        if prio > best_prio:
            best_prio = prio
            best_cat = cat

    if not segments:
        best_cat = CMD_OTHER_MUTATING

    if has_write_op and _CATEGORY_PRIORITY.get(CMD_FILE_WRITE, 0) > _CATEGORY_PRIORITY.get(best_cat, 0):
        best_cat = CMD_FILE_WRITE

    if not allowed and _is_blocked_reason(reason):
        best_cat = CMD_BLOCKED

    return {
        "command_category": best_cat,
        "command_stems": stems[:8],
        "used_sudo": used_sudo,
    }


def _is_blocked_reason(reason: str) -> bool:
    low = (reason or "").strip().lower()
    if not low:
        return False
    return any(marker in low for marker in _BLOCKED_REASON_MARKERS)


def classify_audit_entry(
    tool: str,
    args: Optional[Mapping[str, Any]] = None,
    *,
    allowed: bool = True,
    reason: str = "",
) -> Dict[str, Any]:
    """Return classification metadata for an audit entry."""
    tool_name = str(tool or "")
    arg_map = args if isinstance(args, Mapping) else {}

    if tool_name in _REMOTE_COMMAND_TOOLS:
        op_class = OP_REMOTE_COMMAND
        remote_exec = True
        cmd = str(arg_map.get("command") or "")
        shell_info = classify_shell_command(cmd, allowed=allowed, reason=reason)
        return {
            "op_class": op_class,
            "remote_exec": remote_exec,
            "command_category": shell_info["command_category"],
            "command_stems": shell_info["command_stems"],
            "used_sudo": shell_info["used_sudo"],
        }

    if tool_name in _REMOTE_PROBE_TOOLS:
        op_class = OP_REMOTE_PROBE
        remote_exec = True
    elif tool_name in _REMOTE_TRANSFER_TOOLS:
        op_class = OP_REMOTE_TRANSFER
        remote_exec = True
    elif tool_name in _REMOTE_DB_TOOLS:
        op_class = OP_REMOTE_DB
        remote_exec = True
    elif tool_name in _CLOUD_API_EXACT or tool_name.startswith(_CLOUD_API_PREFIXES):
        op_class = OP_CLOUD_API
        remote_exec = False
    else:
        op_class = OP_LOCAL_OR_META
        remote_exec = False

    category = CMD_BLOCKED if (not allowed and _is_blocked_reason(reason)) else op_class
    return {
        "op_class": op_class,
        "remote_exec": remote_exec,
        "command_category": category,
        "command_stems": [],
        "used_sudo": False,
    }


def enrich_entry_metadata(entry: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a normalized view of an audit entry, backfilling missing metadata.

    Never mutates *entry* in place. Safe for legacy pre-enrichment rows.
    """
    # Fast path for already-enriched rows (avoids extra dict copy + re-classifying).
    if (
        isinstance(entry, dict)
        and "origin" in entry
        and "op_class" in entry
        and "remote_exec" in entry
        and "command_category" in entry
    ):
        return entry

    normalized = dict(entry)
    normalized["origin"] = infer_origin(entry)
    transport = infer_transport(entry)
    if transport and not normalized.get("transport_used"):
        normalized["transport_used"] = transport

    if "op_class" not in normalized or "command_category" not in normalized or "remote_exec" not in normalized:
        classified = classify_audit_entry(
            str(entry.get("tool") or ""),
            entry.get("args") if isinstance(entry.get("args"), Mapping) else None,
            allowed=bool(entry.get("allowed", True)),
            reason=str(entry.get("reason") or ""),
        )
        normalized.setdefault("op_class", classified["op_class"])
        normalized.setdefault("remote_exec", classified["remote_exec"])
        normalized.setdefault("command_category", classified["command_category"])
        if classified["command_stems"]:
            normalized.setdefault("command_stems", classified["command_stems"])
        if classified["used_sudo"]:
            normalized.setdefault("used_sudo", True)

    return normalized
