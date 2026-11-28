"""Read-time classification and origin helpers for MCP / Agent audit entries.

Classifies every tool invocation at read time (never written to disk, so
classifier improvements automatically apply to existing audit history and a
classifier edge case can never drop an audit write):

- ``op_class``: broad execution scope (``remote_command``, ``remote_probe``,
  ``remote_transfer``, ``remote_db``, ``cloud_api``, ``local_or_meta``)
- ``remote_exec``: whether the tool executes on or transfers to/from a remote host
- ``command_category``: finer-grained intent for shell commands run on remotes
  (``readonly_inspect``, ``service_control``, ``file_write``, ``package_deploy``,
  ``network_firewall``, ``user_privilege``, ``other_mutating``, ``unknown``,
  ``blocked``), or ``op_class`` for non-shell tools
- ``command_stems`` & ``used_sudo``: parsed command names and sudo usage for
  ``run_command`` entries
"""
from __future__ import annotations

from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

from servonaut.mcp.guards import (
    _ARGUMENT_RULES,
    _PIPE,
    _is_operator,
    _tokenize,
)

# Canonical origin values displayed in the TUI and CLI.
VALID_ORIGINS: FrozenSet[str] = frozenset({"mcp", "ui", "relay", "proactive", "cli", "unknown"})

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
CMD_UNKNOWN = "unknown"
CMD_BLOCKED = "blocked"

ALL_CATEGORIES: Tuple[str, ...] = (
    CMD_READONLY_INSPECT,
    CMD_SERVICE_CONTROL,
    CMD_FILE_WRITE,
    CMD_PACKAGE_DEPLOY,
    CMD_NETWORK_FIREWALL,
    CMD_USER_PRIVILEGE,
    CMD_OTHER_MUTATING,
    CMD_UNKNOWN,
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

# Strictly read-only inspection stems (interpreters, env, mount, journalctl,
# hostnamectl are handled explicitly below with argument inspection).
_READONLY_STEMS: FrozenSet[str] = frozenset({
    "ls", "cat", "grep", "egrep", "fgrep", "rg", "zgrep", "zcat",
    "ps", "df", "du", "top", "htop", "free", "uptime", "whoami", "id",
    "hostname", "uname", "date", "w", "who", "last", "netstat", "ss",
    "ip", "ifconfig", "ping", "dig", "nslookup", "host", "traceroute",
    "head", "tail", "wc", "sort", "uniq", "cut", "tr", "find",
    "file", "stat", "lsof", "lsblk", "blkid", "dmesg",
    "printenv", "which", "readlink", "realpath", "timedatectl",
    "loginctl", "nproc", "vmstat", "iostat", "mpstat", "sar",
    "md5sum", "sha256sum", "cksum", "diff", "less", "more",
    "strings", "echo", "printf", "test", "true", "false", "pwd", "tree",
})

# Shells and interpreters whose inline code cannot be classified safely without
# parsing the embedded script.
_SHELL_WRAPPER_STEMS: FrozenSet[str] = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "eval", "exec", "xargs",
})
_INTERPRETER_STEMS: FrozenSet[str] = frozenset({
    "python", "python3", "php", "perl", "ruby", "node", "nodejs", "lua",
})
_VERSION_ONLY_FLAGS: FrozenSet[str] = frozenset({"-v", "-V", "--version"})

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
_DPKG_READ_FLAGS: FrozenSet[str] = frozenset({
    "-l", "--list", "-s", "--status", "-S", "--search", "-L", "--listfiles",
    "-p", "--print-avail", "--version",
})
_RPM_READ_FLAGS: FrozenSet[str] = frozenset({
    "-q", "-qa", "-qi", "-ql", "-qf", "-qd", "-qc", "--query", "--version",
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
    "setfacl",
})
_JOURNALCTL_MUTATE_PREFIXES: Tuple[str, ...] = (
    "--vacuum-",
    "--rotate",
    "--flush",
    "--relinquish-var",
    "--sync",
    "--update-catalog",
)

# Priority order when a pipeline/compound command mixes categories.
_CATEGORY_PRIORITY: Dict[str, int] = {
    CMD_USER_PRIVILEGE: 70,
    CMD_NETWORK_FIREWALL: 60,
    CMD_FILE_WRITE: 50,
    CMD_SERVICE_CONTROL: 45,
    CMD_PACKAGE_DEPLOY: 40,
    CMD_OTHER_MUTATING: 35,
    CMD_UNKNOWN: 30,
    CMD_READONLY_INSPECT: 10,
}

# Only genuine guard/policy/approval refusal reasons map to `blocked`.
# Deliberately excludes generic substrings like "denied" / "forbidden" so
# upstream AWS AccessDenied or SSM Permission denied errors stay distinct.
_BLOCKED_REASON_EXACT: FrozenSet[str] = frozenset({
    "team_rule",
    "user_declined",
    "confirm_denied",
    "denied_local",
    "aws_switched_off",
    "team_option_refused",
    "dangerous_floor_escalation",
})
_BLOCKED_REASON_MARKERS: Tuple[str, ...] = (
    "command matches blocklist",
    "not in allowlist",
    "not allowed in readonly mode",
    "not allowed in standard mode",
    "command execution not allowed",
    "not available in readonly mode",
    "not available in standard mode",
    "command substitution and multiple lines are not allowed",
    "only single pipes between allowlisted commands",
    "sudo options are not allowed",
    "sudo must be followed by an allowlisted command",
    "empty pipeline segment is not allowed",
    "blocked:",
)

_DYNAMIC_SHELL_MARKERS: Tuple[str, ...] = ("\n", "\r", "\x00", "`", "$(", "<(", ">(")
_OUTPUT_REDIR_TOKENS: FrozenSet[str] = frozenset({">", ">>", ">|", "&>", "&>>"})
_INPUT_REDIR_TOKENS: FrozenSet[str] = frozenset({"<", "<<"})
_FD_DUP_REDIR_TOKENS: FrozenSet[str] = frozenset({">&", "<&"})
_NULL_SINKS: FrozenSet[str] = frozenset({"/dev/null"})


def infer_origin(entry: Mapping[str, Any]) -> str:
    """Resolve an entry's origin (``mcp``, ``ui``, ``relay``, ``proactive``, ``cli``, ``unknown``).

    Explicit ``origin`` wins; older entries without ``origin`` fall back to
    ``source``, and rows with neither are labeled ``unknown``.
    """
    explicit = str(entry.get("origin") or "").strip().lower()
    if explicit:
        return explicit
    source = str(entry.get("source") or "").strip().lower()
    if source == "proactive":
        return "proactive"
    if source == "ai_chat":
        return "ui"
    if source == "relay":
        return "relay"
    if source == "mcp":
        return "mcp"
    if not source:
        return "unknown"
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
        reason = str(entry.get("tool_reason") or entry.get("reason") or "").lower()
        if reason.startswith("ssm"):
            return "ssm"
        if reason.startswith("ssh") or "ssh" in reason:
            return "ssh"
        return "auto" if req == "auto" else ""
    if tool in _REMOTE_PROBE_TOOLS or tool in _REMOTE_DB_TOOLS:
        return "ssh"
    return ""


def is_entry_failed_or_denied(entry: Mapping[str, Any]) -> bool:
    """True when an entry was blocked, refused, timed out, or failed."""
    if not entry.get("allowed", True):
        return True
    if entry.get("tool_allowed") is False:
        return True
    status = str(entry.get("status") or "").strip().lower()
    if status in ("error", "timeout", "denied"):
        return True
    return False


def _is_fd_digit(token: str) -> bool:
    return len(token) == 1 and token.isdigit()


def _unwrap_sudo_and_env(words: List[str]) -> Tuple[List[str], bool]:
    """Strip leading ``KEY=VAL``, ``sudo``, and ``env`` prefixes.

    Returns ``(remaining_words, used_sudo)``. Bare ``env`` (with no command
    after flags/assignments) stays as ``["env", ...]`` so it classifies as
    read-only inspection.
    """
    used_sudo = False
    cur = list(words)
    while cur:
        # Strip leading VAR=VALUE assignments.
        idx = 0
        while idx < len(cur) and "=" in cur[idx] and not cur[idx].startswith("-"):
            idx += 1
        cur = cur[idx:]
        if not cur:
            break
        head = cur[0].rsplit("/", 1)[-1]
        if head == "sudo":
            used_sudo = True
            w_idx = 1
            while w_idx < len(cur) and cur[w_idx].startswith("-"):
                flag = cur[w_idx]
                w_idx += 2 if flag in ("-u", "-g", "-C", "-h", "-p", "-r", "-t") else 1
            cur = cur[w_idx:]
            continue
        if head == "env":
            w_idx = 1
            while w_idx < len(cur):
                tok = cur[w_idx]
                if tok in ("-u", "--unset", "-C", "--chdir", "-S", "--split-string"):
                    w_idx += 2
                elif tok.startswith("-"):
                    w_idx += 1
                elif "=" in tok:
                    w_idx += 1
                else:
                    break
            if w_idx < len(cur):
                cur = cur[w_idx:]
                continue
            # Bare `env` / `env -0` prints environment only.
            break
        break
    return cur, used_sudo


def _extract_segments(command: str) -> Tuple[List[List[str]], bool, bool, bool]:
    """Parse *command* into executable segments, stripping redirections accurately.

    Returns ``(segments, used_sudo, has_file_write_redirect, has_uncertain_syntax)``.
    """
    if any(marker in command for marker in _DYNAMIC_SHELL_MARKERS):
        return [], ("sudo" in command.split()), False, True

    try:
        tokens = _tokenize(command)
    except ValueError:
        return [], ("sudo" in command.split()), False, True

    segments: List[List[str]] = [[]]
    has_file_write_redir = False
    has_uncertain = False

    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]

        # Handle redirection with optional preceding single-digit fd (e.g. `2`, `>`, `/dev/null`
        # or `2`, `>&`, `1`, or `2`, `>`, `&`, `1`).
        is_redir_with_fd = (
            _is_fd_digit(tok)
            and i + 1 < n
            and (
                tokens[i + 1] in _OUTPUT_REDIR_TOKENS
                or tokens[i + 1] in _INPUT_REDIR_TOKENS
                or tokens[i + 1] in _FD_DUP_REDIR_TOKENS
            )
        )
        if is_redir_with_fd:
            # Drop the fd token from the current segment and process the redir operator next.
            i += 1
            tok = tokens[i]

        if tok in _FD_DUP_REDIR_TOKENS:
            # e.g. `2>&1` or `>&2` — consume fd target; not a file write or segment.
            i += 2 if i + 1 < n else 1
            continue

        if tok in _OUTPUT_REDIR_TOKENS:
            # Check for `2>&1` split by shlex into `2`, `>`, `&`, `1`.
            if i + 1 < n and tokens[i + 1] == "&":
                i += 3 if i + 2 < n else 2
                continue
            target = tokens[i + 1] if i + 1 < n else ""
            if target.startswith("&"):
                # e.g. `>&1` / `>&2`
                i += 2
                continue
            if target and target not in _NULL_SINKS:
                has_file_write_redir = True
            i += 2 if i + 1 < n else 1
            continue

        if tok in _INPUT_REDIR_TOKENS:
            if tok == "<<":
                has_uncertain = True
            i += 2 if i + 1 < n else 1
            continue

        if tok == _PIPE or _is_operator(tok):
            if tok in ("(", ")"):
                has_uncertain = True
            segments.append([])
            i += 1
            continue

        segments[-1].append(tok)
        i += 1

    cleaned: List[List[str]] = []
    used_sudo = False
    for seg in segments:
        if not seg:
            continue
        words, seg_sudo = _unwrap_sudo_and_env(seg)
        if seg_sudo:
            used_sudo = True
        if words:
            cleaned.append(words)
    return cleaned, used_sudo, has_file_write_redir, has_uncertain


def _has_sed_inplace(args: List[str]) -> bool:
    for arg in args:
        if arg == "--in-place" or arg.startswith("--in-place="):
            return True
        if arg.startswith("-") and not arg.startswith("--") and len(arg) > 1:
            # Bundled short flags like `-i`, `-Ei`, `-ni`, `-rni`, `-i.bak`.
            if "i" in arg[1:]:
                return True
    return False


def _is_curl_mutating(args: List[str]) -> bool:
    mutating_methods = {"POST", "PUT", "DELETE", "PATCH"}
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-o", "-O", "--output", "--remote-name", "-T", "--upload-file",
                   "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
                   "--json", "-F", "--form", "--form-string", "-K", "--config"):
            return True
        if arg.startswith(("-o", "-T", "-d", "-F")) and len(arg) > 2:
            return True
        if arg.startswith(("--output=", "--upload-file=", "--data=", "--data-raw=",
                           "--data-binary=", "--json=", "--form=", "--config=")):
            return True
        if arg in ("-X", "--request"):
            method = args[i + 1].upper() if i + 1 < len(args) else ""
            if method in mutating_methods:
                return True
            i += 2
            continue
        if arg.startswith("-X") and len(arg) > 2:
            if arg[2:].upper() in mutating_methods:
                return True
        if arg.startswith("--request="):
            if arg.split("=", 1)[1].upper() in mutating_methods:
                return True
        i += 1
    return False


def _classify_segment(words: List[str]) -> str:
    """Classify one parsed command segment (after stripping sudo/env)."""
    stem = words[0].rsplit("/", 1)[-1]
    args = words[1:]

    if stem in _SHELL_WRAPPER_STEMS:
        return CMD_UNKNOWN

    if stem in _INTERPRETER_STEMS:
        if len(args) == 1 and args[0] in _VERSION_ONLY_FLAGS:
            return CMD_READONLY_INSPECT
        return CMD_UNKNOWN

    if stem == "awk" or stem == "gawk" or stem == "mawk":
        joined = " ".join(args)
        if "system(" in joined or "|" in joined or ">" in joined:
            return CMD_UNKNOWN
        return CMD_READONLY_INSPECT

    if stem == "env":
        return CMD_READONLY_INSPECT

    if stem == "mount":
        positionals = [a for a in args if not a.startswith("-")]
        if not positionals:
            return CMD_READONLY_INSPECT
        return CMD_OTHER_MUTATING

    if stem == "journalctl":
        if any(a.startswith(_JOURNALCTL_MUTATE_PREFIXES) for a in args):
            return CMD_FILE_WRITE
        return CMD_READONLY_INSPECT

    if stem == "hostnamectl":
        verb = next((a for a in args if not a.startswith("-")), "")
        if verb in ("", "status", "hostname") and not verb.startswith("set-"):
            # `hostnamectl hostname NEWNAME` sets hostname; check positional count.
            positionals = [a for a in args if not a.startswith("-")]
            if verb == "hostname" and len(positionals) > 1:
                return CMD_OTHER_MUTATING
            return CMD_READONLY_INSPECT
        return CMD_OTHER_MUTATING

    if stem in _USER_PRIVILEGE_STEMS:
        return CMD_USER_PRIVILEGE

    if stem in _NETWORK_FIREWALL_STEMS:
        if stem == "curl":
            return CMD_NETWORK_FIREWALL if _is_curl_mutating(args) else CMD_READONLY_INSPECT
        if stem == "wget":
            # wget writes a file unless `-O -` / `--spider` / `-qO-` is used.
            if "--spider" in args or "-O-" in args or "-qO-" in args:
                return CMD_READONLY_INSPECT
            if "-O" in args:
                idx = args.index("-O")
                if idx + 1 < len(args) and args[idx + 1] == "-":
                    return CMD_READONLY_INSPECT
            return CMD_NETWORK_FIREWALL
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
        return CMD_FILE_WRITE if _has_sed_inplace(args) else CMD_READONLY_INSPECT

    if stem in _PACKAGE_DEPLOY_STEMS:
        if stem == "git":
            sub = next((a for a in args if not a.startswith("-")), "")
            if sub in ("status", "log", "diff", "show", "branch", "rev-parse", "describe", "tag"):
                return CMD_READONLY_INSPECT
        elif stem == "dpkg":
            if any(a in _DPKG_READ_FLAGS for a in args):
                return CMD_READONLY_INSPECT
        elif stem == "rpm":
            if any(a in _RPM_READ_FLAGS for a in args):
                return CMD_READONLY_INSPECT
        elif stem in ("apt", "apt-get", "yum", "dnf"):
            sub = next((a for a in args if not a.startswith("-")), "")
            if sub in ("list", "show", "search", "policy", "info", "check-update"):
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

    if stem == "openssl":
        sub = next((a for a in args if not a.startswith("-")), "")
        if sub in ("x509", "s_client", "version", "verify", "crl", "asn1parse"):
            if "-out" not in args:
                return CMD_READONLY_INSPECT
        return CMD_OTHER_MUTATING

    if stem in _READONLY_STEMS:
        return CMD_READONLY_INSPECT

    return CMD_OTHER_MUTATING


def _is_blocked_reason(reason: str) -> bool:
    low = (reason or "").strip().lower()
    if not low:
        return False
    if low in _BLOCKED_REASON_EXACT:
        return True
    return any(marker in low for marker in _BLOCKED_REASON_MARKERS)


def classify_shell_command(command: str, *, allowed: bool = True, reason: str = "") -> Dict[str, Any]:
    """Classify a shell command string passed to ``run_command``.

    Returns ``{command_category, command_stems, used_sudo}``.
    """
    cmd = (command or "").strip()
    if not cmd:
        return {
            "command_category": CMD_BLOCKED if (not allowed and _is_blocked_reason(reason)) else CMD_UNKNOWN,
            "command_stems": [],
            "used_sudo": False,
        }

    segments, used_sudo, has_file_write_redir, has_uncertain = _extract_segments(cmd)

    if not allowed and _is_blocked_reason(reason):
        stems_blocked: List[str] = []
        seen_b = set()
        for words in segments:
            s = words[0].rsplit("/", 1)[-1]
            if s and s not in seen_b:
                seen_b.add(s)
                stems_blocked.append(s[:48])
        return {
            "command_category": CMD_BLOCKED,
            "command_stems": stems_blocked[:8],
            "used_sudo": used_sudo,
        }

    if has_uncertain:
        return {
            "command_category": CMD_UNKNOWN,
            "command_stems": [],
            "used_sudo": used_sudo,
        }

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
        best_cat = CMD_UNKNOWN

    if has_file_write_redir and _CATEGORY_PRIORITY.get(CMD_FILE_WRITE, 0) > _CATEGORY_PRIORITY.get(best_cat, 0):
        best_cat = CMD_FILE_WRITE

    return {
        "command_category": best_cat,
        "command_stems": stems[:8],
        "used_sudo": used_sudo,
    }


def classify_audit_entry(
    tool: str,
    args: Optional[Mapping[str, Any]] = None,
    *,
    allowed: bool = True,
    reason: str = "",
) -> Dict[str, Any]:
    """Return read-time classification metadata for an audit entry."""
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
    """Return a normalized view of an audit entry, classifying at read time.

    Never mutates *entry* in place. Always runs the current classifier so
    improvements apply retroactively to existing log history.
    """
    normalized = dict(entry)
    normalized["origin"] = infer_origin(entry)
    transport = infer_transport(entry)
    if transport and not normalized.get("transport_used"):
        normalized["transport_used"] = transport

    effective_allowed = bool(entry.get("allowed", True)) and entry.get("tool_allowed") is not False
    effective_reason = str(entry.get("tool_reason") or entry.get("reason") or "")
    classified = classify_audit_entry(
        str(entry.get("tool") or ""),
        entry.get("args") if isinstance(entry.get("args"), Mapping) else None,
        allowed=effective_allowed,
        reason=effective_reason,
    )
    normalized["op_class"] = classified["op_class"]
    normalized["remote_exec"] = classified["remote_exec"]
    normalized["command_category"] = classified["command_category"]
    if classified["command_stems"]:
        normalized["command_stems"] = classified["command_stems"]
    if classified["used_sudo"]:
        normalized["used_sudo"] = True

    return normalized
