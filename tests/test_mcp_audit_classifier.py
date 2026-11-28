"""Tests for read-time remote command & operation classification and origin inference."""
from __future__ import annotations

import pytest

from servonaut.mcp.audit_classifier import (
    CMD_BLOCKED,
    CMD_FILE_WRITE,
    CMD_NETWORK_FIREWALL,
    CMD_OTHER_MUTATING,
    CMD_PACKAGE_DEPLOY,
    CMD_READONLY_INSPECT,
    CMD_SERVICE_CONTROL,
    CMD_UNKNOWN,
    CMD_USER_PRIVILEGE,
    OP_CLOUD_API,
    OP_LOCAL_OR_META,
    OP_REMOTE_COMMAND,
    OP_REMOTE_DB,
    OP_REMOTE_PROBE,
    OP_REMOTE_TRANSFER,
    classify_audit_entry,
    classify_shell_command,
    enrich_entry_metadata,
    infer_origin,
    infer_transport,
    is_entry_failed_or_denied,
)


class TestShellCommandClassifier:
    @pytest.mark.parametrize("cmd,expected_cat,expected_sudo", [
        # Plain read-only inspection
        ("uptime", CMD_READONLY_INSPECT, False),
        ("ps aux | grep nginx", CMD_READONLY_INSPECT, False),
        ("sudo tail -n 100 /var/log/nginx/error.log", CMD_READONLY_INSPECT, True),
        ("systemctl status nginx", CMD_READONLY_INSPECT, False),
        ("docker ps -a", CMD_READONLY_INSPECT, False),
        ("docker logs --tail 50 web", CMD_READONLY_INSPECT, False),
        ("ip addr show", CMD_READONLY_INSPECT, False),
        ("ufw status verbose", CMD_READONLY_INSPECT, False),
        ("iptables -L -n", CMD_READONLY_INSPECT, False),
        ("git status", CMD_READONLY_INSPECT, False),
        ("nginx -t", CMD_READONLY_INSPECT, False),
        ("dpkg -l", CMD_READONLY_INSPECT, False),
        ("rpm -qa", CMD_READONLY_INSPECT, False),
        ("journalctl -u nginx -n 50", CMD_READONLY_INSPECT, False),
        ("hostnamectl status", CMD_READONLY_INSPECT, False),
        ("mount", CMD_READONLY_INSPECT, False),
        ("env", CMD_READONLY_INSPECT, False),
        ("php -v", CMD_READONLY_INSPECT, False),
        ("python3 --version", CMD_READONLY_INSPECT, False),
        ("curl -sI https://example.com", CMD_READONLY_INSPECT, False),
        # Redirections to /dev/null and fd-to-fd must NOT become writes or fake stems
        ("ls /x 2>/dev/null", CMD_READONLY_INSPECT, False),
        ("cat f 2>&1 | grep x", CMD_READONLY_INSPECT, False),
        ("ps aux >/dev/null 2>&1", CMD_READONLY_INSPECT, False),
        # Service control
        ("sudo systemctl restart nginx", CMD_SERVICE_CONTROL, True),
        ("service php8.3-fpm reload", CMD_SERVICE_CONTROL, False),
        ("docker compose up -d", CMD_SERVICE_CONTROL, False),
        ("docker restart api", CMD_SERVICE_CONTROL, False),
        # File writes (including bundled sed flags, env unwrapping, journalctl vacuum)
        ("sed -i 's/foo/bar/g' /etc/app.conf", CMD_FILE_WRITE, False),
        ("sed -Ei 's/foo/bar/g' /etc/app.conf", CMD_FILE_WRITE, False),
        ("sed -ni '1p' /etc/app.conf", CMD_FILE_WRITE, False),
        ("echo '127.0.0.1 test' >> /etc/hosts", CMD_FILE_WRITE, False),
        ("sudo tee /etc/nginx/conf.d/app.conf", CMD_FILE_WRITE, True),
        ("rm /tmp/old.log", CMD_FILE_WRITE, False),
        ("env X=1 rm /tmp/f", CMD_FILE_WRITE, False),
        ("find /tmp -name '*.tmp' -delete", CMD_FILE_WRITE, False),
        ("journalctl --vacuum-time=2d", CMD_FILE_WRITE, False),
        # Packages & deploy
        ("sudo apt-get update && sudo apt-get install -y htop", CMD_PACKAGE_DEPLOY, True),
        ("pip install requests", CMD_PACKAGE_DEPLOY, False),
        ("git pull origin main", CMD_PACKAGE_DEPLOY, False),
        # Network & firewall (including attached curl -XPOST and -T)
        ("sudo ufw deny from 1.2.3.4", CMD_NETWORK_FIREWALL, True),
        ("iptables -A INPUT -s 5.6.7.8 -j DROP", CMD_NETWORK_FIREWALL, False),
        ("ip route add 10.0.0.0/8 via 10.0.0.1", CMD_NETWORK_FIREWALL, False),
        ("curl -X POST https://example.com/hook -d '{}'", CMD_NETWORK_FIREWALL, False),
        ("curl -XPOST https://example.com/hook", CMD_NETWORK_FIREWALL, False),
        ("curl -T /tmp/file https://example.com/upload", CMD_NETWORK_FIREWALL, False),
        # User / privilege
        ("sudo useradd deploy", CMD_USER_PRIVILEGE, True),
        ("passwd ubuntu", CMD_USER_PRIVILEGE, False),
        # Other mutating (hostnamectl set-*, mount device, unknown binary)
        ("hostnamectl set-hostname prod-2", CMD_OTHER_MUTATING, False),
        ("mount /dev/sdb1 /mnt/data", CMD_OTHER_MUTATING, False),
        ("/opt/custom/reconcile --apply", CMD_OTHER_MUTATING, False),
        # Dynamic / uncertain syntax & interpreters -> unknown (never readonly_inspect!)
        ("uptime\nsystemctl restart nginx", CMD_UNKNOWN, False),
        ('echo "$(touch /tmp/x)"', CMD_UNKNOWN, False),
        ("echo `whoami`", CMD_UNKNOWN, False),
        ("sudo php artisan migrate", CMD_UNKNOWN, True),
        ("python3 -c 'import os; os.remove(\"/tmp/x\")'", CMD_UNKNOWN, False),
        ("bash -c 'systemctl restart nginx'", CMD_UNKNOWN, False),
        ("sh -c 'rm -f /tmp/x'", CMD_UNKNOWN, False),
    ])
    def test_command_categories(self, cmd, expected_cat, expected_sudo):
        info = classify_shell_command(cmd, allowed=True, reason="")
        assert info["command_category"] == expected_cat
        assert info["used_sudo"] is expected_sudo

    def test_redirection_targets_never_become_command_stems(self):
        info1 = classify_shell_command("ls /x 2>/dev/null")
        assert info1["command_category"] == CMD_READONLY_INSPECT
        assert info1["command_stems"] == ["ls"]

        info2 = classify_shell_command("cat f 2>&1 | grep x")
        assert info2["command_category"] == CMD_READONLY_INSPECT
        assert info2["command_stems"] == ["cat", "grep"]

    def test_blocked_reason_only_matches_policy_refusals(self):
        # Genuine policy / guard refusal -> blocked
        refused = classify_shell_command("systemctl restart nginx", allowed=False, reason="team_rule")
        assert refused["command_category"] == CMD_BLOCKED
        assert refused["command_stems"] == ["systemctl"]

        # Upstream AWS AccessDenied / SSM Permission denied -> NOT blocked!
        ssm_err = classify_shell_command(
            "uptime", allowed=False, reason="ssm: send_command: AccessDeniedException",
        )
        assert ssm_err["command_category"] == CMD_READONLY_INSPECT

        ssm_perm = classify_shell_command(
            "uptime", allowed=False, reason="ssm: Permission denied on remote host",
        )
        assert ssm_perm["command_category"] == CMD_READONLY_INSPECT

        api_err = classify_audit_entry(
            "aws_call", {"service": "ec2"}, allowed=False, reason="api_error: Forbidden / AccessDenied",
        )
        assert api_err["command_category"] == OP_CLOUD_API

    def test_pipeline_picks_highest_impact_category(self):
        info = classify_shell_command("cat /etc/app.env | tee /tmp/copy.env", allowed=True)
        assert info["command_category"] == CMD_FILE_WRITE
        assert info["command_stems"] == ["cat", "tee"]


class TestToolOperationClass:
    @pytest.mark.parametrize("tool,expected_op,expected_remote", [
        ("run_command", OP_REMOTE_COMMAND, True),
        ("get_server_info", OP_REMOTE_PROBE, True),
        ("get_logs", OP_REMOTE_PROBE, True),
        ("docker_stats", OP_REMOTE_PROBE, True),
        ("security_audit", OP_REMOTE_PROBE, True),
        ("transfer_file", OP_REMOTE_TRANSFER, True),
        ("db_processlist", OP_REMOTE_DB, True),
        ("aws_call", OP_CLOUD_API, False),
        ("cloudwatch_top_ips", OP_CLOUD_API, False),
        ("ip_ban_set", OP_CLOUD_API, False),
        ("ovh_list_ips", OP_CLOUD_API, False),
        ("hetzner_list_servers", OP_CLOUD_API, False),
        ("list_instances", OP_LOCAL_OR_META, False),
        ("get_server_memory", OP_LOCAL_OR_META, False),
        ("whoami", OP_LOCAL_OR_META, False),
    ])
    def test_op_class_and_remote_flag(self, tool, expected_op, expected_remote):
        out = classify_audit_entry(tool, {"command": "uptime"} if tool == "run_command" else {})
        assert out["op_class"] == expected_op
        assert out["remote_exec"] is expected_remote


class TestLegacyEntryInference:
    def test_infer_origin_for_legacy_rows(self):
        assert infer_origin({"tool": "list_instances"}) == "unknown"
        assert infer_origin({"tool": "list_instances", "source": "mcp"}) == "mcp"
        assert infer_origin({"tool": "run_command", "source": "ai_chat"}) == "ui"
        assert infer_origin({"tool": "docker_ps", "source": "proactive"}) == "proactive"
        assert infer_origin({"tool": "run_command", "source": "ai_chat", "origin": "relay"}) == "relay"

    def test_infer_transport_for_legacy_rows(self):
        assert infer_transport({"tool": "transfer_file"}) == "scp"
        assert infer_transport({"tool": "get_server_info"}) == "ssh"
        assert infer_transport({"tool": "run_command", "args": {"transport": "ssm"}}) == "ssm"
        assert infer_transport({"tool": "run_command", "args": {"transport": "auto"}, "transport_used": "ssm"}) == "ssm"
        assert infer_transport({"tool": "list_instances"}) == ""

    def test_is_entry_failed_or_denied(self):
        assert is_entry_failed_or_denied({"allowed": True}) is False
        assert is_entry_failed_or_denied({"allowed": False}) is True
        assert is_entry_failed_or_denied({"allowed": True, "tool_allowed": False}) is True
        assert is_entry_failed_or_denied({"allowed": True, "status": "error"}) is True
        assert is_entry_failed_or_denied({"allowed": True, "status": "timeout"}) is True

    def test_enrich_entry_metadata_reclassifies_at_read_time(self):
        legacy = {
            "timestamp": "2026-11-26T10:00:00+00:00",
            "tool": "run_command",
            "args": {"instance_id": "web-1", "command": "sudo systemctl reload nginx", "transport": "ssh"},
            "allowed": True,
            "reason": "",
            "result_length": 42,
        }
        enriched = enrich_entry_metadata(legacy)
        assert enriched["origin"] == "unknown"
        assert enriched["transport_used"] == "ssh"
        assert enriched["op_class"] == OP_REMOTE_COMMAND
        assert enriched["remote_exec"] is True
        assert enriched["command_category"] == CMD_SERVICE_CONTROL
        assert enriched["used_sudo"] is True
        assert "origin" not in legacy  # input dict not mutated
