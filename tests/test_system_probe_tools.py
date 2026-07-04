"""Tests for the system-health probe tools (journal / TLS / auth log)
and the stack-summary recon projection.

Pure parsers plus tool-layer plumbing with a mocked SSH seam, mirroring
the docker probe test structure. Fixtures are generic (web-1, RFC1918 /
well-known neutral public IPs) — no real hosts or customers.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import AppConfig
from servonaut.mcp.guards import CommandGuard
from servonaut.mcp.tools import ServonautTools
from servonaut.services.memory.stack_summary import build_stack_summary
from servonaut.utils.system_probe import (
    parse_journal_errors,
    parse_tls_certs,
    summarize_auth_log,
)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Pure parsers
# ---------------------------------------------------------------------------


class TestParseJournalErrors:
    def test_sections_aggregate(self):
        err1 = json.dumps({"_SYSTEMD_UNIT": "nginx.service", "PRIORITY": "3",
                           "MESSAGE": "worker process exited"})
        err2 = json.dumps({"_SYSTEMD_UNIT": "nginx.service", "PRIORITY": "3",
                           "MESSAGE": "another error"})
        err3 = json.dumps({"SYSLOG_IDENTIFIER": "cron", "PRIORITY": "2",
                           "MESSAGE": "job failed"})
        stdout = "\n".join([
            "===ERR===", err1, err2, err3, "not-json",
            "===OOM===",
            "Jul  4 03:12:01 web-1 kernel: Out of memory: "
            "Killed process 4242 (mysqld) total-vm:2048kB",
            "===RESTARTS===",
            "Jul  4 03:13:01 web-1 systemd[1]: app.service: "
            "Scheduled restart job, restart counter is at 3.",
            "Jul  4 03:14:01 web-1 systemd[1]: app.service: "
            "Failed with result 'exit-code'.",
        ])
        out = parse_journal_errors(stdout)
        nginx = next(e for e in out["entries"] if e["unit"] == "nginx.service")
        assert nginx["count"] == 2
        assert nginx["level"] == "err"
        assert nginx["sample"] == "worker process exited"
        cron = next(e for e in out["entries"] if e["unit"] == "cron")
        assert cron["level"] == "crit"
        assert out["oom_kills"] == [
            {"unit": "mysqld", "count": 1, "last_at": "Jul  4 03:12:01"},
        ]
        assert out["restarts"][0]["unit"] == "app.service"
        assert out["restarts"][0]["count"] == 2

    def test_empty_output(self):
        out = parse_journal_errors("===ERR===\n===OOM===\n===RESTARTS===")
        assert out == {"entries": [], "oom_kills": [], "restarts": []}


class TestParseTlsCerts:
    def test_certbot_and_selfsigned(self):
        stdout = "\n".join([
            "===CERT:/etc/letsencrypt/live/app.example.com/fullchain.pem===",
            "subject=CN = app.example.com",
            "issuer=C = US, O = Let's Encrypt, CN = R11",
            "notAfter=Aug 10 12:00:00 2026 GMT",
            "===CERT:/etc/ssl/snakeoil.pem===",
            "subject=CN = web-1",
            "issuer=CN = web-1",
            "notAfter=Jan  1 00:00:00 2027 GMT",
        ])
        now = datetime(2026, 7, 4, tzinfo=timezone.utc)
        certs = parse_tls_certs(stdout, now=now)
        le = next(c for c in certs if c["domain"] == "app.example.com")
        assert le["days_left"] == 37
        assert le["issuer"] == "R11"
        assert le["self_signed"] is False
        snake = next(c for c in certs if c["path"] == "/etc/ssl/snakeoil.pem")
        assert snake["self_signed"] is True

    def test_domain_from_letsencrypt_path_when_no_cn(self):
        stdout = "\n".join([
            "===CERT:/etc/letsencrypt/live/shop.example.com/fullchain.pem===",
            "subject=O = ACME Corp",
            "issuer=CN = R11",
            "notAfter=Aug 10 12:00:00 2026 GMT",
        ])
        certs = parse_tls_certs(stdout)
        assert certs[0]["domain"] == "shop.example.com"

    def test_duplicate_paths_deduped(self):
        block = "\n".join([
            "===CERT:/etc/ssl/a.pem===",
            "subject=CN = a.example.com",
            "issuer=CN = R11",
            "notAfter=Aug 10 12:00:00 2026 GMT",
        ])
        assert len(parse_tls_certs(block + "\n" + block)) == 1


class TestSummarizeAuthLog:
    def test_grouping(self):
        lines = []
        for _ in range(3):
            lines.append(
                "Jul  4 03:00:01 web-1 sshd[100]: Failed password for "
                "invalid user admin from 9.9.9.9 port 22 ssh2",
            )
        lines.append(
            "Jul  4 03:00:05 web-1 sshd[101]: Invalid user admin "
            "from 9.9.9.9 port 22",
        )
        lines.append(
            "Jul  4 03:01:00 web-1 sshd[102]: Accepted publickey for "
            "deploy from 10.0.0.5 port 51000 ssh2",
        )
        out = summarize_auth_log("\n".join(lines))
        assert out["failed_logins"] == [
            {"ip": "9.9.9.9", "user": "admin", "count": 3,
             "method": "password"},
        ]
        assert out["invalid_users"] == [{"ip": "9.9.9.9", "count": 1}]
        assert out["accepted_logins"] == [
            {"ip": "10.0.0.5", "user": "deploy", "count": 1,
             "method": "publickey"},
        ]

    def test_top_n_bounds(self):
        lines = [
            f"sshd[1]: Failed password for user{i} from 10.0.0.{i} port 1 ssh2"
            for i in range(30)
        ]
        out = summarize_auth_log("\n".join(lines), top_n=5)
        assert len(out["failed_logins"]) == 5


# ---------------------------------------------------------------------------
# Stack-summary projection
# ---------------------------------------------------------------------------


class TestStackSummary:
    def test_projection_shape(self):
        modules = {
            "os": {"observed": {"pretty_name": "Ubuntu 22.04.5 LTS"}},
            "containers": {"observed": {
                "docker_running": True,
                "docker_containers": [{"name": "web"}, {"name": "db"}],
            }},
            "databases": {"observed": {
                "mysql_version": "8.0", "mariadb_version": None,
                "postgres_version": None,
            }},
            "web_stack": {"observed": {
                "nginx": "1.25", "nginx_sites_enabled": ["a", "b"],
                "apache_sites_enabled": [],
            }},
            "logs": {"observed": {"probed_paths": [
                "/var/log/nginx/access.log", "/var/log/auth.log",
            ]}},
            "services": {"observed": {"enabled_units": [
                "nginx.service", "cron.service",
            ]}},
        }
        s = build_stack_summary(modules, provider="ovh")
        assert s["os"] == "Ubuntu 22.04.5 LTS"
        assert s["cloud_provider"] == "ovh"
        assert s["docker"] == {"present": True, "container_count": 2}
        assert s["databases"] == [{"engine": "mysql", "version": "8.0"}]
        assert s["web"]["server"] == "nginx"
        assert s["web"]["vhosts_count"] == 2
        assert s["web"]["access_log_paths"] == ["/var/log/nginx/access.log"]
        assert "/var/log/auth.log" in s["log_paths"]

    def test_empty_modules(self):
        s = build_stack_summary({}, provider="aws")
        assert s["docker"] == {"present": False, "container_count": 0}
        assert s["databases"] == []
        assert s["web"]["server"] is None


# ---------------------------------------------------------------------------
# Tool layer (mocked SSH seam)
# ---------------------------------------------------------------------------


def _tools() -> ServonautTools:
    cfg = AppConfig()
    cm = MagicMock()
    cm.get.return_value = cfg
    tools = ServonautTools(
        config_manager=cm,
        aws_service=MagicMock(),
        custom_server_service=MagicMock(),
        cache_service=MagicMock(),
        ssh_service=MagicMock(),
        connection_service=MagicMock(),
        scp_service=MagicMock(),
        guard=CommandGuard(cfg.mcp),
        audit=MagicMock(),
    )
    tools._find_instance = AsyncMock(return_value={
        "id": "i-0000test01", "name": "web-1", "public_ip": "10.0.0.5",
    })
    return tools


class TestSystemProbeToolLayer:
    def test_journal_errors_json(self):
        tools = _tools()
        stdout = "===ERR===\n" + json.dumps({
            "_SYSTEMD_UNIT": "app.service", "PRIORITY": "3", "MESSAGE": "x",
        }) + "\n===OOM===\n===RESTARTS==="
        tools._exec_ssh = AsyncMock(return_value=(stdout, ""))
        payload = json.loads(run(tools.journal_errors("web-1")))
        assert payload["entries"][0]["unit"] == "app.service"

    def test_journal_sentinels(self):
        for sentinel, slug in (
            ("JOURNAL_NOT_AVAILABLE", "journal_not_available"),
            ("JOURNAL_PERMISSION_DENIED", "journal_permission_denied"),
        ):
            tools = _tools()
            tools._exec_ssh = AsyncMock(return_value=(sentinel + "\n", ""))
            assert run(tools.journal_errors("web-1")) == f"Error: {slug}"

    def test_tls_no_certs_is_empty_not_error(self):
        tools = _tools()
        tools._exec_ssh = AsyncMock(return_value=("", ""))
        payload = json.loads(run(tools.tls_cert_check("web-1")))
        assert payload == {"certs": []}

    def test_tls_openssl_missing(self):
        tools = _tools()
        tools._exec_ssh = AsyncMock(
            return_value=("OPENSSL_NOT_AVAILABLE\n", ""))
        assert run(tools.tls_cert_check("web-1")) == "Error: openssl_not_available"

    def test_auth_log_summary_json(self):
        tools = _tools()
        stdout = ("===AUTHLOG:/var/log/auth.log===\n"
                  "sshd[1]: Failed password for root from 9.9.9.9 port 1 ssh2")
        tools._exec_ssh = AsyncMock(return_value=(stdout, ""))
        payload = json.loads(run(tools.auth_log_summary("web-1")))
        assert payload["failed_logins"][0]["ip"] == "9.9.9.9"

    def test_auth_log_sentinels(self):
        tools = _tools()
        tools._exec_ssh = AsyncMock(
            return_value=("AUTH_LOG_NOT_AVAILABLE\n", ""))
        assert run(tools.auth_log_summary("web-1")) == "Error: auth_log_not_available"

    def test_probe_policy_allows_new_tools(self):
        from servonaut.services.relay_listener import probe_tool_allowed
        for tool in ("journal_errors", "tls_cert_check", "auth_log_summary"):
            assert probe_tool_allowed(tool)


class TestStackSummaryToolFormat:
    def test_get_server_memory_stack_summary(self):
        tools = _tools()
        memory = MagicMock()
        memory.get_all_modules.return_value = {
            "os": {"observed": {"pretty_name": "Ubuntu 22.04.5 LTS"}},
            "containers": {"observed": {
                "docker_running": True,
                "docker_containers": [{"name": "web"}],
            }},
        }
        tools._memory_service = memory
        out = run(tools.get_server_memory("web-1", format="stack_summary"))
        payload = json.loads(out)
        assert payload["docker"] == {"present": True, "container_count": 1}
        assert payload["os"] == "Ubuntu 22.04.5 LTS"
        assert "_trust_notice" in payload
