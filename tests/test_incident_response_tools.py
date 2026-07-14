"""Tests for the Group A incident-response tools.

Covers the pure parsers (log_analysis), config plumbing (db_profiles), secret
handling for the DB tools, the on-box DB command builder, and IP-enrichment
formatting. All IO-free: no SSH, no network — the SSH round-trip and the
HTTP calls live behind seams the tool layer owns.
"""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import AppConfig, DBProfile
from servonaut.config.manager import ConfigManager
from servonaut.mcp.guards import CommandGuard, GuardLevel
from servonaut.mcp.tools import ServonautTools
from servonaut.services.ip_enrichment_service import (
    IPEnrichmentService, format_enrichment, _resolve_key,
)
from servonaut.utils.log_analysis import (
    extract_client_ip, summarize_web_traffic, format_web_traffic,
    parse_fleet_probe, fleet_row_from_probe, format_fleet_table,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tools(config: AppConfig | None = None, secret_provider=None) -> ServonautTools:
    """Minimal ServonautTools for testing pure-ish methods (no live services)."""
    cfg = config or AppConfig()
    cm = MagicMock()
    cm.get.return_value = cfg
    return ServonautTools(
        config_manager=cm,
        aws_service=MagicMock(),
        custom_server_service=MagicMock(),
        cache_service=MagicMock(),
        ssh_service=MagicMock(),
        connection_service=MagicMock(),
        scp_service=MagicMock(),
        guard=CommandGuard(cfg.mcp),
        audit=MagicMock(),
        secret_provider=secret_provider,
    )


# ---------------------------------------------------------------------------
# web_traffic_summary parsing
# ---------------------------------------------------------------------------

# Real public IPs (RFC-5737 doc ranges are is_private=True on Python 3.12+).
_PUB_A = "1.1.1.1"
_PUB_B = "8.8.8.8"
_ALB = "10.0.4.21"


def test_extract_client_ip_direct():
    assert extract_client_ip(f'{_PUB_A} - - ...', _PUB_A) == _PUB_A


def test_extract_client_ip_xff_behind_alb():
    line = f'{_ALB} - - [..] "GET / HTTP/1.1" 503 0 "-" "curl" "{_PUB_A}"'
    # %h is the private ALB hop → real client comes from the XFF tail.
    assert extract_client_ip(line, _ALB) == _PUB_A


def test_summarize_web_traffic_multi_vhost():
    raw = (
        "===VHOST:/var/log/nginx/shop.access.log===\n"
        f'{_PUB_A} - - [03/Jun/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 12\n'
        f'{_PUB_A} - - [03/Jun/2026:10:00:30 +0000] "GET /search?q=a HTTP/1.1" 503 0\n'
        f'{_PUB_B} - - [03/Jun/2026:10:00:40 +0000] "GET /login HTTP/1.1" 200 99\n'
        f'{_ALB} - - [03/Jun/2026:10:01:00 +0000] "GET / HTTP/1.1" 503 0 "-" "x" "{_PUB_A}"\n'
        "===VHOST:/var/log/apache2/blog.access.log===\n"
        f'{_PUB_B} - - [03/Jun/2026:10:00:00 +0000] "POST /api HTTP/1.1" 201 5\n'
    )
    s = summarize_web_traffic(raw, top_n=5)
    assert s["total_requests"] == 5
    # Label derived from the log filename: shop.access.log → "shop".
    shop = s["vhosts"]["shop"]
    assert shop["requests"] == 4
    # _PUB_A: 2 direct + 1 via XFF == 3, the top IP.
    assert shop["top_ips"][0] == (_PUB_A, 3)
    # Query string stripped: /search?q=a groups under /search.
    urls = dict(shop["top_urls"])
    assert urls["/"] == 2 and urls["/search"] == 1
    assert shop["status_mix"]["503"] == 2
    # 60s window over 4 reqs.
    assert shop["window_seconds"] == 60.0
    assert "blog" in s["vhosts"]


def test_vhost_label_generic_keeps_full_path():
    from servonaut.utils.log_analysis import vhost_label
    assert vhost_label("/var/log/nginx/shop.access.log") == "shop"
    assert vhost_label("/var/log/apache2/shop-access.log") == "shop"
    # Generic default log → keep the full path so it's recognizable, not "access".
    assert vhost_label("/var/log/nginx/access.log") == "/var/log/nginx/access.log"


def test_summarize_web_traffic_empty():
    s = summarize_web_traffic("not a log line at all\n", top_n=5)
    assert s["vhosts"] == {}
    out = format_web_traffic(s, "somepath")
    assert "No parseable" in out and "somepath" in out


def test_format_web_traffic_busiest_first():
    raw = (
        "===VHOST:/var/log/nginx/sitea.access.log===\n"
        f'{_PUB_A} - - [03/Jun/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1\n'
        "===VHOST:/var/log/nginx/siteb.access.log===\n"
        f'{_PUB_A} - - [03/Jun/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1\n'
        f'{_PUB_B} - - [03/Jun/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 1\n'
    )
    out = format_web_traffic(summarize_web_traffic(raw))
    assert out.index("siteb") < out.index("sitea")


# ---------------------------------------------------------------------------
# fleet_health_snapshot parsing
# ---------------------------------------------------------------------------

def test_parse_fleet_probe_and_row():
    probe = (
        "LOAD=78.20 60.10 40.00\nCPU=4\nMEM=16000 15000 1000\n"
        "FPM=80/80\nSTACK= nginx php-fpm\nLISTEN=80,443,9000,\n"
    )
    kv = parse_fleet_probe(probe)
    assert kv["LOAD"].startswith("78.20")
    row = fleet_row_from_probe("web-prod-1", probe)
    assert row["load1"] == "78.20"
    assert row["mem_pct"] == "94%"  # 15000/16000
    assert row["fpm"] == "80/80"
    assert "nginx" in row["stack"]


def test_format_fleet_table_sorts_load_desc_errors_last():
    rows = [
        fleet_row_from_probe("idle", "LOAD=0.10 0.1 0.1\nCPU=2\nMEM=4000 1000 3000\nFPM=\nSTACK= nginx\nLISTEN=80,"),
        fleet_row_from_probe("busy", "LOAD=78.2 60 40\nCPU=4\nMEM=16000 15000 1000\nFPM=80/80\nSTACK= nginx\nLISTEN=80,"),
        {"name": "dead", "error": "timeout"},
    ]
    out = format_fleet_table(rows)
    assert out.index("busy") < out.index("idle") < out.index("dead")
    assert "timeout" in out  # the dead host's reason is shown, not a generic word
    assert "L/core" in out   # load-per-core column present


# ---------------------------------------------------------------------------
# db_profiles config + resolver
# ---------------------------------------------------------------------------

def test_db_profile_for_matches_by_id_and_name():
    cfg = AppConfig(db_profiles=[
        DBProfile(instance="i-123", engine="mysql"),
        DBProfile(instance="prod-db", engine="postgres"),
    ])
    assert cfg.db_profile_for("i-123").engine == "mysql"
    assert cfg.db_profile_for("nope", "prod-db").engine == "postgres"
    assert cfg.db_profile_for("PROD-DB").engine == "postgres"  # case-insensitive
    assert cfg.db_profile_for("unknown") is None


def test_db_profiles_round_trip_through_manager(tmp_path, monkeypatch):
    """from_dict must coerce db_profiles dicts into DBProfile instances."""
    raw = {
        "version": AppConfig().version,
        "db_profiles": [
            {"instance": "i-1", "engine": "mysql", "user": "app",
             "password_secret": "db/app", "port": 3306,
             "unknown_key": "dropped"},
        ],
    }
    cm = ConfigManager.__new__(ConfigManager)  # bypass __init__/disk load
    cfg = cm._deserialize(raw)
    assert len(cfg.db_profiles) == 1
    p = cfg.db_profiles[0]
    assert isinstance(p, DBProfile)
    assert p.instance == "i-1" and p.password_secret == "db/app"


# ---------------------------------------------------------------------------
# DB command builder — password via env, never via -p / argv on the box
# ---------------------------------------------------------------------------

def test_build_db_command_mysql_password_in_env_not_client_argv():
    t = _tools()
    profile = DBProfile(instance="x", engine="mysql", host="127.0.0.1",
                        port=3306, user="root")
    cmd = t._build_db_command(profile, "SHOW PROCESSLIST;", "s3cr3t")
    # Password is exported as DBP (env), consumed via MYSQL_PWD="$DBP" — never
    # as a -p argv on the mysql client itself.
    assert "DBP='s3cr3t'" in cmd or "DBP=s3cr3t" in cmd
    assert "-ps3cr3t" not in cmd and "-p s3cr3t" not in cmd
    assert 'MYSQL_PWD="$DBP" mysql -h "$DBH"' in cmd


def test_build_db_command_has_php_fallback_when_no_mysql_client():
    t = _tools()
    cmd = t._build_db_command(
        DBProfile(instance="x", engine="mysql", user="root"),
        "SHOW FULL PROCESSLIST;", "pw")
    # The decisive fix: when the box has no mysql client, fall back to php
    # (always present on a PHP/Joomla box).
    assert "command -v mysql" in cmd
    assert "elif command -v php" in cmd and "php -r" in cmd and "multi_query" in cmd
    # The password is NOT inside the php -r argument (php reads it via getenv).
    php_part = cmd.split("php -r", 1)[1]
    assert "pw" not in php_part


def test_build_db_command_postgres_uses_pdo_fallback():
    t = _tools()
    cmd = t._build_db_command(
        DBProfile(instance="x", engine="postgres", host="db.internal",
                  port=5432, user="app", database="appdb"),
        "SELECT 1;", "pw")
    assert 'PGPASSWORD="$DBP" psql -h "$DBH"' in cmd
    assert "command -v psql" in cmd and "PDO" in cmd  # php PDO_pgsql fallback


def test_build_db_command_quotes_dangerous_password():
    t = _tools()
    # A password with shell metacharacters must be shlex-quoted in the DBP
    # export so it can't break out of the command.
    cmd = t._build_db_command(
        DBProfile(instance="x", engine="mysql", user="root"),
        "SELECT 1;", "p@ss'; rm -rf /")
    assert "DBP='p@ss'\"'\"'; rm -rf /'" in cmd  # shlex-quoted, inert


def test_db_setup_remove():
    cfg = AppConfig(db_profiles=[
        DBProfile(instance="web", engine="mysql", password_secret="db/web"),
    ])
    t = _tools(cfg)
    sp = MagicMock(); sp.delete_secret = AsyncMock(return_value=True)
    t._secret_provider = sp
    out = asyncio.run(t.db_setup_remove("web"))
    assert "Removed db_profile for web" in out and "deleted" in out
    sp.delete_secret.assert_awaited_once_with("db/web")
    t._config_manager.update.assert_called_once()


def test_db_setup_remove_no_profile():
    t = _tools(AppConfig())
    out = asyncio.run(t.db_setup_remove("nope"))
    assert "No db_profile found" in out


def test_scan_command_searches_deep():
    cmd = DBCredentialScanner.build_scan_command()
    assert "-maxdepth 7" in cmd  # reaches /home/<user>/<domain>/<sub>/html/...
    assert "configuration.php" in cmd


# ---------------------------------------------------------------------------
# DB tool error paths (no secret provider / no profile)
# ---------------------------------------------------------------------------

def test_db_processlist_errors_without_profile():
    t = _tools(AppConfig())
    t._find_instance = _async_return({"id": "i-1", "name": "n"})  # type: ignore
    out = asyncio.run(t.db_processlist("i-1"))
    assert "No db_profile configured" in out


def test_db_processlist_errors_without_secret_provider():
    cfg = AppConfig(db_profiles=[
        DBProfile(instance="i-1", engine="mysql", password_secret="db/app"),
    ])
    t = _tools(cfg, secret_provider=None)
    t._find_instance = _async_return({"id": "i-1", "name": "n"})  # type: ignore
    out = asyncio.run(t.db_processlist("i-1"))
    assert "no secret store is" in out.lower() or "log in" in out.lower()


def _async_return(value):
    async def _f(*_a, **_k):
        return value
    return _f


# ---------------------------------------------------------------------------
# IP enrichment
# ---------------------------------------------------------------------------

def test_resolve_key_env_indirection(monkeypatch):
    monkeypatch.setenv("MY_ABUSE_KEY", "abc123")
    assert _resolve_key("$MY_ABUSE_KEY") == "abc123"
    assert _resolve_key("literal") == "literal"
    assert _resolve_key("") == ""


def test_format_enrichment_table():
    rows = [{
        "ip": "1.1.1.1", "rdns": "bad.example.net", "asn": "AS12345",
        "org": "Bulletproof LLC", "country": "RU", "hosting": True,
        "proxy": False, "abuse_score": 100, "total_reports": 42, "error": "",
    }]
    out = format_enrichment(rows)
    assert "1.1.1.1" in out and "100%" in out and "AS12345" in out
    assert "hosting" in out and "42 reports" in out


def test_enrich_ips_caps_and_dedupes():
    svc = IPEnrichmentService(config_manager=None)
    assert svc.max_ips == 100
    # No network: empty input returns empty without any HTTP.
    assert asyncio.run(svc.enrich([])) == []


# ---------------------------------------------------------------------------
# Guard tiers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tool", ["web_traffic_summary", "fleet_health_snapshot", "enrich_ips"])
def test_readonly_probes_allowed_at_readonly(tool):
    cfg = AppConfig()
    cfg.mcp.guard_level = GuardLevel.READONLY
    g = CommandGuard(cfg.mcp)
    ok, _ = g.check_tool(tool)
    assert ok


@pytest.mark.parametrize("tool", ["db_processlist", "db_top_queries"])
def test_db_tools_blocked_at_readonly_allowed_at_standard(tool):
    cfg = AppConfig()
    cfg.mcp.guard_level = GuardLevel.READONLY
    assert not CommandGuard(cfg.mcp).check_tool(tool)[0]
    cfg.mcp.guard_level = GuardLevel.STANDARD
    assert CommandGuard(cfg.mcp).check_tool(tool)[0]


def test_describe_ingress_path_allowed_at_readonly():
    cfg = AppConfig()
    cfg.mcp.guard_level = GuardLevel.READONLY
    assert CommandGuard(cfg.mcp).check_tool("describe_ingress_path")[0]


# ---------------------------------------------------------------------------
# describe_ingress_path — boto3 topology walk (mocked clients)
# ---------------------------------------------------------------------------

from servonaut.services import ingress_path_service as ips_mod
from servonaut.services.ingress_path_service import (
    IngressPathService, format_ingress_path,
)

_LB_ARN = "arn:aws:elasticloadbalancing:eu-west-1:1:loadbalancer/app/shop/abc"
_TG_ARN = "arn:aws:elasticloadbalancing:eu-west-1:1:targetgroup/shop-tg/xyz"


def _fake_elbv2(target_id, *, tg_lb_arns=(_LB_ARN,)):
    c = MagicMock()
    c.get_paginator.return_value.paginate.return_value = [{
        "TargetGroups": [{
            "TargetGroupArn": _TG_ARN, "TargetGroupName": "shop-tg",
            "Port": 443, "Protocol": "HTTPS",
            "LoadBalancerArns": list(tg_lb_arns),
        }],
    }]
    c.describe_target_health.return_value = {
        "TargetHealthDescriptions": [
            {"Target": {"Id": target_id}, "TargetHealth": {"State": "healthy"}},
        ],
    }
    c.describe_load_balancers.return_value = {
        "LoadBalancers": [{
            "LoadBalancerArn": _LB_ARN, "DNSName": "shop-123.elb.amazonaws.com",
            "Type": "application", "Scheme": "internet-facing",
        }],
    }
    c.describe_listeners.return_value = {
        "Listeners": [{"ListenerArn": "li-1", "Port": 443, "Protocol": "HTTPS"}],
    }
    c.describe_rules.return_value = {
        "Rules": [{
            "Priority": "1",
            "Conditions": [{"Field": "host-header", "Values": ["shop.example"]}],
            "Actions": [{"Type": "forward"}],
        }],
    }
    return c


def _fake_wafv2(*, attached=True, raise_for_resource=False):
    c = MagicMock()
    if raise_for_resource:
        c.get_web_acl_for_resource.side_effect = RuntimeError("AccessDenied")
        return c
    c.get_web_acl_for_resource.return_value = (
        {"WebACL": {"ARN": "acl-arn", "Name": "am-aws-waf", "Id": "acl-id"}}
        if attached else {}
    )
    c.get_web_acl.return_value = {"WebACL": {
        "DefaultAction": {"Allow": {}},
        "Rules": [
            {"Name": "ipblock", "Statement": {
                "IPSetReferenceStatement": {"ARN": "ipset-arn"}}},
            {"Name": "rate", "Statement": {"AndStatement": {"Statements": [
                {"RateBasedStatement": {"Limit": 2000, "AggregateKeyType": "IP"}},
            ]}}},
        ],
    }}
    return c


def _patch_boto3(monkeypatch, elbv2, wafv2):
    def _factory(service, **_kw):
        return {"elbv2": elbv2, "wafv2": wafv2}[service]
    monkeypatch.setattr(ips_mod.boto3, "client", _factory)


def test_ingress_full_topology(monkeypatch):
    _patch_boto3(monkeypatch, _fake_elbv2("i-123"), _fake_wafv2())
    topo = asyncio.run(IngressPathService().describe("i-123", "10.0.0.9", "eu-west-1"))
    assert topo["errors"] == []
    assert topo["target_groups"][0]["name"] == "shop-tg"
    lb = topo["load_balancers"][0]
    assert lb["type"] == "application"
    assert lb["listeners"][0]["rules"][0]["actions"] == ["forward"]
    acl = lb["web_acl"]
    assert acl["name"] == "am-aws-waf"
    assert acl["ip_sets"][0]["arn"] == "ipset-arn"
    # Rate rule nested in AndStatement is found by the recursive scan.
    assert acl["rate_rules"][0]["limit_per_5min"] == 2000
    out = format_ingress_path(topo, mod_remoteip_trusted=False)
    assert "am-aws-waf" in out and "2000/5min" in out
    assert "real-IP trust on box: no" in out


def test_ingress_match_by_private_ip(monkeypatch):
    # Target registered by IP (ip-type TG), not instance id.
    _patch_boto3(monkeypatch, _fake_elbv2("10.0.0.9"), _fake_wafv2())
    topo = asyncio.run(IngressPathService().describe("i-999", "10.0.0.9", "eu-west-1"))
    assert topo["target_groups"], "should match on private IP"


def test_ingress_no_target_groups(monkeypatch):
    elbv2 = _fake_elbv2("i-OTHER")  # health lists a different target
    _patch_boto3(monkeypatch, elbv2, _fake_wafv2())
    topo = asyncio.run(IngressPathService().describe("i-123", "10.0.0.9", "eu-west-1"))
    assert topo["target_groups"] == []
    assert topo["load_balancers"] == []
    out = format_ingress_path(topo, None)
    assert "NOT" in out and "ALB" in out


def test_ingress_no_webacl_attached(monkeypatch):
    _patch_boto3(monkeypatch, _fake_elbv2("i-123"), _fake_wafv2(attached=False))
    topo = asyncio.run(IngressPathService().describe("i-123", "", "eu-west-1"))
    assert topo["load_balancers"][0]["web_acl"] is None
    out = format_ingress_path(topo, True)
    assert "NONE attached" in out and "no WAF" in out


def test_ingress_partial_failure_on_waf(monkeypatch):
    # wafv2 denied → topology still returned, error recorded (incident reality).
    _patch_boto3(monkeypatch, _fake_elbv2("i-123"),
                 _fake_wafv2(raise_for_resource=True))
    topo = asyncio.run(IngressPathService().describe("i-123", "", "eu-west-1"))
    assert topo["target_groups"], "TG topology survives a WAF denial"
    assert any("get_web_acl_for_resource" in e for e in topo["errors"])
    out = format_ingress_path(topo, None)
    assert "Partial result" in out


# ---------------------------------------------------------------------------
# run_command transport (SSH → SSM fallback)
# ---------------------------------------------------------------------------

from unittest.mock import AsyncMock
from servonaut.mcp import tools as tools_mod
from servonaut.services import ssm_service as ssm_mod

_AWS_INSTANCE = {"id": "i-1", "name": "web", "region": "eu-west-1",
                 "private_ip": "10.0.0.1"}


def _run_tools():
    cfg = AppConfig()
    cfg.mcp.guard_level = GuardLevel.DANGEROUS  # so 'ls' passes the command guard
    t = _tools(cfg)
    t._find_instance = _async_return(_AWS_INSTANCE)  # type: ignore
    return t


def _patch_ssh(monkeypatch, *, stdout=b"", stderr=b"", timeout=False):
    if timeout:
        monkeypatch.setattr(tools_mod, "run_ssh_subprocess",
                            AsyncMock(side_effect=asyncio.TimeoutError()))
    else:
        monkeypatch.setattr(tools_mod, "run_ssh_subprocess",
                            AsyncMock(return_value=(stdout, stderr)))


def _patch_ssm(monkeypatch, result):
    fake = MagicMock()
    fake.run_command = AsyncMock(return_value=result)
    monkeypatch.setattr(ssm_mod, "SSMService", lambda: fake)
    return fake


def test_run_command_ssh_success_annotates_transport(monkeypatch):
    _patch_ssh(monkeypatch, stdout=b"hello\n")
    out = asyncio.run(_run_tools().run_command("i-1", "ls", transport="ssh"))
    assert "hello" in out and "[transport_used: ssh]" in out


def test_run_command_ssh_only_conn_failure_suggests_ssm(monkeypatch):
    _patch_ssh(monkeypatch, stdout=b"", stderr=b"ssh: connect to host x port 22: Connection refused")
    out = asyncio.run(_run_tools().run_command("i-1", "ls", transport="ssh"))
    assert "SSH connection failed" in out and "ssm" in out.lower()


def test_run_command_auto_falls_back_to_ssm_on_conn_failure(monkeypatch):
    _patch_ssh(monkeypatch, stdout=b"", stderr=b"Connection timed out")
    _patch_ssm(monkeypatch, {"ok": True, "status": "Success",
                             "stdout": "from-ssm\n", "stderr": "", "error": ""})
    out = asyncio.run(_run_tools().run_command("i-1", "ls"))  # auto
    assert "fell back to SSM" in out
    assert "from-ssm" in out and "[transport_used: ssm]" in out


def test_run_command_auto_timeout_reports_not_ssm(monkeypatch):
    # Behavior change (intentional): a command-duration timeout means SSH is
    # healthy but the command ran longer than mcp.command_timeout_seconds. With
    # SSH keepalives now detecting genuine transport failures separately (which
    # DO still fall back to SSM), a timeout must NOT silently switch to SSM —
    # it reports clearly so the caller can raise the timeout for long ops.
    _patch_ssh(monkeypatch, timeout=True)
    fake = _patch_ssm(monkeypatch, {"ok": True, "status": "Success",
                                    "stdout": "ok", "stderr": "", "error": ""})
    out = asyncio.run(_run_tools().run_command("i-1", "ls"))
    assert "timed out" in out
    assert "[transport_used: ssm]" not in out
    fake.run_command.assert_not_called()  # timeout is not a transport failure


def test_run_command_auto_ssh_success_no_ssm(monkeypatch):
    _patch_ssh(monkeypatch, stdout=b"direct\n")
    fake = _patch_ssm(monkeypatch, {"ok": True})
    out = asyncio.run(_run_tools().run_command("i-1", "ls"))
    assert "[transport_used: ssh]" in out
    fake.run_command.assert_not_called()  # SSH worked → SSM never touched


def test_run_command_ssm_forced(monkeypatch):
    fake = _patch_ssm(monkeypatch, {"ok": True, "status": "Success",
                                    "stdout": "ssm-out", "stderr": "", "error": ""})
    out = asyncio.run(_run_tools().run_command("i-1", "ls", transport="ssm"))
    assert "ssm-out" in out and "[transport_used: ssm]" in out
    fake.run_command.assert_called_once()


def test_run_command_ssm_non_aws_rejected(monkeypatch):
    t = _run_tools()
    t._find_instance = _async_return(  # type: ignore
        {"id": "srv", "name": "c", "is_custom": True})
    out = asyncio.run(t.run_command("srv", "ls", transport="ssm"))
    assert "AWS-only" in out


def test_run_command_invalid_transport(monkeypatch):
    out = asyncio.run(_run_tools().run_command("i-1", "ls", transport="carrier-pigeon"))
    assert "transport must be" in out


def test_run_command_auto_ssm_failure_reports_both(monkeypatch):
    _patch_ssh(monkeypatch, stdout=b"", stderr=b"Connection refused")
    _patch_ssm(monkeypatch, {"ok": False, "status": "Failed",
                             "stdout": "", "stderr": "agent error",
                             "error": "send_command: InvalidInstanceId"})
    out = asyncio.run(_run_tools().run_command("i-1", "ls"))
    assert "fell back to SSM" in out and "Error (SSM)" in out


def test_is_ssh_connection_failure_detection():
    t = _tools()
    assert t._is_ssh_connection_failure("ssh: connect to host: Connection refused")
    assert t._is_ssh_connection_failure("Connection timed out during banner exchange")
    # A command that ran but failed is NOT a connection failure.
    assert not t._is_ssh_connection_failure("bash: foo: command not found")
    assert not t._is_ssh_connection_failure("Permission denied (publickey).")


# ---------------------------------------------------------------------------
# Group C: WAF mitigation
# ---------------------------------------------------------------------------

from servonaut.services import waf_management_service as waf_mod
from servonaut.services.waf_management_service import (
    WAFManagementService, parse_wafv2_arn,
)
from servonaut.services.ip_ban_service import IPBanService, _to_cidr

_WEBACL_ARN = "arn:aws:wafv2:eu-west-1:123:regional/webacl/am-aws-waf/acl-id"
_IPSET_ARN = "arn:aws:wafv2:eu-west-1:123:regional/ipset/blocklist/ip-id"


def test_parse_wafv2_arn():
    p = parse_wafv2_arn(_WEBACL_ARN)
    assert p == {"region": "eu-west-1", "scope": "REGIONAL", "kind": "webacl",
                 "name": "am-aws-waf", "id": "acl-id"}
    assert parse_wafv2_arn(_IPSET_ARN)["kind"] == "ipset"
    assert parse_wafv2_arn("not-an-arn") is None


def test_to_cidr_and_validate():
    assert _to_cidr("9.9.9.9") == "9.9.9.9/32"
    assert _to_cidr("1.2.3.0/24") == "1.2.3.0/24"
    svc = IPBanService(MagicMock())
    assert svc.validate_ip("1.1.1.1")
    assert svc.validate_ip("8.8.0.0/16")
    assert not svc.validate_ip("not-an-ip")


def _fake_wafv2_for_ipset(monkeypatch, addresses):
    client = MagicMock()
    client.get_web_acl.return_value = {"WebACL": {"Rules": [{
        "Name": "blockrule", "Action": {"Block": {}},
        "Statement": {"IPSetReferenceStatement": {"ARN": _IPSET_ARN}},
    }]}}
    client.get_ip_set.return_value = {
        "IPSet": {"Addresses": list(addresses)}, "LockToken": "lt"}
    monkeypatch.setattr(waf_mod.boto3, "client", lambda *a, **k: client)
    return client


def test_add_ip_to_block_ipset_applies(monkeypatch):
    client = _fake_wafv2_for_ipset(monkeypatch, ["9.9.9.9/32"])  # pre-existing entry
    res = asyncio.run(WAFManagementService().add_ip_to_block_ipset(
        "am-aws-waf", "acl-id", "REGIONAL", "eu-west-1", ["1.1.1.1"]))
    assert res["applied"] == ["1.1.1.1"] and res["ip_set"] == "blocklist"
    # update_ip_set called with the new address appended.
    _, kw = client.update_ip_set.call_args
    assert "1.1.1.1/32" in kw["Addresses"]


def test_add_ip_to_block_ipset_duplicate(monkeypatch):
    _fake_wafv2_for_ipset(monkeypatch, ["1.1.1.1/32"])
    res = asyncio.run(WAFManagementService().add_ip_to_block_ipset(
        "am-aws-waf", "acl-id", "REGIONAL", "eu-west-1", ["1.1.1.1"]))
    assert res["applied"] == []
    assert res["failed"][0]["reason"] == "already present"


def test_add_ip_to_block_ipset_no_blockset(monkeypatch):
    client = MagicMock()
    client.get_web_acl.return_value = {"WebACL": {"Rules": []}}
    monkeypatch.setattr(waf_mod.boto3, "client", lambda *a, **k: client)
    res = asyncio.run(WAFManagementService().add_ip_to_block_ipset(
        "am-aws-waf", "acl-id", "REGIONAL", "eu-west-1", ["1.1.1.1"]))
    assert "no block rule" in res["error"].lower()


def test_set_rate_rule_add_and_remove(monkeypatch):
    client = MagicMock()
    client.get_web_acl.return_value = {
        "WebACL": {"DefaultAction": {"Allow": {}},
                   "VisibilityConfig": {"SampledRequestsEnabled": True,
                                        "CloudWatchMetricsEnabled": True,
                                        "MetricName": "acl"},
                   "Rules": []},
        "LockToken": "lt"}
    monkeypatch.setattr(waf_mod.boto3, "client", lambda *a, **k: client)
    res = asyncio.run(WAFManagementService().set_rate_rule(
        "am-aws-waf", "acl-id", "REGIONAL", "eu-west-1",
        rule_name="flood", limit=500, uri_scope="/"))
    assert res["applied"] is True
    _, kw = client.update_web_acl.call_args
    rule = kw["Rules"][0]
    assert rule["Statement"]["RateBasedStatement"]["Limit"] == 500
    assert "ScopeDownStatement" in rule["Statement"]["RateBasedStatement"]

    assert res["created_or_updated"] == "created" and res["previous"] is None

    # Removing a non-existent rule errors.
    res2 = asyncio.run(WAFManagementService().set_rate_rule(
        "am-aws-waf", "acl-id", "REGIONAL", "eu-west-1",
        rule_name="ghost", remove=True))
    assert res2["applied"] is False and "not found" in res2["error"]


def test_set_rate_rule_update_captures_previous(monkeypatch):
    # An existing rule of the same name → updated + previous state captured
    # (so the change is reversible to the prior limit, not just deletable).
    client = MagicMock()
    client.get_web_acl.return_value = {
        "WebACL": {"DefaultAction": {"Allow": {}},
                   "VisibilityConfig": {"SampledRequestsEnabled": True,
                                        "CloudWatchMetricsEnabled": True,
                                        "MetricName": "acl"},
                   "Rules": [{
                       "Name": "flood", "Priority": 3,
                       "Statement": {"RateBasedStatement": {"Limit": 1000}},
                       "Action": {"Block": {}},
                       "VisibilityConfig": {"SampledRequestsEnabled": True,
                                            "CloudWatchMetricsEnabled": True,
                                            "MetricName": "flood"},
                   }]},
        "LockToken": "lt"}
    monkeypatch.setattr(waf_mod.boto3, "client", lambda *a, **k: client)
    res = asyncio.run(WAFManagementService().set_rate_rule(
        "am-aws-waf", "acl-id", "REGIONAL", "eu-west-1",
        rule_name="flood", limit=500))
    assert res["applied"] is True
    assert res["created_or_updated"] == "updated"
    assert res["previous"] == {"limit": 1000, "uri_scoped": False, "action": "block"}


# --- tool-level flows -------------------------------------------------------

class _FakeWAF:
    """Fake WAFManagementService injected into the tools module."""
    def __init__(self, *, ipset=None, rate=None):
        self._ipset = ipset or {"applied": ["1.1.1.1"], "failed": [], "ip_set": "blocklist", "error": ""}
        self._rate = rate or {"applied": True, "error": "", "rule_name": "servonaut-rate",
                              "created_or_updated": "created", "previous": None}
    async def add_ip_to_block_ipset(self, *a, **k):
        return self._ipset
    async def set_rate_rule(self, *a, **k):
        return self._rate


def test_ip_ban_set_bulk_via_config(monkeypatch):
    cfg = AppConfig(); cfg.mcp.guard_level = GuardLevel.DANGEROUS
    t = _tools(cfg)
    t._find_instance = _async_return({"id": "i-1"})  # type: ignore
    svc = MagicMock()
    svc.ban_ip = AsyncMock(side_effect=[
        {"success": True, "message": "ok"},
        {"success": False, "message": "invalid"},
    ])
    t._ip_ban_service = svc
    out = asyncio.run(t.ip_ban_set(
        config_name="waf-set", action="ban",
        ip_addresses=["1.1.1.1", "999.0.0.0"]))
    assert "Banned (1): 1.1.1.1" in out
    assert "Failed (1)" in out and "999.0.0.0" in out
    assert "reverse_hint: ip_ban_set action=unban" in out


def test_ip_ban_set_via_site(monkeypatch):
    cfg = AppConfig(); cfg.mcp.guard_level = GuardLevel.DANGEROUS
    t = _tools(cfg)
    t._resolve_webacl = _async_return(  # type: ignore
        {"name": "am-aws-waf", "id": "acl-id", "scope": "REGIONAL",
         "region": "eu-west-1", "arn": _WEBACL_ARN})
    monkeypatch.setattr(waf_mod, "WAFManagementService", lambda: _FakeWAF())
    out = asyncio.run(t.ip_ban_set(site="shop-ec2", ip_address="1.1.1.1/32"))
    assert "WebACL: am-aws-waf" in out and "Banned (1)" in out


def test_waf_rate_rule_set_apply(monkeypatch):
    cfg = AppConfig(); cfg.mcp.guard_level = GuardLevel.DANGEROUS
    t = _tools(cfg)
    t._resolve_webacl = _async_return(  # type: ignore
        {"name": "am-aws-waf", "id": "acl-id", "scope": "REGIONAL",
         "region": "eu-west-1", "arn": _WEBACL_ARN})
    monkeypatch.setattr(waf_mod, "WAFManagementService", lambda: _FakeWAF())
    out = asyncio.run(t.waf_rate_rule_set(
        site="shop-ec2", rule_name="flood", limit=500, uri_scope="/"))
    assert "Created rate rule 'flood'" in out and "500 req/5min" in out
    assert "reverse_hint" in out and "remove=true" in out


def test_waf_rate_rule_set_update_surfaces_previous(monkeypatch):
    cfg = AppConfig(); cfg.mcp.guard_level = GuardLevel.DANGEROUS
    t = _tools(cfg)
    t._resolve_webacl = _async_return(  # type: ignore
        {"name": "am-aws-waf", "id": "acl-id", "scope": "REGIONAL",
         "region": "eu-west-1", "arn": _WEBACL_ARN})
    rate = {"applied": True, "error": "", "rule_name": "flood",
            "created_or_updated": "updated",
            "previous": {"limit": 1000, "uri_scoped": False, "action": "block"}}
    monkeypatch.setattr(waf_mod, "WAFManagementService",
                        lambda: _FakeWAF(rate=rate))
    out = asyncio.run(t.waf_rate_rule_set(site="shop-ec2", rule_name="flood", limit=500))
    assert "Updated rate rule 'flood'" in out
    assert "previous: 1000 req/5min" in out
    # reverse_hint restores the PRIOR limit, not a delete.
    assert "restore prior" in out and "limit=1000" in out


def test_block_ip_prefers_webacl(monkeypatch):
    cfg = AppConfig(); cfg.mcp.guard_level = GuardLevel.DANGEROUS
    t = _tools(cfg)
    t._resolve_webacl = _async_return(  # type: ignore
        {"name": "am-aws-waf", "id": "acl-id", "scope": "REGIONAL",
         "region": "eu-west-1", "arn": _WEBACL_ARN})
    monkeypatch.setattr(waf_mod, "WAFManagementService", lambda: _FakeWAF())
    out = asyncio.run(t.block_ip("1.1.1.1", site="shop-ec2"))
    assert "layer_used: waf" in out and "applied: True" in out
    assert "why:" in out and "real client IP" in out  # layer rationale surfaced


def test_block_ip_falls_back_to_host_recommendation(monkeypatch):
    cfg = AppConfig(); cfg.mcp.guard_level = GuardLevel.DANGEROUS
    t = _tools(cfg)
    t._resolve_webacl = _async_return({"error": "no WebACL found"})  # type: ignore
    t._ip_ban_service = None
    out = asyncio.run(t.block_ip("1.1.1.1", site="shop-ec2"))
    assert "layer_used: host" in out and "applied: False" in out
    assert "Require not ip" in out  # host-level recommendation, not auto-applied


@pytest.mark.parametrize("tool", ["waf_rate_rule_set", "block_ip"])
def test_group_c_dangerous_tier(tool):
    cfg = AppConfig()
    cfg.mcp.guard_level = GuardLevel.STANDARD
    assert not CommandGuard(cfg.mcp).check_tool(tool)[0]
    cfg.mcp.guard_level = GuardLevel.DANGEROUS
    assert CommandGuard(cfg.mcp).check_tool(tool)[0]


# ---------------------------------------------------------------------------
# rds_metrics
# ---------------------------------------------------------------------------

from datetime import datetime as _dt
import servonaut.services.rds_metrics_service as rds_mod
from servonaut.services.cloudwatch_service import CloudWatchService as _CWS


def test_rds_metrics_service(monkeypatch):
    client = MagicMock()

    def _gms(**kw):
        name = kw["MetricName"]
        dp = {"Timestamp": _dt(2026, 6, 3, 10)}
        if name == "CPUUtilization":
            return {"Datapoints": [{**dp, "Average": 40, "Maximum": 95, "Minimum": 10}]}
        if name == "DatabaseConnections":
            return {"Datapoints": [{**dp, "Average": 50, "Maximum": 80, "Minimum": 20}]}
        if name == "ReadLatency":  # seconds → ms
            return {"Datapoints": [{**dp, "Average": 0.005, "Maximum": 0.02, "Minimum": 0.001}]}
        return {"Datapoints": []}

    client.get_metric_statistics.side_effect = _gms
    monkeypatch.setattr(rds_mod.boto3, "client", lambda *a, **k: client)
    data = asyncio.run(rds_mod.RDSMetricsService().fetch(
        "db-1", region="eu-west-1", window_hours=3))
    assert data["metrics"]["cpu_pct"]["max"] == 95
    assert data["metrics"]["read_latency_ms"]["avg"] == 5.0  # 0.005s → 5ms
    # CPUCreditBalance had no datapoints → absent, not an error.
    assert "cpu_credit_balance" not in data["metrics"]
    out = rds_mod.format_rds_metrics(data)
    assert "RDS metrics for db-1" in out and "95.0%" in out and "Read latency" in out


def test_rds_metrics_partial_failure(monkeypatch):
    client = MagicMock()
    client.get_metric_statistics.side_effect = RuntimeError("AccessDenied")
    monkeypatch.setattr(rds_mod.boto3, "client", lambda *a, **k: client)
    data = asyncio.run(rds_mod.RDSMetricsService().fetch("db-1", region="eu-west-1"))
    assert data["metrics"] == {} and data["errors"]
    assert "No datapoints" in rds_mod.format_rds_metrics(data)


def test_rds_metrics_tool(monkeypatch):
    class _FakeRDS:
        async def fetch(self, *a, **k):
            return {"db_instance": "db-1", "window_hours": 3,
                    "metrics": {"cpu_pct": {"avg": 40, "max": 95, "min": 10, "latest": 40}},
                    "errors": []}
    monkeypatch.setattr(rds_mod, "RDSMetricsService", lambda: _FakeRDS())
    out = asyncio.run(_tools().rds_metrics("db-1", region="eu-west-1"))
    assert "RDS metrics for db-1" in out and "95%" in out


def test_rds_metrics_requires_id():
    out = asyncio.run(_tools().rds_metrics(""))
    assert "provide a db_instance" in out


def test_rds_metrics_readonly_tier():
    cfg = AppConfig(); cfg.mcp.guard_level = GuardLevel.READONLY
    assert CommandGuard(cfg.mcp).check_tool("rds_metrics")[0]


# ---------------------------------------------------------------------------
# cloudwatch_get_log_events aggregation
# ---------------------------------------------------------------------------

def _cw_tools(events):
    t = _tools()
    cw = MagicMock()
    cw.get_log_events = AsyncMock(return_value=events)
    cw.aggregate_events = _CWS.aggregate_events  # real static aggregator
    t._cloudwatch_service = cw
    return t


def test_cloudwatch_group_by_clientip():
    import json
    ev = [{"message": json.dumps({"httpRequest": {"clientIp": "1.1.1.1"},
                                  "action": "BLOCK"})}] * 3
    out = asyncio.run(_cw_tools(ev).cloudwatch_get_log_events(
        "waf-lg", group_by="clientIp"))
    assert "top clientIp" in out and "1.1.1.1" in out and "100.0%" in out


def test_cloudwatch_group_by_uri_strips_query():
    import json
    ev = [
        {"message": json.dumps({"httpRequest": {"clientIp": "1.1.1.1", "uri": "/search?q=a"}})},
        {"message": json.dumps({"httpRequest": {"clientIp": "1.1.1.1", "uri": "/search?q=b"}})},
    ]
    out = asyncio.run(_cw_tools(ev).cloudwatch_get_log_events(
        "lg", group_by="uri", top_n=5))
    assert "/search" in out and "2" in out


def test_cloudwatch_bad_group_by():
    out = asyncio.run(_cw_tools([{"message": "x"}]).cloudwatch_get_log_events(
        "lg", group_by="banana"))
    assert "group_by must be" in out


def test_cloudwatch_summary_only():
    out = asyncio.run(_cw_tools([{"message": "x"}] * 5).cloudwatch_get_log_events(
        "lg", summary_only=True))
    assert "5 events in lg" in out


def test_cloudwatch_raw_listing_still_default():
    ts = _dt(2026, 6, 3, 10)
    out = asyncio.run(_cw_tools([{"timestamp": ts, "message": "hello"}]
                                ).cloudwatch_get_log_events("lg"))
    assert "hello" in out and "top " not in out


# ---------------------------------------------------------------------------
# DB credential scanner + db_setup_scan / db_setup_save
# ---------------------------------------------------------------------------

from servonaut.services.db_credential_scanner import (
    DBCredentialScanner, DBCandidate, redact,
)

_SECRET_PW = "s3cr3tP@ss!word"


def _dsn(scheme, user, pw, host, port, db):
    """Assemble a DB DSN at runtime so no credentialed connection-string literal
    (a URL embedding user + password) sits in the source — a synthetic test
    fixture must not read like a leaked secret to the repo's scanner."""
    auth = f"{user}:{pw}"
    return f"{scheme}://{auth}@{host}:{port}/{db}"


def test_scanner_parses_laravel_dotenv():
    text = ("===FILE:/var/www/app/.env===\n"
            "DB_CONNECTION=mysql\nDB_HOST=10.0.0.5\nDB_PORT=3306\n"
            f"DB_USERNAME=app\nDB_PASSWORD={_SECRET_PW}\nDB_DATABASE=appdb\n")
    cands = DBCredentialScanner().parse(text)
    assert len(cands) == 1
    c = cands[0]
    assert (c.engine, c.host, c.port, c.user, c.database) == \
        ("mysql", "10.0.0.5", 3306, "app", "appdb")
    assert c.password == _SECRET_PW


def test_scanner_parses_database_url():
    text = (f"===FILE:/app/.env===\nDATABASE_URL=postgres://u:{_SECRET_PW}@db.x:5433/mydb\n")
    c = DBCredentialScanner().parse(text)[0]
    assert c.engine == "postgres" and c.host == "db.x" and c.port == 5433
    assert c.user == "u" and c.database == "mydb" and c.password == _SECRET_PW


def test_scanner_parses_wp_config():
    text = ("===FILE:/var/www/html/wp-config.php===\n"
            "<?php\ndefine('DB_NAME', 'wp');\ndefine('DB_USER', 'wpuser');\n"
            f"define('DB_PASSWORD', '{_SECRET_PW}');\n"
            "define('DB_HOST', 'localhost:3307');\n")
    c = DBCredentialScanner().parse(text)[0]
    assert c.engine == "mysql" and c.user == "wpuser" and c.port == 3307
    assert c.database == "wp" and c.password == _SECRET_PW


def test_scanner_parses_docker_postgres():
    text = ("===FILE:/srv/.env===\nPOSTGRES_USER=pg\n"
            f"POSTGRES_PASSWORD={_SECRET_PW}\nPOSTGRES_DB=app\n")
    c = DBCredentialScanner().parse(text)[0]
    assert c.engine == "postgres" and c.user == "pg" and c.database == "app"


def test_scanner_skips_unusable_and_dedupes():
    text = (
        "===FILE:/a/.env===\nDB_HOST=h\n"  # no password → unusable
        "===FILE:/b/.env===\nDB_HOST=h2\nDB_USERNAME=u\nDB_PASSWORD=p\n"
        "===FILE:/c/.env===\nDB_HOST=h2\nDB_USERNAME=u\nDB_PASSWORD=p\n"  # dup of b
    )
    cands = DBCredentialScanner().parse(text)
    assert len(cands) == 1  # unusable skipped, duplicate collapsed


def test_redact_masks_password():
    c = DBCandidate("mysql", "h", 3306, "u", _SECRET_PW)
    r = redact(c)
    assert _SECRET_PW not in str(r)
    assert r["password_preview"].startswith("****")


def test_db_setup_scan_stages_without_leaking_password():
    t = _tools()
    t._find_instance = _async_return({"id": "i-1", "name": "web"})  # type: ignore
    dump = ("===FILE:/var/www/app/.env===\nDB_CONNECTION=mysql\nDB_HOST=127.0.0.1\n"
            f"DB_PORT=3306\nDB_USERNAME=app\nDB_PASSWORD={_SECRET_PW}\nDB_DATABASE=appdb\n")
    t._exec_ssh = _async_return((dump, ""))  # type: ignore
    out = asyncio.run(t.db_setup_scan("i-1"))
    # The plaintext password must NEVER appear in the model-facing result...
    assert _SECRET_PW not in out
    assert "token=dbstg_" in out and "****" in out
    # ...but it IS held server-side for the commit step.
    assert len(t._db_staging) == 1
    assert list(t._db_staging.values())[0].password == _SECRET_PW
    # ...and never reaches the audit trail either.
    audit_blob = str([c.args for c in t._audit.log.call_args_list])
    assert _SECRET_PW not in audit_blob


def test_db_setup_save_commits_and_consumes_token():
    t = _tools()
    sp = MagicMock(); sp.set_secret = AsyncMock()
    t._secret_provider = sp
    # Bare web-root path → no derivable site label → legacy db/<instance> name.
    t._db_staging["tok1"] = DBCandidate(
        "mysql", "127.0.0.1", 3306, "app", _SECRET_PW, "appdb", "/var/www/html/.env")
    out = asyncio.run(t.db_setup_save("tok1", instance_id="web"))
    assert "Saved db_profile for web" in out
    assert _SECRET_PW not in out
    # Secret stored with the plaintext; result/audit carry only the key name.
    name, value = sp.set_secret.call_args.args
    assert name == "db/web" and value == _SECRET_PW
    t._config_manager.update.assert_called_once()
    assert "tok1" not in t._db_staging  # token consumed
    audit_blob = str([c.args for c in t._audit.log.call_args_list])
    assert _SECRET_PW not in audit_blob


def test_db_setup_save_unknown_token():
    t = _tools()
    t._secret_provider = MagicMock()
    out = asyncio.run(t.db_setup_save("nope"))
    assert "unknown or expired" in out


def test_db_setup_save_no_secret_provider():
    t = _tools(secret_provider=None)
    t._db_staging["tok"] = DBCandidate("mysql", "h", 3306, "u", _SECRET_PW)
    out = asyncio.run(t.db_setup_save("tok"))
    assert "no secret store" in out.lower()


@pytest.mark.parametrize("tool", ["db_setup_scan", "db_setup_save"])
def test_db_setup_tools_standard_tier(tool):
    cfg = AppConfig(); cfg.mcp.guard_level = GuardLevel.READONLY
    assert not CommandGuard(cfg.mcp).check_tool(tool)[0]
    cfg.mcp.guard_level = GuardLevel.STANDARD
    assert CommandGuard(cfg.mcp).check_tool(tool)[0]


# ---------------------------------------------------------------------------
# Feedback round: Joomla/Magento scanner, FPM/load-per-core, rule collapse
# ---------------------------------------------------------------------------

def test_scanner_parses_joomla_configuration():
    text = (
        "===FILE:/var/www/shop/configuration.php===\n<?php\nclass JConfig {\n"
        "public $dbtype = 'mysqli';\npublic $host = 'db.internal';\n"
        "public $user = 'joomla';\n"
        f"public $password = '{_SECRET_PW}';\npublic $db = 'shop';\n"
        "public $dbprefix = 'jos_';\n}\n"
    )
    c = DBCredentialScanner().parse(text)[0]
    assert c.engine == "mysql" and c.host == "db.internal" and c.user == "joomla"
    assert c.database == "shop" and c.password == _SECRET_PW


def test_scanner_joomla_pgsql_engine():
    text = ("===FILE:/srv/site/configuration.php===\n"
            "public $dbtype = 'pgsql';\npublic $host = 'h';\npublic $user = 'u';\n"
            f"public $password = '{_SECRET_PW}';\npublic $db = 'd';\n")
    assert DBCredentialScanner().parse(text)[0].engine == "postgres"


def test_scanner_parses_magento_env():
    text = (
        "===FILE:/var/www/m/app/etc/env.php===\n<?php return ['db'=>['connection'=>"
        "['default'=>[\n'host' => 'localhost',\n'dbname' => 'magento',\n"
        f"'username' => 'mage',\n'password' => '{_SECRET_PW}',\n]]]];\n"
    )
    c = DBCredentialScanner().parse(text)[0]
    assert c.engine == "mysql" and c.user == "mage"
    assert c.database == "magento" and c.password == _SECRET_PW


def test_scan_command_includes_joomla_magento():
    cmd = DBCredentialScanner.build_scan_command()
    assert "configuration.php" in cmd and "env.php" in cmd and "wp-config.php" in cmd


# ---------------------------------------------------------------------------
# Dockerised stacks: compose parsing, sudo read fallback, *_PROD URL variants
# ---------------------------------------------------------------------------

def test_scan_command_includes_compose_and_sudo_fallback():
    cmd = DBCredentialScanner.build_scan_command()
    # Compose files are now discovered...
    assert "compose*.yml" in cmd and "docker-compose*.yaml" in cmd
    # ...and root-owned configs get a non-interactive sudo read fallback.
    assert "sudo -n sed" in cmd


def test_scanner_parses_compose_literal_map_form():
    text = (
        "===FILE:/home/deploy/apps/shop.example.com/compose.prod.yaml===\n"
        "services:\n  db:\n    image: mariadb:11\n    environment:\n"
        "      MYSQL_USER: shopuser\n"
        f"      MYSQL_PASSWORD: {_SECRET_PW}\n"
        "      MYSQL_DATABASE: shopdb\n"
        "      MYSQL_HOST: 127.0.0.1\n"
    )
    cands = DBCredentialScanner().parse(text)
    assert len(cands) == 1
    c = cands[0]
    assert c.engine == "mysql" and c.user == "shopuser"
    assert c.database == "shopdb" and c.password == _SECRET_PW
    # Label is derived from the domain dir, not the compose filename.
    assert redact(c)["label"] == "shop.example.com"


def test_scanner_parses_compose_list_form():
    text = (
        "===FILE:/srv/apps/site/compose.yaml===\n"
        "services:\n  db:\n    environment:\n"
        "      - MYSQL_USER=u\n"
        f"      - MYSQL_PASSWORD={_SECRET_PW}\n"
        "      - MYSQL_DATABASE=d\n"
    )
    c = DBCredentialScanner().parse(text)[0]
    assert c.user == "u" and c.database == "d" and c.password == _SECRET_PW


def test_scanner_resolves_compose_interpolation_from_sibling_env():
    # compose references ${VAR}; the real value lives in the co-located .env.
    text = (
        "===FILE:/srv/apps/blog.example.com/.env===\n"
        f"MYSQL_PASSWORD={_SECRET_PW}\nMYSQL_USER=bloguser\n"
        "===FILE:/srv/apps/blog.example.com/compose.yaml===\n"
        "services:\n  db:\n    environment:\n"
        "      - MYSQL_USER=${MYSQL_USER}\n"
        "      - MYSQL_PASSWORD=${MYSQL_PASSWORD}\n"
        "      - MYSQL_DATABASE=blogdb\n"
    )
    cands = DBCredentialScanner().parse(text)
    # The .env twin (no database) is collapsed into the richer compose row.
    assert len(cands) == 1
    c = cands[0]
    assert c.user == "bloguser" and c.database == "blogdb"
    assert c.password == _SECRET_PW


def test_scanner_compose_interpolation_default():
    text = (
        "===FILE:/srv/apps/x/compose.yaml===\n"
        "services:\n  db:\n    environment:\n"
        "      MYSQL_USER: ${MYSQL_USER:-root}\n"
        f"      MYSQL_PASSWORD: ${{MYSQL_PW:-{_SECRET_PW}}}\n"
        "      MYSQL_DATABASE: appdb\n"
    )
    c = DBCredentialScanner().parse(text)[0]
    assert c.user == "root" and c.password == _SECRET_PW


def test_scanner_compose_unresolved_interpolation_is_dropped():
    # ${VAR} with no sibling .env and no default → we must NOT invent a secret.
    text = (
        "===FILE:/srv/apps/x/compose.yaml===\n"
        "services:\n  db:\n    environment:\n"
        "      - MYSQL_USER=u\n"
        "      - MYSQL_PASSWORD=${MYSQL_PASSWORD}\n"
    )
    assert DBCredentialScanner().parse(text) == []


def test_scanner_compose_bare_key_passthrough_skipped():
    # `- MYSQL_PASSWORD` (value from host env) carries no value we can see.
    text = (
        "===FILE:/srv/apps/x/compose.yaml===\n"
        "services:\n  db:\n    environment:\n"
        "      - MYSQL_PASSWORD\n      - MYSQL_USER=u\n"
    )
    assert DBCredentialScanner().parse(text) == []


def test_scanner_compose_postgres():
    text = (
        "===FILE:/srv/apps/api.example.com/compose.yaml===\n"
        "services:\n  db:\n    image: postgres:16\n    environment:\n"
        "      POSTGRES_USER: pg\n"
        f"      POSTGRES_PASSWORD: {_SECRET_PW}\n"
        "      POSTGRES_DB: apidb\n"
    )
    c = DBCredentialScanner().parse(text)[0]
    assert c.engine == "postgres" and c.user == "pg" and c.database == "apidb"


def test_scanner_prefers_prod_url_over_placeholder():
    # Committed DATABASE_URL is an empty-password placeholder; the real
    # credential is in DATABASE_URL_PROD, which must win.
    text = (
        "===FILE:/var/www/site/.env===\n"
        "APP_ENV=prod\n"
        "DATABASE_URL=mysql://app:@127.0.0.1:3306/app\n"
        f"DATABASE_URL_PROD={_dsn('mysql', 'real', _SECRET_PW, 'db.internal', 3306, 'prod')}\n"
    )
    cands = DBCredentialScanner().parse(text)
    assert len(cands) == 1
    c = cands[0]
    assert c.user == "real" and c.host == "db.internal"
    assert c.database == "prod" and c.password == _SECRET_PW


def test_scanner_compose_map_value_with_colons():
    # Regression: a map-form value that itself contains colons (a DSN) must
    # survive — partition(':') keeps everything after the first colon.
    text = (
        "===FILE:/srv/apps/api.example.com/compose.prod.yaml===\n"
        "services:\n  app:\n    environment:\n"
        f'      DATABASE_URL: "{_dsn("mysql", "apiuser", _SECRET_PW, "db.internal", 3307, "apidb")}"\n'
        "      APP_ENV: prod\n"
    )
    c = DBCredentialScanner().parse(text)[0]
    assert c.user == "apiuser" and c.host == "db.internal" and c.port == 3307
    assert c.database == "apidb" and c.password == _SECRET_PW


def test_scanner_compose_partial_unresolved_interpolation_dropped():
    # A value mixing a literal with an unresolvable ${VAR} must be dropped
    # whole — never keep the literal remainder as an invented secret.
    text = (
        "===FILE:/srv/apps/x/compose.yaml===\n"
        "services:\n  db:\n    environment:\n"
        "      - MYSQL_USER=u\n"
        "      - MYSQL_PASSWORD=prefix-${MISSING_SECRET}\n"
    )
    assert DBCredentialScanner().parse(text) == []


def test_scanner_multi_db_same_host_user_preserved():
    # Two sites sharing a DB host + user but distinct databases must both
    # survive de-dup (the multi-DB-per-instance case).
    text = (
        "===FILE:/srv/a/compose.yaml===\n"
        "services:\n  db:\n    environment:\n"
        "      MYSQL_USER: shared\n"
        f"      MYSQL_PASSWORD: {_SECRET_PW}\n"
        "      MYSQL_DATABASE: db_a\n      MYSQL_HOST: 10.0.0.9\n"
        "===FILE:/srv/b/compose.yaml===\n"
        "services:\n  db:\n    environment:\n"
        "      MYSQL_USER: shared\n"
        f"      MYSQL_PASSWORD: {_SECRET_PW}\n"
        "      MYSQL_DATABASE: db_b\n      MYSQL_HOST: 10.0.0.9\n"
    )
    dbs = sorted(c.database for c in DBCredentialScanner().parse(text))
    assert dbs == ["db_a", "db_b"]


def test_fleet_row_load_per_core_and_fpm():
    probe = ("LOAD=8.0 4.0 2.0\nCPU=4\nMEM=16000 8000 8000\n"
             "FPM=80/80\nSTACK= nginx php-fpm\nLISTEN=80,443,")
    row = fleet_row_from_probe("busy", probe)
    assert row["cores"] == "4"
    assert row["load_per_core"] == "2.00"  # 8.0 / 4 — the triage ratio
    assert row["fpm"] == "80/80"


def test_fleet_row_no_data_becomes_error():
    row = fleet_row_from_probe("weird", "some ssh login banner, no KEY=VALUE\n")
    assert row.get("error") and "no probe data" in row["error"]


def test_fleet_table_has_cores_and_lcore_headers():
    row = fleet_row_from_probe("h", "LOAD=1.0 1 1\nCPU=2\nMEM=4000 1000 3000\nFPM=\nSTACK= nginx\nLISTEN=80,")
    out = format_fleet_table([row])
    assert "Cores" in out and "L/core" in out and "CPU" not in out.split("\n")[0]


def test_format_ingress_collapses_and_surfaces_webacl_first():
    topo = {
        "instance_id": "i-1", "region": "eu-west-1",
        "target_groups": [{"name": "shop-tg", "arn": "a", "port": 443,
                           "protocol": "HTTPS", "target_state": "healthy"}],
        "load_balancers": [{
            "arn": "lb", "dns_name": "x.elb", "type": "application",
            "scheme": "internet-facing",
            "listeners": [{"port": 443, "protocol": "HTTPS", "rules": [
                {"priority": "1", "conditions": ["host-header=shop.example"],
                 "actions": ["forward"], "targets_our_tg": True},
                {"priority": "2", "conditions": ["host-header=other.example"],
                 "actions": ["forward"], "targets_our_tg": False},
                {"priority": "3", "conditions": ["host-header=z.example"],
                 "actions": ["forward"], "targets_our_tg": False},
            ]}],
            "web_acl": {"name": "ELB-WAF-ACL", "default_action": "allow",
                        "ip_sets": [], "rate_rules": [
                            {"rule": "Rate_limit_shop", "limit_per_5min": 1000,
                             "aggregate_key": "IP"}]},
        }],
        "errors": [],
    }
    out = format_ingress_path(topo, True)
    # WebACL gold surfaced before the load-balancer detail.
    assert out.index("WAF / WebACL") < out.index("Load balancers")
    assert "Rate_limit_shop" in out and "1000/5min" in out
    # Matching rule shown + marked; non-matching collapsed to a count.
    assert "shop.example" in out and "←this instance" in out
    assert "+2 other rule(s)" in out
    assert "other.example" not in out
    # verbose shows everything.
    assert "other.example" in format_ingress_path(topo, True, verbose=True)


# ---------------------------------------------------------------------------
# Carry-over: db_processlist summarises by default; FPM probe robustness
# ---------------------------------------------------------------------------

def _db_tools_capturing_sql(engine: str):
    """ServonautTools whose db_processlist SQL is captured, no live SSH/DB."""
    cfg = AppConfig(db_profiles=[
        DBProfile(instance="i-1", engine=engine, password_secret="db/app"),
    ])
    cfg.mcp.guard_level = GuardLevel.STANDARD
    t = _tools(cfg)
    profile = cfg.db_profiles[0]
    captured: dict = {}
    t._resolve_db = _async_return(({"id": "i-1", "name": "n"}, profile, "pw", ""))  # type: ignore

    def _build(_p, sql, _pw):
        captured["sql"] = sql
        return "DBCMD"
    t._build_db_command = _build  # type: ignore
    t._exec_ssh = _async_return(("out", ""))  # type: ignore
    return t, captured


def test_db_processlist_summarises_by_default_mysql():
    t, captured = _db_tools_capturing_sql("mysql")
    asyncio.run(t.db_processlist("i-1"))
    sql = captured["sql"]
    assert "information_schema.PROCESSLIST" in sql
    assert "GROUP BY COMMAND" in sql            # aggregated breakdown
    assert "Threads_running" in sql             # saturation signal
    assert "SHOW FULL PROCESSLIST" not in sql   # NOT the 300-row dump


def test_db_processlist_full_dumps_mysql():
    t, captured = _db_tools_capturing_sql("mysql")
    asyncio.run(t.db_processlist("i-1", full=True))
    assert "SHOW FULL PROCESSLIST" in captured["sql"]


def test_db_processlist_summarises_by_default_postgres():
    t, captured = _db_tools_capturing_sql("postgres")
    asyncio.run(t.db_processlist("i-1"))
    sql = captured["sql"]
    assert "pg_stat_activity" in sql
    assert "GROUP BY state" in sql
    assert "max_connections" in sql
    assert "LIMIT 10" in sql                     # only the 10 oldest non-idle


def test_db_processlist_full_dumps_postgres():
    t, captured = _db_tools_capturing_sql("postgres")
    asyncio.run(t.db_processlist("i-1", full=True))
    sql = captured["sql"]
    assert "GROUP BY state" not in sql           # raw, not aggregated
    assert "ORDER BY query_start NULLS LAST" in sql


def test_fleet_probe_detects_fpm_via_master():
    # Regression guard for the blank-FPM-column fix: presence is detected via
    # the master process title (can't self-match the probe shell, survives an
    # idle ondemand pool), capacity is SUMMED across pools, and a sudo fallback
    # covers root-only pool.d configs.
    cmd = ServonautTools._FLEET_PROBE_CMD
    assert "php-fpm: master" in cmd
    assert "php-fpm: pool" in cmd                # worker count
    assert "pm.max_children" in cmd
    assert "s+=$1" in cmd                        # summed capacity, not single max
    assert "sudo -n" in cmd
