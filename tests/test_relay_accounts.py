"""The relay across several accounts per provider."""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.models.relay_messages import CommandRequest, CommandType
from servonaut.services.relay_executors import RelayExecutors
from servonaut.services.relay_listener import RelayListener, _resolve_account_labels
from servonaut.services.remediation_executor import REMEDIATION_SOURCE
from tests._account_fixtures import build_registry


def _run(coro):
    return asyncio.run(coro)


HETZNER_WEB = {"id": "1", "name": "web-1", "public_ip": "9.9.9.9", "is_hetzner": True,
               "ssh_key": "~/.ssh/hetzner", "username": "root"}
STAGING_WEB = {"id": "2", "name": "web-1", "public_ip": "8.8.8.8", "is_hetzner": True}
OVH_VPS = {"id": "vps-1.example", "name": "mail", "public_ip": "1.1.1.1",
           "is_ovh": True, "provider_type": "vps"}


def _executors(registry):
    config_manager = MagicMock()
    config_manager.get.return_value = registry.config
    ssh_service = MagicMock()
    ssh_service.build_ssh_command.return_value = ["ssh", "host", "uptime"]
    connection = MagicMock()
    connection.resolve_profile.return_value = None
    connection.get_target_host.side_effect = lambda inst, profile: inst["public_ip"]
    connection.get_proxy_args.return_value = []
    connection.get_extra_options.return_value = []
    connection.resolve_ovh_connection.return_value = {"username": "ubuntu", "key_path": "~/.ssh/ovh"}
    custom = MagicMock()
    custom.list_as_instances.return_value = []
    return RelayExecutors(
        config_manager, registry.default_service("aws"), custom,
        ssh_service, connection, MagicMock(), accounts=registry,
    )


def _request(target):
    return CommandRequest(
        id="req-1", user_id="u", type=CommandType.RUN_COMMAND,
        target_server_id=target, payload={"command": "uptime"}, ttl_seconds=30,
    )


@pytest.fixture
def executors(monkeypatch):
    registry, _ = build_registry(
        monkeypatch,
        hetzner={"hetzner": [HETZNER_WEB], "staging": [STAGING_WEB]},
        ovh={"ovh": [OVH_VPS]},
    )
    return _executors(registry)


def _ssh_ok(monkeypatch):
    fake = AsyncMock(return_value=(b"up 3 days\n", b""))
    monkeypatch.setattr("servonaut.services.relay_executors.run_ssh_subprocess", fake)
    monkeypatch.setattr(
        "servonaut.services.relay_executors.detect_host_key_problem", lambda *a, **k: None,
    )
    return fake


def test_hetzner_and_ovh_servers_can_be_targeted(executors, monkeypatch):
    _ssh_ok(monkeypatch)
    response = _run(executors.execute(_request("mail")))
    assert response.status == "success" and "up 3 days" in response.output
    kwargs = executors._ssh_service.build_ssh_command.call_args.kwargs
    assert (kwargs["host"], kwargs["username"], kwargs["key_path"]) == (
        "1.1.1.1", "ubuntu", "~/.ssh/ovh",
    )

    response = _run(executors.execute(_request("staging/web-1")))
    assert response.status == "success"
    assert executors._ssh_service.build_ssh_command.call_args.kwargs["host"] == "8.8.8.8"


def test_hetzner_row_uses_its_own_ssh_defaults(executors, monkeypatch):
    _ssh_ok(monkeypatch)
    _run(executors.execute(_request("hetzner/web-1")))
    kwargs = executors._ssh_service.build_ssh_command.call_args.kwargs
    assert (kwargs["username"], kwargs["key_path"]) == ("root", "~/.ssh/hetzner")


def test_ambiguous_target_is_refused_with_candidates(executors, monkeypatch):
    ssh = _ssh_ok(monkeypatch)
    response = _run(executors.execute(_request("web-1")))
    assert response.status == "error"
    assert "hetzner/web-1" in response.error_message
    assert "staging/web-1" in response.error_message
    ssh.assert_not_awaited()


def test_unknown_target_is_still_not_found(executors):
    response = _run(executors.execute(_request("nope")))
    assert (response.status, response.error_message) == ("error", "Instance not found: nope")


def test_resolve_webacl_walks_the_instance_in_its_account(monkeypatch):
    registry, _ = build_registry(
        monkeypatch,
        aws={"aws": [], "prod": [{"id": "i-2", "name": "shop", "private_ip": "10.0.0.2",
                                  "region": "eu-west-1"}]},
    )
    executors = _executors(registry)
    walked = []

    class _Ingress:
        def __init__(self, account=None):
            self.account = account

        async def describe(self, *args):
            walked.append(self.account.ref.label)
            return {"load_balancers": [{"web_acl": {
                "arn": "arn:aws:wafv2:eu-west-1:111:regional/webacl/acl/id-1",
            }}]}

    with patch("servonaut.services.ingress_path_service.IngressPathService", _Ingress):
        acl = _run(executors.resolve_webacl("shop"))
    assert walked == ["prod"]
    assert acl["name"] == "acl" and acl["account"] == "prod"
    assert executors.webacl_account(acl).ref.label == "prod"


def test_resolve_webacl_reports_an_ambiguous_site(executors):
    acl = _run(executors.resolve_webacl("web-1"))
    assert "matches 2 servers" in acl["error"]


def test_ban_configs_act_in_their_own_accounts(executors):
    assert executors.ip_ban_service._strategies["waf"]._accounts is executors._accounts


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------


def _listener(**kwargs):
    return RelayListener(
        executors=MagicMock(), base_url="https://api.example.com",
        mercure_url="https://example.com/.well-known/mercure",
        auth_token="t", user_id="42", **kwargs,
    )


def test_handshake_names_the_account_labels(monkeypatch):
    registry, _ = build_registry(
        monkeypatch, aws={"aws": [], "prod": []}, hetzner={"hetzner": [], "staging": []},
    )
    app = MagicMock()
    app.accounts = registry
    labels = _resolve_account_labels(app)
    handshake = _listener(providers_configured=["aws", "hetzner"], accounts=labels)._build_handshake()
    assert handshake["accounts"] == {
        "aws": ["aws", "prod"], "hetzner": ["hetzner", "staging"], "ovh": [],
    }
    assert handshake["providers_configured"] == ["aws", "hetzner"]
    # Labels only: nothing about profiles or credentials.
    assert "profile" not in str(handshake) and "token" not in str(handshake["accounts"])


def test_handshake_without_accounts_keeps_its_shape():
    handshake = _listener()._build_handshake()
    assert "accounts" not in handshake
    assert "accounts" not in _listener(accounts={"aws": ["aws"]})._build_heartbeat()


def test_app_without_a_registry_sends_no_accounts():
    assert _resolve_account_labels(None) is None
    app = MagicMock(spec=[])
    assert _resolve_account_labels(app) is None


def test_tui_listener_factory_passes_accounts(monkeypatch):
    from servonaut.services import relay_manager

    registry, _ = build_registry(monkeypatch, hetzner={"hetzner": [], "staging": []})
    built = {}

    def fake_executors(config_manager, accounts=None):
        built["accounts"] = accounts
        return MagicMock()

    monkeypatch.setattr(relay_manager, "_build_executors", fake_executors)
    monkeypatch.setattr(relay_manager, "_extract_user_id", lambda auth: "42")
    captured = {}
    monkeypatch.setattr(
        "servonaut.services.relay_listener.RelayListener",
        lambda **kw: captured.update(kw) or MagicMock(),
    )
    app = MagicMock()
    app.accounts = registry
    manager = relay_manager.RelayManager.__new__(relay_manager.RelayManager)
    manager._app = app
    manager._config_manager = MagicMock()
    manager._config_manager.get.return_value = registry.config
    manager._auth_service = MagicMock(access_token="tok")
    manager._build_probe_bridge = lambda executors: None
    manager._handle_degraded = lambda *a: None
    manager._default_listener_factory(on_connected=None, on_disconnected=None)
    assert built["accounts"] is registry
    assert captured["accounts"]["hetzner"] == ["hetzner", "staging"]


def test_build_executors_builds_a_registry_when_none_is_given(monkeypatch):
    from servonaut.services import relay_manager

    registry, _ = build_registry(monkeypatch, ovh={"ovh": [OVH_VPS]})
    config_manager = MagicMock()
    config_manager.get.return_value = registry.config
    executors = relay_manager._build_executors(config_manager)
    assert _run(executors.find_instance("mail"))["id"] == "vps-1.example"


# ---------------------------------------------------------------------------
# Ban remediations act in the target server's AWS account
# ---------------------------------------------------------------------------

PROD_SHOP = {"id": "i-2", "name": "shop", "region": "eu-west-1",
             "public_ip": "1.1.1.1", "private_ip": "10.0.0.2"}


def _ban_configs():
    from servonaut.config.schema import IPBanConfig

    return [
        IPBanConfig(name="waf-a", method="waf", ip_set_name="a", region="eu-west-1"),
        IPBanConfig(name="waf-prod", method="waf", ip_set_name="p", region="eu-west-1",
                    account="prod"),
    ]


def _ban_listener(monkeypatch, *, configs, instance, aws_accounts=("aws", "prod")):
    from servonaut.services.relay_listener import RelayListener

    registry, _ = build_registry(monkeypatch, aws={label: [] for label in aws_accounts})
    executors = MagicMock()
    executors.accounts = registry
    executors.find_instance = AsyncMock(
        return_value=None if instance is None else dict(instance, account=aws_accounts[-1]),
    )
    ip_ban = MagicMock()
    ip_ban.get_configs = MagicMock(return_value=configs)
    ip_ban.ban_ip = AsyncMock(return_value={"success": True, "message": "banned", "rule_id": "r"})
    ip_ban.unban_ip = AsyncMock(return_value={"success": True, "message": "unbanned"})
    executors.ip_ban_service = ip_ban
    listener = RelayListener(
        executors=executors, base_url="https://app.example.com",
        mercure_url="https://hub.example.com/.well-known/mercure",
        auth_token="tok", user_id="user-1",
    )
    listener._post_result = AsyncMock()
    return listener, ip_ban


def _remediation(verb, target="shop"):
    return json.dumps({
        "id": f"rmd-{verb}", "user_id": "user-1", "type": verb,
        "target_server_id": target,
        "payload": {"finding_id": "fnd-1", "action": verb, "ip": "9.9.9.9",
                    "method": "waf", "dry_run": False, "applied_strategy": "waf",
                    "rule_id": "9.9.9.9/32"},
        "ttl_seconds": 300,
        "source": REMEDIATION_SOURCE,
    })


def _posted(listener):
    return listener._post_result.await_args.args[0]


@pytest.mark.parametrize("verb,method", [("block_ip", "ban_ip"), ("unblock_ip", "unban_ip")])
def test_ban_remediation_uses_the_config_of_the_servers_account(monkeypatch, verb, method):
    listener, ip_ban = _ban_listener(monkeypatch, configs=_ban_configs(), instance=PROD_SHOP)
    _run(listener._handle_event(_remediation(verb)))
    getattr(ip_ban, method).assert_awaited_once_with("9.9.9.9", "waf-prod")
    assert _posted(listener).status == "success"


@pytest.mark.parametrize("verb,slug", [
    ("block_ip", "block_ip_config_missing"), ("unblock_ip", "unblock_ip_config_missing"),
])
def test_no_config_in_the_servers_account_is_refused(monkeypatch, verb, slug):
    configs = [c for c in _ban_configs() if c.name == "waf-a"]
    listener, ip_ban = _ban_listener(monkeypatch, configs=configs, instance=PROD_SHOP)
    _run(listener._handle_event(_remediation(verb)))
    ip_ban.ban_ip.assert_not_awaited()
    ip_ban.unban_ip.assert_not_awaited()
    response = _posted(listener)
    assert response.status == "error"
    assert response.error_message.startswith(f"{slug}: no IP-ban configuration with method "
                                             "'waf' acts in AWS account 'prod'")


def test_unknown_target_is_refused_with_several_accounts(monkeypatch):
    listener, ip_ban = _ban_listener(monkeypatch, configs=_ban_configs(), instance=None)
    _run(listener._handle_event(_remediation("block_ip", target="i-gone")))
    ip_ban.ban_ip.assert_not_awaited()
    response = _posted(listener)
    assert response.status == "error"
    assert response.error_message.startswith("block_ip_config_missing: cannot choose")


def test_single_account_keeps_the_first_matching_config(monkeypatch):
    listener, ip_ban = _ban_listener(
        monkeypatch, configs=_ban_configs(), instance=PROD_SHOP, aws_accounts=("aws",),
    )
    _run(listener._handle_event(_remediation("block_ip")))
    ip_ban.ban_ip.assert_awaited_once_with("9.9.9.9", "waf-a")
