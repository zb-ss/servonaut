"""The OVH read tools check the guard and write exactly one audit row per call.

Every outcome is covered: success (including empty results), guard refusal,
service unavailable, unknown instance, validation errors and API errors. Each
failure is recorded with ``allowed=False`` and a distinct reason code, and the
text returned to the agent is unchanged.
"""
from __future__ import annotations

import asyncio
from typing import Any, Callable, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, PropertyMock

import pytest

from servonaut.mcp.guards import GuardLevel
from tests.test_mcp_tools import make_tools

_UNAVAILABLE = "Error: OVH {} is not available. Ensure OVH is configured and enabled."
_VPS = {"id": "vps-1", "name": "vps-1", "provider_type": "vps"}
_CLOUD_WITHOUT_PROJECT = {"id": "cloud-1", "name": "cloud-1", "provider_type": "cloud"}

# tool -> (service attribute, service method, kwargs, successful payload)
_SERVICE_TOOLS: Dict[str, tuple] = {
    "ovh_list_ips": (
        "_ovh_ip_service", "list_ips", {},
        [{"ip": "192.0.2.10", "type": "failover",
          "routedTo": {"serviceName": "vps-1"}, "country": "FR"}],
    ),
    "ovh_firewall_rules": (
        "_ovh_ip_service", "list_firewall_rules", {"ip": "192.0.2.10"},
        [{"sequence": 0, "action": "permit", "protocol": "tcp",
          "source": "0.0.0.0/0", "destinationPort": "80"}],
    ),
    "ovh_snapshots": (
        "_ovh_snapshot_service", "list_vps_snapshots", {"instance_id": "vps-1"},
        [{"id": "snap-1", "name": "nightly", "creationDate": "2026-01-01"}],
    ),
    "ovh_dns_records": (
        "_ovh_dns_service", "list_records", {"zone": "example.com", "record_type": "A"},
        [{"fieldType": "A", "subDomain": "www", "ttl": 3600, "target": "192.0.2.10"}],
    ),
    "ovh_billing": (
        "_ovh_billing_service", "get_current_usage", {},
        {"current_spend": {"totalPrice": 1.5}, "forecast": {"totalPrice": 3}},
    ),
    "ovh_invoices": (
        "_ovh_billing_service", "get_invoices", {"limit": 3},
        [{"billId": "B-1", "date": "2026-01-01",
          "priceWithTax": {"value": 1.5, "currencyCode": "EUR"}, "status": "paid"}],
    ),
}
_UNAVAILABLE_LABELS = {
    "ovh_list_ips": "IP service",
    "ovh_firewall_rules": "IP service",
    "ovh_ssh_keys": "service",
    "ovh_snapshots": "snapshot service",
    "ovh_dns_records": "DNS service",
    "ovh_billing": "billing service",
    "ovh_invoices": "billing service",
}
_KWARGS = {name: spec[2] for name, spec in _SERVICE_TOOLS.items()}
_KWARGS["ovh_ssh_keys"] = {}


def _tools():
    tools = make_tools(guard_level=GuardLevel.READONLY)
    tools._find_instance = AsyncMock(return_value=_VPS)
    for attribute, *_ in _SERVICE_TOOLS.values():
        setattr(tools, attribute, None)
    tools._ovh_service = None
    return tools


def _wire(tool: str, behaviour: Any) -> Callable:
    """Wire the tool's service so its call returns ``behaviour`` (or raises it)."""
    def setup(tools):
        if tool == "ovh_ssh_keys":
            service = MagicMock()
            if isinstance(behaviour, BaseException):
                service.client.get.side_effect = behaviour
            else:
                service.client.get.side_effect = lambda path: (
                    behaviour if path == "/me/sshKey"
                    else {"key": "ssh-ed25519 AAAAC3Nza deploy", "default": True}
                )
            tools._ovh_service = service
            return
        attribute, method, _kwargs, _payload = _SERVICE_TOOLS[tool]
        service = MagicMock()
        if isinstance(behaviour, BaseException):
            setattr(service, method, AsyncMock(side_effect=behaviour))
        else:
            setattr(service, method, AsyncMock(return_value=behaviour))
        setattr(tools, attribute, service)
    return setup


def _success_payload(tool: str) -> Any:
    return ["deploy"] if tool == "ovh_ssh_keys" else _SERVICE_TOOLS[tool][3]


def _deny_guard(tool: str) -> Callable:
    def setup(tools):
        _wire(tool, _success_payload(tool))(tools)
        tools._guard = MagicMock()
        tools._guard.check_tool.return_value = (False, "denied_for_test")
    return setup


def _ssh_client_unavailable(tools):
    service = MagicMock()
    type(service).client = PropertyMock(side_effect=ImportError("python-ovh is not installed"))
    tools._ovh_service = service


def _instance(found: Optional[dict]) -> Callable:
    def setup(tools):
        _wire("ovh_snapshots", _success_payload("ovh_snapshots"))(tools)
        tools._find_instance = AsyncMock(return_value=found)
    return setup


def _case(tool, setup, allowed, reason, output, case_id):
    return pytest.param(tool, setup, allowed, reason, output, id=f"{tool}-{case_id}")


def _cases():
    cases = []
    for tool in _UNAVAILABLE_LABELS:
        cases += [
            _case(tool, _wire(tool, _success_payload(tool)), True, None, None, "success"),
            _case(tool, _deny_guard(tool), False, "denied_for_test",
                  "Blocked: denied_for_test", "guard_denied"),
            _case(tool, lambda tools: None, False, "ovh_unavailable",
                  _UNAVAILABLE.format(_UNAVAILABLE_LABELS[tool]), "unavailable"),
            _case(tool, _wire(tool, RuntimeError("boom")), False, "api_error: boom",
                  "Error fetching", "api_error"),
        ]
        if tool != "ovh_billing":  # billing renders "no data" rows instead
            cases.append(_case(tool, _wire(tool, []), True, None, "No ", "empty"))
    for tool in ("ovh_firewall_rules", "ovh_snapshots", "ovh_dns_records"):
        cases.append(_case(tool, _wire(tool, ValueError("bad input")), False,
                           "validation: bad input", "Error: bad input", "validation"))
    cases += [
        _case("ovh_snapshots", _instance(None), False, "instance_not_found",
              "Instance not found: vps-1", "instance_not_found"),
        _case("ovh_snapshots", _instance(_CLOUD_WITHOUT_PROJECT), False,
              "missing_project_id", "Error: Cannot determine project_id", "missing_project_id"),
        _case("ovh_ssh_keys", _ssh_client_unavailable, False,
              "api_error: python-ovh is not installed",
              "Error fetching OVH SSH keys: python-ovh is not installed", "client_error"),
    ]
    return cases


@pytest.mark.parametrize(("tool", "setup", "allowed", "reason", "output"), _cases())
def test_ovh_read_tool_writes_one_audit_row(tool, setup, allowed, reason, output):
    tools = _tools()
    setup(tools)
    kwargs = _KWARGS[tool]

    result = asyncio.run(getattr(tools, tool)(**kwargs))

    assert tools._audit.log.call_count == 1, tools._audit.log.call_args_list
    call = tools._audit.log.call_args
    assert call.args[0] == tool
    assert call.args[1] == kwargs
    assert call.args[3] is allowed
    if allowed:
        assert call.args[2] == result
        assert len(call.args) == 4 and not call.kwargs
    else:
        assert call.args[2] == ""
        assert call.args[4] == reason
    if output is not None:
        assert result.startswith(output), result


def test_guard_refusal_does_not_reach_the_service():
    tools = _tools()
    _deny_guard("ovh_list_ips")(tools)

    asyncio.run(tools.ovh_list_ips())

    tools._guard.check_tool.assert_called_once_with("ovh_list_ips")
    tools._ovh_ip_service.list_ips.assert_not_called()
