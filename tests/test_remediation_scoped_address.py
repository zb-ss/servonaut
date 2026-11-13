"""An address with a scope id never reaches a firewall command.

``ipaddress`` accepts ``2606:4700::1%anything`` and keeps the text after the
``%`` in ``str()``, so a scope id could carry shell syntax into the command.
"""
from __future__ import annotations

import pytest

from servonaut.services.remediation_executor import (
    RemediationValidationError,
    build_onbox_block_command,
    build_onbox_unblock_command,
    validate_block_ip_payload,
    validate_unblock_ip_payload,
)

SCOPED = [
    "2606:4700::1%$(touch${IFS}marker)",
    "2606:4700::1%`touch${IFS}marker`",
    "2606:4700::1%eth0",
    "2606:4700::1%25",
    "2606:4700::1%",
    "2606:4700::1%';touch marker;'",
]
METHODS = ["ufw", "firewalld", "nftables"]


@pytest.mark.parametrize("address", SCOPED)
def test_block_payload_with_a_scope_id_is_refused(address) -> None:
    with pytest.raises(RemediationValidationError, match="scope id"):
        validate_block_ip_payload({"ip": address, "method": "ufw"})


@pytest.mark.parametrize("address", SCOPED)
def test_unblock_payload_with_a_scope_id_is_refused(address) -> None:
    with pytest.raises(RemediationValidationError, match="scope id"):
        validate_unblock_ip_payload({"ip": address, "method": "ufw"})


@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize("address", SCOPED)
def test_builders_refuse_a_scope_id_too(method, address) -> None:
    with pytest.raises(RemediationValidationError):
        build_onbox_block_command(method, address)
    with pytest.raises(RemediationValidationError):
        build_onbox_unblock_command(method, address)


@pytest.mark.parametrize("method", METHODS)
def test_a_plain_address_is_unchanged(method) -> None:
    command = build_onbox_block_command(method, "2606:4700::1")
    assert "2606:4700::1" in command and "%" not in command
    assert build_onbox_unblock_command(method, "9.9.9.9").count("9.9.9.9") >= 2
