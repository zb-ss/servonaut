from __future__ import annotations

import pytest

from servonaut.services.vault.bindings import VaultBindingService


def test_binding_rejects_host_key_comment_and_invalid_key() -> None:
    with pytest.raises(ValueError):
        VaultBindingService._validate_host_keys(["ssh-ed25519 AAAA comment"])


def test_binding_rejects_boolean_port_before_signature_verification() -> None:
    class Vaults:
        def verify_vault(self, _vault):
            return None

    service = VaultBindingService(None, Vaults())
    with pytest.raises(Exception, match="destination"):
        service.verify_binding(
            {"source": "servonaut_vault", "valid": True, "hostname": "host", "port": True},
            {}, target="shared_server:x", hostname="host", port=1,
        )
