from __future__ import annotations

from servonaut.services.vault.grant_processor import GrantProcessor


def test_grant_processor_exposes_strict_verification_option() -> None:
    assert GrantProcessor.__init__.__kwdefaults__["strict_verification"] is False
