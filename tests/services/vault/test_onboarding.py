"""The next vault step follows the identity, then the vaults the user can open."""
from __future__ import annotations

from typing import Any

import pytest

from servonaut.services.vault import onboarding


def _status(*, identity: dict[str, Any] | None = None, local: str | None = "fp") -> dict[str, Any]:
    return {"remote": {"identity": identity}, "local_identity": local, "fingerprint": local}


_CONFIRMED = {"trust_status": "confirmed", "grantable": True}


@pytest.mark.parametrize(("status", "code"), [
    (_status(identity=None, local=None), "setup"),
    (_status(identity=_CONFIRMED, local=None), "add_device"),
    (_status(identity={"trust_status": "compromised"}), "reset_identity"),
    (_status(identity={"trust_status": "pending_confirmation", "grantable": False}), "confirm_identity"),
    (_status(identity=_CONFIRMED), "ready"),
])
def test_identity_steps_come_first(status: dict[str, Any], code: str) -> None:
    assert onboarding.next_step(status).code == code


def test_identity_step_ignores_vaults_until_the_identity_is_confirmed() -> None:
    pending = _status(identity={"trust_status": "pending_confirmation"})

    assert onboarding.next_step(pending, [], can_create_personal=True).code == "confirm_identity"


def test_a_solo_user_without_a_vault_is_offered_a_personal_one() -> None:
    step = onboarding.next_step(_status(identity=_CONFIRMED), [], can_create_personal=True)

    assert step.code == "create_vault"
    assert step.command == "servonaut vault create --name Personal"
    assert step.action == "vault_create"


def test_a_user_whose_plan_has_no_personal_vault_is_told_who_creates_one() -> None:
    step = onboarding.next_step(_status(identity=_CONFIRMED), [], can_create_personal=False)

    assert step.code == "no_vault"
    assert step.command is None


def test_a_member_without_a_grant_is_waiting_for_access() -> None:
    vaults = [{"kind": "team", "my_role": "member", "my_grant": None}]

    assert onboarding.next_step(_status(identity=_CONFIRMED), vaults).code == "awaiting_access"


def test_a_viewer_is_not_waiting_for_a_team_vault_key() -> None:
    vaults = [{"kind": "team", "my_role": "viewer", "my_grant": None}]

    assert onboarding.next_step(_status(identity=_CONFIRMED), vaults).code == "ready"


def test_granted_and_personal_vaults_are_ready() -> None:
    vaults = [{"kind": "team", "my_role": "member", "my_grant": {"version": 1}},
              {"kind": "personal", "my_role": "owner", "my_grant": {"version": 1}}]

    step = onboarding.next_step(_status(identity=_CONFIRMED), vaults)

    assert step.code == "ready"
    assert step.to_dict() == {"code": "ready", "message": "Your vault is ready.", "command": None, "action": None}
