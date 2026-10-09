"""The next vault step for this user, worked out from what the service reports.

Pure functions: they read the identity status (``GET /api/v1/vault/identity/me``
as returned by ``VaultCommandService.status``) and the vault list, and never
make requests. Every message is fixed client text, so it is safe to show as-is.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class NextStep:
    """One thing the user should do next, for the CLI and the Vault screen."""

    code: str
    message: str
    command: Optional[str] = None
    # Vault screen button that performs the step, when there is one.
    action: Optional[str] = None

    def to_dict(self) -> dict[str, Optional[str]]:
        return asdict(self)


SETUP = NextStep(
    "setup",
    "Create your vault identity and write down its recovery key.",
    "servonaut vault setup",
    "vault_setup",
)
ADD_DEVICE = NextStep(
    "add_device",
    "Your vault identity lives on another device. Add this device and approve it there, "
    "or recover it here with your recovery key.",
    "servonaut vault devices add",
    "vault_add_device",
)
RECOVER_DEVICE = NextStep(
    "recover_device",
    "This computer used your vault before, but its vault key file is missing. "
    "Recover it with your recovery key: your vaults and items are safe on the server.",
    "servonaut vault recover",
    "vault_recover",
)
RESET_IDENTITY = NextStep(
    "reset_identity",
    "Your vault identity was reported compromised. Reset it to get a new one.",
    "servonaut vault reset-identity --reason compromised",
    "vault_reset",
)
CONFIRM_IDENTITY = NextStep(
    "confirm_identity",
    "Confirm your vault identity: open the link we e-mailed you, "
    "or sign in again with two-factor and confirm it here.",
    "servonaut vault identity confirm",
    "vault_confirm_identity",
)
AWAITING_ACCESS = NextStep(
    "awaiting_access",
    "Waiting for access to your team's vault: an owner's or admin's Servonaut grants it "
    "while it is open, automatically or after their approval.",
)
CREATE_VAULT = NextStep(
    "create_vault",
    "Create your personal vault to keep SSH keys and secrets encrypted.",
    "servonaut vault create --name Personal",
    "vault_create",
)
NO_VAULT = NextStep(
    "no_vault",
    "You have no vault yet. A team owner or admin creates the team vault; "
    "a personal vault needs a plan that includes it.",
)
READY = NextStep("ready", "Your vault is ready.")


def identity_step(status: Mapping[str, Any]) -> Optional[NextStep]:
    """The identity step still to do, or ``None`` once the identity is usable."""
    remote = status.get("remote") if isinstance(status, Mapping) else None
    identity = remote.get("identity") if isinstance(remote, Mapping) else None
    local = status.get("local_identity") if isinstance(status, Mapping) else None
    if not isinstance(identity, Mapping):
        return SETUP
    if not local:
        return RECOVER_DEVICE if status.get("custody_missing") is True else ADD_DEVICE
    trust = identity.get("trust_status")
    if trust == "compromised":
        return RESET_IDENTITY
    if trust == "pending_confirmation":
        return CONFIRM_IDENTITY
    return None


def vault_step(vaults: Sequence[Mapping[str, Any]], *, can_create_personal: bool) -> NextStep:
    """The vault step for a user whose identity is confirmed."""
    if not vaults:
        return CREATE_VAULT if can_create_personal else NO_VAULT
    if any(is_awaiting_access(vault) for vault in vaults):
        return AWAITING_ACCESS
    return READY


def next_step(
    status: Mapping[str, Any],
    vaults: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    can_create_personal: bool = False,
) -> NextStep:
    """The identity step first; then, when the vault list is known, the vault step."""
    step = identity_step(status)
    if step is not None:
        return step
    if vaults is None:
        return READY
    return vault_step(vaults, can_create_personal=can_create_personal)


def is_awaiting_access(vault: Mapping[str, Any]) -> bool:
    """A team vault this member may read but holds no key for yet.

    Viewers never read team vault items, so they are not waiting for anything.
    """
    return (
        vault.get("kind") == "team"
        and vault.get("my_grant") is None
        and vault.get("my_role") in {"owner", "admin", "member"}
    )
