"""User-facing failure text for vault and SSH CA surfaces.

Vault failures normally reach the user as their exception class only, so
server text or local key material can never leak into a terminal or toast.
:class:`VaultUserError` is the one exception whose message is shown verbatim:
raise it only with fixed, client-authored text that tells the user what
happened or what to do.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from servonaut.services.api_client import APIError

from .display import terminal_safe

_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_SAFE_FIELD = re.compile(r"[a-z][a-z0-9_.-]{0,127}")


class VaultUserError(RuntimeError):
    """A fixed, secret-free message that is safe to show the user as-is."""


class HostKeysNeeded(VaultUserError):
    """A first vault binding has no host keys to pin.

    The message names no surface's controls: each surface adds its own way
    to supply the keys (command-line flags, or the dialog's buttons).
    *looked_up_trusted_keys* says whether the keys this machine trusts were
    looked up (and none found), or the caller chose neither to pin them nor
    to supply any.
    """

    def __init__(self, *, looked_up_trusted_keys: bool) -> None:
        self.looked_up_trusted_keys = looked_up_trusted_keys
        super().__init__(
            "this machine does not trust a host key for the server yet: connect to it once and check "
            "its fingerprint, or supply verified host keys"
            if looked_up_trusted_keys else
            "the first vault key for a server needs its host keys pinned: pin the ones this machine "
            "trusts, or supply verified host keys"
        )


class VaultKeyInUse(VaultUserError):
    """A key still bound to servers, or whose bindings could not be checked."""

    def __init__(
        self, *, team_servers: list[str], own_servers: list[str], unchecked: list[str],
    ) -> None:
        self.team_servers = [terminal_safe(name) for name in team_servers]
        self.own_servers = [terminal_safe(name) for name in own_servers]
        self.unchecked = [terminal_safe(name) for name in unchecked]
        message = (
            "this key is still used by the servers listed: give them another vault key first"
            if self.team_servers or self.own_servers else
            "could not read the saved key assignments from the Servonaut service; "
            "the hosts do not need to be running: retry the service check or use the Vault screen to confirm deletion with unchecked assignments"
        )
        super().__init__(message)

    @classmethod
    def from_usage(cls, usage: Mapping[str, Any]) -> VaultKeyInUse:
        """Build a refusal from the server-usage result shared by CLI and TUI."""
        return cls(
            team_servers=usage["team_servers"], own_servers=usage["own_servers"], unchecked=usage["unchecked"],
        )


# Why a recovery key was refused, in the user's terms.
RECOVERY_KEY_NOT_A_KEY = (
    "that is not a recovery key: a recovery key starts with SVRK1- and has 11 groups of five characters"
)
RECOVERY_KEY_TYPO = (
    "this recovery key has a typo: compare it character by character with the copy you wrote down"
)
RECOVERY_KEY_NOT_THIS_IDENTITY = (
    "this recovery key does not unlock your current vault identity: it may belong to an earlier "
    "identity, or it was replaced by Rotate recovery key or Reset identity"
)

# Shown wherever an operation needs this device's vault identity and there is none.
NO_LOCAL_IDENTITY = (
    "this device has no vault identity yet; run `servonaut vault setup` on your first device, "
    "`servonaut vault devices add` on another one, or `servonaut vault recover`"
)


# A bound server's address or port is not the one its vault key was bound to:
# the pinned host keys belong to the old address, so the key is not used.
SERVER_MOVED_SINCE_BINDING = (
    "this server's address changed after its vault key was bound; "
    "bind the key again (Use Vault Key) to pin the new address"
)


# A request signed by a device the server no longer accepts fails with
# ``device_not_active``; ``details.status`` says why.
_INACTIVE_DEVICE_REASONS = {
    "rejected": "the other device rejected this registration; run `servonaut vault devices add` to try again",
    "revoked": "this device was revoked; recover it or add it again",
    "expired": "the approval window expired; run `servonaut vault devices add` to try again",
}

# Where people reach Servonaut support.
_CONTACT_URL = "https://servonaut.dev/contact"

# Refusals the user can act on; keyed by the server's machine-readable code.
_ACTIONABLE_CODES = {
    "revision_conflict": "this item changed since it was read; reload and try again",
    "identity_unconfirmed": (
        "your vault identity is not confirmed yet; open the confirmation e-mail, "
        "or sign in with MFA (`servonaut login`) and run `servonaut vault identity confirm`"
    ),
    "identity_compromised": "this vault identity is marked compromised; reset it with `servonaut vault reset-identity`",
    "mfa_required": "this needs a recent MFA sign-in; run `servonaut login` and try again",
    "step_up_required": "this needs a recent MFA sign-in; run `servonaut login` and try again",
    "mfa_enrollment_required": "turn on two-factor authentication for your account first",
    "vault_exists": "that vault already exists: there is one personal vault per account and one vault per team",
    "ssh_ca_unavailable": (
        "the Servonaut service cannot issue SSH certificates right now; "
        "nothing is wrong with your setup, so try again later"
    ),
    # Switching certificates on (or back on) is paused for teams the service
    # has not cleared yet; the pause covers the whole service.
    "ssh_ca_enable_frozen": (
        "switching on SSH certificates is paused on the Servonaut service for now; "
        f"nothing is wrong with your setup, so contact support at {_CONTACT_URL} to ask for them for your team"
    ),
    # Another switch-on is in progress somewhere on the service, not necessarily
    # for this team.
    "ssh_ca_busy": (
        "the Servonaut service is busy switching on SSH certificates; "
        "nothing is wrong with your setup, so try again in a minute"
    ),
    "no_identity": (
        "this device does not hold your current vault identity; add it from an active device "
        "(`servonaut vault devices add`) or recover it (`servonaut vault recover`)"
    ),
    # The service takes no item writes while the vault key is due for rotation
    # (``details.current_version`` is the version to rotate from).
    "vault_rotation_required": (
        "the vault key must be rotated first, usually because a member left; a team owner or admin "
        "rotates it with Rotate vault key or `servonaut vault rotate --vault <vault>`, then try again"
    ),
}

# An SSH key rotation first rotates a vault key that is due; these say why it
# stopped there, before any server was touched.
VAULT_ROTATION_NOT_PERMITTED = (
    "the vault key must be rotated before this SSH key can be replaced, usually because a member left, "
    "and only a team owner or admin can do that; ask one to run `servonaut vault rotate --vault {vault_id}` "
    "or use Rotate vault key, then try again; no server was changed"
)
VAULT_ROTATION_FAILED = (
    "the vault key must be rotated before this SSH key can be replaced, and rotating it failed "
    "({reason}); no server was changed"
)

# A service can run with SSH certificates switched off; that is the service's
# choice rather than a failure, so it reads as information, not an error.
SSH_CA_SWITCHED_OFF = (
    "SSH certificates are switched off on this Servonaut service. "
    "Team members connect with vault keys."
)

# ``feature_disabled`` names the feature switched off on the service in ``details.feature``.
# Reasons are shown inside "... failed (reason)." so they carry no final stop.
_DISABLED_FEATURES = {
    "ssh_ca": SSH_CA_SWITCHED_OFF.rstrip("."),
}

# ``entitlement_required`` names the missing plan feature in ``details.feature``.
_PLAN_FEATURES = {
    "personal_vault": "a personal vault",
    "team_vault": "a team vault",
    "ssh_ca": "SSH certificates",
}


def is_feature_disabled(exc: BaseException, feature: str) -> bool:
    """Whether *exc*, or the API refusal a wrapper was raised from, says *feature* is switched off."""
    cause = exc.__cause__
    if not isinstance(exc, (VaultUserError, APIError)) and isinstance(cause, APIError):
        exc = cause
    if not isinstance(exc, APIError) or exc.code != "feature_disabled":
        return False
    details = exc.details if isinstance(exc.details, dict) else {}
    return details.get("feature") == feature


def vault_failure_reason(exc: BaseException) -> str:
    """Return the short reason shown after "... failed" for *exc*.

    A generic wrapper (for example the SSH resolver's) is looked through when
    it was raised from a user-safe error or an API refusal.
    """
    cause = exc.__cause__
    if not isinstance(exc, (VaultUserError, APIError)) and isinstance(cause, (VaultUserError, APIError)):
        return vault_failure_reason(cause)
    if isinstance(exc, VaultUserError):
        return str(exc)
    if isinstance(exc, APIError) and exc.code == "device_not_active":
        details = exc.details if isinstance(exc.details, dict) else {}
        reason = _INACTIVE_DEVICE_REASONS.get(str(details.get("status")))
        if reason:
            return reason
    if isinstance(exc, APIError) and exc.code in _ACTIONABLE_CODES:
        return _ACTIONABLE_CODES[exc.code]
    if isinstance(exc, APIError) and exc.code == "feature_disabled":
        details = exc.details if isinstance(exc.details, dict) else {}
        return _DISABLED_FEATURES.get(
            str(details.get("feature")), "this feature is switched off on this Servonaut service right now",
        )
    if isinstance(exc, APIError) and exc.code == "entitlement_required":
        details = exc.details if isinstance(exc.details, dict) else {}
        feature = _PLAN_FEATURES.get(str(details.get("feature")))
        return f"your plan does not include {feature}" if feature else "your plan does not include this feature"
    if isinstance(exc, APIError):
        code = exc.code if isinstance(exc.code, str) and _SAFE_CODE.fullmatch(exc.code) else None
        status = f"HTTP {exc.status}" if exc.status else "request error"
        reason = f"{status}, {code}" if code else status
        field = exc.details.get("field") if isinstance(exc.details, dict) else None
        if isinstance(field, str) and _SAFE_FIELD.fullmatch(field):
            reason += f", field {field}"
        return reason
    return type(exc).__name__
