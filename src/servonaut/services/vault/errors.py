"""User-facing failure text for vault and SSH CA surfaces.

Vault failures normally reach the user as their exception class only, so
server text or local key material can never leak into a terminal or toast.
:class:`VaultUserError` is the one exception whose message is shown verbatim:
raise it only with fixed, client-authored text that tells the user what
happened or what to do.
"""
from __future__ import annotations

import re

from servonaut.services.api_client import APIError

_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_SAFE_FIELD = re.compile(r"[a-z][a-z0-9_.-]{0,127}")


class VaultUserError(RuntimeError):
    """A fixed, secret-free message that is safe to show the user as-is."""


# Shown wherever an operation needs this device's vault identity and there is none.
NO_LOCAL_IDENTITY = (
    "this device has no vault identity yet; run `servonaut vault setup` on your first device, "
    "`servonaut vault devices add` on another one, or `servonaut vault recover`"
)


# A request signed by a device the server no longer accepts fails with
# ``device_not_active``; ``details.status`` says why.
_INACTIVE_DEVICE_REASONS = {
    "rejected": "the other device rejected this registration; run `servonaut vault devices add` to try again",
    "revoked": "this device was revoked; recover it or add it again",
    "expired": "the approval window expired; run `servonaut vault devices add` to try again",
}

# Refusals the user can act on; keyed by the server's machine-readable code.
_ACTIONABLE_CODES = {
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
    "no_identity": (
        "this device does not hold your current vault identity; add it from an active device "
        "(`servonaut vault devices add`) or recover it (`servonaut vault recover`)"
    ),
}

# ``feature_disabled`` names the feature switched off on the service in ``details.feature``.
_DISABLED_FEATURES = {
    "ssh_ca": "SSH certificates are not available on this Servonaut service",
}

# ``entitlement_required`` names the missing plan feature in ``details.feature``.
_PLAN_FEATURES = {
    "personal_vault": "a personal vault",
    "team_vault": "a team vault",
    "ssh_ca": "SSH certificates",
}


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
