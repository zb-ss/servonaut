"""More people than the one account: further users, each with their own session.

The scenario's account (``Scenario.user_id`` with ``ScenarioStore.session``)
stays the only one unless a journey adds another with
``FakeCloud.add_user``. Each added user has a token pair of their own; a
request carrying it is answered for that user: entitlements, ``/api/v1/me``,
the teams they belong to, their Vault identity and devices. Requests with
the scenario account's token, or with none, behave exactly as before.

A device-flow sign-in completes as the scenario's account unless
``sign_in_next_as`` named a user first: the next device code issued then
belongs to that user, as if they had approved it in their browser.

:data:`REQUEST_ACCOUNT` holds the added user a request was made by, for the
length of that request (``None`` for the scenario's account).
"""

from __future__ import annotations

import contextvars
import threading
from dataclasses import dataclass
from typing import Optional

from e2e.harness.fake_cloud.session import TokenSession

# The added user the current request was made by; None for the scenario's account.
REQUEST_ACCOUNT: contextvars.ContextVar[Optional["Account"]] = contextvars.ContextVar(
    "fake_cloud_request_account", default=None
)


@dataclass
class Account:
    """One added user: who they are, their plan, and their token pair."""

    user_id: int
    email: str
    name: str
    plan: str
    session: TokenSession


class Accounts:
    """Thread-safe registry of the added users and their device-flow sign-ins."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._accounts: dict[int, Account] = {}
            self._next_sign_ins: list[int] = []
            self._device_codes: dict[str, int] = {}

    def add(self, user_id: int, *, email: str, name: str, plan: str) -> Account:
        """Register a user; a user id or e-mail address may be added once."""
        with self._lock:
            if user_id in self._accounts:
                raise ValueError(f"user {user_id} was already added")
            if any(a.email.lower() == email.lower() for a in self._accounts.values()):
                raise ValueError(f"a user with the e-mail address {email} was already added")
            account = Account(user_id, email, name, plan, TokenSession())
            self._accounts[user_id] = account
            return account

    def get(self, user_id: int) -> Optional[Account]:
        with self._lock:
            return self._accounts.get(user_id)

    def by_email(self, email: str) -> Optional[Account]:
        with self._lock:
            return next(
                (a for a in self._accounts.values() if a.email.lower() == email.lower()), None
            )

    def all(self) -> list[Account]:
        with self._lock:
            return list(self._accounts.values())

    def for_bearer(self, authorization: Optional[str]) -> Optional[Account]:
        """The added user whose current access token *authorization* carries."""
        if not authorization:
            return None
        return next((a for a in self.all() if a.session.bearer_valid(authorization)), None)

    def rotate(self, presented: object) -> Optional[tuple[Account, tuple[str, str]]]:
        """Refresh an added user's pair; None when no added user holds *presented*."""
        for account in self.all():
            pair = account.session.rotate(presented)
            if pair is not None:
                return account, pair
        return None

    def revoke_token(self, token: object) -> bool:
        """Sign-out: revoke the added user's session *token* belongs to."""
        return any(account.session.revoke_token(token) for account in self.all())

    # -- device-flow sign-ins ------------------------------------------------

    def sign_in_next_as(self, user_id: int) -> None:
        """The next device code issued belongs to *user_id* (their browser approves it)."""
        with self._lock:
            if user_id not in self._accounts:
                raise KeyError(f"user {user_id} was never added")
            self._next_sign_ins.append(user_id)

    def claim_device_code(self, device_code: str) -> None:
        """Give a newly issued device code to the user waiting for one, if any."""
        with self._lock:
            if self._next_sign_ins:
                self._device_codes[device_code] = self._next_sign_ins.pop(0)

    def for_device_code(self, device_code: object) -> Optional[Account]:
        """The added user a device code belongs to; None for the scenario's account."""
        with self._lock:
            user_id = self._device_codes.get(device_code) if isinstance(device_code, str) else None
            return self._accounts.get(user_id) if user_id is not None else None


def current_account() -> Optional[Account]:
    """The added user the request being answered was made by, if any."""
    return REQUEST_ACCOUNT.get()
