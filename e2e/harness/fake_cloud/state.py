"""Mutable scenario state shared by the FakeCloud routes."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, field, fields
from typing import Any, Optional

from e2e.harness.fake_cloud.session import ACCESS_TOKEN, REFRESH_TOKEN, TokenSession
from e2e.harness.fake_cloud.users import Accounts, current_account
from servonaut.services.version_policy import DEFAULT_UPDATE_URL, normalize_public_version

__all__ = ["ACCESS_TOKEN", "REFRESH_TOKEN", "USER_CODE", "Scenario", "ScenarioStore"]

USER_CODE = "E2E-0001"

# Device-flow poll outcomes a scenario can script for /api/oauth/token.
TOKEN_OUTCOMES = frozenset({"pending", "slow_down", "expired", "denied", "success"})
CLIENT_VERSION_MODES = frozenset({"off", "log", "enforce"})
# Scenario keys holding lists or dicts: stored as deep copies so caller objects stay independent.
_COPY_KEYS = frozenset({
    "token_outcomes",
    "pypi_files",
    "pypi_yanked_files",
    "quota",
    "balance",
    "client_upcoming",
    "client_latest",
    "client_update_hints",
})


@dataclass
class Scenario:
    """What FakeCloud answers. Tests change it through ``FakeCloud.configure``."""

    # Consumed one per /api/oauth/token call; once empty every poll succeeds.
    token_outcomes: list[str] = field(default_factory=list)
    device_interval: int = 1
    device_expires_in: int = 60
    plan: str = "solo"
    user_id: int = 4242
    # The account's e-mail address in tokens and entitlements ("" = none).
    email: str = ""
    # The sign-in page the device flow names; None = this fake's own /device.
    # Display only: the fake approves the sign-in itself.
    verification_uri: Optional[str] = None
    # The code the device flow shows the person. Display only, like the page.
    user_code: str = USER_CODE
    premium_ai: bool = True
    # Relay listeners the plan allows (0 keeps the relay off).
    mcp_connections: int = 1
    quota: Optional[dict[str, Any]] = field(
        default_factory=lambda: {
            "tokens_used": 1200,
            "tokens_limit": 500000,
            "tokens_topup_remaining": 0,
            "resets_at": "2030-01-01T00:00:00+00:00",
            "soft_capped": False,
            "hard_capped": False,
            "rpm_limit": 30,
            "tokens_per_minute_limit": 60000,
        }
    )
    # Optional additive hosted-money contract. Set to None for old-server
    # compatibility journeys.
    balance: Optional[dict[str, Any]] = None
    # Version the fake package index reports for servonaut.
    pypi_version: str = "0.0.0"
    # Wheel files the fake package index offers (absolute paths).
    pypi_files: list[str] = field(default_factory=list)
    pypi_yanked_files: list[str] = field(default_factory=list)
    pypi_download_delay: float = 0.0
    # When set, personal binding reads answer 429 with this Retry-After
    # (seconds), like the service's per-user request limiter.
    binding_reads_retry_after: Optional[int] = None
    # Client-version policy & HTTP 426 enforcement gate.
    client_version_mode: str = "off"
    client_minimum_version: Optional[str] = None
    client_upcoming: Optional[dict[str, str]] = None
    client_latest: Optional[dict[str, Optional[str]]] = None
    client_update_url: str = DEFAULT_UPDATE_URL
    client_update_hints: Optional[dict[str, str]] = None


class ScenarioStore:
    """Thread-safe holder for the active :class:`Scenario`."""

    def __init__(self, default_pypi_version: str) -> None:
        self._lock = threading.Lock()
        self._default_pypi_version = default_pypi_version
        self._scenario = self._fresh()
        self._device_codes = 0
        self.session = TokenSession()
        # Users beyond the scenario's account (see ``users.py``).
        self.accounts = Accounts()

    def _fresh(self) -> Scenario:
        return Scenario(pypi_version=self._default_pypi_version)

    def reset(self) -> None:
        with self._lock:
            self._scenario = self._fresh()
            self._device_codes = 0
        self.session.reset()
        self.accounts.reset()

    def bearer_valid(self, authorization: Optional[str]) -> bool:
        """True when *authorization* carries a current access token of any user."""
        return self.session.bearer_valid(authorization) or (
            self.accounts.for_bearer(authorization) is not None
        )

    def configure(self, **changes: Any) -> None:
        known = {f.name for f in fields(Scenario)}
        unknown = set(changes) - known
        if unknown:
            raise KeyError(f"unknown FakeCloud scenario keys: {sorted(unknown)}")
        outcomes = changes.get("token_outcomes")
        if outcomes is not None and not set(outcomes) <= TOKEN_OUTCOMES:
            raise ValueError(f"token outcomes must be among {sorted(TOKEN_OUTCOMES)}")
        files = changes.get("pypi_files")
        if files is not None and not all(str(f).endswith(".whl") for f in files):
            raise ValueError("the package index offers wheel files only")
        mode = changes.get("client_version_mode")
        if mode is not None and mode not in CLIENT_VERSION_MODES:
            raise ValueError(f"client_version_mode must be among {sorted(CLIENT_VERSION_MODES)}")
        min_ver = changes.get("client_minimum_version")
        if min_ver is not None:
            normalized = normalize_public_version(min_ver)
            if normalized is None:
                raise ValueError(f"invalid client_minimum_version: {min_ver!r}")
            changes = {**changes, "client_minimum_version": normalized}
        with self._lock:
            for key, value in changes.items():
                setattr(self._scenario, key, copy.deepcopy(value) if key in _COPY_KEYS else value)

    def snapshot(self) -> Scenario:
        """The scenario, as the user the current request was made by sees it.

        For a request with an added user's token, ``user_id`` and ``plan``
        are that user's; everything else is the scenario's.
        """
        with self._lock:
            current = self._scenario
            scenario = Scenario(**{
                f.name: (
                    copy.deepcopy(getattr(current, f.name))
                    if f.name in _COPY_KEYS
                    else getattr(current, f.name)
                )
                for f in fields(Scenario)
            })
        account = current_account()
        if account is not None:
            scenario.user_id, scenario.plan = account.user_id, account.plan
        return scenario

    def next_token_outcome(self) -> str:
        with self._lock:
            if self._scenario.token_outcomes:
                return self._scenario.token_outcomes.pop(0)
            return "success"

    def next_device_code(self) -> str:
        with self._lock:
            self._device_codes += 1
            code = f"dc-fake-{self._device_codes}"
        self.accounts.claim_device_code(code)
        return code
