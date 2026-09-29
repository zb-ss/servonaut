"""Provider accounts as the Hetzner and OVH screens use them.

Account-level screens (SSH keys, billing, DNS, IPs, storage, the create
wizards) work on one account chosen with an ``AccountPicker``; anything
done to one server acts in the account that server belongs to; the
managers list every account's servers.

Hosts that never build the account registry (tests, previews), and a
provider the registry has no account for, keep using the app's
single-account service attributes, exactly as these screens did before
extra accounts existed.

Demo mode redacts the rows a screen draws, account label included, so
every account lookup starts from the real record behind a drawn row.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from textual.css.query import NoMatches
from textual.widgets import Select

from servonaut.config.accounts import PROVIDER_TITLES, AccountRef
from servonaut.screens._demo_resolve import connection_instance
from servonaut.services.accounts.registry import (
    AccountRegistry,
    OVHAccountServices,
    UnknownAccountError,
    row_provider,
)

__all__ = [
    "ServerAccountMixin",
    "UnknownAccountError",
    "account_ref",
    "account_service",
    "account_settings",
    "fetched_row",
    "inventory",
    "ovh_services",
    "provider_accounts",
    "registry_for",
    "row_account_label",
    "row_ovh_services",
    "row_service",
    "show_account_labels",
    "shown_label",
]

# The app attribute holding each provider's default-account service.
_ALIASES: Dict[str, str] = {
    "aws": "aws_service",
    "hetzner": "hetzner_service",
    "ovh": "ovh_service",
}

# OVHAccountServices field -> the app attribute holding the default one.
_OVH_ALIASES: Dict[str, str] = {
    "billing": "ovh_billing_service",
    "vps": "ovh_vps_service",
    "dedicated": "ovh_dedicated_service",
    "cloud": "ovh_cloud_service",
    "ip": "ovh_ip_service",
    "snapshot": "ovh_snapshot_service",
    "storage": "ovh_storage_service",
    "dns": "ovh_dns_service",
}


def registry_for(app: Any, provider: str) -> Optional[AccountRegistry]:
    """The app's account registry when it serves *provider*, else None."""
    registry = getattr(app, "accounts", None)
    if not isinstance(registry, AccountRegistry) or not registry.accounts(provider):
        return None
    return registry


def provider_accounts(app: Any, provider: str) -> List[AccountRef]:
    """Usable accounts of *provider*, primary first (empty without a registry)."""
    registry = registry_for(app, provider)
    return registry.accounts(provider) if registry is not None else []


def inventory(app: Any, provider: str) -> Any:
    """Every account of *provider* as one inventory, or None when unused.

    The inventory refreshes all accounts at once and tags each row with
    its account, so a caller that replaces the provider's slice of the
    fleet always hands over every account's servers.
    """
    if registry_for(app, provider) is not None:
        found = app.provider_inventory(provider)
        if found is not None:
            return found
    return getattr(app, _ALIASES[provider], None)


def _unavailable(registry: AccountRegistry, provider: str, label: Optional[str],
                 error: UnknownAccountError) -> UnknownAccountError:
    """*error*, or a clearer one when *label* is configured but cannot connect."""
    reason = registry.unavailable.get(f"{provider}:{(label or '').strip().lower()}")
    if not reason:
        return error
    title = PROVIDER_TITLES.get(provider, provider)
    return UnknownAccountError(f"{title} account {label!r} is not available: {reason}")


def account_ref(app: Any, provider: str, account: Optional[str] = None) -> Optional[AccountRef]:
    """The account named *account* ("" or None = default); None without a registry.

    Raises:
        UnknownAccountError: No usable account of *provider* has that label.
    """
    registry = registry_for(app, provider)
    if registry is None:
        return None
    try:
        return registry.account(provider, account or None)
    except UnknownAccountError as exc:
        raise _unavailable(registry, provider, account, exc) from None


def account_service(app: Any, provider: str, account: Optional[str] = None) -> Any:
    """One account's provider service ("" or None = default account).

    Raises:
        UnknownAccountError: No usable account of *provider* has that label.
    """
    registry = registry_for(app, provider)
    if registry is None:
        return getattr(app, _ALIASES[provider], None)
    ref = account_ref(app, provider, account)
    return registry.service(provider, ref.label)


def row_account_label(app: Any, row: Dict[str, Any]) -> str:
    """Label of the account a server row belongs to ("" without a registry).

    Raises:
        UnknownAccountError: The row's account is gone or cannot connect.
    """
    provider = row_provider(row)
    ref = account_ref(app, provider, row.get("account") or None)
    return ref.label if ref is not None else ""


def row_service(app: Any, row: Dict[str, Any]) -> Any:
    """The provider service of the account a server row belongs to.

    Raises:
        UnknownAccountError: The row's account is gone or cannot connect.
    """
    provider = row_provider(row)
    return account_service(app, provider, row.get("account") or None)


def _alias_ovh_services(app: Any) -> OVHAccountServices:
    return OVHAccountServices(
        ovh=getattr(app, "ovh_service", None),
        **{field: getattr(app, attr, None) for field, attr in _OVH_ALIASES.items()},
    )


def ovh_services(app: Any, account: Optional[str] = None) -> OVHAccountServices:
    """One OVH account's services ("" or None = default account).

    Raises:
        UnknownAccountError: No usable OVH account has that label.
    """
    registry = registry_for(app, "ovh")
    if registry is None:
        return _alias_ovh_services(app)
    ref = account_ref(app, "ovh", account)
    return registry.ovh_services(ref.label)


def row_ovh_services(app: Any, row: Dict[str, Any]) -> OVHAccountServices:
    """The services of the OVH account a server row belongs to.

    Raises:
        UnknownAccountError: The row's account is gone or cannot connect.
    """
    return ovh_services(app, row.get("account") or None)


def account_settings(app: Any, provider: str, account: Optional[str] = None) -> Any:
    """The settings one account runs with.

    The primary account reads the live provider block, as these screens
    always did; an extra account reads its effective settings (its own
    credentials, projects and SSH key on top of the provider defaults).

    Raises:
        UnknownAccountError: No usable account of *provider* has that label.
    """
    live = getattr(app.config_manager.get(), provider)
    ref = account_ref(app, provider, account)
    if ref is None or ref.primary:
        return live
    return getattr(account_service(app, provider, ref.label), "_config", live)


class ServerAccountMixin:
    """Per-server screens: act in the account the server belongs to.

    The host screen keeps the server's row, as drawn, in ``_instance``;
    the account is read from the real record behind it.
    """

    _instance: Dict[str, Any]

    def _ovh_service(self, kind: str) -> Any:
        """The server's OVH account's *kind* service (``vps``, ``ip``, ...).

        None when OVH is unavailable; an account that no longer exists is
        also reported to the user.
        """
        row = connection_instance(self.app, self._instance)  # type: ignore[attr-defined]
        try:
            services = row_ovh_services(self.app, row)  # type: ignore[attr-defined]
        except UnknownAccountError as exc:
            self.notify(str(exc), severity="error", markup=False)  # type: ignore[attr-defined]
            return None
        return getattr(services, kind, None)


def fetched_row(shown_rows: List[dict], fetched_rows: List[dict], row: dict) -> dict:
    """The fetched (real) row behind *row*, one of the rows a table draws.

    Provider managers draw demo-mode copies of what they fetched, in the
    same order; the account tag of a copy is a stand-in in demo mode.
    """
    for shown, fetched in zip(shown_rows, fetched_rows):
        if shown is row:
            return fetched
    return row


def shown_label(app: Any, label: str) -> str:
    """An account label as a screen may show it (a stand-in in demo mode)."""
    redaction = getattr(app, "redaction_service", None)
    redact = getattr(redaction, "redact_account_label", None)
    if not label or not getattr(app, "demo_mode", False) or not callable(redact):
        return label
    return redact(label)


def show_account_labels(picker: Any) -> None:
    """Draw *picker*'s accounts as demo mode shows them.

    Only the text changes: each option's value stays the real label, so
    the chosen account and every lookup made with it are unaffected.
    """
    accounts = picker.accounts
    if len(accounts) <= 1:
        return  # hidden: nothing to draw
    try:
        select = picker.query_one(Select)
    except NoMatches:
        return
    app = picker.app
    with select.prevent(Select.Changed):
        select.set_options([(shown_label(app, ref.label), ref.label) for ref in accounts])
        select.value = picker.account
