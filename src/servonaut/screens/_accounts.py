"""Provider accounts as the account-level screens reach them.

The running app always has an account registry (``app.accounts``). Stand-in
apps (tests, previews, renderer probes) usually carry only the default
``*_service`` attributes; every helper here falls back to those, so a
stand-in keeps driving the default account exactly as the screens did before
extra accounts existed. An empty account label means the default account.
"""
from __future__ import annotations

from typing import Any, Optional, Tuple

from servonaut.config.accounts import AWS
from servonaut.services.accounts import AccountRegistry


def account_registry(app: Any) -> Optional[AccountRegistry]:
    """The app's account registry, or None on a stand-in app without one."""
    accounts = getattr(app, "accounts", None)
    return accounts if isinstance(accounts, AccountRegistry) else None


def is_multi(app: Any, provider: str) -> bool:
    """True when *provider* has more than one usable account."""
    accounts = account_registry(app)
    return accounts is not None and accounts.is_multi(provider)


def provider_inventory(app: Any, provider: str) -> Any:
    """Every account of *provider* as one inventory (None when unavailable)."""
    if account_registry(app) is None:
        return getattr(app, f"{provider}_service", None)
    return app.provider_inventory(provider)


def row_service(app: Any, provider: str, row: dict) -> Tuple[Any, str]:
    """The service of the account *row* belongs to, and that account's label.

    Raises:
        UnknownAccountError: The row's account was removed since it was listed.
    """
    accounts = account_registry(app)
    if accounts is None:
        return getattr(app, f"{provider}_service", None), str(row.get("account") or "")
    ref = accounts.account_for(row)
    return accounts.service(provider, ref.label), ref.label


def default_label(app: Any, provider: str) -> str:
    """Label of *provider*'s default account ("" without a registry)."""
    accounts = account_registry(app)
    refs = accounts.accounts(provider) if accounts is not None else []
    return refs[0].label if refs else ""


def aws_service(app: Any, account: str = "") -> Any:
    """One AWS account's EC2 service.

    Raises:
        UnknownAccountError: No usable AWS account has that label.
    """
    accounts = account_registry(app)
    if accounts is None:
        return getattr(app, "aws_service", None)
    return accounts.service(AWS, account or None)


def cloudtrail_service(app: Any, account: str = "") -> Any:
    """One AWS account's CloudTrail service (see :func:`aws_service`)."""
    accounts = account_registry(app)
    if accounts is None:
        return getattr(app, "cloudtrail_service", None)
    return accounts.aws_services(account or None).cloudtrail


def cloudwatch_service(app: Any, account: str = "") -> Any:
    """One AWS account's CloudWatch Logs service (see :func:`aws_service`)."""
    accounts = account_registry(app)
    if accounts is None:
        return getattr(app, "cloudwatch_service", None)
    return accounts.aws_services(account or None).cloudwatch


def aws_context(app: Any, account: str = "") -> Any:
    """One AWS account's credentials, or None for the default credential chain.

    Raises:
        UnknownAccountError: No usable AWS account has that label.
    """
    accounts = account_registry(app)
    if accounts is None:
        return None
    return accounts.aws_context(account or None)


def object_storage(app: Any, provider: str, account: str = "") -> Any:
    """One account's object storage service, or None when not configured.

    The primary account's storage is the app's own service, which the
    provider's settings panel rebuilds whenever its S3 keys change. It is
    also the only one when the provider has no usable compute account:
    object storage is a product of its own, so a Hetzner or OVH user may
    have S3 keys and no API token.

    Raises:
        UnknownAccountError: No usable account of *provider* has that label.
    """
    own = getattr(app, f"{provider}_object_storage_service", None)
    accounts = account_registry(app)
    if accounts is None or not accounts.accounts(provider):
        return own
    ref = accounts.account(provider, account or None)
    if ref.primary:
        return own
    return accounts.object_storage(provider, ref.label)
