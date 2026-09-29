"""AWS services and object storage per provider account, for the screens.

Complements :mod:`servonaut.screens._provider_accounts` (registry lookup,
each account's provider service, demo-mode account labels) with what the
AWS account-level screens and the object storage screen need: one AWS
account's CloudTrail, CloudWatch and credentials, and each account's S3
storage.

Apps without an account registry (tests, previews) keep the app's
single-account attributes, so those screens behave exactly as they did
before extra accounts existed. An empty account label means the default
account.
"""
from __future__ import annotations

from typing import Any, List, Optional

from servonaut.config.accounts import (
    AWS,
    HETZNER,
    AccountRef,
    hetzner_accounts,
    ovh_accounts,
    usable_extra_indexes,
)
from servonaut.screens._provider_accounts import account_ref, registry_for
from servonaut.services.accounts import AccountRegistry, AWSAccountServices


def aws_services(app: Any, account: str = "") -> Optional[AWSAccountServices]:
    """One AWS account's services, or None on an app without a registry.

    Raises:
        UnknownAccountError: No usable AWS account has that label.
    """
    registry = registry_for(app, AWS)
    if registry is None:
        return None
    return registry.aws_services(account_ref(app, AWS, account).label)


def cloudtrail_service(app: Any, account: str = "") -> Any:
    """One AWS account's CloudTrail service (see :func:`aws_services`)."""
    services = aws_services(app, account)
    if services is None:
        return getattr(app, "cloudtrail_service", None)
    return services.cloudtrail


def cloudwatch_service(app: Any, account: str = "") -> Any:
    """One AWS account's CloudWatch Logs service (see :func:`aws_services`)."""
    services = aws_services(app, account)
    if services is None:
        return getattr(app, "cloudwatch_service", None)
    return services.cloudwatch


def aws_context(app: Any, account: str = "") -> Any:
    """One AWS account's credentials; None (the default credential chain)
    on an app without a registry (see :func:`aws_services`)."""
    services = aws_services(app, account)
    return services.context if services is not None else None


def _registry(app: Any) -> Optional[AccountRegistry]:
    registry = getattr(app, "accounts", None)
    return registry if isinstance(registry, AccountRegistry) else None


def object_storage_accounts(app: Any, provider: str) -> List[AccountRef]:
    """Accounts of *provider* that can have object storage, primary first.

    Object storage is a product of its own: a Hetzner project or OVH
    account needs S3 keys, not working API credentials, so every usable
    configured account is offered. Empty on an app without a registry.
    """
    registry = _registry(app)
    if registry is None:
        return []
    if provider == AWS:
        return registry.accounts(AWS)
    config = registry.config
    configured = (
        hetzner_accounts(config.hetzner) if provider == HETZNER else ovh_accounts(config.ovh)
    )
    usable = set(usable_extra_indexes(config, provider))
    return [
        ref for index, (ref, _settings) in enumerate(configured)
        if ref.primary or index - 1 in usable
    ]


def object_storage(app: Any, provider: str, account: str = "") -> Any:
    """One account's object storage service, or None when not configured.

    Raises:
        UnknownAccountError: No account of *provider* has that label.
    """
    registry = _registry(app)
    if registry is None:
        return getattr(app, f"{provider}_object_storage_service", None)
    return registry.object_storage(provider, account or None)
