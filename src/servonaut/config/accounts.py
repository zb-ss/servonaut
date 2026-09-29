"""Provider accounts: the primary account plus any extra ones, per provider.

Each provider block in the config (``aws``, ``hetzner``, ``ovh``) is the
PRIMARY account, exactly as before multi-account support existed. Its
``accounts`` list adds EXTRA accounts. This module turns that shape into one
ordered list of accounts per provider, each with the effective settings the
provider service needs, and checks the list for problems.

Everything that needs "the accounts of provider X" goes through here, so the
additive config shape is interpreted in exactly one place.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from servonaut.config.schema import (
    ACCOUNT_LABEL_MAX_LENGTH,
    AWSAccount,
    AWSConfig,
    HetznerAccount,
    HetznerConfig,
    OVHAccount,
    OVHConfig,
)

if TYPE_CHECKING:
    from servonaut.config.schema import AppConfig

AWS = "aws"
HETZNER = "hetzner"
OVH = "ovh"
PROVIDERS: Tuple[str, ...] = (AWS, HETZNER, OVH)

# Display names used in messages ("Hetzner · staging: ...").
PROVIDER_TITLES: Dict[str, str] = {AWS: "AWS", HETZNER: "Hetzner", OVH: "OVH"}

LABEL_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,%d}$" % (ACCOUNT_LABEL_MAX_LENGTH - 1)
)


@dataclass(frozen=True)
class AccountRef:
    """Identifies one provider account.

    Attributes:
        provider: ``"aws"``, ``"hetzner"`` or ``"ovh"``.
        label: Display label, unique across all providers (case-insensitive).
        primary: True for the account described by the provider block itself.
    """

    provider: str
    label: str
    primary: bool

    @property
    def key(self) -> str:
        """Case-insensitive identity of the account (its lower-cased label)."""
        return self.label.lower()

    @property
    def title(self) -> str:
        """``"Hetzner · staging"`` style name for messages."""
        return f"{PROVIDER_TITLES.get(self.provider, self.provider)} · {self.label}"


@dataclass(frozen=True)
class AWSAccountSettings:
    """Effective settings for one AWS account."""

    ref: AccountRef
    profile: str
    regions: Tuple[str, ...]


def primary_label(provider: str, provider_config) -> str:
    """Label of the primary account: the configured one, else the provider slug.

    A configured label that is not a valid label (hand-edited config) is not
    used: it could not be typed in an ``account/name`` reference, so the
    account keeps the provider slug and the problem is reported instead.
    """
    label = (getattr(provider_config, "label", "") or "").strip()
    if not label or label_problem(label) is not None:
        return provider
    return label


def account_cache_path(base_path: str, key: str) -> str:
    """Cache file for an extra account, next to the primary account's cache.

    ``~/.servonaut/hetzner_cache.json`` becomes
    ``~/.servonaut/hetzner_cache.staging.json``. The primary account keeps the
    original path, so an existing cache survives the upgrade untouched.
    """
    root, ext = os.path.splitext(base_path)
    return f"{root}.{key}{ext or '.json'}"


# ---------------------------------------------------------------------------
# Per-provider account lists
# ---------------------------------------------------------------------------


def aws_accounts(config: AWSConfig) -> List[AWSAccountSettings]:
    """Every configured AWS account, primary first, in config order."""
    accounts = [
        AWSAccountSettings(
            ref=AccountRef(AWS, primary_label(AWS, config), True),
            profile=(config.profile or "").strip(),
            regions=tuple(config.regions or ()),
        )
    ]
    for extra in config.accounts:
        accounts.append(
            AWSAccountSettings(
                ref=AccountRef(AWS, (extra.label or "").strip(), False),
                profile=(extra.profile or "").strip(),
                regions=tuple(extra.regions or ()),
            )
        )
    return accounts


def hetzner_accounts(config: HetznerConfig) -> List[Tuple[AccountRef, HetznerConfig]]:
    """Every configured Hetzner project with the HetznerConfig it runs with.

    The primary project uses the block unchanged. An extra project gets a
    copy of the block with its own token, SSH defaults, object storage and
    cache file; provider-wide settings (image, type, location, TTL, audit
    log) are shared.
    """
    accounts: List[Tuple[AccountRef, HetznerConfig]] = [
        (AccountRef(HETZNER, primary_label(HETZNER, config), True), config)
    ]
    for extra in config.accounts:
        ref = AccountRef(HETZNER, (extra.label or "").strip(), False)
        accounts.append((ref, _hetzner_effective(config, extra, ref)))
    return accounts


def _hetzner_effective(
    base: HetznerConfig, extra: HetznerAccount, ref: AccountRef
) -> HetznerConfig:
    return replace(
        base,
        api_token=extra.api_token,
        # A Hetzner-side key name belongs to one project, so it is never
        # borrowed from the primary project.
        default_hetzner_ssh_key=extra.default_hetzner_ssh_key,
        default_local_ssh_key=extra.default_local_ssh_key or base.default_local_ssh_key,
        default_username=extra.default_username or base.default_username,
        cache_path=account_cache_path(base.cache_path, ref.key),
        object_storage=extra.object_storage,
        label=ref.label,
        accounts=[],
    )


def ovh_accounts(config: OVHConfig) -> List[Tuple[AccountRef, OVHConfig]]:
    """Every configured OVH account with the OVHConfig it runs with."""
    accounts: List[Tuple[AccountRef, OVHConfig]] = [
        (AccountRef(OVH, primary_label(OVH, config), True), config)
    ]
    for extra in config.accounts:
        ref = AccountRef(OVH, (extra.label or "").strip(), False)
        accounts.append((ref, _ovh_effective(config, extra, ref)))
    return accounts


def _ovh_effective(base: OVHConfig, extra: OVHAccount, ref: AccountRef) -> OVHConfig:
    return replace(
        base,
        endpoint=extra.endpoint or "ovh-eu",
        application_key=extra.application_key,
        application_secret=extra.application_secret,
        consumer_key=extra.consumer_key,
        client_id=extra.client_id,
        client_secret=extra.client_secret,
        cloud_project_ids=list(extra.cloud_project_ids),
        include_dedicated=extra.include_dedicated,
        include_vps=extra.include_vps,
        include_cloud=extra.include_cloud,
        default_ssh_key=extra.default_ssh_key or base.default_ssh_key,
        default_username=extra.default_username or base.default_username,
        object_storage=extra.object_storage,
        label=ref.label,
        accounts=[],
    )


def ovh_cache_path(base_path: str, ref: AccountRef) -> str:
    """OVH has no cache path setting; extra accounts get a sibling file."""
    return base_path if ref.primary else account_cache_path(base_path, ref.key)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def all_account_refs(config: "AppConfig") -> List[AccountRef]:
    """Every configured account of every provider, primaries first per provider."""
    refs: List[AccountRef] = [a.ref for a in aws_accounts(config.aws)]
    refs.extend(ref for ref, _ in hetzner_accounts(config.hetzner))
    refs.extend(ref for ref, _ in ovh_accounts(config.ovh))
    return refs


# Qualifier that addresses custom servers in "custom/<name>" references.
RESERVED_LABELS = frozenset({"custom"})


def label_problem(label: str) -> Optional[str]:
    """Why *label* cannot name an account, or None when it can."""
    if not label:
        return "an account label is required"
    if label.lower() in RESERVED_LABELS:
        return f"account label {label!r} is reserved"
    if not LABEL_RE.match(label):
        return (
            f"account label {label!r} must start with a letter or digit and use "
            f"only letters, digits, '.', '_' or '-' "
            f"(at most {ACCOUNT_LABEL_MAX_LENGTH} characters)"
        )
    return None


def _credentials_problem(provider: str, index: int, config: "AppConfig") -> Optional[str]:
    """Why extra account *index* of *provider* cannot connect, or None."""
    if provider == AWS:
        extra: AWSAccount = config.aws.accounts[index]
        if not (extra.profile or "").strip():
            return "needs a named AWS profile"
    elif provider == HETZNER:
        extra_h: HetznerAccount = config.hetzner.accounts[index]
        if not (extra_h.api_token or "").strip():
            return "needs its own API token"
    elif provider == OVH:
        extra_o: OVHAccount = config.ovh.accounts[index]
        classic = all(
            (v or "").strip()
            for v in (extra_o.application_key, extra_o.application_secret, extra_o.consumer_key)
        )
        oauth = all((v or "").strip() for v in (extra_o.client_id, extra_o.client_secret))
        if not (classic or oauth):
            return (
                "needs an application key, application secret and consumer key, "
                "or a client ID and client secret"
            )
    return None


def account_problems(config: "AppConfig") -> Dict[Tuple[str, int], str]:
    """Problems that stop an EXTRA account from being used.

    Keys are ``(provider, index into that provider's accounts list)``. A
    primary account is never reported here: it keeps working exactly as it
    did before extra accounts existed. Labels are unique across every
    provider, compared case-insensitively; the first holder of a label keeps
    it and later duplicates are reported.
    """
    problems: Dict[Tuple[str, int], str] = {}
    taken: Dict[str, AccountRef] = {}
    for ref in (
        AccountRef(AWS, primary_label(AWS, config.aws), True),
        AccountRef(HETZNER, primary_label(HETZNER, config.hetzner), True),
        AccountRef(OVH, primary_label(OVH, config.ovh), True),
    ):
        taken.setdefault(ref.key, ref)

    extras = (
        (AWS, config.aws.accounts),
        (HETZNER, config.hetzner.accounts),
        (OVH, config.ovh.accounts),
    )
    for provider, entries in extras:
        for index, entry in enumerate(entries):
            label = (entry.label or "").strip()
            problem = label_problem(label)
            if problem is None:
                holder = taken.get(label.lower())
                if holder is not None:
                    problem = (
                        f"account label {label!r} is already used by "
                        f"{holder.title}"
                    )
            if problem is None:
                problem = _credentials_problem(provider, index, config)
            if problem is not None:
                problems[(provider, index)] = problem
                continue
            taken[label.lower()] = AccountRef(provider, label, False)
    return problems


def primary_label_problems(config: "AppConfig") -> List[str]:
    """Problems with the primary accounts' own labels (charset, collisions)."""
    problems: List[str] = []
    seen: Dict[str, str] = {}
    for provider, block in ((AWS, config.aws), (HETZNER, config.hetzner), (OVH, config.ovh)):
        configured = (getattr(block, "label", "") or "").strip()
        problem = label_problem(configured) if configured else None
        if problem is not None:
            problems.append(
                f"{PROVIDER_TITLES[provider]} primary account: {problem}; "
                f"using {provider!r} instead"
            )
        label = primary_label(provider, block)
        if label.lower() in seen:
            problems.append(
                f"{PROVIDER_TITLES[provider]} primary account label {label!r} is "
                f"already used by the {seen[label.lower()]} primary account"
            )
        seen.setdefault(label.lower(), PROVIDER_TITLES[provider])
    return problems


def describe_account_problems(config: "AppConfig") -> List[str]:
    """Every account problem as a readable sentence, for logs and settings."""
    messages = primary_label_problems(config)
    entries = {AWS: config.aws.accounts, HETZNER: config.hetzner.accounts, OVH: config.ovh.accounts}
    for (provider, index), problem in account_problems(config).items():
        label = (entries[provider][index].label or "").strip() or f"#{index + 1}"
        messages.append(
            f"{PROVIDER_TITLES[provider]} account {label!r} is skipped: {problem}"
        )
    return messages


def usable_extra_indexes(config: "AppConfig", provider: str) -> List[int]:
    """Indexes of *provider*'s extra accounts that have no problem."""
    problems = account_problems(config)
    entries = {AWS: config.aws.accounts, HETZNER: config.hetzner.accounts, OVH: config.ovh.accounts}
    return [i for i in range(len(entries[provider])) if (provider, i) not in problems]
