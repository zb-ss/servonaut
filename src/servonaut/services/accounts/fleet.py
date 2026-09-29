"""One provider's instances across all of its accounts.

:class:`AccountFleet` has the same inventory surface as a single-account
provider service (``fetch_instances_cached``, ``get_cached_instances``,
``is_cache_fresh``, ``last_fetch_error``, ``last_fetch_partial``), so every
caller that used to read one service reads the whole provider instead.

Rows are copies tagged with their account; each account's own service still
writes its own cache, untagged, exactly as before.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence

from servonaut.config.accounts import AccountRef

logger = logging.getLogger(__name__)

# Row keys added to every provider row.
ACCOUNT_KEY = "account"
ACCOUNT_ID_KEY = "account_id"
# Present (True) only when the row's provider has more than one account:
# surfaces then show and accept the row as "<account>/<name>".
QUALIFIED_KEY = "account_qualified"


@dataclass
class AccountBinding:
    """One account of a provider and the service that serves it."""

    ref: AccountRef
    service: Any
    # Blocking lookup of a provider-side account id (AWS); None when n/a.
    account_id: Optional[Callable[[], str]] = None


def tag_rows(
    rows: Sequence[dict], ref: AccountRef, *, qualified: bool, account_id: str = ""
) -> List[dict]:
    """Copies of *rows* carrying their account."""
    tagged: List[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        copy = dict(row)
        copy[ACCOUNT_KEY] = ref.label
        if qualified:
            copy[QUALIFIED_KEY] = True
        else:
            copy.pop(QUALIFIED_KEY, None)
        if account_id:
            copy[ACCOUNT_ID_KEY] = account_id
        tagged.append(copy)
    return tagged


class AccountFleet:
    """All accounts of one provider behind a single-service-like surface."""

    def __init__(self, provider: str, bindings: Sequence[AccountBinding]):
        if not bindings:
            raise ValueError(f"AccountFleet for {provider} needs at least one account")
        self.provider = provider
        self.bindings: List[AccountBinding] = list(bindings)
        # Why the last refresh could not be trusted (per account, labelled
        # when the provider has several accounts), or None after a clean one.
        self.last_fetch_error: Optional[str] = None
        # True when some rows are fresh and others are cached fallbacks.
        self.last_fetch_partial: bool = False
        # Accounts whose servers were already listed by an earlier account
        # (the same account configured twice): {later label: earlier label}.
        self.duplicate_accounts: Dict[str, str] = {}
        self._account_ids: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def multi(self) -> bool:
        """True when this provider has more than one account."""
        return len(self.bindings) > 1

    @property
    def refs(self) -> List[AccountRef]:
        return [b.ref for b in self.bindings]

    def binding(self, account: Optional[str] = None) -> Optional[AccountBinding]:
        """The binding for *account* (label, case-insensitive); None = default."""
        if not account:
            return self.bindings[0]
        wanted = account.strip().lower()
        for binding in self.bindings:
            if binding.ref.key == wanted:
                return binding
        return None

    # ------------------------------------------------------------------
    # Inventory surface
    # ------------------------------------------------------------------

    def get_cached_instances(self) -> List[dict]:
        """Every account's cached rows, tagged, regardless of age (sync)."""
        rows: List[dict] = []
        for binding in self.bindings:
            try:
                cached = binding.service.get_cached_instances() or []
            except Exception as exc:  # a broken cache never hides the others
                logger.warning("Reading %s cache failed: %s", binding.ref.title, exc)
                cached = []
            rows.extend(self._tag(binding, cached))
        return self._dedupe(rows)

    def is_cache_fresh(self) -> bool:
        """True only when every account's cache is within its TTL."""
        for binding in self.bindings:
            check = getattr(binding.service, "is_cache_fresh", None)
            try:
                if check is None or not check():
                    return False
            except Exception:
                return False
        return True

    async def fetch_instances_cached(self, force_refresh: bool = False) -> List[dict]:
        """Refresh (or read the cache of) every account concurrently.

        One account failing never hides another: its own service falls back
        to its cache where it has one, and its error is reported under its
        label. Only when EVERY account raised does this raise too, with the
        first error, which is what a single-account provider always did.
        """
        results = await asyncio.gather(
            *(self._fetch_one(b, force_refresh) for b in self.bindings),
            return_exceptions=True,
        )
        rows: List[dict] = []
        errors: List[str] = []
        partial = False
        clean = 0
        raised: List[BaseException] = []
        for binding, result in zip(self.bindings, results):
            if isinstance(result, BaseException):
                if isinstance(result, asyncio.CancelledError):
                    raise result
                raised.append(result)
                errors.append(self._labelled(binding, str(result) or type(result).__name__))
                continue
            rows.extend(result)
            error = getattr(binding.service, "last_fetch_error", None)
            if isinstance(error, str) and error:
                errors.append(self._labelled(binding, error))
            else:
                clean += 1
            if getattr(binding.service, "last_fetch_partial", False) is True:
                partial = True

        self.last_fetch_error = "; ".join(errors) if errors else None
        if raised and len(raised) == len(self.bindings):
            self.last_fetch_partial = False
            raise raised[0]

        # Some accounts refreshed cleanly while others failed: the fleet
        # mixes fresh rows with cached (or missing) ones.
        self.last_fetch_partial = partial or (bool(errors) and clean > 0)
        return self._dedupe(rows)

    async def _fetch_one(self, binding: AccountBinding, force_refresh: bool) -> List[dict]:
        rows = await binding.service.fetch_instances_cached(force_refresh=force_refresh)
        if self.multi and binding.account_id is not None and binding.ref.key not in self._account_ids:
            self._account_ids[binding.ref.key] = await asyncio.to_thread(binding.account_id)
        return self._tag(binding, rows or [])

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _tag(self, binding: AccountBinding, rows: Sequence[dict]) -> List[dict]:
        return tag_rows(
            rows,
            binding.ref,
            qualified=self.multi,
            account_id=self._account_ids.get(binding.ref.key, ""),
        )

    def _labelled(self, binding: AccountBinding, message: str) -> str:
        return f"{binding.ref.label}: {message}" if self.multi else message

    def _dedupe(self, rows: List[dict]) -> List[dict]:
        """Drop rows whose id an earlier account already listed.

        Instance ids are unique per provider, so a repeat means the same
        underlying account is configured twice (for example two AWS profiles
        for one account). The first (primary-most) account keeps the row.
        """
        seen: Dict[str, str] = {}
        kept: List[dict] = []
        duplicates: Dict[str, str] = {}
        for row in rows:
            instance_id = str(row.get("id") or "")
            owner = row.get(ACCOUNT_KEY, "")
            if instance_id and instance_id in seen:
                if seen[instance_id] != owner:
                    duplicates.setdefault(owner, seen[instance_id])
                continue
            if instance_id:
                seen[instance_id] = owner
            kept.append(row)
        if duplicates and duplicates != self.duplicate_accounts:
            for later, earlier in duplicates.items():
                logger.warning(
                    "%s account %r lists the same servers as %r; it is probably "
                    "the same account configured twice",
                    self.provider, later, earlier,
                )
        self.duplicate_accounts = duplicates
        return kept
