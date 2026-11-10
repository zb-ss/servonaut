"""What a provider's inventory reports while it is being listed."""

from __future__ import annotations

from typing import NamedTuple


class LoadProgress(NamedTuple):
    """Where a provider's listing is: the account being read and its region.

    ``account`` counts from 1 and never exceeds ``accounts``; ``region`` is
    empty when the provider has no region to name.
    """

    account: int
    accounts: int
    region: str
