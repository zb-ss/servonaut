"""Workspace preferences that last for one application session."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class WorkspaceState:
    """Requested layout, independent of temporary keyboard navigation."""

    navigation_visible: bool = True

    # The fleet list's quick filters (see ``screens/_fleet_filter``) and when
    # the fleet was last refreshed (epoch seconds), so leaving the list and
    # coming back keeps them.
    fleet_state_filter: str = "all"
    fleet_provider_filter: str = "all"
    fleet_updated_at: Optional[float] = None
