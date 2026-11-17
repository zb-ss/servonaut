"""Workspace preferences that last for one application session."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class WorkspaceState:
    """Requested layout, independent of temporary keyboard navigation."""

    navigation_visible: bool = True
    # The width class ("wide" or "narrow", see ``WorkspaceScreen``) in which the
    # user last chose to show or hide the navigation. While the terminal stays
    # in that class the choice stands; crossing into the other one hands the
    # decision back to the automatic rule. None until the user chooses.
    navigation_choice_class: Optional[str] = None

    # The fleet list's quick filters (see ``screens/_fleet_filter``) and when
    # the fleet was last refreshed (epoch seconds), so leaving the list and
    # coming back keeps them.
    fleet_state_filter: str = "all"
    fleet_provider_filter: str = "all"
    fleet_updated_at: Optional[float] = None
