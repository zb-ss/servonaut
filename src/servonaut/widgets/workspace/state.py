"""Workspace preferences that last for one application session."""

from dataclasses import dataclass


@dataclass
class WorkspaceState:
    """Requested layout, independent of temporary keyboard navigation."""

    navigation_visible: bool = True
