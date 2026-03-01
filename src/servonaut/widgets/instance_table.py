"""Instance table widget for Servonaut v2.0."""

from __future__ import annotations
from typing import List, Optional

from textual.widgets import DataTable


class InstanceTable(DataTable):
    """DataTable subclass for displaying EC2 instances."""

    def __init__(self) -> None:
        """Initialize instance table."""
        super().__init__(cursor_type="row")
        self._all_instances: List[dict] = []
        self._filtered_instances: List[dict] = []
        self._setup_columns()

    def _setup_columns(self) -> None:
        """Set up table columns with auto-sizing for available width."""
        self.add_column("#", width=4, key="index")
        self.add_column("Name", key="name")
        self.add_column("ID", width=20, key="id")
        self.add_column("Type", width=12, key="type")
        self.add_column("State", width=10, key="state")
        self.add_column("Public IP", width=16, key="public_ip")
        self.add_column("Private IP", width=16, key="private_ip")
        self.add_column("Region", width=14, key="region")
        self.add_column("Key", key="key")

    def populate(self, instances: List[dict]) -> None:
        """Populate table with instances.

        Args:
            instances: List of instance dictionaries.
        """
        self._all_instances = instances
        self._filtered_instances = instances.copy()
        self._refresh_table()

    def filter(self, query: str) -> None:
        """Filter table rows by query string.

        Filters by instance name or type (case-insensitive substring match).

        Args:
            query: Search query string.
        """
        if not query:
            self._filtered_instances = self._all_instances.copy()
        else:
            query_lower = query.lower()
            self._filtered_instances = [
                inst for inst in self._all_instances
                if query_lower in inst.get('name', '').lower()
                or query_lower in inst.get('type', '').lower()
                or query_lower in inst.get('id', '').lower()
            ]
        self._refresh_table()

    def get_selected_instance(self) -> Optional[dict]:
        """Get the currently selected instance.

        Returns:
            Instance dictionary for selected row, or None if no selection.
        """
        if not self._filtered_instances:
            return None

        cursor_row = self.cursor_row
        if cursor_row < 0 or cursor_row >= len(self._filtered_instances):
            return None

        return self._filtered_instances[cursor_row]

    def _refresh_table(self) -> None:
        """Refresh table display with current filtered instances."""
        self.clear()

        for idx, instance in enumerate(self._filtered_instances):
            self.add_row(
                str(idx + 1),
                instance.get('name', ''),
                instance.get('id', ''),
                instance.get('type', ''),
                self._colorize_state(instance.get('state', '')),
                instance.get('public_ip', '') or '-',
                instance.get('private_ip', '') or '-',
                instance.get('region', ''),
                instance.get('key_name', '') or '-',
            )

    def _colorize_state(self, state: str) -> str:
        """Add color markup to instance state.

        Args:
            state: Instance state string.

        Returns:
            Colorized state string with markup.
        """
        state_colors = {
            'running': '[green]running[/green]',
            'stopped': '[red]stopped[/red]',
            'stopping': '[yellow]stopping[/yellow]',
            'pending': '[cyan]pending[/cyan]',
            'terminated': '[dim]terminated[/dim]',
        }
        return state_colors.get(state, state)
