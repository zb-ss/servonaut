"""Widgets package for Servonaut v2.0 TUI."""

from __future__ import annotations

from servonaut.widgets.instance_table import InstanceTable
from servonaut.widgets.status_bar import StatusBar
from servonaut.widgets.progress_indicator import ProgressIndicator
from servonaut.widgets.remote_tree import RemoteTree
from servonaut.widgets.command_output import CommandOutput

__all__ = [
    'InstanceTable',
    'StatusBar',
    'ProgressIndicator',
    'RemoteTree',
    'CommandOutput',
]
