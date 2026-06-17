"""Settings package: master/detail side-menu settings UI.

Back-compat re-export keeps ``from servonaut.screens.settings import
SettingsScreen`` working for existing call sites (``app.py``, ``main_menu.py``).
"""

from __future__ import annotations

from servonaut.screens.settings.shell import SettingsScreen

__all__ = ["SettingsScreen"]
