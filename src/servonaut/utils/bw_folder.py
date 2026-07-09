"""Resolve the Bitwarden vault folder name configured in Settings.

Single source of truth for every screen that needs the folder (vault manager,
item picker, key import, settings panel). The value lives on ``AppConfig``
(``bw_vault_folder``) and MUST be read through ``app.config_manager.get()`` —
``ServonautApp`` exposes no ``config`` attribute, so a ``self.app.config``
read silently yields ``None`` and the Settings value is ignored.
"""

from __future__ import annotations

from typing import Any

DEFAULT_BW_VAULT_FOLDER = "Servonaut"


def resolved_bw_vault_folder(app: Any) -> str:
    """Return the Settings-configured vault folder name, or the default.

    ``app`` is the running Textual app (or a test double). Tolerates a
    missing ``config_manager`` (headless/test contexts) by falling back to
    :data:`DEFAULT_BW_VAULT_FOLDER`.
    """
    config_manager = getattr(app, "config_manager", None)
    config = config_manager.get() if config_manager is not None else None
    return getattr(config, "bw_vault_folder", None) or DEFAULT_BW_VAULT_FOLDER
