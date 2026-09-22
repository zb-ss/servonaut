"""Retain OVH client modules selected by provider configuration."""

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules("ovh")
