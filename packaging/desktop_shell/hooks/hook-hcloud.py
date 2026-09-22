"""Retain Hetzner Cloud SDK models used through generic client calls."""

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules("hcloud")
