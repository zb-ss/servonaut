#!/usr/bin/env python3
"""Servonaut — Interactive TUI for managing AWS EC2 SSH connections."""
__version__ = '2.25.4'


def get_version() -> str:
    """Return the running version, resiliently.

    Prefers the installed package metadata; falls back to the source
    ``__version__`` when metadata isn't available — e.g. running from a
    checkout via ``PYTHONPATH=src`` with no install. Never raises, so a
    missing/locked dist can't crash startup (the UI, User-Agent, etc.).
    """
    try:
        from importlib.metadata import version, PackageNotFoundError
        try:
            return version("servonaut")
        except PackageNotFoundError:
            return __version__
    except Exception:  # noqa: BLE001 — version display must never crash
        return __version__
