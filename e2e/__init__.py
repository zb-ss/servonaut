"""End-to-end journeys for Servonaut.

This directory is a separate pytest suite. Run it in its own process::

    python -m pytest e2e

It must not share a process with ``tests/``: several Servonaut modules bind
paths under the home directory at import time, so the hermetic environment
in ``e2e/conftest.py`` has to be in place before the first ``servonaut``
import.
"""
