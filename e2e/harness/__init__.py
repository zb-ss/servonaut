"""Harness for the end-to-end suite: hermetic environment, fakes and drivers.

Modules here must not import ``servonaut`` at module level unless they are
only imported after ``e2e/conftest.py`` has applied the hermetic environment.
"""
