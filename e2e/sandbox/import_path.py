"""Keep Servonaut's package directories off the import path of the TUI host.

A Python process started with its working directory inside ``src/servonaut``
(or with an empty ``PYTHONPATH`` entry there) has that directory on its
import path, and Servonaut's own ``secrets.py`` or ``os.py`` then stand in
for the standard library's. The textual-pilot-mcp specs call
:func:`require_clean` before they import anything else.

Standard library only: nothing may be imported before the path is clean.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _is_package(directory: Path) -> bool:
    """A checkout's ``src/servonaut`` package: named so, and a package.

    A checkout that itself lives at ``.../src/servonaut`` is not one: its
    root holds no ``__init__.py``.
    """
    return (
        directory.name == "servonaut"
        and directory.parent.name == "src"
        and (directory / "__init__.py").is_file()
    )


def inside_package(path: str) -> bool:
    """True when *path* is a checkout's ``src/servonaut`` package, or below it."""
    resolved = Path(os.path.realpath(path))
    return any(_is_package(candidate) for candidate in (resolved, *resolved.parents))


def drop_package_dirs() -> list[str]:
    """Remove import path entries that lie inside a Servonaut package; return them.

    An empty entry means the working directory. ``<checkout>/src`` itself
    stays: that is where ``servonaut`` is imported from.
    """
    dropped = [entry for entry in sys.path if inside_package(entry or os.getcwd())]
    sys.path[:] = [entry for entry in sys.path if entry not in dropped]
    return dropped


def shadowed_modules() -> list[str]:
    """Imported modules outside the ``servonaut`` package whose file lies inside it."""
    found = []
    for name, module in list(sys.modules.items()):
        path = getattr(module, "__file__", None)
        if path and name.split(".")[0] != "servonaut" and inside_package(path):
            found.append(f"{name} ({path})")
    return sorted(found)


def require_clean() -> None:
    """Drop Servonaut's package directories from the import path; refuse if too late."""
    drop_package_dirs()
    shadowed = shadowed_modules()
    if shadowed:
        raise ImportError(
            "this process imported Servonaut files in place of other modules: "
            f"{', '.join(shadowed)}. Its working directory (or PYTHONPATH) put a directory "
            "inside src/servonaut on the import path. Start the textual-pilot-mcp server "
            "from the checkout root."
        )
