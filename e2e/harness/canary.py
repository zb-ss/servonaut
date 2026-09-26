"""Hermeticity checks: every path Servonaut binds at import time is sandboxed.

Several modules compute locations such as ``Path.home() / ".servonaut"`` when
they are imported. The bootstrap swaps ``HOME`` first, so all of them must
resolve inside the test root. These checks prove it, and prove that loading
Servonaut made no network attempt.
"""

from __future__ import annotations

import importlib
import os
import pkgutil
import sys
from pathlib import PurePath
from typing import Any, Iterator

from e2e.harness.bootstrap import E2EContext, is_within, load_guard

# Module-level constants that must live in the sandbox; checked on every
# worker before any journey runs.
CRITICAL_PATHS: tuple[tuple[str, str], ...] = (
    ("servonaut.config.manager", "CONFIG_DIR"),
    ("servonaut.config.manager", "CONFIG_PATH"),
    ("servonaut.config.manager", "BACKUP_DIR"),
    ("servonaut.config.secrets", "DEFAULT_SECRETS_PATH"),
    ("servonaut.services.cache_service", "CacheService.CACHE_PATH"),
    ("servonaut.services.auth_service", "AUTH_FILE"),
    ("servonaut.services.terminal_service", "_WRAPPER_DIR"),
)


def _resolve(module_name: str, dotted: str) -> Any:
    value: Any = importlib.import_module(module_name)
    for part in dotted.split("."):
        value = getattr(value, part)
    return value


def path_problem(ctx: E2EContext, path: PurePath) -> str | None:
    """Why *path* is not acceptable as an import-time location, or None."""
    if not os.path.isabs(str(path)):
        return None
    text = os.path.realpath(path)
    if load_guard().is_protected(text):
        return "points into the real home directory"
    if ".servonaut" in PurePath(text).parts and not is_within(text, ctx.root):
        return "is a Servonaut data path outside the test root"
    return None


def critical_path_problems(ctx: E2EContext) -> list[str]:
    """Check the known import-time data locations."""
    problems = []
    for module_name, dotted in CRITICAL_PATHS:
        try:
            value = _resolve(module_name, dotted)
        except (ImportError, AttributeError) as exc:
            problems.append(f"{module_name}.{dotted}: cannot resolve ({exc})")
            continue
        if not is_within(value, ctx.sandbox.home):
            problems.append(f"{module_name}.{dotted} is not inside the sandbox home")
    return problems


def import_all_modules() -> list[str]:
    """Import every servonaut module; return those needing absent extras."""
    import servonaut

    skipped = []
    for info in pkgutil.walk_packages(servonaut.__path__, "servonaut."):
        try:
            importlib.import_module(info.name)
        except ImportError as exc:
            skipped.append(f"{info.name} ({exc.name or exc})")
    return skipped


def _module_paths() -> Iterator[tuple[str, PurePath]]:
    for name, module in list(sys.modules.items()):
        if module is None or not (name == "servonaut" or name.startswith("servonaut.")):
            continue
        for attr, value in list(vars(module).items()):
            if isinstance(value, PurePath):
                yield f"{name}.{attr}", value
            elif isinstance(value, type) and getattr(value, "__module__", None) == name:
                for class_attr, class_value in list(vars(value).items()):
                    if isinstance(class_value, PurePath):
                        yield f"{name}.{attr}.{class_attr}", class_value


def import_time_path_problems(ctx: E2EContext) -> list[str]:
    """Check every module-level and class-level Path in loaded servonaut modules."""
    problems = []
    for label, path in _module_paths():
        reason = path_problem(ctx, path)
        if reason:
            problems.append(f"{label} {reason}")
    return problems
