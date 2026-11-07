"""Compact renderer for the cached server-memory snapshot.

Turns the ``{module: {observed: {...}, probed_at: ..., partial: ...}}`` dict
returned by ``MemoryService.get_all_modules`` into a few human-readable
styled lines for the server actions detail pane.  Pure and side-effect free so
it can be unit-tested without a live store.

Every observed value is built as ``Content`` and never parsed as markup
(probed strings can contain ``[`` sequences).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from textual.content import Content

from servonaut.utils.markup import literal

# Runtimes the panel lists, in order, with the name it shows for each.
_RUNTIME_NAMES = (
    ("python", "Python"),
    ("node", "Node"),
    ("php", "PHP"),
    ("go", "Go"),
    ("ruby", "Ruby"),
)


def human_age(probed_at_str: str) -> str:
    """Return a short age string ("5m", "2h", "3d") for an ISO timestamp."""
    if not probed_at_str:
        return "?"
    try:
        probed_at = datetime.fromisoformat(probed_at_str.rstrip("Z"))
        if not probed_at.tzinfo:
            probed_at = probed_at.replace(tzinfo=timezone.utc)
        secs = (datetime.now(tz=timezone.utc) - probed_at).total_seconds()
    except (ValueError, TypeError):
        return "?"
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{int(secs // 60)}m ago"
    if secs < 86400:
        return f"{int(secs // 3600)}h ago"
    return f"{int(secs // 86400)}d ago"


def _val(observed: Dict[str, Any], key: str) -> Optional[str]:
    """Return a stripped string for *key* in *observed*, or ``None`` if empty."""
    raw = observed.get(key)
    if raw is None or raw == "" or raw == []:
        return None
    return str(raw)


def format_runtime(runtime: str, version: str) -> str:
    """Show a runtime as its name and version once: ``Python 3.11.2``.

    The runtimes probe stores what each runtime's own version command
    printed, and most of those already start with the runtime's name
    (``Python 3.11.2``, ``PHP 8.2.7``, ``go1.22.1``, ``ruby 3.2.2``) or a
    ``v`` (``v20.11.1``). Both are dropped before the display name is put
    in front, so every runtime reads the same way.

    Args:
        runtime: The probe's key for the runtime (``python``, ``node``...).
        version: The stored version string.

    Returns:
        Plain text (not markup-escaped).
    """
    names = dict(_RUNTIME_NAMES)
    number = re.sub(rf"^\s*{re.escape(runtime)}\s*", "", version, flags=re.IGNORECASE)
    number = re.sub(r"^v(?=\d)", "", number.strip())
    return f"{names.get(runtime, runtime)} {number}".rstrip()


def _newest_probed_at(modules: Dict[str, Dict[str, Any]]) -> str:
    """Return the most recent ``probed_at`` across all modules."""
    stamps = [
        str(data.get("probed_at", ""))
        for data in modules.values()
        if data.get("probed_at")
    ]
    return max(stamps) if stamps else ""


def render_memory_panel(modules: Dict[str, Dict[str, Any]]) -> Content:
    """Render the cached-memory snapshot as styled content.

    Args:
        modules: Mapping returned by ``MemoryService.get_all_modules``.

    Returns:
        Content in which every probed value is shown literally. Empty
        modules give a build call-to-action.
    """
    if not modules:
        return Content.assemble(
            Content.styled("Server Memory", "bold"),
            "\n\n",
            Content.styled("No memory cached yet.", "dim"),
            "\n",
            Content.assemble(
                Content.styled("Press ", "dim"),
                Content.styled("M", "bold dim"),
                Content.styled(
                    " to build an AI-queryable fact cache (OS, disk, services, web stack…).",
                    "dim",
                ),
            ),
        )

    age = human_age(_newest_probed_at(modules))
    partial = any(data.get("partial") for data in modules.values())
    header = Content.assemble(
        Content.styled("Server Memory", "bold"),
        "  ",
        literal(f"· {age}", "dim"),
    )
    if partial:
        header = Content.assemble(header, "  ", Content.styled("⚠ partial", "$text-warning"))

    rows: List[Content] = []

    def row(label: str, *value: Union[str, Content]) -> None:
        rows.append(Content.assemble("  ", Content.styled(f"{label:<10}", "dim"), " ", *value))

    def add(label: str, value: Optional[str]) -> None:
        if value:
            row(label, literal(value))

    def obs(module: str) -> Dict[str, Any]:
        return modules.get(module, {}).get("observed", {}) or {}

    # OS
    os_o = obs("os")
    add("OS", _val(os_o, "pretty_name") or _val(os_o, "id"))
    add("Kernel", _val(os_o, "kernel"))

    # Disk
    disk_o = obs("disk")
    pct = _val(disk_o, "pct_used")
    mount = _val(disk_o, "mount") or "/"
    if pct:
        row("Disk", literal(pct), " used ", literal(f"({mount})", "dim"))

    # Web stack
    web_o = obs("web_stack")
    web_bits = [
        literal(f"{name} {_val(web_o, name)}")
        for name in ("nginx", "apache")
        if _val(web_o, name)
    ]
    if web_bits:
        row("Web", _joined(web_bits))

    # Databases
    db_o = obs("databases")
    db_bits = []
    for engine, key in (("postgres", "postgres_version"), ("mysql", "mysql_version"),
                        ("mariadb", "mariadb_version"), ("redis", "redis_version"),
                        ("mongodb", "mongodb_version")):
        v = _val(db_o, key)
        if v:
            db_bits.append(literal(f"{engine} {v}"))
    if db_bits:
        row("DB", _joined(db_bits))

    # Runtimes
    rt_o = obs("runtimes")
    rt_bits = [
        literal(format_runtime(name, _val(rt_o, name)))
        for name, _label in _RUNTIME_NAMES
        if _val(rt_o, name)
    ]
    if rt_bits:
        row("Runtime", _joined(rt_bits))

    # Containers
    ct_o = obs("containers")
    dv = _val(ct_o, "docker_version")
    if dv:
        running = _val(ct_o, "docker_running")
        suffix = literal(f" ({running} running)", "dim") if running else ""
        row("Docker", literal(dv), suffix)

    if not rows:
        rows.append(Content.styled(
            "  No structured facts parsed (modules may be partial).", "dim",
        ))

    return Content.assemble(header, "\n\n", Content("\n").join(rows))


def _joined(parts: List[Content]) -> Content:
    return Content(" · ").join(parts)
