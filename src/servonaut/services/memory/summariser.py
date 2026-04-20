"""Deterministic, token-efficient server memory summary generator.

Produces Markdown suitable for injection into an AI system prompt inside a
``<server_memory>`` tag.  Target: ≤1500 tokens (~6000 chars); char count is
used as the proxy — no real tokeniser required.

Design rules:
- Deterministic: same input always produces byte-identical output.
- No raw_output: raw probe output is never included (that's what MCP "full"
  format returns).
- No LLM: purely data-in → string-out transformation.
- Observed-vs-declared: when a declared value differs from observed, both are
  shown with attribution.
- Stable ordering: sections always appear in the same order; lists are sorted
  alphabetically within each section.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .store import MemoryStore
    from servonaut.config.schema import MemoryConfig

from .interfaces import ModuleResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Approximate char-to-token ratio used throughout.
CHARS_PER_TOKEN = 4

# Maximum runtimes table rows (all non-null runtimes; effectively unlimited
# but keeps the section bounded).
_MAX_RUNTIMES = 20

# Maximum enabled service units shown in the ## Services section.
_MAX_SERVICES = 25

# Maximum site names shown in ## Web stack.
_MAX_SITES = 10

# Maximum annotations chars to include verbatim.
_MAX_ANNOTATIONS_CHARS = 1000

# Section ordering for bottom-up truncation (least-important first so Data
# quality survives).  Lower index → dropped first.
_SECTION_ORDER = [
    "identity",
    "runtimes",
    "services",
    "web_stack",
    "logs",
    "databases",
    "containers",
    "network",
    "git",
    "disk",
    "annotations",
    "data_quality",  # highest priority — never dropped first
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _render_value(
    key: str,
    observed: Any,
    declared_entry: Optional[Dict[str, Any]],
) -> str:
    """Return a rendered string for one field, handling observed-vs-declared.

    Args:
        key: Field name.
        observed: The observed value.
        declared_entry: The declared dict for this key (with ``value``,
            ``pinned_by``, ``at`` subkeys), or ``None``.

    Returns:
        A string like ``"v20.11.0"`` when they match, or
        ``"observed=v20.11.0 declared=v22.0.0 (pinned by zoltan at 2026-04-10T09:00Z)"``
        when they differ.
    """
    if declared_entry is None:
        return str(observed) if observed is not None else ""

    declared_value = declared_entry.get("value")
    # Compare as strings to avoid type mismatch false-positives.
    if str(declared_value) == str(observed):
        return str(observed) if observed is not None else ""

    pinned_by = declared_entry.get("pinned_by", "?")
    at = declared_entry.get("at", "?")
    return (
        f"observed={observed} declared={declared_value}"
        f" (pinned by {pinned_by} at {at})"
    )


def _is_stale(probed_at: str, ttl_seconds: int, now: datetime) -> bool:
    """Return True if a module result is past its TTL."""
    if not probed_at:
        return True
    try:
        ts = datetime.fromisoformat(probed_at.rstrip("Z"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        age = (now - ts).total_seconds()
        return age > ttl_seconds
    except (ValueError, TypeError):
        return True


# ---------------------------------------------------------------------------
# Summariser
# ---------------------------------------------------------------------------

class Summariser:
    """Deterministic Markdown summary builder.

    Args:
        annotations_dir: Optional path to the instance memory directory, used
            to read ``annotations.md`` verbatim.

    Usage::

        s = Summariser(annotations_dir=Path("~/.servonaut/memory/aws/i-abc"))
        markdown = s.summarise(instance_meta, modules)
    """

    def __init__(self, annotations_dir: Optional[Path] = None) -> None:
        self._annotations_dir = annotations_dir

    def summarise(
        self,
        instance_meta: Dict[str, Any],
        modules: Dict[str, Any],
        now: Optional[datetime] = None,
    ) -> str:
        """Build and return a Markdown summary string.

        Args:
            instance_meta: Instance dict with ``name``, ``id``, ``provider``
                keys (mirrors ``app.instances`` entries).
            modules: Mapping of module name → raw module dict (as stored on
                disk) or ``ModuleResult`` instance.  Both forms are accepted.
            now: Reference time for staleness checks (injected for tests;
                defaults to ``datetime.now(timezone.utc)``).

        Returns:
            Markdown string, target ≤6000 chars.
        """
        if now is None:
            now = datetime.now(tz=timezone.utc)

        # Normalise modules to plain dicts.
        raw: Dict[str, Dict[str, Any]] = {}
        for name, mod in modules.items():
            if isinstance(mod, ModuleResult):
                raw[name] = {
                    "module": mod.module,
                    "observed": mod.observed,
                    "declared": mod.declared,
                    "sudo_used": mod.sudo_used,
                    "truncated": mod.truncated,
                    "partial": mod.partial,
                    "probed_at": mod.probed_at,
                    "ttl_seconds": mod.ttl_seconds,
                }
            else:
                raw[name] = mod

        instance_name = instance_meta.get("name", "unknown")
        instance_id = instance_meta.get("id") or instance_meta.get("name", "unknown")
        provider = instance_meta.get("provider", "custom")

        # Collect sections as (key, text) pairs in _SECTION_ORDER priority.
        sections: Dict[str, str] = {}

        # -- Header ----------------------------------------------------------
        header = f"# Memory — {instance_name} ({instance_id}) @ {provider}"

        # -- Identity --------------------------------------------------------
        if "os" in raw:
            sections["identity"] = self._render_identity(raw["os"])

        # -- Runtimes --------------------------------------------------------
        if "runtimes" in raw:
            section = self._render_runtimes(raw["runtimes"])
            if section:
                sections["runtimes"] = section

        # -- Services --------------------------------------------------------
        if "services" in raw:
            section = self._render_services(raw["services"])
            if section:
                sections["services"] = section

        # -- Web stack -------------------------------------------------------
        if "web_stack" in raw:
            section = self._render_web_stack(raw["web_stack"])
            if section:
                sections["web_stack"] = section

        # -- Logs ------------------------------------------------------------
        if "logs" in raw:
            section = self._render_logs(raw["logs"])
            if section:
                sections["logs"] = section

        # -- Databases -------------------------------------------------------
        if "databases" in raw:
            section = self._render_databases(raw["databases"])
            if section:
                sections["databases"] = section

        # -- Containers ------------------------------------------------------
        if "containers" in raw:
            section = self._render_containers(raw["containers"])
            if section:
                sections["containers"] = section

        # -- Network ---------------------------------------------------------
        if "network" in raw:
            section = self._render_network(raw["network"])
            if section:
                sections["network"] = section

        # -- Git -------------------------------------------------------------
        if "git" in raw:
            section = self._render_git(raw["git"])
            if section:
                sections["git"] = section

        # -- Disk ------------------------------------------------------------
        if "disk" in raw:
            section = self._render_disk(raw["disk"])
            if section:
                sections["disk"] = section

        # -- Annotations -----------------------------------------------------
        ann_text = self._load_annotations()
        if ann_text:
            sections["annotations"] = f"## Annotations\n{ann_text}"

        # -- Data quality ----------------------------------------------------
        dq = self._render_data_quality(raw, now)
        if dq:
            sections["data_quality"] = dq

        # Assemble in canonical order, skipping absent sections.
        parts = [header]
        for key in _SECTION_ORDER:
            if key in sections:
                parts.append(sections[key])

        return "\n\n".join(parts)

    # ------------------------------------------------------------------
    # Section renderers
    # ------------------------------------------------------------------

    def _render_identity(self, mod: Dict[str, Any]) -> str:
        observed = mod.get("observed", {})
        declared = mod.get("declared", {})
        if not observed:
            return ""

        lines = ["## Identity"]
        # Probe emits ``version_id`` (from /etc/os-release VERSION_ID).
        # The field label shown to the user is still "version" for brevity.
        for field, label in (
            ("pretty_name", "pretty_name"),
            ("version_id", "version"),
            ("kernel", "kernel"),
            ("arch", "arch"),
        ):
            val = observed.get(field)
            if val is None:
                continue
            dec = declared.get(field)
            rendered = _render_value(field, val, dec)
            if rendered:
                lines.append(f"{label}: {rendered}")

        return "\n".join(lines) if len(lines) > 1 else ""

    def _render_runtimes(self, mod: Dict[str, Any]) -> str:
        observed = mod.get("observed", {})
        declared = mod.get("declared", {})

        # Only rows where runtime is installed (non-null).
        rows = []
        for runtime in sorted(observed.keys()):
            val = observed[runtime]
            if val is None:
                continue
            dec = declared.get(runtime)
            rendered = _render_value(runtime, val, dec)
            rows.append((runtime, rendered))

        if not rows:
            return ""

        lines = ["## Runtimes", "| Runtime | Version |", "| --- | --- |"]
        for runtime, version in rows[:_MAX_RUNTIMES]:
            lines.append(f"| {runtime} | {version} |")
        return "\n".join(lines)

    def _render_services(self, mod: Dict[str, Any]) -> str:
        observed = mod.get("observed", {})
        units = observed.get("enabled_units", [])
        if not units:
            return ""

        sorted_units = sorted(units)
        total = len(sorted_units)
        shown = sorted_units[:_MAX_SERVICES]

        lines = ["## Services"]
        lines.append("| Unit |")
        lines.append("| --- |")
        for unit in shown:
            lines.append(f"| {unit} |")

        if total > _MAX_SERVICES:
            lines.append(f"_(showing {_MAX_SERVICES} of {total} enabled units)_")

        return "\n".join(lines)

    def _render_web_stack(self, mod: Dict[str, Any]) -> str:
        observed = mod.get("observed", {})
        declared = mod.get("declared", {})
        if not observed:
            return ""

        lines = ["## Web stack"]

        # Nginx version — prober emits key ``"nginx"``.
        nginx_ver = observed.get("nginx")
        if nginx_ver:
            dec = declared.get("nginx")
            lines.append(f"nginx: {_render_value('nginx', nginx_ver, dec)}")

        # Apache version — prober emits key ``"apache"``.
        apache_ver = observed.get("apache")
        if apache_ver:
            dec = declared.get("apache")
            lines.append(f"apache: {_render_value('apache', apache_ver, dec)}")

        # Sites-enabled — prober emits separate ``nginx_sites_enabled`` and
        # ``apache_sites_enabled`` lists; merge and deduplicate for the summary.
        nginx_sites = observed.get("nginx_sites_enabled") or []
        apache_sites = observed.get("apache_sites_enabled") or []
        sites = sorted(set(nginx_sites) | set(apache_sites))
        if sites:
            total = len(sites)
            shown = sites[:_MAX_SITES]
            lines.append(f"sites-enabled ({total} total):")
            lines.append("| Site |")
            lines.append("| --- |")
            for site in shown:
                lines.append(f"| {site} |")
            if total > _MAX_SITES:
                lines.append(f"_(showing {_MAX_SITES} of {total})_")

        return "\n".join(lines) if len(lines) > 1 else ""

    def _render_logs(self, mod: Dict[str, Any]) -> str:
        observed = mod.get("observed", {})
        paths = observed.get("probed_paths", [])
        if not paths:
            return ""

        sorted_paths = sorted(paths)
        lines = ["## Logs"]
        for p in sorted_paths:
            lines.append(f"- {p}")
        return "\n".join(lines)

    def _render_databases(self, mod: Dict[str, Any]) -> str:
        observed = mod.get("observed", {})
        declared = mod.get("declared", {})
        if not observed:
            return ""

        lines = ["## Databases"]
        for key in sorted(observed.keys()):
            val = observed[key]
            if val is None:
                continue
            dec = declared.get(key)
            lines.append(f"{key}: {_render_value(key, val, dec)}")

        return "\n".join(lines) if len(lines) > 1 else ""

    def _render_containers(self, mod: Dict[str, Any]) -> str:
        observed = mod.get("observed", {})
        if not observed:
            return ""

        lines = ["## Containers"]
        for key in sorted(observed.keys()):
            val = observed[key]
            if val is None:
                continue
            lines.append(f"{key}: {val}")

        return "\n".join(lines) if len(lines) > 1 else ""

    def _render_network(self, mod: Dict[str, Any]) -> str:
        observed = mod.get("observed", {})
        if not observed:
            return ""

        lines = ["## Network"]
        for key in sorted(observed.keys()):
            val = observed[key]
            if val is None:
                continue
            lines.append(f"{key}: {val}")

        return "\n".join(lines) if len(lines) > 1 else ""

    def _render_git(self, mod: Dict[str, Any]) -> str:
        observed = mod.get("observed", {})
        if not observed:
            return ""

        lines = ["## Git"]
        for key in sorted(observed.keys()):
            val = observed[key]
            if val is None:
                continue
            lines.append(f"{key}: {val}")

        return "\n".join(lines) if len(lines) > 1 else ""

    def _render_disk(self, mod: Dict[str, Any]) -> str:
        observed = mod.get("observed", {})
        if not observed:
            return ""

        lines = ["## Disk"]
        for key in sorted(observed.keys()):
            val = observed[key]
            if val is None:
                continue
            lines.append(f"{key}: {val}")

        return "\n".join(lines) if len(lines) > 1 else ""

    def _load_annotations(self) -> str:
        """Load annotations.md verbatim up to _MAX_ANNOTATIONS_CHARS chars."""
        if self._annotations_dir is None:
            return ""
        ann_path = self._annotations_dir / "annotations.md"
        if not ann_path.exists():
            return ""
        try:
            text = ann_path.read_text(encoding="utf-8")
            if len(text) > _MAX_ANNOTATIONS_CHARS:
                text = text[:_MAX_ANNOTATIONS_CHARS] + "\n_(truncated)_"
            return text
        except OSError:
            return ""

    def _render_data_quality(
        self, raw: Dict[str, Dict[str, Any]], now: datetime
    ) -> str:
        """Render the Data quality section for all modules that have flags."""
        lines: list[str] = []
        for module_name in sorted(raw.keys()):
            mod = raw[module_name]
            flags = []
            if mod.get("partial"):
                flags.append("partial")
            if mod.get("truncated"):
                flags.append("truncated")
            if mod.get("sudo_used"):
                flags.append("sudo_used")
            ttl = mod.get("ttl_seconds", 86400)
            probed_at = mod.get("probed_at", "")
            if _is_stale(probed_at, ttl, now):
                flags.append("stale")
            if flags:
                lines.append(f"- {module_name}: {', '.join(flags)}")

        if not lines:
            return ""
        return "## Data quality\n" + "\n".join(lines)


# ---------------------------------------------------------------------------
# Public convenience wrapper
# ---------------------------------------------------------------------------

def build_summary_markdown(
    store: "MemoryStore",
    instance_meta: Dict[str, Any],
    config: "MemoryConfig",
    now: Optional[datetime] = None,
) -> str:
    """Build a full summary Markdown string for one instance.

    Pulls all stored modules from *store*, checks TTL staleness using
    *config*, and delegates to :class:`Summariser`.

    Args:
        store: ``MemoryStore`` instance to read modules from.
        instance_meta: Instance dict with ``id``, ``name``, ``provider``.
        config: ``MemoryConfig`` for TTL overrides.
        now: Reference time (injected for tests; defaults to UTC now).

    Returns:
        Markdown string suitable for injection into an AI system prompt.
    """
    if now is None:
        now = datetime.now(tz=timezone.utc)

    instance_id = instance_meta.get("id") or instance_meta.get("name", "")
    provider = instance_meta.get("provider", "custom")

    raw_modules = store.get_all_modules(instance_id, provider=provider)

    annotations_dir: Optional[Path] = None
    if instance_id:
        from .store import _provider_slug
        slug = _provider_slug(provider)
        annotations_dir = store._root / slug / instance_id

    summariser = Summariser(annotations_dir=annotations_dir)
    return summariser.summarise(instance_meta, raw_modules, now=now)
