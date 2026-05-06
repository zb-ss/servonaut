"""Build <CONTEXT name="server_memory:..."> blocks for chat injection.

The Servonaut chat backend (and BYO providers, when we control the system
prompt) understands a synthetic message of the form::

    <CONTEXT name="server_memory:<instance_id>" snapshot_at="<iso8601>">
    {
      "os": { ... },
      "services": { ... },
      ...
    }
    </CONTEXT>

This module is the *pre-flight* step that runs before every chat send.
It selects modules from local memory, formats them deterministically as
JSON, applies layered compaction so the request stays under a configurable
byte budget, and runs a defence-in-depth secret regex pass before
returning the assembled block.

The module is **pure** in the sense that it performs no network IO and no
disk writes — only the injected ``memory_service.get_all_modules`` reads
from disk.  All curation, ordering, compaction, and formatting decisions
are deterministic functions of the inputs.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from servonaut.services.memory.redaction import default_redactor

logger = logging.getLogger("servonaut.ai_memory_injector")

# ---------------------------------------------------------------------------
# Curation rules
# ---------------------------------------------------------------------------

#: Modules included on every send (high-signal, small footprint).
DEFAULT_MODULES: Tuple[str, ...] = (
    "os", "services", "containers", "runtimes", "web_stack", "network",
)

#: Conditional modules — included only when the user prompt mentions a
#: matching keyword.  Keywords are case-insensitive whole-token matches
#: against the prompt text.
CONDITIONAL_MODULES: Dict[str, Tuple[str, ...]] = {
    "logs":      ("log", "logs", "error", "errors", "warn", "warning",
                  "fail", "failed", "crash", "crashed", "trace", "stack"),
    "disk":      ("disk", "space", "storage", "usage", "df", "full",
                  "inode", "mount"),
    "databases": ("db", "database", "databases", "mysql", "postgres",
                  "postgresql", "mariadb", "mongo", "mongodb", "redis",
                  "query", "queries", "schema"),
    "git":       ("deploy", "deployment", "commit", "commits", "branch",
                  "branches", "release", "rollback", "tag"),
}

#: Drop-order when stage-2 compaction kicks in: lowest-priority first.
#: Defaults stay until last because they're the highest signal-per-byte
#: modules (a server with no os/services context is useless to the model).
DROP_ORDER: Tuple[str, ...] = (
    "git", "databases", "disk", "logs",
    "web_stack", "network", "containers", "runtimes", "services", "os",
)

#: Default byte budget for the injected memory section.  The hosted chat
#: endpoint accepts a 1 MB body; the chat history + tool schemas + system
#: prompt eat ~50-200 KB depending on conversation length, so we cap the
#: memory budget at ~700 KB to leave headroom.  Callers can override.
DEFAULT_BYTE_BUDGET = 700 * 1024

#: A module's ``observed.<key>`` whose value is a list of dicts gets
#: trimmed to this many entries during stage-1 compaction (lossless if
#: the model only needs a recent slice — services, processes, log paths).
STAGE1_TRIM_KEEP = 20

#: Staleness threshold — block-level ``snapshot_at`` older than this
#: triggers a ``[stale: …]`` marker in the block body.
STALE_AFTER_SECONDS = 7 * 24 * 3600


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class InstanceScope:
    """Resolved in-scope instance for memory injection.

    Decoupled from the AWS/custom instance dict so the injector doesn't
    care which provider produced the row.  Only ``id``, ``name``, and
    ``provider`` are required.
    """

    id: str
    name: str = ""
    provider: str = "custom"


@dataclass
class InjectorTelemetry:
    """One row per chat send — emitted to the application log at INFO."""

    instance_count: int = 0
    blocks_emitted: int = 0
    total_bytes: int = 0
    compaction: str = "none"          # none | stage1 | stage2 | truncated
    dropped_modules: List[str] = field(default_factory=list)
    dropped_instances: List[str] = field(default_factory=list)
    stale_instances: List[str] = field(default_factory=list)

    def as_log_kv(self) -> str:
        parts = [
            f"injected_memory_blocks={self.blocks_emitted}",
            f"total_bytes={self.total_bytes}",
            f"compaction={self.compaction}",
        ]
        if self.dropped_modules:
            parts.append(f"dropped_modules={','.join(self.dropped_modules)}")
        if self.dropped_instances:
            parts.append(f"dropped_instances={','.join(self.dropped_instances)}")
        if self.stale_instances:
            parts.append(f"stale={','.join(self.stale_instances)}")
        return " ".join(parts)


# ---------------------------------------------------------------------------
# Token matching
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"[A-Za-z0-9_.\-]+")


def _tokens(text: str) -> List[str]:
    return [t.lower() for t in _WORD_RE.findall(text or "")]


def select_conditional_modules(prompt: str) -> List[str]:
    """Return conditional module names whose keywords appear in *prompt*."""
    tokens = set(_tokens(prompt))
    matched: List[str] = []
    for module, keywords in CONDITIONAL_MODULES.items():
        if any(kw in tokens for kw in keywords):
            matched.append(module)
    return matched


def resolve_instance_scope(
    *,
    prompt: str,
    explicit: Sequence[Dict[str, Any]] = (),
    context_instance_ids: Sequence[str] = (),
    candidate_instances: Sequence[Dict[str, Any]] = (),
) -> List[InstanceScope]:
    """Pick the in-scope instance set for one chat turn.

    Priority (highest first):

    1. ``explicit`` — instance dicts the chat UI attached deliberately
       (e.g. the user clicked a row in the sidebar before sending).
    2. ``context_instance_ids`` — already present in the chat context
       payload (the existing ``context["instance_ids"]`` list).
    3. Token-match against ``prompt`` over ``candidate_instances``
       (case-insensitive, whole-token; matches both id and name).

    Each instance is included at most once; first match wins.

    Args:
        prompt: The user's message text for token-matching.
        explicit: Instance dicts already attached to the turn.
        context_instance_ids: IDs already in ``context["instance_ids"]``.
        candidate_instances: All known instances (AWS + custom merged).

    Returns:
        Ordered list of InstanceScope, with duplicates removed.
    """
    seen: set[str] = set()
    out: List[InstanceScope] = []

    def _add(inst: Dict[str, Any]) -> None:
        iid = inst.get("id") or inst.get("name") or ""
        if not iid or iid in seen:
            return
        seen.add(iid)
        out.append(InstanceScope(
            id=iid,
            name=inst.get("name", "") or "",
            provider=inst.get("provider", "custom") or "custom",
        ))

    for inst in explicit:
        _add(inst)

    if context_instance_ids:
        by_id = {(c.get("id") or "").lower(): c for c in candidate_instances}
        by_name = {(c.get("name") or "").lower(): c for c in candidate_instances}
        for raw in context_instance_ids:
            key = (raw or "").lower()
            inst = by_id.get(key) or by_name.get(key)
            if inst is not None:
                _add(inst)
            elif raw:
                # ID was passed but we can't look up provider/name —
                # fall back to a minimal scope so the model still gets
                # *something* identifying which server is in play.
                _add({"id": raw, "name": raw, "provider": "custom"})

    if candidate_instances and prompt:
        tokens = set(_tokens(prompt))
        for inst in candidate_instances:
            iid = (inst.get("id") or "").lower()
            iname = (inst.get("name") or "").lower()
            if (iid and iid in tokens) or (iname and iname in tokens):
                _add(inst)

    return out


# ---------------------------------------------------------------------------
# Module curation + serialisation
# ---------------------------------------------------------------------------


def _module_view(raw_module: Dict[str, Any]) -> Dict[str, Any]:
    """Return the agent-visible slice of a stored module dict.

    Drops ``raw_output`` (large + risky), ``module``, ``instance_id``,
    ``ttl_seconds``, and any null/empty values that would just be noise.
    Keeps ``observed`` and ``declared`` (the structured facts) plus the
    boolean flags that meaningfully change interpretation.
    """
    view: Dict[str, Any] = {}
    observed = raw_module.get("observed")
    declared = raw_module.get("declared")
    if isinstance(observed, dict) and observed:
        view["observed"] = _strip_nulls(observed)
    if isinstance(declared, dict) and declared:
        view["declared"] = _strip_nulls(declared)
    for flag in ("partial", "truncated", "sudo_used"):
        if raw_module.get(flag):
            view[flag] = True
    return view


def _strip_nulls(value: Any) -> Any:
    """Recursively drop None / empty-string / empty-collection values."""
    if isinstance(value, dict):
        return {
            k: _strip_nulls(v)
            for k, v in value.items()
            if v not in (None, "", [], {}, ())
        }
    if isinstance(value, list):
        cleaned = [_strip_nulls(v) for v in value]
        return [v for v in cleaned if v not in (None, "", [], {}, ())]
    return value


def _oldest_probed_at(modules: Dict[str, Dict[str, Any]]) -> Optional[datetime]:
    """Oldest ``probed_at`` across the modules — drives staleness."""
    oldest: Optional[datetime] = None
    for raw in modules.values():
        probed = raw.get("probed_at")
        if not probed:
            continue
        try:
            dt = datetime.fromisoformat(str(probed).rstrip("Z"))
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if oldest is None or dt < oldest:
            oldest = dt
    return oldest


def _stale_age_days(snapshot_at: Optional[datetime]) -> Optional[int]:
    if snapshot_at is None:
        return None
    age = datetime.now(timezone.utc) - snapshot_at
    if age.total_seconds() < STALE_AFTER_SECONDS:
        return None
    return int(age.total_seconds() // 86400)


# ---------------------------------------------------------------------------
# Compaction
# ---------------------------------------------------------------------------


def _stage1_trim_arrays(view: Dict[str, Any], keep: int = STAGE1_TRIM_KEEP) -> Dict[str, Any]:
    """Lossless-ish compaction: cap large lists in ``observed.<key>``.

    Many modules carry "all systemd units" or "all running processes" —
    structurally identical entries the model only needs a slice of.  We
    keep the LAST *keep* entries (most recent) per list and annotate the
    truncation in a sibling ``_truncated_<key>`` counter so the model
    knows the picture isn't complete.
    """
    out = dict(view)
    for section in ("observed", "declared"):
        block = out.get(section)
        if not isinstance(block, dict):
            continue
        new_block = dict(block)
        for key, val in list(new_block.items()):
            if isinstance(val, list) and len(val) > keep:
                new_block[key] = val[-keep:]
                new_block[f"_{key}_total"] = len(val)
        out[section] = new_block
    return out


def _format_block(
    instance: InstanceScope,
    modules: Dict[str, Dict[str, Any]],
    *,
    snapshot_at: Optional[datetime],
    stale_days: Optional[int],
    omitted_modules: Iterable[str] = (),
) -> str:
    """Render one ``<CONTEXT>`` block for a single instance."""
    snapshot_str = (snapshot_at or datetime.now(timezone.utc)).isoformat()
    body_parts: List[str] = []
    if stale_days is not None:
        body_parts.append(
            f"[stale: snapshot is {stale_days} days old; "
            f"consider refreshing memory]"
        )
    omitted = list(omitted_modules)
    if omitted:
        body_parts.append(
            f"[truncated: omitted modules {', '.join(omitted)} due to size]"
        )
    payload = {name: _module_view(raw) for name, raw in modules.items()}
    payload = {k: v for k, v in payload.items() if v}
    body_parts.append(json.dumps(payload, indent=2, sort_keys=True, default=str))
    body = "\n".join(body_parts)
    header = (
        f'<CONTEXT name="server_memory:{instance.id}" '
        f'snapshot_at="{snapshot_str}">'
    )
    return f"{header}\n{body}\n</CONTEXT>"


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def build_memory_context(
    *,
    instances: Sequence[InstanceScope],
    prompt: str,
    memory_service: Any,
    config_memory: Any,
    byte_budget: int = DEFAULT_BYTE_BUDGET,
    redaction_enabled: bool = True,
) -> Tuple[str, InjectorTelemetry]:
    """Assemble the synthetic-message body for one chat turn.

    Returns the concatenated ``<CONTEXT>`` blocks plus a telemetry row.
    Empty body when no instances qualify (memory disabled, opted out,
    no modules stored, or empty input).

    Args:
        instances: In-scope instances for this turn (caller resolves).
        prompt: User message — drives conditional-module inclusion.
        memory_service: MemoryService-like object exposing
            ``get_all_modules(instance_id, provider) -> dict``.
        config_memory: MemoryConfig — checks ``enabled`` and
            ``is_instance_disabled(id, name)``.
        byte_budget: Max bytes for the assembled body.
        redaction_enabled: When True (default), every emitted block
            passes through ``default_redactor`` so secrets that slipped
            past the prober's redaction get masked before injection.

    Returns:
        ``(body, telemetry)``.  ``body`` is empty when nothing was
        emitted; ``telemetry`` always reports the decision so callers
        can log it even on no-op turns.
    """
    telemetry = InjectorTelemetry(instance_count=len(instances))

    if memory_service is None or config_memory is None:
        return "", telemetry
    if not getattr(config_memory, "enabled", False):
        return "", telemetry
    if not instances:
        return "", telemetry

    modules_for_prompt = list(DEFAULT_MODULES) + select_conditional_modules(prompt)
    blocks: List[Tuple[InstanceScope, Dict[str, Dict[str, Any]],
                       Optional[datetime], Optional[int]]] = []

    for inst in instances:
        try:
            disabled = config_memory.is_instance_disabled(inst.id, inst.name)
        except Exception:
            disabled = False
        if disabled:
            continue
        try:
            stored = memory_service.get_all_modules(inst.id, inst.provider) or {}
        except Exception as exc:
            logger.warning(
                "memory_injector: get_all_modules failed for %s/%s: %s",
                inst.provider, inst.id, exc,
            )
            continue
        if not stored:
            continue
        selected = {
            name: stored[name]
            for name in modules_for_prompt
            if name in stored
        }
        if not selected:
            continue
        snapshot_at = _oldest_probed_at(selected)
        stale_days = _stale_age_days(snapshot_at)
        if stale_days is not None:
            telemetry.stale_instances.append(inst.id)
        blocks.append((inst, selected, snapshot_at, stale_days))

    if not blocks:
        return "", telemetry

    body = _render_all(blocks, telemetry, omitted_per_instance={})
    if len(body.encode("utf-8")) <= byte_budget:
        telemetry.compaction = "none"
        return _maybe_redact(body, redaction_enabled, telemetry)

    blocks = [(inst, _apply_stage1(mods), s, sd) for inst, mods, s, sd in blocks]
    body = _render_all(blocks, telemetry, omitted_per_instance={})
    if len(body.encode("utf-8")) <= byte_budget:
        telemetry.compaction = "stage1"
        return _maybe_redact(body, redaction_enabled, telemetry)

    body, omitted_per_instance = _stage2_drop_modules(blocks, byte_budget)
    if body and len(body.encode("utf-8")) <= byte_budget:
        telemetry.compaction = "stage2"
        for omitted in omitted_per_instance.values():
            for mod in omitted:
                if mod not in telemetry.dropped_modules:
                    telemetry.dropped_modules.append(mod)
        return _maybe_redact(body, redaction_enabled, telemetry)

    body, dropped_inst_ids = _stage3_drop_instances(blocks, byte_budget)
    telemetry.compaction = "truncated"
    telemetry.dropped_instances.extend(dropped_inst_ids)
    return _maybe_redact(body, redaction_enabled, telemetry)


def _render_all(
    blocks: Sequence[Tuple[InstanceScope, Dict[str, Dict[str, Any]],
                           Optional[datetime], Optional[int]]],
    telemetry: InjectorTelemetry,
    *,
    omitted_per_instance: Dict[str, List[str]],
) -> str:
    rendered: List[str] = []
    for inst, mods, snapshot_at, stale_days in blocks:
        rendered.append(_format_block(
            inst, mods,
            snapshot_at=snapshot_at,
            stale_days=stale_days,
            omitted_modules=omitted_per_instance.get(inst.id, ()),
        ))
    body = "\n\n".join(rendered)
    telemetry.blocks_emitted = len(rendered)
    telemetry.total_bytes = len(body.encode("utf-8"))
    return body


def _apply_stage1(modules: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for name, raw in modules.items():
        # Only the "view" portion gets trimmed; the original raw dict on
        # disk is untouched (we never write back).
        out[name] = _trim_in_place(dict(raw))
    return out


def _trim_in_place(raw: Dict[str, Any]) -> Dict[str, Any]:
    for section in ("observed", "declared"):
        block = raw.get(section)
        if isinstance(block, dict):
            new_block = dict(block)
            for key, val in list(new_block.items()):
                if isinstance(val, list) and len(val) > STAGE1_TRIM_KEEP:
                    new_block[key] = val[-STAGE1_TRIM_KEEP:]
                    new_block[f"_{key}_total"] = len(val)
            raw[section] = new_block
    return raw


def _stage2_drop_modules(
    blocks: Sequence[Tuple[InstanceScope, Dict[str, Dict[str, Any]],
                           Optional[datetime], Optional[int]]],
    byte_budget: int,
) -> Tuple[str, Dict[str, List[str]]]:
    """Drop modules in DROP_ORDER until under budget — deepest priority first."""
    omitted_per_instance: Dict[str, List[str]] = {b[0].id: [] for b in blocks}
    working: List[Tuple[InstanceScope, Dict[str, Dict[str, Any]],
                        Optional[datetime], Optional[int]]] = [
        (inst, dict(mods), s, sd) for inst, mods, s, sd in blocks
    ]
    for module_to_drop in DROP_ORDER:
        body = _render_all_minimal(working, omitted_per_instance)
        if len(body.encode("utf-8")) <= byte_budget:
            return body, omitted_per_instance
        for inst, mods, _s, _sd in working:
            if module_to_drop in mods:
                mods.pop(module_to_drop)
                omitted_per_instance[inst.id].append(module_to_drop)
    body = _render_all_minimal(working, omitted_per_instance)
    return body, omitted_per_instance


def _stage3_drop_instances(
    blocks: Sequence[Tuple[InstanceScope, Dict[str, Dict[str, Any]],
                           Optional[datetime], Optional[int]]],
    byte_budget: int,
) -> Tuple[str, List[str]]:
    """Last resort: drop entire instance blocks lowest-priority-first.

    "Lowest-priority" here means whichever instance is largest after
    stage-2 — dropping it gives us the most headroom per drop.
    """
    working = [(inst, dict(mods), s, sd) for inst, mods, s, sd in blocks]
    dropped: List[str] = []
    while working:
        # Render with remaining modules — even after stage-2 we may have
        # an empty mods dict for some instances; skip those.
        rendered = [
            _format_block(inst, mods, snapshot_at=s, stale_days=sd)
            for inst, mods, s, sd in working if mods
        ]
        body = "\n\n".join(rendered)
        if len(body.encode("utf-8")) <= byte_budget or len(working) == 1:
            return body, dropped
        # Drop the largest remaining block.
        sizes = [
            (i, len(_format_block(inst, mods, snapshot_at=s, stale_days=sd)
                    .encode("utf-8")))
            for i, (inst, mods, s, sd) in enumerate(working)
            if mods
        ]
        if not sizes:
            return "", dropped
        idx_to_drop = max(sizes, key=lambda x: x[1])[0]
        dropped.append(working[idx_to_drop][0].id)
        del working[idx_to_drop]
    return "", dropped


def _render_all_minimal(
    blocks: Sequence[Tuple[InstanceScope, Dict[str, Dict[str, Any]],
                           Optional[datetime], Optional[int]]],
    omitted_per_instance: Dict[str, List[str]],
) -> str:
    rendered = [
        _format_block(
            inst, mods,
            snapshot_at=s,
            stale_days=sd,
            omitted_modules=omitted_per_instance.get(inst.id, ()),
        )
        for inst, mods, s, sd in blocks
    ]
    return "\n\n".join(rendered)


def _maybe_redact(
    body: str, enabled: bool, telemetry: InjectorTelemetry,
) -> Tuple[str, InjectorTelemetry]:
    if enabled:
        body = default_redactor(body)
    telemetry.total_bytes = len(body.encode("utf-8"))
    return body, telemetry
