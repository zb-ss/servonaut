"""Disk-backed storage layer for server memory.

Per-module JSON files live at::

    ~/.servonaut/memory/<provider>/<instance_id>/<module>.json

A global ``index.json`` tracks which instances have been scanned and when.
All writes are atomic (tmp file + ``os.replace``) with mode ``0o600``.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.config.schema import MemoryConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MEMORY_ROOT = Path.home() / ".servonaut" / "memory"
INDEX_PATH = MEMORY_ROOT / "index.json"
INDEX_VERSION = 1

# Provider slug mapping: instance dict ``provider`` value → directory name.
_PROVIDER_SLUGS: Dict[str, str] = {
    "aws": "aws",
    "ec2": "aws",
    "amazon": "aws",
    "custom": "custom",
    "ovh": "ovh",
    "ovhcloud": "ovh",
}

# Regex that detects forbidden characters/sequences in instance IDs.
_UNSAFE_ID_RE = re.compile(r"[/\\]|\.\.")

# Whitelist for module names: lowercase identifier, first char alpha, max 31 chars.
# This prevents path-traversal via module names (e.g. "os.json/../../evil").
_SAFE_MODULE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,30}$")

# Whitelist for finding IDs: must start with "f_" followed by 16–32 lowercase
# hex/alphanumeric characters. This prevents path-traversal via finding IDs.
_SAFE_FINDING_ID_RE = re.compile(r"^f_[a-z0-9]{16,32}$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _provider_slug(provider: str) -> str:
    """Normalise a provider string to its canonical slug.

    Unknown providers are lower-cased and used as-is (safe fallback).
    """
    return _PROVIDER_SLUGS.get(provider.lower(), provider.lower() or "custom")


def _validate_instance_id(instance_id: str) -> None:
    """Raise ``ValueError`` if *instance_id* could enable path traversal.

    Args:
        instance_id: Raw identifier to validate.

    Raises:
        ValueError: On empty string, path-separator characters, or ``..``.
    """
    if not instance_id:
        raise ValueError("instance_id must not be empty")
    if _UNSAFE_ID_RE.search(instance_id):
        raise ValueError(
            f"instance_id {instance_id!r} contains unsafe characters "
            "(path separators or '..' are not allowed)"
        )


def _validate_module_name(name: str) -> None:
    """Raise ``ValueError`` if *name* is not a safe module identifier.

    Module names are whitelisted to ``^[a-z][a-z0-9_]{0,30}$`` — a lowercase
    Python-style identifier capped at 31 characters.  This prevents path
    traversal via module names such as ``"os.json/../../evil"``.

    Args:
        name: Raw module name to validate.

    Raises:
        ValueError: If *name* does not match the whitelist pattern.
    """
    if not _SAFE_MODULE_NAME_RE.fullmatch(name):
        raise ValueError(
            f"Invalid module name: {name!r}. "
            "Module names must match ^[a-z][a-z0-9_]{{0,30}}$ "
            "(lowercase letter, digits, underscores only; max 31 chars)."
        )


def _validate_finding_id(finding_id: str) -> None:
    """Raise ``ValueError`` if *finding_id* is not a safe finding identifier.

    Finding IDs are whitelisted to ``^f_[a-z0-9]{16,32}$`` — a literal
    ``f_`` prefix followed by 16–32 lowercase alphanumeric characters.
    This prevents path traversal via finding IDs such as ``"f_../../../evil"``.

    Args:
        finding_id: Raw finding ID to validate.

    Raises:
        ValueError: If *finding_id* does not match the whitelist pattern.
    """
    if not _SAFE_FINDING_ID_RE.fullmatch(finding_id or ""):
        raise ValueError(
            f"Invalid finding ID: {finding_id!r}. "
            "Finding IDs must match ^f_[a-z0-9]{{16,32}}$ "
            "(literal 'f_' prefix followed by 16–32 lowercase alphanumeric chars)."
        )


def _atomic_write_json(path: Path, data: Any) -> None:
    """Write *data* as JSON to *path* atomically with mode 0o600.

    Uses a sibling ``.tmp`` file + ``os.replace`` so readers never see a
    partially written file.  The tmp file is removed on failure.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(
        tmp_path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    # Belt-and-suspenders: ensure mode is right even if umask stripped bits.
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)


# ---------------------------------------------------------------------------
# Index migration
# ---------------------------------------------------------------------------

def _migrate_index(data: Any, from_version: int) -> Dict[str, Any]:
    """Upgrade an index dict from *from_version* to the current version.

    Raises:
        ValueError: If *from_version* is unrecognised (not 0 or 1).
    """
    if from_version == INDEX_VERSION:
        return data  # already current

    if from_version == 0:
        # Pre-versioned index: wrap existing keys under ``instances`` if needed
        # and stamp the current version.
        instances = data if isinstance(data, dict) else {}
        # Remove any top-level bookkeeping keys that don't look like instance IDs.
        instances.pop("version", None)
        return {"version": INDEX_VERSION, "instances": instances}

    raise ValueError(
        f"Unknown index version {from_version!r}; "
        "cannot migrate. Delete ~/.servonaut/memory/index.json to reset."
    )


# ---------------------------------------------------------------------------
# MemoryStore
# ---------------------------------------------------------------------------

class MemoryStore:
    """Read/write per-module JSON memory for server instances.

    Each module is stored as a separate JSON file so modules can be
    refreshed independently.  The global ``index.json`` tracks which
    instances have been scanned.

    Args:
        root: Override the default ``~/.servonaut/memory`` directory (used
            by tests to isolate state).
        redactor: Optional callable ``(text: str) -> str`` applied to the
            ``raw_output`` field before it is written to disk when
            ``MemoryConfig.redaction_enabled`` is True.  Defaults to
            ``None`` (no redaction applied).  T9 will supply the real
            regex-based redactor; until then, ``noop_redactor`` from
            :mod:`servonaut.services.memory.redaction` is injected by
            ``MemoryService.__init__`` so the plumbing is live end-to-end.
    """

    def __init__(
        self,
        root: Optional[Path] = None,
        redactor: Optional[Callable[[str], str]] = None,
    ) -> None:
        self._root = root or MEMORY_ROOT
        self._index_path = self._root / "index.json"
        self._redactor = redactor

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def _instance_dir(self, instance_id: str, provider: str = "custom") -> Path:
        """Return the directory for a given instance (without creating it)."""
        slug = _provider_slug(provider)
        return self._root / slug / instance_id

    def _module_path(
        self, instance_id: str, module: str, provider: str = "custom"
    ) -> Path:
        return self._instance_dir(instance_id, provider) / f"{module}.json"

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save_module(
        self,
        instance_id: str,
        module: str,
        data: Dict[str, Any],
        provider: str = "custom",
    ) -> None:
        """Persist *data* as the JSON blob for *module* on *instance_id*.

        If a *redactor* was supplied at construction time, it is applied to the
        ``raw_output`` field of *data* before writing.  This is the seam that
        T9 plugs into — T9 replaces ``noop_redactor`` with a real implementation
        without touching any call sites.

        Args:
            instance_id: Instance identifier (validated against path traversal).
            module: Module name, e.g. ``"runtimes"``.
            data: JSON-serialisable dict to persist.
            provider: Provider slug used to select the storage sub-directory.

        Raises:
            ValueError: If *instance_id* or *module* fails safety validation.
        """
        _validate_instance_id(instance_id)
        _validate_module_name(module)
        # Apply redactor to raw_output if one is configured.
        if self._redactor is not None and "raw_output" in data:
            data = dict(data)  # shallow copy — do not mutate the caller's dict
            data["raw_output"] = self._redactor(data["raw_output"])
        path = self._module_path(instance_id, module, provider)
        _atomic_write_json(path, data)
        logger.debug("Saved memory module %s for %s at %s", module, instance_id, path)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_module(
        self,
        instance_id: str,
        module: str,
        provider: str = "custom",
    ) -> Optional[Dict[str, Any]]:
        """Return the stored dict for *module*, or ``None`` if absent.

        Args:
            instance_id: Instance identifier.
            module: Module name.
            provider: Provider slug.

        Raises:
            ValueError: If *instance_id* or *module* fails safety validation.
        """
        _validate_instance_id(instance_id)
        _validate_module_name(module)
        path = self._module_path(instance_id, module, provider)
        if not path.exists():
            return None
        try:
            with open(path, "r") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not read module %s for %s: %s", module, instance_id, exc)
            return None

    def get_all_modules(
        self,
        instance_id: str,
        provider: str = "custom",
    ) -> Dict[str, Dict[str, Any]]:
        """Return all stored modules for *instance_id* as ``{module: data}``.

        Missing or corrupt modules are silently omitted.
        """
        _validate_instance_id(instance_id)
        result: Dict[str, Dict[str, Any]] = {}
        # Search across all provider directories in case caller doesn't know.
        dirs_to_search: List[Path] = []
        if provider:
            dirs_to_search.append(self._instance_dir(instance_id, provider))
        else:
            # Scan every provider sub-directory.
            if self._root.exists():
                for candidate in self._root.iterdir():
                    if candidate.is_dir() and candidate.name != "index.json":
                        dirs_to_search.append(candidate / instance_id)

        for instance_dir in dirs_to_search:
            if not instance_dir.exists():
                continue
            for json_file in instance_dir.glob("*.json"):
                module_name = json_file.stem
                try:
                    with open(json_file, "r") as fh:
                        result[module_name] = json.load(fh)
                except (json.JSONDecodeError, OSError) as exc:
                    logger.warning(
                        "Skipping corrupt module file %s: %s", json_file, exc
                    )
        return result

    def list_instances(self) -> List[str]:
        """Return instance IDs of every entry in the index."""
        index = self._load_index()
        return list(index.get("instances", {}).keys())

    # ------------------------------------------------------------------
    # TTL / freshness
    # ------------------------------------------------------------------

    def is_stale(
        self,
        instance_id: str,
        module: str,
        config: "MemoryConfig",
        provider: str = "custom",
        module_default_ttl: int = 86400,
    ) -> bool:
        """Return ``True`` if the module data has exceeded its TTL.

        TTL precedence (highest first):
        1. ``config.default_ttl_overrides[module]``
        2. *module_default_ttl* (the prober's built-in default)

        A module is stale if no data exists yet.

        Args:
            instance_id: Instance identifier.
            module: Module name.
            config: ``MemoryConfig`` instance for TTL overrides.
            provider: Provider slug.
            module_default_ttl: Fallback TTL when config has no override.
        """
        _validate_module_name(module)
        data = self.get_module(instance_id, module, provider)
        if data is None:
            return True

        probed_at_str = data.get("probed_at", "")
        if not probed_at_str:
            return True

        try:
            probed_at = datetime.fromisoformat(probed_at_str.rstrip("Z"))
            if not probed_at.tzinfo:
                probed_at = probed_at.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return True

        ttl = config.default_ttl_overrides.get(module, module_default_ttl)
        now = datetime.now(tz=timezone.utc)
        age_seconds = (now - probed_at).total_seconds()
        return age_seconds > ttl

    def _is_stale_from_data(self, data: Optional[Dict[str, Any]], ttl: int) -> bool:
        """Return ``True`` if *data* has exceeded *ttl* seconds since ``probed_at``.

        Args:
            data: Module JSON dict (may be ``None``).
            ttl: Time-to-live in seconds to compare against.

        Returns:
            ``True`` when *data* is ``None``, has no ``probed_at``, or the age
            exceeds *ttl*.  ``False`` only when data is present and still fresh.
        """
        if data is None:
            return True
        probed_at_str = data.get("probed_at", "")
        if not probed_at_str:
            return True
        try:
            probed_at = datetime.fromisoformat(probed_at_str.rstrip("Z"))
            if not probed_at.tzinfo:
                probed_at = probed_at.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return True
        now = datetime.now(tz=timezone.utc)
        return (now - probed_at).total_seconds() > ttl

    def stale_modules(
        self,
        instance_id: str,
        config: "MemoryConfig",
        provider: str = "custom",
        module_default_ttls: Optional[Dict[str, int]] = None,
    ) -> List[str]:
        """Return module names whose stored data has exceeded its TTL.

        Only modules that are *present on disk* are considered.  Modules with
        no data are not returned — callers treat missing modules differently
        from stale ones.

        TTL precedence (highest first):
        1. ``config.default_ttl_overrides[module]``
        2. ``module_default_ttls[module]`` (prober built-in, optional)
        3. Hard-coded fallback: 86 400 s (24 h)

        Args:
            instance_id: Instance identifier.
            config: ``MemoryConfig`` for TTL overrides.
            provider: Provider slug for the storage sub-directory.
            module_default_ttls: Mapping of module name → prober default TTL.
                When ``None``, only ``config.default_ttl_overrides`` and the
                86 400 s fallback are used.

        Returns:
            List of module names (strings) that are stale, in filesystem
            iteration order (non-deterministic across runs).
        """
        _validate_instance_id(instance_id)
        instance_dir = self._instance_dir(instance_id, provider)
        if not instance_dir.exists():
            return []

        stale: List[str] = []
        default_ttls: Dict[str, int] = module_default_ttls or {}

        for json_file in instance_dir.glob("*.json"):
            module_name = json_file.stem
            # Skip non-module files (e.g. annotations.md, summary.md).
            try:
                _validate_module_name(module_name)
            except ValueError:
                continue
            try:
                with open(json_file, "r") as fh:
                    data: Optional[Dict[str, Any]] = json.load(fh)
            except (json.JSONDecodeError, OSError):
                data = None
            ttl = (
                config.default_ttl_overrides.get(module_name)
                or data.get("ttl_seconds", default_ttls.get(module_name, 86400))
                if data is not None
                else default_ttls.get(module_name, 86400)
            )
            if self._is_stale_from_data(data, ttl):
                stale.append(module_name)

        return stale

    # ------------------------------------------------------------------
    # Clear
    # ------------------------------------------------------------------

    def clear(
        self,
        instance_id: str,
        modules: Optional[List[str]] = None,
        provider: str = "custom",
    ) -> None:
        """Delete stored memory for *instance_id*.

        Args:
            instance_id: Instance identifier.
            modules: Module names to clear.  ``None`` → remove the entire
                instance directory (all modules).
            provider: Provider slug.

        Raises:
            ValueError: If *instance_id* fails safety validation.
        """
        _validate_instance_id(instance_id)
        instance_dir = self._instance_dir(instance_id, provider)

        if modules is None:
            # Full clear: remove the entire instance directory.
            if instance_dir.exists():
                import shutil
                shutil.rmtree(instance_dir)
                logger.debug("Cleared all memory for %s", instance_id)
            self._remove_from_index(instance_id)
            return

        # Partial clear: remove specified module files only.
        for module in modules:
            _validate_module_name(module)
            path = self._module_path(instance_id, module, provider)
            if path.exists():
                try:
                    path.unlink()
                    logger.debug("Cleared module %s for %s", module, instance_id)
                except OSError as exc:
                    logger.warning("Could not clear module %s: %s", module, exc)

    # ------------------------------------------------------------------
    # Index
    # ------------------------------------------------------------------

    def _load_index(self) -> Dict[str, Any]:
        """Load and return the index dict (migrated to current version)."""
        if not self._index_path.exists():
            return {"version": INDEX_VERSION, "instances": {}}
        try:
            with open(self._index_path, "r") as fh:
                raw = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not read index.json: %s", exc)
            return {"version": INDEX_VERSION, "instances": {}}

        from_version = raw.get("version", 0) if isinstance(raw, dict) else 0
        try:
            return _migrate_index(raw, from_version)
        except ValueError as exc:
            logger.error("Index migration failed: %s", exc)
            return {"version": INDEX_VERSION, "instances": {}}

    def _save_index(self, index: Dict[str, Any]) -> None:
        """Persist *index* to disk atomically."""
        _atomic_write_json(self._index_path, index)

    def update_index(
        self,
        instance_id: str,
        name: str,
        provider: str,
        modules: List[str],
        summary_tokens: int = 0,
        annotations_hash: str = "",
    ) -> None:
        """Upsert an entry for *instance_id* in the index.

        Args:
            instance_id: Instance identifier.
            name: Human-readable server name.
            provider: Provider label (e.g. ``"AWS"``).
            modules: List of module names that have been probed.
            summary_tokens: Approximate token count of the summary.
            annotations_hash: SHA-256 hash of annotations content (if any).
        """
        index = self._load_index()
        instances = index.setdefault("instances", {})

        now_iso = datetime.now(tz=timezone.utc).isoformat()
        entry = instances.get(instance_id, {})

        if not entry.get("first_scan"):
            entry["first_scan"] = now_iso

        entry.update(
            {
                "name": name,
                "provider": provider,
                "last_scan": now_iso,
                "modules": sorted(set(entry.get("modules", []) + modules)),
                "summary_tokens": summary_tokens,
                "annotations_hash": annotations_hash,
            }
        )
        instances[instance_id] = entry
        self._save_index(index)

    def _remove_from_index(self, instance_id: str) -> None:
        """Remove *instance_id* from the index (called by ``clear``)."""
        index = self._load_index()
        index.get("instances", {}).pop(instance_id, None)
        self._save_index(index)

    def get_index_entry(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """Return the index entry for *instance_id*, or ``None``."""
        return self._load_index().get("instances", {}).get(instance_id)

    # ------------------------------------------------------------------
    # Summary file
    # ------------------------------------------------------------------

    def write_summary(
        self,
        instance_id: str,
        markdown_text: str,
        provider: str = "custom",
    ) -> Path:
        """Write *markdown_text* as ``summary.md`` for *instance_id*.

        The file is written atomically with mode 0o600.

        Args:
            instance_id: Instance identifier (validated against path traversal).
            markdown_text: Markdown content to persist.
            provider: Provider slug used to select the storage sub-directory.

        Returns:
            The ``Path`` of the written ``summary.md`` file.

        Raises:
            ValueError: If *instance_id* fails safety validation.
        """
        _validate_instance_id(instance_id)
        instance_dir = self._instance_dir(instance_id, provider)
        instance_dir.mkdir(parents=True, exist_ok=True)
        summary_path = instance_dir / "summary.md"
        tmp_path = summary_path.with_suffix(".md.tmp")
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(markdown_text)
                fh.flush()
                os.fsync(fh.fileno())
        except Exception:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, summary_path)
        logger.debug("Wrote summary.md for %s at %s", instance_id, summary_path)
        return summary_path

    def get_annotations_path(
        self, instance_id: str, provider: str = "custom"
    ) -> Path:
        """Return the path for ``annotations.md`` (may not exist yet).

        Args:
            instance_id: Instance identifier.
            provider: Provider slug.

        Raises:
            ValueError: If *instance_id* fails safety validation (path traversal guard).
        """
        _validate_instance_id(instance_id)
        return self._instance_dir(instance_id, provider) / "annotations.md"

    def read_annotations(
        self,
        instance_id: str,
        provider: str = "custom",
    ) -> str:
        """Return the annotations content for *instance_id*, or ``""`` if absent.

        Args:
            instance_id: Instance identifier (validated against path traversal).
            provider: Provider slug used to select the storage sub-directory.

        Returns:
            UTF-8 text content of ``annotations.md``, or an empty string when
            the file does not exist or cannot be read.

        Raises:
            ValueError: If *instance_id* fails safety validation.
        """
        _validate_instance_id(instance_id)
        path = self.get_annotations_path(instance_id, provider)
        try:
            if path.exists():
                return path.read_text(encoding="utf-8")
        except OSError:
            pass
        return ""

    def write_annotations(
        self,
        instance_id: str,
        content: str,
        provider: str = "custom",
    ) -> Path:
        """Write *content* as ``annotations.md`` for *instance_id* atomically.

        The file is written with mode 0o600 using a sibling tmp file +
        ``os.replace`` so readers never see a partially written file.

        Args:
            instance_id: Instance identifier (validated against path traversal).
            content: Markdown content to persist.
            provider: Provider slug used to select the storage sub-directory.

        Returns:
            The ``Path`` of the written ``annotations.md`` file.

        Raises:
            ValueError: If *instance_id* fails safety validation.
        """
        _validate_instance_id(instance_id)
        final_path = self.get_annotations_path(instance_id, provider)
        final_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = final_path.with_suffix(".md.tmp")
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
        except Exception:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, final_path)
        logger.debug(
            "Wrote annotations.md for %s at %s", instance_id, final_path
        )
        return final_path

    def get_annotations_meta(self, instance_id: str) -> Dict[str, Any]:
        """Return annotation bookkeeping keys from the index entry for *instance_id*.

        The three keys returned are:
        - ``annotations_hash`` — SHA-256 hex of annotation content (or ``""``).
        - ``annotations_synced_at`` — ISO-8601 UTC of last enqueue/pull (or ``""``).
        - ``annotations_modified_at`` — ISO-8601 UTC of last local save (or ``""``).

        Args:
            instance_id: Instance identifier (validated against path traversal).

        Returns:
            Dict with the three annotation meta keys, all defaulting to ``""``.

        Raises:
            ValueError: If *instance_id* fails safety validation.
        """
        _validate_instance_id(instance_id)
        entry = self._load_index().get("instances", {}).get(instance_id, {})
        return {
            "annotations_hash": entry.get("annotations_hash", ""),
            "annotations_synced_at": entry.get("annotations_synced_at", ""),
            "annotations_modified_at": entry.get("annotations_modified_at", ""),
        }

    def set_annotations_meta(
        self,
        instance_id: str,
        *,
        annotations_hash: Optional[str] = None,
        annotations_synced_at: Optional[str] = None,
        annotations_modified_at: Optional[str] = None,
    ) -> None:
        """Update annotation bookkeeping keys in the index entry for *instance_id*.

        Only the explicitly provided (non-``None``) keys are written; all other
        keys on the existing index entry are left untouched.  If no entry exists
        yet a minimal one is created so the keys can be stored without requiring
        the caller to pass ``name`` / ``provider`` (unlike :meth:`update_index`).

        Args:
            instance_id: Instance identifier (validated against path traversal).
            annotations_hash: SHA-256 hex of annotation content.
            annotations_synced_at: ISO-8601 UTC of last enqueue/pull timestamp.
            annotations_modified_at: ISO-8601 UTC of last local save timestamp.

        Raises:
            ValueError: If *instance_id* fails safety validation.
        """
        _validate_instance_id(instance_id)
        index = self._load_index()
        instances = index.setdefault("instances", {})
        entry = instances.setdefault(instance_id, {})
        if annotations_hash is not None:
            entry["annotations_hash"] = annotations_hash
        if annotations_synced_at is not None:
            entry["annotations_synced_at"] = annotations_synced_at
        if annotations_modified_at is not None:
            entry["annotations_modified_at"] = annotations_modified_at
        self._save_index(index)

    # ------------------------------------------------------------------
    # Findings storage
    # ------------------------------------------------------------------

    def _findings_dir(self, instance_id: str, provider: str = "custom") -> Path:
        """Return the findings sub-directory for *instance_id* (without creating it).

        Findings live in a sub-directory of the instance directory so the
        existing ``instance_dir.glob("*.json")`` calls in :meth:`stale_modules`
        and :meth:`get_all_modules` never see them — findings are not TTL modules.

        Args:
            instance_id: Instance identifier (validated against path traversal).
            provider: Provider slug used to select the storage sub-directory.

        Raises:
            ValueError: If *instance_id* fails safety validation.
        """
        _validate_instance_id(instance_id)
        return self._instance_dir(instance_id, provider) / "findings"

    def save_finding(
        self,
        instance_id: str,
        record: Dict[str, Any],
        provider: str = "custom",
    ) -> Path:
        """Persist *record* as a finding JSON file for *instance_id*.

        The file is written atomically with mode 0o600.  The ``"id"`` key
        of *record* is used as the filename (validated before writing).

        Args:
            instance_id: Instance identifier (validated against path traversal).
            record: JSON-serialisable dict that MUST contain an ``"id"`` key
                matching the finding ID whitelist (``^f_[a-z0-9]{16,32}$``).
            provider: Provider slug used to select the storage sub-directory.

        Returns:
            The ``Path`` of the written finding JSON file.

        Raises:
            ValueError: If *instance_id* or ``record["id"]`` fails safety
                validation.
            KeyError: If *record* has no ``"id"`` key.
        """
        _validate_instance_id(instance_id)
        finding_id = record["id"]
        _validate_finding_id(finding_id)
        findings_dir = self._findings_dir(instance_id, provider)
        findings_dir.mkdir(parents=True, exist_ok=True)
        path = findings_dir / f"{finding_id}.json"
        _atomic_write_json(path, record)
        logger.debug(
            "Saved finding %s for %s at %s", finding_id, instance_id, path
        )
        return path

    def get_finding(
        self,
        instance_id: str,
        finding_id: str,
        provider: str = "custom",
    ) -> Optional[Dict[str, Any]]:
        """Return the stored dict for *finding_id*, or ``None`` if absent.

        Args:
            instance_id: Instance identifier.
            finding_id: Finding identifier (validated against path traversal).
            provider: Provider slug.

        Returns:
            Parsed JSON dict, or ``None`` if the file is missing, unreadable,
            or contains malformed JSON.

        Raises:
            ValueError: If *instance_id* or *finding_id* fails safety validation.
        """
        _validate_instance_id(instance_id)
        _validate_finding_id(finding_id)
        path = self._findings_dir(instance_id, provider) / f"{finding_id}.json"
        if not path.exists():
            return None
        try:
            with open(path, "r") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "Could not read finding %s for %s: %s", finding_id, instance_id, exc
            )
            return None

    def list_findings(
        self,
        instance_id: str,
        provider: str = "custom",
        *,
        include_superseded: bool = False,
    ) -> List[Dict[str, Any]]:
        """Return all findings for *instance_id*, sorted newest-first by ``created_at``.

        Args:
            instance_id: Instance identifier (validated against path traversal).
            provider: Provider slug.
            include_superseded: When ``False`` (default), findings whose
                ``"superseded_by"`` key is non-empty are excluded.  Pass
                ``True`` to include them.

        Returns:
            List of finding dicts.  Malformed files are silently skipped.
            Results are sorted descending by ``"created_at"``; findings without
            that key sort last (treated as earliest).

        Raises:
            ValueError: If *instance_id* fails safety validation.
        """
        _validate_instance_id(instance_id)
        findings_dir = self._findings_dir(instance_id, provider)
        if not findings_dir.exists():
            return []

        results: List[Dict[str, Any]] = []
        for json_file in findings_dir.glob("*.json"):
            try:
                with open(json_file, "r") as fh:
                    record: Dict[str, Any] = json.load(fh)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Skipping corrupt finding file %s: %s", json_file, exc)
                continue
            if not include_superseded and record.get("superseded_by"):
                continue
            results.append(record)

        # Sort newest-first; findings without created_at sort after those that have it.
        results.sort(key=lambda r: r.get("created_at") or "", reverse=True)
        return results

    def delete_finding(
        self,
        instance_id: str,
        finding_id: str,
        provider: str = "custom",
    ) -> bool:
        """Delete the finding file for *finding_id* if it exists.

        Args:
            instance_id: Instance identifier.
            finding_id: Finding identifier (validated against path traversal).
            provider: Provider slug.

        Returns:
            ``True`` if the file existed and was deleted; ``False`` if the
            file was not found.

        Raises:
            ValueError: If *instance_id* or *finding_id* fails safety validation.
        """
        _validate_instance_id(instance_id)
        _validate_finding_id(finding_id)
        path = self._findings_dir(instance_id, provider) / f"{finding_id}.json"
        if not path.exists():
            return False
        try:
            path.unlink()
            logger.debug("Deleted finding %s for %s", finding_id, instance_id)
            return True
        except OSError as exc:
            logger.warning(
                "Could not delete finding %s for %s: %s", finding_id, instance_id, exc
            )
            return False

    def get_findings_meta(self, instance_id: str) -> Dict[str, Any]:
        """Return findings bookkeeping keys from the index entry for *instance_id*.

        The two keys returned are:

        - ``findings_count`` — number of findings recorded (or ``0``).
        - ``findings_synced_at`` — ISO-8601 UTC of last sync push (or ``""``).

        Args:
            instance_id: Instance identifier (validated against path traversal).

        Returns:
            Dict with the two findings meta keys at their defaults.

        Raises:
            ValueError: If *instance_id* fails safety validation.
        """
        _validate_instance_id(instance_id)
        entry = self._load_index().get("instances", {}).get(instance_id, {})
        return {
            "findings_count": entry.get("findings_count", 0),
            "findings_synced_at": entry.get("findings_synced_at", ""),
        }

    def set_findings_meta(
        self,
        instance_id: str,
        *,
        findings_count: Optional[int] = None,
        findings_synced_at: Optional[str] = None,
    ) -> None:
        """Update findings bookkeeping keys in the index entry for *instance_id*.

        Only the explicitly provided (non-``None``) keys are written; all other
        keys on the existing index entry are left untouched.  If no entry exists
        yet a minimal one is created so the keys can be stored without requiring
        the caller to pass ``name`` / ``provider`` (mirrors
        :meth:`set_annotations_meta`).

        Args:
            instance_id: Instance identifier (validated against path traversal).
            findings_count: Total number of findings for this instance.
            findings_synced_at: ISO-8601 UTC of last cloud sync push.

        Raises:
            ValueError: If *instance_id* fails safety validation.
        """
        _validate_instance_id(instance_id)
        index = self._load_index()
        instances = index.setdefault("instances", {})
        entry = instances.setdefault(instance_id, {})
        if findings_count is not None:
            entry["findings_count"] = findings_count
        if findings_synced_at is not None:
            entry["findings_synced_at"] = findings_synced_at
        self._save_index(index)
