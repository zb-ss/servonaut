"""Thin client over the Servonaut /api/ai/conversations/* surface.

Exposes a small CRUD client for the "Previous chats" panel and Markdown /
JSON export helpers. Caching is local-only (60s TTL) and is invalidated
defensively on every mutating call.

Path-traversal hardening (Risk register §10) for the export helpers: the
destination must resolve under either ``Path.cwd()`` or
``Path.home() / "Downloads"`` and the file is written atomically via a
``.tmp`` sibling + ``os.replace``.

This module is intentionally UI-free; screens and CLI subcommands wrap it.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient

logger = logging.getLogger(__name__)


_VALID_STATUSES = ("active", "archived", "deleted")
_LIST_CACHE_TTL_SECONDS = 60.0
_LIMIT_MIN = 1
_LIMIT_MAX = 100


@dataclass
class ConversationSummary:
    """One row in the Previous-chats list."""

    id: str
    title: str
    status: str          # "active" | "archived" | "deleted"
    created_at: str      # ISO 8601
    updated_at: str      # ISO 8601
    message_count: int
    last_model: str      # may be empty for unfinished threads


def _is_under(path: Path, root: Path) -> bool:
    """Backport-friendly ``is_relative_to`` (Path.is_relative_to is 3.9+)."""
    try:
        return path.is_relative_to(root)
    except AttributeError:  # pragma: no cover — defensive only
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False


class AIConversationsClient:
    """CRUD + export helpers for /api/ai/conversations."""

    def __init__(self, api_client: "APIClient") -> None:
        self._api = api_client
        # Keyed by (status, before_or_empty) — list responses only.
        self._cache: Dict[Tuple[str, str], Tuple[float, List[ConversationSummary]]] = {}

    # -- list -----------------------------------------------------------------

    async def list(
        self,
        *,
        limit: int = 25,
        before: Optional[str] = None,
        status: str = "active",
    ) -> List[ConversationSummary]:
        """List conversations for the current user.

        ``status`` is validated client-side (no round-trip on bad input).
        ``limit`` is silently clamped to [1, 100] with a warning.
        ``before`` is a server-issued ISO cursor — passed through as-is.
        """
        if status not in _VALID_STATUSES:
            raise ValueError(
                f"status must be one of {_VALID_STATUSES!r}, got {status!r}"
            )

        clamped = limit
        if limit < _LIMIT_MIN:
            clamped = _LIMIT_MIN
        elif limit > _LIMIT_MAX:
            clamped = _LIMIT_MAX
        if clamped != limit:
            logger.warning(
                "list(limit=%d) out of range; clamped to %d", limit, clamped
            )

        cache_key = (status, before or "")
        cached = self._cache.get(cache_key)
        now = time.monotonic()
        if cached is not None and (now - cached[0]) < _LIST_CACHE_TTL_SECONDS:
            return list(cached[1])

        params: Dict[str, Any] = {"limit": clamped, "status": status}
        if before:
            params["before"] = before

        response = await self._api.get(
            "/api/ai/conversations", params=params
        )

        # Server returns {"items": [...], "next_before": "..."} canonically,
        # but tolerate a bare list response if the contract ever flattens.
        if isinstance(response, list):
            raw_items = response
        elif isinstance(response, dict):
            raw_items = response.get("items", []) or []
        else:
            logger.warning("Unexpected list response type: %r", type(response))
            raw_items = []

        summaries = [self._summary_from_dict(d) for d in raw_items if isinstance(d, dict)]
        self._cache[cache_key] = (now, list(summaries))
        return summaries

    # -- get / patch / delete -------------------------------------------------

    async def get(self, uuid: str) -> dict:
        """Return the full thread payload (assistant + user + tool messages)."""
        return await self._api.get(f"/api/ai/conversations/{uuid}")

    async def patch(
        self,
        uuid: str,
        *,
        title: Optional[str] = None,
        status: Optional[str] = None,
    ) -> dict:
        """Rename / archive / restore a conversation. None keys are omitted."""
        if status is not None and status not in _VALID_STATUSES:
            raise ValueError(
                f"status must be one of {_VALID_STATUSES!r}, got {status!r}"
            )

        payload: Dict[str, Any] = {}
        if title is not None:
            payload["title"] = title
        if status is not None:
            payload["status"] = status

        result = await self._api.patch(
            f"/api/ai/conversations/{uuid}", json=payload
        )
        # Any mutation invalidates the entire list cache — simpler than
        # surgically updating per-key entries when status moves a row.
        self._cache.clear()
        return result

    async def delete(self, uuid: str) -> None:
        """Soft-delete a conversation. Server returns 204 — we return None."""
        await self._api.delete(f"/api/ai/conversations/{uuid}")
        self._cache.clear()
        return None

    # -- export ---------------------------------------------------------------

    async def export_md(
        self, uuid: str, dest_path: Path, *, force: bool = False,
    ) -> Path:
        """Download a Markdown export of the thread to ``dest_path``.

        Args:
            uuid: Conversation UUID.
            dest_path: Local destination path. Validated to be inside
                ``Path.cwd()`` or ``~/Downloads`` (Risk register §10).
            force: When True, allow overwriting an existing file
                **after** path-validation passes. The unlink happens
                inside the validated scope so a malicious caller cannot
                use ``force=True`` to delete files outside CWD/Downloads
                before the validator runs (A6).
        """
        return await self._download_export(
            uuid, dest_path, suffix="md", force=force,
        )

    async def export_json(
        self, uuid: str, dest_path: Path, *, force: bool = False,
    ) -> Path:
        """Download a JSON export of the thread to ``dest_path``.

        See :meth:`export_md` for ``force`` semantics — same A6 invariant
        applies here: validation runs first, unlink only afterwards.
        """
        return await self._download_export(
            uuid, dest_path, suffix="json", force=force,
        )

    # -- internals ------------------------------------------------------------

    async def _download_export(
        self,
        uuid: str,
        dest_path: Path,
        *,
        suffix: str,
        force: bool = False,
    ) -> Path:
        # A6 — validation FIRST. If dest_path resolves outside CWD/~Downloads
        # we raise ValueError BEFORE any unlink — even when force=True.
        # This protects callers from a "rm /etc/sudoers" footgun in --force.
        resolved = self._validate_export_path(dest_path, force=force)

        path = f"/api/ai/conversations/{uuid}/export.{suffix}"
        content, _headers = await self._api.get_bytes(path)

        # Atomic write: write to <dest>.tmp then os.replace to final.
        tmp_path = resolved.with_suffix(resolved.suffix + ".tmp")
        try:
            tmp_path.write_bytes(content)
            os.replace(tmp_path, resolved)
        except Exception:
            # Best-effort cleanup of the temp file before re-raising.
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except OSError:  # pragma: no cover — best-effort
                pass
            raise
        return resolved

    @staticmethod
    def _validate_export_path(dest_path: Path, *, force: bool = False) -> Path:
        """Ensure ``dest_path`` resolves under CWD or ~/Downloads.

        Order of checks (A6):
            1. Path-traversal validation FIRST. ``ValueError`` is raised
               before *any* mutation of the filesystem when ``dest_path``
               escapes CWD/Downloads.
            2. Existence check ONLY fires when ``force`` is False — when
               ``force`` is True we permit overwrite, but only after the
               path is provably inside the allowed roots. The actual
               unlink happens in :meth:`_download_export` via
               :func:`os.replace` of the atomic ``.tmp`` file.

        Returns:
            The resolved absolute path.
        """
        resolved = dest_path.resolve()

        cwd = Path.cwd().resolve()
        downloads = (Path.home() / "Downloads").resolve()
        if not (_is_under(resolved, cwd) or _is_under(resolved, downloads)):
            raise ValueError(
                "Export path must be inside CWD or ~/Downloads"
            )

        # Only refuse-to-overwrite when force is False. force=True permits
        # clobber — but only because we've already verified the path is
        # safely inside CWD or ~/Downloads.
        if not force and resolved.exists():
            raise FileExistsError(
                f"Refusing to overwrite existing file: {resolved}"
            )
        return resolved

    @staticmethod
    def _summary_from_dict(d: dict) -> ConversationSummary:
        """Defensive unmarshal — server keys may be missing on partial rows."""
        return ConversationSummary(
            id=str(d.get("id", "")),
            title=str(d.get("title", "")),
            status=str(d.get("status", "active")),
            created_at=str(d.get("created_at", "")),
            updated_at=str(d.get("updated_at", "")),
            message_count=int(d.get("message_count", 0) or 0),
            last_model=str(d.get("last_model", "")),
        )
