"""Tests for AIConversationsClient — CRUD + export path-traversal hardening."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.ai_conversations import (
    AIConversationsClient,
    ConversationSummary,
)
from servonaut.services.api_client import APIClient


def run(coro):
    """Synchronous asyncio wrapper — matches the project test convention."""
    return asyncio.run(coro)


def _make_client() -> tuple[AIConversationsClient, MagicMock]:
    api = MagicMock(spec=APIClient)
    api.get = AsyncMock()
    api.post = AsyncMock()
    api.patch = AsyncMock()
    api.delete = AsyncMock()
    api.get_bytes = AsyncMock()
    return AIConversationsClient(api), api


_SAMPLE_ITEM = {
    "id": "conv-1",
    "title": "Why is nginx 502ing?",
    "status": "active",
    "created_at": "2026-04-15T10:00:00Z",
    "updated_at": "2026-04-15T10:30:00Z",
    "message_count": 4,
    "last_model": "gemini-2-flash-002",
}


def test_list_pagination_cursor_parsed():
    """Passing a `before` cursor must propagate to the GET params."""
    client, api = _make_client()
    api.get.return_value = {"items": [_SAMPLE_ITEM], "next_before": None}

    cursor = "2026-04-01T00:00:00Z"
    summaries = run(client.list(before=cursor, limit=25))

    api.get.assert_awaited_once()
    _args, kwargs = api.get.call_args
    assert kwargs["params"]["before"] == cursor
    assert kwargs["params"]["limit"] == 25
    assert kwargs["params"]["status"] == "active"
    assert len(summaries) == 1
    assert isinstance(summaries[0], ConversationSummary)
    assert summaries[0].id == "conv-1"


def test_list_clamps_limit_above_100():
    """Out-of-range limits clamp silently (with a warning); never reach server."""
    client, api = _make_client()
    api.get.return_value = {"items": []}

    run(client.list(limit=500))

    _args, kwargs = api.get.call_args
    assert kwargs["params"]["limit"] == 100


def test_list_invalid_status_raises_value_error():
    """Unknown `status` raises before any network call."""
    client, api = _make_client()

    with pytest.raises(ValueError):
        run(client.list(status="bogus"))

    api.get.assert_not_called()


def test_get_full_thread():
    """`get(uuid)` returns the raw full-thread dict from the server."""
    client, api = _make_client()
    full_thread = {
        "id": "conv-1",
        "title": "Why is nginx 502ing?",
        "messages": [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "hello"},
        ],
    }
    api.get.return_value = full_thread

    result = run(client.get("conv-1"))

    api.get.assert_awaited_once_with("/api/ai/conversations/conv-1")
    assert result == full_thread


def test_patch_omits_none_keys():
    """`patch(uuid, title=..., status=None)` only sends `title`."""
    client, api = _make_client()
    api.patch.return_value = {"id": "conv-1", "title": "renamed"}

    run(client.patch("conv-1", title="renamed", status=None))

    api.patch.assert_awaited_once()
    _args, kwargs = api.patch.call_args
    assert kwargs["json"] == {"title": "renamed"}
    assert "status" not in kwargs["json"]


def test_delete_204():
    """`delete()` swallows the {"success": True} envelope and returns None."""
    client, api = _make_client()
    api.delete.return_value = {"success": True}

    result = run(client.delete("conv-1"))

    api.delete.assert_awaited_once_with("/api/ai/conversations/conv-1")
    assert result is None


def test_export_md_path_traversal_rejected(tmp_path, monkeypatch):
    """A destination outside CWD and ~/Downloads is rejected before any network call."""
    client, api = _make_client()

    # Pin CWD to tmp_path and HOME elsewhere so /etc/passwd is provably outside both.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    with pytest.raises(ValueError):
        run(client.export_md("conv-1", Path("/etc/passwd")))

    api.get_bytes.assert_not_called()


def test_export_md_writes_file_atomically(tmp_path, monkeypatch):
    """A valid destination under CWD writes the bytes and leaves no .tmp behind."""
    client, api = _make_client()
    monkeypatch.chdir(tmp_path)

    payload = b"# Conversation\n\nHello world\n"
    api.get_bytes.return_value = (payload, {"content-type": "text/markdown"})

    dest = tmp_path / "thread.md"
    result = run(client.export_md("conv-1", dest))

    assert result == dest.resolve()
    assert dest.exists()
    assert dest.read_bytes() == payload
    # No leftover .tmp sibling after a successful write.
    assert not (tmp_path / "thread.md.tmp").exists()
    api.get_bytes.assert_awaited_once_with(
        "/api/ai/conversations/conv-1/export.md"
    )


def test_export_refuses_to_overwrite_existing(tmp_path, monkeypatch):
    """If the destination already exists we raise FileExistsError (no clobber)."""
    client, api = _make_client()
    monkeypatch.chdir(tmp_path)

    dest = tmp_path / "thread.md"
    dest.write_text("preexisting")

    with pytest.raises(FileExistsError):
        run(client.export_md("conv-1", dest))

    api.get_bytes.assert_not_called()
    # Original content untouched.
    assert dest.read_text() == "preexisting"


# ---------------------------------------------------------------------------
# A6 — --force still respects path-traversal validation
# ---------------------------------------------------------------------------


def test_export_force_outside_cwd_still_rejected(tmp_path, monkeypatch):
    """A6 — ``force=True`` does NOT bypass the path-traversal validator.

    Previously the CLI unlinked the destination BEFORE the client's
    validator ran, which meant ``--force /etc/sudoers`` would attempt to
    delete the file even though the export itself rejected the path.
    The fix moves the unlink decision INSIDE the validated scope —
    ValueError fires first, and no unlink ever happens.
    """
    client, api = _make_client()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    # Try to overwrite a path outside CWD with force=True. Validation
    # MUST fire BEFORE any filesystem mutation.
    with pytest.raises(ValueError):
        run(client.export_md("conv-1", Path("/etc/sudoers"), force=True))

    api.get_bytes.assert_not_called()


def test_export_force_inside_cwd_overwrites(tmp_path, monkeypatch):
    """A6 — ``force=True`` permits overwrite of an existing file in CWD."""
    client, api = _make_client()
    monkeypatch.chdir(tmp_path)

    dest = tmp_path / "thread.md"
    dest.write_text("preexisting content")

    payload = b"# fresh\n"
    api.get_bytes.return_value = (payload, {"content-type": "text/markdown"})

    saved = run(client.export_md("conv-1", dest, force=True))

    assert saved == dest.resolve()
    assert dest.read_bytes() == payload


def test_cache_invalidates_on_patch():
    """list() then patch() then list() — second list() makes a fresh API call."""
    client, api = _make_client()
    api.get.return_value = {"items": [_SAMPLE_ITEM]}
    api.patch.return_value = {"id": "conv-1"}

    run(client.list())
    run(client.list())  # should hit cache
    assert api.get.await_count == 1

    run(client.patch("conv-1", title="renamed"))

    run(client.list())  # cache invalidated → second network round-trip
    assert api.get.await_count == 2
