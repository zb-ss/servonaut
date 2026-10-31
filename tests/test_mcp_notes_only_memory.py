"""Notes or findings with no probed module are existing memory, and the tool shows them."""
from __future__ import annotations

import asyncio
import json

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.store import MemoryStore
from tests.test_mcp_findings_tools import _CANNED_INSTANCE, _make_tools

NOTE = "restart the worker after deploys"


def _service(tmp_path):
    return MemoryService(store=MemoryStore(root=tmp_path), config=MemoryConfig(enabled=True), probers=[])


def _get(tools, fmt):
    return asyncio.run(tools.get_server_memory("i-abc123", format=fmt))


@pytest.mark.parametrize("fmt", ["summary", "markdown", "full", "context_block"])
def test_a_record_with_only_notes_is_returned_not_missing(tmp_path, fmt):
    service = _service(tmp_path)
    service.write_annotations("i-abc123", NOTE, "aws")
    result = _get(_make_tools(memory_service=service), fmt)
    assert '"missing"' not in result
    assert NOTE in result


def test_a_record_with_only_findings_is_returned_not_missing(tmp_path):
    service = _service(tmp_path)
    service.remember_finding(_CANNED_INSTANCE, title="cron skips on DST", body="detail")
    result = _get(_make_tools(memory_service=service), "summary")
    assert '"missing"' not in result
    assert "cron skips on DST" in result


def test_an_empty_record_is_still_missing(tmp_path):
    service = _service(tmp_path)
    service.write_annotations("i-abc123", "  \n", "aws")
    result = _get(_make_tools(memory_service=service), "summary")
    assert json.loads(result)["error"]["code"] == "missing"
