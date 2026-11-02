"""The seeded notes template is not notes, wherever Servonaut asks.

Opening a server's notes once seeds a template (title, primer comment, empty
sections). Left as it is, the summary, the MCP tools, sync and the team
merge must all treat the server as having no notes.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory.notes import (
    has_notes,
    notes_for_display,
    notes_template,
    strip_comments,
)
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.store import MemoryStore
from servonaut.services.memory.summariser import Summariser
from servonaut.services.memory.team_merge import merge_annotation_text

TEMPLATE = notes_template("web-1", "i-abc123", "aws")


def _filled(section: str, text: str) -> str:
    """The template with *text* written under *section*."""
    return TEMPLATE.replace(f"{section}\n\n", f"{section}\n\n{text}\n\n", 1)


# ---------------------------------------------------------------------------
# The helper
# ---------------------------------------------------------------------------

class TestHasNotes:
    def test_the_template_is_not_notes(self):
        assert has_notes(TEMPLATE) is False

    @pytest.mark.parametrize("text", ["", "   \n\n", "<!-- just a comment -->"])
    def test_empty_or_comment_only_is_not_notes(self, text):
        assert has_notes(text) is False

    def test_text_under_a_template_section_is_notes(self):
        assert has_notes(_filled("## Runbook", "Restart php-fpm after deploys.")) is True

    def test_plain_text_is_notes(self):
        assert has_notes("This is the staging DB. Do not restart.") is True

    def test_a_heading_the_user_wrote_is_notes(self):
        assert has_notes("# Do not reboot during business hours") is True

    def test_an_unterminated_comment_hides_the_rest(self):
        assert has_notes("<!-- started a comment\nand never closed it") is False


class TestNotesForDisplay:
    def test_the_template_shows_nothing(self):
        assert notes_for_display(TEMPLATE) == ""

    def test_keeps_what_the_user_wrote_and_drops_the_scaffolding(self):
        shown = notes_for_display(_filled("## Runbook", "Restart php-fpm after deploys."))
        assert shown == "## Runbook\n\nRestart php-fpm after deploys."

    def test_plain_notes_are_shown_as_written(self):
        assert notes_for_display("line one\nline two") == "line one\nline two"

    def test_strip_comments_collapses_blank_runs(self):
        assert strip_comments("a\n\n<!-- x -->\n\n\nb") == "a\n\nb"


# ---------------------------------------------------------------------------
# Everywhere that decides whether a server has notes
# ---------------------------------------------------------------------------

class TestSummary:
    def _summary(self, tmp_path: Path, text: str) -> str:
        directory = tmp_path / "aws" / "i-abc123"
        directory.mkdir(parents=True)
        (directory / "annotations.md").write_text(text)
        return Summariser(annotations_dir=directory).summarise(
            {"id": "i-abc123", "name": "web-1", "provider": "aws"}, {}
        )

    def test_a_bare_template_is_not_presented_as_notes(self, tmp_path):
        assert "## Annotations" not in self._summary(tmp_path, TEMPLATE)

    def test_filled_notes_are_included_without_the_primer(self, tmp_path):
        summary = self._summary(tmp_path, _filled("## Purpose", "Primary billing API."))
        assert "## Annotations" in summary
        assert "Primary billing API." in summary
        assert "one-shot primer" not in summary


def _memory_service(tmp_path: Path) -> MemoryService:
    return MemoryService(
        store=MemoryStore(root=tmp_path), config=MemoryConfig(enabled=True), probers=[],
    )


def test_mcp_reports_a_template_only_record_as_missing(tmp_path):
    from tests.test_mcp_findings_tools import _make_tools

    service = _memory_service(tmp_path)
    service.write_annotations("i-abc123", TEMPLATE, "aws")
    tools = _make_tools(memory_service=service)
    result = asyncio.run(tools.get_server_memory("i-abc123", format="summary"))
    assert json.loads(result)["error"]["code"] == "missing"


def test_sync_backfill_skips_a_bare_template(tmp_path):
    from tests.test_memory_annotations_sync import _make_service

    notes = {"web-1": TEMPLATE, "db-1": "Replica lags during backups."}
    memory = MagicMock()
    memory.is_memory_disabled.return_value = False
    memory.list_all.return_value = [
        {"instance_id": iid, "name": iid, "provider": "custom"} for iid in notes
    ]
    memory.get_all_modules.return_value = {}
    memory.read_annotations.side_effect = lambda iid, provider="custom": notes[iid]
    memory.get_annotations_meta.return_value = {}
    sync = _make_service(memory_service=memory, tmp_path=tmp_path)

    assert sync.backfill_from_local_store() == 1
    assert {(e.instance_id, e.module) for e in sync._pending} == {("db-1", "annotations")}


class TestTeamMerge:
    def test_a_template_copy_adds_nothing(self):
        own = "Primary billing API."
        assert merge_annotation_text(own, TEMPLATE, source="team-a", merged_on="2030-01-01") == (
            own, False,
        )

    def test_a_copy_with_notes_is_still_merged(self):
        copy = _filled("## Runbook", "Restart php-fpm after deploys.")
        text, changed = merge_annotation_text("", copy, source="team-a", merged_on="2030-01-01")
        assert changed and "Restart php-fpm" in text
