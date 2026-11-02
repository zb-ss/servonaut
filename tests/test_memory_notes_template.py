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

    def test_an_unclosed_comment_opener_is_text(self):
        # As in rendered Markdown: without a closing --> it is not a comment.
        assert has_notes("<!-- started a comment\nand never closed it") is True

    def test_a_byte_order_mark_does_not_turn_the_template_into_notes(self):
        assert has_notes("\ufeff" + TEMPLATE) is False

    def test_a_server_name_with_a_line_break_stays_on_the_title_line(self):
        assert has_notes(notes_template("web\n1", "i-abc123", "aws")) is False


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

    def test_comment_markers_inside_code_are_kept(self):
        runbook = (
            "Find stray markers with `grep -rn '<!--' templates/`.\n"
            "```\n<!--#include virtual=\"/footer.html\" -->\n```\n"
            "Then reload nginx."
        )
        assert strip_comments(runbook) == runbook
        assert "Then reload nginx." in notes_for_display(runbook)


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
    def test_a_template_only_copy_is_verified_without_being_merged(self, tmp_path):
        from servonaut.services.memory.team_merge import MemoryKey, TeamCopyMerger

        service = _memory_service(tmp_path)
        service.write_annotations("share-1", TEMPLATE, "aws")
        service.write_annotations("i-abc123", "Primary billing API.", "aws")
        stats = TeamCopyMerger(service).merge(
            MemoryKey("aws", "share-1"), MemoryKey("aws", "i-abc123"),
            source_label="team-a", merged_on="2030-01-01",
        )
        assert stats.verified and stats.notes == 0 and not stats.held_notes
        assert service.read_annotations("i-abc123", "aws") == "Primary billing API."

    def test_a_template_from_the_service_is_verified_too(self, tmp_path):
        from servonaut.services.memory.team_merge import MemoryKey, TeamCopyMerger

        service = _memory_service(tmp_path)
        service.write_annotations("i-abc123", "Primary billing API.", "aws")
        own = MemoryKey("aws", "i-abc123")
        stats = TeamCopyMerger(service).merge(
            own, own, source_label="team-a", merged_on="2030-01-01", remote_notes=TEMPLATE,
        )
        assert stats.verified and stats.notes == 0

    def test_a_template_copy_adds_nothing(self):
        own = "Primary billing API."
        assert merge_annotation_text(own, TEMPLATE, source="team-a", merged_on="2030-01-01") == (
            own, False,
        )

    def test_a_copy_with_notes_is_still_merged(self):
        copy = _filled("## Runbook", "Restart php-fpm after deploys.")
        text, changed = merge_annotation_text("", copy, source="team-a", merged_on="2030-01-01")
        assert changed and "Restart php-fpm" in text


class TestEditorExit:
    """After the external editor closes, the template it was seeded with is not recorded."""

    def _record(self, service: MemoryService, seeded=None):
        from servonaut.screens.memory import MemoryScreen

        return MemoryScreen._store_annotations_hash("i-abc123", "aws", service, seeded)

    def test_the_untouched_seeded_template_is_not_recorded(self, tmp_path):
        service = _memory_service(tmp_path)
        service.write_annotations("i-abc123", TEMPLATE, "aws")
        assert self._record(service, seeded=TEMPLATE) is None
        assert not service.get_annotations_meta("i-abc123").get("annotations_hash")

    def test_notes_never_recorded_and_then_emptied_are_recorded(self, tmp_path):
        # Notes from an older release (no hash on record) cleared by hand:
        # the deletion must reach sync, or a pull would bring the notes back.
        service = _memory_service(tmp_path)
        service.write_annotations("i-abc123", "", "aws")
        recorded = self._record(service)
        assert recorded is not None and recorded[0] == ""

    def test_filled_notes_are_recorded(self, tmp_path):
        service = _memory_service(tmp_path)
        text = _filled("## Purpose", "Primary billing API.")
        service.write_annotations("i-abc123", text, "aws")
        recorded = self._record(service)
        assert recorded is not None and recorded[0] == text

    def test_notes_cleared_back_to_the_template_are_recorded(self, tmp_path):
        # Once notes were recorded, emptying them is a change sync must carry.
        service = _memory_service(tmp_path)
        service.write_annotations("i-abc123", "Primary billing API.", "aws")
        assert self._record(service) is not None
        service.write_annotations("i-abc123", TEMPLATE, "aws")
        recorded = self._record(service)
        assert recorded is not None and recorded[0] == TEMPLATE


class TestPull:
    """Pulling the service's notes over a template nobody filled in."""

    def test_an_untouched_template_takes_the_services_notes(self, tmp_path):
        from tests.test_pull_annotations_cases import _Notes

        notes = _Notes(tmp_path, remote="Real notes from another device")
        notes.put_file(TEMPLATE.encode())  # seeded just now: newer than the service's
        assert notes.pull() == "updated"
        assert notes.on_disk() == b"Real notes from another device"

    def test_a_template_recorded_on_purpose_is_judged_by_its_age(self, tmp_path):
        from tests.test_pull_annotations_cases import OWN_ID, _Notes

        notes = _Notes(tmp_path, remote="older notes")
        notes.service.write_annotations(
            OWN_ID, TEMPLATE, "aws", modified_at="2026-03-01T00:00:00+00:00",
        )
        assert notes.pull() == "local_newer"
        assert notes.on_disk() == TEMPLATE.encode()
