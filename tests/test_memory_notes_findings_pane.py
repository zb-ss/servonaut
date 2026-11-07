"""The Memory screen shows a server's notes and its agent findings.

Before, only probed modules were listed: notes were reachable through the
editor alone, and findings agents saved had no view in the app at all.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App, ComposeResult
from textual.widgets import DataTable, Footer, Static, TextArea

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory.notes import notes_template
from servonaut.services.memory.redaction import noop_redactor
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.shared_view import SharedMemory
from servonaut.services.memory.store import MemoryStore
from servonaut.widgets.safe_header import SafeHeader

pytestmark = pytest.mark.asyncio

ROW: Dict[str, Any] = {"id": "i-abc123", "name": "web-1", "provider": "aws"}
SHARED_ROW: Dict[str, Any] = {
    "id": "share-1", "name": "web-2", "provider": "Team Team A", "is_shared": True,
    "team_slug": "team-a", "team_name": "Team A", "instance_id": "i-owner-1",
    "public_ip": "1.2.3.4", "port": 22, "username": "deploy", "state": "shared",
}


def _service(tmp_path: Path, config: Optional[MemoryConfig] = None) -> MemoryService:
    store = MemoryStore(root=tmp_path, redactor=noop_redactor)
    return MemoryService(store=store, config=config or MemoryConfig(), probers=[])


def _host(
    service: MemoryService,
    row: Dict[str, Any] = ROW,
    *,
    config: Optional[MemoryConfig] = None,
    shared: Optional[SharedMemory] = None,
    demo: bool = False,
):
    from servonaut.screens.memory import MemoryScreen

    reader = None
    if shared is not None:
        reader = MagicMock()
        reader.read = AsyncMock(return_value=shared)

    class Host(App):
        CSS = ""
        memory_service = service
        shared_memory_reader = reader
        demo_mode = demo
        instances = [dict(row)]

        def compose(self) -> ComposeResult:
            yield SafeHeader()
            yield Footer()

        def on_mount(self) -> None:
            if config is not None:
                self.config_manager = MagicMock()
                self.config_manager.get.return_value.memory = config
            if demo:
                self.redaction_service = MagicMock()
                self.redaction_service.redact_name = lambda name: "stand-in"
                self.redaction_service.scrub_stream = lambda text: text.replace("php-fpm", "<svc>")
            self.push_screen(MemoryScreen(dict(row)))

    return Host()


async def _until(pilot, predicate, what: str):
    for _ in range(200):
        await pilot.pause(0.02)
        try:
            if predicate():
                return
        except Exception:  # noqa: BLE001 - the screen may not be mounted yet
            pass
    raise AssertionError(f"timed out waiting for {what}")


def _notes(app) -> str:
    return str(app.screen.query_one("#memory-notes", Static).render())


def _heading(app) -> str:
    return str(app.screen.query_one("#memory-findings-heading", Static).render())


def _rows(app) -> list:
    table = app.screen.query_one("#memory-findings-table", DataTable)
    return [[str(cell) for cell in table.get_row_at(i)] for i in range(table.row_count)]


def _remember(service: MemoryService, title: str, **fields: Any) -> str:
    fields.setdefault("body", "detail")
    fields.setdefault("source", "agent")
    fields.setdefault("confidence", 0.9)
    return service.store_finding(dict(ROW), title=title, **fields)["finding_id"]


TEMPLATE = notes_template("web-1", "i-abc123", "aws")


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------

async def test_real_notes_are_shown_without_the_template_scaffolding(tmp_path):
    service = _service(tmp_path)
    service.write_annotations(
        "i-abc123",
        TEMPLATE.replace("## Runbook\n\n", "## Runbook\n\nRestart php-fpm after deploys.\n\n"),
        "aws",
    )
    app = _host(service)
    async with app.run_test(headless=True) as pilot:
        await _until(pilot, lambda: "Restart" in _notes(app), "the notes")
        assert _notes(app) == "## Runbook\n\nRestart php-fpm after deploys."


async def test_a_bare_template_reads_as_no_notes(tmp_path):
    service = _service(tmp_path)
    service.write_annotations("i-abc123", TEMPLATE, "aws")
    app = _host(service)
    async with app.run_test(headless=True) as pilot:
        await _until(pilot, lambda: _notes(app), "the notes panel")
        assert _notes(app) == "No notes yet. Press a to add some."


async def test_long_notes_are_cut_with_a_count(tmp_path):
    service = _service(tmp_path)
    service.write_annotations("i-abc123", "\n".join(f"line {n}" for n in range(1, 21)), "aws")
    app = _host(service, config=MemoryConfig(notes_preview_lines=3))
    async with app.run_test(headless=True) as pilot:
        await _until(pilot, lambda: "line 1" in _notes(app), "the notes")
        assert _notes(app) == "line 1\nline 2\nline 3\n… 17 more lines. Press a to read them all."


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

async def test_findings_are_listed_and_superseded_ones_shown_on_request(tmp_path):
    service = _service(tmp_path)
    old = _remember(service, "nginx reload needs php-fpm first")
    _remember(service, "nginx reload waits for the php-fpm socket", supersede_id=old)
    _remember(service, "cron runs twice on DST change", confidence=0.4)
    app = _host(service)
    async with app.run_test(headless=True) as pilot:
        await _until(pilot, lambda: len(_rows(app)) == 2, "two findings")
        assert _heading(app) == "Agent findings (2)  · 1 superseded — press f to show"
        assert _rows(app) == [
            ["cron runs twice on DST change", "agent", "0.40 · recall only", _rows(app)[0][3]],
            ["nginx reload waits for the php-fpm socket", "agent", "0.90", _rows(app)[1][3]],
        ]
        app.screen.query_one("#memory-findings-table", DataTable).focus()
        await pilot.press("f")
        await _until(pilot, lambda: len(_rows(app)) == 3, "the superseded finding")
        assert _rows(app)[2][0] == "(superseded) nginx reload needs php-fpm first"
        assert _heading(app).endswith("press f to hide")


async def test_no_findings_says_where_they_come_from(tmp_path):
    app = _host(_service(tmp_path))
    async with app.run_test(headless=True) as pilot:
        empty = app.screen.query_one("#memory-findings-empty", Static)
        await _until(pilot, lambda: not empty.has_class("hidden"), "the empty line")
        assert "No findings recorded yet" in str(empty.render())
        assert _heading(app) == "Agent findings (0)"
        assert not app.screen.query_one("#memory-findings-table").display


async def test_markup_in_a_finding_title_is_shown_literally(tmp_path):
    service = _service(tmp_path)
    _remember(service, "[bold]restart[/bold] the worker [/]")
    app = _host(service)
    async with app.run_test(headless=True) as pilot:
        await _until(pilot, lambda: _rows(app), "the finding")
        table = app.screen.query_one("#memory-findings-table", DataTable)
        title = table.get_row_at(0)[0]
        # Literal text with no style of its own: the brackets were not parsed.
        assert title.plain == "[bold]restart[/bold] the worker [/]" and not title.spans
        await pilot.pause(0.1)  # drawn: "[/]" as markup would have raised


async def test_enter_opens_a_finding_with_its_body_and_what_it_replaced(tmp_path):
    from servonaut.screens.memory_authored import MemoryFindingScreen

    service = _service(tmp_path)
    old = _remember(service, "nginx reload needs php-fpm first")
    _remember(
        service, "nginx reload waits for the php-fpm socket",
        supersede_id=old, body="Reloading before the socket exists returns 502.",
        tags=["nginx", "deploy"],
    )
    app = _host(service)
    async with app.run_test(headless=True) as pilot:
        await _until(pilot, lambda: _rows(app), "the finding")
        app.screen.query_one("#memory-findings-table", DataTable).focus()
        await pilot.press("enter")
        await _until(pilot, lambda: isinstance(app.screen, MemoryFindingScreen), "the detail")
        screen = app.screen

        def text(selector: str) -> str:
            return str(screen.query_one(selector, Static).render())

        assert text("#memory-finding-title") == "nginx reload waits for the php-fpm socket"
        assert text("#memory-finding-body") == "Reloading before the socket exists returns 502."
        assert "Tags: nginx, deploy" in text("#memory-finding-meta")
        assert "Confidence: 0.90 (added to AI context)" in text("#memory-finding-meta")
        assert text("#memory-finding-chain").startswith("Replaces:\n  nginx reload needs php-fpm first")
        assert "not verified" in text("#memory-finding-notice")
        await pilot.press("escape")
        await _until(pilot, lambda: type(app.screen).__name__ == "MemoryScreen", "the way back")


# ---------------------------------------------------------------------------
# Shared copies, demo mode, opt-out
# ---------------------------------------------------------------------------

def _shared_authored() -> SharedMemory:
    return SharedMemory("team-a", "Team A", {
        "annotations": {"observed": {}, "declared": {}, "content": "Owned by the payments team.",
                        "probed_at": "2026-10-20T08:00:00+00:00"},
        "findings": {"observed": {}, "declared": {}, "probed_at": "2026-10-20T08:00:00+00:00",
                     "findings": [{"id": "f_team1", "title": "disk fills from php-fpm logs",
                                   "source": "agent", "confidence": 0.8,
                                   "created_at": "2026-10-19T08:00:00+00:00"}]},
    })


async def test_a_teams_notes_and_findings_are_labelled_with_the_team(tmp_path):
    app = _host(_service(tmp_path), SHARED_ROW, shared=_shared_authored())
    async with app.run_test(headless=True) as pilot:
        await _until(pilot, lambda: _rows(app), "the shared finding")
        assert _notes(app) == "Shared by Team A (read-only)\nOwned by the payments team."
        assert _rows(app)[0][:3] == ["disk fills from php-fpm logs", "agent · shared by Team A", "0.80"]


async def test_demo_mode_scrubs_authored_text_and_team_names(tmp_path):
    app = _host(_service(tmp_path), SHARED_ROW, shared=_shared_authored(), demo=True)
    async with app.run_test(headless=True) as pilot:
        await _until(pilot, lambda: _rows(app), "the shared finding")
        assert _notes(app).startswith("Shared by stand-in (read-only)")
        assert _rows(app)[0][:2] == ["disk fills from <svc> logs", "agent · shared by stand-in"]


async def test_an_opted_out_server_shows_no_notes_or_findings(tmp_path):
    config = MemoryConfig(per_server_overrides={"i-abc123": {"memory_disabled": True}})
    service = _service(tmp_path, config)
    app = _host(service)
    async with app.run_test(headless=True) as pilot:
        section = app.screen.query_one("#memory-authored")
        await _until(pilot, lambda: section.has_class("hidden"), "the hidden panels")


async def test_a_long_notes_setting_written_as_a_float_still_works(tmp_path):
    service = _service(tmp_path)
    service.write_annotations("i-abc123", "\n".join(f"line {n}" for n in range(1, 6)), "aws")
    app = _host(service, config=MemoryConfig(notes_preview_lines=2.0))
    async with app.run_test(headless=True) as pilot:
        await _until(pilot, lambda: "line 1" in _notes(app), "the notes")
        assert _notes(app).startswith("line 1\nline 2\n… 3 more lines")


async def test_a_teammates_short_note_is_not_hidden_by_a_longer_line_of_mine(tmp_path):
    service = _service(tmp_path)
    service.write_annotations("share-1", "Watch the production database.", "shared")
    shared = SharedMemory("team-a", "Team A", {
        "annotations": {"observed": {}, "declared": {}, "content": "production",
                        "probed_at": "2026-10-20T08:00:00+00:00"},
    })
    app = _host(service, SHARED_ROW, shared=shared)
    async with app.run_test(headless=True) as pilot:
        await _until(pilot, lambda: "Shared by" in _notes(app), "the team's note")
        assert _notes(app).endswith("Shared by Team A (read-only)\nproduction")


MALFORMED = [
    {"id": ["not", "text"], "title": "an id that is a list", "created_at": "2026-10-19T08:00:00"},
    {"id": "f_dup", "title": "first with a repeated id", "tags": 5,
     "superseded_by": ["x"], "created_at": "2026-10-18T08:00:00"},
    {"id": "f_dup", "title": "second with a repeated id", "confidence": "high",
     "created_at": "2026-10-17T08:00:00"},
    7,
    "a finding written as plain text",
]


@pytest.mark.parametrize("findings", [5, "not a list", MALFORMED])
async def test_a_malformed_shared_findings_payload_does_not_break_the_screen(tmp_path, findings):
    shared = SharedMemory("team-a", "Team A", {
        "findings": {"observed": {}, "declared": {}, "probed_at": "2026-10-20T08:00:00+00:00",
                     "findings": findings},
    })
    app = _host(_service(tmp_path), SHARED_ROW, shared=shared)
    async with app.run_test(headless=True) as pilot:
        heading = "Agent findings (4)" if findings is MALFORMED else "Agent findings (0)"
        await _until(pilot, lambda: _heading(app).startswith(heading), heading)
        if findings is MALFORMED:
            titles = [row[0] for row in _rows(app)]
            assert "first with a repeated id" in titles and "second with a repeated id" in titles
            app.screen.query_one("#memory-findings-table", DataTable).focus()
            await pilot.press("enter")
            await _until(pilot, lambda: type(app.screen).__name__ == "MemoryFindingScreen",
                         "the detail")


async def test_the_open_finding_follows_a_demo_mode_toggle(tmp_path):
    from servonaut.screens.memory_authored import MemoryFindingScreen

    service = _service(tmp_path)
    _remember(service, "restart php-fpm after deploys", body="php-fpm holds the socket")
    app = _host(service)
    async with app.run_test(headless=True) as pilot:
        await _until(pilot, lambda: _rows(app), "the finding")
        app.screen.query_one("#memory-findings-table", DataTable).focus()
        await pilot.press("enter")
        await _until(pilot, lambda: isinstance(app.screen, MemoryFindingScreen), "the detail")
        screen = app.screen
        app.demo_mode = True
        app.redaction_service = MagicMock()
        app.redaction_service.redact_name = lambda name: "stand-in"
        app.redaction_service.scrub_stream = lambda text: text.replace("php-fpm", "<svc>")
        screen.refresh_after_demo_toggle()
        await pilot.pause()
        assert str(screen.query_one("#memory-finding-title", Static).render()) == (
            "restart <svc> after deploys"
        )
        assert str(screen.query_one("#memory-finding-body", Static).render()) == "<svc> holds the socket"


async def test_a_read_only_row_with_only_notes_offers_no_probe(tmp_path):
    row = {
        "id": "i-owner-1", "name": "owner-web", "provider": "aws", "is_shared": True,
        "state": "shared", "memory_only": True, "team_slug": "team-a",
        "team_name": "Team A", "instance_id": "i-owner-1",
    }
    shared = SharedMemory("team-a", "Team A", {
        "annotations": {"observed": {}, "declared": {}, "content": "Owned by payments.",
                        "probed_at": "2026-10-20T08:00:00+00:00"},
    })
    app = _host(_service(tmp_path), row, shared=shared)
    async with app.run_test(headless=True) as pilot:
        await _until(pilot, lambda: "Owned by payments." in _notes(app), "the shared note")
        assert app.screen.query_one("#memory-empty-state").has_class("hidden")


@pytest.mark.parametrize("authored", [False, True], ids=["empty-authored", "with-authored"])
async def test_narrow_records_open_in_view_and_authored_content_stays_reachable(
    tmp_path, monkeypatch, authored: bool,
):
    service = _service(tmp_path)
    service._store.save_module(ROW["id"], "os", {
        "module": "os", "instance_id": ROW["id"],
        "observed": {"id": "sample-linux", "pretty_name": "Sample Linux"},
        "declared": {"id": {"value": "pinned-linux"}},
        "probed_at": datetime.now(timezone.utc).isoformat(), "ttl_seconds": 86400,
    }, provider=ROW["provider"])
    notes = "## Runbook\n\nKeep [literal] notes accessible."
    title = "Check [literal] restart order"
    finding_body = "Read the complete stored runbook before changing anything."
    if authored:
        service.write_annotations(ROW["id"], notes, ROW["provider"])
        _remember(service, title, body=finding_body)
    probe = AsyncMock(side_effect=AssertionError("Browsing stored memory must not probe"))
    monkeypatch.setattr(service, "refresh", probe)
    monkeypatch.setattr(service, "refresh_report", probe)
    app = _host(service)
    async with app.run_test(size=(100, 30), headless=True) as pilot:
        await _until(pilot, lambda: app.screen.query_one("#memory-table", DataTable).row_count == 2
                     and app.focused is app.screen.query_one("#memory-table")
                     and app.screen.has_class("-content-narrow"), "stored records")
        await pilot.pause()
        screen = app.screen
        page = screen.query_one("#memory-container")
        records = screen.query_one("#memory-table", DataTable)
        reader = screen.query_one("#memory-record-detail", TextArea)

        def painted(widget) -> str:
            region = widget.region.intersection(page.content_region).intersection(screen.region)
            strips = screen._compositor.render_strips()
            return "\n".join(strips[y].crop(region.x, region.right).text
                             for y in range(region.y, region.bottom))

        # Check final native paint before any focus/reveal can repair the opening view.
        assert page.scroll_y == 0
        assert "sample-linux" in painted(records)
        selected = records.coordinate_to_cell_key(records.cursor_coordinate).row_key
        document = reader.document
        text = reader.text
        assert "Observed\nsample-linux" in text and "Declared\npinned-linux" in text
        await pilot.press("tab")
        await _until(pilot, lambda: app.focused is reader, "the full-value reader")
        reader.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        assert "sample-linux" in painted(reader) and "pinned-linux" in painted(reader)

        if authored:
            notes_widget = screen.query_one("#memory-notes", Static)
            notes_widget.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            assert _notes(app) == notes and "Keep [literal] notes accessible." in painted(notes_widget)
            findings = screen.query_one("#memory-findings-table", DataTable)
            findings.focus()
            await _until(pilot, lambda: app.focused is findings, "the findings table")
            findings.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            assert title in painted(findings)
            await pilot.press("enter")
            await _until(pilot, lambda: type(app.screen).__name__ == "MemoryFindingScreen"
                         and str(app.screen.query_one("#memory-finding-body", Static).render()) == finding_body,
                         "the complete finding")
            assert str(app.screen.query_one("#memory-finding-title", Static).render()) == title
            await pilot.press("escape")
            await _until(pilot, lambda: app.screen is screen, "the memory page again")
        else:
            screen.query_one("#memory-authored").scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            assert "No notes yet." in painted(screen.query_one("#memory-notes"))
            assert "No findings recorded yet" in painted(screen.query_one("#memory-findings-empty"))
        assert records.coordinate_to_cell_key(records.cursor_coordinate).row_key == selected
        assert reader.document is document
        assert reader.text == text
        probe.assert_not_awaited()
        assert app._exception is None
